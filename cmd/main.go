package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/spf13/pflag"
	"open-cluster-management.io/ocm-kustomize-generator-plugins/internal"
	"sigs.k8s.io/kustomize/kyaml/kio"
)

var debug = false

func main() {
	// Parse command input
	debugFlag := pflag.Bool("debug", false, "Print the stack trace with error messages")
	pflag.Parse()

	debug = *debugFlag

	// Collect and parse PolicyGeneratorConfig file paths
	generators := pflag.Args()
	var outputBuffer bytes.Buffer

	if len(generators) == 0 {
		if err := runKRMplugin(os.Stdin, os.Stdout); err != nil {
			errorAndExit(err.Error())
		}

		return
	}

	for _, gen := range generators {
		outputBuffer.Write(processGeneratorConfig(gen))
	}

	// Output results to stdout for Kustomize to handle
	// nolint:forbidigo
	fmt.Print(outputBuffer.String())
}

// errorAndExit takes a message string with formatting verbs and associated formatting
// arguments similar to fmt.Errorf(). If `debug` is set or it is given an empty message
// string, it throws a panic to print the message along with the trace. Otherwise
// it prints the formatted message to stderr and exits with error code 1.
func errorAndExit(msg string, formatArgs ...interface{}) {
	printArgs := make([]interface{}, len(formatArgs))
	copy(printArgs, formatArgs)
	// Show trace if the debug flag is set
	if msg == "" || debug {
		panic(fmt.Sprintf(msg, printArgs...))
	}

	fmt.Fprintf(os.Stderr, msg, printArgs...)
	fmt.Fprint(os.Stderr, "\n")
	os.Exit(1)
}

// processGeneratorConfig takes a string file path to a PolicyGenerator YAML file.
// It reads the file, processes and validates the contents, uses the contents to
// generate policies, and returns the generated policies as a byte array.
func processGeneratorConfig(filePath string) []byte {
	cwd, err := os.Getwd()
	if err != nil {
		errorAndExit("failed to determine the current directory: %v", err)
	}

	p := internal.Plugin{}

	// #nosec G304
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		errorAndExit("failed to read file '%s': %s", filePath, err)
	}

	err = p.Config(fileData, cwd)
	if err != nil {
		errorAndExit("error processing the PolicyGenerator file '%s': %s", filePath, err)
	}

	generatedOutput, err := p.Generate()
	if err != nil {
		errorAndExit("error generating policies from the PolicyGenerator file '%s': %s", filePath, err)
	}

	return generatedOutput
}

func runKRMplugin(input io.Reader, output io.Writer) error {
	inputReader := kio.ByteReader{Reader: input}

	inputs, err := inputReader.Read()
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	config, err := inputReader.FunctionConfig.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal KRM configuration from input: %w", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to determine the current directory: %w", err)
	}

	p := internal.Plugin{}

	err = p.Config(config, cwd)
	if err != nil {
		return fmt.Errorf("error processing the PolicyGenerator file '[stdin]': %w", err)
	}

	// in KRM generator mode, this annotation will be set by kustomize
	if inputs[0].GetAnnotations()["config.kubernetes.io/local-config"] != "true" {
		// in KRM transformer mode, convert the KRM-style input yaml into the
		// flat yaml format the generator uses, and write it to a temp file.
		inpFile, err := os.CreateTemp(".", "transformer-intput-*.yaml")
		if err != nil {
			return fmt.Errorf("error creating an input file: %w", err)
		}

		defer os.Remove(inpFile.Name()) // clean up

		inpwriter := kio.ByteWriter{
			Writer: inpFile,
			ClearAnnotations: []string{
				"config.k8s.io/id",
				"internal.config.kubernetes.io/annotations-migration-resource-id",
				"internal.config.kubernetes.io/id",
				"kustomize.config.k8s.io/id",
			},
		}

		err = inpwriter.Write(inputs)
		if err != nil {
			return fmt.Errorf("error writing input KRM yaml to the temporary manifest: %w", err)
		}

		if len(p.Policies) == 0 || len(p.Policies[0].Manifests) == 0 {
			return errors.New("no manifests in config file")
		}

		// overwrites the path in the generator yaml, from stdin to the temp file.
		p.Policies[0].Manifests[0].Path = inpFile.Name()
	}

	generatedOutput, err := p.Generate()
	if err != nil {
		return fmt.Errorf("error generating policies from the PolicyGenerator file: %w", err)
	}

	nodes, err := (&kio.ByteReader{Reader: bytes.NewReader(generatedOutput)}).Read()
	if err != nil {
		return fmt.Errorf("error reading generator output: %w", err)
	}

	// Write the result in a ResourceList
	outputWriter := kio.ByteWriter{
		Writer:             output,
		WrappingAPIVersion: "config.kubernetes.io/v1",
		WrappingKind:       "ResourceList",
	}

	err = outputWriter.Write(nodes)
	if err != nil {
		return fmt.Errorf("error writing generator output: %w", err)
	}

	return nil
}
