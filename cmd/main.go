package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/open-cluster-management/policy-generator-plugin/internal"
	"github.com/spf13/pflag"
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
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		errorAndExit("failed to read file '%s': %s", filePath, err)
	}

	err = p.Config(fileData, path.Dir(cwd))
	if err != nil {
		errorAndExit("error processing the PolicyGenerator file '%s': %s", filePath, err)
	}

	generatedOutput, err := p.Generate()
	if err != nil {
		errorAndExit("error generating policies from the PolicyGenerator file '%s': %s", filePath, err)
	}

	return generatedOutput
}
