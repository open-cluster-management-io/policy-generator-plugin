package main

import (
	"bytes"
	"fmt"
	"os"
	runtimeDebug "runtime/debug"
	"strings"

	"github.com/spf13/pflag"

	"open-cluster-management.io/policy-generator-plugin/internal"
)

var Version string

var debug = false

func main() {
	// Parse command input
	debugFlag := pflag.Bool("debug", false, "Print the stack trace with error messages")
	helpFlag := pflag.BoolP("help", "h", false, "Print the help message")
	versionFlag := pflag.Bool("version", false, "Print the version of the generator")
	pflag.Parse()

	if *helpFlag {
		//nolint:forbidigo
		fmt.Println("Usage: PolicyGenerator [flags] <policy-generator-config-file>...")
		pflag.PrintDefaults()
		os.Exit(0)
	}

	if *versionFlag {
		if Version == "" {
			// Gather the version from the build info
			if info, ok := runtimeDebug.ReadBuildInfo(); ok {
				Version = info.Main.Version
			}

			if Version == "" || Version == "(devel)" {
				Version = "Unversioned binary"
			}
		}
		//nolint:forbidigo
		fmt.Println(strings.TrimSpace(Version))
		os.Exit(0)
	}

	debug = *debugFlag

	// Collect and parse PolicyGeneratorConfig file paths
	generators := pflag.Args()
	var outputBuffer bytes.Buffer

	for _, gen := range generators {
		outputBuffer.Write(processGeneratorConfig(gen))
	}

	// Output results to stdout for Kustomize to handle
	//nolint:forbidigo
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
	fileData, err := os.ReadFile(filePath)
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
