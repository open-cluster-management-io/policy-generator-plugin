package main

import (
	"bytes"
	"fmt"
	"os"

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
	fmt.Print(outputBuffer.String())
}

// Error handler.
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

// Process generator file.
func processGeneratorConfig(filePath string) []byte {
	p := internal.Plugin{}
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		errorAndExit("failed to read file '%s': %s", filePath, err)
	}

	err = p.Config(fileData)
	if err != nil {
		errorAndExit("error processing the PolicyGenerator file '%s': %s", filePath, err)
	}

	generatedOutput, err := p.Generate()
	if err != nil {
		errorAndExit("error generating policies from the PolicyGenerator file '%s': %s", filePath, err)
	}

	return generatedOutput
}
