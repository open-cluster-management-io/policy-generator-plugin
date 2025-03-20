package internal

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"testing"
)

func TestConfigTypos(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	suggestFmt := "line %v: field %v found but not defined in type %v - did you mean '%v'?"

	tests := map[string]struct {
		desiredErrs []string
		generator   []byte
	}{
		"no typos": {
			desiredErrs: []string{},
			generator: []byte(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-minimal
policyDefaults:
  namespace: minimal
policies:
- name: my-minimal
  manifests:
  - path: @@@
`),
		},
		"one typo with suggestion": {
			desiredErrs: []string{
				fmt.Sprintf(suggestFmt, "6", "policyDefault", "PolicyGenerator", "policyDefaults"),
			},
			generator: []byte(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-minimal
policyDefault:
  namespace: minimal
policies:
- name: my-minimal
  manifests:
  - path: @@@
`),
		},
		"two typos with suggestions": {
			desiredErrs: []string{
				fmt.Sprintf(suggestFmt, "6", "policyDefault", "PolicyGenerator", "policyDefaults"),
				fmt.Sprintf(suggestFmt, "8", "policie", "PolicyGenerator", "policies"),
			},
			generator: []byte(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-minimal
policyDefault:
  namespace: minimal
policie:
- name: my-minimal
  manifests:
  - path: @@@
`),
		},
		"one deeper typo": {
			desiredErrs: []string{
				fmt.Sprintf(suggestFmt, "7", "configPolicyAnnotations", "policyDefaults",
					"configurationPolicyAnnotations"),
			},
			generator: []byte(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-minimal
policyDefaults:
  configPolicyAnnotations: {}
  namespace: minimal
policies:
- name: my-minimal
  manifests:
  - path: @@@
`),
		},
		"typo inside a list": {
			desiredErrs: []string{
				fmt.Sprintf(suggestFmt, "11", "paths", "manifests", "path"),
			},
			generator: []byte(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-minimal
policyDefaults:
  namespace: minimal
policies:
- name: my-minimal
  manifests:
  - paths: @@@
`),
		},
		"typo no suggestion": {
			desiredErrs: []string{
				"line 12: field namespace found but not defined in type manifests$",
			},
			generator: []byte(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-minimal
policyDefaults:
  namespace: minimal
policies:
- name: my-minimal
  manifests:
  - path: @@@
    namespace: foo
`),
		},
		"non-typo error": {
			desiredErrs: []string{
				"line 6: cannot unmarshal !!seq into string",
			},
			generator: []byte(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: 
  - policy-generator-minimal
policyDefaults:
  namespace: minimal
policies:
- name: my-minimal
  manifests:
  - path: @@@
`),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := Plugin{}
			generatorYaml := bytes.ReplaceAll(
				test.generator,
				[]byte(`@@@`),
				[]byte(path.Join(tmpDir, "configmap.yaml")))

			err := p.Config(generatorYaml, tmpDir)
			if err == nil && len(test.desiredErrs) > 0 {
				t.Fatal("Expected an error to be emitted, got nil")
			}

			for _, want := range test.desiredErrs {
				if match, _ := regexp.MatchString(want, err.Error()); !match {
					t.Errorf("Expected error to include '%v' - got '%v'", want, err.Error())
				}
			}
		})
	}
}
