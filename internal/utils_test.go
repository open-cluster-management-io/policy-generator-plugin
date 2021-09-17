// Copyright Contributors to the Open Cluster Management project
package internal

import (
	"fmt"
	"io/ioutil"
	"path"
	"reflect"
	"testing"

	"github.com/open-cluster-management/policy-generator-plugin/internal/types"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func assertEqual(t *testing.T, a interface{}, b interface{}) {
	t.Helper()
	if a != b {
		t.Fatalf("%s != %s", a, b)
	}
}

func assertReflectEqual(t *testing.T, a interface{}, b interface{}) {
	t.Helper()
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("%s != %s", a, b)
	}
}

func TestGetPolicyTemplate(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestFiles := []types.Manifest{}
	for i, enemy := range []string{"goldfish", "potato"} {
		manifestPath := path.Join(tmpDir, fmt.Sprintf("configmap%d.yaml", i))
		manifestYAML := fmt.Sprintf(
			`
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-configmap
data:
  game.properties: enemies=%s
`,
			enemy,
		)
		err := ioutil.WriteFile(manifestPath, []byte(manifestYAML), 0o666)
		if err != nil {
			t.Fatalf("Failed to write %s", manifestPath)
		}

		manifestFiles = append(manifestFiles, types.Manifest{Path: manifestPath})
	}

	// Write a bogus file to ensure it is not picked up when creating the policy
	// template
	bogusFilePath := path.Join(tmpDir, "README.md")
	err := ioutil.WriteFile(bogusFilePath, []byte("# My Manifests"), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", bogusFilePath)
	}

	// Test both passing in individual files and a flat directory
	tests := []struct{ Manifests []types.Manifest }{
		{Manifests: manifestFiles},
		{Manifests: []types.Manifest{{Path: tmpDir}}},
	}
	for _, test := range tests {
		policyConf := types.PolicyConfig{
			ComplianceType:    "musthave",
			Manifests:         test.Manifests,
			Name:              "policy-app-config",
			RemediationAction: "inform",
			Severity:          "low",
		}

		policyTemplate, err := getPolicyTemplate(&policyConf)
		if err != nil {
			t.Fatalf("Failed to get the policy template: %v", err)
		}
		objdef := (*policyTemplate)["objectDefinition"]
		assertEqual(t, objdef["metadata"].(map[string]string)["name"], "policy-app-config")
		spec, ok := objdef["spec"].(map[string]interface{})
		if !ok {
			t.Fatal("The spec field is an invalid format")
		}
		assertEqual(t, spec["remediationAction"], "inform")
		assertEqual(t, spec["severity"], "low")
		objTemplates, ok := spec["object-templates"].([]map[string]interface{})
		if !ok {
			t.Fatal("The object-templates field is an invalid format")
		}
		assertEqual(t, len(objTemplates), 2)
		assertEqual(t, objTemplates[0]["complianceType"], "musthave")
		kind1, ok := objTemplates[0]["objectDefinition"].(map[string]interface{})["kind"]
		if !ok {
			t.Fatal("The objectDefinition field is an invalid format")
		}
		assertEqual(t, kind1, "ConfigMap")
		assertEqual(t, objTemplates[1]["complianceType"], "musthave")
		kind2, ok := objTemplates[1]["objectDefinition"].(map[string]interface{})["kind"]
		if !ok {
			t.Fatal("The objectDefinition field is an invalid format")
		}
		assertEqual(t, kind2, "ConfigMap")
	}
}

func TestGetPolicyTemplatePatches(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestPath := path.Join(tmpDir, "configmap.yaml")
	manifestYAML := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-configmap
data:
  game.properties: enemies=potato
`
	err := ioutil.WriteFile(manifestPath, []byte(manifestYAML), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", manifestPath)
	}

	patches := []map[string]interface{}{
		{
			"metadata": map[string]interface{}{
				"labels": map[string]string{"chandler": "bing"},
			},
		},
		{
			"metadata": map[string]interface{}{
				"annotations": map[string]string{"monica": "geller"},
			},
		},
	}
	manifests := []types.Manifest{
		{Path: manifestPath, Patches: patches},
	}
	policyConf := types.PolicyConfig{
		Manifests: manifests,
		Name:      "policy-app-config",
	}

	policyTemplate, err := getPolicyTemplate(&policyConf)
	if err != nil {
		t.Fatalf("Failed to get the policy template: %v", err)
	}
	objdef := (*policyTemplate)["objectDefinition"]
	assertEqual(t, objdef["metadata"].(map[string]string)["name"], "policy-app-config")
	spec, ok := objdef["spec"].(map[string]interface{})
	if !ok {
		t.Fatal("The spec field is an invalid format")
	}

	objTemplates, ok := spec["object-templates"].([]map[string]interface{})
	if !ok {
		t.Fatal("The object-templates field is an invalid format")
	}
	assertEqual(t, len(objTemplates), 1)

	objDef, ok := objTemplates[0]["objectDefinition"].(map[string]interface{})
	if !ok {
		t.Fatal("The objectDefinition field is an invalid format")
	}

	metadata, ok := objDef["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("The metadata field is an invalid format")
	}

	labels, ok := metadata["labels"].(map[string]interface{})
	if !ok {
		t.Fatal("The labels field is an invalid format")
	}
	assertReflectEqual(t, labels, map[string]interface{}{"chandler": "bing"})

	annotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok {
		t.Fatal("The annotations field is an invalid format")
	}
	assertReflectEqual(t, annotations, map[string]interface{}{"monica": "geller"})
}

func TestGetPolicyTemplateNoManifests(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	policyConf := types.PolicyConfig{
		ComplianceType:    "musthave",
		Manifests:         []types.Manifest{{Path: tmpDir}},
		Name:              "policy-app-config",
		RemediationAction: "inform",
		Severity:          "low",
	}

	_, err := getPolicyTemplate(&policyConf)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "the policy policy-app-config must specify at least one non-empty manifest file"
	assertEqual(t, err.Error(), expected)
}

func TestGetPolicyTemplateInvalidPath(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestPath := path.Join(tmpDir, "does-not-exist.yaml")
	policyConf := types.PolicyConfig{
		ComplianceType:    "musthave",
		Manifests:         []types.Manifest{{Path: manifestPath}},
		Name:              "policy-app-config",
		RemediationAction: "inform",
		Severity:          "low",
	}

	_, err := getPolicyTemplate(&policyConf)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf("failed to read the manifest path %s", manifestPath)
	assertEqual(t, err.Error(), expected)
}

func TestGetPolicyTemplateInvalidManifest(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestPath := path.Join(tmpDir, "configmap.yaml")
	// Ensure an error is returned when there is an invalid manifest file
	err := ioutil.WriteFile(manifestPath, []byte("$i am not YAML!"), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", manifestPath)
	}

	policyConf := types.PolicyConfig{
		ComplianceType:    "musthave",
		Manifests:         []types.Manifest{{Path: manifestPath}},
		Name:              "policy-app-config",
		RemediationAction: "inform",
		Severity:          "low",
	}

	_, err = getPolicyTemplate(&policyConf)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf(
		"failed to decode the manifest file at %s: the input manifests must be in the format of "+
			"YAML objects", manifestPath,
	)
	assertEqual(t, err.Error(), expected)
}

func TestUnmarshalManifestFile(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestsPath := path.Join(tmpDir, "configmaps.yaml")
	yamlContent := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-configmap
data:
  game.properties: |
    enemies=goldfish
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-configmap2
data:
  game.properties: |
    enemies=potato
`
	err := ioutil.WriteFile(manifestsPath, []byte(yamlContent), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", manifestsPath)
	}

	manifests, err := unmarshalManifestFile(manifestsPath)
	if err != nil {
		t.Fatalf("Failed to unmarshal the YAML content, got: %v", err)
	}

	assertEqual(t, len(*manifests), 2)
	name1, _, _ := unstructured.NestedString((*manifests)[0], "metadata", "name")
	assertEqual(t, name1, "my-configmap")
	name2, _, _ := unstructured.NestedString((*manifests)[1], "metadata", "name")
	assertEqual(t, name2, "my-configmap2")
}

func TestUnmarshalManifestFileUnreadable(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestsPath := path.Join(tmpDir, "configmaps.yaml")
	_, err := unmarshalManifestFile(manifestsPath)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf("failed to read the manifest file %s", manifestsPath)
	assertEqual(t, err.Error(), expected)
}

func TestUnmarshalManifestFileInvalidYAML(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestPath := path.Join(tmpDir, "configmaps.yaml")
	yamlContent := `$I am not YAML`
	err := ioutil.WriteFile(manifestPath, []byte(yamlContent), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", manifestPath)
	}

	_, err = unmarshalManifestFile(manifestPath)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}
}

func TestUnmarshalManifestFileNotObject(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestPath := path.Join(tmpDir, "configmaps.yaml")
	yamlContent := `- i am an array`
	err := ioutil.WriteFile(manifestPath, []byte(yamlContent), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", manifestPath)
	}

	_, err = unmarshalManifestFile(manifestPath)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf(
		"failed to decode the manifest file at %s: the input manifests must be in the format of "+
			"YAML objects", manifestPath,
	)
	assertEqual(t, err.Error(), expected)
}
