// Copyright Contributors to the Open Cluster Management project
package internal

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"open-cluster-management.io/policy-generator-plugin/internal/types"
)

func assertEqual(t *testing.T, a interface{}, b interface{}) {
	t.Helper()

	diff := cmp.Diff(a, b, cmpopts.EquateErrors())

	if diff != "" {
		t.Fatalf(diff)
	}
}

func assertEqualYaml(t *testing.T, a, b []byte) {
	t.Helper()

	aDec := yaml.NewDecoder(bytes.NewReader(a))
	bDec := yaml.NewDecoder(bytes.NewReader(b))

	for {
		aOut := map[string]interface{}{}
		aErr := aDec.Decode(aOut)

		bOut := map[string]interface{}{}
		bErr := bDec.Decode(bOut)

		aDone := errors.Is(aErr, io.EOF)
		bDone := errors.Is(bErr, io.EOF)

		if aDone && bDone {
			return // both inputs had the same number of documents
		} else if aDone && !bDone {
			t.Fatalf("extra yaml doc in second input")
		} else if !aDone && bDone {
			t.Fatalf("missing yaml doc in second input")
		}

		assertEqual(t, aErr, bErr)
		assertEqual(t, aOut, bOut)
	}
}

func assertReflectEqual(t *testing.T, a interface{}, b interface{}) {
	t.Helper()

	if !reflect.DeepEqual(a, b) {
		t.Fatalf("%s != %s", a, b)
	}
}

func assertSelectorEqual(t *testing.T, a map[string]interface{}, b types.NamespaceSelector) {
	t.Helper()

	if !compareSelectors(a, b) {
		t.Fatalf("%s != %s", a, b)
	}
}

func compareStringArrays(a []interface{}, b []string) bool {
	// Account for when b is []string(nil)
	if len(a) == 0 && len(b) == 0 {
		return true
	}

	// Create a string array from []interface{}
	aTyped := make([]string, len(a))
	for i, val := range a {
		aTyped[i] = val.(string)
	}

	return reflect.DeepEqual(aTyped, b)
}

func compareSelectors(a map[string]interface{}, b types.NamespaceSelector) bool {
	if includeA, ok := a["include"].([]interface{}); ok {
		if !compareStringArrays(includeA, b.Include) {
			return false
		}
	} else if len(b.Include) != 0 {
		return false
	}

	if excludeA, ok := a["exclude"].([]interface{}); ok {
		if !compareStringArrays(excludeA, b.Exclude) {
			return false
		}
	} else if len(b.Exclude) != 0 {
		return false
	}

	if matchLabelsA, ok := a["matchLabels"].(map[string]string); ok {
		if !reflect.DeepEqual(matchLabelsA, b.MatchLabels) {
			return false
		}
	} else if matchLabelsA != nil && b.MatchLabels != nil {
		return false
	}

	if matchExpressionsA, ok := a["matchExpressions"].([]interface{}); ok {
		if a["matchExpressions"] != b.MatchExpressions {
			if b.MatchExpressions == nil {
				return false
			}

			if len(matchExpressionsA) != len(*b.MatchExpressions) {
				return false
			}

			for i := range matchExpressionsA {
				meA := matchExpressionsA[i]
				valuesA := meA.(map[string]interface{})["values"].([]interface{})
				meB := (*b.MatchExpressions)[i]

				if meA.(map[string]interface{})["key"].(string) != meB.Key ||
					meA.(map[string]interface{})["operator"].(string) != string(meB.Operator) ||
					!compareStringArrays(valuesA, meB.Values) {
					return false
				}
			}
		}
	} else if matchExpressionsA != nil && b.MatchExpressions != nil {
		return false
	}

	return true
}

func TestGetPolicyTemplate(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestFiles := []types.Manifest{}
	manifestFilesMustNotHave := []types.Manifest{}

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

		err := os.WriteFile(manifestPath, []byte(manifestYAML), 0o666)
		if err != nil {
			t.Fatalf("Failed to write %s", manifestPath)
		}

		// The applyDefaults method would normally fill in ComplianceType on each manifest entry.
		manifestFiles = append(
			manifestFiles, types.Manifest{
				ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
					ComplianceType:         "musthave",
					MetadataComplianceType: "mustonlyhave",
					RecordDiff:             "Log",
				},
				Path: manifestPath,
			},
		)

		manifestFilesMustNotHave = append(
			manifestFilesMustNotHave,
			types.Manifest{
				ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
					ComplianceType:         "mustnothave",
					MetadataComplianceType: "musthave",
					RecordDiff:             "None",
				},
				Path: manifestPath,
			},
		)
	}

	// Write a bogus file to ensure it is not picked up when creating the policy
	// template
	bogusFilePath := path.Join(tmpDir, "README.md")

	err := os.WriteFile(bogusFilePath, []byte("# My Manifests"), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", bogusFilePath)
	}

	// Test both passing in individual files and a flat directory
	tests := map[string]struct {
		ExpectedComplianceType         string
		ExpectedMetadataComplianceType string
		ExpectedRecordDiff             string
		Manifests                      []types.Manifest
	}{
		"musthave compType/mustonlyhave metaCompType/Log recDiff": {
			ExpectedComplianceType:         "musthave",
			ExpectedMetadataComplianceType: "mustonlyhave",
			ExpectedRecordDiff:             "Log",
			Manifests:                      manifestFiles,
		},
		"mustnothave compType/musthave metaCompType/None recDiff": {
			ExpectedComplianceType:         "mustnothave",
			ExpectedMetadataComplianceType: "musthave",
			ExpectedRecordDiff:             "None",
			Manifests:                      manifestFilesMustNotHave,
		},
		// The applyDefaults method would normally fill in ComplianceType on each manifest entry.
		"musthave compType/empty metaCompType/empty recDiff": {
			ExpectedComplianceType:         "musthave",
			ExpectedMetadataComplianceType: "",
			ExpectedRecordDiff:             "",
			Manifests: []types.Manifest{{
				ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{ComplianceType: "musthave"},
				Path:                       tmpDir,
			}},
		},
	}
	// test ConsolidateManifests = true (default case)
	// policyTemplates will have only one policyTemplate
	// and two objTemplate under this policyTemplate
	for testName, test := range tests {
		test := test

		t.Run(testName, func(t *testing.T) {
			t.Parallel()
			policyConf := types.PolicyConfig{
				PolicyOptions: types.PolicyOptions{
					ConsolidateManifests: true,
				},
				ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
					ComplianceType:    "musthave",
					RemediationAction: "inform",
					Severity:          "low",
				},
				Manifests: test.Manifests,
				Name:      "policy-app-config",
			}

			policyTemplates, err := getPolicyTemplates(&policyConf)
			if err != nil {
				t.Fatalf("Failed to get the policy templates: %v", err)
			}

			assertEqual(t, len(policyTemplates), 1)

			policyTemplate := policyTemplates[0]
			objdef := policyTemplate["objectDefinition"].(map[string]interface{})

			assertEqual(t, objdef["metadata"].(map[string]interface{})["name"].(string), "policy-app-config")

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
			assertEqual(t, objTemplates[0]["complianceType"], test.ExpectedComplianceType)

			if test.ExpectedMetadataComplianceType != "" {
				assertEqual(t, objTemplates[0]["metadataComplianceType"], test.ExpectedMetadataComplianceType)
			} else {
				assertEqual(t, objTemplates[0]["metadataComplianceType"], nil)
			}

			if test.ExpectedRecordDiff != "" {
				assertEqual(t, objTemplates[0]["recordDiff"], test.ExpectedRecordDiff)
			} else {
				assertEqual(t, objTemplates[0]["recordDiff"], nil)
			}

			kind1, ok := objTemplates[0]["objectDefinition"].(map[string]interface{})["kind"]
			if !ok {
				t.Fatal("The objectDefinition field is an invalid format")
			}

			assertEqual(t, kind1, "ConfigMap")
			assertEqual(t, objTemplates[1]["complianceType"], test.ExpectedComplianceType)

			if test.ExpectedMetadataComplianceType != "" {
				assertEqual(t, objTemplates[1]["metadataComplianceType"], test.ExpectedMetadataComplianceType)
			} else {
				assertEqual(t, objTemplates[1]["metadataComplianceType"], nil)
			}

			if test.ExpectedRecordDiff != "" {
				assertEqual(t, objTemplates[1]["recordDiff"], test.ExpectedRecordDiff)
			} else {
				assertEqual(t, objTemplates[1]["recordDiff"], nil)
			}

			kind2, ok := objTemplates[1]["objectDefinition"].(map[string]interface{})["kind"]
			if !ok {
				t.Fatal("The objectDefinition field is an invalid format")
			}

			assertEqual(t, kind2, "ConfigMap")
		})
	}
}

func TestGetPolicyTemplateKustomize(t *testing.T) {
	t.Parallel()
	kustomizeDir := t.TempDir()
	configStrings := []string{"tomato", "potato"}

	manifestsDir := path.Join(kustomizeDir, "manifests")

	err := os.Mkdir(manifestsDir, 0o777)
	if err != nil {
		t.Fatalf("Failed to create the directory structure %s: %v", manifestsDir, err)
	}

	for i, enemy := range configStrings {
		manifestPath := path.Join(manifestsDir, fmt.Sprintf("configmap%d.yaml", i))
		manifestYAML := fmt.Sprintf(
			`
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-configmap-%d
data:
  game.properties: enemies=%s
`,
			i, enemy,
		)

		err := os.WriteFile(manifestPath, []byte(manifestYAML), 0o666)
		if err != nil {
			t.Fatalf("Failed to write %s", manifestPath)
		}
	}

	kustomizeManifests := map[string]string{
		path.Join(kustomizeDir, "kustomization.yml"): `
resources:
- manifests/

labels:
- pairs:
    cool: "true"
`,
		path.Join(manifestsDir, "kustomization.yml"): fmt.Sprintf(`
resources:
- %s
- %s
`, "configmap0.yaml", "configmap1.yaml"),
	}

	for kustomizePath, kustomizeYAML := range kustomizeManifests {
		err := os.WriteFile(kustomizePath, []byte(kustomizeYAML), 0o666)
		if err != nil {
			t.Fatalf("Failed to write %s", kustomizePath)
		}
	}

	// Write a bogus directory to verify it's not picked up
	bogusDirectory := path.Join(kustomizeDir, "this-other-dir")

	err = os.Mkdir(bogusDirectory, 0o777)
	if err != nil {
		t.Fatalf("Failed to create the directory structure %s: %v", bogusDirectory, err)
	}

	// Write a bogus file to verify it is not picked up when creating the policy template
	bogusFilePath := path.Join(kustomizeDir, "this-other-file.yaml")

	err = os.WriteFile(bogusFilePath, []byte("# My Manifests"), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", bogusFilePath)
	}

	tests := []struct {
		ExpectedComplianceType string
		ManifestPath           string
		ErrMsg                 string
	}{
		{
			ExpectedComplianceType: "musthave",
			ManifestPath:           kustomizeDir,
		},
		{
			ExpectedComplianceType: "musthave",
			ManifestPath:           "not-a-directory",
			ErrMsg:                 "failed to read the manifest path not-a-directory",
		},
	}
	for _, test := range tests {
		policyConf := types.PolicyConfig{
			ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
				ComplianceType:    "musthave",
				RemediationAction: "inform",
				Severity:          "low",
			},
			Manifests: []types.Manifest{{
				ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
					ComplianceType: "musthave",
				},
				Path: test.ManifestPath,
			}},
			PolicyOptions: types.PolicyOptions{
				ConsolidateManifests: true,
			},
			Name: "policy-kustomize",
		}

		policyTemplates, err := getPolicyTemplates(&policyConf)
		if err != nil {
			if test.ErrMsg != "" {
				assertEqual(t, err.Error(), test.ErrMsg)

				continue
			}

			t.Fatalf("Failed to get the policy templates: %v", err)
		}

		assertEqual(t, len(policyTemplates), 1)

		policyTemplate := policyTemplates[0]
		objdef := policyTemplate["objectDefinition"].(map[string]interface{})

		assertEqual(t, objdef["metadata"].(map[string]interface{})["name"].(string), "policy-kustomize")

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
		assertEqual(t, objTemplates[0]["complianceType"], test.ExpectedComplianceType)

		kind1, ok := objTemplates[0]["objectDefinition"].(map[string]interface{})["kind"]
		if !ok {
			t.Fatal("The objectDefinition field is an invalid format")
		}

		assertEqual(t, kind1, "ConfigMap")
		assertEqual(t, objTemplates[1]["complianceType"], test.ExpectedComplianceType)

		kind2, ok := objTemplates[1]["objectDefinition"].(map[string]interface{})["kind"]
		if !ok {
			t.Fatal("The objectDefinition field is an invalid format")
		}

		assertEqual(t, kind2, "ConfigMap")
	}
}

func TestGetPolicyTemplateNoConsolidate(t *testing.T) {
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
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-configmap2
data:
  game.properties: enemies=%s
`,
			enemy,
			enemy,
		)

		err := os.WriteFile(manifestPath, []byte(manifestYAML), 0o666)
		if err != nil {
			t.Fatalf("Failed to write %s", manifestPath)
		}

		// The applyDefaults method would normally fill in ComplianceType on each manifest entry.
		manifestFiles = append(
			manifestFiles, types.Manifest{
				ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
					ComplianceType:         "musthave",
					MetadataComplianceType: "mustonlyhave",
				},
				Path: manifestPath,
			},
		)
	}

	// Write a bogus file to ensure it is not picked up when creating the policy
	// template
	bogusFilePath := path.Join(tmpDir, "README.md")

	err := os.WriteFile(bogusFilePath, []byte("# My Manifests"), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", bogusFilePath)
	}

	// Test both passing in individual files and a flat directory
	tests := []struct {
		Manifests []types.Manifest
	}{
		{Manifests: manifestFiles},
		// The applyDefaults method would normally fill in ComplianceType on each manifest entry.
		{
			Manifests: []types.Manifest{{
				ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
					ComplianceType:         "musthave",
					MetadataComplianceType: "mustonlyhave",
				},
				Path: tmpDir,
			}},
		},
	}

	// test ConsolidateManifests = false case
	// policyTemplates will skip the consolidation and have four policyTemplate
	// and each policyTemplate has only one objTemplate
	for _, test := range tests {
		policyConf := types.PolicyConfig{
			PolicyOptions: types.PolicyOptions{
				ConsolidateManifests: false,
			},
			ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
				ComplianceType:         "musthave",
				MetadataComplianceType: "musthave",
				RemediationAction:      "inform",
				Severity:               "low",
			},
			Manifests: test.Manifests,
			Name:      "policy-app-config",
		}

		policyTemplates, err := getPolicyTemplates(&policyConf)
		if err != nil {
			t.Fatalf("Failed to get the policy templates: %v", err)
		}

		assertEqual(t, len(policyTemplates), 4)

		for i := 0; i < len(policyTemplates); i++ {
			policyTemplate := policyTemplates[i]
			objdef := policyTemplate["objectDefinition"].(map[string]interface{})
			name := "policy-app-config"

			if i > 0 {
				name += fmt.Sprintf("%d", i+1)
			}

			assertEqual(t, objdef["metadata"].(map[string]interface{})["name"].(string), name)

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

			assertEqual(t, len(objTemplates), 1)
			assertEqual(t, objTemplates[0]["complianceType"], "musthave")
			assertEqual(t, objTemplates[0]["metadataComplianceType"], "mustonlyhave")

			kind1, ok := objTemplates[0]["objectDefinition"].(map[string]interface{})["kind"]
			if !ok {
				t.Fatal("The objectDefinition field is an invalid format")
			}

			assertEqual(t, kind1, "ConfigMap")
		}
	}
}

func TestIsPolicyTypeManifest(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		manifest                 map[string]interface{}
		informGatekeeperPolicies bool
		wantIsPolicy             bool
		wantIsOcmPolicy          bool
		wantErr                  string
	}{
		"valid RandomPolicy": {
			manifest: map[string]interface{}{
				"apiVersion": policyAPIVersion,
				"kind":       "RandomPolicy",
				"metadata": map[string]interface{}{
					"name": "foo",
				},
			},
			wantIsPolicy:    true,
			wantIsOcmPolicy: true,
			wantErr:         "",
		},
		"valid ConfigurationPolicy": {
			manifest: map[string]interface{}{
				"apiVersion": policyAPIVersion,
				"kind":       "ConfigurationPolicy",
				"metadata": map[string]interface{}{
					"name": "foo",
				},
			},
			wantIsPolicy:    true,
			wantIsOcmPolicy: true,
			wantErr:         "",
		},
		"valid Gatekeeper Constraint with expander": {
			manifest: map[string]interface{}{
				"apiVersion": "constraints.gatekeeper.sh",
				"kind":       "Foo",
				"metadata": map[string]interface{}{
					"name": "foo",
				},
			},
			informGatekeeperPolicies: true,
			wantIsPolicy:             false,
			wantIsOcmPolicy:          false,
			wantErr:                  "",
		},
		"valid Gatekeeper ConstraintTemplate with expander": {
			manifest: map[string]interface{}{
				"apiVersion": "templates.gatekeeper.sh",
				"kind":       "ConstraintTemplate",
				"metadata": map[string]interface{}{
					"name": "foo",
				},
			},
			informGatekeeperPolicies: true,
			wantIsPolicy:             false,
			wantIsOcmPolicy:          false,
			wantErr:                  "",
		},
		"valid Gatekeeper Constraint without expander": {
			manifest: map[string]interface{}{
				"apiVersion": "constraints.gatekeeper.sh",
				"kind":       "Foo",
				"metadata": map[string]interface{}{
					"name": "foo",
				},
			},
			wantIsPolicy:    true,
			wantIsOcmPolicy: false,
			wantErr:         "",
		},
		"valid Gatekeeper ConstraintTemplate without expander": {
			manifest: map[string]interface{}{
				"apiVersion": "templates.gatekeeper.sh",
				"kind":       "ConstraintTemplate",
				"metadata": map[string]interface{}{
					"name": "foo",
				},
			},
			wantIsPolicy:    true,
			wantIsOcmPolicy: false,
			wantErr:         "",
		},
		"valid Policy": {
			manifest: map[string]interface{}{
				"apiVersion": policyAPIVersion,
				"kind":       "Policy",
				"metadata": map[string]interface{}{
					"name": "foo",
				},
			},
			wantIsPolicy:    false,
			wantIsOcmPolicy: false,
			wantErr: "providing a root Policy kind is not supported by the generator; " +
				"the manifest should be applied to the hub cluster directly",
		},
		"valid PlacementRule": {
			manifest: map[string]interface{}{
				"apiVersion": "apps.open-cluster-management.io/v1",
				"kind":       "PlacementRule",
				"metadata": map[string]interface{}{
					"name": "foo",
				},
			},
			wantIsPolicy:    false,
			wantIsOcmPolicy: false,
			wantErr:         "",
		},
		"wrong ApiVersion": {
			manifest: map[string]interface{}{
				"apiVersion": "fake.test.io/v3alpha2",
				"kind":       "RandomPolicy",
				"metadata": map[string]interface{}{
					"name": "foo",
				},
			},
			wantIsPolicy:    false,
			wantIsOcmPolicy: false,
			wantErr:         "",
		},
		"invalid kind": {
			manifest: map[string]interface{}{
				"apiVersion": policyAPIVersion,
				"kind":       []interface{}{"foo", "bar", "baz"},
				"metadata": map[string]interface{}{
					"name": "foo",
				},
			},
			wantIsPolicy:    false,
			wantIsOcmPolicy: false,
			wantErr:         "invalid or not found kind",
		},
		"missing apiVersion": {
			manifest: map[string]interface{}{
				"kind": "ConfigurationPolicy",
				"metadata": map[string]interface{}{
					"name": "foo",
				},
			},
			wantIsPolicy:    false,
			wantIsOcmPolicy: false,
			wantErr:         "invalid or not found apiVersion",
		},
		"missing name in ConfigurationPolicy": {
			manifest: map[string]interface{}{
				"apiVersion": policyAPIVersion,
				"kind":       "ConfigurationPolicy",
				"metadata": map[string]interface{}{
					"namespace": "foo",
				},
			},
			wantIsPolicy:    true,
			wantIsOcmPolicy: true,
			wantErr:         "invalid or not found metadata.name",
		},
		"missing name in non-policy": {
			manifest: map[string]interface{}{
				"apiVersion": "apps.open-cluster-management.io/v1",
				"kind":       "PlacementRule",
				"metadata": map[string]interface{}{
					"name": "foo",
				},
			},
			wantIsPolicy:    false,
			wantIsOcmPolicy: false,
			wantErr:         "",
		},
	}

	for name, test := range tests {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			gotIsPolicy, gotIsOcmPolicy, gotErr := isPolicyTypeManifest(test.manifest, test.informGatekeeperPolicies)
			if gotErr != nil {
				assertEqual(t, gotErr.Error(), test.wantErr)
			} else if test.wantErr != "" {
				t.Fatalf("expected the error `%s` but got none", test.wantErr)
			}
			assertEqual(t, gotIsPolicy, test.wantIsPolicy)
			assertEqual(t, gotIsOcmPolicy, test.wantIsOcmPolicy)
		})
	}
}

func TestGetPolicyTemplateFromPolicyTypeManifest(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestFiles := []types.Manifest{}

	createIamPolicyManifest(t, tmpDir, "iamKindManifest.yaml")
	// Test manifest is non-root IAM policy type.
	IamManifestPath := path.Join(tmpDir, "iamKindManifest.yaml")

	manifestFiles = append(
		manifestFiles, types.Manifest{Path: IamManifestPath},
	)

	// Test both passing in individual files and a flat directory.
	tests := []struct {
		Manifests []types.Manifest
	}{
		{Manifests: manifestFiles},
		{
			Manifests: []types.Manifest{{Path: tmpDir}},
		},
	}

	for _, test := range tests {
		policyConf := types.PolicyConfig{
			Manifests: test.Manifests,
			Name:      "policy-limitclusteradmin",
			ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
				RemediationAction: "inform",
				Severity:          "low",
			},
		}

		policyTemplates, err := getPolicyTemplates(&policyConf)
		if err != nil {
			t.Fatalf("Failed to get the policy templates: %v", err)
		}

		assertEqual(t, len(policyTemplates), 1)

		IamPolicyTemplate := policyTemplates[0]
		IamObjdef := IamPolicyTemplate["objectDefinition"].(map[string]interface{})
		assertEqual(t, IamObjdef["apiVersion"], "policy.open-cluster-management.io/v1")
		// kind will not be overridden by "ConfigurationPolicy".
		assertEqual(t, IamObjdef["kind"], "IamPolicy")
		assertEqual(t, IamObjdef["metadata"].(map[string]interface{})["name"], "policy-limitclusteradmin-example")

		IamSpec, ok := IamObjdef["spec"].(map[string]interface{})
		if !ok {
			t.Fatal("The spec field is an invalid format")
		}

		// remediationAction will not be overridden by policyConf.
		assertEqual(t, IamSpec["remediationAction"], "enforce")
		// severity will not be overridden by policyConf.
		assertEqual(t, IamSpec["severity"], "medium")
		assertEqual(t, IamSpec["maxClusterRoleBindingUsers"], 5)

		namespaceSelector, ok := IamSpec["namespaceSelector"].(map[string]interface{})
		if !ok {
			t.Fatal("The namespaceSelector field is an invalid format")
		}

		assertReflectEqual(t, namespaceSelector["include"], []interface{}{"*"})
		assertReflectEqual(t, namespaceSelector["exclude"], []interface{}{"kube-*", "openshift-*"})
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

	err := os.WriteFile(manifestPath, []byte(manifestYAML), 0o666)
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

	policyTemplates, err := getPolicyTemplates(&policyConf)
	if err != nil {
		t.Fatalf("Failed to get the policy templates: %v", err)
	}

	assertEqual(t, len(policyTemplates), 1)

	policyTemplate := policyTemplates[0]
	objdef := policyTemplate["objectDefinition"].(map[string]interface{})
	assertEqual(t, objdef["metadata"].(map[string]interface{})["name"].(string), "policy-app-config")

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

func TestGetPolicyTemplateMetadataPatches(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestPath := path.Join(tmpDir, "patch-configmap.yaml")
	manifestYAML := `
---
apiVersion: v1
kind: configmap
metadata:
  name: test-configmap
  namespace: test-namespace
data:
  image: "quay.io/potatos1"
`

	err := os.WriteFile(manifestPath, []byte(manifestYAML), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", manifestPath)
	}

	patches := []map[string]interface{}{
		{
			"metadata": map[string]interface{}{
				"name":      "patch-configmap",
				"namespace": "patch-namespace",
			},
			"data": map[string]interface{}{
				"image": "quay.io/potatos2",
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

	policyTemplates, err := getPolicyTemplates(&policyConf)
	if err != nil {
		t.Fatalf("Failed to get the policy templates: %v ", err)
	}

	assertEqual(t, len(policyTemplates), 1)

	policyTemplate := policyTemplates[0]
	objdef := policyTemplate["objectDefinition"].(map[string]interface{})

	assertEqual(t, objdef["metadata"].(map[string]interface{})["name"].(string), "policy-app-config")

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

	name, ok := metadata["name"].(string)
	if !ok {
		t.Fatal("The metadata.name field is an invalid format")
	}

	assertEqual(t, name, "patch-configmap")

	namespace, ok := metadata["namespace"].(string)
	if !ok {
		t.Fatal("The metadata.namespace field is an invalid format")
	}

	assertEqual(t, namespace, "patch-namespace")

	data, ok := objDef["data"].(map[string]interface{})
	if !ok {
		t.Fatal("The data field is an invalid format")
	}

	image, ok := data["image"].(string)
	if !ok {
		t.Fatal("The data.image field is an invalid format")
	}

	assertEqual(t, image, "quay.io/potatos2")
}

func TestGetPolicyTemplateMetadataPatchesFail(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestPath := path.Join(tmpDir, "multi-configmaps.yaml")
	manifestYAML := `
---
apiVersion: v1
kind: configmap
metadata:
  name: test-configmap
  namespace: test-namespace
data:
  image: "quay.io/potatos1"
---
apiVersion: v1
kind: configmap
metadata:
  name: test2-configmap
  namespace: test2-namespace
data:
  image: "quay.io/potatos1"
`

	err := os.WriteFile(manifestPath, []byte(manifestYAML), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", manifestPath)
	}

	patches := []map[string]interface{}{
		{
			"metadata": map[string]interface{}{
				"name":      "patch-configmap",
				"namespace": "patch-namespace",
			},
			"data": map[string]interface{}{
				"image": "quay.io/potatos2",
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

	_, err = getPolicyTemplates(&policyConf)
	assertEqual(t, err != nil, true)
}

func TestGetPolicyTemplateKyverno(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestPath := path.Join(tmpDir, "kyverno.yaml")
	manifestYAML := `
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: my-awesome-policy`

	err := os.WriteFile(manifestPath, []byte(manifestYAML), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", manifestPath)
	}

	policyConf := types.PolicyConfig{
		PolicyOptions: types.PolicyOptions{
			InformKyvernoPolicies: true,
		},
		ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
			ComplianceType:    "musthave",
			RemediationAction: "enforce",
			Severity:          "low",
		},
		Manifests: []types.Manifest{{Path: manifestPath}},
		Name:      "policy-kyverno-config",
	}

	policyTemplates, err := getPolicyTemplates(&policyConf)
	if err != nil {
		t.Fatalf("Failed to get the policy templates: %v", err)
	}

	assertEqual(t, len(policyTemplates), 2)

	// This is not an in-depth test since the Kyverno expansion is tested elsewhere. This is
	// to test that glue code is working as expected.
	expandedPolicyTemplate := policyTemplates[1]
	objdef := expandedPolicyTemplate["objectDefinition"].(map[string]interface{})

	spec, ok := objdef["spec"].(map[string]interface{})
	if !ok {
		t.Fatal("The spec field is an invalid format")
	}

	objTemplates, ok := spec["object-templates"].([]map[string]interface{})
	if !ok {
		t.Fatal("The object-templates field is an invalid format")
	}

	assertEqual(t, len(objTemplates), 2)
	assertEqual(t, objTemplates[0]["complianceType"], "mustnothave")
	assertEqual(t, objTemplates[0]["metadataComplianceType"], nil)

	kind1, ok := objTemplates[0]["objectDefinition"].(map[string]interface{})["kind"]
	if !ok {
		t.Fatal("The objectDefinition field is an invalid format")
	}

	assertEqual(t, kind1, "ClusterPolicyReport")

	assertEqual(t, objTemplates[1]["complianceType"], "mustnothave")
	assertEqual(t, objTemplates[1]["metadataComplianceType"], nil)

	kind2, ok := objTemplates[1]["objectDefinition"].(map[string]interface{})["kind"]
	if !ok {
		t.Fatal("The objectDefinition field is an invalid format")
	}

	assertEqual(t, kind2, "PolicyReport")
}

func TestGetPolicyTemplateNoManifests(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	policyConf := types.PolicyConfig{
		ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
			ComplianceType:    "musthave",
			RemediationAction: "inform",
			Severity:          "low",
		},
		Manifests: []types.Manifest{{Path: tmpDir}},
		Name:      "policy-app-config",
	}

	_, err := getPolicyTemplates(&policyConf)
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
		ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
			ComplianceType:    "musthave",
			RemediationAction: "inform",
			Severity:          "low",
		},
		Manifests: []types.Manifest{{
			ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
				ComplianceType: "musthave",
			},
			Path: manifestPath,
		}},
		Name: "policy-app-config",
	}

	_, err := getPolicyTemplates(&policyConf)
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
	err := os.WriteFile(manifestPath, []byte("$i am not YAML!"), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", manifestPath)
	}

	policyConf := types.PolicyConfig{
		ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
			ComplianceType:    "musthave",
			RemediationAction: "inform",
			Severity:          "low",
		},
		Manifests: []types.Manifest{{Path: manifestPath}},
		Name:      "policy-app-config",
	}

	_, err = getPolicyTemplates(&policyConf)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf(
		"failed to decode the manifest file at %s: the input manifests must be in the format of "+
			"YAML objects", manifestPath,
	)
	assertEqual(t, err.Error(), expected)
}

func TestGetPolicyTemplateObjectTemplatesRaw(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestPath := path.Join(tmpDir, "object-templates-raw.yaml")
	manifestYAMLMultiple := `
object-templates-raw: |
  content1
---
object-templates-raw: |
  content2
`
	manifestYAMLContent1 := `content1
`
	manifestYAMLContent2 := `content2
`

	err := os.WriteFile(manifestPath, []byte(manifestYAMLMultiple), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", manifestPath)
	}

	policyConf := types.PolicyConfig{
		PolicyOptions: types.PolicyOptions{
			ConsolidateManifests: true,
		},
		ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
			ComplianceType:    "musthave",
			RemediationAction: "enforce",
			Severity:          "low",
		},
		Manifests: []types.Manifest{{Path: manifestPath}},
		Name:      "configpolicy-object-templates-raw-config",
	}

	policyTemplates, err := getPolicyTemplates(&policyConf)
	if err != nil {
		t.Fatalf("Failed to get the policy templates: %v", err)
	}

	assertEqual(t, len(policyTemplates), 2)

	policyTemplate1 := policyTemplates[0]
	objdef := policyTemplate1["objectDefinition"].(map[string]interface{})

	spec, ok := objdef["spec"].(map[string]interface{})
	if !ok {
		t.Fatal("The spec field is an invalid format")
	}

	objectTemplatesRaw, ok := spec["object-templates-raw"].(string)
	if !ok {
		t.Fatal("The object-templates-raw field is an invalid format")
	}

	assertEqual(t, objectTemplatesRaw, manifestYAMLContent1)

	policyTemplate2 := policyTemplates[1]
	objdef = policyTemplate2["objectDefinition"].(map[string]interface{})

	spec, ok = objdef["spec"].(map[string]interface{})
	if !ok {
		t.Fatal("The spec field is an invalid format")
	}

	objectTemplatesRaw, ok = spec["object-templates-raw"].(string)
	if !ok {
		t.Fatal("The object-templates-raw field is an invalid format")
	}

	assertEqual(t, objectTemplatesRaw, manifestYAMLContent2)
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

	err := os.WriteFile(manifestsPath, []byte(yamlContent), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", manifestsPath)
	}

	manifests, err := unmarshalManifestFile(manifestsPath)
	if err != nil {
		t.Fatalf("Failed to unmarshal the YAML content, got: %v", err)
	}

	assertEqual(t, len(manifests), 2)

	name1, _, _ := unstructured.NestedString((manifests)[0], "metadata", "name")
	assertEqual(t, name1, "my-configmap")

	name2, _, _ := unstructured.NestedString((manifests)[1], "metadata", "name")
	assertEqual(t, name2, "my-configmap2")
}

func TestUnmarshalManifestFileNilYaml(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestsPath := path.Join(tmpDir, "configmaps.yaml")
	yamlContent := `
---
---
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
---
---
`

	err := os.WriteFile(manifestsPath, []byte(yamlContent), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", manifestsPath)
	}

	manifests, err := unmarshalManifestFile(manifestsPath)
	if err != nil {
		t.Fatalf("Failed to unmarshal the YAML content, got: %v", err)
	}

	assertEqual(t, len(manifests), 2)

	name1, _, _ := unstructured.NestedString((manifests)[0], "metadata", "name")
	assertEqual(t, name1, "my-configmap")

	name2, _, _ := unstructured.NestedString((manifests)[1], "metadata", "name")
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

	err := os.WriteFile(manifestPath, []byte(yamlContent), 0o666)
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

	err := os.WriteFile(manifestPath, []byte(yamlContent), 0o666)
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

//nolint:paralleltest
func TestVerifyManifestPath(t *testing.T) {
	baseDirectory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to evaluate symlinks for the base directory: %v", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get the current working directory: %v", err)
	}

	defer func() {
		err := os.Chdir(cwd)
		if err != nil {
			// panic since this could affect other tests that haven't yet run
			panic(fmt.Sprintf("Couldn't go back to the original working directory: %v", err))
		}
	}()

	// Set up directory structure, with 'workingdir' as target directory:
	// baseDirectory (t.TempDir())
	// ├── workingdir
	// │   └── subdir
	// └── otherdir
	workingDir := path.Join(baseDirectory, "workingdir")
	subDir := path.Join(workingDir, "subdir")
	otherDir := path.Join(baseDirectory, "otherdir")

	err = os.MkdirAll(subDir, 0o777)
	if err != nil {
		t.Fatalf("Failed to create the directory structure %s: %v", subDir, err)
	}

	err = os.Mkdir(otherDir, 0o777)
	if err != nil {
		t.Fatalf("Failed to create the directory structure %s: %v", otherDir, err)
	}

	// Create files in baseDirectory/workingdir and baseDirectory/otherdir
	manifestPath := path.Join(workingDir, "configmap.yaml")
	yamlContent := "---\nkind: ConfigMap"

	err = os.WriteFile(manifestPath, []byte(yamlContent), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", manifestPath)
	}

	otherManifestPath := path.Join(otherDir, "configmap.yaml")

	err = os.WriteFile(otherManifestPath, []byte(yamlContent), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", otherManifestPath)
	}

	err = os.Chdir(workingDir)
	if err != nil {
		t.Fatalf("Failed to change the working directory to %s: %v", workingDir, err)
	}

	grandParentDir := path.Join("..", "..")
	relOtherManifestPath := path.Join("..", "otherdir", "configmap.yaml")

	tests := []struct {
		ManifestPath   string
		ExpectedErrMsg string
	}{
		{manifestPath, ""},
		{"configmap.yaml", ""},
		{"subdir", ""},
		{
			"..",
			"the manifest path .. is not in the same directory tree as the kustomization.yaml file",
		},
		{
			grandParentDir,
			fmt.Sprintf(
				"the manifest path %s is not in the same directory tree as the kustomization.yaml file",
				grandParentDir,
			),
		},
		{
			baseDirectory,
			fmt.Sprintf(
				"the manifest path %s is not in the same directory tree as the kustomization.yaml file",
				baseDirectory,
			),
		},
		{
			workingDir,
			fmt.Sprintf(
				"the manifest path %s may not refer to the same directory as the kustomization.yaml file",
				workingDir,
			),
		},
		{
			".",
			fmt.Sprintf(
				"the manifest path %s may not refer to the same directory as the kustomization.yaml file",
				".",
			),
		},
		{
			otherManifestPath,
			fmt.Sprintf(
				"the manifest path %s is not in the same directory tree as the kustomization.yaml file",
				otherManifestPath,
			),
		},
		{
			relOtherManifestPath,
			fmt.Sprintf(
				"the manifest path %s is not in the same directory tree as the kustomization.yaml file",
				relOtherManifestPath,
			),
		},
		{
			otherDir,
			fmt.Sprintf(
				"the manifest path %s is not in the same directory tree as the kustomization.yaml file", otherDir,
			),
		},
	}

	for _, test := range tests {
		test := test
		//nolint:paralleltest
		t.Run(
			"manifestPath="+test.ManifestPath,
			func(t *testing.T) {
				err := verifyFilePath(workingDir, test.ManifestPath, "manifest")
				if err == nil {
					assertEqual(t, "", test.ExpectedErrMsg)
				} else {
					assertEqual(t, err.Error(), test.ExpectedErrMsg)
				}
			},
		)
	}
}

func TestProcessKustomizeDir(t *testing.T) {
	baseDirectory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to evaluate symlinks for the base directory: %v", err)
	}

	// Set up directory structure, with 'workingdir' as target directory:
	// baseDirectory (t.TempDir())
	// └── kustomizedir
	kustomizeDir := path.Join(baseDirectory, "kustomizedir")

	err = os.Mkdir(kustomizeDir, 0o777)
	if err != nil {
		t.Fatalf("Failed to create the directory structure %s: %v", kustomizeDir, err)
	}

	// Create files in baseDirectory/kustomizedir
	manifestPaths := map[string]string{
		"kustomization.yaml": `
resources:
- configmap.yaml
- https://github.com/stolostron/policy-generator-plugin/examples/input-kustomize/?ref=main

namespace: kustomize-test
`,
		"configmap.yaml": `
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-configmap
data:
  game.properties: |
    enemies=goldfish
`,
	}

	for filename, content := range manifestPaths {
		manifestPath := path.Join(kustomizeDir, filename)

		err = os.WriteFile(manifestPath, []byte(content), 0o666)
		if err != nil {
			t.Fatalf("Failed to write %s", manifestPath)
		}
	}

	manifests, err := processKustomizeDir(kustomizeDir)
	if err != nil {
		t.Fatalf(fmt.Sprintf("Unexpected error: %s", err))
	}

	assertEqual(t, len(manifests), 3)

	for _, manifest := range manifests {
		if metadata, ok := manifest["metadata"]; ok {
			ns := metadata.(map[string]interface{})["namespace"]
			assertEqual(t, ns, "kustomize-test")
		}
	}
}

func TestGetRootRemediationAction(t *testing.T) {
	t.Parallel()

	policyTemplates := []map[string]interface{}{{
		"objectDefinition": map[string]interface{}{
			"apiVersion": policyAPIVersion,
			"kind":       configPolicyKind,
			"metadata": map[string]interface{}{
				"name": "my-template",
			},
			"spec": map[string]interface{}{
				"remediationAction": "inform",
				"severity":          "low",
			},
		},
	}}

	expected := getRootRemediationAction(policyTemplates)
	assertEqual(t, "inform", expected)

	objDef := policyTemplates[0]["objectDefinition"].(map[string]interface{})
	objDef["spec"].(map[string]interface{})["remediationAction"] = "enforce"
	expected = getRootRemediationAction(policyTemplates)
	assertEqual(t, "enforce", expected)

	objDef["spec"].(map[string]interface{})["remediationAction"] = "InformOnly"
	expected = getRootRemediationAction(policyTemplates)
	assertEqual(t, "inform", expected)

	objDef["spec"].(map[string]interface{})["remediationAction"] = "iNfOrMoNlY"
	expected = getRootRemediationAction(policyTemplates)
	assertEqual(t, "inform", expected)
}
