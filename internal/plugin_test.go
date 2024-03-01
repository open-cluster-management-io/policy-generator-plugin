// Copyright Contributors to the Open Cluster Management project
package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"open-cluster-management.io/policy-generator-plugin/internal/types"
)

type testCase struct {
	name                            string
	setupFunc                       func(p *Plugin)
	expectedPolicySetConfigInPolicy [][]string
	expectedPolicySetConfigs        []types.PolicySetConfig
	expectedErrMsg                  string
}

func TestGenerate(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	var err error

	p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	p.PlacementBindingDefaults.Name = "my-placement-binding"
	p.PolicyDefaults.Placement.Name = "my-placement"
	p.PolicyDefaults.Namespace = "my-policies"
	p.PolicyDefaults.MetadataComplianceType = "musthave"
	p.PolicyDefaults.RecordDiff = "Log"
	p.PolicyDefaults.PruneObjectBehavior = "DeleteAll"
	patch := map[string]interface{}{
		"metadata": map[string]interface{}{
			"labels": map[string]string{
				"chandler": "bing",
			},
		},
	}
	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
			PruneObjectBehavior: "None",
		},
		Manifests: []types.Manifest{
			{
				Path:    path.Join(tmpDir, "configmap.yaml"),
				Patches: []map[string]interface{}{patch},
			},
		},
	}
	policyConf2 := types.PolicyConfig{
		Name: "policy-app-config2",
		Manifests: []types.Manifest{
			{
				ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
					MetadataComplianceType: "mustonlyhave",
					RecordDiff:             "None",
				},
				Path: path.Join(tmpDir, "configmap.yaml"),
			},
		},
	}
	p.Policies = append(p.Policies, policyConf, policyConf2)
	p.applyDefaults(map[string]interface{}{})
	// Default all policy ConsolidateManifests flags are set to true
	// unless explicitly set
	assertEqual(t, p.Policies[0].ConsolidateManifests, true)
	assertEqual(t, p.Policies[1].ConsolidateManifests, true)

	if err := p.assertValidConfig(); err != nil {
		t.Fatal(err.Error())
	}

	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                object-templates:
                    - complianceType: musthave
                      metadataComplianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            labels:
                                chandler: bing
                            name: my-configmap
                      recordDiff: Log
                pruneObjectBehavior: None
                remediationAction: inform
                severity: low
    remediationAction: inform
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-app-config2
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config2
            spec:
                object-templates:
                    - complianceType: musthave
                      metadataComplianceType: mustonlyhave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                      recordDiff: None
                pruneObjectBehavior: DeleteAll
                remediationAction: inform
                severity: low
    remediationAction: inform
---
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    name: my-placement
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions: []
    tolerations:
        - key: cluster.open-cluster-management.io/unavailable
          operator: Exists
        - key: cluster.open-cluster-management.io/unreachable
          operator: Exists
---
apiVersion: policy.open-cluster-management.io/v1
kind: PlacementBinding
metadata:
    name: my-placement-binding
    namespace: my-policies
placementRef:
    apiGroup: cluster.open-cluster-management.io
    kind: Placement
    name: my-placement
subjects:
    - apiGroup: policy.open-cluster-management.io
      kind: Policy
      name: policy-app-config
    - apiGroup: policy.open-cluster-management.io
      kind: Policy
      name: policy-app-config2
`
	expected = strings.TrimPrefix(expected, "\n")

	output, err := p.Generate()
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, string(output), expected)
}

func TestConfigManifestKeyOverride(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	tests := map[string]struct {
		// Individual values can't be used for compliant/noncompliant since an empty string means
		// to not inherit from the policy defaults.
		keyName     string
		defaultKey  string
		policyKey   string
		manifestKey string
	}{
		"pruneObjectBehavior specified in manifest": {
			"pruneObjectBehavior",
			"None",
			"DeleteIfCreated",
			`"DeleteAll"`,
		},
		"namespaceSelector specified in manifest": {
			"namespaceSelector",
			`{"matchLabels":{"name":"test"}}`,
			`{"exclude":["test"]}`,
			`{"include":["test"]}`,
		},
		"remediationAction specified in manifest": {
			"remediationAction",
			"inform",
			"inform",
			`"enforce"`,
		},
		"severity specified in manifest": {
			"severity",
			"low",
			"medium",
			`"critical"`,
		},
	}

	for testName, test := range tests {
		test := test

		t.Run(
			testName,
			func(t *testing.T) {
				t.Parallel()
				config := fmt.Sprintf(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
  consolidateManifests: false
  %s: %s
policies:
- name: policy-app
  %s: %s
  manifests:
    - path: %s
      %s: %s
`,
					test.keyName, test.defaultKey,
					test.keyName, test.policyKey,
					path.Join(tmpDir, "configmap.yaml"),
					test.keyName, test.manifestKey,
				)

				p := Plugin{}
				err := p.Config([]byte(config), tmpDir)
				if err != nil {
					t.Fatal("Unexpected error", err)
				}

				assertEqual(t, p.Policies[0].ConsolidateManifests, false)

				output, err := p.Generate()
				if err != nil {
					t.Fatal("Failed to generate policies from PolicyGenerator manifest", err)
				}

				var policyObj map[string]interface{}
				err = yaml.Unmarshal(output, &policyObj)
				if err != nil {
					t.Fatal("Failed to unmarshal object", err)
				}

				policyTemplate := policyObj["spec"].(map[string]interface{})["policy-templates"].([]interface{})[0]
				objectDef := policyTemplate.(map[string]interface{})["objectDefinition"].(map[string]interface{})
				configSpec := objectDef["spec"].(map[string]interface{})

				jsonConfig, err := json.Marshal(configSpec[test.keyName])
				if err != nil {
					t.Fatal("Failed to marshal policy to JSON", err)
				}

				assertEqual(t, string(jsonConfig), test.manifestKey)
			},
		)
	}
}

func TestGeneratePolicyDisablePlacement(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	var err error

	p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	p.PolicyDefaults.Namespace = "my-policies"
	p.PolicyDefaults.MetadataComplianceType = "musthave"
	p.PolicyDefaults.Placement.PlacementName = "my-placement"
	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{
				Path: path.Join(tmpDir, "configmap.yaml"),
			},
		},
	}
	p.Policies = append(p.Policies, policyConf)
	p.applyDefaults(map[string]interface{}{
		"policyDefaults": map[string]interface{}{
			"generatePolicyPlacement": false,
		},
	})
	assertEqual(t, p.Policies[0].GeneratePolicyPlacement, false)
	// Default all policy ConsolidateManifests flags are set to true
	// unless explicitly set
	assertEqual(t, p.Policies[0].ConsolidateManifests, true)

	if err := p.assertValidConfig(); err != nil {
		t.Fatal(err.Error())
	}

	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                object-templates:
                    - complianceType: musthave
                      metadataComplianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
`
	expected = strings.TrimPrefix(expected, "\n")

	output, err := p.Generate()
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, string(output), expected)
}

func TestGeneratePolicyDisablePlacementOverride(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	var err error

	p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	p.PolicyDefaults.Namespace = "my-policies"
	p.PolicyDefaults.MetadataComplianceType = "musthave"
	p.PolicyDefaults.Placement.PlacementName = "my-placement"
	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{
				Path: path.Join(tmpDir, "configmap.yaml"),
			},
		},
		PolicyOptions: types.PolicyOptions{
			GeneratePolicyPlacement: false,
			Placement: types.PlacementConfig{
				PlacementName: "my-placement",
			},
		},
	}
	p.Policies = append(p.Policies, policyConf)
	p.applyDefaults(map[string]interface{}{
		"policies": []interface{}{
			map[string]interface{}{
				"generatePolicyPlacement": false,
			},
		},
	})
	assertEqual(t, p.Policies[0].GeneratePolicyPlacement, false)
	// Default all policy ConsolidateManifests flags are set to true
	// unless explicitly set
	assertEqual(t, p.Policies[0].ConsolidateManifests, true)

	if err := p.assertValidConfig(); err != nil {
		t.Fatal(err.Error())
	}

	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                object-templates:
                    - complianceType: musthave
                      metadataComplianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
`
	expected = strings.TrimPrefix(expected, "\n")

	output, err := p.Generate()
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, string(output), expected)
}

func TestGeneratePolicyExistingPlacementRuleName(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	var err error

	p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	p.PolicyDefaults.Placement.PlacementRuleName = "plrexistingname"
	p.PolicyDefaults.Namespace = "my-policies"
	p.PolicyDefaults.MetadataComplianceType = "musthave"
	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{
				Path: path.Join(tmpDir, "configmap.yaml"),
			},
		},
	}
	p.Policies = append(p.Policies, policyConf)
	p.applyDefaults(map[string]interface{}{})
	// Default all policy ConsolidateManifests flags are set to true
	// unless explicitly set
	assertEqual(t, p.Policies[0].ConsolidateManifests, true)

	if err := p.assertValidConfig(); err != nil {
		t.Fatal(err.Error())
	}

	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                object-templates:
                    - complianceType: musthave
                      metadataComplianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
---
apiVersion: policy.open-cluster-management.io/v1
kind: PlacementBinding
metadata:
    name: binding-policy-app-config
    namespace: my-policies
placementRef:
    apiGroup: apps.open-cluster-management.io
    kind: PlacementRule
    name: plrexistingname
subjects:
    - apiGroup: policy.open-cluster-management.io
      kind: Policy
      name: policy-app-config
`
	expected = strings.TrimPrefix(expected, "\n")

	output, err := p.Generate()
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, string(output), expected)
}

func TestGeneratePolicyExistingPlacementName(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	var err error

	p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	p.PolicyDefaults.Placement.PlacementName = "plexistingname"
	p.PolicyDefaults.Namespace = "my-policies"
	p.PolicyDefaults.MetadataComplianceType = "musthave"
	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{
				Path: path.Join(tmpDir, "configmap.yaml"),
			},
		},
	}
	p.Policies = append(p.Policies, policyConf)
	p.applyDefaults(map[string]interface{}{})
	// Default all policy ConsolidateManifests flags are set to true
	// unless explicitly set
	assertEqual(t, p.Policies[0].ConsolidateManifests, true)

	if err := p.assertValidConfig(); err != nil {
		t.Fatal(err.Error())
	}

	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                object-templates:
                    - complianceType: musthave
                      metadataComplianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
---
apiVersion: policy.open-cluster-management.io/v1
kind: PlacementBinding
metadata:
    name: binding-policy-app-config
    namespace: my-policies
placementRef:
    apiGroup: cluster.open-cluster-management.io
    kind: Placement
    name: plexistingname
subjects:
    - apiGroup: policy.open-cluster-management.io
      kind: Policy
      name: policy-app-config
`
	expected = strings.TrimPrefix(expected, "\n")

	output, err := p.Generate()
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, string(output), expected)
}

func TestGenerateSeparateBindings(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	var err error

	p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "configmap.yaml")},
		},
	}
	policyConf2 := types.PolicyConfig{
		Name: "policy-app-config2",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "configmap.yaml")},
		},
	}
	p.Policies = append(p.Policies, policyConf, policyConf2)
	p.applyDefaults(map[string]interface{}{})

	if err := p.assertValidConfig(); err != nil {
		t.Fatal(err.Error())
	}

	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                object-templates:
                    - complianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-app-config2
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config2
            spec:
                object-templates:
                    - complianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
---
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    name: placement-policy-app-config
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions: []
    tolerations:
        - key: cluster.open-cluster-management.io/unavailable
          operator: Exists
        - key: cluster.open-cluster-management.io/unreachable
          operator: Exists
---
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    name: placement-policy-app-config2
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions: []
    tolerations:
        - key: cluster.open-cluster-management.io/unavailable
          operator: Exists
        - key: cluster.open-cluster-management.io/unreachable
          operator: Exists
---
apiVersion: policy.open-cluster-management.io/v1
kind: PlacementBinding
metadata:
    name: binding-policy-app-config
    namespace: my-policies
placementRef:
    apiGroup: cluster.open-cluster-management.io
    kind: Placement
    name: placement-policy-app-config
subjects:
    - apiGroup: policy.open-cluster-management.io
      kind: Policy
      name: policy-app-config
---
apiVersion: policy.open-cluster-management.io/v1
kind: PlacementBinding
metadata:
    name: binding-policy-app-config2
    namespace: my-policies
placementRef:
    apiGroup: cluster.open-cluster-management.io
    kind: Placement
    name: placement-policy-app-config2
subjects:
    - apiGroup: policy.open-cluster-management.io
      kind: Policy
      name: policy-app-config2
`
	expected = strings.TrimPrefix(expected, "\n")

	output, err := p.Generate()
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, string(output), expected)
}

func TestGenerateMissingBindingName(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	var err error

	p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	p.PlacementBindingDefaults.Name = ""
	p.PolicyDefaults.Placement.Name = "my-placement-rule"
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "configmap.yaml")},
		},
	}
	policyConf2 := types.PolicyConfig{
		Name: "policy-app-config2",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "configmap.yaml")},
		},
	}
	p.Policies = append(p.Policies, policyConf, policyConf2)
	p.applyDefaults(map[string]interface{}{})

	if err := p.assertValidConfig(); err != nil {
		t.Fatal(err.Error())
	}

	_, err = p.Generate()
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf(
		"placementBindingDefaults.name must be set but is empty (multiple policies or policy sets were found for the "+
			"PlacementBinding to placement %s)",
		p.PolicyDefaults.Placement.Name,
	)
	assertEqual(t, err.Error(), expected)
}

func TestCreatePolicy(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "configmap.yaml")},
		},
	}
	p.Policies = append(p.Policies, policyConf)
	p.applyDefaults(map[string]interface{}{})

	err := p.createPolicy(&p.Policies[0])
	if err != nil {
		t.Fatal(err.Error())
	}

	output := p.outputBuffer.String()
	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                object-templates:
                    - complianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePolicyEmptyManifest(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	err := os.WriteFile(path.Join(tmpDir, "empty.yaml"), []byte{}, 0o666)
	if err != nil {
		t.Fatalf("Failed to write empty.yaml")
	}

	p := Plugin{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{
				Path:                       path.Join(tmpDir, "empty.yaml"),
				ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{ComplianceType: "mustonlyhave"},
			}, {
				Path:                       path.Join(tmpDir, "configmap.yaml"),
				ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{ComplianceType: "mustnothave"},
			},
		},
	}
	p.Policies = append(p.Policies, policyConf)
	p.applyDefaults(map[string]interface{}{})

	err = p.createPolicy(&p.Policies[0])
	expectedErr := fmt.Sprintf("found empty YAML in the manifest at %s", path.Join(tmpDir, "empty.yaml"))
	assertEqual(t, err.Error(), expectedErr)
}

func TestCreatePolicyWithAnnotations(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	p.PolicyDefaults.Namespace = "my-policies"
	p.PolicyDefaults.PolicyAnnotations = map[string]string{"test-default-annotation": "default"}

	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "configmap.yaml")},
		},
	}
	p.Policies = append(p.Policies, policyConf)
	p.applyDefaults(map[string]interface{}{})

	err := p.createPolicy(&p.Policies[0])
	if err != nil {
		t.Fatal(err.Error())
	}

	output := p.outputBuffer.String()
	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
        test-default-annotation: default
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                object-templates:
                    - complianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)

	// Check for override default policy with empty map to skip default annotations from the policy
	p.outputBuffer.Reset()
	p.Policies[0].PolicyAnnotations = map[string]string{}
	p.applyDefaults(map[string]interface{}{})

	err = p.createPolicy(&p.Policies[0])
	if err != nil {
		t.Fatal(err.Error())
	}

	output = p.outputBuffer.String()
	expected = `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                object-templates:
                    - complianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)

	// Check for override default policy annotation
	p.outputBuffer.Reset()
	p.Policies[0].PolicyAnnotations = map[string]string{"test-wave-annotation": "100"}
	p.applyDefaults(map[string]interface{}{})

	err = p.createPolicy(&p.Policies[0])
	if err != nil {
		t.Fatal(err.Error())
	}

	output = p.outputBuffer.String()
	expected = `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
        test-wave-annotation: "100"
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                object-templates:
                    - complianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePolicyWithLabels(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	p.PolicyDefaults.Namespace = "my-policies"
	p.PolicyDefaults.PolicyLabels = map[string]string{"test-default-label": "default"}

	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "configmap.yaml")},
		},
	}
	p.Policies = append(p.Policies, policyConf)
	p.applyDefaults(map[string]interface{}{})

	err := p.createPolicy(&p.Policies[0])
	if err != nil {
		t.Fatal(err.Error())
	}

	output := p.outputBuffer.String()
	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    labels:
        test-default-label: default
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                object-templates:
                    - complianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)

	// Check for override default policy with empty map to skip default labels from the policy
	p.outputBuffer.Reset()
	p.Policies[0].PolicyLabels = map[string]string{}
	p.applyDefaults(map[string]interface{}{})

	err = p.createPolicy(&p.Policies[0])
	if err != nil {
		t.Fatal(err.Error())
	}

	output = p.outputBuffer.String()
	expected = `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                object-templates:
                    - complianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)

	// Check for override default policy labels
	p.outputBuffer.Reset()
	p.Policies[0].PolicyLabels = map[string]string{"test-wave-label": "100"}
	p.applyDefaults(map[string]interface{}{})

	err = p.createPolicy(&p.Policies[0])
	if err != nil {
		t.Fatal(err.Error())
	}

	output = p.outputBuffer.String()
	expected = `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    labels:
        test-wave-label: "100"
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                object-templates:
                    - complianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePolicyFromIamPolicyTypeManifest(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createIamPolicyManifest(t, tmpDir, "iamKindManifestPluginTest.yaml")

	p := Plugin{}
	p.PolicyDefaults.Namespace = "Iam-policies"
	policyConf := types.PolicyConfig{
		PolicyOptions: types.PolicyOptions{
			Categories: []string{"AC Access Control"},
			Controls:   []string{"AC-3 Access Enforcement"},
			Standards:  []string{"NIST SP 800-53"},
		},
		Name: "policy-limitclusteradmin",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "iamKindManifestPluginTest.yaml")},
		},
	}
	p.Policies = append(p.Policies, policyConf)
	p.applyDefaults(map[string]interface{}{})

	err := p.createPolicy(&p.Policies[0])
	if err != nil {
		t.Fatal(err.Error())
	}

	output := p.outputBuffer.String()
	// expected Iam policy generated from
	// non-root IAM policy type manifest
	// in createIamPolicyTypeConfigMap()
	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: AC Access Control
        policy.open-cluster-management.io/controls: AC-3 Access Enforcement
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-limitclusteradmin
    namespace: Iam-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: IamPolicy
            metadata:
                name: policy-limitclusteradmin-example
            spec:
                maxClusterRoleBindingUsers: 5
                namespaceSelector:
                    exclude:
                        - kube-*
                        - openshift-*
                    include:
                        - '*'
                remediationAction: enforce
                severity: medium
    remediationAction: enforce
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePolicyWithGkConstraintTemplate(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	gatekeeperPath := path.Join(tmpDir, "gatekeeper.yaml")
	yamlContent := `
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: myconstrainingtemplate
`

	err := os.WriteFile(gatekeeperPath, []byte(yamlContent), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", gatekeeperPath)
	}

	p := Plugin{}

	p.PolicyDefaults.Namespace = "gatekeeper-policies"
	p.PolicyDefaults.InformGatekeeperPolicies = false
	p.PolicyDefaults.Severity = "critical"
	policyConf := types.PolicyConfig{
		Name: "policy-gatekeeper",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "gatekeeper.yaml")},
		},
	}
	p.Policies = append(p.Policies, policyConf)
	p.applyDefaults(map[string]interface{}{
		"policyDefaults": map[string]interface{}{
			"informGatekeeperPolicies": false,
		},
	})

	err = p.createPolicy(&p.Policies[0])
	if err != nil {
		t.Fatal(err.Error())
	}

	output := p.outputBuffer.String()
	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-gatekeeper
    namespace: gatekeeper-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: templates.gatekeeper.sh/v1
            kind: ConstraintTemplate
            metadata:
                annotations:
                    policy.open-cluster-management.io/severity: critical
                name: myconstrainingtemplate
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePolicyWithGkConstraint(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	gatekeeperPath := path.Join(tmpDir, "gatekeeper.yaml")
	yamlContent := `
apiVersion: constraints.gatekeeper.sh/v1
kind: MyConstrainingTemplate
metadata:
  name: thisthingimconstraining
`

	err := os.WriteFile(gatekeeperPath, []byte(yamlContent), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", gatekeeperPath)
	}

	p := Plugin{}

	p.PolicyDefaults.Namespace = "gatekeeper-policies"
	p.PolicyDefaults.InformGatekeeperPolicies = false
	policyConf := types.PolicyConfig{
		Name: "policy-gatekeeper",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "gatekeeper.yaml")},
		},
	}
	p.Policies = append(p.Policies, policyConf)
	p.applyDefaults(map[string]interface{}{
		"policyDefaults": map[string]interface{}{
			"informGatekeeperPolicies": false,
		},
	})

	err = p.createPolicy(&p.Policies[0])
	if err != nil {
		t.Fatal(err.Error())
	}

	output := p.outputBuffer.String()
	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-gatekeeper
    namespace: gatekeeper-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: constraints.gatekeeper.sh/v1
            kind: MyConstrainingTemplate
            metadata:
                annotations:
                    policy.open-cluster-management.io/severity: low
                name: thisthingimconstraining
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePolicyWithDifferentRemediationAction(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createIamPolicyManifest(t, tmpDir, "iamKindManifestPluginTest.yaml")
	createIamPolicyManifest(t, tmpDir, "iamKindManifestPluginTest2.yaml")

	p := Plugin{}
	p.PolicyDefaults.Namespace = "Iam-policies"

	patches := []map[string]interface{}{
		{
			"spec": map[string]interface{}{
				"remediationAction": "inform",
			},
		},
	}
	policyConf := types.PolicyConfig{
		PolicyOptions: types.PolicyOptions{
			Categories: []string{"AC Access Control"},
			Controls:   []string{"AC-3 Access Enforcement"},
			Standards:  []string{"NIST SP 800-53"},
		},
		Name: "policy-limitclusteradmin",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "iamKindManifestPluginTest.yaml")},
			{
				Path:    path.Join(tmpDir, "iamKindManifestPluginTest2.yaml"),
				Patches: patches,
			},
		},
	}
	p.Policies = append(p.Policies, policyConf)
	p.applyDefaults(map[string]interface{}{})

	err := p.createPolicy(&p.Policies[0])
	if err != nil {
		t.Fatal(err.Error())
	}

	output := p.outputBuffer.String()
	// expected Iam policy generated from
	// non-root IAM policy type manifest
	// in createIamPolicyTypeConfigMap()
	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: AC Access Control
        policy.open-cluster-management.io/controls: AC-3 Access Enforcement
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-limitclusteradmin
    namespace: Iam-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: IamPolicy
            metadata:
                name: policy-limitclusteradmin-example
            spec:
                maxClusterRoleBindingUsers: 5
                namespaceSelector:
                    exclude:
                        - kube-*
                        - openshift-*
                    include:
                        - '*'
                remediationAction: enforce
                severity: medium
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: IamPolicy
            metadata:
                name: policy-limitclusteradmin-example
            spec:
                maxClusterRoleBindingUsers: 5
                namespaceSelector:
                    exclude:
                        - kube-*
                        - openshift-*
                    include:
                        - '*'
                remediationAction: inform
                severity: medium
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePolicyDir(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	createConfigMap(t, tmpDir, "configmap2.yaml")

	p := Plugin{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{
		Name:      "policy-app-config",
		Manifests: []types.Manifest{{Path: tmpDir}},
		ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
			NamespaceSelector: types.NamespaceSelector{Include: []string{"default"}},
		},
	}
	p.Policies = append(p.Policies, policyConf)
	p.applyDefaults(map[string]interface{}{})

	err := p.createPolicy(&p.Policies[0])
	if err != nil {
		t.Fatal(err.Error())
	}

	output := p.outputBuffer.String()
	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                namespaceSelector:
                    include:
                        - default
                object-templates:
                    - complianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                    - complianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePolicyInvalidYAML(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestPath := path.Join(tmpDir, "configmap.yaml")

	err := os.WriteFile(manifestPath, []byte("$ not Yaml!"), 0o666)
	if err != nil {
		t.Fatalf("Failed to create %s: %v", manifestPath, err)
	}

	p := Plugin{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{
		Name:      "policy-app-config",
		Manifests: []types.Manifest{{Path: manifestPath}},
	}
	p.Policies = append(p.Policies, policyConf)
	p.applyDefaults(map[string]interface{}{})

	err = p.createPolicy(&p.Policies[0])
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf(
		"failed to decode the manifest file at %s: the input manifests must be in the format of "+
			"YAML objects", manifestPath,
	)
	assertEqual(t, err.Error(), expected)
}

func TestCreatePolicyInvalidAPIOrKind(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestPath := path.Join(tmpDir, "invalidAPIOrKind.yaml")
	yamlContent := `
apiVersion: policy.open-cluster-management.io/v1
kind:
  - IamPolicy
  - CertificatePolicy
metadata:
  name: policy-limitclusteradmin-example
`

	err := os.WriteFile(manifestPath, []byte(yamlContent), 0o666)
	if err != nil {
		t.Fatalf("Failed to create %s: %v", manifestPath, err)
	}

	p := Plugin{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{
		Name:      "policy-limitclusteradmin",
		Manifests: []types.Manifest{{Path: manifestPath}},
	}
	p.Policies = append(p.Policies, policyConf)
	p.applyDefaults(map[string]interface{}{})

	err = p.createPolicy(&p.Policies[0])
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf(
		"invalid or not found kind in manifest path: %s", manifestPath,
	)
	assertEqual(t, err.Error(), expected)
}

func TestCreatePlacementDefault(t *testing.T) {
	t.Parallel()

	p := Plugin{}
	p.allPlcs = map[string]bool{}
	p.csToPlc = map[string]string{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{Name: "policy-app-config"}

	name, err := p.createPolicyPlacement(policyConf.Placement, policyConf.Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, name, "placement-policy-app-config")

	output := p.outputBuffer.String()
	expected := `
---
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    name: placement-policy-app-config
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions: []
    tolerations:
        - key: cluster.open-cluster-management.io/unavailable
          operator: Exists
        - key: cluster.open-cluster-management.io/unreachable
          operator: Exists
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePlacementSinglePlr(t *testing.T) {
	t.Parallel()

	p := Plugin{}
	p.allPlcs = map[string]bool{}
	p.csToPlc = map[string]string{}
	p.PolicyDefaults.Namespace = "my-policies"
	p.PolicyDefaults.Placement.Name = "my-placement-rule"
	policyConf := types.PolicyConfig{Name: "policy-app-config"}

	name, err := p.createPolicyPlacement(policyConf.Placement, policyConf.Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	name2, err := p.createPolicyPlacement(policyConf.Placement, policyConf.Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	// Verify that another placement rule is not created when the same cluster selectors are used
	assertEqual(t, name, "my-placement-rule")
	assertEqual(t, name2, "my-placement-rule")

	output := p.outputBuffer.String()
	expected := `
---
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    name: my-placement-rule
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions: []
    tolerations:
        - key: cluster.open-cluster-management.io/unavailable
          operator: Exists
        - key: cluster.open-cluster-management.io/unreachable
          operator: Exists
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePlacementClusterSelectors(t *testing.T) {
	t.Parallel()

	p := Plugin{}
	p.usingPlR = true
	p.allPlcs = map[string]bool{}
	p.csToPlc = map[string]string{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{Name: "policy-app-config"}
	policyConf.Placement.ClusterSelectors = map[string]interface{}{
		"cloud":  "red hat",
		"doesIt": "",
		"game":   "pacman",
	}

	name, err := p.createPolicyPlacement(policyConf.Placement, policyConf.Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, name, "placement-policy-app-config")

	output := p.outputBuffer.String()
	expected := `
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
    name: placement-policy-app-config
    namespace: my-policies
spec:
    clusterSelector:
        matchExpressions:
            - key: cloud
              operator: In
              values:
                - red hat
            - key: doesIt
              operator: Exists
            - key: game
              operator: In
              values:
                - pacman
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePlacementLabelSelector(t *testing.T) {
	t.Parallel()

	p := Plugin{}
	p.allPlcs = map[string]bool{}
	p.csToPlc = map[string]string{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{Name: "policy-app-config"}
	policyConf.Placement.LabelSelector = map[string]interface{}{
		"cloud":  "red hat",
		"doesIt": "",
		"game":   "pacman",
	}

	name, err := p.createPolicyPlacement(policyConf.Placement, policyConf.Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, name, "placement-policy-app-config")

	output := p.outputBuffer.String()
	expected := `
---
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    name: placement-policy-app-config
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions:
                    - key: cloud
                      operator: In
                      values:
                        - red hat
                    - key: doesIt
                      operator: Exists
                    - key: game
                      operator: In
                      values:
                        - pacman
    tolerations:
        - key: cluster.open-cluster-management.io/unavailable
          operator: Exists
        - key: cluster.open-cluster-management.io/unreachable
          operator: Exists
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePlacementDuplicateName(t *testing.T) {
	t.Parallel()

	p := Plugin{}
	p.allPlcs = map[string]bool{}
	p.csToPlc = map[string]string{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		PolicyOptions: types.PolicyOptions{
			Placement: types.PlacementConfig{
				Name: "my-placement",
			},
		},
	}
	policyConf2 := types.PolicyConfig{
		Name: "policy-app-config2",
		PolicyOptions: types.PolicyOptions{
			Placement: types.PlacementConfig{
				ClusterSelectors: map[string]interface{}{"my": "app"},
				Name:             "my-placement",
			},
		},
	}

	_, err := p.createPolicyPlacement(policyConf.Placement, policyConf.Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	_, err = p.createPolicyPlacement(policyConf2.Placement, policyConf2.Name)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	assertEqual(t, err.Error(), "a duplicate placement name was detected: my-placement")
}

func plPathHelper(t *testing.T, plrYAML string, usingPlR bool) (*Plugin, string) {
	t.Helper()
	tmpDir := t.TempDir()
	plrPath := path.Join(tmpDir, "pl.yaml")
	plrYAML = strings.TrimPrefix(plrYAML, "\n")

	err := os.WriteFile(plrPath, []byte(plrYAML), 0o666)
	if err != nil {
		t.Fatal(err.Error())
	}

	p := Plugin{}
	p.usingPlR = usingPlR
	p.allPlcs = map[string]bool{}
	p.processedPlcs = map[string]bool{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{Name: "policy-app-config"}

	if usingPlR {
		policyConf.Placement.PlacementRulePath = plrPath
	} else {
		policyConf.Placement.PlacementPath = plrPath
	}

	p.Policies = append(p.Policies, policyConf)

	return &p, plrPath
}

func TestCreatePlacementPlrPath(t *testing.T) {
	t.Parallel()

	plrYAML := `
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
    name: my-plr
    namespace: my-policies
spec:
    clusterSelector:
        matchExpressions:
            - key: game
              operator: In
              values:
                - pacman
`
	plrYAML = strings.TrimPrefix(plrYAML, "\n")
	p, _ := plPathHelper(t, plrYAML, true)

	name, err := p.createPolicyPlacement(p.Policies[0].Placement, p.Policies[0].Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, name, "my-plr")

	output := p.outputBuffer.String()

	assertEqual(t, output, plrYAML)
}

func TestCreatePlacementPlrPathSkip(t *testing.T) {
	t.Parallel()

	plrYAML := `
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
    name: my-plr
    namespace: my-policies
`
	plrYAML = strings.TrimPrefix(plrYAML, "\n")
	p, _ := plPathHelper(t, plrYAML, true)

	p.processedPlcs = map[string]bool{"my-plr": true}

	name, err := p.createPolicyPlacement(p.Policies[0].Placement, p.Policies[0].Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, name, "my-plr")
	assertEqual(t, p.outputBuffer.String(), "")
}

func TestCreatePlacementPlrPathNoName(t *testing.T) {
	t.Parallel()

	plrYAML := `
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions: []
    tolerations:
        - key: cluster.open-cluster-management.io/unavailable
          operator: Exists
        - key: cluster.open-cluster-management.io/unreachable
          operator: Exists
`
	p, plrPath := plPathHelper(t, plrYAML, true)

	_, err := p.createPolicyPlacement(p.Policies[0].Placement, p.Policies[0].Name)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf("the placement %s must have a name set", plrPath)
	assertEqual(t, err.Error(), expected)
}

func TestCreatePlacementPlrPathNoNamespace(t *testing.T) {
	t.Parallel()

	plrYAML := `
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
    name: my-plr
spec:
    clusterSelector:
        matchExpressions: []
`
	p, plrPath := plPathHelper(t, plrYAML, true)

	_, err := p.createPolicyPlacement(p.Policies[0].Placement, p.Policies[0].Name)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf("the placement %s must have a namespace set", plrPath)
	assertEqual(t, err.Error(), expected)
}

func TestCreatePlacementPlrPathWrongNamespace(t *testing.T) {
	t.Parallel()

	plrYAML := `
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
    name: my-plr
    namespace: wrong-namespace
spec:
    clusterSelector:
        matchExpressions: []
`
	p, plrPath := plPathHelper(t, plrYAML, true)

	_, err := p.createPolicyPlacement(p.Policies[0].Placement, p.Policies[0].Name)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf(
		"the placement %s must have the same namespace as the policy (%s)",
		plrPath,
		p.PolicyDefaults.Namespace,
	)
	assertEqual(t, err.Error(), expected)
}

func TestCreatePlacementPlrPathNoPlr(t *testing.T) {
	t.Parallel()

	plrYAML := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-configmap2
  namespace: my-policies
data:
  game.properties: |
    enemies=potato
`
	p, plrPath := plPathHelper(t, plrYAML, true)

	_, err := p.createPolicyPlacement(p.Policies[0].Placement, p.Policies[0].Name)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf("the placement manifest %s did not have a placement", plrPath)
	assertEqual(t, err.Error(), expected)
}

func TestCreatePlacementPlPath(t *testing.T) {
	t.Parallel()

	plrYAML := `
---
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    name: my-plr
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions:
                    - key: game
                      operator: In
                      values:
                        - pacman
    tolerations:
        - key: cluster.open-cluster-management.io/unavailable
          operator: Exists
        - key: cluster.open-cluster-management.io/unreachable
          operator: Exists
`
	plrYAML = strings.TrimPrefix(plrYAML, "\n")
	p, _ := plPathHelper(t, plrYAML, false)

	name, err := p.createPolicyPlacement(p.Policies[0].Placement, p.Policies[0].Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, name, "my-plr")

	output := p.outputBuffer.String()

	assertEqual(t, output, plrYAML)
}

func TestCreatePlacementPlPathSkip(t *testing.T) {
	t.Parallel()

	plrYAML := `
---
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    name: my-plr
    namespace: my-policies
`
	plrYAML = strings.TrimPrefix(plrYAML, "\n")
	p, _ := plPathHelper(t, plrYAML, false)

	p.processedPlcs = map[string]bool{"my-plr": true}

	name, err := p.createPolicyPlacement(p.Policies[0].Placement, p.Policies[0].Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, name, "my-plr")
	assertEqual(t, p.outputBuffer.String(), "")
}

func TestCreatePlacementPlPathNoName(t *testing.T) {
	t.Parallel()

	plrYAML := `
---
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions: []
    tolerations:
        - key: cluster.open-cluster-management.io/unavailable
          operator: Exists
        - key: cluster.open-cluster-management.io/unreachable
          operator: Exists
`
	p, plrPath := plPathHelper(t, plrYAML, false)

	_, err := p.createPolicyPlacement(p.Policies[0].Placement, p.Policies[0].Name)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf("the placement %s must have a name set", plrPath)
	assertEqual(t, err.Error(), expected)
}

func TestCreatePlacementPlPathNoNamespace(t *testing.T) {
	t.Parallel()

	plrYAML := `
---
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    name: my-plr
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions: []
    tolerations:
        - key: cluster.open-cluster-management.io/unavailable
          operator: Exists
        - key: cluster.open-cluster-management.io/unreachable
          operator: Exists
`
	p, plrPath := plPathHelper(t, plrYAML, false)

	_, err := p.createPolicyPlacement(p.Policies[0].Placement, p.Policies[0].Name)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf("the placement %s must have a namespace set", plrPath)
	assertEqual(t, err.Error(), expected)
}

func TestCreatePlacementPlPathWrongNamespace(t *testing.T) {
	t.Parallel()

	plrYAML := `
---
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    name: my-plr
    namespace: wrong-namespace
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions: []
    tolerations:
        - key: cluster.open-cluster-management.io/unavailable
          operator: Exists
        - key: cluster.open-cluster-management.io/unreachable
          operator: Exists
`
	p, plrPath := plPathHelper(t, plrYAML, false)

	_, err := p.createPolicyPlacement(p.Policies[0].Placement, p.Policies[0].Name)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf(
		"the placement %s must have the same namespace as the policy (%s)",
		plrPath,
		p.PolicyDefaults.Namespace,
	)
	assertEqual(t, err.Error(), expected)
}

func TestCreatePlacementPlPathFoundPlR(t *testing.T) {
	t.Parallel()

	plrYAML := `
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
    name: my-plr
    namespace: my-policies
`
	p, plrPath := plPathHelper(t, plrYAML, false)

	_, err := p.createPolicyPlacement(p.Policies[0].Placement, p.Policies[0].Name)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf(
		"the placement %s specified a placementRule kind but expected a placement kind",
		plrPath,
	)
	assertEqual(t, err.Error(), expected)
}

func TestCreatePlacementPlrPathFoundPl(t *testing.T) {
	t.Parallel()

	plrYAML := `
---
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    name: my-plr
    namespace: my-policies
`
	p, plrPath := plPathHelper(t, plrYAML, true)

	_, err := p.createPolicyPlacement(p.Policies[0].Placement, p.Policies[0].Name)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf(
		"the placement %s specified a placement kind but expected a placementRule kind",
		plrPath,
	)
	assertEqual(t, err.Error(), expected)
}

func TestCreatePlacementPlPathNoPl(t *testing.T) {
	t.Parallel()

	plrYAML := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-configmap2
  namespace: my-policies
data:
  game.properties: |
    enemies=potato
`
	p, plrPath := plPathHelper(t, plrYAML, false)

	_, err := p.createPolicyPlacement(p.Policies[0].Placement, p.Policies[0].Name)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf("the placement manifest %s did not have a placement", plrPath)
	assertEqual(t, err.Error(), expected)
}

func TestCreatePlacementBinding(t *testing.T) {
	t.Parallel()

	p := Plugin{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{Name: "policy-app-config"}
	p.Policies = append(p.Policies, policyConf)
	policyConf2 := types.PolicyConfig{Name: "policy-app-config2"}
	p.Policies = append(p.Policies, policyConf2)

	bindingName := "my-placement-binding"
	plrName := "my-placement-rule"
	policyConfs := []*types.PolicyConfig{}
	policyConfs = append(policyConfs, &p.Policies[0], &p.Policies[1])

	policySetConfs := []*types.PolicySetConfig{
		{
			Name: "my-policyset",
		},
	}

	err := p.createPlacementBinding(bindingName, plrName, policyConfs, policySetConfs)
	if err != nil {
		t.Fatal(err)
	}

	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: PlacementBinding
metadata:
    name: my-placement-binding
    namespace: my-policies
placementRef:
    apiGroup: cluster.open-cluster-management.io
    kind: Placement
    name: my-placement-rule
subjects:
    - apiGroup: policy.open-cluster-management.io
      kind: Policy
      name: policy-app-config
    - apiGroup: policy.open-cluster-management.io
      kind: Policy
      name: policy-app-config2
    - apiGroup: policy.open-cluster-management.io
      kind: PolicySet
      name: my-policyset
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, p.outputBuffer.String(), expected)
}

func TestGeneratePolicySets(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	testCases := []testCase{
		{
			name: "Use p.PolicyDefaults.PolicySets only",
			setupFunc: func(p *Plugin) {
				// PolicyDefaults.PolicySets should be applied to both policies
				p.PolicyDefaults.PolicySets = []string{"policyset-default"}
			},
			expectedPolicySetConfigInPolicy: [][]string{
				{"policyset-default"},
				{"policyset-default"},
			},
			expectedPolicySetConfigs: []types.PolicySetConfig{
				{
					Name: "policyset-default",
					Policies: []string{
						"policy-app-config",
						"policy-app-config2",
					},
					PolicySetOptions: types.PolicySetOptions{
						GeneratePolicySetPlacement: true,
					},
				},
			},
		},
		{
			name: "Use p.Policies[0].PolicySets to override with a different policy set",
			setupFunc: func(p *Plugin) {
				// p.PolicyDefaults.PolicySets should be overridden by p.Policies[0].PolicySets
				p.PolicyDefaults.PolicySets = []string{"policyset-default"}
				p.Policies[0] = types.PolicyConfig{
					Name: "policy-app-config",
					Manifests: []types.Manifest{
						{
							Path: path.Join(tmpDir, "configmap.yaml"),
						},
					},
					PolicyOptions: types.PolicyOptions{
						PolicySets: []string{"policyset0"},
					},
				}
			},
			expectedPolicySetConfigInPolicy: [][]string{
				{"policyset0"},
				{"policyset-default"},
			},
			expectedPolicySetConfigs: []types.PolicySetConfig{
				{
					Name: "policyset0",
					Policies: []string{
						"policy-app-config",
					},
					PolicySetOptions: types.PolicySetOptions{
						GeneratePolicySetPlacement: true,
					},
				},
				{
					Name: "policyset-default",
					Policies: []string{
						"policy-app-config2",
					},
					PolicySetOptions: types.PolicySetOptions{
						GeneratePolicySetPlacement: true,
					},
				},
			},
		},
		{
			name: "Use p.Policies[0].PolicySets to override with an empty policyset",
			setupFunc: func(p *Plugin) {
				// p.PolicyDefaults.PolicySets should be overridden by p.Policies[0].PolicySets
				p.PolicyDefaults.PolicySets = []string{"policyset-default"}
				p.Policies[0] = types.PolicyConfig{
					Name: "policy-app-config",
					Manifests: []types.Manifest{
						{
							Path: path.Join(tmpDir, "configmap.yaml"),
						},
					},
					PolicyOptions: types.PolicyOptions{
						PolicySets: []string{},
					},
				}
			},
			expectedPolicySetConfigInPolicy: [][]string{
				{},
				{"policyset-default"},
			},
			expectedPolicySetConfigs: []types.PolicySetConfig{
				{
					Name: "policyset-default",
					Policies: []string{
						"policy-app-config2",
					},
					PolicySetOptions: types.PolicySetOptions{
						GeneratePolicySetPlacement: true,
					},
				},
			},
		},
		{
			name: "Use p.Policies[0].PolicySets and p.PolicySets, should merge",
			setupFunc: func(p *Plugin) {
				// p.Policies[0].PolicySets and p.PolicySets should merge
				p.PolicySets = []types.PolicySetConfig{
					{
						Name:        "policyset-default",
						Description: "This is a default policyset.",
						Policies: []string{
							"policy-app-config",
							"policy-app-config2",
							"pre-exists-policy",
						},
					},
				}
			},
			expectedPolicySetConfigInPolicy: [][]string{
				{"policyset-default"},
				{"policyset-default"},
			},
			expectedPolicySetConfigs: []types.PolicySetConfig{
				{
					Name:        "policyset-default",
					Description: "This is a default policyset.",
					Policies: []string{
						"policy-app-config",
						"policy-app-config2",
						"pre-exists-policy",
					},
					PolicySetOptions: types.PolicySetOptions{
						GeneratePolicySetPlacement: true,
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := Plugin{}
			var err error
			p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
			if err != nil {
				t.Fatal(err.Error())
			}
			p.PlacementBindingDefaults.Name = "my-placement-binding"
			p.PolicyDefaults.Placement.Name = "my-placement-rule"
			p.PolicyDefaults.Namespace = "my-policies"
			policyConf := types.PolicyConfig{
				Name: "policy-app-config",
				Manifests: []types.Manifest{
					{
						Path: path.Join(tmpDir, "configmap.yaml"),
					},
				},
			}
			policyConf2 := types.PolicyConfig{
				Name: "policy-app-config2",
				Manifests: []types.Manifest{
					{Path: path.Join(tmpDir, "configmap.yaml")},
				},
			}
			p.Policies = append(p.Policies, policyConf, policyConf2)
			tc.setupFunc(&p)
			p.applyDefaults(map[string]interface{}{})
			assertReflectEqual(t, p.Policies[0].PolicySets, tc.expectedPolicySetConfigInPolicy[0])
			assertReflectEqual(t, p.Policies[1].PolicySets, tc.expectedPolicySetConfigInPolicy[1])
			assertReflectEqual(t, p.PolicySets, tc.expectedPolicySetConfigs)
		})
	}
}

func TestGeneratePolicySetsWithPlacement(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	var err error

	p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	p.PlacementBindingDefaults.Name = "my-placement-binding"
	p.PolicyDefaults.Placement.Name = "my-placement"
	p.PolicyDefaults.Namespace = "my-policies"

	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{
				Path: path.Join(tmpDir, "configmap.yaml"),
			},
		},
		PolicyOptions: types.PolicyOptions{
			PolicySets: []string{"policyset"},
		},
	}
	p.Policies = append(p.Policies, policyConf)

	p.applyDefaults(map[string]interface{}{})

	if err := p.assertValidConfig(); err != nil {
		t.Fatal(err.Error())
	}

	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                object-templates:
                    - complianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
---
apiVersion: policy.open-cluster-management.io/v1beta1
kind: PolicySet
metadata:
    name: policyset
    namespace: my-policies
spec:
    description: ""
    policies:
        - policy-app-config
---
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    name: my-placement
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions: []
    tolerations:
        - key: cluster.open-cluster-management.io/unavailable
          operator: Exists
        - key: cluster.open-cluster-management.io/unreachable
          operator: Exists
---
apiVersion: policy.open-cluster-management.io/v1
kind: PlacementBinding
metadata:
    name: my-placement-binding
    namespace: my-policies
placementRef:
    apiGroup: cluster.open-cluster-management.io
    kind: Placement
    name: my-placement
subjects:
    - apiGroup: policy.open-cluster-management.io
      kind: PolicySet
      name: policyset
`
	expected = strings.TrimPrefix(expected, "\n")

	output, err := p.Generate()
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, string(output), expected)
}

func TestGeneratePolicySetsOverridePlacement(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	var err error

	p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	p.PlacementBindingDefaults.Name = "my-placement-binding"
	p.PolicyDefaults.Placement.Name = "my-placement"
	p.PolicyDefaults.Namespace = "my-policies"
	p.PolicySetDefaults.Placement.Name = "other-placement"

	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{
				Path: path.Join(tmpDir, "configmap.yaml"),
			},
		},
		PolicyOptions: types.PolicyOptions{
			PolicySets: []string{"policyset-overrides"},
		},
	}
	p.Policies = append(p.Policies, policyConf)

	policySetConf := types.PolicySetConfig{
		Name: "policyset-overrides",
		PolicySetOptions: types.PolicySetOptions{
			Placement: types.PlacementConfig{
				LabelSelector: map[string]interface{}{
					"my-label": "my-cluster",
				},
			},
		},
	}
	p.PolicySets = append(p.PolicySets, policySetConf)

	p.applyDefaults(map[string]interface{}{})

	if err := p.assertValidConfig(); err != nil {
		t.Fatal(err.Error())
	}

	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                object-templates:
                    - complianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
---
apiVersion: policy.open-cluster-management.io/v1beta1
kind: PolicySet
metadata:
    name: policyset-overrides
    namespace: my-policies
spec:
    description: ""
    policies:
        - policy-app-config
---
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    name: other-placement
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions:
                    - key: my-label
                      operator: In
                      values:
                        - my-cluster
    tolerations:
        - key: cluster.open-cluster-management.io/unavailable
          operator: Exists
        - key: cluster.open-cluster-management.io/unreachable
          operator: Exists
---
apiVersion: policy.open-cluster-management.io/v1
kind: PlacementBinding
metadata:
    name: my-placement-binding
    namespace: my-policies
placementRef:
    apiGroup: cluster.open-cluster-management.io
    kind: Placement
    name: other-placement
subjects:
    - apiGroup: policy.open-cluster-management.io
      kind: PolicySet
      name: policyset-overrides
`
	expected = strings.TrimPrefix(expected, "\n")

	output, err := p.Generate()
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, string(output), expected)
}

func TestGeneratePolicySetsWithoutPlacement(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	var err error

	p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	p.PlacementBindingDefaults.Name = "my-placement-binding"
	p.PolicyDefaults.Placement.Name = "my-placement-rule"
	p.PolicyDefaults.Namespace = "my-policies"

	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{
				Path: path.Join(tmpDir, "configmap.yaml"),
			},
		},
		PolicyOptions: types.PolicyOptions{
			PolicySets: []string{"policyset"},
		},
	}
	p.Policies = append(p.Policies, policyConf)

	p.applyDefaults(map[string]interface{}{
		"policySetDefaults": map[string]interface{}{
			"generatePolicySetPlacement": false,
		},
	})

	if err := p.assertValidConfig(); err != nil {
		t.Fatal(err.Error())
	}

	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                object-templates:
                    - complianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
---
apiVersion: policy.open-cluster-management.io/v1beta1
kind: PolicySet
metadata:
    name: policyset
    namespace: my-policies
spec:
    description: ""
    policies:
        - policy-app-config
`
	expected = strings.TrimPrefix(expected, "\n")

	output, err := p.Generate()
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, string(output), expected)
}

func TestGeneratePolicySetsWithPolicyPlacement(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	var err error

	p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	p.PlacementBindingDefaults.Name = "my-placement-binding"
	p.PolicyDefaults.Placement.Name = "my-placement"
	p.PolicyDefaults.Namespace = "my-policies"

	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{
				Path: path.Join(tmpDir, "configmap.yaml"),
			},
		},
		PolicyOptions: types.PolicyOptions{
			PolicySets: []string{"my-policyset"},
		},
	}
	p.Policies = append(p.Policies, policyConf)
	p.PolicySets = []types.PolicySetConfig{
		{
			Name: "my-policyset",
			PolicySetOptions: types.PolicySetOptions{
				Placement: types.PlacementConfig{
					Name:             "policyset-placement",
					ClusterSelectors: map[string]interface{}{"my": "app"},
				},
			},
		},
	}

	p.applyDefaults(map[string]interface{}{})

	if err := p.assertValidConfig(); err != nil {
		t.Fatal(err.Error())
	}

	p.Policies[0].GeneratePlacementWhenInSet = true

	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: NIST SP 800-53
    name: policy-app-config
    namespace: my-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                object-templates:
                    - complianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        data:
                            game.properties: enemies=potato
                        kind: ConfigMap
                        metadata:
                            name: my-configmap
                remediationAction: inform
                severity: low
    remediationAction: inform
---
apiVersion: policy.open-cluster-management.io/v1beta1
kind: PolicySet
metadata:
    name: my-policyset
    namespace: my-policies
spec:
    description: ""
    policies:
        - policy-app-config
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
    name: my-placement
    namespace: my-policies
spec:
    clusterSelector:
        matchExpressions: []
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
    name: policyset-placement
    namespace: my-policies
spec:
    clusterSelector:
        matchExpressions:
            - key: my
              operator: In
              values:
                - app
---
apiVersion: policy.open-cluster-management.io/v1
kind: PlacementBinding
metadata:
    name: binding-policy-app-config
    namespace: my-policies
placementRef:
    apiGroup: apps.open-cluster-management.io
    kind: PlacementRule
    name: my-placement
subjects:
    - apiGroup: policy.open-cluster-management.io
      kind: Policy
      name: policy-app-config
---
apiVersion: policy.open-cluster-management.io/v1
kind: PlacementBinding
metadata:
    name: my-placement-binding
    namespace: my-policies
placementRef:
    apiGroup: apps.open-cluster-management.io
    kind: PlacementRule
    name: policyset-placement
subjects:
    - apiGroup: policy.open-cluster-management.io
      kind: PolicySet
      name: my-policyset
`
	expected = strings.TrimPrefix(expected, "\n")

	output, err := p.Generate()
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, string(output), expected)
}

func TestCreatePolicySet(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	var err error

	p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	p.PlacementBindingDefaults.Name = "my-placement-binding"
	p.PolicyDefaults.Placement.Name = "my-placement-rule"
	p.PolicyDefaults.Namespace = "my-policies"
	patch := map[string]interface{}{
		"metadata": map[string]interface{}{
			"labels": map[string]string{
				"chandler": "bing",
			},
		},
	}
	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{
				Path:    path.Join(tmpDir, "configmap.yaml"),
				Patches: []map[string]interface{}{patch},
			},
		},
	}
	policyConf2 := types.PolicyConfig{
		Name: "policy-app-config2",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "configmap.yaml")},
		},
	}
	p.Policies = append(p.Policies, policyConf, policyConf2)

	p.PolicyDefaults.PolicySets = []string{"policyset-default"}
	p.PolicySets = []types.PolicySetConfig{
		{
			Name:        "policyset-default",
			Description: "This is a default policyset.",
			Policies: []string{
				"policy-app-config",
				"policy-app-config2",
				"pre-exists-policy",
			},
		},
	}
	p.applyDefaults(map[string]interface{}{})

	err = p.createPolicySet(&p.PolicySets[0])
	if err != nil {
		t.Fatal(err.Error())
	}

	output := p.outputBuffer.String()
	expected := `
---
apiVersion: policy.open-cluster-management.io/v1beta1
kind: PolicySet
metadata:
    name: policyset-default
    namespace: my-policies
spec:
    description: This is a default policyset.
    policies:
        - policy-app-config
        - policy-app-config2
        - pre-exists-policy
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func getYAMLEvaluationInterval(
	t *testing.T, policyTemplate interface{}, skipFinalValidation bool,
) map[string]interface{} {
	t.Helper()

	plcTemplate, ok := policyTemplate.(map[string]interface{})
	assertEqual(t, ok, true)

	configPolicy, ok := plcTemplate["objectDefinition"].(map[string]interface{})
	assertEqual(t, ok, true)

	configPolicyOptions, ok := configPolicy["spec"].(map[string]interface{})
	assertEqual(t, ok, true)

	evaluationInterval, ok := configPolicyOptions["evaluationInterval"].(map[string]interface{})

	if !skipFinalValidation {
		assertEqual(t, ok, true)
	}

	return evaluationInterval
}

func TestGenerateEvaluationInterval(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	var err error

	p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	p.PolicyDefaults.Namespace = "my-policies"
	p.PolicyDefaults.EvaluationInterval = types.EvaluationInterval{
		Compliant:    "never",
		NonCompliant: "15s",
	}

	// Test that the policy evaluation interval gets inherited when not set on a manifest.
	policyConf := types.PolicyConfig{
		PolicyOptions: types.PolicyOptions{
			ConsolidateManifests: false,
		},
		ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
			EvaluationInterval: types.EvaluationInterval{
				Compliant:    "30m",
				NonCompliant: "30s",
			},
		},
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "configmap.yaml")},
			{
				ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
					EvaluationInterval: types.EvaluationInterval{
						Compliant:    "25m",
						NonCompliant: "5m",
					},
				},
				Path: path.Join(tmpDir, "configmap.yaml"),
			},
			// Test that it does not get an inherited value when it is explicitly set to empty in the YAML below.
			{
				Path: path.Join(tmpDir, "configmap.yaml"),
			},
		},
	}
	// Test that the policy defaults get inherited.
	policyConf2 := types.PolicyConfig{
		Name: "policy-app-config2",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "configmap.yaml")},
		},
	}
	// Test that explicitly setting evaluationInterval to an empty value overrides the policy default.
	policyConf3 := types.PolicyConfig{
		ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
			EvaluationInterval: types.EvaluationInterval{},
		},
		Name: "policy-app-config3",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "configmap.yaml")},
		},
	}
	p.Policies = append(p.Policies, policyConf, policyConf2, policyConf3)
	p.applyDefaults(
		map[string]interface{}{
			"policies": []interface{}{
				map[string]interface{}{
					"consolidateManifests": false,
					"manifests": []interface{}{
						map[string]interface{}{},
						map[string]interface{}{},
						map[string]interface{}{
							"evaluationInterval": map[string]interface{}{
								"compliant":    "",
								"noncompliant": "",
							},
						},
					},
				},
				map[string]interface{}{},
				map[string]interface{}{
					"evaluationInterval": map[string]interface{}{
						"compliant":    "",
						"noncompliant": "",
					},
				},
			},
		},
	)

	if err := p.assertValidConfig(); err != nil {
		t.Fatal(err.Error())
	}

	output, err := p.Generate()
	if err != nil {
		t.Fatal(err.Error())
	}

	generatedManifests, err := unmarshalManifestBytes(output)
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, len(generatedManifests), 9)

	for _, manifest := range generatedManifests {
		kind, _ := manifest["kind"].(string)
		if kind != "Policy" {
			continue
		}

		metadata, _ := manifest["metadata"].(map[string]interface{})

		name, _ := metadata["name"].(string)

		spec, _ := manifest["spec"].(map[string]interface{})
		policyTemplates, _ := spec["policy-templates"].([]interface{})

		if name == "policy-app-config" {
			assertEqual(t, len(policyTemplates), 3)
			evaluationInterval := getYAMLEvaluationInterval(t, policyTemplates[0], false)
			assertEqual(t, evaluationInterval["compliant"], "30m")
			assertEqual(t, evaluationInterval["noncompliant"], "30s")

			evaluationInterval = getYAMLEvaluationInterval(t, policyTemplates[1], false)
			assertEqual(t, evaluationInterval["compliant"], "25m")
			assertEqual(t, evaluationInterval["noncompliant"], "5m")

			evaluationInterval = getYAMLEvaluationInterval(t, policyTemplates[2], true)
			assertEqual(t, len(evaluationInterval), 0)
		} else if name == "policy-app-config2" {
			assertEqual(t, len(policyTemplates), 1)
			evaluationInterval := getYAMLEvaluationInterval(t, policyTemplates[0], false)
			assertEqual(t, evaluationInterval["compliant"], "never")
			assertEqual(t, evaluationInterval["noncompliant"], "15s")
		} else if name == "policy-app-config3" {
			assertEqual(t, len(policyTemplates), 1)
			evaluationInterval := getYAMLEvaluationInterval(t, policyTemplates[0], true)
			assertEqual(t, len(evaluationInterval), 0)
		}
	}
}

func TestCreatePolicyWithConfigPolicyAnnotations(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	tests := []struct {
		name        string
		annotations map[string]string
	}{
		{name: "no-override", annotations: nil},
		{
			name: "override",
			annotations: map[string]string{
				"policy.open-cluster-management.io/disable-templates": "true",
			},
		},
		{
			name:        "override-empty",
			annotations: map[string]string{},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			p := Plugin{}
			p.PolicyDefaults.Namespace = "my-policies"
			p.PolicyDefaults.ConfigurationPolicyAnnotations = map[string]string{"test-default-annotation": "default"}
			policyConf := types.PolicyConfig{
				Name: "policy-app-config", Manifests: []types.Manifest{
					{Path: path.Join(tmpDir, "configmap.yaml")},
				},
			}

			if test.annotations != nil {
				policyConf.ConfigurationPolicyAnnotations = test.annotations
			}

			p.Policies = append(p.Policies, policyConf)
			p.applyDefaults(map[string]interface{}{})

			err := p.createPolicy(&p.Policies[0])
			if err != nil {
				t.Fatal(err.Error())
			}

			output := p.outputBuffer.Bytes()
			policyManifests, err := unmarshalManifestBytes(output)
			if err != nil {
				t.Fatal(err.Error())
			}
			//nolint:forcetypeassert
			spec := policyManifests[0]["spec"].(map[string]interface{})
			policyTemplates := spec["policy-templates"].([]interface{})
			//nolint:forcetypeassert
			configPolicy := policyTemplates[0].(map[string]interface{})["objectDefinition"].(map[string]interface{})
			//nolint:forcetypeassert
			metadata := configPolicy["metadata"].(map[string]interface{})

			if test.annotations != nil && len(test.annotations) == 0 {
				assertEqual(t, metadata["annotations"], nil)
			} else {
				annotations := map[string]string{}
				for key, val := range metadata["annotations"].(map[string]interface{}) {
					//nolint:forcetypeassert
					annotations[key] = val.(string)
				}

				if test.annotations == nil {
					assertReflectEqual(t, annotations, map[string]string{"test-default-annotation": "default"})
				} else {
					assertReflectEqual(t, annotations, test.annotations)
				}
			}
		})
	}
}

func TestCreatePolicyWithNamespaceSelector(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	tests := map[string]struct {
		name              string
		namespaceSelector types.NamespaceSelector
	}{
		"nil-selector": {namespaceSelector: types.NamespaceSelector{}},
		"empty-selector-values": {
			namespaceSelector: types.NamespaceSelector{
				Include:          []string{},
				Exclude:          []string{},
				MatchLabels:      &map[string]string{},
				MatchExpressions: &[]metav1.LabelSelectorRequirement{},
			},
		},
		"completely-filled-values": {
			namespaceSelector: types.NamespaceSelector{
				Include: []string{"test-ns-1", "test-ns-2"},
				Exclude: []string{"*-ns-[1]"},
				MatchLabels: &map[string]string{
					"testing": "is awesome",
				},
				MatchExpressions: &[]metav1.LabelSelectorRequirement{{
					Key:      "door",
					Operator: "Exists",
				}},
			},
		},
		"include-exclude-only": {
			namespaceSelector: types.NamespaceSelector{
				Include: []string{"test-ns-1", "test-ns-2"},
				Exclude: []string{"*-ns-[1]"},
			},
		},
		"label-selectors-only": {
			namespaceSelector: types.NamespaceSelector{
				MatchLabels: &map[string]string{
					"testing": "is awesome",
				},
				MatchExpressions: &[]metav1.LabelSelectorRequirement{{
					Key:      "door",
					Operator: "Exists",
				}},
			},
		},
	}

	for name, test := range tests {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := Plugin{}
			p.PolicyDefaults.Namespace = "my-policies"
			p.PolicyDefaults.NamespaceSelector = types.NamespaceSelector{
				MatchLabels: &map[string]string{},
			}
			policyConf := types.PolicyConfig{
				Name: "policy-app-config", Manifests: []types.Manifest{
					{Path: path.Join(tmpDir, "configmap.yaml")},
				},
			}
			policyConf.NamespaceSelector = test.namespaceSelector

			p.Policies = append(p.Policies, policyConf)
			p.applyDefaults(map[string]interface{}{})

			err := p.createPolicy(&p.Policies[0])
			if err != nil {
				t.Fatal(err.Error())
			}

			output := p.outputBuffer.Bytes()
			policyManifests, err := unmarshalManifestBytes(output)
			if err != nil {
				t.Fatal(err.Error())
			}
			//nolint:forcetypeassert
			spec := policyManifests[0]["spec"].(map[string]interface{})
			policyTemplates := spec["policy-templates"].([]interface{})
			//nolint:forcetypeassert
			configPolicy := policyTemplates[0].(map[string]interface{})["objectDefinition"].(map[string]interface{})
			//nolint:forcetypeassert
			configPolicyOptions := configPolicy["spec"].(map[string]interface{})
			//nolint:forcetypeassert
			configPolicySelector := configPolicyOptions["namespaceSelector"].(map[string]interface{})

			if reflect.DeepEqual(test.namespaceSelector, types.NamespaceSelector{}) {
				assertSelectorEqual(t, configPolicySelector, p.PolicyDefaults.NamespaceSelector)
			} else {
				assertSelectorEqual(t, configPolicySelector, test.namespaceSelector)
			}
		})
	}
}

func TestGenerateNonDNSPolicyName(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	tests := []struct {
		name       string
		policyName string
	}{
		{
			name:       "capitalized",
			policyName: "policy-APP-CONFIG",
		},
		{
			name:       "invalid character",
			policyName: "policy_app_config",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			p := Plugin{}
			var err error

			p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
			if err != nil {
				t.Fatal(err.Error())
			}

			p.PlacementBindingDefaults.Name = "my-placement-binding"
			p.PolicyDefaults.Placement.Name = "my-placement-rule"
			p.PolicyDefaults.Namespace = "my-policies"
			policyConf := types.PolicyConfig{
				Name: test.policyName,
				Manifests: []types.Manifest{
					{Path: path.Join(tmpDir, "configmap.yaml")},
				},
			}
			basePolicies := p.Policies
			p.Policies = append(basePolicies, policyConf)
			p.applyDefaults(map[string]interface{}{})

			err = p.assertValidConfig()
			if err == nil {
				t.Fatal("Expected an error but did not get one")
			}

			expected := fmt.Sprintf(
				"policy name `%s` is not DNS compliant. See "+
					"https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names",
				test.policyName,
			)
			assertEqual(t, err.Error(), expected)
		})
	}
}

func TestGenerateNonDNSPlacementName(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	tests := []struct {
		name          string
		placementName string
	}{
		{
			name:          "capitalized",
			placementName: "my-placement-RULE",
		},
		{
			name:          "invalid character",
			placementName: "my-placement?rule",
		},
		{
			name: "too many characters",
			placementName: "placementplacementplacementplacementplacementplacementplacementplacementplacement" +
				"placementplacementplacementplacementplacementplacementplacementplacementplacementplacement" +
				"placementplacementplacementplacementplacementplacementplacementplacementplacementrule",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			p := Plugin{}
			var err error

			p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
			if err != nil {
				t.Fatal(err.Error())
			}

			p.PlacementBindingDefaults.Name = "my-placement-binding"
			p.PolicyDefaults.Placement.Name = test.placementName
			p.PolicyDefaults.Namespace = "my-policies"
			policyConf := types.PolicyConfig{
				Name: "policy-app-config",
				Manifests: []types.Manifest{
					{Path: path.Join(tmpDir, "configmap.yaml")},
				},
			}
			p.Policies = append(p.Policies, policyConf)
			p.applyDefaults(map[string]interface{}{})

			err = p.assertValidConfig()
			if err == nil {
				t.Fatal("Expected an error but did not get one")
			}

			expected := fmt.Sprintf(
				"policyDefaults placement.name `%s` is not DNS compliant. See "+
					"https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names",
				test.placementName,
			)
			assertEqual(t, err.Error(), expected)
		})
	}
}

func TestGenerateNonDNSBindingName(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	tests := []struct {
		name        string
		bindingName string
	}{
		{
			name:        "capitalized",
			bindingName: "my-placement-BINDING",
		},
		{
			name:        "invalid character",
			bindingName: "my-placement?binding",
		},
		{
			name: "too many characters",
			bindingName: "placementplacementplacementplacementplacementplacementplacementplacementplacement" +
				"placementplacementplacementplacementplacementplacementplacementplacementplacementplacement" +
				"placementplacementplacementplacementplacementplacementplacementplacementplacementbinding",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			p := Plugin{}
			var err error

			p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
			if err != nil {
				t.Fatal(err.Error())
			}

			p.PlacementBindingDefaults.Name = test.bindingName
			p.PolicyDefaults.Placement.Name = "my-placement-rule"
			p.PolicyDefaults.Namespace = "my-policies"
			policyConf := types.PolicyConfig{
				Name: "policy-app-config",
				Manifests: []types.Manifest{
					{Path: path.Join(tmpDir, "configmap.yaml")},
				},
			}
			policyConf2 := types.PolicyConfig{
				Name: "policy-app-config2",
				Manifests: []types.Manifest{
					{Path: path.Join(tmpDir, "configmap.yaml")},
				},
			}
			p.Policies = append(p.Policies, policyConf, policyConf2)
			p.applyDefaults(map[string]interface{}{})

			err = p.assertValidConfig()
			if err == nil {
				t.Fatal("Expected an error but did not get one")
			}

			expected := fmt.Sprintf(
				"PlacementBindingDefaults.Name `%s` is not DNS compliant. See "+
					"https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names",
				test.bindingName,
			)
			assertEqual(t, err.Error(), expected)
		})
	}
}

func TestCreatePlacementRuleFromMatchExpressions(t *testing.T) {
	t.Parallel()

	p := Plugin{}
	p.usingPlR = true
	p.allPlcs = map[string]bool{}
	p.csToPlc = map[string]string{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{Name: "policy-app-config"}
	me := map[string]interface{}{
		"key":      "cloud",
		"operator": "In",
		"values": []string{
			"red hat",
			"test",
		},
	}
	policyConf.Placement.ClusterSelectors = map[string]interface{}{
		"matchExpressions": []interface{}{me},
	}

	name, err := p.createPolicyPlacement(policyConf.Placement, policyConf.Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, name, "placement-policy-app-config")

	output := p.outputBuffer.String()
	expected := `
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
    name: placement-policy-app-config
    namespace: my-policies
spec:
    clusterSelector:
        matchExpressions:
            - key: cloud
              operator: In
              values:
                - red hat
                - test
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePlacementRuleWithClusterSelector(t *testing.T) {
	t.Parallel()

	p := Plugin{}
	p.usingPlR = true
	p.allPlcs = map[string]bool{}
	p.csToPlc = map[string]string{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{Name: "policy-app-config"}
	me := map[string]interface{}{
		"key":      "cloud",
		"operator": "In",
		"values": []string{
			"red hat",
			"test",
		},
	}
	policyConf.Placement.ClusterSelector = map[string]interface{}{
		"matchExpressions": []interface{}{me},
	}

	name, err := p.createPolicyPlacement(policyConf.Placement, policyConf.Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, name, "placement-policy-app-config")

	output := p.outputBuffer.String()
	expected := `
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
    name: placement-policy-app-config
    namespace: my-policies
spec:
    clusterSelector:
        matchExpressions:
            - key: cloud
              operator: In
              values:
                - red hat
                - test
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePlacementFromMatchLabels(t *testing.T) {
	t.Parallel()

	p := Plugin{}
	p.allPlcs = map[string]bool{}
	p.csToPlc = map[string]string{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{Name: "policy-app-config"}
	ml := map[string]interface{}{
		"cloud": "red hat",
	}
	policyConf.Placement.ClusterSelectors = map[string]interface{}{
		"matchLabels": ml,
	}

	name, err := p.createPolicyPlacement(policyConf.Placement, policyConf.Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, name, "placement-policy-app-config")

	output := p.outputBuffer.String()
	expected := `
---
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    name: placement-policy-app-config
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchLabels:
                    cloud: red hat
    tolerations:
        - key: cluster.open-cluster-management.io/unavailable
          operator: Exists
        - key: cluster.open-cluster-management.io/unreachable
          operator: Exists
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePlacementFromMatchExpressions(t *testing.T) {
	t.Parallel()

	p := Plugin{}
	p.allPlcs = map[string]bool{}
	p.csToPlc = map[string]string{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{Name: "policy-app-config"}
	me := map[string]interface{}{
		"key":      "cloud",
		"operator": "In",
		"values": []string{
			"red hat",
			"test",
		},
	}
	policyConf.Placement.LabelSelector = map[string]interface{}{
		"matchExpressions": []interface{}{me},
	}

	name, err := p.createPolicyPlacement(policyConf.Placement, policyConf.Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, name, "placement-policy-app-config")

	output := p.outputBuffer.String()
	expected := `
---
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    name: placement-policy-app-config
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions:
                    - key: cloud
                      operator: In
                      values:
                        - red hat
                        - test
    tolerations:
        - key: cluster.open-cluster-management.io/unavailable
          operator: Exists
        - key: cluster.open-cluster-management.io/unreachable
          operator: Exists
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePlacementInvalidMatchExpressions(t *testing.T) {
	t.Parallel()

	p := Plugin{}
	p.allPlcs = map[string]bool{}
	p.csToPlc = map[string]string{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{Name: "policy-app-config"}
	nestedMap := map[string]interface{}{
		"test": "invalid",
	}
	me := map[string]interface{}{
		"key":      "cloud",
		"operator": "In",
		"values": []interface{}{
			"red hat",
			nestedMap,
		},
	}
	policyConf.Placement.LabelSelector = map[string]interface{}{
		"matchExpressions": []interface{}{me},
	}

	_, err := p.createPolicyPlacement(policyConf.Placement, policyConf.Name)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "the input is not a valid label selector or key-value label matching map"
	assertEqual(t, err.Error(), expected)
}

func TestCreatePlacementMultipleSelectors(t *testing.T) {
	t.Parallel()

	p := Plugin{}
	p.allPlcs = map[string]bool{}
	p.csToPlc = map[string]string{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{Name: "policy-app-config"}
	me := map[string]interface{}{
		"key":      "cloud",
		"operator": "In",
		"values": []string{
			"red hat",
		},
	}
	ml := map[string]interface{}{
		"cloud": "red hat",
	}
	policyConf.Placement.LabelSelector = map[string]interface{}{
		"matchExpressions": []interface{}{me},
		"matchLabels":      ml,
	}

	_, err := p.createPolicyPlacement(policyConf.Placement, policyConf.Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	output := p.outputBuffer.String()
	expected := `
---
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    name: placement-policy-app-config
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions:
                    - key: cloud
                      operator: In
                      values:
                        - red hat
                matchLabels:
                    cloud: red hat
    tolerations:
        - key: cluster.open-cluster-management.io/unavailable
          operator: Exists
        - key: cluster.open-cluster-management.io/unreachable
          operator: Exists
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePolicyWithCopyPolicyMetadata(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	bTrue := true
	bFalse := false

	tests := []struct {
		name               string
		copyPolicyMetadata *bool
		expected           *bool
	}{
		{name: "unset", copyPolicyMetadata: nil, expected: nil},
		{name: "true", copyPolicyMetadata: &bTrue, expected: nil},
		{name: "false", copyPolicyMetadata: &bFalse, expected: &bFalse},
	}

	for _, mode := range []string{"policyDefault", "policy"} {
		mode := mode

		for _, test := range tests {
			test := test
			t.Run(mode+" "+test.name, func(t *testing.T) {
				t.Parallel()

				p := Plugin{}
				p.PolicyDefaults.Namespace = "my-policies"
				policyConf := types.PolicyConfig{
					Name: "policy-app-config", Manifests: []types.Manifest{
						{Path: path.Join(tmpDir, "configmap.yaml")},
					},
				}

				policyDefaultsUnmarshaled := map[string]interface{}{}
				policyUnmarshaled := map[string]interface{}{}

				if test.copyPolicyMetadata != nil {
					if mode == "policyDefault" {
						policyDefaultsUnmarshaled["copyPolicyMetadata"] = *test.copyPolicyMetadata
					} else if mode == "policy" {
						policyUnmarshaled["copyPolicyMetadata"] = *test.copyPolicyMetadata
					}
				}

				p.Policies = append(p.Policies, policyConf)
				p.applyDefaults(
					map[string]interface{}{
						"policyDefaults": policyDefaultsUnmarshaled,
						"policies":       []interface{}{policyUnmarshaled},
					},
				)

				err := p.createPolicy(&p.Policies[0])
				if err != nil {
					t.Fatal(err.Error())
				}

				output := p.outputBuffer.Bytes()
				policyManifests, err := unmarshalManifestBytes(output)
				if err != nil {
					t.Fatal(err.Error())
				}

				//nolint:forcetypeassert
				spec := policyManifests[0]["spec"].(map[string]interface{})

				if test.expected == nil {
					if _, set := spec["copyPolicyMetadata"]; set {
						t.Fatal("Expected the policy's spec.copyPolicyMetadata to be unset")
					}
				} else {
					assertEqual(t, spec["copyPolicyMetadata"], *test.expected)
				}
			})
		}
	}
}
