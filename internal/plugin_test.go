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
	p.PolicyDefaults.RecreateOption = "IfRequired"
	p.PolicyDefaults.ObjectSelector = types.LabelSelector{
		MatchLabels: &map[string]string{},
	}
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
			ObjectSelector: types.LabelSelector{
				MatchLabels: &map[string]string{"phoebe": "buffay"},
			},
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
					RecreateOption:         "None",
					ObjectSelector: types.LabelSelector{
						MatchExpressions: &[]metav1.LabelSelectorRequirement{},
					},
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
                      objectSelector:
                        matchLabels:
                            phoebe: buffay
                      recordDiff: Log
                      recreateOption: IfRequired
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
                      objectSelector:
                        matchExpressions: []
                      recordDiff: None
                      recreateOption: None
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
  gatekeeperEnforcementAction: deny
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

				assertEqual(t, p.PolicyDefaults.GatekeeperEnforcementAction, "deny")
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

	p.PolicyDefaults.Placement.PlacementName = "plrexistingname"
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

func TestGeneratePolicyOverrideDefaultPlacement(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	var err error

	p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	p.PolicyDefaults.Placement.PlacementName = "my-placement"
	p.PolicyDefaults.Namespace = "my-policies"
	PolicyConf := types.PolicyConfig{
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{
				Path: path.Join(tmpDir, "configmap.yaml"),
			},
		},
		PolicyOptions: types.PolicyOptions{
			Placement: types.PlacementConfig{
				PlacementName: "my-placement-rule",
			},
		},
	}
	p.Policies = append(p.Policies, PolicyConf)
	p.applyDefaults(map[string]interface{}{})

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
    name: my-placement-rule
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
	expectedErr := "found empty YAML in the manifest at " + path.Join(tmpDir, "empty.yaml")
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

func TestCreatePolicyHubTemplateOptions(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	p := Plugin{}
	p.PolicyDefaults.Namespace = "my-policies"
	p.PolicyDefaults.HubTemplateOptions = types.HubTemplateOptions{ServiceAccountName: "default-sa"}

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
    hubTemplateOptions:
        serviceAccountName: default-sa
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

	// Override the value on the policy
	p.outputBuffer.Reset()
	p.Policies[0].PolicyOptions = types.PolicyOptions{
		HubTemplateOptions: types.HubTemplateOptions{ServiceAccountName: "override-sa"},
	}
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
    hubTemplateOptions:
        serviceAccountName: override-sa
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

func TestCreatePolicyFromCertificatePolicyTypeManifest(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createCertPolicyManifest(t, tmpDir, "certKindManifestPluginTest.yaml")

	p := Plugin{}
	p.PolicyDefaults.Namespace = "cert-policies"
	policyConf := types.PolicyConfig{
		PolicyOptions: types.PolicyOptions{
			Categories: []string{"AC Access Control"},
			Controls:   []string{"AC-3 Access Enforcement"},
			Standards:  []string{"NIST SP 800-53"},
		},
		Name: "certpolicy-minduration",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "certKindManifestPluginTest.yaml")},
		},
	}
	p.Policies = append(p.Policies, policyConf)
	p.applyDefaults(map[string]interface{}{})

	err := p.createPolicy(&p.Policies[0])
	if err != nil {
		t.Fatal(err.Error())
	}

	output := p.outputBuffer.String()
	// expected Cert policy generated from
	// non-root Cert policy type manifest
	// in createCertPolicyTypeConfigMap()
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
    name: certpolicy-minduration
    namespace: cert-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: CertificatePolicy
            metadata:
                name: certpolicy-minduration
            spec:
                minimumDuration: 720h
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

func TestCreatePolicyFromObjectTemplatesRawManifest(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createObjectTemplatesRawManifest(t, tmpDir, "objectTemplatesRawPluginTest.yaml")

	p := Plugin{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{
		PolicyOptions: types.PolicyOptions{
			Categories: []string{"AC Access Control"},
			Controls:   []string{"AC-3 Access Enforcement"},
			Standards:  []string{"NIST SP 800-53"},
		},
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "objectTemplatesRawPluginTest.yaml")},
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
        policy.open-cluster-management.io/categories: AC Access Control
        policy.open-cluster-management.io/controls: AC-3 Access Enforcement
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
                object-templates-raw: |-
                    - complianceType: musthave
                      objectDefinition:
                        apiVersion: v1
                        kind: ConfigMap
                        metadata:
                          name: example
                          namespace: default
                        data:
                          extraData: data
                remediationAction: inform
                severity: low
    remediationAction: inform
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

func TestOverrideConstraintEnforcementAction(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	gatekeeperPath := path.Join(tmpDir, "gatekeeper.yaml")
	yamlContent := `
apiVersion: constraints.gatekeeper.sh/v1
kind: MyConstrainingTemplate
metadata:
  name: thisthingimconstraining
`

	common := `
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
            spec:
                enforcementAction: `

	err := os.WriteFile(gatekeeperPath, []byte(yamlContent), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", gatekeeperPath)
	}

	tests := []struct {
		policyConf      types.PolicyConfig
		policyDefaultEA string
		expectedEA      string
	}{
		{
			policyConf: types.PolicyConfig{
				Name: "policy-gatekeeper",
				Manifests: []types.Manifest{
					{
						Path:              gatekeeperPath,
						GatekeeperOptions: types.GatekeeperOptions{GatekeeperEnforcementAction: "deny"},
					},
				},
			},
			policyDefaultEA: "",
			expectedEA:      "deny",
		},
		{
			policyConf: types.PolicyConfig{
				Name: "policy-gatekeeper",
				Manifests: []types.Manifest{
					{
						Path:              gatekeeperPath,
						GatekeeperOptions: types.GatekeeperOptions{GatekeeperEnforcementAction: "warn"},
					},
				},
			},
			policyDefaultEA: "",
			expectedEA:      "warn",
		},
		{
			policyConf: types.PolicyConfig{
				Name: "policy-gatekeeper",
				Manifests: []types.Manifest{
					{
						Path: gatekeeperPath,
					},
				},
			},
			policyDefaultEA: "deny",
			expectedEA:      "deny",
		},
		{
			policyConf: types.PolicyConfig{
				Name: "policy-gatekeeper",
				Manifests: []types.Manifest{
					{
						Path:              gatekeeperPath,
						GatekeeperOptions: types.GatekeeperOptions{GatekeeperEnforcementAction: "dryrun"},
					},
				},
			},
			policyDefaultEA: "deny",
			expectedEA:      "dryrun",
		},
		{
			policyConf: types.PolicyConfig{
				Name:              "policy-gatekeeper",
				GatekeeperOptions: types.GatekeeperOptions{GatekeeperEnforcementAction: "dryrun"},
				Manifests: []types.Manifest{
					{
						Path: gatekeeperPath,
					},
				},
			},
			policyDefaultEA: "deny",
			expectedEA:      "dryrun",
		},
	}

	for _, tc := range tests {
		p := Plugin{}

		p.PolicyDefaults.Namespace = "gatekeeper-policies"
		p.PolicyDefaults.InformGatekeeperPolicies = false

		p.PolicyDefaults.GatekeeperEnforcementAction = tc.policyDefaultEA

		p.Policies = append(p.Policies, tc.policyConf)

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

		expected := strings.TrimPrefix(common+tc.expectedEA+"\n", "\n")

		assertEqual(t, output, expected)
	}
}

func TestCreatePolicyWithDifferentRemediationAction(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createCertPolicyManifest(t, tmpDir, "certKindManifestPluginTest.yaml")
	createCertPolicyManifest(t, tmpDir, "certKindManifestPluginTest2.yaml")

	p := Plugin{}
	p.PolicyDefaults.Namespace = "cert-policies"

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
		Name: "certpolicy-minduration",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "certKindManifestPluginTest.yaml")},
			{
				Path:    path.Join(tmpDir, "certKindManifestPluginTest2.yaml"),
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
	// expected Cert policy generated from
	// non-root Cert policy type manifest
	// in createCertificatePolicyTypeConfigMap()
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
    name: certpolicy-minduration
    namespace: cert-policies
spec:
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: CertificatePolicy
            metadata:
                name: certpolicy-minduration
            spec:
                minimumDuration: 720h
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
            kind: CertificatePolicy
            metadata:
                name: certpolicy-minduration
            spec:
                minimumDuration: 720h
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
  - ConfigurationPolicy
  - CertificatePolicy
metadata:
  name: certpolicy-minduration-example
`

	err := os.WriteFile(manifestPath, []byte(yamlContent), 0o666)
	if err != nil {
		t.Fatalf("Failed to create %s: %v", manifestPath, err)
	}

	p := Plugin{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{
		Name:      "certpolicy-minduration",
		Manifests: []types.Manifest{{Path: manifestPath}},
	}
	p.Policies = append(p.Policies, policyConf)
	p.applyDefaults(map[string]interface{}{})

	err = p.createPolicy(&p.Policies[0])
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "invalid or not found kind in manifest path: " + manifestPath
	assertEqual(t, err.Error(), expected)
}

func TestCreatePlacementDefault(t *testing.T) {
	t.Parallel()

	p := Plugin{}
	p.allPlcs = map[string]bool{}
	p.selectorToPlc = map[string]string{}
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
	p.selectorToPlc = map[string]string{}
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

func TestCreatePlacementLabelSelector(t *testing.T) {
	t.Parallel()

	p := Plugin{}
	p.allPlcs = map[string]bool{}
	p.selectorToPlc = map[string]string{}
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
	p.selectorToPlc = map[string]string{}
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
				LabelSelector: map[string]interface{}{"my": "app"},
				Name:          "my-placement",
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

func plPathHelper(t *testing.T, placementYAML string) (*Plugin, string) {
	t.Helper()
	tmpDir := t.TempDir()
	placementPath := path.Join(tmpDir, "pl.yaml")
	placementYAML = strings.TrimPrefix(placementYAML, "\n")

	err := os.WriteFile(placementPath, []byte(placementYAML), 0o666)
	if err != nil {
		t.Fatal(err.Error())
	}

	p := Plugin{}
	p.allPlcs = map[string]bool{}
	p.processedPlcs = map[string]bool{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{Name: "policy-app-config"}

	policyConf.Placement.PlacementPath = placementPath

	p.Policies = append(p.Policies, policyConf)

	return &p, placementPath
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
	p, _ := plPathHelper(t, plrYAML)

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
	p, _ := plPathHelper(t, plrYAML)

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
	p, plrPath := plPathHelper(t, plrYAML)

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
	p, plrPath := plPathHelper(t, plrYAML)

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
	p, plrPath := plPathHelper(t, plrYAML)

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
	p, plrPath := plPathHelper(t, plrYAML)

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
		// capture range variable
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
					Name:          "policyset-placement",
					LabelSelector: map[string]interface{}{"my": "app"},
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
apiVersion: cluster.open-cluster-management.io/v1beta1
kind: Placement
metadata:
    name: policyset-placement
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions:
                    - key: my
                      operator: In
                      values:
                        - app
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
    apiGroup: cluster.open-cluster-management.io
    kind: Placement
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
	createObjectTemplatesRawManifest(t, tmpDir, "object-templates-raw.yaml")

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
	// Test that the policy defaults get inherited with object-templates-raw.
	policyConf4 := types.PolicyConfig{
		Name: "policy-app-config4",
		Manifests: []types.Manifest{
			{Path: path.Join(tmpDir, "object-templates-raw.yaml")},
		},
	}
	p.Policies = append(p.Policies, policyConf, policyConf2, policyConf3, policyConf4)
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

	assertEqual(t, len(generatedManifests), 12)

	for _, manifest := range generatedManifests {
		kind, _ := manifest["kind"].(string)
		if kind != "Policy" {
			continue
		}

		metadata, _ := manifest["metadata"].(map[string]interface{})

		name, _ := metadata["name"].(string)

		spec, _ := manifest["spec"].(map[string]interface{})
		policyTemplates, _ := spec["policy-templates"].([]interface{})

		switch name {
		case "policy-app-config":
			assertEqual(t, len(policyTemplates), 3)
			evaluationInterval := getYAMLEvaluationInterval(t, policyTemplates[0], false)
			assertEqual(t, evaluationInterval["compliant"], "30m")
			assertEqual(t, evaluationInterval["noncompliant"], "30s")

			evaluationInterval = getYAMLEvaluationInterval(t, policyTemplates[1], false)
			assertEqual(t, evaluationInterval["compliant"], "25m")
			assertEqual(t, evaluationInterval["noncompliant"], "5m")

			evaluationInterval = getYAMLEvaluationInterval(t, policyTemplates[2], true)
			assertEqual(t, len(evaluationInterval), 0)

		case "policy-app-config2", "policy-app-config4":
			assertEqual(t, len(policyTemplates), 1)
			evaluationInterval := getYAMLEvaluationInterval(t, policyTemplates[0], false)
			assertEqual(t, evaluationInterval["compliant"], "never")
			assertEqual(t, evaluationInterval["noncompliant"], "15s")

		case "policy-app-config3":
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
				Include: []string{},
				Exclude: []string{},
				LabelSelector: types.LabelSelector{
					MatchLabels:      &map[string]string{},
					MatchExpressions: &[]metav1.LabelSelectorRequirement{},
				},
			},
		},
		"completely-filled-values": {
			namespaceSelector: types.NamespaceSelector{
				Include: []string{"test-ns-1", "test-ns-2"},
				Exclude: []string{"*-ns-[1]"},
				LabelSelector: types.LabelSelector{
					MatchLabels: &map[string]string{
						"testing": "is awesome",
					},
					MatchExpressions: &[]metav1.LabelSelectorRequirement{{
						Key:      "door",
						Operator: "Exists",
					}},
				},
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
				LabelSelector: types.LabelSelector{
					MatchLabels: &map[string]string{
						"testing": "is awesome",
					},
					MatchExpressions: &[]metav1.LabelSelectorRequirement{{
						Key:      "door",
						Operator: "Exists",
					}},
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := Plugin{}
			p.PolicyDefaults.Namespace = "my-policies"
			p.PolicyDefaults.NamespaceSelector = types.NamespaceSelector{
				LabelSelector: types.LabelSelector{
					MatchLabels: &map[string]string{},
				},
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

			p.Policies = append(p.Policies, policyConf)
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

func TestCreatePlacementFromMatchExpressions(t *testing.T) {
	t.Parallel()

	p := Plugin{}
	p.allPlcs = map[string]bool{}
	p.selectorToPlc = map[string]string{}
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

func TestCreatePlacementFromMatchLabels(t *testing.T) {
	t.Parallel()

	p := Plugin{}
	p.allPlcs = map[string]bool{}
	p.selectorToPlc = map[string]string{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{Name: "policy-app-config"}
	ml := map[string]interface{}{
		"cloud": "red hat",
	}
	policyConf.Placement.LabelSelector = map[string]interface{}{
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

func TestCreatePlacementInvalidMatchExpressions(t *testing.T) {
	t.Parallel()

	p := Plugin{}
	p.allPlcs = map[string]bool{}
	p.selectorToPlc = map[string]string{}
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
	p.selectorToPlc = map[string]string{}
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
		for _, test := range tests {
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

func TestCreatePolicyWithCustomMessage(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	createConfigMap(t, tmpDir, "configmap2.yaml")

	p := Plugin{}
	var err error

	p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	p.PolicyDefaults.Namespace = "my-policies"
	p.PolicyDefaults.CustomMessage = types.CustomMessage{
		Compliant:    "{{ default }}",
		NonCompliant: "{{ default }}",
	}

	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		PolicyOptions: types.PolicyOptions{
			ConsolidateManifests: false,
		},
		Manifests: []types.Manifest{
			{
				Path: path.Join(tmpDir, "configmap.yaml"),
			},
			{
				Path: path.Join(tmpDir, "configmap2.yaml"),
			},
		},
	}
	p.Policies = append(p.Policies, policyConf)

	// Ensure values are correctly propagated/overridden
	p.applyDefaults(map[string]interface{}{})
	assertEqual(t, policyConf.Manifests[0].ConfigurationPolicyOptions.CustomMessage.Compliant, "{{ default }}")
	assertEqual(t, policyConf.Manifests[0].ConfigurationPolicyOptions.CustomMessage.NonCompliant, "{{ default }}")
	assertEqual(t, policyConf.Manifests[1].ConfigurationPolicyOptions.CustomMessage.Compliant, "{{ default }}")
	assertEqual(t, policyConf.Manifests[1].ConfigurationPolicyOptions.CustomMessage.NonCompliant, "{{ default }}")

	// With consolidateManifest = false
	policyConf.ConfigurationPolicyOptions = types.ConfigurationPolicyOptions{
		CustomMessage: types.CustomMessage{
			Compliant:    "{{ root }}",
			NonCompliant: "{{ root }}",
		},
	}
	policyConf.Manifests[0].ConfigurationPolicyOptions = types.ConfigurationPolicyOptions{
		CustomMessage: types.CustomMessage{
			Compliant:    "{{ manifest1 }}",
			NonCompliant: "{{ manifest1 }}",
		},
	}
	policyConf.Manifests[1].ConfigurationPolicyOptions = types.ConfigurationPolicyOptions{
		CustomMessage: types.CustomMessage{
			Compliant:    "{{ manifest2 }}",
			NonCompliant: "{{ manifest2 }}",
		},
	}

	p.applyDefaults(map[string]interface{}{})

	err = p.createPolicy(&policyConf)
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
        policy.open-cluster-management.io/categories: ""
        policy.open-cluster-management.io/controls: ""
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: ""
    name: policy-app-config
    namespace: my-policies
spec:
    copyPolicyMetadata: false
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                customMessage:
                    compliant: '{{ manifest1 }}'
                    noncompliant: '{{ manifest1 }}'
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
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config2
            spec:
                customMessage:
                    compliant: '{{ manifest2 }}'
                    noncompliant: '{{ manifest2 }}'
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
	p.outputBuffer.Reset()

	// With consolidateManifest = true
	policyConf.PolicyOptions.ConsolidateManifests = true
	err = p.assertValidConfig()
	expectedErr := "the policy policy-app-config has the customMessage " +
		"value set on manifest[0] but consolidateManifests is true"
	assertEqual(t, err.Error(), expectedErr)

	// Note: customMessage field at the manifest level must be set to
	// the same value as in the policy level when consolidateManifest = true
	// to successfully generate a policy. If customMessage field is unset
	// at the manifest level, applyDefaults() can be used to populate this field
	// if it's set at the policyDefaults or policy level.
	policyConf.Manifests[0].ConfigurationPolicyOptions.CustomMessage.Compliant = "{{ root }}"
	policyConf.Manifests[0].ConfigurationPolicyOptions.CustomMessage.NonCompliant = "{{ root }}"
	policyConf.Manifests[1].ConfigurationPolicyOptions.CustomMessage.Compliant = "{{ root }}"
	policyConf.Manifests[1].ConfigurationPolicyOptions.CustomMessage.NonCompliant = "{{ root }}"

	err = p.createPolicy(&policyConf)
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
        policy.open-cluster-management.io/categories: ""
        policy.open-cluster-management.io/controls: ""
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: ""
    name: policy-app-config
    namespace: my-policies
spec:
    copyPolicyMetadata: false
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: policy-app-config
            spec:
                customMessage:
                    compliant: '{{ root }}'
                    noncompliant: '{{ root }}'
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
                remediationAction: ""
                severity: ""
`

	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

// Test Patching a CR object, "MyCr", containing a list of profile objects.
// Patching profile interface name and (not profile) recommend
// - metadata:
// name: "profile1"
// spec:
// recommend:
// - match:
//   - nodeLabel: node-role.kubernetes.io/master
//     priority: 4
//     listOfStuff: profile1
//
// listOfStuff:
//   - name: "profile1"
//     interface: "ens5f1"
//
// The profile name is used to locate the right profile entry in the patch
func TestOpenAPIListPatch(t *testing.T) {
	const (
		crFilename      = "cr1.yaml"
		openAPIFilename = "openapi-schema.json"
	)

	t.Parallel()
	tmpDir := t.TempDir()
	// relative path to the CR file
	crRelativePath := filepath.Join(tmpDir, crFilename)
	// Relative path to the openAPI schema
	openAPIRelativePath := filepath.Join(tmpDir, openAPIFilename)
	// Loading plugin file, CR file, and shema file to memory
	pluginFileContent, err := os.ReadFile("testdata/OpenAPI/policy-generator1.yaml")
	assertEqual(t, err, nil)
	crFileContent, err := os.ReadFile("testdata/OpenAPI/cr-files/" + crFilename)
	assertEqual(t, err, nil)
	openAPIFileContent, err := os.ReadFile("testdata/OpenAPI/openapi-schema.json")
	assertEqual(t, err, nil)

	// Writing CR file and shema file to temporary directory
	err = os.WriteFile(crRelativePath, crFileContent, 0o666)
	assertEqual(t, err, nil)
	err = os.WriteFile(openAPIRelativePath, openAPIFileContent, 0o666)
	assertEqual(t, err, nil)

	p := Plugin{}

	// Load plugin object from file
	err = yaml.Unmarshal(pluginFileContent, &p)
	assertEqual(t, err, nil)

	p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	// Set CR file path and OpenAPI path with temporary directory
	p.Policies[0].Manifests[0].Path = crRelativePath
	p.Policies[0].Manifests[0].OpenAPI.Path = openAPIRelativePath

	// Check configuration
	if err := p.assertValidConfig(); err != nil {
		t.Fatal(err.Error())
	}

	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: ""
        policy.open-cluster-management.io/controls: ""
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: ""
    name: group-du-sno-latest-config-policy
    namespace: ztp-group
spec:
    copyPolicyMetadata: false
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: group-du-sno-latest-config-policy
            spec:
                object-templates:
                    - complianceType: ""
                      objectDefinition:
                        apiVersion: myapp.myorg.io/v1
                        kind: MyCr
                        metadata:
                            name: profile1
                            namespace: mynamespace
                        spec:
                            listOfStuff:
                                - myattribute: ens5f1
                                  name: profile1
                remediationAction: ""
                severity: ""
`
	expected = strings.TrimPrefix(expected, "\n")
	// Generated Policies
	output, err := p.Generate()
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, string(output), expected)
}

// Test patching unknown fields in the MyCr CR.
// The "plugins" object is a generic object (part of the profile list) not defined by the schema
// Patching :
// LocalHoldoverTimeout: 14400
// to
// LocalHoldoverTimeout: 14401
func TestOpenAPIListUnkownFieldsPatch(t *testing.T) {
	const (
		crFilename      = "cr2.yaml"
		openAPIFilename = "openapi-schema.json"
	)

	t.Parallel()
	tmpDir := t.TempDir()
	// relative path to the CR file
	crRelativePath := filepath.Join(tmpDir, crFilename)
	// Relative path to the openAPI schema
	openAPIRelativePath := filepath.Join(tmpDir, openAPIFilename)
	// Loading plugin file, CR file, and shema file to memory
	pluginFileContent, err := os.ReadFile("testdata/OpenAPI/policy-generator2.yaml")
	assertEqual(t, err, nil)
	crFileContent, err := os.ReadFile("testdata/OpenAPI/cr-files/" + crFilename)
	assertEqual(t, err, nil)
	openAPIFileContent, err := os.ReadFile("testdata/OpenAPI/openapi-schema.json")
	assertEqual(t, err, nil)

	// Writing CR file and shema file to temporary directory
	err = os.WriteFile(crRelativePath, crFileContent, 0o666)
	assertEqual(t, err, nil)
	err = os.WriteFile(openAPIRelativePath, openAPIFileContent, 0o666)
	assertEqual(t, err, nil)

	p := Plugin{}

	// Load plugin object from file
	err = yaml.Unmarshal(pluginFileContent, &p)
	assertEqual(t, err, nil)

	p.baseDirectory, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	// Set CR file path and OpenAPI path with temporary directory
	p.Policies[0].Manifests[0].Path = crRelativePath
	p.Policies[0].Manifests[0].OpenAPI.Path = openAPIRelativePath

	// Check configuration
	if err := p.assertValidConfig(); err != nil {
		t.Fatal(err.Error())
	}

	expected := `
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: ""
        policy.open-cluster-management.io/controls: ""
        policy.open-cluster-management.io/description: ""
        policy.open-cluster-management.io/standards: ""
    name: group-du-sno-v4.14-config-policy
    namespace: ztp-group
spec:
    copyPolicyMetadata: false
    disabled: false
    policy-templates:
        - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
                name: group-du-sno-v4.14-config-policy
            spec:
                object-templates:
                    - complianceType: ""
                      objectDefinition:
                        apiVersion: myapp.myorg.io/v1
                        kind: MyCr
                        metadata:
                            name: profile1
                            namespace: mynamespace
                        spec:
                            listOfStuff:
                                - name: profile1
                                  plugins:
                                    e810:
                                        enableDefaultConfig: false
                                        pins: $e810_pins
                                        settings:
                                            LocalHoldoverTimeout: 14401
                                            LocalMaxHoldoverOffSet: 1500
                                            MaxInSpecOffset: 100
                remediationAction: ""
                severity: ""
`
	expected = strings.TrimPrefix(expected, "\n")
	// Generated Policies
	output, err := p.Generate()
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, string(output), expected)
}
