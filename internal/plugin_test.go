// Copyright Contributors to the Open Cluster Management project
package internal

import (
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stolostron/policy-generator-plugin/internal/types"
)

type testCase struct {
	name                            string
	setupFunc                       func(p *Plugin, policyConf types.PolicyConfig, policyConf2 types.PolicyConfig)
	expectedPolicySetConfigInPolicy [][]string
	expectedPolicySetConfigs        []types.PolicySetConfig
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
                            labels:
                                chandler: bing
                            name: my-configmap
                remediationAction: inform
                severity: low
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
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
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
    name: my-placement-rule
    namespace: my-policies
spec:
    clusterConditions:
        - status: "True"
          type: ManagedClusterConditionAvailable
    clusterSelector:
        matchExpressions: []
---
apiVersion: policy.open-cluster-management.io/v1
kind: PlacementBinding
metadata:
    name: my-placement-binding
    namespace: my-policies
placementRef:
    apiGroup: apps.open-cluster-management.io
    kind: PlacementRule
    name: my-placement-rule
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
---
apiVersion: policy.open-cluster-management.io/v1
kind: Policy
metadata:
    annotations:
        policy.open-cluster-management.io/categories: CM Configuration Management
        policy.open-cluster-management.io/controls: CM-2 Baseline Configuration
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
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
    name: placement-policy-app-config
    namespace: my-policies
spec:
    clusterConditions:
        - status: "True"
          type: ManagedClusterConditionAvailable
    clusterSelector:
        matchExpressions: []
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
    name: placement-policy-app-config2
    namespace: my-policies
spec:
    clusterConditions:
        - status: "True"
          type: ManagedClusterConditionAvailable
    clusterSelector:
        matchExpressions: []
---
apiVersion: policy.open-cluster-management.io/v1
kind: PlacementBinding
metadata:
    name: binding-policy-app-config
    namespace: my-policies
placementRef:
    apiGroup: apps.open-cluster-management.io
    kind: PlacementRule
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
    apiGroup: apps.open-cluster-management.io
    kind: PlacementRule
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
		Name:              "policy-app-config",
		Manifests:         []types.Manifest{{Path: tmpDir}},
		NamespaceSelector: types.NamespaceSelector{Include: []string{"default"}},
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
`
	expected = strings.TrimPrefix(expected, "\n")
	assertEqual(t, output, expected)
}

func TestCreatePolicyInvalidYAML(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestPath := path.Join(tmpDir, "configmap.yaml")
	err := ioutil.WriteFile(manifestPath, []byte("$ not Yaml!"), 0o666)
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

func TestCreatePlacementDefault(t *testing.T) {
	t.Parallel()
	p := Plugin{}
	p.allPlcs = map[string]bool{}
	p.csToPlc = map[string]string{}
	p.PolicyDefaults.Namespace = "my-policies"
	policyConf := types.PolicyConfig{Name: "policy-app-config"}

	name, err := p.createPlacement(&policyConf.Placement, policyConf.Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, name, "placement-policy-app-config")
	output := p.outputBuffer.String()
	expected := `
---
apiVersion: cluster.open-cluster-management.io/v1alpha1
kind: Placement
metadata:
    name: placement-policy-app-config
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions: []
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

	name, err := p.createPlacement(&policyConf.Placement, policyConf.Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	name2, err := p.createPlacement(&policyConf.Placement, policyConf.Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	// Verify that another placement rule is not created when the same cluster selectors are used
	assertEqual(t, name, "my-placement-rule")
	assertEqual(t, name2, "my-placement-rule")
	output := p.outputBuffer.String()
	expected := `
---
apiVersion: cluster.open-cluster-management.io/v1alpha1
kind: Placement
metadata:
    name: my-placement-rule
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions: []
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
	policyConf.Placement.ClusterSelectors = map[string]string{
		"cloud":  "red hat",
		"doesIt": "",
		"game":   "pacman",
	}

	name, err := p.createPlacement(&policyConf.Placement, policyConf.Name)
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
    clusterConditions:
        - status: "True"
          type: ManagedClusterConditionAvailable
    clusterSelector:
        matchExpressions:
            - key: cloud
              operator: In
              values:
                - red hat
            - key: doesIt
              operator: Exist
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
	policyConf.Placement.LabelSelector = map[string]string{
		"cloud":  "red hat",
		"doesIt": "",
		"game":   "pacman",
	}

	name, err := p.createPlacement(&policyConf.Placement, policyConf.Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, name, "placement-policy-app-config")
	output := p.outputBuffer.String()
	expected := `
---
apiVersion: cluster.open-cluster-management.io/v1alpha1
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
                      operator: Exist
                    - key: game
                      operator: In
                      values:
                        - pacman
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
		Placement: types.PlacementConfig{
			Name: "my-placement",
		},
	}
	policyConf2 := types.PolicyConfig{
		Name: "policy-app-config2",
		Placement: types.PlacementConfig{
			ClusterSelectors: map[string]string{"my": "app"},
			Name:             "my-placement",
		},
	}

	_, err := p.createPlacement(&policyConf.Placement, policyConf.Name)
	if err != nil {
		t.Fatal(err.Error())
	}

	_, err = p.createPlacement(&policyConf2.Placement, policyConf2.Name)
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
	err := ioutil.WriteFile(plrPath, []byte(plrYAML), 0o666)
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
    clusterConditions:
        - status: "True"
          type: ManagedClusterConditionAvailable
    clusterSelector:
        matchExpressions:
            - key: game
              operator: In
              values:
                - pacman
`
	plrYAML = strings.TrimPrefix(plrYAML, "\n")
	p, _ := plPathHelper(t, plrYAML, true)

	name, err := p.createPlacement(&p.Policies[0].Placement, p.Policies[0].Name)
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
	name, err := p.createPlacement(&p.Policies[0].Placement, p.Policies[0].Name)
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
    clusterConditions:
        - status: "True"
          type: ManagedClusterConditionAvailable
    clusterSelector:
        matchExpressions: []
`
	p, plrPath := plPathHelper(t, plrYAML, true)

	_, err := p.createPlacement(&p.Policies[0].Placement, p.Policies[0].Name)
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
    clusterConditions:
        - status: "True"
          type: ManagedClusterConditionAvailable
    clusterSelector:
        matchExpressions: []
`
	p, plrPath := plPathHelper(t, plrYAML, true)

	_, err := p.createPlacement(&p.Policies[0].Placement, p.Policies[0].Name)
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
    clusterConditions:
        - status: "True"
          type: ManagedClusterConditionAvailable
    clusterSelector:
        matchExpressions: []
`
	p, plrPath := plPathHelper(t, plrYAML, true)

	_, err := p.createPlacement(&p.Policies[0].Placement, p.Policies[0].Name)
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

	_, err := p.createPlacement(&p.Policies[0].Placement, p.Policies[0].Name)
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
apiVersion: cluster.open-cluster-management.io/v1alpha1
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
`
	plrYAML = strings.TrimPrefix(plrYAML, "\n")
	p, _ := plPathHelper(t, plrYAML, false)

	name, err := p.createPlacement(&p.Policies[0].Placement, p.Policies[0].Name)
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
apiVersion: cluster.open-cluster-management.io/v1alpha1
kind: Placement
metadata:
    name: my-plr
    namespace: my-policies
`
	plrYAML = strings.TrimPrefix(plrYAML, "\n")
	p, _ := plPathHelper(t, plrYAML, false)

	p.processedPlcs = map[string]bool{"my-plr": true}
	name, err := p.createPlacement(&p.Policies[0].Placement, p.Policies[0].Name)
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
apiVersion: cluster.open-cluster-management.io/v1alpha1
kind: Placement
metadata:
    namespace: my-policies
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions: []
`
	p, plrPath := plPathHelper(t, plrYAML, false)

	_, err := p.createPlacement(&p.Policies[0].Placement, p.Policies[0].Name)
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
apiVersion: cluster.open-cluster-management.io/v1alpha1
kind: Placement
metadata:
    name: my-plr
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions: []
`
	p, plrPath := plPathHelper(t, plrYAML, false)

	_, err := p.createPlacement(&p.Policies[0].Placement, p.Policies[0].Name)
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
apiVersion: cluster.open-cluster-management.io/v1alpha1
kind: Placement
metadata:
    name: my-plr
    namespace: wrong-namespace
spec:
    predicates:
        - requiredClusterSelector:
            labelSelector:
                matchExpressions: []
`
	p, plrPath := plPathHelper(t, plrYAML, false)

	_, err := p.createPlacement(&p.Policies[0].Placement, p.Policies[0].Name)
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

	_, err := p.createPlacement(&p.Policies[0].Placement, p.Policies[0].Name)
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
apiVersion: cluster.open-cluster-management.io/v1alpha1
kind: Placement
metadata:
    name: my-plr
    namespace: my-policies
`
	p, plrPath := plPathHelper(t, plrYAML, true)

	_, err := p.createPlacement(&p.Policies[0].Placement, p.Policies[0].Name)
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

	_, err := p.createPlacement(&p.Policies[0].Placement, p.Policies[0].Name)
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
			setupFunc: func(p *Plugin, policyConf types.PolicyConfig, policyConf2 types.PolicyConfig) {
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
				},
			},
		},
		{
			name: "Use p.Policies[0].PolicySets to override with a different policy set",
			setupFunc: func(p *Plugin, policyConf types.PolicyConfig, policyConf2 types.PolicyConfig) {
				// p.PolicyDefaults.PolicySets should be overridden by p.Policies[0].PolicySets
				p.PolicyDefaults.PolicySets = []string{"policyset-default"}
				p.Policies[0] = types.PolicyConfig{
					Name: "policy-app-config",
					Manifests: []types.Manifest{
						{
							Path: path.Join(tmpDir, "configmap.yaml"),
						},
					},
					PolicySets: []string{"policyset0"},
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
				},
				{
					Name: "policyset-default",
					Policies: []string{
						"policy-app-config2",
					},
				},
			},
		},
		{
			name: "Use p.Policies[0].PolicySets to override with an empty policyset",
			setupFunc: func(p *Plugin, policyConf types.PolicyConfig, policyConf2 types.PolicyConfig) {
				// p.PolicyDefaults.PolicySets should be overridden by p.Policies[0].PolicySets
				p.PolicyDefaults.PolicySets = []string{"policyset-default"}
				p.Policies[0] = types.PolicyConfig{
					Name: "policy-app-config",
					Manifests: []types.Manifest{
						{
							Path: path.Join(tmpDir, "configmap.yaml"),
						},
					},
					PolicySets: []string{},
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
				},
			},
		},
		{
			name: "Use p.Policies[0].PolicySets and p.PolicySets, should merge",
			setupFunc: func(p *Plugin, policyConf types.PolicyConfig, policyConf2 types.PolicyConfig) {
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
			tc.setupFunc(&p, policyConf, policyConf2)
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
	p.PolicyDefaults.Placement.Name = "my-placement-rule"
	p.PolicyDefaults.Namespace = "my-policies"

	policyConf := types.PolicyConfig{
		Name: "policy-app-config",
		Manifests: []types.Manifest{
			{
				Path: path.Join(tmpDir, "configmap.yaml"),
			},
		},
		PolicySets: []string{"policyset"},
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
---
apiVersion: policy.open-cluster-management.io/v1
kind: PolicySet
metadata:
    name: policyset
    namespace: my-policies
spec:
    description: ""
    policies:
        - policy-app-config
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
    name: my-placement-rule
    namespace: my-policies
spec:
    clusterConditions:
        - status: "True"
          type: ManagedClusterConditionAvailable
    clusterSelector:
        matchExpressions: []
---
apiVersion: policy.open-cluster-management.io/v1
kind: PlacementBinding
metadata:
    name: my-placement-binding
    namespace: my-policies
placementRef:
    apiGroup: apps.open-cluster-management.io
    kind: PlacementRule
    name: my-placement-rule
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
		PolicySets: []string{"my-policyset"},
	}
	p.Policies = append(p.Policies, policyConf)
	p.PolicySets = []types.PolicySetConfig{
		{
			Name: "my-policyset",
			Placement: types.PlacementConfig{
				Name:             "policyset-placement",
				ClusterSelectors: map[string]string{"my": "app"},
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
---
apiVersion: policy.open-cluster-management.io/v1
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
    clusterConditions:
        - status: "True"
          type: ManagedClusterConditionAvailable
    clusterSelector:
        matchExpressions: []
---
apiVersion: apps.open-cluster-management.io/v1
kind: PlacementRule
metadata:
    name: policyset-placement
    namespace: my-policies
spec:
    clusterConditions:
        - status: "True"
          type: ManagedClusterConditionAvailable
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
apiVersion: policy.open-cluster-management.io/v1
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
