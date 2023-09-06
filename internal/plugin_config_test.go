// Copyright Contributors to the Open Cluster Management project
package internal

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"

	"open-cluster-management.io/policy-generator-plugin/internal/types"
)

func createConfigMap(t *testing.T, tmpDir, filename string) {
	t.Helper()

	manifestsPath := path.Join(tmpDir, filename)
	yamlContent := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-configmap
data:
  game.properties: enemies=potato
`

	err := os.WriteFile(manifestsPath, []byte(yamlContent), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", manifestsPath)
	}
}

func createConfigPolicyManifest(t *testing.T, tmpDir, filename string) {
	t.Helper()

	manifestsPath := path.Join(tmpDir, filename)
	yamlContent := `
apiVersion: policy.open-cluster-management.io/v1
kind: ConfigurationPolicy
metadata:
  name: configpolicy-my-configmap
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

	err := os.WriteFile(manifestsPath, []byte(yamlContent), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", manifestsPath)
	}
}

func createIamPolicyManifest(t *testing.T, tmpDir, filename string) {
	t.Helper()

	manifestsPath := path.Join(tmpDir, filename)
	yamlContent := `
apiVersion: policy.open-cluster-management.io/v1
kind: IamPolicy
metadata:
  name: policy-limitclusteradmin-example
spec:
  severity: medium
  namespaceSelector:
    include: ["*"]
    exclude: ["kube-*", "openshift-*"]
  remediationAction: enforce
  maxClusterRoleBindingUsers: 5
`

	err := os.WriteFile(manifestsPath, []byte(yamlContent), 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", manifestsPath)
	}
}

func TestConfig(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	configMapPath := path.Join(tmpDir, "configmap.yaml")
	createConfigMap(t, tmpDir, "configmap2.yaml")
	configMapPath2 := path.Join(tmpDir, "configmap.yaml")
	createConfigMap(t, tmpDir, "configmap3.yaml")
	configMapPath3 := path.Join(tmpDir, "configmap.yaml")
	exampleConfig := fmt.Sprintf(
		`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
placementBindingDefaults:
  name: my-placement-binding
policyDefaults:
  controls:
    - PR.DS-1 Data-at-rest
  metadataComplianceType: musthave
  namespace: my-policies
  namespaceSelector:
    include:
      - default
    exclude:
      - my-protected-ns
  placement:
    clusterSelectors:
      cloud: red hat
  remediationAction: enforce
  severity: medium
policies:
- name: policy-app-config
  disabled: false
  manifests:
    - path: %s
  namespaceSelector:
    include:
      - app-ns
  remediationAction: inform
- name: policy-app-config2
  metadataComplianceType: mustonlyhave
  disabled: true
  manifests:
    - path: %s
      metadataComplianceType: musthave
    - path: %s
  placement:
    clusterSelectors:
      cloud: weather
`,
		configMapPath,
		configMapPath2,
		configMapPath3,
	)

	p := Plugin{}

	err := p.Config([]byte(exampleConfig), tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, p.Metadata.Name, "policy-generator-name")
	assertEqual(t, p.PlacementBindingDefaults.Name, "my-placement-binding")
	assertReflectEqual(t, p.PolicyDefaults.Categories, []string{"CM Configuration Management"})
	assertEqual(t, p.PolicyDefaults.ComplianceType, "musthave")
	assertReflectEqual(t, p.PolicyDefaults.Controls, []string{"PR.DS-1 Data-at-rest"})
	assertEqual(t, p.PolicyDefaults.Namespace, "my-policies")

	expectedNsSelector := types.NamespaceSelector{
		Exclude: []string{"my-protected-ns"}, Include: []string{"default"},
	}

	assertReflectEqual(t, p.PolicyDefaults.NamespaceSelector, expectedNsSelector)
	assertEqual(t, p.PolicyDefaults.Placement.PlacementRulePath, "")
	assertEqual(t, p.PolicyDefaults.Placement.PlacementPath, "")
	assertReflectEqual(
		t,
		p.PolicyDefaults.Placement.ClusterSelectors,
		map[string]interface{}{"cloud": "red hat"},
	)
	assertEqual(t, len(p.PolicyDefaults.Placement.LabelSelector), 0)
	assertEqual(t, p.PolicyDefaults.RemediationAction, "enforce")
	assertEqual(t, p.PolicyDefaults.Severity, "medium")
	assertReflectEqual(t, p.PolicyDefaults.Standards, []string{"NIST SP 800-53"})
	assertEqual(t, len(p.Policies), 2)

	policy1 := p.Policies[0]
	assertReflectEqual(t, policy1.Categories, []string{"CM Configuration Management"})
	assertEqual(t, policy1.ComplianceType, "musthave")
	assertEqual(t, policy1.MetadataComplianceType, "musthave")
	assertReflectEqual(t, policy1.Controls, []string{"PR.DS-1 Data-at-rest"})
	assertEqual(t, policy1.Disabled, false)
	assertEqual(t, len(policy1.Manifests), 1)
	assertEqual(t, policy1.Manifests[0].Path, configMapPath)
	assertEqual(t, policy1.Manifests[0].MetadataComplianceType, "musthave")
	assertEqual(t, policy1.Name, "policy-app-config")

	p1ExpectedNsSelector := types.NamespaceSelector{
		Exclude: nil, Include: []string{"app-ns"},
	}

	assertReflectEqual(t, policy1.NamespaceSelector, p1ExpectedNsSelector)
	assertReflectEqual(
		t,
		policy1.Placement.ClusterSelectors,
		map[string]interface{}{"cloud": "red hat"},
	)
	assertEqual(t, policy1.RemediationAction, "inform")
	assertEqual(t, policy1.Severity, "medium")
	assertReflectEqual(t, policy1.Standards, []string{"NIST SP 800-53"})

	policy2 := p.Policies[1]
	assertReflectEqual(t, policy2.Categories, []string{"CM Configuration Management"})
	assertEqual(t, policy2.ComplianceType, "musthave")
	assertEqual(t, policy2.MetadataComplianceType, "mustonlyhave")
	assertReflectEqual(t, policy2.Controls, []string{"PR.DS-1 Data-at-rest"})
	assertEqual(t, policy2.Disabled, true)
	assertEqual(t, len(policy2.Manifests), 2)
	assertEqual(t, policy2.Manifests[0].Path, configMapPath2)
	assertEqual(t, policy2.Manifests[0].MetadataComplianceType, "musthave")
	assertEqual(t, policy2.Manifests[1].Path, configMapPath3)
	assertEqual(t, policy2.Manifests[1].MetadataComplianceType, "mustonlyhave")
	assertEqual(t, policy2.Name, "policy-app-config2")
	assertReflectEqual(t, policy2.NamespaceSelector, expectedNsSelector)
	assertReflectEqual(
		t,
		policy2.Placement.ClusterSelectors,
		map[string]interface{}{"cloud": "weather"},
	)
	assertEqual(t, policy2.RemediationAction, "enforce")
	assertEqual(t, policy2.Severity, "medium")
	assertReflectEqual(t, policy2.Standards, []string{"NIST SP 800-53"})
}

func TestConfigAllDefaults(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	configMapPath := path.Join(tmpDir, "configmap.yaml")
	defaultsConfig := fmt.Sprintf(
		`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
policies:
- name: policy-app-config
  manifests:
    - path: %s
`,
		configMapPath,
	)
	p := Plugin{}

	err := p.Config([]byte(defaultsConfig), tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, p.Metadata.Name, "policy-generator-name")
	assertEqual(t, p.PlacementBindingDefaults.Name, "")
	assertReflectEqual(t, p.PolicyDefaults.Categories, []string{"CM Configuration Management"})
	assertEqual(t, p.PolicyDefaults.Disabled, false)
	assertEqual(t, p.PolicyDefaults.ComplianceType, "musthave")
	assertEqual(t, p.PolicyDefaults.MetadataComplianceType, "")
	assertReflectEqual(t, p.PolicyDefaults.Controls, []string{"CM-2 Baseline Configuration"})
	assertEqual(t, p.PolicyDefaults.Namespace, "my-policies")

	expectedNsSelector := types.NamespaceSelector{Exclude: nil, Include: nil}

	assertEqual(t, p.PolicyDefaults.InformGatekeeperPolicies, true)
	assertEqual(t, p.PolicyDefaults.InformKyvernoPolicies, true)
	assertReflectEqual(t, p.PolicyDefaults.NamespaceSelector, expectedNsSelector)
	assertEqual(t, p.PolicyDefaults.Placement.PlacementRulePath, "")
	assertEqual(t, len(p.PolicyDefaults.Placement.ClusterSelectors), 0)
	assertEqual(t, p.PolicyDefaults.Placement.PlacementPath, "")
	assertEqual(t, len(p.PolicyDefaults.Placement.LabelSelector), 0)
	assertEqual(t, p.PolicyDefaults.RemediationAction, "inform")
	assertEqual(t, p.PolicyDefaults.Severity, "low")
	assertReflectEqual(t, p.PolicyDefaults.Standards, []string{"NIST SP 800-53"})
	assertEqual(t, len(p.Policies), 1)

	policy := p.Policies[0]
	assertReflectEqual(t, policy.Categories, []string{"CM Configuration Management"})
	assertEqual(t, policy.Disabled, false)
	assertEqual(t, policy.ComplianceType, "musthave")
	assertEqual(t, policy.MetadataComplianceType, "")
	assertReflectEqual(t, policy.Controls, []string{"CM-2 Baseline Configuration"})
	assertEqual(t, policy.Disabled, false)
	assertEqual(t, len(policy.Manifests), 1)
	assertEqual(t, policy.Manifests[0].Path, configMapPath)
	assertEqual(t, policy.Name, "policy-app-config")
	assertReflectEqual(t, policy.NamespaceSelector, expectedNsSelector)
	assertEqual(t, len(policy.Placement.ClusterSelectors), 0)
	assertEqual(t, policy.Placement.PlacementRulePath, "")
	assertEqual(t, len(policy.Placement.LabelSelector), 0)
	assertEqual(t, policy.Placement.PlacementPath, "")
	assertEqual(t, policy.RemediationAction, "inform")
	assertEqual(t, policy.Severity, "low")
	assertReflectEqual(t, policy.Standards, []string{"NIST SP 800-53"})
	assertEqual(t, policy.InformGatekeeperPolicies, true)
	assertEqual(t, policy.InformKyvernoPolicies, true)
}

func TestConfigNoNamespace(t *testing.T) {
	t.Parallel()
	const config = `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policies:
- name: policy-app-config
  manifests:
    - path: input/configmap.yaml
`

	p := Plugin{}

	err := p.Config([]byte(config), "")
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policyDefaults.namespace is empty but it must be set"
	assertEqual(t, err.Error(), expected)
}

func TestConfigInvalidPolicyName(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	configMapPath := path.Join(tmpDir, "configmap.yaml")
	policyNS := "my-policies-my-policies-my-policies"
	policyName := "policy-app-config-policy-app-config-policy-app-config"
	defaultsConfig := fmt.Sprintf(
		`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: %s
policies:
- name: %s
  manifests:
    - path: %s
`,
		policyNS, policyName, configMapPath,
	)

	p := Plugin{}

	err := p.Config([]byte(defaultsConfig), tmpDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf(
		"the policy namespace and name cannot be more than 63 characters: %s.%s", policyNS, policyName,
	)
	assertEqual(t, err.Error(), expected)
}

func TestConfigNoPolicies(t *testing.T) {
	t.Parallel()
	const config = `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
`

	p := Plugin{}

	err := p.Config([]byte(config), "")
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policies is empty but it must be set"
	assertEqual(t, err.Error(), expected)
}

func TestConfigInvalidPath(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	configMapPath := path.Join(tmpDir, "configmap.yaml")
	policyNS := "my-policies"
	policyName := "policy-app-config"
	defaultsConfig := fmt.Sprintf(
		`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: %s
policies:
- name: %s
  manifests:
    - path: %s
`,
		policyNS, policyName, configMapPath,
	)

	p := Plugin{}
	// Provide a base directory that isn't in the same directory tree as tmpDir.
	baseDir := t.TempDir()

	err := p.Config([]byte(defaultsConfig), baseDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf(
		"the manifest path %s is not in the same directory tree as the kustomization.yaml file", configMapPath,
	)
	assertEqual(t, err.Error(), expected)
}

func TestConfigMultiplePlacementsClusterSelectorAndPlRPath(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	config := fmt.Sprintf(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
policies:
- name: policy-app-config
  placement:
    clusterSelectors:
      cloud: red hat
    placementRulePath: path/to/plr.yaml
  manifests:
    - path: %s
`,
		path.Join(tmpDir, "configmap.yaml"),
	)
	p := Plugin{}

	err := p.Config([]byte(config), tmpDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policy policy-app-config must specify only one of " +
		"placement selector, placement path, or placement name"
	assertEqual(t, err.Error(), expected)
}

func TestConfigMultiplePlacementsClusterSelectorAndPlRName(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	config := fmt.Sprintf(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
policies:
- name: policy-app-config
  placement:
    clusterSelectors:
      cloud: red hat
    placementRuleName: plrexistingname
  manifests:
    - path: %s
`,
		path.Join(tmpDir, "configmap.yaml"),
	)
	p := Plugin{}

	err := p.Config([]byte(config), tmpDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policy policy-app-config must specify only one of " +
		"placement selector, placement path, or placement name"
	assertEqual(t, err.Error(), expected)
}

func TestConfigMultiplePlacementsLabelSelectorAndPlRPath(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	config := fmt.Sprintf(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
policies:
- name: policy-app-config
  placement:
    labelSelector:
      cloud: red hat
    placementRulePath: path/to/plr.yaml
  manifests:
    - path: %s
`,
		path.Join(tmpDir, "configmap.yaml"),
	)
	p := Plugin{}

	err := p.Config([]byte(config), tmpDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policy policy-app-config must specify only one of " +
		"placement selector, placement path, or placement name"
	assertEqual(t, err.Error(), expected)
}

func TestConfigMultiplePlacementsLabelSelectorAndPlRName(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	config := fmt.Sprintf(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
policies:
- name: policy-app-config
  placement:
    labelSelector:
      cloud: red hat
    placementRuleName: plrexistingname
  manifests:
    - path: %s
`,
		path.Join(tmpDir, "configmap.yaml"),
	)
	p := Plugin{}

	err := p.Config([]byte(config), tmpDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policy policy-app-config must specify only one of " +
		"placement selector, placement path, or placement name"
	assertEqual(t, err.Error(), expected)
}

func TestConfigMultiplePlacementsLabelSelectorAndPlPath(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	config := fmt.Sprintf(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
policies:
- name: policy-app-config
  placement:
    labelSelector:
      cloud: red hat
    placementPath: path/to/pl.yaml
  manifests:
    - path: %s
`,
		path.Join(tmpDir, "configmap.yaml"),
	)
	p := Plugin{}

	err := p.Config([]byte(config), tmpDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policy policy-app-config must specify only one of " +
		"placement selector, placement path, or placement name"
	assertEqual(t, err.Error(), expected)
}

func TestConfigMultiplePlacementsLabelSelectorAndPlName(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	config := fmt.Sprintf(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
policies:
- name: policy-app-config
  placement:
    labelSelector:
      cloud: red hat
    placementName: plexistingname
  manifests:
    - path: %s
`,
		path.Join(tmpDir, "configmap.yaml"),
	)
	p := Plugin{}

	err := p.Config([]byte(config), tmpDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policy policy-app-config must specify only one of " +
		"placement selector, placement path, or placement name"
	assertEqual(t, err.Error(), expected)
}

func TestConfigMultipleDefaultPlacementLabels(t *testing.T) {
	t.Parallel()
	const config = `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
  placement:
    clusterSelectors:
      cloud: red hat
    labelSelector:
      cloud: red hat
policies:
- name: policy-app-config
  manifests:
    - path: input/configmap.yaml
`

	p := Plugin{}

	err := p.Config([]byte(config), "")
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policyDefaults must provide only one of " +
		"placement.labelSelector or placement.clusterSelectors"
	assertEqual(t, err.Error(), expected)
}

func TestConfigMultiplePolicyPlacementLabels(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	config := fmt.Sprintf(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
policies:
- name: policy-app-config
  placement:
    clusterSelectors:
      cloud: red hat
    labelSelector:
      cloud: red hat
  manifests:
    - path: %s
`,
		path.Join(tmpDir, "configmap.yaml"),
	)

	p := Plugin{}

	err := p.Config([]byte(config), tmpDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policy policy-app-config must provide only one of " +
		"placement.labelSelector or placement.clusterSelectors"
	assertEqual(t, err.Error(), expected)
}

func TestConfigMultipleDefaultPlacementPaths(t *testing.T) {
	t.Parallel()
	const config = `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
  placement:
    placementPath: path/to/pl.yaml
    placementRulePath: path/to/plr.yaml
policies:
- name: policy-app-config
  placement:
    clusterSelectors:
      cloud: red hat
    placementRulePath: path/to/plr.yaml
  manifests:
    - path: input/configmap.yaml
`

	p := Plugin{}

	err := p.Config([]byte(config), "")
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policyDefaults must provide only one of " +
		"placement.placementPath or placement.placementRulePath"
	assertEqual(t, err.Error(), expected)
}

func TestConfigMultipleDefaultPlacementName(t *testing.T) {
	t.Parallel()
	const config = `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
  placement:
    placementName: plExistingName
    placementRuleName: plrExistingName
policies:
- name: policy-app-config
  placement:
    clusterSelectors:
      cloud: red hat
    placementRuleName: plrExistingName
  manifests:
    - path: input/configmap.yaml
`

	p := Plugin{}

	err := p.Config([]byte(config), "")
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policyDefaults must provide only one of " +
		"placement.placementName or placement.placementRuleName"
	assertEqual(t, err.Error(), expected)
}

func TestConfigMultipleDefaultAndPolicyPlacements(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	plFileName := "plr.yaml"
	cmFileName := "configmap.yaml"

	createConfigMap(t, tmpDir, cmFileName)

	err := os.WriteFile(path.Join(tmpDir, plFileName), []byte{}, 0o666)
	if err != nil {
		t.Fatalf("Failed to write %s", plFileName)
	}

	config := fmt.Sprintf(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
  placement:
    placementPath: %s
policies:
- name: policy-app-config
  placement:
    clusterSelectors:
      cloud: red hat
  manifests:
  - path: %s
`,
		path.Join(tmpDir, plFileName),
		path.Join(tmpDir, cmFileName),
	)
	p := Plugin{}

	err = p.Config([]byte(config), tmpDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policy policy-app-config must specify only one of " +
		"placement selector, placement path, or placement name"
	assertEqual(t, err.Error(), expected)
}

func TestConfigMultipleDefaultAndPolicyPlacementNames(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	config := fmt.Sprintf(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
  placement:
    placementName: plexistingname
policies:
- name: policy-app-config
  placement:
    clusterSelectors:
      cloud: red hat
  manifests:
  - path: %s
`,
		path.Join(tmpDir, "configmap.yaml"),
	)

	p := Plugin{}

	err := p.Config([]byte(config), tmpDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policy policy-app-config must specify only one of " +
		"placement selector, placement path, or placement name"
	assertEqual(t, err.Error(), expected)
}

func TestConfigPlacementInvalidMixture(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	config := fmt.Sprintf(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
policies:
- name: policy-app-config-1
  placement:
    clusterSelectors:
      cloud: red hat
  manifests:
    - path: %s
- name: policy-app-config-2
  placement:
    labelSelector:
      cloud: red hat
  manifests:
    - path: %s
`,
		path.Join(tmpDir, "configmap.yaml"), path.Join(tmpDir, "configmap.yaml"),
	)
	p := Plugin{}

	err := p.Config([]byte(config), tmpDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "may not use a mix of Placement and PlacementRule for " +
		"policies and policysets; found 1 Placement and 1 PlacementRule"
	assertEqual(t, err.Error(), expected)
}

func TestConfigPlacementPathNotFound(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	config := fmt.Sprintf(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
policies:
- name: policy-app-config
  placement:
    placementPath: path/to/pl.yaml
  manifests:
    - path: %s
`,
		path.Join(tmpDir, "configmap.yaml"),
	)
	p := Plugin{}

	err := p.Config([]byte(config), tmpDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policy policy-app-config placement.placementPath could not read the path path/to/pl.yaml"
	assertEqual(t, err.Error(), expected)
}

func TestConfigDuplicateNames(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	createConfigMap(t, tmpDir, "configmap2.yaml")
	config := fmt.Sprintf(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
placementBindingDefaults:
  name: my-pb
policyDefaults:
  namespace: my-policies
policies:
- name: policy-app-config
  manifests:
    - path: %s
- name: policy-app-config
  manifests:
    - path: %s
`,
		path.Join(tmpDir, "configmap.yaml"),
		path.Join(tmpDir, "configmap2.yaml"),
	)
	p := Plugin{}

	err := p.Config([]byte(config), tmpDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "each policy must have a unique name set, " +
		"but found a duplicate name: policy-app-config"
	assertEqual(t, err.Error(), expected)
}

func TestConfigInvalidEvalInterval(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	tests := []struct {
		// Individual values can't be used for compliant/noncompliant since an empty string means
		// to not inherit from the policy defaults.
		defaultEvalInterval  string
		policyEvalInterval   string
		manifestEvalInterval string
		expectedMsg          string
	}{
		{
			`{"compliant": "not a duration"}`,
			"",
			"",
			`the policy policy-app has an invalid policy.evaluationInterval.compliant value: time: invalid duration ` +
				`"not a duration"`,
		},
		{
			`{"noncompliant": "not a duration"}`,
			"",
			"",
			`the policy policy-app has an invalid policy.evaluationInterval.noncompliant value: time: invalid ` +
				`duration "not a duration"`,
		},
		{
			"",
			`{"compliant": "not a duration"}`,
			"",
			`the policy policy-app has an invalid policy.evaluationInterval.compliant value: time: invalid duration ` +
				`"not a duration"`,
		},
		{
			"",
			`{"noncompliant": "not a duration"}`,
			"",
			`the policy policy-app has an invalid policy.evaluationInterval.noncompliant value: time: invalid ` +
				`duration "not a duration"`,
		},
		{
			"",
			"",
			`{"compliant": "not a duration"}`,
			`the policy policy-app has the evaluationInterval value set on manifest[0] but consolidateManifests is ` +
				`true`,
		},
		{
			"",
			"",
			`{"noncompliant": "not a duration"}`,
			`the policy policy-app has the evaluationInterval value set on manifest[0] but consolidateManifests is ` +
				`true`,
		},
		{
			"",
			`{"compliant": "10d5h1m"}`,
			"",
			`the policy policy-app has an invalid policy.evaluationInterval.compliant value: time: unknown unit "d" ` +
				`in duration "10d5h1m"`,
		},
		{
			"",
			`{"noncompliant": "1w2d"}`,
			"",
			`the policy policy-app has an invalid policy.evaluationInterval.noncompliant value: time: unknown unit ` +
				`"w" in duration "1w2d"`,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(
			fmt.Sprintf("expected=%s", test.expectedMsg),
			func(t *testing.T) {
				t.Parallel()
				config := fmt.Sprintf(`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
  evaluationInterval: %s
policies:
- name: policy-app
  evaluationInterval: %s
  manifests:
    - path: %s
      evaluationInterval: %s
`,
					test.defaultEvalInterval,
					test.policyEvalInterval,
					path.Join(tmpDir, "configmap.yaml"),
					test.manifestEvalInterval,
				)

				p := Plugin{}
				err := p.Config([]byte(config), tmpDir)
				if err == nil {
					t.Fatal("Expected an error but did not get one")
				}

				assertEqual(t, err.Error(), test.expectedMsg)
			},
		)
	}
}

func TestConfigInvalidManifestKey(t *testing.T) {
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
		expectedMsg string
	}{
		"pruneObjectBehavior specified in manifest": {
			"pruneObjectBehavior",
			"",
			"",
			"None",
			`the policy policy-app has the pruneObjectBehavior value set` +
				` on manifest[0] but consolidateManifests is true`,
		},
		"namespaceSelector specified in manifest": {
			"namespaceSelector",
			"",
			"",
			`{"include": ["test"]}`,
			`the policy policy-app has the namespaceSelector value set` +
				` on manifest[0] but consolidateManifests is true`,
		},
		"remediationAction specified in manifest": {
			"remediationAction",
			"",
			"",
			"enforce",
			`the policy policy-app has the remediationAction value set` +
				` on manifest[0] but consolidateManifests is true`,
		},
		"severity specified in manifest": {
			"severity",
			"",
			"",
			"critical",
			`the policy policy-app has the severity value set` +
				` on manifest[0] but consolidateManifests is true`,
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
				if err == nil {
					t.Fatal("Expected an error but did not get one")
				}

				assertEqual(t, err.Error(), test.expectedMsg)
			},
		)
	}
}

func TestConfigNoManifests(t *testing.T) {
	t.Parallel()
	const config = `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
policies:
- name: policy-app-config
`

	p := Plugin{}

	err := p.Config([]byte(config), "")
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "each policy must have at least one manifest, " +
		"but found none in policy policy-app-config"
	assertEqual(t, err.Error(), expected)
}

func TestConfigManifestNotFound(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	manifestPath := path.Join(tmpDir, "configmap.yaml")
	config := fmt.Sprintf(
		`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
policies:
- name: policy-app-config
  manifests:
    - path: %s
`,
		manifestPath,
	)
	p := Plugin{}

	err := p.Config([]byte(config), tmpDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf(
		"could not read the manifest path %s in policy policy-app-config", manifestPath,
	)
	assertEqual(t, err.Error(), expected)
}

func TestConfigNoPolicyName(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	config := fmt.Sprintf(
		`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
policies:
- manifests:
    - path: %s
`,
		path.Join(tmpDir, "configmap.yaml"),
	)
	p := Plugin{}

	err := p.Config([]byte(config), tmpDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "each policy must have a name set, but did not find a name at policy array index 0"
	assertEqual(t, err.Error(), expected)
}

func TestConfigPlrNotFound(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	plrPath := path.Join(tmpDir, "plr.yaml")
	config := fmt.Sprintf(
		`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
  placement:
    placementRulePath: %s
policies:
- name: policy-app-config
  manifests:
    - path: %s
`,
		plrPath,
		path.Join(tmpDir, "configmap.yaml"),
	)
	p := Plugin{}

	err := p.Config([]byte(config), tmpDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf("policyDefaults placement.placementRulePath could not read the path %s", plrPath)
	assertEqual(t, err.Error(), expected)
}

func TestPolicySetConfig(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	testCases := []testCase{
		{
			name: "policySet must have a name set",
			setupFunc: func(p *Plugin) {
				p.PolicySets = []types.PolicySetConfig{
					{
						PolicySetOptions: types.PolicySetOptions{
							Placement: types.PlacementConfig{
								Name:             "policyset-placement",
								ClusterSelectors: map[string]interface{}{"my": "app"},
							},
						},
					},
				}
			},
			expectedErrMsg: "each policySet must have a name set, but did not find a name at policySet array index 0",
		},
		{
			name: "policySet must be unique",
			setupFunc: func(p *Plugin) {
				p.PolicySets = []types.PolicySetConfig{
					{
						Name: "my-policyset",
					},
					{
						Name: "my-policyset",
					},
				}
			},
			expectedErrMsg: "each policySet must have a unique name set, but found a duplicate name: my-policyset",
		},
		{
			name: "policySet must provide only one of placementRulePath or placementPath",
			setupFunc: func(p *Plugin) {
				p.PolicySets = []types.PolicySetConfig{
					{
						Name: "my-policyset",
						PolicySetOptions: types.PolicySetOptions{
							Placement: types.PlacementConfig{
								PlacementPath:     "../config/plc.yaml",
								PlacementRulePath: "../config/plr.yaml",
							},
						},
					},
				}
			},
			expectedErrMsg: "policySet my-policyset must provide only one of " +
				"placement.placementPath or placement.placementRulePath",
		},
		{
			name: "policySet must provide only one of placementRuleName or placementName",
			setupFunc: func(p *Plugin) {
				p.PolicySets = []types.PolicySetConfig{
					{
						Name: "my-policyset",
						PolicySetOptions: types.PolicySetOptions{
							Placement: types.PlacementConfig{
								PlacementName:     "plExistingName",
								PlacementRuleName: "plrExistingName",
							},
						},
					},
				}
			},
			expectedErrMsg: "policySet my-policyset must provide only one of " +
				"placement.placementName or placement.placementRuleName",
		},
		{
			name: "policySet must provide only one of labelSelector or clusterSelectors",
			setupFunc: func(p *Plugin) {
				p.PolicySets = []types.PolicySetConfig{
					{
						Name: "my-policyset",
						PolicySetOptions: types.PolicySetOptions{
							Placement: types.PlacementConfig{
								LabelSelector:    map[string]interface{}{"cloud": "red hat"},
								ClusterSelectors: map[string]interface{}{"cloud": "red hat"},
							},
						},
					},
				}
			},
			expectedErrMsg: "policySet my-policyset must provide only one of placement.labelSelector or " +
				"placement.clusterSelectors",
		},
		{
			name: "policySet may not specify a cluster selector and placement path together",
			setupFunc: func(p *Plugin) {
				p.PolicySets = []types.PolicySetConfig{
					{
						Name: "my-policyset",
						PolicySetOptions: types.PolicySetOptions{
							Placement: types.PlacementConfig{
								PlacementPath:    "../config/plc.yaml",
								ClusterSelectors: map[string]interface{}{"cloud": "red hat"},
							},
						},
					},
				}
			},
			expectedErrMsg: "policySet my-policyset must specify only one of placement selector, placement path, or " +
				"placement name",
		},
		{
			name: "policySet may not specify a cluster selector and placement name together",
			setupFunc: func(p *Plugin) {
				p.PolicySets = []types.PolicySetConfig{
					{
						Name: "my-policyset",
						PolicySetOptions: types.PolicySetOptions{
							Placement: types.PlacementConfig{
								PlacementName:    "plexistingname",
								ClusterSelectors: map[string]interface{}{"cloud": "red hat"},
							},
						},
					},
				}
			},
			expectedErrMsg: "policySet my-policyset must specify only one of placement selector, placement path, or " +
				"placement name",
		},
		{
			name: "policySet may not specify a label selector and placement path together",
			setupFunc: func(p *Plugin) {
				p.PolicySets = []types.PolicySetConfig{
					{
						Name: "my-policyset",
						PolicySetOptions: types.PolicySetOptions{
							Placement: types.PlacementConfig{
								PlacementPath: "../config/plc.yaml",
								LabelSelector: map[string]interface{}{"cloud": "red hat"},
							},
						},
					},
				}
			},
			expectedErrMsg: "policySet my-policyset must specify only one of placement selector, placement path, or " +
				"placement name",
		},
		{
			name: "policySet may not specify a label selector and placement name together",
			setupFunc: func(p *Plugin) {
				p.PolicySets = []types.PolicySetConfig{
					{
						Name: "my-policyset",
						PolicySetOptions: types.PolicySetOptions{
							Placement: types.PlacementConfig{
								PlacementName: "plexistingname",
								LabelSelector: map[string]interface{}{"cloud": "red hat"},
							},
						},
					},
				}
			},
			expectedErrMsg: "policySet my-policyset must specify only one of placement selector, placement path, or " +
				"placement name",
		},
		{
			name: "policySet may not specify a cluster selector and placementrule path together",
			setupFunc: func(p *Plugin) {
				p.PolicySets = []types.PolicySetConfig{
					{
						Name: "my-policyset",
						PolicySetOptions: types.PolicySetOptions{
							Placement: types.PlacementConfig{
								PlacementRulePath: "../config/plc.yaml",
								ClusterSelectors:  map[string]interface{}{"cloud": "red hat"},
							},
						},
					},
				}
			},
			expectedErrMsg: "policySet my-policyset must specify only one of placement selector, placement path, or " +
				"placement name",
		},
		{
			name: "policySet may not specify a cluster selector and placementrule name together",
			setupFunc: func(p *Plugin) {
				p.PolicySets = []types.PolicySetConfig{
					{
						Name: "my-policyset",
						PolicySetOptions: types.PolicySetOptions{
							Placement: types.PlacementConfig{
								PlacementRuleName: "plrexistingname",
								ClusterSelectors:  map[string]interface{}{"cloud": "red hat"},
							},
						},
					},
				}
			},
			expectedErrMsg: "policySet my-policyset must specify only one of placement selector, placement path, or " +
				"placement name",
		},
		{
			name: "policySet may not specify a label selector and placementrule path together",
			setupFunc: func(p *Plugin) {
				p.PolicySets = []types.PolicySetConfig{
					{
						Name: "my-policyset",
						PolicySetOptions: types.PolicySetOptions{
							Placement: types.PlacementConfig{
								PlacementRulePath: "../config/plc.yaml",
								LabelSelector:     map[string]interface{}{"cloud": "red hat"},
							},
						},
					},
				}
			},
			expectedErrMsg: "policySet my-policyset must specify only one of placement selector, placement path, or " +
				"placement name",
		},
		{
			name: "policySet may not specify a label selector and placementrule name together",
			setupFunc: func(p *Plugin) {
				p.PolicySets = []types.PolicySetConfig{
					{
						Name: "my-policyset",
						PolicySetOptions: types.PolicySetOptions{
							Placement: types.PlacementConfig{
								PlacementRuleName: "plrexistingname",
								LabelSelector:     map[string]interface{}{"cloud": "red hat"},
							},
						},
					},
				}
			},
			expectedErrMsg: "policySet my-policyset must specify only one of placement selector, placement path, or " +
				"placement name",
		},
		{
			name: "policySet placementrule path not resolvable",
			setupFunc: func(p *Plugin) {
				p.PolicySets = []types.PolicySetConfig{
					{
						Name: "my-policyset",
						PolicySetOptions: types.PolicySetOptions{
							Placement: types.PlacementConfig{
								PlacementRulePath: "../config/plc.yaml",
							},
						},
					},
				}
			},
			expectedErrMsg: "policySet my-policyset placement.placementRulePath " +
				"could not read the path ../config/plc.yaml",
		},
		{
			name: "policySet placement path not resolvable",
			setupFunc: func(p *Plugin) {
				p.PolicySets = []types.PolicySetConfig{
					{
						Name: "my-policyset",
						PolicySetOptions: types.PolicySetOptions{
							Placement: types.PlacementConfig{
								PlacementPath: "../config/plc.yaml",
							},
						},
					},
				}
			},
			expectedErrMsg: "policySet my-policyset placement.placementPath could not read the path ../config/plc.yaml",
		},
		{
			name: "Placement and PlacementRule can't be mixed",
			setupFunc: func(p *Plugin) {
				p.Policies[0].Placement = types.PlacementConfig{
					LabelSelector: map[string]interface{}{"cloud": "red hat"},
				}
				p.PolicySets = []types.PolicySetConfig{
					{
						Name: "my-policyset",
						PolicySetOptions: types.PolicySetOptions{
							Placement: types.PlacementConfig{
								ClusterSelectors: map[string]interface{}{"cloud": "red hat"},
							},
						},
					},
				}
			},
			expectedErrMsg: "may not use a mix of Placement and PlacementRule for policies and policysets; found 1 " +
				"Placement and 1 PlacementRule",
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
			policyConf1 := types.PolicyConfig{
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
					{
						Path: path.Join(tmpDir, "configmap.yaml"),
					},
				},
			}
			p.Policies = append(p.Policies, policyConf1, policyConf2)
			tc.setupFunc(&p)
			p.applyDefaults(map[string]interface{}{})
			err = p.assertValidConfig()
			if err == nil {
				t.Fatal("Expected an error but did not get one")
			}
			assertEqual(t, err.Error(), tc.expectedErrMsg)
		})
	}
}

func TestDisabled(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	configMapPath := path.Join(tmpDir, "configmap.yaml")
	defaultsConfig := fmt.Sprintf(
		`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: my-policies
  disabled: true
policies:
- name: policy-app-config
  disabled: false
  manifests:
    - path: %s
  namespaceSelector:
    include:
      - app-ns
  remediationAction: inform
- name: policy-app-config2
  manifests:
    - path: %s
`,
		configMapPath,
		configMapPath,
	)
	p := Plugin{}

	err := p.Config([]byte(defaultsConfig), tmpDir)
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, p.PolicyDefaults.Disabled, true)

	enabledPolicy := p.Policies[0]
	assertEqual(t, enabledPolicy.Disabled, false)

	disabledPolicy := p.Policies[1]
	assertEqual(t, disabledPolicy.Disabled, true)
}

func TestConflictingPlacementSelectors(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	configMapPath := path.Join(tmpDir, "configmap.yaml")
	policyNS := "my-policies"
	policyName := "policy-app"
	defaultsConfig := fmt.Sprintf(
		`
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: policy-generator-name
policyDefaults:
  namespace: %s
  placement:
    labelSelector:
      matchExpressions:
      - key: cloud
        operator: In
        values:
          - red hat
          - hello
      cloud: red hat
      clusterID: 1234-5678
policies:
- name: %s
  manifests:
    - path: %s
`,
		policyNS, policyName, configMapPath,
	)

	p := Plugin{}

	err := p.Config([]byte(defaultsConfig), tmpDir)
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policyDefaults placement has invalid selectors: " +
		"the input is not a valid label selector or key-value label matching map"
	assertEqual(t, err.Error(), expected)
}
