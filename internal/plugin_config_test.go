// Copyright Contributors to the Open Cluster Management project
package internal

import (
	"fmt"
	"io/ioutil"
	"path"
	"testing"

	"github.com/open-cluster-management/policy-generator-plugin/internal/types"
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
	err := ioutil.WriteFile(manifestsPath, []byte(yamlContent), 0o666)
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
  disabled: true
  manifests:
    - path: %s
  placement:
    clusterSelectors:
      cloud: weather
`,
		configMapPath,
		configMapPath2,
	)

	p := Plugin{}
	err := p.Config([]byte(exampleConfig))
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
	assertReflectEqual(
		t,
		p.PolicyDefaults.Placement.ClusterSelectors,
		map[string]string{"cloud": "red hat"},
	)
	assertEqual(t, p.PolicyDefaults.RemediationAction, "enforce")
	assertEqual(t, p.PolicyDefaults.Severity, "medium")
	assertReflectEqual(t, p.PolicyDefaults.Standards, []string{"NIST SP 800-53"})
	assertEqual(t, len(p.Policies), 2)

	policy1 := p.Policies[0]
	assertReflectEqual(t, policy1.Categories, []string{"CM Configuration Management"})
	assertEqual(t, policy1.ComplianceType, "musthave")
	assertReflectEqual(t, policy1.Controls, []string{"PR.DS-1 Data-at-rest"})
	assertEqual(t, policy1.Disabled, false)
	assertEqual(t, len(policy1.Manifests), 1)
	assertEqual(t, policy1.Manifests[0].Path, configMapPath)
	assertEqual(t, policy1.Name, "policy-app-config")
	p1ExpectedNsSelector := types.NamespaceSelector{
		Exclude: nil, Include: []string{"app-ns"},
	}
	assertReflectEqual(t, policy1.NamespaceSelector, p1ExpectedNsSelector)
	assertReflectEqual(
		t,
		policy1.Placement.ClusterSelectors,
		map[string]string{"cloud": "red hat"},
	)
	assertEqual(t, policy1.RemediationAction, "inform")
	assertEqual(t, policy1.Severity, "medium")
	assertReflectEqual(t, policy1.Standards, []string{"NIST SP 800-53"})

	policy2 := p.Policies[1]
	assertReflectEqual(t, policy2.Categories, []string{"CM Configuration Management"})
	assertEqual(t, policy2.ComplianceType, "musthave")
	assertReflectEqual(t, policy2.Controls, []string{"PR.DS-1 Data-at-rest"})
	assertEqual(t, policy2.Disabled, true)
	assertEqual(t, len(policy2.Manifests), 1)
	assertEqual(t, policy2.Manifests[0].Path, configMapPath2)
	assertEqual(t, policy2.Name, "policy-app-config2")
	assertReflectEqual(t, policy2.NamespaceSelector, expectedNsSelector)
	assertReflectEqual(
		t,
		policy2.Placement.ClusterSelectors,
		map[string]string{"cloud": "weather"},
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
	err := p.Config([]byte(defaultsConfig))
	if err != nil {
		t.Fatal(err.Error())
	}

	assertEqual(t, p.Metadata.Name, "policy-generator-name")
	assertEqual(t, p.PlacementBindingDefaults.Name, "")
	assertReflectEqual(t, p.PolicyDefaults.Categories, []string{"CM Configuration Management"})
	assertEqual(t, p.PolicyDefaults.ComplianceType, "musthave")
	assertReflectEqual(t, p.PolicyDefaults.Controls, []string{"CM-2 Baseline Configuration"})
	assertEqual(t, p.PolicyDefaults.Namespace, "my-policies")
	expectedNsSelector := types.NamespaceSelector{Exclude: nil, Include: nil}
	assertReflectEqual(t, p.PolicyDefaults.NamespaceSelector, expectedNsSelector)
	assertEqual(t, p.PolicyDefaults.Placement.PlacementRulePath, "")
	assertEqual(t, len(p.PolicyDefaults.Placement.ClusterSelectors), 0)
	assertEqual(t, p.PolicyDefaults.RemediationAction, "inform")
	assertEqual(t, p.PolicyDefaults.Severity, "low")
	assertReflectEqual(t, p.PolicyDefaults.Standards, []string{"NIST SP 800-53"})
	assertEqual(t, len(p.Policies), 1)

	policy := p.Policies[0]
	assertReflectEqual(t, policy.Categories, []string{"CM Configuration Management"})
	assertEqual(t, policy.ComplianceType, "musthave")
	assertReflectEqual(t, policy.Controls, []string{"CM-2 Baseline Configuration"})
	assertEqual(t, policy.Disabled, false)
	assertEqual(t, len(policy.Manifests), 1)
	assertEqual(t, policy.Manifests[0].Path, configMapPath)
	assertEqual(t, policy.Name, "policy-app-config")
	assertReflectEqual(t, policy.NamespaceSelector, expectedNsSelector)
	assertEqual(t, len(policy.Placement.ClusterSelectors), 0)
	assertEqual(t, policy.Placement.PlacementRulePath, "")
	assertEqual(t, policy.RemediationAction, "inform")
	assertEqual(t, policy.Severity, "low")
	assertReflectEqual(t, policy.Standards, []string{"NIST SP 800-53"})
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
	err := p.Config([]byte(config))
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policyDefaults.namespace is empty but it must be set"
	assertEqual(t, err.Error(), expected)
}

func TestCreateInvalidPolicyName(t *testing.T) {
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
	err := p.Config([]byte(defaultsConfig))
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf("the policy namespace and name cannot be more than 63 characters %s.%s", policyNS, policyName)
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
	err := p.Config([]byte(config))
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "policies is empty but it must be set"
	assertEqual(t, err.Error(), expected)
}

func TestConfigMultiplePlacements(t *testing.T) {
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
  placement:
    clusterSelectors:
      cloud: red hat
    placementRulePath: path/to/plr.yaml
  manifests:
    - path: input/configmap.yaml
`
	p := Plugin{}
	err := p.Config([]byte(config))
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "a policy may not specify placement.clusterSelectors and " +
		"placement.placementRulePath together"
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
	err := p.Config([]byte(config))
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	assertEqual(t, err.Error(), "each policy must have a unique name set: policy-app-config")
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
	err := p.Config([]byte(config))
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "each policy must have at least one manifest"
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
	err := p.Config([]byte(config))
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf("could not read the manifest path %s", manifestPath)
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
	err := p.Config([]byte(config))
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := "each policy must have a name set"
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
	err := p.Config([]byte(config))
	if err == nil {
		t.Fatal("Expected an error but did not get one")
	}

	expected := fmt.Sprintf("could not read the placement rule path %s", plrPath)
	assertEqual(t, err.Error(), expected)
}
