// Copyright Contributors to the Open Cluster Management project
package internal

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	configPolicyKind           = "ConfigurationPolicy"
	policyAPIVersion           = "policy.open-cluster-management.io/v1"
	policyKind                 = "Policy"
	placementBindingAPIVersion = "policy.open-cluster-management.io/v1"
	placementBindingKind       = "PlacementBinding"
	placementRuleAPIVersion    = "apps.open-cluster-management.io/v1"
	placementRuleKind          = "PlacementRule"
)

type manifest struct {
	Path string `json:"path,omitempty" yaml:"path,omitempty"`
}

type namespaceSelector struct {
	Exclude []string `json:"exclude,omitempty" yaml:"exclude,omitempty"`
	Include []string `json:"include,omitempty" yaml:"include,omitempty"`
}

// policyConfig represents a policy entry in the PolicyGenerator configuration.
type policyConfig struct {
	Categories     []string `json:"categories,omitempty" yaml:"categories,omitempty"`
	ComplianceType string   `json:"complianceType,omitempty" yaml:"complianceType,omitempty"`
	Controls       []string `json:"controls,omitempty" yaml:"controls,omitempty"`
	Disabled       bool     `json:"disabled,omitempty" yaml:"disabled,omitempty"`
	// Make this a slice of structs in the event we want additional configuration related to
	// a manifest such as accepting patches.
	Manifests         []manifest        `json:"manifests,omitempty" yaml:"manifests,omitempty"`
	Name              string            `json:"name,omitempty" yaml:"name,omitempty"`
	NamespaceSelector namespaceSelector `json:"namespaceSelector,omitempty" yaml:"namespaceSelector,omitempty"`
	// This is named Placement so that eventually PlacementRules and Placements will be supported
	Placement struct {
		ClusterSelectors  map[string]string `json:"clusterSelectors,omitempty" yaml:"clusterSelectors,omitempty"`
		PlacementRulePath string            `json:"placementRulePath,omitempty" yaml:"placementRulePath,omitempty"`
	} `json:"placement,omitempty" yaml:"placement,omitempty"`
	RemediationAction string   `json:"remediationAction,omitempty" yaml:"remediationAction,omitempty"`
	Severity          string   `json:"severity,omitempty" yaml:"severity,omitempty"`
	Standards         []string `json:"standards,omitempty" yaml:"standards,omitempty"`
}

type policyDefaults struct {
	Categories        []string          `json:"categories,omitempty" yaml:"categories,omitempty"`
	ComplianceType    string            `json:"complianceType,omitempty" yaml:"complianceType,omitempty"`
	Controls          []string          `json:"controls,omitempty" yaml:"controls,omitempty"`
	Namespace         string            `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	NamespaceSelector namespaceSelector `json:"namespaceSelector,omitempty" yaml:"namespaceSelector,omitempty"`
	// This is named Placement so that eventually PlacementRules and Placements will be supported
	Placement struct {
		ClusterSelectors  map[string]string `json:"clusterSelectors,omitempty" yaml:"clusterSelectors,omitempty"`
		PlacementRulePath string            `json:"placementRulePath,omitempty" yaml:"placementRulePath,omitempty"`
	} `json:"placement,omitempty" yaml:"placement,omitempty"`
	RemediationAction string   `json:"remediationAction,omitempty" yaml:"remediationAction,omitempty"`
	Severity          string   `json:"severity,omitempty" yaml:"severity,omitempty"`
	Standards         []string `json:"standards,omitempty" yaml:"standards,omitempty"`
}

// Plugin is used to store the PolicyGenerator configuration and the methods to generate the
// desired policies.
type Plugin struct {
	Metadata struct {
		Name string `json:"name,omitempty" yaml:"name,omitempty"`
	} `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	PlacementBindingDefaults struct {
		Name string `json:"name,omitempty" yaml:"name,omitempty"`
	} `json:"placementBindingDefaults,omitempty" yaml:"placementBindingDefaults,omitempty"`
	PolicyDefaults policyDefaults `json:"policyDefaults,omitempty" yaml:"policyDefaults,omitempty"`
	Policies       []policyConfig `json:"policies" yaml:"policies"`
	outputBuffer   bytes.Buffer
}

var defaults = policyDefaults{
	Categories:        []string{"CM Configuration Management"},
	ComplianceType:    "musthave",
	Controls:          []string{"CM-2 Baseline Configuration"},
	RemediationAction: "inform",
	Severity:          "low",
	Standards:         []string{"NIST SP 800-53"},
}

// Config validates the input PolicyGenerator configuration, applies any missing defaults, and
// configures the Policy object.
func (p *Plugin) Config(config []byte) error {
	err := yaml.Unmarshal(config, p)
	if err != nil {
		return fmt.Errorf("the PolicyGenerator configuration file is invalid: %w", err)
	}
	p.applyDefaults()

	return p.assertValidConfig()
}

// Generate generates the policies, placement rules, and placement bindings and returns them as
// a single YAML file as a byte array. An error is returned if they cannot be created.
func (p *Plugin) Generate() ([]byte, error) {
	for i := range p.Policies {
		err := p.createPolicy(&p.Policies[i])
		if err != nil {
			return nil, err
		}
	}

	// Keep track of which placement rule maps to which policy. This will be used to determine
	// how many placement bindings are required since one per placement rule is required.
	plrNameToPolicyIdxs := map[string][]int{}
	// seen keeps track of which placement rules have been seen by name. This is so that if the
	// same placementRulePath is provided for multiple policies, it's not reincluded in the
	// generated output of the plugin.
	seen := map[string]bool{}
	for i := range p.Policies {
		plrName, err := p.createPlacementRule(&p.Policies[i], seen)
		if err != nil {
			return nil, err
		}
		plrNameToPolicyIdxs[plrName] = append(plrNameToPolicyIdxs[plrName], i)
		seen[plrName] = true
	}

	plcBindingCount := 0
	for plrName, policyIdxs := range plrNameToPolicyIdxs {
		plcBindingCount++
		// Determine which policies to be included in the placement binding.
		policyConfs := []*policyConfig{}
		for i := range policyIdxs {
			policyConfs = append(policyConfs, &p.Policies[i])
		}

		// If there are multiple policies, still use the default placement binding name
		// but append a number to it so it's a unique name.
		var bindingName string
		if plcBindingCount == 1 {
			bindingName = p.PlacementBindingDefaults.Name
		} else {
			bindingName = fmt.Sprintf("%s%d", p.PlacementBindingDefaults.Name, plcBindingCount)
		}

		err := p.createPlacementBinding(bindingName, plrName, policyConfs)
		if err != nil {
			return nil, fmt.Errorf("failed to create a placement binding: %w", err)
		}
	}

	return p.outputBuffer.Bytes(), nil
}

// applyDefaults applies any missing defaults under Policy.PlacementBindingDefaults and
// Policy.PolicyDefaults. It then applies the defaults and user provided defaults on each
// policy entry if they are not overridden by the user.
func (p *Plugin) applyDefaults() {
	if len(p.Policies) == 0 {
		return
	}

	// Set defaults to the defaults that aren't overridden
	if p.PlacementBindingDefaults.Name == "" && len(p.Policies) == 1 {
		p.PlacementBindingDefaults.Name = "binding-" + p.Policies[0].Name
	}

	if p.PolicyDefaults.Categories == nil {
		p.PolicyDefaults.Categories = defaults.Categories
	}

	if p.PolicyDefaults.ComplianceType == "" {
		p.PolicyDefaults.ComplianceType = defaults.ComplianceType
	}

	if p.PolicyDefaults.Controls == nil {
		p.PolicyDefaults.Controls = defaults.Controls
	}

	if p.PolicyDefaults.RemediationAction == "" {
		p.PolicyDefaults.RemediationAction = defaults.RemediationAction
	}

	if p.PolicyDefaults.Severity == "" {
		p.PolicyDefaults.Severity = defaults.Severity
	}

	if p.PolicyDefaults.Standards == nil {
		p.PolicyDefaults.Standards = defaults.Standards
	}

	for i := range p.Policies {
		policy := &p.Policies[i]
		if policy.Categories == nil {
			policy.Categories = p.PolicyDefaults.Categories
		}

		if policy.ComplianceType == "" {
			policy.ComplianceType = p.PolicyDefaults.ComplianceType
		}

		if policy.Controls == nil {
			policy.Controls = p.PolicyDefaults.Controls
		}

		// If both cluster selectors and placement rule path aren't set, then use the
		// defaults with a priority on placement rule path.
		if len(policy.Placement.ClusterSelectors) == 0 && policy.Placement.PlacementRulePath == "" {
			if p.PolicyDefaults.Placement.PlacementRulePath != "" {
				policy.Placement.PlacementRulePath = p.PolicyDefaults.Placement.PlacementRulePath
			} else if len(p.PolicyDefaults.Placement.ClusterSelectors) > 0 {
				policy.Placement.ClusterSelectors = p.PolicyDefaults.Placement.ClusterSelectors
			}
		}

		// Only use defaults when when both include and exclude are not set on the policy
		nsSelector := policy.NamespaceSelector
		defNsSelector := p.PolicyDefaults.NamespaceSelector
		if nsSelector.Exclude == nil && nsSelector.Include == nil {
			policy.NamespaceSelector = defNsSelector
		}

		if policy.RemediationAction == "" {
			policy.RemediationAction = p.PolicyDefaults.RemediationAction
		}

		if policy.Severity == "" {
			policy.Severity = p.PolicyDefaults.Severity
		}

		if policy.Standards == nil {
			policy.Standards = p.PolicyDefaults.Standards
		}
	}
}

// assertValidConfig verifies that the user provided configuration has all the
// required fields. Note that this should be run only after applyDefaults is run.
func (p *Plugin) assertValidConfig() error {
	if p.PlacementBindingDefaults.Name == "" && len(p.Policies) > 1 {
		return errors.New(
			"placementBindingDefaults.name must be set when there are mutiple policies",
		)
	}

	if p.PolicyDefaults.Namespace == "" {
		return errors.New("policyDefaults.namespace is empty but it must be set")
	}

	if len(p.Policies) == 0 {
		return errors.New("policies is empty but it must be set")
	}

	seen := map[string]bool{}
	for i := range p.Policies {
		policy := &p.Policies[i]
		if len(policy.Placement.ClusterSelectors) != 0 && policy.Placement.PlacementRulePath != "" {
			return errors.New(
				"a policy may not specify placement.clusterSelectors and " +
					"placement.placementRulePath together",
			)
		}

		if len(policy.Manifests) == 0 {
			return errors.New("each policy must have at least one manifest")
		}

		for _, manifest := range policy.Manifests {
			if manifest.Path == "" {
				return errors.New("each policy manifest entry must have path set")
			}

			_, err := os.Stat(manifest.Path)
			if err != nil {
				return fmt.Errorf("could not read the manifest path %s", manifest.Path)
			}
		}

		if policy.Name == "" {
			return errors.New("each policy must have a name set")
		}

		if seen[policy.Name] {
			return fmt.Errorf("each policy must have a unique name set: %s", policy.Name)
		}

		if policy.Placement.PlacementRulePath != "" {
			_, err := os.Stat(policy.Placement.PlacementRulePath)
			if err != nil {
				return fmt.Errorf(
					"could not read the placement rule path %s",
					policy.Placement.PlacementRulePath,
				)
			}
		}

		seen[policy.Name] = true
	}

	return nil
}

// createPolicy will generate the root policy based on the PolicyGenerator configuration.
// The generated policy is written to the plugin's output buffer. An error is returned if the
// manifests specified in the configuration are invalid or can't be read.
func (p *Plugin) createPolicy(policyConf *policyConfig) error {
	policyTemplate, err := getPolicyTemplate(policyConf)
	if err != nil {
		return err
	}

	policy := map[string]interface{}{
		"apiVersion": policyAPIVersion,
		"kind":       policyKind,
		"metadata": map[string]interface{}{
			"annotations": map[string]string{
				"policy.open-cluster-management.io/categories": strings.Join(policyConf.Categories, ","),
				"policy.open-cluster-management.io/controls":   strings.Join(policyConf.Controls, ","),
				"policy.open-cluster-management.io/standards":  strings.Join(policyConf.Standards, ","),
			},
			"name":      policyConf.Name,
			"namespace": p.PolicyDefaults.Namespace,
		},
		"spec": map[string]interface{}{
			"disabled":          policyConf.Disabled,
			"policy-templates":  []map[string]map[string]interface{}{*policyTemplate},
			"remediationAction": policyConf.RemediationAction,
		},
	}

	policyYAML, err := yaml.Marshal(policy)
	if err != nil {
		return fmt.Errorf(
			"an unexpected error occurred when converting the policy to YAML: %w", err,
		)
	}

	p.outputBuffer.Write([]byte("---\n"))
	p.outputBuffer.Write(policyYAML)

	return nil
}

// getPlrFromPath finds the placement rule manifest in the input manifest file. It will return
// the name of the placement rule, the unmarshaled placement rule manifest, and an error. An error
// is returned if the placement rule manifest cannot be found or is invalid.
func (p *Plugin) getPlrFromPath(plrPath string) (string, map[string]interface{}, error) {
	manifests, err := unmarshalManifestFile(plrPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read the placement rule: %w", err)
	}

	var name string
	var rule map[string]interface{}
	for _, manifest := range *manifests {
		if kind, _, _ := unstructured.NestedString(manifest, "kind"); kind != placementRuleKind {
			continue
		}

		var found bool
		name, found, err = unstructured.NestedString(manifest, "metadata", "name")
		if !found || err != nil {
			return "", nil, fmt.Errorf("the placement %s must have a name set", plrPath)
		}

		var namespace string
		namespace, found, err = unstructured.NestedString(manifest, "metadata", "namespace")
		if !found || err != nil {
			return "", nil, fmt.Errorf("the placement %s must have a namespace set", plrPath)
		}

		if namespace != p.PolicyDefaults.Namespace {
			err = fmt.Errorf(
				"the placement %s must have the same namespace as the policy (%s)",
				plrPath,
				p.PolicyDefaults.Namespace,
			)

			return "", nil, err
		}

		rule = manifest

		break
	}

	if name == "" {
		err = fmt.Errorf(
			"the placement manifest %s did not have a placement rule", plrPath,
		)

		return "", nil, err
	}

	return name, rule, nil
}

// createPlacementRule creates a placement rule for the input policy configuration by writing it to
// the policy generator's output buffer. The name of the placement rule or an error is returned.
// If the placement rule name is in the skip map and is set to true, it will not be added to the
// policy generator's output buffer. An error is returned if the placement rule cannot be created.
func (p *Plugin) createPlacementRule(policyConf *policyConfig, skip map[string]bool) (
	name string, err error,
) {
	plrPath := policyConf.Placement.PlacementRulePath
	var rule map[string]interface{}
	// If a path to a placement rule is provided, find the placement rule and reuse it.
	if plrPath != "" {
		name, rule, err = p.getPlrFromPath(plrPath)
		if err != nil {
			return
		}

		if skip[name] {
			return
		}
	} else {
		// Sort the keys so that the match expressions can be ordered based on the label name
		keys := make([]string, 0, len(policyConf.Placement.ClusterSelectors))
		for key := range policyConf.Placement.ClusterSelectors {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		matchExpressions := []map[string]interface{}{}
		for _, label := range keys {
			matchExpression := map[string]interface{}{
				"key":      label,
				"operator": "In",
				"values":   []string{policyConf.Placement.ClusterSelectors[label]},
			}
			matchExpressions = append(matchExpressions, matchExpression)
		}

		name = "placement-" + policyConf.Name
		rule = map[string]interface{}{
			"apiVersion": placementRuleAPIVersion,
			"kind":       placementRuleKind,
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": p.PolicyDefaults.Namespace,
			},
			"spec": map[string]interface{}{
				"clusterConditions": []map[string]string{
					{"status": "True", "type": "ManagedClusterConditionAvailable"},
				},
				"clusterSelector": map[string]interface{}{
					"matchExpressions": matchExpressions,
				},
			},
		}
	}

	var ruleYAML []byte
	ruleYAML, err = yaml.Marshal(rule)
	if err != nil {
		err = fmt.Errorf(
			"an unexpected error occurred when converting the placement rule to YAML: %w", err,
		)

		return
	}

	p.outputBuffer.Write([]byte("---\n"))
	p.outputBuffer.Write(ruleYAML)

	return
}

// createPlacementBinding creates a placement binding for the input placement rule and policies by
// writing it to the policy generator's output buffer. An error is returned if the placement binding
// cannot be created.
func (p *Plugin) createPlacementBinding(
	bindingName, plrName string, policyConfs []*policyConfig,
) error {
	subjects := make([]map[string]string, 0, len(policyConfs))
	for _, policyConf := range policyConfs {
		subject := map[string]string{
			// Remove the version at the end
			"apiGroup": strings.Split(policyAPIVersion, "/")[0],
			"kind":     policyKind,
			"name":     policyConf.Name,
		}
		subjects = append(subjects, subject)
	}

	binding := map[string]interface{}{
		"apiVersion": placementBindingAPIVersion,
		"kind":       placementBindingKind,
		"metadata": map[string]interface{}{
			"name":      bindingName,
			"namespace": p.PolicyDefaults.Namespace,
		},
		"placementRef": map[string]string{
			// Remove the version at the end
			"apiGroup": strings.Split(placementRuleAPIVersion, "/")[0],
			"name":     plrName,
			"kind":     placementRuleKind,
		},
		"subjects": subjects,
	}

	bindingYAML, err := yaml.Marshal(binding)
	if err != nil {
		return fmt.Errorf(
			"an unexpected error occurred when converting the placement binding to YAML: %w", err,
		)
	}

	p.outputBuffer.Write([]byte("---\n"))
	p.outputBuffer.Write(bindingYAML)

	return nil
}
