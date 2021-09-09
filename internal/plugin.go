// Copyright Contributors to the Open Cluster Management project
package internal

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
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
