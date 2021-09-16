// Copyright Contributors to the Open Cluster Management project
package types

type Manifest struct {
	Patches []map[string]interface{} `json:"patches,omitempty" yaml:"patches,omitempty"`
	Path    string                   `json:"path,omitempty" yaml:"path,omitempty"`
}

type NamespaceSelector struct {
	Exclude []string `json:"exclude,omitempty" yaml:"exclude,omitempty"`
	Include []string `json:"include,omitempty" yaml:"include,omitempty"`
}

type PlacementConfig struct {
	ClusterSelectors  map[string]string `json:"clusterSelectors,omitempty" yaml:"clusterSelectors,omitempty"`
	Name              string            `json:"name,omitempty" yaml:"name,omitempty"`
	PlacementRulePath string            `json:"placementRulePath,omitempty" yaml:"placementRulePath,omitempty"`
}

// PolicyConfig represents a policy entry in the PolicyGenerator configuration.
type PolicyConfig struct {
	Categories     []string `json:"categories,omitempty" yaml:"categories,omitempty"`
	ComplianceType string   `json:"complianceType,omitempty" yaml:"complianceType,omitempty"`
	Controls       []string `json:"controls,omitempty" yaml:"controls,omitempty"`
	// Make this a slice of structs in the event we want additional configuration related to
	// a manifest such as accepting patches.
	Manifests         []Manifest        `json:"manifests,omitempty" yaml:"manifests,omitempty"`
	Name              string            `json:"name,omitempty" yaml:"name,omitempty"`
	NamespaceSelector NamespaceSelector `json:"namespaceSelector,omitempty" yaml:"namespaceSelector,omitempty"`
	// This is named Placement so that eventually PlacementRules and Placements will be supported
	Placement             PlacementConfig `json:"placement,omitempty" yaml:"placement,omitempty"`
	RemediationAction     string          `json:"remediationAction,omitempty" yaml:"remediationAction,omitempty"`
	Severity              string          `json:"severity,omitempty" yaml:"severity,omitempty"`
	Standards             []string        `json:"standards,omitempty" yaml:"standards,omitempty"`
	InformKyvernoPolicies bool            `json:"informKyvernoPolicies,omitempty" yaml:"informKyvernoPolicies,omitempty"`
	Disabled              bool            `json:"disabled,omitempty" yaml:"disabled,omitempty"`
	// NonConsolidated = false (default value) will consolidate multi manifests specified
	// in policyConf into single policy template
	NonConsolidated bool `json:"nonConsolidated,omitempty" yaml:"nonConsolidated,omitempty"`
}

type PolicyDefaults struct {
	Categories            []string          `json:"categories,omitempty" yaml:"categories,omitempty"`
	ComplianceType        string            `json:"complianceType,omitempty" yaml:"complianceType,omitempty"`
	Controls              []string          `json:"controls,omitempty" yaml:"controls,omitempty"`
	InformKyvernoPolicies bool              `json:"informKyvernoPolicies,omitempty" yaml:"informKyvernoPolicies,omitempty"`
	Namespace             string            `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	NamespaceSelector     NamespaceSelector `json:"namespaceSelector,omitempty" yaml:"namespaceSelector,omitempty"`
	// This is named Placement so that eventually PlacementRules and Placements will be supported
	Placement         PlacementConfig `json:"placement,omitempty" yaml:"placement,omitempty"`
	RemediationAction string          `json:"remediationAction,omitempty" yaml:"remediationAction,omitempty"`
	Severity          string          `json:"severity,omitempty" yaml:"severity,omitempty"`
	Standards         []string        `json:"standards,omitempty" yaml:"standards,omitempty"`
}
