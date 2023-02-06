// Copyright Contributors to the Open Cluster Management project
package types

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PolicyOptions struct {
	Categories                     []string           `json:"categories,omitempty" yaml:"categories,omitempty"`
	Controls                       []string           `json:"controls,omitempty" yaml:"controls,omitempty"`
	Dependencies                   []PolicyDependency `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
	ExtraDependencies              []PolicyDependency `json:"extraDependencies,omitempty" yaml:"extraDependencies,omitempty"`
	Placement                      PlacementConfig    `json:"placement,omitempty" yaml:"placement,omitempty"`
	Standards                      []string           `json:"standards,omitempty" yaml:"standards,omitempty"`
	ConsolidateManifests           bool               `json:"consolidateManifests,omitempty" yaml:"consolidateManifests,omitempty"`
	OrderManifests                 bool               `json:"orderManifests" yaml:"orderManifests"`
	Disabled                       bool               `json:"disabled,omitempty" yaml:"disabled,omitempty"`
	IgnorePending                  bool               `json:"ignorePending,omitempty" yaml:"ignorePending,omitempty"`
	InformGatekeeperPolicies       bool               `json:"informGatekeeperPolicies,omitempty" yaml:"informGatekeeperPolicies,omitempty"`
	InformKyvernoPolicies          bool               `json:"informKyvernoPolicies,omitempty" yaml:"informKyvernoPolicies,omitempty"`
	GeneratePolicyPlacement        bool               `json:"generatePolicyPlacement,omitempty" yaml:"generatePolicyPlacement,omitempty"`
	GeneratePlacementWhenInSet     bool               `json:"generatePlacementWhenInSet,omitempty" yaml:"generatePlacementWhenInSet,omitempty"`
	PolicySets                     []string           `json:"policySets,omitempty" yaml:"policySets,omitempty"`
	PolicyAnnotations              map[string]string  `json:"policyAnnotations,omitempty" yaml:"policyAnnotations,omitempty"`
	ConfigurationPolicyAnnotations map[string]string  `json:"configurationPolicyAnnotations,omitempty" yaml:"configurationPolicyAnnotations,omitempty"`
}

type PolicySetOptions struct {
	Placement                  PlacementConfig `json:"placement,omitempty" yaml:"placement,omitempty"`
	GeneratePolicySetPlacement bool            `json:"generatePolicySetPlacement,omitempty" yaml:"generatePolicySetPlacement,omitempty"`
}

type ConfigurationPolicyOptions struct {
	RemediationAction      string             `json:"remediationAction,omitempty" yaml:"remediationAction,omitempty"`
	Severity               string             `json:"severity,omitempty" yaml:"severity,omitempty"`
	ComplianceType         string             `json:"complianceType,omitempty" yaml:"complianceType,omitempty"`
	MetadataComplianceType string             `json:"metadataComplianceType,omitempty" yaml:"metadataComplianceType,omitempty"`
	EvaluationInterval     EvaluationInterval `json:"evaluationInterval,omitempty" yaml:"evaluationInterval,omitempty"`
	NamespaceSelector      NamespaceSelector  `json:"namespaceSelector,omitempty" yaml:"namespaceSelector,omitempty"`
	PruneObjectBehavior    string             `json:"pruneObjectBehavior,omitempty" yaml:"pruneObjectBehavior,omitempty"`
}

type Manifest struct {
	ConfigurationPolicyOptions `json:",inline" yaml:",inline"`
	Patches                    []map[string]interface{} `json:"patches,omitempty" yaml:"patches,omitempty"`
	Path                       string                   `json:"path,omitempty" yaml:"path,omitempty"`
	ExtraDependencies          []PolicyDependency       `json:"extraDependencies,omitempty" yaml:"extraDependencies,omitempty"`
	IgnorePending              bool                     `json:"ignorePending,omitempty" yaml:"ignorePending,omitempty"`
}

type NamespaceSelector struct {
	Exclude          []string                           `json:"exclude,omitempty" yaml:"exclude,omitempty"`
	Include          []string                           `json:"include,omitempty" yaml:"include,omitempty"`
	MatchLabels      *map[string]string                 `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty"`
	MatchExpressions *[]metav1.LabelSelectorRequirement `json:"matchExpressions,omitempty" yaml:"matchExpressions,omitempty"`
}

// Define String() so that the LabelSelector is dereferenced in the logs
func (t NamespaceSelector) String() string {
	fmtSelectorStr := "{include:%s,exclude:%s,matchLabels:%+v,matchExpressions:%+v}"
	if t.MatchLabels == nil && t.MatchExpressions == nil {
		return fmt.Sprintf(fmtSelectorStr, t.Include, t.Exclude, nil, nil)
	}

	if t.MatchLabels == nil {
		return fmt.Sprintf(fmtSelectorStr, t.Include, t.Exclude, nil, *t.MatchExpressions)
	}

	if t.MatchExpressions == nil {
		return fmt.Sprintf(fmtSelectorStr, t.Include, t.Exclude, *t.MatchLabels, nil)
	}

	return fmt.Sprintf(fmtSelectorStr, t.Include, t.Exclude, *t.MatchLabels, *t.MatchExpressions)
}

type PlacementConfig struct {
	ClusterSelectors  map[string]interface{} `json:"clusterSelectors,omitempty" yaml:"clusterSelectors,omitempty"`
	ClusterSelector   map[string]interface{} `json:"clusterSelector,omitempty" yaml:"clusterSelector,omitempty"`
	LabelSelector     map[string]interface{} `json:"labelSelector,omitempty" yaml:"labelSelector,omitempty"`
	Name              string                 `json:"name,omitempty" yaml:"name,omitempty"`
	PlacementPath     string                 `json:"placementPath,omitempty" yaml:"placementPath,omitempty"`
	PlacementRulePath string                 `json:"placementRulePath,omitempty" yaml:"placementRulePath,omitempty"`
	PlacementName     string                 `json:"placementName,omitempty" yaml:"placementName,omitempty"`
	PlacementRuleName string                 `json:"placementRuleName,omitempty" yaml:"placementRuleName,omitempty"`
}

type EvaluationInterval struct {
	Compliant    string `json:"compliant,omitempty" yaml:"compliant,omitempty"`
	NonCompliant string `json:"noncompliant,omitempty" yaml:"noncompliant,omitempty"`
}

// PolicyConfig represents a policy entry in the PolicyGenerator configuration.
type PolicyConfig struct {
	PolicyOptions              `json:",inline" yaml:",inline"`
	ConfigurationPolicyOptions `json:",inline" yaml:",inline"`
	Name                       string `json:"name,omitempty" yaml:"name,omitempty"`
	// This a slice of structs to allow additional configuration related to a manifest such as
	// accepting patches.
	Manifests []Manifest `json:"manifests,omitempty" yaml:"manifests,omitempty"`
}

type PolicyDefaults struct {
	PolicyOptions              `json:",inline" yaml:",inline"`
	ConfigurationPolicyOptions `json:",inline" yaml:",inline"`
	Namespace                  string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	OrderPolicies              bool   `json:"orderPolicies,omitempty" yaml:"orderPolicies,omitempty"`
}

type PolicySetConfig struct {
	Name             string   `json:"name,omitempty" yaml:"name,omitempty"`
	Description      string   `json:"description,omitempty" yaml:"description,omitempty"`
	Policies         []string `json:"policies,omitempty" yaml:"policies,omitempty"`
	PolicySetOptions `json:",inline" yaml:",inline"`
}

type PolicySetDefaults struct {
	PolicySetOptions `json:",inline" yaml:",inline"`
}

type PolicyDependency struct {
	APIVersion string `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Compliance string `json:"compliance,omitempty" yaml:"compliance,omitempty"`
	Kind       string `json:"kind,omitempty" yaml:"kind,omitempty"`
	Name       string `json:"name" yaml:"name"`
	Namespace  string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
}
