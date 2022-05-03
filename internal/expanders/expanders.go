// Copyright Contributors to the Open Cluster Management project
package expanders

import (
	"open-cluster-management.io/ocm-kustomize-generator-plugins/internal/types"
)

// GetExpanders returns the list of available expanders.
func GetExpanders() map[string]Expander {
	return map[string]Expander{
		"gatekeeper": GatekeeperPolicyExpander{},
		"kyverno":    KyvernoPolicyExpander{},
	}
}

// Expander is the interface for all policy expander instances.
type Expander interface {
	// CanHandle determines if the manifest is a policy that can be expanded.
	CanHandle(manifest map[string]interface{}) bool
	// Enabled determines if the policy configuration allows a policy to be expanded.
	Enabled(policyConf *types.PolicyConfig) bool
	// Expand will generate additional policy templates for the policy for auditing purposes.
	Expand(manifest map[string]interface{}, severity string) []map[string]map[string]interface{}
}

// Common constants for the expanders.
const (
	configPolicyAPIVersion = "policy.open-cluster-management.io/v1"
	configPolicyKind       = "ConfigurationPolicy"
)
