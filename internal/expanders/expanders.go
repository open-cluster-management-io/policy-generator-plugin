// Copyright Contributors to the Open Cluster Management project
package expanders

import (
	"github.com/open-cluster-management/policy-generator-plugin/internal/types"
)

func GetExpanders() map[string]Expander {
	return map[string]Expander{
		"kyverno": KyvernoPolicyExpander{},
	}
}

type Expander interface {
	CanHandle(manifest map[string]interface{}) bool
	Enabled(policyConf *types.PolicyConfig) bool
	Expand(manifest map[string]interface{}, severity string) []map[string]map[string]interface{}
}

// Common constants for the expanders.
const (
	configPolicyAPIVersion = "policy.open-cluster-management.io/v1"
	configPolicyKind       = "ConfigurationPolicy"
)
