// Copyright Contributors to the Open Cluster Management project
package expanders

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"open-cluster-management.io/ocm-kustomize-generator-plugins/internal/types"
)

type GatekeeperPolicyExpander struct{}

const (
	gatekeeperConstraintAPIVersion = "constraints.gatekeeper.sh/v1beta1"
)

// CanHandle determines if the manifest is a Gatekeeper policy that can be expanded.
func (g GatekeeperPolicyExpander) CanHandle(manifest map[string]interface{}) bool {
	// Verify the APIVersion
	if a, _, _ := unstructured.NestedString(manifest, "apiVersion"); a != gatekeeperConstraintAPIVersion {
		return false
	}

	// The Gatekeeper kind for a constraint is user-defined, so for now we we're going to assume the
	// template has been set up properly and we'll make sure the kind is populated in the constraint
	// (This could be improved in the future by making sure the ConstraintTemplate is also provided in
	// the policy and parsing the kind from that).
	if k, _, _ := unstructured.NestedString(manifest, "kind"); k == "" {
		return false
	}

	// Verify the name is included in the metadata.
	if n, _, _ := unstructured.NestedString(manifest, "metadata", "name"); n == "" {
		return false
	}

	return true
}

// Enabled determines if the policy configuration allows a Gatekeeper policy to be expanded.
func (g GatekeeperPolicyExpander) Enabled(policyConf *types.PolicyConfig) bool {
	return policyConf.InformGatekeeperPolicies
}

// Expand will generate additional policy templates for the Gatekeeper policy
// for auditing purposes through Open Cluster Management. This should be run after the CanHandle
// method.
func (g GatekeeperPolicyExpander) Expand(
	manifest map[string]interface{}, severity string,
) []map[string]map[string]interface{} {
	templates := []map[string]map[string]interface{}{}
	// These were previously validated in the CanHandle method.
	constraintName, _, _ := unstructured.NestedString(manifest, "metadata", "name")
	constraintKind, _, _ := unstructured.NestedString(manifest, "kind")

	auditConfigPolicyName := fmt.Sprintf("inform-gatekeeper-audit-%s", constraintName)
	auditConfigurationPolicy := map[string]map[string]interface{}{
		"objectDefinition": {
			"apiVersion": configPolicyAPIVersion,
			"kind":       configPolicyKind,
			"metadata":   map[string]interface{}{"name": auditConfigPolicyName},
			"spec": map[string]interface{}{
				"namespaceSelector": map[string]interface{}{
					"exclude": []string{"kube-*"},
					"include": []string{"*"},
				},
				"remediationAction": "inform",
				"severity":          severity,
				"object-templates": []map[string]interface{}{
					{
						"complianceType": "musthave",
						"objectDefinition": map[string]interface{}{
							"apiVersion": gatekeeperConstraintAPIVersion,
							"kind":       constraintKind,
							"metadata": map[string]interface{}{
								"name": constraintName,
							},
							"status": map[string]interface{}{
								"totalViolations": 0,
							},
						},
					},
				},
			},
		},
	}
	// Further improvements here could be made by having the user specify the Gatekeeper namespace and
	// targeting the events for the constraint kind to just that namespace.
	admissionConfigPolicyName := fmt.Sprintf("inform-gatekeeper-admission-%s", constraintName)
	admissionConfigurationPolicy := map[string]map[string]interface{}{
		"objectDefinition": {
			"apiVersion": configPolicyAPIVersion,
			"kind":       configPolicyKind,
			"metadata":   map[string]interface{}{"name": admissionConfigPolicyName},
			"spec": map[string]interface{}{
				"namespaceSelector": map[string]interface{}{
					"exclude": []string{"kube-*"},
					"include": []string{"*"},
				},
				"remediationAction": "inform",
				"severity":          severity,
				"object-templates": []map[string]interface{}{
					{
						"complianceType": "mustnothave",
						"objectDefinition": map[string]interface{}{
							"apiVersion": "v1",
							"kind":       "Event",
							"annotations": []map[string]interface{}{
								{
									"constraint_action": "deny",
									"constraint_kind":   constraintKind,
									"constraint_name":   constraintName,
									"event_type":        "violation",
								},
							},
						},
					},
				},
			},
		},
	}

	templates = append(templates, auditConfigurationPolicy, admissionConfigurationPolicy)

	return templates
}
