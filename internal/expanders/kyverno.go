// Copyright Contributors to the Open Cluster Management project
package expanders

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"open-cluster-management.io/policy-generator-plugin/internal/types"
)

type KyvernoPolicyExpander struct{}

const (
	kyvernoAPIVersion                      = "kyverno.io/v1"
	kyvernoPolicyAPIVersion                = "policies.kyverno.io/v1"
	kyvernoPolicyReportAPIVersion          = "wgpolicyk8s.io/v1alpha2"
	kyvernoClusterPolicy                   = "ClusterPolicy"
	kyvernoNamespacedPolicy                = "Policy"
	kyvernoValidatingPolicy                = "ValidatingPolicy"
	kyvernoMutatingPolicy                  = "MutatingPolicy"
	kyvernoGeneratingPolicy                = "GeneratingPolicy"
	kyvernoImageValidatingPolicy           = "ImageValidatingPolicy"
	kyvernoNamespacedValidatingPolicy      = "NamespacedValidatingPolicy"
	kyvernoNamespacedMutatingPolicy        = "NamespacedMutatingPolicy"
	kyvernoNamespacedGeneratingPolicy      = "NamespacedGeneratingPolicy"
	kyvernoNamespacedImageValidatingPolicy = "NamespacedImageValidatingPolicy"
	clusterPolicyReportKind                = "ClusterPolicyReport"
	namespacedPolicyReportKind             = "PolicyReport"
)

// isValidKyvernoKind checks if the apiVersion and kind represent a supported Kyverno policy.
func isValidKyvernoKind(apiVersion, kind string) bool {
	switch kind {
	case kyvernoClusterPolicy, kyvernoNamespacedPolicy:
		return apiVersion == kyvernoAPIVersion
	case kyvernoValidatingPolicy, kyvernoMutatingPolicy, kyvernoGeneratingPolicy, kyvernoImageValidatingPolicy,
		kyvernoNamespacedValidatingPolicy, kyvernoNamespacedMutatingPolicy,
		kyvernoNamespacedGeneratingPolicy, kyvernoNamespacedImageValidatingPolicy:
		return apiVersion == kyvernoPolicyAPIVersion
	default:
		return false
	}
}

// CanHandle determines if the manifest is a Kyverno policy that can be expanded.
func (k KyvernoPolicyExpander) CanHandle(manifest map[string]interface{}) bool {
	apiVersion, _, _ := unstructured.NestedString(manifest, "apiVersion")
	kind, _, _ := unstructured.NestedString(manifest, "kind")

	if !isValidKyvernoKind(apiVersion, kind) {
		return false
	}

	if n, _, _ := unstructured.NestedString(manifest, "metadata", "name"); n == "" {
		return false
	}

	return true
}

// Enabled determines if the policy configuration allows a Kyverno policy to be expanded.
func (k KyvernoPolicyExpander) Enabled(policyConf *types.PolicyConfig) bool {
	return policyConf.InformKyvernoPolicies
}

// Expand will generate additional policy templates for the Kyverno policy for auditing purposes
// through Open Cluster Management. This should be run after the CanHandle method.
func (k KyvernoPolicyExpander) Expand(
	manifest map[string]interface{}, severity string,
) []map[string]interface{} {
	templates := []map[string]interface{}{}
	// This was previously validated in the CanHandle method.
	policyName, _, _ := unstructured.NestedString(manifest, "metadata", "name")

	configPolicyName := "inform-kyverno-" + policyName
	configurationPolicy := map[string]interface{}{
		"objectDefinition": map[string]interface{}{
			"apiVersion": configPolicyAPIVersion,
			"kind":       configPolicyKind,
			"metadata":   map[string]interface{}{"name": configPolicyName},
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
							"apiVersion": kyvernoPolicyReportAPIVersion,
							"kind":       clusterPolicyReportKind,
							"results": []map[string]interface{}{
								{
									"policy": policyName,
									"result": "fail",
								},
							},
						},
					},
					{
						"complianceType": "mustnothave",
						"objectDefinition": map[string]interface{}{
							"apiVersion": kyvernoPolicyReportAPIVersion,
							"kind":       namespacedPolicyReportKind,
							"results": []map[string]interface{}{
								{
									"policy": policyName,
									"result": "fail",
								},
							},
						},
					},
				},
			},
		},
	}

	templates = append(templates, configurationPolicy)

	return templates
}
