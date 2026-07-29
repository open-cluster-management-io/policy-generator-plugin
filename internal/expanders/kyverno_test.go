package expanders

import (
	"fmt"
	"testing"

	"open-cluster-management.io/policy-generator-plugin/internal/types"
)

func TestKyvernoCanHandle(t *testing.T) {
	t.Parallel()

	k := KyvernoPolicyExpander{}

	tests := []struct {
		apiVersion string
		kind       string
	}{
		{kyvernoAPIVersion, kyvernoClusterPolicy},
		{kyvernoAPIVersion, kyvernoNamespacedPolicy},
		{kyvernoPolicyAPIVersion, "ValidatingPolicy"},
		{kyvernoPolicyAPIVersion, "MutatingPolicy"},
		{kyvernoPolicyAPIVersion, "GeneratingPolicy"},
		{kyvernoPolicyAPIVersion, "ImageValidatingPolicy"},
		{kyvernoPolicyAPIVersion, "NamespacedValidatingPolicy"},
		{kyvernoPolicyAPIVersion, "NamespacedMutatingPolicy"},
		{kyvernoPolicyAPIVersion, "NamespacedGeneratingPolicy"},
		{kyvernoPolicyAPIVersion, "NamespacedImageValidatingPolicy"},
	}

	for _, test := range tests {
		t.Run(
			"kind="+test.kind,
			func(t *testing.T) {
				t.Parallel()

				manifest := map[string]any{
					"apiVersion": test.apiVersion,
					"kind":       test.kind,
					"metadata": map[string]any{
						"name": "my-awesome-policy",
					},
				}
				assertEqual(t, k.CanHandle(manifest), true)
			},
		)
	}
}

func TestKyvernoCanHandleInvalid(t *testing.T) {
	t.Parallel()

	k := KyvernoPolicyExpander{}
	tests := []struct{ apiVersion, kind, name string }{
		{"v1", kyvernoClusterPolicy, "my-awesome-policy"},
		{"v1", kyvernoNamespacedPolicy, "my-awesome-policy"},
		{kyvernoAPIVersion, "ConfigMap", "my-awesome-policy"},
		{kyvernoAPIVersion, kyvernoClusterPolicy, ""},
		{kyvernoAPIVersion, kyvernoNamespacedPolicy, ""},
		{kyvernoPolicyAPIVersion, kyvernoClusterPolicy, "my-awesome-policy"},
		{kyvernoPolicyAPIVersion, kyvernoNamespacedPolicy, "my-awesome-policy"},
		{"policies.kyverno.io/v2", "ValidatingPolicy", "my-awesome-policy"},
		{kyvernoPolicyAPIVersion, "ValidatingPolicy", ""},
	}

	for _, test := range tests {
		t.Run(
			fmt.Sprintf("apiVersion=%s,kind=%s,name=%s", test.apiVersion, test.kind, test.name),
			func(t *testing.T) {
				t.Parallel()

				manifest := map[string]any{
					"apiVersion": test.apiVersion,
					"kind":       test.kind,
					"metadata": map[string]any{
						"name": test.name,
					},
				}
				assertEqual(t, k.CanHandle(manifest), false)
			},
		)
	}
}

func TestKyvernoEnabled(t *testing.T) {
	t.Parallel()

	k := KyvernoPolicyExpander{}
	tests := []struct {
		Enabled  bool
		Expected bool
	}{{true, true}, {false, false}}

	for _, test := range tests {
		var policyConf types.PolicyConfig
		policyConf.InformKyvernoPolicies = test.Enabled
		assertEqual(t, k.Enabled(&policyConf), test.Expected)
	}
}

func TestKyvernoExpand(t *testing.T) {
	t.Parallel()

	k := KyvernoPolicyExpander{}

	tests := []struct {
		apiVersion string
		kind       string
	}{
		{kyvernoAPIVersion, kyvernoClusterPolicy},
		{kyvernoAPIVersion, kyvernoNamespacedPolicy},
		{kyvernoPolicyAPIVersion, kyvernoValidatingPolicy},
		{kyvernoPolicyAPIVersion, kyvernoMutatingPolicy},
		{kyvernoPolicyAPIVersion, kyvernoGeneratingPolicy},
		{kyvernoPolicyAPIVersion, kyvernoImageValidatingPolicy},
		{kyvernoPolicyAPIVersion, kyvernoNamespacedValidatingPolicy},
		{kyvernoPolicyAPIVersion, kyvernoNamespacedMutatingPolicy},
		{kyvernoPolicyAPIVersion, kyvernoNamespacedGeneratingPolicy},
		{kyvernoPolicyAPIVersion, kyvernoNamespacedImageValidatingPolicy},
	}

	for _, test := range tests {
		t.Run(
			"kind="+test.kind,
			func(t *testing.T) {
				t.Parallel()

				manifest := map[string]any{
					"apiVersion": test.apiVersion,
					"kind":       test.kind,
					"metadata": map[string]any{
						"name": "my-awesome-policy",
					},
				}

				expected := []map[string]any{
					{
						"objectDefinition": map[string]any{
							"apiVersion": configPolicyAPIVersion,
							"kind":       configPolicyKind,
							"metadata":   map[string]any{"name": "inform-kyverno-my-awesome-policy"},
							"spec": map[string]any{
								"namespaceSelector": map[string]any{
									"exclude": []string{"kube-*"},
									"include": []string{"*"},
								},
								"remediationAction": "inform",
								"severity":          "medium",
								"object-templates": []map[string]any{
									{
										"complianceType": "mustnothave",
										"objectDefinition": map[string]any{
											"apiVersion": kyvernoPolicyReportAPIVersion,
											"kind":       clusterPolicyReportKind,
											"results": []map[string]any{
												{
													"policy": "my-awesome-policy",
													"result": "fail",
												},
											},
										},
									},
									{
										"complianceType": "mustnothave",
										"objectDefinition": map[string]any{
											"apiVersion": kyvernoPolicyReportAPIVersion,
											"kind":       namespacedPolicyReportKind,
											"results": []map[string]any{
												{
													"policy": "my-awesome-policy",
													"result": "fail",
												},
											},
										},
									},
								},
							},
						},
					},
				}
				templates := k.Expand(manifest, "medium")

				assertReflectEqual(t, templates, expected)
			},
		)
	}
}
