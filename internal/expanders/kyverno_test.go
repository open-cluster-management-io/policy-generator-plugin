// Copyright Contributors to the Open Cluster Management project
package expanders

import (
	"fmt"
	"testing"

	"open-cluster-management.io/ocm-kustomize-generator-plugins/internal/types"
)

func TestKyvernoCanHandle(t *testing.T) {
	t.Parallel()
	k := KyvernoPolicyExpander{}

	tests := []struct{ kind string }{
		{kyvernoClusterKind},
		{kyvernoNamespacedKind},
	}

	for _, test := range tests {
		test := test
		t.Run(
			fmt.Sprintf("kind=%s", test.kind),
			func(t *testing.T) {
				t.Parallel()
				manifest := map[string]interface{}{
					"apiVersion": kyvernoAPIVersion,
					"kind":       test.kind,
					"metadata": map[string]interface{}{
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
		{"v1", kyvernoClusterKind, "my-awesome-policy"},
		{"v1", kyvernoNamespacedKind, "my-awesome-policy"},
		{kyvernoAPIVersion, "ConfigMap", "my-awesome-policy"},
		{kyvernoAPIVersion, kyvernoClusterKind, ""},
		{kyvernoAPIVersion, kyvernoNamespacedKind, ""},
	}

	for _, test := range tests {
		test := test
		t.Run(
			fmt.Sprintf("apiVersion=%s,kind=%s,name=%s", test.apiVersion, test.kind, test.name),
			func(t *testing.T) {
				t.Parallel()
				manifest := map[string]interface{}{
					"apiVersion": test.apiVersion,
					"kind":       test.kind,
					"metadata": map[string]interface{}{
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
		policyConf := types.PolicyConfig{InformKyvernoPolicies: test.Enabled}
		assertEqual(t, k.Enabled(&policyConf), test.Expected)
	}
}

func TestKyvernoExpand(t *testing.T) {
	t.Parallel()
	k := KyvernoPolicyExpander{}
	manifest := map[string]interface{}{
		"apiVersion": kyvernoAPIVersion,
		"kind":       kyvernoClusterKind,
		"metadata": map[string]interface{}{
			"name": "my-awesome-policy",
		},
	}

	expected := []map[string]map[string]interface{}{
		{
			"objectDefinition": {
				"apiVersion": configPolicyAPIVersion,
				"kind":       configPolicyKind,
				"metadata":   map[string]interface{}{"name": "inform-kyverno-my-awesome-policy"},
				"spec": map[string]interface{}{
					"namespaceSelector": map[string]interface{}{
						"exclude": []string{"kube-*"},
						"include": []string{"*"},
					},
					"remediationAction": "inform",
					"severity":          "medium",
					"object-templates": []map[string]interface{}{
						{
							"complianceType": "mustnothave",
							"objectDefinition": map[string]interface{}{
								"apiVersion": kyvernoPolicyReportAPIVersion,
								"kind":       "ClusterPolicyReport",
								"results": []map[string]interface{}{
									{
										"policy": "my-awesome-policy",
										"result": "fail",
									},
								},
							},
						},
						{
							"complianceType": "mustnothave",
							"objectDefinition": map[string]interface{}{
								"apiVersion": kyvernoPolicyReportAPIVersion,
								"kind":       "PolicyReport",
								"results": []map[string]interface{}{
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
}
