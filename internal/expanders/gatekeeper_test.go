// // Copyright Contributors to the Open Cluster Management project
package expanders

import (
	"fmt"
	"testing"

	"open-cluster-management.io/ocm-kustomize-generator-plugins/internal/types"
)

func TestGatekeeperCanHandle(t *testing.T) {
	t.Parallel()
	g := GatekeeperPolicyExpander{}

	tests := []struct{ kind string }{
		{"MyConstraint"},
	}

	for _, test := range tests {
		test := test
		t.Run(
			fmt.Sprintf("kind=%s", test.kind),
			func(t *testing.T) {
				t.Parallel()
				manifest := map[string]interface{}{
					"apiVersion": gatekeeperConstraintAPIVersion,
					"kind":       test.kind,
					"metadata": map[string]interface{}{
						"name": "my-awesome-constraint",
					},
				}
				assertEqual(t, g.CanHandle(manifest), true)
			},
		)
	}
}

func TestGatekeeperCanHandleInvalid(t *testing.T) {
	t.Parallel()
	g := GatekeeperPolicyExpander{}

	tests := []struct{ apiVersion, kind, name string }{
		{"v1", "MyConstraint", "my-awesomer-policy"},
		{gatekeeperConstraintAPIVersion, "MyConstraint", ""},
		{gatekeeperConstraintAPIVersion, "", "my-awesome-constraint"},
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
				assertEqual(t, g.CanHandle(manifest), false)
			},
		)
	}
}

func TestGatekeeperEnabled(t *testing.T) {
	t.Parallel()
	g := GatekeeperPolicyExpander{}
	tests := []struct {
		Enabled  bool
		Expected bool
	}{{true, true}, {false, false}}
	for _, test := range tests {
		policyConf := types.PolicyConfig{InformGatekeeperPolicies: test.Enabled}
		assertEqual(t, g.Enabled(&policyConf), test.Expected)
	}
}

func TestGatekeeperExpand(t *testing.T) {
	t.Parallel()
	g := GatekeeperPolicyExpander{}
	manifest := map[string]interface{}{
		"apiVersion": gatekeeperConstraintAPIVersion,
		"kind":       "MyConstraint",
		"metadata": map[string]interface{}{
			"name": "my-awesome-constraint",
		},
	}

	expected := []map[string]map[string]interface{}{
		{
			"objectDefinition": {
				"apiVersion": configPolicyAPIVersion,
				"kind":       configPolicyKind,
				"metadata":   map[string]interface{}{"name": "inform-gatekeeper-audit-my-awesome-constraint"},
				"spec": map[string]interface{}{
					"namespaceSelector": map[string]interface{}{
						"exclude": []string{"kube-*"},
						"include": []string{"*"},
					},
					"remediationAction": "inform",
					"severity":          "medium",
					"object-templates": []map[string]interface{}{
						{
							"complianceType": "musthave",
							"objectDefinition": map[string]interface{}{
								"apiVersion": gatekeeperConstraintAPIVersion,
								"kind":       "MyConstraint",
								"metadata": map[string]interface{}{
									"name": "my-awesome-constraint",
								},
								"status": map[string]interface{}{
									"totalViolations": 0,
								},
							},
						},
					},
				},
			},
		},
		{
			"objectDefinition": {
				"apiVersion": configPolicyAPIVersion,
				"kind":       configPolicyKind,
				"metadata":   map[string]interface{}{"name": "inform-gatekeeper-admission-my-awesome-constraint"},
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
								"apiVersion": "v1",
								"kind":       "Event",
								"annotations": []map[string]interface{}{
									{
										"constraint_action": "deny",
										"constraint_kind":   "MyConstraint",
										"constraint_name":   "my-awesome-constraint",
										"event_type":        "violation",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	templates := g.Expand(manifest, "medium")

	assertReflectEqual(t, templates, expected)
}
