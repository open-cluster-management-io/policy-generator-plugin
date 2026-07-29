package expanders

import (
	"fmt"
	"testing"

	"open-cluster-management.io/policy-generator-plugin/internal/types"
)

func TestGatekeeperCanHandle(t *testing.T) {
	t.Parallel()

	g := GatekeeperPolicyExpander{}
	tests := []struct{ kind string }{
		{"MyConstraint"},
	}

	for _, test := range tests {
		t.Run(
			"kind="+test.kind,
			func(t *testing.T) {
				t.Parallel()

				manifest := map[string]any{
					"apiVersion": gatekeeperConstraintAPIVersion,
					"kind":       test.kind,
					"metadata": map[string]any{
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
		var policyConf types.PolicyConfig
		policyConf.InformGatekeeperPolicies = test.Enabled
		assertEqual(t, g.Enabled(&policyConf), test.Expected)
	}
}

func TestGatekeeperExpand(t *testing.T) {
	t.Parallel()

	g := GatekeeperPolicyExpander{}
	manifest := map[string]any{
		"apiVersion": gatekeeperConstraintAPIVersion,
		"kind":       "MyConstraint",
		"metadata": map[string]any{
			"name": "my-awesome-constraint",
		},
	}

	expected := []map[string]any{
		{
			"objectDefinition": map[string]any{
				"apiVersion": configPolicyAPIVersion,
				"kind":       configPolicyKind,
				"metadata":   map[string]any{"name": "inform-gatekeeper-audit-my-awesome-constraint"},
				"spec": map[string]any{
					"namespaceSelector": map[string]any{
						"exclude": []string{"kube-*"},
						"include": []string{"*"},
					},
					"remediationAction": "inform",
					"severity":          "medium",
					"object-templates": []map[string]any{
						{
							"complianceType": "musthave",
							"objectDefinition": map[string]any{
								"apiVersion": gatekeeperConstraintAPIVersion,
								"kind":       "MyConstraint",
								"metadata": map[string]any{
									"name": "my-awesome-constraint",
								},
								"status": map[string]any{
									"totalViolations": 0,
								},
							},
						},
					},
				},
			},
		},
		{
			"objectDefinition": map[string]any{
				"apiVersion": configPolicyAPIVersion,
				"kind":       configPolicyKind,
				"metadata":   map[string]any{"name": "inform-gatekeeper-admission-my-awesome-constraint"},
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
								"apiVersion": "v1",
								"kind":       "Event",
								"annotations": map[string]any{
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
	}

	templates := g.Expand(manifest, "medium")

	assertReflectEqual(t, templates, expected)
}
