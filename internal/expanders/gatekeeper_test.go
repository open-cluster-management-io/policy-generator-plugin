// // Copyright Contributors to the Open Cluster Management project
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
		var policyConf types.PolicyConfig
		policyConf.InformGatekeeperPolicies = test.Enabled
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

	expected := []map[string]interface{}{
		{
			"objectDefinition": map[string]interface{}{
				"apiVersion": configPolicyAPIVersion,
				"kind":       configPolicyKind,
				"metadata":   map[string]interface{}{"name": "inform-gatekeeper-violations-my-awesome-constraint"},
				"spec": map[string]interface{}{
					"namespaceSelector": map[string]interface{}{
						"exclude": []interface{}{"kube-*"},
						"include": []interface{}{"*"},
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
			"objectDefinition": map[string]interface{}{
				"apiVersion": configPolicyAPIVersion,
				"kind":       configPolicyKind,
				"metadata":   map[string]interface{}{"name": "inform-gatekeeper-admission-my-awesome-constraint"},
				"spec": map[string]interface{}{
					"namespaceSelector": map[string]interface{}{
						"exclude": []interface{}{"kube-*"},
						"include": []interface{}{"*"},
					},
					"remediationAction": "inform",
					"severity":          "medium",
					"object-templates": []map[string]interface{}{
						{
							"complianceType": "mustnothave",
							"objectDefinition": map[string]interface{}{
								"apiVersion": "v1",
								"kind":       "Event",
								"annotations": map[string]interface{}{
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
		{
			"objectDefinition": map[string]interface{}{
				"apiVersion": configPolicyAPIVersion,
				"kind":       configPolicyKind,
				"metadata":   map[string]interface{}{"name": "inform-gatekeeper-audit-my-awesome-constraint"},
				"spec": map[string]interface{}{
					"namespaceSelector": map[string]interface{}{
						"exclude": []interface{}{"kube-*"},
						"include": []interface{}{"*"},
					},
					"remediationAction": "inform",
					"severity":          "medium",
					"object-templates": []map[string]interface{}{
						{
							"complianceType": "mustnothave",
							"objectDefinition": map[string]interface{}{
								"apiVersion": "v1",
								"kind":       "Event",
								"annotations": map[string]interface{}{
									"constraint_action": "deny",
									"constraint_kind":   "MyConstraint",
									"constraint_name":   "my-awesome-constraint",
									"event_type":        "violation_audited",
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

func TestGatekeeperExpandWithCustomIncludeNamespace(t *testing.T) {
	t.Parallel()

	g := GatekeeperPolicyExpander{}
	manifest := map[string]interface{}{
		"apiVersion": gatekeeperConstraintAPIVersion,
		"kind":       "MyConstraint",
		"metadata": map[string]interface{}{
			"name": "my-awesome-constraint",
		},
		"spec": map[string]interface{}{
			"match": map[string]interface{}{
				"namespaces": []interface{}{
					"include1",
					"include2",
				},
			},
		},
	}

	expected := []map[string]interface{}{
		{
			"objectDefinition": map[string]interface{}{
				"apiVersion": configPolicyAPIVersion,
				"kind":       configPolicyKind,
				"metadata":   map[string]interface{}{"name": "inform-gatekeeper-violations-my-awesome-constraint"},
				"spec": map[string]interface{}{
					"namespaceSelector": map[string]interface{}{
						"exclude": []interface{}{"kube-*"},
						"include": []interface{}{
							"include1",
							"include2",
						},
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
			"objectDefinition": map[string]interface{}{
				"apiVersion": configPolicyAPIVersion,
				"kind":       configPolicyKind,
				"metadata":   map[string]interface{}{"name": "inform-gatekeeper-admission-my-awesome-constraint"},
				"spec": map[string]interface{}{
					"namespaceSelector": map[string]interface{}{
						"exclude": []interface{}{"kube-*"},
						"include": []interface{}{
							"include1",
							"include2",
						},
					},
					"remediationAction": "inform",
					"severity":          "medium",
					"object-templates": []map[string]interface{}{
						{
							"complianceType": "mustnothave",
							"objectDefinition": map[string]interface{}{
								"apiVersion": "v1",
								"kind":       "Event",
								"annotations": map[string]interface{}{
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
		{
			"objectDefinition": map[string]interface{}{
				"apiVersion": configPolicyAPIVersion,
				"kind":       configPolicyKind,
				"metadata":   map[string]interface{}{"name": "inform-gatekeeper-audit-my-awesome-constraint"},
				"spec": map[string]interface{}{
					"namespaceSelector": map[string]interface{}{
						"exclude": []interface{}{"kube-*"},
						"include": []interface{}{
							"include1",
							"include2",
						},
					},
					"remediationAction": "inform",
					"severity":          "medium",
					"object-templates": []map[string]interface{}{
						{
							"complianceType": "mustnothave",
							"objectDefinition": map[string]interface{}{
								"apiVersion": "v1",
								"kind":       "Event",
								"annotations": map[string]interface{}{
									"constraint_action": "deny",
									"constraint_kind":   "MyConstraint",
									"constraint_name":   "my-awesome-constraint",
									"event_type":        "violation_audited",
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

func TestGatekeeperExpandWithCustomExcludedNamespace(t *testing.T) {
	t.Parallel()

	g := GatekeeperPolicyExpander{}
	manifest := map[string]interface{}{
		"apiVersion": gatekeeperConstraintAPIVersion,
		"kind":       "MyConstraint",
		"metadata": map[string]interface{}{
			"name": "my-awesome-constraint",
		},
		"spec": map[string]interface{}{
			"match": map[string]interface{}{
				"excludedNamespaces": []interface{}{
					"exclude1",
					"exclude2",
				},
			},
		},
	}

	expected := []map[string]interface{}{
		{
			"objectDefinition": map[string]interface{}{
				"apiVersion": configPolicyAPIVersion,
				"kind":       configPolicyKind,
				"metadata":   map[string]interface{}{"name": "inform-gatekeeper-violations-my-awesome-constraint"},
				"spec": map[string]interface{}{
					"namespaceSelector": map[string]interface{}{
						"exclude": []interface{}{
							"exclude1",
							"exclude2",
						},
						"include": []interface{}{"*"},
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
			"objectDefinition": map[string]interface{}{
				"apiVersion": configPolicyAPIVersion,
				"kind":       configPolicyKind,
				"metadata":   map[string]interface{}{"name": "inform-gatekeeper-admission-my-awesome-constraint"},
				"spec": map[string]interface{}{
					"namespaceSelector": map[string]interface{}{
						"exclude": []interface{}{
							"exclude1",
							"exclude2",
						},
						"include": []interface{}{"*"},
					},
					"remediationAction": "inform",
					"severity":          "medium",
					"object-templates": []map[string]interface{}{
						{
							"complianceType": "mustnothave",
							"objectDefinition": map[string]interface{}{
								"apiVersion": "v1",
								"kind":       "Event",
								"annotations": map[string]interface{}{
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
		{
			"objectDefinition": map[string]interface{}{
				"apiVersion": configPolicyAPIVersion,
				"kind":       configPolicyKind,
				"metadata":   map[string]interface{}{"name": "inform-gatekeeper-audit-my-awesome-constraint"},
				"spec": map[string]interface{}{
					"namespaceSelector": map[string]interface{}{
						"exclude": []interface{}{
							"exclude1",
							"exclude2",
						},
						"include": []interface{}{"*"},
					},
					"remediationAction": "inform",
					"severity":          "medium",
					"object-templates": []map[string]interface{}{
						{
							"complianceType": "mustnothave",
							"objectDefinition": map[string]interface{}{
								"apiVersion": "v1",
								"kind":       "Event",
								"annotations": map[string]interface{}{
									"constraint_action": "deny",
									"constraint_kind":   "MyConstraint",
									"constraint_name":   "my-awesome-constraint",
									"event_type":        "violation_audited",
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

func TestGatekeeperExpandWithCustomIncludeAndExcludedNamespace(t *testing.T) {
	t.Parallel()

	g := GatekeeperPolicyExpander{}
	manifest := map[string]interface{}{
		"apiVersion": gatekeeperConstraintAPIVersion,
		"kind":       "MyConstraint",
		"metadata": map[string]interface{}{
			"name": "my-awesome-constraint",
		},
		"spec": map[string]interface{}{
			"match": map[string]interface{}{
				"namespaces": []interface{}{
					"include1",
					"include2",
				},
				"excludedNamespaces": []interface{}{
					"exclude1",
					"exclude2",
				},
			},
		},
	}

	expected := []map[string]interface{}{
		{
			"objectDefinition": map[string]interface{}{
				"apiVersion": configPolicyAPIVersion,
				"kind":       configPolicyKind,
				"metadata":   map[string]interface{}{"name": "inform-gatekeeper-violations-my-awesome-constraint"},
				"spec": map[string]interface{}{
					"namespaceSelector": map[string]interface{}{
						"exclude": []interface{}{
							"exclude1",
							"exclude2",
						},
						"include": []interface{}{
							"include1",
							"include2",
						},
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
			"objectDefinition": map[string]interface{}{
				"apiVersion": configPolicyAPIVersion,
				"kind":       configPolicyKind,
				"metadata":   map[string]interface{}{"name": "inform-gatekeeper-admission-my-awesome-constraint"},
				"spec": map[string]interface{}{
					"namespaceSelector": map[string]interface{}{
						"exclude": []interface{}{
							"exclude1",
							"exclude2",
						},
						"include": []interface{}{
							"include1",
							"include2",
						},
					},
					"remediationAction": "inform",
					"severity":          "medium",
					"object-templates": []map[string]interface{}{
						{
							"complianceType": "mustnothave",
							"objectDefinition": map[string]interface{}{
								"apiVersion": "v1",
								"kind":       "Event",
								"annotations": map[string]interface{}{
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
		{
			"objectDefinition": map[string]interface{}{
				"apiVersion": configPolicyAPIVersion,
				"kind":       configPolicyKind,
				"metadata":   map[string]interface{}{"name": "inform-gatekeeper-audit-my-awesome-constraint"},
				"spec": map[string]interface{}{
					"namespaceSelector": map[string]interface{}{
						"exclude": []interface{}{
							"exclude1",
							"exclude2",
						},
						"include": []interface{}{
							"include1",
							"include2",
						},
					},
					"remediationAction": "inform",
					"severity":          "medium",
					"object-templates": []map[string]interface{}{
						{
							"complianceType": "mustnothave",
							"objectDefinition": map[string]interface{}{
								"apiVersion": "v1",
								"kind":       "Event",
								"annotations": map[string]interface{}{
									"constraint_action": "deny",
									"constraint_kind":   "MyConstraint",
									"constraint_name":   "my-awesome-constraint",
									"event_type":        "violation_audited",
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
