package internal

import (
	"bytes"
	"embed"
	"testing"
	"text/template"
)

func mockProcess(filePath, generator string) ([]byte, error) {
	p := Plugin{}

	tmpl, err := template.New("generator").Parse(generator)
	if err != nil {
		return nil, err
	}

	genBytes := &bytes.Buffer{}

	templateVars := struct {
		Dir string
	}{
		Dir: filePath,
	}

	err = tmpl.Execute(genBytes, templateVars)
	if err != nil {
		return nil, err
	}

	err = p.Config(genBytes.Bytes(), filePath)
	if err != nil {
		return nil, err
	}

	return p.Generate()
}

type genOutTest struct {
	tmpDir    string
	generator string
	wantFile  string
	wantErr   string
}

func (g genOutTest) run(t *testing.T) {
	t.Parallel()

	gotVal, gotErr := mockProcess(g.tmpDir, g.generator)
	if gotErr != nil {
		if g.wantErr != gotErr.Error() {
			t.Fatalf("expected err %v, got %v", g.wantErr, gotErr)
		} else {
			return
		}
	}

	want, err := wantedOutputs.ReadFile(g.wantFile)
	if err != nil {
		t.Fatalf("could not read wanted test output %v, err: %v", g.wantFile, err)
	}

	assertEqualYaml(t, want, gotVal)
}

//go:embed testdata/ordering/*
var wantedOutputs embed.FS

func TestOrderPolicies(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	tests := map[string]genOutTest{
		"one ordered policy": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  orderPolicies: true
  namespace: my-policies
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/one-ordered-policy.yaml",
			wantErr:  "",
		},
		"two ordered policies": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  orderPolicies: true
  namespace: my-policies
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
- name: two
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/two-ordered-policies.yaml",
			wantErr:  "",
		},
		"policyDefaults dependencies and orderPolicies": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  orderPolicies: true
  dependencies:
  - name: foo
  namespace: my-policies
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
- name: two
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "",
			wantErr:  "policyDefaults must specify only one of dependencies or orderPolicies",
		},
		"policy dependencies and orderPolicies": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  orderPolicies: true
  namespace: my-policies
policies:
- name: one
  dependencies:
  - name: foo
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
- name: two
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "",
			wantErr:  "dependencies may not be set in policy one when policyDefaults.orderPolicies is true",
		},
	}

	for name := range tests {
		t.Run(name, tests[name].run)
	}
}

func TestDependencies(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	tests := map[string]genOutTest{
		"policyDefaults go in both policies": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  dependencies:
  - name: foo
  namespace: my-policies
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
- name: two
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/default-deps-propagated.yaml",
			wantErr:  "",
		},
		"additional dependency details are configurable": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  dependencies:
  - apiVersion: fake.test.io/v2
    compliance: Pending
    kind: FakeThing
    name: foo
    namespace: bar
  namespace: my-policies
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/dependency-details-config.yaml",
			wantErr:  "",
		},
		"one policy can override policyDefaults": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  dependencies:
  - name: foo
  namespace: my-policies
policies:
- name: one
  dependencies:
  - name: bar
    compliance: NonCompliant
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
- name: two
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/override-dependencies.yaml",
			wantErr:  "",
		},
		"dependencies are configurable at the policy level": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  namespace: my-policies
policies:
- name: one
  dependencies:
  - name: baz
    namespace: default
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/policy-level-dependencies.yaml",
			wantErr:  "",
		},
	}

	for name := range tests {
		t.Run(name, tests[name].run)
	}
}

func TestIgnorePending(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	createObjectTemplatesRawManifest(t, tmpDir, "object-templates-raw.yaml")

	tests := map[string]genOutTest{
		"policyDefaults.ignorePending is propagated to all manifests": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: false
  ignorePending: true
  namespace: my-policies
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
- name: two
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/ignore-pending-propagation.yaml",
			wantErr:  "",
		},
		"policyDefaults.ignorePending is propagated with consolidated manifests": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: true
  ignorePending: true
  namespace: my-policies
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
- name: two
  ignorePending: false
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/ignore-pending-policy-consolidated.yaml",
			wantErr:  "",
		},
		"policyDefaults.ignorePending can be overridden at policy level": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: false
  ignorePending: true
  namespace: my-policies
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
- name: two
  ignorePending: false
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/ignore-pending-policy-override.yaml",
			wantErr:  "",
		},
		"policyDefaults.ignorePending can be overridden at manifest level": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: false
  namespace: my-policies
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
    ignorePending: true
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
- name: two
  ignorePending: true
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/ignore-pending-manifest-override.yaml",
			wantErr:  "",
		},
		"policyDefaults.ignorePending is propagated with object-templates-raw": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: false
  ignorePending: true
  namespace: my-policies
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "object-templates-raw.yaml"}}
- name: two
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "object-templates-raw.yaml"}}
`,
			wantFile: "testdata/ordering/ignore-pending-object-templates-raw.yaml",
			wantErr:  "",
		},
	}

	for name := range tests {
		t.Run(name, tests[name].run)
	}
}

func TestOrderManifests(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")

	tests := map[string]genOutTest{
		"orderManifests from policyDefaults": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: false
  orderManifests: true
  namespace: my-policies
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/three-ordered-manifests.yaml",
			wantErr:  "",
		},
		"orderManifests from policy setting": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: false
  namespace: my-policies
policies:
- name: one
  orderManifests: true
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/three-ordered-manifests.yaml",
			wantErr:  "",
		},
		"orderManifests and extraDependencies in policyDefaults": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: false
  orderManifests: true
  extraDependencies:
    - name: foo
  namespace: my-policies
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "",
			wantErr:  "policyDefaults may not specify both extraDependencies and orderManifests",
		},
		"orderManifests in policyDefaults and extraDependencies in policy": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: false
  orderManifests: true
  namespace: my-policies
policies:
- name: one
  extraDependencies:
  - name: foo
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "",
			wantErr:  "extraDependencies may not be set in policy one when orderManifests is true",
		},
		"orderManifests in policyDefaults and extraDependencies in manifest": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: false
  orderManifests: true
  namespace: my-policies
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
    extraDependencies:
    - name: foo
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "",
			wantErr:  "extraDependencies may not be set in policy one manifest[0] because orderManifests is set",
		},
		"orderManifests is true in policyDefaults and consolidateManifests is unset": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  orderManifests: true
  namespace: my-policies
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/three-ordered-manifests.yaml",
			wantErr:  "",
		},
		"orderManifests is true in policy and consolidateManifests is unset": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  namespace: my-policies
policies:
- name: one
  orderManifests: true
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/three-ordered-manifests.yaml",
			wantErr:  "",
		},
	}

	for name := range tests {
		t.Run(name, tests[name].run)
	}
}

func TestExtraDependencies(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	createConfigMap(t, tmpDir, "configmap.yaml")
	createConfigPolicyManifest(t, tmpDir, "configpolicy.yaml")
	createObjectTemplatesRawManifest(t, tmpDir, "object-templates-raw.yaml")

	tests := map[string]genOutTest{
		"policyDefaults.extraDependencies are propagated to all manifests": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: false
  namespace: my-policies
  extraDependencies:
  - name: extrafoo
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
- name: two
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/default-extradeps-propagated.yaml",
			wantErr:  "",
		},
		"policyDefaults.extraDependencies is propagated with consolidated manifests": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: true
  namespace: my-policies
  extraDependencies:
  - name: extrafoo
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
- name: two
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/default-extradeps-consolidated.yaml",
			wantErr:  "",
		},
		"policy extraDependencies are propagated": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: false
  namespace: my-policies
policies:
- name: one
  extraDependencies:
  - name: myextrafoo
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
- name: two
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/policy-extradeps.yaml",
			wantErr:  "",
		},
		"manifest extraDependencies are handled": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: false
  namespace: my-policies
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
    extraDependencies:
    - name: manifestextra
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
- name: two
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/manifest-extradeps.yaml",
			wantErr:  "",
		},
		"manifest extraDependencies are handled with ConfigurationPolicy manifests": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: false
  namespace: my-policies
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configpolicy.yaml"}}
    extraDependencies:
    - kind: CertificatePolicy
      name: manifestextra
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
- name: two
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/manifest-extradeps-configpolicy.yaml",
			wantErr:  "",
		},
		"manifest extraDependencies are handled with ConfigurationPolicy manifests when defaults are set": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  namespace: my-policies
  placement:
    clusterSelector:
      matchExpressions: []
  extraDependencies:
  - kind: CertificatePolicy
    name: manifestextra
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configpolicy.yaml"}}
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
- name: two
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/manifest-extradeps-configpolicy-defaults.yaml",
			wantErr:  "",
		},
		"extraDependencies defaults can be overwritten": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: false
  namespace: my-policies
  extraDependencies:
  - name: defaultextradep
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
    extraDependencies:
    - name: manifestextra
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
- name: two
  extraDependencies:
  - name: policyextra
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/default-extradeps-override.yaml",
			wantErr:  "",
		},
		"extraDependencies default fields can be overwritten": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: false
  namespace: my-policies
  extraDependencies:
  - apiVersion: fake.test.io/v2
    compliance: Pending
    kind: FakeThing
    name: foo
    namespace: bar
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
`,
			wantFile: "testdata/ordering/extradeps-overrides.yaml",
			wantErr:  "",
		},
		"policyDefaults.extraDependencies are propagated with object-templates-raw": {
			tmpDir: tmpDir,
			generator: `
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
metadata:
  name: test
policyDefaults:
  consolidateManifests: false
  namespace: my-policies
  extraDependencies:
  - name: extrafoo
policies:
- name: one
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "object-templates-raw.yaml"}}
- name: two
  manifests:
  - path: {{printf "%v/%v" .Dir "configmap.yaml"}}
  - path: {{printf "%v/%v" .Dir "object-templates-raw.yaml"}}
`,
			wantFile: "testdata/ordering/default-extradeps-object-templates-raw.yaml",
			wantErr:  "",
		},
	}

	for name := range tests {
		t.Run(name, tests[name].run)
	}
}
