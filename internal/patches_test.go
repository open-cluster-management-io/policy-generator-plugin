// Copyright Contributors to the Open Cluster Management project
package internal

import (
	"fmt"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"open-cluster-management.io/policy-generator-plugin/internal/types"
)

func createExConfigMap(name string) *map[string]interface{} {
	return &map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": "default",
		},
		"data": map[string]string{
			"game.properties": "enemies=goldfish",
			"ui.properties":   "color.good=neon-green",
		},
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	manifests := []map[string]interface{}{}
	manifests = append(
		manifests, *createExConfigMap("configmap1"), *createExConfigMap("configmap2"),
	)
	patches := []map[string]interface{}{
		{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"name":      "configmap2",
				"namespace": "default",
				"labels": map[string]string{
					"chandler": "bing",
				},
			},
		},
	}

	openAPIConfig := types.OpenAPI{Path: ""}

	patcher := manifestPatcher{manifests: manifests, patches: patches, openAPI: openAPIConfig}
	err := patcher.Validate()

	assertEqual(t, err, nil)
}

func TestValidateDefaults(t *testing.T) {
	t.Parallel()

	manifests := []map[string]interface{}{*createExConfigMap("configmap1")}
	patches := []map[string]interface{}{
		{
			"metadata": map[string]interface{}{
				"labels": map[string]string{
					"chandler": "bing",
				},
			},
		},
	}

	patcher := manifestPatcher{manifests: manifests, patches: patches}
	err := patcher.Validate()

	assertEqual(t, err, nil)
}

func TestValidateNoManifests(t *testing.T) {
	t.Parallel()

	patcher := manifestPatcher{
		manifests: []map[string]interface{}{}, patches: []map[string]interface{}{},
	}
	err := patcher.Validate()

	assertEqual(t, err.Error(), "there must be one or more manifests")
}

func TestValidateManifestMissingData(t *testing.T) {
	t.Parallel()

	tests := []struct{ missingFields []string }{
		{missingFields: []string{"apiVersion"}},
		{missingFields: []string{"kind"}},
		{missingFields: []string{"metadata", "name"}},
	}

	for _, test := range tests {
		test := test
		name := fmt.Sprintf("manifest missing %s", strings.Join(test.missingFields, "."))

		t.Run(
			name,
			func(t *testing.T) {
				t.Parallel()
				configmap := *createExConfigMap("configmap1")
				err := unstructured.SetNestedField(configmap, "", test.missingFields...)
				if err != nil {
					t.Fatal(err.Error())
				}
				manifests := []map[string]interface{}{configmap}

				patcher := manifestPatcher{manifests: manifests, patches: []map[string]interface{}{}}
				err = patcher.Validate()

				expected := fmt.Sprintf(
					`all manifests must have the "%s" field set to a non-empty string`,
					strings.Join(test.missingFields, "."),
				)
				assertEqual(t, err.Error(), expected)
			},
		)
	}
}

func TestValidatePatchMissingData(t *testing.T) {
	t.Parallel()

	tests := []struct{ missingFields []string }{
		{missingFields: []string{"apiVersion"}},
		{missingFields: []string{"kind"}},
		{missingFields: []string{"metadata", "name"}},
	}

	for _, test := range tests {
		test := test
		name := fmt.Sprintf("patch missing %s", strings.Join(test.missingFields, "."))

		t.Run(
			name,
			func(t *testing.T) {
				t.Parallel()

				manifests := []map[string]interface{}{
					*createExConfigMap("configmap1"), *createExConfigMap("configmap2"),
				}

				patch := map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
					"metadata": map[string]interface{}{
						"name":      "configmap2",
						"namespace": "default",
						"labels": map[string]string{
							"chandler": "bing",
						},
					},
				}
				err := unstructured.SetNestedField(patch, "", test.missingFields...)
				if err != nil {
					t.Fatal(err.Error())
				}
				patches := []map[string]interface{}{patch}

				patcher := manifestPatcher{manifests: manifests, patches: patches}
				err = patcher.Validate()

				expected := fmt.Sprintf(
					`patches must have the "%s" field set to a non-empty string when there is `+
						"more than one manifest it can apply to",
					strings.Join(test.missingFields, "."),
				)
				assertEqual(t, err.Error(), expected)
			},
		)
	}
}

func TestValidatePatchInvalidSingleManifest(t *testing.T) {
	t.Parallel()

	tests := []struct{ invalidFields []string }{
		{invalidFields: []string{"apiVersion"}},
	}

	for _, test := range tests {
		test := test
		name := fmt.Sprintf("patch invalid %s", strings.Join(test.invalidFields, "."))

		t.Run(
			name,
			func(t *testing.T) {
				t.Parallel()

				manifests := []map[string]interface{}{*createExConfigMap("configmap1")}
				patch := map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
					"metadata": map[string]interface{}{
						"name":      "configmap2",
						"namespace": "default",
						"labels": map[string]string{
							"chandler": "bing",
						},
					},
				}
				err := unstructured.SetNestedField(patch, true, test.invalidFields...)
				if err != nil {
					t.Fatal(err.Error())
				}
				patches := []map[string]interface{}{patch}

				patcher := manifestPatcher{manifests: manifests, patches: patches}
				err = patcher.Validate()

				invalidFieldsStr := strings.Join(test.invalidFields, ".")
				expected := fmt.Sprintf(
					`failed to retrieve the "%s" field from the manifest of name `+
						`"configmap1" and kind "ConfigMap": .%s accessor error: true is of the type `+
						`bool, expected string`,
					invalidFieldsStr,
					invalidFieldsStr,
				)
				assertEqual(t, err.Error(), expected)
			},
		)
	}
}

func TestApplyPatches(t *testing.T) {
	t.Parallel()

	manifests := []map[string]interface{}{}
	manifests = append(
		manifests, *createExConfigMap("configmap1"), *createExConfigMap("configmap2"),
	)
	patches := []map[string]interface{}{
		{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"name":      "configmap2",
				"namespace": "default",
				"labels": map[string]string{
					"chandler": "bing",
				},
			},
		},
	}

	patcher := manifestPatcher{manifests: manifests, patches: patches}
	patchedManifests, err := patcher.ApplyPatches()

	assertEqual(t, err, nil)

	patchedManifest1 := patchedManifests[0]
	_, found, _ := unstructured.NestedStringMap(patchedManifest1, "metadata", "labels")

	assertEqual(t, found, false)

	patchedManifest2 := patchedManifests[1]
	labels, found, _ := unstructured.NestedStringMap(patchedManifest2, "metadata", "labels")

	assertEqual(t, found, true)

	expectedLabels := map[string]string{"chandler": "bing"}

	assertReflectEqual(t, labels, expectedLabels)
}

func TestApplyPatchesInvalidPatch(t *testing.T) {
	t.Parallel()

	manifests := []map[string]interface{}{}
	manifests = append(
		manifests, *createExConfigMap("configmap1"), *createExConfigMap("configmap2"),
	)
	patches := []map[string]interface{}{
		{
			"apiVersion": "v1",
			"kind":       "ToasterOven",
			"metadata": map[string]interface{}{
				"name":      "configmap2",
				"namespace": "default",
				"labels": map[string]string{
					"chandler": "bing",
				},
			},
		},
	}

	patcher := manifestPatcher{manifests: manifests, patches: patches}
	_, err := patcher.ApplyPatches()

	expected := "failed to apply the patch(es) to the manifest(s) using Kustomize: no resource " +
		"matches strategic merge patch \"ToasterOven.v1.[noGrp]/configmap2.default\": no matches " +
		"for Id ToasterOven.v1.[noGrp]/configmap2.default; failed to find unique target for patch " +
		"ToasterOven.v1.[noGrp]/configmap2.default"
	assertEqual(t, err.Error(), expected)
}
