// Copyright Contributors to the Open Cluster Management project
package internal

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"

	"github.com/open-cluster-management/policy-generator-plugin/internal/expanders"
	"github.com/open-cluster-management/policy-generator-plugin/internal/types"
	"gopkg.in/yaml.v3"
)

// getManifests will get all of the manifest files associated with the input policy configuration.
// An error is returned if a manifest path cannot be read.
func getManifests(policyConf *types.PolicyConfig) ([]map[string]interface{}, error) {
	manifests := []map[string]interface{}{}
	for _, manifest := range policyConf.Manifests {
		manifestPaths := []string{}
		readErr := fmt.Errorf("failed to read the manifest path %s", manifest.Path)
		manifestPathInfo, err := os.Stat(manifest.Path)
		if err != nil {
			return nil, readErr
		}

		if manifestPathInfo.IsDir() {
			files, err := ioutil.ReadDir(manifest.Path)
			if err != nil {
				return nil, readErr
			}

			for _, f := range files {
				if f.IsDir() {
					continue
				}

				ext := path.Ext(f.Name())
				if ext != ".yaml" && ext != ".yml" {
					continue
				}

				yamlPath := path.Join(manifest.Path, f.Name())
				manifestPaths = append(manifestPaths, yamlPath)
			}
		} else {
			manifestPaths = append(manifestPaths, manifest.Path)
		}

		manifestFiles := []map[string]interface{}{}
		for _, manifestPath := range manifestPaths {
			manifestFile, err := unmarshalManifestFile(manifestPath)
			if err != nil {
				return nil, err
			}

			if len(*manifestFile) == 0 {
				continue
			}

			manifestFiles = append(manifestFiles, *manifestFile...)
		}

		if len(manifest.Patches) > 0 {
			patcher := manifestPatcher{manifests: manifestFiles, patches: manifest.Patches}
			const errTemplate = `failed to process the manifest at "%s": %w`
			err = patcher.Validate()
			if err != nil {
				return nil, fmt.Errorf(errTemplate, manifest.Path, err)
			}

			patchedFiles, err := patcher.ApplyPatches()
			if err != nil {
				return nil, fmt.Errorf(errTemplate, manifest.Path, err)
			}

			manifestFiles = *patchedFiles
		}

		manifests = append(manifests, manifestFiles...)
	}

	return manifests, nil
}

// getPolicyTemplates generates the policy templates for the ConfigurationPolicy manifests
// that includes the manifests specified in policyConf. An error is returned
// if one or more manifests cannot be read or are invalid.
func getPolicyTemplates(policyConf *types.PolicyConfig) ([]map[string]map[string]interface{}, error) {
	manifests, err := getManifests(policyConf)
	if err != nil {
		return nil, err
	}

	if len(manifests) == 0 {
		return nil, fmt.Errorf(
			"the policy %s must specify at least one non-empty manifest file", policyConf.Name,
		)
	}

	objectTemplates := make([]map[string]interface{}, 0, len(manifests))
	for _, manifest := range manifests {
		objTemplate := map[string]interface{}{
			"complianceType":   policyConf.ComplianceType,
			"objectDefinition": manifest,
		}
		objectTemplates = append(objectTemplates, objTemplate)
	}
	policyTemplate := map[string]map[string]interface{}{
		"objectDefinition": {
			"apiVersion": policyAPIVersion,
			"kind":       configPolicyKind,
			"metadata": map[string]string{
				"name": policyConf.Name,
			},
			"spec": map[string]interface{}{
				"object-templates":  objectTemplates,
				"remediationAction": policyConf.RemediationAction,
				"severity":          policyConf.Severity,
			},
		},
	}

	if policyConf.NamespaceSelector.Exclude != nil || policyConf.NamespaceSelector.Include != nil {
		policyTemplate["objectDefinition"]["spec"].(map[string]interface{})["namespaceSelector"] = policyConf.NamespaceSelector
	}

	policyTemplates := []map[string]map[string]interface{}{policyTemplate}
	expandedPolicyTemplates := handleExpanders(manifests, policyConf)
	policyTemplates = append(policyTemplates, expandedPolicyTemplates...)

	return policyTemplates, nil
}

// handleExpanders will go through all the enabled expanders and generate additional
// policy templates to include in the policy.
func handleExpanders(
	manifests []map[string]interface{}, policyConf *types.PolicyConfig,
) []map[string]map[string]interface{} {
	policyTemplates := []map[string]map[string]interface{}{}
	expanders := expanders.GetExpanders()
	kyvernoExpander, ok := expanders["kyverno"]
	if !ok {
		// Panic since this is a programmer error that is unrecoverable
		panic("The kyverno expander was not returned in GetExpanders")
	}

	// Not the most efficient loop but it lends itself nicely for when there are
	// additional expanders. Delete this comment when that occurs.
	for _, m := range manifests {
		if kyvernoExpander.Enabled(policyConf) && kyvernoExpander.CanHandle(m) {
			kyvernoPolicyTemplates := kyvernoExpander.Expand(m, policyConf.Severity)
			policyTemplates = append(policyTemplates, kyvernoPolicyTemplates...)
		}
	}

	return policyTemplates
}

// unmarshalManifestFile unmarshals the input object manifest/definition file into
// a slice in order to account for multiple YAML documents in the same file.
// If the file cannot be decoded or each document is not a map, an error will
// be returned.
func unmarshalManifestFile(manifestPath string) (*[]map[string]interface{}, error) {
	manifestBytes, err := ioutil.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read the manifest file %s", manifestPath)
	}

	rv, err := unmarshalManifestBytes(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode the manifest file at %s: %w", manifestPath, err)
	}

	return rv, nil
}

// unmarshalManifestBytes unmarshals the input bytes slice of an object manifest/definition file
// into a slice of maps in order to account for multiple YAML documents in the bytes slice. If each
// document is not a map, an error will be returned.
func unmarshalManifestBytes(manifestBytes []byte) (*[]map[string]interface{}, error) {
	yamlDocs := []map[string]interface{}{}
	d := yaml.NewDecoder(bytes.NewReader(manifestBytes))
	for {
		var obj interface{}
		err := d.Decode(&obj)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			// nolint:wrapcheck
			return nil, err
		}

		if _, ok := obj.(map[string]interface{}); !ok {
			err := errors.New("the input manifests must be in the format of YAML objects")

			return nil, err
		}

		yamlDocs = append(yamlDocs, obj.(map[string]interface{}))
	}

	return &yamlDocs, nil
}
