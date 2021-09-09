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

	"gopkg.in/yaml.v3"
)

// getPolicyTemplate generates a policy template for a ConfigurationPolicy
// that includes the manifests specified in policyConf. An error is returned
// if one or more manifests cannot be read or are invalid.
func getPolicyTemplate(policyConf *policyConfig) (
	*map[string]map[string]interface{}, error,
) {
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

		for _, manifestPath := range manifestPaths {
			manifestFile, err := unmarshalManifestFile(manifestPath)
			if err != nil {
				return nil, err
			}

			if len(*manifestFile) == 0 {
				continue
			}

			manifests = append(manifests, *manifestFile...)
		}
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

	return &policyTemplate, nil
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

	yamlDocs := []map[string]interface{}{}
	d := yaml.NewDecoder(bytes.NewReader(manifestBytes))
	for {
		var obj interface{}
		err := d.Decode(&obj)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			err = fmt.Errorf("failed to decode the manifest file at %s: %w", manifestPath, err)

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
