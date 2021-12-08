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
	"path/filepath"
	"strings"

	"github.com/open-cluster-management/policy-generator-plugin/internal/expanders"
	"github.com/open-cluster-management/policy-generator-plugin/internal/types"
	"gopkg.in/yaml.v3"
)

// getManifests will get all of the manifest files associated with the input policy configuration
// separated by policyConf.Manifests entries. An error is returned if a manifest path cannot
// be read.
func getManifests(policyConf *types.PolicyConfig) ([][]map[string]interface{}, error) {
	manifests := [][]map[string]interface{}{}
	for _, manifest := range policyConf.Manifests {
		manifestPaths := []string{}
		manifestFiles := []map[string]interface{}{}
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
			// Unmarshal the manifest in order to check for metadata patch replacement
			manifestFile, err := unmarshalManifestFile(manifest.Path)
			if err != nil {
				return nil, err
			}

			if len(*manifestFile) == 0 {
				continue
			}
			// Allowing replace the original manifest metadata.name and/or metadata.namespace if it is a single
			// yaml structure in the manifest path
			if len(*manifestFile) == 1 && len(manifest.Patches) == 1 {
				if patchMetadata, ok := manifest.Patches[0]["metadata"].(map[string]interface{}); ok {
					if metadata, ok := (*manifestFile)[0]["metadata"].(map[string]interface{}); ok {
						name, ok := patchMetadata["name"].(string)
						if ok && name != "" {
							metadata["name"] = name
						}
						namespace, ok := patchMetadata["namespace"].(string)
						if ok && namespace != "" {
							metadata["namespace"] = namespace
						}
						(*manifestFile)[0]["metadata"] = metadata
					}
				}
			}

			manifestFiles = append(manifestFiles, *manifestFile...)
		}

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

		manifests = append(manifests, manifestFiles)
	}

	return manifests, nil
}

// getPolicyTemplates generates the policy templates for the ConfigurationPolicy manifests
// policyConf.ConsolidateManifests = true (default value) will generate a policy templates slice
// that just has one template which includes all the manifests specified in policyConf.
// policyConf.ConsolidateManifests = false will generate a policy templates slice
// that each template includes a single manifest specified in policyConf.
// An error is returned if one or more manifests cannot be read or are invalid.
func getPolicyTemplates(policyConf *types.PolicyConfig) ([]map[string]map[string]interface{}, error) {
	manifestGroups, err := getManifests(policyConf)
	if err != nil {
		return nil, err
	}

	objectTemplatesLength := len(manifestGroups)
	policyTemplatesLength := 1
	if !policyConf.ConsolidateManifests {
		policyTemplatesLength = len(manifestGroups)
		objectTemplatesLength = 0
	}
	objectTemplates := make([]map[string]interface{}, 0, objectTemplatesLength)
	policyTemplates := make([]map[string]map[string]interface{}, 0, policyTemplatesLength)
	for i, manifestGroup := range manifestGroups {
		complianceType := policyConf.Manifests[i].ComplianceType
		for _, manifest := range manifestGroup {
			objTemplate := map[string]interface{}{
				"complianceType":   complianceType,
				"objectDefinition": manifest,
			}
			if policyConf.ConsolidateManifests {
				// put all objTemplate with manifest into single consolidated objectTemplates object
				objectTemplates = append(objectTemplates, objTemplate)
			} else {
				// casting each objTemplate with manifest to objectTemplates type
				// build policyTemplate for each objectTemplates
				policyTemplate := buildPolicyTemplate(
					policyConf, len(policyTemplates)+1, &[]map[string]interface{}{objTemplate},
				)
				setNamespaceSelector(policyConf, policyTemplate)
				policyTemplates = append(policyTemplates, *policyTemplate)
			}
		}
	}

	if len(policyTemplates) == 0 && len(objectTemplates) == 0 {
		return nil, fmt.Errorf(
			"the policy %s must specify at least one non-empty manifest file", policyConf.Name,
		)
	}

	//  just build one policyTemplate by using the above consolidated objectTemplates
	if policyConf.ConsolidateManifests {
		policyTemplate := buildPolicyTemplate(policyConf, 1, &objectTemplates)
		setNamespaceSelector(policyConf, policyTemplate)
		policyTemplates = append(policyTemplates, *policyTemplate)
	}

	// check the enabled expanders and add additional policy templates
	for _, manifestGroup := range manifestGroups {
		expandedPolicyTemplates := handleExpanders(manifestGroup, policyConf)
		policyTemplates = append(policyTemplates, expandedPolicyTemplates...)
	}

	return policyTemplates, nil
}

// setNamespaceSelector sets the namespace selector, if set, on the input policy template.
func setNamespaceSelector(policyConf *types.PolicyConfig, policyTemplate *map[string]map[string]interface{}) {
	if policyConf.NamespaceSelector.Exclude != nil || policyConf.NamespaceSelector.Include != nil {
		(*policyTemplate)["objectDefinition"]["spec"].(map[string]interface{})["namespaceSelector"] = policyConf.NamespaceSelector
	}
}

// buildPolicyTemplate generates single policy template by using objectTemplates with manifests.
// policyNum defines which number the configuration policy is in the policy. If it is greater than
// one then the configuration policy name will have policyNum appended to it.
func buildPolicyTemplate(
	policyConf *types.PolicyConfig, policyNum int, objectTemplates *[]map[string]interface{},
) *map[string]map[string]interface{} {
	var name string
	if policyNum > 1 {
		name = fmt.Sprintf("%s%d", policyConf.Name, policyNum)
	} else {
		name = policyConf.Name
	}
	policyTemplate := map[string]map[string]interface{}{
		"objectDefinition": {
			"apiVersion": policyAPIVersion,
			"kind":       configPolicyKind,
			"metadata": map[string]string{
				"name": name,
			},
			"spec": map[string]interface{}{
				"object-templates":  *objectTemplates,
				"remediationAction": policyConf.RemediationAction,
				"severity":          policyConf.Severity,
			},
		},
	}

	return &policyTemplate
}

// handleExpanders will go through all the enabled expanders and generate additional
// policy templates to include in the policy.
func handleExpanders(
	manifests []map[string]interface{}, policyConf *types.PolicyConfig,
) []map[string]map[string]interface{} {
	policyTemplates := []map[string]map[string]interface{}{}
	for _, expander := range expanders.GetExpanders() {
		for _, m := range manifests {
			if expander.Enabled(policyConf) && expander.CanHandle(m) {
				expandedPolicyTemplates := expander.Expand(m, policyConf.Severity)
				policyTemplates = append(policyTemplates, expandedPolicyTemplates...)
			}
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

// verifyManifestPath verifies that the manifest path is in the directory tree under baseDirectory.
// An error is returned if it is not or the paths couldn't be properly resolved.
func verifyManifestPath(baseDirectory string, manifestPath string) error {
	absPath, err := filepath.Abs(manifestPath)
	if err != nil {
		return fmt.Errorf("could not resolve the manifest path %s to an absolute path", manifestPath)
	}
	absPath, err = filepath.EvalSymlinks(absPath)
	if err != nil {
		return fmt.Errorf("could not resolve symlinks to the manifest path %s", manifestPath)
	}

	relPath, err := filepath.Rel(baseDirectory, absPath)
	if err != nil {
		return fmt.Errorf(
			"could not resolve the manifest path %s to a relative path from the kustomization.yaml file",
			manifestPath,
		)
	}

	parDir := ".." + string(filepath.Separator)
	if strings.HasPrefix(relPath, parDir) || relPath == ".." {
		return fmt.Errorf(
			"the manifest path %s is not in the same directory tree as the kustomization.yaml file",
			manifestPath,
		)
	}

	return nil
}
