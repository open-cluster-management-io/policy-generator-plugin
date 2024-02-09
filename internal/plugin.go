// Copyright Contributors to the Open Cluster Management project
package internal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"

	"open-cluster-management.io/policy-generator-plugin/internal/types"
)

const (
	configPolicyKind           = "ConfigurationPolicy"
	policyAPIGroup             = "policy.open-cluster-management.io"
	policyAPIVersion           = policyAPIGroup + "/v1"
	policyKind                 = "Policy"
	policySetAPIVersion        = policyAPIGroup + "/v1beta1"
	policySetKind              = "PolicySet"
	placementBindingAPIVersion = policyAPIGroup + "/v1"
	placementBindingKind       = "PlacementBinding"
	placementRuleAPIVersion    = "apps.open-cluster-management.io/v1"
	placementRuleKind          = "PlacementRule"
	placementAPIVersion        = "cluster.open-cluster-management.io/v1beta1"
	placementKind              = "Placement"
	maxObjectNameLength        = 63
	dnsReference               = "https://kubernetes.io/docs/concepts/overview/working-with-objects/names/" +
		"#dns-subdomain-names"
	severityAnnotation = "policy.open-cluster-management.io/severity"
)

// Plugin is used to store the PolicyGenerator configuration and the methods to generate the
// desired policies.
type Plugin struct {
	APIVersion string `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty" yaml:"kind,omitempty"`
	Metadata   struct {
		Name string `json:"name,omitempty" yaml:"name,omitempty"`
	} `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	PlacementBindingDefaults struct {
		Name string `json:"name,omitempty" yaml:"name,omitempty"`
	} `json:"placementBindingDefaults,omitempty" yaml:"placementBindingDefaults,omitempty"`
	PolicyDefaults    types.PolicyDefaults    `json:"policyDefaults,omitempty" yaml:"policyDefaults,omitempty"`
	PolicySetDefaults types.PolicySetDefaults `json:"policySetDefaults,omitempty" yaml:"policySetDefaults,omitempty"`
	Policies          []types.PolicyConfig    `json:"policies" yaml:"policies"`
	PolicySets        []types.PolicySetConfig `json:"policySets" yaml:"policySets"`
	// A set of all placement names that have been processed or generated
	allPlcs map[string]bool
	// The base of the directory tree to restrict all manifest files to be within
	baseDirectory string
	// This is a mapping of cluster/label selectors formatted as the return value of getCsKey to
	// placement names. This is used to find common cluster/label selectors that can be consolidated
	// to a single placement.
	csToPlc      map[string]string
	outputBuffer bytes.Buffer
	// Track placement kind (we only expect to have one kind)
	usingPlR bool
	// A set of processed placements from external placements (either Placement.PlacementRulePath or
	// Placement.PlacementPath)
	processedPlcs map[string]bool
	// Track previous policy name for use if policies are being ordered
	previousPolicyName string
}

var defaults = types.PolicyDefaults{
	PolicyOptions: types.PolicyOptions{
		Categories: []string{"CM Configuration Management"},
		Controls:   []string{"CM-2 Baseline Configuration"},
		Standards:  []string{"NIST SP 800-53"},
	},
	ConfigurationPolicyOptions: types.ConfigurationPolicyOptions{
		ComplianceType:    "musthave",
		RemediationAction: "inform",
		Severity:          "low",
	},
}

// Config validates the input PolicyGenerator configuration, applies any missing defaults, and
// configures the Policy object.
func (p *Plugin) Config(config []byte, baseDirectory string) error {
	dec := yaml.NewDecoder(bytes.NewReader(config))
	dec.KnownFields(true) // emit an error on unknown fields in the input

	err := dec.Decode(p)
	const errTemplate = "the PolicyGenerator configuration file is invalid: %w"

	if err != nil {
		return fmt.Errorf(errTemplate, addFieldNotFoundHelp(err))
	}

	var unmarshaledConfig map[string]interface{}

	err = yaml.Unmarshal(config, &unmarshaledConfig)
	if err != nil {
		return fmt.Errorf(errTemplate, err)
	}

	p.applyDefaults(unmarshaledConfig)

	baseDirectory, err = filepath.EvalSymlinks(baseDirectory)
	if err != nil {
		return fmt.Errorf("failed to evaluate symlinks for the base directory: %w", err)
	}

	p.baseDirectory = baseDirectory

	return p.assertValidConfig()
}

// Generate generates the policies, placements, and placement bindings and returns them as
// a single YAML file as a byte array. An error is returned if they cannot be created.
func (p *Plugin) Generate() ([]byte, error) {
	// Set the default empty values to the fields that track state
	p.allPlcs = map[string]bool{}
	p.csToPlc = map[string]string{}
	p.outputBuffer = bytes.Buffer{}
	p.processedPlcs = map[string]bool{}

	for i := range p.Policies {
		err := p.createPolicy(&p.Policies[i])
		if err != nil {
			return nil, err
		}
	}

	for i := range p.PolicySets {
		err := p.createPolicySet(&p.PolicySets[i])
		if err != nil {
			return nil, err
		}
	}

	// Keep track of which placement maps to which policy and policySet. This will be used to determine
	// how many placement bindings are required since one binding per placement is required.
	// plcNameToPolicyAndSetIdxs[plcName]["policy"] stores the index of policy
	// plcNameToPolicyAndSetIdxs[plcName]["policyset"] stores the index of policyset
	plcNameToPolicyAndSetIdxs := map[string]map[string][]int{}

	for i := range p.Policies {
		// only generate placement when GeneratePlacementWhenInSet equals to true, GeneratePlacement is true,
		// or policy is not part of any policy sets
		if p.Policies[i].GeneratePlacementWhenInSet ||
			(p.Policies[i].GeneratePolicyPlacement && len(p.Policies[i].PolicySets) == 0) {
			plcName, err := p.createPolicyPlacement(p.Policies[i].Placement, p.Policies[i].Name)
			if err != nil {
				return nil, err
			}

			if plcNameToPolicyAndSetIdxs[plcName] == nil {
				plcNameToPolicyAndSetIdxs[plcName] = map[string][]int{}
			}

			plcNameToPolicyAndSetIdxs[plcName]["policy"] = append(plcNameToPolicyAndSetIdxs[plcName]["policy"], i)
		}
	}

	for i := range p.PolicySets {
		// only generate placement when GeneratePolicySetPlacement equals to true
		if p.PolicySets[i].GeneratePolicySetPlacement {
			plcName, err := p.createPolicySetPlacement(p.PolicySets[i].Placement, p.PolicySets[i].Name)
			if err != nil {
				return nil, err
			}

			if plcNameToPolicyAndSetIdxs[plcName] == nil {
				plcNameToPolicyAndSetIdxs[plcName] = map[string][]int{}
			}

			plcNameToPolicyAndSetIdxs[plcName]["policyset"] = append(plcNameToPolicyAndSetIdxs[plcName]["policyset"], i)
		}
	}

	// Sort the keys of plcNameToPolicyseetsIdxs so that the policy bindings are generated in a
	// consistent order.
	plcNames := make([]string, len(plcNameToPolicyAndSetIdxs))
	i := 0

	for k := range plcNameToPolicyAndSetIdxs {
		plcNames[i] = k
		i++
	}

	sort.Strings(plcNames)

	plcBindingCount := 0

	for _, plcName := range plcNames {
		// Determine which policies and policy sets to be included in the placement binding.
		policyConfs := []*types.PolicyConfig{}
		for _, i := range plcNameToPolicyAndSetIdxs[plcName]["policy"] {
			policyConfs = append(policyConfs, &p.Policies[i])
		}

		policySetConfs := []*types.PolicySetConfig{}
		for _, i := range plcNameToPolicyAndSetIdxs[plcName]["policyset"] {
			policySetConfs = append(policySetConfs, &p.PolicySets[i])
		}

		// If there is more than one policy associated with a placement but no default binding name
		// specified, throw an error
		if (len(policyConfs) > 1 || len(policySetConfs) > 1) && p.PlacementBindingDefaults.Name == "" {
			return nil, fmt.Errorf(
				"placementBindingDefaults.name must be set but is empty (multiple policies or policy sets were found "+
					"for the PlacementBinding to placement %s)",
				plcName,
			)
		}

		var bindingName string

		existMultiple := false

		// If there is only one policy or one policy set, use the policy or policy set name if there is no default
		// binding name specified
		if len(policyConfs) == 1 && len(policySetConfs) == 0 {
			bindingName = "binding-" + policyConfs[0].Name
		} else if len(policyConfs) == 0 && len(policySetConfs) == 0 {
			bindingName = "binding-" + policySetConfs[0].Name
		} else {
			existMultiple = true
		}
		// If there are multiple policies or policy sets, use the default placement binding name
		// but append a number to it so it's a unique name.
		if p.PlacementBindingDefaults.Name != "" && existMultiple {
			plcBindingCount++
			if plcBindingCount == 1 {
				bindingName = p.PlacementBindingDefaults.Name
			} else {
				bindingName = fmt.Sprintf("%s%d", p.PlacementBindingDefaults.Name, plcBindingCount)
			}
		}

		err := p.createPlacementBinding(bindingName, plcName, policyConfs, policySetConfs)
		if err != nil {
			return nil, fmt.Errorf("failed to create a placement binding: %w", err)
		}
	}

	return p.outputBuffer.Bytes(), nil
}

func getPolicyDefaultBool(config map[string]interface{}, key string) (value bool, set bool) {
	return getDefaultBool(config, "policyDefaults", key)
}

func getPolicySetDefaultBool(config map[string]interface{}, key string) (value bool, set bool) {
	return getDefaultBool(config, "policySetDefaults", key)
}

func getDefaultBool(config map[string]interface{}, defaultKey string, key string) (value bool, set bool) {
	defaults, ok := config[defaultKey].(map[string]interface{})
	if ok {
		value, set = defaults[key].(bool)

		return
	}

	return false, false
}

func getPolicyBool(
	config map[string]interface{}, policyIndex int, key string,
) (value bool, set bool) {
	policy := getPolicy(config, policyIndex)
	if policy == nil {
		return false, false
	}

	value, set = policy[key].(bool)

	return
}

func getPolicySetBool(
	config map[string]interface{}, policySetIndex int, key string,
) (value bool, set bool) {
	policySet := getPolicySet(config, policySetIndex)
	if policySet == nil {
		return false, false
	}

	value, set = policySet[key].(bool)

	return
}

func getArrayObject(config map[string]interface{}, key string, idx int) map[string]interface{} {
	array, ok := config[key].([]interface{})
	if !ok {
		return nil
	}

	if len(array)-1 < idx {
		return nil
	}

	object, ok := array[idx].(map[string]interface{})
	if !ok {
		return nil
	}

	return object
}

// getPolicy will return a policy at the specified index in the Policy Generator configuration YAML.
func getPolicy(config map[string]interface{}, policyIndex int) map[string]interface{} {
	return getArrayObject(config, "policies", policyIndex)
}

// getPolicySet will return a policy at the specified index in the Policy Generator configuration YAML.
func getPolicySet(config map[string]interface{}, policySetIndex int) map[string]interface{} {
	return getArrayObject(config, "policySets", policySetIndex)
}

// getEvaluationInterval will return the evaluation interval of specified policy in the Policy Generator configuration
// YAML.
func isEvaluationIntervalSet(config map[string]interface{}, policyIndex int, complianceType string) bool {
	policy := getPolicy(config, policyIndex)
	if policy == nil {
		return false
	}

	evaluationInterval, ok := policy["evaluationInterval"].(map[string]interface{})
	if !ok {
		return false
	}

	_, set := evaluationInterval[complianceType].(string)

	return set
}

// isEvaluationIntervalSetManifest will return whether the evaluation interval of the specified manifest
// of the specified policy is set in the Policy Generator configuration YAML.
func isEvaluationIntervalSetManifest(
	config map[string]interface{}, policyIndex int, manifestIndex int, complianceType string,
) bool {
	policy := getPolicy(config, policyIndex)
	if policy == nil {
		return false
	}

	manifests, ok := policy["manifests"].([]interface{})
	if !ok {
		return false
	}

	if len(manifests)-1 < manifestIndex {
		return false
	}

	manifest, ok := manifests[manifestIndex].(map[string]interface{})
	if !ok {
		return false
	}

	evaluationInterval, ok := manifest["evaluationInterval"].(map[string]interface{})
	if !ok {
		return false
	}

	_, set := evaluationInterval[complianceType].(string)

	return set
}

func isPolicyFieldSet(config map[string]interface{}, policyIndex int, field string) bool {
	policy := getPolicy(config, policyIndex)
	if policy == nil {
		return false
	}

	_, set := policy[field]

	return set
}

func isManifestFieldSet(config map[string]interface{}, policyIdx, manifestIdx int, field string) bool {
	policy := getPolicy(config, policyIdx)
	if policy == nil {
		return false
	}

	manifests, ok := policy["manifests"].([]interface{})
	if !ok {
		return false
	}

	if len(manifests)-1 < manifestIdx {
		return false
	}

	manifest, ok := manifests[manifestIdx].(map[string]interface{})
	if !ok {
		return false
	}

	_, set := manifest[field]

	return set
}

// applyDefaults applies any missing defaults under Policy.PlacementBindingDefaults,
// Policy.PolicyDefaults and PolicySets. It then applies the defaults and user provided
// defaults on each policy and policyset entry if they are not overridden by the user. The
// input unmarshaledConfig is used in situations where it is necessary to know if an explicit
// false is provided rather than rely on the default Go value on the Plugin struct.
func (p *Plugin) applyDefaults(unmarshaledConfig map[string]interface{}) {
	if len(p.Policies) == 0 {
		return
	}

	// Set defaults to the defaults that aren't overridden
	if p.PolicyDefaults.Categories == nil {
		p.PolicyDefaults.Categories = defaults.Categories
	}

	if p.PolicyDefaults.ComplianceType == "" {
		p.PolicyDefaults.ComplianceType = defaults.ComplianceType
	}

	if p.PolicyDefaults.Controls == nil {
		p.PolicyDefaults.Controls = defaults.Controls
	}

	cpmValue, setCPM := getPolicyDefaultBool(unmarshaledConfig, "copyPolicyMetadata")
	if setCPM {
		p.PolicyDefaults.CopyPolicyMetadata = cpmValue
	} else {
		p.PolicyDefaults.CopyPolicyMetadata = true
	}

	// Policy expanders default to true unless explicitly set in the config.
	// Gatekeeper policy expander policyDefault
	igvValue, setIgv := getPolicyDefaultBool(unmarshaledConfig, "informGatekeeperPolicies")
	if setIgv {
		p.PolicyDefaults.InformGatekeeperPolicies = igvValue
	} else {
		p.PolicyDefaults.InformGatekeeperPolicies = true
	}
	// Kyverno policy expander policyDefault
	ikvValue, setIkv := getPolicyDefaultBool(unmarshaledConfig, "informKyvernoPolicies")
	if setIkv {
		p.PolicyDefaults.InformKyvernoPolicies = ikvValue
	} else {
		p.PolicyDefaults.InformKyvernoPolicies = true
	}

	consolidatedValue, setConsolidated := getPolicyDefaultBool(unmarshaledConfig, "consolidateManifests")
	if setConsolidated {
		p.PolicyDefaults.ConsolidateManifests = consolidatedValue
	} else if p.PolicyDefaults.OrderManifests {
		p.PolicyDefaults.ConsolidateManifests = false
	} else {
		p.PolicyDefaults.ConsolidateManifests = true
	}

	if p.PolicyDefaults.RemediationAction == "" {
		p.PolicyDefaults.RemediationAction = defaults.RemediationAction
	}

	if p.PolicyDefaults.Severity == "" {
		p.PolicyDefaults.Severity = defaults.Severity
	}

	if p.PolicyDefaults.Standards == nil {
		p.PolicyDefaults.Standards = defaults.Standards
	}

	// GeneratePolicyPlacement defaults to true unless explicitly set in the config.
	gppValue, setGpp := getPolicyDefaultBool(unmarshaledConfig, "generatePolicyPlacement")
	if setGpp {
		p.PolicyDefaults.GeneratePolicyPlacement = gppValue
	} else {
		p.PolicyDefaults.GeneratePolicyPlacement = true
	}

	// Generate temporary sets to later merge the policy sets declared in p.Policies[*] and p.PolicySets
	plcsetToPlc := make(map[string]map[string]bool)
	plcToPlcset := make(map[string]map[string]bool)

	for _, plcset := range p.PolicySets {
		if plcsetToPlc[plcset.Name] == nil {
			plcsetToPlc[plcset.Name] = make(map[string]bool)
		}

		for _, plc := range plcset.Policies {
			plcsetToPlc[plcset.Name][plc] = true

			if plcToPlcset[plc] == nil {
				plcToPlcset[plc] = make(map[string]bool)
			}

			plcToPlcset[plc][plcset.Name] = true
		}
	}

	applyDefaultDependencyFields(p.PolicyDefaults.Dependencies, p.PolicyDefaults.Namespace)
	applyDefaultDependencyFields(p.PolicyDefaults.ExtraDependencies, p.PolicyDefaults.Namespace)

	for i := range p.Policies {
		policy := &p.Policies[i]

		if policy.PolicyAnnotations == nil {
			annotations := map[string]string{}
			for k, v := range p.PolicyDefaults.PolicyAnnotations {
				annotations[k] = v
			}

			policy.PolicyAnnotations = annotations
		}

		if policy.PolicyLabels == nil {
			labels := map[string]string{}
			for k, v := range p.PolicyDefaults.PolicyLabels {
				labels[k] = v
			}

			policy.PolicyLabels = labels
		}

		if policy.Categories == nil {
			policy.Categories = p.PolicyDefaults.Categories
		}

		if policy.ConfigurationPolicyAnnotations == nil {
			annotations := map[string]string{}
			for k, v := range p.PolicyDefaults.ConfigurationPolicyAnnotations {
				annotations[k] = v
			}

			policy.ConfigurationPolicyAnnotations = annotations
		}

		cpmValue, setCpm := getPolicyBool(unmarshaledConfig, i, "copyPolicyMetadata")
		if setCpm {
			policy.CopyPolicyMetadata = cpmValue
		} else {
			policy.CopyPolicyMetadata = p.PolicyDefaults.CopyPolicyMetadata
		}

		if policy.Standards == nil {
			policy.Standards = p.PolicyDefaults.Standards
		}

		if policy.Controls == nil {
			policy.Controls = p.PolicyDefaults.Controls
		}

		if policy.Description == "" {
			policy.Description = p.PolicyDefaults.Description
		}

		if policy.RecordDiff == "" {
			policy.RecordDiff = p.PolicyDefaults.RecordDiff
		}

		if policy.ComplianceType == "" {
			policy.ComplianceType = p.PolicyDefaults.ComplianceType
		}

		if policy.MetadataComplianceType == "" {
			policy.MetadataComplianceType = p.PolicyDefaults.MetadataComplianceType
		}

		// Only use the policyDefault evaluationInterval value when it's not explicitly set on the policy.
		if policy.EvaluationInterval.Compliant == "" {
			set := isEvaluationIntervalSet(unmarshaledConfig, i, "compliant")
			if !set {
				policy.EvaluationInterval.Compliant = p.PolicyDefaults.EvaluationInterval.Compliant
			}
		}

		if policy.EvaluationInterval.NonCompliant == "" {
			set := isEvaluationIntervalSet(unmarshaledConfig, i, "noncompliant")
			if !set {
				policy.EvaluationInterval.NonCompliant = p.PolicyDefaults.EvaluationInterval.NonCompliant
			}
		}

		if policy.PruneObjectBehavior == "" {
			policy.PruneObjectBehavior = p.PolicyDefaults.PruneObjectBehavior
		}

		if policy.PolicySets == nil {
			policy.PolicySets = p.PolicyDefaults.PolicySets
		}

		// GeneratePolicyPlacement defaults to true unless explicitly set in the config.
		gppValue, setGpp := getPolicyBool(unmarshaledConfig, i, "generatePolicyPlacement")
		if setGpp {
			policy.GeneratePolicyPlacement = gppValue
		} else {
			policy.GeneratePolicyPlacement = p.PolicyDefaults.GeneratePolicyPlacement
		}

		// GeneratePlacementWhenInSet defaults to false unless explicitly set in the config.
		gpsetValue, setGpset := getPolicyBool(unmarshaledConfig, i, "generatePlacementWhenInSet")
		if setGpset {
			policy.GeneratePlacementWhenInSet = gpsetValue
		} else {
			policy.GeneratePlacementWhenInSet = p.PolicyDefaults.GeneratePlacementWhenInSet
		}

		// Policy expanders default to the policy default unless explicitly set.
		// Gatekeeper policy expander policy override
		igvValue, setIgv := getPolicyBool(unmarshaledConfig, i, "informGatekeeperPolicies")
		if setIgv {
			policy.InformGatekeeperPolicies = igvValue
		} else {
			policy.InformGatekeeperPolicies = p.PolicyDefaults.InformGatekeeperPolicies
		}
		// Kyverno policy expander policy override
		ikvValue, setIkv := getPolicyBool(unmarshaledConfig, i, "informKyvernoPolicies")
		if setIkv {
			policy.InformKyvernoPolicies = ikvValue
		} else {
			policy.InformKyvernoPolicies = p.PolicyDefaults.InformKyvernoPolicies
		}

		if !isPolicyFieldSet(unmarshaledConfig, i, "orderManifests") {
			policy.OrderManifests = p.PolicyDefaults.OrderManifests
		}

		consolidatedValue, setConsolidated := getPolicyBool(unmarshaledConfig, i, "consolidateManifests")
		if setConsolidated {
			policy.ConsolidateManifests = consolidatedValue
		} else if policy.OrderManifests {
			policy.ConsolidateManifests = false
		} else {
			policy.ConsolidateManifests = p.PolicyDefaults.ConsolidateManifests
		}

		disabledValue, setDisabled := getPolicyBool(unmarshaledConfig, i, "disabled")
		if setDisabled {
			policy.Disabled = disabledValue
		} else {
			policy.Disabled = p.PolicyDefaults.Disabled
		}

		ignorePending, ignorePendingIsSet := getPolicyBool(unmarshaledConfig, i, "ignorePending")
		if ignorePendingIsSet {
			policy.IgnorePending = ignorePending
		} else {
			policy.IgnorePending = p.PolicyDefaults.IgnorePending
		}

		if isPolicyFieldSet(unmarshaledConfig, i, "dependencies") {
			applyDefaultDependencyFields(policy.Dependencies, p.PolicyDefaults.Namespace)
		} else {
			policy.Dependencies = p.PolicyDefaults.Dependencies
		}

		if isPolicyFieldSet(unmarshaledConfig, i, "extraDependencies") {
			applyDefaultDependencyFields(policy.ExtraDependencies, p.PolicyDefaults.Namespace)
		} else {
			policy.ExtraDependencies = p.PolicyDefaults.ExtraDependencies
		}

		applyDefaultPlacementFields(&policy.Placement, p.PolicyDefaults.Placement)

		// Only use defaults when the namespaceSelector is not set on the policy
		nsSelector := policy.NamespaceSelector
		defNsSelector := p.PolicyDefaults.NamespaceSelector

		if nsSelector.Exclude == nil && nsSelector.Include == nil &&
			nsSelector.MatchLabels == nil && nsSelector.MatchExpressions == nil {
			policy.NamespaceSelector = defNsSelector
		}

		if policy.RemediationAction == "" {
			policy.RemediationAction = p.PolicyDefaults.RemediationAction
		}

		if policy.Severity == "" {
			policy.Severity = p.PolicyDefaults.Severity
		}

		for j := range policy.Manifests {
			manifest := &policy.Manifests[j]

			// Only use the policy's ConfigurationPolicyOptions values when they're not explicitly set in
			// the manifest.
			if manifest.ComplianceType == "" {
				manifest.ComplianceType = policy.ComplianceType
			}

			if manifest.MetadataComplianceType == "" {
				manifest.MetadataComplianceType = policy.MetadataComplianceType
			}

			if manifest.EvaluationInterval.Compliant == "" {
				set := isEvaluationIntervalSetManifest(unmarshaledConfig, i, j, "compliant")
				if !set {
					manifest.EvaluationInterval.Compliant = policy.EvaluationInterval.Compliant
				}
			}

			if manifest.EvaluationInterval.NonCompliant == "" {
				set := isEvaluationIntervalSetManifest(unmarshaledConfig, i, j, "noncompliant")
				if !set {
					manifest.EvaluationInterval.NonCompliant = policy.EvaluationInterval.NonCompliant
				}
			}

			selector := manifest.NamespaceSelector
			if selector.Exclude == nil && selector.Include == nil &&
				selector.MatchLabels == nil && selector.MatchExpressions == nil {
				manifest.NamespaceSelector = policy.NamespaceSelector
			}

			if manifest.RemediationAction == "" && policy.RemediationAction != "" {
				manifest.RemediationAction = policy.RemediationAction
			}

			if manifest.PruneObjectBehavior == "" && policy.PruneObjectBehavior != "" {
				manifest.PruneObjectBehavior = policy.PruneObjectBehavior
			}

			if manifest.Severity == "" && policy.Severity != "" {
				manifest.Severity = policy.Severity
			}

			if manifest.RecordDiff == "" {
				manifest.RecordDiff = policy.RecordDiff
			}

			if isManifestFieldSet(unmarshaledConfig, i, j, "extraDependencies") {
				applyDefaultDependencyFields(manifest.ExtraDependencies, p.PolicyDefaults.Namespace)
			} else {
				manifest.ExtraDependencies = policy.ExtraDependencies
			}

			if !isManifestFieldSet(unmarshaledConfig, i, j, "ignorePending") {
				manifest.IgnorePending = policy.IgnorePending
			}
		}

		for _, plcsetInPlc := range policy.PolicySets {
			if _, ok := plcsetToPlc[plcsetInPlc]; !ok {
				newPlcset := types.PolicySetConfig{
					Name: plcsetInPlc,
				}
				p.PolicySets = append(p.PolicySets, newPlcset)
				plcsetToPlc[plcsetInPlc] = make(map[string]bool)
			}

			if plcToPlcset[policy.Name] == nil {
				plcToPlcset[policy.Name] = make(map[string]bool)
			}

			plcToPlcset[policy.Name][plcsetInPlc] = true

			plcsetToPlc[plcsetInPlc][policy.Name] = true
		}

		policy.PolicySets = make([]string, 0, len(plcToPlcset[policy.Name]))

		for plcset := range plcToPlcset[policy.Name] {
			policy.PolicySets = append(policy.PolicySets, plcset)
		}
	}

	gpspValue, setGpsp := getPolicySetDefaultBool(unmarshaledConfig, "generatePolicySetPlacement")
	if setGpsp {
		p.PolicySetDefaults.GeneratePolicySetPlacement = gpspValue
	} else {
		p.PolicySetDefaults.GeneratePolicySetPlacement = true
	}

	// Sync up the declared policy sets in p.Policies[*]
	for i := range p.PolicySets {
		plcset := &p.PolicySets[i]
		plcset.Policies = make([]string, 0, len(plcsetToPlc[plcset.Name]))

		for plc := range plcsetToPlc[plcset.Name] {
			plcset.Policies = append(plcset.Policies, plc)
		}

		// GeneratePolicySetPlacement defaults to true unless explicitly set in the config.
		gpspValue, setGpsp := getPolicySetBool(unmarshaledConfig, i, "generatePolicySetPlacement")
		if setGpsp {
			plcset.GeneratePolicySetPlacement = gpspValue
		} else {
			plcset.GeneratePolicySetPlacement = p.PolicySetDefaults.GeneratePolicySetPlacement
		}

		applyDefaultPlacementFields(&plcset.Placement, p.PolicySetDefaults.Placement)

		// Sort alphabetically to make it deterministic
		sort.Strings(plcset.Policies)
	}
}

func applyDefaultDependencyFields(deps []types.PolicyDependency, namespace string) {
	for i, dep := range deps {
		if dep.Kind == "" {
			deps[i].Kind = policyKind
		}

		if dep.APIVersion == "" {
			deps[i].APIVersion = policyAPIVersion
		}

		if dep.Namespace == "" && deps[i].Kind == policyKind {
			deps[i].Namespace = namespace
		}

		if dep.Compliance == "" {
			deps[i].Compliance = "Compliant"
		}
	}
}

// applyDefaultPlacementFields is a helper for applyDefaults that handles default Placement configuration
func applyDefaultPlacementFields(placement *types.PlacementConfig, defaultPlacement types.PlacementConfig) {
	// Determine whether defaults are set for placement
	plcDefaultSet := len(defaultPlacement.LabelSelector) != 0 ||
		defaultPlacement.PlacementPath != "" ||
		defaultPlacement.PlacementName != ""
	plrDefaultSet := len(defaultPlacement.ClusterSelectors) != 0 ||
		len(defaultPlacement.ClusterSelector) != 0 ||
		defaultPlacement.PlacementRulePath != "" ||
		defaultPlacement.PlacementRuleName != ""

	// If both cluster label selectors and placement path/name aren't set, then use the defaults with a
	// priority on placement path followed by placement name.
	if len(placement.LabelSelector) == 0 &&
		placement.PlacementPath == "" &&
		placement.PlacementName == "" &&
		plcDefaultSet {
		if defaultPlacement.PlacementPath != "" {
			placement.PlacementPath = defaultPlacement.PlacementPath
		} else if defaultPlacement.PlacementName != "" {
			placement.PlacementName = defaultPlacement.PlacementName
		} else if len(defaultPlacement.LabelSelector) > 0 {
			placement.LabelSelector = defaultPlacement.LabelSelector
		}
	} else if len(placement.ClusterSelectors) == 0 &&
		// Else if both cluster selectors and placement rule path/name aren't set, then use the defaults with a
		// priority on placement rule path followed by placement rule name.
		len(placement.ClusterSelector) == 0 &&
		placement.PlacementRulePath == "" &&
		placement.PlacementRuleName == "" &&
		plrDefaultSet {
		if defaultPlacement.PlacementRulePath != "" {
			placement.PlacementRulePath = defaultPlacement.PlacementRulePath
		} else if defaultPlacement.PlacementRuleName != "" {
			placement.PlacementRuleName = defaultPlacement.PlacementRuleName
		} else if len(defaultPlacement.ClusterSelectors) > 0 {
			placement.ClusterSelectors = defaultPlacement.ClusterSelectors
		} else if len(defaultPlacement.ClusterSelector) > 0 {
			placement.ClusterSelector = defaultPlacement.ClusterSelector
		}
	}
}

// assertValidConfig verifies that the user provided configuration has all the
// required fields. Note that this should be run only after applyDefaults is run.
func (p *Plugin) assertValidConfig() error {
	if p.PolicyDefaults.Namespace == "" {
		return errors.New("policyDefaults.namespace is empty but it must be set")
	}

	// Validate default policy placement settings
	err := p.assertValidPlacement(p.PolicyDefaults.Placement, "policyDefaults", nil)
	if err != nil {
		return err
	}

	// validate placement binding names are DNS compliant
	if p.PlacementBindingDefaults.Name != "" &&
		len(validation.IsDNS1123Subdomain(p.PlacementBindingDefaults.Name)) > 0 {
		return fmt.Errorf(
			"PlacementBindingDefaults.Name `%s` is not DNS compliant. See %s",
			p.PlacementBindingDefaults.Name,
			dnsReference,
		)
	}

	if len(p.Policies) == 0 {
		return errors.New("policies is empty but it must be set")
	}

	if p.PolicyDefaults.OrderPolicies && len(p.PolicyDefaults.Dependencies) != 0 {
		return errors.New("policyDefaults must specify only one of dependencies or orderPolicies")
	}

	for i, dep := range p.PolicyDefaults.Dependencies {
		if dep.Name == "" {
			return fmt.Errorf("dependency name must be set in policyDefaults dependency %v", i)
		}
	}

	if p.PolicyDefaults.OrderManifests && p.PolicyDefaults.ConsolidateManifests {
		return errors.New("policyDefaults may not specify both consolidateManifests and orderManifests")
	}

	if len(p.PolicyDefaults.ExtraDependencies) > 0 && p.PolicyDefaults.OrderManifests {
		return errors.New("policyDefaults may not specify both extraDependencies and orderManifests")
	}

	for i, dep := range p.PolicyDefaults.ExtraDependencies {
		if dep.Name == "" {
			return fmt.Errorf("extraDependency name must be set in policyDefaults extraDependency %v", i)
		}
	}

	seenPlc := map[string]bool{}
	plCount := struct {
		plc int
		plr int
	}{}

	for i := range p.Policies {
		policy := &p.Policies[i]
		if policy.Name == "" {
			return fmt.Errorf(
				"each policy must have a name set, but did not find a name at policy array index %d", i,
			)
		}

		if len(validation.IsDNS1123Subdomain(policy.Name)) > 0 {
			return fmt.Errorf(
				"policy name `%s` is not DNS compliant. See %s", policy.Name, dnsReference,
			)
		}

		if seenPlc[policy.Name] {
			return fmt.Errorf(
				"each policy must have a unique name set, but found a duplicate name: %s", policy.Name,
			)
		}

		seenPlc[policy.Name] = true

		if len(p.PolicyDefaults.Namespace+"."+policy.Name) > maxObjectNameLength {
			return fmt.Errorf("the policy namespace and name cannot be more than 63 characters: %s.%s",
				p.PolicyDefaults.Namespace, policy.Name)
		}

		if policy.EvaluationInterval.Compliant != "" && policy.EvaluationInterval.Compliant != "never" {
			_, err := time.ParseDuration(policy.EvaluationInterval.Compliant)
			if err != nil {
				return fmt.Errorf(
					"the policy %s has an invalid policy.evaluationInterval.compliant value: %w", policy.Name, err,
				)
			}
		}

		if policy.EvaluationInterval.NonCompliant != "" && policy.EvaluationInterval.NonCompliant != "never" {
			_, err := time.ParseDuration(policy.EvaluationInterval.NonCompliant)
			if err != nil {
				return fmt.Errorf(
					"the policy %s has an invalid policy.evaluationInterval.noncompliant value: %w", policy.Name, err,
				)
			}
		}

		if len(policy.Manifests) == 0 {
			return fmt.Errorf(
				"each policy must have at least one manifest, but found none in policy %s", policy.Name,
			)
		}

		if len(policy.Dependencies) > 0 && p.PolicyDefaults.OrderPolicies {
			return fmt.Errorf(
				"dependencies may not be set in policy %v when policyDefaults.orderPolicies is true", policy.Name,
			)
		}

		for x, dep := range policy.Dependencies {
			if dep.Name == "" {
				return fmt.Errorf("dependency name must be set in policy %v dependency %v", policy.Name, x)
			}
		}

		if policy.ConsolidateManifests && policy.OrderManifests {
			return fmt.Errorf("policy %v may not set orderManifests when consolidateManifests is true", policy.Name)
		}

		if len(policy.ExtraDependencies) > 0 && policy.OrderManifests {
			return fmt.Errorf("extraDependencies may not be set in policy %v when orderManifests is true", policy.Name)
		}

		for x, dep := range policy.ExtraDependencies {
			if dep.Name == "" {
				return fmt.Errorf("extraDependency name must be set in policy %v extraDependency %v", policy.Name, x)
			}
		}

		for j := range policy.Manifests {
			manifest := &policy.Manifests[j]

			if manifest.Path == "" {
				return fmt.Errorf(
					"each policy manifest entry must have path set, but did not find a path in policy %s",
					policy.Name,
				)
			}

			_, err := os.Stat(manifest.Path)
			if err != nil {
				return fmt.Errorf(
					"could not read the manifest path %s in policy %s", manifest.Path, policy.Name,
				)
			}

			err = verifyManifestPath(p.baseDirectory, manifest.Path)
			if err != nil {
				return err
			}

			evalInterval := manifest.EvaluationInterval

			// Verify that consolidated manifests fields match that of the policy configuration.
			if policy.ConsolidateManifests {
				errorMsgFmt := fmt.Sprintf(
					"the policy %s has the %%s value set on manifest[%d] but consolidateManifests is true",
					policy.Name, j,
				)

				if !reflect.DeepEqual(evalInterval, policy.EvaluationInterval) {
					return fmt.Errorf(errorMsgFmt, "evaluationInterval")
				}

				if !reflect.DeepEqual(manifest.NamespaceSelector, policy.NamespaceSelector) {
					return fmt.Errorf(errorMsgFmt, "namespaceSelector")
				}

				if manifest.PruneObjectBehavior != policy.PruneObjectBehavior {
					return fmt.Errorf(errorMsgFmt, "pruneObjectBehavior")
				}

				if manifest.RemediationAction != policy.RemediationAction {
					return fmt.Errorf(errorMsgFmt, "remediationAction")
				}

				if manifest.Severity != policy.Severity {
					return fmt.Errorf(errorMsgFmt, "severity")
				}

				if !reflect.DeepEqual(manifest.ExtraDependencies, policy.ExtraDependencies) {
					return fmt.Errorf(errorMsgFmt, "extraDependencies")
				}

				if manifest.IgnorePending != policy.IgnorePending {
					return fmt.Errorf(errorMsgFmt, "ignorePending")
				}
			}

			if evalInterval.Compliant != "" && evalInterval.Compliant != "never" {
				_, err := time.ParseDuration(evalInterval.Compliant)
				if err != nil {
					return fmt.Errorf(
						"the policy %s has an invalid policy.evaluationInterval.manifest[%d].compliant value: %w",
						policy.Name,
						j,
						err,
					)
				}
			}

			if evalInterval.NonCompliant != "" && evalInterval.NonCompliant != "never" {
				_, err := time.ParseDuration(evalInterval.NonCompliant)
				if err != nil {
					return fmt.Errorf(
						"the policy %s has an invalid policy.evaluationInterval.manifest[%d].noncompliant value: %w",
						policy.Name,
						j,
						err,
					)
				}
			}

			if len(manifest.ExtraDependencies) > 0 && policy.OrderManifests {
				return fmt.Errorf(
					"extraDependencies may not be set in policy %v manifest[%d] because orderManifests is set",
					policy.Name,
					j,
				)
			}

			for x, dep := range manifest.ExtraDependencies {
				if dep.Name == "" {
					return fmt.Errorf(
						"extraDependency name must be set in policy %v manifest[%d] extraDependency %v",
						policy.Name, j, x)
				}
			}
		}

		err := p.assertValidPlacement(policy.Placement, fmt.Sprintf("policy %s", policy.Name), &plCount)
		if err != nil {
			return err
		}
	}

	// Validate default policy set placement settings
	err = p.assertValidPlacement(p.PolicySetDefaults.Placement, "policySetDefaults", nil)
	if err != nil {
		return err
	}

	seenPlcset := map[string]bool{}

	for i := range p.PolicySets {
		plcset := &p.PolicySets[i]

		if plcset.Name == "" {
			return fmt.Errorf(
				"each policySet must have a name set, but did not find a name at policySet array index %d", i,
			)
		}

		if len(validation.IsDNS1123Subdomain(plcset.Name)) > 0 {
			return fmt.Errorf(
				"policy set name `%s` is not DNS compliant. See %s", plcset.Name, dnsReference,
			)
		}

		if seenPlcset[plcset.Name] {
			return fmt.Errorf(
				"each policySet must have a unique name set, but found a duplicate name: %s", plcset.Name,
			)
		}

		seenPlcset[plcset.Name] = true

		// Validate policy set Placement settings
		err := p.assertValidPlacement(plcset.Placement, fmt.Sprintf("policySet %s", plcset.Name), &plCount)
		if err != nil {
			return err
		}
	}

	// Validate only one type of placement kind is in use
	if plCount.plc != 0 && plCount.plr != 0 {
		return fmt.Errorf(
			"may not use a mix of Placement and PlacementRule for policies and policysets; found %d Placement and "+
				"%d PlacementRule",
			plCount.plc, plCount.plr,
		)
	}

	p.usingPlR = plCount.plr != 0

	return nil
}

// assertValidPlacement is a helper for assertValidConfig to verify placement configurations
func (p *Plugin) assertValidPlacement(
	placement types.PlacementConfig,
	path string,
	plCount *struct {
		plc int
		plr int
	},
) error {
	if placement.PlacementRulePath != "" && placement.PlacementPath != "" {
		return fmt.Errorf(
			"%s must provide only one of placement.placementPath or placement.placementRulePath", path,
		)
	}

	if (len(placement.ClusterSelectors) > 0 || len(placement.ClusterSelector) > 0) &&
		len(placement.LabelSelector) > 0 {
		return fmt.Errorf(
			"%s must provide only one of placement.labelSelector or placement.clusterSelectors", path,
		)
	}

	if placement.PlacementRuleName != "" && placement.PlacementName != "" {
		return fmt.Errorf(
			"%s must provide only one of placement.placementName or placement.placementRuleName", path,
		)
	}

	placementOptionCount := 0
	if len(placement.LabelSelector) != 0 || len(placement.ClusterSelectors) != 0 ||
		len(placement.ClusterSelector) != 0 {
		placementOptionCount++
	}

	if placement.PlacementRulePath != "" || placement.PlacementPath != "" {
		placementOptionCount++
	}

	if placement.PlacementRuleName != "" || placement.PlacementName != "" {
		placementOptionCount++
	}

	if placementOptionCount > 1 {
		return fmt.Errorf(
			"%s must specify only one of placement selector, placement path, or placement name", path,
		)
	}

	// validate placement names are DNS compliant
	defPlrName := placement.PlacementRuleName
	if defPlrName != "" && len(validation.IsDNS1123Subdomain(defPlrName)) > 0 {
		return fmt.Errorf(
			"%s placement.placementRuleName placement name `%s` is not DNS compliant. See %s",
			path,
			defPlrName,
			dnsReference,
		)
	}

	defPlcmtPlName := placement.PlacementName
	if defPlcmtPlName != "" && len(validation.IsDNS1123Subdomain(defPlcmtPlName)) > 0 {
		return fmt.Errorf(
			"%s placement.placementName `%s` is not DNS compliant. See %s",
			path,
			defPlcmtPlName,
			dnsReference,
		)
	}

	defPlName := placement.Name
	if defPlName != "" && len(validation.IsDNS1123Subdomain(defPlName)) > 0 {
		return fmt.Errorf(
			"%s placement.name `%s` is not DNS compliant. See %s", path, defPlName, dnsReference,
		)
	}

	if placement.PlacementRulePath != "" {
		_, err := os.Stat(placement.PlacementRulePath)
		if err != nil {
			return fmt.Errorf(
				"%s placement.placementRulePath could not read the path %s",
				path, placement.PlacementRulePath,
			)
		}
	}

	if placement.PlacementPath != "" {
		_, err := os.Stat(placement.PlacementPath)
		if err != nil {
			return fmt.Errorf(
				"%s placement.placementPath could not read the path %s",
				path, placement.PlacementPath,
			)
		}
	}

	if plCount != nil {
		foundPl := false

		if len(placement.LabelSelector) != 0 ||
			placement.PlacementPath != "" ||
			placement.PlacementName != "" {
			plCount.plc++

			foundPl = true
		}

		if len(placement.ClusterSelectors) != 0 ||
			len(placement.ClusterSelector) != 0 ||
			placement.PlacementRulePath != "" ||
			placement.PlacementRuleName != "" {
			plCount.plr++

			if foundPl {
				return fmt.Errorf(
					"%s may not use both Placement and PlacementRule kinds", path,
				)
			}
		}
	}

	if len(placement.ClusterSelectors) > 0 && len(placement.ClusterSelector) > 0 {
		return fmt.Errorf("cannot use both clusterSelector and clusterSelectors in %s placement config "+
			"(clusterSelector is recommended since it matches the actual placement field)", path)
	}

	// Determine which selectors to use
	var resolvedSelectors map[string]interface{}
	if len(placement.ClusterSelectors) > 0 {
		resolvedSelectors = placement.ClusterSelectors
	} else if len(placement.ClusterSelector) > 0 {
		resolvedSelectors = placement.ClusterSelector
	} else if len(placement.LabelSelector) > 0 {
		resolvedSelectors = placement.LabelSelector
	}

	_, err := p.generateSelector(resolvedSelectors)
	if err != nil {
		return fmt.Errorf("%s placement has invalid selectors: %w", path, err)
	}

	return nil
}

// createPolicy will generate the root policy based on the PolicyGenerator configuration.
// The generated policy is written to the plugin's output buffer. An error is returned if the
// manifests specified in the configuration are invalid or can't be read.
func (p *Plugin) createPolicy(policyConf *types.PolicyConfig) error {
	policyTemplates, err := getPolicyTemplates(policyConf)
	if err != nil {
		return err
	}

	if policyConf.PolicyAnnotations == nil {
		policyConf.PolicyAnnotations = map[string]string{}
	}

	if policyConf.PolicyLabels == nil {
		policyConf.PolicyLabels = map[string]string{}
	}

	policyConf.PolicyAnnotations["policy.open-cluster-management.io/categories"] = strings.Join(
		policyConf.Categories, ",",
	)
	policyConf.PolicyAnnotations["policy.open-cluster-management.io/controls"] = strings.Join(
		policyConf.Controls, ",",
	)
	policyConf.PolicyAnnotations["policy.open-cluster-management.io/standards"] = strings.Join(
		policyConf.Standards, ",",
	)
	policyConf.PolicyAnnotations["policy.open-cluster-management.io/description"] = policyConf.Description

	spec := map[string]interface{}{
		"disabled":         policyConf.Disabled,
		"policy-templates": policyTemplates,
	}

	if p.PolicyDefaults.OrderPolicies && p.previousPolicyName != "" {
		policyConf.Dependencies = []types.PolicyDependency{{
			Name:       p.previousPolicyName,
			Namespace:  p.PolicyDefaults.Namespace,
			Compliance: "Compliant",
			Kind:       policyKind,
			APIVersion: policyAPIVersion,
		}}
	}

	p.previousPolicyName = policyConf.Name

	if len(policyConf.Dependencies) != 0 {
		spec["dependencies"] = policyConf.Dependencies
	}

	// When copyPolicyMetadata is unset, it defaults to the behavior of true, so this leaves it out entirely when set to
	// true to avoid unnecessarily including it in the Policy YAML.
	if !policyConf.CopyPolicyMetadata {
		spec["copyPolicyMetadata"] = false
	}

	policy := map[string]interface{}{
		"apiVersion": policyAPIVersion,
		"kind":       policyKind,
		"metadata": map[string]interface{}{
			"annotations": policyConf.PolicyAnnotations,
			"name":        policyConf.Name,
			"namespace":   p.PolicyDefaults.Namespace,
		},
		"spec": spec,
	}

	if len(policyConf.PolicyLabels) != 0 {
		policy["metadata"].(map[string]interface{})["labels"] = policyConf.PolicyLabels
	}

	// set the root policy remediation action if all the remediation actions match
	if rootRemediationAction := getRootRemediationAction(policyTemplates); rootRemediationAction != "" {
		policy["spec"].(map[string]interface{})["remediationAction"] = rootRemediationAction
	}

	policyYAML, err := yaml.Marshal(policy)
	if err != nil {
		return fmt.Errorf(
			"an unexpected error occurred when converting the policy to YAML: %w", err,
		)
	}

	p.outputBuffer.Write([]byte("---\n"))
	p.outputBuffer.Write(policyYAML)

	return nil
}

// createPolicySet will generate the policyset based on the Policy Generator configuration.
// The generated policyset is written to the plugin's output buffer. An error is returned if the
// manifests specified in the configuration are invalid or can't be read.
func (p *Plugin) createPolicySet(policySetConf *types.PolicySetConfig) error {
	policyset := map[string]interface{}{
		"apiVersion": policySetAPIVersion,
		"kind":       policySetKind,
		"metadata": map[string]interface{}{
			"name":      policySetConf.Name,
			"namespace": p.PolicyDefaults.Namespace, // policyset should be generated in the same namespace of policy
		},
		"spec": map[string]interface{}{
			"description": policySetConf.Description,
			"policies":    policySetConf.Policies,
		},
	}

	policysetYAML, err := yaml.Marshal(policyset)
	if err != nil {
		return fmt.Errorf(
			"an unexpected error occurred when converting the policyset to YAML: %w", err,
		)
	}

	p.outputBuffer.Write([]byte("---\n"))
	p.outputBuffer.Write(policysetYAML)

	return nil
}

// getPlcFromPath finds the placement manifest in the input manifest file. It will return the name
// of the placement, the unmarshaled placement manifest, and an error. An error is returned if the
// placement manifest cannot be found or is invalid.
func (p *Plugin) getPlcFromPath(plcPath string) (string, map[string]interface{}, error) {
	manifests, err := unmarshalManifestFile(plcPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read the placement: %w", err)
	}

	var name string
	var placement map[string]interface{}

	for _, manifest := range manifests {
		kind, _, _ := unstructured.NestedString(manifest, "kind")
		if kind != placementRuleKind && kind != placementKind {
			continue
		}

		// Validate PlacementRule Kind given in manifest
		if kind == placementRuleKind {
			if !p.usingPlR {
				return "", nil, fmt.Errorf(
					"the placement %s specified a placementRule kind but expected a placement kind", plcPath,
				)
			}
		}

		// Validate Placement Kind given in manifest
		if kind == placementKind {
			if p.usingPlR {
				return "", nil, fmt.Errorf(
					"the placement %s specified a placement kind but expected a placementRule kind", plcPath,
				)
			}
		}

		var found bool
		name, found, err = unstructured.NestedString(manifest, "metadata", "name")

		if !found || err != nil {
			return "", nil, fmt.Errorf("the placement %s must have a name set", plcPath)
		}

		var namespace string
		namespace, found, err = unstructured.NestedString(manifest, "metadata", "namespace")

		if !found || err != nil {
			return "", nil, fmt.Errorf("the placement %s must have a namespace set", plcPath)
		}

		if namespace != p.PolicyDefaults.Namespace {
			err = fmt.Errorf(
				"the placement %s must have the same namespace as the policy (%s)",
				plcPath,
				p.PolicyDefaults.Namespace,
			)

			return "", nil, err
		}

		placement = manifest

		break
	}

	if name == "" {
		err = fmt.Errorf(
			"the placement manifest %s did not have a placement", plcPath,
		)

		return "", nil, err
	}

	return name, placement, nil
}

// getCsKey generates the key for the policy's cluster/label selectors to be used in
// Policies.csToPlc.
func getCsKey(placementConfig types.PlacementConfig) string {
	return fmt.Sprintf("%#v", placementConfig.ClusterSelectors)
}

// getPlcName will generate a placement name for the policy. If the placement has
// previously been generated, skip will be true.
func (p *Plugin) getPlcName(
	defaultPlacementConfig types.PlacementConfig,
	placementConfig types.PlacementConfig,
	nameDefault string,
) (string, bool) {
	if placementConfig.Name != "" {
		// If the policy explicitly specifies a placement name, use it
		return placementConfig.Name, false
	} else if defaultPlacementConfig.Name != "" || p.PolicyDefaults.Placement.Name != "" {
		// Prioritize the provided default but fall back to policyDefaults
		defaultPlacementName := p.PolicyDefaults.Placement.Name
		if defaultPlacementConfig.Name != "" {
			defaultPlacementName = defaultPlacementConfig.Name
		}
		// If the policy doesn't explicitly specify a placement name, and there is a
		// default placement name set, check if one has already been generated for these
		// cluster/label selectors
		csKey := getCsKey(placementConfig)
		if _, ok := p.csToPlc[csKey]; ok {
			// Just reuse the previously created placement with the same cluster/label selectors
			return p.csToPlc[csKey], true
		}
		// If the policy doesn't explicitly specify a placement name, and there is a
		// default placement name, use that
		if len(p.csToPlc) == 0 {
			// If this is the first generated placement, just use it as is
			return defaultPlacementName, false
		}
		// If there is already one or more generated placements, increment the name
		return fmt.Sprintf("%s%d", defaultPlacementName, len(p.csToPlc)+1), false
	}
	// Default to a placement per policy
	return "placement-" + nameDefault, false
}

func (p *Plugin) createPolicyPlacement(placementConfig types.PlacementConfig, nameDefault string) (
	name string, err error,
) {
	return p.createPlacement(p.PolicyDefaults.Placement, placementConfig, nameDefault)
}

func (p *Plugin) createPolicySetPlacement(placementConfig types.PlacementConfig, nameDefault string) (
	name string, err error,
) {
	return p.createPlacement(p.PolicySetDefaults.Placement, placementConfig, nameDefault)
}

// createPlacement creates a placement for the input placement config and default name by writing it to
// the policy generator's output buffer. The name of the placement or an error is returned.
// If the placement has already been generated, it will be reused and not added to the
// policy generator's output buffer. An error is returned if the placement cannot be created.
func (p *Plugin) createPlacement(
	defaultPlacementConfig types.PlacementConfig,
	placementConfig types.PlacementConfig,
	nameDefault string) (
	name string, err error,
) {
	// If a placementName or placementRuleName is defined just return it
	if placementConfig.PlacementName != "" {
		name = placementConfig.PlacementName

		return
	}

	if placementConfig.PlacementRuleName != "" {
		name = placementConfig.PlacementRuleName

		return
	}

	plrPath := placementConfig.PlacementRulePath
	plcPath := placementConfig.PlacementPath
	var placement map[string]interface{}
	// If a path to a placement is provided, find the placement and reuse it.
	if plrPath != "" || plcPath != "" {
		var resolvedPlPath string
		if plrPath != "" {
			resolvedPlPath = plrPath
		} else {
			resolvedPlPath = plcPath
		}

		name, placement, err = p.getPlcFromPath(resolvedPlPath)
		if err != nil {
			return
		}

		// processedPlcs keeps track of which placements have been seen by name. This is so
		// that if the same placement path is provided for multiple policies, it's not re-included
		// in the generated output of the plugin.
		if p.processedPlcs[name] {
			return
		}

		p.processedPlcs[name] = true
	} else {
		var skip bool
		name, skip = p.getPlcName(defaultPlacementConfig, placementConfig, nameDefault)
		if skip {
			return
		}

		// Determine which selectors to use
		var resolvedSelectors map[string]interface{}
		if len(placementConfig.ClusterSelectors) > 0 {
			resolvedSelectors = placementConfig.ClusterSelectors
		} else if len(placementConfig.ClusterSelector) > 0 {
			resolvedSelectors = placementConfig.ClusterSelector
		} else if len(placementConfig.LabelSelector) > 0 {
			resolvedSelectors = placementConfig.LabelSelector
		}

		// Build cluster selector object
		selectorObj, err := p.generateSelector(resolvedSelectors)
		if err != nil {
			return "", err
		}

		if p.usingPlR {
			placement = map[string]interface{}{
				"apiVersion": placementRuleAPIVersion,
				"kind":       placementRuleKind,
				"metadata": map[string]interface{}{
					"name":      name,
					"namespace": p.PolicyDefaults.Namespace,
				},
				"spec": map[string]interface{}{
					"clusterSelector": selectorObj,
				},
			}
		} else {
			placement = map[string]interface{}{
				"apiVersion": placementAPIVersion,
				"kind":       placementKind,
				"metadata": map[string]interface{}{
					"name":      name,
					"namespace": p.PolicyDefaults.Namespace,
				},
				"spec": map[string]interface{}{
					"predicates": []map[string]interface{}{
						{
							"requiredClusterSelector": map[string]interface{}{
								"labelSelector": selectorObj,
							},
						},
					},
					"tolerations": []map[string]interface{}{
						{
							"key":      "cluster.open-cluster-management.io/unreachable",
							"operator": "Exists",
						},
					},
				},
			}
		}

		csKey := getCsKey(placementConfig)
		p.csToPlc[csKey] = name
	}

	if p.allPlcs[name] {
		return "", fmt.Errorf("a duplicate placement name was detected: %s", name)
	}

	p.allPlcs[name] = true

	var placementYAML []byte

	placementYAML, err = yaml.Marshal(placement)
	if err != nil {
		err = fmt.Errorf(
			"an unexpected error occurred when converting the placement to YAML: %w", err,
		)

		return
	}

	p.outputBuffer.Write([]byte("---\n"))
	p.outputBuffer.Write(placementYAML)

	return
}

// generateSelector determines the type of input and creates a map of selectors to be used in either the
// clusterSelector or labelSelector field
func (p *Plugin) generateSelector(
	resolvedSelectors map[string]interface{},
) (map[string]interface{}, error) {
	if resolvedSelectors == nil {
		return map[string]interface{}{"matchExpressions": []interface{}{}}, nil
	}

	resolvedSelectorsJSON, err := json.Marshal(resolvedSelectors)
	if err != nil {
		return nil, err
	}

	resolvedSelectorsLS := metav1.LabelSelector{}
	decoder := json.NewDecoder(bytes.NewReader(resolvedSelectorsJSON))
	decoder.DisallowUnknownFields()

	err = decoder.Decode(&resolvedSelectorsLS)
	if err != nil {
		resolvedSelectorsLS = metav1.LabelSelector{}

		// Check if it's a legacy selector
		for label, value := range resolvedSelectors {
			valueStr, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf(
					"the input is not a valid label selector or key-value label matching map",
				)
			}

			lsReq := metav1.LabelSelectorRequirement{Key: label}

			if valueStr == "" {
				lsReq.Operator = metav1.LabelSelectorOpExists
			} else {
				lsReq.Operator = metav1.LabelSelectorOpIn
				lsReq.Values = []string{valueStr}
			}

			resolvedSelectorsLS.MatchExpressions = append(resolvedSelectorsLS.MatchExpressions, lsReq)
		}

		// Sort the MatchExpressions to make the result deterministic
		sort.Slice(resolvedSelectorsLS.MatchExpressions, func(i, j int) bool {
			return resolvedSelectorsLS.MatchExpressions[i].Key < resolvedSelectorsLS.MatchExpressions[j].Key
		})

		resolved, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&resolvedSelectorsLS)
		if err != nil {
			panic(err)
		}

		return resolved, nil
	}

	return resolvedSelectors, nil
}

// createPlacementBinding creates a placement binding for the input placement, policies and policy sets by
// writing it to the policy generator's output buffer. An error is returned if the placement binding
// cannot be created.
func (p *Plugin) createPlacementBinding(
	bindingName, plcName string, policyConfs []*types.PolicyConfig, policySetConfs []*types.PolicySetConfig,
) error {
	subjects := make([]map[string]string, 0, len(policyConfs)+len(policySetConfs))

	for _, policyConf := range policyConfs {
		subject := map[string]string{
			"apiGroup": policyAPIGroup,
			"kind":     policyKind,
			"name":     policyConf.Name,
		}
		subjects = append(subjects, subject)
	}

	for _, policySetConf := range policySetConfs {
		subject := map[string]string{
			"apiGroup": policyAPIGroup,
			"kind":     policySetKind,
			"name":     policySetConf.Name,
		}
		subjects = append(subjects, subject)
	}

	var resolvedPlcKind string
	var resolvedPlcAPIVersion string

	if p.usingPlR {
		resolvedPlcKind = placementRuleKind
		resolvedPlcAPIVersion = placementRuleAPIVersion
	} else {
		resolvedPlcKind = placementKind
		resolvedPlcAPIVersion = placementAPIVersion
	}

	binding := map[string]interface{}{
		"apiVersion": placementBindingAPIVersion,
		"kind":       placementBindingKind,
		"metadata": map[string]interface{}{
			"name":      bindingName,
			"namespace": p.PolicyDefaults.Namespace,
		},
		"placementRef": map[string]string{
			// Remove the version at the end
			"apiGroup": strings.Split(resolvedPlcAPIVersion, "/")[0],
			"name":     plcName,
			"kind":     resolvedPlcKind,
		},
		"subjects": subjects,
	}

	bindingYAML, err := yaml.Marshal(binding)
	if err != nil {
		return fmt.Errorf(
			"an unexpected error occurred when converting the placement binding to YAML: %w", err,
		)
	}

	p.outputBuffer.Write([]byte("---\n"))
	p.outputBuffer.Write(bindingYAML)

	return nil
}
