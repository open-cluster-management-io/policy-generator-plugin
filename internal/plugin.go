// Copyright Contributors to the Open Cluster Management project
package internal

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"
	"open-cluster-management.io/ocm-kustomize-generator-plugins/internal/types"
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
)

// Plugin is used to store the PolicyGenerator configuration and the methods to generate the
// desired policies.
type Plugin struct {
	Metadata struct {
		Name string `json:"name,omitempty" yaml:"name,omitempty"`
	} `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	PlacementBindingDefaults struct {
		Name string `json:"name,omitempty" yaml:"name,omitempty"`
	} `json:"placementBindingDefaults,omitempty" yaml:"placementBindingDefaults,omitempty"`
	PolicyDefaults types.PolicyDefaults    `json:"policyDefaults,omitempty" yaml:"policyDefaults,omitempty"`
	Policies       []types.PolicyConfig    `json:"policies" yaml:"policies"`
	PolicySets     []types.PolicySetConfig `json:"policySets" yaml:"policySets"`
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
	err := yaml.Unmarshal(config, p)
	const errTemplate = "the PolicyGenerator configuration file is invalid: %w"

	if err != nil {
		return fmt.Errorf(errTemplate, err)
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
		// only generate placement when GeneratePlacementWhenInSet equals to true or policy is not
		// part of any policy sets
		if p.Policies[i].GeneratePlacementWhenInSet || len(p.Policies[i].PolicySets) == 0 {
			plcName, err := p.createPlacement(&p.Policies[i].Placement, p.Policies[i].Name)
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
		plcName, err := p.createPlacement(&p.PolicySets[i].Placement, p.PolicySets[i].Name)
		if err != nil {
			return nil, err
		}

		if plcNameToPolicyAndSetIdxs[plcName] == nil {
			plcNameToPolicyAndSetIdxs[plcName] = map[string][]int{}
		}

		plcNameToPolicyAndSetIdxs[plcName]["policyset"] = append(plcNameToPolicyAndSetIdxs[plcName]["policyset"], i)
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

func getDefaultBool(config map[string]interface{}, key string) (value bool, set bool) {
	defaults, ok := config["policyDefaults"].(map[string]interface{})
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

// getPolicy will return a policy at the specified index in the Policy Generator configuration YAML.
func getPolicy(config map[string]interface{}, policyIndex int) map[string]interface{} {
	policies, ok := config["policies"].([]interface{})
	if !ok {
		return nil
	}

	if len(policies)-1 < policyIndex {
		return nil
	}

	policy, ok := policies[policyIndex].(map[string]interface{})
	if !ok {
		return nil
	}

	return policy
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

// isEvaluationIntervalSetManifest will return the evaluation interval of the specified manifest of the specified policy
// in the Policy Generator configuration YAML.
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

	// Policy expanders default to true unless explicitly set in the config.
	// Gatekeeper policy expander policyDefault
	igvValue, setIgv := getDefaultBool(unmarshaledConfig, "informGatekeeperPolicies")
	if setIgv {
		p.PolicyDefaults.InformGatekeeperPolicies = igvValue
	} else {
		p.PolicyDefaults.InformGatekeeperPolicies = true
	}
	// Kyverno policy expander policyDefault
	ikvValue, setIkv := getDefaultBool(unmarshaledConfig, "informKyvernoPolicies")
	if setIkv {
		p.PolicyDefaults.InformKyvernoPolicies = ikvValue
	} else {
		p.PolicyDefaults.InformKyvernoPolicies = true
	}

	consolidatedValue, setConsolidated := getDefaultBool(unmarshaledConfig, "consolidateManifests")
	if setConsolidated {
		p.PolicyDefaults.ConsolidateManifests = consolidatedValue
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

	for i := range p.Policies {
		policy := &p.Policies[i]

		if policy.PolicyAnnotations == nil {
			annotations := map[string]string{}
			for k, v := range p.PolicyDefaults.PolicyAnnotations {
				annotations[k] = v
			}

			policy.PolicyAnnotations = annotations
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

		if policy.Standards == nil {
			policy.Standards = p.PolicyDefaults.Standards
		}

		if policy.Controls == nil {
			policy.Controls = p.PolicyDefaults.Controls
		}

		if policy.ComplianceType == "" {
			policy.ComplianceType = p.PolicyDefaults.ComplianceType
		}

		if policy.MetadataComplianceType == "" && p.PolicyDefaults.MetadataComplianceType != "" {
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

		// GeneratePlacementWhenInSet default to false unless explicitly set in the config.
		gpValue, setGp := getPolicyBool(unmarshaledConfig, i, "generatePlacementWhenInSet")
		if setGp {
			policy.GeneratePlacementWhenInSet = gpValue
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

		consolidatedValue, setConsolidated := getPolicyBool(unmarshaledConfig, i, "consolidateManifests")
		if setConsolidated {
			policy.ConsolidateManifests = consolidatedValue
		} else {
			policy.ConsolidateManifests = p.PolicyDefaults.ConsolidateManifests
		}

		disabledValue, setDisabled := getPolicyBool(unmarshaledConfig, i, "disabled")
		if setDisabled {
			policy.Disabled = disabledValue
		} else {
			policy.Disabled = p.PolicyDefaults.Disabled
		}

		// Determine whether defaults are set for placement
		plcDefaultSet := len(p.PolicyDefaults.Placement.LabelSelector) != 0 ||
			p.PolicyDefaults.Placement.PlacementPath != "" ||
			p.PolicyDefaults.Placement.PlacementName != ""
		plrDefaultSet := len(p.PolicyDefaults.Placement.ClusterSelectors) != 0 ||
			p.PolicyDefaults.Placement.PlacementRulePath != "" ||
			p.PolicyDefaults.Placement.PlacementRuleName != ""

		// If both cluster label selectors and placement path/name aren't set, then use the defaults with a
		// priority on placement path followed by placement name.
		if len(policy.Placement.LabelSelector) == 0 &&
			policy.Placement.PlacementPath == "" &&
			policy.Placement.PlacementName == "" &&
			plcDefaultSet {
			if p.PolicyDefaults.Placement.PlacementPath != "" {
				policy.Placement.PlacementPath = p.PolicyDefaults.Placement.PlacementPath
			} else if p.PolicyDefaults.Placement.PlacementName != "" {
				policy.Placement.PlacementName = p.PolicyDefaults.Placement.PlacementName
			} else if len(p.PolicyDefaults.Placement.LabelSelector) > 0 {
				policy.Placement.LabelSelector = p.PolicyDefaults.Placement.LabelSelector
			}
		} else if len(policy.Placement.ClusterSelectors) == 0 &&
			// Else if both cluster selectors and placement rule path/name aren't set, then use the defaults with a
			// priority on placement rule path followed by placement rule name.
			policy.Placement.PlacementRulePath == "" &&
			policy.Placement.PlacementRuleName == "" &&
			plrDefaultSet {
			if p.PolicyDefaults.Placement.PlacementRulePath != "" {
				policy.Placement.PlacementRulePath = p.PolicyDefaults.Placement.PlacementRulePath
			} else if p.PolicyDefaults.Placement.PlacementRuleName != "" {
				policy.Placement.PlacementRuleName = p.PolicyDefaults.Placement.PlacementRuleName
			} else if len(p.PolicyDefaults.Placement.ClusterSelectors) > 0 {
				policy.Placement.ClusterSelectors = p.PolicyDefaults.Placement.ClusterSelectors
			}
		}

		// Only use defaults when when the namespaceSelector is not set on the policy
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

			if manifest.ComplianceType == "" {
				manifest.ComplianceType = policy.ComplianceType
			}

			if manifest.MetadataComplianceType == "" && policy.MetadataComplianceType != "" {
				manifest.MetadataComplianceType = policy.MetadataComplianceType
			}

			// If the manifests are consolidated to a single ConfigurationPolicy object, don't set
			// ConfigurationPolicy options per manifest.
			if policy.ConsolidateManifests {
				continue
			}

			// Only use the policy's ConfigurationPolicyOptions values when they're not explicitly set in the manifest.
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
			if selector.Exclude != nil || selector.Include != nil ||
				selector.MatchLabels != nil || selector.MatchExpressions != nil {
				manifest.NamespaceSelector = policy.NamespaceSelector
			}

			if manifest.RemediationAction == "" && policy.RemediationAction != "" {
				manifest.RemediationAction = policy.RemediationAction
			}

			if manifest.PruneObjectBehavior == "" && policy.PruneObjectBehavior != "" {
				manifest.PruneObjectBehavior = policy.PruneObjectBehavior
			}

			if manifest.Severity == "" && manifest.Severity != "" {
				manifest.Severity = policy.Severity
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

	// Sync up the declared policy sets in p.Policies[*]
	for i := range p.PolicySets {
		plcset := &p.PolicySets[i]
		plcset.Policies = make([]string, 0, len(plcsetToPlc[plcset.Name]))

		for plc := range plcsetToPlc[plcset.Name] {
			plcset.Policies = append(plcset.Policies, plc)
		}

		// Sort alphabetically to make it deterministic
		sort.Strings(plcset.Policies)
	}
}

// assertValidConfig verifies that the user provided configuration has all the
// required fields. Note that this should be run only after applyDefaults is run.
func (p *Plugin) assertValidConfig() error {
	if p.PolicyDefaults.Namespace == "" {
		return errors.New("policyDefaults.namespace is empty but it must be set")
	}

	// Validate default Placement settings
	if p.PolicyDefaults.Placement.PlacementRulePath != "" && p.PolicyDefaults.Placement.PlacementPath != "" {
		return errors.New(
			"policyDefaults must provide only one of placement.placementPath or placement.placementRulePath",
		)
	}

	if len(p.PolicyDefaults.Placement.ClusterSelectors) > 0 && len(p.PolicyDefaults.Placement.LabelSelector) > 0 {
		return errors.New(
			"policyDefaults must provide only one of placement.labelSelector or placement.clusterSelectors",
		)
	}

	if p.PolicyDefaults.Placement.PlacementRuleName != "" && p.PolicyDefaults.Placement.PlacementName != "" {
		return errors.New(
			"policyDefaults must provide only one of placement.placementName or placement.placementRuleName",
		)
	}

	// validate placement and binding names are DNS compliant
	defPlrName := p.PolicyDefaults.Placement.PlacementRuleName
	if defPlrName != "" && len(validation.IsDNS1123Subdomain(defPlrName)) > 0 {
		return fmt.Errorf(
			"PolicyDefaults.Placement.PlacementRuleName placement name `%s` is not DNS compliant. See %s",
			defPlrName,
			dnsReference,
		)
	}

	defPlcmtPlName := p.PolicyDefaults.Placement.PlacementName
	if defPlcmtPlName != "" && len(validation.IsDNS1123Subdomain(defPlcmtPlName)) > 0 {
		return fmt.Errorf(
			"PolicyDefaults.Placement.PlacementName `%s` is not DNS compliant. See %s",
			defPlcmtPlName,
			dnsReference,
		)
	}

	defPlName := p.PolicyDefaults.Placement.Name
	if defPlName != "" && len(validation.IsDNS1123Subdomain(defPlName)) > 0 {
		return fmt.Errorf(
			"PolicyDefaults.Placement.Name `%s` is not DNS compliant. See %s", defPlName, dnsReference,
		)
	}

	if p.PlacementBindingDefaults.Name != "" &&
		len(validation.IsDNS1123Subdomain(p.PlacementBindingDefaults.Name)) > 0 {
		return fmt.Errorf(
			"PlacementBindingDefaults.Name `%s` is not DNS compliant. See %s",
			p.PlacementBindingDefaults.Name,
			dnsReference,
		)
	}

	defaultPlacementOptions := 0
	if len(p.PolicyDefaults.Placement.LabelSelector) != 0 || len(p.PolicyDefaults.Placement.ClusterSelectors) != 0 {
		defaultPlacementOptions++
	}

	if p.PolicyDefaults.Placement.PlacementRulePath != "" || p.PolicyDefaults.Placement.PlacementPath != "" {
		defaultPlacementOptions++
	}

	if p.PolicyDefaults.Placement.PlacementRuleName != "" || p.PolicyDefaults.Placement.PlacementName != "" {
		defaultPlacementOptions++
	}

	if defaultPlacementOptions > 1 {
		return errors.New(
			"policyDefaults must specify only one of placement selector, placement path, or placement name",
		)
	}

	if len(p.Policies) == 0 {
		return errors.New("policies is empty but it must be set")
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

			// Verify that consolidated manifests don't specify fields
			// that can't be overridden at the objectTemplate level
			if policy.ConsolidateManifests {
				errorMsgFmt := fmt.Sprintf(
					"the policy %s has the %%s value set on manifest[%d] but consolidateManifests is true",
					policy.Name, j,
				)

				if evalInterval.Compliant != "" || evalInterval.NonCompliant != "" {
					return fmt.Errorf(errorMsgFmt, "evaluationInterval")
				}

				selector := manifest.NamespaceSelector
				if selector.Exclude != nil || selector.Include != nil ||
					selector.MatchLabels != nil || selector.MatchExpressions != nil {
					return fmt.Errorf(errorMsgFmt, "namespaceSelector")
				}

				if manifest.PruneObjectBehavior != "" {
					return fmt.Errorf(errorMsgFmt, "pruneObjectBehavior")
				}

				if manifest.RemediationAction != "" {
					return fmt.Errorf(errorMsgFmt, "remediationAction")
				}

				if manifest.Severity != "" {
					return fmt.Errorf(errorMsgFmt, "severity")
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
		}

		// Validate policy Placement settings
		if policy.Placement.PlacementRulePath != "" && policy.Placement.PlacementPath != "" {
			return fmt.Errorf(
				"policy %s must provide only one of placementRulePath or placementPath", policy.Name,
			)
		}

		if policy.Placement.PlacementRuleName != "" && policy.Placement.PlacementName != "" {
			return fmt.Errorf(
				"policy %s must provide only one of placementRuleName or placementName", policy.Name,
			)
		}

		if len(policy.Placement.ClusterSelectors) > 0 && len(policy.Placement.LabelSelector) > 0 {
			return fmt.Errorf(
				"policy %s must provide only one of placement.labelSelector or placement.clusterselectors",
				policy.Name,
			)
		}

		// validate placement names are DNS compliant
		plcPlrName := policy.Placement.PlacementRuleName
		if plcPlrName != "" && len(validation.IsDNS1123Subdomain(plcPlrName)) > 0 {
			return fmt.Errorf(
				"policy.Placement.PlacementRuleName `%s` is not DNS compliant. See %s",
				plcPlrName,
				dnsReference,
			)
		}

		plcPlcmtPlName := policy.Placement.PlacementName
		if plcPlcmtPlName != "" && len(validation.IsDNS1123Subdomain(plcPlcmtPlName)) > 0 {
			return fmt.Errorf(
				"policy.Placement.PlacementRuleName `%s` is not DNS compliant. See %s",
				plcPlcmtPlName,
				dnsReference,
			)
		}

		plcPlName := policy.Placement.Name
		if plcPlName != "" && len(validation.IsDNS1123Subdomain(plcPlName)) > 0 {
			return fmt.Errorf(
				"policy.Placement.PlacementRuleName `%s` is not DNS compliant. See %s",
				plcPlName,
				dnsReference,
			)
		}

		policyPlacementOptions := 0
		if len(policy.Placement.LabelSelector) != 0 || len(policy.Placement.ClusterSelectors) != 0 {
			policyPlacementOptions++
		}

		if policy.Placement.PlacementRulePath != "" || policy.Placement.PlacementPath != "" {
			policyPlacementOptions++
		}

		if policy.Placement.PlacementRuleName != "" || policy.Placement.PlacementName != "" {
			policyPlacementOptions++
		}

		if policyPlacementOptions > 1 {
			return fmt.Errorf(
				"policy %s must specify only one of placement selector, placement path, or placement name", policy.Name,
			)
		}

		if policy.Placement.PlacementRulePath != "" {
			_, err := os.Stat(policy.Placement.PlacementRulePath)
			if err != nil {
				return fmt.Errorf(
					"could not read the placement rule path %s",
					policy.Placement.PlacementRulePath,
				)
			}
		}

		if policy.Placement.PlacementPath != "" {
			_, err := os.Stat(policy.Placement.PlacementPath)
			if err != nil {
				return fmt.Errorf(
					"could not read the placement path %s",
					policy.Placement.PlacementPath,
				)
			}
		}

		foundPl := false

		if len(policy.Placement.LabelSelector) != 0 ||
			policy.Placement.PlacementPath != "" ||
			policy.Placement.PlacementName != "" {
			plCount.plc++

			foundPl = true
		}

		if len(policy.Placement.ClusterSelectors) != 0 ||
			policy.Placement.PlacementRulePath != "" ||
			policy.Placement.PlacementRuleName != "" {
			plCount.plr++

			if foundPl {
				return fmt.Errorf(
					"policy %s may not use both Placement and PlacementRule kinds", policy.Name,
				)
			}
		}
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

		// Validate policy Placement settings
		if plcset.Placement.PlacementRulePath != "" && plcset.Placement.PlacementPath != "" {
			return fmt.Errorf(
				"policySet %s must provide only one of placementRulePath or placementPath", plcset.Name,
			)
		}

		if plcset.Placement.PlacementRuleName != "" && plcset.Placement.PlacementName != "" {
			return fmt.Errorf(
				"policySet %s must provide only one of placementRuleName or placementName", plcset.Name,
			)
		}

		if len(plcset.Placement.ClusterSelectors) > 0 && len(plcset.Placement.LabelSelector) > 0 {
			return fmt.Errorf(
				"policySet %s must provide only one of placement.labelSelector or placement.clusterselectors",
				plcset.Name,
			)
		}

		// validate placement names are DNS compliant
		plcSetPlrName := plcset.Placement.PlacementRuleName
		if plcSetPlrName != "" && len(validation.IsDNS1123Subdomain(plcSetPlrName)) > 0 {
			return fmt.Errorf(
				"plcset.Placement.PlacementRuleName `%s` is not DNS compliant. See %s", plcSetPlrName, dnsReference,
			)
		}

		plcSetPlcmtPlName := plcset.Placement.PlacementName
		if plcSetPlcmtPlName != "" && len(validation.IsDNS1123Subdomain(plcSetPlcmtPlName)) > 0 {
			return fmt.Errorf(
				"plcset.Placement.PlacementName `%s` is not DNS compliant. See %s", plcSetPlcmtPlName, dnsReference,
			)
		}

		plcSetPlName := plcset.Placement.Name
		if plcSetPlName != "" && len(validation.IsDNS1123Subdomain(plcSetPlName)) > 0 {
			return fmt.Errorf(
				"plcset.Placement.Name `%s` is not DNS compliant. See %s", plcSetPlName, dnsReference,
			)
		}

		policySetPlacementOptions := 0
		if len(plcset.Placement.LabelSelector) != 0 || len(plcset.Placement.ClusterSelectors) != 0 {
			policySetPlacementOptions++
		}

		if plcset.Placement.PlacementRulePath != "" || plcset.Placement.PlacementPath != "" {
			policySetPlacementOptions++
		}

		if plcset.Placement.PlacementRuleName != "" || plcset.Placement.PlacementName != "" {
			policySetPlacementOptions++
		}

		if policySetPlacementOptions > 1 {
			return fmt.Errorf(
				"policySet %s must specify only one of placement selector, placement path, or placement name",
				plcset.Name,
			)
		}

		if plcset.Placement.PlacementRulePath != "" {
			_, err := os.Stat(plcset.Placement.PlacementRulePath)
			if err != nil {
				return fmt.Errorf(
					"could not read the placement rule path %s",
					plcset.Placement.PlacementRulePath,
				)
			}
		}

		if plcset.Placement.PlacementPath != "" {
			_, err := os.Stat(plcset.Placement.PlacementPath)
			if err != nil {
				return fmt.Errorf(
					"could not read the placement path %s",
					plcset.Placement.PlacementPath,
				)
			}
		}

		foundPl := false

		plcSetPlc := plcset.Placement
		if len(plcSetPlc.LabelSelector) != 0 || plcSetPlc.PlacementPath != "" || plcSetPlc.PlacementName != "" {
			plCount.plc++

			foundPl = true
		}

		if len(plcSetPlc.ClusterSelectors) != 0 ||
			plcSetPlc.PlacementRulePath != "" ||
			plcSetPlc.PlacementRuleName != "" {
			plCount.plr++

			if foundPl {
				return fmt.Errorf(
					"policySet %s may not use both Placement and PlacementRule kinds", plcset.Name,
				)
			}
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

	p.usingPlR = plCount.plc == 0

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

	policyConf.PolicyAnnotations["policy.open-cluster-management.io/categories"] = strings.Join(
		policyConf.Categories, ",",
	)
	policyConf.PolicyAnnotations["policy.open-cluster-management.io/controls"] = strings.Join(
		policyConf.Controls, ",",
	)
	policyConf.PolicyAnnotations["policy.open-cluster-management.io/standards"] = strings.Join(
		policyConf.Standards, ",",
	)

	policy := map[string]interface{}{
		"apiVersion": policyAPIVersion,
		"kind":       policyKind,
		"metadata": map[string]interface{}{
			"annotations": policyConf.PolicyAnnotations,
			"name":        policyConf.Name,
			"namespace":   p.PolicyDefaults.Namespace,
		},
		"spec": map[string]interface{}{
			"disabled":         policyConf.Disabled,
			"policy-templates": policyTemplates,
		},
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

	for _, manifest := range *manifests {
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
func getCsKey(placementConfig *types.PlacementConfig) string {
	return fmt.Sprintf("%#v", placementConfig.ClusterSelectors)
}

// getPlcName will generate a placement name for the policy. If the placement has
// previously been generated, skip will be true.
func (p *Plugin) getPlcName(placementConfig *types.PlacementConfig, nameDefault string) (string, bool) {
	if placementConfig.Name != "" {
		// If the policy explicitly specifies a placement name, use it
		return placementConfig.Name, false
	} else if p.PolicyDefaults.Placement.Name != "" {
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
			return p.PolicyDefaults.Placement.Name, false
		}
		// If there is already one or more generated placements, increment the name
		return fmt.Sprintf("%s%d", p.PolicyDefaults.Placement.Name, len(p.csToPlc)+1), false
	}
	// Default to a placement per policy
	return "placement-" + nameDefault, false
}

// createPlacement creates a placement for the input placement config and default name by writing it to
// the policy generator's output buffer. The name of the placement or an error is returned.
// If the placement has already been generated, it will be reused and not added to the
// policy generator's output buffer. An error is returned if the placement cannot be created.
func (p *Plugin) createPlacement(placementConfig *types.PlacementConfig, nameDefault string) (
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
		name, skip = p.getPlcName(placementConfig, nameDefault)
		if skip {
			return
		}

		// Determine which selectors to use
		var resolvedSelectors map[string]string
		if len(placementConfig.ClusterSelectors) > 0 {
			resolvedSelectors = placementConfig.ClusterSelectors
		} else if len(placementConfig.LabelSelector) > 0 {
			resolvedSelectors = placementConfig.LabelSelector
		}

		// Sort the keys so that the match expressions can be ordered based on the label name
		keys := make([]string, 0, len(resolvedSelectors))
		for key := range resolvedSelectors {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		matchExpressions := []map[string]interface{}{}
		for _, label := range keys {
			matchExpression := map[string]interface{}{
				"key": label,
			}
			if resolvedSelectors[label] == "" {
				matchExpression["operator"] = "Exists"
			} else {
				matchExpression["operator"] = "In"
				matchExpression["values"] = []string{resolvedSelectors[label]}
			}
			matchExpressions = append(matchExpressions, matchExpression)
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
					"clusterSelector": map[string]interface{}{
						"matchExpressions": matchExpressions,
					},
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
								"labelSelector": map[string]interface{}{
									"matchExpressions": matchExpressions,
								},
							},
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
