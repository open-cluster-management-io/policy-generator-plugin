# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

The Policy Generator is a Kustomize exec plugin that constructs Open Cluster Management policies from Kubernetes YAML files. It's a Go binary that processes PolicyGenerator Custom Resources and outputs Policy, Placement, and PlacementBinding manifests.

## Build Commands

```bash
# Build the plugin (installs to ~/.config/kustomize/plugin/...)
make build

# Build binary in repository root (for standalone use)
make build-binary

# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run single test
go test -v -run TestName ./internal

# Build release binaries for all platforms
make build-release
```

## Testing

Tests use the standard Go testing framework. Test files are colocated with source files (e.g., `plugin.go` has `plugin_test.go`).

## Development Workflow

Before submitting PRs:
```bash
make fmt
make lint
make test
```

## High-Level Architecture

### Core Flow

1. **Input**: PolicyGenerator YAML manifest (custom resource)
2. **Processing**: Plugin.Config() validates and applies defaults → Plugin.Generate() creates policies
3. **Output**: YAML stream with Policy, Placement, and PlacementBinding manifests

### Key Components

**cmd/PolicyGenerator/main.go**
- Entry point that reads PolicyGenerator YAML files
- Calls Plugin.Config() then Plugin.Generate()
- Outputs YAML to stdout (for Kustomize consumption)

**internal/plugin.go** (Plugin struct)
- `Config()`: Validates input, applies defaults, sets base directory
- `Generate()`: Main generation orchestrator
  - Creates policies via `createPolicy()`
  - Creates policy sets via `createPolicySet()`
  - Creates placements (consolidated where possible)
  - Creates placement bindings
- Placement consolidation: Tracks cluster/label selectors in `selectorToPlc` map to reuse placements when selectors match

**internal/types/types.go**
- Defines all configuration structs:
  - `PolicyConfig`: Individual policy specification
  - `PolicyDefaults`: Default values applied to all policies
  - `PolicySetConfig`: Policy set groupings
  - `PlacementConfig`: Cluster targeting configuration
  - `Manifest`: References to Kubernetes manifests to wrap in policies

**internal/expanders/**
- Policy expanders create additional policies for specific policy engines (Gatekeeper, Kyverno)
- Each expander implements the interface in `expanders.go`
- Enabled by default via `InformGatekeeperPolicies` and `InformKyvernoPolicies` flags

**internal/patches.go**
- Handles Kustomize-style patching of manifests using strategic merge or JSON patches
- OpenAPI schema support for patching non-Kubernetes CRs with list fields

**internal/utils.go**
- Helper functions for manifest processing, YAML/JSON conversion, file operations

### Default Handling

The plugin has a sophisticated defaults system:
- Hard-coded defaults in `defaults` variable (internal/plugin.go:77)
- User-specified `policyDefaults` in PolicyGenerator YAML
- Per-policy overrides in `policies` array
- Per-manifest overrides in `manifests` array

The `applyDefaults()` method (internal/plugin.go:446) cascades these defaults in order, considering:
- Explicit false values (requires checking raw YAML via `unmarshaledConfig`)
- Special relationships (e.g., `orderManifests=true` forces `consolidateManifests=false`)

### Placement Logic

**Consolidation**: Multiple policies can share a Placement if they have identical cluster/label selectors. The `selectorToPlc` map tracks selector → placement name mappings.

**Kind Selection**: Plugin only supports Placement (cluster.open-cluster-management.io/v1beta1).

**Placement Sources**:
1. External file via `placementPath`
2. Referenced by name via `placementName`
3. Generated from inline `labelSelector`

### Manifest Processing

Manifests can be:
- Individual YAML/JSON files
- Directories (processed recursively)
- Kustomize directories (if not disabled via env var)

The generator wraps each manifest in a ConfigurationPolicy, which is then wrapped in a Policy template. Policy expanders may create additional inform-only policies for Gatekeeper/Kyverno resources.

## Environment Variables

- `POLICY_GEN_ENABLE_HELM`: Set to "true" to enable Helm processing in Kustomize directories
- `POLICY_GEN_DISABLE_LOAD_RESTRICTORS`: Set to "true" to allow Helm directories outside Kustomize path

## Important Validation Rules

- Policy names must be DNS-compliant (RFC 1123)
- Policy namespace + name must be ≤ 63 characters
- `consolidateManifests` and `orderManifests` are mutually exclusive
- `orderManifests` incompatible with `extraDependencies`
- When consolidating manifests, all ConfigurationPolicy options must match at policy level

## Code Modification Guidance

**Adding a Policy Expander**:
1. Create file in `internal/expanders/`
2. Implement the expander interface
3. Register in `getExpanders()` (expanders/expanders.go)
4. Add boolean flag to `PolicyDefaults` and `PolicyConfig` structs (types/types.go)
5. Add default handling in `applyDefaults()` (plugin.go)
6. Update docs/policygenerator-reference.yaml

**Modifying Defaults**:
- Edit `defaults` variable in internal/plugin.go
- Update `applyDefaults()` method for cascade logic
- Check both `PolicyDefaults` and `PolicyConfig` structs

**Adding Manifest Processing**:
- Most logic is in `getPolicyTemplates()` (internal/utils.go)
- Patching handled in internal/patches.go
- Use `unmarshalManifestFile()` for reading YAML/JSON files
