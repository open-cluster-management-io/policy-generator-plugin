# Policy Generator

## Overview

The Policy Generator constructs Open Cluster Management policies from Kubernetes YAML files provided through a
PolicyGenerator Custom Resource. The Policy Generator is a binary compiled for use as a
[kustomize](https://kustomize.io/) exec plugin.

- [Installing the Policy Generator](#installing-the-policy-generator)
  - [Prerequisite](#prerequisite)
  - [Install the binary](#install-the-binary)
    - [Download a released version](#download-a-released-version)
    - [Using `go install` (available for `v1.11.0` and higher)](#using-go-install-available-for-v1110-and-higher)
    - [Build from source](#build-from-source)
- [Using the Policy Generator](#using-the-policy-generator)
  - [As a Kustomize plugin](#as-a-kustomize-plugin)
  - [As a standalone binary](#as-a-standalone-binary)
- [Additional Policy Generator references](#additional-policy-generator-references)

For more about Open Cluster Management and its Policy Framework:

- [Open Cluster Management website](https://open-cluster-management.io/)
- [Governance Policy Framework](https://open-cluster-management.io/getting-started/integration/policy-framework/)
- [Policy Collection repository](https://github.com/open-cluster-management-io/policy-collection)

## Install the Policy Generator

### Prerequisite

Create the plugin directory (optional if using the generator without Kustomize):

```bash
mkdir -p ${HOME}/.config/kustomize/plugin/policy.open-cluster-management.io/v1/policygenerator
```

**NOTE:** The default directory for Kustomize plugins is `${HOME}/.config/kustomize/plugin/`, which is used directly in
this readme. You can change this by exporting `KUSTOMIZE_PLUGIN_HOME` to a different path and updating the root of the
paths used in this document.

### Install the binary

#### Download a released version

1. Download the precompiled plugin binary from the
   [release](https://github.com/open-cluster-management-io/policy-generator-plugin/releases) of your choice.

2. Make the binary executable and move the binary to the plugin directory:

   - Linux:

     ```bash
     chmod +x linux-amd64-PolicyGenerator
     mv linux-amd64-PolicyGenerator ${HOME}/.config/kustomize/plugin/policy.open-cluster-management.io/v1/policygenerator/PolicyGenerator
     ```

   - MacOS:
     ```bash
     chmod +x darwin-amd64-PolicyGenerator
     mv darwin-amd64-PolicyGenerator ${HOME}/.config/kustomize/plugin/policy.open-cluster-management.io/v1/policygenerator/PolicyGenerator
     ```

#### Use `go install` (available for `v1.11.0` and higher)

Set the `GOBIN` to the plugin directory and specify the desired version (this command uses `latest`):

```bash
GOBIN=${HOME}/.config/kustomize/plugin/policy.open-cluster-management.io/v1/policygenerator \
go install open-cluster-management.io/policy-generator-plugin/cmd/PolicyGenerator@latest
```

#### Build from source

```bash
make build
```

**NOTE:**

- This defaults to placing the binary in the Kustomize default plugin directory `${HOME}/.config/kustomize/plugin/`. You
  can change this by exporting `KUSTOMIZE_PLUGIN_HOME` to a different path.
- Alternatively, you can run `make build-binary` to place the binary at the root of the repository and either use it
  directly from there or move it to the plugin directory to use with Kustomize.

## Using the Policy Generator

### As a Kustomize plugin

1. Create a `kustomization.yaml` file that points to `PolicyGenerator` manifest(s), with any additional desired patches
   or customizations (see [`examples/policyGenerator.yaml`](./examples/policyGenerator.yaml) for an example):

   ```yaml
   generators:
     - path/to/generator/file.yaml
   ```

   - To read more about the `PolicyGenerator` YAML structure, see the
     [Policy Generator reference YAML](./docs/policygenerator-reference.yaml)

2. To use the plugin to generate policies, run the Kustomize build command from any directory with a
   `kustomization.yaml` file pointing to `PolicyGenerator` manifests:
   ```bash
   kustomize build --enable-alpha-plugins
   ```

### As a standalone binary

In order to bypass Kustomize and run the generator binary directly, change to the directory of PolicyGenerator
manifest(s) and run the binary with the manifest(s) as the input arguments:

```bash
path/to/PolicyGenerator <path/to/file/1> ... <path/to/file/n>
```

For example:

```bash
make build-binary # This places the binary at the root of the repo, so this is optional if it was done previously
cd examples
../PolicyGenerator policyGenerator.yaml
```

**NOTE:** To print the trace in the case of an error, you can add the `--debug` flag to the arguments.

## Additional Policy Generator references

- [Policy Generator reference YAML](./docs/policygenerator-reference.yaml)
- [Policy Generator technical documentation](./docs/policygenerator.md)
