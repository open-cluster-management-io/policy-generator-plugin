# Policy Generator

## Overview

The Policy Generator constructs Open Cluster Management policies from Kubernetes YAML files provided through a PolicyGenerator Custom Resource. The Policy Generator is a binary compiled for use as a [kustomize](https://kustomize.io/) exec plugin.

For more about Open Cluster Management and its Policy Framework:
- [Open Cluster Management website](open-cluster-management.io/)
- [Governance Policy Framework](https://open-cluster-management.io/getting-started/integration/policy-framework/)
- [Policy Collection repository](https://github.com/open-cluster-management/policy-collection)

## Using the Policy Generator

### As a Kustomize plugin

1. Build the plugin binary (only needed once or to update the plugin):
    ```bash
    make build
    ```
    **NOTE:** This will default to placing the binary in `${HOME}/.config/kustomize/plugin/`. You can change this by exporting `KUSTOMIZE_PLUGIN_HOME` to a different path.

2. Create a `kustomization.yaml` file that points to `PolicyGenerator` manifest(s), with any additional desired patches or customizations (see [`examples/policyGenerator.yaml`](./examples/policyGenerator.yaml) for an example):
    ```yaml
    generators:
    - path/to/generator/file.yaml
    ...
    ```

3. To use the plugin to generate policies, do one of:
    - Utilize the `examples/` directory in this repository (the directory can be modified by exporting a new path to `SOURCE_DIR`):
      ```bash
      make generate
      ```
    - From any directory with a `kustomization.yaml` file pointing to `PolicyGenerator` manifests:
      ```bash
      kustomize build --enable-alpha-plugins
      ```

### As a standalone binary

In order to bypass Kustomize and run the generator binary directly:

1. Build the binary:
    ```bash
    make build-binary
    ```

2. Run the binary from the location of the PolicyGenerator manifest(s):
    ```bash
    path/to/PolicyGenerator <path/to/file/1> ... <path/to/file/n>
    ```
    - For example:
      ```bash
      cd examples
      ../PolicyGenerator policyGenerator.yaml
      ```
    **NOTE:** To print the trace in the case of an error, you can add the `--debug` flag to the arguments.
