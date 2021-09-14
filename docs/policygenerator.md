# About the PolicyGenerator plugin

See the [PolicyGenerator reference YAML](./policygenerator-reference.yaml) to see the full structure of the PolicyGenerator manifest.

## The Kustomize exec plugin explained

The policy generator plugin is a binary written in Go. The binary accepts an input manifest of the `PolicyGenerator` kind in the `policy.open-cluster-management.io/v1` API. When Kustomize finds a manifest of that kind under the `generators:` array in `kustomization.yaml`, it looks in its directories for a binary of the same name ("PolicyGenerator") in the `policy.open-cluster-management.io/vi/policygenerator` directory and calls the binary as `<path>/PolicyGenerator <cached-manifest>` to run our generator as its plugin. The flag `--enable-alpha-plugins` must be specified in the kustomize command in order for our custom plugin to be enabled.

## Placement

By default, a Placement and PlacementBinding are created for each policy with the policy name as the suffix. To signal that you'd like to consolidate policies that use the same Placement under a single PlacementBinding, either specify `placement.placementRulePath` to an existing Placement manifest or set `placement.name` along with `placement.clusterSelectors`. When the PlacementBinding is consolidated in this way, `placementBindingDefaults.name` must be specified so that the generator can create unique names for the bindings.
