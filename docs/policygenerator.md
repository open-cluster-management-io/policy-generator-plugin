# About the PolicyGenerator plugin

See the [PolicyGenerator reference YAML](./policygenerator-reference.yaml) to see the full structure
of the PolicyGenerator manifest.

## The Kustomize exec plugin explained

The policy generator plugin is a binary written in Go. The binary accepts an input manifest of the
`PolicyGenerator` kind in the `policy.open-cluster-management.io/v1` API. When Kustomize finds a
manifest of that kind under the `generators:` array in `kustomization.yaml`, it looks in its
directories for a binary of the same name ("PolicyGenerator") in the
`policy.open-cluster-management.io/vi/policygenerator` directory and calls the binary as
`<path>/PolicyGenerator <cached-manifest>` to run the generator as its plugin. The flag
`--enable-alpha-plugins` must be specified in the Kustomize command in order for the external
generator plugin to be enabled.

## Placement

By default, a Placement and PlacementBinding are created for each policy with the policy name as the
suffix. To signal that you'd like to consolidate policies that use the same Placement under a single
PlacementBinding, either specify `placement.placementRulePath` to an existing Placement rule manifest or 
set `placement.name` along with `placement.clusterSelector`. When the PlacementBinding is consolidated in
this way, `placementBindingDefaults.name` must be specified so that the generator can create unique
names for the bindings.

The Placement kind in the `cluster.open-cluster-management.io` API group is used by default if no
placement is given. However, you can use the deprecated PlacementRule kind in the
`apps.open-cluster-management.io` API group by specifying a PlacementRule manifest in
`placement.placementRulePath` or specifying labels in `placement.clusterSelector`.

## Policy expanders

Policy expanders provide logic to create additional policies based on a given kind to give a
complete picture of violations or status using Open Cluster Management policies. Generally, the
expanders point to kinds provided by policy engines such as [Kyverno](https://kyverno.io/) and
[Gatekeeper](https://open-policy-agent.github.io/gatekeeper/). These expanders are enabled by
default but can be disabled individually by setting the flag associated with the expander in the
`PolicyGenerator` manifest either in `policyDefaults` or for a particular manifest in the `policies`
array.

### Contributing a policy expander

To contribute a policy expander, you'll need to:

1. Add your expander to the `getExpanders()` method in
   [expanders.go](../internal/expanders/expanders.go) and familiarize yourself with the Interface
   there that you'll be implementing.
2. Add your expander file to the [internal/expanders/](../internal/expanders/) directory. You can
   follow the other files there as an example.
3. Choose a name for your boolean expander setting. (Existing names have followed the pattern
   `Inform<engine-name>Policies`.)
4. Add your expander setting to both the `PolicyDefaults` and the `PolicyConfig` structs in
   [types.go](../internal/types/types.go)
5. Add your expander setting to the `applyDefaults()` method in [plugin.go](../internal/plugin.go)
   to set defaults for both `PolicyDefaults` and `Policies`.
6. Update the [policygenerator-reference.yaml](./policygenerator-reference.yaml) with your expander
   setting.
7. Add tests for your expander to the [internal/expanders/](../internal/expanders/) directory.

## PolicyGenerator code structure

```
DIRECTORY TREE              PACKAGE                 DESCRIPTION
================================================================================================
.
├── cmd
│   └── main.go             main                    Parent binary (imports the internal package)
└── internal
    ├── expanders
    │   ├── expanders.go    expanders               Policy expander interface
    ├── types
    │   └── types.go        types                   Generator structs
    ├── patches.go          internal                Code to patch input manifests
    ├── plugin.go           internal                Primary generator methods
    ├── typohelper.go       internal                Helpers for identifying manifest typos
    ├── utils.go            internal                Helper/utility functions
```
## Openapi schema support 
policy-genenerator-plugin supports openapi schemas as defined in  https://kubectl.docs.kubernetes.io/references/kustomize/kustomization/openapi by Kustomize. The goal of this feature is to support patching non kubernetest CR objects that contain list of objects.
The openapi object in this project has the same format of the openapi object in the kustomize project. The Path indicates the relative path of the schema json file relative to the kustomization.yaml file
``` yaml
openapi:
   path: schema.json
```
The openapi object is part of the manifest object in the plugin file:
``` yaml
apiVersion: policy.open-cluster-management.io/v1
kind: PolicyGenerator
...
policies:
- name: myapp
  manifests:
    - path: input-kustomize/
      patches:
      openapi:
        path: schema.json
```
### How to create a Kustomize schema manually
Ideally the openapi schema should be provided by the developper of the Custom Resource (CR).  
To retrieve a schema from a running kubernetes cluster manually, do the following:

``` default
kustomize openapi fetch
```

Then cut and paste the subset containing the resources that need to be patched.

Next, identify the list objects in the schema and select a key from the fields
of the object that would be use to index the list, for instance a name. After
the definition of the list, add the following text:

``` default
              "x-kubernetes-patch-merge-key": "name",
              "x-kubernetes-patch-strategy": "merge"
```

`x-kubernetes-patch-merge-key` indicates the field in the object that is used to
uniquely identify it in the list in this case the `name` field
`x-kubernetes-patch-strategy` indicates the patch strategy. Merge would merge
fields, replace would replace the object identified by the key with patch
content.  
`Note:` The "key" selected in this step is used in patches to uniquely identify a list object.
  
An example of schema for the ptp-operator PtpConfig CR is shown at [link](internal/testdata/OpenAPI/newptpconfig-schema.json)
