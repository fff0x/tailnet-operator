# TailnetGateway: experimental admission contract

**There is no gateway controller in this implementation yet.** The cluster-scoped
`tsunaro.io/v1alpha1` CRD validates configuration, but creates no workloads, keys,
routes, policy entries or DNS records. `spec.suspend` defaults to `true`; admission
rejects `false`. An accepted CR is not a working gateway or an adoption proof.
Existing ingress and egress controllers do not reconcile this resource.

This API is a development foundation, not a release or migration instruction.
The operator has no additional gateway workload/RBAC permissions in this step.
Do not remove an existing gateway, move its Secret, or change Headscale split-DNS
because this CRD is installed. See [compatibility](../COMPATIBILITY.md#experimental-gateway-api).

## Configuration

All Secret and adopted-object references resolve in the operator namespace.
There is no configurable target namespace or arbitrary Pod/Corefile/shell template.

| Field | Contract |
| --- | --- |
| `tailnetRef.name` | Required Tailnet name; immutable |
| `hostname` | Required lowercase node hostname; immutable, never inferred from a default cluster name |
| `stateSecretRef.name` | Persistent Kubernetes state Secret; immutable, no key selector |
| `authKeySecretRef.{name,key}` | Optional external bootstrap key, default key `TS_AUTHKEY`; must not be the state Secret |
| `image` | Kernel Tailscale image with a concrete version tag or SHA256 digest, not the userspace agent image |
| `replicas` | Exactly `1`, also the default |
| `deletionPolicy` | Only `Retain`, also the default; adopted resources and persistent identity must survive CR deletion |
| `tags` | Bootstrap tags, default `[tag:fabric]`; not authority to drop existing tags during adoption |
| `routes.lan[]` | 1–32 canonical masked non-default IPv4/IPv6 prefixes |
| `routes.advertiseEgressTargets` | Default `true`; literal IPv4/IPv6 targets yield /32 or /128; DNS targets are not resolved |
| `service.loadBalancerIP` | Stable unicast IP, immutable and inside `tailnetLBCIDR` |
| `service.tailnetLBCIDR` | Mandatory route to the gateway's own LB address, independent of automatic egress routes |
| `service.poolLabels` | At most 16 Service labels for pool selection; does not configure pod selectors |
| `service.loadBalancerClass` | Optional qualified class; presence and value immutable |
| `dns.zone` | Primary lowercase DNS zone |
| `dns.serviceName`, `dns.serviceClusterIP` | Explicit stable DNS Service name/address, immutable |
| `dns.image` | Separate CoreDNS version/digest pin |
| `dns.extraZones[]` | Unique, non-overlapping zones with explicit unicast-IP upstreams; no resolver URLs |
| `dns.staticRecords[]` | Unique relative labels and explicit A/AAAA addresses below the primary zone |
| `dns.wildcardAddress` | Optional file-zone fallback; never a `template` plugin that shadows dynamic hosts |
| `forwards[]` | Named TCP port to `targetAddress` IP and `targetPort`; unique listener ports |
| `forwardImage` | Separate socat version/digest pin, required when forwards are present |

The CR name must be a DNS-1035 label of at most 40 characters, because it also
names the gateway Service. `dns.serviceName` must be a DNS-1035 label of at most
63 characters. Version tags such as `v1.102.4` and `1.8.0.3-r2` preserve existing
pod templates during adoption; bare images, `latest`, and major-only tags are rejected.
A digest pin is preferable for new workloads, but must not force an adoption rollout.

Forward listeners cannot use DNS/sidecar ports `53`, `8080`, `8181` or `9153`.
Subnet prefixes cannot intersect unspecified, loopback or multicast ranges;
IPv4-mapped CIDRs and noncanonical spellings are rejected. These checks do not
prove reachability or exclude deployment-specific control/peer networks.
The eventual runtime must validate those conflicts and the selected Tailnet scope.
Cluster CoreDNS forwarding and Headscale split-DNS remain externally managed.

The future desired route set is **LAN ∪ LB CIDR ∪ optional egress host routes**.
The pure planner preserves explicit prefix granularity and waits for a 30-second
quiet period before making a route update eligible. Status must acknowledge a
successful write, not merely elapsed time. No running router is changed yet.

## Adoption and retention

`adoption` is optional but immutable once the CR is created. It contains:

- `nodeId`: the inventoried numeric Headscale node ID.
- `objects[]`: explicit `apiVersion`, `kind`, `name`, and `uid` references.

The inventory must include exactly one StatefulSet named after the gateway CR
and exactly one Secret matching `stateSecretRef`. Additional allowed objects are
Services, ConfigMaps, ServiceAccounts, Roles, RoleBindings and a PodDisruptionBudget.
UIDs and kind/name pairs must be unique. Only the reviewed stable API versions are
accepted. This list is not a substitute for a complete runtime dependency inventory.

The eventual controller must verify every object's
`tsunaro.io/adopt-gateway: <gateway-CR-UID>` annotation. A name alone is not consent.
First adoption must preserve the existing defaulted payloads, pod template,
Service addresses and state bytes; configuration differences block takeover.
The first operation must not restart the gateway or install garbage-collection
owner references. Existing tags must not be silently replaced by bootstrap defaults.

Admission cannot verify any of those live conditions or bind a Secret to a
Headscale node. The read-only planner also does not implement transactional
multi-object takeover. A future writer must revalidate snapshots, use UID/resource-
version preconditions, preserve externally owned credentials, and coordinate with
GitOps. Ephemeral-agent duplicate deletion and node renaming must not be reused.

## Status

The status subresource reserves `nodeId`, `ipv4`, `serviceIP`, advertised/approved
route lists, stale node IDs, route-planner hashes/timestamp and conditions.
Intended conditions include `Registered`, `RoutesInSync`, `DNSReady`, `StaleNodes`,
`ClusterDNSForward`, and `Ready`. Stale nodes are reported, not automatically deleted.
No controller currently populates these fields, so absence of conditions is not success.

The [example](../../deploy/examples/tailnetgateway.yaml) uses synthetic digest pins
and is suitable only for admission validation in a disposable API server.
