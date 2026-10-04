# TailnetGateway: experimental suspended contract

**The gateway controller reports suspension only.** The cluster-scoped
`tsunaro.io/v1alpha1` CRD validates configuration, but creates no workloads, keys,
routes, policy entries or DNS records. `spec.suspend` defaults to `true`; admission
rejects `false`. An accepted CR is not a working gateway or an adoption proof.
Existing ingress and egress controllers do not reconcile this resource.

The registered gateway controller reads only the gateway CR and patches its status.
It does not resolve the Tailnet, read Secrets, invoke a resource renderer, call
Headscale or watch child resources. Missing dependencies do not prevent suspension.
It adds no owner references or finalizers and performs no deletion cleanup.

This API is a development foundation, not a release or migration instruction.
The only additional permissions are gateway get/list/watch and status get/update/patch.
Gateway spec/lifecycle, finalizer, StatefulSet and RBAC management remain unauthorized.
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

## Fresh resource model: not a runtime

`internal/gateway.RenderFresh` models initial resources without reading or writing
Kubernetes or Headscale. The suspension controller does not call it. Rendering
success is not permission to create resources or evidence of a runnable gateway.

The model requires admitted, defaulted CRs and the operator namespace. It rejects
adoption, historical identity signals, implicit bootstrap, TCP forwards and extra
DNS zones. Losing status does not authorize treating retained resources as fresh.

It returns nine resources:

- A singleton StatefulSet with `OnDelete` updates and a matching headless Service.
- A DNS ClusterIP Service and a LoadBalancer Service, each with an explicit IP family.
  The DNS ClusterIP and requested LB IP remain explicit. NodePorts are disabled.
- A derived CoreDNS ConfigMap, ServiceAccount, Role, RoleBinding and singleton PDB.

UID-bound selectors isolate gateways. Pool labels affect only the LB Service and
cannot overwrite identity labels. No resource receives a gateway GC owner reference
or finalizer. This models retention; it does not prove live deletion behavior.
The PDB blocks voluntary eviction of the singleton and can therefore block drains.

State and auth Secrets are deliberately absent from the returned objects. Before
any future creation, the writer must verify all of these prerequisites:

- Every resource name is available, with no retained or foreign object to overwrite.
- The referenced state Secret already exists, is mutable and contains no retained identity.
- The separate auth Secret contains a verified non-ephemeral key for the selected Headscale instance and tags.
- Source ownership, Tailnet scope, Service addresses, network conflicts and image compatibility are valid.

`internal/gateway.InspectFreshSnapshots` is a disconnected read-only inventory
check. `InspectFreshFromReader` gathers its Kubernetes snapshots through an
explicit `client.Reader` (no default kubeconfig): Gateway, selected Tailnet,
state Secret, owned hosts ConfigMap, scoped Egresses, peer Gateways and all nine
resource names. It treats any read error as unknown, never as NotFound. Neither
function is called by the controller, and a cache observation is not an
exclusive name reservation. It requires revisioned Gateway, Tailnet, empty mutable state Secret and an
owned hosts ConfigMap whose `hosts` content matches the render input. It checks
all nine planned names for explicitly observed absence and rejects retained
objects even if they carry the Gateway UID label. Peer Gateway identity/address
collisions and supplied Headscale node names also block. Its receipt contains
only UIDs and resource versions; errors have fixed, non-secret text.

**A passing inventory still returns `ErrFreshProvenance`.** The current Headscale
client cannot verify an external auth key's non-ephemeral status, tags and
server binding; an absent node and an empty Secret are not such proof.
`PlanGatewayMint` and `ValidateGatewayMint` model the alternative: request a
reusable, **non-ephemeral** key with exact tags and a bounded 24-hour expiry from
the selected authenticated Headscale client, then reject a response with the
wrong flags, tags or expiry. These helpers do not call Headscale, persist a
Secret or authorize a Pod. If minting succeeds but the Secret write fails, the
orphaned key expires; the controller must re-read before retrying and must not
infer ownership from a masked key list. A package-private `storeGatewayMint`
models an exclusive Kubernetes Secret **Create** after validating the response
and re-reading Gateway/Tailnet revisions. The retained, immutable Secret records
UID-bound metadata; an existing name is never overwritten. This disconnected
helper does not mint, verify a later state-to-node binding, or start a Pod; the
production manager has no path to call it. `ReadGatewayAuthReceipt` checks the
retained Secret's UID/revision, immutability, scope hashes, key presence and
expiration without returning key bytes. These Kubernetes annotations are **not**
a Headscale-signed proof of the full credential; restrictive Secret-write RBAC
and later state-to-node verification remain necessary. A caller
must not use this diagnostic receipt as a writer authorization. Read snapshots
are not an exclusive lock; every absence needs revalidation immediately before
creation, with conflict handling. DNS serial/hash persistence and CAS, image and
network compatibility, and a safe creation sequence are also pending. The
suspended controller never invokes this inspection or `RenderFresh`.

The pod Role permits only `get`, `update` and `patch` of the exact state Secret.
It cannot create missing state, read the auth Secret through the API, or list Secrets.
Only Tailscale mounts the rotating service-account token and state-cache directory.
The kubelet supplies the auth key through a Secret reference; the plan contains no key value.
Operator RBAC is unchanged and still cannot create the modeled workloads or roles.

### Kernel prerequisites and startup boundary

The model uses kernel Tailscale with only `NET_ADMIN`, no privilege escalation and
a read-only root filesystem. CoreDNS is non-root with only `NET_BIND_SERVICE`.
An unprivileged init container checks the TUN character device and the forwarding
sysctls required by the initial route families. It only reads; missing or disabled
prerequisites fail startup before the main containers start. No privileged init
container, host network namespace or sysctl writer is provided.

Tailscale 1.102.4 source inspection shows that `containerboot` skips sysctl writes
when forwarding is already enabled, so the pod network namespace must already have
`net.ipv4.ip_forward=1`. On a Talos node the pod inherits this from the host
(`net.core.devconf_inherit_init_net=0`, host forwarding enabled). Where the host
does not forward, a node that allows the namespaced `net.ipv4.ip_forward` unsafe
sysctl lets the pod set it through `securityContext.sysctls` with no added capability.
The operator must not relax node or namespace security to bypass a failed check.
A later route update that adds a family needs a new runtime prerequisite check.

For fresh state, bootstrap uses `TS_AUTH_ONCE=false`, `--reset` and explicit
`--accept-routes=false`. Tailscale 1.102.4 does not apply all `TS_EXTRA_ARGS` through
its `TS_AUTH_ONCE=true` restart path. This model never resets an adopted node.
There is no `--force-reauth`, ephemeral-key minting or offline-node deletion.

Routes include mandatory LAN and LB prefixes plus optional scoped literal egress
addresses. DNS targets are not resolved. Only non-deleting egress CRs from the
operator namespace and selected Tailnet contribute. These are **initial** pod
settings; later route writes must not reuse this template as an update plan.

Tailscale's health endpoint and CoreDNS's TCP listener are only pod-readiness inputs.
They do not establish persistent identity, route approval, DNS answers or Gateway Ready.
No liveness probe restarts the identity on a transient control-plane failure.

Unit tests check the model and execute the read-only preflight against synthetic
files. Isolated Kubernetes 1.31 tests admit the resources and dry-run the pod.
They verify IPv4/IPv6 Service allocation and real service-account authorization,
including refusal to recreate missing state. They run no kubelet or data plane.
Tailscale source inspection and these checks **do not verify an OCI image, TUN
ioctls, packet routing, bootstrap or identity retention across restart**.

### Read-only Kind prerequisite gate

Run the fixed selection through the existing delegated, rootless runner:

```sh
systemd-run --user --scope -p Delegate=yes -- \
  bash hack/e2e-kind-projection.sh --gateway-preflight-only
```

The runner requires its usual tools and cached assets, including Kind 0.32.0 and
Helm 3. It creates a disposable isolated cluster; it never uses the current context.
The new selection has a 10-minute test budget. Existing selections and budgets are
unchanged. Evidence and cleanup results remain under the runner's XDG State directory.

The probe only reads fixed paths. It checks the node's TUN character-device metadata
and the pod forwarding value in a startup-gated, unprivileged observation pod. It does
not mount or open TUN, load modules, write sysctls or start gateway containers.
Unknown, unreadable or disabled required observations fail the gate, not skip it.

The observation pod provisions `net.ipv4.ip_forward=1` through `securityContext.sysctls`,
which the kind node permits as an allowed unsafe sysctl (`kind-http.yaml`). This mirrors
the forwarding a Talos node provides to the real gateway pod and adds no capability,
privilege or host change. The gate then confirms the node TUN character device and the
pod IPv4 forwarding prerequisite are observable before any gateway container exists.

A green result proves only that the IPv4 kernel prerequisites are present in the pod;
it does not prove image compatibility, TUN permissions/ioctls, persistent bootstrap or
subnet routing. IPv6 is out of scope: the initial LAN and LB route families are IPv4,
matching the production gateway.

`test/internal/kindfixture.AddGatewayNetworkGate` now validates a separate,
fixture-only kernel pod shape: exactly one Tailscale container (UID 0, only
`NET_ADMIN`), one non-root CoreDNS container (only `NET_BIND_SERVICE`), and
exactly one `HostPathCharDev /dev/net/tun` mounted only by Tailscale. It rejects
extra host paths, privilege escalation, other capabilities, unexpected sysctls,
shared gate storage and foreign init/ephemeral containers before prepending the
same UID-bound unprivileged startup init used by `AddNetworkGate`. The one
pre-existing, constrained, read-only `kernel-preflight` remains second, after
fixture release. The latter's
UID-65532/no-HostPath/no-added-capabilities contract remains unchanged.

Offline contract tests also check the actual `RenderFresh` pod shape, but are
**not** a running kernel gateway or a TUN permission proof. A future isolated fixture must still bind and release the
live Pod with the runner before starting a kernel process. Writer, bootstrap,
identity and routing proofs remain open.

## Fresh DNS rendering: partial implementation

`internal/gateway.RenderDNS` compiles a primary authoritative zone into `Corefile`
and `zone.db`. This pure renderer is **not connected to the controller**. It does
not render a pod or authorize adoption of an existing CoreDNS configuration.

The caller supplies a snapshot of the selected Tailnet's owned hosts ConfigMap.
Dynamic names replace the entire static address set for the same name, not just
one address family. Dynamic and static records share one file zone: a known name's
missing record type returns NODATA, without falling through to a wildcard or upstream.
Wildcards follow normal DNS closest-encloser semantics; they are not catch-all templates.
The primary apex is reserved for the gateway nameserver/address. Host snapshots that
claim it are rejected. Names outside the primary zone are not served.

**Additional forward zones are deliberately unsupported by this renderer.** Any
nonempty `extraZones` returns an error and no partial output. With CoreDNS 1.14.6,
`hosts` followed by `forward` keeps missing A/AAAA local, but forwards TXT for a
known name. That does not satisfy the required strict-local contract. Admission
still accepts the future API field; it does not activate this weaker behavior.

Before runtime integration, the caller must:

- Verify Tailnet/namespace scope and hosts-ConfigMap ownership.
- Render every source-host change into the derived zone ConfigMap; mounting the
  source hosts file alone does not update this file-zone design.
- Advance the nonzero SOA serial for every zone-data change, including hosts-only
  changes. Gateway generation alone is insufficient. `PlanDNSRevision` now computes
  a canonical zone-data hash and a transition with the expected target resourceVersion;
  unchanged data keep their serial after restart, while wraparound fails closed.
  `ReadDNSRevision` rejects a missing, reset or payload-inconsistent persisted
  serial/hash pair; it does not establish ownership or freshness. **Neither function
  persists or compare-and-swaps anything.** A writer must store serial/hash with
  the rendered ConfigMap, verify the stored payload, and retry from fresh source
  and target snapshots on conflict; it must never reset the serial on restart.
  A package-private `updateDNSRevision` now exercises that CAS for an **existing,
  revisioned, UID-labelled** ConfigMap through an explicit client. It re-reads
  Gateway, Tailnet and owned hosts source before updating, retries conflicts
  from a fresh snapshot and refuses to create/adopt a target. It is unreachable
  from the suspend-only controller and the installed admission contract. Cross-
  object source/target writes are not atomic; source watches, initial creation,
  proven field ownership and live DNS checks are still required.
- Project the configuration directory without `subPath` and set CoreDNS's working
  directory to `/etc/coredns`. The file plugin checks for zone updates each second.
- Select supported bind addresses explicitly and verify the actual image, Service
  allocation and DNS reachability. No management/metrics ports are rendered yet.

The renderer rejects malformed input with fixed errors and no partial files.
Like `GatewayIP`, snapshot addresses must be canonical unicast literals, excluding
loopback, link-local and IPv4-mapped addresses. Hosts input is bounded to 1 MiB and 16,384 distinct names. Combined ConfigMap output
is also limited to 1 MiB; the renderer never silently truncates either.
Clients can cache answers for the rendered 30-second TTL. File-reload evidence does
not establish Kubernetes ConfigMap propagation time or client-cache freshness.

### Local DNS behavior gate

```sh
COREDNS_BINARY=/absolute/path/to/coredns task test-gateway-dns
```

Supply a trusted binary explicitly. The gate starts only owned loopback listeners,
requires IPv4 and IPv6 loopback, and uses no Kubernetes context. CoreDNS **1.14.6**
was checked over UDP/TCP. Cases cover A/AAAA, negative record types (including
HTTPS/SVCB), wildcards, closest-encloser behavior, NXDOMAIN, refused zones and
dynamic/static priority. Atomic directory-projection reloads were also checked.
An intentionally unsafe hosts+forward
control reproduces TXT fallthrough against an owned loopback upstream.

This does not verify the lab's CoreDNS 1.14.7 image, a running Kubernetes sidecar,
external forwarding support, kernel subnet routing or interruption-free adoption.
The fresh resource model above includes a StatefulSet and Services, but source
watches, serial persistence and the writer remain pending. The controller remains
suspended and does not call either renderer.

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
The controller sets `Ready=False/Suspended` and the other listed conditions to
`Unknown/Suspended`. It preserves last-known identity, routes and debounce fields;
these are not fresh observations. `observedGeneration` means the suspension was
processed, not that configuration was applied. Unrelated conditions are preserved.
A nil suspend value is treated as true. If admission is bypassed to set false,
the controller still performs no runtime work and reports `RuntimeUnavailable`.

Status patches use resource-version preconditions. Conflicts retry through the
work queue, unchanged status is not rewritten, and status-only events withdraw
stale success conditions. API errors retain machine-readable classification but
expose only fixed, non-sensitive text. There are no gateway-specific operational
metrics or alerts yet; generic Ready gauges do not include suspended gateways.

Isolated API-server tests exercise the production manager with generated RBAC,
status events and deletion without state mutation. No kubelet or garbage collector
runs there: these tests do not prove live pod retention or interruption-free adoption.

The [example](../../deploy/examples/tailnetgateway.yaml) uses synthetic digest pins
and is suitable only for admission validation in a disposable API server.
