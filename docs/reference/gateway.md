# TailnetGateway: experimental fresh-only writer

**`spec.suspend` defaults to `true`. Setting it to `false` opts into fresh IPv4 creation.**
The cluster-scoped `tsunaro.io/v1alpha1` resource does not adopt existing gateways.
CR acceptance alone is not runtime or data-plane evidence. Existing ingress and
egress controllers do not reconcile this resource.

While suspended, the controller reads only the Gateway CR and patches its status.
Missing dependencies do not prevent suspension. Suspension does not stop an already
running gateway. CR deletion retains everything by default: resources have no Gateway
owner references. Only `deletionPolicy: Delete` consents to the operator tearing down
its own fresh resources; see [Deletion](#deletion). StatefulSets retain and recreate their own Pods.

This is a development feature, not a release or migration instruction. New permissions
are namespace-local `get/create/delete` for StatefulSets, PDBs, ServiceAccounts, Roles and
RoleBindings, and `patch` on `tailnetgateways` for the teardown finalizer. `delete` is
used only by the teardown and always with a UID precondition. There are no update,
escalation, binding or CR-spec grants.
Do not remove an existing gateway, move its Secret, or change Headscale split-DNS
because this CRD is installed. See [compatibility](../COMPATIBILITY.md#experimental-gateway-api).

## Minimal fresh lifecycle

The active controller uses uncached API reads and the selected Tailnet's existing
working API key. It requires owned DNS hosts input, available resource names and
nonconflicting Gateway identities/addresses. External auth references, adoption,
IPv6, extra DNS zones and TCP forwards remain unsupported by this writer.

1. Render the initial plan without side effects; reject unsupported inputs and occupied names.
2. Exclusively create the empty mutable State Secret. Its successful Create response supplies the expected UID.
   This also prevents competing or ambiguous attempts from minting again.
   Pod-name/selector conflicts block creation. Workload, Service and PDB selectors
   additionally bind to this new State UID, preventing selection of old orphan Pods.
3. Call `PlanGatewayMint`, then the existing Headscale client, then `storeGatewayMintRecord`.
   The reusable key is non-ephemeral, tag-bound and limited to 24 hours.
4. Recheck source revisions, empty State UID and durable auth before each resource Create.
   Create the nine rendered resources, with the StatefulSet last. Never patch or adopt an existing object.
5. Create immutable `<gateway>-fresh` completion evidence: scope, independent State UID,
   auth receipt, child UIDs and admitted payload hashes. It contains no credentials or private-state hash.
6. Observe the retained set. Report runtime Ready only after a running, Ready Pod matches
   the StatefulSet and its state binds to an online Headscale node with the advertised routes.

The completion record (format 2) binds Gateway/Tailnet UIDs and hashes of the
[identity fields](#spec-updates), not generations or full specs. It permits later
metadata/status-only CR revision changes and the mutable spec changes listed below.
Replaced state/resources, payload drift, expired auth or a changed identity field block observation.
A suspend/resume cycle no longer invalidates completion evidence.
No keys are renewed and no resources are adopted, compensated or deleted
outside the explicit [Deletion](#deletion) consent. The only workload write is
the container-image reconcile described under [Spec updates](#spec-updates).
Partial creation without a complete receipt remains blocked, even if a workload started.
A lost completion response may be recovered only when the complete immutable record actually exists.
These are sequential checks, not a transaction or a general crash-recovery protocol.

Protect both receipt ConfigMaps as strictly as Secrets. An administrator who can replace
all retained evidence can forge it. The initial zone is rendered at SOA serial 1 and
carries the `tsunaro.io/dns-serial` and `tsunaro.io/dns-content-sha256` annotations.
Changes to the Tailnet hosts source are reconciled live into the derived `-coredns`
ConfigMap (see [Deletion](#deletion)-neighbour [Live DNS reconcile](#live-dns-reconcile)); routes remain unchanged.
Runtime Ready does not assert approved routes, LoadBalancer allocation, DNS answers or
cluster DNS forwarding. The isolated Kind probe supplies separate forwarding/DNS evidence.

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
| `deletionPolicy` | `Retain` (default): CR deletion leaves every resource, the Headscale node and the key in place. `Delete`: consent to the fail-closed teardown below |
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

## Pure fresh resource renderer

`internal/gateway.RenderFresh` models initial resources without reading or writing
Kubernetes or Headscale. The active writer calls it after selecting fresh inputs.
Rendering alone is not permission to create resources or evidence of a runnable gateway.

The model requires admitted, defaulted CRs and the operator namespace. It rejects
adoption, historical identity signals, implicit bootstrap, TCP forwards and extra
DNS zones. Losing status does not authorize treating retained resources as fresh.

It returns nine resources:

- A singleton StatefulSet with `OnDelete` updates and a matching headless Service.
- A DNS ClusterIP Service and a LoadBalancer Service, each with an explicit IP family.
  The DNS ClusterIP and requested LB IP remain explicit. NodePorts are disabled.
- A derived CoreDNS ConfigMap, ServiceAccount, Role, RoleBinding and singleton PDB.

UID-bound selectors isolate gateways. Pool labels affect only the LB Service and
cannot overwrite identity labels. No resource receives a gateway GC owner reference.
Retention is the default; the explicit teardown is described under [Deletion](#deletion).
The PDB blocks voluntary eviction of the singleton and can therefore block drains.

State and auth Secrets are deliberately absent from the returned objects. Before
workload creation, the writer checks these prerequisites:

- Every resource name is available, with no retained or foreign object to overwrite.
- The referenced state Secret already exists, is mutable and contains no retained identity.
- The separate auth Secret contains a verified non-ephemeral key for the selected Headscale instance and tags.
- Source ownership, Tailnet scope and declared identity/address conflicts are checked.
- Kernel and image compatibility remain deployment prerequisites; the Pod's read-only init check can block startup.

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
wrong flags, tags or expiry, or a noncanonical numeric key ID. These helpers do not call Headscale, persist a
Secret or authorize a Pod. If minting succeeds but the Secret write fails, the
orphaned key expires; the controller must re-read before retrying and must not
infer ownership from a masked key list. A package-private `storeGatewayMint`
models an exclusive Kubernetes Secret **Create** after validating the response
and re-reading Gateway/Tailnet revisions. The retained, immutable Secret records
UID-bound metadata; an existing name is never overwritten. This helper does not
itself mint, verify a later state-to-node binding, or start a Pod. The fresh writer
connects those steps. `ReadGatewayAuthReceipt` checks the
retained Secret's UID/revision, immutability, scope hashes, key presence and
expiration without returning key bytes. The caller must supply an independently
captured, durable Create-time Secret UID; using the read Secret's own UID is
not a recreation check. These Kubernetes annotations are **not**
a Headscale-signed proof of the full credential; restrictive Secret-write RBAC
and later state-to-node verification remain necessary.

The package-private `storeGatewayMintRecord` captures the Secret UID
and revision from a successful **Create response**, never from a later Get.
It rejects returned key bytes, key ID or expiry that differ from the mint response.
It then exclusively creates an immutable, ownerless `<gateway>-auth-receipt`
ConfigMap in the operator namespace. This record is separate from the nine rendered
resources and contains no credential bytes or credential hash. Its versioned schema
binds the Gateway and Tailnet names, UIDs, exact revisions and complete typed-spec
hashes to the Secret name, Create UID/revision, numeric key ID and absolute expiry.
Spec hashes use `encoding/json`: sorted map keys, original list order and the
Go types' default/omission semantics. Only admitted snapshots belong in this protocol.

`readGatewayMintRecord` uses explicit uncached reads and checks the trusted record
before accepting the Secret. Missing records, replaced Secrets, unknown schema
fields, expiry or changed scope block recovery. **Even metadata/status-only CR
updates or Secret metadata updates block reuse**, because revisions must match.
This strict reader is used during bootstrap. Completed-set observation uses the
separate `<gateway>-fresh` record to tolerate status/metadata-only CR changes;
Secret metadata changes and auth expiry still block it.
The ConfigMap is the durable trust anchor: its create/update/delete permissions
must be restricted as strictly as the Secret's. Immutability does not prevent
an authorized actor from deleting and forging both objects. Recording the
ConfigMap's own UID inside itself would not resolve that trust requirement.
These trust requirements also apply to the writer's completion receipt.

Failure handling does not adopt, overwrite, delete or remint:

- Secret Create response lost: no UID evidence; any persisted Secret remains blocked.
- Secret exists without a record: never reconstruct the record from Secret metadata.
- Record Create response lost: that attempt reports failure; a later read may verify
  an already persisted, trusted record.
- Scope changes between writes: partial objects remain retained; they do not authorize a Pod.

Isolated Kubernetes 1.31 tests exercise persistence through a new client, competing
writers, response loss, Create-time mutation, dry-run, immutability and UID replacement.
Their explicit legacy test adapter changes only in-memory suspend observations;
ordinary suspended observations still block writes. Admission now accepts activation.
Run them with `task test-validation` and explicit envtest assets. These tests do not prove process restart, production crash recovery or
cross-object atomicity. Sequential rechecks cannot close every race, and a durable
record does not prove that postflight checks completed. The writer also requires
its completion receipt and a live state-to-node check before reporting Ready.

`VerifyGatewayState` is the writer's post-registration check. For a retained
state Secret with the inventoried UID, it reads `_machinekey` and the active
`profile-*`, derives **public** machine and node keys, then requires one unique,
online Headscale node with matching public keys, name, tags and address; for a
new mint it can also require the issued key ID. The receipt contains only node
ID, IPv4 and Secret UID/revision. This reads **private Tailscale key material in
operator memory**; it never returns or logs it. The Go module pins Tailscale
1.94.1 while the modeled kernel image is 1.102.4. The isolated fresh-Pod gate
below verifies this state layout against Headscale 0.29.3 on Linux amd64,
including Pod recreation. The check alone does not establish service, DNS or route
health, or authorize adoption. The controller combines it with retained provenance,
Pod readiness and advertised-route observations. Read snapshots are not exclusive
locks; every Create can still conflict. DNS updates and live deployment compatibility
remain separate concerns. Suspended reconciliation never calls these helpers.

The pod Role permits only `get`, `update` and `patch` of the exact state Secret.
It cannot create missing state, read the auth Secret through the API, or list Secrets.
Only Tailscale mounts the rotating service-account token and state-cache directory.
The kubelet supplies the auth key through a Secret reference; the plan contains no key value.
Operator RBAC permits namespace-local creation of these resources. It does not
grant the Gateway Pod broader Secret access.

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
its `TS_AUTH_ONCE=true` restart path. Tags come from the verified bootstrap key,
not `--advertise-tags`: Headscale 0.29.3 rejects requested tags on pre-auth-key
registration, even when they match the key. This model never resets an adopted
node. There is no `--force-reauth`, ephemeral-key minting or offline-node deletion.

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
**not** a running kernel gateway or a TUN permission proof. The separate fresh-Pod
gate below binds and releases the live Pod before starting its kernel preflight.
The active writer connects credential provenance and resource creation. Broader
routing coverage and adoption remain open.

### Isolated fresh-Pod bootstrap gate

```sh
systemd-run --user --scope -p Delegate=yes -- \
  bash hack/e2e-kind-projection.sh --gateway-fresh-only
```

This opt-in selection has a 10-minute test budget, plus setup and cleanup. It
requires the runner's existing assets and the pinned gateway OCI archives
listed in the [Kind suite requirements](../../test/e2e-kind/README.md#requirements).
The runner verifies archive contents, platform/config digests and imported CRI
references before creating the Pod. A containerd archive-index alias is accepted
only when it belongs to that same verified image configuration.

`TestGatewayFreshPod` uses real Tailscale 1.102.4, CoreDNS 1.14.6 and Headscale
0.29.3. The test admits an active fresh CR and drives the production reconciler
in-process against the real Kubernetes API and Headscale REST endpoint.
The controller mints the key and creates state, receipts and rendered resources;
the StatefulSet controller creates the Pod. The test supplies the working API key
and owned hosts source, not the gateway bootstrap key or runtime objects.
The StatefulSet template gets fixture-only overrides: `PullNever`, the public fixture control CA,
IPv4 forwarding via the permitted namespaced sysctl, a short termination grace,
and `fsGroup: 65532` for the unprivileged gate's private EmptyDir. This does not
change the production template's security context. TUN, token and state mounts
remain isolated from CoreDNS and the gate.

The dedicated two-app/two-init startup contract preserves the existing single-app
contract. It checks the gate before `kernel-preflight`, rejects early execution,
requires successful preflight and binds both running images with zero restarts.
Both contracts share the same live UID/node/network proof and expiring approval.

On Linux amd64, the gate verifies a non-ephemeral tagged key, private state-to-node
binding, readiness and advertisement of the LAN and LB route prefixes. It then
deletes only the owned Pod; the StatefulSet creates its replacement with the same state Secret.
The new Pod must retain the Secret UID, Headscale node ID and IPv4, pass a new
startup proof and establish the same state-to-node binding. Private key bytes
remain in memory and are not written to evidence.

The same gate also checks the actual IPv4 data path, before and after Pod recreation:

- A separate, unprivileged target Pod supplies the advertised LAN /32. An independent
  UID65532 tsnet peer accepts routes; both pass the unchanged single-app startup gate.
- The fixture explicitly approves only that /32 on the state-bound Headscale node.
  A fresh TCP challenge must reach the target, whose accepted socket must observe
  the gateway Pod's source IPv4. A native-underlay control instead observes the peer
  Pod's IPv4. A connection alone, stale reply or direct Kubernetes shortcut cannot pass.
- Before approval and after revocation, the peer must observe the route as absent.
  It refuses to dial without a selected gateway route because `tsnet.Dial` can otherwise
  fall back to the native network. This checks route withdrawal and prevents fallback;
  it does **not** establish packet-level ACL denial or interruption of existing flows.
- UDP and TCP DNS queries go through tsnet to the gateway's tailnet IPv4 on port 53.
  Only `app.tail.example. IN A` is queried, without recursion. The response must be
  authoritative, match the fresh transaction/question, contain exactly the configured
  `198.51.100.8` answer and the expected local `tail.example. NS tail.example.` authority.
  Foreign authorities, CNAMEs, additional records and malformed wire data are rejected.

The target, peer and gateway retain their verified UIDs/processes throughout each phase.
This proves one IPv4 TCP subnet path and one local DNS name over UDP/TCP, not every route
or DNS feature. It does **not** prove DNS reload, egress-derived host routes, IPv6 routing,
arm64 execution, crash-safe writer recovery or interruption-free adoption. The same
run ends with a `deletionPolicy: Delete` teardown and checks that no labelled object,
the Headscale node or a usable bootstrap key remains. Activation requires explicit `suspend: false`; no production Pod-template
security change is needed for these checks.

## Deletion

`deletionPolicy` is the only consent record. With the default `Retain`, deleting the
CR removes nothing: no finalizer is set, the StatefulSet keeps running, the state and
auth Secrets, receipts, Headscale node and bootstrap key stay. Clean up by hand.

Setting `Delete` on an active (non-suspended) Gateway adds the finalizer
`tsunaro.io/gateway-teardown` on the next reconcile. Switching back to `Retain`
removes it again, also while the CR is already terminating: that is the escape hatch
when a teardown is blocked. The policy is consent, not identity: flipping it does
not touch the completion receipt, and a running Gateway stays Ready.

On deletion with the finalizer present the controller tears down, in this order and
fail-closed, only what this Gateway provably created:

1. The StatefulSet recorded in the `<gateway>-fresh` receipt, then it waits until no
   Pod labelled `tsunaro.io/gateway-uid=<CR UID>` remains (`Ready=False/Deleting`).
2. The Headscale node bound to the state Secret (`VerifyGatewayState`, falling back to
   `status.nodeId`); deleting it drops its route approvals. Then the minted bootstrap
   key is expired by its recorded ID. A user-supplied `authKeySecretRef` is never touched.
3. The remaining receipt children, each by the UID recorded at creation.
4. The auth Secret, the state Secret (UID must equal the receipt's), then the
   `-auth-receipt` and `-fresh` ConfigMaps last: the receipt is the inventory.

Every Kubernetes delete carries a UID precondition. An object under one of our names
with a different UID, a receipt without our label, or a Headscale error other than 404
blocks at that step: `Ready=False/TeardownBlocked` names the step, nothing further is
deleted, and the finalizer stays until the conflict is removed or the policy is set to
`Retain`. Without a completion receipt (partial creation) there is no child inventory:
only the state/auth Secrets and receipts carrying our label are removed and the key is
expired; children created before the fault remain. Deleting a suspended Gateway or one
reconciled without a runtime client always retains.

## Live DNS reconcile

Once a Gateway has recorded its completion receipt (`FreshObservation.Completed`),
the controller reconciles the derived `-coredns` ConfigMap against the Tailnet
hosts source on every pass of the normal 5 s requeue. The write path is the
existing `UpdateDNSRevision`:

- Re-render the zone from the live `hosts` source, Gateway and Tailnet; the SOA
  serial advances only when the semantic content hash changes (cosmetic
  reformatting of `hosts` is a no-op), and exhaustion is a hard failure, not a
  reset.
- Compare against the persisted CAS annotations `tsunaro.io/dns-serial` and
  `tsunaro.io/dns-content-sha256`; the hash is validated against the ConfigMap's
  actual payload, so a replaced zone without a matching hash blocks the write.
- Update the `-coredns` ConfigMap with the exact `resourceVersion` observed; a
  concurrent change retries up to three times, then surfaces as a conflict.
- Never create, replace or adopt the ConfigMap, the hosts source or any other
  receipt child. kubelet refreshes the Pod's projected volume (~60 s) and the
  CoreDNS `file` plugin reloads the zone (`reload 1s`).

The `DNSReady` condition reflects the writer verdict:

- `True / DNSInSync` — the derived zone matches the hosts source at the
  recorded serial.
- `False / DNSUpdateBlocked` — source, target or revision annotations are not
  verified; no update is attempted. Also used until the Gateway has a completion
  receipt and for Gateways rendered by versions before this slice (missing
  annotations are never treated as a fresh serial 1). Delete and recreate the
  Gateway (`deletionPolicy: Delete`) to migrate.
- `False / DNSUpdateConflict` — a concurrent change on the ConfigMap aborted
  the CAS; the next reconcile retries.

Only `zone.db` is excluded from the completion fingerprint; `Corefile` and every
other key stay digest-bound and still trip `FreshBlocked` on drift. The
`DNSReady` condition is independent of `Ready`: a successful live reconcile does
not make the gateway Ready, and a blocked DNS reconcile does not revoke it. The
receipt ConfigMaps still demand the trust of a Secret; whoever can rewrite the
`-coredns` annotations can forge zone provenance.

## Spec updates

A completed Gateway tolerates spec changes by field class. The receipt (format 2)
pins an identity hash of the fields whose change would need a new node or a new
runtime shape; everything else is either reconciled or irrelevant to the retained set.

| Class | Fields | Effect of a change |
|---|---|---|
| Pinned identity | `tailnetRef`, `hostname`, `stateSecretRef`, `tags`, `replicas`, `routes.*`, `service.*`, `dns.zone`, `dns.serviceName`, `dns.serviceClusterIP`, `dns.extraZones`, `forwardImage`, `forwards`; Tailnet `spec.server` and `spec.dns.hostsConfigMap` | `Ready=False/IdentityChanged`; nothing is written. Revert the field, or delete with `deletionPolicy: Delete` and recreate. |
| Live DNS | `dns.staticRecords`, `dns.wildcardAddress`, the hosts source | Re-rendered into `zone.db` ([Live DNS reconcile](#live-dns-reconcile)). |
| Images | `image` (tailscale and kernel-preflight), `dns.image` | Written into `spec.template` of the receipt StatefulSet; see below. |
| Consent / lifecycle | `deletionPolicy`, `suspend` | No effect on the receipt. |
| Other Tailnet fields | everything except `server` and `dns.hostsConfigMap` | No effect on the receipt. |

Routes stay pinned until a route reconciler exists. Receipts written before format 2
(releases up to 0.8.0) report `IdentityChanged`; migrate by deleting with
`deletionPolicy: Delete` and recreating.

**Images.** `UpdateWorkloadRevision` rewrites only the container `image` fields of the
StatefulSet template, after re-verifying the receipt UID and the image-less digest, with
the observed `resourceVersion` as CAS. The StatefulSet uses `OnDelete`: the operator
never restarts the Pod. The `WorkloadCurrent` condition reports the result:

- `True / PodCurrent` — the running Pod already uses the wanted images.
- `False / PodTemplateStale` — the template follows the spec; delete Pod `<gateway>-0`
  to apply it. The running Pod keeps serving and `Ready` is unaffected.
- `False / WorkloadUpdateConflict` — concurrent change; the next reconcile retries.
- `False / WorkloadUpdateBlocked` — StatefulSet or receipt is not verified; nothing is written.

The condition is absent while suspended, terminating or before a completion receipt.
The StatefulSet digest in the receipt covers everything except container images:
selector, `serviceName`, `updateStrategy`, `replicas` and every other template field
(command, env, volumes, security context, labels) still trip `FreshBlocked` on drift.

Ready no longer requires the Pod to match the current template (it may legitimately
predate an image change); it requires StatefulSet ownership by UID, the gateway and
state-UID labels, the service account, running and Ready containers, a verified state
binding and the advertised routes. The `update` verb on `statefulsets` is the only
write right added for this; it is never used on other kinds.

Envtest covers the controller path against a real API server with a synthetic Pod.
Kind proves, with the real StatefulSet controller, that an `image` change updates the
template, reports `PodTemplateStale`, keeps the Pod UID and container IDs, and
converges back after reverting. Rolling a Pod onto a *different* image is not proven in
kind: the startup gate binds the exact pinned reference.

## Fresh DNS rendering: partial implementation

`internal/gateway.RenderDNS` compiles a primary authoritative zone into `Corefile`
and `zone.db`. The fresh writer uses it through `RenderFresh` for initial creation.
It does not itself render a Pod or authorize adoption of existing CoreDNS configuration.

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

Initial creation checks scope and ownership. Future dynamic DNS integration must also:

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
  from the fresh-only controller. Cross-object source/target writes are not atomic;
  source watches, update ownership and live reload checks remain unimplemented.

  `TestDNSUpdateAPICAS` exercises this helper against an isolated Kubernetes 1.31
  API server in `task test-validation` and CI. It checks real resource-version
  conflicts, source/serial recomputation, preservation of concurrent metadata,
  three-attempt limits for target conflicts and source changes, and no-op behavior
  after a conflict or with a new client. Deleted
  or immutable targets are not recreated or replaced. A test-only client changes
  the legacy suspended fixture's in-memory observation to reach the helper;
  unmodified suspended observations still block it. The CRD now admits activation.
  This proves ConfigMap CAS behavior, not an admitted runtime, process restart,
  exclusive ownership, cross-object atomicity or live DNS reload.

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
watches and update serial persistence remain pending. The active controller creates
only the initial snapshot and never rewrites or resets a retained DNS ConfigMap.

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
While suspended, the controller sets `Ready=False/Suspended` and the other listed conditions to
`Unknown/Suspended`. It preserves last-known identity, routes and debounce fields;
these are not fresh observations. `observedGeneration` means the suspension was
processed, not that configuration was applied. Unrelated conditions are preserved.
A nil suspend value is treated as true. With explicit `false`, the minimal writer
reports `Provisioning`, `FreshBlocked`, `IdentityChanged`, missing dependencies, or `FreshRuntimeReady`.
`Registered`, `DNSReady` and `Ready` describe verified identity plus Pod/listener
health, not DNS query results. `RoutesInSync` is `True/Approved` once Headscale approved every
route of the completion receipt, `False/NotApproved` (message names the missing prefixes) otherwise,
and `Unknown` until the gateway is Ready. The gateway controller only reads this: when the Tailnet
owns its policy (`policy.mode: Apply`), the policy controller renders the gateway tags and routes
into `tagOwners`/`autoApprovers.routes` and its replay approves them within one policy reconcile
(≤ 5 min); otherwise approve in Headscale or through your own `autoApprovers`. Stale-node
management and cluster DNS forwarding stay `Unknown/ExternallyManaged`. No fresh Service-IP allocation
or debounce acknowledgement is claimed. Active gateways poll uncached children
every five seconds; unchanged status is not rewritten.

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
