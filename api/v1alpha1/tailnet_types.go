package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretKeyRef points at one key in a Secret in the operator's own namespace.
type SecretKeyRef struct {
	Name string `json:"name"`
	// +kubebuilder:default="apiKey"
	Key string `json:"key,omitempty"`
}

// ProxySpec are the defaults for the per-CR agent pods this Tailnet spawns. A TailnetEgress may
// override image and resources.
type ProxySpec struct {
	// Container image carrying the tailnet-agent binary. Empty → the operator's own image, so a
	// single pushed image serves both control and data plane.
	// +optional
	Image string `json:"image,omitempty"`
	// Names of existing image-pull Secrets in each agent pod's namespace. Omitted inherits
	// the operator defaults; an explicit empty list disables those defaults. Duplicate names
	// are collapsed when building pods because Kubernetes merges these references by name.
	// +optional
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=253
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	ImagePullSecrets *[]string `json:"imagePullSecrets,omitempty"`
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// tsnet outer path MTU. 1200 leaves headroom for a ~1320-byte outer path (typical cloud CNI overlay).
	// +kubebuilder:default=1200
	// +kubebuilder:validation:Minimum=576
	// +kubebuilder:validation:Maximum=1500
	MTU int32 `json:"mtu,omitempty"`
	// How often the agent probes each target for reachability. "0s" disables probing.
	// +kubebuilder:default="5m"
	ProbeInterval metav1.Duration `json:"probeInterval,omitempty"`
}

// DNSSpec turns CR names into DNS records. The operator renders a CoreDNS `hosts` file into a
// ConfigMap in its own namespace; the cluster mounts it into a resolver that is authoritative for
// the zones involved (see README "DNS names"). Both fields empty → no records are rendered.
type DNSSpec struct {
	// Name of the ConfigMap (operator namespace, key "hosts") that receives the rendered hosts file.
	// Empty → the feature is off and a previously rendered ConfigMap is removed.
	// +optional
	HostsConfigMap string `json:"hostsConfigMap,omitempty"`
	// Template for a TailnetIngress's DNS name; {name} is the CR name, {namespace} its namespace.
	// Keep the result one label below your gateway's wildcard certificate, e.g.
	// "{name}-{namespace}.prod-1.tailnet.example.internal". Empty → ingresses get no name.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:XValidation:rule="self == '' || (self.contains('{name}') && self.replace('{name}', 'n').replace('{namespace}', 'ns').matches('^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?([.][a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$') && self.matches('[.][a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?[.][a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$'))",message="ingressNameTemplate must contain {name} and end in a literal lowercase DNS zone with at least two labels"
	IngressNameTemplate string `json:"ingressNameTemplate,omitempty"`
	// Optional template for a shorter DNS alias of an HTTP expose that opts in with `alias: true`.
	// Same placeholders as ingressNameTemplate; {name} is the expose's effective label (dnsLabel or
	// the CR name). The operator requires the alias to end in the SAME literal zone as
	// ingressNameTemplate, because only that zone is guaranteed to resolve over the tailnet.
	// Empty → aliases are disabled. The alias becomes an additional certificate SAN and SNI route;
	// a name claimed by two CRs is resolved oldest-first and the loser reports DNSNameConflict.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:XValidation:rule="self == '' || (self.contains('{name}') && self.replace('{name}', 'n').replace('{namespace}', 'ns').matches('^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?([.][a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$') && self.matches('[.][a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?[.][a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$'))",message="ingressAliasTemplate must contain {name} and end in a literal lowercase DNS zone with at least two labels"
	IngressAliasTemplate string `json:"ingressAliasTemplate,omitempty"`
}

// PolicySpec lets the operator own the control server's policy (Headscale "database" policy mode).
// A human-written base document stays in Git; the operator appends what the CRs imply — tagOwners
// for every egress/ingress/gateway tag, autoApprovers for every egress target /32 (approved by
// routeApprovers) and for every TailnetGateway route (approved by that gateway's own tags), and one
// grant per (egress, port) or ingress — and writes the union with PUT /api/v1/policy. Base entries always win
// over generated ones; the operator never removes anything from the base.
// Exactly one operator may run in Apply mode against a control server.
// +kubebuilder:validation:XValidation:rule="!((has(self.baseConfigMap) && size(self.baseConfigMap) > 0) || (has(self.mode) && self.mode == 'Export')) || (has(self.tagOwners) && size(self.tagOwners) > 0 && has(self.routeApprovers) && size(self.routeApprovers) > 0)",message="policy.tagOwners and policy.routeApprovers are required when baseConfigMap is set or mode is Export"
// +kubebuilder:validation:XValidation:rule="!(has(self.mode) && self.mode == 'Export') || ((!has(self.baseConfigMap) || size(self.baseConfigMap) == 0) && (!has(self.fragmentConfigMaps) || size(self.fragmentConfigMaps) == 0))",message="mode Export is a spoke: leave baseConfigMap and fragmentConfigMaps empty"
// +kubebuilder:validation:XValidation:rule="!has(self.fragmentConfigMaps) || size(self.fragmentConfigMaps) == 0 || (has(self.baseConfigMap) && size(self.baseConfigMap) > 0)",message="policy.fragmentConfigMaps requires baseConfigMap"
// +kubebuilder:validation:XValidation:rule="!has(self.spokes) || size(self.spokes) == 0 || ((has(self.baseConfigMap) && size(self.baseConfigMap) > 0) && (!has(self.mode) || self.mode != 'Export'))",message="policy.spokes requires baseConfigMap and is not allowed in mode Export"
type PolicySpec struct {
	// ConfigMap (operator namespace, key "policy") holding the base policy in HuJSON.
	// Empty → the feature is off and nothing is rendered or written.
	// +optional
	BaseConfigMap string `json:"baseConfigMap,omitempty"`
	// ConfigMap (operator namespace, key "policy") that receives the rendered policy (Apply/DryRun)
	// or the exported fragment (Export) for review.
	// Empty → "<baseConfigMap>-rendered" (Apply/DryRun) or "<tailnet>-policy-fragment" (Export).
	// +optional
	RenderedConfigMap string `json:"renderedConfigMap,omitempty"`
	// DryRun renders into renderedConfigMap only; Apply also writes the control server when the
	// live policy differs; Export renders only this Tailnet's generated entries (no base, no write)
	// into renderedConfigMap so a hub operator can merge them via fragmentConfigMaps; PolicyApplied
	// reports HubMerged/HubPending by comparing the fragment with the live policy. Start with
	// DryRun, compare, then switch.
	// +kubebuilder:validation:Enum=DryRun;Apply;Export
	// +kubebuilder:default=DryRun
	Mode string `json:"mode,omitempty"`
	// ConfigMaps (operator namespace, key "policy") holding fragments exported by spoke Tailnets
	// (mode Export on another cluster, committed here after review). Each is merged after the base
	// and this cluster's own CRs; base and own entries win. A listed fragment that is missing or
	// malformed fails the render closed (no write) rather than dropping the spoke's grants.
	// Only valid alongside baseConfigMap.
	// +optional
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MaxLength=253
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	// +listType=set
	FragmentConfigMaps []string `json:"fragmentConfigMaps,omitempty"`
	// Spoke clusters whose exported fragment this hub pulls itself (instead of a committed
	// fragmentConfigMaps entry): the hub reads the spoke's fragment ConfigMap with the kubeconfig
	// in kubeconfigSecretRef, validates it against this hub's limits and the spoke's tagPatterns /
	// routeAllowlist, and merges it per the spoke's approval mode. Only valid alongside
	// baseConfigMap; never in mode Export.
	// +optional
	// +kubebuilder:validation:MaxItems=32
	// +listType=map
	// +listMapKey=name
	Spokes []SpokeRef `json:"spokes,omitempty"`
	// Owners of the generated tags (tagOwners value), e.g. ["group:operator"]. Required when on.
	// +optional
	TagOwners []string `json:"tagOwners,omitempty"`
	// Approvers for the generated autoApprovers.routes entries (one /32 per egress target), i.e.
	// the tag your subnet routers carry, e.g. ["tag:fabric"]. Required when on.
	// +optional
	RouteApprovers []string `json:"routeApprovers,omitempty"`
	// Glob patterns a TailnetIngress.spec.allowFrom entry must match, e.g. ["group:*"]. Ingress CRs
	// live in tenant namespaces, so this is the admin's veto over who tenants may grant access to.
	// Empty → no ingress grants are generated (only the tag is declared).
	// +optional
	// +kubebuilder:validation:items:MaxLength=253
	// +kubebuilder:validation:items:Pattern=`^((group:|tag:|autogroup:)[^[:space:]]+|[^@[:space:]]+@[^@[:space:]]+)$`
	IngressSourceAllowlist []string `json:"ingressSourceAllowlist,omitempty"`
}

// SpokeRef is one spoke cluster the hub pulls a policy fragment from.
type SpokeRef struct {
	// Spoke name; used in status, events, metrics and the approve annotation
	// "tsunaro.io/approve-spoke.<name>".
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`
	// Secret (operator namespace) holding a kubeconfig for the spoke's API server. Mint it for a
	// ServiceAccount that may only get/list/watch the fragment ConfigMap (the chart's
	// policy.fragmentReader on the spoke renders exactly that).
	KubeconfigSecretRef SpokeKubeconfigRef `json:"kubeconfigSecretRef"`
	// Namespace on the spoke holding the fragment ConfigMap. Empty → this operator's namespace.
	// +optional
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^([a-z0-9]([-a-z0-9]*[a-z0-9])?)?$`
	Namespace string `json:"namespace,omitempty"`
	// Fragment ConfigMap on the spoke (key "policy"). Empty → "<name>-policy-fragment".
	// +optional
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^([a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*)?$`
	ConfigMap string `json:"configMap,omitempty"`
	// Glob patterns the spoke's own tags must match, e.g. ["tag:*-prod-2-*"]; tags already owned
	// by the hub's base document are exempt. Empty → ["tag:*-<name>-*"].
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MaxLength=253
	// +kubebuilder:validation:items:Pattern=`^tag:[^[:space:]]+$`
	TagPatterns []string `json:"tagPatterns,omitempty"`
	// Prefixes (besides this hub's TailnetSites) a spoke route or grant destination that is not a
	// host address may lie within. Host routes (/32, /128) are always accepted unless reserved.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	RouteAllowlist []GatewayPrefix `json:"routeAllowlist,omitempty"`
	// Auto merges every valid fetched fragment at once. Manual merges the last approved fragment
	// only and reports a changed fetch as pending until an admin annotates the Tailnet with
	// "tsunaro.io/approve-spoke.<name>: <pendingHash>".
	// +kubebuilder:validation:Enum=Auto;Manual
	// +kubebuilder:default=Auto
	Approval string `json:"approval,omitempty"`
}

// SpokeKubeconfigRef names the Secret key holding a spoke kubeconfig.
type SpokeKubeconfigRef struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// +kubebuilder:default="kubeconfig"
	Key string `json:"key,omitempty"`
}

// HeadscaleSpec describes the external control server. Version is an optional operator-supplied
// hint, not an observed version; capability probes determine compatibility.
type HeadscaleSpec struct {
	// Optional version hint for diagnostics, e.g. "0.29.3". Does not bypass capability checks.
	// +optional
	Version string `json:"version,omitempty"`
	// Reserved for an operator-managed Headscale. Must remain empty until managed mode is supported.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == ''",message="headscale.ref is reserved; managed Headscale is not supported yet"
	Ref string `json:"ref,omitempty"`
}

// ReservedNetwork is address space no TailnetSite may overlap: the node prefix of the control
// server, and per cluster its LAN, pod, service and tailnet-LB ranges. A site overlapping one of
// these is blocked with RouteConflict/OverlapsReserved naming this entry.
type ReservedNetwork struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +listType=set
	Prefixes []GatewayPrefix `json:"prefixes"`
}

// TailnetSpec describes a control server and how the operator authenticates to it.
type TailnetSpec struct {
	// Defaults inherited by ingress resources that do not select their own TLS source.
	// +optional
	Defaults TailnetDefaults `json:"defaults,omitempty"`
	// Login/control URL, becomes the agent's ControlURL (e.g. https://ts.example.com).
	// +kubebuilder:validation:Pattern=`^https://`
	// +kubebuilder:validation:MinLength=9
	Server string `json:"server"`
	// In-cluster URL for the REST API if it differs from Server. Empty → Server.
	// +optional
	APIURL string `json:"apiUrl,omitempty"`
	// External Headscale metadata; compatibility is checked against the API, not the version hint.
	// +optional
	Headscale HeadscaleSpec `json:"headscale,omitempty"`
	// Bootstrap API key, read only. The operator mints its own rotating working key from it and
	// never writes back here — so this may live in GitOps without a rotation fight.
	APISecretRef SecretKeyRef `json:"apiSecretRef"`
	// Lifetime of the self-minted working API key. Rotated at half-life.
	// +kubebuilder:default="720h"
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:MaxLength=32
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('1h')",message="apiKeyLifetime must be a valid duration of at least 1h"
	APIKeyLifetime metav1.Duration `json:"apiKeyLifetime,omitempty"`
	// Lifetime of the reusable ephemeral pre-auth keys handed to agents. Rotated at half-life.
	// +kubebuilder:default="168h"
	AuthKeyLifetime metav1.Duration `json:"authKeyLifetime,omitempty"`
	// +optional
	Proxy ProxySpec `json:"proxy,omitempty"`
	// Template for a TailnetEgress's tag when it sets none. {name} is the CR name.
	// The tag IS the authorization — its grants decide which routes the node sees.
	// +kubebuilder:default="tag:egress-{name}"
	TagTemplate string `json:"tagTemplate,omitempty"`
	// Template for a TailnetEgress's tailnet hostname when it sets none. {name} is the CR name.
	// +kubebuilder:default="egress-{name}"
	HostnameTemplate string `json:"hostnameTemplate,omitempty"`
	// Template for a TailnetIngress's tag when it sets none. {name} is the CR name.
	// The tag IS the authorization — its grants (dst = this tag) decide which peers may reach it.
	// +kubebuilder:default="tag:ingress-{name}"
	IngressTagTemplate string `json:"ingressTagTemplate,omitempty"`
	// Template for a TailnetIngress's tailnet (MagicDNS) hostname when it sets none. {name} is the CR name.
	// +kubebuilder:default="ingress-{name}"
	IngressHostnameTemplate string `json:"ingressHostnameTemplate,omitempty"`
	// DNS records rendered from egress aliases and ingress names. Off when empty.
	// +optional
	DNS DNSSpec `json:"dns,omitempty"`
	// Policy generation from CRs. Off when baseConfigMap is empty.
	// +optional
	Policy PolicySpec `json:"policy,omitempty"`
	// Address space TailnetSite prefixes must not overlap (node prefix, every cluster's LAN/pod/
	// service/LB ranges on this control server). Only consulted for TailnetSite CRs.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +listType=map
	// +listMapKey=name
	ReservedNetworks []ReservedNetwork `json:"reservedNetworks,omitempty"`
	// Client prefixes a TailnetEgress.spec.expose.allowFrom entry must lie within. Egress CRs are
	// written by tenants, so this is the admin's veto over which site hosts may use a bridge.
	// Empty → no egress may be exposed (Exposed=False/Denied).
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	ExposeSourceAllowlist []GatewayPrefix `json:"exposeSourceAllowlist,omitempty"`
	// DNS zones a TailnetIngress.spec.exposes[].bridgeNames entry must lie within (proper
	// subdomain), e.g. ["site.example.internal"]. Bridge names are extra certificate SANs and SNI
	// routes for clients that reach the ingress through a bridge and resolve the name in their own
	// zone; the operator neither renders nor claims them. Ingress CRs are written by tenants, so
	// this is the admin's veto over which foreign zones may be served. Empty → no bridge names
	// (TLSReady=False/BridgeNameDenied).
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MaxLength=253
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)+$`
	// +listType=set
	BridgeNameAllowlist []string `json:"bridgeNameAllowlist,omitempty"`
}

// PolicyGenerated counts what the operator added to the base policy.
type PolicyGenerated struct {
	Tags   int `json:"tags"`
	Grants int `json:"grants"`
	Routes int `json:"routes"`
}

// PolicyStatus reports the rendered and applied policy.
type PolicyStatus struct {
	// sha256 of the canonical rendered policy.
	// +optional
	RenderedHash string `json:"renderedHash,omitempty"`
	// sha256 of the policy last written to (or found identical on) the control server.
	// +optional
	AppliedHash string `json:"appliedHash,omitempty"`
	// +optional
	AppliedAt *metav1.Time `json:"appliedAt,omitempty"`
	// +optional
	Generated PolicyGenerated `json:"generated,omitempty"`
}

// SpokeStatus reports one pulled spoke fragment: what was fetched, what is merged, what waits.
type SpokeStatus struct {
	Name string `json:"name"`
	// sha256 of the last fragment fetched and found valid.
	// +optional
	FetchedHash string `json:"fetchedHash,omitempty"`
	// When fetchedHash last changed — not a heartbeat. The SpokeReachable condition is refreshed on
	// every reconcile.
	// +optional
	FetchedAt *metav1.Time `json:"fetchedAt,omitempty"`
	// sha256 of the fragment currently merged into the hub policy, and when it was adopted.
	// +optional
	ApprovedHash string `json:"approvedHash,omitempty"`
	// +optional
	ApprovedAt *metav1.Time `json:"approvedAt,omitempty"`
	// Manual approval only: hash of a valid fetch that differs from approvedHash, since when, and
	// what it would add or remove. Annotate the Tailnet with
	// "tsunaro.io/approve-spoke.<name>: <pendingHash>" to adopt it.
	// +optional
	PendingHash string `json:"pendingHash,omitempty"`
	// +optional
	PendingSince *metav1.Time `json:"pendingSince,omitempty"`
	// +optional
	PendingDelta *SpokeDelta `json:"pendingDelta,omitempty"`
	// Conditions: SpokeReachable, SpokeFragmentValid, SpokeFragmentApproved.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// SpokeDelta counts the entries a pending fragment adds (+) and removes (-) against the approved one.
type SpokeDelta struct {
	TagsAdded     int `json:"tagsAdded"`
	TagsRemoved   int `json:"tagsRemoved"`
	GrantsAdded   int `json:"grantsAdded"`
	GrantsRemoved int `json:"grantsRemoved"`
	RoutesAdded   int `json:"routesAdded"`
	RoutesRemoved int `json:"routesRemoved"`
}

// TailnetStatus is the observed state of the control server binding.
type TailnetStatus struct {
	// Policy rendering/apply state; conditions PolicyRendered and PolicyApplied carry the reasons.
	// +optional
	Policy *PolicyStatus `json:"policy,omitempty"`
	// One entry per policy.spokes[] item; condition SpokesReady summarises them.
	// +optional
	// +listType=map
	// +listMapKey=name
	Spokes []SpokeStatus `json:"spokes,omitempty"`
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Reported control-server version, for the operator log and the printcolumn.
	// +optional
	Version string `json:"version,omitempty"`
	// Expiry of the current working API key, drives the ApiKeyValid condition and its metric.
	// +optional
	APIKeyExpiresAt *metav1.Time `json:"apiKeyExpiresAt,omitempty"`
	// Headscale user names that more than one user carries. Such a collision makes Headscale
	// reject every policy write ("multiple users found"); condition UsersUnique reports it. Only
	// the count is published, never a name.
	// +optional
	UserConflicts int32 `json:"userConflicts,omitempty"`
	// Conditions: ApiReachable, ApiKeyValid, HeadscaleCompatible, PolicyMode, SplitDNS,
	// UsersUnique, PolicyRendered, PolicyApplied, SpokesReady (only with policy.spokes).
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=tn
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Server",type=string,JSONPath=`.spec.server`
// +kubebuilder:printcolumn:name="ApiKey",type=string,JSONPath=`.status.conditions[?(@.type=="ApiKeyValid")].status`
// Expires is a string, not a date: kubectl's date column renders future timestamps as "<invalid>".
// +kubebuilder:printcolumn:name="Expires",type=string,JSONPath=`.status.apiKeyExpiresAt`
// +kubebuilder:printcolumn:name="Compat",type=string,JSONPath=`.status.conditions[?(@.type=="HeadscaleCompatible")].reason`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.status.conditions[?(@.type=="PolicyApplied")].reason`
// +kubebuilder:printcolumn:name="Spokes",type=string,JSONPath=`.status.conditions[?(@.type=="SpokesReady")].reason`
// +kubebuilder:printcolumn:name="DNS",type=string,JSONPath=`.status.conditions[?(@.type=="SplitDNS")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Tailnet is a cluster-scoped binding to one control server.
type Tailnet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TailnetSpec   `json:"spec"`
	Status TailnetStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TailnetList is a list of Tailnet.
type TailnetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Tailnet `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Tailnet{}, &TailnetList{})
}
