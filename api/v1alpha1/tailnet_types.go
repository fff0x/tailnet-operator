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
}

// PolicySpec lets the operator own the control server's policy (Headscale "database" policy mode).
// A human-written base document stays in Git; the operator appends what the CRs imply — tagOwners
// for every egress/ingress tag, autoApprovers for every egress target /32 and one grant per
// (egress, port) or ingress — and writes the union with PUT /api/v1/policy. Base entries always win
// over generated ones; the operator never removes anything from the base.
// Exactly one operator may run in Apply mode against a control server.
// +kubebuilder:validation:XValidation:rule="!has(self.baseConfigMap) || size(self.baseConfigMap) == 0 || (has(self.tagOwners) && size(self.tagOwners) > 0 && has(self.routeApprovers) && size(self.routeApprovers) > 0)",message="policy.tagOwners and policy.routeApprovers are required when baseConfigMap is set"
type PolicySpec struct {
	// ConfigMap (operator namespace, key "policy") holding the base policy in HuJSON.
	// Empty → the feature is off and nothing is rendered or written.
	// +optional
	BaseConfigMap string `json:"baseConfigMap,omitempty"`
	// ConfigMap (operator namespace, key "policy") that receives the rendered policy for review.
	// Empty → "<baseConfigMap>-rendered".
	// +optional
	RenderedConfigMap string `json:"renderedConfigMap,omitempty"`
	// DryRun renders into renderedConfigMap only; Apply also writes the control server when the
	// live policy differs. Start with DryRun, compare, then switch.
	// +kubebuilder:validation:Enum=DryRun;Apply
	// +kubebuilder:default=DryRun
	Mode string `json:"mode,omitempty"`
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

// TailnetStatus is the observed state of the control server binding.
type TailnetStatus struct {
	// Policy rendering/apply state; conditions PolicyRendered and PolicyApplied carry the reasons.
	// +optional
	Policy *PolicyStatus `json:"policy,omitempty"`
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Reported control-server version, for the operator log and the printcolumn.
	// +optional
	Version string `json:"version,omitempty"`
	// Expiry of the current working API key, drives the ApiKeyValid condition and its metric.
	// +optional
	APIKeyExpiresAt *metav1.Time `json:"apiKeyExpiresAt,omitempty"`
	// Conditions: ApiReachable, ApiKeyValid, HeadscaleCompatible, PolicyMode, SplitDNS,
	// PolicyRendered, PolicyApplied.
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
