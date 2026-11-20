package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TailnetRef selects a cluster-scoped Tailnet by name.
type TailnetRef struct {
	Name string `json:"name"`
}

// Target is one off-cluster host reachable over the tailnet, published as a Service.
type Target struct {
	// DNS-1035 label; used verbatim as the Service name, so consumers dial <name>.<ns>:<port>.
	// Start with a letter for compatibility with Kubernetes 1.31 Service admission.
	// +kubebuilder:validation:Pattern=`^[a-z]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`
	// IPv4/IPv6 address or lowercase MagicDNS name, not a CIDR, URL or host:port.
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:XValidation:rule="isIP(self) || (!self.matches('^[0-9.]+$') && self.matches('^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?([.][a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$'))",message="address must be an IP or a lowercase DNS name, not a CIDR or host:port"
	Address string `json:"address"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
	// Extra DNS names that resolve to this target's Service ClusterIP, rendered into the Tailnet's
	// dns.hostsConfigMap. Use them when the far end routes by name (TLS SNI, HTTP Host): a consumer
	// dialling the alias sends the real hostname, and the L4 tunnel passes it through untouched.
	// +optional
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	// +kubebuilder:validation:items:MaxLength=63
	Aliases []string `json:"aliases,omitempty"`
}

// SourcePrefix is a canonical, non-default CIDR of legacy clients allowed to use an exposed egress.
// Bounded (IPv4 at least /16, IPv6 at least /48) so a typo cannot open the bridge to a whole site.
// +kubebuilder:validation:MaxLength=49
// +kubebuilder:validation:XValidation:rule="isCIDR(self) && cidr(self).prefixLength() > 0 && string(cidr(self).masked()) == self",message="prefix must be a canonical masked non-default CIDR"
// +kubebuilder:validation:XValidation:rule="isCIDR(self) && (cidr(self).ip().family() == 4 ? cidr(self).prefixLength() >= 16 : cidr(self).prefixLength() >= 48)",message="prefix must be at least /16 (IPv4) or /48 (IPv6)"
type SourcePrefix string

// EgressExposeLoadBalancer passes implementation-specific LoadBalancer settings through to the Service.
// The operator interprets none of them; address assignment is the cluster's LB implementation.
type EgressExposeLoadBalancer struct {
	// spec.loadBalancerClass of the Service. Empty → the cluster default implementation.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*(/[a-z0-9A-Z]([-a-z0-9A-Z_.]*[a-z0-9A-Z])?)?$`
	Class string `json:"class,omitempty"`
	// Annotations copied onto the Service (address pools, pool selectors, BGP options …).
	// +optional
	// +kubebuilder:validation:MaxProperties=16
	Annotations map[string]string `json:"annotations,omitempty"`
	// Labels copied onto the Service, e.g. for LB-IPAM pool selectors. The operator's own
	// app.kubernetes.io/* labels cannot be overridden.
	// +optional
	// +kubebuilder:validation:MaxProperties=16
	// +kubebuilder:validation:XValidation:rule="!self.exists(k, k.startsWith('app.kubernetes.io/'))",message="labels must not set app.kubernetes.io/* keys"
	Labels map[string]string `json:"labels,omitempty"`
}

// EgressExpose publishes every target Service of this egress as a LoadBalancer on the site LAN, so hosts
// without a tailnet client reach tailnet services through this cluster. externalTrafficPolicy is
// fixed to Local: the rendered NetworkPolicy filters on the client address, which only survives
// when the LB keeps it. Every allowFrom entry must be inside the Tailnet's exposeSourceAllowlist.
type EgressExpose struct {
	// Client prefixes allowed to dial the exposed Services (NetworkPolicy ipBlock). Required and
	// bounded: no default route, IPv4 at least /16, IPv6 at least /48.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +listType=set
	AllowFrom []SourcePrefix `json:"allowFrom"`
	// +optional
	LoadBalancer EgressExposeLoadBalancer `json:"loadBalancer,omitempty"`
}

// EgressExposeStatus is the observed LAN side of an exposed egress.
type EgressExposeStatus struct {
	// Addresses the LB implementation assigned (IPs or hostnames), across all target Services.
	// +optional
	Addresses []string `json:"addresses,omitempty"`
}

// TailnetEgressSpec is the desired egress into a tailnet for one identity.
type TailnetEgressSpec struct {
	TailnetRef TailnetRef `json:"tailnetRef"`
	// Explicit tailnet tag. Empty → rendered from the Tailnet's tagTemplate. The tag is the
	// authorization: its grants in the tailnet policy decide which routes this node receives.
	// +optional
	Tag string `json:"tag,omitempty"`
	// Explicit tailnet hostname. Empty → rendered from the Tailnet's hostnameTemplate.
	// +optional
	Hostname string `json:"hostname,omitempty"`
	// Namespaces whose pods may reach this proxy's Services (NetworkPolicy ingress).
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	ConsumerNamespaces []string `json:"consumerNamespaces"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=50
	// +kubebuilder:validation:XValidation:rule="self.all(t, self.exists_one(other, other.name == t.name))",message="target names must be unique"
	Targets []Target `json:"targets"`
	// Override the Tailnet's default agent image.
	// +optional
	Image string `json:"image,omitempty"`
	// Override the Tailnet's default agent resources.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// Publish the target Services on the site LAN for clients without a tailnet node. Off when
	// empty: the Services stay ClusterIP, reachable from consumerNamespaces only.
	// +optional
	Expose *EgressExpose `json:"expose,omitempty"`
}

// TargetStatus is the per-target observed state.
type TargetStatus struct {
	Name string `json:"name"`
	// Local port the agent listens on and the Service forwards to.
	ListenPort int32 `json:"listenPort"`
	// The /32 or /128 this target needs in the netmap. Empty for a DNS-named target: a tailnet
	// peer is reached by its own address, no subnet route is involved.
	// +optional
	Route string `json:"route,omitempty"`
	// True once that route is present in the pod's netmap (always true for a DNS-named target).
	Present bool `json:"present"`
	// True once the agent last dialled the target successfully.
	Reachable bool `json:"reachable"`
	// When the route is missing: NotAdvertised, NotApproved or NoGrant. Empty when present.
	// +optional
	Reason string `json:"reason,omitempty"`
}

// TailnetEgressStatus is the observed state.
type TailnetEgressStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	Hostname string `json:"hostname,omitempty"`
	// Effective tag (spec.tag or the Tailnet template) — what the policy and the node carry.
	// +optional
	Tag string `json:"tag,omitempty"`
	// +optional
	NodeID string `json:"nodeId,omitempty"`
	// +optional
	TailnetIPs []string `json:"tailnetIps,omitempty"`
	// Expiry of the reusable pre-auth key currently in the agent's Secret.
	// +optional
	AuthKeyExpiresAt *metav1.Time `json:"authKeyExpiresAt,omitempty"`
	// +optional
	Targets []TargetStatus `json:"targets,omitempty"`
	// LAN side of spec.expose; absent when the egress is not exposed.
	// +optional
	Expose *EgressExposeStatus `json:"expose,omitempty"`
	// Conditions: TagKnown, Registered, RoutesGranted, TargetsReachable, Exposed (only with
	// spec.expose), Ready.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=tneg
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Tag",type=string,JSONPath=`.status.tag`
// +kubebuilder:printcolumn:name="Hostname",type=string,JSONPath=`.status.hostname`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Address",type=string,priority=1,JSONPath=`.status.expose.addresses[0]`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TailnetEgress is a per-identity egress into a Tailnet. It lives in the operator's namespace; a
// NetworkPolicy decides which namespaces may use it.
// +kubebuilder:validation:XValidation:rule="size(self.metadata.name) <= 40 && self.metadata.name.matches('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')",message="name must be a DNS label of at most 40 characters"
type TailnetEgress struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TailnetEgressSpec   `json:"spec"`
	Status TailnetEgressStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TailnetEgressList is a list of TailnetEgress.
type TailnetEgressList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TailnetEgress `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TailnetEgress{}, &TailnetEgressList{})
}
