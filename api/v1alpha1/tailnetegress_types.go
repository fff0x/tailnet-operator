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
}

// TargetStatus is the per-target observed state.
type TargetStatus struct {
	Name string `json:"name"`
	// Local port the agent listens on and the Service forwards to.
	ListenPort int32 `json:"listenPort"`
	// The /32 or /128 this target needs in the netmap.
	Route string `json:"route"`
	// True once that route is present in the pod's netmap.
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
	// Conditions: TagKnown, Registered, RoutesGranted, TargetsReachable, Ready.
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
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
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
