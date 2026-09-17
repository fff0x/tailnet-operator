package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Backend is the in-cluster Service an Expose forwards to. Same namespace as the CR on purpose: a
// tenant exposes exactly what lives in its own namespace, never a Service it does not own.
type Backend struct {
	// Service name in the CR's own namespace.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Service string `json:"service"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// Expose publishes one in-cluster backend on the tailnet node, listening on Port.
type Expose struct {
	// DNS label; identifies the expose in status and in the agent config.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`
	// Port the tailnet node listens on — what a tailnet peer dials on this node's MagicDNS name/IP.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port    int32   `json:"port"`
	Backend Backend `json:"backend"`
}

// TailnetIngressSpec exposes in-cluster L4 services on the tailnet as one tsnet node. It is the
// mirror of TailnetEgress: instead of dialling out over the tailnet, the node listens on the tailnet
// and forwards inbound connections to in-cluster backends.
type TailnetIngressSpec struct {
	TailnetRef TailnetRef `json:"tailnetRef"`
	// Explicit tailnet tag. Empty → rendered from the Tailnet's ingressTagTemplate. The tag is the
	// authorization: policy grants with dst = this tag decide which peers may reach the node.
	// +optional
	Tag string `json:"tag,omitempty"`
	// Explicit tailnet (MagicDNS) hostname. Empty → rendered from the Tailnet's ingressHostnameTemplate.
	// +optional
	Hostname string `json:"hostname,omitempty"`
	// +kubebuilder:validation:MinItems=1
	Exposes []Expose `json:"exposes"`
	// Override the Tailnet's default agent image.
	// +optional
	Image string `json:"image,omitempty"`
	// Override the Tailnet's default agent resources.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
}

// ExposeStatus is the per-expose observed state.
type ExposeStatus struct {
	Name string `json:"name"`
	// Port the tailnet node listens on for this expose.
	ListenPort int32 `json:"listenPort"`
	// The in-cluster backend the agent dials, as service:port.
	Backend string `json:"backend"`
	// True once the agent last dialled the backend successfully.
	Reachable bool `json:"reachable"`
	// Empty when reachable; "Unreachable" otherwise.
	// +optional
	Reason string `json:"reason,omitempty"`
}

// TailnetIngressStatus is the observed state.
type TailnetIngressStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	Hostname string `json:"hostname,omitempty"`
	// +optional
	NodeID string `json:"nodeId,omitempty"`
	// +optional
	TailnetIPs []string `json:"tailnetIps,omitempty"`
	// Expiry of the reusable pre-auth key currently in the agent's Secret.
	// +optional
	AuthKeyExpiresAt *metav1.Time `json:"authKeyExpiresAt,omitempty"`
	// +optional
	Exposes []ExposeStatus `json:"exposes,omitempty"`
	// Conditions: TagKnown, Registered, BackendsReachable, Ready.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=tning
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Tag",type=string,JSONPath=`.spec.tag`
// +kubebuilder:printcolumn:name="Hostname",type=string,JSONPath=`.status.hostname`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TailnetIngress exposes in-cluster L4 services on the tailnet as one tsnet node with a MagicDNS
// name. It lives in the tenant namespace; the tag's grants decide which tailnet peers may reach it.
type TailnetIngress struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TailnetIngressSpec   `json:"spec,omitempty"`
	Status TailnetIngressStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TailnetIngressList is a list of TailnetIngress.
type TailnetIngressList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TailnetIngress `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TailnetIngress{}, &TailnetIngressList{})
}
