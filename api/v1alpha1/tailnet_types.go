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
	IngressNameTemplate string `json:"ingressNameTemplate,omitempty"`
}

// TailnetSpec describes a control server and how the operator authenticates to it.
type TailnetSpec struct {
	// Login/control URL, becomes the agent's ControlURL (e.g. https://ts.example.com).
	Server string `json:"server"`
	// In-cluster URL for the REST API if it differs from Server. Empty → Server.
	// +optional
	APIURL string `json:"apiUrl,omitempty"`
	// Bootstrap API key, read only. The operator mints its own rotating working key from it and
	// never writes back here — so this may live in GitOps without a rotation fight.
	APISecretRef SecretKeyRef `json:"apiSecretRef"`
	// Lifetime of the self-minted working API key. Rotated at half-life.
	// +kubebuilder:default="720h"
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
}

// TailnetStatus is the observed state of the control server binding.
type TailnetStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Reported control-server version, for the operator log and the printcolumn.
	// +optional
	Version string `json:"version,omitempty"`
	// Expiry of the current working API key, drives the ApiKeyValid condition and its metric.
	// +optional
	APIKeyExpiresAt *metav1.Time `json:"apiKeyExpiresAt,omitempty"`
	// Conditions: ApiReachable, ApiKeyValid.
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
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Tailnet is a cluster-scoped binding to one control server.
type Tailnet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TailnetSpec   `json:"spec,omitempty"`
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
