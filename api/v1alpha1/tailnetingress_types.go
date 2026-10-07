package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Backend is the in-cluster Service an Expose forwards to. Namespace defaults to the CR's
// namespace; an explicit namespace can reference a shared gateway or another backend.
type Backend struct {
	// Service name; in the CR's own namespace unless Namespace is set.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=63
	Service string `json:"service"`
	// Namespace of the Service. Empty → the CR's namespace. Set it to funnel HTTPS through a
	// shared gateway (e.g. Envoy in envoy-gateway-system) so TLS terminates there while the tailnet
	// identity stays per app.
	// +optional
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace,omitempty"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
	// Verified HTTPS to the backend. Omission preserves plaintext HTTP.
	// +optional
	TLS *BackendTLS `json:"tls,omitempty"`
}

// BackendTLS selects explicit backend trust, separate from the frontend TLS source.
type BackendTLS struct {
	// DNS name verified against the backend certificate; does not change the dial address or HTTP Host.
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$`
	// +kubebuilder:validation:XValidation:rule="!isIP(self)",message="serverName must be a DNS name, not an IP address"
	ServerName string `json:"serverName"`
	// Public CA bundle in the ingress CR namespace, even if the backend is elsewhere.
	CAConfigMapRef CAConfigMapRef `json:"caConfigMapRef"`
}

// CAConfigMapRef selects exactly one public PEM bundle key. No system-root fallback is used.
type CAConfigMapRef struct {
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[-._a-zA-Z0-9]+$`
	Key string `json:"key"`
}

// HTTPTimeouts controls independent HTTP timers. Omission preserves existing behavior;
// explicit 0s disables the selected timer. Upgraded connections are not timed.
type HTTPTimeouts struct {
	// Whole-response deadline. Omitted means no deadline.
	// +optional
	// +kubebuilder:validation:MaxLength=32
	// +kubebuilder:validation:Pattern=`^([0-9]{1,5}(h|m|s|ms)){1,4}$`
	Request *string `json:"request,omitempty"`
	// Wait for backend response headers after sending the request body. Defaults to 30s.
	// +optional
	// +kubebuilder:validation:MaxLength=32
	// +kubebuilder:validation:Pattern=`^([0-9]{1,5}(h|m|s|ms)){1,4}$`
	BackendRequest *string `json:"backendRequest,omitempty"`
}

// Expose publishes one in-cluster backend on the tailnet node, listening on Port.
// +kubebuilder:validation:XValidation:rule="!has(self.mode) || self.mode != 'http' || self.port == 443",message="HTTP exposes must listen on port 443"
// +kubebuilder:validation:XValidation:rule="!has(self.backend.tls) || (has(self.mode) && self.mode == 'http')",message="backend TLS requires HTTP mode"
// +kubebuilder:validation:XValidation:rule="!has(self.timeouts) || (has(self.mode) && self.mode == 'http')",message="timeouts require HTTP mode"
// +kubebuilder:validation:XValidation:rule="!has(self.dnsLabel) || (has(self.mode) && self.mode == 'http')",message="dnsLabel requires HTTP mode"
// +kubebuilder:validation:XValidation:rule="!has(self.alias) || !self.alias || (has(self.mode) && self.mode == 'http')",message="alias requires HTTP mode"
type Expose struct {
	// Listener mode. Omitted means L4 forwarding; HTTP requests TLS termination.
	// +optional
	// +kubebuilder:default=l4
	// +kubebuilder:validation:Enum=l4;http
	// +kubebuilder:validation:MaxLength=4
	Mode string `json:"mode,omitempty"`
	// DNS label; identifies the expose in status and in the agent config.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`
	// HTTP DNS label substituted for {name} in the Tailnet's ingressNameTemplate.
	// Omitted or empty uses the ingress-level name; does not change the expose identifier.
	// +optional
	// +kubebuilder:validation:Pattern=`^([a-z0-9]([-a-z0-9]*[a-z0-9])?)?$`
	// +kubebuilder:validation:MaxLength=63
	DNSLabel string `json:"dnsLabel,omitempty"`
	// Request a shorter DNS alias for this HTTP expose, rendered from the Tailnet's
	// ingressAliasTemplate with the effective label (dnsLabel or the CR name). Requires
	// ingressAliasTemplate to be set; otherwise the CR reports InvalidDNSName.
	// +optional
	Alias bool `json:"alias,omitempty"`
	// Port the tailnet node listens on — what a tailnet peer dials on this node's MagicDNS name/IP.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port    int32   `json:"port"`
	Backend Backend `json:"backend"`
	// HTTP-only timeout overrides.
	// +optional
	Timeouts *HTTPTimeouts `json:"timeouts,omitempty"`
}

// TailnetIngressSpec exposes in-cluster services through one tsnet node. L4 forwards TCP;
// HTTP mode terminates TLS and proxies HTTP or explicitly verified HTTPS to the selected backend.
// +kubebuilder:validation:XValidation:rule="!has(self.tls) || self.exposes.exists(e, has(e.mode) && e.mode == 'http')",message="tls requires an HTTP expose"
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
	// +kubebuilder:validation:MaxItems=50
	// +kubebuilder:validation:XValidation:rule="self.all(e, (has(e.mode) && e.mode == 'http') || self.exists_one(other, other.port == e.port))",message="L4 expose ports must be unique and must not overlap HTTP ports"
	// +kubebuilder:validation:XValidation:rule="self.all(e, self.exists_one(other, other.name == e.name))",message="expose names must be unique"
	// +kubebuilder:validation:XValidation:rule="self.filter(e, has(e.mode) && e.mode == 'http' && (!has(e.dnsLabel) || e.dnsLabel == '')).size() <= 1",message="at most one HTTP expose without a nonempty dnsLabel is allowed"
	// +kubebuilder:validation:XValidation:rule="self.all(e, !has(e.mode) || e.mode != 'http' || !has(e.dnsLabel) || e.dnsLabel == '' || self.filter(other, has(other.mode) && other.mode == 'http' && has(other.dnsLabel) && other.dnsLabel == e.dnsLabel).size() == 1)",message="nonempty HTTP dnsLabels must be unique"
	Exposes []Expose `json:"exposes"`
	// TLS source shared by the HTTP exposes. An omitted or empty source may use Tailnet defaults.
	// +optional
	TLS *IngressTLS `json:"tls,omitempty"`
	// Peers allowed to reach this node (policy grant src), e.g. ["group:team-a"]. Only used when
	// the Tailnet generates policy; every entry must match Tailnet.spec.policy.ingressSourceAllowlist,
	// otherwise the CR gets PolicyDenied and no grant is written.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:MinLength=1
	AllowFrom []string `json:"allowFrom"`
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
	// Resolved DNS name for an HTTP expose; empty for L4.
	// +optional
	DNSName string `json:"dnsName,omitempty"`
	// Additional resolved DNS aliases for an HTTP expose; empty unless alias is requested and won.
	// +optional
	DNSAliases []string `json:"dnsAliases,omitempty"`
	// Port the tailnet node listens on for this expose.
	ListenPort int32 `json:"listenPort"`
	// The in-cluster backend the agent dials, as service:port.
	Backend string `json:"backend"`
	// Backend reachability. With backend TLS this requires a fresh verified handshake
	// bound to the current configuration, CA bundle and unexpired certificate.
	Reachable bool `json:"reachable"`
	// Local TLS component readiness for an HTTP expose; omitted for L4.
	// This does not establish remote tailnet reachability or client CA trust.
	// +optional
	TLSReady *bool `json:"tlsReady,omitempty"`
	// Bounded backend or frontend failure reason; empty when ready.
	// +optional
	Reason string `json:"reason,omitempty"`
}

// TailnetIngressStatus is the observed state.
type TailnetIngressStatus struct {
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
	// DNS name rendered from the Tailnet's dns.ingressNameTemplate; resolves to TailnetIPs via the
	// hosts ConfigMap. Empty when no template is set.
	// +optional
	DNSName string `json:"dnsName,omitempty"`
	// Names the agent actually serves: the HTTP exposes' DNS names and their aliases, sorted.
	// For a CR without HTTP exposes it is the node's DNS name. Unlike dnsName (the node identity and
	// first certificate name), every entry here answers.
	// +optional
	Hosts []string `json:"hosts,omitempty"`
	// Expiry of the reusable pre-auth key currently in the agent's Secret.
	// +optional
	AuthKeyExpiresAt *metav1.Time `json:"authKeyExpiresAt,omitempty"`
	// +optional
	Exposes []ExposeStatus `json:"exposes,omitempty"`
	// Name of the effective TLS Secret in the ingress namespace; never certificate or key content.
	// +optional
	TLSSecretName string `json:"tlsSecretName,omitempty"`
	// Expiry of the serving TLS certificate.
	// +optional
	TLSNotAfter *metav1.Time `json:"tlsNotAfter,omitempty"`
	// Conditions: TagKnown, Registered, BackendsReachable, TLSReady, Ready.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=tning
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Tag",type=string,JSONPath=`.status.tag`
// +kubebuilder:printcolumn:name="Hostname",type=string,JSONPath=`.status.hostname`
// +kubebuilder:printcolumn:name="Hosts",type=string,JSONPath=`.status.hosts`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TailnetIngress exposes in-cluster L4 services on the tailnet as one tsnet node with a MagicDNS
// name. It lives in the tenant namespace; the tag's grants decide which tailnet peers may reach it.
// +kubebuilder:validation:XValidation:rule="size(self.metadata.name) <= 40 && self.metadata.name.matches('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')",message="name must be a DNS label of at most 40 characters"
// +kubebuilder:validation:XValidation:rule="!self.spec.exposes.exists(e, has(e.mode) && e.mode == 'http' && (!has(e.dnsLabel) || size(e.dnsLabel) == 0)) || !self.spec.exposes.exists(e, has(e.mode) && e.mode == 'http' && has(e.dnsLabel) && e.dnsLabel == self.metadata.name)",message="an HTTP dnsLabel equal to the ingress name conflicts with an unlabeled HTTP expose"
type TailnetIngress struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TailnetIngressSpec   `json:"spec"`
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
