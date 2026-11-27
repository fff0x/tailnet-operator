package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// GrantTarget is what a TailnetGrant gives access to: one ingress node by tag, or hosts and
// networks inside a TailnetSite by prefix.
// +kubebuilder:validation:XValidation:rule="has(self.tag) != has(self.prefixes)",message="exactly one of tag and prefixes must be set"
type GrantTarget struct {
	// Tag of a TailnetIngress bound to the same Tailnet (TailnetIngress.status.tag), or an ingress
	// tag a merged spoke fragment grants to. An unknown tag is never rendered (TargetUnknown).
	// +optional
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^tag:[a-z][a-z0-9-]*$`
	Tag string `json:"tag,omitempty"`
	// Prefixes inside an unblocked TailnetSite of the same Tailnet. A /32 or /128 is a single
	// host. One prefix outside every site blocks the whole grant (TargetOutsideSites).
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=set
	Prefixes []GatewayPrefix `json:"prefixes,omitempty"`
}

// TailnetGrantSpec gives people or policy groups TCP access to one target, permanently or until
// expiresAt. The operator that owns the Tailnet's policy renders it as a grant and removes it at
// expiry without any further event. A grant is administrative: it bypasses a TailnetIngress's
// allowFrom and a spoke's ingressSourceAllowlist. Every field may be changed; to extend a grant,
// set a new expiresAt.
type TailnetGrantSpec struct {
	TailnetRef TailnetRef `json:"tailnetRef"`
	// Who gets access: `group:<name>` (a group the base policy declares) or a Headscale user
	// reference with exactly one `@` — the provider identifier (`<issuer>/<subject>@`, stable), a
	// user name (`alice@`) or an e-mail address. Tags and autogroups are not accepted. An
	// undeclared group is dropped (SourceGroupUnknown); an unknown user grants nothing and is not
	// reported, because Headscale accepts it.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MinLength=2
	// +kubebuilder:validation:items:MaxLength=512
	// +kubebuilder:validation:XValidation:rule="self.all(s, s.startsWith('group:') ? s.matches('^group:[^[:space:]]+$') : (!s.startsWith('tag:') && !s.startsWith('autogroup:') && s.matches('^[^@[:space:]]+@[^@[:space:]]*$')))",message="a source must be group:<name> or a user reference with exactly one @; tags and autogroups are not allowed"
	// +listType=set
	Sources []string    `json:"sources"`
	Target  GrantTarget `json:"target"`
	// TCP ports on the target. There is no "all ports": a grant never widens when the target
	// later listens on more.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:Minimum=1
	// +kubebuilder:validation:items:Maximum=65535
	// +listType=set
	Ports []int32 `json:"ports"`
	// End of the grant by the operator's clock; from this instant on it is no longer rendered.
	// Omitted → permanent. A time in the past is allowed: the grant is expired at once.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=253
	Description string `json:"description,omitempty"`
}

// TailnetGrantStatus reports whether the grant is in the live policy.
type TailnetGrantStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Conditions: Ready. True/Granted when the grant is rendered and the live policy equals the
	// render; otherwise False with NotPolicyWriter, Expired, ExpiryPending, TargetUnknown,
	// TargetOutsideSites, SourceGroupUnknown or PolicyPending.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=tngr
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Tailnet",type=string,JSONPath=`.spec.tailnetRef.name`
// +kubebuilder:printcolumn:name="Expires",type=string,JSONPath=`.spec.expiresAt`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TailnetGrant is a cluster-scoped, optionally time-bound TCP grant for people or policy groups
// to a TailnetIngress or to hosts inside a TailnetSite.
type TailnetGrant struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TailnetGrantSpec   `json:"spec"`
	Status TailnetGrantStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TailnetGrantList is a list of TailnetGrant.
type TailnetGrantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TailnetGrant `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TailnetGrant{}, &TailnetGrantList{})
}
