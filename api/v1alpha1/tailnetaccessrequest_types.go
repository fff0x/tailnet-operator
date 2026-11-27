package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// AccessDuration is a lifetime the console offers, counted from the last approval.
// +kubebuilder:validation:Enum="1h";"8h";"24h";"7d";"30d";"permanent"
type AccessDuration string

// TailnetAccessRequestSpec is what a person asked for. The console writes it once; it never
// changes. The operator does not read this kind: only an approved request becomes a TailnetGrant.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable"
// +kubebuilder:validation:XValidation:rule="(self.action == 'Extend') == has(self.grantName)",message="grantName is set exactly for action Extend"
// +kubebuilder:validation:XValidation:rule="self.action == 'Create' ? (has(self.sources) && has(self.target) && has(self.ports)) : !(has(self.sources) || has(self.target) || has(self.ports))",message="sources, target and ports are set exactly for action Create"
type TailnetAccessRequestSpec struct {
	TailnetRef TailnetRef `json:"tailnetRef"`
	// Create asks for a new TailnetGrant; Extend asks for a new expiresAt of grantName.
	// +kubebuilder:validation:Enum=Create;Extend
	Action string `json:"action"`
	// The console grant to extend.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	GrantName string `json:"grantName,omitempty"`
	// Provider identifier (`<issuer>/<subject>`, as Headscale builds it) of the person who asked.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	Requester string `json:"requester"`
	// The requester's console role at the time of the request; it decides how many approvals
	// the request needs.
	// +kubebuilder:validation:Enum=User;Admin
	RequestedAs string `json:"requestedAs"`
	// Recipients of the grant to create, as in TailnetGrant.spec.sources.
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MinLength=2
	// +kubebuilder:validation:items:MaxLength=512
	// +kubebuilder:validation:XValidation:rule="self.all(s, s.startsWith('group:') ? s.matches('^group:[^[:space:]]+$') : (!s.startsWith('tag:') && !s.startsWith('autogroup:') && s.matches('^[^@[:space:]]+@[^@[:space:]]*$')))",message="a source must be group:<name> or a user reference with exactly one @; tags and autogroups are not allowed"
	// +listType=set
	Sources []string `json:"sources,omitempty"`
	// +optional
	Target *GrantTarget `json:"target,omitempty"`
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:Minimum=1
	// +kubebuilder:validation:items:Maximum=65535
	// +listType=set
	Ports    []int32        `json:"ports,omitempty"`
	Duration AccessDuration `json:"duration"`
	// +optional
	// +kubebuilder:validation:MaxLength=253
	Description string `json:"description,omitempty"`
}

// TailnetAccessRequestStatus is the decision, written by the console only. It names nobody: who
// approved, rejected or withdrew is in the console's audit log.
type TailnetAccessRequestStatus struct {
	// Empty while nobody decided: the request is pending.
	// +optional
	// +kubebuilder:validation:Enum=Pending;Approved;Rejected;Withdrawn
	Phase string `json:"phase,omitempty"`
	// +optional
	DecidedAt *metav1.Time `json:"decidedAt,omitempty"`
	// The TailnetGrant created or extended on approval.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	GrantName string `json:"grantName,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=tnar
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Tailnet",type=string,JSONPath=`.spec.tailnetRef.name`
// +kubebuilder:printcolumn:name="Action",type=string,JSONPath=`.spec.action`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Grant",type=string,JSONPath=`.status.grantName`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TailnetAccessRequest is a request for a TailnetGrant or its extension, kept by the console;
// its approvals are in the console's audit log. The operator ignores it.
type TailnetAccessRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TailnetAccessRequestSpec   `json:"spec"`
	Status TailnetAccessRequestStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TailnetAccessRequestList is a list of TailnetAccessRequest.
type TailnetAccessRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TailnetAccessRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TailnetAccessRequest{}, &TailnetAccessRequestList{})
}
