package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// SiteAdvertiser names the subnet routers that carry a site's prefixes by tag. A router is any
// Headscale node with one of these tags — an operator-managed TailnetGateway as well as a
// hand-built router in another cluster. Empty → Tailnet.spec.policy.routeApprovers.
type SiteAdvertiser struct {
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^tag:[a-z][a-z0-9-]*$`
	// +listType=set
	Tags []string `json:"tags,omitempty"`
}

// TailnetSiteSpec declares a remote network (a branch, a management net, a single host as /32)
// that a tagged router advertises into the tailnet. The operator renders autoApprovers for the
// prefixes, replays approvals on the advertising nodes and reports whether the routes are
// advertised and approved. Who may *reach* the prefixes stays a grant in the base policy.
type TailnetSiteSpec struct {
	TailnetRef TailnetRef `json:"tailnetRef"`
	// Prefixes of the site. A /32 is a single host. Overlap with Tailnet.spec.reservedNetworks
	// or with an older TailnetSite blocks this CR (RouteConflict); nothing is rendered for it.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	Prefixes []GatewayPrefix `json:"prefixes"`
	// +optional
	AdvertisedBy SiteAdvertiser `json:"advertisedBy,omitempty"`
	// Team or person accountable for the network; named in conflict messages.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Owner string `json:"owner"`
	// +optional
	// +kubebuilder:validation:MaxLength=253
	Description string `json:"description,omitempty"`
}

// TailnetSiteStatus records what the control server reports for the site's prefixes.
type TailnetSiteStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Prefixes of this site some advertiser node currently offers.
	// +optional
	RoutesAdvertised []string `json:"routesAdvertised,omitempty"`
	// Prefixes of this site approved on some advertiser node.
	// +optional
	RoutesApproved []string `json:"routesApproved,omitempty"`
	// Conditions: RouteConflict, UnmanagedOverlap, Advertised, Approved, Ready.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=tns
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Tailnet",type=string,JSONPath=`.spec.tailnetRef.name`
// +kubebuilder:printcolumn:name="Owner",type=string,JSONPath=`.spec.owner`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TailnetSite is a cluster-scoped remote network advertised by tagged subnet routers.
type TailnetSite struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TailnetSiteSpec   `json:"spec"`
	Status TailnetSiteStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TailnetSiteList is a list of TailnetSite.
type TailnetSiteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TailnetSite `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TailnetSite{}, &TailnetSiteList{})
}
