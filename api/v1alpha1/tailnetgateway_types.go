package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// GatewayName is a namespace-local Kubernetes object name.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$`
type GatewayName string

// GatewayPrefix is a canonical, non-default subnet route. Network ownership and
// reachability still require runtime validation against the selected Tailnet.
// +kubebuilder:validation:MaxLength=49
// +kubebuilder:validation:XValidation:rule="isCIDR(self) && cidr(self).prefixLength() > 0 && string(cidr(self).masked()) == self",message="route must be a canonical masked non-default CIDR"
// +kubebuilder:validation:XValidation:rule="isCIDR(self) && !self.startsWith('::ffff:') && ['0.0.0.0/32', '127.0.0.0/8', '224.0.0.0/4', '::/128', '::1/128', 'ff00::/8'].all(r, !cidr(self).containsIP(cidr(r).ip()) && !cidr(r).containsCIDR(cidr(self)))",message="route must not overlap unspecified loopback or multicast ranges or use mapped IPv4"
type GatewayPrefix string

// GatewayIP is an unzoned unicast IP literal, not a hostname or a prefix.
// +kubebuilder:validation:MaxLength=45
// +kubebuilder:validation:XValidation:rule="isIP(self) && ip(self).isGlobalUnicast() && !ip(self).isLinkLocalUnicast() && string(ip(self)) == self",message="address must be a canonical unicast IP literal"
type GatewayIP string

// GatewayImage requires a version tag or immutable digest; the runtime never
// rewrites it. Kernel Tailscale, CoreDNS and socat use separate images, not the agent image.
// +kubebuilder:validation:MaxLength=512
// +kubebuilder:validation:Pattern=`^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*(:[0-9]+)?/)?[a-z0-9]+(([._]|__|-+)[a-z0-9]+)*(/[a-z0-9]+(([._]|__|-+)[a-z0-9]+)*)*((:[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127})?@sha256:[a-f0-9]{64}|:v?[0-9]+(\.[0-9]+){2,3}(-[a-zA-Z0-9._-]+)?)$`
// +kubebuilder:validation:XValidation:rule="[self.split('@')[0]].all(n, [n.split('/')[n.split('/').size()-1]].all(p, !p.contains(':') ? n.size() <= 255 : p.split(':')[1].size() <= 128 && n.size()-p.split(':')[1].size()-1 <= 255))",message="image repository name or tag is too long"
type GatewayImage string

// GatewayLocalReference is always resolved in the operator namespace.
type GatewayLocalReference struct {
	Name GatewayName `json:"name"`
}

// GatewayAuthKeyReference never contains the credential itself.
type GatewayAuthKeyReference struct {
	Name GatewayName `json:"name"`
	// +kubebuilder:default=TS_AUTHKEY
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9._-]+$`
	// +optional
	Key string `json:"key,omitempty"`
}

// GatewayRoutes adds literal-IP egress destinations from this Tailnet in the
// operator namespace. DNS targets are explicitly skipped, not resolved.
type GatewayRoutes struct {
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=128
	// +listType=set
	LAN []GatewayPrefix `json:"lan"`
	// +kubebuilder:default=true
	// +optional
	AdvertiseEgressTargets *bool `json:"advertiseEgressTargets,omitempty"`
}

// GatewayLabelValue is a Kubernetes label value.
// +kubebuilder:validation:MaxLength=63
// +kubebuilder:validation:Pattern=`^([a-zA-Z0-9]([a-zA-Z0-9_.-]*[a-zA-Z0-9])?)?$`
type GatewayLabelValue string

// GatewayClass is a Kubernetes qualified load-balancer class name.
// +kubebuilder:validation:MaxLength=317
// +kubebuilder:validation:Pattern=`^([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*/)?[a-zA-Z0-9]([a-zA-Z0-9_.-]{0,61}[a-zA-Z0-9])?$`
// +kubebuilder:validation:XValidation:rule="!self.contains('/') || self.split('/')[0].size() <= 253",message="loadBalancerClass prefix is too long"
type GatewayClass string

// GatewayService preserves the gateway's stable split-DNS LoadBalancer address.
// +kubebuilder:validation:XValidation:rule="cidr(self.tailnetLBCIDR).containsIP(ip(self.loadBalancerIP))",message="loadBalancerIP must be inside tailnetLBCIDR"
// +kubebuilder:validation:XValidation:rule="has(self.loadBalancerClass) == has(oldSelf.loadBalancerClass) && (!has(self.loadBalancerClass) || self.loadBalancerClass == oldSelf.loadBalancerClass)",message="loadBalancerClass is immutable"
type GatewayService struct {
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="loadBalancerIP is immutable"
	LoadBalancerIP GatewayIP     `json:"loadBalancerIP"`
	TailnetLBCIDR  GatewayPrefix `json:"tailnetLBCIDR"`
	// Labels used by the LoadBalancer IP-pool selector, not pod selectors.
	// +optional
	// +kubebuilder:validation:MaxProperties=16
	// +kubebuilder:validation:XValidation:rule="self.all(k, k.size() <= 317 && k.matches('^([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?([.][a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*/)?[a-zA-Z0-9]([a-zA-Z0-9_.-]{0,61}[a-zA-Z0-9])?$') && (!k.contains('/') || k.split('/')[0].size() <= 253))",message="poolLabels keys must be Kubernetes qualified names"
	PoolLabels map[string]GatewayLabelValue `json:"poolLabels,omitempty"`
	// +optional
	LoadBalancerClass GatewayClass `json:"loadBalancerClass,omitempty"`
}

// GatewayExtraZone falls through from dynamic hosts to explicit DNS upstream IPs.
// No arbitrary Corefile text or resolver URLs are accepted.
type GatewayExtraZone struct {
	Zone GatewayName `json:"zone"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	// +listType=set
	Upstreams []GatewayIP `json:"upstreams"`
}

// GatewayStaticRecord is an explicit A/AAAA or CNAME record beneath dns.zone.
// Exactly one of address or target must be set; the wildcard fallback is a
// separate optional IP (dns.wildcardAddress). CNAME targets are rendered as
// absolute names and must point inside the same zone, so CoreDNS resolves them
// from the dynamic hosts without an upstream.
// +kubebuilder:validation:XValidation:rule="(has(self.address) ? 1 : 0) + (has(self.target) ? 1 : 0) == 1",message="exactly one of address or target must be set"
type GatewayStaticRecord struct {
	// Relative single label below dns.zone.
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`
	// +optional
	Address GatewayIP `json:"address,omitempty"`
	// Target FQDN of a CNAME. Must be equal to dns.zone or end with ".<dns.zone>"
	// and must differ from this record's own FQDN. Never resolved by the operator;
	// CoreDNS answers from the authoritative zone (CNAME + target RRset when known,
	// bare CNAME when the target is not yet in the hosts source).
	// +optional
	Target GatewayName `json:"target,omitempty"`
}

// GatewayServiceName follows Kubernetes 1.31's DNS-1035 Service-name contract.
// +kubebuilder:validation:MaxLength=63
// +kubebuilder:validation:Pattern=`^[a-z]([-a-z0-9]*[a-z0-9])?$`
type GatewayServiceName string

// GatewayDNS leaves the cluster CoreDNS Corefile and Headscale split-DNS config
// externally managed. Dynamic hosts remain owned by the existing DNS reconciler.
// +kubebuilder:validation:XValidation:rule="!has(self.extraZones) || self.extraZones.all(z, z.zone != self.zone && !z.zone.endsWith('.' + self.zone) && !self.zone.endsWith('.' + z.zone))",message="extraZones must not overlap the primary zone"
// +kubebuilder:validation:XValidation:rule="!has(self.extraZones) || self.extraZones.all(a, self.extraZones.all(b, a.zone == b.zone || (!a.zone.endsWith('.' + b.zone) && !b.zone.endsWith('.' + a.zone))))",message="extraZones must not overlap each other"
// +kubebuilder:validation:XValidation:rule="!has(self.staticRecords) || self.staticRecords.all(r, r.name.size() + 1 + self.zone.size() <= 253)",message="static record name exceeds the DNS wire limit"
// +kubebuilder:validation:XValidation:rule="!has(self.wildcardAddress) || self.zone.size() + 2 <= 253",message="wildcard record name exceeds the DNS wire limit"
// +kubebuilder:validation:XValidation:rule="!has(self.staticRecords) || self.staticRecords.all(r, !has(r.target) || r.target == self.zone || r.target.endsWith('.' + self.zone))",message="static record target must point inside dns.zone"
// +kubebuilder:validation:XValidation:rule="!has(self.staticRecords) || self.staticRecords.all(r, !has(r.target) || r.target != r.name + '.' + self.zone)",message="static record target must differ from its own FQDN"
type GatewayDNS struct {
	Zone GatewayName `json:"zone"`
	// Explicit name of the gateway's DNS Service; pinned identity.
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="DNS serviceName is immutable"
	ServiceName GatewayServiceName `json:"serviceName"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="DNS serviceClusterIP is immutable"
	ServiceClusterIP GatewayIP    `json:"serviceClusterIP"`
	Image            GatewayImage `json:"image"`
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=zone
	ExtraZones []GatewayExtraZone `json:"extraZones,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=128
	// +listType=map
	// +listMapKey=name
	StaticRecords []GatewayStaticRecord `json:"staticRecords,omitempty"`
	// Optional file-zone fallback, never a template plugin that shadows hosts.
	// +optional
	WildcardAddress GatewayIP `json:"wildcardAddress,omitempty"`
}

// GatewayForward is a TCP forward rendered without shell interpolation.
type GatewayForward struct {
	// +kubebuilder:validation:MaxLength=50
	// +kubebuilder:validation:Pattern=`^[a-z]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`
	// DNS, health, readiness and metrics ports are reserved by the sidecar.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:validation:XValidation:rule="!(self in [53, 8080, 8181, 9153])",message="forward port is reserved"
	Port int32 `json:"port"`
	// IP literal avoids DNS/SNI ambiguity and arbitrary socat address expressions.
	TargetAddress GatewayIP `json:"targetAddress"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	TargetPort int32 `json:"targetPort"`
}

// Values of TailnetGatewaySpec.DeletionPolicy.
const (
	GatewayDeletionPolicyRetain = "Retain"
	GatewayDeletionPolicyDelete = "Delete"
)

// TailnetGatewaySpec is an experimental API contract, suspended by default.
// Explicit suspend=false opts into the fresh writer; existing routers are never
// adopted. Deletion retains everything unless deletionPolicy=Delete explicitly
// consents to tearing down the operator's own fresh resources.
// +kubebuilder:validation:XValidation:rule="self.tailnetRef == oldSelf.tailnetRef && self.hostname == oldSelf.hostname && self.stateSecretRef == oldSelf.stateSecretRef",message="gateway identity references are immutable"
// +kubebuilder:validation:XValidation:rule="!has(self.authKeySecretRef) || self.authKeySecretRef.name != self.stateSecretRef.name",message="auth key and state must use separate Secrets"
// +kubebuilder:validation:XValidation:rule="!has(self.forwards) || self.forwards.size() == 0 || has(self.forwardImage)",message="forwardImage is required for forwards"
// +kubebuilder:validation:XValidation:rule="!has(self.forwards) || self.forwards.all(a, self.forwards.filter(b, b.port == a.port).size() == 1)",message="forward ports must be unique"
type TailnetGatewaySpec struct {
	TailnetRef GatewayLocalReference `json:"tailnetRef"`
	// Explicit until a cluster-name convention is introduced; no inferred identity.
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Hostname       string                `json:"hostname"`
	StateSecretRef GatewayLocalReference `json:"stateSecretRef"`
	// Omitted selects persistent key minting by the operator, never an ephemeral key.
	// +optional
	AuthKeySecretRef *GatewayAuthKeyReference `json:"authKeySecretRef,omitempty"`
	// Explicit false opts into fresh resource creation.
	// +kubebuilder:default=true
	// +optional
	Suspend *bool `json:"suspend,omitempty"`
	// +kubebuilder:default=1
	// +kubebuilder:validation:XValidation:rule="self == 1",message="gateway replicas must equal one"
	// +optional
	Replicas int32 `json:"replicas,omitempty"`
	// Retain leaves every resource, node and key in place when the CR is deleted.
	// Delete records consent through a finalizer: the operator removes only the
	// fresh resources it created (matched by recorded UID or its own gateway-uid
	// label), the Headscale node and the minted bootstrap key, in a fixed order
	// and fail-closed. User-supplied objects are never deleted.
	// +kubebuilder:default=Retain
	// +kubebuilder:validation:Enum=Retain;Delete
	// +optional
	DeletionPolicy string `json:"deletionPolicy,omitempty"`
	// Bootstrap tags of the fresh node.
	// +kubebuilder:default={"tag:fabric"}
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^tag:[a-z][a-z0-9-]*$`
	// +listType=set
	// +optional
	Tags    []string       `json:"tags,omitempty"`
	Image   GatewayImage   `json:"image"`
	Routes  GatewayRoutes  `json:"routes"`
	Service GatewayService `json:"service"`
	DNS     GatewayDNS     `json:"dns"`
	// +optional
	ForwardImage GatewayImage `json:"forwardImage,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=name
	Forwards []GatewayForward `json:"forwards,omitempty"`
}

// GatewayRouteStatus persists the quiet-period planner without process-local timers.
type GatewayRouteStatus struct {
	// +optional
	AppliedHash string `json:"appliedHash,omitempty"`
	// +optional
	PendingHash string `json:"pendingHash,omitempty"`
	// UTC RFC3339Nano; malformed timestamps cause the planner to restart its wait.
	// +optional
	PendingSince string `json:"pendingSince,omitempty"`
}

// TailnetGatewayStatus records observations, not desired-state success claims.
type TailnetGatewayStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	NodeID string `json:"nodeId,omitempty"`
	// +optional
	IPv4 string `json:"ipv4,omitempty"`
	// +optional
	ServiceIP string `json:"serviceIP,omitempty"`
	// +optional
	RoutesAdvertised []string `json:"routesAdvertised,omitempty"`
	// +optional
	RoutesApproved []string `json:"routesApproved,omitempty"`
	// IDs of stale nodes to report only, never delete automatically.
	// +optional
	StaleNodes []string `json:"staleNodes,omitempty"`
	// +optional
	RoutePlan GatewayRouteStatus `json:"routePlan,omitempty"`
	// Registered, RoutesInSync, DNSReady, StaleNodes, ClusterDNSForward and Ready;
	// fresh gateways with a verified completion receipt also report WorkloadCurrent and ServiceReady.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=tngw
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Hostname",type=string,JSONPath=`.spec.hostname`
// +kubebuilder:printcolumn:name="Suspended",type=boolean,JSONPath=`.spec.suspend`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="size(self.metadata.name) <= 40 && self.metadata.name.matches('^[a-z]([-a-z0-9]*[a-z0-9])?$')",message="name must be a DNS-1035 label of at most 40 characters"
// +kubebuilder:validation:XValidation:rule="self.spec.dns.serviceName != self.metadata.name && self.spec.dns.serviceName != self.metadata.name + '-headless'",message="DNS serviceName must not collide with the gateway or headless Service"
// TailnetGateway describes a persistent kernel router in the operator namespace.
// Suspended by default; suspend=false explicitly opts into the fresh writer.
type TailnetGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TailnetGatewaySpec `json:"spec"`
	// +optional
	Status TailnetGatewayStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// TailnetGatewayList contains gateways.
type TailnetGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TailnetGateway `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TailnetGateway{}, &TailnetGatewayList{})
}
