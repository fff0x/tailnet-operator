package gateway

import (
	"errors"
	"maps"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

const gatewayUIDLabel = "tsunaro.io/gateway-uid"

var ErrFreshConfiguration = errors.New("gateway fresh configuration is invalid or unsupported")

// FreshInputs requires admitted, API-defaulted CRs and a verified hosts snapshot.
// Namespace is the operator namespace, not an arbitrary tenant namespace. Egresses
// may contain other scopes: only non-deleting CRs in this namespace/Tailnet count.
// Hosts ownership and DNS serial progression remain the caller's responsibility.
// No credential values belong in this input.
type FreshInputs struct {
	Gateway   *tnv1.TailnetGateway
	Tailnet   *tnv1.Tailnet
	Namespace string
	Egresses  []tnv1.TailnetEgress
	Hosts     string
	DNSSerial uint32
}

// FreshPlan is an INITIAL resource model, not an apply/adoption plan. Never use it
// to update existing resources, including a gateway whose status was lost. Before
// any future creation, a writer must enforce exclusive names, source ownership,
// stable Service allocation, image compatibility, policy and network prerequisites.
// The referenced state Secret must already exist, be mutable and have NO retained
// identity; the separate auth Secret must contain a verified non-ephemeral key for
// the selected Headscale instance/tags. Neither Secret is read, created or returned.
// Resource labels are identity markers, not proof of ownership or consent.
// Objects have no GC owner references: deletion of the CR must not delete them.
type FreshPlan struct {
	Objects []client.Object
	Routes  RoutePlan
}

// RenderFresh builds a disconnected singleton kernel-router/DNS model. It rejects
// adoption, historical identity, implicit bootstrap, forward zones and TCP forwards.
// It performs no I/O and grants no additional permissions to the operator itself.
// Render success is not evidence of kernel forwarding, bootstrap or reachability.
func RenderFresh(in FreshInputs) (FreshPlan, error) {
	g, tn := in.Gateway, in.Tailnet
	if g == nil || tn == nil || g.Namespace != "" || tn.Namespace != "" ||
		g.UID == "" || len(validation.IsValidLabelValue(string(g.UID))) != 0 ||
		len(validation.IsDNS1035Label(g.Name)) != 0 || len(g.Name) > 40 ||
		len(validation.IsDNS1123Label(in.Namespace)) != 0 ||
		!g.DeletionTimestamp.IsZero() || !tn.DeletionTimestamp.IsZero() ||
		string(g.Spec.TailnetRef.Name) != tn.Name || tn.Name == "" ||
		g.Spec.Adoption != nil || g.Status.NodeID != "" || g.Status.IPv4 != "" || g.Status.ServiceIP != "" ||
		len(g.Status.RoutesAdvertised) != 0 || len(g.Status.RoutesApproved) != 0 ||
		g.Status.RoutePlan.AppliedHash != "" || len(g.Status.StaleNodes) != 0 ||
		g.Spec.Replicas != 1 || len(g.Spec.Forwards) != 0 ||
		g.Spec.Image == "" || g.Spec.DNS.Image == "" {
		return FreshPlan{}, ErrFreshConfiguration
	}
	state, auth := string(g.Spec.StateSecretRef.Name), g.Spec.AuthKeySecretRef
	if len(validation.IsDNS1123Subdomain(state)) != 0 || auth == nil ||
		len(validation.IsDNS1123Subdomain(string(auth.Name))) != 0 || string(auth.Name) == state ||
		auth.Key == "" || len(validation.IsConfigMapKey(auth.Key)) != 0 ||
		len(validation.IsDNS1123Label(g.Spec.Hostname)) != 0 || len(g.Spec.Tags) == 0 {
		return FreshPlan{}, ErrFreshConfiguration
	}
	for _, tag := range g.Spec.Tags {
		if !strings.HasPrefix(tag, "tag:") || len(validation.IsDNS1035Label(strings.TrimPrefix(tag, "tag:"))) != 0 {
			return FreshPlan{}, ErrFreshConfiguration
		}
	}
	server, err := url.Parse(tn.Spec.Server)
	if err != nil || server.Hostname() == "" || server.Scheme != "https" ||
		server.User != nil || server.RawQuery != "" || server.ForceQuery || server.Fragment != "" ||
		len(strings.Fields(tn.Spec.Server)) != 1 || strings.Fields(tn.Spec.Server)[0] != tn.Spec.Server {
		return FreshPlan{}, ErrFreshConfiguration
	}
	dnsName := string(g.Spec.DNS.ServiceName)
	lbIP, ok := dnsAddress(string(g.Spec.Service.LoadBalancerIP))
	dnsIP, dnsOK := dnsAddress(string(g.Spec.DNS.ServiceClusterIP))
	lbCIDR, cidrOK := routePrefix(string(g.Spec.Service.TailnetLBCIDR))
	if !ok || !dnsOK || !cidrOK || !lbCIDR.Contains(lbIP) ||
		len(validation.IsDNS1035Label(dnsName)) != 0 || dnsName == g.Name || dnsName == g.Name+"-headless" {
		return FreshPlan{}, ErrFreshConfiguration
	}
	ri := SpecRouteInputs(g, tn.Name, in.Namespace, in.Egresses)
	routes, err := PlanRoutes(ri)
	if err != nil {
		return FreshPlan{}, err
	}
	// Listen on the families used by either Service, independent of cluster defaults.
	binds := []netip.Addr{netip.IPv4Unspecified()}
	if lbIP.Is6() && dnsIP.Is6() {
		binds = []netip.Addr{netip.IPv6Unspecified()}
	} else if lbIP.Is6() || dnsIP.Is6() {
		binds = append(binds, netip.IPv6Unspecified())
	}
	dns, err := RenderDNS(DNSInputs{Config: g.Spec.DNS, ServerIP: lbIP.String(), Hosts: in.Hosts, Serial: in.DNSSerial, BindAddresses: binds})
	if err != nil {
		return FreshPlan{}, err
	}
	selector := func() map[string]string { return map[string]string{gatewayUIDLabel: string(g.UID)} }
	metadata := func(name string) metav1.ObjectMeta {
		labels := selector()
		labels["app.kubernetes.io/name"] = "tailnet-gateway"
		labels["app.kubernetes.io/managed-by"] = "tailnet-operator"
		return metav1.ObjectMeta{Name: name, Namespace: in.Namespace, Labels: labels}
	}
	ports := []corev1.ServicePort{
		{Name: "dns-udp", Port: 53, TargetPort: intstr.FromInt32(53), Protocol: corev1.ProtocolUDP},
		{Name: "dns-tcp", Port: 53, TargetPort: intstr.FromInt32(53), Protocol: corev1.ProtocolTCP},
	}
	service := func(name string, ip netip.Addr) *corev1.Service {
		family := corev1.IPv4Protocol
		if ip.Is6() {
			family = corev1.IPv6Protocol
		}
		return &corev1.Service{ObjectMeta: metadata(name), Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP, Selector: selector(), Ports: slices.Clone(ports),
			IPFamilyPolicy: ptr.To(corev1.IPFamilyPolicySingleStack), IPFamilies: []corev1.IPFamily{family},
		}}
	}
	lb := service(g.Name, lbIP)
	lb.Spec.Type, lb.Spec.LoadBalancerIP = corev1.ServiceTypeLoadBalancer, lbIP.String()
	lb.Spec.AllocateLoadBalancerNodePorts = ptr.To(false)
	if g.Spec.Service.LoadBalancerClass != "" {
		lb.Spec.LoadBalancerClass = ptr.To(string(g.Spec.Service.LoadBalancerClass))
	}
	for key, value := range g.Spec.Service.PoolLabels {
		// A base label key is never a pool key, whatever the value: pool keys are removable.
		if _, exists := lb.Labels[key]; exists {
			return FreshPlan{}, ErrFreshConfiguration
		}
		lb.Labels[key] = string(value)
	}
	// Pool labels follow the spec (UpdateServiceRevision); this records which keys are ours.
	lb.Annotations = map[string]string{PoolLabelKeysAnnotation: poolLabelKeys(g.Spec.Service.PoolLabels)}
	clusterDNS := service(dnsName, dnsIP)
	clusterDNS.Spec.ClusterIP, clusterDNS.Spec.ClusterIPs = dnsIP.String(), []string{dnsIP.String()}
	headless := service(g.Name+"-headless", dnsIP)
	headless.Spec.ClusterIP, headless.Spec.ClusterIPs = corev1.ClusterIPNone, []string{corev1.ClusterIPNone}
	configName := g.Name + "-coredns"
	if in.DNSSerial != 1 {
		return FreshPlan{}, ErrFreshConfiguration
	}
	// The derived zone is reconciled live (see UpdateDNSRevision); the writer
	// receipt excludes zone.db from the digest. The annotations are the CAS
	// precondition for every later update and must match the initial payload.
	configMeta := metadata(configName)
	configMeta.Annotations = map[string]string{DNSSerialAnnotation: "1", DNSHashAnnotation: dnsContentHash(dns.Corefile, dns.ZoneFile)}
	config := &corev1.ConfigMap{ObjectMeta: configMeta, Data: map[string]string{"Corefile": dns.Corefile, DNSZoneFile: dns.ZoneFile}}
	account := &corev1.ServiceAccount{ObjectMeta: metadata(g.Name), AutomountServiceAccountToken: ptr.To(false)}
	role := &rbacv1.Role{ObjectMeta: metadata(g.Name), Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{state}, Verbs: []string{"get", "update", "patch"}}}}
	binding := &rbacv1.RoleBinding{ObjectMeta: metadata(g.Name), RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: g.Name}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: g.Name, Namespace: in.Namespace}}}
	pdb := &policyv1.PodDisruptionBudget{ObjectMeta: metadata(g.Name), Spec: policyv1.PodDisruptionBudgetSpec{MinAvailable: ptr.To(intstr.FromInt32(1)), Selector: &metav1.LabelSelector{MatchLabels: selector()}}}
	pod := freshPod(g, tn.Spec.Server, routes, configName)
	sts := &appsv1.StatefulSet{ObjectMeta: metadata(g.Name), Spec: appsv1.StatefulSetSpec{
		Replicas: ptr.To(int32(1)), ServiceName: headless.Name,
		Selector: &metav1.LabelSelector{MatchLabels: selector()},
		// Never turn a fresh-template recomputation into an automatic identity restart.
		UpdateStrategy: appsv1.StatefulSetUpdateStrategy{Type: appsv1.OnDeleteStatefulSetStrategyType},
		Template:       corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: maps.Clone(metadata(g.Name).Labels)}, Spec: pod},
	}}
	return FreshPlan{Routes: routes, Objects: []client.Object{account, role, binding, config, headless, clusterDNS, lb, pdb, sts}}, nil
}
