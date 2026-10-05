package gateway

import (
	"context"
	"errors"
	"net/netip"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

var (
	ErrDNSWriteBlocked  = errors.New("gateway DNS update: source, target or runtime not verified")
	ErrDNSWriteConflict = errors.New("gateway DNS update: concurrent change, retry later")
)

// UpdateDNSRevision reconciles the derived -coredns ConfigMap for an ALREADY
// provisioned fresh Gateway: it re-renders the zone from the Tailnet hosts
// source, advances the SOA serial only on semantic change and writes with a
// resourceVersion CAS. It never creates resources, bootstraps identity, adopts
// pre-existing DNS or touches any other receipt child. Callers must have
// verified a complete fresh set (FreshObservation.Completed); the writer
// itself re-reads source/target and the Gateway/Tailnet revisions before every
// Update. A conflict is returned to the controller for a later requeue.
func UpdateDNSRevision(ctx context.Context, c client.Client, gatewayName, namespace string) error {
	if c == nil || gatewayName == "" || namespace == "" {
		return ErrDNSWriteBlocked
	}
	for attempt := 0; attempt < 3; attempt++ {
		g := &tnv1.TailnetGateway{}
		if c.Get(ctx, types.NamespacedName{Name: gatewayName}, g) != nil || g.UID == "" || g.ResourceVersion == "" ||
			g.Spec.Suspend == nil || *g.Spec.Suspend || g.DeletionTimestamp != nil {
			return ErrDNSWriteBlocked
		}
		tn := &tnv1.Tailnet{}
		if c.Get(ctx, types.NamespacedName{Name: string(g.Spec.TailnetRef.Name)}, tn) != nil || tn.UID == "" || tn.ResourceVersion == "" ||
			tn.DeletionTimestamp != nil || tn.Name != string(g.Spec.TailnetRef.Name) || tn.Spec.DNS.HostsConfigMap == "" {
			return ErrDNSWriteBlocked
		}
		source := &corev1.ConfigMap{}
		if c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: tn.Spec.DNS.HostsConfigMap}, source) != nil ||
			!ownedHostsSource(source, tn, namespace) {
			return ErrDNSWriteBlocked
		}
		target := &corev1.ConfigMap{}
		if c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: g.Name + "-coredns"}, target) != nil ||
			target.UID == "" || target.ResourceVersion == "" || target.DeletionTimestamp != nil ||
			target.Labels[gatewayUIDLabel] != string(g.UID) || target.Labels["app.kubernetes.io/managed-by"] != "tailnet-operator" ||
			len(target.OwnerReferences) != 0 || target.Name == source.Name {
			return ErrDNSWriteBlocked
		}
		previous, err := ReadDNSRevision(target, string(g.Spec.DNS.Zone))
		if err != nil {
			return ErrDNSWriteBlocked
		}
		lb, lbOK := dnsAddress(string(g.Spec.Service.LoadBalancerIP))
		dnsIP, dnsOK := dnsAddress(string(g.Spec.DNS.ServiceClusterIP))
		if !lbOK || !dnsOK {
			return ErrDNSWriteBlocked
		}
		binds := []netip.Addr{netip.IPv4Unspecified()}
		if lb.Is6() && dnsIP.Is6() {
			binds = []netip.Addr{netip.IPv6Unspecified()}
		} else if lb.Is6() || dnsIP.Is6() {
			binds = append(binds, netip.IPv6Unspecified())
		}
		input := DNSInputs{Config: g.Spec.DNS, ServerIP: lb.String(), Hosts: source.Data["hosts"], BindAddresses: binds}
		plan, err := PlanDNSRevision(input, &previous)
		if err != nil {
			return ErrDNSWriteBlocked
		}
		if !plan.Changed {
			return nil
		}
		input.Serial = plan.Serial
		dns, err := RenderDNS(input)
		if err != nil {
			return ErrDNSWriteBlocked
		}
		// The source is not transactionally linked to the target. Re-check its
		// UID/RV before the target write, then rely on source watches to repair
		// a later race. A stale read is never an exclusive DNS snapshot.
		current := &corev1.ConfigMap{}
		liveGateway := &tnv1.TailnetGateway{}
		liveTailnet := &tnv1.Tailnet{}
		if c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: source.Name}, current) != nil ||
			c.Get(ctx, types.NamespacedName{Name: g.Name}, liveGateway) != nil ||
			c.Get(ctx, types.NamespacedName{Name: tn.Name}, liveTailnet) != nil ||
			current.UID != source.UID || current.ResourceVersion != source.ResourceVersion ||
			liveGateway.UID != g.UID || liveGateway.ResourceVersion != g.ResourceVersion ||
			liveTailnet.UID != tn.UID || liveTailnet.ResourceVersion != tn.ResourceVersion {
			continue
		}
		updated := target.DeepCopy()
		updated.Data = map[string]string{"Corefile": dns.Corefile, DNSZoneFile: dns.ZoneFile}
		if updated.Annotations == nil {
			updated.Annotations = make(map[string]string)
		}
		updated.Annotations[DNSSerialAnnotation] = strconv.FormatUint(uint64(plan.Serial), 10)
		updated.Annotations[DNSHashAnnotation] = plan.ContentHash
		if err := c.Update(ctx, updated); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return ErrDNSWriteBlocked
		}
		return nil
	}
	return ErrDNSWriteConflict
}

func ownedHostsSource(cm *corev1.ConfigMap, tn *tnv1.Tailnet, namespace string) bool {
	if cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || cm.Namespace != namespace ||
		cm.Name != tn.Spec.DNS.HostsConfigMap || cm.Labels["app.kubernetes.io/managed-by"] != "tailnet-operator" ||
		cm.Labels["tsunaro.io/role"] != "dns-hosts" || len(cm.OwnerReferences) != 1 ||
		cm.OwnerReferences[0].UID != tn.UID || cm.OwnerReferences[0].Name != tn.Name ||
		cm.OwnerReferences[0].Kind != "Tailnet" || cm.OwnerReferences[0].APIVersion != "tsunaro.io/v1alpha1" ||
		cm.OwnerReferences[0].Controller == nil || !*cm.OwnerReferences[0].Controller || len(cm.BinaryData) != 0 {
		return false
	}
	_, ok := cm.Data["hosts"]
	return ok
}
