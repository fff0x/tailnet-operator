package gateway

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// PoolLabelKeysAnnotation lists the Service label keys that spec.service.poolLabels owns,
// so a key removed from the spec is removed from the Service and nothing else is touched.
const PoolLabelKeysAnnotation = "tsunaro.io/pool-label-keys"

var (
	ErrServiceBlocked  = errors.New("gateway service update: Service or receipt not verified")
	ErrServiceConflict = errors.New("gateway service update: concurrent change, retry later")
)

func poolLabelKeys(labels map[string]tnv1.GatewayLabelValue) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// PlanSpecRoutes plans the routes the Gateway spec wants right now: its LAN prefixes, the
// tailnet LB CIDR and, unless disabled, the host routes of the current TailnetEgress CRs.
// c MUST use uncached reads. Fresh gateways are IPv4 only, so any other family is refused.
func PlanSpecRoutes(ctx context.Context, c client.Client, namespace string, g *tnv1.TailnetGateway) (RoutePlan, error) {
	egresses := &tnv1.TailnetEgressList{}
	if c == nil || g == nil || c.List(ctx, egresses, client.InNamespace(namespace)) != nil {
		return RoutePlan{}, ErrFreshConfiguration
	}
	plan, err := PlanRoutes(SpecRouteInputs(g, string(g.Spec.TailnetRef.Name), namespace, egresses.Items))
	if err != nil {
		return RoutePlan{}, err
	}
	lbIP, ok := dnsAddress(string(g.Spec.Service.LoadBalancerIP))
	lbCIDR, cidrOK := routePrefix(string(g.Spec.Service.TailnetLBCIDR))
	if !ok || !cidrOK || !lbCIDR.Contains(lbIP) {
		return RoutePlan{}, ErrFreshConfiguration
	}
	for _, r := range plan.Routes {
		if prefix, err := netip.ParsePrefix(r); err != nil || !prefix.Addr().Is4() {
			return RoutePlan{}, ErrFreshConfiguration
		}
	}
	return plan, nil
}

// UpdateServiceRevision makes the labels of the receipt's LoadBalancer Service follow
// spec.service.poolLabels. obs MUST come from a ReconcileFresh call that returned
// Completed. Only labels and the key-list annotation change, with the resourceVersion of
// the Get as CAS, after the UID and digest recorded in the receipt were re-verified.
// A pool key that already exists as a label this reconciler did not write blocks the
// update, whatever its value: only keys recorded in the annotation are ever removed.
func UpdateServiceRevision(ctx context.Context, c client.Client, namespace string, g *tnv1.TailnetGateway, obs FreshObservation) error {
	if c == nil || g == nil || !obs.Completed || obs.service.UID == "" {
		return ErrServiceBlocked
	}
	svc := &corev1.Service{}
	if c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: obs.service.Name}, svc) != nil || svc.DeletionTimestamp != nil || svc.ResourceVersion == "" ||
		len(svc.OwnerReferences) != 0 || svc.UID != obs.service.UID || objectReceipt(svc) != obs.service {
		return ErrServiceBlocked
	}
	owned := map[string]bool{}
	for _, k := range strings.Split(svc.Annotations[PoolLabelKeysAnnotation], ",") {
		if k != "" {
			owned[k] = true
		}
	}
	updated := svc.DeepCopy()
	if updated.Labels == nil {
		updated.Labels = map[string]string{}
	}
	for k := range owned {
		if _, wanted := g.Spec.Service.PoolLabels[k]; !wanted {
			delete(updated.Labels, k)
		}
	}
	for k, v := range g.Spec.Service.PoolLabels {
		if _, exists := svc.Labels[k]; exists && !owned[k] {
			return ErrServiceBlocked
		}
		updated.Labels[k] = string(v)
	}
	if updated.Annotations == nil {
		updated.Annotations = map[string]string{}
	}
	updated.Annotations[PoolLabelKeysAnnotation] = poolLabelKeys(g.Spec.Service.PoolLabels)
	if equalStringMaps(svc.Labels, updated.Labels) && svc.Annotations[PoolLabelKeysAnnotation] == updated.Annotations[PoolLabelKeysAnnotation] {
		return nil
	}
	if err := c.Update(ctx, updated); err != nil {
		if apierrors.IsConflict(err) {
			return ErrServiceConflict
		}
		return ErrServiceBlocked
	}
	return nil
}

func equalStringMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
