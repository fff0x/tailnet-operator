package controller

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// hostsKey is the ConfigMap key carrying the rendered hosts file.
const hostsKey = "hosts"

// TailnetDNSReconciler renders one CoreDNS hosts file per Tailnet: every TailnetEgress alias maps
// to its Service ClusterIP, every TailnetIngress dnsName to the node's tailnet IPs. The operator
// serves no DNS itself — the cluster mounts the ConfigMap into a resolver that is authoritative for
// those zones (README "DNS names"), so a dead operator leaves the last good file in place.
type TailnetDNSReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	OperatorNamespace string
}

// hostEntry is one line of the hosts file; Source orders duplicates deterministically.
type hostEntry struct {
	Name, IP, Source string
}

func (r *TailnetDNSReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)
	var tn tnv1.Tailnet
	if err := r.Get(ctx, req.NamespacedName, &tn); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	name := tn.Spec.DNS.HostsConfigMap
	if name == "" {
		// Feature off: remove a ConfigMap this Tailnet rendered earlier, never a foreign one.
		var cms corev1.ConfigMapList
		if err := r.List(ctx, &cms, client.InNamespace(r.OperatorNamespace)); err != nil {
			return ctrl.Result{}, err
		}
		for i := range cms.Items {
			if cm := &cms.Items[i]; ownedBy(cm, tn.UID) && cm.Labels[roleLabel] != rolePolicyRender {
				if err := r.Delete(ctx, cm, client.Preconditions{UID: &cm.UID}); client.IgnoreNotFound(err) != nil {
					return ctrl.Result{}, err
				}
			}
		}
		return ctrl.Result{}, nil
	}

	// Owner guard: a ConfigMap of that name not created by this Tailnet is somebody else's.
	var existing corev1.ConfigMap
	err := r.Get(ctx, types.NamespacedName{Namespace: r.OperatorNamespace, Name: name}, &existing)
	if err == nil && !ownedBy(&existing, tn.UID) {
		l.Error(nil, "hosts ConfigMap exists and is not owned by this Tailnet; refusing to overwrite",
			"configmap", name)
		return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
	}
	if client.IgnoreNotFound(err) != nil {
		return ctrl.Result{}, err
	}

	entries, err := r.collect(ctx, tn.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	cm := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: r.OperatorNamespace, Labels: map[string]string{"app.kubernetes.io/managed-by": fieldOwner, roleLabel: roleDNSHosts}},
		Data:       map[string]string{hostsKey: renderHosts(tn.Name, entries, l.Info)},
	}
	if err := controllerutil.SetControllerReference(&tn, cm, r.Scheme); err != nil {
		return ctrl.Result{}, err
	}
	if err := ssaApply(ctx, r.Client, cm); err != nil {
		return ctrl.Result{}, err
	}
	l.V(1).Info("rendered hosts", "configmap", name, "entries", len(entries))
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// collect gathers the entries of all CRs bound to the Tailnet tn.
func (r *TailnetDNSReconciler) collect(ctx context.Context, tn string) ([]hostEntry, error) {
	var out []hostEntry
	var egs tnv1.TailnetEgressList
	if err := r.List(ctx, &egs, client.InNamespace(r.OperatorNamespace)); err != nil {
		return nil, err
	}
	for _, eg := range egs.Items {
		if eg.Spec.TailnetRef.Name != tn {
			continue
		}
		for _, t := range eg.Spec.Targets {
			if len(t.Aliases) == 0 {
				continue
			}
			var svc corev1.Service
			if err := r.Get(ctx, types.NamespacedName{Namespace: eg.Namespace, Name: t.Name}, &svc); err != nil {
				if client.IgnoreNotFound(err) != nil {
					return nil, err
				}
				continue // Service not created yet; the egress status update (or the 5m requeue) brings us back
			}
			src := "tailnetegress/" + eg.Namespace + "/" + eg.Name
			for _, a := range t.Aliases {
				for _, ip := range svc.Spec.ClusterIPs {
					if ip != "" && ip != corev1.ClusterIPNone {
						out = append(out, hostEntry{Name: a, IP: ip, Source: src})
					}
				}
			}
		}
	}
	var ins tnv1.TailnetIngressList
	if err := r.List(ctx, &ins); err != nil {
		return nil, err
	}
	for _, in := range ins.Items {
		if in.Spec.TailnetRef.Name != tn || in.Status.DNSName == "" {
			continue
		}
		src := "tailnetingress/" + in.Namespace + "/" + in.Name
		for _, ip := range in.Status.TailnetIPs {
			// ponytail: IPv4 only. Clients prefer AAAA, but tsnet/netstack agents (and pod-hosted
			// routers) do not accept tailnet IPv6 in the clusters seen so far, and Headscale's own
			// MagicDNS publishes A records only — an AAAA here turns a working service into a
			// connect timeout. Upgrade path: a Tailnet.spec.dns switch once IPv6 is verified.
			if a, err := netip.ParseAddr(ip); err == nil && a.Is6() {
				continue
			}
			out = append(out, hostEntry{Name: in.Status.DNSName, IP: ip, Source: src})
		}
	}
	return out, nil
}

// renderHosts writes the CoreDNS hosts file: "IP name" lines sorted by name for a stable diff. A
// name claimed by two different sources keeps the first source (sorted) and reports the loser via
// warn — two IPs for one name would otherwise round-robin between unrelated backends.
// ponytail: first-wins is a heuristic, not a conflict resolution; the upgrade path is a status
// condition on the losing CR.
func renderHosts(tailnet string, entries []hostEntry, warn func(msg string, kv ...any)) string {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Name != entries[j].Name {
			return entries[i].Name < entries[j].Name
		}
		if entries[i].Source != entries[j].Source {
			return entries[i].Source < entries[j].Source
		}
		return entries[i].IP < entries[j].IP
	})
	var b strings.Builder
	fmt.Fprintf(&b, "# managed by tailnet-operator (Tailnet %s) — do not edit\n", tailnet)
	owner := map[string]string{}
	for _, e := range entries {
		if src, ok := owner[e.Name]; ok && src != e.Source {
			warn("duplicate dns name; keeping first source", "name", e.Name, "kept", src, "dropped", e.Source)
			continue
		}
		owner[e.Name] = e.Source
		fmt.Fprintf(&b, "%s\t%s\n", e.IP, e.Name)
	}
	return b.String()
}

// SetupWithManager registers the DNS controller: driven by the Tailnet, re-rendered whenever a
// bound egress or ingress changes (spec or status) and when the ConfigMap itself is touched.
func (r *TailnetDNSReconciler) SetupWithManager(mgr ctrl.Manager) error {
	byRef := func(_ context.Context, o client.Object) []reconcile.Request {
		var name string
		switch cr := o.(type) {
		case *tnv1.TailnetEgress:
			name = cr.Spec.TailnetRef.Name
		case *tnv1.TailnetIngress:
			name = cr.Spec.TailnetRef.Name
		}
		if name == "" {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: name}}}
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("tailnetdns").
		For(&tnv1.Tailnet{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Owns(&corev1.ConfigMap{}).
		Watches(&tnv1.TailnetEgress{}, handler.EnqueueRequestsFromMapFunc(byRef)).
		Watches(&tnv1.TailnetIngress{}, handler.EnqueueRequestsFromMapFunc(byRef)).
		Complete(r)
}
