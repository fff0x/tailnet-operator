package controller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
	"this-is-fine.io/tailnet-operator/internal/headscale"
	"this-is-fine.io/tailnet-operator/internal/naming"
	"this-is-fine.io/tailnet-operator/internal/policy"
)

const (
	// policyKey is the ConfigMap key of both the base and the rendered policy.
	policyKey = "policy"
	// roleLabel tells the operator's ConfigMaps apart (dns hosts file vs rendered policy) so one
	// feature switching off never deletes the other's output.
	roleLabel        = "tailnet.this-is-fine.io/role"
	roleDNSHosts     = "dns-hosts"
	rolePolicyRender = "policy-rendered"

	policyRequeue = 5 * time.Minute
	// policyRetry is the wait after the first rejected/failed write; it doubles per consecutive
	// failure up to policyRequeue. A rejection caused by a node re-registering (test src "resolved
	// to no IP addresses") clears within seconds; a broken base ends up at the regular 5-min cadence.
	policyRetry = 15 * time.Second
)

// TailnetPolicyReconciler owns the control server's policy for a Tailnet: it renders the base
// document from a ConfigMap plus what the bound egress/ingress CRs imply, publishes the result in a
// ConfigMap for review and — in Apply mode — writes it to the server whenever the live policy
// differs. Rendering never removes base content; Headscale validates before storing, so a rejected
// write leaves the previous policy active and shows up as PolicyApplied=False/PolicyRejected.
type TailnetPolicyReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	Recorder          record.EventRecorder
	OperatorNamespace string

	mu       sync.Mutex
	failures map[string]int // consecutive rejected/failed writes per Tailnet
}

// retryAfter records one more failed write for the Tailnet and returns the backoff before the next try.
func (r *TailnetPolicyReconciler) retryAfter(name string) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failures == nil {
		r.failures = map[string]int{}
	}
	n := r.failures[name]
	r.failures[name] = n + 1
	return min(policyRetry<<min(n, 10), policyRequeue)
}

func (r *TailnetPolicyReconciler) clearRetry(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.failures, name)
}

func (r *TailnetPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)
	var tn tnv1.Tailnet
	if err := r.Get(ctx, req.NamespacedName, &tn); err != nil {
		r.clearRetry(req.Name)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	spec := tn.Spec.Policy
	if spec.BaseConfigMap == "" {
		return ctrl.Result{}, r.off(ctx, &tn)
	}
	policyApplyErrors.WithLabelValues(tn.Name).Add(0) // series exists before the first error → increase() works

	// Base document.
	var baseCM corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.OperatorNamespace, Name: spec.BaseConfigMap}, &baseCM); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Minute}, r.status(ctx, tn.Name, func(t *tnv1.Tailnet) {
			setCond(&t.Status.Conditions, t.Generation, "PolicyRendered", metav1.ConditionFalse, "BaseMissing",
				fmt.Sprintf("ConfigMap %s/%s not found", r.OperatorNamespace, spec.BaseConfigMap))
		})
	}
	base, ok := baseCM.Data[policyKey]
	if !ok {
		return ctrl.Result{RequeueAfter: time.Minute}, r.status(ctx, tn.Name, func(t *tnv1.Tailnet) {
			setCond(&t.Status.Conditions, t.Generation, "PolicyRendered", metav1.ConditionFalse, "BaseMissing",
				fmt.Sprintf("ConfigMap %s has no key %q", spec.BaseConfigMap, policyKey))
		})
	}

	// Render.
	in, skipped, err := r.collect(ctx, &tn)
	if err != nil {
		return ctrl.Result{}, err
	}
	rendered, sum, err := policy.Render([]byte(base), in)
	if err != nil {
		reason := "BaseInvalid"
		if errors.Is(err, policy.ErrEmpty) {
			reason = "PolicyEmpty"
		}
		l.Error(err, "policy not rendered; nothing written", "reason", reason)
		return ctrl.Result{RequeueAfter: policyRequeue}, r.status(ctx, tn.Name, func(t *tnv1.Tailnet) {
			setCond(&t.Status.Conditions, t.Generation, "PolicyRendered", metav1.ConditionFalse, reason, err.Error())
		})
	}
	canonical, err := policy.Normalize(rendered)
	if err != nil {
		return ctrl.Result{}, err
	}
	hash := policy.Hash(canonical)

	// Publish for review (owner guard as for the hosts ConfigMap).
	outName := spec.RenderedConfigMap
	if outName == "" {
		outName = spec.BaseConfigMap + "-rendered"
	}
	var existing corev1.ConfigMap
	err = r.Get(ctx, types.NamespacedName{Namespace: r.OperatorNamespace, Name: outName}, &existing)
	if err == nil && !ownedBy(&existing, tn.UID) {
		l.Error(nil, "rendered ConfigMap exists and is not owned by this Tailnet; refusing to overwrite", "configmap", outName)
		return ctrl.Result{RequeueAfter: policyRequeue}, nil
	}
	if client.IgnoreNotFound(err) != nil {
		return ctrl.Result{}, err
	}
	cm := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: outName, Namespace: r.OperatorNamespace,
			Labels: map[string]string{"app.kubernetes.io/managed-by": fieldOwner, roleLabel: rolePolicyRender}},
		Data: map[string]string{policyKey: string(rendered)},
	}
	if err := controllerutil.SetControllerReference(&tn, cm, r.Scheme); err != nil {
		return ctrl.Result{}, err
	}
	if err := ssaApply(ctx, r.Client, cm); err != nil {
		return ctrl.Result{}, err
	}

	msg := fmt.Sprintf("%d tags, %d grants, %d routes generated", sum.Tags, sum.Grants, sum.Routes)
	if len(sum.Denied) > 0 {
		msg += "; denied ingress tags: " + strings.Join(sum.Denied, ", ")
	}
	if len(skipped) > 0 {
		msg += "; name-addressed targets without grant: " + strings.Join(skipped, ", ")
	}
	renderedCond := func(t *tnv1.Tailnet) {
		if t.Status.Policy == nil {
			t.Status.Policy = &tnv1.PolicyStatus{}
		}
		t.Status.Policy.RenderedHash = hash
		t.Status.Policy.Generated = tnv1.PolicyGenerated{Tags: sum.Tags, Grants: sum.Grants, Routes: sum.Routes}
		setCond(&t.Status.Conditions, t.Generation, "PolicyRendered", metav1.ConditionTrue, "Rendered", msg)
	}

	if spec.Mode != "Apply" {
		return ctrl.Result{RequeueAfter: policyRequeue}, r.status(ctx, tn.Name, func(t *tnv1.Tailnet) {
			renderedCond(t)
			setCond(&t.Status.Conditions, t.Generation, "PolicyApplied", metav1.ConditionFalse, "DryRun",
				fmt.Sprintf("mode DryRun: review ConfigMap %s/%s", r.OperatorNamespace, outName))
		})
	}

	// Apply: compare with the live document, write only on difference.
	apiURL := tn.Spec.APIURL
	if apiURL == "" {
		apiURL = tn.Spec.Server
	}
	apiKey, err := readWorkingKey(ctx, r.Client, r.OperatorNamespace, tn.Name)
	if err != nil {
		return ctrl.Result{RequeueAfter: 15 * time.Second}, r.status(ctx, tn.Name, func(t *tnv1.Tailnet) {
			renderedCond(t)
			setCond(&t.Status.Conditions, t.Generation, "PolicyApplied", metav1.ConditionFalse, "NoAPIKey",
				"waiting for the Tailnet working API key")
		})
	}
	hs := headscale.New(apiURL, apiKey)
	liveHash := ""
	live, liveErr := hs.GetPolicy(ctx)
	if liveErr == nil {
		if n, err := policy.Normalize([]byte(live)); err == nil {
			liveHash = policy.Hash(n)
		}
	}
	prevApplied := ""
	if tn.Status.Policy != nil {
		prevApplied = tn.Status.Policy.AppliedHash
	}
	now := metav1.Now()
	if liveHash == hash {
		r.clearRetry(tn.Name)
		r.approveRoutes(ctx, hs, &tn, rendered)
		return ctrl.Result{RequeueAfter: policyRequeue}, r.status(ctx, tn.Name, func(t *tnv1.Tailnet) {
			renderedCond(t)
			if t.Status.Policy.AppliedHash != hash {
				t.Status.Policy.AppliedHash = hash
				t.Status.Policy.AppliedAt = &now
			}
			setCond(&t.Status.Conditions, t.Generation, "PolicyApplied", metav1.ConditionTrue, "InSync", "live policy equals the rendered one")
			if t.Status.Policy.AppliedAt != nil {
				policyAppliedTimestamp.WithLabelValues(t.Name).Set(float64(t.Status.Policy.AppliedAt.Unix()))
			}
		})
	}
	if prevApplied != "" && liveHash != "" && liveHash != prevApplied && r.Recorder != nil {
		// Somebody changed the live policy behind the operator's back (headscale policy set).
		r.Recorder.Eventf(&tn, corev1.EventTypeWarning, "PolicyDriftOverwritten",
			"live policy differed from the last applied one (manual change?); rewriting the rendered policy")
	}
	if err := hs.SetPolicy(ctx, string(rendered)); err != nil {
		policyApplyErrors.WithLabelValues(tn.Name).Inc()
		reason := "PolicyRejected"
		emsg := err.Error()
		if liveErr != nil {
			reason = "ApplyFailed"
			emsg = fmt.Sprintf("read: %v; write: %v", liveErr, err)
		}
		if len(emsg) > 1024 {
			emsg = emsg[:1024] + "…"
		}
		retryIn := r.retryAfter(tn.Name)
		if reason == "ApplyFailed" {
			// Transport error (Headscale restarting, NetworkPolicy): transient, retried with backoff.
			l.Info("policy write failed; previous policy stays active, retrying", "reason", reason, "retryIn", retryIn, "error", err.Error())
		} else {
			l.Error(err, "policy write rejected; previous policy stays active", "reason", reason, "retryIn", retryIn)
		}
		return ctrl.Result{RequeueAfter: retryIn}, r.status(ctx, tn.Name, func(t *tnv1.Tailnet) {
			renderedCond(t)
			setCond(&t.Status.Conditions, t.Generation, "PolicyApplied", metav1.ConditionFalse, reason, emsg)
		})
	}
	r.clearRetry(tn.Name)
	r.approveRoutes(ctx, hs, &tn, rendered)
	l.Info("policy applied", "tailnet", tn.Name, "hash", hash[:12], "tags", sum.Tags, "grants", sum.Grants, "routes", sum.Routes)
	return ctrl.Result{RequeueAfter: policyRequeue}, r.status(ctx, tn.Name, func(t *tnv1.Tailnet) {
		renderedCond(t)
		t.Status.Policy.AppliedHash = hash
		t.Status.Policy.AppliedAt = &now
		setCond(&t.Status.Conditions, t.Generation, "PolicyApplied", metav1.ConditionTrue, "Applied", "rendered policy written to the control server")
		policyAppliedTimestamp.WithLabelValues(t.Name).Set(float64(now.Unix()))
	})
}

// off removes this Tailnet's rendered ConfigMap and policy status when the feature is disabled.
func (r *TailnetPolicyReconciler) off(ctx context.Context, tn *tnv1.Tailnet) error {
	var cms corev1.ConfigMapList
	if err := r.List(ctx, &cms, client.InNamespace(r.OperatorNamespace), client.MatchingLabels{roleLabel: rolePolicyRender}); err != nil {
		return err
	}
	for i := range cms.Items {
		if cm := &cms.Items[i]; ownedBy(cm, tn.UID) {
			if err := r.Delete(ctx, cm, client.Preconditions{UID: &cm.UID}); client.IgnoreNotFound(err) != nil {
				return err
			}
		}
	}
	if tn.Status.Policy == nil {
		return nil
	}
	return r.status(ctx, tn.Name, func(t *tnv1.Tailnet) {
		t.Status.Policy = nil
		for _, c := range []string{"PolicyRendered", "PolicyApplied"} {
			if i := condIndex(t.Status.Conditions, c); i >= 0 {
				t.Status.Conditions = append(t.Status.Conditions[:i], t.Status.Conditions[i+1:]...)
			}
		}
	})
}

// collect turns the CRs bound to tn into policy inputs. Egress CRs live in the operator namespace
// (admin-controlled), ingress CRs anywhere. Targets addressed by name (no IP) get no grant and are
// returned as skipped — the policy cannot express them as a route.
func (r *TailnetPolicyReconciler) collect(ctx context.Context, tn *tnv1.Tailnet) (policy.Inputs, []string, error) {
	in := policy.Inputs{
		TagOwners:              tn.Spec.Policy.TagOwners,
		RouteApprovers:         tn.Spec.Policy.RouteApprovers,
		IngressSourceAllowlist: tn.Spec.Policy.IngressSourceAllowlist,
	}
	var skipped []string
	var egs tnv1.TailnetEgressList
	if err := r.List(ctx, &egs, client.InNamespace(r.OperatorNamespace)); err != nil {
		return in, nil, err
	}
	for _, eg := range egs.Items {
		if eg.Spec.TailnetRef.Name != tn.Name {
			continue
		}
		e := policy.Egress{Tag: egressTag(tn, &eg)}
		for _, t := range eg.Spec.Targets {
			addr, err := netip.ParseAddr(t.Address)
			if err != nil {
				skipped = append(skipped, eg.Name+"/"+t.Name)
				continue
			}
			e.Targets = append(e.Targets, policy.Target{CIDR: netip.PrefixFrom(addr, addr.BitLen()).String(), Port: t.Port})
		}
		in.Egresses = append(in.Egresses, e)
	}
	var ins tnv1.TailnetIngressList
	if err := r.List(ctx, &ins); err != nil {
		return in, nil, err
	}
	for _, ig := range ins.Items {
		if ig.Spec.TailnetRef.Name != tn.Name {
			continue
		}
		i := policy.Ingress{Tag: ingressTag(tn, &ig), AllowFrom: ig.Spec.AllowFrom}
		for _, ex := range ig.Spec.Exposes {
			i.Ports = append(i.Ports, ex.Port)
		}
		in.Ingresses = append(in.Ingresses, i)
	}
	sort.Slice(in.Egresses, func(a, b int) bool { return in.Egresses[a].Tag < in.Egresses[b].Tag })
	sort.Slice(in.Ingresses, func(a, b int) bool { return in.Ingresses[a].Tag < in.Ingresses[b].Tag })
	sort.Strings(skipped)
	return in, skipped, nil
}

// policyOwned reports whether the operator writes this Tailnet's policy (mode Apply), i.e. whether a
// missing tag is a transient state rather than an admin's omission.
func policyOwned(tn *tnv1.Tailnet) bool {
	return tn.Spec.Policy.BaseConfigMap != "" && tn.Spec.Policy.Mode == "Apply"
}

// egressTag / ingressTag mirror the tag resolution of the egress and ingress reconcilers.
func egressTag(tn *tnv1.Tailnet, eg *tnv1.TailnetEgress) string {
	if eg.Spec.Tag != "" {
		return eg.Spec.Tag
	}
	return naming.Render(tn.Spec.TagTemplate, eg.Name)
}

func ingressTag(tn *tnv1.Tailnet, in *tnv1.TailnetIngress) string {
	if in.Spec.Tag != "" {
		return in.Spec.Tag
	}
	return naming.Render(tn.Spec.IngressTagTemplate, in.Name)
}

// status applies mutate to a fresh copy of the Tailnet status, retrying on conflict — the Tailnet
// controller writes the same status object.
func (r *TailnetPolicyReconciler) status(ctx context.Context, name string, mutate func(*tnv1.Tailnet)) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var t tnv1.Tailnet
		if err := r.Get(ctx, types.NamespacedName{Name: name}, &t); err != nil {
			return client.IgnoreNotFound(err)
		}
		mutate(&t)
		return r.Status().Update(ctx, &t)
	})
}

func condIndex(conds []metav1.Condition, t string) int {
	for i, c := range conds {
		if c.Type == t {
			return i
		}
	}
	return -1
}

// readWorkingKey reads the Tailnet's self-minted working API key.
func readWorkingKey(ctx context.Context, c client.Client, ns, tnName string) (string, error) {
	var s corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: workingSecretName(tnName)}, &s); err != nil {
		return "", err
	}
	v := string(s.Data[apiKeyData])
	if v == "" {
		return "", fmt.Errorf("working api key secret is empty")
	}
	return v, nil
}

// SetupWithManager: driven by the Tailnet, re-rendered when a bound egress/ingress or the base
// ConfigMap changes.
func (r *TailnetPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
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
	byBase := func(ctx context.Context, o client.Object) []reconcile.Request {
		if o.GetNamespace() != r.OperatorNamespace {
			return nil
		}
		var tns tnv1.TailnetList
		if err := r.List(ctx, &tns); err != nil {
			return nil
		}
		var out []reconcile.Request
		for _, t := range tns.Items {
			if t.Spec.Policy.BaseConfigMap == o.GetName() {
				out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: t.Name}})
			}
		}
		return out
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("tailnetpolicy").
		// The render depends on specs only; status writes (ours every reconcile, the CRs' every 30 s)
		// must not re-trigger it.
		For(&tnv1.Tailnet{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// The rendered ConfigMap is ours: every reconcile writes it, so reacting to its updates would
		// re-run the reconcile once more each time. Only a deletion matters (re-create it).
		Owns(&corev1.ConfigMap{}, builder.WithPredicates(predicate.Funcs{
			CreateFunc:  func(event.CreateEvent) bool { return false },
			UpdateFunc:  func(event.UpdateEvent) bool { return false },
			GenericFunc: func(event.GenericEvent) bool { return false },
		})).
		Watches(&tnv1.TailnetEgress{}, handler.EnqueueRequestsFromMapFunc(byRef), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&tnv1.TailnetIngress{}, handler.EnqueueRequestsFromMapFunc(byRef), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(byBase)).
		Complete(r)
}
