package controller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
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

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/gateway"
	"tsunaro.io/tailnet-operator/internal/headscale"
	operatormetrics "tsunaro.io/tailnet-operator/internal/metrics"
	"tsunaro.io/tailnet-operator/internal/naming"
	"tsunaro.io/tailnet-operator/internal/policy"
	"tsunaro.io/tailnet-operator/internal/routes"
)

const (
	// policyKey is the ConfigMap key of both the base and the rendered policy.
	policyKey = "policy"
	// roleLabel tells the operator's ConfigMaps apart (dns hosts file vs rendered policy) so one
	// feature switching off never deletes the other's output.
	roleLabel        = "tsunaro.io/role"
	roleDNSHosts     = "dns-hosts"
	rolePolicyRender = "policy-rendered"

	policyRequeue = 5 * time.Minute
	// policyRetry is the wait after the first rejected/failed write; it doubles per consecutive
	// failure. A rejection caused by a node re-registering (test src "resolved to no IP addresses")
	// or by a Headscale-side blocker (duplicate users) clears without any Kubernetes event, so
	// rejected writes stay at policyRejectedMax; transport failures back off to policyRequeue.
	policyRetry       = 15 * time.Second
	policyRejectedMax = time.Minute
)

// TailnetPolicyReconciler owns the control server's policy for a Tailnet: it renders the base
// document from a ConfigMap plus what the bound egress/ingress CRs imply, publishes the result in a
// ConfigMap for review and — in Apply mode — writes it to the server whenever the live policy
// differs. Rendering never removes base content; Headscale validates before storing, so a rejected
// write leaves the previous policy active and shows up as PolicyApplied=False/PolicyRejected.
type TailnetPolicyReconciler struct {
	Metrics *operatormetrics.Metrics
	client.Client
	Scheme            *runtime.Scheme
	Recorder          record.EventRecorder
	OperatorNamespace string

	mu       sync.Mutex
	failures map[string]int // consecutive rejected/failed writes per Tailnet
}

// retryAfter records one more failed write for the Tailnet and returns the backoff before the next
// try, capped at limit.
func (r *TailnetPolicyReconciler) retryAfter(name string, limit time.Duration) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failures == nil {
		r.failures = map[string]int{}
	}
	n := r.failures[name]
	r.failures[name] = n + 1
	return min(policyRetry<<min(n, 10), limit)
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
		if apierrors.IsNotFound(err) {
			r.Metrics.Delete("Tailnet", req.Namespace, req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	spec := tn.Spec.Policy
	if spec.BaseConfigMap == "" && spec.Mode != "Export" {
		return ctrl.Result{}, r.off(ctx, &tn)
	}
	// Idle reconciliations expose a zero baseline before later events, so increase() can
	// observe the first error or replay batch rather than starting with its nonzero total.
	r.Metrics.PolicyError(tn.Name, false)
	r.Metrics.Approved(tn.Name, 0)

	if spec.Mode == "Export" {
		return r.export(ctx, &tn)
	}

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
	in, skipped, sites, err := r.collect(ctx, &tn)
	if err != nil {
		return ctrl.Result{}, err
	}
	// Site status is written on every exit below from the freshest node list this reconcile
	// obtained (nil when the control server was not queried).
	var nodes []headscale.Node
	defer func() { r.siteStatus(ctx, &tn, sites, nodes) }()
	// Spoke fragments committed here after review; a missing one fails closed rather than dropping
	// the spoke's grants from a live policy.
	frags, missing, err := r.readFragments(ctx, spec.FragmentConfigMaps)
	if err != nil {
		return ctrl.Result{}, err
	}
	if missing != "" {
		return ctrl.Result{RequeueAfter: time.Minute}, r.status(ctx, tn.Name, func(t *tnv1.Tailnet) {
			setCond(&t.Status.Conditions, t.Generation, "PolicyRendered", metav1.ConditionFalse, "FragmentMissing",
				fmt.Sprintf("fragment ConfigMap %s/%s not found or has no key %q", r.OperatorNamespace, missing, policyKey))
		})
	}
	// A fragment is another cluster's grants: whoever wrote the ConfigMap, it may only add what the
	// hub's limits allow (own tags, hub owners/approvers/allowlist, tcp ports, no reserved space).
	gitRules := fragmentRules(&tn, []byte(base), in, gitFragmentPatterns, nil, false)
	for i, f := range frags {
		if err := policy.ValidateFragment(f, gitRules); err != nil {
			l.Error(err, "fragment rejected; nothing written", "configmap", spec.FragmentConfigMaps[i])
			return ctrl.Result{RequeueAfter: policyRequeue}, r.status(ctx, tn.Name, func(t *tnv1.Tailnet) {
				setCond(&t.Status.Conditions, t.Generation, "PolicyRendered", metav1.ConditionFalse, "FragmentInvalid",
					fmt.Sprintf("fragment ConfigMap %s: %v", spec.FragmentConfigMaps[i], err))
			})
		}
	}
	// Fragments pulled from spoke clusters; each is validated and gated per spoke, an unreachable
	// or invalid spoke keeps its last approved fragment.
	spokeFrags, spokeStatuses, err := r.spokeFragments(ctx, &tn, []byte(base), in)
	if err != nil {
		return ctrl.Result{}, err
	}
	frags = append(frags, spokeFrags...)
	spokesCond := func(t *tnv1.Tailnet) {
		t.Status.Spokes = spokeStatuses
		if len(spec.Spokes) == 0 {
			meta.RemoveStatusCondition(&t.Status.Conditions, "SpokesReady")
			return
		}
		s, reason, msg := spokesReady(spokeStatuses)
		setCond(&t.Status.Conditions, t.Generation, "SpokesReady", s, reason, msg)
	}
	rendered, sum, err := policy.Render([]byte(base), in, frags...)
	if err != nil {
		reason := "BaseInvalid"
		switch {
		case errors.Is(err, policy.ErrEmpty):
			reason = "PolicyEmpty"
		case errors.Is(err, policy.ErrFragment):
			reason = "FragmentInvalid"
		}
		l.Error(err, "policy not rendered; nothing written", "reason", reason)
		return ctrl.Result{RequeueAfter: policyRequeue}, r.status(ctx, tn.Name, func(t *tnv1.Tailnet) {
			spokesCond(t)
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
	if conflict, err := r.publishRender(ctx, &tn, outName, string(rendered)); err != nil {
		return ctrl.Result{}, err
	} else if conflict {
		l.Error(nil, "rendered ConfigMap exists and is not owned by this Tailnet; refusing to overwrite", "configmap", outName)
		if r.Recorder != nil {
			r.Recorder.Eventf(&tn, corev1.EventTypeWarning, "ConfigMapNotOwned",
				"rendered ConfigMap %s/%s is owned by another resource; refusing to overwrite", r.OperatorNamespace, outName)
		}
		return ctrl.Result{RequeueAfter: policyRequeue}, nil
	}

	msg := fmt.Sprintf("%d tags, %d grants, %d routes generated", sum.Tags, sum.Grants, sum.Routes)
	if sum.Fragments > 0 {
		msg += fmt.Sprintf("; %d fragments merged", sum.Fragments)
	}
	if len(sum.Denied) > 0 {
		msg += "; denied ingress tags: " + strings.Join(sum.Denied, ", ")
	}
	if len(sum.UnknownSources) > 0 {
		msg += "; skipped undeclared sources: " + strings.Join(sum.UnknownSources, ", ")
	}
	if len(skipped) > 0 {
		msg += "; skipped (name-addressed target without grant, gateway routes that do not plan, or blocked site): " + strings.Join(skipped, ", ")
	}
	renderedCond := func(t *tnv1.Tailnet) {
		spokesCond(t)
		if t.Status.Policy == nil {
			t.Status.Policy = &tnv1.PolicyStatus{}
		}
		t.Status.Policy.RenderedHash = hash
		t.Status.Policy.Generated = tnv1.PolicyGenerated{Tags: sum.Tags, Grants: sum.Grants, Routes: sum.Routes}
		setCond(&t.Status.Conditions, t.Generation, "PolicyRendered", metav1.ConditionTrue, "Rendered", msg)
	}

	if spec.Mode != "Apply" {
		// DryRun still observes the control server for the site CRs when the working key exists.
		if len(sites) > 0 {
			nodes = r.observeNodes(ctx, &tn)
		}
		return ctrl.Result{RequeueAfter: policyRequeue}, r.status(ctx, tn.Name, func(t *tnv1.Tailnet) {
			renderedCond(t)
			setCond(&t.Status.Conditions, t.Generation, "PolicyApplied", metav1.ConditionFalse, "DryRun",
				fmt.Sprintf("mode DryRun: review ConfigMap %s/%s", r.OperatorNamespace, outName))
		})
	}

	fileMode := func() (ctrl.Result, error) {
		r.clearRetry(tn.Name)
		return ctrl.Result{RequeueAfter: policyRequeue}, r.status(ctx, tn.Name, func(t *tnv1.Tailnet) {
			renderedCond(t)
			setCond(&t.Status.Conditions, t.Generation, "PolicyMode", metav1.ConditionFalse, "File",
				"operator cannot write policy; set policy.mode: database")
			setCond(&t.Status.Conditions, t.Generation, "PolicyApplied", metav1.ConditionFalse, "PolicyModeFile",
				"policy write skipped; set Headscale policy.mode: database")
		})
	}
	if c := meta.FindStatusCondition(tn.Status.Conditions, "PolicyMode"); c != nil &&
		c.Status == metav1.ConditionFalse && c.Reason == "File" && c.ObservedGeneration == tn.Generation {
		return fileMode()
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
	hs := headscale.New(apiURL, apiKey, r.Metrics.Headscale(tn.Name))
	liveHash := ""
	live, databaseMode, liveErr := hs.GetPolicyWithMode(ctx)
	// The policy controller can run before preflight on startup. Check the live mode as well,
	// so an established file-mode response never results in a PUT or route approvals.
	if databaseMode != nil && !*databaseMode {
		return fileMode()
	}
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
		nodes = r.approveRoutes(ctx, hs, &tn, rendered)
		return ctrl.Result{RequeueAfter: policyRequeue}, r.status(ctx, tn.Name, func(t *tnv1.Tailnet) {
			renderedCond(t)
			if t.Status.Policy.AppliedHash != hash {
				t.Status.Policy.AppliedHash = hash
				t.Status.Policy.AppliedAt = &now
			}
			setCond(&t.Status.Conditions, t.Generation, "PolicyApplied", metav1.ConditionTrue, "InSync", "live policy equals the rendered one")
		})
	}
	if prevApplied != "" && liveHash != "" && liveHash != prevApplied && r.Recorder != nil {
		// Somebody changed the live policy behind the operator's back (headscale policy set).
		r.Recorder.Eventf(&tn, corev1.EventTypeWarning, "PolicyDriftOverwritten",
			"live policy differed from the last applied one (manual change?); rewriting the rendered policy")
	}
	if err := hs.SetPolicy(ctx, string(rendered)); err != nil {
		r.Metrics.PolicyError(tn.Name, true)
		reason := "PolicyRejected"
		emsg := err.Error()
		if meta.IsStatusConditionFalse(tn.Status.Conditions, "UsersUnique") {
			// Headscale answers "multiple users found" (with the colliding e-mail addresses) to every
			// policy write while two users share a name; the client never reads error bodies, so name
			// the known cause from the UsersUnique verdict instead of a bare HTTP status.
			emsg = "policy rejected: duplicate Headscale user names; see condition UsersUnique"
		}
		if liveErr != nil {
			reason = "ApplyFailed"
			emsg = fmt.Sprintf("read: %v; write: %v", liveErr, err)
		}
		if len(emsg) > 1024 {
			emsg = emsg[:1024] + "…"
		}
		// A rejection is usually cleared on the Headscale side (users, tags) without any Kubernetes
		// event, so only the retry cadence decides how fast the write recovers.
		limit := policyRejectedMax
		if reason == "ApplyFailed" {
			limit = policyRequeue
		}
		retryIn := r.retryAfter(tn.Name, limit)
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
	nodes = r.approveRoutes(ctx, hs, &tn, rendered)
	l.Info("policy applied", "tailnet", tn.Name, "hash", hash[:12], "tags", sum.Tags, "grants", sum.Grants, "routes", sum.Routes)
	return ctrl.Result{RequeueAfter: policyRequeue}, r.status(ctx, tn.Name, func(t *tnv1.Tailnet) {
		renderedCond(t)
		t.Status.Policy.AppliedHash = hash
		t.Status.Policy.AppliedAt = &now
		setCond(&t.Status.Conditions, t.Generation, "PolicyApplied", metav1.ConditionTrue, "Applied", "rendered policy written to the control server")
	})
}

// export renders only this Tailnet's generated entries (mode Export, a spoke) into a fragment
// ConfigMap for a hub operator to merge. It never reads a base or writes the control server; the
// spoke's agents stay TagKnown=False until the hub applies the merged policy — that gap is the
// review gate for foreign grants.
func (r *TailnetPolicyReconciler) export(ctx context.Context, tn *tnv1.Tailnet) (ctrl.Result, error) {
	in, skipped, sites, err := r.collect(ctx, tn)
	if err != nil {
		return ctrl.Result{}, err
	}
	// A spoke cannot approve its own routes (the hub owns the policy), but it can read the node
	// list: sites report what the control server shows, and Approved follows the hub's merge.
	var nodes []headscale.Node
	if len(sites) > 0 {
		nodes = r.observeNodes(ctx, tn)
	}
	defer r.siteStatus(ctx, tn, sites, nodes)
	rendered, sum, err := policy.RenderFragment(in)
	if err != nil {
		return ctrl.Result{}, err
	}
	canonical, err := policy.Normalize(rendered)
	if err != nil {
		return ctrl.Result{}, err
	}
	hash := policy.Hash(canonical)
	outName := tn.Spec.Policy.RenderedConfigMap
	if outName == "" {
		outName = tn.Name + "-policy-fragment"
	}
	if conflict, err := r.publishRender(ctx, tn, outName, string(rendered)); err != nil {
		return ctrl.Result{}, err
	} else if conflict {
		log.FromContext(ctx).Error(nil, "fragment ConfigMap exists and is not owned by this Tailnet; refusing to overwrite", "configmap", outName)
		if r.Recorder != nil {
			r.Recorder.Eventf(tn, corev1.EventTypeWarning, "ConfigMapNotOwned",
				"fragment ConfigMap %s/%s is owned by another resource; refusing to overwrite", r.OperatorNamespace, outName)
		}
		return ctrl.Result{RequeueAfter: policyRequeue}, nil
	}
	msg := fmt.Sprintf("%d tags, %d grants, %d routes exported", sum.Tags, sum.Grants, sum.Routes)
	if len(sum.Denied) > 0 {
		msg += "; denied ingress tags: " + strings.Join(sum.Denied, ", ")
	}
	if len(sum.UnknownSources) > 0 {
		msg += "; skipped undeclared sources: " + strings.Join(sum.UnknownSources, ", ")
	}
	if len(skipped) > 0 {
		msg += "; skipped: " + strings.Join(skipped, ", ")
	}
	// The spoke never writes, but it can read: the same API key the agents' TagKnown check uses
	// tells whether the hub has merged this fragment yet, so the status says so instead of a
	// standing "waiting". Unreadable stays the plain Export verdict — the fragment is still valid.
	applied, appliedReason, appliedMsg := metav1.ConditionFalse, "Export",
		fmt.Sprintf("mode Export: waiting for the hub to merge ConfigMap %s/%s (policy.spokes pull or a committed fragmentConfigMaps entry)", r.OperatorNamespace, outName)
	if live, err := r.liveSpokePolicy(ctx, tn); err != nil {
		appliedMsg += "; live policy not readable: " + err.Error()
	} else if missing, err := policy.MissingFromLive([]byte(live), rendered); err != nil {
		appliedMsg += "; " + err.Error()
	} else if len(missing) > 0 {
		appliedReason = "HubPending"
		appliedMsg = fmt.Sprintf("hub policy lacks %d of %d exported entries (%s); fragment ConfigMap %s/%s awaits merge",
			len(missing), sum.Tags+sum.Grants+sum.Routes, strings.Join(truncateList(missing, 5), ", "), r.OperatorNamespace, outName)
	} else {
		applied, appliedReason = metav1.ConditionTrue, "HubMerged"
		appliedMsg = fmt.Sprintf("hub policy carries all %d exported entries", sum.Tags+sum.Grants+sum.Routes)
	}
	now := metav1.Now()
	return ctrl.Result{RequeueAfter: policyRequeue}, r.status(ctx, tn.Name, func(t *tnv1.Tailnet) {
		if t.Status.Policy == nil {
			t.Status.Policy = &tnv1.PolicyStatus{}
		}
		t.Status.Policy.RenderedHash = hash
		t.Status.Policy.Generated = tnv1.PolicyGenerated{Tags: sum.Tags, Grants: sum.Grants, Routes: sum.Routes}
		if applied == metav1.ConditionTrue {
			if t.Status.Policy.AppliedHash != hash {
				t.Status.Policy.AppliedHash, t.Status.Policy.AppliedAt = hash, &now
			}
		} else {
			t.Status.Policy.AppliedHash, t.Status.Policy.AppliedAt = "", nil
		}
		setCond(&t.Status.Conditions, t.Generation, "PolicyRendered", metav1.ConditionTrue, "Rendered", msg)
		setCond(&t.Status.Conditions, t.Generation, "PolicyApplied", applied, appliedReason, appliedMsg)
	})
}

// readClient returns a control-server client on the Tailnet's working API key, for the paths that
// only read (DryRun, Export).
func (r *TailnetPolicyReconciler) readClient(ctx context.Context, tn *tnv1.Tailnet) (*headscale.Client, error) {
	apiKey, err := readWorkingKey(ctx, r.Client, r.OperatorNamespace, tn.Name)
	if err != nil {
		return nil, fmt.Errorf("working api key: %w", err)
	}
	apiURL := tn.Spec.APIURL
	if apiURL == "" {
		apiURL = tn.Spec.Server
	}
	return headscale.New(apiURL, apiKey, r.Metrics.Headscale(tn.Name)), nil
}

// liveSpokePolicy reads the control server's policy with the Tailnet's working API key.
func (r *TailnetPolicyReconciler) liveSpokePolicy(ctx context.Context, tn *tnv1.Tailnet) (string, error) {
	hs, err := r.readClient(ctx, tn)
	if err != nil {
		return "", err
	}
	return hs.GetPolicy(ctx)
}

// observeNodes lists the control server's nodes for the site status without writing anything.
// nil means not observed (no working key, API failure); an empty tailnet is a non-nil empty list.
func (r *TailnetPolicyReconciler) observeNodes(ctx context.Context, tn *tnv1.Tailnet) []headscale.Node {
	hs, err := r.readClient(ctx, tn)
	if err != nil {
		return nil
	}
	nodes, err := hs.ListNodes(ctx)
	if err != nil {
		return nil
	}
	return append([]headscale.Node{}, nodes...)
}

func truncateList(ss []string, n int) []string {
	if len(ss) <= n {
		return ss
	}
	return append(append([]string(nil), ss[:n]...), "…")
}

// publishRender writes the rendered policy or fragment to outName under the owner guard. It reports
// conflict=true when another owner holds the ConfigMap (the caller then requeues without writing).
func (r *TailnetPolicyReconciler) publishRender(ctx context.Context, tn *tnv1.Tailnet, outName, rendered string) (conflict bool, err error) {
	var existing corev1.ConfigMap
	err = r.Get(ctx, types.NamespacedName{Namespace: r.OperatorNamespace, Name: outName}, &existing)
	// An ownerRef-less render/fragment ConfigMap of ours (e.g. left over a Tailnet re-create) is
	// adopted by the SSA apply below; a foreign or otherwise-controlled one is refused.
	if err == nil && !ownedBy(&existing, tn.UID) && !adoptable(&existing, rolePolicyRender) {
		return true, nil
	}
	if client.IgnoreNotFound(err) != nil {
		return false, err
	}
	cm := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: outName, Namespace: r.OperatorNamespace,
			Labels: map[string]string{"app.kubernetes.io/managed-by": fieldOwner, roleLabel: rolePolicyRender}},
		Data: map[string]string{policyKey: rendered},
	}
	if err := controllerutil.SetControllerReference(tn, cm, r.Scheme); err != nil {
		return false, err
	}
	return false, ssaApply(ctx, r.Client, cm)
}

// readFragments loads the policy fragments (operator namespace, key "policy") this hub merges. A
// name whose ConfigMap or key is missing is returned as missing so the caller fails the render
// closed; the rendered policy is never rewritten without every listed fragment present.
func (r *TailnetPolicyReconciler) readFragments(ctx context.Context, names []string) (frags [][]byte, missing string, err error) {
	for _, name := range names {
		var cm corev1.ConfigMap
		if err := r.Get(ctx, types.NamespacedName{Namespace: r.OperatorNamespace, Name: name}, &cm); err != nil {
			if client.IgnoreNotFound(err) != nil {
				return nil, "", err
			}
			return nil, name, nil
		}
		data, ok := cm.Data[policyKey]
		if !ok {
			return nil, name, nil
		}
		frags = append(frags, []byte(data))
	}
	return frags, "", nil
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
		t.Status.Spokes = nil
		for _, c := range []string{"PolicyRendered", "PolicyApplied", "SpokesReady"} {
			if i := condIndex(t.Status.Conditions, c); i >= 0 {
				t.Status.Conditions = append(t.Status.Conditions[:i], t.Status.Conditions[i+1:]...)
			}
		}
	})
}

// collect turns the CRs bound to tn into policy inputs. Egress CRs live in the operator namespace
// (admin-controlled), ingress CRs anywhere. Targets addressed by name (no IP) get no grant and are
// returned as skipped — the policy cannot express them as a route.
func (r *TailnetPolicyReconciler) collect(ctx context.Context, tn *tnv1.Tailnet) (policy.Inputs, []string, []tnv1.TailnetSite, error) {
	in := policy.Inputs{
		TagOwners:              tn.Spec.Policy.TagOwners,
		RouteApprovers:         tn.Spec.Policy.RouteApprovers,
		IngressSourceAllowlist: tn.Spec.Policy.IngressSourceAllowlist,
	}
	var skipped []string
	var egs tnv1.TailnetEgressList
	if err := r.List(ctx, &egs, client.InNamespace(r.OperatorNamespace)); err != nil {
		return in, nil, nil, err
	}
	// render must not depend on List order; a stable tag sort below keeps this order for ties
	sort.Slice(egs.Items, func(a, b int) bool {
		if egs.Items[a].Namespace != egs.Items[b].Namespace {
			return egs.Items[a].Namespace < egs.Items[b].Namespace
		}
		return egs.Items[a].Name < egs.Items[b].Name
	})
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
		return in, nil, nil, err
	}
	sort.Slice(ins.Items, func(a, b int) bool {
		if ins.Items[a].Namespace != ins.Items[b].Namespace {
			return ins.Items[a].Namespace < ins.Items[b].Namespace
		}
		return ins.Items[a].Name < ins.Items[b].Name
	})
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
	// Gateways are cluster-scoped. The routes are exactly what RenderFresh advertises (same planner,
	// same inputs); a gateway whose routes do not plan is skipped and reported, never half-rendered.
	var gws tnv1.TailnetGatewayList
	if err := r.List(ctx, &gws); err != nil {
		return in, nil, nil, err
	}
	sort.Slice(gws.Items, func(a, b int) bool { return gws.Items[a].Name < gws.Items[b].Name }) // merge order must not depend on list order
	for _, g := range gws.Items {
		if string(g.Spec.TailnetRef.Name) != tn.Name || !g.DeletionTimestamp.IsZero() {
			continue
		}
		plan, err := gateway.PlanRoutes(gateway.SpecRouteInputs(&g, tn.Name, r.OperatorNamespace, egs.Items))
		if err != nil {
			skipped = append(skipped, "gateway/"+g.Name)
			continue
		}
		in.Gateways = append(in.Gateways, policy.Gateway{Tags: slices.Clone(g.Spec.Tags), Routes: plan.Routes})
	}
	// Sites are cluster-scoped. Only sites the registry does not block are rendered; blocked ones
	// are reported on the site CR (siteStatus) and listed as skipped here.
	var sites tnv1.TailnetSiteList
	if err := r.List(ctx, &sites); err != nil {
		return in, nil, nil, err
	}
	bound := sites.Items[:0]
	for _, s := range sites.Items {
		if s.Spec.TailnetRef.Name == tn.Name && s.DeletionTimestamp.IsZero() {
			bound = append(bound, s)
		}
	}
	rs, reserved := registryInputs(tn, bound)
	reg := routes.Build(rs, reserved, nil) // blocking does not depend on live nodes
	for _, s := range reg.Shipped {
		in.Sites = append(in.Sites, policy.Site{Prefixes: s.Prefixes, Approvers: s.Tags})
	}
	for name, st := range reg.States {
		if st.Blocked != nil {
			skipped = append(skipped, "site/"+name)
		}
	}
	// Stable: CRs that resolve to the same tag (two exposes of one service) keep their
	// namespace/name order above, so the rendered grant src list is deterministic.
	sort.SliceStable(in.Egresses, func(a, b int) bool { return in.Egresses[a].Tag < in.Egresses[b].Tag })
	sort.SliceStable(in.Ingresses, func(a, b int) bool { return in.Ingresses[a].Tag < in.Ingresses[b].Tag })
	sort.Strings(skipped)
	return in, skipped, bound, nil
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
			if apierrors.IsNotFound(err) {
				r.Metrics.Delete("Tailnet", "", name)
			}
			return client.IgnoreNotFound(err)
		}
		mutate(&t)
		return updateObservedStatus(ctx, r.Client, r.Metrics, &t)
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

// policyModeChanged wakes the policy controller when preflight discovers a mode change, without
// reacting to its own render/apply status writes.
func policyModeChanged(e event.UpdateEvent) bool {
	old, oldOK := e.ObjectOld.(*tnv1.Tailnet)
	current, currentOK := e.ObjectNew.(*tnv1.Tailnet)
	if !oldOK || !currentOK {
		return false
	}
	a := meta.FindStatusCondition(old.Status.Conditions, "PolicyMode")
	b := meta.FindStatusCondition(current.Status.Conditions, "PolicyMode")
	if a == nil || b == nil {
		return (a == nil) != (b == nil)
	}
	return a.Status != b.Status || a.Reason != b.Reason
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
		case *tnv1.TailnetGateway:
			name = string(cr.Spec.TailnetRef.Name)
		case *tnv1.TailnetSite:
			name = cr.Spec.TailnetRef.Name
		}
		if name == "" {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: name}}}
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("tailnetpolicy").
		// A preflight mode change matters; unrelated status writes must not re-trigger the render.
		// An approve-spoke annotation is the admin's gate for a pending spoke fragment.
		For(&tnv1.Tailnet{}, builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.AnnotationChangedPredicate{}, predicate.Funcs{
			CreateFunc:  func(event.CreateEvent) bool { return false },
			DeleteFunc:  func(event.DeleteEvent) bool { return false },
			GenericFunc: func(event.GenericEvent) bool { return false },
			UpdateFunc:  policyModeChanged,
		}))).
		// The rendered ConfigMap is ours: every reconcile writes it, so reacting to its updates would
		// re-run the reconcile once more each time. Only a deletion matters (re-create it).
		Owns(&corev1.ConfigMap{}, builder.WithPredicates(predicate.Funcs{
			CreateFunc:  func(event.CreateEvent) bool { return false },
			UpdateFunc:  func(event.UpdateEvent) bool { return false },
			GenericFunc: func(event.GenericEvent) bool { return false },
		})).
		Watches(&tnv1.TailnetEgress{}, handler.EnqueueRequestsFromMapFunc(byRef), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&tnv1.TailnetIngress{}, handler.EnqueueRequestsFromMapFunc(byRef), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&tnv1.TailnetGateway{}, handler.EnqueueRequestsFromMapFunc(byRef), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// Sites have no reconciler of their own: a deleted site must drop its metrics here.
		Watches(&tnv1.TailnetSite{}, handler.EnqueueRequestsFromMapFunc(byRef), builder.WithPredicates(predicate.Funcs{
			UpdateFunc: predicate.GenerationChangedPredicate{}.Update,
			DeleteFunc: func(e event.DeleteEvent) bool {
				r.Metrics.Delete("TailnetSite", "", e.Object.GetName())
				return true
			},
		})).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.byPolicyConfigMap)).
		Complete(r)
}

// byPolicyConfigMap enqueues every Tailnet whose base or one of whose fragment ConfigMaps is o
// (operator namespace only).
func (r *TailnetPolicyReconciler) byPolicyConfigMap(ctx context.Context, o client.Object) []reconcile.Request {
	if o.GetNamespace() != r.OperatorNamespace {
		return nil
	}
	var tns tnv1.TailnetList
	if err := r.List(ctx, &tns); err != nil {
		return nil
	}
	var out []reconcile.Request
	for _, t := range tns.Items {
		if t.Spec.Policy.BaseConfigMap == o.GetName() || slices.Contains(t.Spec.Policy.FragmentConfigMaps, o.GetName()) {
			out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: t.Name}})
		}
	}
	return out
}
