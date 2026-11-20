package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
	operatormetrics "tsunaro.io/tailnet-operator/internal/metrics"
	"tsunaro.io/tailnet-operator/internal/naming"
	"tsunaro.io/tailnet-operator/internal/ports"
	"tsunaro.io/tailnet-operator/internal/routes"
)

// TailnetEgressReconciler turns one CR into an egress identity: a tag, a pre-auth key, an agent pod
// and one Service per target. It never writes the tailnet policy; a missing grant becomes status.
type TailnetEgressReconciler struct {
	Metrics *operatormetrics.Metrics
	client.Client
	Scheme                *runtime.Scheme
	OperatorNamespace     string
	OperatorImage         string
	AgentImagePullSecrets []string
	AgentResources        corev1.ResourceRequirements
	// AgentScrapePeers may reach the agent health/metrics port besides the operator.
	AgentScrapePeers []networkingv1.NetworkPolicyPeer
	Recorder         record.EventRecorder
}

func (r *TailnetEgressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)
	var eg tnv1.TailnetEgress
	if err := r.Get(ctx, req.NamespacedName, &eg); err != nil {
		if apierrors.IsNotFound(err) {
			r.Metrics.Delete("TailnetEgress", req.Namespace, req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// Emit one event per Ready-reason flip, from whatever this reconcile leaves persisted.
	oldReady := readyReason(eg.Status.Conditions)
	defer func() { emitReadyChange(r.Recorder, &eg, oldReady, readyReason(eg.Status.Conditions)) }()
	if !eg.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, releaseAuthKey(ctx, r.Client, r.OperatorNamespace, &eg, eg.Spec.TailnetRef.Name, r.Metrics.Headscale(eg.Spec.TailnetRef.Name))
	}
	if err := ensureAuthKeyFinalizer(ctx, r.Client, &eg); err != nil {
		return ctrl.Result{}, err
	}
	ns := eg.Namespace

	// Resolve the Tailnet and its working API key (minted by the Tailnet controller).
	var tn tnv1.Tailnet
	if err := r.Get(ctx, types.NamespacedName{Name: eg.Spec.TailnetRef.Name}, &tn); err != nil {
		setCond(&eg.Status.Conditions, eg.Generation, "Ready", metav1.ConditionFalse, "NoTailnet",
			fmt.Sprintf("Tailnet %q not found", eg.Spec.TailnetRef.Name))
		_ = updateObservedStatus(ctx, r.Client, r.Metrics, &eg)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	apiURL := tn.Spec.APIURL
	if apiURL == "" {
		apiURL = tn.Spec.Server
	}
	apiKey, err := r.readWorkingKey(ctx, tn.Name)
	if err != nil {
		// The Tailnet controller has not minted the working key yet; wait for it.
		setCond(&eg.Status.Conditions, eg.Generation, "Ready", metav1.ConditionFalse, "NoAPIKey",
			"waiting for the Tailnet working API key")
		_ = updateObservedStatus(ctx, r.Client, r.Metrics, &eg)
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}
	hs := headscale.New(apiURL, apiKey, r.Metrics.Headscale(tn.Name))

	// Render + validate tag and hostname.
	tag := eg.Spec.Tag
	if tag == "" {
		tag = naming.Render(tn.Spec.TagTemplate, eg.Name)
	}
	hostname := eg.Spec.Hostname
	if hostname == "" {
		hostname = naming.Render(tn.Spec.HostnameTemplate, eg.Name)
	}
	if err := naming.ValidateTag(tag); err != nil {
		return r.fail(ctx, &eg, "InvalidTag", err)
	}
	if err := naming.ValidateHostname(hostname); err != nil {
		return r.fail(ctx, &eg, "InvalidHostname", err)
	}
	eg.Status.Hostname = hostname
	eg.Status.Tag = tag

	// DNS aliases are arbitrated oldest-owner-wins across every CR of this Tailnet. Reject invalid
	// alias derivation and refuse to publish a loser's aliases.
	if set, reason := desiredEgressDNSClaims(&eg, &tn, r.OperatorNamespace); reason != "" {
		return r.fail(ctx, &eg, reason, fmt.Errorf("egress DNS alias configuration is invalid"))
	} else if set != nil {
		decisions, err := collectDNSClaimDecisions(ctx, r.Client, &tn, r.OperatorNamespace)
		if err != nil {
			return r.fail(ctx, &eg, "DNSConflictUnresolved", err)
		}
		ownerKey := dnsClaimOwnerKey{Kind: dnsEgressKind, Namespace: eg.Namespace, Name: eg.Name, UID: eg.UID}
		if d, ok := decisions[ownerKey]; ok && d.Blocked && d.Conflict != nil {
			return r.fail(ctx, &eg, "DNSNameConflict", dnsConflictError(d.Conflict))
		}
	}

	// TagKnown: refuse to mint for a tag the policy never declared. Text search, not HuJSON parsing
	// — a typo is what we are catching, not a crafted policy. ponytail: substring match; upgrade to
	// hujson.Standardize + tagOwners lookup if a tag ever legitimately appears only as a substring.
	policy, err := hs.GetPolicy(ctx)
	if err != nil {
		return r.fail(ctx, &eg, "PolicyUnreadable", err)
	}
	tagKnown := strings.Contains(policy, `"`+tag+`"`)
	if !tagKnown {
		reason, msg := "Unknown", fmt.Sprintf("tag %q is not declared in the tailnet policy; not minting a key", tag)
		if policyOwned(&tn) {
			reason, msg = "PolicyPending", fmt.Sprintf("tag %q not yet in the live policy; the Tailnet policy controller declares it on its next apply", tag)
		}
		setCond(&eg.Status.Conditions, eg.Generation, "TagKnown", metav1.ConditionFalse, reason, msg)
		setCond(&eg.Status.Conditions, eg.Generation, "Ready", metav1.ConditionFalse, "TagUnknown",
			"tag not in policy")
		eg.Status.ObservedGeneration = eg.Generation
		_ = updateObservedStatus(ctx, r.Client, r.Metrics, &eg)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	setCond(&eg.Status.Conditions, eg.Generation, "TagKnown", metav1.ConditionTrue, "Known", "tag declared in policy")

	// Pre-auth key lifecycle.
	authExp, err := r.ensureAuthKey(ctx, &eg, &tn, hs, tag)
	if err != nil {
		return r.fail(ctx, &eg, "AuthKey", err)
	}
	if authExp != nil {
		et := metav1.NewTime(*authExp)
		eg.Status.AuthKeyExpiresAt = &et
	}

	// Stable listen ports: keep whatever the current ConfigMap already assigned.
	existing := r.currentListenPorts(ctx, ns, eg.Name)
	names := make([]string, len(eg.Spec.Targets))
	for i, t := range eg.Spec.Targets {
		names[i] = t.Name
	}
	listen := ports.Assign(existing, names)

	// Expose is the tenant's wish; the Tailnet's exposeSourceAllowlist is the admin's veto. A denied
	// expose is rendered as if absent (ClusterIP, no ipBlock) so shrinking the allowlist closes the
	// LAN door on the next reconcile instead of leaving a stale LoadBalancer behind.
	expose := eg.Spec.Expose
	if expose != nil {
		if outside := exposeDenied(expose, tn.Spec.ExposeSourceAllowlist); outside != "" {
			setCond(&eg.Status.Conditions, eg.Generation, "Exposed", metav1.ConditionFalse, "Denied",
				fmt.Sprintf("allowFrom %s is outside Tailnet %q exposeSourceAllowlist; not exposing", outside, tn.Name))
			expose = nil
		}
	} else {
		meta.RemoveStatusCondition(&eg.Status.Conditions, "Exposed")
		eg.Status.Expose = nil
	}

	// Apply children (Secret is written by ensureAuthKey).
	image := eg.Spec.Image
	if image == "" {
		image = tn.Spec.Proxy.Image
	}
	if image == "" {
		image = r.OperatorImage
	}
	if err := r.applyChildren(ctx, &eg, &tn, ns, image, listen, expose); err != nil {
		return r.fail(ctx, &eg, "Apply", err)
	}
	if expose != nil {
		r.observeExpose(ctx, &eg, ns)
	}

	// Node association + duplicate cleanup.
	nodes, err := hs.ListNodes(ctx)
	if err != nil {
		return r.fail(ctx, &eg, "ListNodes", err)
	}
	r.associateNode(ctx, &eg, hs, nodes, tag, hostname)
	// An agent that never registers because its pod is refused (LimitRange/quota/PodSecurity) looks
	// the same as one still starting; name the admission reason so it is actionable.
	if meta.IsStatusConditionFalse(eg.Status.Conditions, "Registered") {
		if msg := workloadBlocked(ctx, r.Client, types.NamespacedName{Namespace: ns, Name: eg.Name}); msg != "" {
			setCond(&eg.Status.Conditions, eg.Generation, "Registered", metav1.ConditionFalse, "WorkloadBlocked", msg)
		}
	}

	// Diagnosis: classify each target route against the netmap + advertised/approved sets.
	advertised, approved := routeSets(nodes)
	netmap, probeErr := r.scrapeNetmap(ctx, ns, eg.Name)
	probes, probeReasons, err := r.scrapeTargets(ctx, ns, eg.Name)
	if probeErr == nil {
		probeErr = err
	}
	r.computeTargetStatus(&eg, listen, netmap, advertised, approved, probes, probeReasons, probeErr)

	eg.Status.ObservedGeneration = eg.Generation
	if err := updateObservedStatus(ctx, r.Client, r.Metrics, &eg); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}
	r.Metrics.ObserveNodes(&eg, nodes, tag, hostname)
	l.V(1).Info("reconciled", "hostname", hostname, "nodeId", eg.Status.NodeID)
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *TailnetEgressReconciler) fail(ctx context.Context, eg *tnv1.TailnetEgress, reason string, err error) (ctrl.Result, error) {
	setCond(&eg.Status.Conditions, eg.Generation, "Ready", metav1.ConditionFalse, reason, err.Error())
	_ = updateObservedStatus(ctx, r.Client, r.Metrics, eg)
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *TailnetEgressReconciler) readWorkingKey(ctx context.Context, tnName string) (string, error) {
	var s corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.OperatorNamespace, Name: workingSecretName(tnName)}, &s); err != nil {
		return "", err
	}
	v := string(s.Data[apiKeyData])
	if v == "" {
		return "", fmt.Errorf("working api key secret is empty")
	}
	return v, nil
}

// ensureAuthKey mints (or rotates at half-life, or re-mints when server or tag changed) the reusable
// ephemeral pre-auth key and writes it to the CR's authkey Secret. Reusable so a pod restart
// re-registers on its own; ephemeral so a deleted CR's node ages out by itself.
func (r *TailnetEgressReconciler) ensureAuthKey(ctx context.Context, eg *tnv1.TailnetEgress, tn *tnv1.Tailnet, hs *headscale.Client, tag string) (*time.Time, error) {
	lifetime := tn.Spec.AuthKeyLifetime.Duration
	if lifetime == 0 {
		lifetime = 168 * time.Hour
	}
	now := time.Now()

	binding := authKeyBinding(tn, tag)
	var cur corev1.Secret
	var superseded *corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: eg.Namespace, Name: authKeySecretName(eg.Name)}, &cur); err == nil {
		superseded = &cur
		if reuse, relabel := authKeyReuse(&cur, binding, lifetime, now); reuse {
			if relabel {
				// Legacy or transferred Secret, or a re-created Tailnet CR: record the binding without rotating.
				before := cur.DeepCopy()
				if cur.Annotations == nil {
					cur.Annotations = map[string]string{}
				}
				maps.Copy(cur.Annotations, binding)
				if err := r.Patch(ctx, &cur, client.MergeFrom(before)); err != nil {
					return nil, fmt.Errorf("bind authkey: %w", err)
				}
			}
			curExp, _ := time.Parse(time.RFC3339, cur.Annotations[annExpiresAt])
			return &curExp, nil
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, err
	}

	exp := now.Add(lifetime)
	pak, err := hs.CreatePreAuthKey(ctx, headscale.CreatePreAuthKeyRequest{
		Reusable:   true,
		Ephemeral:  true,
		Expiration: exp,
		ACLTags:    []string{tag},
	})
	if err != nil {
		return nil, fmt.Errorf("mint pre-auth key: %w", err)
	}
	sec := authKeySecret(eg, eg.Namespace, pak.Key, exp.UTC().Format(time.RFC3339), binding)
	sec.Annotations[annAuthKeyID] = pak.ID
	if err := controllerutil.SetControllerReference(eg, sec, r.Scheme); err != nil {
		return nil, err
	}
	if err := ssaApply(ctx, r.Client, sec); err != nil {
		return nil, err
	}
	// The new key is in place; the old one must not keep registering nodes.
	if superseded != nil {
		expireAuthKey(ctx, hs, superseded)
	}
	return &exp, nil
}

// currentListenPorts reads the listen ports already assigned in the live ConfigMap, so Assign keeps
// them stable across reconciles.
func (r *TailnetEgressReconciler) currentListenPorts(ctx context.Context, ns, name string) map[string]int32 {
	var cm corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: targetsConfigMapName(name)}, &cm); err != nil {
		return nil
	}
	var ts []agentTarget
	if err := json.Unmarshal([]byte(cm.Data[targetsFile]), &ts); err != nil {
		return nil
	}
	out := map[string]int32{}
	for _, t := range ts {
		out[t.Name] = t.ListenPort
	}
	return out
}

// exposeDenied returns the first allowFrom prefix not contained in the admin allowlist, "" if all
// are. An empty allowlist denies everything: exposing is opt-in per Tailnet.
func exposeDenied(expose *tnv1.EgressExpose, allowlist []tnv1.GatewayPrefix) string {
	allowed := make([]netip.Prefix, 0, len(allowlist))
	for _, a := range allowlist {
		if p, err := netip.ParsePrefix(string(a)); err == nil {
			allowed = append(allowed, p)
		}
	}
	for _, src := range expose.AllowFrom {
		p, err := netip.ParsePrefix(string(src))
		if err != nil {
			return string(src)
		}
		if !slices.ContainsFunc(allowed, func(a netip.Prefix) bool {
			return a.Addr().Is4() == p.Addr().Is4() && a.Bits() <= p.Bits() && a.Contains(p.Addr())
		}) {
			return string(src)
		}
	}
	return ""
}

// observeExpose reads the LB addresses the cluster assigned to the target Services. The operator
// cannot verify that the LB preserves client addresses (that is the implementation's contract, see
// the bridge how-to), so Exposed only reports assignment, never reachability.
func (r *TailnetEgressReconciler) observeExpose(ctx context.Context, eg *tnv1.TailnetEgress, ns string) {
	addrs := map[string]bool{}
	pending := 0
	for _, t := range eg.Spec.Targets {
		var svc corev1.Service
		if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: t.Name}, &svc); err != nil || !ownedBy(&svc, eg.UID) {
			pending++
			continue
		}
		n := 0
		for _, ing := range svc.Status.LoadBalancer.Ingress {
			for _, a := range []string{ing.IP, ing.Hostname} {
				if a != "" {
					addrs[a] = true
					n++
				}
			}
		}
		if n == 0 {
			pending++
		}
	}
	eg.Status.Expose = &tnv1.EgressExposeStatus{Addresses: slices.Sorted(maps.Keys(addrs))}
	if pending > 0 {
		setCond(&eg.Status.Conditions, eg.Generation, "Exposed", metav1.ConditionFalse, "PendingAddress",
			fmt.Sprintf("%d target Service(s) without a LoadBalancer address yet", pending))
		return
	}
	setCond(&eg.Status.Conditions, eg.Generation, "Exposed", metav1.ConditionTrue, "AddressAssigned",
		"LoadBalancer addresses assigned to every target Service")
}

func (r *TailnetEgressReconciler) applyChildren(ctx context.Context, eg *tnv1.TailnetEgress, tn *tnv1.Tailnet, ns, image string, listen map[string]int32, expose *tnv1.EgressExpose) error {
	cm, err := targetsConfigMap(eg, ns, listen)
	if err != nil {
		return err
	}
	dep := agentDeployment(eg, tn, ns, image, r.AgentImagePullSecrets, r.AgentResources)
	np := egressNetworkPolicy(eg, ns, r.OperatorNamespace, r.AgentScrapePeers, expose, listen)
	for _, obj := range []client.Object{cm, dep, np} {
		if err := controllerutil.SetControllerReference(eg, obj, r.Scheme); err != nil {
			return err
		}
		if err := ssaApply(ctx, r.Client, obj); err != nil {
			return err
		}
	}
	// Services: one per target, skipping any name already owned by something else.
	for _, t := range eg.Spec.Targets {
		svc := targetService(eg, ns, t, listen[t.Name], expose)
		var existing corev1.Service
		if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: t.Name}, &existing); err == nil {
			if !ownedBy(&existing, eg.UID) {
				setCond(&eg.Status.Conditions, eg.Generation, "ServiceConflict", metav1.ConditionTrue, "Conflict",
					fmt.Sprintf("Service %q exists and is not owned by this TailnetEgress", t.Name))
				continue
			}
		} else if !apierrors.IsNotFound(err) {
			return err
		}
		if err := controllerutil.SetControllerReference(eg, svc, r.Scheme); err != nil {
			return err
		}
		if err := ssaApply(ctx, r.Client, svc); err != nil {
			return err
		}
	}
	return r.pruneServices(ctx, eg, ns)
}

// pruneServices deletes this CR's Services whose target no longer exists. The GC cannot do it: the
// owner (the CR) lives on, only one entry of spec.targets went away — and the stale Service would
// keep pointing at whatever now sits on its old listen port.
func (r *TailnetEgressReconciler) pruneServices(ctx context.Context, eg *tnv1.TailnetEgress, ns string) error {
	want := make(map[string]bool, len(eg.Spec.Targets))
	for _, t := range eg.Spec.Targets {
		want[t.Name] = true
	}
	var svcs corev1.ServiceList
	if err := r.List(ctx, &svcs, client.InNamespace(ns), client.MatchingLabels(selectorLabels(eg.Name))); err != nil {
		return err
	}
	for i := range svcs.Items {
		svc := &svcs.Items[i]
		if want[svc.Name] || !ownedBy(svc, eg.UID) {
			continue
		}
		if err := r.Delete(ctx, svc, client.Preconditions{UID: &svc.UID}); client.IgnoreNotFound(err) != nil {
			return err
		}
	}
	return nil
}

func ownedBy(obj metav1.Object, uid types.UID) bool {
	for _, o := range obj.GetOwnerReferences() {
		if o.UID == uid {
			return true
		}
	}
	return false
}

// adoptable reports whether cm is a fully-derived operator ConfigMap (the role label has marked our
// hosts and rendered/fragment ConfigMaps since v0.1.0) that currently has no controller — e.g. a
// hosts ConfigMap left ownerRef-less during a Tailnet re-create. Such a ConfigMap carries no state
// worth keeping (every reconcile rewrites it in full), so the next reconcile may take it over.
// A ConfigMap already controlled by someone (a stale ref is cleaned up by Kubernetes GC, which then
// deletes it) or without the operator's role label is never adoptable.
func adoptable(cm *corev1.ConfigMap, role string) bool {
	return metav1.GetControllerOf(cm) == nil && cm.Labels[roleLabel] == role
}

// associateNode records this CR's online node and removes offline duplicates carrying the same tag
// and hostname pattern — but only when an online node exists, so a brief outage deletes nothing.
func (r *TailnetEgressReconciler) associateNode(ctx context.Context, eg *tnv1.TailnetEgress, hs *headscale.Client, nodes []headscale.Node, tag, hostname string) {
	var online *headscale.Node
	var candidates []headscale.Node
	for i := range nodes {
		n := nodes[i]
		if !hasTag(n.Tags, tag) {
			continue
		}
		if n.GivenName != hostname && !strings.HasPrefix(n.GivenName, hostname+"-") {
			continue
		}
		candidates = append(candidates, n)
		if n.Online {
			online = &candidates[len(candidates)-1]
		}
	}
	if online == nil {
		setCond(&eg.Status.Conditions, eg.Generation, "Registered", metav1.ConditionFalse, "NotRegistered",
			"no online node with this tag and hostname yet")
		return
	}
	eg.Status.NodeID = online.ID
	eg.Status.TailnetIPs = online.IPAddresses
	setCond(&eg.Status.Conditions, eg.Generation, "Registered", metav1.ConditionTrue, "Registered",
		fmt.Sprintf("node %s online", online.ID))
	for i := range candidates {
		if !candidates[i].Online && candidates[i].ID != online.ID {
			_ = hs.DeleteNode(ctx, candidates[i].ID)
		}
	}
	restoreGivenName(ctx, hs, online, hostname)
}

func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

// routeSets returns the union of advertised (availableRoutes) and approved (approvedRoutes) across
// all nodes — the two inputs the route classifier needs besides this node's netmap.
func routeSets(nodes []headscale.Node) (advertised, approved map[string]bool) {
	advertised, approved = map[string]bool{}, map[string]bool{}
	for _, n := range nodes {
		for _, r := range n.AvailableRoutes {
			advertised[r] = true
		}
		for _, r := range n.ApprovedRoutes {
			approved[r] = true
		}
	}
	return advertised, approved
}

// computeTargetStatus fills per-target route/reachability status. probeErr != nil means the agent
// could not be scraped at all (no running pod, NetworkPolicy, agent down): then nothing is known
// about the netmap or the dials, and every target reports ProbeFailed instead of a misleading
// NoGrant/Unreachable.
func (r *TailnetEgressReconciler) computeTargetStatus(eg *tnv1.TailnetEgress, listen map[string]int32, netmap, advertised, approved map[string]bool, probes map[string]bool, reasons map[string]string, probeErr error) {
	var ts []tnv1.TargetStatus
	missing := 0
	allReachable := true
	allPresent := true
	nameUnresolved := false
	for _, t := range eg.Spec.Targets {
		// A DNS-named target is a tailnet peer: no subnet route is involved, the far end's grant is
		// the only authorization and it shows as reachable/unreachable, not as a missing route.
		route, reason := "", routes.Present
		if ip, err := netip.ParseAddr(t.Address); err == nil {
			route = ip.String() + "/32"
			if ip.Is6() {
				route = ip.String() + "/128"
			}
			reason = routes.Classify(route, netmap, advertised, approved)
		}
		if probeErr != nil {
			reason = probeFailed
		}
		present := reason == routes.Present
		reachable := probes[t.Name]
		if !present {
			missing++
			allPresent = false
		}
		targetReason := string(reason)
		if present && !reachable {
			allReachable = false
			// A present (route-less or in-netmap) target that will not dial: surface the agent's
			// classification, so an unresolved tailnet-zone name is told apart from a grant/backend
			// failure instead of a blanket "Unreachable".
			if ar := reasons[t.Name]; ar != "" {
				targetReason = ar
				if ar == "NameUnresolved" {
					nameUnresolved = true
				}
			}
		} else if !reachable {
			allReachable = false
		}
		ts = append(ts, tnv1.TargetStatus{
			Name:       t.Name,
			ListenPort: listen[t.Name],
			Route:      route,
			Present:    present,
			Reachable:  reachable,
			Reason:     targetReason,
		})
	}
	eg.Status.Targets = ts

	rgStatus := metav1.ConditionTrue
	rgReason, rgMsg := "AllGranted", "all target routes present in the netmap"
	if !allPresent {
		rgStatus, rgReason, rgMsg = metav1.ConditionFalse, "RoutesMissing",
			fmt.Sprintf("%d target route(s) missing — see status.targets[].reason", missing)
	}
	trStatus := metav1.ConditionTrue
	trReason, trMsg := "AllReachable", "all targets reachable"
	if !allReachable {
		trStatus, trReason, trMsg = metav1.ConditionFalse, "Unreachable", "a target is not reachable; a DNS-named target may lack a grant on the far ingress — see status.targets[].reason"
		if nameUnresolved {
			trReason, trMsg = "NameUnresolved", "a target name did not resolve: use the ingress node's MagicDNS name (<hostname>.<base_domain>), or grant the egress tag :53 to the target cluster's resolver — see status.targets[].reason"
		}
	}
	if probeErr != nil {
		rgReason, rgMsg = string(probeFailed), "agent not scraped: "+truncate(probeErr.Error(), 256)
		trReason, trMsg = rgReason, rgMsg
	}
	setCond(&eg.Status.Conditions, eg.Generation, "RoutesGranted", rgStatus, rgReason, rgMsg)
	setCond(&eg.Status.Conditions, eg.Generation, "TargetsReachable", trStatus, trReason, trMsg)

	ready := allPresent && allReachable && eg.Status.NodeID != ""
	readyStatus := metav1.ConditionFalse
	readyReason, readyMsg := blockingReason(eg.Status.Conditions, "Registered", "RoutesGranted", "TargetsReachable", "Exposed")
	if c := meta.FindStatusCondition(eg.Status.Conditions, "Exposed"); c != nil && c.Status == metav1.ConditionFalse {
		ready = false
	}
	if ready {
		readyStatus, readyReason, readyMsg = metav1.ConditionTrue, "Ready", "all targets served"
	}
	setCond(&eg.Status.Conditions, eg.Generation, "Ready", readyStatus, readyReason, readyMsg)
}

// scrapeNetmap reads the agent's /status and returns the set of routes present in its netmap.
func (r *TailnetEgressReconciler) scrapeNetmap(ctx context.Context, ns, name string) (map[string]bool, error) {
	out := map[string]bool{}
	ip := r.agentPodIP(ctx, ns, name)
	if ip == "" {
		return out, errNoAgentPod
	}
	var st struct {
		Peer map[string]struct {
			PrimaryRoutes []string `json:"PrimaryRoutes"`
			AllowedIPs    []string `json:"AllowedIPs"`
		} `json:"Peer"`
	}
	if err := scrapeJSON(ctx, ip, "status", &st); err != nil {
		return out, err
	}
	for _, p := range st.Peer {
		for _, r := range p.PrimaryRoutes {
			out[r] = true
		}
		for _, r := range p.AllowedIPs {
			out[r] = true
		}
	}
	return out, nil
}

// scrapeTargets reads the agent's /targets and returns reachability and per-target failure reason
// (e.g. NameUnresolved) by target name.
func (r *TailnetEgressReconciler) scrapeTargets(ctx context.Context, ns, name string) (map[string]bool, map[string]string, error) {
	ip := r.agentPodIP(ctx, ns, name)
	if ip == "" {
		return nil, nil, errNoAgentPod
	}
	return scrapeProbes(ctx, ip)
}

// scrapeProbes reads an agent's /targets (egress targets or ingress exposes) → reachable and the
// agent's failure reason by name.
func scrapeProbes(ctx context.Context, ip string) (map[string]bool, map[string]string, error) {
	var results []struct {
		Name      string `json:"name"`
		Reachable bool   `json:"reachable"`
		Reason    string `json:"reason"`
	}
	if err := scrapeJSON(ctx, ip, "targets", &results); err != nil {
		return nil, nil, err
	}
	out := make(map[string]bool, len(results))
	reasons := make(map[string]string, len(results))
	for _, res := range results {
		out[res.Name] = res.Reachable
		if res.Reason != "" {
			reasons[res.Name] = res.Reason
		}
	}
	return out, reasons, nil
}

var errNoAgentPod = errors.New("no running agent pod")

// restoreGivenName undoes Headscale's "-1" suffix: a node registering while a stale duplicate still
// holds its hostname gets "<hostname>-1" as MagicDNS name. Once the duplicate is gone, rename back
// so the MagicDNS name equals status.hostname. Best effort — fails harmlessly while the name is
// still taken and is retried on the next reconcile.
func restoreGivenName(ctx context.Context, hs *headscale.Client, online *headscale.Node, hostname string) {
	if online.GivenName == hostname {
		return
	}
	if err := hs.RenameNode(ctx, online.ID, hostname); err != nil {
		log.FromContext(ctx).V(1).Info("rename node to its hostname failed; retrying next reconcile", "node", online.ID, "givenName", online.GivenName, "error", err.Error())
	}
}

// probeFailed marks targets/exposes whose agent could not be scraped — distinct from a real
// NoGrant/Unreachable, which needs a working scrape to be trusted.
const probeFailed routes.Reason = "ProbeFailed"

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (r *TailnetEgressReconciler) agentPodIP(ctx context.Context, ns, name string) string {
	return runningAgentIP(ctx, r.Client, ns, selectorLabels(name))
}

// SetupWithManager registers the TailnetEgress controller and its owned children.
func (r *TailnetEgressReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&tnv1.TailnetEgress{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Service{}).
		Complete(r)
}
