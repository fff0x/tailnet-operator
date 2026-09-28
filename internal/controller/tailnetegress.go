package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	tnv1 "fr0st.dev/tailnet-operator/api/v1alpha1"
	"fr0st.dev/tailnet-operator/internal/headscale"
	"fr0st.dev/tailnet-operator/internal/keys"
	"fr0st.dev/tailnet-operator/internal/naming"
	"fr0st.dev/tailnet-operator/internal/ports"
	"fr0st.dev/tailnet-operator/internal/routes"
)

// TailnetEgressReconciler turns one CR into an egress identity: a tag, a pre-auth key, an agent pod
// and one Service per target. It never writes the tailnet policy; a missing grant becomes status.
type TailnetEgressReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	OperatorNamespace string
	OperatorImage     string
}

func (r *TailnetEgressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)
	var eg tnv1.TailnetEgress
	if err := r.Get(ctx, req.NamespacedName, &eg); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	ns := eg.Namespace

	// Resolve the Tailnet and its working API key (minted by the Tailnet controller).
	var tn tnv1.Tailnet
	if err := r.Get(ctx, types.NamespacedName{Name: eg.Spec.TailnetRef.Name}, &tn); err != nil {
		setCond(&eg.Status.Conditions, eg.Generation, "Ready", metav1.ConditionFalse, "NoTailnet",
			fmt.Sprintf("Tailnet %q not found", eg.Spec.TailnetRef.Name))
		_ = r.Status().Update(ctx, &eg)
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
		_ = r.Status().Update(ctx, &eg)
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}
	hs := headscale.New(apiURL, apiKey)

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
		_ = r.Status().Update(ctx, &eg)
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
		authKeyExpiresSeconds.WithLabelValues(ns, eg.Name).Set(time.Until(*authExp).Seconds())
	}

	// Stable listen ports: keep whatever the current ConfigMap already assigned.
	existing := r.currentListenPorts(ctx, ns, eg.Name)
	names := make([]string, len(eg.Spec.Targets))
	for i, t := range eg.Spec.Targets {
		names[i] = t.Name
	}
	listen := ports.Assign(existing, names)

	// Apply children (Secret is written by ensureAuthKey).
	image := eg.Spec.Image
	if image == "" {
		image = tn.Spec.Proxy.Image
	}
	if image == "" {
		image = r.OperatorImage
	}
	if err := r.applyChildren(ctx, &eg, &tn, ns, image, listen); err != nil {
		return r.fail(ctx, &eg, "Apply", err)
	}

	// Node association + duplicate cleanup.
	nodes, err := hs.ListNodes(ctx)
	if err != nil {
		return r.fail(ctx, &eg, "ListNodes", err)
	}
	r.associateNode(ctx, &eg, hs, nodes, tag, hostname)

	// Diagnosis: classify each target route against the netmap + advertised/approved sets.
	advertised, approved := routeSets(nodes)
	netmap := r.scrapeNetmap(ctx, ns, eg.Name)
	probes := r.scrapeTargets(ctx, ns, eg.Name)
	r.computeTargetStatus(&eg, listen, netmap, advertised, approved, probes)

	eg.Status.ObservedGeneration = eg.Generation
	if err := r.Status().Update(ctx, &eg); err != nil {
		return ctrl.Result{}, err
	}
	l.V(1).Info("reconciled", "hostname", hostname, "nodeId", eg.Status.NodeID)
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *TailnetEgressReconciler) fail(ctx context.Context, eg *tnv1.TailnetEgress, reason string, err error) (ctrl.Result, error) {
	setCond(&eg.Status.Conditions, eg.Generation, "Ready", metav1.ConditionFalse, reason, err.Error())
	_ = r.Status().Update(ctx, eg)
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

// ensureAuthKey mints (or rotates at half-life) the reusable ephemeral pre-auth key and writes it to
// the CR's authkey Secret. Reusable so a pod restart re-registers on its own; ephemeral so a deleted
// CR's node ages out by itself.
func (r *TailnetEgressReconciler) ensureAuthKey(ctx context.Context, eg *tnv1.TailnetEgress, tn *tnv1.Tailnet, hs *headscale.Client, tag string) (*time.Time, error) {
	lifetime := tn.Spec.AuthKeyLifetime.Duration
	if lifetime == 0 {
		lifetime = 168 * time.Hour
	}
	now := time.Now()

	var cur corev1.Secret
	var curExp time.Time
	if err := r.Get(ctx, types.NamespacedName{Namespace: eg.Namespace, Name: authKeySecretName(eg.Name)}, &cur); err == nil {
		if s := cur.Annotations[annExpiresAt]; s != "" {
			curExp, _ = time.Parse(time.RFC3339, s)
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, err
	}

	if keys.Evaluate(curExp, lifetime, now) == keys.OK {
		return &curExp, nil
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
	sec := authKeySecret(eg, eg.Namespace, pak.Key, exp.UTC().Format(time.RFC3339))
	if err := controllerutil.SetControllerReference(eg, sec, r.Scheme); err != nil {
		return nil, err
	}
	if err := ssaApply(ctx, r.Client, sec); err != nil {
		return nil, err
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

func (r *TailnetEgressReconciler) applyChildren(ctx context.Context, eg *tnv1.TailnetEgress, tn *tnv1.Tailnet, ns, image string, listen map[string]int32) error {
	cm, err := targetsConfigMap(eg, ns, listen)
	if err != nil {
		return err
	}
	dep := agentDeployment(eg, tn, ns, image)
	np := egressNetworkPolicy(eg, ns, r.OperatorNamespace)
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
		svc := targetService(eg, ns, t, listen[t.Name])
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

func (r *TailnetEgressReconciler) computeTargetStatus(eg *tnv1.TailnetEgress, listen map[string]int32, netmap, advertised, approved map[string]bool, probes map[string]bool) {
	var ts []tnv1.TargetStatus
	missing := 0
	allReachable := true
	allPresent := true
	for _, t := range eg.Spec.Targets {
		route := t.Address + "/32"
		if strings.Contains(t.Address, ":") {
			route = t.Address + "/128"
		}
		reason := routes.Classify(route, netmap, advertised, approved)
		present := reason == routes.Present
		reachable := probes[t.Name]
		if !present {
			missing++
			allPresent = false
		}
		if !reachable {
			allReachable = false
		}
		ts = append(ts, tnv1.TargetStatus{
			Name:       t.Name,
			ListenPort: listen[t.Name],
			Route:      route,
			Present:    present,
			Reachable:  reachable,
			Reason:     string(reason),
		})
	}
	eg.Status.Targets = ts
	routesMissing.WithLabelValues(eg.Namespace, eg.Name).Set(float64(missing))

	rgStatus := metav1.ConditionTrue
	rgReason, rgMsg := "AllGranted", "all target routes present in the netmap"
	if !allPresent {
		rgStatus, rgReason, rgMsg = metav1.ConditionFalse, "RoutesMissing",
			fmt.Sprintf("%d target route(s) missing — see status.targets[].reason", missing)
	}
	setCond(&eg.Status.Conditions, eg.Generation, "RoutesGranted", rgStatus, rgReason, rgMsg)

	trStatus := metav1.ConditionTrue
	trReason, trMsg := "AllReachable", "all targets reachable"
	if !allReachable {
		trStatus, trReason, trMsg = metav1.ConditionFalse, "Unreachable", "a target is not reachable"
	}
	setCond(&eg.Status.Conditions, eg.Generation, "TargetsReachable", trStatus, trReason, trMsg)

	ready := allPresent && allReachable && eg.Status.NodeID != ""
	readyStatus := metav1.ConditionFalse
	readyReason, readyMsg := "NotReady", "not all targets are served yet"
	if ready {
		readyStatus, readyReason, readyMsg = metav1.ConditionTrue, "Ready", "all targets served"
	}
	setCond(&eg.Status.Conditions, eg.Generation, "Ready", readyStatus, readyReason, readyMsg)
}

// scrapeNetmap reads the agent's /status and returns the set of routes present in its netmap.
func (r *TailnetEgressReconciler) scrapeNetmap(ctx context.Context, ns, name string) map[string]bool {
	out := map[string]bool{}
	ip := r.agentPodIP(ctx, ns, name)
	if ip == "" {
		return out
	}
	var st struct {
		Peer map[string]struct {
			PrimaryRoutes []string `json:"PrimaryRoutes"`
			AllowedIPs    []string `json:"AllowedIPs"`
		} `json:"Peer"`
	}
	if err := scrapeJSON(ctx, ip, "status", &st); err != nil {
		return out
	}
	for _, p := range st.Peer {
		for _, r := range p.PrimaryRoutes {
			out[r] = true
		}
		for _, r := range p.AllowedIPs {
			out[r] = true
		}
	}
	return out
}

// scrapeTargets reads the agent's /targets and returns reachability by target name.
func (r *TailnetEgressReconciler) scrapeTargets(ctx context.Context, ns, name string) map[string]bool {
	out := map[string]bool{}
	ip := r.agentPodIP(ctx, ns, name)
	if ip == "" {
		return out
	}
	var results []struct {
		Name      string `json:"name"`
		Reachable bool   `json:"reachable"`
	}
	if err := scrapeJSON(ctx, ip, "targets", &results); err != nil {
		return out
	}
	for _, res := range results {
		out[res.Name] = res.Reachable
	}
	return out
}

func (r *TailnetEgressReconciler) agentPodIP(ctx context.Context, ns, name string) string {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(ns), client.MatchingLabels(selectorLabels(name))); err != nil {
		return ""
	}
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning && p.Status.PodIP != "" {
			return p.Status.PodIP
		}
	}
	return ""
}

func scrapeJSON(ctx context.Context, ip, path string, out any) error {
	url := fmt.Sprintf("http://%s:%d/%s", ip, agentHealthPort, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("scrape %s: %s", url, resp.Status)
	}
	return json.Unmarshal(b, out)
}

// SetupWithManager registers the TailnetEgress controller and its owned children.
func (r *TailnetEgressReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&tnv1.TailnetEgress{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Service{}).
		Complete(r)
}
