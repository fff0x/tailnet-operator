package controller

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
	operatormetrics "tsunaro.io/tailnet-operator/internal/metrics"
	"tsunaro.io/tailnet-operator/internal/naming"
	pol "tsunaro.io/tailnet-operator/internal/policy"
)

// TailnetIngressReconciler turns one CR into an ingress identity: a tag, a pre-auth key and an agent
// pod that listens on the tailnet and forwards to in-cluster backends. Like the egress reconciler it
// never writes the tailnet policy; a missing grant is a policy concern, not a mint-time check.
type TailnetIngressReconciler struct {
	Metrics *operatormetrics.Metrics
	client.Client
	Scheme *runtime.Scheme
	// Optional cert-manager uses an uncached dynamic client, never an informer.
	Certificates          dynamic.Interface
	SecretReader          client.Reader
	OperatorNamespace     string
	OperatorImage         string
	AgentImagePullSecrets []string
	AgentResources        corev1.ResourceRequirements
	// AgentScrapePeers may reach the agent health/metrics port besides the operator.
	AgentScrapePeers []networkingv1.NetworkPolicyPeer
	Recorder         record.EventRecorder
}

func (r *TailnetIngressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)
	var in tnv1.TailnetIngress
	if err := r.Get(ctx, req.NamespacedName, &in); err != nil {
		if apierrors.IsNotFound(err) {
			r.Metrics.Delete("TailnetIngress", req.Namespace, req.Name)
			forgetReady("TailnetIngress", req.NamespacedName)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !in.DeletionTimestamp.IsZero() {
		// The node is persistent, so Headscale will not age it out: remove it with the CR.
		return ctrl.Result{}, releaseAuthKey(ctx, r.Client, r.OperatorNamespace, &in, in.Spec.TailnetRef.Name, r.Metrics.Headscale(in.Spec.TailnetRef.Name),
			func(hs *headscale.Client) {
				deleteOwnNode(ctx, hs, in.Status.NodeID, in.Status.Tag, in.Status.Hostname, false)
			})
	}
	if err := ensureAuthKeyFinalizer(ctx, r.Client, &in); err != nil {
		return ctrl.Result{}, err
	}
	// Every return below determines Ready; emit one event per Ready-reason flip.
	statusReady := readyReason(in.Status.Conditions)
	defer func() {
		emitReadyChange(r.Recorder, &in, "TailnetIngress", statusReady, readyReason(in.Status.Conditions))
	}()
	legacy, err := r.retireLegacyIngressWorkload(ctx, &in)
	if err != nil {
		return r.fail(ctx, &in, "WorkloadMigrationBlocked", err)
	}
	if legacy {
		invalidateIngressTLSObservation(&in)
		setCond(&in.Status.Conditions, in.Generation, "Ready", metav1.ConditionFalse, "WorkloadMigrating",
			"replacing the legacy ingress Deployment with ingress-"+in.Name)
		_ = updateObservedStatus(ctx, r.Client, r.Metrics, &in)
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}
	transition, waiting, err := r.retireIngressHTTPPredecessor(ctx, &in)
	if err != nil {
		return r.fail(ctx, &in, "HTTPTransitionBlocked", err)
	}
	if waiting {
		invalidateIngressTLSObservation(&in)
		setCond(&in.Status.Conditions, in.Generation, "Ready", metav1.ConditionFalse, "HTTPTransitionPending",
			"waiting for the previous ingress agent to terminate before changing HTTP configuration")
		_ = updateObservedStatus(ctx, r.Client, r.Metrics, &in)
		// Deployment ownership watches handle scale/status updates. Pods are not
		// directly owned by the CR, so also poll until termination completes.
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}
	ns := in.Namespace

	var tn tnv1.Tailnet
	if err := r.Get(ctx, types.NamespacedName{Name: in.Spec.TailnetRef.Name}, &tn); err != nil {
		setCond(&in.Status.Conditions, in.Generation, "Ready", metav1.ConditionFalse, "NoTailnet",
			fmt.Sprintf("Tailnet %q not found", in.Spec.TailnetRef.Name))
		invalidateIngressTLSObservation(&in)
		_ = updateObservedStatus(ctx, r.Client, r.Metrics, &in)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	resolvedTransition, waiting, err := r.retireIngressHTTPConfiguration(ctx, &in, &tn)
	transition = transition || resolvedTransition
	if err != nil {
		return r.fail(ctx, &in, "HTTPTransitionBlocked", err)
	}
	if waiting {
		invalidateIngressTLSObservation(&in)
		setCond(&in.Status.Conditions, in.Generation, "Ready", metav1.ConditionFalse, "HTTPTransitionPending",
			"waiting for the previous ingress agent to terminate before changing resolved HTTP sources")
		_ = updateObservedStatus(ctx, r.Client, r.Metrics, &in)
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}
	apiURL := tn.Spec.APIURL
	if apiURL == "" {
		apiURL = tn.Spec.Server
	}
	apiKey, err := r.readWorkingKey(ctx, tn.Name)
	if err != nil {
		setCond(&in.Status.Conditions, in.Generation, "Ready", metav1.ConditionFalse, "NoAPIKey",
			"waiting for the Tailnet working API key")
		invalidateIngressTLSObservation(&in)
		_ = updateObservedStatus(ctx, r.Client, r.Metrics, &in)
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}
	hs := headscale.New(apiURL, apiKey, r.Metrics.Headscale(tn.Name))

	// Render + validate tag and hostname from the ingress templates.
	tag := in.Spec.Tag
	if tag == "" {
		tag = naming.Render(tn.Spec.IngressTagTemplate, in.Name)
	}
	hostname := in.Spec.Hostname
	if hostname == "" {
		hostname = naming.Render(tn.Spec.IngressHostnameTemplate, in.Name)
	}
	if err := naming.ValidateTag(tag); err != nil {
		return r.fail(ctx, &in, "InvalidTag", err)
	}
	if err := naming.ValidateHostname(hostname); err != nil {
		return r.fail(ctx, &in, "InvalidHostname", err)
	}
	in.Status.Hostname = hostname
	in.Status.Tag = tag
	// DNS name: rendered here (this reconciler has the Tailnet), consumed by the DNS reconciler.
	names, nameReason := resolveIngressDNSNames(&in, &tn)
	in.Status.DNSName = names.baseName
	if nameReason != "" {
		return r.fail(ctx, &in, nameReason, fmt.Errorf("ingress DNS configuration is invalid"))
	}
	// DNSNameConflict: oldest owner wins a name across all CRs of this Tailnet. A loser reserves
	// its other names but publishes none of its own, so it must not advertise a stale DNS name.
	decisions, err := collectDNSClaimDecisions(ctx, r.Client, &tn, r.OperatorNamespace)
	if err != nil {
		return r.fail(ctx, &in, "DNSConflictUnresolved", err)
	}
	ownerKey := dnsClaimOwnerKey{Kind: dnsIngressKind, Namespace: in.Namespace, Name: in.Name, UID: in.UID}
	if d, ok := decisions[ownerKey]; ok && d.Blocked && d.Conflict != nil {
		in.Status.DNSName = ""
		in.Status.Hosts = nil
		in.Status.Exposes = nil
		return r.fail(ctx, &in, "DNSNameConflict", dnsConflictError(d.Conflict))
	}

	// TagKnown: refuse to mint for a tag the policy never declared (a typo mints a useless node).
	policy, err := hs.GetPolicy(ctx)
	if err != nil {
		return r.fail(ctx, &in, "PolicyUnreadable", err)
	}
	// PolicyDenied: with operator-owned policy, every allowFrom entry must pass the admin allowlist;
	// otherwise no grant is generated and the node would be unreachable by design — say so.
	if policyOwned(&tn) && len(in.Spec.AllowFrom) > 0 {
		var denied []string
		for _, s := range in.Spec.AllowFrom {
			if !pol.Allowed(s, tn.Spec.Policy.IngressSourceAllowlist) {
				denied = append(denied, s)
			}
		}
		if len(denied) > 0 {
			setCond(&in.Status.Conditions, in.Generation, "PolicyGranted", metav1.ConditionFalse, "PolicyDenied",
				fmt.Sprintf("allowFrom %v not permitted by Tailnet policy.ingressSourceAllowlist %v; no grant generated",
					denied, tn.Spec.Policy.IngressSourceAllowlist))
		} else if unknown := undeclaredTagSources(in.Spec.AllowFrom, policy); len(unknown) > 0 {
			// A tag: source the live policy does not declare is dropped from the grant (the renderer
			// no longer lets it freeze the whole policy). The remaining sources stay granted; this
			// ingress becomes reachable from the named tag once its owner (an egress CR, usually)
			// exists. Say so rather than claiming a full grant.
			setCond(&in.Status.Conditions, in.Generation, "PolicyGranted", metav1.ConditionFalse, "SourceTagUnknown",
				fmt.Sprintf("allowFrom source tags %v are not declared in the tailnet policy; the other sources stay granted — this ingress is reachable from these tags once they exist", unknown))
		} else {
			setCond(&in.Status.Conditions, in.Generation, "PolicyGranted", metav1.ConditionTrue, "Granted",
				fmt.Sprintf("grant src %v → %s generated by the Tailnet policy controller", in.Spec.AllowFrom, tag))
		}
	}
	if !strings.Contains(policy, `"`+tag+`"`) {
		reason, msg := "Unknown", fmt.Sprintf("tag %q is not declared in the tailnet policy; not minting a key", tag)
		if policyOwned(&tn) {
			reason, msg = "PolicyPending", fmt.Sprintf("tag %q not yet in the live policy; the Tailnet policy controller declares it on its next apply", tag)
		}
		setCond(&in.Status.Conditions, in.Generation, "TagKnown", metav1.ConditionFalse, reason, msg)
		setCond(&in.Status.Conditions, in.Generation, "Ready", metav1.ConditionFalse, "TagUnknown",
			"tag not in policy")
		invalidateIngressTLSObservation(&in)
		in.Status.ObservedGeneration = in.Generation
		_ = updateObservedStatus(ctx, r.Client, r.Metrics, &in)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	setCond(&in.Status.Conditions, in.Generation, "TagKnown", metav1.ConditionTrue, "Known", "tag declared in policy")

	authExp, err := r.ensureAuthKey(ctx, &in, &tn, hs, tag)
	if err != nil {
		return r.fail(ctx, &in, "AuthKey", err)
	}
	if authExp != nil {
		et := metav1.NewTime(*authExp)
		in.Status.AuthKeyExpiresAt = &et
	}
	r.retireIngressNode(ctx, &in, &tn, hs, tag, hostname)

	tlsState := r.prepareIngressTLS(ctx, &in, &tn, time.Now())
	if transition {
		if reason := ingressTransitionSourceReason(&in, tlsState); reason != "" {
			// Retired workloads have no current probe. Preserve the bounded source
			// diagnostic, including the first uncovered configured certificate name.
			tlsState.reason = reason
			r.computeIngressStatus(&in, tlsState, nil, errIngressProbe, time.Now())
			_ = updateObservedStatus(ctx, r.Client, r.Metrics, &in)
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
	}

	image := in.Spec.Image
	if image == "" {
		image = tn.Spec.Proxy.Image
	}
	if image == "" {
		image = r.OperatorImage
	}
	if err := r.applyChildren(ctx, &in, &tn, ns, image, tlsState, transition); err != nil {
		return r.fail(ctx, &in, "Apply", err)
	}

	nodes, err := hs.ListNodes(ctx)
	if err != nil {
		return r.fail(ctx, &in, "ListNodes", err)
	}
	r.associateNode(ctx, &in, hs, nodes, tag, hostname)
	// A pod refused by admission (LimitRange/quota/PodSecurity) never registers; name that reason
	// instead of leaving the generic "no online node yet".
	if meta.IsStatusConditionFalse(in.Status.Conditions, "Registered") {
		if msg := workloadBlocked(ctx, r.Client, ingressWorkloadKey(&in)); msg != "" {
			setCond(&in.Status.Conditions, in.Generation, "Registered", metav1.ConditionFalse, "WorkloadBlocked", msg)
		}
	}

	probes, probeErr := r.scrapeIngressProbes(ctx, ns, in.Name)
	r.computeIngressStatus(&in, tlsState, probes, probeErr, time.Now())

	in.Status.ObservedGeneration = in.Generation
	if err := updateObservedStatus(ctx, r.Client, r.Metrics, &in); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}
	r.Metrics.ObserveNodes(&in, nodes, tag, hostname)
	l.V(1).Info("reconciled", "hostname", hostname, "nodeId", in.Status.NodeID)
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// undeclaredTagSources returns the sorted tag: entries of allowFrom that the live policy document
// does not declare (no "tag:…" token). Only tag sources can be undeclared this way; groups and
// autogroups are resolved by the base policy, not minted from CRs.
func undeclaredTagSources(allowFrom []string, policy string) []string {
	var unknown []string
	for _, s := range allowFrom {
		if strings.HasPrefix(s, "tag:") && !strings.Contains(policy, `"`+s+`"`) {
			unknown = append(unknown, s)
		}
	}
	sort.Strings(unknown)
	return unknown
}

func (r *TailnetIngressReconciler) fail(ctx context.Context, in *tnv1.TailnetIngress, reason string, err error) (ctrl.Result, error) {
	invalidateIngressTLSObservation(in)
	setCond(&in.Status.Conditions, in.Generation, "Ready", metav1.ConditionFalse, reason, err.Error())
	_ = updateObservedStatus(ctx, r.Client, r.Metrics, in)
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *TailnetIngressReconciler) readWorkingKey(ctx context.Context, tnName string) (string, error) {
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
// pre-auth key and writes it to the CR's authkey Secret in the CR's own namespace.
func (r *TailnetIngressReconciler) ensureAuthKey(ctx context.Context, in *tnv1.TailnetIngress, tn *tnv1.Tailnet, hs *headscale.Client, tag string) (*time.Time, error) {
	lifetime := tn.Spec.AuthKeyLifetime.Duration
	if lifetime == 0 {
		lifetime = 168 * time.Hour
	}
	now := time.Now()

	binding := authKeyBinding(tn, tag)
	var cur corev1.Secret
	var superseded *corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: in.Namespace, Name: authKeySecretName(in.Name)}, &cur); err == nil {
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
	// Not ephemeral: the node keeps its identity in the state Secret across restarts, so Headscale
	// must not age it out while the pod is down. Reusable, so a lost state Secret re-registers.
	pak, err := hs.CreatePreAuthKey(ctx, headscale.CreatePreAuthKeyRequest{
		Reusable:   true,
		Ephemeral:  false,
		Expiration: exp,
		ACLTags:    []string{tag},
	})
	if err != nil {
		return nil, fmt.Errorf("mint pre-auth key: %w", err)
	}
	sec := ingressAuthKeySecret(in, in.Namespace, pak.Key, exp.UTC().Format(time.RFC3339), binding)
	sec.Annotations[annAuthKeyID] = pak.ID
	if err := controllerutil.SetControllerReference(in, sec, r.Scheme); err != nil {
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

func (r *TailnetIngressReconciler) applyChildren(ctx context.Context, in *tnv1.TailnetIngress, tn *tnv1.Tailnet, ns, image string, tlsState ingressTLSState, retiring ...bool) error {
	// Dependencies may have taken time; repeat the barrier before publishing config.
	// This also covers exits and same-owner replacement Deployments.
	transition, waiting, err := r.retireIngressHTTPConfiguration(ctx, in, tn)
	for _, previous := range retiring {
		transition = transition || previous
	}
	if err != nil {
		return err
	}
	if waiting {
		return errIngressTransitionPending
	}
	fenced := ingressConfigVersion(in) >= 2 || transition
	var observed *appsv1.Deployment
	if fenced {
		observed, err = r.ingressHTTPDeploymentSnapshot(ctx, in, transition)
		if err != nil {
			return err
		}
	}
	servingPlan := tlsState.plan
	if tlsState.reason != "" {
		servingPlan = ingressTLSPlan{} // no HTTP listener before its source is valid
	}
	cm, err := ingressExposesConfigMap(in, ns, servingPlan)
	if err != nil {
		return err
	}
	dep := ingressAgentDeploymentTLS(in, tn, ns, image, r.AgentImagePullSecrets, r.AgentResources, tlsState.plan)
	np := ingressNetworkPolicy(in, ns, r.OperatorNamespace, r.AgentScrapePeers)
	// Identity first: the ServiceAccount and state Secret must exist before the pod is created.
	stateSecret := ingressStateSecretName(in, tn)
	for _, obj := range ingressIdentityObjects(in, ns, stateSecret) {
		if err := controllerutil.SetControllerReference(in, obj, r.Scheme); err != nil {
			return err
		}
		if err := ssaApply(ctx, r.Client, obj); err != nil {
			return err
		}
	}
	if err := r.dropRetiredStateSecrets(ctx, in, ns, stateSecret); err != nil {
		return err
	}
	for _, obj := range []client.Object{cm, dep, np} {
		if err := controllerutil.SetControllerReference(in, obj, r.Scheme); err != nil {
			return err
		}
		if fenced {
			var err error
			if obj == dep {
				err = r.applyExtendedIngressDeployment(ctx, in, dep, observed)
			} else {
				err = r.applyIngressHTTPChild(ctx, in, obj)
			}
			if err != nil {
				return err
			}
		} else if err := ssaApply(ctx, r.Client, obj); err != nil {
			return err
		}
	}
	return nil
}

// dropRetiredStateSecrets deletes this CR's state Secrets other than the current one: a tag or
// server change gave the identity a new Secret name, and the old node key must not linger.
func (r *TailnetIngressReconciler) dropRetiredStateSecrets(ctx context.Context, in *tnv1.TailnetIngress, ns, current string) error {
	var list corev1.SecretList
	sel := ingressSelectorLabels(in.Name)
	sel[labelIngressState] = "true"
	if err := r.List(ctx, &list, client.InNamespace(ns), client.MatchingLabels(sel)); err != nil {
		return err
	}
	for i := range list.Items {
		if s := &list.Items[i]; s.Name != current && metav1.IsControlledBy(s, in) {
			if err := r.Delete(ctx, s); client.IgnoreNotFound(err) != nil {
				return err
			}
		}
	}
	return nil
}

// retireIngressNode handles an identity change: the current state Secret does not exist yet, so
// the next pod registers fresh, and the recorded node — persistent, not aged out by Headscale —
// must go unless it still matches tag and hostname (then it is this identity's own node, deleted
// as an offline duplicate by associateNode once the fresh one is online; this keeps the data path
// up until the replacement registers, also on the upgrade that introduces the state Secret).
func (r *TailnetIngressReconciler) retireIngressNode(ctx context.Context, in *tnv1.TailnetIngress, tn *tnv1.Tailnet, hs *headscale.Client, tag, hostname string) {
	if in.Status.NodeID == "" {
		return
	}
	var s corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: in.Namespace, Name: ingressStateSecretName(in, tn)}, &s); !apierrors.IsNotFound(err) {
		return
	}
	deleteOwnNode(ctx, hs, in.Status.NodeID, tag, hostname, true)
}

// deleteOwnNode removes node id when Headscale lists it as this CR's: carrying tag or named
// hostname (or hostname-N). With keepCurrent a node matching both stays. The guard keeps a stale ID
// on a different control server from hitting a foreign node. Best effort: an API error leaves the
// node for the next reconcile or the operator's hands.
func deleteOwnNode(ctx context.Context, hs *headscale.Client, id, tag, hostname string, keepCurrent bool) {
	if id == "" {
		return
	}
	nodes, err := hs.ListNodes(ctx)
	if err != nil {
		return
	}
	for _, n := range nodes {
		if n.ID != id {
			continue
		}
		tagged := hasTag(n.Tags, tag)
		named := hostname != "" && (n.GivenName == hostname || strings.HasPrefix(n.GivenName, hostname+"-"))
		if !tagged && !named || keepCurrent && tagged && named {
			return
		}
		if err := hs.DeleteNode(ctx, id); err != nil {
			log.FromContext(ctx).Info("retired ingress node not deleted", "node", id, "err", err.Error())
		}
		return
	}
}

// associateNode records this CR's online node and removes offline duplicates carrying the same tag
// and hostname pattern — but only when an online node exists, so a brief outage deletes nothing.
func (r *TailnetIngressReconciler) associateNode(ctx context.Context, in *tnv1.TailnetIngress, hs *headscale.Client, nodes []headscale.Node, tag, hostname string) {
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
		in.Status.NodeID, in.Status.TailnetIPs = "", nil
		setCond(&in.Status.Conditions, in.Generation, "Registered", metav1.ConditionFalse, "NotRegistered",
			"no online node with this tag and hostname yet")
		return
	}
	in.Status.NodeID = online.ID
	in.Status.TailnetIPs = online.IPAddresses
	setCond(&in.Status.Conditions, in.Generation, "Registered", metav1.ConditionTrue, "Registered",
		fmt.Sprintf("node %s online", online.ID))
	for i := range candidates {
		if !candidates[i].Online && candidates[i].ID != online.ID {
			_ = hs.DeleteNode(ctx, candidates[i].ID)
		}
	}
	restoreGivenName(ctx, hs, online, hostname)
}

// computeExposeStatus fills per-expose backend reachability and the roll-up conditions. Ready needs
// a registered node AND every backend reachable — an ingress that no peer can dial to a dead backend
// is not ready even though the node is up.
func (r *TailnetIngressReconciler) computeExposeStatus(in *tnv1.TailnetIngress, probes map[string]bool, probeErr error) {
	var es []tnv1.ExposeStatus
	unreachable := 0
	for _, e := range in.Spec.Exposes {
		reachable := probes[e.Name]
		reason := ""
		if !reachable {
			reason = "Unreachable"
			unreachable++
		}
		if probeErr != nil {
			reason = string(probeFailed)
		}
		es = append(es, tnv1.ExposeStatus{
			Name:       e.Name,
			ListenPort: e.Port,
			Backend:    fmt.Sprintf("%s:%d", e.Backend.Service, e.Backend.Port),
			Reachable:  reachable,
			Reason:     reason,
		})
	}
	in.Status.Exposes = es

	brStatus := metav1.ConditionTrue
	brReason, brMsg := "AllReachable", "all backends reachable"
	if unreachable > 0 {
		brStatus, brReason, brMsg = metav1.ConditionFalse, "Unreachable",
			fmt.Sprintf("%d backend(s) not reachable — see status.exposes[].reason", unreachable)
	}
	if probeErr != nil {
		brReason, brMsg = string(probeFailed), "agent not scraped: "+truncate(probeErr.Error(), 256)
	}
	setCond(&in.Status.Conditions, in.Generation, "BackendsReachable", brStatus, brReason, brMsg)

	// PolicyGranted gates Ready too: an ingress whose grant the policy refused (PolicyDenied) or
	// whose source tag is undeclared (SourceTagUnknown) is unreachable by design, even with a live
	// node and a reachable backend — Ready must reflect that, not just backend health.
	ready := unreachable == 0 && in.Status.NodeID != "" &&
		!meta.IsStatusConditionFalse(in.Status.Conditions, "PolicyGranted")
	readyStatus := metav1.ConditionFalse
	readyReason, readyMsg := blockingReason(in.Status.Conditions, "Registered", "PolicyGranted", "BackendsReachable")
	if ready {
		readyStatus, readyReason, readyMsg = metav1.ConditionTrue, "Ready", "all backends served"
	}
	setCond(&in.Status.Conditions, in.Generation, "Ready", readyStatus, readyReason, readyMsg)
}

// scrapeExposeProbes reads the agent's /targets and returns reachability by expose name. L4 ingress
// backends have no DNS-named target, so the per-target reason (egress-only) is not used here.
func (r *TailnetIngressReconciler) scrapeExposeProbes(ctx context.Context, ns, name string) (map[string]bool, error) {
	ip := r.agentPodIP(ctx, ns, name)
	if ip == "" {
		return nil, errNoAgentPod
	}
	reachable, _, err := scrapeProbes(ctx, ip)
	return reachable, err
}

func (r *TailnetIngressReconciler) agentPodIP(ctx context.Context, ns, name string) string {
	return runningAgentIP(ctx, r.Client, ns, ingressSelectorLabels(name))
}

// SetupWithManager registers the TailnetIngress controller and its owned children.
func (r *TailnetIngressReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&tnv1.TailnetIngress{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// The agent writes its node key into the state Secret; those updates are not reconcile input.
		Owns(&corev1.Secret{}, builder.WithPredicates(predicate.NewPredicateFuncs(func(o client.Object) bool {
			return o.GetLabels()[labelIngressState] != "true"
		}))).
		Owns(&corev1.ConfigMap{}).
		Owns(&appsv1.Deployment{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			var requests []ctrl.Request
			for _, key := range r.ingressesForTLSSecret(ctx, obj) {
				requests = append(requests, ctrl.Request{NamespacedName: key})
			}
			return requests
		})).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			var requests []ctrl.Request
			for _, key := range r.ingressesForBackendCA(ctx, obj) {
				requests = append(requests, ctrl.Request{NamespacedName: key})
			}
			return requests
		})).
		Watches(&tnv1.Tailnet{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			var list tnv1.TailnetIngressList
			if err := r.List(ctx, &list); err != nil {
				return nil
			}
			var requests []ctrl.Request
			for _, in := range list.Items {
				if in.Spec.TailnetRef.Name == obj.GetName() {
					requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&in)})
				}
			}
			return requests
		}), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}
