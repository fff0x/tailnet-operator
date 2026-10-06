package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

var ErrFreshWrite = errors.New("gateway fresh write: prerequisites or retained provenance are unverified")

// ErrFreshIdentity means the completion receipt is intact but the Gateway or
// Tailnet no longer matches the identity fields pinned at creation (or the
// receipt predates the identity scope). Nothing is written; revert the field
// or delete and recreate the Gateway.
var ErrFreshIdentity = errors.New("gateway fresh: pinned identity fields differ from the completion receipt")

// GatewayHeadscale is satisfied by the existing authenticated Headscale client.
// No route, policy, node deletion or key-expiry mutations are part of this writer;
// deletion and expiry belong to TeardownFresh (GatewayTeardownHeadscale) only.
type GatewayHeadscale interface {
	ListNodes(context.Context) ([]headscale.Node, error)
	CreatePreAuthKey(context.Context, headscale.CreatePreAuthKeyRequest) (*headscale.PreAuthKey, error)
}

// FreshObservation reports bootstrap health, not end-to-end route/DNS reachability.
// Completed is true for every verified completion receipt even before the Pod is
// Ready; it is the signal that the live DNS reconciler may run.
//
// PodPresent is true for a Pod with verified provenance (owned by the receipt
// StatefulSet); PodCurrent additionally means the Pod carries the StatefulSet's
// current UpdateRevision, so its template matches what UpdateWorkloadRevision
// last wrote (images, env, ports, routes). A stale-but-verified Pod stays Ready:
// the operator never restarts an identity-bearing Pod itself (OnDelete).
type FreshObservation struct {
	Ready, Completed       bool
	PodPresent, PodCurrent bool
	Binding                GatewayStateBinding
	Routes, Approved       []string
	// PodRoutes are the routes the running Pod was started with (its TS_ROUTES), in plan order.
	PodRoutes         []string
	workload, service freshObjectReceipt
	stateUID          types.UID
}

// GatewayTemplateHashAnnotation records the sha256 of the StatefulSet's wanted
// Pod template (as rendered from the Gateway spec + planned routes). It is a
// change detector only; integrity is still rooted in the completion receipt UID
// and the (template-blanked) object digest. The annotation lives on the STS
// metadata, which the receipt digest already excludes.
const GatewayTemplateHashAnnotation = "tsunaro.io/template-sha256"

type freshObjectReceipt struct {
	Kind   string    `json:"kind"`
	Name   string    `json:"name"`
	UID    types.UID `json:"uid"`
	Digest string    `json:"digest"`
}

type freshReceipt struct {
	Scope    map[string]string    `json:"scope"`
	StateUID types.UID            `json:"stateUID"`
	Auth     GatewayAuthReceipt   `json:"auth"`
	Objects  []freshObjectReceipt `json:"objects"`
	Routes   []string             `json:"routes"`
}

// ReconcileFresh exclusively creates a fresh resource set, or observes a complete
// set using its immutable completion receipt. c MUST use uncached API reads.
// An empty State Secret is created before minting: it is also the exclusive claim
// that prevents concurrent/retried attempts from minting again after ambiguity.
// Partial writes are retained and blocked; there is no adoption or rollback.
// A completion receipt stores independently captured State/child Create UIDs, not
// Secret contents. Like the auth receipt, it is a privileged Kubernetes trust
// anchor, not a signature or a cross-object transaction.
func ReconcileFresh(ctx context.Context, c client.Client, namespace string, g *tnv1.TailnetGateway, tn *tnv1.Tailnet, hs GatewayHeadscale, now func() time.Time) (FreshObservation, error) {
	bad := func() (FreshObservation, error) { return FreshObservation{}, ErrFreshWrite }
	if c == nil || hs == nil || now == nil {
		return bad()
	}
	scope, err := freshScope(g, tn, namespace)
	if err != nil {
		return bad()
	}
	g, tn = g.DeepCopy(), tn.DeepCopy()
	completed := &corev1.ConfigMap{}
	err = c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: g.Name + "-fresh"}, completed)
	if err == nil {
		return observeFresh(ctx, c, namespace, g, tn, hs, now(), scope, completed)
	}
	if !apierrors.IsNotFound(err) {
		return bad()
	}

	// Render using a copy: the mint API requires no external auth reference, while
	// the Pod model consumes the newly minted, deterministic internal reference.
	renderG := g.DeepCopy()
	renderG.Spec.AuthKeySecretRef = &tnv1.GatewayAuthKeyReference{Name: tnv1.GatewayName(g.Name + "-auth"), Key: gatewayAuthKeyField}
	hosts := &corev1.ConfigMap{}
	if tn.Spec.DNS.HostsConfigMap == "" || c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: tn.Spec.DNS.HostsConfigMap}, hosts) != nil || !freshHostsOwned(hosts, tn) {
		return bad()
	}
	egresses, peers := &tnv1.TailnetEgressList{}, &tnv1.TailnetGatewayList{}
	if c.List(ctx, egresses, client.InNamespace(namespace)) != nil || c.List(ctx, peers) != nil {
		return bad()
	}
	in := FreshInputs{Gateway: renderG, Tailnet: tn, Namespace: namespace, Egresses: egresses.Items, Hosts: hosts.Data["hosts"], DNSSerial: 1}
	plan, err := RenderFresh(in)
	if err != nil || !freshIPv4(g, plan, in.Hosts) {
		return bad()
	}
	objects := append([]client.Object{}, plan.Objects...)
	objects = append(objects,
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: string(g.Spec.StateSecretRef.Name), Namespace: namespace}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: g.Name + "-auth", Namespace: namespace}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: g.Name + "-auth-receipt", Namespace: namespace}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: g.Name + "-0", Namespace: namespace}}, completedObject(g, namespace))
	names := map[string]bool{}
	for _, obj := range objects {
		k := writerObjectKind(obj) + "/" + obj.GetName()
		if names[k] || k == "ConfigMap/"+hosts.Name {
			return bad()
		}
		names[k] = true
		if err := c.Get(ctx, client.ObjectKeyFromObject(obj), obj); !apierrors.IsNotFound(err) {
			return bad()
		}
	}
	for _, p := range peers.Items {
		if p.UID == g.UID {
			continue
		}
		if p.Namespace != "" || p.UID == "" || strings.EqualFold(p.Spec.Hostname, g.Spec.Hostname) ||
			p.Spec.Service.LoadBalancerIP == g.Spec.Service.LoadBalancerIP || p.Spec.DNS.ServiceClusterIP == g.Spec.DNS.ServiceClusterIP {
			return bad()
		}
		for _, name := range freshNames(&p) {
			if names[name] {
				return bad()
			}
		}
	}
	if !freshPodsAbsent(ctx, c, g, namespace) {
		return bad()
	}
	nodes, err := hs.ListNodes(ctx)
	if err != nil {
		return bad()
	}
	nodeNames := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if strings.EqualFold(n.GivenName, g.Spec.Hostname) {
			return bad()
		}
		nodeNames = append(nodeNames, n.GivenName)
	}
	req, err := PlanGatewayMint(g, now())
	if err != nil || !mintSnapshotsUnchanged(ctx, c, g, tn) {
		return bad()
	}
	state := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: string(g.Spec.StateSecretRef.Name), Namespace: namespace, Labels: map[string]string{gatewayUIDLabel: string(g.UID)}}, Type: corev1.SecretTypeOpaque}
	if c.Create(ctx, state) != nil || state.UID == "" || state.ResourceVersion == "" {
		return bad()
	}
	stateUID := state.UID
	// Bind selectors to the exclusively created state, not just the predictable
	// CR UID. A pre-existing orphan with only the Gateway label cannot be adopted.
	bindFreshState(plan, stateUID)
	inspection := FreshInspectionInputs{Fresh: in, State: state, Hosts: hosts, PeerGateways: peers.Items, NodeNames: nodeNames}
	for _, obj := range plan.Objects {
		inspection.Absent = append(inspection.Absent, FreshObjectKey{Kind: freshObjectKind(obj), Namespace: namespace, Name: obj.GetName()})
	}
	if _, err := inspectFreshSnapshots(inspection); !errors.Is(err, ErrFreshProvenance) {
		return bad()
	}
	currentState := &corev1.Secret{}
	if !freshSourcesUnchanged(ctx, c, g, tn, hosts, egresses) ||
		c.Get(ctx, client.ObjectKeyFromObject(state), currentState) != nil || currentState.UID != stateUID || currentState.ResourceVersion != state.ResourceVersion {
		return bad()
	}
	issued, err := hs.CreatePreAuthKey(ctx, req)
	if err != nil {
		return bad()
	}
	auth, err := storeGatewayMintRecord(ctx, c, namespace, g, tn, req, issued, now)
	if err != nil {
		return bad()
	}
	receipt := freshReceipt{Scope: scope, StateUID: stateUID, Auth: auth, Routes: slices.Clone(plan.Routes.Routes)}
	authRecord := &corev1.ConfigMap{}
	if c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: g.Name + "-auth-receipt"}, authRecord) != nil {
		return bad()
	}
	receipt.Objects = append(receipt.Objects, objectReceipt(authRecord))
	for _, obj := range plan.Objects {
		// Recheck source revisions, the independently captured empty State UID and
		// durable auth before each write, especially before starting the StatefulSet.
		currentState := &corev1.Secret{}
		if !freshSourcesUnchanged(ctx, c, g, tn, hosts, egresses) ||
			c.Get(ctx, client.ObjectKeyFromObject(state), currentState) != nil || currentState.UID != stateUID ||
			currentState.DeletionTimestamp != nil || len(currentState.Data) != 0 || len(currentState.OwnerReferences) != 0 ||
			currentState.Immutable != nil && *currentState.Immutable {
			return bad()
		}
		checked, err := readGatewayMintRecord(ctx, c, g.Name, namespace, now())
		if err != nil || checked != auth {
			return bad()
		}
		if _, isWorkload := obj.(*appsv1.StatefulSet); isWorkload && !freshPodsAbsent(ctx, c, g, namespace) {
			return bad()
		}
		if c.Create(ctx, obj) != nil || obj.GetUID() == "" || obj.GetResourceVersion() == "" || len(obj.GetOwnerReferences()) != 0 {
			return bad()
		}
		receipt.Objects = append(receipt.Objects, objectReceipt(obj))
	}
	if !freshSourcesUnchanged(ctx, c, g, tn, hosts, egresses) {
		return bad()
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return bad()
	}
	completed = completedObject(g, namespace)
	completed.Data = map[string]string{"receipt.json": string(data)}
	if c.Create(ctx, completed) != nil || completed.UID == "" || completed.ResourceVersion == "" || completed.Data["receipt.json"] != string(data) {
		return bad()
	}
	return observeFresh(ctx, c, namespace, g, tn, hs, now(), scope, completed)
}

const gatewayStateUIDLabel = "tsunaro.io/gateway-state-uid"

func freshPodsAbsent(ctx context.Context, c client.Reader, g *tnv1.TailnetGateway, ns string) bool {
	if !apierrors.IsNotFound(c.Get(ctx, client.ObjectKey{Namespace: ns, Name: g.Name + "-0"}, &corev1.Pod{})) {
		return false
	}
	pods := &corev1.PodList{}
	return c.List(ctx, pods, client.InNamespace(ns), client.MatchingLabels{gatewayUIDLabel: string(g.UID)}) == nil && len(pods.Items) == 0
}

func bindFreshState(plan FreshPlan, uid types.UID) {
	for _, obj := range plan.Objects {
		switch obj := obj.(type) {
		case *appsv1.StatefulSet:
			obj.Spec.Selector.MatchLabels[gatewayStateUIDLabel] = string(uid)
			obj.Spec.Template.Labels[gatewayStateUIDLabel] = string(uid)
		case *corev1.Service:
			obj.Spec.Selector[gatewayStateUIDLabel] = string(uid)
		case *policyv1.PodDisruptionBudget:
			obj.Spec.Selector.MatchLabels[gatewayStateUIDLabel] = string(uid)
		}
	}
}

func completedObject(g *tnv1.TailnetGateway, ns string) *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: g.Name + "-fresh", Namespace: ns, Labels: map[string]string{gatewayUIDLabel: string(g.UID), "app.kubernetes.io/managed-by": "tailnet-operator"}}, Immutable: ptr.To(true)}
}

type freshGatewayIdentity struct {
	TailnetRef, StateSecretRef tnv1.GatewayLocalReference
	Hostname                   string
	Tags                       []string
	Replicas                   int32
	LoadBalancerIP             tnv1.GatewayIP
	LoadBalancerClass          tnv1.GatewayClass
	Zone                       tnv1.GatewayName
	DNSServiceName             tnv1.GatewayServiceName
	DNSServiceClusterIP        tnv1.GatewayIP
	ExtraZones                 []tnv1.GatewayExtraZone
	ForwardImage               tnv1.GatewayImage
	Forwards                   []tnv1.GatewayForward
}

// freshScope is receipt format 3: it pins identity, not generations. Mutable
// fields (image, dns.image, staticRecords, wildcardAddress, deletionPolicy,
// suspend, routes.*, service.tailnetLBCIDR, service.poolLabels, Tailnet fields
// other than server and hostsConfigMap) are reconciled live or are irrelevant to
// the retained set. The load-balancer IP and class and the zone fields stay pinned.
func freshScope(g *tnv1.TailnetGateway, tn *tnv1.Tailnet, ns string) (map[string]string, error) {
	// Reuse the preamble checks (not suspended, no adoption, no external auth).
	if _, err := mintRecordScope(g, tn, ns); err != nil {
		return nil, err
	}
	tags := slices.Clone(g.Spec.Tags)
	slices.Sort(tags)
	gateway := freshGatewayIdentity{
		g.Spec.TailnetRef, g.Spec.StateSecretRef, g.Spec.Hostname, tags, g.Spec.Replicas, g.Spec.Service.LoadBalancerIP, g.Spec.Service.LoadBalancerClass,
		g.Spec.DNS.Zone, g.Spec.DNS.ServiceName, g.Spec.DNS.ServiceClusterIP, g.Spec.DNS.ExtraZones, g.Spec.ForwardImage, g.Spec.Forwards,
	}
	tailnet := struct{ Server, HostsConfigMap string }{tn.Spec.Server, tn.Spec.DNS.HostsConfigMap}
	gb, ge := json.Marshal(gateway)
	tb, te := json.Marshal(tailnet)
	if ge != nil || te != nil {
		return nil, ErrGatewayAuthRecord
	}
	gh, th := sha256.Sum256(gb), sha256.Sum256(tb)
	return map[string]string{
		"format": "3", "gatewayName": g.Name, "gatewayUID": string(g.UID), "gatewayIdentitySHA256": hex.EncodeToString(gh[:]),
		"tailnetName": tn.Name, "tailnetUID": string(tn.UID), "tailnetIdentitySHA256": hex.EncodeToString(th[:]),
	}, nil
}

func freshIPv4(g *tnv1.TailnetGateway, p FreshPlan, hosts string) bool {
	parsed, err := parseDNSHosts(hosts)
	if err != nil {
		return false
	}
	for _, addresses := range parsed {
		for _, addr := range addresses {
			if !addr.Is4() {
				return false
			}
		}
	}
	for _, r := range p.Routes.Routes {
		prefix, err := netip.ParsePrefix(r)
		if err != nil || !prefix.Addr().Is4() {
			return false
		}
	}
	ips := []string{string(g.Spec.Service.LoadBalancerIP), string(g.Spec.DNS.ServiceClusterIP)}
	if g.Spec.DNS.WildcardAddress != "" {
		ips = append(ips, string(g.Spec.DNS.WildcardAddress))
	}
	for _, r := range g.Spec.DNS.StaticRecords {
		// CNAME-only records carry no address; the target's family is governed by
		// the record it points to.
		if r.Address == "" {
			continue
		}
		ips = append(ips, string(r.Address))
	}
	for _, s := range ips {
		ip, err := netip.ParseAddr(s)
		if err != nil || !ip.Is4() {
			return false
		}
	}
	return true
}

func freshNames(g *tnv1.TailnetGateway) []string {
	names := []string{"Secret/" + string(g.Spec.StateSecretRef.Name), "Secret/" + g.Name + "-auth", "ConfigMap/" + g.Name + "-auth-receipt", "ConfigMap/" + g.Name + "-fresh", "ConfigMap/" + g.Name + "-coredns", "Service/" + g.Name, "Service/" + g.Name + "-headless", "Service/" + string(g.Spec.DNS.ServiceName), "ServiceAccount/" + g.Name, "Role/" + g.Name, "RoleBinding/" + g.Name, "PodDisruptionBudget/" + g.Name, "StatefulSet/" + g.Name, "Pod/" + g.Name + "-0"}
	if g.Spec.AuthKeySecretRef != nil {
		names = append(names, "Secret/"+string(g.Spec.AuthKeySecretRef.Name))
	}
	return names
}

func freshSourcesUnchanged(ctx context.Context, c client.Reader, g *tnv1.TailnetGateway, tn *tnv1.Tailnet, hosts *corev1.ConfigMap, egresses *tnv1.TailnetEgressList) bool {
	live := &corev1.ConfigMap{}
	current := &tnv1.TailnetEgressList{}
	if !mintSnapshotsUnchanged(ctx, c, g, tn) || c.Get(ctx, client.ObjectKeyFromObject(hosts), live) != nil || live.UID != hosts.UID || live.ResourceVersion != hosts.ResourceVersion || live.DeletionTimestamp != nil || c.List(ctx, current, client.InNamespace(hosts.Namespace)) != nil {
		return false
	}
	revisions := func(rows []tnv1.TailnetEgress) map[types.UID]string {
		out := map[types.UID]string{}
		for _, e := range rows {
			if e.Spec.TailnetRef.Name == tn.Name {
				out[e.UID] = e.ResourceVersion
			}
		}
		return out
	}
	return reflect.DeepEqual(revisions(current.Items), revisions(egresses.Items))
}

func writerObjectKind(obj client.Object) string {
	switch obj.(type) {
	case *corev1.Secret:
		return "Secret"
	case *corev1.Pod:
		return "Pod"
	}
	return freshObjectKind(obj)
}

// Fingerprints cover the admitted payload, excluding API bookkeeping and status.
// StatefulSet status updates and Pod recreation do not change its template hash.
func objectReceipt(obj client.Object) freshObjectReceipt {
	b, _ := json.Marshal(obj)
	var data map[string]any
	_ = json.Unmarshal(b, &data)
	for _, k := range []string{"apiVersion", "kind", "metadata", "status"} {
		delete(data, k)
	}
	// The whole Pod template follows the Gateway spec via UpdateWorkloadRevision
	// (images, env with TS_ROUTES, container ports, etc.); every other field of
	// the StatefulSet (selector, serviceName, strategy, replicas) stays bound.
	if _, ok := obj.(*appsv1.StatefulSet); ok {
		if spec, ok := data["spec"].(map[string]any); ok {
			delete(spec, "template")
		}
	}
	// The derived DNS zone AND Corefile are reconciled live from the Tailnet
	// hosts source and the Gateway spec via UpdateDNSRevision. Their integrity
	// rides on the matching annotations and the DNSReady condition, not on this
	// immutable fingerprint. Every other key of the -coredns ConfigMap stays
	// digest-bound.
	if cm, ok := obj.(*corev1.ConfigMap); ok && strings.HasSuffix(cm.Name, "-coredns") {
		if payload, ok := data["data"].(map[string]any); ok {
			delete(payload, DNSZoneFile)
			delete(payload, "Corefile")
		}
	}
	b, _ = json.Marshal(data)
	hash := sha256.Sum256(b)
	return freshObjectReceipt{Kind: writerObjectKind(obj), Name: obj.GetName(), UID: obj.GetUID(), Digest: hex.EncodeToString(hash[:])}
}

func observeFresh(ctx context.Context, c client.Client, ns string, g *tnv1.TailnetGateway, tn *tnv1.Tailnet, hs GatewayHeadscale, now time.Time, scope map[string]string, record *corev1.ConfigMap) (FreshObservation, error) {
	bad := func() (FreshObservation, error) { return FreshObservation{}, ErrFreshWrite }
	if record.UID == "" || record.ResourceVersion == "" || record.DeletionTimestamp != nil || record.Immutable == nil || !*record.Immutable || len(record.OwnerReferences) != 0 || len(record.Finalizers) != 0 || len(record.BinaryData) != 0 || len(record.Data) != 1 || record.Labels[gatewayUIDLabel] != string(g.UID) || record.Labels["app.kubernetes.io/managed-by"] != "tailnet-operator" {
		return bad()
	}
	raw := record.Data["receipt.json"]
	if len(raw) == 0 || len(raw) > 1<<20 {
		return bad()
	}
	var receipt freshReceipt
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || decoder.Decode(&struct{}{}) != io.EOF || receipt.StateUID == "" || len(receipt.Objects) != 10 {
		return bad()
	}
	if !reflect.DeepEqual(scope, receipt.Scope) {
		return FreshObservation{}, ErrFreshIdentity
	}
	auth := &corev1.Secret{}
	if c.Get(ctx, client.ObjectKey{Namespace: ns, Name: g.Name + "-auth"}, auth) != nil {
		return bad()
	}
	checked, err := ReadGatewayAuthReceipt(auth, g, tn, ns, receipt.Auth.UID, now)
	if err != nil || checked != receipt.Auth {
		return bad()
	}
	// Reconstruct object kinds only, never derive expected UIDs from current Gets.
	renderG := g.DeepCopy()
	renderG.Status = tnv1.TailnetGatewayStatus{}
	renderG.Spec.AuthKeySecretRef = &tnv1.GatewayAuthKeyReference{Name: tnv1.GatewayName(g.Name + "-auth"), Key: gatewayAuthKeyField}
	plan, err := RenderFresh(FreshInputs{Gateway: renderG, Tailnet: tn, Namespace: ns, DNSSerial: 1})
	if err != nil {
		return bad()
	}
	wanted := map[string]client.Object{"ConfigMap/" + g.Name + "-auth-receipt": &corev1.ConfigMap{}}
	for _, obj := range plan.Objects {
		wanted[freshObjectKind(obj)+"/"+obj.GetName()] = emptyFreshObject(obj)
	}
	var sts *appsv1.StatefulSet
	var workload, lbService freshObjectReceipt
	for _, ref := range receipt.Objects {
		k := ref.Kind + "/" + ref.Name
		obj := wanted[k]
		if obj == nil || ref.UID == "" || c.Get(ctx, client.ObjectKey{Namespace: ns, Name: ref.Name}, obj) != nil || obj.GetDeletionTimestamp() != nil || len(obj.GetOwnerReferences()) != 0 || objectReceipt(obj) != ref {
			return bad()
		}
		delete(wanted, k)
		if v, ok := obj.(*appsv1.StatefulSet); ok {
			sts = v
			workload = ref
		}
		if v, ok := obj.(*corev1.Service); ok && v.Name == g.Name {
			lbService = ref
		}
	}
	if len(wanted) != 0 || sts == nil {
		return bad()
	}
	state := &corev1.Secret{}
	if c.Get(ctx, client.ObjectKey{Namespace: ns, Name: string(g.Spec.StateSecretRef.Name)}, state) != nil || state.UID != receipt.StateUID || state.DeletionTimestamp != nil {
		return bad()
	}
	result := FreshObservation{Completed: true, Routes: slices.Clone(receipt.Routes), workload: workload, service: lbService}
	pod := &corev1.Pod{}
	err = c.Get(ctx, client.ObjectKey{Namespace: ns, Name: g.Name + "-0"}, pod)
	if apierrors.IsNotFound(err) {
		return result, nil
	}
	if err != nil {
		return bad()
	}
	owner := metav1.GetControllerOf(pod)
	if pod.DeletionTimestamp != nil || owner == nil || owner.UID != sts.UID || owner.Kind != "StatefulSet" || owner.Name != sts.Name || pod.Labels[gatewayUIDLabel] != string(g.UID) || pod.Spec.ServiceAccountName != g.Name || pod.Labels[gatewayStateUIDLabel] != string(receipt.StateUID) {
		return result, nil
	}
	result.PodPresent = true
	// The StatefulSet controller stamps the current template hash on every pod it
	// creates. A pod created before our last template write will not carry the
	// current UpdateRevision; we never restart it ourselves.
	result.PodCurrent = sts.Status.UpdateRevision != "" && pod.Labels["controller-revision-hash"] == sts.Status.UpdateRevision
	// The Pod's own TS_ROUTES, not the receipt, is what it advertises; no routes, no Ready.
	running, ok := podRoutes(pod.Spec)
	if !ok {
		return result, nil
	}
	result.PodRoutes = running
	ready := false
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	if !ready || pod.Status.Phase != corev1.PodRunning || len(pod.Status.ContainerStatuses) != len(pod.Spec.Containers) {
		return result, nil
	}
	for _, container := range pod.Status.ContainerStatuses {
		if !container.Ready || container.State.Running == nil {
			return result, nil
		}
	}
	nodes, err := hs.ListNodes(ctx)
	if err != nil {
		return bad()
	}
	binding, err := VerifyGatewayState(g, tn, state, ns, receipt.StateUID, nodes, receipt.Auth.KeyID)
	if err != nil {
		return result, nil
	}
	for _, node := range nodes {
		if node.ID != binding.NodeID {
			continue
		}
		advertised := slices.Clone(node.AvailableRoutes)
		slices.Sort(advertised)
		wantedRoutes := slices.Clone(running)
		slices.Sort(wantedRoutes)
		if !slices.Equal(advertised, wantedRoutes) {
			return result, nil
		}
		result.Routes = wantedRoutes
		result.Approved = slices.Clone(node.ApprovedRoutes)
		slices.Sort(result.Approved)
	}
	// Last-read CAS boundaries; nothing below writes workloads or changes identity.
	currentState := &corev1.Secret{}
	if !mintSnapshotsUnchanged(ctx, c, g, tn) || c.Get(ctx, client.ObjectKeyFromObject(state), currentState) != nil || currentState.UID != state.UID || currentState.ResourceVersion != state.ResourceVersion {
		return bad()
	}
	result.Ready, result.Binding = true, binding
	return result, nil
}
