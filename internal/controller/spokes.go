package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/policy"
)

const (
	// spokeLabel marks the hub-side copies of a pulled fragment with the spoke's name.
	spokeLabel = "tsunaro.io/spoke"
	// approveAnnotationPrefix + spoke name, value = pendingHash, adopts a pending fragment in
	// approval mode Manual. The annotation is not removed: once adopted it matches approvedHash and
	// is inert; a later fetch has a different hash and waits again.
	approveAnnotationPrefix = "tsunaro.io/approve-spoke."
	// spokeFetchTimeout bounds one fragment read from a spoke API server. ponytail: fragments are
	// polled on every reconcile (policyRequeue); a watch per spoke is the upgrade path once the
	// number of spokes makes 5-minute polling too coarse.
	spokeFetchTimeout = 10 * time.Second
)

// spokeFragments pulls every policy.spokes[] fragment from its cluster, validates it against the
// hub's limits plus the spoke's own tag patterns and route allowlist, and gates it per the spoke's
// approval mode. It returns the fragments to merge now and the per-spoke status to persist. A spoke
// that is unreachable or sends an invalid fragment keeps its last approved fragment merged: a hub
// never drops a spoke's live grants because of a transient failure. Only the caller's status write
// persists statuses; this function writes the hub-side copies (approved/pending ConfigMaps).
func (r *TailnetPolicyReconciler) spokeFragments(ctx context.Context, tn *tnv1.Tailnet, base []byte, in policy.Inputs) ([][]byte, []tnv1.SpokeStatus, error) {
	spokes := tn.Spec.Policy.Spokes
	if err := r.pruneSpokeCopies(ctx, tn, spokes); err != nil {
		return nil, nil, err
	}
	now := metav1.Now()
	var frags [][]byte
	var statuses []tnv1.SpokeStatus
	for i := range spokes {
		sp := &spokes[i]
		prev := spokeStatusOf(tn, sp.Name)
		st := tnv1.SpokeStatus{Name: sp.Name, FetchedHash: prev.FetchedHash, FetchedAt: prev.FetchedAt,
			ApprovedHash: prev.ApprovedHash, ApprovedAt: prev.ApprovedAt}
		set := func(typ string, ok bool, reason, msg string) {
			s := metav1.ConditionFalse
			if ok {
				s = metav1.ConditionTrue
			}
			setCond(&st.Conditions, tn.Generation, typ, s, reason, msg)
		}

		approved, approvedErr := r.readSpokeCopy(ctx, tn, spokeCopyName(sp.Name, "approved"))
		if approvedErr != nil {
			return nil, nil, approvedErr
		}
		if approved == nil {
			st.ApprovedHash, st.ApprovedAt = "", nil
		}

		fetched, reachable, reason, msg := r.fetchSpokeFragment(ctx, sp)
		set("SpokeReachable", reachable, reason, msg)
		valid := false
		var fetchedHash string
		if fetched != nil {
			rules := fragmentRules(tn, base, in, spokeTagPatterns(sp), prefixStrings(sp.RouteAllowlist), true)
			if err := policy.ValidateFragment(fetched, rules); err != nil {
				set("SpokeFragmentValid", false, "FragmentInvalid", err.Error())
			} else if canonical, err := policy.Normalize(fetched); err != nil {
				set("SpokeFragmentValid", false, "FragmentInvalid", err.Error())
			} else {
				valid = true
				fetchedHash = policy.Hash(canonical)
				set("SpokeFragmentValid", true, "Valid", "fragment within the hub's limits")
				if fetchedHash != prev.FetchedHash {
					st.FetchedAt = &now
				}
				st.FetchedHash = fetchedHash
			}
		} else if reachable {
			set("SpokeFragmentValid", false, reason, msg)
		} else {
			set("SpokeFragmentValid", false, "Unknown", "fragment not fetched")
		}

		// Gate.
		adopt := func(event string) error {
			if err := r.writeSpokeCopy(ctx, tn, sp.Name, "approved", fetched); err != nil {
				return err
			}
			if fetchedHash != prev.ApprovedHash && r.Recorder != nil {
				r.Recorder.Eventf(tn, corev1.EventTypeNormal, event, "spoke %s: fragment %s merged", sp.Name, short(fetchedHash))
			}
			if fetchedHash != prev.ApprovedHash {
				st.ApprovedAt = &now
			}
			st.ApprovedHash = fetchedHash
			approved = fetched
			return nil
		}
		switch {
		case !valid:
			// keep approved
		case sp.Approval != "Manual":
			if err := adopt("SpokeFragmentAdopted"); err != nil {
				return nil, nil, err
			}
		case fetchedHash == st.ApprovedHash:
			// nothing new
		case tn.Annotations[approveAnnotationPrefix+sp.Name] == fetchedHash:
			if err := adopt("SpokeFragmentApproved"); err != nil {
				return nil, nil, err
			}
		default:
			st.PendingHash = fetchedHash
			st.PendingSince = &now
			if prev.PendingHash == fetchedHash && prev.PendingSince != nil {
				st.PendingSince = prev.PendingSince
			}
			st.PendingDelta = spokeDelta(approved, fetched)
		}
		if st.PendingHash != "" {
			if err := r.writeSpokeCopy(ctx, tn, sp.Name, "pending", fetched); err != nil {
				return nil, nil, err
			}
			reason, msg := "ApprovalPending", fmt.Sprintf("fragment %s waits for annotation %s%s=%s; review ConfigMap %s/%s",
				short(st.PendingHash), approveAnnotationPrefix, sp.Name, st.PendingHash, r.OperatorNamespace, spokeCopyName(sp.Name, "pending"))
			if a := tn.Annotations[approveAnnotationPrefix+sp.Name]; a != "" {
				reason, msg = "ApprovalStale", fmt.Sprintf("annotation %s%s names %s, pending is %s; the spoke changed its fragment since — review again",
					approveAnnotationPrefix, sp.Name, short(a), short(st.PendingHash))
			}
			set("SpokeFragmentApproved", false, reason, msg)
		} else {
			if err := r.deleteSpokeCopy(ctx, tn, spokeCopyName(sp.Name, "pending")); err != nil {
				return nil, nil, err
			}
			switch {
			case st.ApprovedHash == "":
				set("SpokeFragmentApproved", false, "NothingApproved", "no fragment merged yet")
			case sp.Approval == "Manual":
				set("SpokeFragmentApproved", true, "Approved", "fragment "+short(st.ApprovedHash)+" merged")
			default:
				set("SpokeFragmentApproved", true, "Auto", "fragment "+short(st.ApprovedHash)+" merged")
			}
		}

		// Merge: Manual with a valid newer fetch merges approved ∩ fetched — removals the spoke
		// made take effect at once, additions wait for approval.
		merge := approved
		if st.PendingHash != "" && approved != nil {
			merge = intersectFragment(approved, fetched)
		}
		if merge != nil {
			frags = append(frags, merge)
		}
		statuses = append(statuses, st)
	}
	return frags, statuses, nil
}

// spokesReady folds the per-spoke conditions into one Tailnet condition; the worst state wins.
func spokesReady(statuses []tnv1.SpokeStatus) (metav1.ConditionStatus, string, string) {
	var unreachable, invalid, pending, empty []string
	for _, s := range statuses {
		switch {
		case meta.IsStatusConditionFalse(s.Conditions, "SpokeReachable"):
			unreachable = append(unreachable, s.Name)
		case meta.IsStatusConditionFalse(s.Conditions, "SpokeFragmentValid"):
			invalid = append(invalid, s.Name)
		case s.PendingHash != "":
			pending = append(pending, s.Name)
		case s.ApprovedHash == "":
			empty = append(empty, s.Name)
		}
	}
	switch {
	case len(unreachable) > 0:
		return metav1.ConditionFalse, "SpokeUnreachable", "unreachable: " + strings.Join(unreachable, ", ")
	case len(invalid) > 0:
		return metav1.ConditionFalse, "SpokeFragmentInvalid", "invalid fragment: " + strings.Join(invalid, ", ")
	case len(pending) > 0:
		return metav1.ConditionFalse, "ApprovalPending", "waiting for approval: " + strings.Join(pending, ", ")
	case len(empty) > 0:
		return metav1.ConditionFalse, "NothingApproved", "no fragment merged yet: " + strings.Join(empty, ", ")
	}
	return metav1.ConditionTrue, "AllMerged", fmt.Sprintf("%d spoke fragments merged", len(statuses))
}

// fetchSpokeFragment reads the spoke's fragment ConfigMap with the kubeconfig from the operator
// namespace. Messages never carry the kubeconfig or server error bodies — only our own words, the
// HTTP status and the dial target.
func (r *TailnetPolicyReconciler) fetchSpokeFragment(ctx context.Context, sp *tnv1.SpokeRef) (frag []byte, reachable bool, reason, msg string) {
	var sec corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.OperatorNamespace, Name: sp.KubeconfigSecretRef.Name}, &sec); err != nil {
		return nil, false, "KubeconfigMissing", fmt.Sprintf("Secret %s/%s: %s", r.OperatorNamespace, sp.KubeconfigSecretRef.Name, statusOnly(err))
	}
	key := sp.KubeconfigSecretRef.Key
	if key == "" {
		key = "kubeconfig"
	}
	raw := sec.Data[key]
	if len(raw) == 0 {
		return nil, false, "KubeconfigMissing", fmt.Sprintf("Secret %s/%s has no key %q", r.OperatorNamespace, sp.KubeconfigSecretRef.Name, key)
	}
	cfg, err := clientcmd.RESTConfigFromKubeConfig(raw)
	if err != nil {
		return nil, false, "KubeconfigInvalid", "kubeconfig does not parse"
	}
	cfg.Timeout = spokeFetchTimeout
	cfg.UserAgent = fieldOwner + "/spoke-fragment"
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, false, "KubeconfigInvalid", "kubeconfig yields no client"
	}
	ns := sp.Namespace
	if ns == "" {
		ns = r.OperatorNamespace
	}
	name := sp.ConfigMap
	if name == "" {
		name = sp.Name + "-policy-fragment"
	}
	ctx, cancel := context.WithTimeout(ctx, spokeFetchTimeout)
	defer cancel()
	cm, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
	switch {
	case err == nil:
	case apierrors.IsNotFound(err):
		return nil, true, "FragmentMissing", fmt.Sprintf("ConfigMap %s/%s not found on the spoke", ns, name)
	case apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err):
		return nil, false, "Forbidden", fmt.Sprintf("spoke API server answered %s for ConfigMap %s/%s; check the reader ServiceAccount and token", statusOnly(err), ns, name)
	default:
		return nil, false, "Unreachable", fmt.Sprintf("spoke API server %s: %s", cfg.Host, statusOnly(err))
	}
	data, ok := cm.Data[policyKey]
	if !ok {
		return nil, true, "FragmentMissing", fmt.Sprintf("ConfigMap %s/%s has no key %q", ns, name, policyKey)
	}
	return []byte(data), true, "Reachable", fmt.Sprintf("ConfigMap %s/%s read", ns, name)
}

// statusOnly reduces a client-go error to its HTTP status or transport class; server bodies and
// URLs with credentials never reach a condition.
func statusOnly(err error) string {
	var st apierrors.APIStatus
	if errors.As(err, &st) && st.Status().Code != 0 {
		return fmt.Sprintf("HTTP %d", st.Status().Code)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return "dial failed"
	}
	return "request failed"
}

func spokeTagPatterns(sp *tnv1.SpokeRef) []string {
	if len(sp.TagPatterns) > 0 {
		return sp.TagPatterns
	}
	return []string{"tag:*-" + sp.Name + "-*"}
}

func prefixStrings(ps []tnv1.GatewayPrefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, string(p))
	}
	return out
}

func spokeStatusOf(tn *tnv1.Tailnet, name string) tnv1.SpokeStatus {
	for _, s := range tn.Status.Spokes {
		if s.Name == name {
			return s
		}
	}
	return tnv1.SpokeStatus{Name: name}
}

func spokeCopyName(spoke, kind string) string { return spoke + "-policy-fragment-" + kind }

func short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

// readSpokeCopy returns the hub-side copy (approved/pending) if this Tailnet owns it; a foreign
// ConfigMap of that name counts as absent and is never read or overwritten.
func (r *TailnetPolicyReconciler) readSpokeCopy(ctx context.Context, tn *tnv1.Tailnet, name string) ([]byte, error) {
	var cm corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.OperatorNamespace, Name: name}, &cm); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	if !ownedBy(&cm, tn.UID) {
		log.FromContext(ctx).Error(nil, "spoke ConfigMap exists and is not owned by this Tailnet; ignoring it", "configmap", name)
		return nil, nil
	}
	data, ok := cm.Data[policyKey]
	if !ok {
		return nil, nil
	}
	return []byte(data), nil
}

func (r *TailnetPolicyReconciler) writeSpokeCopy(ctx context.Context, tn *tnv1.Tailnet, spoke, kind string, data []byte) error {
	name := spokeCopyName(spoke, kind)
	var existing corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.OperatorNamespace, Name: name}, &existing); err == nil {
		if !ownedBy(&existing, tn.UID) {
			if r.Recorder != nil {
				r.Recorder.Eventf(tn, corev1.EventTypeWarning, "ConfigMapNotOwned",
					"spoke ConfigMap %s/%s is owned by another resource; refusing to overwrite", r.OperatorNamespace, name)
			}
			return nil
		}
		if existing.Data[policyKey] == string(data) {
			return nil
		}
	} else if client.IgnoreNotFound(err) != nil {
		return err
	}
	cm := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: r.OperatorNamespace,
			Labels: map[string]string{"app.kubernetes.io/managed-by": fieldOwner, roleLabel: rolePolicyRender, spokeLabel: spoke}},
		Data: map[string]string{policyKey: string(data)},
	}
	if err := controllerutil.SetControllerReference(tn, cm, r.Scheme); err != nil {
		return err
	}
	return ssaApply(ctx, r.Client, cm)
}

func (r *TailnetPolicyReconciler) deleteSpokeCopy(ctx context.Context, tn *tnv1.Tailnet, name string) error {
	var cm corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.OperatorNamespace, Name: name}, &cm); err != nil || !ownedBy(&cm, tn.UID) {
		return client.IgnoreNotFound(err)
	}
	return client.IgnoreNotFound(r.Delete(ctx, &cm, client.Preconditions{UID: &cm.UID}))
}

// pruneSpokeCopies removes the approved/pending copies of spokes no longer listed.
func (r *TailnetPolicyReconciler) pruneSpokeCopies(ctx context.Context, tn *tnv1.Tailnet, spokes []tnv1.SpokeRef) error {
	var cms corev1.ConfigMapList
	if err := r.List(ctx, &cms, client.InNamespace(r.OperatorNamespace), client.HasLabels{spokeLabel}); err != nil {
		return err
	}
	for i := range cms.Items {
		cm := &cms.Items[i]
		if !ownedBy(cm, tn.UID) {
			continue
		}
		listed := false
		for _, sp := range spokes {
			if sp.Name == cm.Labels[spokeLabel] {
				listed = true
			}
		}
		if !listed {
			if err := r.Delete(ctx, cm, client.Preconditions{UID: &cm.UID}); client.IgnoreNotFound(err) != nil {
				return err
			}
		}
	}
	return nil
}

// fragmentEntries flattens a fragment into comparable entries per block: canonical JSON of each
// tagOwners pair, autoApprovers.routes pair and grant object.
type fragmentEntries struct{ tags, routes, grants map[string]bool }

func entriesOf(frag []byte) fragmentEntries {
	e := fragmentEntries{tags: map[string]bool{}, routes: map[string]bool{}, grants: map[string]bool{}}
	var doc struct {
		TagOwners     map[string]json.RawMessage `json:"tagOwners"`
		AutoApprovers struct {
			Routes map[string]json.RawMessage `json:"routes"`
		} `json:"autoApprovers"`
		Grants []json.RawMessage `json:"grants"`
	}
	canonical, err := policy.Normalize(frag)
	if err != nil || json.Unmarshal([]byte(canonical), &doc) != nil {
		return e
	}
	for k, v := range doc.TagOwners {
		e.tags[k+"="+string(v)] = true
	}
	for k, v := range doc.AutoApprovers.Routes {
		e.routes[k+"="+string(v)] = true
	}
	for _, g := range doc.Grants {
		e.grants[string(g)] = true
	}
	return e
}

// spokeDelta counts what fetched adds to and removes from approved.
func spokeDelta(approved, fetched []byte) *tnv1.SpokeDelta {
	a, f := entriesOf(approved), entriesOf(fetched)
	diff := func(x, y map[string]bool) (added int) {
		for k := range y {
			if !x[k] {
				added++
			}
		}
		return
	}
	return &tnv1.SpokeDelta{
		TagsAdded: diff(a.tags, f.tags), TagsRemoved: diff(f.tags, a.tags),
		GrantsAdded: diff(a.grants, f.grants), GrantsRemoved: diff(f.grants, a.grants),
		RoutesAdded: diff(a.routes, f.routes), RoutesRemoved: diff(f.routes, a.routes),
	}
}

// intersectFragment keeps the entries of approved that fetched still carries, so a spoke can shrink
// its grants without approval while every addition waits.
func intersectFragment(approved, fetched []byte) []byte {
	f := entriesOf(fetched)
	var doc struct {
		TagOwners     map[string]json.RawMessage `json:"tagOwners,omitempty"`
		AutoApprovers *struct {
			Routes map[string]json.RawMessage `json:"routes,omitempty"`
		} `json:"autoApprovers,omitempty"`
		Grants []json.RawMessage `json:"grants,omitempty"`
	}
	canonical, err := policy.Normalize(approved)
	if err != nil || json.Unmarshal([]byte(canonical), &doc) != nil {
		return approved
	}
	for k, v := range doc.TagOwners {
		if !f.tags[k+"="+string(v)] {
			delete(doc.TagOwners, k)
		}
	}
	if doc.AutoApprovers != nil {
		for k, v := range doc.AutoApprovers.Routes {
			if !f.routes[k+"="+string(v)] {
				delete(doc.AutoApprovers.Routes, k)
			}
		}
		if len(doc.AutoApprovers.Routes) == 0 {
			doc.AutoApprovers = nil
		}
	}
	kept := doc.Grants[:0]
	for _, g := range doc.Grants {
		if f.grants[string(g)] {
			kept = append(kept, g)
		}
	}
	doc.Grants = kept
	out, err := json.Marshal(doc)
	if err != nil {
		return approved
	}
	return out
}
