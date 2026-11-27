package controller

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/policy"
)

// TailnetGrants have no reconciler of their own: the policy reconcile of their Tailnet renders them
// and writes their status, like TailnetSites. The rule, in full:
//
//  1. A grant is rendered only by the Tailnet that owns the policy (base set, mode DryRun or Apply),
//     only while its target is valid and only while the operator's clock is before expiresAt.
//  2. A target tag is valid when it is the tag of a TailnetIngress bound to the Tailnet or a grant
//     dst of a merged fragment. Target prefixes are valid when each lies inside a prefix of an
//     unblocked TailnetSite.
//  3. Ready is True/Granted when the grant is rendered and the live policy equals the render.
//     Otherwise False with the first reason that applies: NotPolicyWriter, Expired (the live policy
//     has dropped the grant) or ExpiryPending (not confirmed yet), TargetUnknown,
//     TargetOutsideSites, SourceGroupUnknown, PolicyPending.
//
// Status messages, logs and metric labels never name a user reference; group names are allowed.

// grantStage is how far a policy reconcile got. It decides what a grant may report.
type grantStage int

const (
	grantsNotRendered grantStage = iota // stopped before the render (base missing, fragment invalid, error)
	grantsRendered                      // rendered; the live policy differs or was not compared
	grantsLive                          // the live policy equals the render
	grantsNotWriter                     // this Tailnet does not write the policy (off or Export)
)

// grantRun carries the TailnetGrants of one policy reconcile from the early list to the deferred
// status write and the requeue at the next expiry.
type grantRun struct {
	now      time.Time
	grants   []tnv1.TailnetGrant
	next     time.Time               // next future expiry; zero when there is none
	verdicts map[string]grantVerdict // by grant name; nil until resolveGrants ran
	stage    grantStage
	unknown  []string // Summary.UnknownSources of the render
}

// grantVerdict is what the render inputs say about one grant.
type grantVerdict struct {
	expired         bool
	reason, message string // target problem; empty when the grant is rendered
}

func (r *TailnetPolicyReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// grantExpired: from expiresAt on (inclusive) the grant is expired.
func grantExpired(now time.Time, g *tnv1.TailnetGrant) bool {
	return g.Spec.ExpiresAt != nil && !now.Before(g.Spec.ExpiresAt.Time)
}

// nextExpiry returns the earliest expiresAt after now, or the zero time.
func nextExpiry(now time.Time, grants []tnv1.TailnetGrant) time.Time {
	var next time.Time
	for i := range grants {
		if e := grants[i].Spec.ExpiresAt; e != nil && now.Before(e.Time) && (next.IsZero() || e.Time.Before(next)) {
			next = e.Time
		}
	}
	return next
}

// resolveGrants decides, without I/O, which grants are rendered: the policy inputs, a verdict per
// grant and the next future expiry. ingressTags are the tags of the Tailnet's own ingresses,
// fragmentTags the grant dst tags of the merged fragments, sitePrefixes the prefixes of the
// unblocked sites.
func resolveGrants(now time.Time, grants []tnv1.TailnetGrant, ingressTags, fragmentTags, sitePrefixes []string) ([]policy.Grant, map[string]grantVerdict, time.Time) {
	tags := map[string]bool{}
	for _, t := range ingressTags {
		tags[t] = true
	}
	for _, t := range fragmentTags {
		tags[t] = true
	}
	var sites []netip.Prefix
	for _, s := range sitePrefixes {
		if p, err := netip.ParsePrefix(s); err == nil {
			sites = append(sites, p)
		}
	}
	var in []policy.Grant
	verdicts := make(map[string]grantVerdict, len(grants))
	for i := range grants {
		g := &grants[i]
		v := grantVerdict{expired: grantExpired(now, g)}
		v.reason, v.message = grantTarget(g, tags, sites)
		verdicts[g.Name] = v
		if v.expired || v.reason != "" {
			continue
		}
		dst := []string{g.Spec.Target.Tag}
		if g.Spec.Target.Tag == "" {
			dst = dst[:0]
			for _, p := range g.Spec.Target.Prefixes {
				dst = append(dst, string(p))
			}
		}
		in = append(in, policy.Grant{Sources: slices.Clone(g.Spec.Sources), Dst: dst, Ports: slices.Clone(g.Spec.Ports)})
	}
	return in, verdicts, nextExpiry(now, grants)
}

// grantTarget returns the reason and message of an invalid target, or "" when the grant may be
// rendered. A prefix is inside a site with the containment test of policy.ValidateFragment.
func grantTarget(g *tnv1.TailnetGrant, tags map[string]bool, sites []netip.Prefix) (string, string) {
	tn := g.Spec.TailnetRef.Name
	if tag := g.Spec.Target.Tag; tag != "" {
		if tags[tag] {
			return "", ""
		}
		return "TargetUnknown", fmt.Sprintf("target %s is neither the tag of a TailnetIngress bound to Tailnet %s nor an ingress tag of a merged spoke fragment; nothing is rendered for this grant", tag, tn)
	}
	var outside []string
	for _, raw := range g.Spec.Target.Prefixes {
		p, err := netip.ParsePrefix(string(raw))
		inside := false
		for _, s := range sites {
			if err == nil && s.Bits() <= p.Bits() && s.Contains(p.Addr()) {
				inside = true
				break
			}
		}
		if !inside {
			outside = append(outside, string(raw))
		}
	}
	if len(outside) > 0 || len(g.Spec.Target.Prefixes) == 0 {
		return "TargetOutsideSites", fmt.Sprintf("target prefixes %s lie in no unblocked TailnetSite of Tailnet %s; nothing is rendered for this grant", joinMax(outside, 5), tn)
	}
	return "", ""
}

// grantReason returns the Ready reason and message of a grant for the stage the reconcile reached,
// in the order of the rule. An expired grant that this generation already reported as Expired
// stays Expired when a later reconcile cannot compare the live policy: the operator never adds an
// expired grant back, so a failed or skipped write must not raise ExpiryPending for it again.
func grantReason(g *tnv1.TailnetGrant, v grantVerdict, stage grantStage, unknown []string) (string, string) {
	if stage == grantsNotWriter {
		return "NotPolicyWriter", fmt.Sprintf("Tailnet %s does not write the policy (mode Export or no base ConfigMap); a grant is rendered only by the Tailnet that owns the policy", g.Spec.TailnetRef.Name)
	}
	if v.expired {
		at := g.Spec.ExpiresAt.UTC().Format(time.RFC3339)
		c := findCond(g.Status.Conditions, "Ready")
		if stage == grantsLive || (c != nil && c.Reason == "Expired" && c.ObservedGeneration == g.Generation) {
			return "Expired", fmt.Sprintf("expired at %s; the live policy does not carry this grant", at)
		}
		return "ExpiryPending", fmt.Sprintf("expired at %s, but the live policy is not confirmed to have dropped this grant; see the PolicyRendered and PolicyApplied conditions of the Tailnet", at)
	}
	if v.reason != "" {
		return v.reason, v.message
	}
	var groups []string
	for _, s := range g.Spec.Sources {
		if strings.HasPrefix(s, "group:") && slices.Contains(unknown, s) {
			groups = append(groups, s)
		}
	}
	if len(groups) > 0 {
		sort.Strings(groups)
		rest := "the other sources stay granted"
		if len(groups) == len(g.Spec.Sources) {
			rest = "no source is left and nothing is rendered for this grant"
		}
		return "SourceGroupUnknown", fmt.Sprintf("source groups %v are not declared in the base policy groups; %s — these groups get access once the base declares them", groups, rest)
	}
	if stage != grantsLive {
		return "PolicyPending", "rendered, but the live policy does not equal the render; see the PolicyApplied condition of the Tailnet"
	}
	if g.Spec.ExpiresAt != nil {
		return "Granted", fmt.Sprintf("granted in the live policy until %s", g.Spec.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return "Granted", "granted in the live policy"
}

// boundGrants lists the TailnetGrants bound to the Tailnet, by name.
func (r *TailnetPolicyReconciler) boundGrants(ctx context.Context, tailnet string) ([]tnv1.TailnetGrant, error) {
	var list tnv1.TailnetGrantList
	if err := r.List(ctx, &list); err != nil {
		return nil, err
	}
	bound := list.Items[:0]
	for _, g := range list.Items {
		if g.Spec.TailnetRef.Name == tailnet && g.DeletionTimestamp.IsZero() {
			bound = append(bound, g)
		}
	}
	sort.Slice(bound, func(a, b int) bool { return bound[a].Name < bound[b].Name })
	return bound, nil
}

// grantStatus writes the Ready condition of every grant of the run. A reconcile that stopped before
// the render knows nothing about targets and sources: it touches only expired grants. Failures are
// logged; grant status must never fail the policy reconcile.
func (r *TailnetPolicyReconciler) grantStatus(ctx context.Context, run *grantRun) {
	for i := range run.grants {
		g := &run.grants[i]
		v, resolved := run.verdicts[g.Name]
		if !resolved {
			v = grantVerdict{expired: grantExpired(run.now, g)}
		}
		if run.stage == grantsNotRendered && !v.expired {
			continue
		}
		reason, msg := grantReason(g, v, run.stage, run.unknown)
		status := metav1.ConditionFalse
		if reason == "Granted" {
			status = metav1.ConditionTrue
		}
		if err := r.writeGrantStatus(ctx, g, func(t *tnv1.TailnetGrant) {
			t.Status.ObservedGeneration = t.Generation
			setCond(&t.Status.Conditions, t.Generation, "Ready", status, reason, msg)
		}); err != nil {
			log.FromContext(ctx).Error(err, "grant status not written", "grant", g.Name)
		}
	}
}

// writeGrantStatus applies mutate to a fresh copy and persists it only when the status changed, so
// the periodic policy reconcile does not rewrite N unchanged grants. A grant whose spec changed
// since the reconcile listed it is skipped: its change event reconciles the new generation.
func (r *TailnetPolicyReconciler) writeGrantStatus(ctx context.Context, seen *tnv1.TailnetGrant, mutate func(*tnv1.TailnetGrant)) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var g tnv1.TailnetGrant
		if err := r.Get(ctx, types.NamespacedName{Name: seen.Name}, &g); err != nil {
			if apierrors.IsNotFound(err) {
				r.Metrics.Delete("TailnetGrant", "", seen.Name)
			}
			return client.IgnoreNotFound(err)
		}
		if g.UID != seen.UID || g.Generation != seen.Generation {
			return nil
		}
		before := g.Status.DeepCopy()
		mutate(&g)
		if equality.Semantic.DeepEqual(before, &g.Status) {
			r.Metrics.Observe(&g)
			return nil
		}
		return updateObservedStatus(ctx, r.Client, r.Metrics, &g)
	})
}
