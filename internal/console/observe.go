package console

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

const (
	actionObserved = "grant.observed"
	actionExpired  = "grant.expired"
)

// grantState is what the audit log knows of a grant (rule 22).
type grantState struct {
	Tailnet     string   `json:"tailnet,omitempty"`
	Sources     []string `json:"sources,omitempty"`
	Tag         string   `json:"tag,omitempty"`
	Prefixes    []string `json:"prefixes,omitempty"`
	Ports       []int32  `json:"ports,omitempty"`
	ExpiresAt   string   `json:"expiresAt,omitempty"`
	Description string   `json:"description,omitempty"`
	Managed     bool     `json:"managed"`
}

func (g grantState) key() string {
	slices.Sort(g.Sources)
	slices.Sort(g.Prefixes)
	slices.Sort(g.Ports)
	b, _ := json.Marshal(g)
	return string(b)
}

func stateOf(g *tnv1.TailnetGrant) grantState {
	st := grantState{Tailnet: g.Spec.TailnetRef.Name, Sources: slices.Clone(g.Spec.Sources), Tag: g.Spec.Target.Tag,
		Ports: slices.Clone(g.Spec.Ports), ExpiresAt: expiresText(g.Spec.ExpiresAt), Description: g.Spec.Description,
		Managed: g.Labels[managedByLabel] == managedBy}
	for _, p := range g.Spec.Target.Prefixes {
		st.Prefixes = append(st.Prefixes, string(p))
	}
	return st
}

// details is the entry's record of the state; the tailnet is in the entry itself.
func (g grantState) details() map[string]any {
	d := map[string]any{"sources": g.Sources, "ports": g.Ports, "expiresAt": g.ExpiresAt, "managed": g.Managed}
	if g.Tag != "" {
		d["tag"] = g.Tag
	} else {
		d["prefixes"] = g.Prefixes
	}
	if g.Description != "" {
		d["description"] = g.Description
	}
	return d
}

func stateFrom(e auditEntry) grantState {
	var st grantState
	b, _ := json.Marshal(e.Details)
	_ = json.Unmarshal(b, &st)
	st.Tailnet = e.Tailnet
	return st
}

// knownGrants replays the log (rule 24): the state of every grant it knows, and the expiresAt
// values whose expiry it recorded (rule 26).
func knownGrants(entries []auditEntry) (map[string]grantState, map[string]map[string]bool) {
	known := map[string]grantState{}
	expired := map[string]map[string]bool{}
	type undo struct {
		action string
		had    bool
		state  grantState
	}
	last := map[string]undo{} // the state before the latest change of each grant
	for _, e := range entries {
		if e.Grant == "" {
			continue
		}
		old, had := known[e.Grant]
		switch e.Action {
		case "grant.create", "grant.extend", "grant.revoke", "grant.delete", actionObserved:
			last[e.Grant] = undo{action: e.Action, had: had, state: old}
		}
		switch e.Action {
		case "grant.create":
			st := stateFrom(e)
			st.Managed = true
			known[e.Grant] = st
		case "grant.extend", "grant.revoke":
			if to, ok := e.Details["to"].(string); ok && had {
				old.ExpiresAt = to
				known[e.Grant] = old
			}
		case "grant.delete":
			delete(known, e.Grant)
		case actionObserved:
			if e.Details["change"] == "deleted" {
				delete(known, e.Grant)
			} else {
				known[e.Grant] = stateFrom(e)
			}
		case actionExpired:
			at, _ := e.Details["expiresAt"].(string)
			if expired[e.Grant] == nil {
				expired[e.Grant] = map[string]bool{}
			}
			expired[e.Grant][at] = true
		case actionFailed:
			if u, ok := last[e.Grant]; ok && e.Details["action"] == u.action {
				if u.had {
					known[e.Grant] = u.state
				} else {
					delete(known, e.Grant)
				}
				delete(last, e.Grant)
			}
		}
	}
	return known, expired
}

// reportedExpired: the operator has confirmed for this generation that the live policy no longer
// carries the grant.
func reportedExpired(g *tnv1.TailnetGrant) bool {
	c := meta.FindStatusCondition(g.Status.Conditions, "Ready")
	return g.Spec.ExpiresAt != nil && c != nil && c.Status == metav1.ConditionFalse && c.Reason == "Expired" &&
		c.ObservedGeneration == g.Generation
}

// Observe compares the grants with the audit log every interval and, with a retention, deletes
// what is done once an hour (rules 22 to 35). Without access management it does nothing.
func (s *Server) Observe(ctx context.Context, every time.Duration) {
	if s.audit == nil {
		return
	}
	// ponytail: every run reads and hashes the whole log, linear in its size, like WatchAudit.
	t := time.NewTicker(every)
	defer t.Stop()
	var cleaned time.Time
	for {
		s.round(ctx, &cleaned)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// round is one run of Observe. It holds both locks, so no decision and no change runs between an
// audit entry and its write (rule 27); cleaned is when the last cleanup ran.
func (s *Server) round(ctx context.Context, cleaned *time.Time) {
	s.decisions.Lock()
	defer s.decisions.Unlock()
	s.changes.Lock()
	defer s.changes.Unlock()
	if s.observe(ctx) && s.retention > 0 && s.now().Sub(*cleaned) >= time.Hour {
		s.cleanup(ctx)
		*cleaned = s.now()
	}
}

// observe records every grant change the log does not know and every expiry the operator
// confirmed. It reports whether the run completed. Call with s.changes held.
func (s *Server) observe(ctx context.Context) bool {
	st := s.audit.state(ctx)
	if st.Err != nil {
		s.log.Error(st.Err, "audit check failed; nothing observed")
		return false
	}
	s.breaks.Store(int64(len(st.Breaks)))
	var list tnv1.TailnetGrantList
	if err := s.writer.List(ctx, &list); err != nil {
		s.log.Info("grant list failed; nothing observed")
		return false
	}
	known, expired := knownGrants(st.Entries)
	n := 0
	write := func(e auditEntry) bool {
		if err := s.audit.append(ctx, e); err != nil {
			s.log.Error(err, "audit write failed; observation stopped", "action", e.Action)
			return false
		}
		n++
		return true
	}
	defer func() {
		if n > 0 {
			s.log.Info("grant changes observed", "entries", n)
		}
	}()
	seen := map[string]bool{}
	slices.SortFunc(list.Items, func(a, b tnv1.TailnetGrant) int { return strings.Compare(a.Name, b.Name) })
	for i := range list.Items {
		g := &list.Items[i]
		seen[g.Name] = true
		cur := stateOf(g)
		if old, ok := known[g.Name]; !ok || old.key() != cur.key() {
			d := cur.details()
			d["change"] = "created"
			if ok {
				d["change"] = "changed"
			}
			if !write(auditEntry{Action: actionObserved, Grant: g.Name, Tailnet: cur.Tailnet, Details: d}) {
				return false
			}
		}
		if at := expiresText(g.Spec.ExpiresAt); reportedExpired(g) && !expired[g.Name][at] {
			if !write(auditEntry{Action: actionExpired, Grant: g.Name, Tailnet: cur.Tailnet, Details: map[string]any{"expiresAt": at}}) {
				return false
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(known)) {
		if seen[name] {
			continue
		}
		old := known[name]
		d := old.details()
		d["change"] = "deleted"
		if !write(auditEntry{Action: actionObserved, Grant: name, Tailnet: old.Tailnet, Details: d}) {
			return false
		}
	}
	return true
}

// cleanup deletes expired console grants and decided requests after the retention and expires
// pending requests (rules 30 to 35). The first failure ends the run. Call with s.decisions and
// s.changes held.
func (s *Server) cleanup(ctx context.Context) {
	now := s.now().UTC().Truncate(time.Second)
	cutoff := now.Add(-time.Duration(s.retention) * 24 * time.Hour)
	var grants tnv1.TailnetGrantList
	var reqs tnv1.TailnetAccessRequestList
	if err := s.writer.List(ctx, &grants); err != nil {
		s.log.Info("grant list failed; nothing cleaned up")
		return
	}
	if err := s.writer.List(ctx, &reqs); err != nil {
		s.log.Info("request list failed; nothing cleaned up")
		return
	}
	run := func(e auditEntry, apply func() error) bool {
		if e.Details == nil {
			e.Details = map[string]any{}
		}
		e.Details["retentionDays"] = s.retention
		if _, err := s.commit(ctx, e, apply); err != nil {
			s.log.Info("cleanup stopped until the next hour", "action", e.Action)
			return false
		}
		return true
	}
	byName := map[string]*tnv1.TailnetGrant{}
	for i := range grants.Items {
		g := &grants.Items[i]
		byName[g.Name] = g
		if g.Labels[managedByLabel] != managedBy || !reportedExpired(g) || g.Spec.ExpiresAt.After(cutoff) {
			continue
		}
		rv := g.ResourceVersion
		e := auditEntry{Action: "grant.delete", Grant: g.Name, Tailnet: g.Spec.TailnetRef.Name, Details: stateOf(g).details()}
		if !run(e, func() error { return s.writer.Delete(ctx, g, client.Preconditions{ResourceVersion: &rv}) }) {
			return
		}
	}
	for i := range reqs.Items {
		req := &reqs.Items[i]
		e := auditEntry{Grant: grantOf(req), Tailnet: req.Spec.TailnetRef.Name, Details: requestDetails(req)}
		e.Details["requester"] = req.Spec.Requester
		var apply func() error
		switch {
		case phaseOf(req) == phasePending:
			if req.CreationTimestamp.IsZero() || req.CreationTimestamp.After(cutoff) || applied(req, byName[grantOf(req)]) {
				continue
			}
			req.Status.Phase, req.Status.DecidedAt = phaseExpired, &metav1.Time{Time: now}
			e.Action, apply = "request.expire", func() error { return s.writer.Status().Update(ctx, req) }
		case req.Status.DecidedAt != nil && !req.Status.DecidedAt.After(cutoff):
			rv := req.ResourceVersion
			e.Details["phase"], e.Details["decidedAt"] = req.Status.Phase, req.Status.DecidedAt.UTC().Format(time.RFC3339)
			e.Action, apply = "request.delete", func() error { return s.writer.Delete(ctx, req, client.Preconditions{ResourceVersion: &rv}) }
		default:
			continue
		}
		if !run(e, apply) {
			return
		}
	}
}
