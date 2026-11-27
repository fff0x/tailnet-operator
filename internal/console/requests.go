package console

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// Access requests (plan 3b): a person asks for a grant or an extension, admins decide. The rule
// numbers refer to plans/KONSOLE.md, "Regeln 3b".
const (
	requestAnnotation    = "tsunaro.io/access-request"
	extendedByAnnotation = "tsunaro.io/extended-by"
	phasePending         = "Pending"
	phaseApproved        = "Approved"
	phaseRejected        = "Rejected"
	phaseWithdrawn       = "Withdrawn"
	requestedAsUser      = "User"
	requestedAsAdmin     = "Admin"
)

func phaseOf(req *tnv1.TailnetAccessRequest) string { return or(req.Status.Phase, phasePending) }

// identityOf is the session's provider identifier, the form requests and approvals record.
func identityOf(sess *session) string { return providerID(sess.Issuer, sess.Subject) }

func requestedAs(sess *session) string {
	if sess.Role == roleAdmin {
		return requestedAsAdmin
	}
	return requestedAsUser
}

// userOptions keeps the Tailnets whose Headscale knows ref, each with ref as its only
// recipient (rule 2).
func userOptions(opts []grantTailnet, ref string) []grantTailnet {
	var out []grantTailnet
	for _, gt := range opts {
		if i := slices.IndexFunc(gt.Recipients, func(r grantRecipient) bool { return r.Value == ref }); i >= 0 {
			gt.Recipients = []grantRecipient{gt.Recipients[i]}
			out = append(out, gt)
		}
	}
	return out
}

// approvalsNeeded follows rule 4; fourEyes is the setting when the decision is made.
func approvalsNeeded(spec tnv1.TailnetAccessRequestSpec, fourEyes bool) int {
	if spec.RequestedAs == requestedAsUser && fourEyes {
		return 2
	}
	return 1
}

// refusal tells why who, with role, may not take decision on req that approvers approved
// already (rules 5 and 6); "" allows it.
func refusal(req *tnv1.TailnetAccessRequest, decision, who, role string, approvers []string) string {
	if phaseOf(req) != phasePending {
		return "The request is already decided."
	}
	if decision == "withdraw" {
		if who != req.Spec.Requester {
			return "Only the requester withdraws a request."
		}
		return ""
	}
	switch {
	case role != roleAdmin:
		return "Only admins decide requests."
	case who == req.Spec.Requester:
		return "Nobody decides their own request."
	case decision == "approve" && slices.Contains(approvers, who):
		return "You already approved this request."
	}
	return ""
}

// decisionBy is one person's recorded approval or decision, from the audit log.
type decisionBy struct {
	ID, Name string
	At       time.Time
}

// requestHistory is what the audit log knows of one request: its approvals, whose last approval
// set out to write the grant, and who rejected, withdrew or closed it after that.
type requestHistory struct {
	Approvals []decisionBy
	Granted   *decisionBy
	Decided   *decisionBy
}

func (h requestHistory) approvers() []string {
	var out []string
	for _, a := range h.Approvals {
		out = append(out, a.ID)
	}
	return out
}

// histories reads every request's approvals from the audit entries (rules 15 and 16): its
// request.approve entries, one per person, the last approval and the last entry that ended it.
// Granted and Decided are for display only; nothing counts them.
func histories(entries []auditEntry) map[string]requestHistory {
	out := map[string]requestHistory{}
	for _, e := range entries {
		name, _ := e.Details["request"].(string)
		if name == "" || e.Actor == nil {
			continue
		}
		d := decisionBy{ID: providerID(e.Actor.Issuer, e.Actor.Subject), Name: e.Actor.Name, At: e.Time}
		h := out[name]
		switch e.Action {
		case "request.approve":
			if !slices.Contains(h.approvers(), d.ID) {
				h.Approvals = append(h.Approvals, d)
			}
		case "grant.create", "grant.extend":
			h.Granted, h.Decided = &d, nil
		case "request.close", "request.reject", "request.withdraw":
			h.Decided = &d
		default:
			continue
		}
		out[name] = h
	}
	return out
}

// applied tells whether g, the request's grant, carries its change already (rules 18 to 20).
func applied(req *tnv1.TailnetAccessRequest, g *tnv1.TailnetGrant) bool {
	if g == nil || g.Name != grantOf(req) || g.Labels[managedByLabel] != managedBy {
		return false
	}
	key := requestAnnotation
	if req.Spec.Action == "Extend" {
		key = extendedByAnnotation
	}
	return g.Annotations[key] == req.Name
}

// grantSpecFor checks a Create request against the current options and returns the grant it
// makes, expiring the request's duration after now (rules 7 and 8).
func grantSpecFor(spec tnv1.TailnetAccessRequestSpec, opts []grantTailnet, now time.Time) (tnv1.TailnetGrantSpec, bool) {
	if spec.Target == nil {
		return tnv1.TailnetGrantSpec{}, false
	}
	var prefixes, ports []string
	for _, p := range spec.Target.Prefixes {
		prefixes = append(prefixes, string(p))
	}
	for _, p := range spec.Ports {
		ports = append(ports, strconv.Itoa(int(p)))
	}
	f := grantForm{Ports: strings.Join(ports, ","), Prefixes: strings.Join(prefixes, ","), Sources: spec.Sources,
		Duration: string(spec.Duration), Description: spec.Description}
	for _, gt := range opts {
		if gt.Name != spec.TailnetRef.Name {
			continue
		}
		// A tag names one target; site prefixes may lie in any of the Tailnet's sites.
		for _, t := range gt.Targets {
			if t.Tag != spec.Target.Tag {
				continue
			}
			f.Target = t.Key
			if g, errs := buildGrantSpec(f, opts, now); len(errs) == 0 {
				return g, true
			}
		}
	}
	return tnv1.TailnetGrantSpec{}, false
}

// extendable tells whether a request may extend g (rules 3 and 8): a console grant of the
// request's Tailnet that, for a user, names the user alone.
func extendable(g *tnv1.TailnetGrant, tailnet, requester string, user bool) bool {
	return g.Labels[managedByLabel] == managedBy && g.Spec.TailnetRef.Name == tailnet &&
		(!user || slices.Equal(g.Spec.Sources, []string{requester + "@"}))
}

func createRequest(g tnv1.TailnetGrantSpec, duration, requester, as string) tnv1.TailnetAccessRequestSpec {
	target := g.Target
	return tnv1.TailnetAccessRequestSpec{TailnetRef: g.TailnetRef, Action: "Create", Requester: requester, RequestedAs: as,
		Sources: g.Sources, Target: &target, Ports: g.Ports, Duration: tnv1.AccessDuration(duration), Description: g.Description}
}

func grantDetails(spec tnv1.TailnetGrantSpec) map[string]any {
	d := map[string]any{"sources": spec.Sources, "ports": spec.Ports, "expiresAt": expiresText(spec.ExpiresAt)}
	if spec.Target.Tag != "" {
		d["tag"] = spec.Target.Tag
	} else {
		d["prefixes"] = spec.Target.Prefixes
	}
	if spec.Description != "" {
		d["description"] = spec.Description
	}
	return d
}

func requestDetails(req *tnv1.TailnetAccessRequest) map[string]any {
	d := map[string]any{}
	if t := req.Spec.Target; t != nil {
		d = grantDetails(tnv1.TailnetGrantSpec{Sources: req.Spec.Sources, Target: *t, Ports: req.Spec.Ports, Description: req.Spec.Description})
		delete(d, "expiresAt")
	}
	d["request"], d["requestedAs"], d["duration"] = req.Name, req.Spec.RequestedAs, string(req.Spec.Duration)
	return d
}

// grantOf is the grant a request creates or extends.
func grantOf(req *tnv1.TailnetAccessRequest) string {
	if req.Spec.Action == "Extend" {
		return req.Spec.GrantName
	}
	return "console-" + strings.TrimPrefix(req.Name, "request-")
}

// submitRequest records and creates a request (rule 9). A Create names its future grant with the
// same suffix.
func (s *Server) submitRequest(w http.ResponseWriter, r *http.Request, sess *session, spec tnv1.TailnetAccessRequestSpec) {
	if spec.Requester == "" {
		s.message(w, r, http.StatusForbidden, "No identity", "The sign-in gave no issuer and subject, so the console cannot name you in a request.")
		return
	}
	req := &tnv1.TailnetAccessRequest{ObjectMeta: metav1.ObjectMeta{Name: "request-" + nameSuffix()}, Spec: spec}
	e := auditEntry{Action: "request.create", Actor: actorOf(sess), Grant: grantOf(req), Tailnet: spec.TailnetRef.Name, Details: requestDetails(req)}
	if s.change(w, r, e, func() error { return s.writer.Create(r.Context(), req) }) {
		http.Redirect(w, r, "/requests", http.StatusSeeOther)
	}
}

// people names the persons a Tailnet's Headscale knows, by provider identifier. Without the
// directory it names nobody.
func (s *Server) people(ctx context.Context, cache map[string]map[string]string, tn string) map[string]string {
	if names, ok := cache[tn]; ok {
		return names
	}
	names := map[string]string{}
	if data, err := s.dir.get(ctx, tn); err == nil {
		for _, u := range data.Users {
			if u.ProviderID != "" {
				names[u.ProviderID] = or(u.DisplayName, u.Name)
			}
		}
	}
	cache[tn] = names
	return names
}

// pending counts the undecided requests by Tailnet.
func (s *Server) pending(ctx context.Context) (map[string]int, error) {
	var list tnv1.TailnetAccessRequestList
	if err := s.writer.List(ctx, &list); err != nil {
		return nil, err
	}
	out := map[string]int{}
	for i := range list.Items {
		if phaseOf(&list.Items[i]) == phasePending {
			out[list.Items[i].Spec.TailnetRef.Name]++
		}
	}
	return out, nil
}

type requestRow struct {
	Name, Tailnet, Action, Grant, Duration, Description string
	Requester, RequestedAs, Created, Phase, Decided     string
	Target, Ports, Recipients, Approvals                []string
	Count, Needed                                       int
	Applied, Approve, Reject, Withdraw                  bool
}

type requestsBody struct {
	Rows      []requestRow
	Grants    []grantRow
	Admin     bool
	FourEyes  bool
	Durations any
}

func durationLabel(v string) string {
	for _, d := range grantDurations {
		if d.Value == v {
			return d.Label
		}
	}
	return v
}

// requestsPage shows a user their requests and grants, an admin every request (rule 11). Only
// admins see who approved and decided (rule 17).
func (s *Server) requestsPage(w http.ResponseWriter, r *http.Request, sess *session) {
	ctx := r.Context()
	var list tnv1.TailnetAccessRequestList
	if err := s.writer.List(ctx, &list); err != nil {
		s.log.Info("request list failed")
		s.message(w, r, http.StatusServiceUnavailable, "Requests unavailable", "The console cannot read the requests right now.")
		return
	}
	hist, ok := s.readHistories(w, r)
	if !ok {
		return
	}
	var grants tnv1.TailnetGrantList
	if err := s.writer.List(ctx, &grants, client.MatchingLabels{managedByLabel: managedBy}); err != nil {
		s.log.Info("grant list failed")
	}
	byName := map[string]*tnv1.TailnetGrant{}
	for i := range grants.Items {
		byName[grants.Items[i].Name] = &grants.Items[i]
	}
	me, admin := identityOf(sess), sess.Role == roleAdmin
	when := func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }
	names := map[string]map[string]string{}
	body := requestsBody{Admin: admin, FourEyes: s.fourEyes, Durations: grantDurations}
	for i := range list.Items {
		req := &list.Items[i]
		if !admin && req.Spec.Requester != me {
			continue
		}
		tn := req.Spec.TailnetRef.Name
		who := s.people(ctx, names, tn)
		person := func(id string) string { return or(who[id], id) }
		row := requestRow{Name: req.Name, Tailnet: tn, Action: req.Spec.Action, Grant: grantOf(req), Description: req.Spec.Description,
			Duration: durationLabel(string(req.Spec.Duration)), Requester: person(req.Spec.Requester), RequestedAs: req.Spec.RequestedAs,
			Phase: phaseOf(req), Ports: tcpPorts(req.Spec.Ports), Needed: approvalsNeeded(req.Spec, s.fourEyes)}
		if !req.CreationTimestamp.IsZero() {
			row.Created = req.CreationTimestamp.UTC().Format("2006-01-02 15:04 UTC")
		}
		if t := req.Spec.Target; t != nil {
			if t.Tag != "" {
				row.Target = []string{t.Tag}
			}
			for _, p := range t.Prefixes {
				row.Target = append(row.Target, string(p))
			}
		}
		for _, src := range req.Spec.Sources {
			if n := who[strings.TrimSuffix(src, "@")]; n != "" {
				src = n + " (" + src + ")"
			}
			row.Recipients = append(row.Recipients, src)
		}
		h := hist[req.Name]
		row.Count = len(h.Approvals)
		row.Applied = row.Phase == phasePending && applied(req, byName[grantOf(req)])
		if admin {
			name := func(d decisionBy) string { return or(who[d.ID], or(d.Name, d.ID)) + " · " + when(d.At) }
			for _, a := range h.Approvals {
				row.Approvals = append(row.Approvals, name(a))
			}
			// The last approver counts once the grant is written; a later closing is named apart.
			written := row.Phase == phaseApproved || row.Applied
			if g := h.Granted; g != nil && written && !slices.Contains(h.approvers(), g.ID) {
				row.Approvals = append(row.Approvals, name(*g))
			}
			switch d := h.Decided; {
			case d == nil || row.Phase == phasePending:
			case row.Phase == phaseApproved:
				row.Decided = "closed by " + name(*d)
			default:
				row.Decided = "by " + name(*d)
			}
		} else if req.Status.DecidedAt != nil {
			row.Decided = when(req.Status.DecidedAt.Time)
		}
		approvers := h.approvers()
		if row.Applied {
			approvers = nil
		}
		row.Approve = refusal(req, "approve", me, sess.Role, approvers) == ""
		row.Reject = !row.Applied && refusal(req, "reject", me, sess.Role, approvers) == ""
		row.Withdraw = !row.Applied && refusal(req, "withdraw", me, sess.Role, approvers) == ""
		body.Rows = append(body.Rows, row)
	}
	// Undecided first, then newest first.
	slices.SortStableFunc(body.Rows, func(a, b requestRow) int {
		if (a.Phase == phasePending) != (b.Phase == phasePending) {
			if a.Phase == phasePending {
				return -1
			}
			return 1
		}
		if c := strings.Compare(b.Created, a.Created); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	if !admin {
		now := s.now()
		for i := range grants.Items {
			g := &grants.Items[i]
			if extendable(g, g.Spec.TailnetRef.Name, me, true) {
				body.Grants = append(body.Grants, grantRowOf(g, nil, now))
			}
		}
		slices.SortFunc(body.Grants, func(a, b grantRow) int { return strings.Compare(a.Name, b.Name) })
	}
	s.render(w, http.StatusOK, "requests", page{Title: "Requests", Session: sess, Body: body})
}

func (s *Server) requestForm(sess *session) grantNewBody {
	return grantNewBody{Path: "/requests", Self: true, FourEyes: s.fourEyes, Admin: sess.Role == roleAdmin, Durations: grantDurations}
}

func (s *Server) requestNewPage(w http.ResponseWriter, r *http.Request, sess *session) {
	opts, err := s.grantOptions(r.Context())
	if err != nil {
		s.message(w, r, http.StatusServiceUnavailable, "Requests unavailable", "The console cannot read the cluster state right now.")
		return
	}
	body := s.requestForm(sess)
	body.Tailnets = userOptions(opts, identityOf(sess)+"@")
	s.prefill(&body, r.URL.Query().Get("target"))
	s.render(w, http.StatusOK, "grant_new", page{Title: "New request", Session: sess, Body: body})
}

// requestCreate takes a request for the signed-in person alone (rule 2).
func (s *Server) requestCreate(w http.ResponseWriter, r *http.Request, sess *session) {
	f, ok := s.readGrantForm(w, r)
	if !ok {
		return
	}
	opts, err := s.grantOptions(r.Context())
	if err != nil {
		s.message(w, r, http.StatusServiceUnavailable, "Requests unavailable", "The console cannot read the cluster state right now.")
		return
	}
	me := identityOf(sess)
	opts = userOptions(opts, me+"@")
	f.Sources = []string{me + "@"}
	spec, errs := buildGrantSpec(f, opts, s.now())
	if len(errs) > 0 {
		body := s.requestForm(sess)
		body.Tailnets, body.Form, body.Errors = opts, f, errs
		body.Tailnet, body.Target = findTarget(opts, f.Target)
		s.render(w, http.StatusBadRequest, "grant_new", page{Title: "New request", Session: sess, Body: body})
		return
	}
	s.submitRequest(w, r, sess, createRequest(spec, f.Duration, me, requestedAs(sess)))
}

// requestExtend asks to extend a console grant that names the user alone (rule 3).
func (s *Server) requestExtend(w http.ResponseWriter, r *http.Request, sess *session) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if r.ParseForm() != nil {
		s.message(w, r, http.StatusBadRequest, "Invalid form", "The form could not be read.")
		return
	}
	d := r.PostForm.Get("duration")
	if _, ok := durationOf(d); !ok {
		s.message(w, r, http.StatusBadRequest, "Invalid duration", "Choose a duration from the list.")
		return
	}
	g := s.managedGrant(w, r)
	if g == nil {
		return
	}
	me := identityOf(sess)
	if !extendable(g, g.Spec.TailnetRef.Name, me, sess.Role != roleAdmin) {
		s.message(w, r, http.StatusForbidden, "Not your grant", "You may ask to extend only a console grant that names you alone.")
		return
	}
	s.submitRequest(w, r, sess, extendRequest(g, d, me, requestedAs(sess)))
}

func extendRequest(g *tnv1.TailnetGrant, duration, requester, as string) tnv1.TailnetAccessRequestSpec {
	return tnv1.TailnetAccessRequestSpec{TailnetRef: g.Spec.TailnetRef, Action: "Extend", GrantName: g.Name,
		Requester: requester, RequestedAs: as, Duration: tnv1.AccessDuration(duration)}
}

// readHistories reads the requests' approvals from the audit log; without it nothing is shown or
// decided (rule 16).
func (s *Server) readHistories(w http.ResponseWriter, r *http.Request) (map[string]requestHistory, bool) {
	// ponytail: every request page and decision reads and hashes the whole log, linear in its
	// size; an index of the request entries would bound it once logs grow past a few hundred MB.
	st := s.audit.state(r.Context())
	if st.Err != nil {
		s.log.Error(st.Err, "audit check failed")
		s.message(w, r, http.StatusServiceUnavailable, "Requests unavailable",
			"The console cannot read its audit log, which keeps the approvals. Check the audit volume and the anchor ConfigMap.")
		return nil, false
	}
	s.breaks.Store(int64(len(st.Breaks)))
	return histories(st.Entries), true
}

// decide approves, rejects or withdraws a request (rules 4 to 9 and 15 to 21). One decision runs
// at a time; the status update carries the resourceVersion it read, so another replica's
// decision conflicts.
func (s *Server) decide(decision string) func(http.ResponseWriter, *http.Request, *session) {
	return func(w http.ResponseWriter, r *http.Request, sess *session) {
		me := identityOf(sess)
		if me == "" {
			s.message(w, r, http.StatusForbidden, "No identity", "The sign-in gave no issuer and subject, so the console cannot record your decision.")
			return
		}
		s.decisions.Lock()
		defer s.decisions.Unlock()
		ctx := r.Context()
		var req tnv1.TailnetAccessRequest
		err := s.writer.Get(ctx, client.ObjectKey{Name: r.PathValue("name")}, &req)
		if apierrors.IsNotFound(err) || (err == nil && sess.Role != roleAdmin && req.Spec.Requester != me) {
			s.message(w, r, http.StatusNotFound, "No such request", "The request does not exist.")
			return
		}
		if err != nil {
			s.message(w, r, http.StatusServiceUnavailable, "Requests unavailable", "The console cannot read the request right now.")
			return
		}
		hist, ok := s.readHistories(w, r)
		if !ok {
			return
		}
		var g *tnv1.TailnetGrant
		if phaseOf(&req) == phasePending {
			var have tnv1.TailnetGrant
			if err := s.writer.Get(ctx, client.ObjectKey{Name: grantOf(&req)}, &have); err == nil {
				g = &have
			} else if !apierrors.IsNotFound(err) {
				s.message(w, r, http.StatusServiceUnavailable, "Requests unavailable", "The console cannot read the grant right now.")
				return
			}
		}
		now := s.now().UTC().Truncate(time.Second)
		e := auditEntry{Actor: actorOf(sess), Grant: grantOf(&req), Tailnet: req.Spec.TailnetRef.Name, Details: map[string]any{"request": req.Name}}
		update := func() error { return s.writer.Status().Update(ctx, &req) }
		approvers := hist[req.Name].approvers()
		if applied(&req, g) {
			// Rule 19: the grant was written, the request not closed. Only approving closes it.
			if decision != "approve" {
				s.message(w, r, http.StatusConflict, "Request not changed",
					"Its grant is written already. Approve to close the request; revoke the grant to take the access back.")
				return
			}
			approvers = nil
		}
		if why := refusal(&req, decision, me, sess.Role, approvers); why != "" {
			s.message(w, r, http.StatusConflict, "Request not changed", why)
			return
		}
		switch {
		case applied(&req, g):
			req.Status.Phase, req.Status.DecidedAt, req.Status.GrantName = phaseApproved, &metav1.Time{Time: now}, g.Name
			e.Action = "request.close"
		case decision == "approve":
			needed := approvalsNeeded(req.Spec, s.fourEyes)
			if len(approvers)+1 >= needed {
				s.approve(w, r, sess, &req, append(approvers, me), now)
				return
			}
			// A partial approval lives in the audit log alone (rule 16).
			e.Action, update = "request.approve", func() error { return nil }
			e.Details["approvals"], e.Details["needed"] = len(approvers)+1, needed
		case decision == "reject":
			req.Status.Phase, req.Status.DecidedAt, e.Action = phaseRejected, &metav1.Time{Time: now}, "request.reject"
		default:
			req.Status.Phase, req.Status.DecidedAt, e.Action = phaseWithdrawn, &metav1.Time{Time: now}, "request.withdraw"
		}
		if s.change(w, r, e, update) {
			http.Redirect(w, r, "/requests", http.StatusSeeOther)
		}
	}
}

// approve makes the last approval: it checks the request against the current state, records the
// grant change with requester and approvers, makes it with the request's annotation and closes
// the request (rules 7 to 9 and 18).
func (s *Server) approve(w http.ResponseWriter, r *http.Request, sess *session, req *tnv1.TailnetAccessRequest, approvers []string, now time.Time) {
	ctx := r.Context()
	user := req.Spec.RequestedAs == requestedAsUser
	details := map[string]any{"request": req.Name, "requester": req.Spec.Requester, "approvers": approvers}
	stale := func(why string) {
		s.message(w, r, http.StatusConflict, "Request no longer valid", why+" Reject the request; the requester may ask again.")
	}
	req.Status.Phase, req.Status.DecidedAt = phaseApproved, &metav1.Time{Time: now}
	req.Status.GrantName = grantOf(req)
	e := auditEntry{Actor: actorOf(sess), Grant: req.Status.GrantName, Tailnet: req.Spec.TailnetRef.Name, Details: details}
	var apply func() error
	if req.Spec.Action == "Create" {
		opts, err := s.grantOptions(ctx)
		if err != nil {
			s.message(w, r, http.StatusServiceUnavailable, "Requests unavailable", "The console cannot read the cluster state right now.")
			return
		}
		if user {
			opts = userOptions(opts, req.Spec.Requester+"@")
		}
		spec, ok := grantSpecFor(req.Spec, opts, now)
		if !ok {
			stale("The tailnet no longer offers this target, these ports or these recipients.")
			return
		}
		g := &tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Name: req.Status.GrantName, Labels: map[string]string{managedByLabel: managedBy},
			Annotations: map[string]string{requestAnnotation: req.Name}}, Spec: spec}
		maps.Copy(details, grantDetails(spec))
		e.Action = "grant.create"
		apply = func() error {
			if err := s.writer.Create(ctx, g); err != nil {
				return err
			}
			return s.writer.Status().Update(ctx, req)
		}
	} else {
		var g tnv1.TailnetGrant
		if err := s.writer.Get(ctx, client.ObjectKey{Name: req.Spec.GrantName}, &g); apierrors.IsNotFound(err) {
			stale("The grant no longer exists.")
			return
		} else if err != nil {
			s.message(w, r, http.StatusServiceUnavailable, "Requests unavailable", "The console cannot read the grant right now.")
			return
		}
		if !extendable(&g, req.Spec.TailnetRef.Name, req.Spec.Requester, user) {
			stale("The grant is no longer a console grant of this tailnet that names the requester alone.")
			return
		}
		d, _ := durationOf(string(req.Spec.Duration))
		var next *metav1.Time
		if d > 0 {
			next = &metav1.Time{Time: now.Add(d)}
		}
		details["from"], details["to"] = expiresText(g.Spec.ExpiresAt), expiresText(next)
		e.Action = "grant.extend"
		orig := g.DeepCopy()
		g.Spec.ExpiresAt = next
		metav1.SetMetaDataAnnotation(&g.ObjectMeta, extendedByAnnotation, req.Name)
		apply = func() error {
			if err := s.writer.Patch(ctx, &g, client.MergeFrom(orig)); err != nil {
				return err
			}
			return s.writer.Status().Update(ctx, req)
		}
	}
	if s.change(w, r, e, apply) {
		http.Redirect(w, r, "/requests", http.StatusSeeOther)
	}
}
