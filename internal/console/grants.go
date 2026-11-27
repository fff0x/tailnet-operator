package console

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// managedBy marks the grants the console created; it changes no other grant (rule 7).
const (
	managedByLabel = "app.kubernetes.io/managed-by"
	managedBy      = "tailnet-console"
	maxListItems   = 16 // sources, ports and prefixes, as the CRD allows
)

// grantDurations are the only lifetimes the console offers (rule 6); 0 is permanent.
var grantDurations = []struct {
	Value, Label string
	D            time.Duration
}{
	{"1h", "1 hour", time.Hour}, {"8h", "8 hours", 8 * time.Hour}, {"24h", "24 hours", 24 * time.Hour},
	{"7d", "7 days", 7 * 24 * time.Hour}, {"30d", "30 days", 30 * 24 * time.Hour}, {"permanent", "Permanent", 0},
}

// grantTarget is one destination a grant may name (rule 3). Key is the form value.
type grantTarget struct {
	Key, Tailnet, Label string
	Tag                 string   // ingress or spoke tag; empty for a site
	Site                []string // the site's prefixes, within which the grant's prefixes must lie
	Ports               []int32  // the target's current ports, the form's default (rule 4)
}

type grantRecipient struct{ Value, Label string }

// grantTailnet is what a grant on one policy-owning Tailnet may name.
type grantTailnet struct {
	Name       string
	Targets    []grantTarget
	Recipients []grantRecipient
	Problem    bool // the console API gave no users or policy: no recipients, no spoke tags
}

// grantOptions lists every Tailnet that owns its policy with its targets and recipients. The form
// and the check of a submitted form use the same list (rule 9).
func (s *Server) grantOptions(ctx context.Context) ([]grantTailnet, error) {
	var tns tnv1.TailnetList
	var ins tnv1.TailnetIngressList
	var sites tnv1.TailnetSiteList
	if err := s.reader.List(ctx, &tns); err != nil {
		return nil, err
	}
	if err := s.reader.List(ctx, &ins); err != nil {
		return nil, err
	}
	if err := s.reader.List(ctx, &sites); err != nil {
		return nil, err
	}
	var out []grantTailnet
	for i := range tns.Items {
		tn := &tns.Items[i]
		if m := policyMode(tn); m != "DryRun" && m != "Apply" {
			continue
		}
		data, err := s.dir.get(ctx, tn.Name)
		groups, rules, perr := parseLive(data.Policy)
		gt := grantTailnet{Name: tn.Name, Problem: err != nil || perr != nil}
		if gt.Problem {
			data, groups, rules = tailnetData{}, nil, nil
		}
		hubTags := map[string]bool{}
		for _, in := range ins.Items {
			if in.Spec.TailnetRef.Name != tn.Name || in.Status.Tag == "" {
				continue
			}
			hubTags[in.Status.Tag] = true
			var ports []int32
			for _, e := range in.Spec.Exposes {
				ports = append(ports, e.Port)
			}
			gt.Targets = append(gt.Targets, grantTarget{Key: tn.Name + "/ingress/" + in.Namespace + "/" + in.Name, Tailnet: tn.Name,
				Label: "ingress " + in.Namespace + "/" + in.Name + " (" + in.Status.Tag + ")", Tag: in.Status.Tag, Ports: ports})
		}
		for _, st := range spokeTags(tn, hubTags, data, rules) {
			gt.Targets = append(gt.Targets, grantTarget{Key: tn.Name + "/spoke/" + st.tag, Tailnet: tn.Name,
				Label: "spoke " + st.spoke + " " + st.tag, Tag: st.tag, Ports: tcpPortNumbers(st.ports)})
		}
		for _, st := range sites.Items {
			if st.Spec.TailnetRef.Name != tn.Name || len(st.Spec.Prefixes) == 0 {
				continue
			}
			var ps []string
			for _, p := range st.Spec.Prefixes {
				ps = append(ps, string(p))
			}
			gt.Targets = append(gt.Targets, grantTarget{Key: tn.Name + "/site/" + st.Name, Tailnet: tn.Name,
				Label: "site " + st.Name + " (" + strings.Join(ps, ", ") + ")", Site: ps})
		}
		slices.SortFunc(gt.Targets, func(a, b grantTarget) int { return strings.Compare(a.Key, b.Key) })
		for _, u := range data.Users {
			// The CRD takes a reference with exactly one "@" and no space, of at most 512 bytes.
			if u.ProviderID == "" || strings.ContainsAny(u.ProviderID, "@ \t\r\n") || len(u.ProviderID) >= 512 {
				continue
			}
			label := or(u.DisplayName, u.Name)
			if u.Email != "" {
				label += " · " + u.Email
			}
			gt.Recipients = append(gt.Recipients, grantRecipient{Value: u.ProviderID + "@", Label: label})
		}
		slices.SortFunc(gt.Recipients, func(a, b grantRecipient) int { return strings.Compare(a.Label, b.Label) })
		var names []string
		for g := range groups {
			names = append(names, g)
		}
		slices.Sort(names)
		for _, g := range names {
			gt.Recipients = append(gt.Recipients, grantRecipient{Value: g, Label: g})
		}
		out = append(out, gt)
	}
	slices.SortFunc(out, func(a, b grantTailnet) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// tcpPortNumbers keeps the single TCP ports of rule port strings ("tcp:5432", "5432").
func tcpPortNumbers(ports []string) []int32 {
	var out []int32
	for _, p := range ports {
		if n, err := strconv.ParseUint(strings.TrimPrefix(p, "tcp:"), 10, 16); err == nil && n > 0 {
			out = append(out, int32(n))
		}
	}
	return out
}

func findTarget(opts []grantTailnet, key string) (*grantTailnet, *grantTarget) {
	for i := range opts {
		for j := range opts[i].Targets {
			if opts[i].Targets[j].Key == key {
				return &opts[i], &opts[i].Targets[j]
			}
		}
	}
	return nil, nil
}

// grantForm is a submitted or prefilled form; the page shows it again with its errors.
type grantForm struct {
	Target      string
	Ports       string
	Prefixes    string
	Sources     []string
	Duration    string
	Description string
}

func durationOf(v string) (time.Duration, bool) {
	for _, d := range grantDurations {
		if d.Value == v {
			return d.D, true
		}
	}
	return 0, false
}

// buildGrantSpec checks a form against rules 2 to 6 and returns the spec it may write (rule 9).
func buildGrantSpec(f grantForm, opts []grantTailnet, now time.Time) (tnv1.TailnetGrantSpec, []string) {
	var spec tnv1.TailnetGrantSpec
	var errs []string
	gt, target := findTarget(opts, f.Target)
	if target == nil {
		return spec, []string{"Choose a target from the list."}
	}
	spec.TailnetRef = tnv1.TailnetRef{Name: gt.Name}
	if target.Tag != "" {
		spec.Target.Tag = target.Tag
	} else {
		ps, err := parsePrefixes(f.Prefixes, target.Site)
		if err != "" {
			errs = append(errs, err)
		}
		spec.Target.Prefixes = ps
	}
	ports, err := parsePorts(f.Ports)
	if err != "" {
		errs = append(errs, err)
	}
	spec.Ports = ports
	allowed := map[string]bool{}
	for _, r := range gt.Recipients {
		allowed[r.Value] = true
	}
	for _, src := range f.Sources {
		if !allowed[src] {
			errs = append(errs, "Choose recipients from the list.")
			break
		}
		if !slices.Contains(spec.Sources, src) {
			spec.Sources = append(spec.Sources, src)
		}
	}
	slices.Sort(spec.Sources)
	if len(spec.Sources) == 0 || len(spec.Sources) > maxListItems {
		errs = append(errs, fmt.Sprintf("Choose 1 to %d recipients.", maxListItems))
	}
	d, ok := durationOf(f.Duration)
	switch {
	case !ok:
		errs = append(errs, "Choose a duration from the list.")
	case d > 0:
		spec.ExpiresAt = &metav1.Time{Time: now.Add(d).UTC().Truncate(time.Second)}
	}
	spec.Description = strings.TrimSpace(f.Description)
	if utf8.RuneCountInString(spec.Description) > 253 || strings.ContainsFunc(spec.Description, func(r rune) bool { return r < 0x20 }) {
		errs = append(errs, "Keep the description to one line of at most 253 characters.")
	}
	return spec, errs
}

func parsePorts(v string) ([]int32, string) {
	var out []int32
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		n, err := strconv.ParseUint(f, 10, 16)
		if err != nil || n == 0 {
			return nil, fmt.Sprintf("%q is not a TCP port (1 to 65535).", f)
		}
		if !slices.Contains(out, int32(n)) {
			out = append(out, int32(n))
		}
	}
	slices.Sort(out)
	if len(out) == 0 || len(out) > maxListItems {
		return nil, fmt.Sprintf("Give 1 to %d TCP ports.", maxListItems)
	}
	return out, ""
}

// parsePrefixes accepts addresses (one host) and masked prefixes inside the site (rule 3).
func parsePrefixes(v string, site []string) ([]tnv1.GatewayPrefix, string) {
	var scope []netip.Prefix
	for _, s := range site {
		if p, err := netip.ParsePrefix(s); err == nil {
			scope = append(scope, p)
		}
	}
	var out []tnv1.GatewayPrefix
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		p, err := netip.ParsePrefix(f)
		if !strings.Contains(f, "/") {
			var a netip.Addr
			if a, err = netip.ParseAddr(f); err == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if err != nil || p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" {
			return nil, fmt.Sprintf("%q is not an address or a masked prefix.", f)
		}
		if !slices.ContainsFunc(scope, func(s netip.Prefix) bool { return s.Bits() <= p.Bits() && s.Contains(p.Addr()) }) {
			return nil, fmt.Sprintf("%s is outside the site.", p)
		}
		if gp := tnv1.GatewayPrefix(p.String()); !slices.Contains(out, gp) {
			out = append(out, gp)
		}
	}
	slices.Sort(out)
	if len(out) == 0 || len(out) > maxListItems {
		return nil, fmt.Sprintf("Give 1 to %d addresses or prefixes inside the site.", maxListItems)
	}
	return out, ""
}

const nameAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// nameSuffix names grants and requests: the console chooses names, because the audit entry
// names the object before it exists.
func nameSuffix() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = nameAlphabet[int(b[i])%len(nameAlphabet)]
	}
	return string(b)
}

func actorOf(sess *session) *auditActor {
	return &auditActor{Issuer: sess.Issuer, Subject: sess.Subject, Name: sess.Name}
}

func expiresText(t *metav1.Time) string {
	if t == nil {
		return "permanent"
	}
	return t.UTC().Format(time.RFC3339)
}

func statusCode(err error) int32 {
	if st, ok := err.(apierrors.APIStatus); ok || errors.As(err, &st) {
		return st.Status().Code
	}
	return 0
}

// commit records the change, then makes it; a failed change is followed by grant.failed (rules 12
// and 13). written is false when the audit log refused the entry and nothing was changed. Call
// with s.changes held, so no observation runs between the entry and the change (rule 27).
func (s *Server) commit(ctx context.Context, e auditEntry, apply func() error) (written bool, err error) {
	if err := s.audit.append(ctx, e); err != nil {
		s.log.Error(err, "audit write failed; change refused", "action", e.Action)
		return false, err
	}
	if err := apply(); err != nil {
		code := statusCode(err)
		s.log.Info("write failed", "action", e.Action, "status", code)
		failed := auditEntry{Action: actionFailed, Actor: e.Actor, Grant: e.Grant, Tailnet: e.Tailnet,
			Details: map[string]any{"action": e.Action, "status": code}}
		if aerr := s.audit.append(ctx, failed); aerr != nil {
			s.log.Error(aerr, "audit write failed", "action", actionFailed)
		}
		return true, err
	}
	return true, nil
}

// change commits a change asked for in the console. It answers the request itself when something
// fails and reports whether the change was made.
func (s *Server) change(w http.ResponseWriter, r *http.Request, e auditEntry, apply func() error) bool {
	s.changes.Lock()
	written, err := s.commit(r.Context(), e, apply)
	s.changes.Unlock()
	if !written {
		s.message(w, r, http.StatusServiceUnavailable, "Change refused",
			"The console cannot write its audit log, so it makes no change. Check the audit volume and the anchor ConfigMap.")
		return false
	}
	if err == nil {
		return true
	}
	code := statusCode(err)
	if apierrors.IsConflict(err) {
		s.message(w, r, http.StatusConflict, "Changed meanwhile",
			"Somebody changed it at the same time. Reload the page and try again. The audit log records the attempt.")
		return false
	}
	s.message(w, r, http.StatusBadGateway, "Change failed",
		fmt.Sprintf("The API server did not accept the change (status %d). The audit log records the attempt.", code))
	return false
}

// grantRow is one line of the grant list. Recipients carry names: only admins see the list.
type grantRow struct {
	Name, Tailnet, Description string
	Target                     []string
	Ports                      []string
	Recipients                 []string
	Expires                    string
	Expired                    bool
	Ready                      state
	Managed                    bool
}

type grantsBody struct {
	Rows      []grantRow
	Durations any
	FourEyes  bool
}

// grantRowOf names recipients from names, the persons by provider identifier.
func grantRowOf(g *tnv1.TailnetGrant, names map[string]string, now time.Time) grantRow {
	row := grantRow{Name: g.Name, Tailnet: g.Spec.TailnetRef.Name, Description: g.Spec.Description, Ports: tcpPorts(g.Spec.Ports),
		Ready: condState(g.Status.Conditions, "Ready"), Managed: g.Labels[managedByLabel] == managedBy, Expires: "permanent"}
	if g.Spec.Target.Tag != "" {
		row.Target = []string{g.Spec.Target.Tag}
	}
	for _, p := range g.Spec.Target.Prefixes {
		row.Target = append(row.Target, string(p))
	}
	for _, src := range g.Spec.Sources {
		if n := names[strings.TrimSuffix(src, "@")]; n != "" {
			src = n + " (" + src + ")"
		}
		row.Recipients = append(row.Recipients, src)
	}
	if g.Spec.ExpiresAt != nil {
		row.Expired = !now.Before(g.Spec.ExpiresAt.Time)
		row.Expires = remaining(g.Spec.ExpiresAt.Sub(now)) + " (" + g.Spec.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC") + ")"
	}
	return row
}

func (s *Server) grantsPage(w http.ResponseWriter, r *http.Request, sess *session) {
	var list tnv1.TailnetGrantList
	if err := s.writer.List(r.Context(), &list); err != nil {
		s.log.Info("grant list failed")
		s.message(w, r, http.StatusServiceUnavailable, "Grants unavailable", "The console cannot read the grants right now.")
		return
	}
	names := map[string]map[string]string{}
	now := s.now()
	var rows []grantRow
	for i := range list.Items {
		g := &list.Items[i]
		rows = append(rows, grantRowOf(g, s.people(r.Context(), names, g.Spec.TailnetRef.Name), now))
	}
	slices.SortFunc(rows, func(a, b grantRow) int { return strings.Compare(a.Name, b.Name) })
	s.render(w, http.StatusOK, "grants", page{Title: "Grants", Session: sess,
		Body: grantsBody{Rows: rows, Durations: grantDurations, FourEyes: s.fourEyes}})
}

// grantNewBody serves the grant form at Path ("/grants") and the request form ("/requests"),
// whose only recipient is the signed-in person (Self).
type grantNewBody struct {
	Path      string
	Self      bool
	FourEyes  bool
	Admin     bool
	Tailnets  []grantTailnet
	Tailnet   *grantTailnet
	Target    *grantTarget
	Form      grantForm
	Errors    []string
	Durations any
}

func (s *Server) grantForm() grantNewBody {
	return grantNewBody{Path: "/grants", FourEyes: s.fourEyes, Admin: true, Durations: grantDurations}
}

// prefill fills the second step for the chosen target with its ports and site.
func (s *Server) prefill(body *grantNewBody, target string) {
	body.Form = grantForm{Target: target, Duration: "8h"}
	if target == "" {
		return
	}
	body.Tailnet, body.Target = findTarget(body.Tailnets, target)
	if body.Target == nil {
		body.Errors = []string{"Choose a target from the list."}
		return
	}
	var ports []string
	for _, p := range body.Target.Ports {
		ports = append(ports, strconv.Itoa(int(p)))
	}
	body.Form.Ports, body.Form.Prefixes = strings.Join(ports, ", "), strings.Join(body.Target.Site, ", ")
}

func (s *Server) grantNewPage(w http.ResponseWriter, r *http.Request, sess *session) {
	opts, err := s.grantOptions(r.Context())
	if err != nil {
		s.message(w, r, http.StatusServiceUnavailable, "Grants unavailable", "The console cannot read the cluster state right now.")
		return
	}
	body := s.grantForm()
	body.Tailnets = opts
	s.prefill(&body, r.URL.Query().Get("target"))
	s.render(w, http.StatusOK, "grant_new", page{Title: "New grant", Session: sess, Body: body})
}

func (s *Server) readGrantForm(w http.ResponseWriter, r *http.Request) (grantForm, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if r.ParseForm() != nil {
		s.message(w, r, http.StatusBadRequest, "Invalid form", "The form could not be read.")
		return grantForm{}, false
	}
	return grantForm{Target: r.PostForm.Get("target"), Ports: r.PostForm.Get("ports"), Prefixes: r.PostForm.Get("prefixes"),
		Sources: r.PostForm["sources"], Duration: r.PostForm.Get("duration"), Description: r.PostForm.Get("description")}, true
}

// grantCreate creates the grant, or with four-eyes approval asks another admin for it.
func (s *Server) grantCreate(w http.ResponseWriter, r *http.Request, sess *session) {
	f, ok := s.readGrantForm(w, r)
	if !ok {
		return
	}
	opts, err := s.grantOptions(r.Context())
	if err != nil {
		s.message(w, r, http.StatusServiceUnavailable, "Grants unavailable", "The console cannot read the cluster state right now.")
		return
	}
	spec, errs := buildGrantSpec(f, opts, s.now())
	if len(errs) > 0 {
		body := s.grantForm()
		body.Tailnets, body.Form, body.Errors = opts, f, errs
		body.Tailnet, body.Target = findTarget(opts, f.Target)
		s.render(w, http.StatusBadRequest, "grant_new", page{Title: "New grant", Session: sess, Body: body})
		return
	}
	if s.fourEyes {
		s.submitRequest(w, r, sess, createRequest(spec, f.Duration, identityOf(sess), requestedAsAdmin))
		return
	}
	g := &tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Name: "console-" + nameSuffix(), Labels: map[string]string{managedByLabel: managedBy}}, Spec: spec}
	e := auditEntry{Action: "grant.create", Actor: actorOf(sess), Grant: g.Name, Tailnet: spec.TailnetRef.Name, Details: grantDetails(spec)}
	if s.change(w, r, e, func() error { return s.writer.Create(r.Context(), g) }) {
		http.Redirect(w, r, "/grants", http.StatusSeeOther)
	}
}

// managedGrant loads a grant the console may change (rule 7), or answers the request.
func (s *Server) managedGrant(w http.ResponseWriter, r *http.Request) *tnv1.TailnetGrant {
	var g tnv1.TailnetGrant
	if err := s.writer.Get(r.Context(), client.ObjectKey{Name: r.PathValue("name")}, &g); err != nil {
		if apierrors.IsNotFound(err) {
			s.message(w, r, http.StatusNotFound, "No such grant", "The grant does not exist.")
		} else {
			s.message(w, r, http.StatusServiceUnavailable, "Grants unavailable", "The console cannot read the grant right now.")
		}
		return nil
	}
	if g.Labels[managedByLabel] != managedBy {
		s.message(w, r, http.StatusForbidden, "Not a console grant",
			"The console did not create this grant and does not change it. Change it where it is defined, in Git or with kubectl.")
		return nil
	}
	return &g
}

// setExpiry extends (rule 8, a duration from now) or revokes (expiresAt now) a console grant.
// With four-eyes approval an extension becomes a request; a revocation acts at once.
func (s *Server) setExpiry(revoke bool) func(http.ResponseWriter, *http.Request, *session) {
	return func(w http.ResponseWriter, r *http.Request, sess *session) {
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if r.ParseForm() != nil {
			s.message(w, r, http.StatusBadRequest, "Invalid form", "The form could not be read.")
			return
		}
		g := s.managedGrant(w, r)
		if g == nil {
			return
		}
		now := s.now().UTC().Truncate(time.Second)
		next, action := &metav1.Time{Time: now}, "grant.revoke"
		if !revoke {
			d, ok := durationOf(r.PostForm.Get("duration"))
			if !ok {
				s.message(w, r, http.StatusBadRequest, "Invalid duration", "Choose a duration from the list.")
				return
			}
			if s.fourEyes {
				s.submitRequest(w, r, sess, extendRequest(g, r.PostForm.Get("duration"), identityOf(sess), requestedAsAdmin))
				return
			}
			next, action = nil, "grant.extend"
			if d > 0 {
				next = &metav1.Time{Time: now.Add(d)}
			}
		}
		e := auditEntry{Action: action, Actor: actorOf(sess), Grant: g.Name, Tailnet: g.Spec.TailnetRef.Name,
			Details: map[string]any{"from": expiresText(g.Spec.ExpiresAt), "to": expiresText(next)}}
		orig := g.DeepCopy()
		g.Spec.ExpiresAt = next
		if s.change(w, r, e, func() error { return s.writer.Patch(r.Context(), g, client.MergeFrom(orig)) }) {
			http.Redirect(w, r, "/grants", http.StatusSeeOther)
		}
	}
}

// auditRow is one entry as the audit page shows it.
type auditRow struct {
	Seq                 uint64
	Time, Action, Actor string
	Subject             string
	Origin              string // who acted when the entry names nobody (rule 29)
	Tailnet, Grant      string
	Details             []string
	Broken              bool
}

type auditBody struct {
	Rows    []auditRow
	Breaks  []string
	Problem bool
	Total   int
	Older   uint64 // the "before" of the next page; 0 when there is none
}

const auditPage = 200

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request, sess *session) {
	st := s.audit.state(r.Context())
	if st.Err != nil {
		s.log.Error(st.Err, "audit check failed")
	} else {
		s.breaks.Store(int64(len(st.Breaks)))
	}
	before := uint64(0)
	if v := r.URL.Query().Get("before"); v != "" {
		before, _ = strconv.ParseUint(v, 10, 64)
	}
	body := auditBody{Breaks: st.Breaks, Problem: st.Err != nil, Total: len(st.Entries)}
	for i := len(st.Entries) - 1; i >= 0; i-- {
		e := st.Entries[i]
		if before > 0 && e.Seq >= before {
			continue
		}
		if len(body.Rows) == auditPage {
			body.Older = body.Rows[len(body.Rows)-1].Seq
			break
		}
		row := auditRow{Seq: e.Seq, Time: e.Time.UTC().Format("2006-01-02 15:04:05 UTC"), Action: e.Action,
			Tailnet: e.Tailnet, Grant: e.Grant, Broken: e.Action == actionBroken}
		switch {
		case e.Actor != nil:
			row.Actor, row.Subject = or(e.Actor.Name, e.Actor.Subject), e.Actor.Issuer+" "+e.Actor.Subject
		case e.Action == actionObserved:
			row.Origin = "unknown"
		case e.Action == actionExpired:
			row.Origin = "operator"
		default:
			row.Origin = "console"
		}
		var keys []string
		for k := range e.Details {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			row.Details = append(row.Details, fmt.Sprintf("%s: %v", k, e.Details[k]))
		}
		body.Rows = append(body.Rows, row)
	}
	s.render(w, http.StatusOK, "audit", page{Title: "Audit log", Session: sess, Body: body})
}

// CheckAudit verifies the audit log at start and records its breaks (rule 14). Without access
// management it does nothing.
func (s *Server) CheckAudit(ctx context.Context) {
	if s.audit == nil {
		return
	}
	st := s.audit.state(ctx)
	if st.Err != nil {
		s.log.Error(st.Err, "audit check failed; changes are refused until it succeeds")
		return
	}
	s.breaks.Store(int64(len(st.Breaks)))
}

// WatchAudit repeats CheckAudit every interval until ctx ends, so the break metric notices a
// changed file without a page view.
func (s *Server) WatchAudit(ctx context.Context, every time.Duration) {
	// ponytail: every check reads and hashes the whole log, linear in its size; resume from the
	// last verified offset if logs grow past a few hundred MB.
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.CheckAudit(ctx)
		}
	}
}
