package console

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

// newRequestConsole is the grant console whose Headscale knows the user uma and the admins ada,
// bea and cy by the identifiers their sign-ins produce; ulf signs in but is unknown to it.
func newRequestConsole(t *testing.T, fourEyes bool) *testConsole {
	t.Helper()
	c := newGrantConsole(t)
	c.fourEyes = fourEyes
	var users []headscale.User
	for i, sub := range []string{"uma", "ada", "bea", "cy"} {
		users = append(users, headscale.User{ID: string(rune('1' + i)), Name: sub, DisplayName: strings.ToUpper(sub[:1]) + sub[1:] + " Example",
			ProviderID: c.id(sub)})
	}
	raw, _ := json.Marshal(users)
	op, _, _ := fakeOperator(t, string(raw), `"{\"grants\":[{\"src\":[\"autogroup:member\"],\"dst\":[\"tag:db-zeta-1\"],\"ip\":[\"tcp:5432\"]}]}"`)
	c.dir = newDirectory(op.URL, tokenFile(t, "tok"))
	return c
}

func (c *testConsole) id(sub string) string { return providerID(c.idp.srv.URL, sub) }

func (c *testConsole) as(t *testing.T, sub string, admin bool) []*http.Cookie {
	t.Helper()
	group := "users"
	if admin {
		group = "admins"
	}
	resp := c.signIn(t, flow{returnTo: "/"}, map[string]any{"sub": sub, "name": sub, "groups": []string{group}})
	return []*http.Cookie{cookie(resp, sessionCookie)}
}

func (c *testConsole) requests(t *testing.T) []tnv1.TailnetAccessRequest {
	t.Helper()
	var list tnv1.TailnetAccessRequestList
	if err := c.writer.List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(list.Items, func(a, b tnv1.TailnetAccessRequest) int { return strings.Compare(a.Name, b.Name) })
	return list.Items
}

// latest is the one request not in seen.
func (c *testConsole) latest(t *testing.T, seen ...string) tnv1.TailnetAccessRequest {
	t.Helper()
	var fresh []tnv1.TailnetAccessRequest
	for _, r := range c.requests(t) {
		if !slices.Contains(seen, r.Name) {
			fresh = append(fresh, r)
		}
	}
	if len(fresh) != 1 {
		t.Fatalf("new requests %+v", fresh)
	}
	return fresh[0]
}

func (c *testConsole) request(t *testing.T, name string) tnv1.TailnetAccessRequest {
	t.Helper()
	var r tnv1.TailnetAccessRequest
	if err := c.writer.Get(context.Background(), client.ObjectKey{Name: name}, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func (c *testConsole) expect(t *testing.T, what string, resp *http.Response, status int) {
	t.Helper()
	if resp.StatusCode != status {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s: status %d, want %d\n%s", what, resp.StatusCode, status, body)
	}
}

var wikiForm = url.Values{"target": {"lab/ingress/apps/wiki"}, "ports": {"443"}, "duration": {"8h"}, "description": {"on call"}}

// The approvals a request needs, who may decide it, its history from the audit log and what a
// user may ask for, as pure functions.
func TestRequestRules(t *testing.T) {
	user := tnv1.TailnetAccessRequestSpec{RequestedAs: requestedAsUser, Requester: "u"}
	admin := tnv1.TailnetAccessRequestSpec{RequestedAs: requestedAsAdmin, Requester: "a"}
	for _, tc := range []struct {
		spec     tnv1.TailnetAccessRequestSpec
		fourEyes bool
		want     int
	}{{user, false, 1}, {user, true, 2}, {admin, false, 1}, {admin, true, 1}} {
		if got := approvalsNeeded(tc.spec, tc.fourEyes); got != tc.want {
			t.Errorf("%s, four-eyes %v: %d approvals, want %d", tc.spec.RequestedAs, tc.fourEyes, got, tc.want)
		}
	}
	approved := &tnv1.TailnetAccessRequest{Spec: user}
	for _, tc := range []struct {
		req                 *tnv1.TailnetAccessRequest
		decision, who, role string
		allowed             bool
	}{
		{approved, "approve", "c", roleAdmin, true},
		{approved, "approve", "b", roleAdmin, false}, // approved already
		{approved, "reject", "b", roleAdmin, true},   // an approver may still veto
		{approved, "approve", "u", roleAdmin, false}, // the requester, even as admin
		{approved, "reject", "u", roleAdmin, false},
		{approved, "approve", "c", roleUser, false},
		{approved, "withdraw", "u", roleUser, true},
		{approved, "withdraw", "c", roleAdmin, false}, // only the requester withdraws
		{&tnv1.TailnetAccessRequest{Spec: user, Status: tnv1.TailnetAccessRequestStatus{Phase: phaseRejected}}, "approve", "c", roleAdmin, false},
		{&tnv1.TailnetAccessRequest{Spec: user, Status: tnv1.TailnetAccessRequestStatus{Phase: phaseApproved}}, "withdraw", "u", roleUser, false},
	} {
		if got := refusal(tc.req, tc.decision, tc.who, tc.role, []string{"b"}) == ""; got != tc.allowed {
			t.Errorf("%s by %s (%s) on %s: allowed %v", tc.decision, tc.who, tc.role, phaseOf(tc.req), got)
		}
	}
	// Approvals and decisions come from the audit log, per request and person.
	entry := func(action, req, sub string, min int) auditEntry {
		return auditEntry{Action: action, Actor: &auditActor{Issuer: "https://id", Subject: sub, Name: strings.ToUpper(sub)}, Time: grantNow.Add(time.Duration(min) * time.Minute), Details: map[string]any{"request": req}}
	}
	h := histories([]auditEntry{
		entry("request.create", "r1", "u", 0), entry("request.approve", "r1", "a", 1), entry("request.approve", "r1", "a", 2),
		entry("request.approve", "r2", "c", 3), entry("grant.revoke", "r1", "c", 4), entry("request.approve", "r1", "b", 5),
		entry("grant.create", "r1", "b", 6), {Action: actionBroken, Details: map[string]any{"break": "x"}},
		entry("request.reject", "r2", "d", 7),
		// A rejection that failed, the last approval, then somebody closes the request.
		entry("request.reject", "r3", "d", 8), entry("request.approve", "r3", "a", 9), entry("grant.create", "r3", "b", 10),
		entry("request.close", "r3", "a", 11),
	})
	if got := h["r1"]; !slices.Equal(got.approvers(), []string{"https://id/a", "https://id/b"}) || got.Approvals[0].At != grantNow.Add(time.Minute) ||
		got.Granted == nil || got.Granted.ID != "https://id/b" || got.Granted.Name != "B" || got.Decided != nil {
		t.Errorf("history r1 %+v", got)
	}
	if got := h["r2"]; !slices.Equal(got.approvers(), []string{"https://id/c"}) || got.Granted != nil || got.Decided == nil || got.Decided.ID != "https://id/d" {
		t.Errorf("history r2 %+v", got)
	}
	// Closing does not hide the last approver, and does not count as an approval.
	if got := h["r3"]; !slices.Equal(got.approvers(), []string{"https://id/a"}) || got.Granted == nil || got.Granted.ID != "https://id/b" ||
		got.Decided == nil || got.Decided.ID != "https://id/a" || got.Decided.At != grantNow.Add(11*time.Minute) {
		t.Errorf("history r3 %+v", got)
	}
	// A grant carries the change of the request it names.
	create := &tnv1.TailnetAccessRequest{ObjectMeta: metav1.ObjectMeta{Name: "request-abc"}, Spec: tnv1.TailnetAccessRequestSpec{Action: "Create"}}
	extend := &tnv1.TailnetAccessRequest{ObjectMeta: metav1.ObjectMeta{Name: "request-def"}, Spec: tnv1.TailnetAccessRequestSpec{Action: "Extend", GrantName: "console-abc"}}
	grant := func(name string, ann ...string) *tnv1.TailnetGrant {
		g := &tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{managedByLabel: managedBy}, Annotations: map[string]string{}}}
		for i := 0; i < len(ann); i += 2 {
			g.Annotations[ann[i]] = ann[i+1]
		}
		return g
	}
	for _, tc := range []struct {
		req  *tnv1.TailnetAccessRequest
		g    *tnv1.TailnetGrant
		want bool
	}{
		{create, nil, false},
		{create, grant("console-abc", requestAnnotation, "request-abc"), true},
		{create, grant("console-abc", requestAnnotation, "request-xyz"), false},
		{create, grant("console-xyz", requestAnnotation, "request-abc"), false},
		{create, &tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Name: "console-abc", Annotations: map[string]string{requestAnnotation: "request-abc"}}}, false},
		{extend, grant("console-abc", requestAnnotation, "request-abc"), false},
		{extend, grant("console-abc", requestAnnotation, "request-abc", extendedByAnnotation, "request-def"), true},
		{extend, grant("console-abc", extendedByAnnotation, "request-later"), false},
	} {
		if got := applied(tc.req, tc.g); got != tc.want {
			t.Errorf("%s on %+v: applied %v", tc.req.Name, tc.g, got)
		}
	}
	opts := []grantTailnet{{Name: "a", Recipients: []grantRecipient{{"u@", "U"}, {"group:x", "group:x"}}}, {Name: "b", Recipients: []grantRecipient{{"v@", "V"}}}}
	if got := userOptions(opts, "u@"); len(got) != 1 || got[0].Name != "a" || !slices.Equal(got[0].Recipients, []grantRecipient{{"u@", "U"}}) {
		t.Errorf("user options %+v", got)
	}
	g := &tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{managedByLabel: managedBy}},
		Spec: tnv1.TailnetGrantSpec{TailnetRef: tnv1.TailnetRef{Name: "a"}, Sources: []string{"u@", "w@"}}}
	if extendable(g, "a", "u", true) || !extendable(g, "a", "u", false) || extendable(g, "b", "u", false) {
		t.Error("a user extends only a grant naming them alone")
	}
	g.Spec.Sources = []string{"u@"}
	if !extendable(g, "a", "u", true) {
		t.Error("own grant not extendable")
	}
	g.Labels = nil
	if extendable(g, "a", "u", false) {
		t.Error("grant from Git extendable")
	}
}

// A user's request with four-eyes approval off: one admin decides it.
func TestUserRequestLifecycle(t *testing.T) {
	c := newRequestConsole(t, false)
	uma, ada, bea := c.as(t, "uma", false), c.as(t, "ada", true), c.as(t, "bea", true)
	// The recipient is the requester whatever the form says.
	forged := url.Values{}
	for k, v := range wikiForm {
		forged[k] = v
	}
	forged["sources"] = []string{"group:staff"}
	resp := c.post(t, "/requests", uma, forged)
	c.expect(t, "request", resp, http.StatusSeeOther)
	req := c.latest(t)
	if req.Spec.Action != "Create" || req.Spec.Requester != c.id("uma") || req.Spec.RequestedAs != requestedAsUser ||
		!slices.Equal(req.Spec.Sources, []string{c.id("uma") + "@"}) || req.Spec.Target.Tag != "tag:wiki" || req.Spec.Duration != "8h" ||
		phaseOf(&req) != phasePending || !strings.HasPrefix(req.Name, "request-") || len(req.Name) != len("request-")+10 {
		t.Fatalf("request %+v", req)
	}
	if len(c.consoleGrants(t)) != 0 {
		t.Fatal("grant before approval")
	}
	// A user does not decide; nobody decides their own request.
	c.expect(t, "user approves", c.post(t, "/requests/"+req.Name+"/approve", uma, nil), http.StatusForbidden)
	// The duration counts from the approval.
	approvedAt := grantNow.Add(time.Hour)
	c.now = func() time.Time { return approvedAt }
	c.audit.now = c.now
	c.expect(t, "approve", c.post(t, "/requests/"+req.Name+"/approve", ada, nil), http.StatusSeeOther)
	grantName := "console-" + strings.TrimPrefix(req.Name, "request-")
	g := c.grant(t, grantName)
	if !g.Spec.ExpiresAt.Time.Equal(approvedAt.Add(8*time.Hour)) || !slices.Equal(g.Spec.Sources, []string{c.id("uma") + "@"}) ||
		g.Labels[managedByLabel] != managedBy || g.Annotations[requestAnnotation] != req.Name || g.Spec.Description != "on call" {
		t.Fatalf("grant %+v", g)
	}
	req = c.request(t, req.Name)
	if req.Status.Phase != phaseApproved || req.Status.GrantName != grantName || !req.Status.DecidedAt.Time.Equal(approvedAt) {
		t.Fatalf("status %+v", req.Status)
	}
	c.namesNobody(t, req, "ada")
	c.expect(t, "approve again", c.post(t, "/requests/"+req.Name+"/approve", bea, nil), http.StatusConflict)

	// uma asks to extend her own grant; one rejection ends it.
	c.expect(t, "extend request", c.post(t, "/grants/"+grantName+"/request", uma, url.Values{"duration": {"7d"}}), http.StatusSeeOther)
	ext := c.latest(t, req.Name)
	if ext.Spec.Action != "Extend" || ext.Spec.GrantName != grantName || ext.Spec.Target != nil {
		t.Fatalf("extension %+v", ext.Spec)
	}
	c.expect(t, "reject", c.post(t, "/requests/"+ext.Name+"/reject", bea, nil), http.StatusSeeOther)
	if r := c.request(t, ext.Name); r.Status.Phase != phaseRejected || r.Status.DecidedAt == nil {
		t.Fatalf("rejected %+v", r.Status)
	} else {
		c.namesNobody(t, r, "bea")
	}
	c.expect(t, "approve rejected", c.post(t, "/requests/"+ext.Name+"/approve", ada, nil), http.StatusConflict)
	// uma withdraws, which nobody else may.
	c.expect(t, "extend request", c.post(t, "/grants/"+grantName+"/request", uma, url.Values{"duration": {"7d"}}), http.StatusSeeOther)
	wd := c.latest(t, req.Name, ext.Name)
	ulf := c.as(t, "ulf", false)
	c.expect(t, "foreign withdraw", c.post(t, "/requests/"+wd.Name+"/withdraw", ulf, nil), http.StatusNotFound)
	c.expect(t, "admin withdraws", c.post(t, "/requests/"+wd.Name+"/withdraw", ada, nil), http.StatusConflict)
	c.expect(t, "withdraw", c.post(t, "/requests/"+wd.Name+"/withdraw", uma, nil), http.StatusSeeOther)
	if r := c.request(t, wd.Name); r.Status.Phase != phaseWithdrawn {
		t.Fatalf("withdrawn %+v", r.Status)
	}
	c.expect(t, "extend request", c.post(t, "/grants/"+grantName+"/request", uma, url.Values{"duration": {"7d"}}), http.StatusSeeOther)
	ok := c.latest(t, req.Name, ext.Name, wd.Name)
	c.expect(t, "approve extension", c.post(t, "/requests/"+ok.Name+"/approve", ada, nil), http.StatusSeeOther)
	if g := c.grant(t, grantName); !g.Spec.ExpiresAt.Time.Equal(approvedAt.Add(7*24*time.Hour)) || g.Annotations[extendedByAnnotation] != ok.Name ||
		g.Annotations[requestAnnotation] != req.Name {
		t.Fatalf("extended %+v", g.ObjectMeta.Annotations)
	}
	// No extension of a grant from Git or of a grant naming somebody else.
	c.expect(t, "extend from-git", c.post(t, "/grants/from-git/request", uma, url.Values{"duration": {"7d"}}), http.StatusForbidden)
	c.expect(t, "extend foreign", c.post(t, "/grants/"+grantName+"/request", ulf, url.Values{"duration": {"7d"}}), http.StatusForbidden)
	// A person the tailnet's Headscale does not know is offered nothing.
	c.expect(t, "unknown user", c.post(t, "/requests", ulf, wikiForm), http.StatusBadRequest)
	// A user sees only their own requests.
	body := func(cookies []*http.Cookie) string {
		resp := c.do(t, http.MethodGet, "/requests", cookies)
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if page := body(ulf); strings.Contains(page, req.Name) || !strings.Contains(page, "No request yet") {
		t.Errorf("ulf sees uma's request:\n%s", page)
	}
	if page := body(uma); !strings.Contains(page, req.Name) || !strings.Contains(page, grantName) || !strings.Contains(page, "Ask to extend") {
		t.Errorf("uma's page lacks her request or grant:\n%s", page)
	}
	if page := body(ada); !strings.Contains(page, req.Name) || !strings.Contains(page, "Uma Example") {
		t.Errorf("admin page lacks the request:\n%s", page)
	}
	st := c.audit.state(context.Background())
	want := []string{"request.create", "grant.create", "request.create", "request.reject", "request.create", "request.withdraw", "request.create", "grant.extend"}
	if got := actions(st); !slices.Equal(got, want) || len(st.Breaks) > 0 {
		t.Fatalf("audit %q, breaks %q", got, st.Breaks)
	}
	create := st.Entries[1]
	if create.Grant != grantName || create.Actor.Subject != "ada" || create.Details["requester"] != c.id("uma") ||
		!slices.Equal(anyStrings(create.Details["approvers"]), []string{c.id("ada")}) || create.Details["request"] != req.Name ||
		create.Details["expiresAt"] != "2026-11-27T22:00:00Z" {
		t.Errorf("grant.create entry %+v", create)
	}
	if e := st.Entries[0]; e.Actor.Subject != "uma" || e.Grant != grantName || e.Details["requestedAs"] != requestedAsUser || e.Details["duration"] != "8h" {
		t.Errorf("request.create entry %+v", e)
	}
}

// namesNobody fails when the stored request carries the identifier of one of subs.
func (c *testConsole) namesNobody(t *testing.T, req tnv1.TailnetAccessRequest, subs ...string) {
	t.Helper()
	raw, _ := json.Marshal(req)
	for _, sub := range subs {
		if strings.Contains(string(raw), c.id(sub)) {
			t.Errorf("request %s names %s:\n%s", req.Name, sub, raw)
		}
	}
}

func anyStrings(v any) []string {
	var out []string
	if list, ok := v.([]any); ok {
		for _, s := range list {
			out = append(out, s.(string))
		}
	}
	return out
}

// Four-eyes approval on: two different admins approve a user's request, and the pages say so.
func TestFourEyes(t *testing.T) {
	c := newRequestConsole(t, true)
	uma, ada, bea := c.as(t, "uma", false), c.as(t, "ada", true), c.as(t, "bea", true)
	c.expect(t, "request", c.post(t, "/requests", uma, wikiForm), http.StatusSeeOther)
	req := c.latest(t)
	c.expect(t, "first approval", c.post(t, "/requests/"+req.Name+"/approve", ada, nil), http.StatusSeeOther)
	// A partial approval is in the audit log alone.
	if r := c.request(t, req.Name); r.Status != (tnv1.TailnetAccessRequestStatus{}) || r.ResourceVersion != req.ResourceVersion || len(c.consoleGrants(t)) != 0 {
		t.Fatalf("after one approval: %+v", r.Status)
	}
	c.expect(t, "same admin again", c.post(t, "/requests/"+req.Name+"/approve", ada, nil), http.StatusConflict)
	c.expect(t, "second approval", c.post(t, "/requests/"+req.Name+"/approve", bea, nil), http.StatusSeeOther)
	if r := c.request(t, req.Name); r.Status.Phase != phaseApproved || len(c.consoleGrants(t)) != 1 {
		t.Fatalf("after two approvals: %+v", r.Status)
	} else {
		c.namesNobody(t, r, "ada", "bea")
	}
	// An admin's new grant and extension become requests another admin approves.
	admin := url.Values{"sources": {c.id("bea") + "@"}}
	for k, v := range wikiForm {
		admin[k] = v
	}
	c.expect(t, "admin grant", c.post(t, "/grants", ada, admin), http.StatusSeeOther)
	own := c.latest(t, req.Name)
	if own.Spec.RequestedAs != requestedAsAdmin || !slices.Equal(own.Spec.Sources, []string{c.id("bea") + "@"}) || len(c.consoleGrants(t)) != 1 {
		t.Fatalf("admin request %+v", own.Spec)
	}
	c.expect(t, "own approval", c.post(t, "/requests/"+own.Name+"/approve", ada, nil), http.StatusConflict)
	c.expect(t, "other admin", c.post(t, "/requests/"+own.Name+"/approve", bea, nil), http.StatusSeeOther)
	grantName := "console-" + strings.TrimPrefix(own.Name, "request-")
	if g := c.grant(t, grantName); !slices.Equal(g.Spec.Sources, []string{c.id("bea") + "@"}) {
		t.Fatalf("admin grant %+v", g.Spec)
	}
	c.expect(t, "admin extend", c.post(t, "/grants/"+grantName+"/extend", ada, url.Values{"duration": {"30d"}}), http.StatusSeeOther)
	ext := c.latest(t, req.Name, own.Name)
	if ext.Spec.Action != "Extend" || ext.Spec.RequestedAs != requestedAsAdmin || !c.grant(t, grantName).Spec.ExpiresAt.Time.Equal(grantNow.Add(8*time.Hour)) {
		t.Fatalf("extension %+v", ext.Spec)
	}
	// Revoking acts at once.
	c.expect(t, "revoke", c.post(t, "/grants/"+grantName+"/revoke", ada, nil), http.StatusSeeOther)
	if g := c.grant(t, grantName); !g.Spec.ExpiresAt.Time.Equal(grantNow) {
		t.Fatalf("revoked to %v", g.Spec.ExpiresAt)
	}
	// The setting at decision time counts.
	c.fourEyes = false
	c.expect(t, "request", c.post(t, "/requests", uma, wikiForm), http.StatusSeeOther)
	late := c.latest(t, req.Name, own.Name, ext.Name)
	c.fourEyes = true
	c.expect(t, "approval", c.post(t, "/requests/"+late.Name+"/approve", ada, nil), http.StatusSeeOther)
	if r := c.request(t, late.Name); phaseOf(&r) != phasePending {
		t.Fatalf("switched on later: %+v", r.Status)
	}
	// The notice on the request and grant pages, and who must approve a request.
	get := func(path string, who []*http.Cookie) string {
		b, _ := io.ReadAll(c.do(t, http.MethodGet, path, who).Body)
		return string(b)
	}
	for _, path := range []string{"/requests", "/grants", "/grants/new", "/requests/new"} {
		if !strings.Contains(get(path, ada), "With only one admin, nothing can be approved.") {
			t.Errorf("%s lacks the four-eyes notice", path)
		}
	}
	for _, tc := range []struct {
		who      []*http.Cookie
		fourEyes bool
		want     string
	}{{uma, true, "Two admins must approve it."}, {ada, true, "One other admin must approve it."},
		{uma, false, "An admin must approve it."}, {ada, false, "One other admin must approve it."}} {
		c.fourEyes = tc.fourEyes
		if page := get("/requests/new", tc.who); !strings.Contains(page, tc.want) ||
			strings.Contains(page, "With only one admin") != tc.fourEyes {
			t.Errorf("request form, four-eyes %v, lacks %q or shows the notice wrongly", tc.fourEyes, tc.want)
		}
	}
	c.fourEyes = true
	st := c.audit.state(context.Background())
	want := []string{"request.create", "request.approve", "grant.create", "request.create", "grant.create", "request.create", "grant.revoke", "request.create", "request.approve"}
	if got := actions(st); !slices.Equal(got, want) {
		t.Fatalf("audit %q", got)
	}
	if e := st.Entries[2]; !slices.Equal(anyStrings(e.Details["approvers"]), []string{c.id("ada"), c.id("bea")}) || e.Actor.Subject != "bea" {
		t.Errorf("grant.create entry %+v", e)
	}
}

// The last approval checks the current state, and a retry finds its own grant.
func TestApprovalRecheck(t *testing.T) {
	c := newRequestConsole(t, false)
	uma, ada := c.as(t, "uma", false), c.as(t, "ada", true)
	c.expect(t, "request", c.post(t, "/requests", uma, wikiForm), http.StatusSeeOther)
	req := c.latest(t)
	var in tnv1.TailnetIngress
	if err := c.writer.Get(context.Background(), client.ObjectKey{Namespace: "apps", Name: "wiki"}, &in); err != nil {
		t.Fatal(err)
	}
	if err := c.writer.Delete(context.Background(), &in); err != nil {
		t.Fatal(err)
	}
	c.expect(t, "target gone", c.post(t, "/requests/"+req.Name+"/approve", ada, nil), http.StatusConflict)
	if r := c.request(t, req.Name); r.Status.Phase != "" || len(c.consoleGrants(t)) != 0 {
		t.Fatalf("changed although stale: %+v", r.Status)
	}
	// A site request whose grant was written, the request not closed (half a success).
	site := url.Values{"target": {"lab/site/office"}, "prefixes": {"10.20.30.5"}, "ports": {"3389"}, "duration": {"1h"}}
	c.expect(t, "site request", c.post(t, "/requests", uma, site), http.StatusSeeOther)
	sr := c.latest(t, req.Name)
	name := "console-" + strings.TrimPrefix(sr.Name, "request-")
	pre := &tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{managedByLabel: managedBy},
		Annotations: map[string]string{requestAnnotation: sr.Name}}, Spec: tnv1.TailnetGrantSpec{TailnetRef: tnv1.TailnetRef{Name: "lab"},
		Sources: []string{c.id("uma") + "@"}, Target: tnv1.GrantTarget{Prefixes: []tnv1.GatewayPrefix{"10.20.30.5/32"}}, Ports: []int32{3389}}}
	if err := c.writer.Create(context.Background(), pre); err != nil {
		t.Fatal(err)
	}
	page := func() string {
		b, _ := io.ReadAll(c.do(t, http.MethodGet, "/requests", ada).Body)
		return string(b)
	}
	if p := page(); !strings.Contains(p, "grant written; approve to close") || strings.Contains(p, "/requests/"+sr.Name+"/reject") {
		t.Errorf("written request offers a rejection:\n%s", p)
	}
	c.expect(t, "reject written", c.post(t, "/requests/"+sr.Name+"/reject", ada, nil), http.StatusConflict)
	c.expect(t, "withdraw written", c.post(t, "/requests/"+sr.Name+"/withdraw", uma, nil), http.StatusConflict)
	before := c.grant(t, name).ResourceVersion
	c.expect(t, "close", c.post(t, "/requests/"+sr.Name+"/approve", ada, nil), http.StatusSeeOther)
	if r := c.request(t, sr.Name); r.Status.Phase != phaseApproved || r.Status.GrantName != name || c.grant(t, name).ResourceVersion != before {
		t.Fatalf("close %+v", r.Status)
	}
	// The same for an extension; a later extension makes it an open request again.
	extendOf := func(seen ...string) tnv1.TailnetAccessRequest {
		c.expect(t, "extend request", c.post(t, "/grants/"+name+"/request", uma, url.Values{"duration": {"7d"}}), http.StatusSeeOther)
		return c.latest(t, seen...)
	}
	half := extendOf(req.Name, sr.Name)
	g := c.grant(t, name)
	g.Annotations[extendedByAnnotation] = half.Name
	if err := c.writer.Update(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	c.expect(t, "reject written extension", c.post(t, "/requests/"+half.Name+"/reject", ada, nil), http.StatusConflict)
	later := extendOf(req.Name, sr.Name, half.Name)
	c.expect(t, "approve later", c.post(t, "/requests/"+later.Name+"/approve", ada, nil), http.StatusSeeOther)
	c.expect(t, "reject overtaken", c.post(t, "/requests/"+half.Name+"/reject", ada, nil), http.StatusSeeOther)
	st := c.audit.state(context.Background())
	if got := actions(st); !slices.Equal(got, []string{"request.create", "request.create", "request.close", "request.create", "request.create",
		"grant.extend", "request.reject"}) {
		t.Errorf("audit %q", got)
	}
	// A grant of that name from somebody else is not taken over.
	c.expect(t, "site request", c.post(t, "/requests", uma, site), http.StatusSeeOther)
	other := c.latest(t, req.Name, sr.Name, half.Name, later.Name)
	if err := c.writer.Create(context.Background(), &tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Name: "console-" + strings.TrimPrefix(other.Name, "request-")},
		Spec: pre.Spec}); err != nil {
		t.Fatal(err)
	}
	c.expect(t, "foreign grant", c.post(t, "/requests/"+other.Name+"/approve", ada, nil), http.StatusBadGateway)
	if r := c.request(t, other.Name); r.Status.Phase != "" {
		t.Fatalf("closed over a foreign grant: %+v", r.Status)
	}
	// An extension of a grant that is gone.
	c.expect(t, "extend request", c.post(t, "/grants/"+name+"/request", uma, url.Values{"duration": {"7d"}}), http.StatusSeeOther)
	ext := c.latest(t, req.Name, sr.Name, half.Name, later.Name, other.Name)
	if err := c.writer.Delete(context.Background(), pre); err != nil {
		t.Fatal(err)
	}
	c.expect(t, "grant gone", c.post(t, "/requests/"+ext.Name+"/approve", ada, nil), http.StatusConflict)
}

// A real half success: the last approval writes the grant, its status write fails once. The
// request then only closes, and admins still see every approver.
func TestHalfSuccess(t *testing.T) {
	c := newRequestConsole(t, true)
	fail := true
	c.writer = interceptor.NewClient(c.writer.(client.WithWatch), interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, cl client.Client, _ string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if _, ok := obj.(*tnv1.TailnetAccessRequest); ok && fail {
				fail = false
				return errors.New("status write lost")
			}
			return cl.Status().Update(ctx, obj, opts...)
		}})
	uma, ada, bea, cy := c.as(t, "uma", false), c.as(t, "ada", true), c.as(t, "bea", true), c.as(t, "cy", true)
	c.expect(t, "request", c.post(t, "/requests", uma, wikiForm), http.StatusSeeOther)
	req := c.latest(t)
	path := "/requests/" + req.Name
	c.expect(t, "first approval", c.post(t, path+"/approve", ada, nil), http.StatusSeeOther)
	c.expect(t, "last approval", c.post(t, path+"/approve", bea, nil), http.StatusBadGateway)
	if r := c.request(t, req.Name); phaseOf(&r) != phasePending || len(c.consoleGrants(t)) != 1 {
		t.Fatalf("half success: %+v, %d grants", r.Status, len(c.consoleGrants(t)))
	}
	page := func() string {
		b, _ := io.ReadAll(c.do(t, http.MethodGet, "/requests", cy).Body)
		return string(b)
	}
	for _, want := range []string{"grant written; approve to close", "approved by Ada Example", "approved by Bea Example"} {
		if p := page(); !strings.Contains(p, want) {
			t.Errorf("half done page lacks %q:\n%s", want, p)
		}
	}
	c.expect(t, "reject", c.post(t, path+"/reject", cy, nil), http.StatusConflict)
	c.expect(t, "withdraw", c.post(t, path+"/withdraw", uma, nil), http.StatusConflict)
	grant := c.consoleGrants(t)[0]
	c.expect(t, "close", c.post(t, path+"/approve", ada, nil), http.StatusSeeOther)
	if r := c.request(t, req.Name); r.Status.Phase != phaseApproved || r.Status.GrantName != grant.Name ||
		c.grant(t, grant.Name).ResourceVersion != grant.ResourceVersion {
		t.Fatalf("closed: %+v", r.Status)
	}
	for _, want := range []string{"approved by Ada Example", "approved by Bea Example", "closed by Ada Example"} {
		if p := page(); !strings.Contains(p, want) {
			t.Errorf("closed page lacks %q:\n%s", want, p)
		}
	}
	if got := actions(c.audit.state(context.Background())); !slices.Equal(got, []string{"request.create", "request.approve", "grant.create", actionFailed, "request.close"}) {
		t.Errorf("audit %q", got)
	}
}

// A sign-in without issuer and subject decides nothing.
func TestDecisionWithoutIdentity(t *testing.T) {
	c := newRequestConsole(t, false)
	c.expect(t, "request", c.post(t, "/requests", c.as(t, "uma", false), wikiForm), http.StatusSeeOther)
	req := c.latest(t)
	anon := c.as(t, "", true)
	entries := len(c.audit.state(context.Background()).Entries)
	c.expect(t, "approve", c.post(t, "/requests/"+req.Name+"/approve", anon, nil), http.StatusForbidden)
	if r := c.request(t, req.Name); r.Status != (tnv1.TailnetAccessRequestStatus{}) || len(c.audit.state(context.Background()).Entries) != entries {
		t.Fatalf("decided without identity: %+v", r.Status)
	}
}

// The metrics name Tailnets, never persons, and the break count follows the check.
func TestConsoleMetrics(t *testing.T) {
	if newTestConsole(t, nil).MetricsHandler() != nil {
		t.Fatal("metrics without access management")
	}
	c := newRequestConsole(t, false)
	c.expect(t, "request", c.post(t, "/requests", c.as(t, "uma", false), wikiForm), http.StatusSeeOther)
	scrape := func() string {
		rec := httptest.NewRecorder()
		c.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rec.Body.String()
	}
	c.CheckAudit(context.Background())
	out := scrape()
	if !strings.Contains(out, `tailnet_console_access_requests_pending{tailnet="lab"} 1`) || !strings.Contains(out, "tailnet_console_audit_chain_breaks 0") ||
		strings.Contains(out, "uma") || strings.Contains(out, c.idp.srv.URL) {
		t.Fatalf("metrics:\n%s", out)
	}
	raw, err := os.ReadFile(c.audit.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.audit.path, []byte(strings.Replace(string(raw), "8h", "9h", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	c.audit.ready = false
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.WatchAudit(ctx, time.Millisecond); close(done) }()
	for deadline := time.Now().Add(5 * time.Second); c.breaks.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if out := scrape(); !strings.Contains(out, "tailnet_console_audit_chain_breaks 1") {
		t.Fatalf("break not counted:\n%s", out)
	}
}
