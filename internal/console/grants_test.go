package console

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

const (
	aliceRef     = "https://id.example/alice@"
	testNS       = "tsunaro-system"
	testAnchorCM = "console-audit"
)

var grantNow = time.Date(2026, 11, 27, 13, 0, 0, 0, time.UTC)

// newGrantConsole runs the console with access management on, the sample objects, a grant from
// Git and a fake operator with one OIDC user, one local user and a group.
func newGrantConsole(t *testing.T) *testConsole {
	t.Helper()
	objs := append(sampleObjects(),
		&tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "plain"}, Spec: tnv1.TailnetSpec{Server: "https://hs2.example"}},
		&tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Name: "from-git"}, Spec: tnv1.TailnetGrantSpec{TailnetRef: tnv1.TailnetRef{Name: "lab"},
			Sources: []string{"group:staff"}, Target: tnv1.GrantTarget{Tag: "tag:wiki"}, Ports: []int32{443}}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: testAnchorCM}})
	dir := t.TempDir()
	c := newTestConsole(t, func(cfg *Config) { cfg.AuditDir, cfg.AuditAnchor, cfg.Namespace = dir, testAnchorCM, testNS }, objs...)
	op, _, _ := fakeOperator(t,
		`[{"id":"1","name":"alice","displayName":"Alice A","email":"alice@example.com","providerId":"https://id.example/alice"},{"id":"2","name":"carol"}]`,
		`"{\"groups\":{\"group:staff\":[\"https://id.example/alice@\"]},\"grants\":[{\"src\":[\"group:staff\"],\"dst\":[\"tag:db-zeta-1\"],\"ip\":[\"tcp:5432\"]}]}"`)
	c.dir = newDirectory(op.URL, tokenFile(t, "tok"))
	c.now = func() time.Time { return grantNow }
	c.audit.now = c.now
	return c
}

func (c *testConsole) post(t *testing.T, target string, cookies []*http.Cookie, form url.Values, headers ...string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "https://console.example"+target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	return rec.Result()
}

func (c *testConsole) admin(t *testing.T) []*http.Cookie {
	t.Helper()
	return []*http.Cookie{cookie(c.signIn(t, flow{returnTo: "/"}, map[string]any{"groups": []string{"admins"}}), sessionCookie)}
}

func (c *testConsole) grant(t *testing.T, name string) *tnv1.TailnetGrant {
	t.Helper()
	var g tnv1.TailnetGrant
	if err := c.writer.Get(context.Background(), client.ObjectKey{Name: name}, &g); err != nil {
		t.Fatal(err)
	}
	return &g
}

func (c *testConsole) consoleGrants(t *testing.T) []tnv1.TailnetGrant {
	t.Helper()
	var list tnv1.TailnetGrantList
	if err := c.writer.List(context.Background(), &list, client.MatchingLabels{managedByLabel: managedBy}); err != nil {
		t.Fatal(err)
	}
	return list.Items
}

func actions(st auditState) []string {
	var out []string
	for _, e := range st.Entries {
		out = append(out, e.Action)
	}
	return out
}

// Targets of policy-owning Tailnets only, the hub's own tags not as spoke tags,
// recipients only with a provider identifier, and the live policy's groups.
func TestGrantOptions(t *testing.T) {
	c := newGrantConsole(t)
	opts, err := c.grantOptions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) != 1 || opts[0].Name != "lab" || opts[0].Problem {
		t.Fatalf("tailnets %+v", opts)
	}
	byKey := map[string]grantTarget{}
	for _, tg := range opts[0].Targets {
		byKey[tg.Key] = tg
	}
	if in := byKey["lab/ingress/apps/wiki"]; in.Tag != "tag:wiki" || !slices.Equal(in.Ports, []int32{443, 22}) {
		t.Errorf("ingress target %+v", in)
	}
	if sp := byKey["lab/spoke/tag:db-zeta-1"]; sp.Tag != "tag:db-zeta-1" || !slices.Equal(sp.Ports, []int32{5432}) {
		t.Errorf("spoke target %+v", sp)
	}
	if st := byKey["lab/site/office"]; st.Tag != "" || !slices.Equal(st.Site, []string{"10.20.0.0/16"}) || st.Ports != nil {
		t.Errorf("site target %+v", st)
	}
	if len(byKey) != 3 {
		t.Errorf("targets %v", opts[0].Targets)
	}
	if want := []grantRecipient{{aliceRef, "Alice A · alice@example.com"}, {"group:staff", "group:staff"}}; !slices.Equal(opts[0].Recipients, want) {
		t.Errorf("recipients %+v", opts[0].Recipients)
	}
}

// The server checks every field against the options.
func TestBuildGrantSpec(t *testing.T) {
	c := newGrantConsole(t)
	opts, err := c.grantOptions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ok := grantForm{Target: "lab/ingress/apps/wiki", Ports: "443, 22 443", Sources: []string{"group:staff", aliceRef, aliceRef}, Duration: "7d", Description: " Wiki for Q4 "}
	spec, errs := buildGrantSpec(ok, opts, grantNow)
	if len(errs) > 0 || spec.TailnetRef.Name != "lab" || spec.Target.Tag != "tag:wiki" || spec.Target.Prefixes != nil ||
		!slices.Equal(spec.Ports, []int32{22, 443}) || !slices.Equal(spec.Sources, []string{"group:staff", aliceRef}) ||
		!spec.ExpiresAt.Equal(&metav1.Time{Time: grantNow.Add(7 * 24 * time.Hour)}) || spec.Description != "Wiki for Q4" {
		t.Fatalf("spec %+v, errors %q", spec, errs)
	}
	site := grantForm{Target: "lab/site/office", Prefixes: "10.20.30.5, 10.20.64.0/18", Ports: "3389", Sources: []string{aliceRef}, Duration: "permanent"}
	spec, errs = buildGrantSpec(site, opts, grantNow)
	if len(errs) > 0 || spec.Target.Tag != "" || !slices.Equal(spec.Target.Prefixes, []tnv1.GatewayPrefix{"10.20.30.5/32", "10.20.64.0/18"}) || spec.ExpiresAt != nil {
		t.Fatalf("site spec %+v, errors %q", spec, errs)
	}
	for name, tc := range map[string]struct {
		mutate func(*grantForm)
		want   string
	}{
		"unknown target":         {func(f *grantForm) { f.Target = "lab/ingress/apps/other" }, "target"},
		"tailnet without policy": {func(f *grantForm) { f.Target = "plain/ingress/apps/wiki" }, "target"},
		"no port":                {func(f *grantForm) { f.Ports = " " }, "1 to 16 TCP ports"},
		"port zero":              {func(f *grantForm) { f.Ports = "0" }, "not a TCP port"},
		"port too high":          {func(f *grantForm) { f.Ports = "65536" }, "not a TCP port"},
		"port range":             {func(f *grantForm) { f.Ports = "8000-8080" }, "not a TCP port"},
		"17 ports":               {func(f *grantForm) { f.Ports = "1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17" }, "1 to 16 TCP ports"},
		"no recipient":           {func(f *grantForm) { f.Sources = nil }, "1 to 16 recipients"},
		"local user":             {func(f *grantForm) { f.Sources = []string{"carol@"} }, "recipients from the list"},
		"tag as recipient":       {func(f *grantForm) { f.Sources = []string{"tag:ci"} }, "recipients from the list"},
		"free duration":          {func(f *grantForm) { f.Duration = "2h" }, "duration"},
		"long description":       {func(f *grantForm) { f.Description = strings.Repeat("ä", 254) }, "253 characters"},
		"multi-line":             {func(f *grantForm) { f.Description = "a\nb" }, "one line"},
		"prefix outside":         {func(f *grantForm) { f.Target, f.Prefixes = "lab/site/office", "10.30.0.0/24" }, "outside the site"},
		"prefix wider":           {func(f *grantForm) { f.Target, f.Prefixes = "lab/site/office", "10.0.0.0/8" }, "outside the site"},
		"unmasked prefix":        {func(f *grantForm) { f.Target, f.Prefixes = "lab/site/office", "10.20.0.1/16" }, "masked prefix"},
		"hostname":               {func(f *grantForm) { f.Target, f.Prefixes = "lab/site/office", "db.office" }, "masked prefix"},
		"site without prefix":    {func(f *grantForm) { f.Target, f.Prefixes = "lab/site/office", "" }, "inside the site"},
	} {
		f := ok
		f.Sources = slices.Clone(ok.Sources)
		tc.mutate(&f)
		if _, errs := buildGrantSpec(f, opts, grantNow); !slices.ContainsFunc(errs, func(e string) bool { return strings.Contains(e, tc.want) }) {
			t.Errorf("%s: errors %q, want %q", name, errs, tc.want)
		}
	}
	// A spoke tag keeps its tag; the form's prefixes are ignored.
	sp := grantForm{Target: "lab/spoke/tag:db-zeta-1", Ports: "5432", Prefixes: "10.0.0.0/8", Sources: []string{"group:staff"}, Duration: "1h"}
	if spec, errs := buildGrantSpec(sp, opts, grantNow); len(errs) > 0 || spec.Target.Tag != "tag:db-zeta-1" || spec.Target.Prefixes != nil {
		t.Errorf("spoke spec %+v, errors %q", spec, errs)
	}
}

// Create, extend and revoke through the HTTP routes: only console grants change, and each change
// has its audit entry.
func TestGrantLifecycle(t *testing.T) {
	c := newGrantConsole(t)
	admin := c.admin(t)
	form := url.Values{"target": {"lab/ingress/apps/wiki"}, "ports": {"443"}, "sources": {aliceRef}, "duration": {"8h"}, "description": {"on call"}}
	if resp := c.post(t, "/grants", admin, form); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/grants" {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	gs := c.consoleGrants(t)
	if len(gs) != 1 || !strings.HasPrefix(gs[0].Name, "console-") || len(gs[0].Name) != len("console-")+10 {
		t.Fatalf("grants %+v", gs)
	}
	name := gs[0].Name
	if g := gs[0]; g.Spec.Target.Tag != "tag:wiki" || !g.Spec.ExpiresAt.Time.Equal(grantNow.Add(8*time.Hour)) || g.Spec.Description != "on call" {
		t.Fatalf("spec %+v", g.Spec)
	}
	if resp := c.post(t, "/grants/"+name+"/extend", admin, url.Values{"duration": {"30d"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("extend: %d", resp.StatusCode)
	}
	if g := c.grant(t, name); !g.Spec.ExpiresAt.Time.Equal(grantNow.Add(30 * 24 * time.Hour)) {
		t.Fatalf("extended to %v", g.Spec.ExpiresAt)
	}
	if resp := c.post(t, "/grants/"+name+"/extend", admin, url.Values{"duration": {"permanent"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("extend permanent: %d", resp.StatusCode)
	}
	if g := c.grant(t, name); g.Spec.ExpiresAt != nil {
		t.Fatalf("permanent grant expires %v", g.Spec.ExpiresAt)
	}
	if resp := c.post(t, "/grants/"+name+"/revoke", admin, nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if g := c.grant(t, name); !g.Spec.ExpiresAt.Time.Equal(grantNow) {
		t.Fatalf("revoked to %v", g.Spec.ExpiresAt)
	}
	// A grant from Git stays as it is, and nothing is recorded for it.
	for _, path := range []string{"/grants/from-git/extend", "/grants/from-git/revoke"} {
		if resp := c.post(t, path, admin, url.Values{"duration": {"1h"}}); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
	}
	if g := c.grant(t, "from-git"); g.Spec.ExpiresAt != nil {
		t.Error("grant from Git changed")
	}
	if resp := c.post(t, "/grants/missing/revoke", admin, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing grant: %d", resp.StatusCode)
	}
	if resp := c.post(t, "/grants/"+name+"/extend", admin, url.Values{"duration": {"2h"}}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("free duration: %d", resp.StatusCode)
	}
	// An invalid form shows the form again and changes nothing.
	bad := url.Values{"target": {"lab/ingress/apps/wiki"}, "ports": {"0"}, "sources": {"carol@"}, "duration": {"8h"}}
	if resp := c.post(t, "/grants", admin, bad); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid form: %d", resp.StatusCode)
	}
	st := c.audit.state(context.Background())
	if got := actions(st); !slices.Equal(got, []string{"grant.create", "grant.extend", "grant.extend", "grant.revoke"}) || len(st.Breaks) > 0 {
		t.Fatalf("audit %q, breaks %q", got, st.Breaks)
	}
	create := st.Entries[0]
	if create.Grant != name || create.Tailnet != "lab" || create.Actor.Subject != testSubject || create.Actor.Name != testName ||
		create.Details["tag"] != "tag:wiki" || create.Details["expiresAt"] != "2026-11-27T21:00:00Z" {
		t.Errorf("create entry %+v", create)
	}
	if rv := st.Entries[3].Details; rv["from"] != "permanent" || rv["to"] != "2026-11-27T13:00:00Z" {
		t.Errorf("revoke details %v", rv)
	}
}

// Without the audit anchor the console refuses and creates nothing.
func TestGrantRefusedWithoutAudit(t *testing.T) {
	c := newGrantConsole(t)
	admin := c.admin(t)
	if err := c.writer.Delete(context.Background(), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: testAnchorCM}}); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"target": {"lab/ingress/apps/wiki"}, "ports": {"443"}, "sources": {aliceRef}, "duration": {"8h"}}
	if resp := c.post(t, "/grants", admin, form); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if gs := c.consoleGrants(t); len(gs) != 0 {
		t.Fatalf("grant created without audit: %+v", gs)
	}
	if raw, _ := os.ReadFile(c.audit.path); len(raw) > 0 {
		t.Fatalf("log written without anchor: %s", raw)
	}
	resp := c.do(t, http.MethodGet, "/audit", admin)
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "refuses every change") {
		t.Errorf("audit page does not show the problem:\n%s", body)
	}
}

type conflictWriter struct{ client.Client }

func (conflictWriter) Create(context.Context, client.Object, ...client.CreateOption) error {
	return apierrors.NewConflict(schema.GroupResource{Group: "tsunaro.io", Resource: "tailnetgrants"}, "x", nil)
}

// A refused write follows its entry with a "failed" entry carrying the status code; a conflict
// answers 409.
func TestGrantWriteFailure(t *testing.T) {
	c := newGrantConsole(t)
	admin := c.admin(t)
	c.writer = conflictWriter{c.writer}
	form := url.Values{"target": {"lab/ingress/apps/wiki"}, "ports": {"443"}, "sources": {aliceRef}, "duration": {"8h"}}
	if resp := c.post(t, "/grants", admin, form); resp.StatusCode != http.StatusConflict {
		t.Fatalf("status %d", resp.StatusCode)
	}
	st := c.audit.state(context.Background())
	if got := actions(st); !slices.Equal(got, []string{"grant.create", actionFailed}) {
		t.Fatalf("audit %q", got)
	}
	if f := st.Entries[1]; f.Grant != st.Entries[0].Grant || f.Details["action"] != "grant.create" || f.Details["status"] != float64(http.StatusConflict) {
		t.Errorf("failed entry %+v", f)
	}
}
