package console

import (
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	c := newTestConsole(t, nil)
	for _, path := range []string{"/", "/auth/login", "/static/console.css", "/healthz", "/missing"} {
		resp := c.do(t, http.MethodGet, path, nil)
		h := resp.Header
		if h.Get("Content-Security-Policy") != contentSecurityPolicy || h.Get("X-Content-Type-Options") != "nosniff" ||
			h.Get("Referrer-Policy") != "no-referrer" || !strings.HasPrefix(h.Get("Strict-Transport-Security"), "max-age=") {
			t.Errorf("%s: headers %v", path, h)
		}
		if wantStore := !strings.HasPrefix(path, "/static/"); (h.Get("Cache-Control") == "no-store") != wantStore {
			t.Errorf("%s: Cache-Control %q", path, h.Get("Cache-Control"))
		}
	}
}

func TestStaticAssetsAndHealth(t *testing.T) {
	c := newTestConsole(t, nil)
	for path, ctype := range map[string]string{"/static/console.css": "text/css", "/static/logo.svg": "image/svg+xml",
		"/static/console.js": "text/javascript",
		"/healthz":           "text/plain", "/readyz": "text/plain"} {
		resp := c.do(t, http.MethodGet, path, nil)
		if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), ctype) {
			t.Errorf("%s: %d %q", path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
	}
	if resp := c.do(t, http.MethodGet, "/static/../auth.go", nil); resp.StatusCode == http.StatusOK {
		t.Error("source file served")
	}
}

// The page module is the only script, it is loaded by the overview alone, and the CSP admits no
// other source.
func TestScriptOnlyOnOverview(t *testing.T) {
	if !strings.Contains(contentSecurityPolicy, "script-src 'self';") || strings.Contains(contentSecurityPolicy, "unsafe") {
		t.Fatalf("CSP %q", contentSecurityPolicy)
	}
	c := newTestConsole(t, nil)
	sc := cookie(c.signIn(t, flow{returnTo: "/"}, map[string]any{"groups": []string{"users"}}), sessionCookie)
	const tag = `<script type="module" src="/static/console.js"></script>`
	for path, want := range map[string]bool{"/": true, "/access": false} {
		body, _ := io.ReadAll(c.do(t, http.MethodGet, path, []*http.Cookie{sc}).Body)
		if strings.Contains(string(body), tag) != want || strings.Count(string(body), "<script") != map[bool]int{true: 1}[want] {
			t.Errorf("%s: script present = %t, want %t", path, !want, want)
		}
	}
}

var managePaths = []string{"GET /grants", "GET /grants/new", "GET /audit", "POST /grants", "POST /grants/console-x/extend",
	"POST /requests/request-x/approve", "POST /requests/request-x/reject"}

// requestPaths are open to every signed-in person with access management.
var requestPaths = []string{"GET /requests", "GET /requests/new", "POST /requests", "POST /grants/console-x/request", "POST /requests/request-x/withdraw",
	"POST /grants/console-x/revoke"}

func (c *testConsole) call(t *testing.T, route string, cookies []*http.Cookie) *http.Response {
	t.Helper()
	method, path, _ := strings.Cut(route, " ")
	if method == http.MethodPost {
		return c.post(t, path, cookies, nil)
	}
	return c.do(t, method, path, cookies)
}

// Without the switch the routes and links do not exist; with it, only admins reach them.
func TestAccessManagementRoutes(t *testing.T) {
	off := newTestConsole(t, nil, sampleObjects()...)
	admin := off.admin(t)
	for _, route := range append(slices.Clone(managePaths), requestPaths...) {
		if resp := off.call(t, route, admin); resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("switch off, %s: %d", route, resp.StatusCode)
		}
	}
	body, _ := io.ReadAll(off.do(t, http.MethodGet, "/", admin).Body)
	if strings.Contains(string(body), `href="/grants"`) || strings.Contains(string(body), `href="/audit"`) || strings.Contains(string(body), `href="/requests"`) {
		t.Error("switch off: overview links to grant management")
	}

	on := newGrantConsole(t)
	user := []*http.Cookie{cookie(on.signIn(t, flow{returnTo: "/"}, map[string]any{"groups": []string{"users"}}), sessionCookie)}
	for _, route := range managePaths {
		if resp := on.call(t, route, user); resp.StatusCode != http.StatusForbidden {
			t.Errorf("user, %s: %d", route, resp.StatusCode)
		}
		if resp := on.call(t, route, nil); resp.StatusCode != http.StatusFound {
			t.Errorf("signed out, %s: %d", route, resp.StatusCode)
		}
	}
	for _, route := range requestPaths {
		if resp := on.call(t, route, nil); resp.StatusCode != http.StatusFound {
			t.Errorf("signed out, %s: %d", route, resp.StatusCode)
		}
	}
	body, _ = io.ReadAll(on.do(t, http.MethodGet, "/", user).Body)
	if strings.Contains(string(body), `href="/grants"`) || !strings.Contains(string(body), `href="/requests"`) {
		t.Error("user sees the grant link or lacks the request link")
	}
	admin = on.admin(t)
	body, _ = io.ReadAll(on.do(t, http.MethodGet, "/", admin).Body)
	if !strings.Contains(string(body), `href="/grants"`) || !strings.Contains(string(body), `href="/audit"`) {
		t.Error("admin lacks the grant links")
	}
	// Cross-origin protection covers the new forms.
	form := url.Values{"target": {"lab/ingress/apps/wiki"}, "ports": {"443"}, "sources": {aliceRef}, "duration": {"8h"}}
	if resp := on.post(t, "/grants", admin, form, "Sec-Fetch-Site", "cross-site"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site POST: %d", resp.StatusCode)
	}
	if resp := on.post(t, "/grants", admin, form, "Origin", "https://evil.example"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("foreign Origin POST: %d", resp.StatusCode)
	}
	if gs := on.consoleGrants(t); len(gs) != 0 {
		t.Errorf("cross-origin POST created %d grants", len(gs))
	}
}

// The grant, form and audit pages escape what people typed, and the pod log names nobody.
func TestGrantPagesEscapeAndLog(t *testing.T) {
	c := newGrantConsole(t)
	admin := c.admin(t)
	form := url.Values{"target": {"lab/ingress/apps/wiki"}, "ports": {"443, 22"}, "sources": {aliceRef, "group:staff"}, "duration": {"24h"},
		"description": {`<img src=x onerror=alert(1)>`}}
	if resp := c.post(t, "/grants", admin, form, "Sec-Fetch-Site", "same-origin"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	c.post(t, "/grants", admin, url.Values{"target": {"lab/site/office"}, "prefixes": {"10.99.0.0/24"}, "ports": {"x"}, "duration": {"1h"}})
	pages := map[string][]string{
		"/grants":     {"Alice A (" + aliceRef + ")", "&lt;img src=x", "from-git", "Git or kubectl", "Revoke", "24h 00m"},
		"/grants/new": {"ingress apps/wiki (tag:wiki)", "spoke zeta tag:db-zeta-1", "site office (10.20.0.0/16)"},
		"/grants/new?target=lab/ingress/apps/wiki": {`name="ports" value="443, 22"`, "Alice A · alice@example.com", "group:staff"},
		"/grants/new?target=lab/site/office":       {`name="prefixes" value="10.20.0.0/16"`},
		"/audit":                                   {"intact", "grant.create", testName, "&lt;img src=x"},
	}
	for path, wants := range pages {
		resp := c.do(t, http.MethodGet, path, admin)
		body, _ := io.ReadAll(resp.Body)
		html := string(body)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
		for _, want := range wants {
			if !strings.Contains(html, want) {
				t.Errorf("%s lacks %q", path, want)
			}
		}
		if strings.Contains(html, "<img src=x") {
			t.Errorf("%s does not escape the description", path)
		}
		switch path {
		case "/grants":
			writePreview(t, "grants.html", html)
		case "/grants/new?target=lab/ingress/apps/wiki":
			writePreview(t, "grant-new.html", html)
		case "/audit":
			writePreview(t, "audit.html", html)
		}
	}
	logs := c.logs.String()
	if !strings.Contains(logs, `"audit head"`) {
		t.Errorf("no audit head in the pod log:\n%s", logs)
	}
	for _, leak := range []string{testName, testSubject, "alice", "Alice", "onerror"} {
		if strings.Contains(logs, leak) {
			t.Errorf("pod log contains %q:\n%s", leak, logs)
		}
	}
}

// The request pages escape what people typed, the admin's link counts the undecided requests,
// and the pod log names nobody.
func TestRequestPagesEscapeAndLog(t *testing.T) {
	c := newRequestConsole(t, true)
	uma, ada, bea := c.as(t, "uma", false), c.as(t, "ada", true), c.as(t, "bea", true)
	form := url.Values{"target": {"lab/spoke/tag:db-zeta-1"}, "ports": {"5432"}, "duration": {"7d"}, "description": {`<img src=x onerror=alert(1)>`}}
	c.expect(t, "request", c.post(t, "/requests", uma, form), http.StatusSeeOther)
	first := c.latest(t)
	c.expect(t, "approve", c.post(t, "/requests/"+first.Name+"/approve", ada, nil), http.StatusSeeOther)
	c.expect(t, "approve", c.post(t, "/requests/"+first.Name+"/approve", bea, nil), http.StatusSeeOther)
	c.expect(t, "request", c.post(t, "/requests", uma, wikiForm), http.StatusSeeOther)
	second := c.latest(t, first.Name)
	c.expect(t, "approve", c.post(t, "/requests/"+second.Name+"/approve", ada, nil), http.StatusSeeOther)
	c.expect(t, "request", c.post(t, "/requests", uma, wikiForm), http.StatusSeeOther)
	third := c.latest(t, first.Name, second.Name)
	c.expect(t, "reject", c.post(t, "/requests/"+third.Name+"/reject", bea, nil), http.StatusSeeOther)
	for _, tc := range []struct {
		who     []*http.Cookie
		path    string
		preview string
		wants   []string
		absent  []string
	}{
		{ada, "/requests", "requests.html", []string{"&lt;img src=x", "Uma Example", "1 of 2 approvals", "approved by Ada Example", "by Bea Example",
			`<span class="count" title="1 undecided">1</span>`, "needs two admins", "tag:db-zeta-1", "Approve", "Reject"}, nil},
		// The requester sees how many approved and when it was decided, not who.
		{uma, "/requests", "requests-user.html", []string{"Your grants", "Ask to extend", "Withdraw", "Your requests", "7 days", "1 of 2 approvals",
			"2026-11-27 13:00 UTC"}, []string{"Ada Example", "Bea Example", c.id("ada"), c.id("bea"), "approved by"}},
		{uma, "/requests/new?target=lab/spoke/tag:db-zeta-1", "request-new.html", []string{"Recipient: Uma Example (you)", "Request grant", `action="/requests"`}, nil},
	} {
		resp := c.do(t, http.MethodGet, tc.path, tc.who)
		body, _ := io.ReadAll(resp.Body)
		html := string(body)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: %d", tc.path, resp.StatusCode)
		}
		for _, want := range tc.wants {
			if !strings.Contains(html, want) {
				t.Errorf("%s (%s) lacks %q", tc.path, tc.preview, want)
			}
		}
		for _, no := range tc.absent {
			if strings.Contains(html, no) {
				t.Errorf("%s (%s) shows %q", tc.path, tc.preview, no)
			}
		}
		if strings.Contains(html, "<img src=x") {
			t.Errorf("%s does not escape the description", tc.path)
		}
		writePreview(t, tc.preview, html)
	}
	logs := c.logs.String()
	// The bare "ada" and "bea" are hex and may occur in a logged hash; quoted they are a value.
	for _, leak := range []string{c.id("uma"), c.id("ada"), c.id("bea"), "\"uma\"", "\"ada\"", "\"bea\"", "Example", "onerror"} {
		if strings.Contains(logs, leak) {
			t.Errorf("pod log contains %q:\n%s", leak, logs)
		}
	}
}

func TestMessagePage(t *testing.T) {
	c := newTestConsole(t, nil)
	resp := c.signIn(t, flow{returnTo: "/"}, map[string]any{"groups": []string{"other"}})
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "No access") || strings.Contains(string(body), "/auth/logout") {
		t.Fatalf("message page: %s", body)
	}
	writePreview(t, "no-access.html", string(body))
}
