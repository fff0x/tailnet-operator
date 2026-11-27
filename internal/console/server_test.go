package console

import (
	"io"
	"net/http"
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

func TestMessagePage(t *testing.T) {
	c := newTestConsole(t, nil)
	resp := c.signIn(t, flow{returnTo: "/"}, map[string]any{"groups": []string{"other"}})
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "No access") || strings.Contains(string(body), "/auth/logout") {
		t.Fatalf("message page: %s", body)
	}
	writePreview(t, "no-access.html", string(body))
}
