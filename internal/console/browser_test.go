package console

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// TestBrowserLive runs the page module in a real browser under the console's CSP: the overview
// picks up a change after its first load, and an ended session replaces the map by a notice. Set
// CONSOLE_BROWSER to a Chromium binary to run it.
func TestBrowserLive(t *testing.T) {
	browser := os.Getenv("CONSOLE_BROWSER")
	if browser == "" {
		t.Skip("CONSOLE_BROWSER not set")
	}
	for name, keepSession := range map[string]bool{"update": true, "session expired": false} {
		t.Run(name, func(t *testing.T) {
			c := newTestConsole(t, nil, sampleObjects()...)
			c.poll = 300 * time.Millisecond
			sc := cookie(c.signIn(t, flow{returnTo: "/"}, map[string]any{"groups": []string{"users"}}), sessionCookie)
			var pages atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// The browser cannot be handed the __Host- cookie, so the test server adds it.
				if r.URL.Path == "/" && (pages.Add(1) == 1 || keepSession) {
					r.AddCookie(sc)
				}
				c.h.ServeHTTP(w, r)
				if r.URL.Path == "/" && pages.Load() == 1 {
					added := &tnv1.TailnetSite{ObjectMeta: metav1.ObjectMeta{Name: "added-after-load"},
						Spec: tnv1.TailnetSiteSpec{TailnetRef: tnv1.TailnetRef{Name: "lab"}, Prefixes: []tnv1.GatewayPrefix{"10.30.0.0/16"}}}
					if err := c.reader.(interface {
						Create(context.Context, client.Object, ...client.CreateOption) error
					}).Create(context.Background(), added); err != nil {
						t.Error(err)
					}
				}
			}))
			t.Cleanup(srv.Close)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, browser, "--headless=new", "--disable-gpu", "--no-sandbox",
				"--user-data-dir="+t.TempDir(), "--virtual-time-budget=5000", "--dump-dom", srv.URL+"/").Output()
			if err != nil {
				t.Fatalf("browser: %v", err)
			}
			dom := string(out)
			if pages.Load() < 2 {
				t.Fatalf("the module did not poll: %d page loads\n%s", pages.Load(), dom)
			}
			if keepSession {
				for _, want := range []string{"added-after-load", "Live: updated", "data-tip="} {
					if !strings.Contains(dom, want) {
						t.Errorf("DOM lacks %q", want)
					}
				}
				if strings.Contains(dom, "<title>ingress") {
					t.Error("native tooltips not replaced")
				}
				return
			}
			if !strings.Contains(dom, "Session expired.") || !strings.Contains(dom, `href="/auth/login?return=%2F"`) ||
				strings.Contains(dom, `<figure class="map">`) {
				t.Errorf("no session notice:\n%s", dom)
			}
		})
	}
}
