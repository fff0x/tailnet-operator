package console

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

// TestDemo serves the console with sample data on a local address, for a look at the pages in a
// browser:
//
//	CONSOLE_DEMO=127.0.0.1:8090 go test ./internal/console -run TestDemo -timeout 0 -v
//
// It is not a way to run the console. The data is made up, and this test server puts one session
// into every request, because a browser does not keep the __Host- cookie over plain HTTP. The
// session ends after its hour, which shows the notice of the live update. The site "office"
// changes its state every 15 seconds. Grant management is on with four-eyes approval; its audit
// log lives in a temporary directory that the test removes when it stops. "?as=admin2" and
// "?as=user" switch to the second admin Bob and the user Carol, "?as=admin" back. Stop with Ctrl-C.
func TestDemo(t *testing.T) {
	addr := os.Getenv("CONSOLE_DEMO")
	if addr == "" {
		t.Skip("CONSOLE_DEMO not set")
	}
	objs := sampleObjects()
	for i := range 14 { // more than a list of the map shows one by one
		status := "True"
		if i == 13 {
			status = "False"
		}
		objs = append(objs, &tnv1.TailnetSite{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("branch-%02d", i)},
			Spec: tnv1.TailnetSiteSpec{TailnetRef: tnv1.TailnetRef{Name: "lab"}, Owner: "network team",
				Prefixes: []tnv1.GatewayPrefix{tnv1.GatewayPrefix(fmt.Sprintf("10.%d.0.0/16", 40+i))}},
			Status: tnv1.TailnetSiteStatus{Conditions: []metav1.Condition{cond("Ready", status, "Ready")}}})
	}
	objs = append(objs, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: testAnchorCM}})
	dir := t.TempDir()
	c := newTestConsole(t, func(cfg *Config) { cfg.AuditDir, cfg.AuditAnchor, cfg.Namespace = dir, testAnchorCM, testNS }, objs...)
	c.fourEyes = true
	users, _ := json.Marshal([]headscale.User{{ID: "1", Name: "alice", DisplayName: "Alice Example", Email: "alice@example.com", ProviderID: c.idp.srv.URL + "/" + testSubject},
		{ID: "2", Name: "bob", DisplayName: "Bob Example", ProviderID: c.id("bob")}, {ID: "3", Name: "carol", DisplayName: "Carol Example", ProviderID: c.id("carol")},
		{ID: "4", Name: "dave"}})
	policy, _ := json.Marshal(`{"groups":{"group:staff":["alice@"]},"grants":[` +
		`{"src":["alice@"],"dst":["tag:wiki"],"ip":["tcp:443","tcp:22"]},` +
		`{"src":["alice@"],"dst":["tag:db-zeta-1"],"ip":["tcp:5432"]},` +
		`{"src":["autogroup:member"],"dst":["tag:api-zeta-2"],"ip":["tcp:8443"]}]}`)
	op, _, _ := fakeOperator(t, string(users), string(policy))
	c.dir = newDirectory(op.URL, tokenFile(t, "tok"))
	sessions := map[string]*http.Cookie{
		"admin":  cookie(c.signIn(t, flow{returnTo: "/"}, map[string]any{"groups": []string{"admins"}, "name": "Demo"}), sessionCookie),
		"admin2": c.as(t, "bob", true)[0],
		"user":   c.as(t, "carol", false)[0],
	}
	c.expect(t, "demo request", c.post(t, "/requests", []*http.Cookie{sessions["user"]}, wikiForm), http.StatusSeeOther)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			as := "admin"
			if v := r.URL.Query().Get("as"); sessions[v] != nil {
				as = v
				http.SetCookie(w, &http.Cookie{Name: "demo-as", Value: v, Path: "/"})
			} else if ck, err := r.Cookie("demo-as"); err == nil && sessions[ck.Value] != nil {
				as = ck.Value
			}
			r.AddCookie(sessions[as])
			c.h.ServeHTTP(w, r)
		}))
	}()
	go func() {
		objects := c.reader.(client.Client)
		for ready := true; ; ready = !ready {
			select {
			case <-ctx.Done():
				return
			case <-time.After(15 * time.Second):
			}
			var site tnv1.TailnetSite
			if objects.Get(ctx, client.ObjectKey{Name: "office"}, &site) == nil {
				site.Status.Conditions = []metav1.Condition{cond("Ready", map[bool]string{true: "True", false: "False"}[ready],
					map[bool]string{true: "Ready", false: "NoGateway"}[ready])}
				_ = objects.Update(ctx, &site)
			}
		}
	}()
	t.Logf("console demo at http://%s/ (Ctrl-C stops it)", ln.Addr())
	<-ctx.Done()
	_ = ln.Close()
}
