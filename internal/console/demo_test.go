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
// changes its state every 15 seconds. Stop with Ctrl-C.
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
	c := newTestConsole(t, nil, objs...)
	users, _ := json.Marshal([]headscale.User{{ID: "1", Name: "alice", Email: "alice@example.com", ProviderID: c.idp.srv.URL + "/" + testSubject}})
	policy, _ := json.Marshal(`{"grants":[` +
		`{"src":["alice@"],"dst":["tag:wiki"],"ip":["tcp:443","tcp:22"]},` +
		`{"src":["alice@"],"dst":["tag:db-zeta-1"],"ip":["tcp:5432"]},` +
		`{"src":["autogroup:member"],"dst":["tag:api-zeta-2"],"ip":["tcp:8443"]}]}`)
	op, _, _ := fakeOperator(t, string(users), string(policy))
	c.dir = newDirectory(op.URL, tokenFile(t, "tok"))
	sc := cookie(c.signIn(t, flow{returnTo: "/"}, map[string]any{"groups": []string{"admins"}, "name": "Demo"}), sessionCookie)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.AddCookie(sc)
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
