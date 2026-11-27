package console

import (
	"context"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func cond(t, status, reason string) metav1.Condition {
	return metav1.Condition{Type: t, Status: metav1.ConditionStatus(status), Reason: reason}
}

func sampleObjects() []client.Object {
	return []client.Object{
		&tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "lab"},
			Spec: tnv1.TailnetSpec{Server: "https://hs.example", Policy: tnv1.PolicySpec{BaseConfigMap: "base", Mode: "Apply",
				Spokes: []tnv1.SpokeRef{{Name: "zeta"}, {Name: "alpha"}}}},
			Status: tnv1.TailnetStatus{Version: "0.29.6",
				Policy:     &tnv1.PolicyStatus{Generated: tnv1.PolicyGenerated{Tags: 7, Grants: 12, Routes: 2}},
				Conditions: []metav1.Condition{cond("PolicyApplied", "True", "Applied")},
				Spokes: []tnv1.SpokeStatus{
					{Name: "zeta", Conditions: []metav1.Condition{cond("SpokeReachable", "True", "Fetched"),
						cond("SpokeFragmentValid", "True", "Valid"), cond("SpokeFragmentApproved", "True", "Approved")}},
					{Name: "alpha", PendingHash: "sha256:1", Conditions: []metav1.Condition{cond("SpokeReachable", "False", "Unreachable")}},
				}}},
		&tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "wiki"},
			Spec: tnv1.TailnetIngressSpec{TailnetRef: tnv1.TailnetRef{Name: "lab"},
				AllowFrom: []string{"group:staff", "alice@", "bob@example.com", "tag:ci"},
				Exposes:   []tnv1.Expose{{Name: "web", Mode: "http", Port: 443}, {Name: "ssh", Port: 22}}},
			Status: tnv1.TailnetIngressStatus{Tag: "tag:wiki", Hosts: []string{"wiki.tail.example"},
				Conditions: []metav1.Condition{cond("Ready", "True", "Ready")}}},
		&tnv1.TailnetSite{ObjectMeta: metav1.ObjectMeta{Name: "office"},
			Spec: tnv1.TailnetSiteSpec{TailnetRef: tnv1.TailnetRef{Name: "lab"}, Prefixes: []tnv1.GatewayPrefix{"10.20.0.0/16"},
				Owner: "network team", Description: `<script>alert("x")</script>`},
			Status: tnv1.TailnetSiteStatus{Conditions: []metav1.Condition{cond("Ready", "False", "NoGateway")}}},
	}
}

func TestOverviewModel(t *testing.T) {
	c := newTestConsole(t, nil, sampleObjects()...)
	o, err := c.loadOverview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Tailnets) != 1 || o.Tailnets[0].Mode != "Apply" || o.Tailnets[0].Generated != "7 tags, 12 grants, 2 routes" ||
		o.Tailnets[0].Policy != (state{"Applied", "ok"}) {
		t.Fatalf("tailnets %+v", o.Tailnets)
	}
	if len(o.Spokes) != 2 || o.Spokes[0].Name != "alpha" || !o.Spokes[0].Pending || o.Spokes[0].Reachable.Class != "bad" ||
		o.Spokes[0].Approved.Class != "unknown" || o.Spokes[1].Approved != (state{"Approved", "ok"}) {
		t.Fatalf("spokes %+v", o.Spokes)
	}
	in := o.Ingresses[0]
	if strings.Join(in.AllowFrom, ",") != "group:staff,tag:ci,2 user(s)" || strings.Join(in.Ports, ",") != "443/http,22/l4" {
		t.Fatalf("ingress %+v", in)
	}
	if o.Sites[0].Ready != (state{"NoGateway", "bad"}) || o.Sites[0].Prefixes[0] != "10.20.0.0/16" {
		t.Fatalf("sites %+v", o.Sites)
	}
	for mode, tn := range map[string]tnv1.Tailnet{
		"off":    {},
		"DryRun": {Spec: tnv1.TailnetSpec{Policy: tnv1.PolicySpec{BaseConfigMap: "b"}}},
		"Export": {Spec: tnv1.TailnetSpec{Policy: tnv1.PolicySpec{Mode: "Export"}}},
	} {
		if got := policyMode(&tn); got != mode {
			t.Errorf("policyMode = %q, want %q", got, mode)
		}
	}
}

// Rule: the chosen mode is neutral (DryRun, PolicyModeFile, Export grey); HubPending, NoAPIKey
// and errors are red.
func TestPolicyStateColours(t *testing.T) {
	for reason, want := range map[string]struct{ status, class string }{
		"Applied": {"True", "ok"}, "InSync": {"True", "ok"}, "HubMerged": {"True", "ok"},
		"DryRun": {"False", "unknown"}, "PolicyModeFile": {"False", "unknown"}, "Export": {"False", "unknown"},
		"HubPending": {"False", "bad"}, "NoAPIKey": {"False", "bad"}, "AnyOtherFailure": {"False", "bad"},
	} {
		got := policyState([]metav1.Condition{cond("PolicyApplied", want.status, reason)})
		if got != (state{reason, want.class}) {
			t.Errorf("%s/%s: got %+v, want class %s", want.status, reason, got, want.class)
		}
	}
	if got := policyState(nil); got.Class != "unknown" {
		t.Errorf("no condition: %+v", got)
	}
	// The rule is about PolicyApplied only: another condition with a mode-like reason stays red.
	if got := condState([]metav1.Condition{cond("Ready", "False", "DryRun")}, "Ready"); got.Class != "bad" {
		t.Errorf("Ready=False/DryRun: %+v", got)
	}
}

func TestOverviewPageMasksAndEscapes(t *testing.T) {
	c := newTestConsole(t, nil, sampleObjects()...)
	op, _, _ := fakeOperator(t, `[{"id":"1","name":"alice","email":"alice@example.com"}]`,
		`"{\"grants\":[{\"src\":[\"alice@\"],\"dst\":[\"tag:wiki\"],\"ip\":[\"tcp:443\"]}]}"`)
	c.dir = newDirectory(op.URL, tokenFile(t, "tok"))
	sc := cookie(c.signIn(t, flow{returnTo: "/"}, map[string]any{"groups": []string{"admins"}, "name": `<b>Eve</b>`}), sessionCookie)
	resp := c.do(t, http.MethodGet, "/", []*http.Cookie{sc})
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, want := range []string{"tag:wiki", "wiki.tail.example", "2 user(s)", "group:staff", "NoGateway", "&lt;b&gt;Eve&lt;/b&gt;",
		"&lt;script&gt;", `action="/auth/logout"`, "badge--admin"} {
		if !strings.Contains(html, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, leak := range []string{"alice@", "bob@example.com", "<script>", "<b>Eve"} {
		if strings.Contains(html, leak) {
			t.Errorf("page contains %q", leak)
		}
	}
	// The map: one per Tailnet inside the live part, with the poll interval; rule 8 for its text.
	start, end := strings.Index(html, `<figure class="map">`), strings.Index(html, "</figure>")
	if start < 0 || end < start || !strings.Contains(html, `data-live data-poll="10000"`) {
		t.Fatalf("no map or live part:\n%s", html)
	}
	fig := html[start:end]
	for _, want := range []string{`aria-label="Map of Tailnet lab"`, "Hub · lab", "apps/wiki", "office", "Spoke · alpha", "Spoke · zeta", "map__nodes--offline"} {
		if !strings.Contains(fig, want) {
			t.Errorf("map lacks %q", want)
		}
	}
	for _, leak := range []string{"alice", "db-1", "wiki-1", "network team", "group:staff", "&lt;script&gt;"} {
		if strings.Contains(fig, leak) {
			t.Errorf("map contains %q", leak)
		}
	}
	writePreview(t, "overview.html", html)
}

func TestOverviewReadFailure(t *testing.T) {
	c := newTestConsole(t, nil)
	c.reader = failingReader{}
	sc := cookie(c.signIn(t, flow{returnTo: "/"}, map[string]any{"groups": []string{"users"}}), sessionCookie)
	if resp := c.do(t, http.MethodGet, "/", []*http.Cookie{sc}); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

type failingReader struct{ client.Reader }

func (failingReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return context.DeadlineExceeded
}

// writePreview stores a page with relative asset paths when CONSOLE_PREVIEW_DIR is set, so it opens
// straight from disk.
func writePreview(t *testing.T, name, html string) {
	t.Helper()
	dir := os.Getenv("CONSOLE_PREVIEW_DIR")
	if dir == "" {
		return
	}
	static, _ := fs.Sub(assets, "assets/static")
	if err := os.CopyFS(filepath.Join(dir, "static"), static); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.ReplaceAll(html, `"/static/`, `"static/`)), 0o644); err != nil {
		t.Fatal(err)
	}
}
