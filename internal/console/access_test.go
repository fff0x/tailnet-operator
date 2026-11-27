package console

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

const accessIssuer = "https://id.example"

var accessNow = time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)

// accessPolicy exercises every clause of the rule. Each rule's first port names it in the tests.
const accessPolicy = `{
  // HuJSON, as Headscale stores it
  "groups": {"group:staff": ["alice@"], "group:ops": ["bob@"], "group:pid": ["https://id.example/sub-1@"]},
  "grants": [
    {"src": ["alice@"], "dst": ["tag:wiki"], "ip": ["tcp:443"]},
    {"src": ["alice@example.com"], "dst": ["tag:db"], "ip": ["tcp:5432"]},
    {"src": ["https://id.example/sub-1@"], "dst": ["10.20.0.0/16"], "ip": ["tcp:22"]},
    {"src": ["group:staff"], "dst": ["tag:ci"], "ip": ["tcp:8001"]},
    {"src": ["group:ops"], "dst": ["tag:ops"], "ip": ["tcp:8002"]},
    {"src": ["autogroup:member"], "dst": ["tag:wiki"], "ip": ["tcp:80"]},
    {"src": ["*"], "dst": ["bob@"], "ip": ["tcp:8003"]},
    {"src": ["tag:ci", "autogroup:tagged", "100.64.0.9", "autogroup:danger-all"], "dst": ["tag:db"], "ip": ["tcp:8004"]},
    {"src": ["group:pid", "autogroup:member"], "dst": ["alice@"], "ip": ["tcp:8005"]},
    {"src": ["alice@"], "dst": ["tag:wiki"], "app": {"example.com/cap": [{}]}},
  ],
  "acls": [{"action": "accept", "src": ["alice@"], "dst": ["tag:git:2222", "tag:git:8006"]}],
}`

var accessUsers = []headscale.User{
	{ID: "2", Name: "bob", Email: "bob@example.com", ProviderID: "https://id.example/sub-2"},
	{ID: "1", Name: "alice", DisplayName: "Alice", Email: "alice@example.com", ProviderID: "https://id.example/sub-1"},
}

func ready(status string) []metav1.Condition {
	return []metav1.Condition{cond("Ready", status, "Granted")}
}

func accessObjects() tailnetObjects {
	soon := metav1.NewTime(accessNow.Add(2*time.Hour + 30*time.Minute))
	return tailnetObjects{
		ingresses: []tnv1.TailnetIngress{{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "wiki"},
			Spec:   tnv1.TailnetIngressSpec{AllowFrom: []string{"alice@", "group:ops"}, Exposes: []tnv1.Expose{{Port: 443}}},
			Status: tnv1.TailnetIngressStatus{Tag: "tag:wiki", Hosts: []string{"wiki.tail.example"}}}},
		sites: []tnv1.TailnetSite{{ObjectMeta: metav1.ObjectMeta{Name: "office"},
			Spec: tnv1.TailnetSiteSpec{Prefixes: []tnv1.GatewayPrefix{"10.20.0.0/16"}}}},
		grants: []tnv1.TailnetGrant{
			// Same rule, but not in the live policy: never the origin.
			{ObjectMeta: metav1.ObjectMeta{Name: "stale"}, Spec: tnv1.TailnetGrantSpec{Sources: []string{"alice@example.com"},
				Target: tnv1.GrantTarget{Tag: "tag:db"}, Ports: []int32{5432}}, Status: tnv1.TailnetGrantStatus{Conditions: ready("False")}},
			// The live rule lacks bob@ (a shortened source list still matches).
			{ObjectMeta: metav1.ObjectMeta{Name: "db-alice"}, Spec: tnv1.TailnetGrantSpec{Sources: []string{"alice@example.com", "bob@"},
				Target: tnv1.GrantTarget{Tag: "tag:db"}, Ports: []int32{5432}, ExpiresAt: &soon}, Status: tnv1.TailnetGrantStatus{Conditions: ready("True")}},
		},
	}
}

func byPort(rows []accessRow) map[string]accessRow {
	out := map[string]accessRow{}
	for _, r := range rows {
		out[strings.TrimPrefix(r.Ports[0], "tcp:")] = r
	}
	return out
}

func TestAccessRule(t *testing.T) {
	var sec accessSection
	if err := evaluate(&sec, tailnetData{Users: accessUsers, Policy: accessPolicy}, accessIssuer+"/", "sub-1", accessObjects(), accessNow); err != nil {
		t.Fatal(err)
	}
	personal, everyone := byPort(sec.Personal), byPort(sec.Everyone)
	join := func(v []string) string { return strings.Join(v, ",") }
	for port, want := range map[string]struct{ via, target, name, origin, expires string }{
		"443":  {"you", "tag:wiki", "ingress apps/wiki (wiki.tail.example)", "TailnetIngress apps/wiki", ""}, // user name
		"5432": {"you", "tag:db", "", "TailnetGrant db-alice", "2h 30m (2026-11-27 12:30 UTC)"},              // e-mail
		"22":   {"you", "10.20.0.0/16", "site office", "Policy", ""},                                         // providerId
		"8001": {"group:staff", "tag:ci", "", "Policy", ""},                                                  // own group
		"8005": {"group:pid", "your devices", "", "Policy", ""},                                              // personal wins over everyone
	} {
		r, ok := personal[port]
		if !ok || join(r.Via) != want.via || r.Targets[0].Value != want.target || r.Targets[0].Name != want.name ||
			r.Origin != want.origin || r.Expires != want.expires {
			t.Errorf("personal %s = %+v (present %t), want %+v", port, r, ok, want)
		}
	}
	if r := personal["22"]; len(r.Targets) != 1 || join(r.Ports) != "tcp:22" {
		t.Errorf("rule as written: %+v", r)
	}
	acl := personal["2222"]
	if join(acl.Ports) != "2222,8006" || join(acl.Via) != "you" || len(acl.Targets) != 1 || acl.Targets[0].Value != "tag:git" || acl.Origin != "Policy" {
		t.Errorf("ACL row = %+v", acl)
	}
	if len(sec.Personal) != 6 {
		t.Errorf("personal rows = %d, want 6 (no group:ops, no device sources, no app-only grant)", len(sec.Personal))
	}
	if len(everyone) != 2 || join(everyone["80"].Via) != "autogroup:member" || join(everyone["8003"].Via) != "*" ||
		everyone["8003"].Targets[0].Value != "a user's devices" || everyone["80"].Origin != "Policy" {
		t.Errorf("everyone = %+v", sec.Everyone)
	}
	if sec.Unknown {
		t.Error("person not found")
	}
}

func TestAccessRuleIdentity(t *testing.T) {
	policy := `{"grants":[{"src":["@"],"dst":["tag:a"],"ip":["tcp:1"]},{"src":["autogroup:member"],"dst":["tag:b"],"ip":["tcp:2"]}]}`
	for name, tc := range map[string]struct {
		users           []headscale.User
		issuer, subject string
		unknown         bool
		personal        int
	}{
		"other issuer":         {accessUsers, "https://other.example", "sub-1", true, 0},
		"other subject":        {accessUsers, accessIssuer, "sub-9", true, 0},
		"no providerId":        {[]headscale.User{{Name: "alice"}}, accessIssuer, "", true, 0},
		"empty fields":         {[]headscale.User{{ProviderID: "https://id.example/s"}}, accessIssuer, "s", false, 0},
		"empty issuer segment": {accessUsers, accessIssuer + "//", "sub-1", false, 0},
	} {
		t.Run(name, func(t *testing.T) {
			var sec accessSection
			if err := evaluate(&sec, tailnetData{Users: tc.users, Policy: policy}, tc.issuer, tc.subject, tailnetObjects{}, accessNow); err != nil {
				t.Fatal(err)
			}
			if sec.Unknown != tc.unknown || len(sec.Personal) != tc.personal {
				t.Fatalf("section = %+v", sec)
			}
			if tc.unknown && len(sec.Everyone) != 0 {
				t.Fatal("an unknown person must see nothing")
			}
		})
	}
	if err := evaluate(&accessSection{}, tailnetData{Users: accessUsers, Policy: `{"grants": [alice@`}, accessIssuer, "sub-1", tailnetObjects{}, accessNow); err == nil ||
		strings.Contains(err.Error(), "alice") {
		t.Fatalf("broken policy: %v", err)
	}
	var empty accessSection
	if err := evaluate(&empty, tailnetData{Users: accessUsers}, accessIssuer, "sub-1", tailnetObjects{}, accessNow); err != nil || empty.Unknown {
		t.Fatalf("empty policy: %+v, %v", empty, err)
	}
}

// The first five expectations are Headscale's own (hscontrol/types/users_test.go at v0.29.6); the
// next two are subjects that the URL encoding changes.
func TestProviderID(t *testing.T) {
	for _, tc := range [][3]string{
		{"https://oidc.example.com/", "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "https://oidc.example.com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},
		{"HTTPS://oidc.example.com/", "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "https://oidc.example.com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},
		{"https://login.microsoftonline.com//v2.0", "I-70OQnj3TogrNSfkZQqB3f7dGwyBWSm1dolHNKrMzQ", "https://login.microsoftonline.com/v2.0/I-70OQnj3TogrNSfkZQqB3f7dGwyBWSm1dolHNKrMzQ"},
		{"oidc/", "sub/", "oidc/sub"},
		{"   oidc/   ", "   sub   ", "oidc/sub"},
		{"https://tenant.eu.auth0.com/", "auth0|64f1c0ffee", "https://tenant.eu.auth0.com/auth0%7C64f1c0ffee"},
		{"https://id.example.com", "user name", "https://id.example.com/user%20name"},
		{"", "sub", ""},
		{"https://oidc.example.com", "", ""},
	} {
		if got := providerID(tc[0], tc[1]); got != tc[2] {
			t.Errorf("providerID(%q, %q) = %q, want %q", tc[0], tc[1], got, tc[2])
		}
	}
}

// An ACL gives one row per distinct port set, with exactly the destinations that carry it.
func TestACLRows(t *testing.T) {
	_, rules, err := parseLive(`{"acls": [{"action": "accept", "proto": "tcp", "src": ["alice@"],
		"dst": ["tag:a:80", "tag:b:443", "tag:c:80", "tag:b:8443,443"]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rules {
		got = append(got, strings.Join(r.dst, ",")+" "+strings.Join(r.ports, ","))
	}
	if want := "tag:a,tag:c tcp:80; tag:b tcp:443,tcp:8443"; strings.Join(got, "; ") != want {
		t.Errorf("rows = %q, want %q", got, want)
	}
}

// Of two grants with the same target and ports, the one with the rule's exact sources is named.
func TestOriginPrefersEqualSources(t *testing.T) {
	late, soon := metav1.NewTime(accessNow.Add(72*time.Hour)), metav1.NewTime(accessNow.Add(time.Hour))
	grant := func(name string, expires *metav1.Time, sources ...string) tnv1.TailnetGrant {
		return tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: tnv1.TailnetGrantSpec{Sources: sources,
			Target: tnv1.GrantTarget{Tag: "tag:db"}, Ports: []int32{5432}, ExpiresAt: expires}, Status: tnv1.TailnetGrantStatus{Conditions: ready("True")}}
	}
	objs := tailnetObjects{grants: []tnv1.TailnetGrant{grant("wide", &late, "alice@", "bob@"), grant("narrow", &soon, "alice@")}}
	for src, want := range map[string]string{"alice@": "TailnetGrant narrow", "alice@,bob@": "TailnetGrant wide", "bob@": "TailnetGrant wide"} {
		rule := liveRule{src: strings.Split(src, ","), dst: []string{"tag:db"}, ports: []string{"tcp:5432"}, grant: true}
		if got, _ := origin(rule, objs, accessNow); got != want {
			t.Errorf("origin(src %s) = %q, want %q", src, got, want)
		}
	}
	if _, expires := origin(liveRule{src: []string{"alice@"}, dst: []string{"tag:db"}, ports: []string{"tcp:5432"}}, objs, accessNow); !strings.HasPrefix(expires, "1h 00m") {
		t.Errorf("expiry = %q, want the narrow grant's", expires)
	}
}

func TestRemaining(t *testing.T) {
	for d, want := range map[time.Duration]string{
		-time.Second: "expired", 0: "expired", 20 * time.Second: "1m", 59*time.Minute + time.Second: "60m",
		time.Hour: "1h 00m", 47*time.Hour + 59*time.Minute: "47h 59m", 48 * time.Hour: "2 days", 100 * time.Hour: "4 days",
	} {
		if got := remaining(d); got != want {
			t.Errorf("remaining(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestAccessPage(t *testing.T) {
	objs := []client.Object{
		&tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "lab"}},
		&tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "down"}},
		&tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "wiki"},
			Spec: tnv1.TailnetIngressSpec{TailnetRef: tnv1.TailnetRef{Name: "lab"}, AllowFrom: []string{"alice@", "bob@example.com"},
				Exposes: []tnv1.Expose{{Port: 443}}},
			Status: tnv1.TailnetIngressStatus{Tag: "tag:wiki", Hosts: []string{`<i>wiki</i>`}}},
	}
	c := newTestConsole(t, nil, objs...)
	if resp := c.do(t, http.MethodGet, "/access", nil); resp.StatusCode != http.StatusFound ||
		!strings.HasPrefix(resp.Header.Get("Location"), "/auth/login?return=%2Faccess") {
		t.Fatalf("no session: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// The provider identifier names the test IdP, which exists only now.
	users, _ := json.Marshal([]headscale.User{
		{ID: "1", Name: "alice", Email: "alice@example.com", ProviderID: c.idp.srv.URL + "/" + testSubject},
		{ID: "2", Name: "bob", DisplayName: "Bob Secret", Email: "bob@example.com", ProviderID: c.idp.srv.URL + "/other"},
	})
	policy, _ := json.Marshal(`{"groups":{"group:ops":["bob@"]},"grants":[` +
		`{"src":["alice@","bob@example.com"],"dst":["tag:wiki"],"ip":["tcp:443"]},` +
		`{"src":["group:ops"],"dst":["tag:secret-ops"],"ip":["tcp:9"]},` +
		`{"src":["autogroup:member"],"dst":["bob@"],"ip":["tcp:22"]}]}`)
	op, _, _ := fakeOperator(t, string(users), string(policy))
	c.dir = newDirectory(op.URL, tokenFile(t, "tok"))
	sc := cookie(c.signIn(t, flow{returnTo: "/access"}, map[string]any{"groups": []string{"users"}}), sessionCookie)
	resp := c.do(t, http.MethodGet, "/access", []*http.Cookie{sc})
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, want := range []string{"<h3>Personal</h3>", "<h3>For everyone</h3>", "tag:wiki", "ingress apps/wiki (&lt;i&gt;wiki&lt;/i&gt;)",
		"TailnetIngress apps/wiki", "autogroup:member", "a user&#39;s devices", "cannot provide this tailnet", `aria-current="page">My access`} {
		if !strings.Contains(html, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, leak := range []string{"bob", "Bob Secret", "secret-ops", "group:ops", "<i>wiki", c.idp.srv.URL + "/other"} {
		if strings.Contains(html, leak) {
			t.Errorf("page contains %q", leak)
		}
	}
	for _, leak := range []string{"alice", "bob", testSubject, "tok"} {
		if strings.Contains(c.logs.String(), leak) {
			t.Errorf("log contains %q:\n%s", leak, c.logs)
		}
	}
	writePreview(t, "access.html", html)
}
