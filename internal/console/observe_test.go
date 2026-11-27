package console

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func gentry(action, grant string, details map[string]any) auditEntry {
	return auditEntry{Action: action, Grant: grant, Tailnet: "lab", Details: details}
}

// The state the log gives, including the undo of a failed own change.
func TestKnownState(t *testing.T) {
	create := map[string]any{"sources": []any{"group:b", "group:a"}, "ports": []any{443.0}, "tag": "tag:wiki", "expiresAt": "2026-11-27T21:00:00Z"}
	observed := map[string]any{"change": "created", "sources": []any{"group:x"}, "ports": []any{22.0}, "tag": "tag:db", "expiresAt": "permanent", "managed": false}
	wikiAt := func(at string) string {
		return grantState{Tailnet: "lab", Sources: []string{"group:a", "group:b"}, Tag: "tag:wiki", Ports: []int32{443}, ExpiresAt: at, Managed: true}.key()
	}
	db := grantState{Tailnet: "lab", Sources: []string{"group:x"}, Tag: "tag:db", Ports: []int32{22}, ExpiresAt: "permanent"}.key()
	for _, tc := range []struct {
		name    string
		entries []auditEntry
		want    map[string]string
	}{
		{"create", []auditEntry{gentry("grant.create", "g", create)}, map[string]string{"g": wikiAt("2026-11-27T21:00:00Z")}},
		{"extend and revoke", []auditEntry{gentry("grant.create", "g", create), gentry("grant.extend", "g", map[string]any{"to": "permanent"}),
			gentry("grant.revoke", "g", map[string]any{"to": "2026-11-27T13:00:00Z"})}, map[string]string{"g": wikiAt("2026-11-27T13:00:00Z")}},
		{"failed create", []auditEntry{gentry("grant.create", "g", create), gentry(actionFailed, "g", map[string]any{"action": "grant.create"})}, map[string]string{}},
		{"failed extend of an observed grant", []auditEntry{gentry(actionObserved, "g", observed), gentry("grant.extend", "g", map[string]any{"to": "2026-12-01T00:00:00Z"}),
			gentry(actionFailed, "g", map[string]any{"action": "grant.extend"})}, map[string]string{"g": db}},
		{"failed close changes nothing", []auditEntry{gentry("grant.create", "g", create), gentry("request.close", "g", nil),
			gentry(actionFailed, "g", map[string]any{"action": "request.close"})}, map[string]string{"g": wikiAt("2026-11-27T21:00:00Z")}},
		{"delete, and failed delete", []auditEntry{gentry("grant.create", "g", create), gentry("grant.create", "h", create), gentry("grant.delete", "g", nil),
			gentry("grant.delete", "h", nil), gentry(actionFailed, "h", map[string]any{"action": "grant.delete"})}, map[string]string{"h": wikiAt("2026-11-27T21:00:00Z")}},
		{"observed deleted", []auditEntry{gentry(actionObserved, "g", observed), gentry(actionObserved, "g", map[string]any{"change": "deleted"})}, map[string]string{}},
		{"extend of an unknown grant", []auditEntry{gentry("grant.extend", "g", map[string]any{"to": "permanent"})}, map[string]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			known, _ := knownGrants(tc.entries)
			got := map[string]string{}
			for name, st := range known {
				got[name] = st.key()
			}
			if len(got) != len(tc.want) {
				t.Fatalf("known %v, want %v", got, tc.want)
			}
			for name, k := range tc.want {
				if got[name] != k {
					t.Errorf("%s: %s, want %s", name, got[name], k)
				}
			}
		})
	}
	_, expired := knownGrants([]auditEntry{gentry(actionExpired, "g", map[string]any{"expiresAt": "2026-11-27T13:00:00Z"})})
	if !expired["g"]["2026-11-27T13:00:00Z"] || expired["g"]["2026-11-28T13:00:00Z"] {
		t.Errorf("expired %v", expired)
	}
}

func (c *testConsole) observed(t *testing.T) []auditEntry {
	t.Helper()
	var out []auditEntry
	for _, e := range c.audit.state(context.Background()).Entries {
		if e.Action == actionObserved || e.Action == actionExpired {
			out = append(out, e)
		}
	}
	return out
}

func (c *testConsole) runRound(t *testing.T) {
	t.Helper()
	var cleaned time.Time
	c.round(context.Background(), &cleaned)
}

func expireStatus(g *tnv1.TailnetGrant, reason string, gen int64) {
	g.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionFalse, Reason: reason, ObservedGeneration: gen,
		LastTransitionTime: metav1.Time{Time: grantNow}}}
}

// Observe records each difference between the grants and the log once, a grant the log does not
// know as created, and an expiry once per expiresAt. Without the grant list or the log it records
// nothing, and recipients stay out of the pod log.
func TestObserve(t *testing.T) {
	c := newGrantConsole(t)
	ctx := context.Background()
	admin := c.admin(t)
	c.runRound(t)
	obs := c.observed(t)
	if len(obs) != 1 || obs[0].Grant != "from-git" || obs[0].Details["change"] != "created" || obs[0].Details["managed"] != false || obs[0].Actor != nil {
		t.Fatalf("starting state %+v", obs)
	}
	c.runRound(t)
	if n := len(c.observed(t)); n != 1 {
		t.Fatalf("same state recorded again: %d entries", n)
	}
	// The console's own grant is known from grant.create.
	c.expect(t, "create", c.post(t, "/grants", admin, url.Values{"target": {"lab/ingress/apps/wiki"}, "ports": {"443"}, "sources": {aliceRef}, "duration": {"8h"}}), http.StatusSeeOther)
	c.runRound(t)
	if n := len(c.observed(t)); n != 1 {
		t.Fatalf("own grant observed: %+v", c.observed(t))
	}
	own := c.consoleGrants(t)[0]

	git := c.grant(t, "from-git")
	git.Spec.Ports = []int32{443, 8443}
	if err := c.writer.Update(ctx, git); err != nil {
		t.Fatal(err)
	}
	c.runRound(t)
	git = c.grant(t, "from-git")
	git.Labels = map[string]string{managedByLabel: managedBy}
	if err := c.writer.Update(ctx, git); err != nil {
		t.Fatal(err)
	}
	c.runRound(t)
	made := &tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Name: "by-kubectl"}, Spec: tnv1.TailnetGrantSpec{TailnetRef: tnv1.TailnetRef{Name: "lab"},
		Sources: []string{aliceRef}, Target: tnv1.GrantTarget{Tag: "tag:wiki"}, Ports: []int32{22}}}
	if err := c.writer.Create(ctx, made); err != nil {
		t.Fatal(err)
	}
	c.runRound(t)
	if err := c.writer.Delete(ctx, made); err != nil {
		t.Fatal(err)
	}
	c.runRound(t)
	c.runRound(t)
	var got []string
	for _, e := range c.observed(t)[1:] {
		got = append(got, e.Grant+" "+e.Details["change"].(string))
	}
	if want := []string{"from-git changed", "from-git changed", "by-kubectl created", "by-kubectl deleted"}; !slices.Equal(got, want) {
		t.Fatalf("observed %q, want %q", got, want)
	}
	if last := c.observed(t)[2]; last.Details["managed"] != true {
		t.Errorf("label change not recorded: %+v", last)
	}

	// One grant.expired per expiresAt, only for the current generation.
	own.Spec.ExpiresAt = &metav1.Time{Time: grantNow.Add(-time.Hour)}
	expireStatus(&own, "Expired", own.Generation+1)
	if err := c.writer.Update(ctx, &own); err != nil {
		t.Fatal(err)
	}
	c.runRound(t)
	n := len(c.observed(t))
	if e := c.observed(t)[n-1]; e.Action == actionExpired {
		t.Fatalf("expiry of an older generation recorded: %+v", e)
	}
	g := c.grant(t, own.Name)
	expireStatus(g, "Expired", g.Generation)
	if err := c.writer.Update(ctx, g); err != nil {
		t.Fatal(err)
	}
	c.runRound(t)
	c.runRound(t)
	if e := c.observed(t); len(e) != n+1 || e[n].Action != actionExpired || e[n].Details["expiresAt"] != "2026-11-27T12:00:00Z" || e[n].Actor != nil {
		t.Fatalf("expiry entries %+v", e[n-1:])
	}
	g = c.grant(t, own.Name)
	g.Spec.ExpiresAt = &metav1.Time{Time: grantNow.Add(-time.Minute)}
	if err := c.writer.Update(ctx, g); err != nil {
		t.Fatal(err)
	}
	c.runRound(t)
	if e := c.observed(t); len(e) != n+3 || e[n+2].Action != actionExpired || e[n+2].Details["expiresAt"] != "2026-11-27T12:59:00Z" {
		t.Fatalf("second expiry %+v", e[n:])
	}

	// Without the grant list or the log, nothing is recorded; the next run catches up.
	plain := c.writer
	c.writer = interceptor.NewClient(plain.(client.WithWatch), interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errors.New("list lost")
		}})
	again := made.DeepCopy()
	again.ResourceVersion = ""
	if err := plain.Create(ctx, again); err != nil {
		t.Fatal(err)
	}
	before := len(c.audit.state(ctx).Entries)
	c.runRound(t)
	if after := len(c.audit.state(ctx).Entries); after != before {
		t.Fatalf("entries without a grant list: %d -> %d", before, after)
	}
	c.writer = plain
	anchor := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: testAnchorCM}}
	if err := c.writer.Delete(ctx, anchor); err != nil {
		t.Fatal(err)
	}
	c.runRound(t)
	if err := c.writer.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: testAnchorCM}}); err != nil {
		t.Fatal(err)
	}
	c.runRound(t)
	if e := c.observed(t); e[len(e)-1].Grant != "by-kubectl" || e[len(e)-1].Details["change"] != "created" {
		t.Fatalf("not caught up: %+v", e[len(e)-1])
	}
	// Recipients stay in the log; the page names who acted.
	if strings.Contains(c.logs.String(), "id.example/alice") || strings.Contains(c.logs.String(), "group:staff") {
		t.Errorf("recipient in the pod log:\n%s", c.logs.String())
	}
	page, _ := io.ReadAll(c.do(t, http.MethodGet, "/audit", admin).Body)
	for _, want := range []string{`<span class="muted">unknown</span>`, `<span class="muted">operator</span>`, `<span class="muted">console</span>`} {
		if !strings.Contains(string(page), want) {
			t.Errorf("audit page lacks %s", want)
		}
	}
}

type halfCreate struct{ client.Client }

func (h halfCreate) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if err := h.Client.Create(ctx, obj, opts...); err != nil {
		return err
	}
	return errors.New("answer lost")
}

// A create whose answer was lost is observed once; a run waits for a change that is between its
// entry and its write.
func TestObserveOwnChanges(t *testing.T) {
	c := newGrantConsole(t)
	admin := c.admin(t)
	form := url.Values{"target": {"lab/ingress/apps/wiki"}, "ports": {"443"}, "sources": {aliceRef}, "duration": {"8h"}}
	c.runRound(t)
	plain := c.writer
	c.writer = halfCreate{plain}
	c.expect(t, "half create", c.post(t, "/grants", admin, form), http.StatusBadGateway)
	c.writer = plain
	c.runRound(t)
	if e := c.observed(t); len(e) != 2 || e[1].Grant != c.consoleGrants(t)[0].Name || e[1].Details["change"] != "created" {
		t.Fatalf("half create observed as %+v", e)
	}

	entered, release := make(chan struct{}), make(chan struct{})
	c.writer = interceptor.NewClient(plain.(client.WithWatch), interceptor.Funcs{
		Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			close(entered)
			<-release
			return cl.Create(ctx, obj, opts...)
		}})
	posted := make(chan int)
	go func() { posted <- c.post(t, "/grants", admin, form).StatusCode }()
	<-entered
	ran := make(chan struct{})
	go func() { c.runRound(t); close(ran) }()
	select {
	case <-ran:
		t.Fatal("observation ran between the entry and its write")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if code := <-posted; code != http.StatusSeeOther {
		t.Fatalf("create: %d", code)
	}
	<-ran
	if e := c.observed(t); len(e) != 2 {
		t.Fatalf("own change observed: %+v", e[2:])
	}
}

// Cleanup against grants and requests on both sides of each condition: what it deletes, what
// expires and what it leaves.
func TestCleanup(t *testing.T) {
	c := newRequestConsole(t, true)
	c.retention = 30
	ctx := context.Background()
	day := 24 * time.Hour
	at := func(d time.Duration) *metav1.Time { return &metav1.Time{Time: grantNow.Add(d)} }
	label := map[string]string{managedByLabel: managedBy}
	grant := func(name string, labels map[string]string, expires *metav1.Time, reason string, gen, observed int64) *tnv1.TailnetGrant {
		g := &tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels, Generation: gen}, Spec: tnv1.TailnetGrantSpec{
			TailnetRef: tnv1.TailnetRef{Name: "lab"}, Sources: []string{"group:staff"}, Target: tnv1.GrantTarget{Tag: "tag:wiki"}, Ports: []int32{443}, ExpiresAt: expires}}
		if reason != "" {
			expireStatus(g, reason, observed)
		}
		return g
	}
	uma := c.id("uma")
	request := func(name string, created time.Duration, phase string, decided *metav1.Time) *tnv1.TailnetAccessRequest {
		return &tnv1.TailnetAccessRequest{ObjectMeta: metav1.ObjectMeta{Name: name, CreationTimestamp: *at(created)}, Spec: tnv1.TailnetAccessRequestSpec{
			TailnetRef: tnv1.TailnetRef{Name: "lab"}, Action: "Create", Requester: uma, RequestedAs: requestedAsUser, Sources: []string{uma + "@"},
			Target: &tnv1.GrantTarget{Tag: "tag:wiki"}, Ports: []int32{443}, Duration: "8h"},
			Status: tnv1.TailnetAccessRequestStatus{Phase: phase, DecidedAt: decided}}
	}
	applied := grant("console-applied001", label, at(8*time.Hour), "", 0, 0)
	applied.Annotations = map[string]string{requestAnnotation: "request-applied001"}
	objs := []client.Object{
		grant("console-old", label, at(-31*day), "Expired", 2, 2),
		grant("console-recent", label, at(-29*day), "Expired", 2, 2),
		grant("console-pending", label, at(-31*day), "ExpiryPending", 2, 2),
		grant("console-stale", label, at(-31*day), "Expired", 3, 2),
		grant("git-old", nil, at(-31*day), "Expired", 2, 2),
		grant("console-forever", label, nil, "", 0, 0),
		applied,
		request("request-old", -31*day, "", nil),
		request("request-partial", -31*day, "", nil),
		request("request-young", -29*day, "", nil),
		request("request-applied001", -31*day, "", nil),
		request("request-rejected", -40*day, phaseRejected, at(-31*day)),
		request("request-expired", -70*day, phaseExpired, at(-30*day)),
		request("request-withdrawn", -40*day, phaseWithdrawn, at(-29*day)),
	}
	for _, o := range objs {
		var status tnv1.TailnetAccessRequestStatus
		if r, ok := o.(*tnv1.TailnetAccessRequest); ok {
			status = r.Status
		}
		if err := c.writer.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
		if r, ok := o.(*tnv1.TailnetAccessRequest); ok && status.Phase != "" {
			r.Status = status
			if err := c.writer.Status().Update(ctx, r); err != nil {
				t.Fatal(err)
			}
		}
	}
	if g := c.grant(t, "console-stale"); g.Generation != 3 {
		t.Fatalf("the fake client changed the generation to %d", g.Generation)
	}
	c.expect(t, "partial approval", c.post(t, "/requests/request-partial/approve", c.as(t, "ada", true), nil), http.StatusSeeOther)
	// Each deletion follows its entry.
	plain := c.writer
	c.writer = interceptor.NewClient(plain.(client.WithWatch), interceptor.Funcs{
		Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			es := c.audit.state(ctx).Entries
			if last := es[len(es)-1]; !strings.HasSuffix(last.Action, ".delete") || last.Details["retentionDays"] != 30.0 || last.Actor != nil {
				t.Errorf("delete of %s after %+v", obj.GetName(), last)
			}
			return cl.Delete(ctx, obj, opts...)
		}})
	c.runRound(t)
	c.writer = plain

	var grants tnv1.TailnetGrantList
	if err := c.writer.List(ctx, &grants); err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, g := range grants.Items {
		left = append(left, g.Name)
	}
	slices.Sort(left)
	if want := []string{"console-applied001", "console-forever", "console-pending", "console-recent", "console-stale", "from-git", "git-old"}; !slices.Equal(left, want) {
		t.Errorf("grants left %q, want %q", left, want)
	}
	phases := map[string]string{}
	for _, r := range c.requests(t) {
		phases[r.Name] = phaseOf(&r)
		if r.Status.Phase == phaseExpired && r.Name != "request-expired" && !r.Status.DecidedAt.Time.Equal(grantNow) {
			t.Errorf("%s decided at %v", r.Name, r.Status.DecidedAt)
		}
	}
	want := map[string]string{"request-old": phaseExpired, "request-partial": phaseExpired, "request-young": phasePending,
		"request-applied001": phasePending, "request-withdrawn": phaseWithdrawn}
	if len(phases) != len(want) {
		t.Errorf("requests left %v, want %v", phases, want)
	}
	for name, p := range want {
		if phases[name] != p {
			t.Errorf("%s: %q, want %q", name, phases[name], p)
		}
	}
	var got []string
	for _, e := range c.audit.state(ctx).Entries {
		if e.Action == "grant.delete" || strings.HasPrefix(e.Action, "request.expire") || e.Action == "request.delete" {
			got = append(got, e.Action+" "+e.Grant)
		}
	}
	slices.Sort(got)
	if w := []string{"grant.delete console-old", "request.delete console-expired", "request.delete console-rejected",
		"request.expire console-old", "request.expire console-partial"}; !slices.Equal(got, w) {
		t.Errorf("entries %q, want %q", got, w)
	}
	page, _ := io.ReadAll(c.do(t, http.MethodGet, "/requests", c.as(t, "cy", true)).Body)
	if !strings.Contains(string(page), "expired undecided · 2026-11-27 13:00 UTC") {
		t.Errorf("requests page does not show the expiry:\n%s", page)
	}
}

// A grant changed after the list is not deleted, the failure ends the run, and the next cleanup
// comes an hour later.
func TestCleanupStops(t *testing.T) {
	c := newGrantConsole(t)
	c.retention = 30
	ctx := context.Background()
	for _, name := range []string{"console-a", "console-b"} {
		g := &tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{managedByLabel: managedBy}}, Spec: tnv1.TailnetGrantSpec{
			TailnetRef: tnv1.TailnetRef{Name: "lab"}, Sources: []string{"group:staff"}, Target: tnv1.GrantTarget{Tag: "tag:wiki"}, Ports: []int32{443},
			ExpiresAt: &metav1.Time{Time: grantNow.Add(-40 * 24 * time.Hour)}}}
		expireStatus(g, "Expired", 0)
		if err := c.writer.Create(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	plain := c.writer
	changed := false
	c.writer = interceptor.NewClient(plain.(client.WithWatch), interceptor.Funcs{
		Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if !changed {
				changed = true
				g := c.grant(t, obj.GetName())
				g.Spec.Description = "kept"
				if err := cl.Update(ctx, g); err != nil {
					t.Fatal(err)
				}
			}
			return cl.Delete(ctx, obj, opts...)
		}})
	var cleaned time.Time
	c.round(ctx, &cleaned)
	if n := len(c.consoleGrants(t)); n != 2 {
		t.Fatalf("%d grants left, want 2", n)
	}
	es := c.audit.state(ctx).Entries
	if last := es[len(es)-1]; last.Action != actionFailed || last.Details["action"] != "grant.delete" || last.Details["status"] != float64(http.StatusConflict) {
		t.Fatalf("last entry %+v", last)
	}
	c.round(ctx, &cleaned)
	if n := len(c.consoleGrants(t)); n != 2 {
		t.Fatalf("cleanup ran again within the hour: %d grants left", n)
	}
	c.now = func() time.Time { return grantNow.Add(time.Hour) }
	c.round(ctx, &cleaned)
	if n := len(c.consoleGrants(t)); n != 0 {
		t.Fatalf("%d grants left after the hour", n)
	}
}

// Without a retention nothing is deleted or expires.
func TestCleanupOff(t *testing.T) {
	c := newGrantConsole(t)
	ctx := context.Background()
	g := &tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Name: "console-a", Labels: map[string]string{managedByLabel: managedBy}}, Spec: tnv1.TailnetGrantSpec{
		TailnetRef: tnv1.TailnetRef{Name: "lab"}, Sources: []string{"group:staff"}, Target: tnv1.GrantTarget{Tag: "tag:wiki"}, Ports: []int32{443},
		ExpiresAt: &metav1.Time{Time: grantNow.Add(-4000 * 24 * time.Hour)}}}
	expireStatus(g, "Expired", 0)
	if err := c.writer.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	c.runRound(t)
	if n := len(c.consoleGrants(t)); n != 1 {
		t.Fatalf("deleted without retention: %d left", n)
	}
}

// A user revokes a console grant that names them alone, at once even with four-eyes.
func TestUserRevoke(t *testing.T) {
	c := newRequestConsole(t, true)
	ctx := context.Background()
	uma := c.id("uma") + "@"
	mk := func(name string, managed bool, sources ...string) {
		g := &tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: tnv1.TailnetGrantSpec{TailnetRef: tnv1.TailnetRef{Name: "lab"},
			Sources: sources, Target: tnv1.GrantTarget{Tag: "tag:wiki"}, Ports: []int32{443}, ExpiresAt: &metav1.Time{Time: grantNow.Add(8 * time.Hour)}}}
		if managed {
			g.Labels = map[string]string{managedByLabel: managedBy}
		}
		if err := c.writer.Create(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	mk("console-mine", true, uma)
	mk("console-shared", true, uma, "group:staff")
	mk("console-ada", true, c.id("ada")+"@")
	mk("git-mine", false, uma)
	me := c.as(t, "uma", false)
	page, _ := io.ReadAll(c.do(t, http.MethodGet, "/requests", me).Body)
	if !strings.Contains(string(page), `action="/grants/console-mine/revoke"`) || strings.Contains(string(page), `action="/grants/console-shared/revoke"`) {
		t.Errorf("revoke buttons wrong:\n%s", page)
	}
	for name, status := range map[string]int{"console-shared": http.StatusForbidden, "console-ada": http.StatusForbidden, "git-mine": http.StatusForbidden} {
		c.expect(t, "revoke "+name, c.post(t, "/grants/"+name+"/revoke", me, nil), status)
		if g := c.grant(t, name); !g.Spec.ExpiresAt.Time.Equal(grantNow.Add(8 * time.Hour)) {
			t.Errorf("%s changed", name)
		}
	}
	c.expect(t, "extend", c.post(t, "/grants/console-mine/extend", me, url.Values{"duration": {"30d"}}), http.StatusForbidden)
	resp := c.post(t, "/grants/console-mine/revoke", me, nil)
	c.expect(t, "revoke own", resp, http.StatusSeeOther)
	if loc := resp.Header.Get("Location"); loc != "/requests" {
		t.Errorf("redirect to %q", loc)
	}
	if g := c.grant(t, "console-mine"); !g.Spec.ExpiresAt.Time.Equal(grantNow) {
		t.Fatalf("revoked to %v", g.Spec.ExpiresAt)
	}
	es := c.audit.state(ctx).Entries
	if last := es[len(es)-1]; last.Action != "grant.revoke" || last.Grant != "console-mine" || last.Actor == nil || last.Actor.Subject != "uma" {
		t.Fatalf("audit %+v", last)
	}
	if len(c.requests(t)) != 0 {
		t.Error("a revocation made a request")
	}
	// An expired grant is not revoked again, by nobody: that would move expiresAt and the retention.
	for _, who := range [][]*http.Cookie{me, c.as(t, "ada", true)} {
		c.expect(t, "revoke expired", c.post(t, "/grants/console-mine/revoke", who, nil), http.StatusConflict)
	}
	if n := len(c.audit.state(ctx).Entries); n != len(es) {
		t.Errorf("refused revocations recorded: %d entries, want %d", n, len(es))
	}
}
