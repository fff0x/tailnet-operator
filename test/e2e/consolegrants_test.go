//go:build e2e

package e2e

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// TestConsoleGrantAdmission: the API server admits grants in the shape the console writes them
// (internal/console/grants.go) and the merge patches it sends to extend, make permanent and revoke.
func TestConsoleGrantAdmission(t *testing.T) {
	ctx := testContext(t)
	now := time.Now().UTC().Truncate(time.Second)
	at := func(d time.Duration) *metav1.Time { return &metav1.Time{Time: now.Add(d)} }
	labels := map[string]string{"app.kubernetes.io/managed-by": "tailnet-console"}
	grants := []*tnv1.TailnetGrant{
		{ObjectMeta: metav1.ObjectMeta{Name: "console-e2etag0001", Labels: labels}, Spec: tnv1.TailnetGrantSpec{
			TailnetRef: tnv1.TailnetRef{Name: "lab"}, Sources: []string{"group:staff", "https://id.example/realms/lab/3f2a@"},
			Target: tnv1.GrantTarget{Tag: "tag:wiki"}, Ports: []int32{22, 443}, ExpiresAt: at(8 * time.Hour),
			Description: `on call <b>Q4</b> · ä`}},
		{ObjectMeta: metav1.ObjectMeta{Name: "console-e2esite001", Labels: labels}, Spec: tnv1.TailnetGrantSpec{
			TailnetRef: tnv1.TailnetRef{Name: "lab"}, Sources: []string{"https://id.example/realms/lab/3f2a@"},
			Target: tnv1.GrantTarget{Prefixes: []tnv1.GatewayPrefix{"10.20.30.5/32", "10.20.64.0/18", "fd00:20::/64"}}, Ports: []int32{3389}}},
	}
	for _, g := range grants {
		if err := kube.Create(ctx, g); err != nil {
			t.Fatalf("create %s: %v", g.Name, err)
		}
		t.Cleanup(func() {
			cl, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = client.IgnoreNotFound(kube.Delete(cl, g))
		})
	}
	g := grants[0]
	for _, next := range []*metav1.Time{at(30 * 24 * time.Hour), nil, at(0)} {
		var cur tnv1.TailnetGrant
		if err := kube.Get(ctx, client.ObjectKeyFromObject(g), &cur); err != nil {
			t.Fatal(err)
		}
		orig := cur.DeepCopy()
		cur.Spec.ExpiresAt = next
		if err := kube.Patch(ctx, &cur, client.MergeFrom(orig)); err != nil {
			t.Fatalf("patch expiresAt to %v: %v", next, err)
		}
		if err := kube.Get(ctx, client.ObjectKeyFromObject(g), &cur); err != nil {
			t.Fatal(err)
		}
		if (next == nil) != (cur.Spec.ExpiresAt == nil) || (next != nil && !cur.Spec.ExpiresAt.Equal(next)) {
			t.Fatalf("expiresAt %v, want %v", cur.Spec.ExpiresAt, next)
		}
	}
	// The admission that the console's own checks mirror is really in force.
	bad := &tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Name: "console-e2ebad0001", Labels: labels}, Spec: tnv1.TailnetGrantSpec{
		TailnetRef: tnv1.TailnetRef{Name: "lab"}, Sources: []string{"tag:ci"}, Target: tnv1.GrantTarget{Tag: "tag:wiki"}, Ports: []int32{443}}}
	if err := kube.Create(ctx, bad); err == nil {
		_ = kube.Delete(ctx, bad)
		t.Fatal("a tag source was admitted")
	}
}
