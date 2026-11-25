//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

var serial atomic.Uint64

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 170*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func eventually(t *testing.T, ctx context.Context, description string, check func() bool) {
	t.Helper()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if check() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s: %v", description, ctx.Err())
		case <-ticker.C:
		}
	}
}

func createTailnet(t *testing.T, ctx context.Context, hs *headscaleProcess) string {
	t.Helper()
	name := fmt.Sprintf("fixture-%d", serial.Add(1))
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-bootstrap", Namespace: namespace},
		Data:       map[string][]byte{"apiKey": []byte(hs.key)},
	}
	if err := kube.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	tn := &tnv1.Tailnet{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: tnv1.TailnetSpec{
			Server: "https://headscale.e2e.invalid", APIURL: hs.url,
			APISecretRef:   tnv1.SecretKeyRef{Name: secret.Name},
			APIKeyLifetime: metav1.Duration{Duration: time.Hour},
			DNS:            tnv1.DNSSpec{IngressNameTemplate: "{name}.e2e.invalid"},
		},
	}
	if err := kube.Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := client.IgnoreNotFound(kube.Delete(cleanup, tn)); err != nil {
			t.Errorf("delete Tailnet fixture: %v", err)
		}
		// envtest has no garbage collector. Names are unique; delete the known children explicitly.
		for _, obj := range []client.Object{
			secret,
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name + "-apikey", Namespace: namespace}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name + "-base", Namespace: namespace}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name + "-base-rendered", Namespace: namespace}},
		} {
			if err := client.IgnoreNotFound(kube.Delete(cleanup, obj)); err != nil {
				t.Errorf("delete fixture child: %v", err)
			}
		}
	})
	waitCondition(t, ctx, name, "ApiKeyValid", metav1.ConditionTrue, "Valid")
	return name
}

func getTailnet(t *testing.T, ctx context.Context, name string) *tnv1.Tailnet {
	t.Helper()
	var tn tnv1.Tailnet
	if err := kube.Get(ctx, types.NamespacedName{Name: name}, &tn); err != nil {
		t.Fatal(err)
	}
	return &tn
}

func conditionMatches(tn *tnv1.Tailnet, kind string, status metav1.ConditionStatus, reason string) bool {
	c := meta.FindStatusCondition(tn.Status.Conditions, kind)
	return c != nil && c.Status == status && c.Reason == reason && c.ObservedGeneration == tn.Generation
}

func waitCondition(t *testing.T, ctx context.Context, name, kind string, status metav1.ConditionStatus, reason string) {
	t.Helper()
	eventually(t, ctx, name+" "+kind+"="+string(status)+"/"+reason, func() bool {
		return conditionMatches(getTailnet(t, ctx, name), kind, status, reason)
	})
}

func updateTailnet(t *testing.T, ctx context.Context, name string, mutate func(*tnv1.Tailnet)) {
	t.Helper()
	if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var tn tnv1.Tailnet
		if err := kube.Get(ctx, types.NamespacedName{Name: name}, &tn); err != nil {
			return err
		}
		mutate(&tn)
		return kube.Update(ctx, &tn)
	}); err != nil {
		t.Fatal(err)
	}
}

func enablePolicy(t *testing.T, ctx context.Context, name, base, mode string) {
	t.Helper()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-base", Namespace: namespace},
		Data:       map[string]string{"policy": base},
	}
	if err := kube.Create(ctx, cm); err != nil {
		t.Fatal(err)
	}
	// Headscale accepts a tag as owner or route approver only when tagOwners declares it, so the
	// base must declare tag:fabric.
	updateTailnet(t, ctx, name, func(tn *tnv1.Tailnet) {
		tn.Spec.Policy = tnv1.PolicySpec{
			BaseConfigMap: cm.Name, Mode: mode,
			TagOwners: []string{"tag:fabric"}, RouteApprovers: []string{"tag:fabric"},
		}
	})
}

func updateBase(t *testing.T, ctx context.Context, name, base string) {
	t.Helper()
	if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var cm corev1.ConfigMap
		if err := kube.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name + "-base"}, &cm); err != nil {
			return err
		}
		cm.Data["policy"] = base
		return kube.Update(ctx, &cm)
	}); err != nil {
		t.Fatal(err)
	}
}
