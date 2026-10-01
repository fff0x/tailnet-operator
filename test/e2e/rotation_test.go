//go:build e2e

package e2e

import (
	"context"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

func getSecret(t *testing.T, ctx context.Context, name string) *corev1.Secret {
	t.Helper()
	var secret corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &secret); err != nil {
		t.Fatal(err)
	}
	return &secret
}

func TestKeyRotation(t *testing.T) {
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			if version == "v0.28.0" {
				t.Skip("unsupported capability row; covered by TestPreflight")
			}
			ctx := testContext(t)
			hs := startHeadscale(t, ctx, version, "database", true)
			name := createTailnet(t, ctx, hs)
			bootstrap := getSecret(t, ctx, name+"-bootstrap")
			old := getSecret(t, ctx, name+"-apikey")
			oldKey := string(old.Data["apiKey"])
			oldPrefix := headscale.PrefixOf(oldKey)
			if oldKey != "" && old.Annotations["tsunaro.io/prefix"] == oldKey {
				t.Fatal("working-key prefix annotation contains the complete API token")
			}
			if oldKey == "" || oldKey == hs.key {
				t.Fatal("operator did not mint an independent working key")
			}
			// Reproduce metadata written by older operators, then prove repair does not wait
			// for rotation or alter the working credential. The normal Secret watch wakes it.
			beforeRepair := old.DeepCopy()
			old.Annotations["tsunaro.io/prefix"] = oldKey
			if err := kube.Patch(ctx, old, client.MergeFrom(beforeRepair)); err != nil {
				t.Fatal("could not prepare legacy prefix metadata")
			}
			eventually(t, ctx, "legacy prefix metadata repair", func() bool {
				repaired := getSecret(t, ctx, name+"-apikey")
				if string(repaired.Data["apiKey"]) != oldKey {
					t.Fatal("metadata repair unexpectedly rotated the key")
				}
				return repaired.Annotations["tsunaro.io/prefix"] == oldPrefix
			})
			oldClient := headscale.New(hs.url, oldKey)
			if _, err := oldClient.ListAPIKeys(ctx); err != nil {
				t.Fatal("original working key is not usable")
			}
			// Remove the bootstrap escape hatch: rotation must use the still-valid working key.
			if err := oldClient.ExpireAPIKey(ctx, headscale.PrefixOf(hs.key)); err != nil {
				t.Fatal("could not expire fixture bootstrap key")
			}
			if _, err := hs.client().ListAPIKeys(ctx); !headscale.IsUnauthorized(err) {
				t.Fatal("fixture bootstrap key is unexpectedly still usable")
			}
			started := time.Now()
			// The existing 1h key is now past half-life of the new 4h lifetime. A normal spec
			// change both drives reconciliation and avoids races between Secret/cache updates.
			updateTailnet(t, ctx, name, func(tn *tnv1.Tailnet) {
				tn.Spec.APIKeyLifetime = metav1.Duration{Duration: 4 * time.Hour}
			})
			var replacement *corev1.Secret
			eventually(t, ctx, "replacement working key", func() bool {
				replacement = getSecret(t, ctx, name+"-apikey")
				return len(replacement.Data["apiKey"]) != 0 && string(replacement.Data["apiKey"]) != oldKey
			})
			newKey := string(replacement.Data["apiKey"])
			newPrefix := headscale.PrefixOf(newKey)
			if newKey == hs.key || newPrefix == oldPrefix || replacement.Annotations["tsunaro.io/prefix"] != newPrefix {
				t.Fatal("replacement key or prefix is inconsistent")
			}
			newClient := headscale.New(hs.url, newKey)
			eventually(t, ctx, "old key expiration in Headscale", func() bool {
				keys, err := newClient.ListAPIKeys(ctx)
				if err != nil {
					t.Fatal("replacement working key is not usable")
				}
				oldExpired, newValid := false, false
				for _, key := range keys {
					if headscale.PrefixOf(key.Prefix) == oldPrefix {
						oldExpired = !key.Expiration.After(time.Now())
					}
					if headscale.PrefixOf(key.Prefix) == newPrefix {
						newValid = key.Expiration.After(time.Now())
					}
				}
				return oldExpired && newValid
			})
			if _, err := oldClient.ListAPIKeys(ctx); !headscale.IsUnauthorized(err) {
				t.Fatal("rotated-out working key is still usable")
			}
			waitCondition(t, ctx, name, "ApiKeyValid", metav1.ConditionTrue, "Valid")
			waitCondition(t, ctx, name, "HeadscaleCompatible", metav1.ConditionTrue, "Compatible")
			expires, err := time.Parse(time.RFC3339, replacement.Annotations["tsunaro.io/expires-at"])
			if err != nil || expires.Before(started.Add(4*time.Hour-time.Second)) || expires.After(time.Now().Add(4*time.Hour)) {
				t.Fatal("replacement expiry does not follow the configured lifetime")
			}
			tn := getTailnet(t, ctx, name)
			if tn.Status.APIKeyExpiresAt == nil || tn.Status.APIKeyExpiresAt.Unix() != expires.Unix() {
				t.Fatal("Tailnet status does not report the replacement expiry")
			}
			if !reflect.DeepEqual(bootstrap.Data, getSecret(t, ctx, name+"-bootstrap").Data) {
				t.Fatal("operator changed the read-only bootstrap Secret")
			}
			// All failures deliberately avoid rendering Secret values, API-key lists or tokens.
		})
	}
}
