package gateway

import (
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

func TestGatewayAuthReceiptRejectsRebinding(t *testing.T) {
	c, g, tn, req, key, minted := authStoreFixture(t)
	if err := storeGatewayMint(t.Context(), c, "operator", g, tn, req, key, minted); err != nil {
		t.Fatal("cannot prepare synthetic minted Secret")
	}
	secret := &corev1.Secret{}
	if c.Get(t.Context(), types.NamespacedName{Name: "router-auth", Namespace: "operator"}, secret) != nil {
		t.Fatal("synthetic Secret missing")
	}
	secret.UID = "server-assigned-uid" // fake client does not assign a UID on Create.
	now := minted.Add(time.Minute)
	receipt, err := ReadGatewayAuthReceipt(secret, g, tn, "operator", now)
	if err != nil || receipt.UID != secret.UID || receipt.Version == "" || receipt.SecretName != secret.Name || receipt.KeyID != key.ID || !receipt.Expires.Equal(key.Expiration) || strings.Contains(receipt.SecretName+receipt.KeyID, key.Key) {
		t.Fatal("stored receipt rejected or credential exposed")
	}
	for name, mutate := range map[string]func(*corev1.Secret){
		"missing key":     func(s *corev1.Secret) { delete(s.Data, gatewayAuthKeyField) },
		"extra key":       func(s *corev1.Secret) { s.Data["extra"] = []byte("private") },
		"mutable":         func(s *corev1.Secret) { s.Immutable = nil },
		"recreated":       func(s *corev1.Secret) { s.UID = "" },
		"old version":     func(s *corev1.Secret) { s.ResourceVersion = "" },
		"foreign gateway": func(s *corev1.Secret) { s.Labels[gatewayUIDLabel] = "other-uid" },
		"foreign tailnet": func(s *corev1.Secret) { s.Annotations["tsunaro.io/tailnet-uid"] = "foreign" },
		"wrong server":    func(s *corev1.Secret) { s.Annotations["tsunaro.io/server-sha256"] = "bad" },
		"wrong tags":      func(s *corev1.Secret) { s.Annotations["tsunaro.io/tags-sha256"] = "bad" },
		"expired":         func(s *corev1.Secret) { s.Annotations["tsunaro.io/auth-key-expires"] = minted.Format(time.RFC3339) },
		"deleting":        func(s *corev1.Secret) { s.DeletionTimestamp = ptr.To(metav1.Now()) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := secret.DeepCopy()
			mutate(bad)
			got, err := ReadGatewayAuthReceipt(bad, g, tn, "operator", now)
			if !errors.Is(err, ErrGatewayAuthReceipt) || got != (GatewayAuthReceipt{}) || strings.Contains(err.Error(), key.Key) {
				t.Fatal("tampered, unversioned or expired receipt accepted")
			}
		})
	}
	if got, err := ReadGatewayAuthReceipt(secret, g, tn, "foreign", now); !errors.Is(err, ErrGatewayAuthReceipt) || got != (GatewayAuthReceipt{}) {
		t.Fatal("cross-namespace credential accepted")
	}
	if got, err := ReadGatewayAuthReceipt(secret, g, tn, "operator", minted.Add(25*time.Hour)); !errors.Is(err, ErrGatewayAuthReceipt) || got != (GatewayAuthReceipt{}) {
		t.Fatal("expired key accepted")
	}
}
