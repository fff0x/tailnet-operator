package gateway

import (
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestGatewayAuthReceiptRejectsRebinding(t *testing.T) {
	c, g, tn, req, key, minted := authStoreFixture(t)
	created, err := storeGatewayMint(t.Context(), c, "operator", g, tn, req, key, minted)
	if err != nil {
		t.Fatal("cannot prepare synthetic minted Secret")
	}
	secret := &corev1.Secret{}
	if c.Get(t.Context(), client.ObjectKey{Name: "router-auth", Namespace: "operator"}, secret) != nil {
		t.Fatal("synthetic Secret missing")
	}
	createdUID := created.UID // Captured by storage from Create, not this Get.
	if createdUID == "" || secret.UID != createdUID {
		t.Fatal("Create UID was not captured independently")
	}
	now := minted.Add(time.Minute)
	receipt, err := ReadGatewayAuthReceipt(secret, g, tn, "operator", createdUID, now)
	if err != nil || receipt.UID != secret.UID || receipt.Version == "" || receipt.SecretName != secret.Name || receipt.KeyID != key.ID || !receipt.Expires.Equal(key.Expiration) || strings.Contains(receipt.SecretName+receipt.KeyID, key.Key) {
		t.Fatal("stored receipt rejected or credential exposed")
	}
	for name, mutate := range map[string]func(*corev1.Secret){
		"missing key":      func(s *corev1.Secret) { delete(s.Data, gatewayAuthKeyField) },
		"credential in ID": func(s *corev1.Secret) { s.Annotations["tsunaro.io/auth-key-id"] = key.Key },
		"noncanonical ID":  func(s *corev1.Secret) { s.Annotations["tsunaro.io/auth-key-id"] = "017" },
		"extra key":        func(s *corev1.Secret) { s.Data["extra"] = []byte("private") },
		"mutable":          func(s *corev1.Secret) { s.Immutable = nil },
		"blank uid":        func(s *corev1.Secret) { s.UID = "" },
		"recreated": func(s *corev1.Secret) {
			s.UID = "recreated-uid"
			s.ResourceVersion = "new-version"
			s.Data[gatewayAuthKeyField] = []byte("different-secret-key")
		},
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
			got, err := ReadGatewayAuthReceipt(bad, g, tn, "operator", createdUID, now)
			if !errors.Is(err, ErrGatewayAuthReceipt) || got != (GatewayAuthReceipt{}) || strings.Contains(err.Error(), key.Key) {
				t.Fatal("tampered, unversioned or expired receipt accepted")
			}
		})
	}
	if got, err := ReadGatewayAuthReceipt(secret, g, tn, "foreign", createdUID, now); !errors.Is(err, ErrGatewayAuthReceipt) || got != (GatewayAuthReceipt{}) {
		t.Fatal("cross-namespace credential accepted")
	}
	if got, err := ReadGatewayAuthReceipt(secret, g, tn, "operator", createdUID, minted.Add(25*time.Hour)); !errors.Is(err, ErrGatewayAuthReceipt) || got != (GatewayAuthReceipt{}) {
		t.Fatal("expired key accepted")
	}
	if got, err := ReadGatewayAuthReceipt(secret, g, tn, "operator", "", now); !errors.Is(err, ErrGatewayAuthReceipt) || got != (GatewayAuthReceipt{}) {
		t.Fatal("missing independent UID expectation accepted")
	}
}
