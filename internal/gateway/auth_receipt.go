package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

var ErrGatewayAuthReceipt = errors.New("gateway auth bootstrap: stored mint receipt is invalid or expired")

// GatewayAuthReceipt contains NO credential. It can identify the immutable
// operator-created Secret for a future pod projection, but is not proof that
// Headscale still accepts the full key, or that a later state Secret belongs
// to any particular node. Never turn it alone into Ready or adoption consent.
type GatewayAuthReceipt struct {
	SecretName string
	UID        types.UID
	Version    string
	KeyID      string
	Expires    time.Time
}

// ReadGatewayAuthReceipt validates the local provenance metadata written by
// storeGatewayMint. It rejects an external or recreated Secret, mismatched
// gateway/Tailnet scope, missing credential, and expiry. Trust in this receipt
// relies on restricting Kubernetes Secret writes to the operator; annotations
// are NOT Headscale-signed attestations and do not verify the full key remotely.
// expectedUID must be independently captured at Create and durably retained
// before recovery. Passing secret.UID as the expectation proves nothing.
func ReadGatewayAuthReceipt(secret *corev1.Secret, g *tnv1.TailnetGateway, tn *tnv1.Tailnet, namespace string, expectedUID types.UID, now time.Time) (GatewayAuthReceipt, error) {
	bad := func() (GatewayAuthReceipt, error) { return GatewayAuthReceipt{}, ErrGatewayAuthReceipt }
	if secret == nil || g == nil || tn == nil || g.UID == "" || tn.UID == "" || now.IsZero() ||
		g.Spec.AuthKeySecretRef != nil || g.Spec.Adoption != nil || string(g.Spec.TailnetRef.Name) != tn.Name ||
		secret.Name != g.Name+"-auth" || secret.Namespace != namespace || expectedUID == "" || secret.UID != expectedUID || secret.ResourceVersion == "" ||
		secret.DeletionTimestamp != nil || secret.Immutable == nil || !*secret.Immutable ||
		secret.Type != corev1.SecretTypeOpaque || len(secret.OwnerReferences) != 0 || len(secret.StringData) != 0 ||
		len(secret.Data) != 1 || len(secret.Data[gatewayAuthKeyField]) == 0 || len(secret.Data[gatewayAuthKeyField]) > 4096 ||
		secret.Labels[gatewayUIDLabel] != string(g.UID) || secret.Labels["app.kubernetes.io/managed-by"] != "tailnet-operator" ||
		secret.Annotations["tsunaro.io/tailnet-uid"] != string(tn.UID) || !validGatewayKeyID(secret.Annotations["tsunaro.io/auth-key-id"]) {
		return bad()
	}
	server := sha256.Sum256([]byte(tn.Spec.Server))
	tags := slices.Clone(g.Spec.Tags)
	slices.Sort(tags)
	tagHash := sha256.Sum256([]byte(strings.Join(tags, "\x00")))
	if secret.Annotations["tsunaro.io/server-sha256"] != hex.EncodeToString(server[:]) ||
		secret.Annotations["tsunaro.io/tags-sha256"] != hex.EncodeToString(tagHash[:]) {
		return bad()
	}
	exp, err := time.Parse(time.RFC3339, secret.Annotations["tsunaro.io/auth-key-expires"])
	if err != nil || !exp.After(now) || exp.After(now.Add(gatewayKeyLifetime+time.Second)) {
		return bad()
	}
	return GatewayAuthReceipt{SecretName: secret.Name, UID: secret.UID, Version: secret.ResourceVersion,
		KeyID: secret.Annotations["tsunaro.io/auth-key-id"], Expires: exp}, nil
}
