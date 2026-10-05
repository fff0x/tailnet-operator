package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

var ErrGatewayAuthStore = errors.New("gateway auth bootstrap: exclusive key storage failed")

const gatewayAuthKeyField = "TS_AUTHKEY"

// storeGatewayMint is package-private and uncalled by the production manager.
// It stores only a freshly returned key from the selected Headscale client;
// no pre-existing Secret is ever adopted or overwritten. API Create is the
// name-exclusivity gate. An orphaned minted key after a crash or failed Create
// expires within the bounded mint lifetime. This alone is NOT authorization to
// create a StatefulSet or proof of later node/state binding.
func storeGatewayMint(ctx context.Context, c client.Client, namespace string, g *tnv1.TailnetGateway, tn *tnv1.Tailnet, req headscale.CreatePreAuthKeyRequest, issued *headscale.PreAuthKey, now time.Time) (GatewayAuthReceipt, error) {
	if c == nil || len(validation.IsDNS1123Label(namespace)) != 0 || g == nil || tn == nil || g.UID == "" || g.ResourceVersion == "" || tn.UID == "" || tn.ResourceVersion == "" ||
		g.Namespace != "" || tn.Namespace != "" || g.Spec.Suspend == nil || *g.Spec.Suspend ||
		g.DeletionTimestamp != nil || tn.DeletionTimestamp != nil || g.Spec.Adoption != nil || g.Spec.AuthKeySecretRef != nil ||
		string(g.Spec.TailnetRef.Name) != tn.Name || ValidateGatewayMint(req, issued, now) != nil {
		return GatewayAuthReceipt{}, ErrGatewayAuthStore
	}
	g, tn = g.DeepCopy(), tn.DeepCopy()
	req.ACLTags = slices.Clone(req.ACLTags)
	issuedCopy := *issued
	issued = &issuedCopy
	server, parseErr := url.Parse(tn.Spec.Server)
	name := g.Name + "-auth"
	if parseErr != nil || server.Scheme != "https" || server.Hostname() == "" || server.User != nil || server.RawQuery != "" || server.Fragment != "" ||
		len(validation.IsDNS1035Label(g.Name)) != 0 || len(g.Name) > 40 ||
		len(validation.IsDNS1123Subdomain(name)) != 0 || len(validation.IsDNS1123Subdomain(string(g.Spec.StateSecretRef.Name))) != 0 ||
		name == string(g.Spec.StateSecretRef.Name) ||
		len(g.Spec.Tags) != len(req.ACLTags) || !sameGatewayTags(g.Spec.Tags, req.ACLTags) ||
		req.Expiration.After(now.Add(gatewayKeyLifetime+time.Second)) {
		return GatewayAuthReceipt{}, ErrGatewayAuthStore
	}
	// Re-read the two identity CRs immediately before Create. A concurrent
	// change or deletion must not leave a newly written key attached to a
	// different gateway/Tailnet; this is still not a cross-object transaction.
	if !mintSnapshotsUnchanged(ctx, c, g, tn) {
		return GatewayAuthReceipt{}, ErrGatewayAuthStore
	}
	serverHash := sha256.Sum256([]byte(tn.Spec.Server))
	tags := slices.Clone(req.ACLTags)
	slices.Sort(tags)
	tagsHash := sha256.Sum256([]byte(strings.Join(tags, "\x00")))
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace,
		Labels: map[string]string{gatewayUIDLabel: string(g.UID), "app.kubernetes.io/managed-by": "tailnet-operator"},
		Annotations: map[string]string{
			"tsunaro.io/tailnet-uid": string(tn.UID), "tsunaro.io/server-sha256": hex.EncodeToString(serverHash[:]),
			"tsunaro.io/tags-sha256": hex.EncodeToString(tagsHash[:]), "tsunaro.io/auth-key-id": issued.ID,
			"tsunaro.io/auth-key-expires": issued.Expiration.UTC().Format(time.RFC3339),
		}}, Immutable: ptr.To(true), Type: corev1.SecretTypeOpaque, Data: map[string][]byte{gatewayAuthKeyField: []byte(issued.Key)}}
	if err := c.Create(ctx, secret); err != nil {
		// Neither Kubernetes errors nor server responses may contain the key in
		// an event, status condition or log. Never surface the raw cause.
		return GatewayAuthReceipt{}, ErrGatewayAuthStore
	}
	// Only the successful Create response may establish the expected UID.
	// A later Get, an AlreadyExists response or a lost response cannot do so.
	if string(secret.Data[gatewayAuthKeyField]) != issued.Key {
		return GatewayAuthReceipt{}, ErrGatewayAuthStore
	}
	receipt, err := ReadGatewayAuthReceipt(secret, g, tn, namespace, secret.UID, now)
	if err != nil || receipt.KeyID != issued.ID || !receipt.Expires.Equal(issued.Expiration.UTC().Truncate(time.Second)) ||
		!mintSnapshotsUnchanged(ctx, c, g, tn) {
		return GatewayAuthReceipt{}, ErrGatewayAuthStore
	}
	return receipt, nil
}

func mintSnapshotsUnchanged(ctx context.Context, r client.Reader, g *tnv1.TailnetGateway, tn *tnv1.Tailnet) bool {
	liveG, liveTN := &tnv1.TailnetGateway{}, &tnv1.Tailnet{}
	return r.Get(ctx, client.ObjectKeyFromObject(g), liveG) == nil && r.Get(ctx, client.ObjectKeyFromObject(tn), liveTN) == nil &&
		liveG.UID == g.UID && liveG.ResourceVersion == g.ResourceVersion && liveG.Generation == g.Generation && liveG.DeletionTimestamp == nil && equality.Semantic.DeepEqual(liveG.Spec, g.Spec) &&
		liveTN.UID == tn.UID && liveTN.ResourceVersion == tn.ResourceVersion && liveTN.Generation == tn.Generation && liveTN.DeletionTimestamp == nil && equality.Semantic.DeepEqual(liveTN.Spec, tn.Spec)
}

func sameGatewayTags(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
