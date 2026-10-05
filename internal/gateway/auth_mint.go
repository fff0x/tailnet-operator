package gateway

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

var ErrGatewayAuthMint = errors.New("gateway auth bootstrap: persistent key provenance is not verified")

const gatewayKeyLifetime = 24 * time.Hour

// PlanGatewayMint is only for a NEW gateway with no external auth reference or
// adoption. It returns a request, not a key or permission to create a Pod.
// The caller must authenticate the selected Headscale server via the Tailnet
// API client, persist the returned key in an exclusive Secret, and re-read it
// before bootstrap. A crash after mint but before persist leaves an orphaned
// key until this bounded expiration; never infer ownership from a masked list.
func PlanGatewayMint(g *tnv1.TailnetGateway, now time.Time) (headscale.CreatePreAuthKeyRequest, error) {
	if g == nil || g.UID == "" || g.Spec.Adoption != nil || g.Spec.AuthKeySecretRef != nil ||
		now.IsZero() || g.DeletionTimestamp != nil || len(g.Spec.Tags) == 0 || len(g.Spec.Tags) > 16 {
		return headscale.CreatePreAuthKeyRequest{}, ErrGatewayAuthMint
	}
	tags := slices.Clone(g.Spec.Tags)
	for _, tag := range tags {
		if !strings.HasPrefix(tag, "tag:") || len(validation.IsDNS1035Label(strings.TrimPrefix(tag, "tag:"))) != 0 {
			return headscale.CreatePreAuthKeyRequest{}, ErrGatewayAuthMint
		}
	}
	slices.Sort(tags)
	if len(slices.Compact(tags)) != len(tags) {
		return headscale.CreatePreAuthKeyRequest{}, ErrGatewayAuthMint
	}
	return headscale.CreatePreAuthKeyRequest{Reusable: true, Ephemeral: false, Expiration: now.UTC().Truncate(time.Second).Add(gatewayKeyLifetime), ACLTags: tags}, nil
}

// Headscale key IDs are uint64s. Restrict nonsecret receipts to their canonical
// decimal representation rather than echoing arbitrary upstream/annotation text.
func validGatewayKeyID(s string) bool {
	id, err := strconv.ParseUint(s, 10, 64)
	return err == nil && id != 0 && strconv.FormatUint(id, 10) == s
}

// ValidateGatewayMint checks the response to the exact request sent to the
// selected Headscale instance. It never logs or returns the full key. The
// response alone cannot bind a node to a later Kubernetes state Secret; the
// caller still needs atomic Secret creation and a post-registration identity
// proof before reporting Ready. External key references are NOT verified here.
func ValidateGatewayMint(req headscale.CreatePreAuthKeyRequest, got *headscale.PreAuthKey, now time.Time) error {
	if got == nil || now.IsZero() || !req.Reusable || req.Ephemeral || len(req.ACLTags) == 0 ||
		got.ID == "" || got.Key == "" || len(got.Key) > 4096 || got.Ephemeral || !got.Reusable || got.Used ||
		got.Expiration.IsZero() || got.Expiration.Before(now.Add(time.Minute)) ||
		got.Expiration.Before(req.Expiration.Add(-time.Second)) || got.Expiration.After(req.Expiration.Add(time.Second)) ||
		len(req.ACLTags) != len(got.ACLTags) {
		return ErrGatewayAuthMint
	}
	if !validGatewayKeyID(got.ID) {
		return ErrGatewayAuthMint
	}
	want, actual := slices.Clone(req.ACLTags), slices.Clone(got.ACLTags)
	slices.Sort(want)
	slices.Sort(actual)
	if !slices.Equal(want, actual) || len(slices.Compact(actual)) != len(actual) {
		return ErrGatewayAuthMint
	}
	return nil
}
