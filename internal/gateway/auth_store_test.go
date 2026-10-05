package gateway

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

// The fake client assigns RVs but not UIDs. Simulate only server allocation;
// actual Create identities and persistence are covered by the envtest gate.
type authFixtureClient struct {
	client.Client
	creates int
}

func (c *authFixtureClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	c.creates++
	if obj.GetUID() == "" {
		obj.SetUID(types.UID("created-" + strconv.Itoa(c.creates)))
	}
	return c.Client.Create(ctx, obj, opts...)
}

func authStoreFixture(t *testing.T) (client.Client, *tnv1.TailnetGateway, *tnv1.Tailnet, headscale.CreatePreAuthKeyRequest, *headscale.PreAuthKey, time.Time) {
	t.Helper()
	in := freshInspectionFixture(t)
	g, tn := in.Fresh.Gateway, in.Fresh.Tailnet
	g.Spec.AuthKeySecretRef = nil
	g.Spec.Suspend = ptr.To(false) // Synthetic bypass; real admission still forbids this.
	now := time.Date(2026, 10, 4, 20, 0, 0, 0, time.UTC)
	req, err := PlanGatewayMint(g, now)
	if err != nil {
		t.Fatal(err)
	}
	key := &headscale.PreAuthKey{ID: "17", Key: "synthetic-private-key-do-not-print", Reusable: true, Expiration: req.Expiration, ACLTags: req.ACLTags}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, tnv1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return &authFixtureClient{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(g, tn).Build()}, g, tn, req, key, now
}

func TestStoreGatewayMintCreatesExclusiveRetainedSecret(t *testing.T) {
	ctx := context.Background()
	c, g, tn, req, key, now := authStoreFixture(t)
	if _, err := storeGatewayMint(ctx, c, "operator", g, tn, req, key, now); err != nil {
		t.Fatal("minted key not stored")
	}
	secret := &corev1.Secret{}
	if c.Get(ctx, types.NamespacedName{Name: "router-auth", Namespace: "operator"}, secret) != nil ||
		secret.Immutable == nil || !*secret.Immutable || secret.Type != corev1.SecretTypeOpaque ||
		len(secret.Data) != 1 || string(secret.Data[gatewayAuthKeyField]) != key.Key ||
		secret.Labels[gatewayUIDLabel] != string(g.UID) || secret.Annotations["tsunaro.io/tailnet-uid"] != string(tn.UID) ||
		len(secret.OwnerReferences) != 0 {
		t.Fatal("credential receipt or retention boundary incorrect")
	}
	if _, err := storeGatewayMint(ctx, c, "operator", g, tn, req, key, now); !errors.Is(err, ErrGatewayAuthStore) || strings.Contains(err.Error(), key.Key) {
		t.Fatal("existing key overwritten or leaked")
	}
	unchanged := &corev1.Secret{}
	if c.Get(ctx, types.NamespacedName{Name: "router-auth", Namespace: "operator"}, unchanged) != nil || unchanged.UID != secret.UID || string(unchanged.Data[gatewayAuthKeyField]) != key.Key {
		t.Fatal("repeated mint storage changed a retained key")
	}
}

func TestStoreGatewayMintRejectsForgedSnapshotsWithMatchingVersions(t *testing.T) {
	for _, change := range []string{"gateway", "tailnet"} {
		t.Run(change, func(t *testing.T) {
			c, g, tn, req, key, now := authStoreFixture(t)
			if change == "gateway" {
				// The supplied object can be mutated without changing its RV;
				// Kubernetes' stored CR still requests the original tags.
				g.Spec.Tags = []string{"tag:foreign"}
				req.ACLTags = []string{"tag:foreign"}
				key.ACLTags = []string{"tag:foreign"}
			} else {
				tn.Spec.Server = "https://foreign.example"
			}
			if _, err := storeGatewayMint(t.Context(), c, "operator", g, tn, req, key, now); !errors.Is(err, ErrGatewayAuthStore) {
				t.Fatal("forged snapshot accepted")
			}
			if err := c.Get(t.Context(), types.NamespacedName{Name: "router-auth", Namespace: "operator"}, &corev1.Secret{}); err == nil {
				t.Fatal("credential for forged scope stored")
			}
		})
	}
}

func TestStoreGatewayMintRejectsUnverifiedInputs(t *testing.T) {
	for name, change := range map[string]func(client.Client, *tnv1.TailnetGateway, *tnv1.Tailnet, *headscale.PreAuthKey){
		"suspended": func(_ client.Client, g *tnv1.TailnetGateway, _ *tnv1.Tailnet, _ *headscale.PreAuthKey) {
			g.Spec.Suspend = ptr.To(true)
		},
		"external reference": func(_ client.Client, g *tnv1.TailnetGateway, _ *tnv1.Tailnet, _ *headscale.PreAuthKey) {
			g.Spec.AuthKeySecretRef = &tnv1.GatewayAuthKeyReference{Name: "external", Key: "TS_AUTHKEY"}
		},
		"wrong tags": func(_ client.Client, _ *tnv1.TailnetGateway, _ *tnv1.Tailnet, key *headscale.PreAuthKey) {
			key.ACLTags = []string{"tag:foreign"}
		},
		"ephemeral": func(_ client.Client, _ *tnv1.TailnetGateway, _ *tnv1.Tailnet, key *headscale.PreAuthKey) {
			key.Ephemeral = true
		},
		"changed gateway": func(c client.Client, g *tnv1.TailnetGateway, _ *tnv1.Tailnet, _ *headscale.PreAuthKey) {
			current := &tnv1.TailnetGateway{}
			_ = c.Get(context.Background(), client.ObjectKey{Name: g.Name}, current)
			current.Labels = map[string]string{"changed": "yes"}
			_ = c.Update(context.Background(), current)
		},
		"changed tailnet": func(c client.Client, _ *tnv1.TailnetGateway, tn *tnv1.Tailnet, _ *headscale.PreAuthKey) {
			current := &tnv1.Tailnet{}
			_ = c.Get(context.Background(), client.ObjectKey{Name: tn.Name}, current)
			current.Labels = map[string]string{"changed": "yes"}
			_ = c.Update(context.Background(), current)
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, g, tn, req, key, now := authStoreFixture(t)
			change(c, g, tn, key)
			if _, err := storeGatewayMint(context.Background(), c, "operator", g, tn, req, key, now); !errors.Is(err, ErrGatewayAuthStore) || strings.Contains(err.Error(), key.Key) {
				t.Fatalf("unverified key stored or disclosed: %v", err)
			}
			if err := c.Get(context.Background(), types.NamespacedName{Name: "router-auth", Namespace: "operator"}, &corev1.Secret{}); err == nil {
				t.Fatal("unsafe credential was created")
			}
		})
	}
}
