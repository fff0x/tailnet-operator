package gateway

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"tsunaro.io/tailnet-operator/internal/headscale"
)

func TestGatewayMintPlanAndResponse(t *testing.T) {
	g := freshFixture().Gateway
	g.Spec.AuthKeySecretRef = nil
	now := time.Date(2026, 10, 4, 19, 0, 0, 123, time.UTC)
	before := g.DeepCopy()
	req, err := PlanGatewayMint(g, now)
	if err != nil || !req.Reusable || req.Ephemeral || !req.Expiration.Equal(now.Truncate(time.Second).Add(24*time.Hour)) || !reflect.DeepEqual(req.ACLTags, []string{"tag:fabric", "tag:mesh"}) || !reflect.DeepEqual(g, before) {
		t.Fatal("mint plan was not persistent, bounded or input-preserving")
	}
	key := &headscale.PreAuthKey{ID: "17", Key: "private-key-do-not-log", Reusable: true, Ephemeral: false, Expiration: req.Expiration, ACLTags: slices.Clone(req.ACLTags)}
	if err := ValidateGatewayMint(req, key, now); err != nil {
		t.Fatal("valid Headscale response rejected")
	}
	for name, change := range map[string]func(*headscale.PreAuthKey){
		"missing key":       func(p *headscale.PreAuthKey) { p.Key = "" },
		"missing ID":        func(p *headscale.PreAuthKey) { p.ID = "" },
		"non-numeric ID":    func(p *headscale.PreAuthKey) { p.ID = key.Key },
		"zero ID":           func(p *headscale.PreAuthKey) { p.ID = "0" },
		"noncanonical ID":   func(p *headscale.PreAuthKey) { p.ID = "017" },
		"overflow ID":       func(p *headscale.PreAuthKey) { p.ID = "18446744073709551616" },
		"ephemeral":         func(p *headscale.PreAuthKey) { p.Ephemeral = true },
		"one shot":          func(p *headscale.PreAuthKey) { p.Reusable = false },
		"used":              func(p *headscale.PreAuthKey) { p.Used = true },
		"wrong tags":        func(p *headscale.PreAuthKey) { p.ACLTags = []string{"tag:foreign"} },
		"missing tag":       func(p *headscale.PreAuthKey) { p.ACLTags = []string{"tag:fabric"} },
		"duplicate tag":     func(p *headscale.PreAuthKey) { p.ACLTags = []string{"tag:fabric", "tag:fabric"} },
		"expired":           func(p *headscale.PreAuthKey) { p.Expiration = now.Add(-time.Second) },
		"unexpected expiry": func(p *headscale.PreAuthKey) { p.Expiration = now.Add(48 * time.Hour) },
		"oversized key":     func(p *headscale.PreAuthKey) { p.Key = strings.Repeat("x", 4097) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *key
			change(&bad)
			if err := ValidateGatewayMint(req, &bad, now); !errors.Is(err, ErrGatewayAuthMint) || strings.Contains(err.Error(), key.Key) {
				t.Fatal("unverified key accepted or disclosed")
			}
		})
	}
	if err := ValidateGatewayMint(req, nil, now); !errors.Is(err, ErrGatewayAuthMint) {
		t.Fatal("missing server response accepted")
	}
}

func TestGatewayMintRejectsExternalOrInvalid(t *testing.T) {
	now := time.Now()
	for name, mutate := range map[string]func(*FreshInputs){
		"external ref": func(i *FreshInputs) {},
		"no tags":      func(i *FreshInputs) { i.Gateway.Spec.Tags = nil; i.Gateway.Spec.AuthKeySecretRef = nil },
		"bad tag": func(i *FreshInputs) {
			i.Gateway.Spec.Tags = []string{"tag:fabric --override"}
			i.Gateway.Spec.AuthKeySecretRef = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			in := freshFixture()
			mutate(&in)
			if req, err := PlanGatewayMint(in.Gateway, now); !errors.Is(err, ErrGatewayAuthMint) || !reflect.DeepEqual(req, headscale.CreatePreAuthKeyRequest{}) {
				t.Fatal("external or unsafe bootstrap admitted")
			}
		})
	}
}
