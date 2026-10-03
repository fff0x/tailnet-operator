package controller

import (
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func dnsClaimsTestMeta(name, namespace, uid string, age int) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name: name, Namespace: namespace, UID: types.UID(uid),
		CreationTimestamp: metav1.NewTime(time.Date(2026, 10, 3, 10, age, 0, 0, time.UTC)),
	}
}

func dnsClaimsTestTailnet() *tnv1.Tailnet {
	tn := &tnv1.Tailnet{ObjectMeta: dnsClaimsTestMeta("tailnet", "", "tailnet-uid", 0)}
	tn.Spec.DNS.HostsConfigMap = "hosts"
	tn.Spec.DNS.IngressNameTemplate = "{name}.{namespace}.example"
	return tn
}

func dnsClaimsTestIngress() *tnv1.TailnetIngress {
	return &tnv1.TailnetIngress{
		ObjectMeta: dnsClaimsTestMeta("bundle", "apps", "ingress-uid", 1),
		Spec: tnv1.TailnetIngressSpec{
			TailnetRef: tnv1.TailnetRef{Name: "tailnet"},
			Exposes: []tnv1.Expose{
				{Name: "z-route", Mode: "http", Port: 443, DNSLabel: "z"},
				{Name: "a-route", Mode: "http", Port: 443, DNSLabel: "a"},
			},
		},
	}
}

func dnsClaimsTestEgress() *tnv1.TailnetEgress {
	return &tnv1.TailnetEgress{
		ObjectMeta: dnsClaimsTestMeta("egress", "operator", "egress-uid", 2),
		Spec: tnv1.TailnetEgressSpec{
			TailnetRef: tnv1.TailnetRef{Name: "tailnet"},
			Targets:    []tnv1.Target{{Name: "remote", Address: "192.0.2.1", Port: 443, Aliases: []string{"z.example", "a.example", "z.example"}}},
		},
	}
}

func dnsClaimsTestSet(kind, namespace, name, uid string, age int, names ...string) dnsDesiredClaims {
	meta := dnsClaimsTestMeta(name, namespace, uid, age)
	set := dnsDesiredClaims{
		Scope: dnsClaimScope{OperatorNamespace: "operator", TailnetName: "tailnet"}, TailnetUID: "tailnet-uid",
		Owner: dnsClaimOwner{dnsClaimOwnerKey: dnsClaimOwnerKey{Kind: kind, Namespace: namespace, Name: name, UID: meta.UID}, CreationTimestamp: meta.CreationTimestamp.Time},
	}
	for _, name := range names {
		set.Claims = append(set.Claims, dnsNameClaim{Name: name, Sources: []dnsClaimSource{{Kind: "base"}}})
	}
	return set
}

func dnsClaimsTestArbitrate(t *testing.T, sets ...dnsDesiredClaims) []dnsClaimDecision {
	t.Helper()
	got, reason := arbitrateDNSClaims(sets)
	if reason != "" {
		t.Fatalf("arbitrate: %s", reason)
	}
	return got
}

func TestDNSClaimsIngressCurrentPlan(t *testing.T) {
	tn, in := dnsClaimsTestTailnet(), dnsClaimsTestIngress()
	beforeTN, beforeIn := tn.DeepCopy(), in.DeepCopy()
	got, reason := desiredIngressDNSClaims(in, tn, "operator")
	want := []dnsNameClaim{
		{Name: "a.apps.example", Sources: []dnsClaimSource{{Kind: "expose", Name: "a-route"}}},
		{Name: "bundle.apps.example", Sources: []dnsClaimSource{{Kind: "base"}}},
		{Name: "z.apps.example", Sources: []dnsClaimSource{{Kind: "expose", Name: "z-route"}}},
	}
	if reason != "" || got == nil || !reflect.DeepEqual(got.Claims, want) {
		t.Fatalf("got %+v, %q; want %+v", got, reason, want)
	}
	if !reflect.DeepEqual(tn, beforeTN) || !reflect.DeepEqual(in, beforeIn) {
		t.Fatal("derivation mutated inputs")
	}
	// A claimed/certified base is not an implicit HTTP route.
	plan, _ := resolveIngressDNSNames(in, tn)
	for _, name := range plan.exposeNames {
		if name == "bundle.apps.example" {
			t.Fatal("base unexpectedly became a route")
		}
	}
	in.Spec.Exposes[0].DNSLabel = "bundle" // explicit route equals base: valid, one owner
	got, reason = desiredIngressDNSClaims(in, tn, "operator")
	want[1].Sources = append(want[1].Sources, dnsClaimSource{Kind: "expose", Name: "z-route"})
	want = want[:2]
	if reason != "" || !reflect.DeepEqual(got.Claims, want) {
		t.Fatalf("base equals route: %+v, %q", got, reason)
	}
	in.Spec.Exposes[0].DNSLabel = "" // default HTTP label has the same valid overlap
	got, reason = desiredIngressDNSClaims(in, tn, "operator")
	if reason != "" || !reflect.DeepEqual(got.Claims, want) {
		t.Fatalf("empty route label: %+v, %q", got, reason)
	}
	in.Spec.Exposes = []tnv1.Expose{{Name: "ssh", Port: 22}}
	got, reason = desiredIngressDNSClaims(in, tn, "operator")
	if reason != "" || len(got.Claims) != 1 || got.Claims[0].Name != "bundle.apps.example" {
		t.Fatalf("L4 base lost: %+v, %q", got, reason)
	}
	tn.Spec.DNS.IngressNameTemplate = ""
	got, reason = desiredIngressDNSClaims(in, tn, "operator")
	if reason != "" || got == nil || len(got.Claims) != 0 {
		t.Fatalf("L4 without template: %+v, %q", got, reason)
	}
	in.Spec.Exposes[0].Mode, in.Spec.Exposes[0].Port = "http", 443
	if got, reason = desiredIngressDNSClaims(in, tn, "operator"); got != nil || reason != "TLSInvalidDNSName" {
		t.Fatalf("planner validation bypassed: %+v, %q", got, reason)
	}
}

func TestDNSClaimsStatusAndDeletionIndependent(t *testing.T) {
	tn, in, eg := dnsClaimsTestTailnet(), dnsClaimsTestIngress(), dnsClaimsTestEgress()
	beforeIn, _ := desiredIngressDNSClaims(in, tn, "operator")
	beforeEg, _ := desiredEgressDNSClaims(eg, tn, "operator")
	in.Status.DNSName = "stale.other.example"
	in.Status.TailnetIPs = []string{"100.64.0.1"}
	in.Status.Exposes = []tnv1.ExposeStatus{{Name: "stale", DNSName: "old.example", Reachable: true}}
	in.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}}
	in.Spec.Exposes[0].Backend.TLS = &tnv1.BackendTLS{ServerName: "backend.example", CAConfigMapRef: tnv1.CAConfigMapRef{Name: "absent-ca", Key: "ca.crt"}}
	in.Spec.TLS = &tnv1.IngressTLS{} // no credential/material resolution here
	eg.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionFalse}}
	eg.Status.Targets = []tnv1.TargetStatus{{Name: "remote", Present: false, Reachable: false}}
	now := metav1.NewTime(time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC))
	in.DeletionTimestamp, eg.DeletionTimestamp = &now, &now
	in.Finalizers, eg.Finalizers = []string{"example.test/drain"}, []string{"example.test/drain"}
	afterIn, ri := desiredIngressDNSClaims(in, tn, "operator")
	afterEg, re := desiredEgressDNSClaims(eg, tn, "operator")
	if ri != "" || re != "" || !reflect.DeepEqual(beforeIn, afterIn) || !reflect.DeepEqual(beforeEg, afterEg) {
		t.Fatalf("status/material/deletion changed desired claims: %q %q", ri, re)
	}
	younger := dnsClaimsTestSet(dnsIngressKind, "younger", "app", "younger", 3, afterIn.Claims[0].Name)
	decisions := dnsClaimsTestArbitrate(t, younger, *afterIn)
	if !decisions[1].Blocked || decisions[1].Conflict.Owner.UID != in.UID {
		t.Fatal("deleting owner did not reserve its name")
	}
	// Missing/stale Ready cannot select ownership in either direction.
	in.Status.Conditions[0].Status = metav1.ConditionFalse
	afterIn, _ = desiredIngressDNSClaims(in, tn, "operator")
	if !reflect.DeepEqual(beforeIn, afterIn) {
		t.Fatal("Ready=False changed claims")
	}
}

func TestDNSClaimsEgressAliases(t *testing.T) {
	tn, eg := dnsClaimsTestTailnet(), dnsClaimsTestEgress()
	before := eg.DeepCopy()
	got, reason := desiredEgressDNSClaims(eg, tn, "operator")
	want := []dnsNameClaim{
		{Name: "a.example", Sources: []dnsClaimSource{{Kind: "target", Name: "remote"}}},
		{Name: "z.example", Sources: []dnsClaimSource{{Kind: "target", Name: "remote"}}},
	}
	if reason != "" || got == nil || !reflect.DeepEqual(got.Claims, want) || !reflect.DeepEqual(eg, before) {
		t.Fatalf("dedup/sort/preservation: %+v, %q", got, reason)
	}
	for _, tc := range []struct {
		name, reason string
		mutate       func(*tnv1.TailnetEgress)
	}{
		{"distinct targets same alias", dnsEgressAliasAmbiguous, func(e *tnv1.TailnetEgress) {
			e.Spec.Targets = append(e.Spec.Targets, tnv1.Target{Name: "second", Address: "192.0.2.2", Port: 443, Aliases: []string{"a.example"}})
		}},
		{"duplicate target different backend", dnsEgressTargetInvalid, func(e *tnv1.TailnetEgress) {
			e.Spec.Targets = append(e.Spec.Targets, tnv1.Target{Name: "remote", Address: "192.0.2.2", Port: 80, Aliases: []string{"elsewhere.example"}})
		}},
		{"duplicate identical target", dnsEgressTargetInvalid, func(e *tnv1.TailnetEgress) { e.Spec.Targets = append(e.Spec.Targets, e.Spec.Targets[0]) }},
		{"DNS1035 target name", dnsEgressTargetInvalid, func(e *tnv1.TailnetEgress) { e.Spec.Targets[0].Name = "1remote" }},
		{"empty target name", dnsEgressTargetInvalid, func(e *tnv1.TailnetEgress) { e.Spec.Targets[0].Name = "" }},
		{"no targets", dnsEgressTargetInvalid, func(e *tnv1.TailnetEgress) { e.Spec.Targets = nil }},
		{"uppercase", dnsEgressAliasInvalid, func(e *tnv1.TailnetEgress) { e.Spec.Targets[0].Aliases = []string{"UP.example"} }},
		{"trailing dot", dnsEgressAliasInvalid, func(e *tnv1.TailnetEgress) { e.Spec.Targets[0].Aliases = []string{"a.example."} }},
		{"space", dnsEgressAliasInvalid, func(e *tnv1.TailnetEgress) { e.Spec.Targets[0].Aliases = []string{" a.example"} }},
		{"empty alias", dnsEgressAliasInvalid, func(e *tnv1.TailnetEgress) { e.Spec.Targets[0].Aliases = []string{""} }},
		{"IP", dnsEgressAliasInvalid, func(e *tnv1.TailnetEgress) { e.Spec.Targets[0].Aliases = []string{"192.0.2.1"} }},
		{"IPv6", dnsEgressAliasInvalid, func(e *tnv1.TailnetEgress) { e.Spec.Targets[0].Aliases = []string{"2001:db8::1"} }},
		{"wildcard", dnsEgressAliasInvalid, func(e *tnv1.TailnetEgress) { e.Spec.Targets[0].Aliases = []string{"*.example"} }},
		{"API length bound", dnsEgressAliasInvalid, func(e *tnv1.TailnetEgress) { e.Spec.Targets[0].Aliases = []string{strings.Repeat("a", 60) + ".com"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := eg.DeepCopy()
			tc.mutate(e)
			for range 2 {
				got, reason := desiredEgressDNSClaims(e, tn, "operator")
				if got != nil || reason != tc.reason {
					t.Fatalf("got %+v, %q; want %q", got, reason, tc.reason)
				}
				slices.Reverse(e.Spec.Targets)
			}
		})
	}
	// No need for a Service/IP/health/backend lookup, and no address-derived claims.
	eg.Spec.Targets[0].Aliases = nil
	got, reason = desiredEgressDNSClaims(eg, tn, "operator")
	if reason != "" || len(got.Claims) != 0 {
		t.Fatalf("unexpected address claim: %+v, %q", got, reason)
	}
	eg.Spec.Targets[0].Aliases = []string{"1", strings.Repeat("a", 63)}
	if _, reason = desiredEgressDNSClaims(eg, tn, "operator"); reason != "" {
		t.Fatalf("valid numeric label / maximum length rejected: %s", reason)
	}
}

func TestDNSClaimsFeatureOffAndBoundaries(t *testing.T) {
	tn, in, eg := dnsClaimsTestTailnet(), dnsClaimsTestIngress(), dnsClaimsTestEgress()
	tn.Spec.DNS.HostsConfigMap = ""
	// Off means no validation/enforcement, even for malformed specs/identities.
	in.UID, eg.UID = "", ""
	in.Spec.Exposes, eg.Spec.Targets = nil, nil
	if got, reason := desiredIngressDNSClaims(in, tn, ""); got != nil || reason != "" {
		t.Fatalf("off ingress enforced: %+v, %q", got, reason)
	}
	if got, reason := desiredEgressDNSClaims(eg, tn, ""); got != nil || reason != "" {
		t.Fatalf("off egress enforced: %+v, %q", got, reason)
	}
	tn, in, eg = dnsClaimsTestTailnet(), dnsClaimsTestIngress(), dnsClaimsTestEgress()
	eg.Namespace = "tenant"
	if got, reason := desiredEgressDNSClaims(eg, tn, "operator"); got != nil || reason != "" {
		t.Fatalf("egress outside operator namespace included: %+v, %q", got, reason)
	}
	in.Namespace = "tenant"
	if got, reason := desiredIngressDNSClaims(in, tn, "operator"); got == nil || reason != "" {
		t.Fatalf("tenant ingress excluded: %+v, %q", got, reason)
	}
	eg.Namespace = "operator"
	in.Spec.TailnetRef.Name, eg.Spec.TailnetRef.Name = "other", "other"
	if got, reason := desiredIngressDNSClaims(in, tn, "operator"); got != nil || reason != "" {
		t.Fatalf("other Tailnet ingress included: %+v, %q", got, reason)
	}
	if got, reason := desiredEgressDNSClaims(eg, tn, "operator"); got != nil || reason != "" {
		t.Fatalf("other Tailnet egress included: %+v, %q", got, reason)
	}
	if got := dnsClaimsTestArbitrate(t); len(got) != 0 {
		t.Fatal("empty snapshot invented decisions")
	}
}

func TestDNSClaimsRanking(t *testing.T) {
	base := dnsClaimsTestSet(dnsIngressKind, "operator", "same", "same-uid", 1, "shared.example")
	for _, tc := range []struct {
		name   string
		mutate func(*dnsDesiredClaims, *dnsDesiredClaims)
	}{
		{"timestamp before namespace", func(a, b *dnsDesiredClaims) {
			a.Owner.Namespace = "z"
			b.Owner.Namespace = "a"
			b.Owner.CreationTimestamp = b.Owner.CreationTimestamp.Add(time.Second)
		}},
		{"namespace before name", func(a, b *dnsDesiredClaims) {
			a.Owner.Namespace = "a"
			b.Owner.Namespace = "b"
			a.Owner.Name = "z"
			b.Owner.Name = "a"
		}},
		{"name before UID", func(a, b *dnsDesiredClaims) {
			a.Owner.Name = "a"
			b.Owner.Name = "b"
			a.Owner.UID = "z"
			b.Owner.UID = "a"
		}},
		{"same name different UID", func(a, b *dnsDesiredClaims) {
			a.Owner.UID = "a"
			b.Owner.UID = "b"
			a.Owner.Kind = dnsIngressKind
			b.Owner.Kind = dnsEgressKind
		}},
		{"kind last", func(a, b *dnsDesiredClaims) { a.Owner.Kind = dnsEgressKind; b.Owner.Kind = dnsIngressKind }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := base, base
			tc.mutate(&a, &b)
			for _, sets := range [][]dnsDesiredClaims{{a, b}, {b, a}} {
				got := dnsClaimsTestArbitrate(t, sets...)
				if got[0].Desired.Owner != a.Owner || got[0].Blocked || !got[1].Blocked || got[1].Conflict.Owner != a.Owner {
					t.Fatalf("rank mismatch: %+v", got)
				}
			}
		})
	}
	// Same instant, different time.Location pointers: rank reaches UID, while
	// the stable key also detects repeated snapshots of the very same owner.
	a, b := base, base
	a.Owner.CreationTimestamp = a.Owner.CreationTimestamp.In(time.FixedZone("first", 3600))
	b.Owner.CreationTimestamp = b.Owner.CreationTimestamp.In(time.FixedZone("second", -3600))
	if a.Owner.dnsClaimOwnerKey != b.Owner.dnsClaimOwnerKey || compareDNSClaimOwners(a.Owner, b.Owner) != 0 {
		t.Fatal("location affected key/rank")
	}
	if got, reason := arbitrateDNSClaims([]dnsDesiredClaims{a, b}); got != nil || reason != dnsClaimInputInvalid {
		t.Fatalf("repeated identity accepted: %+v, %q", got, reason)
	}
	b.Owner.UID = "younger-uid"
	got := dnsClaimsTestArbitrate(t, b, a)
	if got[0].Desired.Owner.UID != a.Owner.UID || got[0].Desired.Owner.CreationTimestamp.Location() != time.UTC {
		t.Fatal("equal timestamp instant was not normalized/ranked")
	}
}

func TestDNSClaimsCrossKindAndReservationChain(t *testing.T) {
	a := dnsClaimsTestSet(dnsIngressKind, "apps", "a", "a-uid", 0, "first.example", "z.example")
	b := dnsClaimsTestSet(dnsEgressKind, "operator", "b", "b-uid", 1, "second.example", "z.example", "first.example")
	c := dnsClaimsTestSet(dnsIngressKind, "tenant", "c", "c-uid", 2, "second.example", "third.example")
	d := dnsClaimsTestSet(dnsEgressKind, "operator", "d", "d-uid", 3, "third.example")
	got := dnsClaimsTestArbitrate(t, d, c, b, a)
	for i, want := range [][]string{{"first.example", "z.example"}, {"second.example"}, {"third.example"}, nil} {
		if !reflect.DeepEqual(got[i].OwnedNames, want) || got[i].Blocked != (i > 0) {
			t.Fatalf("owner %d lost reservation: %+v", i, got[i])
		}
	}
	for i, name := range []string{"first.example", "second.example", "third.example"} {
		if got[i+1].Conflict.Name != name || got[i+1].Conflict.Owner != got[i].Desired.Owner {
			t.Fatalf("deterministic conflict mismatch: %+v", got[i+1])
		}
	}
}

func TestDNSClaimsCurrentIntentIsNotServedHistory(t *testing.T) {
	tn, in, eg := dnsClaimsTestTailnet(), dnsClaimsTestIngress(), dnsClaimsTestEgress()
	old, _ := desiredIngressDNSClaims(in, tn, "operator")
	in.Status.DNSName = old.Claims[0].Name
	in.Status.Exposes = []tnv1.ExposeStatus{{Name: "a-route", DNSName: old.Claims[0].Name}}
	in.Spec.Exposes[1].DNSLabel = "new"
	current, reason := desiredIngressDNSClaims(in, tn, "operator")
	if reason != "" {
		t.Fatal(reason)
	}
	eg.Spec.Targets[0].Aliases = []string{old.Claims[0].Name}
	successor, _ := desiredEgressDNSClaims(eg, tn, "operator")
	got := dnsClaimsTestArbitrate(t, *current, *successor)
	if got[1].Blocked || !reflect.DeepEqual(got[1].OwnedNames, []string{old.Claims[0].Name}) {
		t.Fatal("historical status was treated as current intent")
	}
	// This ONLY proves current ownership. It says nothing about whether old
	// ingress listeners still serve the name: future history/drain code must wait.
	for _, kind := range []string{dnsIngressKind, dnsEgressKind} {
		a := dnsClaimsTestSet(kind, "operator", "a", "a-uid", 0, "same.example")
		b := dnsClaimsTestSet(kind, "operator", "b", "b-uid", 1, "same.example")
		if decisions := dnsClaimsTestArbitrate(t, b, a); decisions[0].Blocked || !decisions[1].Blocked {
			t.Fatalf("same-kind %s conflict missing", kind)
		}
	}
}

func TestDNSClaimsScopeVersusIncarnation(t *testing.T) {
	a := dnsClaimsTestSet(dnsIngressKind, "apps", "a", "a-uid", 0, "shared.example")
	b := dnsClaimsTestSet(dnsEgressKind, "operator", "b", "b-uid", 1, "shared.example")
	b.TailnetUID = "recreated-tailnet-uid"
	got := dnsClaimsTestArbitrate(t, b, a)
	if !got[1].Blocked || got[1].Desired.TailnetUID != b.TailnetUID {
		t.Fatal("Tailnet UID partitioned logical scope or provenance lost")
	}
	b.Scope.TailnetName = "other"
	for _, d := range dnsClaimsTestArbitrate(t, a, b) {
		if d.Blocked {
			t.Fatal("disjoint Tailnets conflict")
		}
	}
	b.Scope.TailnetName, b.Scope.OperatorNamespace = a.Scope.TailnetName, "other-operator"
	b.Owner.Namespace = "other-operator"
	for _, d := range dnsClaimsTestArbitrate(t, a, b) {
		if d.Blocked {
			t.Fatal("disjoint operator boundaries conflict")
		}
	}
}

func TestDNSClaimsInvalidIdentity(t *testing.T) {
	base := dnsClaimsTestSet(dnsIngressKind, "apps", "a", "a-uid", 0, "shared.example")
	for _, tc := range []struct {
		name   string
		mutate func(*dnsDesiredClaims)
	}{
		{"kind", func(s *dnsDesiredClaims) { s.Owner.Kind = "" }},
		{"unknown kind", func(s *dnsDesiredClaims) { s.Owner.Kind = "Pod" }},
		{"namespace", func(s *dnsDesiredClaims) { s.Owner.Namespace = "" }},
		{"name", func(s *dnsDesiredClaims) { s.Owner.Name = "" }},
		{"malformed name", func(s *dnsDesiredClaims) { s.Owner.Name = "bad/name" }},
		{"UID", func(s *dnsDesiredClaims) { s.Owner.UID = "" }},
		{"malformed UID", func(s *dnsDesiredClaims) { s.Owner.UID = "not a uid\n" }},
		{"zero timestamp", func(s *dnsDesiredClaims) { s.Owner.CreationTimestamp = time.Time{} }},
		{"operator boundary", func(s *dnsDesiredClaims) { s.Scope.OperatorNamespace = "" }},
		{"Tailnet name", func(s *dnsDesiredClaims) { s.Scope.TailnetName = "" }},
		{"Tailnet UID", func(s *dnsDesiredClaims) { s.TailnetUID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := base
			tc.mutate(&bad)
			for _, sets := range [][]dnsDesiredClaims{{base, bad}, {bad, base}} {
				if got, reason := arbitrateDNSClaims(sets); got != nil || reason != dnsClaimIdentityInvalid {
					t.Fatalf("partial/invalid decision: %+v %q", got, reason)
				}
			}
		})
	}
	tn, in, eg := dnsClaimsTestTailnet(), dnsClaimsTestIngress(), dnsClaimsTestEgress()
	in.CreationTimestamp, eg.CreationTimestamp = metav1.Time{}, metav1.Time{}
	if got, reason := desiredIngressDNSClaims(in, tn, "operator"); got != nil || reason != dnsClaimIdentityInvalid {
		t.Fatalf("zero ingress timestamp: %+v %q", got, reason)
	}
	if got, reason := desiredEgressDNSClaims(eg, tn, "operator"); got != nil || reason != dnsClaimIdentityInvalid {
		t.Fatalf("zero egress timestamp: %+v %q", got, reason)
	}
	if got, reason := desiredIngressDNSClaims(nil, tn, "operator"); got != nil || reason != dnsClaimInputInvalid {
		t.Fatalf("nil ingress: %+v %q", got, reason)
	}
	if got, reason := desiredEgressDNSClaims(nil, tn, "operator"); got != nil || reason != dnsClaimInputInvalid {
		t.Fatalf("nil egress: %+v %q", got, reason)
	}
	if got, reason := desiredIngressDNSClaims(in, nil, "operator"); got != nil || reason != dnsClaimInputInvalid {
		t.Fatalf("nil Tailnet: %+v %q", got, reason)
	}
	if got, reason := desiredEgressDNSClaims(eg, nil, "operator"); got != nil || reason != dnsClaimInputInvalid {
		t.Fatalf("nil Tailnet: %+v %q", got, reason)
	}
}

func TestDNSClaimsMalformedSnapshotsAndDerivationIdentity(t *testing.T) {
	for _, mutate := range []func(*dnsDesiredClaims){
		func(s *dnsDesiredClaims) { s.Claims[0].Name = "INVALID" },
		func(s *dnsDesiredClaims) { s.Owner.Kind = dnsEgressKind; s.Owner.Namespace = "tenant" },
	} {
		set := dnsClaimsTestSet(dnsIngressKind, "operator", "app", "app-uid", 1, "a.example")
		mutate(&set)
		if got, reason := arbitrateDNSClaims([]dnsDesiredClaims{set}); got != nil || reason != dnsClaimInputInvalid {
			t.Fatalf("malformed snapshot accepted: %+v %q", got, reason)
		}
	}
	for _, mutate := range []func(*metav1.ObjectMeta){
		func(m *metav1.ObjectMeta) { m.UID = "" },
		func(m *metav1.ObjectMeta) { m.Name = "" },
		func(m *metav1.ObjectMeta) { m.CreationTimestamp = metav1.Time{} },
	} {
		tn, in, eg := dnsClaimsTestTailnet(), dnsClaimsTestIngress(), dnsClaimsTestEgress()
		mutate(&in.ObjectMeta)
		mutate(&eg.ObjectMeta)
		if got, reason := desiredIngressDNSClaims(in, tn, "operator"); got != nil || reason != dnsClaimIdentityInvalid {
			t.Fatalf("malformed ingress identity accepted: %+v %q", got, reason)
		}
		if got, reason := desiredEgressDNSClaims(eg, tn, "operator"); got != nil || reason != dnsClaimIdentityInvalid {
			t.Fatalf("malformed egress identity accepted: %+v %q", got, reason)
		}
	}
	tn, in, eg := dnsClaimsTestTailnet(), dnsClaimsTestIngress(), dnsClaimsTestEgress()
	in.Spec.TailnetRef.Name, eg.Spec.TailnetRef.Name = "", ""
	if got, reason := desiredIngressDNSClaims(in, tn, "operator"); got != nil || reason != dnsClaimIdentityInvalid {
		t.Fatalf("missing ingress reference accepted: %+v %q", got, reason)
	}
	if got, reason := desiredEgressDNSClaims(eg, tn, "operator"); got != nil || reason != dnsClaimIdentityInvalid {
		t.Fatalf("missing egress reference accepted: %+v %q", got, reason)
	}
	in, eg = dnsClaimsTestIngress(), dnsClaimsTestEgress()
	tn.UID = ""
	if got, reason := desiredIngressDNSClaims(in, tn, "operator"); got != nil || reason != dnsClaimIdentityInvalid {
		t.Fatalf("missing Tailnet provenance accepted: %+v %q", got, reason)
	}
	if got, reason := desiredEgressDNSClaims(eg, tn, "operator"); got != nil || reason != dnsClaimIdentityInvalid {
		t.Fatalf("missing Tailnet provenance accepted: %+v %q", got, reason)
	}
}

func TestDNSClaimsOrderIndependenceAndOwnership(t *testing.T) {
	tn, in, eg := dnsClaimsTestTailnet(), dnsClaimsTestIngress(), dnsClaimsTestEgress()
	eg.Spec.Targets = append(eg.Spec.Targets, tnv1.Target{Name: "other", Aliases: []string{"b.example"}})
	inBefore, egBefore, tnBefore := in.DeepCopy(), eg.DeepCopy(), tn.DeepCopy()
	is, _ := desiredIngressDNSClaims(in, tn, "operator")
	es, _ := desiredEgressDNSClaims(eg, tn, "operator")
	slices.Reverse(in.Spec.Exposes)
	slices.Reverse(eg.Spec.Targets)
	for i := range eg.Spec.Targets {
		slices.Reverse(eg.Spec.Targets[i].Aliases)
	}
	is2, _ := desiredIngressDNSClaims(in, tn, "operator")
	es2, _ := desiredEgressDNSClaims(eg, tn, "operator")
	if !reflect.DeepEqual(is, is2) || !reflect.DeepEqual(es, es2) {
		t.Fatal("object list order changed claims")
	}
	// Restore fixtures, then exercise arbitrary claim/provenance/owner orders.
	in, eg = inBefore.DeepCopy(), egBefore.DeepCopy()
	sets := []dnsDesiredClaims{*is, *es, dnsClaimsTestSet(dnsIngressKind, "tenant", "last", "last-uid", 4, is.Claims[0].Name, es.Claims[0].Name)}
	want := dnsClaimsTestArbitrate(t, sets...)
	rng := rand.New(rand.NewSource(42))
	for range 100 {
		rng.Shuffle(len(sets), func(i, j int) { sets[i], sets[j] = sets[j], sets[i] })
		for i := range sets {
			s := &sets[i]
			rng.Shuffle(len(s.Claims), func(i, j int) { s.Claims[i], s.Claims[j] = s.Claims[j], s.Claims[i] })
			for _, claim := range s.Claims {
				rng.Shuffle(len(claim.Sources), func(i, j int) { claim.Sources[i], claim.Sources[j] = claim.Sources[j], claim.Sources[i] })
			}
		}
		if got := dnsClaimsTestArbitrate(t, sets...); !reflect.DeepEqual(got, want) {
			t.Fatal("reordered snapshot changed output")
		}
	}
	// Arbitration must not sort or compact the caller's nested slices in place.
	input := []dnsDesiredClaims{dnsClaimsTestSet(dnsIngressKind, "apps", "one", "one-uid", 0, "z.example", "a.example")}
	input[0].Claims[0].Sources = []dnsClaimSource{{Kind: "expose", Name: "z"}, {Kind: "base"}, {Kind: "expose", Name: "z"}}
	copyBefore := dnsClaimsTestArbitrate(t, input...)
	original := []dnsNameClaim{
		{Name: "z.example", Sources: []dnsClaimSource{{Kind: "expose", Name: "z"}, {Kind: "base"}, {Kind: "expose", Name: "z"}}},
		{Name: "a.example", Sources: []dnsClaimSource{{Kind: "base"}}},
	}
	got := dnsClaimsTestArbitrate(t, input...)
	if !reflect.DeepEqual(input[0].Claims, original) {
		t.Fatal("arbitration mutated nested input")
	}
	got[0].Desired.Claims[0].Name = "mutated.example"
	got[0].Desired.Claims[1].Sources[0].Kind = "mutated"
	got[0].OwnedNames[0] = "mutated.example"
	if !reflect.DeepEqual(input[0].Claims, original) || !reflect.DeepEqual(copyBefore, dnsClaimsTestArbitrate(t, input...)) {
		t.Fatal("output aliases input or another output")
	}
	fresh := dnsClaimsTestArbitrate(t, sets...)
	fresh[2].Conflict.Owner.Name = "mutated"
	fresh[0].Desired.Claims[0].Sources[0].Name = "mutated"
	if !reflect.DeepEqual(want, dnsClaimsTestArbitrate(t, sets...)) {
		t.Fatal("conflict/desired output aliases another result or input")
	}
	is.Claims[0].Sources[0].Name, es.Claims[0].Name = "mutated", "mutated"
	if !reflect.DeepEqual(in, inBefore) || !reflect.DeepEqual(eg, egBefore) || !reflect.DeepEqual(tn, tnBefore) {
		t.Fatal("derived output aliases Kubernetes inputs")
	}
}
