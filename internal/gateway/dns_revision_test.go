package gateway

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func TestDNSRevisionTransitions(t *testing.T) {
	in := dnsFixture()
	in.Serial = 99
	original := in
	fresh, err := PlanDNSRevision(in, nil)
	if err != nil || !fresh.Changed || fresh.Serial != 1 || fresh.ExpectedResourceVersion != "" || !dnsRevisionHash.MatchString(fresh.ContentHash) || !reflect.DeepEqual(in, original) {
		t.Fatal("initial DNS revision failed or changed its input")
	}
	stored := fresh.DNSRevision
	stored.ResourceVersion = "rv-10"
	same, err := PlanDNSRevision(in, &stored)
	if err != nil || same.Changed || same.Serial != 1 || same.ExpectedResourceVersion != "rv-10" || same.ContentHash != fresh.ContentHash {
		t.Fatal("restart or identical data changed the serial")
	}
	// Different source text with the same rendered RRset must not churn SOA.
	in.Hosts = "# comment only\n"
	cosmetic, err := PlanDNSRevision(in, &stored)
	if err != nil || cosmetic.Changed || cosmetic.ContentHash != stored.ContentHash {
		t.Fatal("cosmetic hosts change churned the zone")
	}
	// Only the Tailnet-owned hosts snapshot changed; the gateway spec did not.
	in.Hosts += "203.0.113.7\tother.tail.example\n"
	changed, err := PlanDNSRevision(in, &stored)
	if err != nil || !changed.Changed || changed.Serial != 2 || changed.ExpectedResourceVersion != "rv-10" || changed.ContentHash == stored.ContentHash {
		t.Fatal("hosts-only zone change did not advance with CAS receipt")
	}
	// A concurrent writer's new resourceVersion must be read and supplied to
	// the next plan; no successful API compare-and-swap is claimed here.
	persisted := changed.DNSRevision
	persisted.ResourceVersion = "rv-11"
	restarted, err := PlanDNSRevision(in, &persisted)
	if err != nil || restarted.Changed || restarted.Serial != 2 || restarted.ExpectedResourceVersion != "rv-11" {
		t.Fatal("restart lost the persisted revision")
	}
	in.Hosts = strings.ReplaceAll(in.Hosts, "203.0.113.7", "203.0.113.8")
	advance, err := PlanDNSRevision(in, &persisted)
	if err != nil || advance.Serial != 3 || advance.ExpectedResourceVersion != "rv-11" {
		t.Fatal("second change used stale CAS receipt")
	}
}

func TestDNSRevisionFailClosed(t *testing.T) {
	in := dnsFixture()
	initial, err := PlanDNSRevision(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, prior := range []DNSRevision{
		{Serial: 0, ContentHash: initial.ContentHash, ResourceVersion: "rv"},
		{Serial: 1, ContentHash: "", ResourceVersion: "rv"},
		{Serial: 1, ContentHash: strings.Repeat("G", 64), ResourceVersion: "rv"},
		{Serial: 1, ContentHash: initial.ContentHash},
	} {
		if result, err := PlanDNSRevision(in, &prior); !errors.Is(err, ErrDNSRevisionInvalid) || result != (DNSRevisionPlan{}) {
			t.Fatal("invalid persisted revision accepted")
		}
	}
	last := DNSRevision{Serial: math.MaxUint32, ContentHash: initial.ContentHash, ResourceVersion: "rv"}
	if unchanged, err := PlanDNSRevision(in, &last); err != nil || unchanged.Changed || unchanged.Serial != math.MaxUint32 {
		t.Fatal("stable maximum serial should not change")
	}
	in.Hosts += "203.0.113.4\tnew.tail.example\n"
	if result, err := PlanDNSRevision(in, &last); !errors.Is(err, ErrDNSRevisionExhausted) || result != (DNSRevisionPlan{}) {
		t.Fatal("serial wrapped or reset")
	}
	in.Config.ExtraZones = []tnv1.GatewayExtraZone{{Zone: "site.example", Upstreams: []tnv1.GatewayIP{"192.0.2.53"}}}
	if result, err := PlanDNSRevision(in, nil); !errors.Is(err, ErrDNSForwardingUnsupported) || result != (DNSRevisionPlan{}) {
		t.Fatal("unsupported zones bypassed renderer")
	}
}
