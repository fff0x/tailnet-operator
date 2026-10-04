package gateway

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func TestReadDNSRevisionChecksPersistedPayload(t *testing.T) {
	in := dnsFixture()
	plan, err := PlanDNSRevision(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	in.Serial = plan.Serial
	payload, err := RenderDNS(in)
	if err != nil {
		t.Fatal(err)
	}
	fixture := func() *corev1.ConfigMap {
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{UID: "config-uid", ResourceVersion: "rv-42", Annotations: map[string]string{
			DNSSerialAnnotation: "1", DNSHashAnnotation: plan.ContentHash,
		}}, Data: map[string]string{"Corefile": payload.Corefile, DNSZoneFile: payload.ZoneFile}}
	}
	if got, err := ReadDNSRevision(fixture(), "tail.example"); err != nil || got != (DNSRevision{Serial: 1, ContentHash: plan.ContentHash, ResourceVersion: "rv-42"}) {
		t.Fatal("persisted revision not recovered")
	}
	changed := in
	changed.Hosts = "192.0.2.12\tnew.tail.example\n"
	prev := plan.DNSRevision
	prev.ResourceVersion = "rv-42"
	next, err := PlanDNSRevision(changed, &prev)
	if err != nil || next.Serial != 2 {
		t.Fatal("cannot plan hosts-only update")
	}
	changed.Serial = next.Serial
	updated, err := RenderDNS(changed)
	if err != nil {
		t.Fatal(err)
	}
	cm := fixture()
	cm.ResourceVersion = "rv-43"
	cm.Annotations[DNSSerialAnnotation] = "2"
	cm.Annotations[DNSHashAnnotation] = next.ContentHash
	cm.Data[DNSZoneFile] = updated.ZoneFile
	if got, err := ReadDNSRevision(cm, "tail.example"); err != nil || got.Serial != 2 || got.ContentHash != next.ContentHash || got.ResourceVersion != "rv-43" {
		t.Fatal("persisted advanced serial not recovered")
	}
	for name, change := range map[string]func(*corev1.ConfigMap){
		"missing hash":     func(cm *corev1.ConfigMap) { delete(cm.Annotations, DNSHashAnnotation) },
		"reset serial":     func(cm *corev1.ConfigMap) { cm.Annotations[DNSSerialAnnotation] = "0" },
		"leading zero":     func(cm *corev1.ConfigMap) { cm.Annotations[DNSSerialAnnotation] = "01" },
		"wrong serial":     func(cm *corev1.ConfigMap) { cm.Annotations[DNSSerialAnnotation] = "2" },
		"wrong digest":     func(cm *corev1.ConfigMap) { cm.Annotations[DNSHashAnnotation] = strings.Repeat("0", 64) },
		"changed records":  func(cm *corev1.ConfigMap) { cm.Data[DNSZoneFile] += "other.tail.example. 30 IN A 192.0.2.8\n" },
		"changed corefile": func(cm *corev1.ConfigMap) { cm.Data["Corefile"] += "forward . 192.0.2.53\n" },
		"unversioned":      func(cm *corev1.ConfigMap) { cm.ResourceVersion = "" },
		"extra payload":    func(cm *corev1.ConfigMap) { cm.Data["private"] = "unexpected" },
	} {
		t.Run(name, func(t *testing.T) {
			cm := fixture()
			change(cm)
			if got, err := ReadDNSRevision(cm, "tail.example"); !errors.Is(err, ErrDNSRevisionInvalid) || got != (DNSRevision{}) {
				t.Fatal("inconsistent prior state accepted")
			}
		})
	}
	if got, err := ReadDNSRevision(fixture(), "other.example"); !errors.Is(err, ErrDNSRevisionInvalid) || got != (DNSRevision{}) {
		t.Fatal("wrong zone accepted")
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
