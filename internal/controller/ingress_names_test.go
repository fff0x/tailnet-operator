package controller

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func TestResolveIngressDNSNames(t *testing.T) {
	http := func(name, label string) tnv1.Expose {
		return tnv1.Expose{Name: name, Mode: "http", Port: 443, DNSLabel: label}
	}
	l4 := func(name string, port int32) tnv1.Expose {
		return tnv1.Expose{Name: name, Port: port}
	}
	for _, tt := range []struct {
		name    string
		tmpl    string
		exposes []tnv1.Expose
		base    string
		routes  map[string]string
		certs   []string
	}{
		{"legacy-single-http", "{name}.example", []tnv1.Expose{http("web", "")}, "apps.example", map[string]string{"web": "apps.example"}, []string{"apps.example"}},
		{"multi-http-and-l4", "{name}.example", []tnv1.Expose{http("z", "zeta"), l4("db", 5432), http("a", "alpha")}, "apps.example", map[string]string{"z": "zeta.example", "a": "alpha.example"}, []string{"apps.example", "alpha.example", "zeta.example"}},
		{"unlabeled-and-labeled", "{name}.example", []tnv1.Expose{http("base", ""), http("a", "alpha")}, "apps.example", map[string]string{"base": "apps.example", "a": "alpha.example"}, []string{"apps.example", "alpha.example"}},
		{"base-san-dedup", "{name}.example", []tnv1.Expose{http("web", "apps")}, "apps.example", map[string]string{"web": "apps.example"}, []string{"apps.example"}},
		{"base-san-dedup-with-sibling", "{name}.example", []tnv1.Expose{http("web", "apps"), http("a", "alpha")}, "apps.example", map[string]string{"web": "apps.example", "a": "alpha.example"}, []string{"apps.example", "alpha.example"}},
		{"namespace", "{name}-{namespace}.example", []tnv1.Expose{http("web", "shop")}, "apps-team.example", map[string]string{"web": "shop-team.example"}, []string{"apps-team.example", "shop-team.example"}},
		{"l4-empty-template", "", []tnv1.Expose{l4("db", 5432), {Name: "https", Mode: "l4", Port: 443}}, "", nil, nil},
		{"l4-template", "{name}.example", []tnv1.Expose{l4("db", 5432)}, "apps.example", nil, nil},
		{"static-single-dedup", "fixed.example", []tnv1.Expose{http("web", "shop")}, "fixed.example", map[string]string{"web": "fixed.example"}, []string{"fixed.example"}},
		{"label-63", "{name}.example", []tnv1.Expose{http("web", strings.Repeat("a", 63))}, "apps.example", map[string]string{"web": strings.Repeat("a", 63) + ".example"}, []string{"apps.example", strings.Repeat("a", 63) + ".example"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "apps", Namespace: "team"}, Spec: tnv1.TailnetIngressSpec{Exposes: tt.exposes}}
			in.Status.DNSName = "stale.example"
			in.Status.Exposes = []tnv1.ExposeStatus{{Name: "web", DNSName: "also-stale.example"}}
			tn := &tnv1.Tailnet{}
			tn.Spec.DNS.IngressNameTemplate = tt.tmpl
			beforeIn, beforeTN := in.DeepCopy(), tn.DeepCopy()
			want := ingressDNSPlan{baseName: tt.base, exposeNames: tt.routes, certificateNames: tt.certs}
			got, reason := resolveIngressDNSNames(in, tn)
			if reason != "" || !reflect.DeepEqual(got, want) {
				t.Fatalf("plan=%+v reason=%q; want %+v", got, reason, want)
			}
			if !reflect.DeepEqual(in, beforeIn) || !reflect.DeepEqual(tn, beforeTN) {
				t.Fatal("resolver mutated caller input")
			}
			// Route order must not affect SAN ordering or the route map.
			reversed := in.DeepCopy()
			for i, j := 0, len(reversed.Spec.Exposes)-1; i < j; i, j = i+1, j-1 {
				reversed.Spec.Exposes[i], reversed.Spec.Exposes[j] = reversed.Spec.Exposes[j], reversed.Spec.Exposes[i]
			}
			if reordered, reason := resolveIngressDNSNames(reversed, tn); reason != "" || !reflect.DeepEqual(reordered, got) {
				t.Fatalf("reordered plan=%+v reason=%q; want %+v", reordered, reason, got)
			}
			// Returned collections are caller-owned, not aliases of input or later plans.
			if got.exposeNames != nil {
				got.exposeNames["caller"] = "changed.example"
				got.certificateNames[0] = "changed.example"
			}
			if again, reason := resolveIngressDNSNames(in, tn); reason != "" || !reflect.DeepEqual(again, want) {
				t.Fatalf("plan aliases prior result: %+v (%s)", again, reason)
			}
		})
	}
}

func TestResolveIngressDNSNamesInvalid(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*tnv1.TailnetIngress, *tnv1.Tailnet)
		reason string
	}{
		{"absent-template-http", func(_ *tnv1.TailnetIngress, tn *tnv1.Tailnet) { tn.Spec.DNS.IngressNameTemplate = "" }, "TLSInvalidDNSName"},
		{"invalid-template", func(_ *tnv1.TailnetIngress, tn *tnv1.Tailnet) { tn.Spec.DNS.IngressNameTemplate = "{unknown}.example" }, "TLSInvalidDNSName"},
		{"ipv4-literal-base", func(_ *tnv1.TailnetIngress, tn *tnv1.Tailnet) { tn.Spec.DNS.IngressNameTemplate = "192.0.2.1" }, "TLSInvalidDNSName"},
		{"ipv4-literal-expose", func(in *tnv1.TailnetIngress, tn *tnv1.Tailnet) {
			tn.Spec.DNS.IngressNameTemplate = "{name}.0.2.1"
			in.Spec.Exposes[0].DNSLabel = "192"
		}, "TLSInvalidDNSName"},
		{"static-template-collapse", func(in *tnv1.TailnetIngress, tn *tnv1.Tailnet) {
			tn.Spec.DNS.IngressNameTemplate = "fixed.example"
			in.Spec.Exposes = append(in.Spec.Exposes, tnv1.Expose{Name: "two", Mode: "http", Port: 443, DNSLabel: "two"})
		}, "TLSInvalidDNSName"},
		{"namespace-template-collapse", func(in *tnv1.TailnetIngress, tn *tnv1.Tailnet) {
			tn.Spec.DNS.IngressNameTemplate = "{namespace}.example"
			in.Spec.Exposes = append(in.Spec.Exposes, tnv1.Expose{Name: "two", Mode: "http", Port: 443, DNSLabel: "two"})
		}, "TLSInvalidDNSName"},
		{"base-and-unlabeled", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes = append(in.Spec.Exposes, tnv1.Expose{Name: "two", Mode: "http", Port: 443, DNSLabel: in.Name})
		}, "TLSInvalidDNSName"},
		{"overlong-rendered-label", func(in *tnv1.TailnetIngress, tn *tnv1.Tailnet) {
			tn.Spec.DNS.IngressNameTemplate = "{name}-app.example"
			in.Spec.Exposes[0].DNSLabel = strings.Repeat("a", 63)
		}, "TLSInvalidDNSName"},
		{"overlong-base-label", func(_ *tnv1.TailnetIngress, tn *tnv1.Tailnet) {
			tn.Spec.DNS.IngressNameTemplate = "{name}-" + strings.Repeat("a", 63) + ".example"
		}, "TLSInvalidDNSName"},
		{"overlong-name", func(_ *tnv1.TailnetIngress, tn *tnv1.Tailnet) {
			tn.Spec.DNS.IngressNameTemplate = "{name}." + strings.Repeat(strings.Repeat("a", 63)+".", 4) + "example"
		}, "TLSInvalidDNSName"},
		{"duplicate-expose-name", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes = append(in.Spec.Exposes, tnv1.Expose{Name: "web", Port: 22})
		}, "TLSConfigurationInvalid"},
		{"invalid-expose-name", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) { in.Spec.Exposes[0].Name = "Upper" }, "TLSConfigurationInvalid"},
		{"empty-expose-name", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) { in.Spec.Exposes[0].Name = "" }, "TLSConfigurationInvalid"},
		{"duplicate-label", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes[0].DNSLabel = "one"
			in.Spec.Exposes = append(in.Spec.Exposes, tnv1.Expose{Name: "two", Mode: "http", Port: 443, DNSLabel: "one"})
		}, "TLSConfigurationInvalid"},
		{"two-unlabeled", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes = append(in.Spec.Exposes, tnv1.Expose{Name: "two", Mode: "http", Port: 443})
		}, "TLSConfigurationInvalid"},
		{"l4-http-collision", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes = append(in.Spec.Exposes, tnv1.Expose{Name: "tcp", Port: 443})
		}, "TLSConfigurationInvalid"},
		{"l4-duplicate-port", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes = []tnv1.Expose{{Name: "tcp", Port: 22}, {Name: "ssh", Mode: "l4", Port: 22}}
		}, "TLSConfigurationInvalid"},
		{"l4-label", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes[0].Mode = "l4"
			in.Spec.Exposes[0].DNSLabel = "app"
		}, "TLSConfigurationInvalid"},
		{"implicit-l4-label", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes[0].Mode = ""
			in.Spec.Exposes[0].DNSLabel = "app"
		}, "TLSConfigurationInvalid"},
		{"unknown-mode", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) { in.Spec.Exposes[0].Mode = "tcp" }, "TLSConfigurationInvalid"},
		{"http-port", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) { in.Spec.Exposes[0].Port = 80 }, "TLSConfigurationInvalid"},
		{"zero-port", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) { in.Spec.Exposes[0].Port = 0 }, "TLSConfigurationInvalid"},
		{"high-port", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) { in.Spec.Exposes[0].Port = 65536 }, "TLSConfigurationInvalid"},
		{"l4-backend-tls", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes[0].Mode = "l4"
			in.Spec.Exposes[0].Backend.TLS = &tnv1.BackendTLS{}
		}, "TLSConfigurationInvalid"},
		{"l4-timeouts", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes[0].Mode = "l4"
			in.Spec.Exposes[0].Timeouts = &tnv1.HTTPTimeouts{}
		}, "TLSConfigurationInvalid"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "apps", Namespace: "team"}, Spec: tnv1.TailnetIngressSpec{Exposes: []tnv1.Expose{{Name: "web", Mode: "http", Port: 443}}}}
			in.Status.DNSName = "valid-but-stale.example"
			tn := &tnv1.Tailnet{}
			tn.Spec.DNS.IngressNameTemplate = "{name}.example"
			tt.mutate(in, tn)
			beforeIn, beforeTN := in.DeepCopy(), tn.DeepCopy()
			for range 2 { // Reject regardless of order, without returning a partially usable plan.
				got, reason := resolveIngressDNSNames(in, tn)
				if reason != tt.reason || !reflect.DeepEqual(got, ingressDNSPlan{}) {
					t.Fatalf("plan=%+v reason=%q; want empty plan, %q", got, reason, tt.reason)
				}
				if !reflect.DeepEqual(in, beforeIn) || !reflect.DeepEqual(tn, beforeTN) {
					t.Fatal("resolver mutated caller input")
				}
				for i, j := 0, len(in.Spec.Exposes)-1; i < j; i, j = i+1, j-1 {
					in.Spec.Exposes[i], in.Spec.Exposes[j] = in.Spec.Exposes[j], in.Spec.Exposes[i]
				}
				beforeIn = in.DeepCopy()
			}
		})
	}
}

func TestResolveIngressDNSNamesBoundaries(t *testing.T) {
	tn := &tnv1.Tailnet{}
	tn.Spec.DNS.IngressNameTemplate = "{name}.example"
	in := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "apps", Namespace: "team"}}
	for _, label := range []string{"Upper", "a.b", "a_b", "a/b", "-a", "a-", " ", strings.Repeat("a", 64)} {
		in.Spec.Exposes = []tnv1.Expose{{Name: "web", Mode: "http", Port: 443, DNSLabel: label}}
		if _, reason := resolveIngressDNSNames(in, tn); reason != "TLSConfigurationInvalid" {
			t.Errorf("label %q: reason=%q", label, reason)
		}
	}
	for _, count := range []int{0, 50, 51} {
		in.Spec.Exposes = make([]tnv1.Expose, count)
		for i := range in.Spec.Exposes {
			name := fmt.Sprintf("app-%d", i)
			in.Spec.Exposes[i] = tnv1.Expose{Name: name, Mode: "http", Port: 443, DNSLabel: name}
		}
		plan, reason := resolveIngressDNSNames(in, tn)
		if count == 50 {
			if reason != "" || len(plan.exposeNames) != 50 || len(plan.certificateNames) != 51 {
				t.Errorf("count=%d: plan=%+v reason=%q", count, plan, reason)
			}
		} else if reason != "TLSConfigurationInvalid" {
			t.Errorf("count=%d: reason=%q", count, reason)
		}
	}
	if _, reason := resolveIngressDNSNames(nil, tn); reason != "TLSConfigurationInvalid" {
		t.Errorf("nil ingress: reason=%q", reason)
	}
	if _, reason := resolveIngressDNSNames(in, nil); reason != "TLSConfigurationInvalid" {
		t.Errorf("nil tailnet: reason=%q", reason)
	}
}
