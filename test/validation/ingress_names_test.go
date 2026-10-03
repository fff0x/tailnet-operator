//go:build integration

package validation

import (
	"fmt"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Raw unstructured values test field presence too: dnsLabel: "" is HTTP-only even though
// the typed API's string/omitempty representation cannot distinguish it from omission.
func testHTTPVirtualHostAdmission(t *testing.T, newIngress func() *unstructured.Unstructured,
	admit func(*testing.T, *unstructured.Unstructured),
	reject func(*testing.T, *unstructured.Unstructured, string),
) {
	expose := func(name, mode string, port int64, label any) any {
		e := map[string]any{"name": name, "port": port, "backend": map[string]any{"service": "app", "port": int64(8080)}}
		if mode != "" {
			e["mode"] = mode
		}
		if label != nil {
			e["dnsLabel"] = label
		}
		return e
	}
	http := func(name string, label any) any { return expose(name, "http", 443, label) }
	check := func(t *testing.T, exposes []any, reason string) {
		t.Helper()
		obj := newIngress() // metadata.name = http-api
		obj.Object["spec"].(map[string]any)["exposes"] = exposes
		if reason == "" {
			admit(t, obj)
		} else {
			reject(t, obj, reason)
		}
	}
	for _, tt := range []struct {
		name    string
		exposes []any
		reason  string
	}{
		{"multi-http", []any{http("a", "alpha"), http("b", "beta")}, ""},
		{"omitted-alone", []any{http("a", nil)}, ""},
		{"empty-alone", []any{http("a", "")}, ""},
		{"omitted-and-label", []any{http("a", nil), http("b", "beta")}, ""},
		{"empty-and-label", []any{http("a", ""), http("b", "beta")}, ""},
		{"base-label-alone", []any{http("a", "http-api")}, ""},
		{"base-label-and-label", []any{http("a", "http-api"), http("b", "beta")}, ""},
		{"multi-http-and-l4", []any{http("a", "alpha"), http("b", "beta"), expose("db", "l4", 5432, nil), expose("ssh", "", 22, nil)}, ""},
		{"distinct-l4", []any{expose("a", "", 443, nil), expose("b", "l4", 65535, nil)}, ""},
		{"duplicate-labels", []any{http("a", "alpha"), http("b", "alpha")}, "nonempty HTTP dnsLabels must be unique"},
		{"duplicate-names", []any{http("a", "alpha"), http("a", "beta")}, "expose names must be unique"},
		{"duplicate-cross-mode-names", []any{http("a", "alpha"), expose("a", "l4", 22, nil)}, "expose names must be unique"},
		{"duplicate-l4-ports", []any{expose("a", "", 22, nil), expose("b", "l4", 22, nil)}, "L4 expose ports must be unique"},
		{"http-wrong-port", []any{expose("a", "http", 80, "alpha")}, "HTTP exposes must listen on port 443"},
	} {
		t.Run(tt.name, func(t *testing.T) { check(t, tt.exposes, tt.reason) })
	}
	for _, mode := range []string{"", "l4"} {
		for _, label := range []any{"", "alpha"} {
			t.Run(fmt.Sprintf("l4-label/mode=%s/label=%s", mode, label), func(t *testing.T) {
				check(t, []any{expose("a", mode, 22, label)}, "dnsLabel requires HTTP mode")
			})
		}
		for _, reversed := range []bool{false, true} {
			t.Run(fmt.Sprintf("port-collision/mode=%s/reversed=%v", mode, reversed), func(t *testing.T) {
				es := []any{http("a", "alpha"), expose("b", mode, 443, nil)}
				if reversed {
					es[0], es[1] = es[1], es[0]
				}
				check(t, es, "L4 expose ports must be unique and must not overlap HTTP ports")
			})
		}
	}
	for i, first := range []any{nil, ""} {
		for j, second := range []any{nil, ""} {
			t.Run(fmt.Sprintf("unlabeled/%d-%d", i, j), func(t *testing.T) {
				check(t, []any{http("a", first), http("b", second)}, "at most one HTTP expose without a nonempty dnsLabel is allowed")
			})
		}
		for _, reversed := range []bool{false, true} {
			t.Run(fmt.Sprintf("base-collision/%d/reversed=%v", i, reversed), func(t *testing.T) {
				es := []any{http("a", first), http("b", "http-api")}
				if reversed {
					es[0], es[1] = es[1], es[0]
				}
				check(t, es, "an HTTP dnsLabel equal to the ingress name conflicts with an unlabeled HTTP expose")
			})
		}
	}
	for _, label := range []string{"a", "0", "a-0", strings.Repeat("a", 63)} {
		t.Run("valid-label/"+label, func(t *testing.T) { check(t, []any{http("a", label)}, "") })
	}
	for _, label := range []string{"Upper", "a.b", "a_b", "a/b", "-a", "a-", " ", strings.Repeat("a", 64)} {
		t.Run("invalid-label/"+label, func(t *testing.T) { check(t, []any{http("a", label)}, "dnsLabel") })
	}
	for _, count := range []int{50, 51} {
		t.Run(fmt.Sprintf("count/%d", count), func(t *testing.T) {
			es := make([]any, count)
			for i := range es {
				label := fmt.Sprintf("app-%d", i)
				es[i] = http(label, label)
			}
			reason := ""
			if count > 50 {
				reason = "must have at most 50 items"
			}
			check(t, es, reason)
		})
	}
}
