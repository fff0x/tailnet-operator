//go:build integration

package validation

import (
	"reflect"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Called from TestAdmission so these cases use the same disposable API server.
func testHTTPExtensionAdmission(t *testing.T, newIngress func() *unstructured.Unstructured,
	admit func(*testing.T, *unstructured.Unstructured), reject func(*testing.T, *unstructured.Unstructured, string)) {
	expose := func(o *unstructured.Unstructured) map[string]any {
		return o.Object["spec"].(map[string]any)["exposes"].([]any)[0].(map[string]any)
	}
	backendTLS := func() map[string]any {
		return map[string]any{"serverName": "app.backend.svc.cluster.local", "caConfigMapRef": map[string]any{"name": "public-ca", "key": "ca.crt"}}
	}
	withTLS := func() (*unstructured.Unstructured, map[string]any) {
		o := newIngress()
		tls := backendTLS()
		expose(o)["backend"].(map[string]any)["tls"] = tls
		return o, tls
	}
	t.Run("namespace-local-tls", func(t *testing.T) {
		o, tls := withTLS()
		expose(o)["backend"].(map[string]any)["namespace"] = "separate-backend"
		admit(t, o)
		if !reflect.DeepEqual(expose(o)["backend"].(map[string]any)["tls"], tls) {
			t.Fatal("backend TLS reference was not preserved by admission")
		}
	})
	for _, field := range []string{"request", "backendRequest"} {
		for _, value := range []string{"0s", "1ms", "30s", "600s", "1h2m3s4ms", "99999h", "99999h99999h99999h99999h"} {
			t.Run(field+"/valid/"+value, func(t *testing.T) {
				o := newIngress()
				expose(o)["timeouts"] = map[string]any{field: value}
				admit(t, o)
				if got := expose(o)["timeouts"].(map[string]any); !reflect.DeepEqual(got, map[string]any{field: value}) {
					t.Fatalf("timeout defaulting lost absence/zero distinction: %v", got)
				}
			})
		}
		for _, value := range []string{"", "0", "-1s", "+1s", "1.5s", "1us", "1d", "100000s", "1s1s1s1s1s", strings.Repeat("1", 33)} {
			t.Run(field+"/invalid/"+value, func(t *testing.T) {
				o := newIngress()
				expose(o)["timeouts"] = map[string]any{field: value}
				reject(t, o, "spec.exposes[0].timeouts."+field)
			})
		}
	}
	t.Run("empty-timeouts-preserved", func(t *testing.T) {
		o := newIngress()
		expose(o)["timeouts"] = map[string]any{}
		admit(t, o)
		if value, found := expose(o)["timeouts"]; !found || !reflect.DeepEqual(value, map[string]any{}) {
			t.Fatal("empty timeouts presence is a v2 protocol selection and must survive admission")
		}
	})
	for _, mode := range []string{"omitted", "l4"} {
		for _, setting := range []string{"tls", "timeouts"} {
			t.Run(mode+"/"+setting, func(t *testing.T) {
				o := newIngress()
				if mode == "omitted" {
					delete(expose(o), "mode")
				} else {
					expose(o)["mode"] = mode
				}
				if setting == "tls" {
					expose(o)["backend"].(map[string]any)["tls"] = backendTLS()
					reject(t, o, "backend TLS requires HTTP mode")
				} else {
					expose(o)["timeouts"] = map[string]any{}
					reject(t, o, "timeouts require HTTP mode")
				}
			})
		}
	}
	for _, value := range []string{"a", "a.example", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)} {
		o, tls := withTLS()
		tls["serverName"] = value
		admit(t, o)
	}
	for _, value := range []string{"", "10.0.0.1", "::1", "*.example", "Upper.example", "https://app", "app.", strings.Repeat("a", 64) + ".example", strings.Repeat("a", 254)} {
		t.Run("invalid-server-name/"+value, func(t *testing.T) {
			o, tls := withTLS()
			tls["serverName"] = value
			reject(t, o, "serverName")
		})
	}
	for _, field := range []string{"serverName", "caConfigMapRef"} {
		o, tls := withTLS()
		delete(tls, field)
		reject(t, o, "Required value")
	}
	for _, field := range []string{"name", "key"} {
		for _, value := range []string{"", "../ca", "bad/key", strings.Repeat("a", 254)} {
			o, tls := withTLS()
			tls["caConfigMapRef"].(map[string]any)[field] = value
			reject(t, o, "caConfigMapRef."+field)
		}
		o, tls := withTLS()
		delete(tls["caConfigMapRef"].(map[string]any), field)
		reject(t, o, "Required value")
	}
	for _, key := range []string{"root.pem", "CA_BUNDLE-1", strings.Repeat("a", 253)} {
		o, tls := withTLS()
		tls["caConfigMapRef"].(map[string]any)["key"] = key
		admit(t, o)
	}
}
