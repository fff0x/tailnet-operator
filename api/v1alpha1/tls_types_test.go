package v1alpha1

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestTLSStatusJSON(t *testing.T) {
	for _, tt := range []struct {
		name  string
		ready *bool
	}{
		{name: "l4"},
		{name: "http-not-ready", ready: new(bool)},
		{name: "http-ready", ready: func() *bool { v := true; return &v }()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			status := TailnetIngressStatus{Exposes: []ExposeStatus{{Name: "app", TLSReady: tt.ready}}}
			data, err := json.Marshal(status)
			if err != nil {
				t.Fatal(err)
			}
			var raw map[string]any
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatal(err)
			}
			got, present := raw["exposes"].([]any)[0].(map[string]any)["tlsReady"]
			if present != (tt.ready != nil) || (tt.ready != nil && got != *tt.ready) {
				t.Fatalf("tlsReady=%v present=%v: %s", got, present, data)
			}
			for _, key := range []string{"tlsSecretName", "tlsNotAfter"} {
				if _, present := raw[key]; present {
					t.Errorf("unset %s must be omitted: %s", key, data)
				}
			}
			var decoded TailnetIngressStatus
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(status, decoded) {
				t.Fatalf("roundtrip: got %#v, want %#v", decoded, status)
			}
		})
	}
}

func TestTLSJSONSources(t *testing.T) {
	for _, tt := range []struct {
		name string
		tls  *IngressTLS
		want string
	}{
		{name: "omitted", want: `{}`},
		{name: "empty-inherits", tls: &IngressTLS{}, want: `{"tls":{}}`},
		{name: "secret", tls: &IngressTLS{SecretName: "app-tls"}, want: `{"tls":{"secretName":"app-tls"}}`},
		{name: "issuer", tls: &IngressTLS{IssuerRef: &TLSIssuerReference{Name: "ca"}}, want: `{"tls":{"issuerRef":{"name":"ca"}}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			type source struct {
				TLS *IngressTLS `json:"tls,omitempty"`
			}
			data, err := json.Marshal(source{TLS: tt.tls})
			if err != nil || string(data) != tt.want {
				t.Fatalf("JSON=%s err=%v, want %s", data, err, tt.want)
			}
			var decoded source
			if err := json.Unmarshal(data, &decoded); err != nil || !reflect.DeepEqual(decoded.TLS, tt.tls) {
				t.Fatalf("roundtrip=%#v err=%v", decoded.TLS, err)
			}
		})
	}
}

func TestTLSDeepCopy(t *testing.T) {
	ready := false
	expiry := metav1.NewTime(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	ingress := &TailnetIngress{
		Spec: TailnetIngressSpec{TLS: &IngressTLS{IssuerRef: &TLSIssuerReference{
			Name: "ca", Kind: "ClusterIssuer", Group: "cert-manager.io",
		}}},
		Status: TailnetIngressStatus{
			TLSSecretName: "app-tls", TLSNotAfter: &expiry,
			Exposes: []ExposeStatus{{Name: "app", TLSReady: &ready}, {Name: "db"}},
		},
	}
	copy := ingress.DeepCopy()
	if !reflect.DeepEqual(copy, ingress) {
		t.Fatal("ingress deepcopy changed values")
	}
	if copy.Status.TLSNotAfter == ingress.Status.TLSNotAfter {
		t.Fatal("ingress deepcopy aliased certificate expiry")
	}
	copy.Spec.TLS.IssuerRef.Name = "different"
	copy.Status.TLSNotAfter.Time = expiry.Add(time.Hour)
	*copy.Status.Exposes[0].TLSReady = true
	if ingress.Spec.TLS.IssuerRef.Name != "ca" || !ingress.Status.TLSNotAfter.Equal(&expiry) || *ingress.Status.Exposes[0].TLSReady {
		t.Fatal("ingress deepcopy aliased TLS pointers")
	}
	if copy.Status.Exposes[1].TLSReady != nil {
		t.Fatal("L4 deepcopy must preserve nil TLSReady")
	}
	data, err := json.Marshal(ingress.Status)
	if err != nil {
		t.Fatal(err)
	}
	var decoded TailnetIngressStatus
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.TLSNotAfter == nil || !decoded.TLSNotAfter.Equal(ingress.Status.TLSNotAfter) {
		t.Fatalf("certificate expiry roundtrip=%v, want %v", decoded.TLSNotAfter, ingress.Status.TLSNotAfter)
	}
	// metav1.Time unmarshals in time.Local; compare the remaining fields independently.
	decoded.TLSNotAfter = ingress.Status.TLSNotAfter
	if !reflect.DeepEqual(decoded, ingress.Status) {
		t.Fatalf("TLS status roundtrip=%#v", decoded)
	}

	tailnet := &Tailnet{Spec: TailnetSpec{Defaults: TailnetDefaults{TLS: &TLSDefaults{
		IssuerRef: &TLSIssuerReference{Name: "default-ca", Kind: "Issuer", Group: "cert-manager.io"},
	}}}}
	tailnetCopy := tailnet.DeepCopy()
	if !reflect.DeepEqual(tailnetCopy, tailnet) {
		t.Fatal("tailnet deepcopy changed values")
	}
	tailnetCopy.Spec.Defaults.TLS.IssuerRef.Name = "different"
	if tailnet.Spec.Defaults.TLS.IssuerRef.Name != "default-ca" {
		t.Fatal("tailnet deepcopy aliased issuer reference")
	}
	if (&TailnetIngress{}).DeepCopy().Spec.TLS != nil || (&Tailnet{}).DeepCopy().Spec.Defaults.TLS != nil {
		t.Fatal("deepcopy must preserve omitted TLS")
	}
	if (&IngressTLS{}).DeepCopy().IssuerRef != nil || (&TLSDefaults{}).DeepCopy().IssuerRef != nil {
		t.Fatal("deepcopy must preserve omitted issuer")
	}
}
