//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// assertNoCredentials never prints captured output or the credential on failure.
func assertNoCredentials(t *testing.T, surface, output string, credentials []string) {
	t.Helper()
	for i, credential := range credentials {
		if credential == "" {
			t.Fatal("empty redaction fixture credential")
		}
		if strings.Contains(output, credential) {
			t.Errorf("credential fixture %d leaked into %s (raw output withheld)", i, surface)
		}
	}
}

func assertCapturedLogs(t *testing.T, credentials []string) string {
	t.Helper()
	logs, overflow := operatorLogs.snapshot()
	if overflow {
		t.Fatal("operator log capture overflowed; cannot establish a redaction verdict")
	}
	assertNoCredentials(t, "operator logs", logs, credentials)
	return logs
}

// proveRealPolicyEcho checks that this is a real adversarial Headscale response, not a synthetic
// handler and not a vacuous happy-path check. Only the boolean verdict may leave this function.
func proveRealPolicyEcho(t *testing.T, ctx context.Context, hs *headscaleProcess, policy string, credentials []string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"policy": policy})
	if err != nil {
		t.Fatal("encode adversarial fixture")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, hs.url+"/api/v1/policy", bytes.NewReader(body))
	if err != nil {
		t.Fatal("construct real Headscale probe")
	}
	req.Header.Set("Authorization", "Bearer "+hs.key)
	req.Header.Set("Content-Type", "application/json")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	resp, err := (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal("real Headscale echo probe failed (details withheld)")
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode < 400 {
		t.Fatal("real Headscale did not reject adversarial policy")
	}
	for i, credential := range credentials {
		if !bytes.Contains(response, []byte(credential)) {
			t.Fatalf("real Headscale rejection did not echo credential fixture %d; fixture no longer tests upstream disclosure", i)
		}
	}
}

func TestNoSecretsInOutput(t *testing.T) {
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			if version == "v0.28.0" {
				t.Skip("unsupported capability row; real manager/key lifecycle redaction exercise requires v0.29.3")
			}
			var credentials []string
			// Registered first: include fixture cleanup logs, not only the snapshot before cleanup.
			t.Cleanup(func() { assertCapturedLogs(t, credentials) })
			ctx := testContext(t)
			hs := startHeadscale(t, ctx, version, "database", true)
			credentials = append(credentials, hs.key)
			name := createTailnet(t, ctx, hs)
			working := string(getSecret(t, ctx, name+"-apikey").Data["apiKey"])
			if working == "" || working == hs.key {
				t.Fatal("working credential was not independently minted")
			}
			credentials = append(credentials, working)
			base := `{"tagOwners":{"tag:redaction-egress":[],"tag:redaction-ingress":[],"tag:fabric":[]},"acls":[{"action":"accept","src":["*"],"dst":["192.0.2.1:443"]}]}`
			enablePolicy(t, ctx, name, base, "Apply")
			waitApplied(t, ctx, name, "192.0.2.1:443", hs)
			eg := &tnv1.TailnetEgress{
				ObjectMeta: metav1.ObjectMeta{Name: name + "-eg", Namespace: namespace},
				Spec: tnv1.TailnetEgressSpec{
					TailnetRef: tnv1.TailnetRef{Name: name}, Tag: "tag:redaction-egress",
					ConsumerNamespaces: []string{namespace},
					Targets:            []tnv1.Target{{Name: name + "-target", Address: "192.0.2.1", Port: 443}},
				},
			}
			in := &tnv1.TailnetIngress{
				ObjectMeta: metav1.ObjectMeta{Name: name + "-in", Namespace: namespace},
				Spec: tnv1.TailnetIngressSpec{
					TailnetRef: tnv1.TailnetRef{Name: name}, Tag: "tag:redaction-ingress",
					AllowFrom: []string{"autogroup:member"},
					Exposes:   []tnv1.Expose{{Name: "https", Port: 443, Backend: tnv1.Backend{Service: "fixture-backend", Port: 443}}},
				},
			}
			for _, obj := range []client.Object{eg, in} {
				if err := kube.Create(ctx, obj); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					if err := client.IgnoreNotFound(kube.Delete(cleanup, obj)); err != nil {
						t.Error("delete redaction CR failed")
					}
					// No garbage collector runs in envtest. Finalizers do not need agent pods.
					for _, child := range []client.Object{
						&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: obj.GetName(), Namespace: namespace}},
						&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: obj.GetName(), Namespace: namespace}},
						&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "ingress-" + obj.GetName(), Namespace: namespace}},
						&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "ingress-" + obj.GetName(), Namespace: namespace}},
						&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: obj.GetName() + "-authkey", Namespace: namespace}},
						&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: obj.GetName() + "-targets", Namespace: namespace}},
					} {
						if err := client.IgnoreNotFound(kube.Delete(cleanup, child)); err != nil {
							t.Error("delete redaction child failed")
						}
					}
					if obj.GetName() == eg.Name {
						if err := client.IgnoreNotFound(kube.Delete(cleanup, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name + "-target", Namespace: namespace}})); err != nil {
							t.Error("delete redaction Service failed")
						}
					}
				})
				var authKey string
				eventually(t, ctx, "operator-minted preauth key", func() bool {
					var secret corev1.Secret
					if err := kube.Get(ctx, types.NamespacedName{Namespace: namespace, Name: obj.GetName() + "-authkey"}, &secret); err != nil {
						return false
					}
					authKey = string(secret.Data["TS_AUTHKEY"])
					return authKey != ""
				})
				credentials = append(credentials, authKey)
			}
			eventually(t, ctx, "both agent CR statuses populated", func() bool {
				var currentEgress tnv1.TailnetEgress
				var currentIngress tnv1.TailnetIngress
				if kube.Get(ctx, client.ObjectKeyFromObject(eg), &currentEgress) != nil ||
					kube.Get(ctx, client.ObjectKeyFromObject(in), &currentIngress) != nil {
					return false
				}
				return currentEgress.Status.AuthKeyExpiresAt != nil && currentIngress.Status.AuthKeyExpiresAt != nil &&
					len(currentEgress.Status.Conditions) > 0 && len(currentIngress.Status.Conditions) > 0
			})
			waitApplied(t, ctx, name, "192.0.2.1:443", hs)
			// A malformed local literal must not enter logs/status through HuJSON's parser error.
			// This is separate from valid JSON rejected by Headscale below.
			malformed := `{"secret":"` + strings.Join(credentials, " ") + `\q"}`
			updateBase(t, ctx, name, malformed)
			waitCondition(t, ctx, name, "PolicyRendered", metav1.ConditionFalse, "BaseInvalid")
			localStatus, err := json.Marshal(getTailnet(t, ctx, name).Status)
			if err != nil {
				t.Fatal("encode malformed-policy status failed")
			}
			assertNoCredentials(t, "malformed-policy status", string(localStatus), credentials)
			assertCapturedLogs(t, credentials)
			// Use the actual bootstrap, working and both preauth keys in an invalid action. The
			// base ConfigMap intentionally carries this fixture; only output surfaces are checked.
			invalid := strings.Replace(base, `"action":"accept"`, `"action":"`+strings.Join(credentials, " ")+`"`, 1)
			proveRealPolicyEcho(t, ctx, hs, invalid, credentials)
			// A real external policy change drives the manager's warning Event, avoiding a
			// vacuous check of an empty Event list. The following invalid write must be rejected.
			if err := hs.client().SetPolicy(ctx, policyBase("accept", "192.0.2.99:443")); err != nil {
				t.Fatal("seed real policy drift failed")
			}
			updateBase(t, ctx, name, invalid)
			waitCondition(t, ctx, name, "PolicyApplied", metav1.ConditionFalse, "PolicyRejected")
			eventually(t, ctx, "captured rejection log", func() bool {
				return strings.Contains(assertCapturedLogs(t, credentials), "policy write rejected; previous policy stays active")
			})

			var events corev1.EventList
			eventually(t, ctx, "operator policy drift Event", func() bool {
				if err := kube.List(ctx, &events); err != nil {
					t.Fatal("list Events failed")
				}
				for _, event := range events.Items {
					if event.InvolvedObject.Name == name && event.Reason == "PolicyDriftOverwritten" {
						return true
					}
				}
				return false
			})
			checkJSON := func(surface string, value any) {
				t.Helper()
				data, err := json.Marshal(value)
				if err != nil {
					t.Fatal("encode output surface failed")
				}
				assertNoCredentials(t, surface, string(data), credentials)
			}
			checkJSON("Events", events)
			var tailnets tnv1.TailnetList
			var egresses tnv1.TailnetEgressList
			var ingresses tnv1.TailnetIngressList
			var secrets corev1.SecretList
			for _, list := range []client.ObjectList{&tailnets, &egresses, &ingresses, &secrets} {
				if err := kube.List(ctx, list); err != nil {
					t.Fatal("list output surfaces failed")
				}
			}
			for _, cr := range tailnets.Items {
				checkJSON("Tailnet status", cr.Status)
			}
			for _, cr := range egresses.Items {
				checkJSON("TailnetEgress status", cr.Status)
			}
			for _, cr := range ingresses.Items {
				checkJSON("TailnetIngress status", cr.Status)
			}
			for _, secret := range secrets.Items {
				// Secret Data is supposed to contain the credentials; metadata must not.
				checkJSON("Secret metadata", secret.ObjectMeta)
			}
			assertCapturedLogs(t, credentials)
		})
	}
}
