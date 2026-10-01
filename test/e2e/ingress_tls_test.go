//go:build e2e

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"reflect"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
)

func ingressTLSMaterial(t *testing.T, dns string, serial int64) (map[string][]byte, time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate private fixture key")
	}
	expires := time.Now().UTC().Truncate(time.Second).Add(time.Duration(serial+1) * time.Hour)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{dns},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: expires,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal("generate public fixture leaf")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("encode private fixture key")
	}
	return map[string][]byte{
		corev1.TLSCertKey:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, expires
}

// Real API/manager/Headscale, but no kubelet, agent, garbage collector or cert-manager.
// This verifies optional-API absence, Secret watches and source-to-workload wiring, not serving TLS.
func TestIngressTLSExternalSecretAndMissingManager(t *testing.T) {
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			if version == "v0.28.0" {
				t.Skip("unsupported lifecycle row; covered by TestPreflight")
			}
			ctx := testContext(t)
			hs := startHeadscale(t, ctx, version, "database", true)
			name := createTailnet(t, ctx, hs)
			if err := hs.client().SetPolicy(ctx, `{"tagOwners":{"tag:tls-fixture":[]}}`); err != nil {
				t.Fatal("set isolated ingress tag policy")
			}
			in := &tnv1.TailnetIngress{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec: tnv1.TailnetIngressSpec{
					TailnetRef: tnv1.TailnetRef{Name: name}, Tag: "tag:tls-fixture", AllowFrom: []string{"autogroup:member"},
					TLS: &tnv1.IngressTLS{IssuerRef: &tnv1.TLSIssuerReference{Name: "absent-issuer"}},
					Exposes: []tnv1.Expose{{Name: "web", Mode: "http", Port: 443,
						Backend: tnv1.Backend{Service: "unused", Namespace: "backend-only", Port: 8080}}},
				},
			}
			key := client.ObjectKeyFromObject(in)
			secretKey := types.NamespacedName{Name: name + "-external", Namespace: namespace}
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				for _, obj := range []client.Object{
					in,
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name + "-authkey", Namespace: namespace}},
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretKey.Name, Namespace: namespace}},
					&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name + "-targets", Namespace: namespace}},
					&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}},
					&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}},
				} {
					if err := client.IgnoreNotFound(kube.Delete(cleanup, obj)); err != nil {
						t.Error("delete isolated ingress fixture object")
					}
				}
			})
			if err := kube.Create(ctx, in); err != nil {
				t.Fatal(err)
			}
			waitTLS := func(reason string, expires *time.Time, limit time.Duration) {
				t.Helper()
				deadline, cancel := context.WithTimeout(ctx, limit)
				defer cancel()
				eventually(t, deadline, "bounded TLS verdict "+reason, func() bool {
					if err := kube.Get(deadline, key, in); err != nil {
						t.Fatal("read ingress fixture")
					}
					cond := meta.FindStatusCondition(in.Status.Conditions, "TLSReady")
					return cond != nil && cond.Status == metav1.ConditionFalse && cond.Reason == reason &&
						cond.ObservedGeneration == in.Generation && (expires == nil ||
						(in.Status.TLSNotAfter != nil && in.Status.TLSNotAfter.Time.Equal(*expires)))
				})
			}
			waitTLS("CertManagerMissing", nil, 45*time.Second)
			var pending corev1.ConfigMap
			if err := kube.Get(ctx, types.NamespacedName{Name: name + "-targets", Namespace: namespace}, &pending); err != nil {
				t.Fatal("read pending HTTP configuration")
			}
			var envelope struct {
				Version int               `json:"version"`
				Targets []json.RawMessage `json:"targets"`
			}
			if json.Unmarshal([]byte(pending.Data["targets.json"]), &envelope) != nil || envelope.Version != 1 || len(envelope.Targets) != 0 {
				t.Fatal("missing cert-manager enabled an HTTP/plaintext target")
			}

			material, expiry := ingressTLSMaterial(t, name+".e2e.invalid", 1)
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretKey.Name, Namespace: namespace}, Type: corev1.SecretTypeTLS, Data: material}
			if err := kube.Create(ctx, secret); err != nil {
				t.Fatal("create isolated external TLS Secret")
			}
			if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				if err := kube.Get(ctx, key, in); err != nil {
					return err
				}
				in.Spec.TLS = &tnv1.IngressTLS{SecretName: secretKey.Name}
				return kube.Update(ctx, in)
			}); err != nil {
				t.Fatal("select external TLS source")
			}
			waitTLS("TLSProbeFailed", &expiry, 15*time.Second) // no agent Pod exists in envtest
			var beforeCM corev1.ConfigMap
			var beforeDep appsv1.Deployment
			if kube.Get(ctx, types.NamespacedName{Name: name + "-targets", Namespace: namespace}, &beforeCM) != nil || kube.Get(ctx, key, &beforeDep) != nil {
				t.Fatal("read external TLS workloads")
			}
			if json.Unmarshal([]byte(beforeCM.Data["targets.json"]), &envelope) != nil || len(envelope.Targets) != 1 {
				t.Fatal("external Secret did not enable HTTP source configuration")
			}
			if len(secret.OwnerReferences) != 0 {
				t.Fatal("fixture Secret must be externally owned")
			}

			updateSecret := func(data map[string][]byte) {
				t.Helper()
				if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
					if err := kube.Get(ctx, secretKey, secret); err != nil {
						return err
					}
					secret.Data = data
					return kube.Update(ctx, secret)
				}); err != nil {
					t.Fatal("update isolated TLS Secret")
				}
			}
			rotated, nextExpiry := ingressTLSMaterial(t, name+".e2e.invalid", 2)
			updateSecret(rotated)
			// Eight seconds is below the regular30s reconcile interval: this tests the external
			// Secret watch, not eventual polling. All assertions use the uncached API client.
			waitTLS("TLSProbeFailed", &nextExpiry, 8*time.Second)
			var afterCM corev1.ConfigMap
			var afterDep appsv1.Deployment
			if kube.Get(ctx, types.NamespacedName{Name: name + "-targets", Namespace: namespace}, &afterCM) != nil || kube.Get(ctx, key, &afterDep) != nil {
				t.Fatal("read rotated TLS workloads")
			}
			if !reflect.DeepEqual(beforeCM.Data, afterCM.Data) || !reflect.DeepEqual(beforeDep.Spec.Template, afterDep.Spec.Template) || beforeDep.Generation != afterDep.Generation {
				t.Fatal("ordinary certificate rotation changed targets or Pod template")
			}
			updateSecret(map[string][]byte{corev1.TLSCertKey: []byte("invalid fixture certificate"), corev1.TLSPrivateKeyKey: rotated[corev1.TLSPrivateKeyKey]})
			waitTLS("TLSCertificateInvalid", nil, 8*time.Second)
			if in.Status.TLSNotAfter != nil {
				t.Fatal("invalid material retained a public expiry verdict")
			}
			var invalidCM corev1.ConfigMap
			if kube.Get(ctx, types.NamespacedName{Name: name + "-targets", Namespace: namespace}, &invalidCM) != nil ||
				json.Unmarshal([]byte(invalidCM.Data["targets.json"]), &envelope) != nil || len(envelope.Targets) != 0 {
				t.Fatal("invalid Secret failed to withdraw HTTP")
			}
			updateSecret(rotated)
			waitTLS("TLSProbeFailed", &nextExpiry, 8*time.Second)
		})
	}
}
