package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// Get transformations are static malformed snapshots, NOT simulations of API
// admission, concurrent writes or response loss. Those require envtest.
// Only Reader is exposed; accidental write calls fail the test explicitly.
type authRecordReader struct {
	client.Reader
	t      *testing.T
	mutate func(client.Object)
}

func (r authRecordReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := r.Reader.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if r.mutate != nil {
		r.mutate(obj)
	}
	return nil
}

func (r authRecordReader) Create(context.Context, client.Object, ...client.CreateOption) error {
	r.t.Fatal("recovery attempted Create")
	return nil
}
func (r authRecordReader) Update(context.Context, client.Object, ...client.UpdateOption) error {
	r.t.Fatal("recovery attempted Update")
	return nil
}
func (r authRecordReader) Patch(context.Context, client.Object, client.Patch, ...client.PatchOption) error {
	r.t.Fatal("recovery attempted Patch")
	return nil
}
func (r authRecordReader) Delete(context.Context, client.Object, ...client.DeleteOption) error {
	r.t.Fatal("recovery attempted Delete")
	return nil
}
func (r authRecordReader) DeleteAllOf(context.Context, client.Object, ...client.DeleteAllOfOption) error {
	r.t.Fatal("recovery attempted DeleteAllOf")
	return nil
}

func assertAuthRecordCanary(t *testing.T, key string, record any, err error) {
	t.Helper()
	encoded, marshalErr := json.Marshal(record)
	if marshalErr != nil {
		t.Fatal("cannot marshal record for disclosure check")
	}
	hash := sha256.Sum256([]byte(key))
	text := string(encoded)
	if err != nil {
		text += err.Error()
	}
	if strings.Contains(text, key) || strings.Contains(text, hex.EncodeToString(hash[:])) {
		t.Fatal("credential or credential hash disclosed")
	}
}

func assertAuthRecordBlocked(t *testing.T, key string, got GatewayAuthReceipt, err error) {
	t.Helper()
	assertAuthRecordCanary(t, key, got, err)
	if !errors.Is(err, ErrGatewayAuthRecord) || got != (GatewayAuthReceipt{}) {
		t.Fatal("unverified record did not fail closed")
	}
}

type authCreateResponseClient struct {
	client.Client
	mutate func(*corev1.Secret)
}

func (c authCreateResponseClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if err := c.Client.Create(ctx, obj, opts...); err != nil {
		return err
	}
	if secret, ok := obj.(*corev1.Secret); ok {
		c.mutate(secret)
	}
	return nil
}

func TestGatewayMintRecordRejectsChangedCreateResponse(t *testing.T) {
	for _, field := range []string{"key", "keyID", "expires"} {
		t.Run(field, func(t *testing.T) {
			c, g, tn, req, key, now := authStoreFixture(t)
			changed := authCreateResponseClient{Client: c, mutate: func(s *corev1.Secret) {
				switch field {
				case "key":
					s.Data[gatewayAuthKeyField] = []byte("different-key")
				case "keyID":
					s.Annotations["tsunaro.io/auth-key-id"] = "18"
				case "expires":
					s.Annotations["tsunaro.io/auth-key-expires"] = key.Expiration.Add(-time.Hour).Format(time.RFC3339)
				}
			}}
			got, err := storeGatewayMintRecord(t.Context(), changed, "operator", g, tn, req, key, func() time.Time { return now })
			assertAuthRecordBlocked(t, key.Key, got, err)
			if !apierrors.IsNotFound(c.Get(t.Context(), client.ObjectKey{Namespace: "operator", Name: g.Name + "-auth-receipt"}, &corev1.ConfigMap{})) {
				t.Fatal("changed Create response acquired durable evidence")
			}
		})
	}
}

func TestGatewayMintRecordRetainedReadOnlyRecovery(t *testing.T) {
	c, g, tn, req, key, now := authStoreFixture(t)
	created, err := storeGatewayMintRecord(t.Context(), c, "operator", g, tn, req, key, func() time.Time { return now })
	assertAuthRecordCanary(t, key.Key, created, err)
	if err != nil {
		t.Fatal("cannot store synthetic mint record")
	}
	record, secret := &corev1.ConfigMap{}, &corev1.Secret{}
	if c.Get(t.Context(), client.ObjectKey{Namespace: "operator", Name: g.Name + "-auth-receipt"}, record) != nil ||
		c.Get(t.Context(), client.ObjectKey{Namespace: "operator", Name: g.Name + "-auth"}, secret) != nil {
		t.Fatal("retained objects missing")
	}
	if record.Immutable == nil || !*record.Immutable || len(record.OwnerReferences) != 0 || len(record.Finalizers) != 0 || len(record.BinaryData) != 0 ||
		record.UID == "" || record.ResourceVersion == "" || secret.UID != created.UID || secret.ResourceVersion != created.Version ||
		created.UID == "" || created.Version == "" || created.KeyID != key.ID || !created.Expires.Equal(key.Expiration) {
		t.Fatal("retention or Create identity boundary incorrect")
	}
	gb, _ := json.Marshal(g.Spec)
	tb, _ := json.Marshal(tn.Spec)
	gh, th := sha256.Sum256(gb), sha256.Sum256(tb)
	want := map[string]string{
		"format": "1", "gatewayName": g.Name, "gatewayUID": string(g.UID), "gatewayVersion": g.ResourceVersion,
		"gatewaySpecSHA256": hex.EncodeToString(gh[:]), "tailnetName": tn.Name, "tailnetUID": string(tn.UID),
		"tailnetVersion": tn.ResourceVersion, "tailnetSpecSHA256": hex.EncodeToString(th[:]),
		"secretName": g.Name + "-auth", "secretUID": string(created.UID), "secretVersion": created.Version,
		"keyID": key.ID, "expires": key.Expiration.UTC().Format(time.RFC3339),
	}
	assertAuthRecordCanary(t, key.Key, record, nil)
	if len(record.Data) != 14 || !reflect.DeepEqual(record.Data, want) {
		t.Fatal("record is not the exact versioned credential-free scope")
	}
	reader := authRecordReader{Reader: c, t: t}
	for _, at := range []time.Time{now, key.Expiration.Add(-time.Nanosecond)} {
		recovered, err := readGatewayMintRecord(t.Context(), reader, g.Name, "operator", at)
		assertAuthRecordCanary(t, key.Key, recovered, err)
		if err != nil || recovered != created {
			t.Fatal("read-only recovery changed or rejected the original receipt")
		}
	}
	// Existing retained evidence blocks another storage attempt; it is not an
	// invitation to overwrite or automatically mint a replacement.
	got, err := storeGatewayMintRecord(t.Context(), c, "operator", g, tn, req, key, func() time.Time { return now })
	assertAuthRecordBlocked(t, key.Key, got, err)
	after := &corev1.ConfigMap{}
	if c.Get(t.Context(), client.ObjectKeyFromObject(record), after) != nil || !reflect.DeepEqual(record, after) {
		t.Fatal("retry changed the trusted record")
	}
}

func TestGatewayMintRecordRejectsMalformedEvidence(t *testing.T) {
	c, g, tn, req, key, now := authStoreFixture(t)
	if _, err := storeGatewayMintRecord(t.Context(), c, "operator", g, tn, req, key, func() time.Time { return now }); err != nil {
		t.Fatal("cannot prepare mint record")
	}
	cases := map[string]func(*corev1.ConfigMap){
		"extra field":     func(cm *corev1.ConfigMap) { cm.Data["extra"] = "unexpected" },
		"binary":          func(cm *corev1.ConfigMap) { cm.BinaryData = map[string][]byte{"extra": {1}} },
		"owner":           func(cm *corev1.ConfigMap) { cm.OwnerReferences = []metav1.OwnerReference{{UID: g.UID}} },
		"finalizer":       func(cm *corev1.ConfigMap) { cm.Finalizers = []string{"example.test/retain"} },
		"mutable":         func(cm *corev1.ConfigMap) { cm.Immutable = ptr.To(false) },
		"unset immutable": func(cm *corev1.ConfigMap) { cm.Immutable = nil },
		"deleting":        func(cm *corev1.ConfigMap) { cm.DeletionTimestamp = ptr.To(metav1.NewTime(now)) },
		"missing UID":     func(cm *corev1.ConfigMap) { cm.UID = "" },
		"missing version": func(cm *corev1.ConfigMap) { cm.ResourceVersion = "" },
		"foreign label":   func(cm *corev1.ConfigMap) { cm.Labels[gatewayUIDLabel] = "foreign" },
		"foreign manager": func(cm *corev1.ConfigMap) { cm.Labels["app.kubernetes.io/managed-by"] = "foreign" },
	}
	for field, value := range map[string]string{
		"format": "2", "gatewayName": "foreign", "gatewayUID": "foreign", "gatewayVersion": "foreign",
		"gatewaySpecSHA256": strings.Repeat("0", 64), "tailnetName": "foreign", "tailnetUID": "foreign", "tailnetVersion": "foreign",
		"tailnetSpecSHA256": strings.Repeat("0", 64), "secretName": "foreign-auth", "secretUID": "foreign", "secretVersion": "foreign",
		"keyID": "18", "expires": now.Format(time.RFC3339),
	} {
		cases["missing "+field] = func(cm *corev1.ConfigMap) { delete(cm.Data, field) }
		cases["wrong "+field] = func(cm *corev1.ConfigMap) { cm.Data[field] = value }
	}
	for _, value := range []string{"", "0", "017", "+17", "-1", "18446744073709551616", "not-numeric"} {
		cases["keyID "+value] = func(cm *corev1.ConfigMap) { cm.Data["keyID"] = value }
	}
	cases["malformed expiry"] = func(cm *corev1.ConfigMap) { cm.Data["expires"] = "not-a-time" }
	cases["noncanonical expiry"] = func(cm *corev1.ConfigMap) {
		cm.Data["expires"] = key.Expiration.In(time.FixedZone("offset", 3600)).Format(time.RFC3339)
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			reader := authRecordReader{Reader: c, t: t, mutate: func(obj client.Object) {
				if cm, ok := obj.(*corev1.ConfigMap); ok {
					mutate(cm)
					assertAuthRecordCanary(t, key.Key, cm, nil)
				}
				// Matching Secret metadata must not legitimize a noncanonical ID.
				if secret, ok := obj.(*corev1.Secret); ok && strings.HasPrefix(name, "keyID ") {
					secret.Annotations["tsunaro.io/auth-key-id"] = strings.TrimPrefix(name, "keyID ")
				}
			}}
			got, err := readGatewayMintRecord(t.Context(), reader, g.Name, "operator", now)
			assertAuthRecordBlocked(t, key.Key, got, err)
		})
	}
}

func TestGatewayMintRecordRejectsChangedScope(t *testing.T) {
	c, g, tn, req, key, now := authStoreFixture(t)
	if _, err := storeGatewayMintRecord(t.Context(), c, "operator", g, tn, req, key, func() time.Time { return now }); err != nil {
		t.Fatal("cannot prepare mint record")
	}
	// Keep RVs unchanged for spec-only mutations to exercise the full typed
	// hashes, including fields that are not in the Secret's provenance metadata.
	for _, kind := range []string{"gateway", "tailnet", "secret"} {
		for _, change := range []string{"UID", "version", "metadata", "status", "spec", "namespace"} {
			if kind == "secret" && change == "status" {
				continue
			}
			t.Run(kind+"/"+change, func(t *testing.T) {
				reader := authRecordReader{Reader: c, t: t, mutate: func(obj client.Object) {
					switch o := obj.(type) {
					case *tnv1.TailnetGateway:
						if kind != "gateway" {
							return
						}
						if change == "spec" {
							o.Spec.Hostname += "-changed"
						}
						if change == "status" {
							o.Status.ObservedGeneration++
						}
					case *tnv1.Tailnet:
						if kind != "tailnet" {
							return
						}
						if change == "spec" {
							o.Spec.APISecretRef.Name += "-changed"
						}
						if change == "status" {
							o.Status.ObservedGeneration++
						}
					case *corev1.Secret:
						if kind != "secret" {
							return
						}
						if change == "spec" {
							o.Annotations["tsunaro.io/auth-key-id"] = "18"
						}
					default:
						return
					}
					switch change {
					case "UID":
						obj.SetUID("replacement-uid") // Same bytes/RV do not excuse recreation.
					case "version":
						obj.SetResourceVersion("changed-version")
					case "metadata":
						obj.SetLabels(map[string]string{"changed": "yes"})
						obj.SetResourceVersion("metadata-only-version")
					case "status":
						obj.SetResourceVersion("status-only-version")
					case "namespace":
						obj.SetNamespace("foreign")
					}
				}}
				got, err := readGatewayMintRecord(t.Context(), reader, g.Name, "operator", now)
				assertAuthRecordBlocked(t, key.Key, got, err)
			})
		}
	}
	for _, ns := range []string{"foreign", "", "INVALID"} {
		t.Run("namespace/"+ns, func(t *testing.T) {
			got, err := readGatewayMintRecord(t.Context(), authRecordReader{Reader: c, t: t}, g.Name, ns, now)
			assertAuthRecordBlocked(t, key.Key, got, err)
		})
	}
	for _, at := range []time.Time{{}, key.Expiration, key.Expiration.Add(time.Second)} {
		got, err := readGatewayMintRecord(t.Context(), authRecordReader{Reader: c, t: t}, g.Name, "operator", at)
		assertAuthRecordBlocked(t, key.Key, got, err)
	}
}

func TestGatewayMintRecordExpiryAcrossWritesRetainsBlockedObjects(t *testing.T) {
	for _, boundary := range []int{1, 2, 3, 4} {
		t.Run([]string{"", "before Secret", "before record", "after record", "before return"}[boundary], func(t *testing.T) {
			c, g, tn, req, key, now := authStoreFixture(t)
			calls := 0
			clock := func() time.Time {
				calls++
				if calls >= boundary {
					return key.Expiration.Add(time.Second)
				}
				return now
			}
			got, err := storeGatewayMintRecord(t.Context(), c, "operator", g, tn, req, key, clock)
			assertAuthRecordBlocked(t, key.Key, got, err)
			if calls != boundary {
				t.Fatal("unexpected clock boundary")
			}
			secret, record := &corev1.Secret{}, &corev1.ConfigMap{}
			secretErr := c.Get(t.Context(), client.ObjectKey{Namespace: "operator", Name: g.Name + "-auth"}, secret)
			recordErr := c.Get(t.Context(), client.ObjectKey{Namespace: "operator", Name: g.Name + "-auth-receipt"}, record)
			if boundary == 1 {
				if !apierrors.IsNotFound(secretErr) {
					t.Fatal("expired key was persisted")
				}
			} else if secretErr != nil || string(secret.Data[gatewayAuthKeyField]) != key.Key || len(secret.OwnerReferences) != 0 {
				t.Fatal("partial retained credential was deleted or changed")
			}
			if boundary < 3 {
				if !apierrors.IsNotFound(recordErr) {
					t.Fatal("record persisted before expiry check")
				}
			} else if recordErr != nil {
				t.Fatal("late-expired record was not retained")
			}
			assertAuthRecordCanary(t, key.Key, record, err)
			got, err = readGatewayMintRecord(t.Context(), authRecordReader{Reader: c, t: t}, g.Name, "operator", key.Expiration.Add(time.Second))
			assertAuthRecordBlocked(t, key.Key, got, err)
			if boundary > 1 {
				// A partial Secret cannot be adopted on retry, even with an earlier
				// test clock; a complete record cannot be overwritten either.
				got, err = storeGatewayMintRecord(t.Context(), c, "operator", g, tn, req, key, func() time.Time { return now })
				assertAuthRecordBlocked(t, key.Key, got, err)
				after := &corev1.Secret{}
				if c.Get(t.Context(), client.ObjectKeyFromObject(secret), after) != nil || !reflect.DeepEqual(secret, after) {
					t.Fatal("retry changed the retained credential")
				}
			}
		})
	}
}
