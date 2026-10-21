//go:build integration

package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

// The same explicit experiment boundary as the DNS CAS tests: only Gateway
// Get snapshots become active in memory; stored fixtures remain suspended.
// Hooks inject response loss/races around REAL writes, never invent UIDs/RVs.
type authRecordAPIClient struct {
	client.Client
	beforeCreate                 func(client.Object)
	afterCreate                  func(client.Object) error
	dryRunSecret                 bool
	secretCreates, recordCreates int
}

func (c *authRecordAPIClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := c.Client.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if g, ok := obj.(*tnv1.TailnetGateway); ok {
		g.Spec.Suspend = ptr.To(false)
	}
	return nil
}

func (c *authRecordAPIClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if _, ok := obj.(*corev1.Secret); ok {
		c.secretCreates++
		if c.dryRunSecret {
			opts = append(opts, client.DryRunAll)
		}
	} else {
		c.recordCreates++
	}
	if c.beforeCreate != nil {
		c.beforeCreate(obj)
	}
	if err := c.Client.Create(ctx, obj, opts...); err != nil {
		return err
	}
	if c.afterCreate != nil {
		return c.afterCreate(obj)
	}
	return nil
}

func TestGatewayAuthRecordAPI(t *testing.T) {
	for _, variable := range os.Environ() {
		name, _, _ := strings.Cut(variable, "=")
		if strings.HasPrefix(name, "ETCD_") || strings.HasPrefix(name, "TEST_ASSET_") {
			if os.Unsetenv(name) != nil {
				t.Fatal("clear envtest override")
			}
		}
	}
	assets := os.Getenv("KUBEBUILDER_ASSETS")
	if !filepath.IsAbs(assets) {
		t.Fatal("explicit absolute envtest assets required")
	}
	env := &envtest.Environment{UseExistingCluster: ptr.To(false), BinaryAssetsDirectory: assets,
		CRDDirectoryPaths: []string{filepath.Join("..", "..", "deploy", "crds")}, ErrorIfCRDPathMissing: true,
		ControlPlaneStartTimeout: 30 * time.Second, ControlPlaneStopTimeout: 10 * time.Second}
	t.Cleanup(func() {
		if env.Stop() != nil {
			t.Error("stop isolated auth API server")
		}
	})
	cfg, err := env.Start()
	if err != nil {
		t.Fatal("start isolated auth API server")
	}
	scheme := runtime.NewScheme()
	if corev1.AddToScheme(scheme) != nil || tnv1.AddToScheme(scheme) != nil {
		t.Fatal("register auth API types")
	}
	newClient := func() client.Client {
		c, err := client.New(cfg, client.Options{Scheme: scheme})
		if err != nil {
			t.Fatal("create isolated auth API client")
		}
		return c
	}
	admin := newClient()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	must := func(t *testing.T, err error) {
		t.Helper()
		if err != nil {
			t.Fatal("auth API fixture operation failed")
		}
	}
	fixture := func(t *testing.T, name string) (*tnv1.TailnetGateway, *tnv1.Tailnet, headscale.CreatePreAuthKeyRequest, *headscale.PreAuthKey, time.Time) {
		t.Helper()
		in := freshFixture()
		g, tn := in.Gateway, in.Tailnet
		g.Name, g.UID, g.ResourceVersion = name, "", ""
		g.Spec.AuthKeySecretRef = nil
		g.Spec.TailnetRef.Name = tnv1.GatewayName(name)
		tn.Name = name
		tn.Spec.APISecretRef = tnv1.SecretKeyRef{Name: "unused-bootstrap"}
		tn.Spec.APIKeyLifetime = metav1.Duration{Duration: 24 * time.Hour}
		must(t, admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}))
		must(t, admin.Create(ctx, tn))
		must(t, admin.Create(ctx, g))
		g.Spec.Suspend = ptr.To(false) // only the in-memory test observation
		now := time.Now().UTC().Truncate(time.Second)
		req, err := PlanGatewayMint(g, now)
		must(t, err)
		key := &headscale.PreAuthKey{ID: "17", Key: "synthetic-private-key-do-not-print", Reusable: true, ACLTags: req.ACLTags, Expiration: req.Expiration}
		return g, tn, req, key, now
	}
	secretKey := func(g *tnv1.TailnetGateway) client.ObjectKey {
		return client.ObjectKey{Namespace: g.Name, Name: g.Name + "-auth"}
	}
	recordKey := func(g *tnv1.TailnetGateway) client.ObjectKey {
		return client.ObjectKey{Namespace: g.Name, Name: g.Name + "-auth-receipt"}
	}
	readSecret := func(t *testing.T, g *tnv1.TailnetGateway) *corev1.Secret {
		t.Helper()
		s := &corev1.Secret{}
		must(t, admin.Get(ctx, secretKey(g), s))
		return s
	}
	readRecord := func(t *testing.T, g *tnv1.TailnetGateway) *corev1.ConfigMap {
		t.Helper()
		cm := &corev1.ConfigMap{}
		must(t, admin.Get(ctx, recordKey(g), cm))
		return cm
	}
	assertBlocked := func(t *testing.T, got GatewayAuthReceipt, err error) {
		t.Helper()
		if !errors.Is(err, ErrGatewayAuthRecord) || got != (GatewayAuthReceipt{}) || strings.Contains(err.Error(), "synthetic-private") {
			t.Fatal("failed persistence returned evidence or leaked credentials")
		}
	}
	changeGateway := func(t *testing.T, g *tnv1.TailnetGateway) {
		t.Helper()
		// A spec move: label/status-only moves no longer block a mint (format 2).
		live := &tnv1.TailnetGateway{}
		must(t, admin.Get(ctx, client.ObjectKeyFromObject(g), live))
		live.Spec.Routes.LAN = append(live.Spec.Routes.LAN, "10.99.0.0/16")
		must(t, admin.Update(ctx, live))
	}

	t.Run("create-and-recover-with-new-client", func(t *testing.T) {
		g, tn, req, key, now := fixture(t, "auth-persist")
		c := &authRecordAPIClient{Client: newClient()}
		created, err := storeGatewayMintRecord(ctx, c, g.Name, g, tn, req, key, func() time.Time { return now })
		must(t, err)
		secret, record := readSecret(t, g), readRecord(t, g)
		if created.UID == "" || created.UID != secret.UID || created.Version != secret.ResourceVersion || record.UID == "" ||
			record.Data["secretUID"] != string(created.UID) || record.Immutable == nil || !*record.Immutable || len(record.OwnerReferences) != 0 || c.secretCreates != 1 || c.recordCreates != 1 {
			t.Fatal("real Create identities not retained")
		}
		// Neither helper/client memory nor the Create response is reused here.
		restarted := &authRecordAPIClient{Client: newClient()}
		recovered, err := readGatewayMintRecord(ctx, restarted, g.Name, g.Name, now.Add(time.Minute))
		must(t, err)
		if recovered != created || restarted.secretCreates != 0 || restarted.recordCreates != 0 || !reflect.DeepEqual(secret, readSecret(t, g)) || !reflect.DeepEqual(record, readRecord(t, g)) {
			t.Fatal("recovery changed retained artifacts")
		}
		// API immutability is real, not a fake-client assertion.
		badSecret, badRecord := secret.DeepCopy(), record.DeepCopy()
		badSecret.Data[gatewayAuthKeyField] = []byte("replacement")
		badRecord.Data["secretUID"] = "replacement"
		if !apierrors.IsInvalid(admin.Update(ctx, badSecret)) || !apierrors.IsInvalid(admin.Update(ctx, badRecord)) {
			t.Fatal("API allowed immutable payload mutation")
		}
		got, err := storeGatewayMintRecord(ctx, c, g.Name, g, tn, req, key, func() time.Time { return now })
		assertBlocked(t, got, err)
		if c.secretCreates != 1 || c.recordCreates != 1 {
			t.Fatal("occupied receipt caused another create")
		}
		must(t, admin.Delete(ctx, record, client.Preconditions{UID: &record.UID}))
		got, err = readGatewayMintRecord(ctx, restarted, g.Name, g.Name, now)
		assertBlocked(t, got, err)
		got, err = storeGatewayMintRecord(ctx, c, g.Name, g, tn, req, key, func() time.Time { return now })
		assertBlocked(t, got, err)
		if !apierrors.IsNotFound(admin.Get(ctx, recordKey(g), &corev1.ConfigMap{})) || !reflect.DeepEqual(secret, readSecret(t, g)) {
			t.Fatal("missing receipt was reconstructed from retained Secret")
		}
	})

	t.Run("activation-admitted-but-stored-suspension-blocks", func(t *testing.T) {
		g, tn, req, key, now := fixture(t, "auth-suspended")
		active := g.DeepCopy()
		must(t, admin.Update(ctx, active, client.DryRunAll))
		if active.Spec.Suspend == nil || *active.Spec.Suspend {
			t.Fatal("real admission did not preserve explicit activation")
		}
		stored := &tnv1.TailnetGateway{}
		must(t, admin.Get(ctx, client.ObjectKeyFromObject(g), stored))
		if stored.Spec.Suspend == nil || !*stored.Spec.Suspend {
			t.Fatal("dry-run activation changed stored suspension")
		}
		// Even forged active input cannot pass the ordinary client's live Get.
		got, err := storeGatewayMintRecord(ctx, admin, g.Name, g, tn, req, key, func() time.Time { return now })
		assertBlocked(t, got, err)
		if !apierrors.IsNotFound(admin.Get(ctx, secretKey(g), &corev1.Secret{})) {
			t.Fatal("suspended storage created a Secret")
		}
	})

	for _, artifact := range []string{"secret", "record"} {
		t.Run("lost-"+artifact+"-create-response", func(t *testing.T) {
			g, tn, req, key, now := fixture(t, "auth-lost-"+artifact)
			c := &authRecordAPIClient{Client: newClient()}
			c.afterCreate = func(obj client.Object) error {
				_, secret := obj.(*corev1.Secret)
				if secret == (artifact == "secret") {
					return errors.New(key.Key)
				}
				return nil
			}
			got, err := storeGatewayMintRecord(ctx, c, g.Name, g, tn, req, key, func() time.Time { return now })
			assertBlocked(t, got, err)
			secret := readSecret(t, g) // persisted, but its response was lost
			restarted := &authRecordAPIClient{Client: newClient()}
			got, err = readGatewayMintRecord(ctx, restarted, g.Name, g.Name, now)
			if artifact == "secret" {
				assertBlocked(t, got, err)
				if c.recordCreates != 0 || !apierrors.IsNotFound(admin.Get(ctx, recordKey(g), &corev1.ConfigMap{})) {
					t.Fatal("ambiguous Secret Create acquired a UID by Get")
				}
			} else {
				must(t, err)
				if got.UID != secret.UID || got.Version != secret.ResourceVersion {
					t.Fatal("persisted trusted receipt did not survive response loss")
				}
			}
		})
	}

	for _, field := range []string{"uid", "version"} {
		t.Run("missing-secret-create-"+field, func(t *testing.T) {
			g, tn, req, key, now := fixture(t, "auth-no-"+field)
			c := &authRecordAPIClient{Client: newClient()}
			c.afterCreate = func(obj client.Object) error {
				if _, ok := obj.(*corev1.Secret); ok {
					if field == "uid" {
						obj.SetUID("")
					} else {
						obj.SetResourceVersion("")
					}
				}
				return nil
			}
			got, err := storeGatewayMintRecord(ctx, c, g.Name, g, tn, req, key, func() time.Time { return now })
			assertBlocked(t, got, err)
			if c.recordCreates != 0 {
				t.Fatal("missing Create evidence recovered through a Get")
			}
		})
	}

	for _, field := range []string{"key", "key-id", "id-canary", "expires"} {
		t.Run("create-mutation-"+field, func(t *testing.T) {
			g, tn, req, key, now := fixture(t, "auth-mutated-"+field)
			c := &authRecordAPIClient{Client: newClient()}
			c.beforeCreate = func(obj client.Object) {
				s, ok := obj.(*corev1.Secret)
				if !ok {
					return
				}
				switch field {
				case "key":
					s.Data[gatewayAuthKeyField] = []byte("different-private-key")
				case "key-id":
					s.Annotations["tsunaro.io/auth-key-id"] = "18"
				case "id-canary":
					s.Annotations["tsunaro.io/auth-key-id"] = key.Key
				case "expires":
					s.Annotations["tsunaro.io/auth-key-expires"] = key.Expiration.Add(-time.Hour).Format(time.RFC3339)
				}
			}
			got, err := storeGatewayMintRecord(ctx, c, g.Name, g, tn, req, key, func() time.Time { return now })
			assertBlocked(t, got, err)
			_ = readSecret(t, g) // persisted mutation cannot seed a trusted receipt
			if c.recordCreates != 0 {
				t.Fatal("Create-time mutation authorized a durable record")
			}
			got, err = readGatewayMintRecord(ctx, &authRecordAPIClient{Client: newClient()}, g.Name, g.Name, now)
			assertBlocked(t, got, err)
		})
	}

	t.Run("dry-run-is-not-persistence", func(t *testing.T) {
		g, tn, req, key, now := fixture(t, "auth-dry-run")
		c := &authRecordAPIClient{Client: newClient(), dryRunSecret: true}
		got, err := storeGatewayMintRecord(ctx, c, g.Name, g, tn, req, key, func() time.Time { return now })
		assertBlocked(t, got, err)
		if c.recordCreates != 0 || !apierrors.IsNotFound(admin.Get(ctx, secretKey(g), &corev1.Secret{})) {
			t.Fatal("dry-run response authorized persistence")
		}
	})

	for _, subject := range []string{"g", "tn", "delete-g"} {
		for _, boundary := range []string{"before-secret", "after-secret", "before-record", "after-record"} {
			t.Run("scope-change-"+subject+"-"+boundary, func(t *testing.T) {
				g, tn, req, key, now := fixture(t, "auth-"+subject+"-"+boundary)
				c := &authRecordAPIClient{Client: newClient()}
				mutate := func(obj client.Object) {
					_, secret := obj.(*corev1.Secret)
					if secret == strings.HasSuffix(boundary, "secret") {
						switch subject {
						case "g":
							changeGateway(t, g)
						case "delete-g":
							must(t, admin.Delete(ctx, g, client.Preconditions{UID: &g.UID}))
						case "tn":
							live := &tnv1.Tailnet{}
							must(t, admin.Get(ctx, client.ObjectKeyFromObject(tn), live))
							live.Spec.Server = "https://changed.example"
							must(t, admin.Update(ctx, live))
						}
					}
				}
				if strings.HasPrefix(boundary, "before") {
					c.beforeCreate = mutate
				} else {
					c.afterCreate = func(obj client.Object) error { mutate(obj); return nil }
				}
				got, err := storeGatewayMintRecord(ctx, c, g.Name, g, tn, req, key, func() time.Time { return now })
				assertBlocked(t, got, err)
				_ = readSecret(t, g) // partial artifact retained, never compensating deletion
				if strings.HasSuffix(boundary, "secret") && c.recordCreates != 0 {
					t.Fatal("changed CR scope authorized a receipt")
				}
				got, err = readGatewayMintRecord(ctx, &authRecordAPIClient{Client: newClient()}, g.Name, g.Name, now)
				assertBlocked(t, got, err)
			})
		}

	}
	t.Run("concurrent-receipt-name-is-not-adopted", func(t *testing.T) {
		g, tn, req, key, now := fixture(t, "auth-name-race")
		c := &authRecordAPIClient{Client: newClient()}
		foreign := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: recordKey(g).Name, Namespace: g.Name}, Data: map[string]string{"foreign": "preserve"}}
		c.beforeCreate = func(obj client.Object) {
			if _, ok := obj.(*corev1.ConfigMap); ok {
				must(t, admin.Create(ctx, foreign))
			}
		}
		got, err := storeGatewayMintRecord(ctx, c, g.Name, g, tn, req, key, func() time.Time { return now })
		assertBlocked(t, got, err)
		if !reflect.DeepEqual(foreign, readRecord(t, g)) {
			t.Fatal("concurrent foreign receipt overwritten")
		}
		_ = readSecret(t, g)
	})

	t.Run("two-writers-have-one-winner", func(t *testing.T) {
		g, tn, req, key, now := fixture(t, "auth-two-writers")
		raceCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		entered := make(chan struct{}, 2)
		release := make(chan struct{})
		type result struct {
			receipt GatewayAuthReceipt
			err     error
			issued  string
		}
		results := make(chan result, 2)
		for _, id := range []string{"17", "18"} {
			c := &authRecordAPIClient{Client: newClient()}
			go func() {
				c.beforeCreate = func(obj client.Object) {
					if _, ok := obj.(*corev1.Secret); !ok {
						return
					}
					entered <- struct{}{}
					select {
					case <-release:
					case <-raceCtx.Done():
					}
				}
				issued := *key
				issued.ID, issued.Key = id, key.Key+id
				got, err := storeGatewayMintRecord(raceCtx, c, g.Name, g, tn, req, &issued, func() time.Time { return now })
				results <- result{got, err, issued.Key}
			}()
		}
		for range 2 {
			select {
			case <-entered:
			case <-raceCtx.Done():
				t.Fatal("writers did not reach bounded Create barrier")
			}
		}
		close(release)
		var winner result
		wins := 0
		for range 2 {
			select {
			case got := <-results:
				if got.err == nil {
					wins++
					winner = got
				} else {
					assertBlocked(t, got.receipt, got.err)
				}
			case <-raceCtx.Done():
				t.Fatal("writers did not finish")
			}
		}
		if wins != 1 {
			t.Fatal("exclusive Create did not elect exactly one winner")
		}
		secret := readSecret(t, g)
		if winner.receipt.UID != secret.UID || string(secret.Data[gatewayAuthKeyField]) != winner.issued || readRecord(t, g).Data["keyID"] != winner.receipt.KeyID {
			t.Fatal("durable evidence bound to losing writer")
		}
	})

	t.Run("secret-recreation-between-writes", func(t *testing.T) {
		g, tn, req, key, now := fixture(t, "auth-recreated")
		c := &authRecordAPIClient{Client: newClient()}
		c.beforeCreate = func(obj client.Object) {
			if _, ok := obj.(*corev1.ConfigMap); !ok {
				return
			}
			secret := readSecret(t, g)
			oldUID := secret.UID
			must(t, admin.Delete(ctx, secret, client.Preconditions{UID: &oldUID}))
			secret.UID, secret.ResourceVersion = "", ""
			secret.CreationTimestamp = metav1.Time{}
			must(t, admin.Create(ctx, secret))
			if secret.UID == oldUID {
				t.Fatal("API did not assign a new Secret identity")
			}
		}
		got, err := storeGatewayMintRecord(ctx, c, g.Name, g, tn, req, key, func() time.Time { return now })
		assertBlocked(t, got, err)
		if readRecord(t, g).Data["secretUID"] == string(readSecret(t, g).UID) {
			t.Fatal("Create-time UID rebound to replacement Secret")
		}
		got, err = readGatewayMintRecord(ctx, &authRecordAPIClient{Client: newClient()}, g.Name, g.Name, now)
		assertBlocked(t, got, err)
	})
}
