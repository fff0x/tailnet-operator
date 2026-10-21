package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

var ErrGatewayAuthRecord = errors.New("gateway auth bootstrap: durable mint record is missing or unverified")

// mintRecordScope v2 hashes the complete typed specs as encoding/json encodes
// them: sorted map keys, original list order, and the types' omitempty/default
// semantics. Only admitted snapshots should enter this protocol. Status and
// referenced credential bytes are excluded; spec references themselves are not.
// Format 1 also pinned the exact CR resourceVersions, so a status write by the
// Tailnet or policy controller during the bootstrap blocked the mint for good;
// v2 binds UID and spec hash only (mintSnapshotsUnchanged guards the generation).
func mintRecordScope(g *tnv1.TailnetGateway, tn *tnv1.Tailnet, namespace string) (map[string]string, error) {
	if g == nil || tn == nil || g.UID == "" || tn.UID == "" || g.ResourceVersion == "" || tn.ResourceVersion == "" ||
		g.Namespace != "" || tn.Namespace != "" || g.DeletionTimestamp != nil || tn.DeletionTimestamp != nil ||
		g.Spec.Suspend == nil || *g.Spec.Suspend || g.Spec.Adoption != nil || g.Spec.AuthKeySecretRef != nil ||
		string(g.Spec.TailnetRef.Name) != tn.Name || len(validation.IsDNS1035Label(g.Name)) != 0 || len(g.Name) > 40 ||
		len(validation.IsDNS1123Label(namespace)) != 0 || tn.Spec.DNS.HostsConfigMap == g.Name+"-auth-receipt" {
		return nil, ErrGatewayAuthRecord
	}
	gb, ge := json.Marshal(g.Spec)
	tb, te := json.Marshal(tn.Spec)
	if ge != nil || te != nil {
		return nil, ErrGatewayAuthRecord
	}
	gh, th := sha256.Sum256(gb), sha256.Sum256(tb)
	return map[string]string{
		"format": "2", "gatewayName": g.Name, "gatewayUID": string(g.UID), "gatewaySpecSHA256": hex.EncodeToString(gh[:]),
		"tailnetName": tn.Name, "tailnetUID": string(tn.UID), "tailnetSpecSHA256": hex.EncodeToString(th[:]),
	}, nil
}

func mintRecordData(g *tnv1.TailnetGateway, tn *tnv1.Tailnet, namespace string, receipt GatewayAuthReceipt) (map[string]string, error) {
	data, err := mintRecordScope(g, tn, namespace)
	if err != nil || receipt.SecretName != g.Name+"-auth" || receipt.UID == "" || receipt.Version == "" || receipt.Expires.IsZero() ||
		!validGatewayKeyID(receipt.KeyID) {
		return nil, ErrGatewayAuthRecord
	}
	data["secretName"], data["secretUID"], data["secretVersion"] = receipt.SecretName, string(receipt.UID), receipt.Version
	data["keyID"], data["expires"] = receipt.KeyID, receipt.Expires.UTC().Format(time.RFC3339)
	return data, nil
}

// storeGatewayMintRecord persists fresh auth provenance, not workload
// authorization or a cross-object transaction. Its Client must perform uncached
// API reads. It never mints, adopts, patches, deletes or starts workloads.
// Only a successful Secret Create response can seed the separate immutable
// receipt. Partial writes remain retained and blocked; no compensating deletion
// or automatic remint attempts to repair an ambiguous outcome.
func storeGatewayMintRecord(ctx context.Context, c client.Client, namespace string, g *tnv1.TailnetGateway, tn *tnv1.Tailnet, req headscale.CreatePreAuthKeyRequest, issued *headscale.PreAuthKey, now func() time.Time) (GatewayAuthReceipt, error) {
	bad := func() (GatewayAuthReceipt, error) { return GatewayAuthReceipt{}, ErrGatewayAuthRecord }
	if c == nil || now == nil {
		return bad()
	}
	if _, err := mintRecordScope(g, tn, namespace); err != nil {
		return bad()
	}
	g, tn = g.DeepCopy(), tn.DeepCopy()
	name := client.ObjectKey{Namespace: namespace, Name: g.Name + "-auth-receipt"}
	// An occupied/unreadable receipt name is not an invitation to mint/store
	// another key. Create still arbitrates a race after this absence check.
	if err := c.Get(ctx, name, &corev1.ConfigMap{}); !apierrors.IsNotFound(err) {
		return bad()
	}
	started := now()
	created, err := storeGatewayMint(ctx, c, namespace, g, tn, req, issued, started)
	if err != nil {
		return bad()
	}
	secret := &corev1.Secret{}
	if c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: created.SecretName}, secret) != nil ||
		!mintSnapshotsUnchanged(ctx, c, g, tn) {
		return bad()
	}
	checked, err := ReadGatewayAuthReceipt(secret, g, tn, namespace, created.UID, now())
	if err != nil || checked != created {
		return bad()
	}
	data, err := mintRecordData(g, tn, namespace, created)
	if err != nil {
		return bad()
	}
	record := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name.Name, Namespace: namespace,
		Labels: map[string]string{gatewayUIDLabel: string(g.UID), "app.kubernetes.io/managed-by": "tailnet-operator"}},
		Immutable: ptr.To(true), Data: data}
	if c.Create(ctx, record) != nil || record.UID == "" || record.ResourceVersion == "" {
		return bad()
	}
	// A fresh clock at each boundary preserves absolute expiry; it never slides
	// the issued lifetime. Even successful persistence can finish after expiry.
	recovered, err := readGatewayMintRecord(ctx, c, g.Name, namespace, now())
	if err != nil || recovered != created {
		return bad()
	}
	current := &corev1.ConfigMap{}
	if c.Get(ctx, name, current) != nil || current.UID != record.UID || current.ResourceVersion != record.ResourceVersion ||
		!mintSnapshotsUnchanged(ctx, c, g, tn) {
		return bad()
	}
	finished := now()
	if finished.IsZero() || finished.Before(started) || !recovered.Expires.After(finished) {
		return bad()
	}
	return recovered, nil
}

// readGatewayMintRecord uses the immutable ConfigMap as the DURABLE TRUST ANCHOR.
// Its create/update/delete permissions must be as restricted as the auth Secret's.
// This is NOT a signed Headscale attestation: an actor who can replace both
// objects can forge this evidence. Self-recording the ConfigMap UID would not
// solve that. It proves neither completed postflight checks nor permission to
// start a Pod. A Secret without a record is never adopted after a crash.
// The Reader must be an explicit uncached API reader; no kubeconfig is discovered.
func readGatewayMintRecord(ctx context.Context, r client.Reader, gatewayName, namespace string, now time.Time) (GatewayAuthReceipt, error) {
	bad := func() (GatewayAuthReceipt, error) { return GatewayAuthReceipt{}, ErrGatewayAuthRecord }
	if r == nil || gatewayName == "" || now.IsZero() {
		return bad()
	}
	g, tn := &tnv1.TailnetGateway{}, &tnv1.Tailnet{}
	if r.Get(ctx, client.ObjectKey{Name: gatewayName}, g) != nil ||
		r.Get(ctx, client.ObjectKey{Name: string(g.Spec.TailnetRef.Name)}, tn) != nil {
		return bad()
	}
	scope, err := mintRecordScope(g, tn, namespace)
	if err != nil {
		return bad()
	}
	record := &corev1.ConfigMap{}
	if r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: g.Name + "-auth-receipt"}, record) != nil ||
		record.UID == "" || record.ResourceVersion == "" || record.DeletionTimestamp != nil || record.Immutable == nil || !*record.Immutable ||
		len(record.OwnerReferences) != 0 || len(record.Finalizers) != 0 || len(record.BinaryData) != 0 || len(record.Data) != len(scope)+5 ||
		record.Labels[gatewayUIDLabel] != string(g.UID) || record.Labels["app.kubernetes.io/managed-by"] != "tailnet-operator" {
		return bad()
	}
	for key, value := range scope {
		if record.Data[key] != value {
			return bad()
		}
	}
	// Never let a record select an arbitrary Secret. This name is fixed by the
	// Gateway, and its expected UID comes from durable data, not this Get.
	secret := &corev1.Secret{}
	if r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: g.Name + "-auth"}, secret) != nil {
		return bad()
	}
	receipt, err := ReadGatewayAuthReceipt(secret, g, tn, namespace, types.UID(record.Data["secretUID"]), now)
	if err != nil {
		return bad()
	}
	expected, err := mintRecordData(g, tn, namespace, receipt)
	if err != nil || !reflect.DeepEqual(record.Data, expected) || !mintSnapshotsUnchanged(ctx, r, g, tn) {
		return bad()
	}
	// Bound the read observation on both retained objects as well as the CRs.
	// A change after these checks remains possible; there is no multi-object CAS.
	liveRecord, liveSecret := &corev1.ConfigMap{}, &corev1.Secret{}
	if r.Get(ctx, client.ObjectKeyFromObject(record), liveRecord) != nil || r.Get(ctx, client.ObjectKeyFromObject(secret), liveSecret) != nil ||
		liveRecord.UID != record.UID || liveRecord.ResourceVersion != record.ResourceVersion ||
		liveSecret.UID != secret.UID || liveSecret.ResourceVersion != secret.ResourceVersion {
		return bad()
	}
	return receipt, nil
}
