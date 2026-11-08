package controller

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

const (
	// annAuthKeyID records the Headscale ID of the pre-auth key held in an authkey Secret, so the
	// key can be expired once it is superseded or its CR is gone. Older Secrets lack it.
	annAuthKeyID = "tsunaro.io/authkey-id"
	// authKeyFinalizer lets the controller expire the CR's pre-auth key on delete. Best effort:
	// it is always removed, whatever Headscale answered.
	authKeyFinalizer = "tsunaro.io/authkey"
	// authKeyExpireTimeout bounds every best-effort expire call so a dead Headscale cannot hold
	// up a rotation or a delete.
	authKeyExpireTimeout = 10 * time.Second
)

// expireAuthKey expires the pre-auth key recorded on sec, if any. Failures are logged only: the
// key still ages out at its own expiry, as it always did.
func expireAuthKey(ctx context.Context, hs *headscale.Client, sec *corev1.Secret) {
	id := sec.Annotations[annAuthKeyID]
	if id == "" || hs == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, authKeyExpireTimeout)
	defer cancel()
	if err := hs.ExpirePreAuthKey(ctx, id); err != nil {
		log.FromContext(ctx).Info("superseded pre-auth key not expired; it ages out on its own", "id", id, "err", err.Error())
	}
}

// ensureAuthKeyFinalizer adds the authkey finalizer once. The write is the only CR metadata write
// of the egress/ingress controllers and needs patch on the CR.
func ensureAuthKeyFinalizer(ctx context.Context, c client.Client, obj client.Object) error {
	if controllerutil.ContainsFinalizer(obj, authKeyFinalizer) {
		return nil
	}
	before := obj.DeepCopyObject().(client.Object)
	controllerutil.AddFinalizer(obj, authKeyFinalizer)
	return c.Patch(ctx, obj, client.MergeFrom(before))
}

// releaseAuthKey runs when a CR with the finalizer is deleted: expire the recorded key when the
// Tailnet, its working API key and the authkey Secret are still there, then drop the finalizer.
// Nothing here blocks the delete — a missing Tailnet, a Secret already collected, or a Headscale
// that is down all end with the finalizer removed. also runs with the same client, for cleanup
// that needs Headscale beyond the key (the ingress deletes its persistent node).
func releaseAuthKey(ctx context.Context, c client.Client, operatorNS string, obj client.Object, tailnetName string, observe headscale.Observer, also ...func(*headscale.Client)) error {
	if !controllerutil.ContainsFinalizer(obj, authKeyFinalizer) {
		return nil
	}
	var sec corev1.Secret
	var tn tnv1.Tailnet
	var working corev1.Secret
	if c.Get(ctx, types.NamespacedName{Namespace: obj.GetNamespace(), Name: authKeySecretName(obj.GetName())}, &sec) == nil &&
		c.Get(ctx, types.NamespacedName{Name: tailnetName}, &tn) == nil &&
		c.Get(ctx, types.NamespacedName{Namespace: operatorNS, Name: workingSecretName(tn.Name)}, &working) == nil &&
		len(working.Data[apiKeyData]) > 0 {
		apiURL := tn.Spec.APIURL
		if apiURL == "" {
			apiURL = tn.Spec.Server
		}
		hs := headscale.New(apiURL, string(working.Data[apiKeyData]), observe)
		expireAuthKey(ctx, hs, &sec)
		for _, f := range also {
			f(hs)
		}
	}
	before := obj.DeepCopyObject().(client.Object)
	controllerutil.RemoveFinalizer(obj, authKeyFinalizer)
	return c.Patch(ctx, obj, client.MergeFrom(before))
}
