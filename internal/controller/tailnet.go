package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
	"this-is-fine.io/tailnet-operator/internal/headscale"
	"this-is-fine.io/tailnet-operator/internal/keys"
)

const (
	annExpiresAt = "tailnet.this-is-fine.io/expires-at"
	annPrefix    = "tailnet.this-is-fine.io/prefix"
	apiKeyData   = "apiKey"
)

// TailnetReconciler owns the working API key for one control server: it mints one from the bootstrap
// key, then rotates it at half-life, always verifying the new key before expiring the old.
type TailnetReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	OperatorNamespace string
}

// workingSecretName is where the self-managed API key lives. Not in GitOps, so Flux never reverts a
// rotation.
func workingSecretName(tn string) string { return tn + "-apikey" }

// apiKeyFor resolves the current working API key for a Tailnet, minting or rotating as needed, and
// returns the key plus its expiry. It is the single entry point both reconcilers use.
func (r *TailnetReconciler) apiKeyFor(ctx context.Context, tn *tnv1.Tailnet) (string, time.Time, error) {
	apiURL := tn.Spec.APIURL
	if apiURL == "" {
		apiURL = tn.Spec.Server
	}
	lifetime := tn.Spec.APIKeyLifetime.Duration
	if lifetime == 0 {
		lifetime = 720 * time.Hour
	}
	now := time.Now()

	// Current working secret, if any.
	var cur corev1.Secret
	haveCur := false
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.OperatorNamespace, Name: workingSecretName(tn.Name)}, &cur); err == nil {
		haveCur = true
	} else if !apierrors.IsNotFound(err) {
		return "", time.Time{}, err
	}

	var (
		curKey    string
		curExpiry time.Time
		curPrefix string
	)
	if haveCur {
		curKey = string(cur.Data[apiKeyData])
		curPrefix = cur.Annotations[annPrefix]
		if s := cur.Annotations[annExpiresAt]; s != "" {
			curExpiry, _ = time.Parse(time.RFC3339, s)
		}
	}

	switch keys.Evaluate(curExpiry, lifetime, now) {
	case keys.OK:
		return curKey, curExpiry, nil

	case keys.Due:
		// Rotate with the still-valid current key, verify, then expire the old prefix.
		newKey, newExp, err := r.mintAndVerify(ctx, apiURL, curKey, lifetime, now)
		if err != nil {
			// Current key is still valid until curExpiry; keep using it and retry next reconcile.
			return curKey, curExpiry, err
		}
		if err := r.writeWorkingSecret(ctx, tn, newKey, newExp); err != nil {
			return "", time.Time{}, err
		}
		if curPrefix != "" {
			// Best-effort: a lingering old key expires on its own at worst.
			_ = headscale.New(apiURL, newKey).ExpireAPIKey(ctx, curPrefix)
		}
		return newKey, newExp, nil

	default: // Expired or none: bootstrap from the read-only start key.
		bootstrap, err := r.bootstrapKey(ctx, tn)
		if err != nil {
			return "", time.Time{}, err
		}
		newKey, newExp, err := r.mintAndVerify(ctx, apiURL, bootstrap, lifetime, now)
		if err != nil {
			return "", time.Time{}, err
		}
		if err := r.writeWorkingSecret(ctx, tn, newKey, newExp); err != nil {
			return "", time.Time{}, err
		}
		return newKey, newExp, nil
	}
}

// mintAndVerify creates a working key with authKey and confirms the NEW key works before returning
// it. This is the guard against a rotation that locks the operator out: nothing is stored or expired
// until the replacement has served a real request.
func (r *TailnetReconciler) mintAndVerify(ctx context.Context, apiURL, authKey string, lifetime time.Duration, now time.Time) (string, time.Time, error) {
	exp := now.Add(lifetime)
	newKey, err := headscale.New(apiURL, authKey).CreateAPIKey(ctx, exp)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mint api key: %w", err)
	}
	if _, err := headscale.New(apiURL, newKey).GetPolicy(ctx); err != nil {
		// The new key does not work; expire it so it does not linger, and fail.
		_ = headscale.New(apiURL, authKey).ExpireAPIKey(ctx, headscale.PrefixOf(newKey))
		return "", time.Time{}, fmt.Errorf("verify new api key: %w", err)
	}
	return newKey, exp, nil
}

func (r *TailnetReconciler) bootstrapKey(ctx context.Context, tn *tnv1.Tailnet) (string, error) {
	var s corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.OperatorNamespace, Name: tn.Spec.APISecretRef.Name}, &s); err != nil {
		return "", fmt.Errorf("read bootstrap secret %s: %w", tn.Spec.APISecretRef.Name, err)
	}
	key := tn.Spec.APISecretRef.Key
	if key == "" {
		key = "apiKey"
	}
	v := string(s.Data[key])
	if v == "" {
		return "", fmt.Errorf("bootstrap secret %s has no key %q", tn.Spec.APISecretRef.Name, key)
	}
	return v, nil
}

func (r *TailnetReconciler) writeWorkingSecret(ctx context.Context, tn *tnv1.Tailnet, key string, exp time.Time) error {
	s := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      workingSecretName(tn.Name),
			Namespace: r.OperatorNamespace,
			Labels:    map[string]string{"app.kubernetes.io/managed-by": fieldOwner},
			Annotations: map[string]string{
				annExpiresAt: exp.UTC().Format(time.RFC3339),
				annPrefix:    headscale.PrefixOf(key),
			},
		},
		Type:       corev1.SecretTypeOpaque,
		StringData: map[string]string{apiKeyData: key},
	}
	if err := controllerutil.SetControllerReference(tn, s, r.Scheme); err != nil {
		return err
	}
	return ssaApply(ctx, r.Client, s)
}

// Reconcile keeps the working API key valid and reports reachability + key validity.
func (r *TailnetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)
	var tn tnv1.Tailnet
	if err := r.Get(ctx, req.NamespacedName, &tn); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	apiURL := tn.Spec.APIURL
	if apiURL == "" {
		apiURL = tn.Spec.Server
	}

	key, exp, err := r.apiKeyFor(ctx, &tn)
	if err != nil {
		l.Error(err, "api key lifecycle")
		setCond(&tn.Status.Conditions, tn.Generation, "ApiKeyValid", metav1.ConditionFalse, "Error", err.Error())
		_ = r.Status().Update(ctx, &tn)
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	// Reachability and key validity are two questions: /health answers without a key and fails when
	// Headscale has lost its database (which it otherwise masks as 401 on every call); only a healthy
	// server can tell us whether the working key is accepted.
	ok := healthConditions(ctx, headscale.New(apiURL, key), &tn, exp)

	et := metav1.NewTime(exp)
	tn.Status.APIKeyExpiresAt = &et
	tn.Status.ObservedGeneration = tn.Generation
	apiKeyExpiresSeconds.WithLabelValues(tn.Name).Set(time.Until(exp).Seconds())

	if err := r.Status().Update(ctx, &tn); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil // another controller wrote the status; re-read and retry
		}
		return ctrl.Result{}, err
	}

	// Requeue before half-life so rotation is timely even without other events.
	lifetime := tn.Spec.APIKeyLifetime.Duration
	if lifetime == 0 {
		lifetime = 720 * time.Hour
	}
	// Capped at policyRequeue so ApiReachable/ApiKeyValid stay live instead of freezing for weeks.
	requeue := min(time.Until(exp.Add(-lifetime/2)), policyRequeue)
	if requeue < time.Minute || !ok {
		requeue = time.Minute
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

// healthConditions sets ApiReachable from GET /health and, only on a healthy server, ApiKeyValid from
// GET /api/v1/policy with the working key. Returns false when either failed so the caller re-checks
// in a minute. While the server is down the key verdict is unknown and the last one is kept.
func healthConditions(ctx context.Context, hs *headscale.Client, tn *tnv1.Tailnet, exp time.Time) bool {
	if err := hs.Health(ctx); err != nil {
		reason := "Unreachable"
		var se *headscale.StatusError
		if errors.As(err, &se) {
			reason = "Unhealthy" // answered, but reports a failed database ping
		}
		setCond(&tn.Status.Conditions, tn.Generation, "ApiReachable", metav1.ConditionFalse, reason, err.Error())
		return false
	}
	setCond(&tn.Status.Conditions, tn.Generation, "ApiReachable", metav1.ConditionTrue, "Reachable", "control API reachable")
	if _, err := hs.GetPolicy(ctx); err != nil {
		reason := "Error"
		if headscale.IsUnauthorized(err) {
			reason = "Rejected"
		}
		setCond(&tn.Status.Conditions, tn.Generation, "ApiKeyValid", metav1.ConditionFalse, reason, err.Error())
		return false
	}
	setCond(&tn.Status.Conditions, tn.Generation, "ApiKeyValid", metav1.ConditionTrue, "Valid",
		fmt.Sprintf("working key valid until %s", exp.UTC().Format(time.RFC3339)))
	return true
}

// setCond is meta.SetStatusCondition with the observed generation stamped in.
func setCond(conds *[]metav1.Condition, gen int64, t string, status metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(conds, metav1.Condition{
		Type:               t,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: gen,
	})
}

// SetupWithManager registers the Tailnet controller.
func (r *TailnetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&tnv1.Tailnet{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Owns(&corev1.Secret{}).
		Complete(r)
}
