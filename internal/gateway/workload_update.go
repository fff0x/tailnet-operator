package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

var (
	ErrWorkloadBlocked  = errors.New("gateway workload update: StatefulSet or receipt not verified")
	ErrWorkloadConflict = errors.New("gateway workload update: concurrent change, retry later")
)

// podRoutes returns the routes a Pod template asks the tailscale container to advertise
// (TS_ROUTES, in plan order). ok is false when the variable is absent or empty.
func podRoutes(spec corev1.PodSpec) ([]string, bool) {
	for _, c := range spec.Containers {
		if c.Name != "tailscale" {
			continue
		}
		for _, e := range c.Env {
			if e.Name == "TS_ROUTES" && e.Value != "" && e.ValueFrom == nil {
				return strings.Split(e.Value, ","), true
			}
		}
	}
	return nil, false
}

// podTemplateHash is a change detector over the fields UpdateWorkloadRevision
// writes. It covers labels and the full PodSpec; the StatefulSet metadata we
// store it on is already outside the receipt digest.
func podTemplateHash(t corev1.PodTemplateSpec) string {
	b, _ := json.Marshal(struct {
		Labels map[string]string `json:"labels"`
		Spec   corev1.PodSpec    `json:"spec"`
	}{Labels: t.Labels, Spec: t.Spec})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// UpdateWorkloadRevision writes the wanted Pod template into the receipt's
// StatefulSet. obs MUST come from a ReconcileFresh call that returned Completed;
// g is the Gateway snapshot it observed, tn supplies the login server used by
// freshPod, and routes is the sorted plan from PlanSpecRoutes. Only spec.template
// (and the template-hash annotation) change, with the resourceVersion of the
// Get as CAS, after the UID and the template-less digest recorded in the
// receipt were re-verified. Under OnDelete this never restarts the running Pod;
// that stays a manual, identity-aware action (delete Pod <name>-0).
func UpdateWorkloadRevision(ctx context.Context, c client.Client, namespace string, g *tnv1.TailnetGateway, tn *tnv1.Tailnet, obs FreshObservation, routes []string) error {
	if c == nil || g == nil || tn == nil || !obs.Completed || obs.workload.UID == "" || len(routes) == 0 {
		return ErrWorkloadBlocked
	}
	sts := &appsv1.StatefulSet{}
	if c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: g.Name}, sts) != nil || sts.DeletionTimestamp != nil || sts.ResourceVersion == "" ||
		len(sts.OwnerReferences) != 0 || sts.UID != obs.workload.UID || objectReceipt(sts) != obs.workload {
		return ErrWorkloadBlocked
	}
	// Reconstruct the wanted PodSpec from the live Gateway/Tailnet with the planned
	// routes; the state-UID label stays bound to the live template so the hash
	// matches what the writer would have produced on create. AuthKeySecretRef is
	// synthetic (never a user-facing field) and matches what ReconcileFresh set.
	renderG := g.DeepCopy()
	renderG.Spec.AuthKeySecretRef = &tnv1.GatewayAuthKeyReference{Name: tnv1.GatewayName(g.Name + "-auth"), Key: gatewayAuthKeyField}
	pod := freshPod(renderG, tn.Spec.Server, RoutePlan{Routes: append([]string(nil), routes...)}, g.Name+"-coredns")
	wanted := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: maps.Clone(sts.Spec.Template.Labels)},
		Spec:       pod,
	}
	want := podTemplateHash(wanted)
	// The annotation is the operator's own change marker on the StatefulSet.
	// Hashing the live Pod template would false-positive on K8s API server
	// defaults (dnsPolicy, terminationGracePeriodSeconds, imagePullPolicy, ...)
	// that we deliberately do not set in freshPod. Foreign actors that edit
	// spec.template bypass admin controls and are not part of the threat model
	// for this reconciler; the receipt still binds every other StatefulSet
	// field.
	if sts.Annotations[GatewayTemplateHashAnnotation] == want {
		return nil
	}
	updated := sts.DeepCopy()
	updated.Spec.Template = wanted
	if updated.Annotations == nil {
		updated.Annotations = map[string]string{}
	}
	updated.Annotations[GatewayTemplateHashAnnotation] = want
	if err := c.Update(ctx, updated); err != nil {
		if apierrors.IsConflict(err) {
			return ErrWorkloadConflict
		}
		return ErrWorkloadBlocked
	}
	return nil
}
