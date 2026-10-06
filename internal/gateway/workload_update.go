package gateway

import (
	"context"
	"errors"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

var (
	ErrWorkloadBlocked  = errors.New("gateway workload update: StatefulSet or receipt not verified")
	ErrWorkloadConflict = errors.New("gateway workload update: concurrent change, retry later")
)

// freshImages is the image the live spec wants per container name. Images are
// the only part of the Pod template that follows the spec; every other template
// field stays bound by the completion receipt (see objectReceipt).
func freshImages(g *tnv1.TailnetGateway) map[string]string {
	return map[string]string{"kernel-preflight": string(g.Spec.Image), "tailscale": string(g.Spec.Image), "coredns": string(g.Spec.DNS.Image)}
}

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

// podImagesCurrent reports whether every container we name already runs the
// wanted image. Containers added by anyone else (admission, fixtures) are ignored.
func podImagesCurrent(spec corev1.PodSpec, want map[string]string) bool {
	for _, list := range [][]corev1.Container{spec.InitContainers, spec.Containers} {
		for _, c := range list {
			if image, ok := want[c.Name]; ok && c.Image != image {
				return false
			}
		}
	}
	return true
}

// UpdateWorkloadRevision writes the wanted container images and the planned routes
// (TS_ROUTES of the tailscale container) into the receipt's StatefulSet. obs MUST come
// from a ReconcileFresh call that returned Completed; g is the Gateway snapshot it
// observed and routes the sorted plan from PlanSpecRoutes. Only those fields of
// spec.template change, with the resourceVersion of the Get as CAS, after the
// UID and the image-less digest recorded in the receipt were re-verified. Under
// OnDelete this never restarts the running Pod; that stays a manual,
// identity-aware action (delete Pod <name>-0).
func UpdateWorkloadRevision(ctx context.Context, c client.Client, namespace string, g *tnv1.TailnetGateway, obs FreshObservation, routes []string) error {
	if c == nil || g == nil || !obs.Completed || obs.workload.UID == "" || len(routes) == 0 {
		return ErrWorkloadBlocked
	}
	sts := &appsv1.StatefulSet{}
	if c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: g.Name}, sts) != nil || sts.DeletionTimestamp != nil || sts.ResourceVersion == "" ||
		len(sts.OwnerReferences) != 0 || sts.UID != obs.workload.UID || objectReceipt(sts) != obs.workload {
		return ErrWorkloadBlocked
	}
	want, updated := freshImages(g), sts.DeepCopy()
	for _, list := range [][]corev1.Container{updated.Spec.Template.Spec.InitContainers, updated.Spec.Template.Spec.Containers} {
		for i := range list {
			if image, ok := want[list[i].Name]; ok {
				list[i].Image = image
			}
		}
	}
	wantRoutes := strings.Join(routes, ",")
	for i := range updated.Spec.Template.Spec.Containers {
		c := &updated.Spec.Template.Spec.Containers[i]
		for j := range c.Env {
			if c.Name == "tailscale" && c.Env[j].Name == "TS_ROUTES" {
				c.Env[j].Value = wantRoutes
			}
		}
	}
	if current, _ := podRoutes(sts.Spec.Template.Spec); podImagesCurrent(sts.Spec.Template.Spec, want) && strings.Join(current, ",") == wantRoutes {
		return nil
	}
	if err := c.Update(ctx, updated); err != nil {
		if apierrors.IsConflict(err) {
			return ErrWorkloadConflict
		}
		return ErrWorkloadBlocked
	}
	return nil
}
