//go:build e2e_kind

package e2ekind

import (
	"context"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tsunaro.io/tailnet-operator/test/internal/kindfixture"
)

func TestPodNetworkGate(t *testing.T) {
	if os.Getenv("E2E_KIND_HTTP_NETWORK_GATE") == "" {
		t.Skip("requires owned layered-isolation runner")
	}
	f := ownedFixture(t)
	if os.Getenv("E2E_KIND_HTTP_NETWORK_GATE") != "passed" {
		t.Fatal("network gate missing")
	}
	image := os.Getenv("E2E_KIND_FIXTURE_IMAGE")
	if image != "localhost/tn-source-netprobe:"+f.cluster {
		t.Fatal("unexpected init fixture image")
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	if f.kube.Create(t.Context(), ns) != nil {
		t.Fatal("init fixture namespace creation failed")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if err := f.kube.Delete(ctx, ns, client.Preconditions{UID: &ns.UID}); err != nil && !apierrors.IsNotFound(err) {
			t.Error("init namespace cleanup failed")
			return
		}
		for {
			if apierrors.IsNotFound(f.kube.Get(ctx, client.ObjectKey{Name: namespace}, &corev1.Namespace{})) {
				t.Log("gate: owned init namespace removed")
				return
			}
			select {
			case <-ctx.Done():
				t.Error("init namespace cleanup timed out")
				return
			case <-time.After(time.Second):
			}
		}
	})
	yes, no := true, false
	uid := int64(65532)
	grace := int64(1)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "gated-proof", Namespace: namespace, Labels: map[string]string{"fixture-app": "network-gate"}}, Spec: corev1.PodSpec{AutomountServiceAccountToken: &no, EnableServiceLinks: &no, TerminationGracePeriodSeconds: &grace,
		SecurityContext: &corev1.PodSecurityContext{RunAsUser: &uid, RunAsGroup: &uid, RunAsNonRoot: &yes, FSGroup: &uid, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
		Containers:      []corev1.Container{{Name: "application", Image: image, ImagePullPolicy: corev1.PullNever, Command: []string{"/hold"}, Args: []string{"--fixture=p1.8-layered-isolation"}, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}}},
	}}
	if kindfixture.AddNetworkGate(pod, image) != nil {
		t.Fatal("init fixture mutation rejected")
	}
	pod.Spec.Containers[0].Resources = pod.Spec.InitContainers[0].Resources
	if f.kube.Create(t.Context(), pod) != nil {
		t.Fatal("gated Pod creation failed")
	}
	releaseFixturePod(t, f, pod)
}
