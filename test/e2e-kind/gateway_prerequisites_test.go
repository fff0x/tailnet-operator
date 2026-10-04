//go:build e2e_kind

package e2ekind

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tsunaro.io/tailnet-operator/test/internal/kernelcheck"
	"tsunaro.io/tailnet-operator/test/internal/kindfixture"
)

// This is a prerequisite gate, NOT a gateway Pod/routing/bootstrap test. It uses
// the existing unprivileged startup-proof contract unchanged. No TUN is opened,
// device mounted/created, sysctl written or kernel-router container started.
func TestGatewayKernelPrerequisites(t *testing.T) {
	if os.Getenv("E2E_KIND_HTTP_NETWORK_GATE") == "" {
		t.Skip("requires the isolated layered runner")
	}
	f := ownedFixture(t)
	if os.Getenv("E2E_KIND_HTTP_NETWORK_GATE") != "passed" {
		t.Fatal("fresh network proof required")
	}
	image := os.Getenv("E2E_KIND_FIXTURE_IMAGE")
	if image != "localhost/tn-source-netprobe:"+f.cluster {
		t.Fatal("owned source image required")
	}
	root := os.Getenv("E2E_KIND_NET_EVIDENCE")
	info, err := os.Lstat(root)
	if err != nil || !filepath.IsAbs(root) || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		t.Fatal("private evidence required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	if f.kube.Create(ctx, ns) != nil {
		t.Fatal("owned prerequisite namespace creation failed")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if err := f.kube.Delete(ctx, ns, client.Preconditions{UID: &ns.UID}); err != nil && !apierrors.IsNotFound(err) {
			t.Error("prerequisite namespace deletion failed")
			return
		}
		for {
			if apierrors.IsNotFound(f.kube.Get(ctx, client.ObjectKey{Name: namespace}, &corev1.Namespace{})) {
				return
			}
			select {
			case <-ctx.Done():
				t.Error("prerequisite namespace cleanup timed out")
				return
			case <-time.After(time.Second):
			}
		}
	})
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "kernel-observer", Namespace: namespace}, Spec: corev1.PodSpec{
		AutomountServiceAccountToken: ptr.To(false), EnableServiceLinks: ptr.To(false), TerminationGracePeriodSeconds: ptr.To(int64(1)),
		// net.ipv4.ip_forward is a namespaced unsafe sysctl: the kind node allows it
		// (kind-http.yaml KubeletConfiguration), so the fixture pod provisions forwarding
		// itself, mirroring the forwarding the real gateway pod inherits from a Talos node.
		// No host sysctl and no added capability or privilege are involved.
		SecurityContext: &corev1.PodSecurityContext{RunAsUser: ptr.To(int64(65532)), RunAsGroup: ptr.To(int64(65532)), RunAsNonRoot: ptr.To(true), FSGroup: ptr.To(int64(65532)), SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}, Sysctls: []corev1.Sysctl{{Name: "net.ipv4.ip_forward", Value: "1"}}},
		Containers:      []corev1.Container{{Name: "application", Image: image, ImagePullPolicy: corev1.PullNever, Command: []string{"/hold"}, Args: []string{"--fixture=p1.8-layered-isolation"}, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}}},
	}}
	if kindfixture.AddNetworkGate(pod, image) != nil {
		t.Fatal("unchanged startup contract rejected observer")
	}
	pod.Spec.Containers[0].Resources = pod.Spec.InitContainers[0].Resources
	if f.kube.Create(ctx, pod) != nil {
		t.Fatal("observer creation failed")
	}
	releaseFixturePod(t, f, pod)
	before := pod.DeepCopy() // Preserve the identity/processes actually released.
	pod, err = refreshGatewayObserver(ctx, f.kube, before, f.cluster+"-control-plane", image)
	if err != nil {
		t.Fatal("observer source image/process not bound")
	}
	var baseline []nodeObservation
	b, err := os.ReadFile(filepath.Join(root, "node-container-after.json"))
	if err != nil || len(b) > 4<<20 || json.Unmarshal(b, &baseline) != nil || len(baseline) != 1 {
		t.Fatal("owned node baseline missing")
	}
	stableNode := func() {
		b, err := f.command(ctx, "", filepath.Join(f.work, "node-observation"), "inspect")
		var actual []nodeObservation
		if err != nil || len(b) > 4<<20 || json.Unmarshal(b, &actual) != nil || len(actual) != 1 {
			t.Fatal("owned node observation unavailable")
		}
		a, w := actual[0], baseline[0]
		if a.ID != w.ID || a.Name != f.cluster+"-control-plane" || !a.State.Running || a.State.Pid != w.State.Pid || !reflect.DeepEqual(a.Config.Labels, w.Config.Labels) || !bytes.Equal(a.NetworkSettings, w.NetworkSettings) {
			t.Fatal("node binding changed")
		}
	}
	stableNode()
	nb, err := f.command(ctx, "", filepath.Join(f.work, "node-observation"), "kernel")
	if err != nil {
		t.Fatal("read-only node kernel capture failed")
	}
	node, err := kernelcheck.Decode(nb)
	if err != nil || node.Scope != "node" {
		t.Fatal("node kernel observation rejected")
	}
	pb, err := f.command(ctx, "", "kubectl", "--kubeconfig", f.config, "--context", f.context, "--request-timeout=10s", "-n", namespace, "exec", pod.Name, "-c", "application", "--", "/kernelcheck", "--capture=pod", "--fixture=p2.1-kernel-prerequisites")
	if err != nil {
		t.Fatal("read-only pod kernel capture failed")
	}
	observed, err := kernelcheck.Decode(pb)
	if err != nil || observed.Scope != "pod" {
		t.Fatal("pod kernel observation rejected")
	}
	stableNode()
	pod, err = refreshGatewayObserver(ctx, f.kube, before, f.cluster+"-control-plane", image)
	if err != nil {
		t.Fatal("observer changed during capture")
	}
	ready := kernelcheck.IPv4Prerequisites(node, observed)
	result := struct {
		Node              kernelcheck.Snapshot `json:"node"`
		Pod               kernelcheck.Snapshot `json:"pod"`
		PodUID            string               `json:"podUID"`
		NodeContainerID   string               `json:"nodeContainerID"`
		IPv4Prerequisites bool                 `json:"ipv4Prerequisites"`
		GatewayStarted    bool                 `json:"gatewayStarted"`
		RoutingTested     bool                 `json:"routingTested"`
	}{Node: node, Pod: observed, PodUID: string(pod.UID), NodeContainerID: baseline[0].ID, IPv4Prerequisites: ready}
	b, err = json.Marshal(result)
	if err != nil {
		t.Fatal("encode bounded kernel evidence")
	}
	file, err := os.OpenFile(filepath.Join(root, "gateway-kernel-prerequisites.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("create private kernel evidence")
	}
	_, writeErr := file.Write(append(b, '\n'))
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("write kernel evidence")
	}
	if !ready {
		t.Fatal("gateway IPv4 kernel prerequisites unavailable; no gateway started or environment repaired")
	}
	t.Log("gate: necessary IPv4 kernel prerequisites observed; no image, TUN ioctl, gateway bootstrap or routing proof")
}
