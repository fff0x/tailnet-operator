//go:build e2e_kind

package e2ekind

import (
	"context"
	"errors"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var errGatewayObserver = errors.New("kernel observer identity rejected")

func refreshGatewayObserver(ctx context.Context, kube client.Reader, released *corev1.Pod, node, image string) (*corev1.Pod, error) {
	if released == nil {
		return nil, errGatewayObserver
	}
	actual := released.DeepCopy()
	if kube.Get(ctx, client.ObjectKeyFromObject(released), actual) != nil {
		return nil, errGatewayObserver
	}
	// Compare against the released object, never a baseline derived from this Get.
	if actual.UID == "" || actual.UID != released.UID || actual.DeletionTimestamp != nil || actual.Name != released.Name || actual.Namespace != released.Namespace || actual.Spec.NodeName != node || !reflect.DeepEqual(actual.Spec, released.Spec) ||
		len(actual.Spec.Containers) != 1 || len(actual.Status.ContainerStatuses) != 1 || len(actual.Status.InitContainerStatuses) != 1 || len(released.Status.ContainerStatuses) != 1 || len(released.Status.InitContainerStatuses) != 1 {
		return nil, errGatewayObserver
	}
	app, init := actual.Status.ContainerStatuses[0], actual.Status.InitContainerStatuses[0]
	if actual.Spec.Containers[0].Image != image || app.State.Running == nil || app.RestartCount != 0 || app.ImageID == "" || app.ImageID != init.ImageID || app.ImageID != released.Status.ContainerStatuses[0].ImageID || init.ImageID != released.Status.InitContainerStatuses[0].ImageID ||
		app.ContainerID == "" || app.ContainerID != released.Status.ContainerStatuses[0].ContainerID || init.ContainerID == "" || init.ContainerID != released.Status.InitContainerStatuses[0].ContainerID ||
		init.RestartCount != 0 || init.State.Terminated == nil || init.State.Terminated.ExitCode != 0 {
		return nil, errGatewayObserver
	}
	return actual, nil
}

func TestGatewayObserverRejectsRebinding(t *testing.T) {
	scheme := runtime.NewScheme()
	if corev1.AddToScheme(scheme) != nil {
		t.Fatal("test scheme")
	}
	released := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "observer", Namespace: "owned", UID: "released-uid"}, Spec: corev1.PodSpec{NodeName: "owned-node", Containers: []corev1.Container{{Name: "application", Image: "owned-image"}}}, Status: corev1.PodStatus{
		ContainerStatuses:     []corev1.ContainerStatus{{Name: "application", ContainerID: "app-id", ImageID: "same-image-id", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}},
		InitContainerStatuses: []corev1.ContainerStatus{{Name: "fixture-network-gate", ContainerID: "init-id", ImageID: "same-image-id", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}}},
	}}
	for name, change := range map[string]func(*corev1.Pod){
		"unchanged":       func(*corev1.Pod) {},
		"replacement UID": func(p *corev1.Pod) { p.UID = "replacement-uid" },
		"changed command": func(p *corev1.Pod) { p.Spec.Containers[0].Command = []string{"/skip-approval"} },
		"new application": func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ContainerID = "new-app" },
		"new init":        func(p *corev1.Pod) { p.Status.InitContainerStatuses[0].ContainerID = "new-init" },
		"changed image IDs": func(p *corev1.Pod) {
			p.Status.ContainerStatuses[0].ImageID = "foreign"
			p.Status.InitContainerStatuses[0].ImageID = "foreign"
		},
		"restart":     func(p *corev1.Pod) { p.Status.ContainerStatuses[0].RestartCount = 1 },
		"init failed": func(p *corev1.Pod) { p.Status.InitContainerStatuses[0].State.Terminated.ExitCode = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			current := released.DeepCopy()
			change(current)
			kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(current).Build()
			before := released.DeepCopy()
			got, err := refreshGatewayObserver(t.Context(), kube, released, "owned-node", "owned-image")
			if name == "unchanged" {
				if err != nil || got == nil {
					t.Fatal("unchanged observer rejected")
				}
			} else if !errors.Is(err, errGatewayObserver) || got != nil {
				t.Fatal("observer rebound to unproved identity or process")
			}
			if !reflect.DeepEqual(released, before) {
				t.Fatal("released baseline mutated")
			}
		})
	}
}
