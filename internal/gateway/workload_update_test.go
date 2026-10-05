package gateway

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

func freshStatefulSet(t *testing.T) *appsv1.StatefulSet {
	t.Helper()
	plan, err := RenderFresh(freshFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, obj := range plan.Objects {
		if v, ok := obj.(*appsv1.StatefulSet); ok {
			return v
		}
	}
	t.Fatal("no StatefulSet rendered")
	return nil
}

// Every container the spec names must be covered by freshImages, otherwise the
// image bump would silently skip it.
func TestFreshImagesCoverRenderedContainers(t *testing.T) {
	in := freshFixture()
	spec := freshStatefulSet(t).Spec.Template.Spec
	want := freshImages(in.Gateway)
	if !podImagesCurrent(spec, want) {
		t.Fatal("rendered template does not match its own wanted images")
	}
	for _, c := range append(append([]corev1.Container{}, spec.InitContainers...), spec.Containers...) {
		if _, ok := want[c.Name]; !ok {
			t.Fatalf("container %s is not covered by freshImages", c.Name)
		}
	}
	bumped := in.Gateway.DeepCopy()
	bumped.Spec.Image, bumped.Spec.DNS.Image = "ghcr.io/tailscale/tailscale:v1.102.5", "coredns/coredns:1.14.7"
	if podImagesCurrent(spec, freshImages(bumped)) {
		t.Fatal("image bump not detected")
	}
}

// The receipt digest binds everything of the StatefulSet except container images.
func TestObjectReceiptStatefulSetImagesExcluded(t *testing.T) {
	sts := freshStatefulSet(t)
	base := objectReceipt(sts)
	changed := sts.DeepCopy()
	changed.Spec.Template.Spec.Containers[0].Image = "ghcr.io/tailscale/tailscale:v1.102.5"
	changed.Spec.Template.Spec.Containers[1].Image = "coredns/coredns:1.14.7"
	changed.Spec.Template.Spec.InitContainers[0].Image = "ghcr.io/tailscale/tailscale:v1.102.5"
	if objectReceipt(changed) != base {
		t.Fatal("image change altered the receipt digest")
	}
	for name, mutate := range map[string]func(*appsv1.StatefulSet){
		"replicas": func(s *appsv1.StatefulSet) { s.Spec.Replicas = ptr.To(int32(2)) },
		"service":  func(s *appsv1.StatefulSet) { s.Spec.ServiceName = "other" },
		"strategy": func(s *appsv1.StatefulSet) { s.Spec.UpdateStrategy.Type = appsv1.RollingUpdateStatefulSetStrategyType },
		"selector": func(s *appsv1.StatefulSet) { s.Spec.Selector.MatchLabels["x"] = "y" },
		"env":      func(s *appsv1.StatefulSet) { s.Spec.Template.Spec.Containers[0].Env[0].Value = "x" },
		"command":  func(s *appsv1.StatefulSet) { s.Spec.Template.Spec.Containers[0].Command = []string{"/bin/sh"} },
		"labels":   func(s *appsv1.StatefulSet) { s.Spec.Template.Labels["x"] = "y" },
	} {
		c := sts.DeepCopy()
		mutate(c)
		if objectReceipt(c) == base {
			t.Fatalf("%s drift escaped the receipt digest", name)
		}
	}
}
