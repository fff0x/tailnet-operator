package controller

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
)

func TestAgentDeploymentSecurity(t *testing.T) {
	tn := &tnv1.Tailnet{}
	for name, dep := range map[string]*appsv1.Deployment{
		"egress":  agentDeployment(&tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "out"}}, tn, "agents", "image", nil),
		"ingress": ingressAgentDeployment(&tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "in"}}, tn, "agents", "image", nil),
	} {
		t.Run(name, func(t *testing.T) {
			pod := dep.Spec.Template.Spec
			if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
				t.Fatal("agent must explicitly disable service-account token automount")
			}
			if dep.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType || len(pod.Containers) != 1 {
				t.Fatal("agent topology changed")
			}
			sec := pod.SecurityContext
			if sec == nil || sec.RunAsNonRoot == nil || !*sec.RunAsNonRoot || sec.RunAsUser == nil || *sec.RunAsUser != 65532 || sec.SeccompProfile == nil || sec.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
				t.Fatal("restricted pod security context changed")
			}
			c := pod.Containers[0]
			cs := c.SecurityContext
			if cs == nil || cs.ReadOnlyRootFilesystem == nil || !*cs.ReadOnlyRootFilesystem {
				t.Fatal("agent root filesystem must be read-only")
			}
			if cs.AllowPrivilegeEscalation == nil || *cs.AllowPrivilegeEscalation || cs.Capabilities == nil || len(cs.Capabilities.Drop) != 1 || cs.Capabilities.Drop[0] != "ALL" {
				t.Fatal("container privilege restrictions changed")
			}
			stateMount, targetsMount, stateVolume, stateEnv, homeEnv, keyRef := false, false, false, false, false, false
			for _, mount := range c.VolumeMounts {
				if mount.Name == "state" {
					stateMount = mount.MountPath == "/state" && !mount.ReadOnly
				}
				if mount.Name == "targets" {
					targetsMount = mount.MountPath == "/config" && mount.ReadOnly
				}
			}
			for _, volume := range pod.Volumes {
				if volume.Name == "state" {
					stateVolume = volume.EmptyDir != nil
				}
			}
			for _, env := range c.Env {
				switch env.Name {
				case "TS_STATE_DIR":
					stateEnv = env.Value == "/state"
				case "HOME":
					homeEnv = env.Value == "/state"
				case "TS_AUTHKEY":
					keyRef = env.Value == "" && env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil
				}
			}
			if !stateMount || !targetsMount || !stateVolume || !stateEnv || !homeEnv || !keyRef {
				t.Fatal("writable state emptyDir, read-only config, or Secret reference changed")
			}
		})
	}
}
