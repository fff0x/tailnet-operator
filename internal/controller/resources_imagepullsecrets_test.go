package controller

import (
	"encoding/json"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func TestAgentDeploymentImagePullSecrets(t *testing.T) {
	for _, builder := range []struct {
		name      string
		namespace string
		build     func(*tnv1.Tailnet, []string) *appsv1.Deployment
	}{
		{
			name: "egress", namespace: "tailnet-system",
			build: func(tn *tnv1.Tailnet, defaults []string) *appsv1.Deployment {
				eg := &tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "tailnet-system"}}
				return agentDeployment(eg, tn, eg.Namespace, "selected-image", defaults)
			},
		},
		{
			name: "ingress", namespace: "tenant-app",
			build: func(tn *tnv1.Tailnet, defaults []string) *appsv1.Deployment {
				in := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant-app"}}
				return ingressAgentDeployment(in, tn, in.Namespace, "selected-image", defaults)
			},
		},
	} {
		for _, tt := range []struct {
			name     string
			proxy    string
			defaults []string
			want     []corev1.LocalObjectReference
		}{
			{name: "omitted", proxy: `{}`, want: []corev1.LocalObjectReference{}},
			{name: "inherit", proxy: `{}`, defaults: []string{"operator-registry", "shared"}, want: []corev1.LocalObjectReference{{Name: "operator-registry"}, {Name: "shared"}}},
			{name: "duplicate-defaults", proxy: `{}`, defaults: []string{"registry", "registry", "second"}, want: []corev1.LocalObjectReference{{Name: "registry"}, {Name: "second"}}},
			{name: "duplicate-override", proxy: `{"imagePullSecrets":["registry","registry","second"]}`, defaults: []string{"ignored"}, want: []corev1.LocalObjectReference{{Name: "registry"}, {Name: "second"}}},
			{name: "explicit-empty", proxy: `{"imagePullSecrets":[]}`, defaults: []string{"operator-registry"}, want: []corev1.LocalObjectReference{}},
			{name: "override", proxy: `{"imagePullSecrets":["tenant-registry","second"]}`, defaults: []string{"operator-registry"}, want: []corev1.LocalObjectReference{{Name: "tenant-registry"}, {Name: "second"}}},
		} {
			t.Run(builder.name+"/"+tt.name, func(t *testing.T) {
				tn := &tnv1.Tailnet{}
				if err := json.Unmarshal([]byte(tt.proxy), &tn.Spec.Proxy); err != nil {
					t.Fatal(err)
				}
				defaults := append([]string(nil), tt.defaults...)
				dep := builder.build(tn, defaults)
				pod := &dep.Spec.Template.Spec
				if dep.Namespace != builder.namespace || !reflect.DeepEqual(pod.ImagePullSecrets, tt.want) {
					t.Fatalf("namespace=%s secrets=%v; want %s %v", dep.Namespace, pod.ImagePullSecrets, builder.namespace, tt.want)
				}
				if pod.Containers[0].Image != "selected-image" || pod.ServiceAccountName != "" {
					t.Fatal("image or ServiceAccount changed")
				}
				// A second build and the source lists must not share storage with this pod.
				other := builder.build(tn, defaults)
				if len(pod.ImagePullSecrets) > 0 {
					pod.ImagePullSecrets[0].Name = "changed-pod"
				}
				if !reflect.DeepEqual(other.Spec.Template.Spec.ImagePullSecrets, tt.want) {
					t.Fatal("pod mutation changed another build")
				}
				if !reflect.DeepEqual(defaults, tt.defaults) {
					t.Fatal("pod mutation changed defaults")
				}
				if override := tn.Spec.Proxy.ImagePullSecrets; override != nil && len(*override) > 0 {
					if (*override)[0] != tt.want[0].Name {
						t.Fatal("pod mutation changed Tailnet")
					}
					(*override)[0] = "changed-tailnet"
				}
				if len(defaults) > 0 {
					defaults[0] = "changed-default"
				}
				if !reflect.DeepEqual(other.Spec.Template.Spec.ImagePullSecrets, tt.want) {
					t.Fatal("source mutation changed generated pod")
				}
			})
		}
	}
}
