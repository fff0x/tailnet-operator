package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

// The ingress identity is the state Secret: its name follows server and tag (a new identity is a
// new, empty Secret), the Deployment points at it, and the Role grants nothing beyond that Secret.
func TestIngressIdentityObjects(t *testing.T) {
	tn := &tnv1.Tailnet{Spec: tnv1.TailnetSpec{Server: "https://hs.example.com", IngressTagTemplate: "tag:ingress-{name}"}}
	in := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant"}}

	name := ingressStateSecretName(in, tn)
	if name == ingressStateSecretName(in, &tnv1.Tailnet{Spec: tnv1.TailnetSpec{Server: "https://other.example.com", IngressTagTemplate: tn.Spec.IngressTagTemplate}}) {
		t.Fatal("server change must rename the state Secret")
	}
	tagged := in.DeepCopy()
	tagged.Spec.Tag = "tag:custom"
	if name == ingressStateSecretName(tagged, tn) {
		t.Fatal("tag change must rename the state Secret")
	}
	renamed := in.DeepCopy()
	renamed.Status.Hostname = "other"
	if name == ingressStateSecretName(renamed, tn) {
		t.Fatal("hostname change must rename the state Secret (a rename re-registers the node)")
	}
	if ingressStateSecretName(in, tn) != name {
		t.Fatal("state Secret name must be stable for an unchanged identity")
	}

	dep := ingressAgentDeployment(in, tn, in.Namespace, "img", nil, corev1.ResourceRequirements{})
	var env string
	for _, e := range dep.Spec.Template.Spec.Containers[0].Env {
		if e.Name == "TS_STATE_SECRET" {
			env = e.Value
		}
	}
	if env != name || dep.Spec.Template.Spec.ServiceAccountName != "ingress-app" {
		t.Fatalf("deployment identity wiring: env=%q sa=%q", env, dep.Spec.Template.Spec.ServiceAccountName)
	}

	objs := ingressIdentityObjects(in, in.Namespace, name)
	var role *rbacv1.Role
	var secret *corev1.Secret
	for _, o := range objs {
		switch v := o.(type) {
		case *rbacv1.Role:
			role = v
		case *corev1.Secret:
			secret = v
		}
	}
	if role == nil || len(role.Rules) != 1 || len(role.Rules[0].ResourceNames) != 1 || role.Rules[0].ResourceNames[0] != name ||
		len(role.Rules[0].Verbs) != 3 {
		t.Fatalf("role must cover exactly the state Secret with get/update/patch: %+v", role)
	}
	if secret == nil || secret.Name != name || secret.Labels[labelIngressState] != "true" || len(secret.Data) != 0 {
		t.Fatalf("state Secret must be empty and labelled: %+v", secret)
	}
}

// A retired identity's Secret (same CR, other name) is removed; the current one and foreign
// Secrets stay.
func TestDropRetiredStateSecrets(t *testing.T) {
	in := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", UID: "in-uid"}}
	mk := func(name string, owned bool) *corev1.Secret {
		l := ingressObjLabels(in.Name)
		l[labelIngressState] = "true"
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: in.Namespace, Labels: l}}
		if owned {
			_ = controllerutil.SetControllerReference(in, s, transitionClient(t).Scheme())
		}
		return s
	}
	c := transitionClient(t, mk("ingress-app-state-old", true), mk("ingress-app-state-new", true), mk("ingress-app-state-foreign", false))
	r := &TailnetIngressReconciler{Client: c, Scheme: c.Scheme()}
	if err := r.dropRetiredStateSecrets(context.Background(), in, in.Namespace, "ingress-app-state-new"); err != nil {
		t.Fatal(err)
	}
	var s corev1.Secret
	for name, want := range map[string]bool{"ingress-app-state-old": false, "ingress-app-state-new": true, "ingress-app-state-foreign": true} {
		err := c.Get(context.Background(), types.NamespacedName{Namespace: in.Namespace, Name: name}, &s)
		if got := err == nil; got != want {
			t.Fatalf("%s present=%v want %v (%v)", name, got, want, client.IgnoreNotFound(err))
		}
	}
}

// deleteOwnNode must only ever delete a node that is recognisably this CR's, and with keepCurrent
// leave the node that still matches the current identity to associateNode.
func TestDeleteOwnNode(t *testing.T) {
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/node":
			_ = json.NewEncoder(w).Encode(map[string]any{"nodes": []map[string]any{
				{"id": "1", "givenName": "ingress-app", "tags": []string{"tag:ingress-app"}},
				{"id": "2", "givenName": "ingress-app", "tags": []string{"tag:old"}},
				{"id": "3", "givenName": "old-name-1", "tags": []string{"tag:ingress-app"}},
				{"id": "4", "givenName": "someone-else", "tags": []string{"tag:other"}},
			}})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/node/"):
			deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/api/v1/node/"))
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()
	hs := headscale.New(srv.URL, "key")
	ctx := context.Background()
	deleteOwnNode(ctx, hs, "4", "tag:ingress-app", "ingress-app", false) // foreign: never
	deleteOwnNode(ctx, hs, "1", "tag:ingress-app", "ingress-app", true)  // current identity: kept
	deleteOwnNode(ctx, hs, "2", "tag:ingress-app", "ingress-app", true)  // tag changed: gone
	deleteOwnNode(ctx, hs, "3", "tag:ingress-app", "ingress-app", true)  // hostname changed: gone
	deleteOwnNode(ctx, hs, "1", "tag:ingress-app", "ingress-app", false) // CR deleted: gone
	deleteOwnNode(ctx, hs, "", "tag:ingress-app", "ingress-app", false)  // nothing recorded
	if want := []string{"2", "3", "1"}; !reflect.DeepEqual(deleted, want) {
		t.Fatalf("deleted %v, want %v", deleted, want)
	}
}
