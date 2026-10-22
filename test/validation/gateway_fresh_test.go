//go:build integration

package validation

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/gateway"
	"tsunaro.io/tailnet-operator/test/internal/isolation"
)

// Real API validation and authorization only. No StatefulSet controller, kubelet,
// token projection, GC or data plane runs; this does NOT verify a runnable pod,
// bootstrap, forwarding, persistence across restart or retention.
func TestGatewayFreshResources(t *testing.T) {
	must := func(err error, message string) {
		t.Helper()
		if err != nil {
			t.Fatal(message)
		}
	}
	must(isolation.ClearEnvtestOverrides(), "isolate envtest")
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Fatal("explicit isolated envtest assets required")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	must(err, "resolve repository")
	useExisting := false
	env := &envtest.Environment{UseExistingCluster: &useExisting, CRDDirectoryPaths: []string{filepath.Join(root, "deploy/crds")}, ErrorIfCRDPathMissing: true, ControlPlaneStartTimeout: 20 * time.Second, ControlPlaneStopTimeout: 10 * time.Second}
	env.ControlPlane.GetAPIServer().Configure().Set("service-cluster-ip-range", "10.96.0.0/12,2001:db8:2::/112")
	t.Cleanup(func() { must(env.Stop(), "stop isolated API server") })
	cfg, err := env.Start()
	must(err, "start isolated API server")
	scheme := runtime.NewScheme()
	must(clientgoscheme.AddToScheme(scheme), "register Kubernetes types")
	must(tnv1.AddToScheme(scheme), "register gateway types")
	admin, err := client.New(cfg, client.Options{Scheme: scheme})
	must(err, "create isolated client")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "corp"}, Spec: tnv1.TailnetSpec{Server: "https://headscale.example", APISecretRef: tnv1.SecretKeyRef{Name: "bootstrap"}, APIKeyLifetime: metav1.Duration{Duration: 24 * time.Hour}}}
	must(admin.Create(ctx, tn), "admit Tailnet fixture")
	fixture, err := os.ReadFile(filepath.Join(root, "deploy/examples/tailnetgateway.yaml"))
	must(err, "read gateway example")
	for _, family := range []string{"ipv4", "ipv6"} {
		t.Run(family, func(t *testing.T) {
			must := func(err error, message string) {
				t.Helper()
				if err != nil {
					t.Fatal(message)
				}
			}
			namespace := "gateway-fresh-" + family
			must(admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}), "create test namespace")
			g := &tnv1.TailnetGateway{}
			must(yaml.Unmarshal(fixture, g), "decode gateway example")
			g.Name = "router-" + family
			g.Spec.DNS.ServiceName = tnv1.GatewayServiceName(g.Name + "-dns")
			g.Spec.AuthKeySecretRef = &tnv1.GatewayAuthKeyReference{Name: "router-auth"}
			if family == "ipv6" {
				g.Spec.Service.LoadBalancerIP = "2001:db8:1::17"
				g.Spec.Service.TailnetLBCIDR = "2001:db8:1::/64"
				g.Spec.DNS.ServiceClusterIP = "2001:db8:2::53"
			}
			must(admin.Create(ctx, g), "admit and default gateway")
			plan, err := gateway.RenderFresh(gateway.FreshInputs{Gateway: g, Tailnet: tn, Namespace: namespace, DNSSerial: 1})
			must(err, "render admitted fresh gateway")
			for _, obj := range plan.Objects {
				must(admin.Create(ctx, obj), "admit planned resource")
			}
			// Validate the Pod itself too, without starting one. StatefulSet admission
			// alone does not run Pod admission. Dry-run does not execute the image.
			var pod *corev1.Pod
			for _, obj := range plan.Objects {
				if sts, ok := obj.(*appsv1.StatefulSet); ok {
					pod = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: g.Name + "-0", Namespace: namespace, Labels: sts.Spec.Template.Labels}, Spec: sts.Spec.Template.Spec}
				}
			}
			if pod == nil {
				t.Fatal("missing pod template")
			}
			must(admin.Create(ctx, pod, client.DryRunAll), "admit pod template in dry-run")
			for _, obj := range plan.Objects {
				if s, ok := obj.(*corev1.Service); ok {
					want := corev1.IPv4Protocol
					if family == "ipv6" {
						want = corev1.IPv6Protocol
					}
					if len(s.Spec.IPFamilies) != 1 || s.Spec.IPFamilies[0] != want {
						t.Fatal("API changed explicit family")
					}
					if s.Name == string(g.Spec.DNS.ServiceName) && s.Spec.ClusterIP != string(g.Spec.DNS.ServiceClusterIP) {
						t.Fatal("API changed stable DNS IP")
					}
					if s.Spec.Type == corev1.ServiceTypeLoadBalancer {
						for _, p := range s.Spec.Ports {
							if p.NodePort != 0 {
								t.Fatal("unexpected NodePort allocation")
							}
						}
					}
				}
			}
			// The renderer must not silently provide a state/auth Secret. Initialize a
			// synthetic empty state as test admin, not through the gateway SA.
			state := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: string(g.Spec.StateSecretRef.Name), Namespace: namespace}}
			must(admin.Create(ctx, state), "create empty state fixture")
			scoped := rest.CopyConfig(cfg)
			scoped.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:" + namespace + ":" + g.Name, Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + namespace, "system:authenticated"}}
			account, err := client.New(scoped, client.Options{Scheme: scheme})
			must(err, "construct scoped client")
			access := func(verb, name string, want bool) {
				t.Helper()
				review := &authv1.SelfSubjectAccessReview{Spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Namespace: namespace, Verb: verb, Resource: "secrets", Name: name}}}
				must(account.Create(ctx, review), "check scoped Secret authorization")
				if review.Status.Allowed != want {
					t.Fatal("incorrect Secret authorization")
				}
			}
			for _, verb := range []string{"get", "update", "patch"} {
				access(verb, state.Name, true)
				access(verb, "router-auth", false)
				access(verb, "foreign-state", false)
			}
			for _, verb := range []string{"create", "delete", "list", "watch"} {
				access(verb, state.Name, false)
			}
			must(account.Get(ctx, client.ObjectKeyFromObject(state), state), "read exact state")
			before := state.DeepCopy()
			state.Data = map[string][]byte{"fixture": []byte("synthetic-not-a-credential")}
			must(account.Patch(ctx, state, client.MergeFrom(before)), "patch exact state")
			state.Data["fixture"] = []byte("updated-synthetic-fixture")
			must(account.Update(ctx, state), "update exact state")
			must(admin.Delete(ctx, state), "remove synthetic state as admin")
			if err := account.Get(ctx, client.ObjectKeyFromObject(state), &corev1.Secret{}); !apierrors.IsNotFound(err) {
				t.Fatal("missing state not observable")
			}
			state.ResourceVersion = ""
			state.UID = ""
			if err := account.Update(ctx, state); !apierrors.IsNotFound(err) {
				t.Fatal("update could recreate missing state")
			}
			if err := account.Patch(ctx, state, client.MergeFrom(state.DeepCopy())); !apierrors.IsNotFound(err) {
				t.Fatal("patch could recreate missing state")
			}
			if err := account.Create(ctx, state); !apierrors.IsForbidden(err) {
				t.Fatal("gateway could recreate missing state")
			}
		})
	}
}
