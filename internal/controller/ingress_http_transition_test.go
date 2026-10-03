package controller

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func transitionClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := tnv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&tnv1.TailnetIngress{}, &tnv1.Tailnet{}, &appsv1.Deployment{}).
		WithObjects(objects...).Build()
}

func transitionFixture(t *testing.T, previousV2 bool) (*TailnetIngressReconciler, *tnv1.TailnetIngress, *appsv1.Deployment, *corev1.ConfigMap, *corev1.Pod) {
	t.Helper()
	in := tlsResourceIngress()
	in.Spec.TailnetRef.Name = "corp"
	in.Spec.Tag, in.Spec.Hostname = "tag:ingress-app", "app"
	in.Spec.TLS = &tnv1.IngressTLS{SecretName: "frontend"}
	if previousV2 {
		in.Spec.Exposes[0].Timeouts = &tnv1.HTTPTimeouts{Request: extensionString("60s")}
	}
	plan := tlsTestPlan(in, "frontend")
	dep := ingressAgentDeploymentTLS(in, &tnv1.Tailnet{}, in.Namespace, "old:agent", nil, corev1.ResourceRequirements{}, plan)
	dep.UID, dep.Generation = "deployment-uid", 4
	dep.Status.ObservedGeneration, dep.Status.Replicas = 4, 1
	cm, err := ingressExposesConfigMap(in, in.Namespace, plan)
	if err != nil {
		t.Fatal(err)
	}
	c := transitionClient(t)
	for _, child := range []client.Object{dep, cm} {
		if err := controllerutil.SetControllerReference(in, child, c.Scheme()); err != nil {
			t.Fatal(err)
		}
	}
	controller := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app-old-agent", Namespace: in.Namespace,
		UID: "pod-uid", Labels: ingressSelectorLabels(in.Name), Annotations: dep.Spec.Template.Annotations,
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "app-old", UID: "rs-uid", Controller: &controller}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	in.Spec.Exposes[0].Backend.TLS = backendTLSFixture()
	in.Generation++
	c = transitionClient(t, in, dep, cm, pod)
	for _, obj := range []client.Object{dep, cm, pod} {
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(obj), obj); err != nil {
			t.Fatal(err)
		}
	}
	return &TailnetIngressReconciler{Client: c, Scheme: c.Scheme(), OperatorNamespace: "operator", OperatorImage: "new:agent"}, in, dep, cm, pod
}

func transitionReconcile(t *testing.T, r *TailnetIngressReconciler, in *tnv1.TailnetIngress) (ctrl.Result, string) {
	t.Helper()
	result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(in)})
	if err != nil {
		t.Fatal(err)
	}
	var got tnv1.TailnetIngress
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(in), &got); err != nil {
		t.Fatal(err)
	}
	if condStatus(got.Status.Conditions, "Ready") != metav1.ConditionFalse {
		t.Fatal("transition/failure must not be Ready")
	}
	return result, condReason(got.Status.Conditions, "Ready")
}

func transitionDeployment(t *testing.T, r *TailnetIngressReconciler, in *tnv1.TailnetIngress) *appsv1.Deployment {
	t.Helper()
	var dep appsv1.Deployment
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(in), &dep); err != nil {
		t.Fatal(err)
	}
	return &dep
}

func transitionAcknowledgeScale(t *testing.T, r *TailnetIngressReconciler, in *tnv1.TailnetIngress) {
	t.Helper()
	dep := transitionDeployment(t, r, in)
	dep.Status.ObservedGeneration, dep.Status.Replicas = dep.Generation, 0
	if err := r.Status().Update(context.Background(), dep); err != nil {
		t.Fatal(err)
	}
}

func transitionControlPlane(t *testing.T, r *TailnetIngressReconciler, healthyPolicy bool) *tnv1.Tailnet {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/v1/policy":
			if !healthyPolicy {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"policy": `{"tagOwners":{"tag:ingress-app":["autogroup:admin"]}}`})
		case "/api/v1/node":
			_, _ = w.Write([]byte(`{"nodes":[]}`))
		default:
			t.Errorf("unexpected Headscale call: %s", req.URL.Path)
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(server.Close)
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "corp"}}
	tn.Spec.Server, tn.Spec.APIURL = server.URL, server.URL
	tn.Spec.DNS.IngressNameTemplate = "{name}.{namespace}.tailnet.invalid"
	if err := r.Create(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	return tn
}

func transitionWorkingKey() *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: workingSecretName("corp"), Namespace: "operator"}, Data: map[string][]byte{apiKeyData: []byte("test-key")}}
}

func TestIngressHTTPTransitionPrecedesControlPlaneFailures(t *testing.T) {
	for _, previousV2 := range []bool{false, true} {
		for _, failure := range []string{"NoTailnet", "NoAPIKey", "InvalidTag", "PolicyUnreadable"} {
			name := "v1/" + failure
			if previousV2 {
				name = "v2-timeouts/" + failure
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				r, in, oldDep, oldCM, pod := transitionFixture(t, previousV2)
				if failure != "NoTailnet" {
					transitionControlPlane(t, r, false)
				}
				if failure == "InvalidTag" || failure == "PolicyUnreadable" {
					if err := r.Create(ctx, transitionWorkingKey()); err != nil {
						t.Fatal(err)
					}
				}
				if failure == "InvalidTag" {
					in.Spec.Tag = "invalid"
					if err := r.Update(ctx, in); err != nil {
						t.Fatal(err)
					}
				}
				for i := 0; i < 2; i++ {
					result, reason := transitionReconcile(t, r, in)
					if reason != "HTTPTransitionPending" || result.RequeueAfter <= 0 {
						t.Fatalf("transition did not poll: %+v %s", result, reason)
					}
					dep := transitionDeployment(t, r, in)
					if *dep.Spec.Replicas != 0 || !reflect.DeepEqual(dep.Spec.Template, oldDep.Spec.Template) {
						t.Fatal("did not pause the predecessor without changing its marker/config")
					}
					transitionAcknowledgeScale(t, r, in)
				}
				// Even after scale-down acknowledgement, terminating Pods block.
				if err := r.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
					t.Fatal(err)
				}
				pod.Finalizers = []string{"test.example/hold"}
				if err := r.Update(ctx, pod); err != nil {
					t.Fatal(err)
				}
				if err := r.Delete(ctx, pod); err != nil {
					t.Fatal(err)
				}
				if _, reason := transitionReconcile(t, r, in); reason != "HTTPTransitionPending" {
					t.Fatalf("bypassed Pod termination: %s", reason)
				}
				if err := r.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
					t.Fatal(err)
				}
				pod.Finalizers = nil
				if err := r.Update(ctx, pod); err != nil {
					t.Fatal(err)
				}
				if _, reason := transitionReconcile(t, r, in); reason != failure {
					t.Fatalf("after retirement: %s, want %s", reason, failure)
				}
				if *transitionDeployment(t, r, in).Spec.Replicas != 0 {
					t.Fatal("control-plane failure restarted the plaintext agent")
				}
				var cm corev1.ConfigMap
				if err := r.Get(ctx, client.ObjectKeyFromObject(oldCM), &cm); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(cm.Data, oldCM.Data) {
					t.Fatal("changed listener config before transition prerequisites succeeded")
				}
			})
		}
	}
}

func TestIngressHTTPTransitionRecovery(t *testing.T) {
	ctx := context.Background()
	r, in, _, oldCM, pod := transitionFixture(t, true)
	tn := transitionControlPlane(t, r, true)
	transitionReconcile(t, r, in)
	transitionAcknowledgeScale(t, r, in)
	if err := r.Delete(ctx, pod); err != nil {
		t.Fatal(err)
	}
	if _, reason := transitionReconcile(t, r, in); reason != "NoAPIKey" {
		t.Fatalf("expected unavailable key, got %s", reason)
	}
	auth := ingressAuthKeySecret(in, in.Namespace, "auth-key", time.Now().Add(168*time.Hour).Format(time.RFC3339))
	for _, obj := range []client.Object{transitionWorkingKey(), auth} {
		if err := r.Create(ctx, obj); err != nil {
			t.Fatal(err)
		}
	}
	// Shared frontend failure stays paused; a missing backend CA is target-local.
	if _, reason := transitionReconcile(t, r, in); reason != "TLSSecretMissing" {
		t.Fatalf("expected missing TLS source, got %s", reason)
	}
	if *transitionDeployment(t, r, in).Spec.Replicas != 0 {
		t.Fatal("missing frontend source restarted predecessor")
	}
	secret, _ := ingressTestCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{in.Status.DNSName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	secret.Name = "frontend"
	if err := r.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	transitionReconcile(t, r, in)
	var got tnv1.TailnetIngress
	if err := r.Get(ctx, client.ObjectKeyFromObject(in), &got); err != nil {
		t.Fatal(err)
	}
	if condReason(got.Status.Conditions, "BackendsReachable") != "BackendCAMissing" {
		t.Fatalf("expected per-backend missing CA: %+v", got.Status.Conditions)
	}
	if *transitionDeployment(t, r, in).Spec.Replicas != 1 {
		t.Fatal("missing backend CA blocked the new configuration and healthy siblings")
	}
	if err := r.Create(ctx, backendCAFixture(t, in.Namespace, time.Now())); err != nil {
		t.Fatal(err)
	}
	transitionReconcile(t, r, in)
	dep := transitionDeployment(t, r, in)
	if *dep.Spec.Replicas != 1 || dep.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType ||
		!ingressHTTPMarkersMatch(dep.Spec.Template.Annotations, ingressProtocolAnnotations(in), false) ||
		dep.Spec.Template.Annotations[ingressHTTPSourceAnnotation] != ingressResolvedSourceDigest(in, tn) {
		t.Fatalf("did not recover with new marker/config: %+v", dep.Spec)
	}
	var cm corev1.ConfigMap
	if err := r.Get(ctx, client.ObjectKeyFromObject(oldCM), &cm); err != nil {
		t.Fatal(err)
	}
	if cm.Data[targetsFile] == oldCM.Data[targetsFile] {
		t.Fatal("restarted without installing extended config")
	}
	var envelope struct {
		Version int
		Targets []agentTarget
	}
	if err := json.Unmarshal([]byte(cm.Data[targetsFile]), &envelope); err != nil || envelope.Version != 2 ||
		len(envelope.Targets) != 2 || envelope.Targets[0].BackendCAFile == "" {
		t.Fatal("recovery did not install backend TLS")
	}
}

func TestIngressHTTPTransitionPreservesForeignDeployment(t *testing.T) {
	for _, owner := range []string{"different-uid", ""} {
		t.Run(owner, func(t *testing.T) {
			r, in, dep, cm, pod := transitionFixture(t, false)
			if owner == "" {
				dep.OwnerReferences = nil
			} else {
				dep.OwnerReferences[0].UID = types.UID(owner)
			}
			r.Client = transitionClient(t, in, dep, cm, pod)
			before := transitionDeployment(t, r, in)
			if _, reason := transitionReconcile(t, r, in); reason != "HTTPTransitionBlocked" {
				t.Fatal(reason)
			}
			if !reflect.DeepEqual(before, transitionDeployment(t, r, in)) {
				t.Fatal("modified foreign Deployment")
			}
			var gotCM corev1.ConfigMap
			var gotPod corev1.Pod
			if err := r.Get(context.Background(), client.ObjectKeyFromObject(cm), &gotCM); err != nil {
				t.Fatal(err)
			}
			if err := r.Get(context.Background(), client.ObjectKeyFromObject(pod), &gotPod); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(gotCM.Data, cm.Data) || gotPod.DeletionTimestamp != nil {
				t.Fatal("foreign collision mutated config or deleted Pod")
			}
		})
	}
}

func TestIngressHTTPTransitionOptimisticLock(t *testing.T) {
	r, in, _, _, _ := transitionFixture(t, false)
	base := r.Client
	patched := false
	r.Client = interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
		if _, ok := obj.(*appsv1.Deployment); !ok {
			return c.Patch(ctx, obj, patch, opts...)
		}
		patched = true
		data, err := patch.Data(obj)
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			Metadata struct{ ResourceVersion string }
		}
		if err := json.Unmarshal(data, &body); err != nil || body.Metadata.ResourceVersion == "" {
			t.Fatal("scale-down must use resourceVersion precondition")
		}
		var current appsv1.Deployment
		if err := c.Get(ctx, client.ObjectKeyFromObject(obj), &current); err != nil {
			t.Fatal(err)
		}
		current.OwnerReferences[0].UID = "changed-concurrently"
		if err := c.Update(ctx, &current); err != nil {
			t.Fatal(err)
		}
		return c.Patch(ctx, obj, patch, opts...)
	}})
	if _, reason := transitionReconcile(t, r, in); reason != "HTTPTransitionBlocked" || !patched {
		t.Fatalf("concurrent ownership change was not blocked: %s", reason)
	}
	if *transitionDeployment(t, r, in).Spec.Replicas != 1 {
		t.Fatal("stale read scaled a different owner")
	}
}

func TestIngressHTTPTransitionReadErrorsAreBounded(t *testing.T) {
	for _, operation := range []string{"get", "list"} {
		t.Run(operation, func(t *testing.T) {
			r, in, _, _, pod := transitionFixture(t, false)
			transitionReconcile(t, r, in)
			transitionAcknowledgeScale(t, r, in)
			if err := r.Delete(context.Background(), pod); err != nil {
				t.Fatal(err)
			}
			r.Client = interceptor.NewClient(r.Client.(client.WithWatch), interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*appsv1.Deployment); ok && operation == "get" {
						return apierrors.NewForbidden(schema.GroupResource{Resource: "deployments"}, key.Name, errors.New("secret-sentinel"))
					}
					return c.Get(ctx, key, obj, opts...)
				},
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if operation == "list" {
						return errors.New("secret-sentinel")
					}
					return c.List(ctx, list, opts...)
				},
			})
			if _, reason := transitionReconcile(t, r, in); reason != "HTTPTransitionBlocked" {
				t.Fatal(reason)
			}
			var got tnv1.TailnetIngress
			if err := r.Get(context.Background(), client.ObjectKeyFromObject(in), &got); err != nil {
				t.Fatal(err)
			}
			for _, condition := range got.Status.Conditions {
				if condition.Type == "Ready" && condition.Message != errIngressTransitionRead.Error() && condition.Message != errIngressTransitionPods.Error() {
					t.Fatalf("unbounded transition error: %s", condition.Message)
				}
			}
		})
	}
}
