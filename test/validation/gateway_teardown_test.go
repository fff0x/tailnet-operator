//go:build integration

package validation

import (
	"k8s.io/client-go/tools/record"
	"maps"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/gateway"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

// Teardown against the real API server. Envtest runs no garbage collector or
// kubelet: the test deletes the synthetic Pod itself where a cluster's GC would.
func gatewayTeardownCases(t *testing.T, newFixture func(*testing.T, bool) *gatewayWriterFixture) {
	t.Run("retain default leaves everything and never adds a finalizer", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		if controllerutil.ContainsFinalizer(f.g, gateway.TeardownFinalizer) {
			t.Fatal("Retain must not record a teardown finalizer")
		}
		before := f.snapshot()
		gatewayWriterMust(t, f.c.Delete(f.ctx, f.g), "delete gateway")
		if !f.teardownReconcile() {
			t.Fatal("Retain deletion must not be held by the operator")
		}
		f.assertRetainedExactly(before)
		f.assertHeadscale(nil, nil)
	})

	t.Run("delete tears down the complete set, node and key", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		node := f.seedSyntheticState()
		f.hs.setNodes([]headscale.Node{node})
		f.createSyntheticReadyPod()
		f.reconcile("FreshRuntimeReady")
		f.setDeletionPolicy(tnv1.GatewayDeletionPolicyDelete)
		f.reconcile("FreshRuntimeReady") // consent is not identity; the workload keeps running
		if !controllerutil.ContainsFinalizer(f.g, gateway.TeardownFinalizer) {
			t.Fatal("Delete must record the teardown finalizer before deletion")
		}
		gatewayWriterMust(t, f.c.Delete(f.ctx, f.g), "delete gateway")
		if f.teardownReconcile() {
			t.Fatal("teardown must wait for the Pod before releasing the finalizer")
		}
		f.assertTeardownReason("Deleting")
		f.absent(f.g.Name, &appsv1.StatefulSet{})
		f.get(f.g.Name+"-auth", &corev1.Secret{}) // nothing beyond the workload yet
		f.assertHeadscale(nil, nil)
		f.simulateGC()
		if !f.teardownReconcile() {
			t.Fatal("teardown did not complete after the Pod was gone")
		}
		f.assertNoRuntime()
		f.assertHeadscale([]string{node.ID}, []string{"9"})
		f.assertMints(1)
		select {
		case event := <-f.r.Recorder.(*record.FakeRecorder).Events:
			if !strings.Contains(event, "GatewayTeardownFinished") {
				t.Fatalf("unexpected event %q", event)
			}
		default:
			t.Fatal("no teardown event recorded")
		}
	})

	t.Run("delete also removes a leftover migration stage", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		// A -fresh-next left by an interrupted receipt migration must not survive
		// teardown.
		fresh := &corev1.ConfigMap{}
		f.get(f.g.Name+"-fresh", fresh)
		stage := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: f.g.Name + "-fresh-next", Namespace: f.ns, Labels: fresh.Labels}, Immutable: ptr.To(true), Data: map[string]string{"receipt.json": fresh.Data["receipt.json"]}}
		gatewayWriterMust(t, f.c.Create(f.ctx, stage), "seed a leftover migration stage")
		f.setDeletionPolicy(tnv1.GatewayDeletionPolicyDelete)
		f.reconcile("Provisioning")
		gatewayWriterMust(t, f.c.Delete(f.ctx, f.g), "delete gateway")
		if !f.teardownReconcile() {
			t.Fatal("teardown did not complete for a never-started workload")
		}
		f.assertNoRuntime()
		f.absent(f.g.Name+"-fresh-next", &corev1.ConfigMap{})
	})

	t.Run("replaced child blocks at that step until removed", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		f.setDeletionPolicy(tnv1.GatewayDeletionPolicyDelete)
		f.reconcile("Provisioning")
		role := &rbacv1.Role{}
		f.get(f.g.Name, role)
		gatewayWriterMust(t, f.c.Delete(f.ctx, role), "delete child as test admin")
		role.ResourceVersion, role.UID = "", ""
		gatewayWriterMust(t, f.c.Create(f.ctx, role), "replace child with a foreign UID")
		gatewayWriterMust(t, f.c.Delete(f.ctx, f.g), "delete gateway")
		if f.teardownReconcile() {
			t.Fatal("foreign child must block the teardown")
		}
		f.assertTeardownReason("TeardownBlocked")
		foreign := &rbacv1.Role{}
		f.get(f.g.Name, foreign)
		if foreign.UID != role.UID {
			t.Fatal("teardown deleted an object it did not create")
		}
		// Later steps did not run: provenance and the receipt are untouched.
		f.get(f.g.Name+"-auth", &corev1.Secret{})
		f.get(string(f.g.Spec.StateSecretRef.Name), &corev1.Secret{})
		f.get(f.g.Name+"-fresh", &corev1.ConfigMap{})
		gatewayWriterMust(t, f.c.Delete(f.ctx, foreign), "remove foreign child as test admin")
		if !f.teardownReconcile() {
			t.Fatal("teardown did not resume after the conflict was removed")
		}
		f.assertNoRuntime()
	})

	t.Run("switching back to retain releases the finalizer", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		f.setDeletionPolicy(tnv1.GatewayDeletionPolicyDelete)
		f.reconcile("Provisioning")
		if !controllerutil.ContainsFinalizer(f.g, gateway.TeardownFinalizer) {
			t.Fatal("finalizer missing after Delete")
		}
		f.setDeletionPolicy(tnv1.GatewayDeletionPolicyRetain)
		f.reconcile("Provisioning")
		if controllerutil.ContainsFinalizer(f.g, gateway.TeardownFinalizer) {
			t.Fatal("finalizer must follow deletionPolicy back to Retain")
		}
		before := f.snapshot()
		gatewayWriterMust(t, f.c.Delete(f.ctx, f.g), "delete gateway")
		if !f.teardownReconcile() {
			t.Fatal("retained deletion was held")
		}
		f.assertRetainedExactly(before)
		f.assertHeadscale(nil, nil)
	})

	t.Run("retain while terminating is the escape hatch", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		f.setDeletionPolicy(tnv1.GatewayDeletionPolicyDelete)
		f.reconcile("Provisioning")
		f.hs.setFailDelete(true)
		node := f.seedSyntheticState()
		f.hs.setNodes([]headscale.Node{node})
		gatewayWriterMust(t, f.c.Delete(f.ctx, f.g), "delete gateway")
		if f.teardownReconcile() {
			t.Fatal("Headscale outage must block the teardown")
		}
		f.assertTeardownReason("TeardownBlocked")
		for _, obj := range f.objects()[:4] {
			f.get(obj.GetName(), obj) // provenance untouched while blocked
		}
		f.get(f.g.Name, &corev1.Service{})
		before := f.snapshot()
		f.setDeletionPolicy(tnv1.GatewayDeletionPolicyRetain)
		if !f.teardownReconcile() {
			t.Fatal("Retain while terminating must release the finalizer")
		}
		f.assertRetainedExactly(before)
		f.assertHeadscale(nil, nil)
	})

	t.Run("headscale outage blocks and a retry completes", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		f.setDeletionPolicy(tnv1.GatewayDeletionPolicyDelete)
		f.reconcile("Provisioning")
		node := f.seedSyntheticState()
		f.hs.setNodes([]headscale.Node{node})
		f.hs.setFailDelete(true)
		gatewayWriterMust(t, f.c.Delete(f.ctx, f.g), "delete gateway")
		if f.teardownReconcile() {
			t.Fatal("Headscale outage must block the teardown")
		}
		f.assertTeardownReason("TeardownBlocked")
		f.get(f.g.Name, &corev1.ServiceAccount{})
		f.get(f.g.Name+"-fresh", &corev1.ConfigMap{})
		f.assertHeadscale(nil, nil)
		f.hs.setFailDelete(false)
		if !f.teardownReconcile() {
			t.Fatal("teardown did not complete after Headscale recovered")
		}
		f.assertNoRuntime()
		f.assertHeadscale([]string{node.ID}, []string{"9"})
	})

	t.Run("partial creation deletes only labelled provenance", func(t *testing.T) {
		f := newFixture(t, false)
		f.writes.failName = f.g.Name + "-coredns"
		f.reconcile("FreshBlocked")
		f.absent(f.g.Name+"-fresh", &corev1.ConfigMap{})
		f.setDeletionPolicy(tnv1.GatewayDeletionPolicyDelete)
		f.reconcile("FreshBlocked")
		gatewayWriterMust(t, f.c.Delete(f.ctx, f.g), "delete gateway")
		if !f.teardownReconcile() {
			t.Fatal("partial set without a receipt must still release")
		}
		// Without a completion receipt there is no child inventory: the children
		// created before the fault stay, labelled provenance goes, the key expires.
		f.absent(string(f.g.Spec.StateSecretRef.Name), &corev1.Secret{})
		f.absent(f.g.Name+"-auth", &corev1.Secret{})
		f.absent(f.g.Name+"-auth-receipt", &corev1.ConfigMap{})
		f.get(f.g.Name, &corev1.ServiceAccount{})
		f.assertHeadscale(nil, []string{"9"})
	})

	t.Run("foreign objects with our names are left alone", func(t *testing.T) {
		f := newFixture(t, false)
		foreign := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: string(f.g.Spec.StateSecretRef.Name), Namespace: f.ns}}
		gatewayWriterMust(t, f.c.Create(f.ctx, foreign), "occupy state name without label")
		f.reconcile("FreshBlocked")
		f.setDeletionPolicy(tnv1.GatewayDeletionPolicyDelete)
		f.reconcile("FreshBlocked")
		gatewayWriterMust(t, f.c.Delete(f.ctx, f.g), "delete gateway")
		if !f.teardownReconcile() {
			t.Fatal("foreign objects must not hold the deletion")
		}
		kept := &corev1.Secret{}
		f.get(foreign.Name, kept)
		if kept.UID != foreign.UID {
			t.Fatal("teardown touched a foreign Secret")
		}
		f.assertHeadscale(nil, nil)
	})
}

func (f *gatewayWriterFixture) setDeletionPolicy(policy string) {
	f.t.Helper()
	gatewayWriterMust(f.t, f.c.Get(f.ctx, client.ObjectKeyFromObject(f.g), f.g), "read gateway")
	f.g.Spec.DeletionPolicy = policy
	gatewayWriterMust(f.t, f.c.Update(f.ctx, f.g), "set deletionPolicy")
}

// teardownReconcile runs one reconcile and reports whether the CR is gone.
func (f *gatewayWriterFixture) teardownReconcile() bool {
	f.t.Helper()
	_, err := f.r.Reconcile(f.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.g)})
	gatewayWriterMust(f.t, err, "reconcile terminating gateway")
	err = f.c.Get(f.ctx, client.ObjectKeyFromObject(f.g), f.g)
	if apierrors.IsNotFound(err) {
		return true
	}
	gatewayWriterMust(f.t, err, "read terminating gateway")
	return false
}

func (f *gatewayWriterFixture) assertTeardownReason(reason string) {
	f.t.Helper()
	ready := meta.FindStatusCondition(f.g.Status.Conditions, "Ready")
	if f.g.DeletionTimestamp == nil || !controllerutil.ContainsFinalizer(f.g, gateway.TeardownFinalizer) || ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != reason {
		f.t.Fatalf("terminating gateway: want finalizer and Ready=False/%s", reason)
	}
}

// simulateGC stands in for the cluster garbage collector envtest does not run.
func (f *gatewayWriterFixture) simulateGC() {
	f.t.Helper()
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: f.g.Name + "-0", Namespace: f.ns}}
	gatewayWriterMust(f.t, client.IgnoreNotFound(f.c.Delete(f.ctx, pod)), "collect synthetic Pod")
}

func (f *gatewayWriterFixture) assertRetainedExactly(before map[string]string) {
	f.t.Helper()
	if len(before) == 0 || !maps.Equal(before, f.snapshot()) {
		f.t.Fatal("Retain changed or removed retained resources")
	}
}

func (f *gatewayWriterFixture) assertHeadscale(deleted, expired []string) {
	f.t.Helper()
	f.hs.mu.Lock()
	defer f.hs.mu.Unlock()
	if !slices.Equal(f.hs.deletedNodes, deleted) || !slices.Equal(f.hs.expiredKeys, expired) {
		f.t.Fatalf("Headscale mutations: want delete %v / expire %d keys, got delete %v / expire %d keys", deleted, len(expired), f.hs.deletedNodes, len(f.hs.expiredKeys))
	}
}

func (h *gatewayWriterHeadscale) setFailDelete(fail bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.failDelete = fail
}
