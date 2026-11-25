package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func readyObj(name, uid string) *tnv1.TailnetIngress {
	return &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", UID: types.UID(uid)}}
}

func nextEvent(rec *record.FakeRecorder) string {
	select {
	case ev := <-rec.Events:
		return ev
	default:
		return ""
	}
}

// An event fires exactly when the new Ready reason differs from the one this process last
// determined for the same object (same UID); without one, the reason read with the object counts,
// else <none>. Normal for Ready, Warning otherwise.
func TestEmitReadyChange(t *testing.T) {
	const kind = "TailnetIngress"
	emit := func(rec record.EventRecorder, obj client.Object, status, next string) {
		emitReadyChange(rec, obj, kind, status, next)
	}
	cases := []struct {
		name  string
		steps func(rec *record.FakeRecorder, obj *tnv1.TailnetIngress)
		want  string // the last event; "" means none
	}{
		{"first reason without status", func(rec *record.FakeRecorder, obj *tnv1.TailnetIngress) {
			emit(rec, obj, "", "Registered")
		}, "Warning ReadyChanged Ready: <none> -> Registered"},
		{"first reason from status", func(rec *record.FakeRecorder, obj *tnv1.TailnetIngress) {
			emit(rec, obj, "TLSProbeFailed", "Ready")
		}, "Normal ReadyChanged Ready: TLSProbeFailed -> Ready"},
		{"stale status, remembered reason wins", func(rec *record.FakeRecorder, obj *tnv1.TailnetIngress) {
			emit(rec, obj, "Ready", "TLSProbeFailed")
			nextEvent(rec)
			emit(rec, obj, "Ready", "Apply")
		}, "Warning ReadyChanged Ready: TLSProbeFailed -> Apply"},
		{"stale status equal to the new reason still flips", func(rec *record.FakeRecorder, obj *tnv1.TailnetIngress) {
			emit(rec, obj, "Ready", "TLSProbeFailed")
			nextEvent(rec)
			emit(rec, obj, "Ready", "Ready")
		}, "Normal ReadyChanged Ready: TLSProbeFailed -> Ready"},
		{"remembered equals new, stale status differs", func(rec *record.FakeRecorder, obj *tnv1.TailnetIngress) {
			emit(rec, obj, "Ready", "Apply")
			nextEvent(rec)
			emit(rec, obj, "Ready", "Apply")
		}, ""},
		{"unchanged reason", func(rec *record.FakeRecorder, obj *tnv1.TailnetIngress) {
			emit(rec, obj, "Ready", "Ready")
		}, ""},
		{"re-created object ignores the old memory", func(rec *record.FakeRecorder, obj *tnv1.TailnetIngress) {
			emit(rec, obj, "", "Apply")
			nextEvent(rec)
			emit(rec, readyObj(obj.Name, "other-uid"), "", "Apply")
		}, "Warning ReadyChanged Ready: <none> -> Apply"},
		{"no recorder still remembers", func(rec *record.FakeRecorder, obj *tnv1.TailnetIngress) {
			emit(nil, obj, "", "Apply")
			emit(rec, obj, "", "Apply")
		}, ""},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obj := readyObj("event-"+string(rune('a'+i)), "uid")
			t.Cleanup(func() { forgetReady(kind, client.ObjectKeyFromObject(obj)) })
			rec := record.NewFakeRecorder(4)
			tc.steps(rec, obj)
			if got := nextEvent(rec); got != tc.want {
				t.Fatalf("event %q, want %q", got, tc.want)
			}
		})
	}
}

// A reconcile of a deleted object does not determine Ready, so it emits nothing and keeps the
// remembered reason; a reconcile of a vanished object forgets it.
func TestReconcileReadyMemory(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = tnv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	now := metav1.Now()
	deleting := metav1.ObjectMeta{Namespace: "ns", UID: "uid", DeletionTimestamp: &now, Finalizers: []string{authKeyFinalizer}}
	in := &tnv1.TailnetIngress{ObjectMeta: deleting}
	in.Name = "deleting-in"
	eg := &tnv1.TailnetEgress{ObjectMeta: deleting}
	eg.Name = "deleting-eg"
	for _, o := range []*[]metav1.Condition{&in.Status.Conditions, &eg.Status.Conditions} {
		setCond(o, 1, "Ready", metav1.ConditionTrue, "Ready", "ok")
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(in, eg).Build()
	rec := record.NewFakeRecorder(4)
	ir := TailnetIngressReconciler{Client: c, Recorder: rec}
	er := TailnetEgressReconciler{Client: c, Recorder: rec}
	for _, tc := range []struct {
		kind      string
		obj       client.Object
		reconcile func(context.Context, ctrl.Request) (ctrl.Result, error)
	}{{"TailnetIngress", in, ir.Reconcile}, {"TailnetEgress", eg, er.Reconcile}} {
		key := readyKey{tc.kind, client.ObjectKeyFromObject(tc.obj)}
		readyMemory.Store(key, readyEntry{"uid", "Registered"})
		req := ctrl.Request{NamespacedName: key.name}
		if _, err := tc.reconcile(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		if ev := nextEvent(rec); ev != "" {
			t.Fatalf("%s: deletion emitted %q", tc.kind, ev)
		}
		if v, ok := readyMemory.Load(key); !ok || v.(readyEntry).reason != "Registered" {
			t.Fatalf("%s: deletion changed the remembered reason: %v", tc.kind, v)
		}
		// The finalizer is gone, so the fake client has removed the object.
		if _, err := tc.reconcile(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		if _, ok := readyMemory.Load(key); ok {
			t.Fatalf("%s: vanished object still remembered", tc.kind)
		}
	}
}
