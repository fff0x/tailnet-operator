package controller

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

const gatewayTestCanary = "synthetic-gateway-credential-do-not-emit"

var gatewayTestConditionTypes = []string{"Ready", "Registered", "RoutesInSync", "DNSReady", "StaleNodes", "ClusterDNSForward"}

// Only Get(gateway) and Status().Patch(gateway) are available to the reconciler.
// The deliberately nil embedded interfaces make any other client operation fail
// the test, rather than silently allowing child, Secret or Tailnet access.
// The fake models status separation and resource-version conflicts, not API-server
// admission, defaulting, RBAC or real persistence.
type gatewayTestClient struct {
	client.Client
	t           *testing.T
	base        client.Client
	key         client.ObjectKey
	gets        int
	patches     int
	readErr     error
	writeErr    error
	beforePatch func()
}

type gatewayTestStatusWriter struct {
	client.SubResourceWriter
	guard *gatewayTestClient
}

func (c *gatewayTestClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	c.t.Helper()
	if _, ok := obj.(*tnv1.TailnetGateway); !ok || key != c.key {
		c.t.Fatal("reconciler attempted a read outside its gateway")
	}
	c.gets++
	if c.readErr != nil {
		return c.readErr
	}
	return c.base.Get(ctx, key, obj, opts...)
}

func (c *gatewayTestClient) Status() client.SubResourceWriter {
	return gatewayTestStatusWriter{guard: c}
}

func (w gatewayTestStatusWriter) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	c := w.guard
	c.t.Helper()
	if _, ok := obj.(*tnv1.TailnetGateway); !ok || client.ObjectKeyFromObject(obj) != c.key {
		c.t.Fatal("reconciler attempted a status write outside its gateway")
	}
	c.patches++
	if patch.Type() != types.MergePatchType {
		c.t.Fatal("status must use a merge patch")
	}
	data, err := patch.Data(obj)
	if err != nil {
		c.t.Fatal("cannot inspect gateway status patch")
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(data, &body) != nil {
		c.t.Fatal("invalid status patch JSON")
	}
	for key := range body {
		if key != "status" && key != "metadata" {
			c.t.Fatal("status patch changes fields outside status and resourceVersion")
		}
	}
	var metadata map[string]json.RawMessage
	if json.Unmarshal(body["metadata"], &metadata) != nil || len(metadata) != 1 {
		c.t.Fatal("status patch must contain only resourceVersion in metadata")
	}
	var rv string
	if json.Unmarshal(metadata["resourceVersion"], &rv) != nil || rv == "" {
		c.t.Fatal("status patch lacks an optimistic-lock resourceVersion")
	}
	current := &tnv1.TailnetGateway{}
	if c.base.Get(ctx, c.key, current) != nil || rv != current.ResourceVersion {
		c.t.Fatal("status patch does not use the version that was read")
	}
	if c.beforePatch != nil {
		c.beforePatch()
	}
	if c.writeErr != nil {
		return c.writeErr
	}
	return c.base.Status().Patch(ctx, obj, patch, opts...)
}

func gatewayTestFixture(suspend *bool) *tnv1.TailnetGateway {
	return &tnv1.TailnetGateway{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gateway", UID: "gateway-uid", Generation: 7, ResourceVersion: "10",
			Labels:          map[string]string{"fixture": "retained"},
			Annotations:     map[string]string{"fixture": gatewayTestCanary},
			Finalizers:      []string{"example.test/retain"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "foreign-owner", UID: "owner-uid"}},
		},
		Spec: tnv1.TailnetGatewaySpec{
			Suspend:          suspend,
			TailnetRef:       tnv1.GatewayLocalReference{Name: gatewayTestCanary},
			Hostname:         gatewayTestCanary,
			StateSecretRef:   tnv1.GatewayLocalReference{Name: gatewayTestCanary},
			AuthKeySecretRef: &tnv1.GatewayAuthKeyReference{Name: gatewayTestCanary, Key: gatewayTestCanary},
			Routes:           tnv1.GatewayRoutes{LAN: []tnv1.GatewayPrefix{"192.0.2.0/24"}},
		},
		Status: tnv1.TailnetGatewayStatus{
			ObservedGeneration: 3, NodeID: "41", IPv4: "100.64.0.41", ServiceIP: "192.0.2.41",
			RoutesAdvertised: []string{"198.51.100.0/24"}, RoutesApproved: []string{"203.0.113.0/24"},
			StaleNodes: []string{"42", "43"},
			RoutePlan:  tnv1.GatewayRouteStatus{AppliedHash: "last-applied", PendingHash: "not-applied", PendingSince: "2025-01-02T03:04:05Z"},
		},
	}
}

func gatewayTestSetup(t *testing.T, gw *tnv1.TailnetGateway) (*gatewayTestClient, context.Context, *strings.Builder) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := tnv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	builder := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&tnv1.TailnetGateway{})
	key := client.ObjectKey{Name: "gateway"}
	if gw != nil {
		builder.WithObjects(gw)
		key = client.ObjectKeyFromObject(gw)
	}
	logs := &strings.Builder{}
	logger := funcr.New(func(prefix, args string) {
		logs.WriteString(prefix)
		logs.WriteString(args)
	}, funcr.Options{Verbosity: 10})
	return &gatewayTestClient{t: t, base: builder.Build(), key: key}, ctrl.LoggerInto(context.Background(), logger), logs
}

func gatewayTestReconcile(t *testing.T, ctx context.Context, c *gatewayTestClient) error {
	t.Helper()
	r := &TailnetGatewayReconciler{Client: c}
	result, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: c.key})
	if result != (ctrl.Result{}) {
		t.Fatal("status-only reconcile unexpectedly requested a requeue")
	}
	return err
}

func gatewayTestGet(t *testing.T, c *gatewayTestClient) *tnv1.TailnetGateway {
	t.Helper()
	gw := &tnv1.TailnetGateway{}
	if err := c.base.Get(context.Background(), c.key, gw); err != nil {
		t.Fatal("cannot read gateway test fixture")
	}
	return gw
}

func gatewayTestAssertStatus(t *testing.T, gw *tnv1.TailnetGateway, reason string) {
	t.Helper()
	if gw.Status.ObservedGeneration != gw.Generation {
		t.Fatal("gateway observedGeneration was not advanced")
	}
	for _, typ := range gatewayTestConditionTypes {
		cond := meta.FindStatusCondition(gw.Status.Conditions, typ)
		want := metav1.ConditionUnknown
		if typ == "Ready" {
			want = metav1.ConditionFalse
		}
		if cond == nil || cond.Status != want || cond.Reason != reason || cond.ObservedGeneration != gw.Generation {
			t.Fatalf("condition %s does not reflect the blocked runtime", typ)
		}
		if strings.TrimSpace(cond.Message) == "" || strings.Contains(cond.Message, gatewayTestCanary) || cond.LastTransitionTime.IsZero() {
			t.Fatalf("condition %s has an unsafe or incomplete message/timestamp", typ)
		}
	}
}

func gatewayTestAssertPreserved(t *testing.T, before, after *tnv1.TailnetGateway) {
	t.Helper()
	// The status write may only change the resource version, observed generation
	// and owned conditions. Historic applied state is deliberately not acknowledged.
	got, want := after.DeepCopy(), before.DeepCopy()
	got.ResourceVersion = want.ResourceVersion
	got.Status.ObservedGeneration = want.Status.ObservedGeneration
	got.Status.Conditions = want.Status.Conditions
	if !reflect.DeepEqual(got, want) {
		t.Fatal("gateway metadata, spec or historic runtime status changed")
	}
}

func TestTailnetGatewayBlockedStatus(t *testing.T) {
	for _, tc := range []struct {
		name    string
		suspend *bool
		reason  string
	}{
		{"nil-safe-default", nil, "Suspended"},
		{"suspended", new(true), "Suspended"},
		{"false-admission-bypassed", new(false), "RuntimeUnavailable"},
	} {
		for _, stale := range []bool{false, true} {
			name := tc.name + "/empty-conditions"
			if stale {
				name = tc.name + "/stale-true-conditions"
			}
			t.Run(name, func(t *testing.T) {
				gw := gatewayTestFixture(tc.suspend)
				oldTime := metav1.NewTime(time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC))
				foreign := metav1.Condition{Type: "ForeignController", Status: metav1.ConditionTrue, Reason: "Retained", Message: "not ours", ObservedGeneration: 2, LastTransitionTime: oldTime}
				if stale {
					gw.Status.Conditions = []metav1.Condition{foreign}
					for _, typ := range gatewayTestConditionTypes {
						gw.Status.Conditions = append(gw.Status.Conditions, metav1.Condition{Type: typ, Status: metav1.ConditionTrue, Reason: "OldRuntime", Message: gatewayTestCanary, ObservedGeneration: 3, LastTransitionTime: oldTime})
					}
				}
				c, ctx, logs := gatewayTestSetup(t, gw)
				before := gatewayTestGet(t, c)
				if gatewayTestReconcile(t, ctx, c) != nil {
					t.Fatal("blocked status reconciliation failed")
				}
				got := gatewayTestGet(t, c)
				gatewayTestAssertStatus(t, got, tc.reason)
				gatewayTestAssertPreserved(t, before, got)
				wantCount := len(gatewayTestConditionTypes)
				if stale {
					wantCount++
					if cond := meta.FindStatusCondition(got.Status.Conditions, foreign.Type); cond == nil || !reflect.DeepEqual(cond, meta.FindStatusCondition(before.Status.Conditions, foreign.Type)) {
						t.Fatal("foreign condition changed")
					}
					for _, typ := range gatewayTestConditionTypes {
						if meta.FindStatusCondition(got.Status.Conditions, typ).LastTransitionTime.Equal(&oldTime) {
							t.Fatalf("condition %s retained its old True transition time", typ)
						}
					}
				}
				if len(got.Status.Conditions) != wantCount || c.gets != 1 || c.patches != 1 {
					t.Fatal("unexpected condition count or client calls")
				}
				if strings.Contains(logs.String(), gatewayTestCanary) {
					t.Fatal("credential leaked into reconcile logs")
				}

				// Repeated reconciliation must not even issue an empty patch.
				if gatewayTestReconcile(t, ctx, c) != nil {
					t.Fatal("unchanged reconciliation failed")
				}
				if c.patches != 1 || c.gets != 2 || !reflect.DeepEqual(got, gatewayTestGet(t, c)) {
					t.Fatal("unchanged reconcile wrote status, reordered conditions or changed transition times")
				}
			})
		}
	}
}

func TestTailnetGatewayCurrentConditionsAndGeneration(t *testing.T) {
	for _, suspend := range []bool{true, false} {
		reason := "Suspended"
		if !suspend {
			reason = "RuntimeUnavailable"
		}
		t.Run(reason, func(t *testing.T) {
			c, ctx, _ := gatewayTestSetup(t, gatewayTestFixture(&suspend))
			if gatewayTestReconcile(t, ctx, c) != nil {
				t.Fatal("initial reconciliation failed")
			}
			gw := gatewayTestGet(t, c)
			// Seed already-correct conditions in a different order with fixed old
			// transition times. Idempotence must not depend on controller ordering.
			oldTime := metav1.NewTime(time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC))
			for i, j := 0, len(gw.Status.Conditions)-1; i < j; i, j = i+1, j-1 {
				gw.Status.Conditions[i], gw.Status.Conditions[j] = gw.Status.Conditions[j], gw.Status.Conditions[i]
			}
			for i := range gw.Status.Conditions {
				gw.Status.Conditions[i].LastTransitionTime = oldTime
			}
			if c.base.Status().Update(ctx, gw) != nil {
				t.Fatal("cannot seed current status")
			}
			before := gatewayTestGet(t, c)
			if gatewayTestReconcile(t, ctx, c) != nil || c.patches != 1 || !reflect.DeepEqual(before, gatewayTestGet(t, c)) {
				t.Fatal("already-current status was rewritten")
			}
			gw = gatewayTestGet(t, c)
			gw.Generation++
			if c.base.Update(ctx, gw) != nil {
				t.Fatal("cannot advance fixture generation")
			}
			before = gatewayTestGet(t, c)
			if gatewayTestReconcile(t, ctx, c) != nil {
				t.Fatal("new generation reconciliation failed")
			}
			got := gatewayTestGet(t, c)
			gatewayTestAssertStatus(t, got, reason)
			gatewayTestAssertPreserved(t, before, got)
			wantConditions := append([]metav1.Condition(nil), before.Status.Conditions...)
			for i := range wantConditions {
				wantConditions[i].ObservedGeneration = got.Generation
			}
			if c.patches != 2 || !reflect.DeepEqual(wantConditions, got.Status.Conditions) {
				t.Fatal("generation change reordered conditions or changed stable transition times")
			}
			// A stale top-level observedGeneration also needs correction when all
			// individual conditions already describe the current generation.
			got.Status.ObservedGeneration--
			if c.base.Status().Update(ctx, got) != nil {
				t.Fatal("cannot seed stale observedGeneration")
			}
			if gatewayTestReconcile(t, ctx, c) != nil || c.patches != 3 {
				t.Fatal("stale observedGeneration was not corrected")
			}
			gatewayTestAssertStatus(t, gatewayTestGet(t, c), reason)
		})
	}
}

func TestTailnetGatewayMissingAndDeleting(t *testing.T) {
	t.Run("not-found", func(t *testing.T) {
		c, ctx, _ := gatewayTestSetup(t, nil)
		if gatewayTestReconcile(t, ctx, c) != nil || c.gets != 1 || c.patches != 0 {
			t.Fatal("missing gateway must be a read-only success")
		}
	})
	for _, suspend := range []*bool{nil, new(true), new(false)} {
		gw := gatewayTestFixture(suspend)
		now := metav1.Now()
		gw.DeletionTimestamp = &now
		c, ctx, _ := gatewayTestSetup(t, gw)
		before := gatewayTestGet(t, c)
		if gatewayTestReconcile(t, ctx, c) != nil || c.gets != 1 || c.patches != 0 || !reflect.DeepEqual(before, gatewayTestGet(t, c)) {
			t.Fatal("deleting gateway was changed or its finalizer was removed")
		}
	}
}

func TestTailnetGatewayErrorsAreRedactedAndUnwrap(t *testing.T) {
	resource := schema.GroupResource{Group: "tsunaro.io", Resource: "tailnetgateways"}
	for _, operation := range []string{"read", "write"} {
		for _, kind := range []string{"ordinary", "conflict", "forbidden"} {
			t.Run(operation+"/"+kind, func(t *testing.T) {
				cause := errors.New("Bearer " + gatewayTestCanary)
				switch kind {
				case "conflict":
					cause = apierrors.NewConflict(resource, gatewayTestCanary, cause)
				case "forbidden":
					cause = apierrors.NewForbidden(resource, gatewayTestCanary, cause)
				}
				c, ctx, logs := gatewayTestSetup(t, gatewayTestFixture(nil))
				before := gatewayTestGet(t, c)
				want := "gateway resource read failed"
				wantPatches := 0
				if operation == "read" {
					c.readErr = cause
				} else {
					c.writeErr = cause
					want = "gateway status write failed"
					wantPatches = 1
				}
				err := gatewayTestReconcile(t, ctx, c)
				if err == nil || err.Error() != want {
					t.Fatal("error did not use the fixed redacted text (details withheld)")
				}
				if !errors.Is(err, cause) || errors.Unwrap(err) == nil {
					t.Fatal("redacted error lost its cause")
				}
				if apierrors.IsConflict(err) != (kind == "conflict") || apierrors.IsForbidden(err) != (kind == "forbidden") {
					t.Fatal("redacted error lost API error classification")
				}
				if strings.Contains(logs.String(), gatewayTestCanary) {
					t.Fatal("API error credential leaked into logs")
				}
				if c.gets != 1 || c.patches != wantPatches || !reflect.DeepEqual(before, gatewayTestGet(t, c)) {
					t.Fatal("failed reconcile changed persisted state or made unexpected calls")
				}
			})
		}
	}
	t.Run("unsafe-not-found-is-ignored", func(t *testing.T) {
		c, ctx, logs := gatewayTestSetup(t, nil)
		c.readErr = apierrors.NewNotFound(resource, gatewayTestCanary)
		if gatewayTestReconcile(t, ctx, c) != nil || c.patches != 0 || strings.Contains(logs.String(), gatewayTestCanary) {
			t.Fatal("NotFound was not safely ignored")
		}
	})
}

func TestTailnetGatewayStatusConflictPreservesConcurrentWriter(t *testing.T) {
	c, ctx, logs := gatewayTestSetup(t, gatewayTestFixture(nil))
	var concurrent *tnv1.TailnetGateway
	c.beforePatch = func() {
		current := gatewayTestGet(t, c)
		current.Status.NodeID = "99"
		current.Status.RoutePlan.AppliedHash = "concurrent-applied"
		current.Status.Conditions = append(current.Status.Conditions, metav1.Condition{
			Type: "ConcurrentWriter", Status: metav1.ConditionTrue, Reason: "Retained", Message: "concurrent observation",
			ObservedGeneration: current.Generation, LastTransitionTime: metav1.Now(),
		})
		if c.base.Status().Update(ctx, current) != nil {
			t.Fatal("cannot simulate concurrent status writer")
		}
		concurrent = gatewayTestGet(t, c)
	}
	err := gatewayTestReconcile(t, ctx, c)
	if err == nil || !apierrors.IsConflict(err) || err.Error() != "gateway status write failed" {
		t.Fatal("stale status patch did not return a sanitized conflict")
	}
	if c.patches != 1 || concurrent == nil || !reflect.DeepEqual(concurrent, gatewayTestGet(t, c)) {
		t.Fatal("conflicting patch clobbered the intervening writer")
	}
	c.beforePatch = nil
	if gatewayTestReconcile(t, ctx, c) != nil {
		t.Fatal("fresh reconcile after conflict failed")
	}
	got := gatewayTestGet(t, c)
	gatewayTestAssertStatus(t, got, "Suspended")
	gatewayTestAssertPreserved(t, concurrent, got)
	if !reflect.DeepEqual(meta.FindStatusCondition(concurrent.Status.Conditions, "ConcurrentWriter"), meta.FindStatusCondition(got.Status.Conditions, "ConcurrentWriter")) {
		t.Fatal("fresh reconcile lost the concurrent foreign condition")
	}
	if strings.Contains(logs.String(), gatewayTestCanary) {
		t.Fatal("conflict logs leaked fixture input")
	}
}

func TestTailnetGatewayMessagesDoNotDependOnInput(t *testing.T) {
	for _, suspend := range []bool{true, false} {
		var first map[string]string
		for _, marker := range []string{gatewayTestCanary, "different-private-fixture"} {
			gw := gatewayTestFixture(&suspend)
			gw.Name = marker
			gw.Spec.Hostname = marker
			gw.Spec.TailnetRef.Name = tnv1.GatewayName(marker)
			gw.Spec.StateSecretRef.Name = tnv1.GatewayName(marker)
			gw.Spec.AuthKeySecretRef = &tnv1.GatewayAuthKeyReference{Name: tnv1.GatewayName(marker), Key: marker}
			c, ctx, _ := gatewayTestSetup(t, gw)
			if gatewayTestReconcile(t, ctx, c) != nil {
				t.Fatal("message fixture reconciliation failed")
			}
			messages := map[string]string{}
			for _, cond := range gatewayTestGet(t, c).Status.Conditions {
				if strings.Contains(cond.Message, marker) {
					t.Fatal("condition message disclosed object input")
				}
				messages[cond.Type] = cond.Message
			}
			if first == nil {
				first = messages
			} else if !reflect.DeepEqual(first, messages) {
				t.Fatal("condition messages are not fixed across object inputs")
			}
		}
	}
}
