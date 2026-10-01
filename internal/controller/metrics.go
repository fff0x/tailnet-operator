package controller

import (
	"context"
	"reflect"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/client"
	operatormetrics "this-is-fine.io/tailnet-operator/internal/metrics"
)

type observedStatusKey struct {
	kind reflect.Type
	name client.ObjectKey
}

type observedStatusLock struct {
	mu   sync.Mutex
	refs int // Holder plus waiting callers; guarded by observedStatusLocks.mu.
}

var observedStatusLocks = struct {
	mu      sync.Mutex
	entries map[observedStatusKey]*observedStatusLock
}{entries: make(map[observedStatusKey]*observedStatusLock)}

func lockObservedStatus(obj client.Object) func() {
	// Concrete types identify kinds even when TypeMeta is unset on typed resources.
	key := observedStatusKey{kind: reflect.TypeOf(obj), name: client.ObjectKeyFromObject(obj)}
	observedStatusLocks.mu.Lock()
	entry := observedStatusLocks.entries[key]
	if entry == nil {
		entry = &observedStatusLock{}
		observedStatusLocks.entries[key] = entry
	}
	entry.refs++ // Retain the entry before waiting so callers cannot split across locks.
	observedStatusLocks.mu.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		observedStatusLocks.mu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(observedStatusLocks.entries, key)
		}
		observedStatusLocks.mu.Unlock()
	}
}

// Tailnet and policy controllers share status. Serialize persistence plus observation per
// object so older writes cannot publish after newer writes, without blocking unrelated CRs.
func updateObservedStatus(ctx context.Context, c client.Client, m *operatormetrics.Metrics, obj client.Object) error {
	unlock := lockObservedStatus(obj)
	defer unlock()
	if err := c.Status().Update(ctx, obj); err != nil {
		return err
	}
	m.Observe(obj)
	return nil
}

// Observe the server-returned snapshot only after a successful status patch.
// Callers use an optimistic-lock patch when later child writes depend on it.
func patchObservedStatus(ctx context.Context, c client.Client, m *operatormetrics.Metrics, obj client.Object, patch client.Patch) error {
	unlock := lockObservedStatus(obj)
	defer unlock()
	if err := c.Status().Patch(ctx, obj, patch); err != nil {
		return err
	}
	m.Observe(obj)
	return nil
}
