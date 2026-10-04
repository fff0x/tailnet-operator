package migration

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A new gateway API is not a fourth legacy parent pair. Fail at discovery,
// even when the gateway CRD has no instances, before listing or writing objects.
func TestPlanInventoryRejectsGatewayAPI(t *testing.T) {
	baseline := newInventoryFixture()
	if _, err := baseline.plan(t); err != nil {
		t.Fatalf("legacy three-kind baseline: %v", err)
	}
	f := newInventoryFixture()
	for _, catalog := range f.discovery.catalog {
		if catalog.GroupVersion == APIVersion {
			catalog.APIResources = append(catalog.APIResources, metav1.APIResource{
				Name: "tailnetgateways", Kind: "TailnetGateway", Namespaced: false,
				Verbs: metav1.Verbs{"get", "list", "watch"},
			})
		}
	}
	inventoryFailure(t, f, ErrInvalid)
	if len(f.calls) != 0 {
		t.Fatal("unsupported gateway discovery reached object inventory")
	}
}
