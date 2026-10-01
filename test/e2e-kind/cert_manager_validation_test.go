//go:build e2e_kind

package e2ekind

import (
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestCertManagerRenewalRejection(t *testing.T) {
	denied := func(code int32, message string) error {
		return &apierrors.StatusError{ErrStatus: metav1.Status{Code: code, Reason: metav1.StatusReasonForbidden, Message: message}}
	}
	exact := `admission webhook "webhook.cert-manager.io" denied the request: spec.renewBefore: Invalid value: "2h": must be less than duration`
	invalid := func(path string) error {
		return apierrors.NewInvalid(schema.GroupKind{Group: "cert-manager.io", Kind: "Certificate"}, "fixture", field.ErrorList{field.Invalid(field.NewPath("spec", path), "2h", "must be less than duration")})
	}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"structured-field", invalid("renewBefore"), true},
		{"webhook-forbidden", denied(403, exact), true},
		{"webhook-bad-request", denied(400, exact), true},
		{"accepted", nil, false},
		{"plain-error", errors.New(exact), false},
		{"generic-rbac", denied(403, "certificates is forbidden"), false},
		{"webhook-transport", denied(500, exact), false},
		{"different-field", invalid("duration"), false},
		{"different-webhook", denied(403, `admission webhook "unrelated.invalid" denied the request: spec.renewBefore`), false},
		{"missing-field", denied(403, `admission webhook "webhook.cert-manager.io" denied the request: another reason`), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cmInvalidRenewal(tc.err); got != tc.want {
				t.Fatalf("classification=%t, want=%t", got, tc.want)
			}
		})
	}
}
