package controller

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// emitReadyChange records exactly one event per Ready-reason flip: a Normal event when a resource
// turns Ready, a Warning otherwise, nothing on an unchanged reason, and no panic without a recorder.
func TestEmitReadyChange(t *testing.T) {
	obj := &tnv1.TailnetIngress{}

	emitReadyChange(nil, obj, "A", "B") // must not panic without a recorder

	cases := []struct {
		old, new string
		want     string // "" means no event
	}{
		{"", "Registered", corev1.EventTypeWarning},
		{"SourceTagUnknown", "Ready", corev1.EventTypeNormal},
		{"Ready", "Ready", ""},
	}
	for _, tc := range cases {
		rec := record.NewFakeRecorder(4)
		emitReadyChange(rec, obj, tc.old, tc.new)
		select {
		case ev := <-rec.Events:
			if tc.want == "" {
				t.Fatalf("%s->%s: unexpected event %q", tc.old, tc.new, ev)
			}
			if !strings.HasPrefix(ev, tc.want) || !strings.Contains(ev, tc.new) {
				t.Fatalf("%s->%s: event %q, want type %s mentioning %s", tc.old, tc.new, ev, tc.want, tc.new)
			}
		default:
			if tc.want != "" {
				t.Fatalf("%s->%s: expected a %s event, got none", tc.old, tc.new, tc.want)
			}
		}
	}
}
