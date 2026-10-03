package main

import (
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestParseAgentResources(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      corev1.ResourceRequirements
	}{
		{name: "absent or empty"},
		{name: "empty object", raw: `{}`},
		{name: "null maps", raw: `{"requests":null,"limits":null}`},
		{name: "empty maps", raw: `{"requests":{},"limits":{}}`, want: corev1.ResourceRequirements{Requests: corev1.ResourceList{}, Limits: corev1.ResourceList{}}},
		{name: "chart defaults", raw: `{"requests":{"cpu":"10m","memory":"32Mi"},"limits":{"memory":"128Mi"}}`, want: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("32Mi")},
			Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("128Mi")},
		}},
		{name: "equal quantities and whitespace", raw: " \n{\"requests\":{\"cpu\":1},\"limits\":{\"cpu\":1}}\t", want: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")},
		}},
		{name: "zero", raw: `{"requests":{"cpu":"0"}}`, want: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("0")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAgentResources(tc.raw)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, %v; want %#v", got, err, tc.want)
			}
		})
	}
}

func TestParseAgentResourcesRejectsInvalidWithoutEcho(t *testing.T) {
	for _, raw := range []string{
		` `, `null`, `[]`, `"private-input"`, `42`, `true`, `{`,
		`{} {}`, `{} null`, `{} private-input`,
		`{"private-input":{}}`, `{"requests":[]}`, `{"limits":"private-input"}`,
		`{"requests":{"cpu":"private-input"}}`, `{"limits":{"memory":{}}}`,
		`{"requests":{"private-input":"-1"}}`, `{"limits":{"private-input":"-1Mi"}}`,
		`{"requests":{"cpu":"1001m"},"limits":{"cpu":"1"}}`,
		`{"requests":{"memory":"1Gi"},"limits":{"memory":"1000Mi"}}`,
		`{"requests":{"cpu":"1m"},"limits":{"cpu":"0"}}`,
		`{"claims":[{"name":"ok","private-input":"secret"}]}`,
	} {
		t.Run(raw, func(t *testing.T) {
			got, err := parseAgentResources(raw)
			if err == nil {
				t.Fatal("accepted invalid resources")
			}
			if strings.Contains(err.Error(), "private-input") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe error: %v", err)
			}
			if !reflect.DeepEqual(got, corev1.ResourceRequirements{}) {
				t.Fatal("error returned partially parsed resources")
			}
		})
	}
}
