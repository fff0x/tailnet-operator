package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// parseAgentResources accepts one non-null ResourceRequirements JSON object.
// An absent/empty environment variable or {} preserves the direct binary's zero
// default. Never return decoder errors or resource names/values: they can contain
// arbitrary environment contents, which must not reach startup logs.
func parseAgentResources(raw string) (corev1.ResourceRequirements, error) {
	var resources corev1.ResourceRequirements
	if raw == "" {
		return resources, nil
	}
	invalid := func() (corev1.ResourceRequirements, error) {
		return corev1.ResourceRequirements{}, fmt.Errorf("must be one non-null ResourceRequirements JSON object with known fields and valid quantities")
	}
	if !strings.HasPrefix(strings.TrimSpace(raw), "{") {
		return invalid()
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&resources); err != nil {
		return invalid()
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return invalid()
	}
	for _, list := range []corev1.ResourceList{resources.Requests, resources.Limits} {
		for _, quantity := range list {
			if quantity.Sign() < 0 {
				return corev1.ResourceRequirements{}, fmt.Errorf("resource quantities must not be negative")
			}
		}
	}
	for name, request := range resources.Requests {
		if limit, ok := resources.Limits[name]; ok && request.Cmp(limit) > 0 {
			return corev1.ResourceRequirements{}, fmt.Errorf("resource requests must not exceed matching limits")
		}
	}
	return resources, nil
}
