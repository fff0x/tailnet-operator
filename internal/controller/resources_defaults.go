package controller

import corev1 "k8s.io/api/core/v1"

// agentResources selects a whole block, never merging individual keys. Preserve
// the existing unset test: nil requests AND nil limits fall through, but either
// non-nil map (even empty) selects that tier. Copy quantities as well as maps so
// deployments never alias CR/cache objects, defaults or one another.
func agentResources(cr, tailnet, defaults corev1.ResourceRequirements) corev1.ResourceRequirements {
	if cr.Requests != nil || cr.Limits != nil {
		return *cr.DeepCopy()
	}
	if tailnet.Requests != nil || tailnet.Limits != nil {
		return *tailnet.DeepCopy()
	}
	return *defaults.DeepCopy()
}
