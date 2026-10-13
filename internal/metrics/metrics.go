// Package metrics owns operator collectors. It observes persisted status, never messages,
// credentials, peer addresses or dynamic Headscale paths.
package metrics

import (
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

type identity struct{ kind, namespace, name string }
type history struct {
	uid        types.UID
	generation int64
	tailnet    string
	conditions map[[2]string]bool
}

// Metrics is one collector so Register is atomic and repeated manager construction shares
// both vectors and object history. New isolated registries get independent collectors.
type Metrics struct {
	mu                                                                     sync.Mutex
	objects                                                                map[identity]*history
	collectors                                                             []prometheus.Collector
	ready, condition, target, expose, generated                            *prometheus.GaugeVec
	apiExpiry, authExpiry, routesMissing, ingressExpiry, backends, applied *prometheus.GaugeVec
	pending, userConflicts                                                 *prometheus.GaugeVec
	nodeOnline, nodeLastSeen                                               *prometheus.GaugeVec
	policyApplyErrors                                                      *prometheus.CounterVec
	approvals, requests                                                    *prometheus.CounterVec
	writeDuration, apiDuration                                             *prometheus.HistogramVec
}

func New() *Metrics {
	m := &Metrics{objects: map[identity]*history{}}
	gauge := func(name, help string, labels ...string) *prometheus.GaugeVec {
		v := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labels)
		m.collectors = append(m.collectors, v)
		return v
	}
	counter := func(name, help string, labels ...string) *prometheus.CounterVec {
		v := prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
		m.collectors = append(m.collectors, v)
		return v
	}
	histogram := func(name, help string, labels ...string) *prometheus.HistogramVec {
		v := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: name, Help: help}, labels)
		m.collectors = append(m.collectors, v)
		return v
	}
	m.nodeOnline = gauge("tailnet_node_online", "One when a successful Headscale node list contains an online node matching this resource's tag and hostname; absent without a current observation.", "kind", "namespace", "name")
	m.nodeLastSeen = gauge("tailnet_node_last_seen_seconds", "Unix timestamp of Headscale lastSeen for the selected matching node; absent when unknown.", "kind", "namespace", "name")
	m.ready = gauge("tailnet_resource_ready", "Current-generation Ready condition is True; absent without a current Ready condition.", "kind", "namespace", "name", "tailnet")
	m.condition = gauge("tailnet_resource_condition", "Current-generation condition reason (including False and Unknown); previously observed reasons are zero.", "kind", "namespace", "name", "type", "reason")
	m.target = gauge("tailnet_egress_target_state", "Current-generation target route reason; Present represents an empty successful route reason.", "namespace", "name", "target", "reason")
	m.expose = gauge("tailnet_ingress_expose_reachable", "Current-generation expose backend reachability.", "namespace", "name", "expose")
	m.generated = gauge("tailnet_policy_generated", "Generated entries in persisted policy status.", "tailnet", "kind")
	m.userConflicts = gauge("tailnet_headscale_user_conflicts", "Number of Headscale user names carried by more than one user (status.userConflicts); such a collision makes Headscale reject every policy write. Absent without a current UsersUnique verdict.", "tailnet")
	m.pending = gauge("tailnet_policy_pending", "One when Apply mode has a nonempty persisted rendered hash different from the applied hash; zero otherwise. Absent without policy status.", "tailnet")
	m.writeDuration = histogram("tailnet_policy_write_duration_seconds", "SetPolicy operation latency including failures.", "tailnet")
	m.approvals = counter("tailnet_route_approvals_replayed_total", "New routes successfully approved by replay, counted per route, not per request.", "tailnet")
	m.requests = counter("tailnet_headscale_api_requests_total", "Headscale operations; code 0 means no response.", "tailnet", "method", "path_template", "code")
	m.apiDuration = histogram("tailnet_headscale_api_duration_seconds", "Headscale operation latency including failures.", "tailnet", "method", "path_template", "code")
	m.apiExpiry = gauge("tailnet_apikey_expires_seconds", "Seconds until the operator's working Headscale API key expires.", "tailnet")
	m.authExpiry = gauge("tailnetegress_authkey_expires_seconds", "Seconds until a TailnetEgress pre-auth key expires.", "namespace", "name")
	m.routesMissing = gauge("tailnetegress_routes_missing", "Deprecated: use tailnet_egress_target_state. Number of target routes missing from a TailnetEgress netmap.", "namespace", "name")
	m.ingressExpiry = gauge("tailnetingress_authkey_expires_seconds", "Seconds until a TailnetIngress pre-auth key expires.", "namespace", "name")
	m.backends = gauge("tailnetingress_backends_unreachable", "Deprecated: use tailnet_ingress_expose_reachable. Number of in-cluster backends a TailnetIngress agent could not reach.", "namespace", "name")
	m.applied = gauge("tailnet_policy_applied_timestamp_seconds", "Unix time the rendered policy was last applied to the control server.", "tailnet")
	m.policyApplyErrors = counter("tailnet_policy_apply_errors_total", "Policy writes the control server rejected or that failed.", "tailnet")
	return m
}

func Register(reg prometheus.Registerer) (*Metrics, error) {
	m := New()
	if err := reg.Register(m); err != nil {
		var duplicate prometheus.AlreadyRegisteredError
		if errors.As(err, &duplicate) {
			if existing, ok := duplicate.ExistingCollector.(*Metrics); ok {
				return existing, nil
			}
		}
		return nil, err
	}
	return m, nil
}
func (m *Metrics) Describe(ch chan<- *prometheus.Desc) {
	for _, c := range m.collectors {
		c.Describe(ch)
	}
}
func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.collectors {
		c.Collect(ch)
	}
}
func (m *Metrics) Headscale(tailnet string) headscale.Observer {
	if m == nil {
		return nil
	}
	return func(method, path string, code int, elapsed time.Duration) {
		labels := []string{tailnet, method, path, strconv.Itoa(code)}
		m.requests.WithLabelValues(labels...).Inc()
		m.apiDuration.WithLabelValues(labels...).Observe(elapsed.Seconds())
		if method == "PUT" && path == "/api/v1/policy" {
			m.writeDuration.WithLabelValues(tailnet).Observe(elapsed.Seconds())
		}
	}
}
func (m *Metrics) Approved(tailnet string, count int) {
	if m != nil {
		m.approvals.WithLabelValues(tailnet).Add(float64(count))
	}
}
func (m *Metrics) PolicyError(tailnet string, failed bool) {
	if m != nil {
		v := m.policyApplyErrors.WithLabelValues(tailnet)
		if failed {
			v.Inc()
		} else {
			v.Add(0)
		}
	}
}

// Delete drops object gauges and reason history. Operational counters/histograms remain cumulative.
func (m *Metrics) Delete(kind, namespace, name string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delete(identity{kind, namespace, name})
}
func (m *Metrics) delete(id identity) {
	labels := prometheus.Labels{"kind": id.kind, "namespace": id.namespace, "name": id.name}
	m.ready.DeletePartialMatch(labels)
	m.condition.DeletePartialMatch(labels)
	m.nodeOnline.DeletePartialMatch(labels)
	m.nodeLastSeen.DeletePartialMatch(labels)
	object := prometheus.Labels{"namespace": id.namespace, "name": id.name}
	switch id.kind {
	case "TailnetEgress":
		m.target.DeletePartialMatch(object)
		m.authExpiry.DeletePartialMatch(object)
		m.routesMissing.DeletePartialMatch(object)
	case "TailnetIngress":
		m.expose.DeletePartialMatch(object)
		m.ingressExpiry.DeletePartialMatch(object)
		m.backends.DeletePartialMatch(object)
	case "Tailnet":
		m.generated.DeletePartialMatch(prometheus.Labels{"tailnet": id.name})
		m.apiExpiry.DeleteLabelValues(id.name)
		m.applied.DeleteLabelValues(id.name)
		m.pending.DeleteLabelValues(id.name)
		m.userConflicts.DeleteLabelValues(id.name)
	}
	delete(m.objects, id)
}

func conditionType(s string) string {
	switch s {
	case "Ready", "ApiKeyValid", "ApiReachable", "PolicyMode", "HeadscaleCompatible", "SplitDNS", "UsersUnique", "PolicyRendered", "PolicyApplied", "TagKnown", "Registered", "ServiceConflict", "RoutesGranted", "TargetsReachable", "BackendsReachable", "PolicyGranted", "TLSReady", "TLSCleanup", "RouteConflict", "UnmanagedOverlap", "Advertised", "Approved",
		"RoutesInSync", "DNSReady", "StaleNodes", "ClusterDNSForward", "WorkloadCurrent", "ServiceReady":
		return s
	default:
		return "Other"
	}
}
func reason(s string) string {
	switch s {
	case "Error", "Unreachable", "Unhealthy", "Reachable", "Rejected", "Valid", "CannotVerify", "Database", "File", "ProbeFailed", "Unique", "Duplicate", "Incompatible", "Compatible", "NoTailnet", "NoAPIKey", "InvalidTag", "InvalidHostname", "InvalidDNSName", "PolicyUnreadable", "Unknown", "PolicyPending", "TagUnknown", "Known", "AuthKey", "Apply", "ListNodes", "Conflict", "NotRegistered", "Registered", "AllGranted", "RoutesMissing", "AllReachable", "NotReady", "Ready", "PolicyDenied", "Granted", "BaseMissing", "BaseInvalid", "PolicyEmpty", "Rendered", "DryRun", "PolicyModeFile", "InSync", "PolicyRejected", "ApplyFailed", "Applied", "Present", "NotAdvertised", "NotApproved", "NoGrant",
		"TLSReady", "TLSConfigurationMissing", "TLSConfigurationInvalid", "TLSInvalidDNSName",
		"TLSSecretMissing", "TLSSecretInvalid", "TLSSecretConflict", "TLSSecretForbidden", "TLSSecretUnavailable",
		"TLSCertificateInvalid", "TLSCertificateNotYetValid", "TLSCertificateExpired", "TLSCertificatePending",
		"TLSCertificateUnavailable", "TLSCertificateForbidden", "TLSCertificateConflict", "CertManagerMissing",
		"TLSProbePending", "TLSProbeFailed", "TLSProbeStale", "TLSConfigMismatch", "TLSCertificateMismatch",
		"DNSNameConflict", "DNSConflictUnresolved", "DNSEgressTargetInvalid", "DNSEgressAliasInvalid",
		"DNSEgressAliasAmbiguous", "DNSClaimIdentityInvalid", "DNSClaimInputInvalid",
		"OverlapsReserved", "OverlapsSite", "Unmanaged", "None", "NotObserved", "Advertised", "Approved", "RouteConflict",
		"FreshBlocked", "IdentityChanged", "Provisioning", "FreshRuntimeReady", "RuntimeUnavailable", "ExternallyManaged",
		"DNSInSync", "DNSUpdateConflict", "DNSUpdateBlocked", "LBPending", "LoadBalancerAssigned":
		return s
	default:
		return "Other"
	}
}
func truth(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

// Observe accepts only successfully persisted resources. Condition observedGeneration, rather
// than the roll-up status generation, controls freshness because controllers share Tailnet status.
func (m *Metrics) Observe(obj metav1.Object) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var kind, tailnet string
	var conditions []metav1.Condition
	switch o := obj.(type) {
	case *tnv1.Tailnet:
		kind = "Tailnet"
		tailnet = o.Name
		conditions = o.Status.Conditions
	case *tnv1.TailnetEgress:
		kind = "TailnetEgress"
		tailnet = o.Spec.TailnetRef.Name
		conditions = o.Status.Conditions
	case *tnv1.TailnetIngress:
		kind = "TailnetIngress"
		tailnet = o.Spec.TailnetRef.Name
		conditions = o.Status.Conditions
	case *tnv1.TailnetSite:
		kind = "TailnetSite"
		tailnet = o.Spec.TailnetRef.Name
		conditions = o.Status.Conditions
	case *tnv1.TailnetGateway:
		kind = "TailnetGateway"
		tailnet = string(o.Spec.TailnetRef.Name)
		conditions = o.Status.Conditions
		// A suspended gateway reports Ready=False/Suspended by design; exporting it would page
		// TailnetResourceNotReady forever. Suspended gateways are absent from the gauges.
		if o.Spec.Suspend == nil || *o.Spec.Suspend {
			m.delete(identity{kind, "", o.Name})
			return
		}
	default:
		return
	}
	id := identity{kind, obj.GetNamespace(), obj.GetName()}
	h := m.objects[id]
	if h != nil && (h.uid != obj.GetUID() || h.tailnet != tailnet) {
		m.delete(id)
		h = nil
	}
	if h == nil {
		h = &history{uid: obj.GetUID(), tailnet: tailnet, conditions: map[[2]string]bool{}}
		m.objects[id] = h
	}
	h.generation = obj.GetGeneration()
	labels := []string{kind, id.namespace, id.name}
	m.ready.DeletePartialMatch(prometheus.Labels{"kind": kind, "namespace": id.namespace, "name": id.name})
	for pair := range h.conditions {
		h.conditions[pair] = false
	}
	for _, c := range conditions {
		if c.ObservedGeneration != obj.GetGeneration() {
			continue
		}
		h.conditions[[2]string{conditionType(c.Type), reason(c.Reason)}] = true
		if c.Type == "Ready" {
			m.ready.WithLabelValues(kind, id.namespace, id.name, tailnet).Set(truth(c.Status == metav1.ConditionTrue))
		}
	}
	for pair, active := range h.conditions {
		m.condition.WithLabelValues(append(append([]string{}, labels...), pair[0], pair[1])...).Set(truth(active))
	}
	current := func(t string) bool {
		for _, c := range conditions {
			if c.Type == t && c.ObservedGeneration == obj.GetGeneration() {
				return true
			}
		}
		return false
	}
	object := prometheus.Labels{"namespace": id.namespace, "name": id.name}
	switch o := obj.(type) {
	case *tnv1.Tailnet:
		m.apiExpiry.DeleteLabelValues(o.Name)
		if o.Status.APIKeyExpiresAt != nil {
			m.apiExpiry.WithLabelValues(o.Name).Set(time.Until(o.Status.APIKeyExpiresAt.Time).Seconds())
		}
		m.generated.DeletePartialMatch(prometheus.Labels{"tailnet": o.Name})
		m.applied.DeleteLabelValues(o.Name)
		m.pending.DeleteLabelValues(o.Name)
		m.userConflicts.DeleteLabelValues(o.Name)
		for _, c := range conditions {
			if c.Type == "UsersUnique" && c.ObservedGeneration == o.Generation && c.Status != metav1.ConditionUnknown {
				m.userConflicts.WithLabelValues(o.Name).Set(float64(o.Status.UserConflicts))
			}
		}
		if o.Status.Policy != nil {
			p := o.Status.Policy
			// AppliedAt deliberately stays fixed for unchanged InSync policies. Alert on
			// pending==1 for a duration, not on the age of that successful application.
			m.pending.WithLabelValues(o.Name).Set(truth(o.Spec.Policy.Mode == "Apply" && p.RenderedHash != "" && p.RenderedHash != p.AppliedHash))
			if current("PolicyRendered") {
				m.generated.WithLabelValues(o.Name, "tags").Set(float64(p.Generated.Tags))
				m.generated.WithLabelValues(o.Name, "grants").Set(float64(p.Generated.Grants))
				m.generated.WithLabelValues(o.Name, "routes").Set(float64(p.Generated.Routes))
			}
			if p.AppliedAt != nil {
				m.applied.WithLabelValues(o.Name).Set(float64(p.AppliedAt.Unix()))
			}
		}
	case *tnv1.TailnetEgress:
		// A successful ListNodes path repopulates node observations after status persistence.
		// Early failure paths must not retain a previously online node as a fresh observation.
		m.nodeOnline.DeleteLabelValues(kind, id.namespace, id.name)
		m.nodeLastSeen.DeleteLabelValues(kind, id.namespace, id.name)
		m.target.DeletePartialMatch(object)
		m.routesMissing.DeletePartialMatch(object)
		m.authExpiry.DeletePartialMatch(object)
		if o.Status.AuthKeyExpiresAt != nil {
			m.authExpiry.WithLabelValues(id.namespace, id.name).Set(time.Until(o.Status.AuthKeyExpiresAt.Time).Seconds())
		}
		if o.Status.ObservedGeneration != o.Generation || !current("RoutesGranted") {
			return
		}
		wanted := map[string]bool{}
		for _, t := range o.Spec.Targets {
			wanted[t.Name] = true
		}
		missing := 0
		for _, t := range o.Status.Targets {
			if wanted[t.Name] {
				state := reason(t.Reason)
				if t.Present && t.Reason == "" {
					state = "Present"
				}
				m.target.WithLabelValues(id.namespace, id.name, t.Name, state).Set(1)
				if !t.Present {
					missing++
				}
			}
		}
		m.routesMissing.WithLabelValues(id.namespace, id.name).Set(float64(missing))
	case *tnv1.TailnetIngress:
		m.nodeOnline.DeleteLabelValues(kind, id.namespace, id.name)
		m.nodeLastSeen.DeleteLabelValues(kind, id.namespace, id.name)
		m.expose.DeletePartialMatch(object)
		m.backends.DeletePartialMatch(object)
		m.ingressExpiry.DeletePartialMatch(object)
		if o.Status.AuthKeyExpiresAt != nil {
			m.ingressExpiry.WithLabelValues(id.namespace, id.name).Set(time.Until(o.Status.AuthKeyExpiresAt.Time).Seconds())
		}
		if o.Status.ObservedGeneration != o.Generation || !current("BackendsReachable") {
			return
		}
		wanted := map[string]bool{}
		for _, e := range o.Spec.Exposes {
			wanted[e.Name] = true
		}
		unreachable := 0
		for _, e := range o.Status.Exposes {
			if wanted[e.Name] {
				m.expose.WithLabelValues(id.namespace, id.name, e.Name).Set(truth(e.Reachable))
				if !e.Reachable {
					unreachable++
				}
			}
		}
		m.backends.WithLabelValues(id.namespace, id.name).Set(float64(unreachable))
	}
}
