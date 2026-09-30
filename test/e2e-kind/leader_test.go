//go:build e2e_kind

package e2ekind

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
	"this-is-fine.io/tailnet-operator/internal/policy"
)

const electionLease = "tailnet-operator.this-is-fine.io"

// Counter series are lazy: an unelected replica has no fixture series yet.
// Missing is not a scrape failure; presence is required on the elected replica.
type policySample struct {
	errors, processStart float64
	present              bool
}

func parsePolicySample(raw []byte) (policySample, error) {
	var sample policySample
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(bytes.NewReader(raw))
	if err != nil {
		return sample, fmt.Errorf("invalid metrics exposition")
	}
	process := families["process_start_time_seconds"]
	if process == nil || process.GetType() != dto.MetricType_GAUGE || len(process.Metric) != 1 {
		return sample, fmt.Errorf("missing process identity metric")
	}
	sample.processStart = process.Metric[0].GetGauge().GetValue()
	if sample.processStart <= 0 || math.IsNaN(sample.processStart) || math.IsInf(sample.processStart, 0) {
		return sample, fmt.Errorf("invalid process identity metric")
	}
	family := families["tailnet_policy_apply_errors_total"]
	if family == nil {
		return sample, nil
	}
	if family.GetType() != dto.MetricType_COUNTER {
		return sample, fmt.Errorf("policy error metric is not a counter")
	}
	for _, metric := range family.Metric {
		for _, label := range metric.Label {
			if label.GetName() != "tailnet" || label.GetValue() != "fixture" {
				continue
			}
			value := metric.GetCounter().GetValue()
			if sample.present || len(metric.Label) != 1 || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
				return sample, fmt.Errorf("invalid or duplicate fixture counter")
			}
			sample.errors, sample.present = value, true
		}
	}
	return sample, nil
}

// Match the entire client-go hostname_UUID identity against observed Pods, never a
// prefix guess or replica order. Kubernetes Pod names cannot contain underscores.
func holderPod(identity string, pods []corev1.Pod) (corev1.Pod, bool) {
	name, suffix, ok := strings.Cut(identity, "_")
	if !ok || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(suffix) {
		return corev1.Pod{}, false
	}
	for _, pod := range pods {
		if pod.Name == name && pod.UID != "" && pod.DeletionTimestamp == nil {
			return pod, true
		}
	}
	return corev1.Pod{}, false
}

func (f *fixture) readyOperators(ctx context.Context) ([]corev1.Pod, bool) {
	var deployment appsv1.Deployment
	if f.kube.Get(ctx, client.ObjectKey{Namespace: namespace, Name: "tailnet-operator"}, &deployment) != nil ||
		deployment.Status.ObservedGeneration != deployment.Generation || deployment.Status.ReadyReplicas != 2 {
		return nil, false
	}
	ready := f.readyOperatorPods(ctx)
	return ready, len(ready) == 2
}

// Leadership can converge while the replacement replica is still being scheduled.
func (f *fixture) readyOperatorPods(ctx context.Context) []corev1.Pod {
	var list corev1.PodList
	if f.kube.List(ctx, &list, client.InNamespace(namespace), client.MatchingLabels{"app.kubernetes.io/name": "tailnet-operator"}) != nil {
		return nil
	}
	var ready []corev1.Pod
	for _, pod := range list.Items {
		if pod.DeletionTimestamp != nil {
			continue
		}
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				ready = append(ready, pod)
			}
		}
	}
	return ready
}

func (f *fixture) holder(ctx context.Context) string {
	var lease coordinationv1.Lease
	if f.kube.Get(ctx, client.ObjectKey{Namespace: namespace, Name: electionLease}, &lease) != nil || lease.Spec.HolderIdentity == nil {
		return ""
	}
	return *lease.Spec.HolderIdentity
}

func (f *fixture) sample(ctx context.Context, pod corev1.Pod) (policySample, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Pod proxy, not Service proxy: both replicas must be sampled independently.
	raw, err := f.command(ctx, "", "kubectl", "--kubeconfig", f.config, "--context", f.context,
		"--request-timeout=5s", "get", "--raw", "/api/v1/namespaces/"+namespace+"/pods/"+pod.Name+":8080/proxy/metrics")
	if err != nil {
		return policySample{}, fmt.Errorf("owned Pod metrics request failed")
	}
	return parsePolicySample(raw)
}

func TestLeaderFailover(t *testing.T) {
	f := installFixture(t)
	var deployment appsv1.Deployment
	if f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: "tailnet-operator"}, &deployment) != nil {
		t.Fatal("get operator Deployment failed")
	}
	replicas := int32(2)
	deployment.Spec.Replicas = &replicas
	if f.kube.Update(t.Context(), &deployment) != nil {
		t.Fatal("scale operator Deployment failed")
	}
	var pods []corev1.Pod
	var leader corev1.Pod
	var original string
	eventually(t, "two ready operators and a mapped Lease holder", func() bool {
		var ready bool
		pods, ready = f.readyOperators(t.Context())
		original = f.holder(t.Context())
		var mapped bool
		leader, mapped = holderPod(original, pods)
		return ready && mapped
	})
	before := map[string]policySample{}
	for _, pod := range pods {
		sample, err := f.sample(t.Context(), pod)
		if err != nil || sample.errors != 0 || (pod.UID == leader.UID && !sample.present) {
			t.Fatal("baseline Pod policy counter missing on leader, nonzero or unreadable (data withheld)")
		}
		before[string(pod.UID)] = sample
	}
	if f.holder(t.Context()) != original {
		t.Fatal("Lease holder changed before controlled deletion")
	}
	var base corev1.ConfigMap
	if f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: "headscale-policy"}, &base) != nil {
		t.Fatal("get base policy failed")
	}
	base.Data["policy"] = strings.ReplaceAll(basePolicy, "192.0.2.1:443", "192.0.2.2:443")
	desired, err := policy.Normalize([]byte(strings.ReplaceAll(f.policy, "192.0.2.1:443", "192.0.2.2:443")))
	if err != nil || desired == f.policy {
		t.Fatal("construct independently expected policy failed")
	}
	desiredHash := policy.Hash(desired)

	// Include normal deletion and the immediate ConfigMap update in the wall-clock
	// budget. Keep production lease expiry, shutdown and ReleaseOnCancel=false.
	start := time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if f.kube.Delete(ctx, &leader, client.Preconditions{UID: &leader.UID}) != nil {
		t.Fatal("normal leader Pod deletion failed")
	}
	if f.kube.Update(ctx, &base) != nil {
		t.Fatal("immediate base policy update failed")
	}
	var replacement corev1.Pod
	var currentPods []corev1.Pod
	var changedIdentity string
	for {
		if ctx.Err() != nil {
			t.Fatalf("failover/policy convergence exceeded 30s (elapsed %s)", time.Since(start).Round(time.Millisecond))
		}
		currentPods = f.readyOperatorPods(ctx)
		changedIdentity = f.holder(ctx)
		var mapped bool
		replacement, mapped = holderPod(changedIdentity, currentPods)
		var tn tnv1.Tailnet
		if mapped && replacement.UID != leader.UID && changedIdentity != original &&
			f.kube.Get(ctx, client.ObjectKey{Name: "fixture"}, &tn) == nil &&
			meta.IsStatusConditionTrue(tn.Status.Conditions, "PolicyApplied") &&
			tn.Status.Policy != nil && tn.Status.Policy.AppliedHash == desiredHash && tn.Status.Policy.RenderedHash == desiredHash {
			readCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			raw, readErr := f.command(readCtx, "", "kubectl", "--kubeconfig", f.config, "--context", f.context,
				"--request-timeout=5s", "--namespace", namespace, "exec", "headscale", "--", "/ko-app/headscale",
				"--config", "/etc/headscale/config.yaml", "policy", "get")
			stop()
			canonical, normalizeErr := policy.Normalize(raw)
			if readErr == nil && normalizeErr == nil && canonical == desired && time.Since(start) < 30*time.Second {
				break
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Logf("gate: different Lease holder and desired status/live Headscale policy converged in %s (budget 30s)", time.Since(start).Round(time.Millisecond))

	// Replacement readiness is separate from the measured leadership/policy budget.
	eventually(t, "two ready operators after failover", func() bool {
		var ready bool
		currentPods, ready = f.readyOperators(t.Context())
		return ready
	})
	if f.holder(t.Context()) != changedIdentity {
		t.Fatal("Lease holder changed again before final counter samples")
	}
	survivors := 0
	for _, pod := range currentPods {
		after, err := f.sample(t.Context(), pod)
		if err != nil || (pod.UID == replacement.UID && !after.present) {
			t.Fatal("final Pod counter unreadable or absent on new leader (data withheld)")
		}
		if previous, found := before[string(pod.UID)]; found {
			survivors++
			if previous.processStart != after.processStart || after.errors != previous.errors || (previous.present && !after.present) {
				t.Fatal("surviving process restarted or policy error counter changed")
			}
		} else if after.errors != 0 {
			t.Fatal("new Pod observed policy apply errors")
		}
	}
	if survivors != 1 {
		t.Fatal("expected exactly one continuously sampled surviving Pod")
	}
	t.Log("gate: both Pods sampled before/after; surviving counter unchanged, new Pod counter zero or uninitialized")
	t.Log("scope: no data-plane claim; samples do not prove exactly-once external writes or cover deleted-Pod counters across the gap")
}
