//go:build e2e_kind

package e2ekind

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestPolicySampleParser(t *testing.T) {
	const process = "# TYPE process_start_time_seconds gauge\nprocess_start_time_seconds 123\n"
	const counter = "# TYPE tailnet_policy_apply_errors_total counter\n"
	for _, tc := range []struct {
		name, raw string
		present   bool
		value     float64
		invalid   bool
	}{
		{"standby", process, false, 0, false},
		{"zero", process + counter + "tailnet_policy_apply_errors_total{tailnet=\"fixture\"} 0\n", true, 0, false},
		{"errors", process + counter + "tailnet_policy_apply_errors_total{tailnet=\"fixture\"} 2\n", true, 2, false},
		{"other-tailnet", process + counter + "tailnet_policy_apply_errors_total{tailnet=\"another\"} 9\n", false, 0, false},
		{"empty", "", false, 0, true},
		{"invalid", "not exposition", false, 0, true},
		{"wrong-type", process + strings.ReplaceAll(counter, " counter", " gauge") + "tailnet_policy_apply_errors_total{tailnet=\"fixture\"} 0\n", false, 0, true},
		{"negative", process + counter + "tailnet_policy_apply_errors_total{tailnet=\"fixture\"} -1\n", false, 0, true},
		{"nan", process + counter + "tailnet_policy_apply_errors_total{tailnet=\"fixture\"} NaN\n", false, 0, true},
		{"infinity", process + counter + "tailnet_policy_apply_errors_total{tailnet=\"fixture\"} +Inf\n", false, 0, true},
		{"extra-label", process + counter + "tailnet_policy_apply_errors_total{tailnet=\"fixture\",extra=\"x\"} 0\n", false, 0, true},
		{"duplicate", process + counter + strings.Repeat("tailnet_policy_apply_errors_total{tailnet=\"fixture\"} 0\n", 2), false, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePolicySample([]byte(tc.raw))
			if (err != nil) != tc.invalid || (!tc.invalid && (got.present != tc.present || got.errors != tc.value || got.processStart != 123)) {
				t.Fatal("unexpected sanitized metric parse result")
			}
		})
	}
}

func TestHolderPod(t *testing.T) {
	const suffix = "_12345678-1234-1234-1234-123456789abc"
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "operator-a", UID: "pod-uid"}}
	for _, identity := range []string{"operator-a", "operator-a_bad-uuid", "operator" + suffix, "operator-a-extra" + suffix, "operator-a" + suffix + "_extra"} {
		if _, ok := holderPod(identity, []corev1.Pod{pod}); ok {
			t.Fatal("accepted unmappable holder identity")
		}
	}
	if got, ok := holderPod(pod.Name+suffix, []corev1.Pod{pod}); !ok || got.UID != pod.UID {
		t.Fatal("did not map complete holder identity")
	}
	now := metav1.Now()
	pod.DeletionTimestamp = &now
	if _, ok := holderPod(pod.Name+suffix, []corev1.Pod{pod}); ok {
		t.Fatal("accepted terminating holder")
	}
}

func TestConfigGuard(t *testing.T) {
	const cluster = "tn-kind-0123456789"
	const name = "kind-" + cluster
	valid := &clientcmdapi.Config{
		CurrentContext: name,
		Contexts:       map[string]*clientcmdapi.Context{name: {Cluster: name, AuthInfo: name}},
		Clusters:       map[string]*clientcmdapi.Cluster{name: {Server: "https://127.0.0.1:23456", CertificateAuthorityData: []byte("inline fixture CA")}},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{name: {ClientCertificateData: []byte("inline fixture cert"), ClientKeyData: []byte("inline fixture key")}},
	}
	if err := validateConfig(valid, cluster); err != nil {
		t.Fatalf("valid shape rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*clientcmdapi.Config)
	}{
		{"current-context", func(c *clientcmdapi.Config) { c.CurrentContext = "production" }},
		{"extra-context", func(c *clientcmdapi.Config) { c.Contexts["production"] = &clientcmdapi.Context{} }},
		{"wrong-cluster", func(c *clientcmdapi.Config) { c.Contexts[name].Cluster = "production" }},
		{"wrong-identity", func(c *clientcmdapi.Config) { c.Contexts[name].AuthInfo = "production" }},
		{"missing-cluster", func(c *clientcmdapi.Config) { c.Clusters[name] = nil }},
		{"missing-identity", func(c *clientcmdapi.Config) { c.AuthInfos[name] = nil }},
		{"remote", func(c *clientcmdapi.Config) { c.Clusters[name].Server = "https://192.0.2.1:6443" }},
		{"http", func(c *clientcmdapi.Config) { c.Clusters[name].Server = "http://127.0.0.1:23456" }},
		{"zero-port", func(c *clientcmdapi.Config) { c.Clusters[name].Server = "https://127.0.0.1:0" }},
		{"named-port", func(c *clientcmdapi.Config) { c.Clusters[name].Server = "https://127.0.0.1:https" }},
		{"proxy", func(c *clientcmdapi.Config) { c.Clusters[name].ProxyURL = "http://proxy.invalid" }},
		{"skip-tls", func(c *clientcmdapi.Config) { c.Clusters[name].InsecureSkipTLSVerify = true }},
		{"external-ca", func(c *clientcmdapi.Config) { c.Clusters[name].CertificateAuthority = "/tmp/ca" }},
		{"exec-plugin", func(c *clientcmdapi.Config) {
			c.AuthInfos[name].Exec = &clientcmdapi.ExecConfig{Command: "credential-helper"}
		}},
		{"auth-provider", func(c *clientcmdapi.Config) {
			c.AuthInfos[name].AuthProvider = &clientcmdapi.AuthProviderConfig{Name: "oidc"}
		}},
		{"external-key", func(c *clientcmdapi.Config) { c.AuthInfos[name].ClientKey = "/tmp/key" }},
		{"token", func(c *clientcmdapi.Config) { c.AuthInfos[name].Token = "fixture-not-a-real-token" }},
		{"impersonate", func(c *clientcmdapi.Config) { c.AuthInfos[name].Impersonate = "admin" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := valid.DeepCopy()
			tc.mutate(c)
			if validateConfig(c, cluster) == nil {
				t.Fatal("unsafe kubeconfig accepted")
			}
		})
	}
	for _, cluster := range []string{"production", "tn-kind-", "tn-kind-0123456789/other"} {
		if validateConfig(valid, cluster) == nil {
			t.Fatalf("unsafe cluster name accepted: %s", cluster)
		}
	}
}
