//go:build e2e

package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
)

func hostsContains(text, ip, name string) bool {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == ip && fields[1] == name {
			return true
		}
	}
	return false
}

// TestIPv4OnlyHosts exercises the real API/watch/render path with injected agent status: envtest
// has no kubelet or live tsnet agent. This is not a data-plane IPv6 connectivity test.
func TestIPv4OnlyHosts(t *testing.T) {
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			if version == "v0.28.0" {
				t.Skip("unsupported capability row; covered by TestPreflight")
			}
			ctx, cancel := context.WithTimeout(testContext(t), 40*time.Second)
			defer cancel()
			hs := startHeadscale(t, ctx, version, "database", true)
			name := createTailnet(t, ctx, hs)
			configName := name + "-hosts"
			updateTailnet(t, ctx, name, func(tn *tnv1.Tailnet) { tn.Spec.DNS.HostsConfigMap = configName })
			// An undeclared tag prevents key/workload creation. Only the DNS name/status path is
			// needed, so there is no test agent making background network calls.
			in := &tnv1.TailnetIngress{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec: tnv1.TailnetIngressSpec{
					TailnetRef: tnv1.TailnetRef{Name: name}, Tag: "tag:undeclared",
					AllowFrom: []string{"group:operator"},
					Exposes:   []tnv1.Expose{{Name: "web", Port: 443, Backend: tnv1.Backend{Service: "unused", Port: 80}}},
				},
			}
			if err := kube.Create(ctx, in); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := client.IgnoreNotFound(kube.Delete(cleanup, in)); err != nil {
					t.Errorf("delete DNS ingress fixture: %v", err)
				}
				cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: configName, Namespace: namespace}}
				if err := client.IgnoreNotFound(kube.Delete(cleanup, cm)); err != nil {
					t.Errorf("delete hosts fixture: %v", err)
				}
			})
			key := types.NamespacedName{Namespace: namespace, Name: name}
			eventually(t, ctx, "ingress DNS name and no-agent guard", func() bool {
				if err := kube.Get(ctx, key, in); err != nil {
					t.Fatal(err)
				}
				c := meta.FindStatusCondition(in.Status.Conditions, "Ready")
				return in.Status.DNSName == name+".e2e.invalid" && c != nil && c.Reason == "TagUnknown"
			})
			status := func(ips ...string) {
				t.Helper()
				if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
					if err := kube.Get(ctx, key, in); err != nil {
						return err
					}
					in.Status.TailnetIPs = ips
					return kube.Status().Update(ctx, in)
				}); err != nil {
					t.Fatal(err)
				}
			}
			hosts := func() string {
				var cm corev1.ConfigMap
				if err := kube.Get(ctx, types.NamespacedName{Namespace: namespace, Name: configName}, &cm); err != nil {
					return ""
				}
				return cm.Data["hosts"]
			}
			status("100.64.0.9", "fd7a:115c:a1e0::9")
			eventually(t, ctx, "IPv4 hosts entry", func() bool { return hostsContains(hosts(), "100.64.0.9", name+".e2e.invalid") })
			if strings.Contains(hosts(), "fd7a:") {
				t.Fatal("hosts ConfigMap published an unverified IPv6 address")
			}
			status("fd7a:115c:a1e0::9")
			eventually(t, ctx, "removal of stale IPv4 entry", func() bool {
				text := hosts()
				return text != "" && !strings.Contains(text, name+".e2e.invalid")
			})
		})
	}
}
