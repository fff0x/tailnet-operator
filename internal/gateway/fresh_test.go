package gateway

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func freshFixture() FreshInputs {
	return FreshInputs{Namespace: "operator", DNSSerial: 1,
		Gateway: &tnv1.TailnetGateway{ObjectMeta: metav1.ObjectMeta{Name: "router", UID: "fixture-uid"}, Spec: tnv1.TailnetGatewaySpec{
			TailnetRef: tnv1.GatewayLocalReference{Name: "tailnet"}, Hostname: "router", Suspend: ptr.To(true), Replicas: 1, DeletionPolicy: "Retain",
			StateSecretRef: tnv1.GatewayLocalReference{Name: "router-state"}, AuthKeySecretRef: &tnv1.GatewayAuthKeyReference{Name: "router-auth", Key: "TS_AUTHKEY"},
			Image: "ghcr.io/tailscale/tailscale:v1.102.4", Tags: []string{"tag:mesh", "tag:fabric"},
			Routes:  tnv1.GatewayRoutes{LAN: []tnv1.GatewayPrefix{"192.0.2.0/24"}, AdvertiseEgressTargets: ptr.To(true)},
			Service: tnv1.GatewayService{LoadBalancerIP: "198.51.100.1", TailnetLBCIDR: "198.51.100.0/24", PoolLabels: map[string]tnv1.GatewayLabelValue{"example.com/pool": "tailnet"}},
			DNS:     tnv1.GatewayDNS{Zone: "tail.example", ServiceName: "router-dns", ServiceClusterIP: "10.96.0.53", Image: "coredns/coredns:1.14.6"},
		}},
		Tailnet:  &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "tailnet"}, Spec: tnv1.TailnetSpec{Server: "https://headscale.example"}},
		Egresses: []tnv1.TailnetEgress{{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "operator"}, Spec: tnv1.TailnetEgressSpec{TailnetRef: tnv1.TailnetRef{Name: "tailnet"}, Targets: []tnv1.Target{{Name: "db", Address: "203.0.113.8", Port: 5432}, {Name: "v6", Address: "2001:db8::8", Port: 443}, {Name: "dns", Address: "external.example", Port: 443}}}}},
	}
}

func TestRenderFresh(t *testing.T) {
	in := freshFixture()
	before, _ := json.Marshal(in)
	plan, err := RenderFresh(in)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(in)
	if string(before) != string(after) {
		t.Fatal("input changed")
	}
	if len(plan.Objects) != 9 || !reflect.DeepEqual(plan.Routes.Routes, []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.8/32", "2001:db8::8/128"}) || !reflect.DeepEqual(plan.Routes.SkippedDNS, []string{"external.example"}) {
		t.Fatal("incorrect inventory or route union")
	}
	seen := map[string]bool{}
	for _, obj := range plan.Objects {
		key := reflect.TypeOf(obj).String() + "/" + obj.GetName()
		if seen[key] || obj.GetNamespace() != in.Namespace || len(obj.GetOwnerReferences()) != 0 || len(obj.GetFinalizers()) != 0 {
			t.Fatal("unsafe resource identity/lifecycle")
		}
		seen[key] = true
		if obj.GetLabels()[gatewayUIDLabel] != string(in.Gateway.UID) {
			t.Fatal("missing identity marker")
		}
		switch obj := obj.(type) {
		case *corev1.Secret:
			t.Fatal("renderer must not mint, copy or initialize Secrets")
		case *rbacv1.Role:
			want := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{"router-state"}, Verbs: []string{"get", "update", "patch"}}}
			if !reflect.DeepEqual(obj.Rules, want) {
				t.Fatal("broad state privileges")
			}
		case *rbacv1.RoleBinding:
			if obj.RoleRef.Kind != "Role" || obj.RoleRef.Name != "router" || len(obj.Subjects) != 1 || obj.Subjects[0].Namespace != "operator" || obj.Subjects[0].Name != "router" {
				t.Fatal("incorrect subject")
			}
		case *corev1.ServiceAccount:
			if obj.AutomountServiceAccountToken == nil || *obj.AutomountServiceAccountToken {
				t.Fatal("automatic token mount")
			}
		case *corev1.ConfigMap:
			if obj.Name != "router-coredns" {
				t.Fatal("unexpected derived ConfigMap")
			}
			if obj.Annotations[DNSSerialAnnotation] != "1" || !dnsRevisionHash.MatchString(obj.Annotations[DNSHashAnnotation]) {
				t.Fatal("derived DNS CAS annotations missing or malformed")
			}
			if obj.Annotations[DNSHashAnnotation] != dnsContentHash(obj.Data["Corefile"], obj.Data[DNSZoneFile]) {
				t.Fatal("CAS hash does not describe the initial payload")
			}
		case *corev1.Service:
			if len(obj.Spec.Ports) != 2 || obj.Spec.Ports[0].Port != 53 || obj.Spec.Ports[1].Port != 53 || obj.Spec.Ports[0].Protocol != corev1.ProtocolUDP || obj.Spec.Ports[1].Protocol != corev1.ProtocolTCP {
				t.Fatal("unexpected exposed ports")
			}
			if !reflect.DeepEqual(obj.Spec.Selector, map[string]string{gatewayUIDLabel: "fixture-uid"}) || !reflect.DeepEqual(obj.Spec.IPFamilies, []corev1.IPFamily{corev1.IPv4Protocol}) || obj.Spec.IPFamilyPolicy == nil || *obj.Spec.IPFamilyPolicy != corev1.IPFamilyPolicySingleStack {
				t.Fatal("implicit service family or unsafe selector")
			}
			if obj.Name == "router" && (obj.Spec.LoadBalancerIP != "198.51.100.1" || obj.Spec.AllocateLoadBalancerNodePorts == nil || *obj.Spec.AllocateLoadBalancerNodePorts || obj.Labels["example.com/pool"] != "tailnet") {
				t.Fatal("incorrect LB")
			}
			if obj.Name != "router" && obj.Labels["example.com/pool"] != "" {
				t.Fatal("pool label leaked")
			}
			if obj.Name == "router-dns" && (obj.Spec.ClusterIP != "10.96.0.53" || len(obj.Spec.ClusterIPs) != 1) {
				t.Fatal("DNS address changed")
			}
		case *appsv1.StatefulSet:
			if *obj.Spec.Replicas != 1 || obj.Spec.UpdateStrategy.Type != appsv1.OnDeleteStatefulSetStrategyType || obj.Spec.ServiceName != "router-headless" {
				t.Fatal("unsafe singleton rollout")
			}
			p := obj.Spec.Template.Spec
			if p.OS == nil || p.OS.Name != corev1.Linux || p.NodeSelector["kubernetes.io/os"] != "linux" || p.HostNetwork || p.HostPID || p.HostIPC || p.AutomountServiceAccountToken == nil || *p.AutomountServiceAccountToken || len(p.SecurityContext.Sysctls) != 0 || len(p.Containers) != 2 || len(p.InitContainers) != 1 {
				t.Fatal("unsafe pod boundary")
			}
			for _, c := range append(slices.Clone(p.InitContainers), p.Containers...) {
				s := c.SecurityContext
				if s == nil || *s.Privileged || *s.AllowPrivilegeEscalation || !*s.ReadOnlyRootFilesystem || !reflect.DeepEqual(s.Capabilities.Drop, []corev1.Capability{"ALL"}) {
					t.Fatal("unsafe container security")
				}
				for _, m := range c.VolumeMounts {
					if (m.Name == "api-access" || m.Name == "state-cache") && c.Name != "tailscale" {
						t.Fatal("identity material shared with sidecar")
					}
					if m.SubPath != "" {
						t.Fatal("subPath freezes projection")
					}
				}
				for _, cap := range s.Capabilities.Add {
					if (c.Name != "tailscale" || cap != "NET_ADMIN") && (c.Name != "coredns" || cap != "NET_BIND_SERVICE") {
						t.Fatal("unnecessary capability")
					}
				}
			}
			vars := map[string]corev1.EnvVar{}
			for _, e := range p.Containers[0].Env {
				vars[e.Name] = e
			}
			if vars["TS_KUBE_SECRET"].Value != "router-state" || vars["TS_USERSPACE"].Value != "false" || vars["TS_ACCEPT_DNS"].Value != "false" || vars["TS_AUTH_ONCE"].Value != "false" || vars["TS_ROUTES"].Value != strings.Join(plan.Routes.Routes, ",") {
				t.Fatal("unsafe kernel preferences")
			}
			// Headscale 0.29 rejects any requested tags on pre-auth-key
			// enrollment. The verified key, not CLI requests, assigns tags.
			if vars["TS_EXTRA_ARGS"].Value != "--login-server=https://headscale.example --reset --accept-routes=false" {
				t.Fatal("unsafe bootstrap flags")
			}
			if vars["TS_AUTHKEY"].Value != "" || vars["TS_AUTHKEY"].ValueFrom.SecretKeyRef.Name != "router-auth" {
				t.Fatal("credential embedded or mixed with state")
			}
			if p.Containers[1].WorkingDir != DNSWorkingDirectory {
				t.Fatal("relative DNS zone cannot be loaded")
			}
		}
	}
	// Set-like order must not change the pod template or published files.
	in.Gateway.Spec.Tags[0], in.Gateway.Spec.Tags[1] = in.Gateway.Spec.Tags[1], in.Gateway.Spec.Tags[0]
	slices.Reverse(in.Egresses[0].Spec.Targets)
	again, err := RenderFresh(in)
	if err != nil || !reflect.DeepEqual(plan, again) {
		t.Fatal("non-deterministic plan")
	}
	// Output maps are independent of one another and of the input.
	plan.Objects[0].GetLabels()[gatewayUIDLabel] = "changed"
	if again.Objects[0].GetLabels()[gatewayUIDLabel] != "fixture-uid" || plan.Objects[1].GetLabels()[gatewayUIDLabel] != "fixture-uid" {
		t.Fatal("aliased output maps")
	}
}

func TestRenderFreshScopeAndOptionalEgress(t *testing.T) {
	in := freshFixture()
	for _, mutate := range []func(*tnv1.TailnetEgress){func(e *tnv1.TailnetEgress) { e.Namespace = "foreign" }, func(e *tnv1.TailnetEgress) { e.Spec.TailnetRef.Name = "foreign" }, func(e *tnv1.TailnetEgress) { e.DeletionTimestamp = ptr.To(metav1.Now()) }} {
		e := in.Egresses[0].DeepCopy()
		mutate(e)
		e.Spec.Targets[0].Address = "invalid private value"
		in.Egresses = append(in.Egresses, *e)
	}
	if _, err := RenderFresh(in); err != nil {
		t.Fatal("foreign/deleting egress affected routes")
	}
	in.Gateway.Spec.Routes.AdvertiseEgressTargets = ptr.To(false)
	in.Egresses[0].Spec.Targets[0].Address = "invalid private value"
	plan, err := RenderFresh(in)
	if err != nil || !reflect.DeepEqual(plan.Routes.Routes, []string{"192.0.2.0/24", "198.51.100.0/24"}) || len(plan.Routes.SkippedDNS) != 0 {
		t.Fatal("optional egress changed mandatory LAN/LB union")
	}
}

func TestRenderFreshServiceFamilies(t *testing.T) {
	for _, dual := range []bool{false, true} {
		in := freshFixture()
		in.Gateway.Spec.Service.LoadBalancerIP = "2001:db8:1::1"
		in.Gateway.Spec.Service.TailnetLBCIDR = "2001:db8:1::/64"
		if !dual {
			in.Gateway.Spec.DNS.ServiceClusterIP = "2001:db8:2::53"
		}
		plan, err := RenderFresh(in)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range plan.Objects {
			if s, ok := o.(*corev1.Service); ok {
				want := corev1.IPv6Protocol
				if dual && s.Name != "router" {
					want = corev1.IPv4Protocol
				}
				if s.Spec.IPFamilies[0] != want {
					t.Fatal("wrong explicit Service family")
				}
			}
		}
	}
}

func TestRenderFreshRejectsUnsupported(t *testing.T) {
	for name, mutate := range map[string]func(*FreshInputs){
		"missing gateway": func(i *FreshInputs) { i.Gateway = nil }, "missing tailnet": func(i *FreshInputs) { i.Tailnet = nil },
		"namespace": func(i *FreshInputs) { i.Namespace = "bad/value" }, "scope": func(i *FreshInputs) { i.Tailnet.Name = "foreign" },
		"uid": func(i *FreshInputs) { i.Gateway.UID = "" }, "adoption": func(i *FreshInputs) { i.Gateway.Spec.Adoption = &tnv1.GatewayAdoption{} },
		"historical": func(i *FreshInputs) { i.Gateway.Status.NodeID = "17" }, "bootstrap missing": func(i *FreshInputs) { i.Gateway.Spec.AuthKeySecretRef = nil },
		"secrets shared":    func(i *FreshInputs) { i.Gateway.Spec.AuthKeySecretRef.Name = i.Gateway.Spec.StateSecretRef.Name },
		"replicas":          func(i *FreshInputs) { i.Gateway.Spec.Replicas = 2 },
		"service collision": func(i *FreshInputs) { i.Gateway.Spec.DNS.ServiceName = "router-headless" }, "outside LB pool": func(i *FreshInputs) { i.Gateway.Spec.Service.LoadBalancerIP = "203.0.113.1" },
		"label collision": func(i *FreshInputs) { i.Gateway.Spec.Service.PoolLabels[gatewayUIDLabel] = "foreign" },
		"http control":    func(i *FreshInputs) { i.Tailnet.Spec.Server = "http://headscale.example" },
		"applied history": func(i *FreshInputs) { i.Gateway.Status.RoutePlan.AppliedHash = strings.Repeat("a", 64) },
		"stale nodes":     func(i *FreshInputs) { i.Gateway.Status.StaleNodes = []string{"17"} },
		"url credentials": func(i *FreshInputs) { i.Tailnet.Spec.Server = "https://private:credential@headscale.example" },
		"url flags":       func(i *FreshInputs) { i.Tailnet.Spec.Server = "https://headscale.example --force-reauth" },
		"tag flags":       func(i *FreshInputs) { i.Gateway.Spec.Tags = []string{"tag:fabric --force-reauth"} },
		"forward":         func(i *FreshInputs) { i.Gateway.Spec.Forwards = []tnv1.GatewayForward{{Name: "api", Port: 6443}} },
	} {
		t.Run(name, func(t *testing.T) {
			in := freshFixture()
			mutate(&in)
			p, err := RenderFresh(in)
			if !errors.Is(err, ErrFreshConfiguration) || err.Error() != ErrFreshConfiguration.Error() || len(p.Objects) != 0 || len(p.Routes.Routes) != 0 {
				t.Fatal("unsafe input did not fail closed")
			}
		})
	}
	// deletionPolicy is consent metadata, not part of the rendered set.
	in := freshFixture()
	in.Gateway.Spec.DeletionPolicy = tnv1.GatewayDeletionPolicyDelete
	if _, err := RenderFresh(in); err != nil {
		t.Fatal("deletionPolicy=Delete must render")
	}
	in = freshFixture()
	in.Gateway.Spec.DNS.ExtraZones = []tnv1.GatewayExtraZone{{Zone: "site.example"}}
	if p, err := RenderFresh(in); !errors.Is(err, ErrDNSForwardingUnsupported) || len(p.Objects) != 0 {
		t.Fatal("extra-zone gate bypassed")
	}
}

// Synthetic files exercise only the read-only preflight script, not TUN, network
// namespaces, capabilities, sysctl writeability, a container or packet routing.
func TestForwardingPreflight(t *testing.T) {
	for _, tc := range []struct {
		name            string
		routes          []string
		v4, v6          string
		device, success bool
	}{
		{"v4", []string{"192.0.2.0/24"}, "1\n", "", true, true},
		{"v6", []string{"2001:db8::/64"}, "", "1\n", true, true},
		{"dual", []string{"192.0.2.0/24", "2001:db8::/64"}, "1\n", "1\n", true, true},
		{"v4 disabled", []string{"192.0.2.0/24"}, "0\n", "1\n", true, false},
		{"v6 disabled", []string{"2001:db8::/64"}, "1\n", "0\n", true, false},
		{"missing forwarding", []string{"192.0.2.0/24"}, "", "", true, false},
		{"no device", []string{"192.0.2.0/24"}, "1\n", "", false, false},
		{"malformed", []string{"192.0.2.0/24"}, "private value\n", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			paths := map[string]string{"proc/sys/net/ipv4/ip_forward": tc.v4, "proc/sys/net/ipv6/conf/all/forwarding": tc.v6}
			for p, v := range paths {
				if v == "" {
					continue
				}
				p = filepath.Join(root, p)
				if os.MkdirAll(filepath.Dir(p), 0700) != nil || os.WriteFile(p, []byte(v), 0400) != nil {
					t.Fatal("create synthetic forwarding fixture")
				}
			}
			if os.MkdirAll(filepath.Join(root, "dev/net"), 0700) != nil {
				t.Fatal("create device fixture directory")
			}
			if tc.device {
				if os.Symlink("/dev/null", filepath.Join(root, "dev/net/tun")) != nil {
					t.Fatal("create synthetic char-device reference")
				}
			}
			for _, r := range tc.routes {
				if _, err := netip.ParsePrefix(r); err != nil {
					t.Fatal("invalid test route")
				}
			}
			cmd := exec.Command("/bin/sh", "-c", forwardingCheck(RoutePlan{Routes: tc.routes}), "fixture", root)
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.success {
				t.Fatal("wrong preflight outcome")
			}
			if !tc.success && string(out) != "gateway kernel prerequisites unavailable\n" {
				t.Fatal("preflight exposed raw diagnostics")
			}
			for p, v := range paths {
				b, err := os.ReadFile(filepath.Join(root, p))
				if v == "" {
					if !os.IsNotExist(err) {
						t.Fatal("preflight created sysctl")
					}
				} else if err != nil || string(b) != v {
					t.Fatal("preflight mutated sysctl")
				}
			}
		})
	}
}
