//go:build e2e_kind

package e2ekind

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tsunaro.io/tailnet-operator/internal/gateway"
	probe "tsunaro.io/tailnet-operator/test/internal/gatewayprobe"
	"tsunaro.io/tailnet-operator/test/internal/kindfixture"
)

type gatewayDataPlane struct {
	pf           *httpPeerFixture
	target, peer *corev1.Pod
	prefix       string
	gatewayIPv4  string
}

func gatewayProbePod(name, role, image string) *corev1.Pod {
	p := httpFixturePod(name, image)
	c := &p.Spec.Containers[0]
	c.Command = []string{"/gatewayprobe"}
	c.Args = []string{"--fixture=gateway-forwarding", "--role=" + role}
	c.ReadinessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromInt32(9081)}}, PeriodSeconds: 1}
	return p
}

func (d *gatewayDataPlane) request(t *testing.T, p *corev1.Pod, path, body string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 9*time.Second)
	defer cancel()
	return d.pf.f.command(ctx, body, "kubectl", peerProxyArgs(d.pf.f.config, d.pf.f.context, p.Name, 9081, path, body != "")...)
}

// The target is a real, unprivileged Pod, not another Tailnet participant or a
// listener in the gateway network namespace. Only its exact /32 is approved.
func newGatewayDataPlane(t *testing.T, pf *httpPeerFixture) *gatewayDataPlane {
	t.Helper()
	d := &gatewayDataPlane{pf: pf}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, before := range []*corev1.Pod{d.target, d.peer} {
			if before == nil || before.UID == "" {
				continue
			}
			current := &corev1.Pod{}
			if pf.f.kube.Get(ctx, client.ObjectKeyFromObject(before), current) == nil && current.UID == before.UID {
				pf.save("failed-"+before.Name+"-status.json", map[string]any{"podUID": current.UID, "status": current.Status})
			}
		}
	})
	d.target = gatewayProbePod("gateway-proof-target", "target", pf.image)
	if kindfixture.AddNetworkGate(d.target, pf.image) != nil {
		t.Fatal("target gate rejected")
	}
	pf.create(d.target)
	releaseFixturePod(t, pf.f, d.target)
	eventually(t, "isolated gateway target ready", func() bool { _, err := d.request(t, d.target, "readyz", ""); return err == nil })
	ip, err := netip.ParseAddr(d.target.Status.PodIP)
	if err != nil || !ip.Is4() || !ip.IsPrivate() {
		t.Fatal("target has no owned private IPv4")
	}
	d.prefix = netip.PrefixFrom(ip, 32).String()
	return d
}

func (d *gatewayDataPlane) startPeer(t *testing.T, gatewayIP string) {
	t.Helper()
	if d.peer != nil {
		if d.gatewayIPv4 != gatewayIP {
			t.Fatal("peer target changed after gateway recreation")
		}
		return
	}
	d.gatewayIPv4 = gatewayIP
	b, err := json.Marshal(probe.Config{TargetIPv4: d.target.Status.PodIP, GatewayIPv4: gatewayIP})
	if err != nil {
		t.Fatal("encode bounded peer configuration")
	}
	d.pf.create(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "gateway-probe-config", Namespace: namespace}, Immutable: ptr.To(true), Data: map[string]string{"config.json": string(b)}})
	d.pf.auth("gateway-probe-auth")
	d.peer = gatewayProbePod("gateway-proof-peer", "peer", d.pf.image)
	c := &d.peer.Spec.Containers[0]
	c.Env = []corev1.EnvVar{{Name: "TS_AUTHKEY", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "gateway-probe-auth"}, Key: "key"}}}}
	c.VolumeMounts = []corev1.VolumeMount{{Name: "ca", MountPath: "/control-ca", ReadOnly: true}, {Name: "state", MountPath: "/state"}, {Name: "probe", MountPath: "/probe", ReadOnly: true}}
	d.peer.Spec.Volumes = []corev1.Volume{fixtureConfigVolume("ca", d.pf.public.Name), fixtureStateVolume("state", "32Mi"), fixtureConfigVolume("probe", "gateway-probe-config")}
	if kindfixture.AddNetworkGate(d.peer, d.pf.image) != nil {
		t.Fatal("gateway peer gate rejected")
	}
	d.pf.create(d.peer)
	releaseFixturePod(t, d.pf.f, d.peer)
	eventually(t, "gateway tsnet peer with route acceptance ready", func() bool { _, err := d.request(t, d.peer, "readyz", ""); return err == nil })
}

func singleGatewayProbeStable(before, now *corev1.Pod) bool {
	if before == nil || now == nil || before.UID == "" || before.UID != now.UID || now.DeletionTimestamp != nil ||
		before.Status.PodIP == "" || before.Status.PodIP != now.Status.PodIP || !reflect.DeepEqual(before.Spec, now.Spec) {
		return false
	}
	for _, pair := range [][2][]corev1.ContainerStatus{{before.Status.InitContainerStatuses, now.Status.InitContainerStatuses}, {before.Status.ContainerStatuses, now.Status.ContainerStatuses}} {
		if len(pair[0]) != 1 || len(pair[1]) != 1 {
			return false
		}
		a, b := pair[0][0], pair[1][0]
		if a.Name != b.Name || a.ContainerID == "" || a.ContainerID != b.ContainerID || a.ImageID == "" || a.ImageID != b.ImageID || b.RestartCount != 0 || !reflect.DeepEqual(a.State, b.State) || !reflect.DeepEqual(a.LastTerminationState, b.LastTerminationState) {
			return false
		}
	}
	return true
}

func forwardedByGateway(r probe.Result, gatewayPodIP string) bool {
	ip, err := netip.ParseAddr(gatewayPodIP)
	if err != nil || !ip.Is4() || !ip.IsPrivate() || ip.String() != gatewayPodIP || r.DNSVerified || r.AnswerIPv4 != "" {
		return false
	}
	return r.Mode == "forward" && r.Connected && r.TargetVerified && r.RouteSelected && r.Error == "" && r.SourceIPv4 == gatewayPodIP
}

func (d *gatewayDataPlane) prove(t *testing.T, phase string, p *corev1.Pod, binding gateway.GatewayStateBinding) {
	t.Helper()
	d.startPeer(t, binding.IPv4)
	if p.Status.PodIP == "" || p.Status.PodIP == d.peer.Status.PodIP || p.Status.PodIP == d.target.Status.PodIP || d.peer.Status.PodIP == d.target.Status.PodIP {
		t.Fatal("data-plane actors are not independent IPv4 Pods")
	}
	stable := func() {
		t.Helper()
		for _, pod := range []*corev1.Pod{d.peer, d.target, p} {
			now := &corev1.Pod{}
			if d.pf.f.kube.Get(t.Context(), client.ObjectKeyFromObject(pod), now) != nil {
				t.Fatal("data-plane actor disappeared")
			}
			ok := singleGatewayProbeStable(pod, now)
			if pod == p {
				ok = gatewayProcessesStable(pod, now)
			}
			if !ok {
				t.Fatal("data-plane actor UID/process changed during proof")
			}
		}
	}
	setApproval := func(approve bool) {
		t.Helper()
		stable()
		routes := ""
		if approve {
			routes = d.prefix
		}
		// Only this isolated, state-bound node is changed. No autoApprovers or
		// production policy changes can make the before/after control pass.
		d.pf.cli("nodes", "approve-routes", "--identifier", binding.NodeID, "--routes", routes, "--output", "json")
		eventually(t, "Headscale acknowledges exact gateway route approval", func() bool {
			nodes, ok := decodeGatewayCLINodes(d.pf.cli("nodes", "list", "--output", "json"))
			if !ok {
				return false
			}
			for _, n := range nodes {
				if n.ID == binding.NodeID {
					if approve {
						return slices.Equal(n.ApprovedRoutes, []string{d.prefix})
					}
					return len(n.ApprovedRoutes) == 0
				}
			}
			return false
		})
	}
	last := map[string]any{}
	t.Cleanup(func() {
		if t.Failed() {
			d.pf.save("gateway-"+phase+"-last-probes.json", last)
		}
	})
	observe := func(mode string) (probe.Result, bool) {
		b, err := d.request(t, d.peer, "probe", probe.RequestBody(mode))
		if err != nil {
			last[mode] = map[string]bool{"requestSucceeded": false}
			return probe.Result{}, false
		}
		r, err := probe.DecodeResult(b)
		if err != nil {
			last[mode] = map[string]bool{"requestSucceeded": true, "decoded": false}
			return probe.Result{}, false
		}
		last[mode] = r
		return r, r.Mode == mode
	}
	noRoute := func() probe.Result {
		t.Helper()
		var result probe.Result
		observations := 0
		eventually(t, "peer observes withdrawn route without native fallback", func() bool {
			r, ok := observe("forward")
			if ok && !r.RouteSelected && !r.Connected && !r.TargetVerified && r.Error == "noRoute" {
				result = r
				observations++
				return observations >= 3
			}
			observations = 0
			return false
		})
		return result
	}
	setApproval(false)
	before := noRoute()
	var native probe.Result
	eventually(t, "underlay control reaches target from peer, not gateway", func() bool {
		r, ok := observe("underlay")
		if ok && r.Connected && r.TargetVerified && r.Error == "" && r.SourceIPv4 == d.peer.Status.PodIP && r.SourceIPv4 != p.Status.PodIP {
			native = r
			return true
		}
		return false
	})
	setApproval(true)
	var forwarded probe.Result
	eventually(t, "real TCP challenge traverses kernel gateway", func() bool {
		r, ok := observe("forward")
		if ok && forwardedByGateway(r, p.Status.PodIP) {
			forwarded = r
			return true
		}
		return false
	})
	dns := map[string]probe.Result{}
	for _, mode := range []string{"dns-udp", "dns-tcp"} {
		eventually(t, "known local DNS answer over gateway tailnet IPv4 ("+mode+")", func() bool {
			r, ok := observe(mode)
			if ok && r.Connected && r.DNSVerified && r.AnswerIPv4 == "198.51.100.8" && r.Error == "" {
				dns[mode] = r
				return true
			}
			return false
		})
	}
	setApproval(false)
	after := noRoute()
	stable()
	d.pf.save("gateway-"+phase+"-data-plane.json", map[string]any{
		"gatewayPodUID": p.UID, "gatewayPodIPv4": p.Status.PodIP, "gatewayTailnetIPv4": binding.IPv4, "nodeID": binding.NodeID,
		"peerPodUID": d.peer.UID, "peerPodIPv4": d.peer.Status.PodIP, "targetPodUID": d.target.UID, "targetPodIPv4": d.target.Status.PodIP,
		"approvedPrefix": d.prefix, "beforeApproval": before, "underlayControl": native, "forwarded": forwarded, "dns": dns, "afterRevocation": after,
	})
}
