//go:build e2e_kind

package e2ekind

import (
	"reflect"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/gateway"
	"tsunaro.io/tailnet-operator/test/internal/kindfixture"
)

const gatewayTestNode = "tn-kind-abcdefghij-control-plane"
const gatewayTestGate = "localhost/tn-source-netprobe:tn-kind-abcdefghij"
const gatewayTestGateDigest = "localhost/tn-source-netprobe@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func gatewayStartupFixture(t *testing.T) (*corev1.Pod, map[string]string) {
	t.Helper()
	images := map[string]string{"tailscale": "ghcr.io/tailscale/tailscale@sha256:" + strings.Repeat("1", 64), "coredns": "docker.io/coredns/coredns@sha256:" + strings.Repeat("2", 64)}
	g := &tnv1.TailnetGateway{ObjectMeta: metav1.ObjectMeta{Name: "router", UID: "gateway-uid"}, Spec: tnv1.TailnetGatewaySpec{
		TailnetRef: tnv1.GatewayLocalReference{Name: "tailnet"}, Hostname: "router", Replicas: 1, DeletionPolicy: "Retain",
		StateSecretRef: tnv1.GatewayLocalReference{Name: "router-state"}, AuthKeySecretRef: &tnv1.GatewayAuthKeyReference{Name: "router-auth", Key: "TS_AUTHKEY"},
		Image: tnv1.GatewayImage(images["tailscale"]), Tags: []string{"tag:fabric"},
		Routes:  tnv1.GatewayRoutes{LAN: []tnv1.GatewayPrefix{"192.0.2.0/24"}},
		Service: tnv1.GatewayService{LoadBalancerIP: "198.51.100.1", TailnetLBCIDR: "198.51.100.0/24"},
		DNS:     tnv1.GatewayDNS{Zone: "tail.example", ServiceName: "router-dns", ServiceClusterIP: "10.96.0.53", Image: tnv1.GatewayImage(images["coredns"])},
	}}
	plan, err := gateway.RenderFresh(gateway.FreshInputs{Namespace: namespace, Gateway: g, Tailnet: &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "tailnet"}, Spec: tnv1.TailnetSpec{Server: "https://headscale.example"}}, DNSSerial: 1})
	if err != nil {
		t.Fatal("render gateway startup fixture")
	}
	for _, obj := range plan.Objects {
		if sts, ok := obj.(*appsv1.StatefulSet); ok {
			p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "router-0", Namespace: namespace, UID: "11111111-1111-1111-1111-111111111111"}, Spec: *sts.Spec.Template.Spec.DeepCopy()}
			p.Spec.NodeName = gatewayTestNode
			for i := range p.Spec.Containers {
				p.Spec.Containers[i].ImagePullPolicy = corev1.PullNever
			}
			p.Spec.InitContainers[0].ImagePullPolicy = corev1.PullNever
			if kindfixture.AddGatewayNetworkGate(p, gatewayTestGate) != nil {
				t.Fatal("gate actual fresh gateway shape")
			}
			return p, images
		}
	}
	t.Fatal("fresh gateway StatefulSet missing")
	return nil, nil
}

func gatewayBlockedStatus() corev1.PodStatus {
	return corev1.PodStatus{
		InitContainerStatuses: []corev1.ContainerStatus{
			{Name: kindfixture.NetworkGateContainer, ContainerID: "containerd://gate", ImageID: gatewayTestGateDigest, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
			{Name: "kernel-preflight", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "PodInitializing"}}},
		},
		ContainerStatuses: []corev1.ContainerStatus{{Name: "tailscale"}, {Name: "coredns"}},
	}
}

func gatewayStartedStatus(images map[string]string) corev1.PodStatus {
	return corev1.PodStatus{
		InitContainerStatuses: []corev1.ContainerStatus{
			{Name: kindfixture.NetworkGateContainer, ContainerID: "containerd://gate", ImageID: gatewayTestGateDigest, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}},
			{Name: "kernel-preflight", ContainerID: "containerd://preflight", ImageID: images["tailscale"], State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}},
		},
		ContainerStatuses: []corev1.ContainerStatus{
			{Name: "tailscale", ContainerID: "containerd://tailscale", ImageID: images["tailscale"], State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
			{Name: "coredns", ContainerID: "containerd://coredns", ImageID: images["coredns"], State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
		},
	}
}

func TestGatewayStartupContract(t *testing.T) {
	p, images := gatewayStartupFixture(t)
	before := p.DeepCopy()
	g, err := newGatewayStartup(p, gatewayTestNode, gatewayTestGate, images)
	if err != nil || !reflect.DeepEqual(p, before) {
		t.Fatal("fresh startup shape rejected or mutated")
	}
	p.Status = gatewayBlockedStatus()
	if !g.blocked(p, []string{gatewayTestGateDigest}) || g.started(p, "containerd://gate", []string{gatewayTestGateDigest}) {
		t.Fatal("blocked gateway classification failed")
	}
	// Pending statuses may be absent; none may already have run.
	p.Status.InitContainerStatuses = p.Status.InitContainerStatuses[:1]
	p.Status.ContainerStatuses = nil
	if !g.blocked(p, []string{gatewayTestGateDigest}) {
		t.Fatal("pending statuses required prematurely")
	}
	p.Status = gatewayStartedStatus(images)
	if !g.started(p, "containerd://gate", []string{gatewayTestGateDigest}) || g.blocked(p, []string{gatewayTestGateDigest}) {
		t.Fatal("started gateway classification failed")
	}
	// The API's status list order is not an identity binding.
	p.Status.InitContainerStatuses[0], p.Status.InitContainerStatuses[1] = p.Status.InitContainerStatuses[1], p.Status.InitContainerStatuses[0]
	p.Status.ContainerStatuses[0], p.Status.ContainerStatuses[1] = p.Status.ContainerStatuses[1], p.Status.ContainerStatuses[0]
	if !g.started(p, "containerd://gate", []string{gatewayTestGateDigest}) || fixtureGateID(p) != "containerd://gate" {
		t.Fatal("status reorder changed process identity")
	}
	if singleFixtureStarted(p, "containerd://gate", nil) || singleFixtureBlocked(p, []string{gatewayTestGateDigest}) {
		t.Fatal("legacy singleton contract admitted gateway")
	}
}

func TestGatewayStartupRejectsEarlyExecution(t *testing.T) {
	for name, change := range map[string]func(*corev1.Pod){
		"preflight started": func(p *corev1.Pod) {
			p.Status.InitContainerStatuses[1].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
		},
		"preflight already finished": func(p *corev1.Pod) {
			p.Status.InitContainerStatuses[1].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}}
		},
		"preflight previous execution": func(p *corev1.Pod) {
			p.Status.InitContainerStatuses[1].LastTerminationState.Terminated = &corev1.ContainerStateTerminated{}
		},
		"app started":         func(p *corev1.Pod) { p.Status.ContainerStatuses[0].State.Running = &corev1.ContainerStateRunning{} },
		"app container ID":    func(p *corev1.Pod) { p.Status.ContainerStatuses[1].ContainerID = "unexpected" },
		"app restart":         func(p *corev1.Pod) { p.Status.ContainerStatuses[1].RestartCount = 1 },
		"gate restart":        func(p *corev1.Pod) { p.Status.InitContainerStatuses[0].RestartCount = 1 },
		"foreign gate digest": func(p *corev1.Pod) { p.Status.InitContainerStatuses[0].ImageID = "foreign" },
		"duplicate gate":      func(p *corev1.Pod) { p.Status.InitContainerStatuses[1] = p.Status.InitContainerStatuses[0] },
		"unknown app":         func(p *corev1.Pod) { p.Status.ContainerStatuses[1].Name = "foreign" },
		"UID":                 func(p *corev1.Pod) { p.UID = "replacement" },
		"node":                func(p *corev1.Pod) { p.Spec.NodeName = "foreign" },
		"spec":                func(p *corev1.Pod) { p.Spec.Containers[0].Command = []string{"/changed"} },
		"ephemeral":           func(p *corev1.Pod) { p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{}} },
		"deleting":            func(p *corev1.Pod) { p.DeletionTimestamp = ptr.To(metav1.Now()) },
	} {
		t.Run(name, func(t *testing.T) {
			p, images := gatewayStartupFixture(t)
			g, err := newGatewayStartup(p, gatewayTestNode, gatewayTestGate, images)
			if err != nil {
				t.Fatal(err)
			}
			p.Status = gatewayBlockedStatus()
			change(p)
			if g.blocked(p, []string{gatewayTestGateDigest}) {
				t.Fatal("unproved pre-release execution accepted")
			}
		})
	}
}

func TestGatewayStartupRejectsUnboundProcesses(t *testing.T) {
	for name, change := range map[string]func(*corev1.Pod){
		"gate replaced":    func(p *corev1.Pod) { p.Status.InitContainerStatuses[0].ContainerID = "replacement" },
		"preflight failed": func(p *corev1.Pod) { p.Status.InitContainerStatuses[1].State.Terminated.ExitCode = 1 },
		"preflight running": func(p *corev1.Pod) {
			p.Status.InitContainerStatuses[1].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
		},
		"preflight wrong image": func(p *corev1.Pod) { p.Status.InitContainerStatuses[1].ImageID = "foreign" },
		"app wrong image":       func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ImageID = "foreign" },
		"app restarted":         func(p *corev1.Pod) { p.Status.ContainerStatuses[0].RestartCount = 1 },
		"app previous execution": func(p *corev1.Pod) {
			p.Status.ContainerStatuses[1].LastTerminationState.Terminated = &corev1.ContainerStateTerminated{}
		},
		"app missing":   func(p *corev1.Pod) { p.Status.ContainerStatuses = p.Status.ContainerStatuses[:1] },
		"duplicate app": func(p *corev1.Pod) { p.Status.ContainerStatuses[1] = p.Status.ContainerStatuses[0] },
		"shared process ID": func(p *corev1.Pod) {
			p.Status.ContainerStatuses[1].ContainerID = p.Status.ContainerStatuses[0].ContainerID
		},
		"preflight missing": func(p *corev1.Pod) { p.Status.InitContainerStatuses = p.Status.InitContainerStatuses[:1] },
		"UID":               func(p *corev1.Pod) { p.UID = "replacement" },
	} {
		t.Run(name, func(t *testing.T) {
			p, images := gatewayStartupFixture(t)
			g, err := newGatewayStartup(p, gatewayTestNode, gatewayTestGate, images)
			if err != nil {
				t.Fatal(err)
			}
			p.Status = gatewayStartedStatus(images)
			change(p)
			if g.started(p, "containerd://gate", []string{gatewayTestGateDigest}) {
				t.Fatal("unbound process accepted")
			}
		})
	}
}
