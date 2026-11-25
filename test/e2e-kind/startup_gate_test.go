//go:build e2e_kind

package e2ekind

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tsunaro.io/tailnet-operator/test/internal/kindfixture"
	"tsunaro.io/tailnet-operator/test/internal/netproof"
)

type nodeObservation struct {
	ID     string                             `json:"Id"`
	Name   string                             `json:"Name"`
	Config struct{ Labels map[string]string } `json:"Config"`
	State  struct {
		Pid     int
		Running bool
	} `json:"State"`
	NetworkSettings json.RawMessage `json:"NetworkSettings"`
}

type outerNetwork struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Internal bool              `json:"internal"`
	DNS      bool              `json:"dns_enabled"`
	IPv6     bool              `json:"ipv6_enabled"`
	Labels   map[string]string `json:"labels"`
	Options  map[string]string `json:"options"`
	Subnets  []struct {
		Subnet  string `json:"subnet"`
		Gateway any    `json:"gateway"`
	} `json:"subnets"`
	Containers map[string]json.RawMessage `json:"containers"`
}

// releaseFixturePod verifies and releases an already-created, gated fixture Pod.
// The caller owns its namespace, cleanup and application image; only the init
// image is bound to the runner's original probe CRI digest here.
func releaseFixturePod(t *testing.T, f *fixture, pod *corev1.Pod) {
	t.Helper()
	if pod == nil || pod.Namespace != namespace || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(string(pod.UID)) || len(pod.Spec.Containers) != 1 {
		t.Fatal("created owned fixture Pod required")
	}
	image := os.Getenv("E2E_KIND_FIXTURE_IMAGE")
	if image != "localhost/tn-source-netprobe:"+f.cluster {
		t.Fatal("unexpected init fixture image")
	}
	if len(pod.Spec.InitContainers) != 1 || pod.Spec.InitContainers[0].Name != kindfixture.NetworkGateContainer || pod.Spec.InitContainers[0].Image != image {
		t.Fatal("fixture network gate required")
	}
	releaseBoundFixturePod(t, f, pod, singleFixtureBlocked, singleFixtureStarted)
}

// Keep the legacy single-app contract separate from the kernel-gateway shape.
func singleFixtureBlocked(p *corev1.Pod, gateDigests []string) bool {
	if len(p.Status.InitContainerStatuses) != 1 {
		return false
	}
	s := p.Status.InitContainerStatuses[0]
	known := false
	for _, d := range gateDigests {
		known = known || s.ImageID == d
	}
	if s.Name != kindfixture.NetworkGateContainer || s.RestartCount != 0 || s.State.Running == nil || s.ContainerID == "" || !known {
		return false
	}
	for _, c := range p.Status.ContainerStatuses {
		if c.State.Running != nil || c.State.Terminated != nil || c.ContainerID != "" || c.RestartCount != 0 {
			return false
		}
	}
	return true
}

func singleFixtureStarted(p *corev1.Pod, initID string, _ []string) bool {
	if len(p.Status.InitContainerStatuses) != 1 || len(p.Status.ContainerStatuses) != 1 {
		return false
	}
	i, c := p.Status.InitContainerStatuses[0], p.Status.ContainerStatuses[0]
	return i.ContainerID == initID && i.RestartCount == 0 && i.State.Terminated != nil && i.State.Terminated.ExitCode == 0 && c.State.Running != nil && c.RestartCount == 0
}

// kubectl exec exits with the remote status. A valid release ends the gate container, and the
// kernel then SIGKILLs the exec if it has not exited yet (pid_namespaces(7)).
func releaseKilled(err error) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == 137
}

func fixtureGateID(p *corev1.Pod) string {
	for _, s := range p.Status.InitContainerStatuses {
		if s.Name == kindfixture.NetworkGateContainer {
			return s.ContainerID
		}
	}
	return ""
}

// Both entrypoints use the same live UID/node/network proof, approval expiry and
// negative releases. Their status predicates are distinct, fixed test contracts.
func releaseBoundFixturePod(t *testing.T, f *fixture, pod *corev1.Pod, blockedState func(*corev1.Pod, []string) bool, startedState func(*corev1.Pod, string, []string) bool) {
	t.Helper()
	if pod == nil || pod.Namespace != namespace || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(string(pod.UID)) {
		t.Fatal("created owned fixture Pod required")
	}
	root := os.Getenv("E2E_KIND_NET_EVIDENCE")
	info, err := os.Lstat(root)
	if err != nil || !filepath.IsAbs(root) || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		t.Fatal("private runner evidence missing")
	}
	evidence := filepath.Join(root, "startup-"+string(pod.UID))
	if os.Mkdir(evidence, 0700) != nil {
		t.Fatal("private startup evidence directory creation failed")
	}
	save := func(name string, b []byte) {
		t.Helper()
		file, err := os.OpenFile(filepath.Join(evidence, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal("private init evidence creation failed")
		}
		_, writeErr := file.Write(b)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatal("private init evidence write failed")
		}
	}
	read := func(name string, dst any) {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || len(b) > 4<<20 || json.Unmarshal(b, dst) != nil {
			t.Fatal("private baseline invalid")
		}
	}
	var baseline []nodeObservation
	read("node-container-after.json", &baseline)
	var nets []outerNetwork
	read("network-before.json", &nets)
	var cri struct {
		Status struct {
			RepoDigests []string `json:"repoDigests"`
		} `json:"status"`
	}
	read("probe-cri-image.json", &cri)
	if len(baseline) != 1 || len(nets) != 1 || len(nets[0].Subnets) != 1 {
		t.Fatal("baseline binding ambiguous")
	}
	base := baseline[0]
	network := nets[0]
	outer, err := netip.ParsePrefix(network.Subnets[0].Subnet)
	if err != nil {
		t.Fatal("outer prefix invalid")
	}
	observation := 0
	observeNodeContext := func(ctx context.Context, mode string) ([]byte, error) {
		b, err := f.command(ctx, "", filepath.Join(f.work, "node-observation"), mode)
		if len(b) > 4<<20 {
			t.Fatal("node observation exceeds bound")
		}
		save(fmt.Sprintf("init-observation-%d-%s.json", observation, mode), b)
		observation++
		return b, err
	}
	saveJSON := func(name string, v any) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal("private observation encoding failed")
		}
		save(name, b)
	}
	nodeBindingContext := func(ctx context.Context) bool {
		b, err := observeNodeContext(ctx, "inspect")
		if err != nil || len(b) > 4<<20 {
			return false
		}
		var v []nodeObservation
		if json.Unmarshal(b, &v) != nil || len(v) != 1 {
			return false
		}
		n := v[0]
		if n.ID != base.ID || n.Name != f.cluster+"-control-plane" || !n.State.Running || n.State.Pid != base.State.Pid || !reflect.DeepEqual(n.Config.Labels, base.Config.Labels) || !bytes.Equal(n.NetworkSettings, base.NetworkSettings) {
			return false
		}
		b, err = observeNodeContext(ctx, "network")
		if err != nil || len(b) > 4<<20 {
			return false
		}
		var ns []outerNetwork
		if json.Unmarshal(b, &ns) != nil || len(ns) != 1 {
			return false
		}
		vnet := ns[0]
		if vnet.ID != network.ID || vnet.Name != f.cluster+"-net" || !vnet.Internal || vnet.DNS || vnet.IPv6 || vnet.Options["isolate"] != "true" || vnet.Labels["netproof-owner"] != f.cluster || !reflect.DeepEqual(vnet.Subnets, network.Subnets) || len(vnet.Containers) != 1 {
			return false
		}
		_, ok := vnet.Containers[base.ID]
		return ok
	}
	observeNode := func(mode string) ([]byte, error) { return observeNodeContext(t.Context(), mode) }
	nodeBinding := func() bool { return nodeBindingContext(t.Context()) }
	if !nodeBinding() {
		t.Fatal("owned node binding changed")
	}
	ownedUID := pod.UID
	blocked := func(p *corev1.Pod) bool {
		return p.UID == ownedUID && p.DeletionTimestamp == nil && p.Spec.NodeName == f.cluster+"-control-plane" && blockedState(p, cri.Status.RepoDigests)
	}
	eventually(t, "blocked init and assigned Pod network", func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(pod), pod) == nil && pod.Status.PodIP != "" && blocked(pod)
	})
	initID := fixtureGateID(pod)
	execGate := func(ctx context.Context, action, input string) ([]byte, error) {
		return f.command(ctx, input, "kubectl", "--kubeconfig", f.config, "--context", f.context, "--request-timeout=10s", "-n", namespace, "exec", "-i", pod.Name, "-c", kindfixture.NetworkGateContainer, "--", "/netgate", "--action="+action, "--fixture=p1.8-http")
	}
	var document struct {
		Version  int             `json:"version"`
		PodUID   string          `json:"podUID"`
		Epoch    string          `json:"epoch"`
		Captured int64           `json:"capturedAtMillis"`
		Snapshot json.RawMessage `json:"snapshot"`
	}
	var raw []byte
	var provedAt time.Time
	var podIPv4 netproof.DialCategory
	// Retain failed captures privately, including transient IPv6 DAD rejection.
	deadline := time.Now().Add(30 * time.Second)
	proved := false
	for attempt := 0; time.Now().Before(deadline); attempt++ {
		var before, after corev1.Node
		if f.kube.Get(t.Context(), client.ObjectKey{Name: f.cluster + "-control-plane"}, &before) != nil {
			t.Fatal("owned node lookup failed")
		}
		if f.kube.Get(t.Context(), client.ObjectKeyFromObject(pod), pod) != nil || !blocked(pod) || !nodeBinding() {
			t.Fatal("pre-capture identity changed")
		}
		podBefore := pod.DeepCopy()
		saveJSON(fmt.Sprintf("init-node-api-before-%d.json", attempt), &before)
		saveJSON(fmt.Sprintf("init-pod-api-before-%d.json", attempt), podBefore)
		started := time.Now()
		nb, ne := observeNode("capture")
		pb, pe := execGate(t.Context(), "snapshot", "")
		save(fmt.Sprintf("init-node-%d.json", attempt), nb)
		save(fmt.Sprintf("init-pod-%d.json", attempt), pb)
		attemptResult, _ := json.Marshal(map[string]bool{"nodeCapturePassed": ne == nil, "podCapturePassed": pe == nil})
		save(fmt.Sprintf("init-capture-%d.json", attempt), attemptResult)
		if ne != nil || pe != nil {
			time.Sleep(time.Second)
			continue
		}
		if time.Since(started) > 12*time.Second {
			continue
		}
		if len(pb) > netproof.MaxJSON+1024 || json.Unmarshal(pb, &document) != nil || document.Version != 1 || document.PodUID != string(ownedUID) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(document.Epoch) {
			t.Fatal("init snapshot envelope rejected")
		}
		nodeSnap, err := netproof.DecodeSnapshot(bytes.NewReader(nb))
		if err != nil {
			t.Fatal("node snapshot rejected")
		}
		podSnap, err := netproof.DecodeSnapshot(bytes.NewReader(document.Snapshot))
		if err != nil {
			t.Fatal("Pod snapshot rejected")
		}
		var nodeIP netip.Addr
		for _, a := range before.Status.Addresses {
			if a.Type == corev1.NodeInternalIP {
				if nodeIP.IsValid() {
					t.Fatal("ambiguous node IP")
				}
				nodeIP, err = netip.ParseAddr(a.Address)
				if err != nil {
					t.Fatal("node IP invalid")
				}
			}
		}
		cidr, err := netip.ParsePrefix(before.Spec.PodCIDR)
		if err != nil {
			t.Fatal("Pod prefix invalid")
		}
		podIP, err := netip.ParseAddr(pod.Status.PodIP)
		if err != nil {
			t.Fatal("Pod IP invalid")
		}
		proof, err := netproof.VerifyNode(nodeSnap, netproof.NodeBinding{OuterCIDR: outer, NodeIP: nodeIP, PodCIDR: cidr})
		if err != nil || netproof.VerifyPod(podSnap, netproof.PodBinding{PodIP: podIP}, proof) != nil {
			t.Fatal("actual init Pod containment rejected")
		}
		podIPv4 = podSnap.Dials.IPv4
		if f.kube.Get(t.Context(), client.ObjectKey{Name: before.Name}, &after) != nil || f.kube.Get(t.Context(), client.ObjectKeyFromObject(pod), pod) != nil || !blocked(pod) || !nodeBinding() || before.UID != after.UID || !reflect.DeepEqual(before.Spec, after.Spec) || !reflect.DeepEqual(before.Status.Addresses, after.Status.Addresses) || !reflect.DeepEqual(podBefore.Spec, pod.Spec) || !reflect.DeepEqual(podBefore.Status, pod.Status) {
			t.Fatal("capture bindings changed")
		}
		saveJSON(fmt.Sprintf("init-node-api-after-%d.json", attempt), &after)
		saveJSON(fmt.Sprintf("init-pod-api-after-%d.json", attempt), pod)
		saveJSON(fmt.Sprintf("init-bindings-%d.json", attempt), map[string]any{"OuterCIDR": outer.String(), "NodeIP": nodeIP.String(), "PodCIDR": cidr.String(), "PodIP": podIP.String(), "hostProofStartedAtMillis": started.UnixMilli()})
		if fixtureGateID(pod) != initID {
			t.Fatal("init process replaced")
		}
		age := time.Since(time.UnixMilli(document.Captured))
		if age < 0 || age > 20*time.Second {
			continue
		}
		raw = pb
		provedAt = started
		proved = true
		break
	}
	if !proved {
		// Diagnose only the still-blocked, UID-bound init. These observations do
		// not approve or replace the failed proof, or extend either deadline.
		if f.kube.Get(t.Context(), client.ObjectKeyFromObject(pod), pod) == nil && blocked(pod) {
			ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
			args := []string{"--kubeconfig", f.config, "--context", f.context, "--request-timeout=5s", "-n", namespace, "exec", pod.Name, "-c", kindfixture.NetworkGateContainer, "--"}
			networkArgs := append(append([]string(nil), args...), "/netprobe", "--capture=pod", "--fixture=p1.8-layered-isolation")
			b, err := f.command(ctx, "", "kubectl", networkArgs...)
			save("failed-direct-netprobe.private.json", b)
			saveJSON("failed-capture-diagnostics.json", map[string]bool{"directCaptureSucceeded": err == nil, "approvalIssued": false})
			cancel()
		}
		t.Fatal("bounded init capture window exhausted")
	}
	// Exact raw stdout bytes (including newline) bind the host's approval.
	sum := sha256.Sum256(raw)
	expires := provedAt.Add(25 * time.Second)
	approval := map[string]any{"version": 1, "podUID": string(ownedUID), "epoch": document.Epoch, "snapshotSHA256": hex.EncodeToString(sum[:]), "hostProofExpiresAtMillis": expires.UnixMilli()}
	wrong := map[string]any{"version": 1, "podUID": string(ownedUID), "epoch": document.Epoch, "snapshotSHA256": string(bytes.Repeat([]byte("0"), 64)), "hostProofExpiresAtMillis": expires.UnixMilli()}
	bad, _ := json.Marshal(wrong)
	if _, err := execGate(t.Context(), "release", string(bad)); err == nil {
		t.Fatal("wrong snapshot approval accepted")
	}
	if f.kube.Get(t.Context(), client.ObjectKeyFromObject(pod), pod) != nil || !blocked(pod) || !nodeBinding() {
		t.Fatal("application started before valid release")
	}
	if time.Since(provedAt) > 25*time.Second {
		t.Fatal("host proof expired before release")
	}
	// A structurally valid hash does not override an expired host proof.
	expired := map[string]any{"version": 1, "podUID": string(ownedUID), "epoch": document.Epoch, "snapshotSHA256": hex.EncodeToString(sum[:]), "hostProofExpiresAtMillis": time.Now().Add(-time.Second).UnixMilli()}
	stale, _ := json.Marshal(expired)
	if _, err := execGate(t.Context(), "release", string(stale)); err == nil {
		t.Fatal("expired host proof accepted")
	}
	if f.kube.Get(t.Context(), client.ObjectKeyFromObject(pod), pod) != nil || !blocked(pod) {
		t.Fatal("expired proof started application")
	}
	good, _ := json.Marshal(approval)
	save("init-approval.json", good)
	saveJSON("init-release-before.json", map[string]int64{"atMillis": time.Now().UnixMilli()})
	releaseCtx, cancel := context.WithDeadline(t.Context(), expires)
	_, releaseErr := execGate(releaseCtx, "release", string(good))
	cancel()
	saveJSON("init-release-after.json", map[string]int64{"atMillis": time.Now().UnixMilli()})
	killed := releaseKilled(releaseErr)
	saveJSON("init-release-exec.json", map[string]bool{"succeeded": releaseErr == nil, "killedWithGate": killed})
	// A killed exec decides nothing; the startup check below requires the same gate container to end with 0.
	if (releaseErr != nil && !killed) || time.Now().After(expires) {
		t.Fatal("verified init release failed or exceeded host deadline")
	}
	eventually(t, "same Pod application startup", func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(pod), pod) == nil && pod.UID == ownedUID &&
			pod.DeletionTimestamp == nil && pod.Spec.NodeName == f.cluster+"-control-plane" && startedState(pod, initID, cri.Status.RepoDigests)
	})
	saveJSON("init-pod-started.json", pod)
	saveJSON("init-result.json", map[string]any{"actualNodeAndPodProof": true, "freshStableBindings": true, "nodeENETUNREACH": true, "podIPv4": podIPv4, "podIPv6": netproof.NetworkUnreachable, "wrongHashRejected": true, "expiredHostProofRejected": true, "applicationBlockedUntilRelease": true, "samePodAndInit": true, "zeroRestarts": true})
	t.Logf("gate: actual init Pod/UID/node proof, node ENETUNREACH, Pod IPv4 %s, wrong-hash/expired-host-proof rejection, blocked application until fresh release", podIPv4)
}

func TestReleaseExecClassification(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script string
		killed bool
	}{
		{"success", "exit 0", false},
		{"rejected", "exit 2", false},
		{"remote-kill", "exit 137", true},
		{"local-signal", "kill -KILL $$", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := releaseKilled(exec.Command("sh", "-c", tc.script).Run()); got != tc.killed {
				t.Fatalf("killed=%t; want %t", got, tc.killed)
			}
		})
	}
	if releaseKilled(errors.New("exit status 137")) || releaseKilled(nil) {
		t.Fatal("non-exit error classified as a killed release")
	}
}
