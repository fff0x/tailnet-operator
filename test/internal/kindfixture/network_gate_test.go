package kindfixture

import (
	"encoding/json"
	"reflect"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	corev1 "k8s.io/api/core/v1"
)

const ownedGateImage = "localhost/tn-source-netprobe:tn-kind-012345abcd"

func hardenedFixturePod(t *testing.T) corev1.Pod {
	t.Helper()
	_, _, p := agentFixture(t)
	yes, no := true, false
	uid := int64(65532)
	p.Spec.SecurityContext = &corev1.PodSecurityContext{RunAsUser: &uid, RunAsNonRoot: &yes}
	p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}
	return p
}

func TestNetworkGatePreservesApplication(t *testing.T) {
	original := hardenedFixturePod(t)
	p := original.DeepCopy()
	if AddNetworkGate(p, ownedGateImage) != nil {
		t.Fatal("safe fixture gate rejected")
	}
	if len(p.Spec.InitContainers) != 1 || len(p.Spec.Volumes) != len(original.Spec.Volumes)+1 {
		t.Fatal("wrong gate shape")
	}
	c := p.Spec.InitContainers[0]
	v := p.Spec.Volumes[len(p.Spec.Volumes)-1]
	if c.Name != NetworkGateContainer || c.Image != ownedGateImage || c.ImagePullPolicy != corev1.PullNever || !reflect.DeepEqual(c.Command, []string{"/netgate"}) || !reflect.DeepEqual(c.Args, []string{"--action=hold", "--fixture=p1.8-http"}) || len(c.Env) != 1 || c.Env[0].ValueFrom == nil || c.Env[0].ValueFrom.FieldRef == nil || c.Env[0].ValueFrom.FieldRef.FieldPath != "metadata.uid" {
		t.Fatal("gate identity is not downward-bound")
	}
	if *c.SecurityContext.RunAsUser != 65532 || *c.SecurityContext.RunAsGroup != 65532 || !*c.SecurityContext.RunAsNonRoot || *c.SecurityContext.AllowPrivilegeEscalation || !*c.SecurityContext.ReadOnlyRootFilesystem || !reflect.DeepEqual(c.SecurityContext.Capabilities.Drop, []corev1.Capability{"ALL"}) || len(c.SecurityContext.Capabilities.Add) != 0 || c.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatal("gate privileges expanded")
	}
	if v.EmptyDir == nil || v.EmptyDir.Medium != corev1.StorageMediumMemory || v.EmptyDir.SizeLimit == nil || v.EmptyDir.SizeLimit.Value() != 4<<20 || len(c.VolumeMounts) != 1 || c.VolumeMounts[0].Name != v.Name || c.VolumeMounts[0].MountPath != "/fixture-gate" || c.VolumeMounts[0].ReadOnly {
		t.Fatal("gate storage not private to init")
	}
	p.Spec.InitContainers = nil
	p.Spec.Volumes = p.Spec.Volumes[:len(p.Spec.Volumes)-1]
	if !reflect.DeepEqual(*p, original) {
		t.Fatal("gate changed application or existing Pod fields")
	}
}

func TestNetworkGateRejectsUnexpectedPod(t *testing.T) {
	for name, change := range map[string]func(*corev1.Pod){
		"init":      func(p *corev1.Pod) { p.Spec.InitContainers = []corev1.Container{{Name: "foreign"}} },
		"ephemeral": func(p *corev1.Pod) { p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{}} },
		"volume":    func(p *corev1.Pod) { p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: networkGateVolume}) },
		"application access": func(p *corev1.Pod) {
			p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: networkGateVolume, MountPath: "/read-gate"})
		},
		"host":     func(p *corev1.Pod) { p.Spec.HostNetwork = true },
		"hostpath": func(p *corev1.Pod) { p.Spec.Volumes[0].HostPath = &corev1.HostPathVolumeSource{Path: "/"} },
		"token":    func(p *corev1.Pod) { p.Spec.AutomountServiceAccountToken = nil },
		"caps": func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"NET_ADMIN"}
		},
		"privilege": func(p *corev1.Pod) { yes := true; p.Spec.Containers[0].SecurityContext.Privileged = &yes },
		"uid":       func(p *corev1.Pod) { root := int64(0); p.Spec.Containers[0].SecurityContext.RunAsUser = &root },
	} {
		t.Run(name, func(t *testing.T) {
			p := hardenedFixturePod(t)
			change(&p)
			before := p.DeepCopy()
			if AddNetworkGate(&p, ownedGateImage) != ErrAgentCA || !reflect.DeepEqual(p, *before) {
				t.Fatal("unsafe Pod accepted or mutated on rejection")
			}
		})
	}
	for _, image := range []string{"", "registry.example/fixture:tag", "localhost/tn-source-netprobe:tn-kind-../x", ownedGateImage + "x"} {
		p := hardenedFixturePod(t)
		if AddNetworkGate(&p, image) != ErrAgentCA {
			t.Fatal("unexpected gate image accepted")
		}
	}
}

func TestAgentCAOptionalNetworkGate(t *testing.T) {
	req, cfg, _ := agentFixture(t)
	p := hardenedFixturePod(t)
	req.Object.Raw, _ = json.Marshal(p)
	cfg.NetworkGateImage = ownedGateImage
	b, err := AgentCAPatch(req, cfg)
	if err != nil {
		t.Fatal("optional gate rejected")
	}
	patch, err := jsonpatch.DecodePatch(b)
	if err != nil {
		t.Fatal("gate patch invalid")
	}
	raw, err := patch.Apply(req.Object.Raw)
	if err != nil {
		t.Fatal("gate patch cannot apply")
	}
	var got corev1.Pod
	if json.Unmarshal(raw, &got) != nil || len(got.Spec.InitContainers) != 1 || len(got.Spec.Volumes) != 3 || len(got.Spec.Containers[0].VolumeMounts) != 2 {
		t.Fatal("optional gate not present")
	}
	got.Spec.InitContainers = nil
	got.Spec.Volumes = got.Spec.Volumes[:1]
	got.Spec.Containers[0].VolumeMounts = got.Spec.Containers[0].VolumeMounts[:1]
	if !reflect.DeepEqual(got, p) {
		t.Fatal("optional gate changed production application fields")
	}
}
