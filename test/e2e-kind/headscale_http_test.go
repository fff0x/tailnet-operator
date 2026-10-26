//go:build e2e_kind

package e2ekind

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"tsunaro.io/tailnet-operator/test/internal/kindfixture"
)

//go:embed headscale-http.json
var headscaleHTTPConfig string

// TestHeadscaleHTTPS is real control-plane TLS bootstrap, not tailnet traffic.
// Headscale and both TLS-check Pods must pass their own startup network proof.
func TestHeadscaleHTTPS(t *testing.T) {
	if os.Getenv("E2E_KIND_HTTP_NETWORK_GATE") == "" {
		t.Skip("requires isolated HTTP runner")
	}
	f := ownedFixture(t)
	if os.Getenv("E2E_KIND_HTTP_NETWORK_GATE") != "passed" {
		t.Fatal("network gate required")
	}
	image := os.Getenv("E2E_KIND_FIXTURE_IMAGE")
	if image != "localhost/tn-source-netprobe:"+f.cluster {
		t.Fatal("owned fixture image required")
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	if f.kube.Create(t.Context(), ns) != nil {
		t.Fatal("Headscale namespace creation failed")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if err := f.kube.Delete(ctx, ns, client.Preconditions{UID: &ns.UID}); err != nil && !apierrors.IsNotFound(err) {
			t.Error("Headscale namespace deletion failed")
			return
		}
		for {
			if apierrors.IsNotFound(f.kube.Get(ctx, client.ObjectKey{Name: namespace}, &corev1.Namespace{})) {
				t.Log("gate: owned HTTPS namespace removed")
				return
			}
			select {
			case <-ctx.Done():
				t.Error("Headscale namespace cleanup timed out")
				return
			case <-time.After(time.Second):
			}
		}
	})
	create := func(o client.Object) {
		t.Helper()
		if f.kube.Create(t.Context(), o) != nil {
			t.Fatal("owned HTTPS resource creation failed")
		}
	}
	if ns.Labels == nil {
		ns.Labels = map[string]string{}
	}
	ns.Labels[kindfixture.OwnerLabel] = string(ns.UID)
	if f.kube.Update(t.Context(), ns) != nil {
		t.Fatal("control namespace ownership binding failed")
	}
	yes, no := true, false
	uid, mode, grace := int64(65532), int32(0440), int64(1)
	ca, err := kindfixture.NewAuthority(time.Now())
	if err != nil {
		t.Fatal("control authority failed")
	}
	public, err := kindfixture.PublicCAConfigMap(ns, "headscale-public-ca", ca.PublicPEM(), time.Now())
	if err != nil {
		t.Fatal("control trust rejected")
	}
	create(public)
	leaf, key, _, err := ca.Issue("fixture-headscale.tailnet-system.svc", time.Now(), time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatal("control leaf failed")
	}
	create(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "headscale-control-tls", Namespace: namespace}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{"tls.crt": leaf, "tls.key": key}})
	create(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "headscale-https-config", Namespace: namespace}, Immutable: &yes, Data: map[string]string{"config.json": headscaleHTTPConfig}})
	base := func(name string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{"fixture-app": name}}, Spec: corev1.PodSpec{
			AutomountServiceAccountToken: &no, EnableServiceLinks: &no, TerminationGracePeriodSeconds: &grace,
			SecurityContext: &corev1.PodSecurityContext{RunAsUser: &uid, RunAsGroup: &uid, RunAsNonRoot: &yes, FSGroup: &uid, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
			Containers:      []corev1.Container{{Name: "application", Image: image, ImagePullPolicy: corev1.PullNever, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}, Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("50m"), corev1.ResourceMemory: resource.MustParse("64Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("256Mi")}}}},
		}}
	}
	headscale := base("fixture-headscale")
	app := &headscale.Spec.Containers[0]
	app.Command = []string{"/headscale"}
	app.Args = []string{"--config", "/headscale-config/config.json", "serve"}
	app.Env = []corev1.EnvVar{{Name: "TS_NO_LOGS_NO_SUPPORT", Value: "1"}, {Name: "TMPDIR", Value: "/tmp"}}
	app.VolumeMounts = []corev1.VolumeMount{{Name: "config", MountPath: "/headscale-config", ReadOnly: true}, {Name: "tls", MountPath: "/headscale-tls", ReadOnly: true}, {Name: "state", MountPath: "/state"}, {Name: "tmp", MountPath: "/tmp"}}
	stateSize, tmpSize := resource.MustParse("64Mi"), resource.MustParse("16Mi")
	headscale.Spec.Volumes = []corev1.Volume{
		{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "headscale-https-config"}}}},
		{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "headscale-control-tls", DefaultMode: &mode}}},
		{Name: "state", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &stateSize}}},
		{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory, SizeLimit: &tmpSize}}},
	}
	if kindfixture.AddNetworkGate(headscale, image) != nil {
		t.Fatal("Headscale startup gate rejected")
	}
	// Service DNS is known before either Pod starts. Embedded DERP uses this same
	// hostname for TCP8443 and STUN UDP3478; no PodIP-generated config is needed.
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "fixture-headscale", Namespace: namespace}, Spec: corev1.ServiceSpec{Selector: headscale.Labels, Ports: []corev1.ServicePort{{Name: "https", Protocol: corev1.ProtocolTCP, Port: 8443, TargetPort: intstr.FromInt32(8443)}, {Name: "stun", Protocol: corev1.ProtocolUDP, Port: 3478, TargetPort: intstr.FromInt32(3478)}}}}
	create(service)
	create(headscale)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		root := os.Getenv("E2E_KIND_NET_EVIDENCE")
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return
		}
		for _, previous := range []bool{false, true} {
			args := []string{"--kubeconfig", f.config, "--context", f.context, "--request-timeout=5s", "-n", namespace, "logs", headscale.Name, "-c", "application", "--tail=100", "--limit-bytes=32768"}
			name := "headscale-current.private.log"
			if previous {
				args = append(args, "--previous")
				name = "headscale-previous.private.log"
			}
			b, _ := f.command(ctx, "", "kubectl", args...)
			file, err := os.OpenFile(filepath.Join(root, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err == nil {
				_, _ = file.Write(b)
				_ = file.Close()
			}
		}
	})
	releaseFixturePod(t, f, headscale)
	version, err := f.command(t.Context(), "", "kubectl", "--kubeconfig", f.config, "--context", f.context, "--request-timeout=10s", "-n", namespace, "exec", headscale.Name, "-c", "application", "--", "/headscale", "version")
	if err != nil || !strings.Contains(string(version), "0.29.6") {
		t.Fatal("pinned Headscale identity unavailable")
	}
	probe := func(name, caName string) *corev1.Pod {
		p := base(name)
		p.Spec.Containers[0].Command = []string{"/hold"}
		p.Spec.Containers[0].Args = []string{"--fixture=p1.8-layered-isolation"}
		p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "public-ca", MountPath: "/control-ca", ReadOnly: true}}
		p.Spec.Volumes = []corev1.Volume{{Name: "public-ca", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: caName}}}}}
		if kindfixture.AddNetworkGate(p, image) != nil {
			t.Fatal("control client startup gate rejected")
		}
		create(p)
		releaseFixturePod(t, f, p)
		return p
	}
	good := probe("control-trusted", public.Name)
	check := func(p *corev1.Pod) (bool, bool) {
		b, err := f.command(t.Context(), "", "kubectl", "--kubeconfig", f.config, "--context", f.context, "--request-timeout=10s", "-n", namespace, "exec", p.Name, "-c", "application", "--", "/controlprobe", "--fixture=p1.8-http")
		var status *exec.ExitError
		untrusted := errors.As(err, &status) && status.ExitCode() == 3 && len(b) == 0
		return err == nil && strings.TrimSpace(string(b)) == `{"verifiedControlTLS":true}`, untrusted
	}
	eventually(t, "verified HTTPS Headscale Service", func() bool { ok, _ := check(good); return ok })
	other, err := kindfixture.NewAuthority(time.Now())
	if err != nil {
		t.Fatal("negative control authority failed")
	}
	wrong, err := kindfixture.PublicCAConfigMap(ns, "headscale-wrong-ca", other.PublicPEM(), time.Now())
	if err != nil {
		t.Fatal("negative control trust rejected")
	}
	create(wrong)
	bad := probe("control-untrusted", wrong.Name)
	if ok, untrusted := check(bad); ok || !untrusted {
		t.Fatal("wrong CA did not produce actual chain rejection")
	}
	if ok, _ := check(good); !ok {
		t.Fatal("trusted control connection did not recover")
	}
	if f.kube.Get(t.Context(), client.ObjectKeyFromObject(headscale), headscale) != nil || len(headscale.Status.ContainerStatuses) != 1 || headscale.Status.ContainerStatuses[0].RestartCount != 0 || headscale.Status.ContainerStatuses[0].State.Running == nil {
		t.Fatal("Headscale restarted during control acceptance")
	}
	result := map[string]any{"headscaleVersion": "0.29.6", "verifiedServiceTLS": true, "wrongCARejected": true, "trustedConnectionAfterRejection": true, "startupGatedPods": 3, "headscaleRestarts": 0, "tsnetStarted": false, "derpTrafficTested": false}
	b, _ := json.Marshal(result)
	evidence := os.Getenv("E2E_KIND_NET_EVIDENCE")
	info, err := os.Lstat(evidence)
	if err != nil || !filepath.IsAbs(evidence) || !info.IsDir() || info.Mode().Perm()&0077 != 0 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("private control evidence missing")
	}
	file, err := os.OpenFile(filepath.Join(evidence, "headscale-https-result.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("control evidence creation failed")
	}
	_, writeErr := file.Write(b)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("control evidence write failed")
	}
	t.Log("gate: real pinned Headscale HTTPS, per-Pod startup proofs, service CA verification/rejection/recovery; no tsnet or DERP traffic claim")
}
