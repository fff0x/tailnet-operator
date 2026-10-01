//go:build e2e_kind

package e2ekind

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"this-is-fine.io/tailnet-operator/test/internal/kindfixture"
)

// admissionFailureCategory never returns API messages, addresses or request data.
func admissionFailureCategory(err error) string {
	out := []string{"unclassified"}
	if apierrors.IsForbidden(err) {
		out = []string{"forbidden"}
	} else if apierrors.IsInvalid(err) {
		out = []string{"invalid"}
	} else if apierrors.IsInternalError(err) {
		out = []string{"internal"}
	} else if apierrors.IsTimeout(err) {
		out = []string{"timeout"}
	}
	text := strings.ToLower(err.Error())
	for _, category := range []string{"network is unreachable", "no route to host", "connection refused", "no such host", "context deadline exceeded", "x509", "unknown authority", "failed calling webhook", "denied the request", "bad response", "400 bad request", "403 forbidden"} {
		if strings.Contains(text, category) {
			out = append(out, category)
		}
	}
	return strings.Join(out, "; ")
}

// TestFixtureCAProjection checks the real admission TLS path and kubelet volume
// mechanics without starting Headscale or tsnet. Agent-shaped Pods are either
// dry-run or persistently scheduling-gated; neither starts an application.
// The running Pod is explicitly a file-observation fixture, not an agent.
func TestFixtureCAProjection(t *testing.T) {
	if os.Getenv("E2E_KIND_HTTP_NETWORK_GATE") == "" {
		t.Skip("projection requires the separate layered-isolation runner, not the foundation fixture")
	}
	f := ownedFixture(t)
	if os.Getenv("E2E_KIND_HTTP_NETWORK_GATE") != "passed" {
		t.Fatal("fresh layered network gate required")
	}
	image := os.Getenv("E2E_KIND_FIXTURE_IMAGE")
	if image != "localhost/tn-source-netprobe:"+f.cluster {
		t.Fatal("unexpected owned fixture image")
	}
	agentImage := "localhost/admission-only:" + f.cluster // admission only; never scheduled or started
	if admissionregv1.AddToScheme(f.kube.Scheme()) != nil {
		t.Fatal("webhook schema unavailable")
	}
	// The isolated node has no default route. Use Kubernetes' endpoint service
	// resolver rather than adding a route for host-originated ClusterIP traffic.
	// Service DNS/SNI and CA verification remain unchanged (Kubernetes v1.36.1).
	var apiPod corev1.Pod
	if f.kube.Get(t.Context(), client.ObjectKey{Namespace: "kube-system", Name: "kube-apiserver-" + f.cluster + "-control-plane"}, &apiPod) != nil || len(apiPod.Spec.Containers) != 1 {
		t.Fatal("owned API server lookup failed")
	}
	flags := append(append([]string(nil), apiPod.Spec.Containers[0].Command...), apiPod.Spec.Containers[0].Args...)
	matches := 0
	for _, arg := range flags {
		if strings.HasPrefix(arg, "--enable-aggregator-routing") {
			if arg != "--enable-aggregator-routing=true" {
				t.Fatal("unexpected API endpoint resolver configuration")
			}
			matches++
		}
	}
	if matches != 1 {
		t.Fatal("owned API endpoint service resolver required")
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	var hook *admissionregv1.MutatingWebhookConfiguration
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if hook != nil && hook.UID != "" {
			if err := f.kube.Delete(ctx, hook, client.Preconditions{UID: &hook.UID}); err != nil && !apierrors.IsNotFound(err) {
				t.Error("owned webhook cleanup failed")
			}
		}
		if ns.UID != "" {
			if err := f.kube.Delete(ctx, ns, client.Preconditions{UID: &ns.UID}); err != nil && !apierrors.IsNotFound(err) {
				t.Error("owned namespace cleanup failed")
				return
			}
			for {
				err := f.kube.Get(ctx, client.ObjectKey{Name: ns.Name}, &corev1.Namespace{})
				if apierrors.IsNotFound(err) {
					t.Log("gate: owned projection namespace removed")
					return
				}
				select {
				case <-ctx.Done():
					t.Error("owned projection namespace cleanup timed out")
					return
				case <-time.After(time.Second):
				}
			}
		}
	})
	create := func(o client.Object) {
		t.Helper()
		if f.kube.Create(t.Context(), o) != nil {
			t.Fatal("owned fixture resource creation failed")
		}
	}
	create(ns)
	if ns.Labels == nil {
		ns.Labels = map[string]string{}
	}
	ns.Labels[kindfixture.OwnerLabel] = string(ns.UID)
	if f.kube.Update(t.Context(), ns) != nil {
		t.Fatal("namespace ownership binding failed")
	}
	now := time.Now()
	ca, err := kindfixture.NewAuthority(now)
	if err != nil {
		t.Fatal("fixture authority failed")
	}
	public, err := kindfixture.PublicCAConfigMap(ns, "fixture-control-ca", ca.PublicPEM(), now)
	if err != nil {
		t.Fatal("public CA rejected")
	}
	create(public)
	originalPublic := public.DeepCopy()
	public.Data["ca.pem"] += "\n"
	if !apierrors.IsInvalid(f.kube.Update(t.Context(), public)) {
		t.Fatal("public CA ConfigMap is not immutable")
	}
	public = originalPublic
	cert, key, _, err := ca.Issue("fixture-admission."+namespace+".svc", now, now.Add(30*time.Minute))
	if err != nil {
		t.Fatal("webhook serving material failed")
	}
	create(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "fixture-admission-tls", Namespace: namespace}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{"tls.crt": cert, "tls.key": key}})
	yes, no := true, false
	uid, mode, replicas := int64(65532), int32(0440), int32(1)
	security := &corev1.SecurityContext{AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}
	podSecurity := &corev1.PodSecurityContext{RunAsNonRoot: &yes, RunAsUser: &uid, RunAsGroup: &uid, FSGroup: &uid, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}
	limits := corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("16Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("200m"), corev1.ResourceMemory: resource.MustParse("128Mi")}}
	labels := map[string]string{"fixture-app": "admission"}
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "fixture-admission", Namespace: namespace}, Spec: appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{
		AutomountServiceAccountToken: &no, SecurityContext: podSecurity, Containers: []corev1.Container{{Name: "admission", Image: image, ImagePullPolicy: corev1.PullNever, Command: []string{"/fixture"}, Resources: limits, Args: []string{"--mode=admission", "--fixture=p1.8-http", "--namespace=" + namespace, "--agent-image=" + agentImage, "--ca-config-map=fixture-control-ca", "--tls-cert=/fixture-tls/tls.crt", "--tls-key=/fixture-tls/tls.key"}, SecurityContext: security,
			ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromInt32(9443), Scheme: corev1.URISchemeHTTPS}}, PeriodSeconds: 1},
			VolumeMounts:   []corev1.VolumeMount{{Name: "tls", MountPath: "/fixture-tls", ReadOnly: true}},
		}}, Volumes: []corev1.Volume{{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "fixture-admission-tls", DefaultMode: &mode}}}},
	}}}}
	create(deployment)
	create(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "fixture-admission", Namespace: namespace}, Spec: corev1.ServiceSpec{Selector: labels, Ports: []corev1.ServicePort{{Name: "https", Port: 443, TargetPort: intstr.FromInt32(9443)}}}})
	eventually(t, "fixture HTTPS admission readiness", func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(deployment), deployment) == nil && deployment.Status.ReadyReplicas == 1 && deployment.Status.ObservedGeneration == deployment.Generation
	})
	hook, err = kindfixture.AgentCAWebhook(ns, "fixture-agent-ca-"+f.cluster, ca.PublicPEM(), time.Now())
	if err != nil {
		t.Fatal("webhook configuration rejected")
	}
	create(hook)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "fixture-serving", Namespace: namespace}, Type: corev1.SecretTypeTLS}
	firstCert, firstKey, firstHash, err := ca.Issue("rotation.fixture.invalid", time.Now(), time.Now().Add(20*time.Minute))
	if err != nil {
		t.Fatal("serving leaf failed")
	}
	secret.Data = map[string][]byte{"tls.crt": firstCert, "tls.key": firstKey}
	create(secret)
	template := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "agent-dry-run", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "tailnet-ingress", "app.kubernetes.io/managed-by": "tailnet-operator"}}, Spec: corev1.PodSpec{
		AutomountServiceAccountToken: &no, SecurityContext: podSecurity, Containers: []corev1.Container{{Name: "agent", Image: agentImage, ImagePullPolicy: corev1.PullNever, Command: []string{"/tailnet-agent"}, Resources: limits, SecurityContext: security,
			Env: []corev1.EnvVar{{Name: "SSL_CERT_FILE", Value: "/ca-certificates.crt"}, {Name: "AGENT_MODE", Value: "ingress"}}, VolumeMounts: []corev1.VolumeMount{{Name: "tls", MountPath: "/tls", ReadOnly: true}},
		}}, Volumes: []corev1.Volume{{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secret.Name, DefaultMode: &mode, Optional: &yes, Items: []corev1.KeyToPath{{Key: "tls.crt", Path: "tls.crt"}, {Key: "tls.key", Path: "tls.key"}}}}}},
	}}
	var admitted *corev1.Pod
	lastDiagnostic := ""
	dryRun := func() bool {
		p := template.DeepCopy()
		if err := f.kube.Create(t.Context(), p, client.DryRunAll); err != nil {
			category := admissionFailureCategory(err)
			if category != lastDiagnostic {
				t.Log("diagnostic: admission", category)
				lastDiagnostic = category
			}
			return false
		}
		if len(p.Spec.Volumes) != 2 || len(p.Spec.Containers[0].VolumeMounts) != 2 {
			return false
		}
		admitted = p
		return true
	}
	eventually(t, "real TLS admission mutation", dryRun)
	if !apierrors.IsNotFound(f.kube.Get(t.Context(), client.ObjectKeyFromObject(template), &corev1.Pod{})) {
		t.Fatal("dry-run created a real agent Pod")
	}
	if !reflect.DeepEqual(admitted.Spec.Volumes[0], template.Spec.Volumes[0]) || !reflect.DeepEqual(admitted.Spec.Containers[0].VolumeMounts[0], template.Spec.Containers[0].VolumeMounts[0]) {
		t.Fatal("admission changed serving projection")
	}
	v, m := admitted.Spec.Volumes[1], admitted.Spec.Containers[0].VolumeMounts[1]
	if v.ConfigMap == nil || v.ConfigMap.Name != public.Name || !m.ReadOnly || m.MountPath != "/ca-certificates.crt" || m.SubPath != "ca.pem" {
		t.Fatal("unexpected public CA injection")
	}
	bad := template.DeepCopy()
	bad.Spec.Containers[0].Image = "localhost/foreign:fixture"
	if !apierrors.IsForbidden(f.kube.Create(t.Context(), bad, client.DryRunAll)) {
		t.Fatal("webhook accepted unexpected image")
	}
	otherCA, err := kindfixture.NewAuthority(time.Now())
	if err != nil {
		t.Fatal("negative trust fixture failed")
	}
	hook.Webhooks[0].ClientConfig.CABundle = otherCA.PublicPEM()
	if f.kube.Update(t.Context(), hook) != nil {
		t.Fatal("negative trust configuration failed")
	}
	eventually(t, "webhook TLS trust rejection", func() bool {
		err := f.kube.Create(t.Context(), template.DeepCopy(), client.DryRunAll)
		return err != nil && apierrors.IsInternalError(err) && strings.Contains(admissionFailureCategory(err), "x509")
	})
	hook.Webhooks[0].ClientConfig.CABundle = ca.PublicPEM()
	if f.kube.Update(t.Context(), hook) != nil {
		t.Fatal("fixture trust restoration failed")
	}
	eventually(t, "verified admission trust restored", dryRun)
	t.Log("gate: verified TLS admission, wrong-CA rejection/recovery, bounded denial, immutable public CA, no agent started")
	// Create an explicitly different probe Pod from the API-admitted volume spec.
	probe := admitted.DeepCopy()
	probe.ObjectMeta = metav1.ObjectMeta{Name: "projection", Namespace: namespace, Labels: map[string]string{"fixture-app": "projection"}}
	probe.Spec.Containers[0].Name = "projection"
	probe.Spec.Containers[0].Image = image
	probe.Spec.Containers[0].Command = []string{"/projection"}
	probe.Spec.Containers[0].Args = []string{"--hold", "--fixture=p1.8-projection"}
	probe.Spec.Containers[0].Env = nil
	create(probe)
	eventually(t, "projection Pod", func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(probe), probe) == nil && len(probe.Status.ContainerStatuses) == 1 && probe.Status.ContainerStatuses[0].Ready
	})
	podUID, containerID := probe.UID, probe.Status.ContainerStatuses[0].ContainerID
	type observation struct {
		UID                                                  int `json:"uid"`
		CertificateReadable, KeyReadable                     bool
		CertificateMode, KeyMode, CertificateGroup, KeyGroup uint32
		ProjectedSymlinks                                    bool
		PublicCASHA256, LeafSHA256                           string
		PairValid                                            bool
	}
	var latest observation
	observe := func() bool {
		b, err := f.command(t.Context(), "", "kubectl", "--kubeconfig", f.config, "--context", f.context, "--request-timeout=10s", "-n", namespace, "exec", probe.Name, "--", "/projection", "--fixture=p1.8-projection", "--dns=rotation.fixture.invalid")
		return err == nil && len(b) < 4096 && json.Unmarshal(b, &latest) == nil
	}
	expectedCA := sha256.Sum256(ca.PublicPEM())
	valid := func(hash string) bool {
		return observe() && latest.UID == 65532 && latest.CertificateReadable && latest.KeyReadable && latest.CertificateMode == 0440 && latest.KeyMode == 0440 && latest.CertificateGroup == 65532 && latest.KeyGroup == 65532 && latest.ProjectedSymlinks && latest.PublicCASHA256 == hex.EncodeToString(expectedCA[:]) && latest.PairValid && latest.LeafSHA256 == hash
	}
	eventually(t, "non-root FSGroup projection", func() bool { return valid(firstHash) })
	update := func(cert, key []byte) {
		t.Helper()
		if f.kube.Get(t.Context(), client.ObjectKeyFromObject(secret), secret) != nil {
			t.Fatal("owned Secret lookup failed")
		}
		secret.Data = map[string][]byte{"tls.crt": cert, "tls.key": key}
		if err := f.kube.Update(t.Context(), secret); err != nil {
			t.Fatal("owned Secret update failed:", admissionFailureCategory(err))
		}
	}
	secondCert, secondKey, secondHash, err := ca.Issue("rotation.fixture.invalid", time.Now(), time.Now().Add(20*time.Minute))
	if err != nil || secondHash == firstHash {
		t.Fatal("replacement leaf failed")
	}
	update(secondCert, secondKey)
	eventually(t, "kubelet certificate replacement", func() bool { return valid(secondHash) })
	invalidSecret := secret.DeepCopy()
	delete(invalidSecret.Data, "tls.key")
	if !apierrors.IsInvalid(f.kube.Update(t.Context(), invalidSecret)) {
		t.Fatal("Kubernetes did not reject a TLS Secret with a missing key")
	}
	t.Log("gate: native TLS Secret validation rejects missing data key")
	// A TLS Secret must contain both data keys. Exercise absence by deleting
	// only this owned Secret, not by bypassing Kubernetes validation or changing
	// its type. Its optional projection must remove the old files.
	if err := f.kube.Delete(t.Context(), secret, client.Preconditions{UID: &secret.UID}); err != nil {
		t.Fatal("owned serving Secret deletion failed")
	}
	eventually(t, "missing projected Secret", func() bool {
		return observe() && !latest.CertificateReadable && !latest.KeyReadable && !latest.PairValid
	})
	secret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "fixture-serving", Namespace: namespace}, Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{"tls.crt": secondCert, "tls.key": firstKey}}
	create(secret)
	eventually(t, "mismatched projected pair", func() bool { return observe() && latest.CertificateReadable && latest.KeyReadable && !latest.PairValid })
	update(secondCert, secondKey)
	eventually(t, "projected pair recovery", func() bool { return valid(secondHash) })
	if f.kube.Get(t.Context(), client.ObjectKeyFromObject(probe), probe) != nil || probe.UID != podUID || len(probe.Status.ContainerStatuses) != 1 || probe.Status.ContainerStatuses[0].ContainerID != containerID || probe.Status.ContainerStatuses[0].RestartCount != 0 {
		t.Fatal("projection required Pod/container replacement")
	}
	var saved corev1.ConfigMap
	if f.kube.Get(t.Context(), types.NamespacedName{Namespace: namespace, Name: public.Name}, &saved) != nil || saved.UID != originalPublic.UID || saved.Immutable == nil || !*saved.Immutable || !reflect.DeepEqual(saved.Data, originalPublic.Data) {
		t.Fatal("public trust bundle changed")
	}
	t.Log("gate: actual kubelet projection, UID/FSGroup65532, mode0440, rotation/missing/mismatch/recovery without restart")

	// Exercise optional init injection through REAL CREATE, not only DryRun.
	// An independent scheduler gate prevents this agent-shaped fixture from
	// acquiring a node or starting even if admission were unexpectedly absent.
	// The placeholder application image is never loaded or pulled.
	if f.kube.Get(t.Context(), client.ObjectKeyFromObject(deployment), deployment) != nil {
		t.Fatal("owned admission deployment lookup failed")
	}
	deployment.Spec.Strategy = appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}
	deployment.Spec.Template.Spec.Containers[0].Args = append(deployment.Spec.Template.Spec.Containers[0].Args, "--network-gate-image="+image)
	if f.kube.Update(t.Context(), deployment) != nil {
		t.Fatal("optional admission configuration failed")
	}
	eventually(t, "optional init admission server readiness", func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(deployment), deployment) == nil && deployment.Status.ObservedGeneration == deployment.Generation && deployment.Status.ReadyReplicas == 1
	})
	gated := template.DeepCopy()
	gated.Name = "agent-admission-only"
	gated.Spec.SchedulingGates = []corev1.PodSchedulingGate{{Name: "fixture.this-is-fine.io/admission-only"}}
	var gatedPreview *corev1.Pod
	eventually(t, "optional init admission mutation", func() bool {
		p := gated.DeepCopy()
		if f.kube.Create(t.Context(), p, client.DryRunAll) != nil || len(p.Spec.InitContainers) != 1 || len(p.Spec.Volumes) != 3 {
			return false
		}
		gatedPreview = p
		return true
	})
	create(gated)
	gatedUID := gated.UID
	if !reflect.DeepEqual(gated.Spec.InitContainers, gatedPreview.Spec.InitContainers) || !reflect.DeepEqual(gated.Spec.Volumes, gatedPreview.Spec.Volumes) || !reflect.DeepEqual(gated.Spec.Containers, admitted.Spec.Containers) {
		t.Fatal("live admission differs from verified mutation or changed application")
	}
	init := gated.Spec.InitContainers[0]
	if init.Name != kindfixture.NetworkGateContainer || init.Image != image || !reflect.DeepEqual(init.Command, []string{"/netgate"}) || !reflect.DeepEqual(init.Args, []string{"--action=hold", "--fixture=p1.8-http"}) || len(init.VolumeMounts) != 1 || init.VolumeMounts[0].MountPath != "/fixture-gate" {
		t.Fatal("unexpected injected startup gate")
	}
	gateVolume := gated.Spec.Volumes[2]
	if gateVolume.Name != init.VolumeMounts[0].Name || gateVolume.EmptyDir == nil || gateVolume.EmptyDir.Medium != corev1.StorageMediumMemory || gateVolume.EmptyDir.SizeLimit == nil || gateVolume.EmptyDir.SizeLimit.Cmp(resource.MustParse("4Mi")) != 0 {
		t.Fatal("unexpected init state volume")
	}
	for _, mount := range gated.Spec.Containers[0].VolumeMounts {
		if mount.Name == gateVolume.Name {
			t.Fatal("application can access init state")
		}
	}
	eventually(t, "real admitted Pod remains scheduling-gated", func() bool {
		if f.kube.Get(t.Context(), client.ObjectKeyFromObject(gated), gated) != nil || gated.UID != gatedUID || len(gated.Spec.SchedulingGates) != 1 || gated.Spec.NodeName != "" || gated.Status.PodIP != "" || len(gated.Status.ContainerStatuses) != 0 || len(gated.Status.InitContainerStatuses) != 0 {
			return false
		}
		for _, c := range gated.Status.Conditions {
			if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse && c.Reason == "SchedulingGated" {
				return true
			}
		}
		return false
	})
	badLive := template.DeepCopy()
	badLive.Name = "agent-admission-rejected"
	badLive.Spec.SchedulingGates = append([]corev1.PodSchedulingGate(nil), gated.Spec.SchedulingGates...)
	badLive.Spec.Containers[0].Image = "localhost/foreign:fixture"
	if !apierrors.IsForbidden(f.kube.Create(t.Context(), badLive)) || !apierrors.IsNotFound(f.kube.Get(t.Context(), client.ObjectKeyFromObject(badLive), &corev1.Pod{})) {
		t.Fatal("real CREATE did not reject unexpected image")
	}
	// Persist only in the runner's already private evidence directory.
	evidence := os.Getenv("E2E_KIND_NET_EVIDENCE")
	info, err := os.Lstat(evidence)
	if err != nil || !filepath.IsAbs(evidence) || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		t.Fatal("private admission evidence missing")
	}
	b, err := json.Marshal(gated)
	if err != nil {
		t.Fatal("admission evidence encoding failed")
	}
	file, err := os.OpenFile(filepath.Join(evidence, "admission-init-pod.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("admission evidence creation failed")
	}
	_, writeErr := file.Write(b)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("admission evidence write failed")
	}
	if f.kube.Delete(t.Context(), gated, client.Preconditions{UID: &gatedUID}) != nil {
		t.Fatal("admission-only Pod cleanup failed")
	}
	eventually(t, "admission-only Pod removed", func() bool {
		return apierrors.IsNotFound(f.kube.Get(t.Context(), client.ObjectKeyFromObject(gated), &corev1.Pod{}))
	})
	t.Log("gate: real CREATE injected public CA and init gate; application preserved; scheduler kept Pod unassigned; foreign image rejected")
}
