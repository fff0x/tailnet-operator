package kindfixture

import (
	"reflect"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type operatorCAFixture struct {
	deployment *appsv1.Deployment
	namespace  *corev1.Namespace
	public     *corev1.ConfigMap
	image      string
}

func operatorCAValue[T any](v T) *T { return &v }

func newOperatorCAFixture(t *testing.T) operatorCAFixture {
	t.Helper()
	now := time.Now()
	ca, err := NewAuthority(now)
	if err != nil {
		t.Fatal("fixture authority failed")
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "owned-test", UID: "namespace-uid", Labels: map[string]string{OwnerLabel: "namespace-uid"}}}
	public, err := PublicCAConfigMap(ns, controlCAVolume, ca.PublicPEM(), now)
	if err != nil {
		t.Fatal("public CA fixture failed")
	}
	image := "localhost/tailnet-operator-e2e:tn-kind-a1b2c3d4e5"
	labels := map[string]string{"app.kubernetes.io/name": "tailnet-operator", "app.kubernetes.io/instance": "fixture", "app.kubernetes.io/managed-by": "Helm"}
	deployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{Name: "tailnet-operator", Namespace: ns.Name, UID: "installed-operator-uid", ResourceVersion: "1234", Generation: 1,
			Labels: labels, Annotations: map[string]string{"meta.helm.sh/release-name": "fixture", "meta.helm.sh/release-namespace": ns.Name}},
		Spec: appsv1.DeploymentSpec{
			Replicas: operatorCAValue(int32(1)), Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "tailnet-operator"}},
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType, RollingUpdate: &appsv1.RollingUpdateDeployment{MaxSurge: operatorCAValue(intstr.FromInt32(1)), MaxUnavailable: operatorCAValue(intstr.FromInt32(0))}},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{
				ServiceAccountName: "tailnet-operator", TerminationGracePeriodSeconds: operatorCAValue(int64(30)),
				SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: operatorCAValue(true), RunAsUser: operatorCAValue(int64(65532)), RunAsGroup: operatorCAValue(int64(65532)), SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
				Containers: []corev1.Container{{Name: "operator", Image: image, ImagePullPolicy: corev1.PullNever, Command: []string{"/tailnet-operator"}, Args: []string{"--leader-elect=true"},
					Env: []corev1.EnvVar{
						{Name: "SSL_CERT_FILE", Value: controlCAPath},
						{Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.namespace"}}},
						{Name: "OPERATOR_IMAGE", Value: image},
						{Name: "AGENT_IMAGE_PULL_SECRETS", Value: "[]"},
					},
					Ports:           []corev1.ContainerPort{{Name: "metrics", ContainerPort: 8080}, {Name: "health", ContainerPort: 8081}},
					LivenessProbe:   &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromString("health")}}, InitialDelaySeconds: 15},
					ReadinessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromString("health")}}},
					SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: operatorCAValue(false), ReadOnlyRootFilesystem: operatorCAValue(true), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
					Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("25m"), corev1.ResourceMemory: resource.MustParse("64Mi")}, Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("128Mi")}},
				}},
			}},
		},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 1, ReadyReplicas: 1},
	}
	return operatorCAFixture{deployment, ns, public, image}
}

func TestAddOperatorCAPreservesInstalledChart(t *testing.T) {
	for _, token := range []*bool{nil, operatorCAValue(true)} {
		f := newOperatorCAFixture(t)
		f.deployment.Spec.Template.Spec.AutomountServiceAccountToken = token
		if token != nil {
			// Extra chart environment and explicit safe overrides must survive.
			c := &f.deployment.Spec.Template.Spec.Containers[0]
			c.Env = append(c.Env, corev1.EnvVar{Name: "FIXTURE_MARKER", Value: "unchanged"})
			c.SecurityContext.Privileged = operatorCAValue(false)
			c.SecurityContext.RunAsNonRoot = operatorCAValue(true)
			c.SecurityContext.RunAsUser = operatorCAValue(int64(65532))
			c.SecurityContext.RunAsGroup = operatorCAValue(int64(65532))
			c.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
		}
		before, nsBefore, publicBefore := f.deployment.DeepCopy(), f.namespace.DeepCopy(), f.public.DeepCopy()
		if err := AddOperatorCA(f.deployment, f.namespace, f.public, f.image); err != nil {
			t.Fatal(err)
		}
		want := before.DeepCopy()
		want.Spec.Template.Spec.Volumes = []corev1.Volume{{Name: "fixture-control-ca", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: "fixture-control-ca"}, DefaultMode: operatorCAValue(int32(0644)), Items: []corev1.KeyToPath{{Key: "ca.pem", Path: "ca.pem"}},
		}}}}
		want.Spec.Template.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "fixture-control-ca", MountPath: "/ca-certificates.crt", SubPath: "ca.pem", ReadOnly: true}}
		if !reflect.DeepEqual(f.deployment, want) || !reflect.DeepEqual(f.namespace, nsBefore) || !reflect.DeepEqual(f.public, publicBefore) {
			t.Fatal("changed fields beyond the public CA volume and mount")
		}
		if err := AddOperatorCA(f.deployment, f.namespace, f.public, f.image); err != ErrOperatorCA || !reflect.DeepEqual(f.deployment, want) {
			t.Fatal("reinvocation did not fail closed without mutation")
		}
	}
}

func TestAddOperatorCARejectsScopeAndCA(t *testing.T) {
	for name, mutate := range map[string]func(*operatorCAFixture){
		"nil deployment":              func(f *operatorCAFixture) { f.deployment = nil },
		"nil namespace":               func(f *operatorCAFixture) { f.namespace = nil },
		"nil public":                  func(f *operatorCAFixture) { f.public = nil },
		"namespace name":              func(f *operatorCAFixture) { f.namespace.Name = "" },
		"namespace uid":               func(f *operatorCAFixture) { f.namespace.UID = "" },
		"namespace wrong uid":         func(f *operatorCAFixture) { f.namespace.UID = "foreign-uid" },
		"namespace label":             func(f *operatorCAFixture) { f.namespace.Labels = nil },
		"namespace deleting":          func(f *operatorCAFixture) { f.namespace.DeletionTimestamp = operatorCAValue(metav1.Now()) },
		"deployment namespace":        func(f *operatorCAFixture) { f.deployment.Namespace = "foreign" },
		"deployment name":             func(f *operatorCAFixture) { f.deployment.Name = "foreign" },
		"deployment uid":              func(f *operatorCAFixture) { f.deployment.UID = "" },
		"deployment resource version": func(f *operatorCAFixture) { f.deployment.ResourceVersion = "" },
		"deployment deleting":         func(f *operatorCAFixture) { f.deployment.DeletionTimestamp = operatorCAValue(metav1.Now()) },
		"foreign CA namespace":        func(f *operatorCAFixture) { f.public.Namespace = "foreign" },
		"foreign CA name":             func(f *operatorCAFixture) { f.public.Name = "foreign" },
		"foreign CA owner":            func(f *operatorCAFixture) { f.public.Labels[OwnerLabel] = "foreign-uid" },
		"missing CA owner":            func(f *operatorCAFixture) { f.public.Labels = nil },
		"CA deleting":                 func(f *operatorCAFixture) { f.public.DeletionTimestamp = operatorCAValue(metav1.Now()) },
		"CA mutable":                  func(f *operatorCAFixture) { f.public.Immutable = operatorCAValue(false) },
		"CA unspecified immutable":    func(f *operatorCAFixture) { f.public.Immutable = nil },
		"CA absent":                   func(f *operatorCAFixture) { f.public.Data = nil },
		"CA extra data":               func(f *operatorCAFixture) { f.public.Data["extra"] = "private-marker" },
		"CA wrong key":                func(f *operatorCAFixture) { f.public.Data = map[string]string{"wrong": f.public.Data[controlCAKey]} },
		"CA binary data":              func(f *operatorCAFixture) { f.public.BinaryData = map[string][]byte{"key": []byte("private-marker")} },
		"CA chain":                    func(f *operatorCAFixture) { f.public.Data[controlCAKey] += f.public.Data[controlCAKey] },
		"CA prefix": func(f *operatorCAFixture) {
			f.public.Data[controlCAKey] = "private-marker" + f.public.Data[controlCAKey]
		},
		"CA invalid": func(f *operatorCAFixture) {
			f.public.Data[controlCAKey] = "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"
		},
		"image missing":      func(f *operatorCAFixture) { f.image = "" },
		"image registry":     func(f *operatorCAFixture) { f.image = "registry.invalid/tailnet-operator-e2e:tn-kind-a1b2c3d4e5" },
		"image latest":       func(f *operatorCAFixture) { f.image = "localhost/tailnet-operator-e2e:latest" },
		"image short suffix": func(f *operatorCAFixture) { f.image = "localhost/tailnet-operator-e2e:tn-kind-a1b2c3d4e" },
		"image long suffix":  func(f *operatorCAFixture) { f.image += "6" },
		"image uppercase":    func(f *operatorCAFixture) { f.image = "localhost/tailnet-operator-e2e:tn-kind-A1b2c3d4e5" },
		"image newline":      func(f *operatorCAFixture) { f.image += "\n" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newOperatorCAFixture(t)
			mutate(&f)
			// Image-scope cases must fail even when both image consumers agree.
			if f.deployment != nil {
				f.deployment.Spec.Template.Spec.Containers[0].Image = f.image
				f.deployment.Spec.Template.Spec.Containers[0].Env[2].Value = f.image
			}
			assertOperatorCARejected(t, f)
		})
	}
}

func assertOperatorCARejected(t *testing.T, f operatorCAFixture) {
	t.Helper()
	before, nsBefore, publicBefore := f.deployment.DeepCopy(), f.namespace.DeepCopy(), f.public.DeepCopy()
	if err := AddOperatorCA(f.deployment, f.namespace, f.public, f.image); err != ErrOperatorCA || err.Error() != "kind fixture: operator CA injection rejected" {
		t.Fatal("unexpected input accepted or error not bounded")
	}
	if !reflect.DeepEqual(f.deployment, before) || !reflect.DeepEqual(f.namespace, nsBefore) || !reflect.DeepEqual(f.public, publicBefore) {
		t.Fatal("rejected input was mutated")
	}
}

func TestAddOperatorCARejectsPrivateOrInvalidRoot(t *testing.T) {
	now := time.Now()
	ca, err := NewAuthority(now)
	if err != nil {
		t.Fatal("fixture authority failed")
	}
	leaf, key, _, err := ca.Issue("fixture.invalid", now, now.Add(time.Minute))
	if err != nil {
		t.Fatal("fixture leaf failed")
	}
	expired, err := NewAuthority(now.Add(-2 * time.Hour))
	if err != nil {
		t.Fatal("expired authority fixture failed")
	}
	future, err := NewAuthority(now.Add(time.Hour))
	if err != nil {
		t.Fatal("future authority fixture failed")
	}
	for _, value := range [][]byte{key, leaf, append(ca.PublicPEM(), key...), expired.PublicPEM(), future.PublicPEM()} {
		f := newOperatorCAFixture(t)
		f.public.Data[controlCAKey] = string(value)
		assertOperatorCARejected(t, f)
	}
}

func TestAddOperatorCARejectsUnexpectedPod(t *testing.T) {
	for name, mutate := range map[string]func(*corev1.PodTemplateSpec){
		"labels":       func(p *corev1.PodTemplateSpec) { p.Labels = nil },
		"no container": func(p *corev1.PodTemplateSpec) { p.Spec.Containers = nil },
		"sidecar": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "sidecar"})
		},
		"container name":  func(p *corev1.PodTemplateSpec) { p.Spec.Containers[0].Name = "foreign" },
		"container image": func(p *corev1.PodTemplateSpec) { p.Spec.Containers[0].Image += "x" },
		"command":         func(p *corev1.PodTemplateSpec) { p.Spec.Containers[0].Command = []string{"/bin/sh"} },
		"extra command": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].Command = append(p.Spec.Containers[0].Command, "extra")
		},
		"args": func(p *corev1.PodTemplateSpec) { p.Spec.Containers[0].Args = []string{"--leader-elect=false"} },
		"extra args": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].Args = append(p.Spec.Containers[0].Args, "extra")
		},
		"missing SSL env":    func(p *corev1.PodTemplateSpec) { p.Spec.Containers[0].Env = p.Spec.Containers[0].Env[1:] },
		"SSL env":            func(p *corev1.PodTemplateSpec) { p.Spec.Containers[0].Env[0].Value = "/foreign" },
		"SSL env indirect":   func(p *corev1.PodTemplateSpec) { p.Spec.Containers[0].Env[0].ValueFrom = &corev1.EnvVarSource{} },
		"image env":          func(p *corev1.PodTemplateSpec) { p.Spec.Containers[0].Env[2].Value = "foreign" },
		"image env indirect": func(p *corev1.PodTemplateSpec) { p.Spec.Containers[0].Env[2].ValueFrom = &corev1.EnvVarSource{} },
		"duplicate SSL": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].Env = append(p.Spec.Containers[0].Env, p.Spec.Containers[0].Env[0])
		},
		"duplicate other env": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].Env = append(p.Spec.Containers[0].Env, p.Spec.Containers[0].Env[3])
		},
		"envFrom": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].EnvFrom = []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "foreign"}}}}
		},
		"service account":     func(p *corev1.PodTemplateSpec) { p.Spec.ServiceAccountName = "foreign" },
		"token disabled":      func(p *corev1.PodTemplateSpec) { p.Spec.AutomountServiceAccountToken = operatorCAValue(false) },
		"host network":        func(p *corev1.PodTemplateSpec) { p.Spec.HostNetwork = true },
		"host pid":            func(p *corev1.PodTemplateSpec) { p.Spec.HostPID = true },
		"host ipc":            func(p *corev1.PodTemplateSpec) { p.Spec.HostIPC = true },
		"shared processes":    func(p *corev1.PodTemplateSpec) { p.Spec.ShareProcessNamespace = operatorCAValue(true) },
		"init container":      func(p *corev1.PodTemplateSpec) { p.Spec.InitContainers = []corev1.Container{{Name: "init"}} },
		"ephemeral container": func(p *corev1.PodTemplateSpec) { p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{}} },
		"existing volume": func(p *corev1.PodTemplateSpec) {
			p.Spec.Volumes = []corev1.Volume{{Name: "foreign", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
		},
		"volume collision": func(p *corev1.PodTemplateSpec) { p.Spec.Volumes = []corev1.Volume{{Name: controlCAVolume}} },
		"hostPath": func(p *corev1.PodTemplateSpec) {
			p.Spec.Volumes = []corev1.Volume{{Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}}}}
		},
		"existing mount": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "foreign", MountPath: "/foreign"}}
		},
		"mount collision": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: controlCAVolume, MountPath: controlCAPath}}
		},
		"volume device": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].VolumeDevices = []corev1.VolumeDevice{{Name: "device", DevicePath: "/dev/fixture"}}
		},
		"pod security absent": func(p *corev1.PodTemplateSpec) { p.Spec.SecurityContext = nil },
		"pod nonroot absent":  func(p *corev1.PodTemplateSpec) { p.Spec.SecurityContext.RunAsNonRoot = nil },
		"pod root allowed":    func(p *corev1.PodTemplateSpec) { p.Spec.SecurityContext.RunAsNonRoot = operatorCAValue(false) },
		"pod root uid":        func(p *corev1.PodTemplateSpec) { p.Spec.SecurityContext.RunAsUser = operatorCAValue(int64(0)) },
		"pod uid absent":      func(p *corev1.PodTemplateSpec) { p.Spec.SecurityContext.RunAsUser = nil },
		"pod root gid":        func(p *corev1.PodTemplateSpec) { p.Spec.SecurityContext.RunAsGroup = operatorCAValue(int64(0)) },
		"pod gid absent":      func(p *corev1.PodTemplateSpec) { p.Spec.SecurityContext.RunAsGroup = nil },
		"pod seccomp absent":  func(p *corev1.PodTemplateSpec) { p.Spec.SecurityContext.SeccompProfile = nil },
		"pod seccomp unconfined": func(p *corev1.PodTemplateSpec) {
			p.Spec.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeUnconfined
		},
		"pod sysctls": func(p *corev1.PodTemplateSpec) {
			p.Spec.SecurityContext.Sysctls = []corev1.Sysctl{{Name: "kernel.shm_rmid_forced", Value: "1"}}
		},
		"pod supplemental groups":   func(p *corev1.PodTemplateSpec) { p.Spec.SecurityContext.SupplementalGroups = []int64{0} },
		"pod fs group":              func(p *corev1.PodTemplateSpec) { p.Spec.SecurityContext.FSGroup = operatorCAValue(int64(0)) },
		"container security absent": func(p *corev1.PodTemplateSpec) { p.Spec.Containers[0].SecurityContext = nil },
		"privileged": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].SecurityContext.Privileged = operatorCAValue(true)
		},
		"escalation": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = operatorCAValue(true)
		},
		"escalation unspecified": func(p *corev1.PodTemplateSpec) { p.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = nil },
		"writable root": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem = operatorCAValue(false)
		},
		"readonly unspecified": func(p *corev1.PodTemplateSpec) { p.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem = nil },
		"override root allowed": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].SecurityContext.RunAsNonRoot = operatorCAValue(false)
		},
		"override root uid": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].SecurityContext.RunAsUser = operatorCAValue(int64(0))
		},
		"override root gid": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].SecurityContext.RunAsGroup = operatorCAValue(int64(0))
		},
		"override seccomp": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
		},
		"unmasked proc": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].SecurityContext.ProcMount = operatorCAValue(corev1.UnmaskedProcMount)
		},
		"capabilities absent": func(p *corev1.PodTemplateSpec) { p.Spec.Containers[0].SecurityContext.Capabilities = nil },
		"drop ALL absent": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].SecurityContext.Capabilities.Drop = []corev1.Capability{"NET_RAW"}
		},
		"capability added": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"SYS_ADMIN"}
		},
		"apparmor unconfined": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined}
		},
		"windows host process": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].SecurityContext.WindowsOptions = &corev1.WindowsSecurityContextOptions{HostProcess: operatorCAValue(true)}
		},
		"selinux override": func(p *corev1.PodTemplateSpec) {
			p.Spec.Containers[0].SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{Type: "unconfined_t"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newOperatorCAFixture(t)
			mutate(&f.deployment.Spec.Template)
			assertOperatorCARejected(t, f)
		})
	}
}
