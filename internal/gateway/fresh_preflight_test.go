package gateway

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

const preflightCanary = "private-auth-or-state-canary-do-not-emit"

func freshInspectionFixture(t *testing.T) FreshInspectionInputs {
	t.Helper()
	fresh := freshFixture()
	fresh.Gateway.ResourceVersion = "10"
	fresh.Tailnet.UID = "tailnet-uid"
	fresh.Tailnet.ResourceVersion = "11"
	fresh.Tailnet.Spec.DNS.HostsConfigMap = "tailnet-hosts"
	fresh.Hosts = "198.51.100.8\tapp.tail.example\n"
	plan, err := RenderFresh(fresh)
	if err != nil {
		t.Fatal(err)
	}
	in := FreshInspectionInputs{Fresh: fresh,
		State: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "router-state", Namespace: "operator", UID: "empty-state-uid", ResourceVersion: "12"}, Type: corev1.SecretTypeOpaque},
		Hosts: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tailnet-hosts", Namespace: "operator", UID: "hosts-uid", ResourceVersion: "13",
			Labels:          map[string]string{"app.kubernetes.io/managed-by": "tailnet-operator", "tsunaro.io/role": "dns-hosts"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "tsunaro.io/v1alpha1", Kind: "Tailnet", Name: "tailnet", UID: "tailnet-uid", Controller: ptr.To(true)}}},
			Data: map[string]string{"hosts": fresh.Hosts}},
	}
	for _, obj := range plan.Objects {
		in.Absent = append(in.Absent, FreshObjectKey{Kind: freshObjectKind(obj), Namespace: obj.GetNamespace(), Name: obj.GetName()})
	}
	return in
}

func TestInspectFreshSnapshotsNeverAuthorizesWriting(t *testing.T) {
	in := freshInspectionFixture(t)
	before := in.State.DeepCopy()
	got, err := InspectFreshSnapshots(in)
	if !errors.Is(err, ErrFreshProvenance) || !reflect.DeepEqual(in.State, before) || got.StateUID != in.State.UID || got.HostsVersion != in.Hosts.ResourceVersion || got.GatewayVersion != in.Fresh.Gateway.ResourceVersion {
		t.Fatal("fresh snapshots did not remain read-only and blocked")
	}
	if strings.Contains(err.Error(), preflightCanary) {
		t.Fatal("error disclosed a credential")
	}
	// A synthetic absence list does not establish exclusive ownership, and
	// neither a matching metadata label nor the lack of a node proves auth.
	in.NodeNames = []string{"another-node"}
	if _, err := InspectFreshSnapshots(in); !errors.Is(err, ErrFreshProvenance) {
		t.Fatal("node absence incorrectly authorized creation")
	}
}

func TestInspectFreshSnapshotsRejectsUnsafeInputs(t *testing.T) {
	cases := map[string]struct {
		change func(*FreshInspectionInputs)
		want   error
	}{
		"missing state":           {func(i *FreshInspectionInputs) { i.State = nil }, ErrFreshSnapshot},
		"unversioned state":       {func(i *FreshInspectionInputs) { i.State.ResourceVersion = "" }, ErrFreshSnapshot},
		"foreign state namespace": {func(i *FreshInspectionInputs) { i.State.Namespace = "foreign" }, ErrFreshSnapshot},
		"immutable state":         {func(i *FreshInspectionInputs) { i.State.Immutable = ptr.To(true) }, ErrFreshState},
		"populated state": {func(i *FreshInspectionInputs) {
			i.State.Data = map[string][]byte{"_current-profile": []byte(preflightCanary)}
		}, ErrFreshState},
		"string data":            {func(i *FreshInspectionInputs) { i.State.StringData = map[string]string{"key": preflightCanary} }, ErrFreshState},
		"state annotation":       {func(i *FreshInspectionInputs) { i.State.Annotations = map[string]string{"state": preflightCanary} }, ErrFreshState},
		"retained state owner":   {func(i *FreshInspectionInputs) { i.State.OwnerReferences = []metav1.OwnerReference{{UID: "foreign"}} }, ErrFreshState},
		"state deleting":         {func(i *FreshInspectionInputs) { i.State.DeletionTimestamp = ptr.To(metav1.Now()) }, ErrFreshState},
		"unversioned hosts":      {func(i *FreshInspectionInputs) { i.Hosts.ResourceVersion = "" }, ErrFreshSnapshot},
		"foreign hosts owner":    {func(i *FreshInspectionInputs) { i.Hosts.OwnerReferences[0].UID = "other" }, ErrFreshHosts},
		"hosts not controlled":   {func(i *FreshInspectionInputs) { i.Hosts.OwnerReferences[0].Controller = ptr.To(false) }, ErrFreshHosts},
		"hosts wrong role":       {func(i *FreshInspectionInputs) { i.Hosts.Labels["tsunaro.io/role"] = "policy-render" }, ErrFreshHosts},
		"hosts key absent":       {func(i *FreshInspectionInputs) { i.Hosts.Data = nil }, ErrFreshHosts},
		"hosts snapshot changed": {func(i *FreshInspectionInputs) { i.Fresh.Hosts = "198.51.100.9\tother.tail.example" }, ErrFreshHosts},
		"hosts name collides": {func(i *FreshInspectionInputs) {
			i.Hosts.Name = "router-coredns"
			i.Fresh.Tailnet.Spec.DNS.HostsConfigMap = "router-coredns"
		}, ErrFreshConflict},
		"absences missing":    {func(i *FreshInspectionInputs) { i.Absent = i.Absent[:8] }, ErrFreshSnapshot},
		"absences duplicated": {func(i *FreshInspectionInputs) { i.Absent[8] = i.Absent[0] }, ErrFreshSnapshot},
		"absences foreign":    {func(i *FreshInspectionInputs) { i.Absent[8].Namespace = "foreign" }, ErrFreshSnapshot},
		"occupied even if same UID": {func(i *FreshInspectionInputs) {
			i.Occupied = []client.Object{&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "router", Namespace: "operator", UID: "retained", Labels: map[string]string{gatewayUIDLabel: string(i.Fresh.Gateway.UID)}}}}
			i.Absent = slices.DeleteFunc(i.Absent, func(k FreshObjectKey) bool { return k.Kind == "Service" && k.Name == "router" })
		}, ErrFreshConflict},
		"node name in use": {func(i *FreshInspectionInputs) { i.NodeNames = []string{"ROUTER"} }, ErrFreshConflict},
		"foreign gateway scope": {func(i *FreshInspectionInputs) {
			i.PeerGateways = []tnv1.TailnetGateway{{ObjectMeta: metav1.ObjectMeta{Name: "foreign", Namespace: "tenant", UID: "peer"}}}
		}, ErrFreshSnapshot},
		"peer hostname": {func(i *FreshInspectionInputs) {
			i.PeerGateways = []tnv1.TailnetGateway{{ObjectMeta: metav1.ObjectMeta{Name: "other", UID: "peer"}, Spec: tnv1.TailnetGatewaySpec{Hostname: "router"}}}
		}, ErrFreshConflict},
		"peer state": {func(i *FreshInspectionInputs) {
			i.PeerGateways = []tnv1.TailnetGateway{{ObjectMeta: metav1.ObjectMeta{Name: "other", UID: "peer"}, Spec: tnv1.TailnetGatewaySpec{StateSecretRef: tnv1.GatewayLocalReference{Name: "router-state"}}}}
		}, ErrFreshConflict},
		"peer lb": {func(i *FreshInspectionInputs) {
			i.PeerGateways = []tnv1.TailnetGateway{{ObjectMeta: metav1.ObjectMeta{Name: "other", UID: "peer"}, Spec: tnv1.TailnetGatewaySpec{Service: tnv1.GatewayService{LoadBalancerIP: "198.51.100.1"}}}}
		}, ErrFreshConflict},
		"admission bypass":  {func(i *FreshInspectionInputs) { i.Fresh.Gateway.Spec.Suspend = ptr.To(false) }, ErrFreshSnapshot},
		"adoption":          {func(i *FreshInspectionInputs) { i.Fresh.Gateway.Spec.Adoption = &tnv1.GatewayAdoption{} }, ErrFreshSnapshot},
		"historical status": {func(i *FreshInspectionInputs) { i.Fresh.Gateway.Status.NodeID = "42" }, ErrFreshSnapshot},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			in := freshInspectionFixture(t)
			tc.change(&in)
			got, err := InspectFreshSnapshots(in)
			if !errors.Is(err, tc.want) || got != (FreshInspection{}) || strings.Contains(err.Error(), preflightCanary) {
				t.Fatalf("unsafe snapshots accepted or disclosed for %s: %v", name, err)
			}
		})
	}
	// A wrong Tailnet UID cannot be treated as proof of an owned hosts file.
	in := freshInspectionFixture(t)
	in.Fresh.Tailnet.UID = types.UID("new-tailnet-uid")
	if _, err := InspectFreshSnapshots(in); !errors.Is(err, ErrFreshHosts) {
		t.Fatal("foreign hosts accepted")
	}
}
