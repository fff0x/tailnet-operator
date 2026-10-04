package gateway

import (
	"errors"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

var (
	ErrFreshSnapshot   = errors.New("gateway fresh preflight: incomplete or inconsistent snapshot")
	ErrFreshState      = errors.New("gateway fresh preflight: state is not empty and mutable")
	ErrFreshHosts      = errors.New("gateway fresh preflight: hosts source is not owned by the selected Tailnet")
	ErrFreshConflict   = errors.New("gateway fresh preflight: identity, address or resource name is in use")
	ErrFreshProvenance = errors.New("gateway fresh preflight: persistent authentication and node provenance unverified")
)

// FreshObjectKey names one of the nine resources RenderFresh would create. An
// absent key means a caller observed NotFound, not that the name is reserved.
// A reader error must NEVER be represented as absence. This snapshot is not
// authorization for a writer: missing names can be taken immediately afterwards.
type FreshObjectKey struct {
	Kind, Namespace, Name string
}

// FreshInspectionInputs contains already-read snapshots; it performs no API
// calls. Callers must obtain peer/node lists from the intended Headscale and
// cluster at one consistent point in time and explicitly report all nine
// absent names. In particular, nil State or Hosts is NOT an empty object.
// Secret contents must not be logged or copied into a receipt.
type FreshInspectionInputs struct {
	Fresh        FreshInputs
	State        *corev1.Secret
	Hosts        *corev1.ConfigMap
	Absent       []FreshObjectKey
	Occupied     []client.Object // observed live objects, including retained objects with our UID label
	PeerGateways []tnv1.TailnetGateway
	NodeNames    []string
}

// FreshInspection records only revision IDs from validated snapshots. It is
// diagnostic evidence, not an apply plan, a lock, or bootstrap permission.
type FreshInspection struct {
	GatewayUID, TailnetUID, StateUID, HostsUID                 types.UID
	GatewayVersion, TailnetVersion, StateVersion, HostsVersion string
}

// InspectFreshSnapshots proves necessary read-only prerequisites, then ALWAYS
// blocks on unverifiable external auth-key provenance. Headscale's current API
// cannot look up the supplied key's server/tags/ephemerality or bind fresh state
// to a persistent node. No success return is possible until that proof is
// implemented and independently reviewed; never mint a key to pass this gate.
// The suspension controller does not call this function.
func InspectFreshSnapshots(in FreshInspectionInputs) (FreshInspection, error) {
	plan, err := RenderFresh(in.Fresh)
	if err != nil || in.Fresh.Gateway != nil && in.Fresh.Gateway.Spec.Suspend != nil && !*in.Fresh.Gateway.Spec.Suspend {
		return FreshInspection{}, ErrFreshSnapshot
	}
	g, tn, state, hosts := in.Fresh.Gateway, in.Fresh.Tailnet, in.State, in.Hosts
	if g.ResourceVersion == "" || tn.UID == "" || tn.ResourceVersion == "" || state == nil || hosts == nil ||
		state.UID == "" || state.ResourceVersion == "" || hosts.UID == "" || hosts.ResourceVersion == "" ||
		state.Name != string(g.Spec.StateSecretRef.Name) || state.Namespace != in.Fresh.Namespace ||
		hosts.Name != tn.Spec.DNS.HostsConfigMap || hosts.Namespace != in.Fresh.Namespace || hosts.Name == "" {
		return FreshInspection{}, ErrFreshSnapshot
	}
	if state.DeletionTimestamp != nil || state.Immutable != nil && *state.Immutable ||
		len(state.Data) != 0 || len(state.StringData) != 0 || len(state.OwnerReferences) != 0 || len(state.Finalizers) != 0 ||
		len(state.Annotations) != 0 ||
		state.Type != "" && state.Type != corev1.SecretTypeOpaque {
		return FreshInspection{}, ErrFreshState
	}
	if hosts.DeletionTimestamp != nil || hosts.Labels["app.kubernetes.io/managed-by"] != "tailnet-operator" ||
		hosts.Labels["tsunaro.io/role"] != "dns-hosts" || len(hosts.OwnerReferences) != 1 ||
		hosts.OwnerReferences[0].UID != tn.UID || hosts.OwnerReferences[0].Name != tn.Name ||
		hosts.OwnerReferences[0].Kind != "Tailnet" || hosts.OwnerReferences[0].APIVersion != "tsunaro.io/v1alpha1" ||
		hosts.OwnerReferences[0].Controller == nil || !*hosts.OwnerReferences[0].Controller {
		return FreshInspection{}, ErrFreshHosts
	}
	if source, ok := hosts.Data["hosts"]; !ok || source != in.Fresh.Hosts || len(hosts.BinaryData) != 0 {
		return FreshInspection{}, ErrFreshHosts
	}
	want := make(map[FreshObjectKey]bool, len(plan.Objects))
	for _, obj := range plan.Objects {
		key := FreshObjectKey{Kind: freshObjectKind(obj), Namespace: obj.GetNamespace(), Name: obj.GetName()}
		if key.Kind == "" || want[key] || key.Name == hosts.Name && key.Kind == "ConfigMap" {
			return FreshInspection{}, ErrFreshConflict
		}
		want[key] = true
	}
	if len(want) != 9 || len(in.Absent)+len(in.Occupied) != len(want) {
		return FreshInspection{}, ErrFreshSnapshot
	}
	for _, obj := range in.Occupied {
		if obj == nil {
			return FreshInspection{}, ErrFreshSnapshot
		}
		key := FreshObjectKey{Kind: freshObjectKind(obj), Namespace: obj.GetNamespace(), Name: obj.GetName()}
		if !want[key] {
			return FreshInspection{}, ErrFreshSnapshot
		}
		// Matching labels/UID do not allow an existing object to be treated as
		// fresh. A retained resource needs the separate adoption protocol.
		return FreshInspection{}, ErrFreshConflict
	}
	for _, key := range in.Absent {
		if !want[key] {
			return FreshInspection{}, ErrFreshSnapshot
		}
		delete(want, key)
	}
	for _, peer := range in.PeerGateways {
		if peer.Namespace != "" || peer.UID == "" {
			return FreshInspection{}, ErrFreshSnapshot
		}
		if peer.UID == g.UID {
			if peer.Name != g.Name {
				return FreshInspection{}, ErrFreshSnapshot
			}
			continue
		}
		if peer.Name == g.Name || strings.EqualFold(peer.Spec.Hostname, g.Spec.Hostname) ||
			peer.Spec.StateSecretRef.Name == g.Spec.StateSecretRef.Name ||
			peer.Spec.AuthKeySecretRef != nil && peer.Spec.AuthKeySecretRef.Name == g.Spec.AuthKeySecretRef.Name ||
			peer.Spec.DNS.ServiceName == g.Spec.DNS.ServiceName ||
			peer.Spec.Service.LoadBalancerIP == g.Spec.Service.LoadBalancerIP ||
			peer.Spec.DNS.ServiceClusterIP == g.Spec.DNS.ServiceClusterIP {
			return FreshInspection{}, ErrFreshConflict
		}
	}
	for _, name := range in.NodeNames {
		if strings.EqualFold(name, g.Spec.Hostname) {
			return FreshInspection{}, ErrFreshConflict
		}
	}
	return FreshInspection{GatewayUID: g.UID, TailnetUID: tn.UID, StateUID: state.UID, HostsUID: hosts.UID,
		GatewayVersion: g.ResourceVersion, TailnetVersion: tn.ResourceVersion, StateVersion: state.ResourceVersion, HostsVersion: hosts.ResourceVersion}, ErrFreshProvenance
}

func freshObjectKind(obj client.Object) string {
	switch obj.(type) {
	case *corev1.ServiceAccount:
		return "ServiceAccount"
	case *rbacv1.Role:
		return "Role"
	case *rbacv1.RoleBinding:
		return "RoleBinding"
	case *corev1.ConfigMap:
		return "ConfigMap"
	case *corev1.Service:
		return "Service"
	case *policyv1.PodDisruptionBudget:
		return "PodDisruptionBudget"
	case *appsv1.StatefulSet:
		return "StatefulSet"
	default:
		return ""
	}
}
