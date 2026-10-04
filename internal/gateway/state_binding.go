package gateway

import (
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"tailscale.com/types/key"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

var (
	ErrGatewayStateBinding = errors.New("gateway identity: persistent state and Headscale node are not bound")
	profileStateKey        = regexp.MustCompile(`^profile-[a-zA-Z0-9_-]{1,96}$`)
	decimalNodeID          = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
)

// GatewayStateBinding includes only public identity and Kubernetes revision
// references. It is not a route, service or DNS health result. The verifier
// consumes private machine/node keys in memory, but never returns or logs them.
type GatewayStateBinding struct {
	NodeID       string
	IPv4         string
	StateUID     types.UID
	StateVersion string
}

// VerifyGatewayState compares the *active* TS_KUBE_SECRET profile and machine
// key to a complete, authenticated ListNodes response from the selected
// Headscale server. State layout is from Tailscale containerboot v1.102.4 and
// the pinned v1.94.1 Go types. A caller must verify the snapshot provenance,
// selected API URL and Secret-write RBAC separately; a matching hostname alone
// is never enough. External keys and adoption still need their own consent and
// identical-payload checks before a controller can use this receipt.
func VerifyGatewayState(g *tnv1.TailnetGateway, tn *tnv1.Tailnet, state *corev1.Secret, namespace string, expectedStateUID types.UID, nodes []headscale.Node, mintedKeyID string) (GatewayStateBinding, error) {
	bad := func() (GatewayStateBinding, error) { return GatewayStateBinding{}, ErrGatewayStateBinding }
	if g == nil || tn == nil || state == nil || g.UID == "" || tn.UID == "" || g.Namespace != "" || tn.Namespace != "" ||
		g.Spec.Hostname == "" || string(g.Spec.TailnetRef.Name) != tn.Name ||
		state.Name != string(g.Spec.StateSecretRef.Name) || state.Namespace != namespace ||
		expectedStateUID == "" || state.UID != expectedStateUID || state.ResourceVersion == "" || state.DeletionTimestamp != nil ||
		state.Immutable != nil && *state.Immutable || state.Type != corev1.SecretTypeOpaque || len(state.OwnerReferences) != 0 ||
		len(state.StringData) != 0 || len(state.Data) < 2 || len(state.Data) > 64 {
		return bad()
	}
	machineText := state.Data["_machinekey"]
	active := string(state.Data["_current-profile"])
	if len(machineText) == 0 || len(machineText) > 128 || !profileStateKey.MatchString(active) || len(state.Data["_current-profile"]) != len(active) {
		return bad()
	}
	profile := state.Data[active]
	if len(profile) == 0 || len(profile) > 1<<20 {
		return bad()
	}
	var machine key.MachinePrivate
	if machine.UnmarshalText(machineText) != nil || machine.IsZero() {
		return bad()
	}
	// Decode only the public control URL and the two persisted identity
	// fields. Never serialize the full Prefs struct or print decoder errors.
	var stored struct {
		ControlURL string `json:"ControlURL"`
		Config     struct {
			PrivateNodeKey key.NodePrivate `json:"PrivateNodeKey"`
		} `json:"Config"`
	}
	if json.Unmarshal(profile, &stored) != nil || stored.ControlURL != tn.Spec.Server || stored.Config.PrivateNodeKey.IsZero() {
		return bad()
	}
	machinePublic := machine.Public().String()
	nodePublic := stored.Config.PrivateNodeKey.Public().String()
	var match *headscale.Node
	for i := range nodes {
		n := &nodes[i]
		if n.MachineKey != machinePublic {
			if n.GivenName == g.Spec.Hostname {
				return bad() // a different node already owns the requested name
			}
			continue
		}
		if match != nil {
			return bad() // duplicate machine key is ambiguous, even if offline
		}
		match = n
	}
	if match == nil || !match.Online || !decimalNodeID.MatchString(match.ID) ||
		match.NodeKey != nodePublic || match.GivenName != g.Spec.Hostname {
		return bad()
	}
	if _, err := strconv.ParseUint(match.ID, 10, 64); err != nil {
		return bad()
	}
	tags, expected := slices.Clone(match.Tags), slices.Clone(g.Spec.Tags)
	slices.Sort(tags)
	slices.Sort(expected)
	if len(expected) == 0 || !slices.Equal(tags, expected) || len(slices.Compact(tags)) != len(tags) ||
		mintedKeyID != "" && (match.PreAuthKey == nil || match.PreAuthKey.ID != mintedKeyID || match.PreAuthKey.Ephemeral) {
		return bad()
	}
	var ipv4 string
	for _, raw := range match.IPAddresses {
		ip, err := netip.ParseAddr(raw)
		if err != nil || ip.Zone() != "" || ip.Is4In6() || !ip.IsGlobalUnicast() {
			return bad()
		}
		if ip.Is4() {
			if ipv4 != "" || ip.String() != raw {
				return bad()
			}
			ipv4 = raw
		}
	}
	if ipv4 == "" {
		return bad()
	}
	return GatewayStateBinding{NodeID: match.ID, IPv4: ipv4, StateUID: state.UID, StateVersion: state.ResourceVersion}, nil
}
