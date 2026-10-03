package controller

import (
	"cmp"
	"net"
	"slices"
	"strings"
	"time"
	"unicode"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/naming"
)

const (
	dnsIngressKind = "TailnetIngress"
	dnsEgressKind  = "TailnetEgress"

	dnsClaimIdentityInvalid = "DNSClaimIdentityInvalid"
	dnsClaimInputInvalid    = "DNSClaimInputInvalid"
	dnsEgressTargetInvalid  = "DNSEgressTargetInvalid"
	dnsEgressAliasInvalid   = "DNSEgressAliasInvalid"
	dnsEgressAliasAmbiguous = "DNSEgressAliasAmbiguous"
)

// dnsClaimScope is logical, within one operator's boundary. Tailnet UID is NOT
// part of this key: recreating a Tailnet cannot create a parallel same-name scope.
type dnsClaimScope struct {
	OperatorNamespace string
	TailnetName       string
}

// dnsClaimOwnerKey deliberately excludes time.Time (including its location and
// monotonic clock representation). CreationTimestamp ranks owners, not identity.
type dnsClaimOwnerKey struct {
	Kind, Namespace, Name string
	UID                   types.UID
}

type dnsClaimOwner struct {
	dnsClaimOwnerKey
	CreationTimestamp time.Time
}

// A source describes why ONE owner claims a name. Base and expose provenance
// may coexist; neither creates another owner or an implicit HTTP route.
type dnsClaimSource struct {
	Kind string // base, expose, or target
	Name string // expose/target identifier; empty for base
}

type dnsNameClaim struct {
	Name    string
	Sources []dnsClaimSource
}

// dnsDesiredClaims contains only current intent. It must never be used to store
// previously served names or infer that an old serving workload has drained.
type dnsDesiredClaims struct {
	Scope      dnsClaimScope
	TailnetUID types.UID // incarnation provenance, not an arbitration partition
	Owner      dnsClaimOwner
	Claims     []dnsNameClaim
}

type dnsClaimConflict struct {
	Name  string
	Owner dnsClaimOwner
}

// dnsClaimDecision is NOT serving permission. Even an unblocked current winner
// may wait for historical serving barriers in the future lifecycle coordinator.
// A blocked owner still owns its other winning names; never re-arbitrate without
// it. Conflict is the lexically first lost name and that name's ranked winner.
type dnsClaimDecision struct {
	Desired    dnsDesiredClaims
	OwnedNames []string
	Blocked    bool
	Conflict   *dnsClaimConflict
}

func validDNSClaimUID(uid types.UID) bool {
	return uid != "" && !strings.ContainsFunc(string(uid), func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	})
}

func validDNSClaimOwner(owner dnsClaimOwner) bool {
	return (owner.Kind == dnsIngressKind || owner.Kind == dnsEgressKind) &&
		len(validation.IsDNS1123Label(owner.Namespace)) == 0 &&
		len(validation.IsDNS1123Subdomain(owner.Name)) == 0 &&
		validDNSClaimUID(owner.UID) && !owner.CreationTimestamp.IsZero() &&
		owner.CreationTimestamp.Year() >= 1 && owner.CreationTimestamp.Year() <= 9999
}

func validDNSClaimScope(scope dnsClaimScope) bool {
	return len(validation.IsDNS1123Label(scope.OperatorNamespace)) == 0 &&
		len(validation.IsDNS1123Subdomain(scope.TailnetName)) == 0
}

func newDNSDesiredClaims(meta metav1.ObjectMeta, kind string, tn *tnv1.Tailnet, operatorNamespace string) (*dnsDesiredClaims, string) {
	set := &dnsDesiredClaims{
		Scope:      dnsClaimScope{OperatorNamespace: operatorNamespace, TailnetName: tn.Name},
		TailnetUID: tn.UID,
		Owner: dnsClaimOwner{
			dnsClaimOwnerKey:  dnsClaimOwnerKey{Kind: kind, Namespace: meta.Namespace, Name: meta.Name, UID: meta.UID},
			CreationTimestamp: meta.CreationTimestamp.Time.Round(0).UTC(),
		},
	}
	if !validDNSClaimOwner(set.Owner) || !validDNSClaimScope(set.Scope) || !validDNSClaimUID(set.TailnetUID) {
		return nil, dnsClaimIdentityInvalid
	}
	return set, ""
}

// desiredIngressDNSClaims derives base + HTTP routes from the existing pure
// planner. Static ingress validity stays with that planner; no status, TLS
// material, Pods, credentials, DNS output, or deletion filtering is consulted.
// nil with an empty reason means feature-off or outside the selected Tailnet.
func desiredIngressDNSClaims(in *tnv1.TailnetIngress, tn *tnv1.Tailnet, operatorNamespace string) (*dnsDesiredClaims, string) {
	if tn == nil {
		return nil, dnsClaimInputInvalid
	}
	if tn.Spec.DNS.HostsConfigMap == "" {
		return nil, ""
	}
	if in == nil {
		return nil, dnsClaimInputInvalid
	}
	if tn.Name == "" || in.Spec.TailnetRef.Name == "" {
		return nil, dnsClaimIdentityInvalid
	}
	if in.Spec.TailnetRef.Name != tn.Name {
		return nil, ""
	}
	set, reason := newDNSDesiredClaims(in.ObjectMeta, dnsIngressKind, tn, operatorNamespace)
	if reason != "" {
		return nil, reason
	}
	plan, reason := resolveIngressDNSNames(in, tn)
	if reason != "" {
		return nil, reason
	}
	names := make(map[string][]dnsClaimSource)
	if plan.baseName != "" {
		names[plan.baseName] = []dnsClaimSource{{Kind: "base"}}
	}
	for expose, name := range plan.exposeNames {
		names[name] = append(names[name], dnsClaimSource{Kind: "expose", Name: expose})
	}
	for expose, alias := range plan.aliasNames {
		names[alias] = append(names[alias], dnsClaimSource{Kind: "alias", Name: expose})
	}
	set.Claims = sortedDNSNameClaims(names)
	return set, ""
}

// desiredEgressDNSClaims preserves the operator-namespace boundary. Aliases
// are already lowercase, non-absolute DNS names in the API contract: do not
// lowercase, trim, or strip a trailing dot to turn invalid input into a claim.
// In addition to the API's 63-character alias bound, reject IP literals.
func desiredEgressDNSClaims(eg *tnv1.TailnetEgress, tn *tnv1.Tailnet, operatorNamespace string) (*dnsDesiredClaims, string) {
	if tn == nil {
		return nil, dnsClaimInputInvalid
	}
	if tn.Spec.DNS.HostsConfigMap == "" {
		return nil, ""
	}
	if eg == nil {
		return nil, dnsClaimInputInvalid
	}
	if operatorNamespace == "" || tn.Name == "" {
		return nil, dnsClaimIdentityInvalid
	}
	if eg.Namespace != operatorNamespace {
		return nil, ""
	}
	if eg.Spec.TailnetRef.Name == "" {
		return nil, dnsClaimIdentityInvalid
	}
	if eg.Spec.TailnetRef.Name != tn.Name {
		return nil, ""
	}
	set, reason := newDNSDesiredClaims(eg.ObjectMeta, dnsEgressKind, tn, operatorNamespace)
	if reason != "" {
		return nil, reason
	}
	if len(eg.Spec.Targets) == 0 || len(eg.Spec.Targets) > 50 {
		return nil, dnsEgressTargetInvalid
	}
	// Validate target identities before aliases so the bounded error is also
	// independent of target order. Even identical duplicate targets violate CEL.
	targets := make(map[string]bool)
	for _, target := range eg.Spec.Targets {
		if len(validation.IsDNS1035Label(target.Name)) != 0 || targets[target.Name] {
			return nil, dnsEgressTargetInvalid
		}
		targets[target.Name] = true
	}
	for _, target := range eg.Spec.Targets {
		for _, alias := range target.Aliases {
			if len(alias) > 63 || naming.ValidateDNSName(alias) != nil || net.ParseIP(alias) != nil {
				return nil, dnsEgressAliasInvalid
			}
		}
	}
	names := make(map[string][]dnsClaimSource)
	for _, target := range eg.Spec.Targets {
		for _, alias := range target.Aliases {
			if sources := names[alias]; len(sources) != 0 && sources[0].Name != target.Name {
				return nil, dnsEgressAliasAmbiguous
			}
			names[alias] = []dnsClaimSource{{Kind: "target", Name: target.Name}}
		}
	}
	set.Claims = sortedDNSNameClaims(names)
	return set, ""
}

func sortedDNSNameClaims(names map[string][]dnsClaimSource) []dnsNameClaim {
	var claims []dnsNameClaim
	for name, sources := range names {
		copySources := slices.Clone(sources)
		slices.SortFunc(copySources, func(a, b dnsClaimSource) int {
			if c := cmp.Compare(a.Kind, b.Kind); c != 0 {
				return c
			}
			return cmp.Compare(a.Name, b.Name)
		})
		claims = append(claims, dnsNameClaim{Name: name, Sources: slices.Compact(copySources)})
	}
	slices.SortFunc(claims, func(a, b dnsNameClaim) int { return cmp.Compare(a.Name, b.Name) })
	return claims
}

// compareDNSClaimOwners is the single rank for both resource kinds.
func compareDNSClaimOwners(a, b dnsClaimOwner) int {
	if c := a.CreationTimestamp.Compare(b.CreationTimestamp); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Namespace, b.Namespace); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Name, b.Name); c != 0 {
		return c
	}
	if c := cmp.Compare(a.UID, b.UID); c != 0 {
		return c
	}
	return cmp.Compare(a.Kind, b.Kind)
}

// arbitrateDNSClaims accepts a complete CURRENT desired snapshot, not historical
// barriers. A caller must not drop invalid contenders and then use a partial
// snapshot: derivation errors require fail-closed coordination. Malformed or
// repeated owner snapshots likewise return a bounded reason and no decisions.
// All output slices are new allocations, including nested claim provenance.
func arbitrateDNSClaims(sets []dnsDesiredClaims) ([]dnsClaimDecision, string) {
	var decisions []dnsClaimDecision
	seen := make(map[dnsClaimOwnerKey]bool)
	for _, set := range sets {
		if !validDNSClaimOwner(set.Owner) || !validDNSClaimScope(set.Scope) || !validDNSClaimUID(set.TailnetUID) {
			return nil, dnsClaimIdentityInvalid
		}
	}
	for _, set := range sets {
		if seen[set.Owner.dnsClaimOwnerKey] ||
			(set.Owner.Kind == dnsEgressKind && set.Owner.Namespace != set.Scope.OperatorNamespace) {
			return nil, dnsClaimInputInvalid
		}
		seen[set.Owner.dnsClaimOwnerKey] = true
		names := make(map[string][]dnsClaimSource)
		for _, claim := range set.Claims {
			if naming.ValidateDNSName(claim.Name) != nil {
				return nil, dnsClaimInputInvalid
			}
			names[claim.Name] = append(names[claim.Name], claim.Sources...)
		}
		set.Owner.CreationTimestamp = set.Owner.CreationTimestamp.Round(0).UTC()
		set.Claims = sortedDNSNameClaims(names)
		decisions = append(decisions, dnsClaimDecision{Desired: set})
	}
	slices.SortFunc(decisions, func(a, b dnsClaimDecision) int {
		if c := cmp.Compare(a.Desired.Scope.OperatorNamespace, b.Desired.Scope.OperatorNamespace); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Desired.Scope.TailnetName, b.Desired.Scope.TailnetName); c != 0 {
			return c
		}
		return compareDNSClaimOwners(a.Desired.Owner, b.Desired.Owner)
	})
	type scopedName struct {
		Scope dnsClaimScope
		Name  string
	}
	winners := make(map[scopedName]dnsClaimOwner)
	// Rank-sorted first pass fixes winners before whole-owner blocking. Blocked
	// owners are never removed to let a younger owner take their other names.
	for _, decision := range decisions {
		for _, claim := range decision.Desired.Claims {
			key := scopedName{Scope: decision.Desired.Scope, Name: claim.Name}
			if _, exists := winners[key]; !exists {
				winners[key] = decision.Desired.Owner
			}
		}
	}
	for i := range decisions {
		d := &decisions[i]
		for _, claim := range d.Desired.Claims {
			winner := winners[scopedName{Scope: d.Desired.Scope, Name: claim.Name}]
			if winner.dnsClaimOwnerKey == d.Desired.Owner.dnsClaimOwnerKey {
				d.OwnedNames = append(d.OwnedNames, claim.Name)
			} else if d.Conflict == nil {
				d.Blocked = true
				d.Conflict = &dnsClaimConflict{Name: claim.Name, Owner: winner}
			}
		}
	}
	return decisions, ""
}
