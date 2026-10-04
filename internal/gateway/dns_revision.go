package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"regexp"
)

var (
	ErrDNSRevisionInvalid   = errors.New("gateway DNS revision: missing or invalid persisted state")
	ErrDNSRevisionExhausted = errors.New("gateway DNS revision: SOA serial exhausted")
	dnsRevisionHash         = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// DNSRevision is the minimal state a future writer must persist *alongside*
// the derived zone, guarded by a Kubernetes ConfigMap resourceVersion. This
// pure model neither reads nor writes Kubernetes, and a string supplied by a
// caller is not proof of a successful CAS. The hash is of canonical rendered
// Corefile/zone bytes at serial 1, never of a Secret or a raw hosts snapshot.
type DNSRevision struct {
	Serial          uint32
	ContentHash     string
	ResourceVersion string
}

// DNSRevisionPlan contains the CAS precondition needed for an UPDATE. A blank
// version denotes a first-time CREATE only; it is NOT permission to overwrite
// an existing object. A writer must re-read the source and target after a
// conflict and recompute the entire render, never retry a stale plan.
type DNSRevisionPlan struct {
	DNSRevision
	ExpectedResourceVersion string
	Changed                 bool
}

// PlanDNSRevision computes a stable semantic hash independent of SOA serial.
// Cosmetic reordering of equivalent hosts input leaves the serial unchanged;
// adding/changing a rendered record advances it, including hosts-only changes.
// The first new zone starts at 1. Wrapping would reuse old serials and confuse
// caches, so exhaustion is a hard failure, not a reset on restart.
func PlanDNSRevision(in DNSInputs, previous *DNSRevision) (DNSRevisionPlan, error) {
	in.Serial = 1
	canonical, err := RenderDNS(in)
	if err != nil {
		return DNSRevisionPlan{}, err
	}
	b := sha256.Sum256([]byte(canonical.Corefile + "\x00" + canonical.ZoneFile))
	hash := hex.EncodeToString(b[:])
	if previous == nil {
		return DNSRevisionPlan{DNSRevision: DNSRevision{Serial: 1, ContentHash: hash}, Changed: true}, nil
	}
	if previous.Serial == 0 || !dnsRevisionHash.MatchString(previous.ContentHash) || previous.ResourceVersion == "" {
		return DNSRevisionPlan{}, ErrDNSRevisionInvalid
	}
	plan := DNSRevisionPlan{DNSRevision: DNSRevision{Serial: previous.Serial, ContentHash: hash, ResourceVersion: previous.ResourceVersion}, ExpectedResourceVersion: previous.ResourceVersion}
	if previous.ContentHash == hash {
		return plan, nil
	}
	if previous.Serial == math.MaxUint32 {
		return DNSRevisionPlan{}, ErrDNSRevisionExhausted
	}
	plan.Serial++
	plan.Changed = true
	return plan, nil
}
