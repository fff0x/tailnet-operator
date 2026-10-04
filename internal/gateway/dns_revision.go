package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

var (
	ErrDNSRevisionInvalid   = errors.New("gateway DNS revision: missing or invalid persisted state")
	ErrDNSRevisionExhausted = errors.New("gateway DNS revision: SOA serial exhausted")
	dnsRevisionHash         = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const (
	DNSSerialAnnotation = "tsunaro.io/dns-serial"
	DNSHashAnnotation   = "tsunaro.io/dns-content-sha256"
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
	hash := dnsContentHash(canonical.Corefile, canonical.ZoneFile)
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

func dnsContentHash(corefile, zoneFile string) string {
	b := sha256.Sum256([]byte(corefile + "\x00" + zoneFile))
	return hex.EncodeToString(b[:])
}

// ReadDNSRevision validates that the persisted serial and hash describe the
// target ConfigMap's *actual* payload. It does not prove ownership, trusted
// origin, freshness of the hosts source, or that the Corefile is safe; a writer
// must verify all of those separately before treating this as prior state.
// Missing annotations must NEVER be interpreted as a fresh serial 1.
func ReadDNSRevision(cm *corev1.ConfigMap, zone string) (DNSRevision, error) {
	if cm == nil || !dnsZone(zone) || cm.UID == "" || cm.ResourceVersion == "" ||
		len(cm.Data) != 2 || len(cm.BinaryData) != 0 || cm.Data["Corefile"] == "" || cm.Data[DNSZoneFile] == "" {
		return DNSRevision{}, ErrDNSRevisionInvalid
	}
	serialText, hash := cm.Annotations[DNSSerialAnnotation], cm.Annotations[DNSHashAnnotation]
	serial, err := strconv.ParseUint(serialText, 10, 32)
	if err != nil || serial == 0 || serialText != strconv.FormatUint(serial, 10) || !dnsRevisionHash.MatchString(hash) {
		return DNSRevision{}, ErrDNSRevisionInvalid
	}
	prefix := fmt.Sprintf("%s. 30 IN SOA %s. hostmaster.invalid. ", zone, zone)
	first, remainder, found := strings.Cut(cm.Data[DNSZoneFile], "\n")
	soa := prefix + serialText + " 7200 3600 1209600 30"
	if !found || first != soa || remainder == "" {
		return DNSRevision{}, ErrDNSRevisionInvalid
	}
	canonical := prefix + "1 7200 3600 1209600 30\n" + remainder
	if dnsContentHash(cm.Data["Corefile"], canonical) != hash {
		return DNSRevision{}, ErrDNSRevisionInvalid
	}
	return DNSRevision{Serial: uint32(serial), ContentHash: hash, ResourceVersion: cm.ResourceVersion}, nil
}
