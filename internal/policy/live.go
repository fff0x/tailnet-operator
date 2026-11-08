package policy

import (
	"fmt"
	"slices"
	"strings"
)

// MissingFromLive reports which entries of a spoke's fragment the live policy does not carry yet,
// mirroring exactly what mergeFragment adds on the hub: a tagOwners key, an approver inside
// autoApprovers.routes[cidr], or a grant by its canonical form. Empty means the hub has merged
// everything (or the fragment is empty). Entries are human-readable, sorted, for a status message.
func MissingFromLive(live, fragment []byte) ([]string, error) {
	l, err := parse(live)
	if err != nil {
		return nil, fmt.Errorf("live policy: %w", err)
	}
	f, err := parse(fragment)
	if err != nil {
		return nil, fmt.Errorf("fragment: %w", err)
	}
	var missing []string
	liveOwners, _ := l["tagOwners"].(map[string]any)
	if fo, ok := f["tagOwners"].(map[string]any); ok {
		for _, t := range sortedKeys(fo) {
			if _, exists := liveOwners[t]; !exists {
				missing = append(missing, t)
			}
		}
	}
	var liveRoutes map[string]any
	if la, ok := l["autoApprovers"].(map[string]any); ok {
		liveRoutes, _ = la["routes"].(map[string]any)
	}
	if fa, ok := f["autoApprovers"].(map[string]any); ok {
		if fr, ok := fa["routes"].(map[string]any); ok {
			for _, cidr := range sortedKeys(fr) {
				have := strs(liveRoutes[cidr])
				for _, approver := range strs(fr[cidr]) {
					if !slices.Contains(have, approver) {
						missing = append(missing, "route "+cidr+" → "+approver)
					}
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, g := range arr(l["grants"]) {
		seen[canon(g)] = true
	}
	for _, g := range arr(f["grants"]) {
		if !seen[canon(g)] {
			m, _ := g.(map[string]any)
			missing = append(missing, "grant "+strings.Join(strs(m["src"]), ",")+" → "+strings.Join(strs(m["dst"]), ","))
		}
	}
	return missing, nil
}
