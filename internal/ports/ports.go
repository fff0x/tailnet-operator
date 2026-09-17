// Package ports assigns each target a stable local listen port. Stable is the point: a target keeps
// its port across reconciles so the agent never rebinds a listener it did not have to, and two
// targets on the same upstream port (two Informix on 1528) still get distinct local ports.
package ports

// Base is the first local listen port. Well above the well-known range, low enough to read at a
// glance in a pod's netstat.
const Base int32 = 10000

// Assign keeps every still-wanted existing assignment and gives each new target the smallest free
// port from Base up. Pure and deterministic: new targets are assigned in slice order, so the result
// depends only on the inputs, not on map iteration.
func Assign(existing map[string]int32, targets []string) map[string]int32 {
	want := make(map[string]bool, len(targets))
	for _, t := range targets {
		want[t] = true
	}

	out := make(map[string]int32, len(targets))
	used := make(map[int32]bool, len(targets))
	for name, p := range existing {
		if want[name] {
			out[name] = p
			used[p] = true
		}
	}

	next := Base
	for _, t := range targets {
		if _, ok := out[t]; ok {
			continue
		}
		for used[next] {
			next++
		}
		out[t] = next
		used[next] = true
	}
	return out
}
