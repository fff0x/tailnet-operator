package main

import (
	"sort"
	"testing"
)

func names(ts []target) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Name
	}
	sort.Strings(out)
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDiffFresh(t *testing.T) {
	start, stop := diffTargets(nil, []target{
		{Name: "a", Address: "1.1.1.1", Port: 1, ListenPort: 10000},
		{Name: "b", Address: "2.2.2.2", Port: 2, ListenPort: 10001},
	})
	if !eq(names(start), []string{"a", "b"}) {
		t.Errorf("start=%v want [a b]", names(start))
	}
	if len(stop) != 0 {
		t.Errorf("stop=%v want none", stop)
	}
}

func TestDiffUnchanged(t *testing.T) {
	run := map[string]target{"a": {Name: "a", Address: "1.1.1.1", Port: 1, ListenPort: 10000}}
	start, stop := diffTargets(run, []target{{Name: "a", Address: "1.1.1.1", Port: 1, ListenPort: 10000}})
	if len(start) != 0 || len(stop) != 0 {
		t.Errorf("unchanged should be a no-op: start=%v stop=%v", names(start), stop)
	}
}

func TestDiffRemoved(t *testing.T) {
	run := map[string]target{
		"a": {Name: "a", Address: "1.1.1.1", Port: 1, ListenPort: 10000},
		"b": {Name: "b", Address: "2.2.2.2", Port: 2, ListenPort: 10001},
	}
	start, stop := diffTargets(run, []target{{Name: "a", Address: "1.1.1.1", Port: 1, ListenPort: 10000}})
	if len(start) != 0 {
		t.Errorf("start=%v want none", names(start))
	}
	sort.Strings(stop)
	if !eq(stop, []string{"b"}) {
		t.Errorf("stop=%v want [b]", stop)
	}
}

func TestDiffChangedStopsAndStarts(t *testing.T) {
	run := map[string]target{"a": {Name: "a", Address: "1.1.1.1", Port: 1, ListenPort: 10000}}
	// Same name, new upstream port → must stop the old listener and start the new one.
	start, stop := diffTargets(run, []target{{Name: "a", Address: "1.1.1.1", Port: 9, ListenPort: 10000}})
	if !eq(names(start), []string{"a"}) {
		t.Errorf("start=%v want [a]", names(start))
	}
	if !eq(stop, []string{"a"}) {
		t.Errorf("stop=%v want [a]", stop)
	}
}
