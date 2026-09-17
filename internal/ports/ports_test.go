package ports

import (
	"reflect"
	"testing"
)

func TestAssignFresh(t *testing.T) {
	got := Assign(nil, []string{"a", "b", "c"})
	want := map[string]int32{"a": 10000, "b": 10001, "c": 10002}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestAssignStableOnReorder(t *testing.T) {
	first := Assign(nil, []string{"a", "b", "c"})
	// Same set, different order: every port must be unchanged.
	second := Assign(first, []string{"c", "a", "b"})
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("ports changed on reorder: %v -> %v", first, second)
	}
}

func TestAssignInsertKeepsExisting(t *testing.T) {
	existing := map[string]int32{"a": 10000, "b": 10001}
	got := Assign(existing, []string{"a", "b", "d"})
	if got["a"] != 10000 || got["b"] != 10001 {
		t.Fatalf("existing moved: %v", got)
	}
	if got["d"] != 10002 {
		t.Fatalf("new target got %d want 10002", got["d"])
	}
}

func TestAssignRemovalFreesPortForReuse(t *testing.T) {
	existing := map[string]int32{"a": 10000, "b": 10001, "c": 10002}
	// Drop "a" (10000 freed), add "d": smallest free from Base is 10000.
	got := Assign(existing, []string{"b", "c", "d"})
	if got["b"] != 10001 || got["c"] != 10002 {
		t.Fatalf("survivors moved: %v", got)
	}
	if got["d"] != 10000 {
		t.Fatalf("d got %d want reclaimed 10000", got["d"])
	}
	if _, ok := got["a"]; ok {
		t.Fatalf("removed target still present: %v", got)
	}
}

func TestAssignEmpty(t *testing.T) {
	if got := Assign(nil, nil); len(got) != 0 {
		t.Fatalf("want empty, got %v", got)
	}
}
