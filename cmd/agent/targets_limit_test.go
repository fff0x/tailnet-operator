package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestTargetsLimitMatchesProbeBudget(t *testing.T) {
	for _, versioned := range []bool{false, true} {
		for _, count := range []int{50, 51} {
			t.Run(fmt.Sprintf("versioned=%t/count=%d", versioned, count), func(t *testing.T) {
				targets := make([]target, count)
				for i := range targets {
					targets[i] = target{Name: fmt.Sprintf("target-%d", i), Address: "127.0.0.1", Port: 80, ListenPort: 10000 + i}
				}
				var value any = targets
				if versioned {
					value = map[string]any{"version": 1, "targets": targets}
				}
				data, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "targets.json")
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				got, err := loadTargets(path)
				if count == 50 {
					if err != nil || len(got) != count {
						t.Fatal("supported configuration was rejected")
					}
				} else if !errors.Is(err, errTargetsConfig) {
					t.Fatal("oversized configuration escaped fixed probe budget")
				}
			})
		}
	}
}
