package metrics

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestReasonAllowlistCoversControllerReasons guards against the silent "Other" collapse: a condition
// reason the controllers emit but that reason()/conditionType() do not know is dropped from every
// metric label, so a new NotReady cause becomes invisible on dashboards. The test scans the
// controller source for the three ways a reason reaches a condition and asserts each is recognized.
//
// ponytail: only multi-word CamelCase reasons are checked (>=2 uppercase letters). Single-word
// reasons (Ready, Denied, File, None) are not auto-covered; add them to reason() by hand. Upgrade
// path if that ceiling bites: parse the package with go/ast and follow the reason variables.
func TestReasonAllowlistCoversControllerReasons(t *testing.T) {
	files, err := filepath.Glob("../controller/*.go")
	if err != nil {
		t.Fatal(err)
	}
	// Reasons reach a condition as: the 5th setCond arg right after the status, an assignment to a
	// reason variable, or the inspect return (result, reason, name).
	producers := []*regexp.Regexp{
		regexp.MustCompile(`metav1\.Condition(?:True|False|Unknown),\s*"([A-Za-z]+)"`),
		regexp.MustCompile(`(?:localReason|state\.reason|targetReason|trReason)\s*(?:,\s*\w+\s*)?=\s*"([A-Za-z]+)"`),
		regexp.MustCompile(`return\s+\w+,\s*"([A-Za-z]+)",`),
	}
	multiWord := regexp.MustCompile(`[A-Z]`)
	seen := map[string]string{} // reason -> first file
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, re := range producers {
			for _, m := range re.FindAllStringSubmatch(string(src), -1) {
				r := m[1]
				if len(multiWord.FindAllString(r, -1)) < 2 { // single-word: outside the ceiling
					continue
				}
				if _, ok := seen[r]; !ok {
					seen[r] = filepath.Base(f)
				}
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("scanned no reasons — the regexes or the glob broke")
	}
	for r, f := range seen {
		if reason(r) != r && conditionType(r) != r {
			t.Errorf("reason %q (emitted in %s) collapses to %q in metrics — add it to reason() in metrics.go",
				r, f, reason(r))
		}
	}
}
