package security

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// Execute the actual native shell with closed mocks, never a build, publication,
// signer or cluster. This checks ordering and cleanup, not artifact acceptance.
func TestNativePipelineOrderingAndCleanup(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../.radicle/native.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Shell string `json:"shell"`
	}
	if err := yaml.Unmarshal(data, &spec); err != nil || spec.Shell == "" {
		t.Fatalf("invalid native specification: %v", err)
	}
	for _, tc := range []struct {
		name string
		want []string
		pass bool
	}{
		{"success", []string{"chart", "preflight", "build", "from", "test", "remove", "publish", "audit"}, true},
		{"chart-failure", []string{"chart"}, false},
		{"preflight-failure", []string{"chart", "preflight"}, false},
		{"build-failure", []string{"chart", "preflight", "build"}, false},
		{"test-failure", []string{"chart", "preflight", "build", "from", "test", "remove"}, false},
		{"remove-failure", []string{"chart", "preflight", "build", "from", "test", "remove", "remove"}, false},
		{"publish-failure", []string{"chart", "preflight", "build", "from", "test", "remove", "publish"}, false},
		{"missing-result", []string{"chart", "preflight", "build", "from", "test", "remove", "publish", "audit"}, false},
		{"audit-failure", []string{"chart", "preflight", "build", "from", "test", "remove", "publish", "audit"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, name := range []string{"bin", "hack", "workspaces", "home"} {
				if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
					t.Fatal(err)
				}
			}
			put := func(name, text string) {
				writeAuditFile(t, filepath.Join(root, name), []byte(text), 0700)
			}
			put("fixture-input", "tracked fixture input\n")
			put("untracked-input", "must not enter context\n")
			put("bin/git", `#!/usr/bin/env bash
set -euo pipefail
[[ $1 == ls-files && $2 == -z ]] || exit 97
printf 'fixture-input\0'
`)
			put("bin/uname", "#!/usr/bin/env bash\n[[ $1 == -m ]] || exit 97\nprintf 'x86_64\\n'\n")
			put("hack/chart-check.sh", `#!/usr/bin/env bash
set -euo pipefail
printf 'chart\n' >> "$PIPELINE_EVENTS"
[[ $PIPELINE_SCENARIO != chart-failure ]]
`)
			put("hack/audit-image.sh", `#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  --check-tools)
    printf 'preflight\n' >> "$PIPELINE_EVENTS"
    [[ $PIPELINE_SCENARIO != preflight-failure ]]
    ;;
  --result)
    printf 'audit\n' >> "$PIPELINE_EVENTS"
    [[ -f $2 && ! -L $2 && $(stat -c %a "$2") == 600 ]]
    [[ $(< "$2") == 'private publication result' ]]
    [[ $PIPELINE_SCENARIO != audit-failure ]]
    ;;
  *) exit 97 ;;
esac
`)
			put("bin/buildah", `#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  bud)
    printf 'build\n' >> "$PIPELINE_EVENTS"
    [[ " $* " == *' --http-proxy=false '* && " $* " == *' --target TEST '* ]]
    context=${!#}
    [[ -f $context/fixture-input && ! -e $context/untracked-input ]]
    iid=''
    while (($#)); do
      if [[ $1 == --iidfile ]]; then iid=$2; break; fi
      shift
    done
    [[ -n $iid && $PIPELINE_SCENARIO != build-failure ]]
    printf 'fixture-image\n' > "$iid"
    ;;
  from)
    printf 'from\n' >> "$PIPELINE_EVENTS"
    [[ $* == 'from --http-proxy=false --pull=never fixture-image' ]]
    printf 'fixture-container\n'
    ;;
  run)
    printf 'test\n' >> "$PIPELINE_EVENTS"
    [[ $* == 'run fixture-container -- bash hack/ci-test.sh' ]]
    [[ $PIPELINE_SCENARIO != test-failure ]]
    ;;
  rm)
    printf 'remove\n' >> "$PIPELINE_EVENTS"
    [[ $* == 'rm fixture-container' && $PIPELINE_SCENARIO != remove-failure ]]
    ;;
  *) exit 97 ;;
esac
`)
			put("bin/ci-build", `#!/usr/bin/env bash
# ci-build-capability: mixed-helm-v1
# ci-build-capability: image-result-v1
set -euo pipefail
printf 'publish\n' >> "$PIPELINE_EVENTS"
[[ -n ${CI_BUILD_RESULT_FILE:-} && $CI_BUILD_RESULT_FILE == "$TMPDIR"/*/published.json ]]
[[ ! -e $CI_BUILD_RESULT_FILE && $PIPELINE_SCENARIO != publish-failure ]]
if [[ $PIPELINE_SCENARIO != missing-result ]]; then
  printf 'private publication result\n' > "$CI_BUILD_RESULT_FILE"
fi
`)
			events := filepath.Join(root, "events")
			cmd := exec.Command("bash", "-euo", "pipefail", "-c", spec.Shell)
			cmd.Dir = root
			cmd.Env = []string{
				"PATH=" + filepath.Join(root, "bin") + ":" + os.Getenv("PATH"),
				"HOME=" + filepath.Join(root, "home"), "TMPDIR=" + filepath.Join(root, "workspaces"),
				"PIPELINE_EVENTS=" + events, "PIPELINE_SCENARIO=" + tc.name,
			}
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.pass {
				t.Fatalf("unexpected mock pipeline result: %v, %s", err, out)
			}
			b, err := os.ReadFile(events)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Fields(string(b)); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("stages: got %v, want %v", got, tc.want)
			}
			left, err := os.ReadDir(filepath.Join(root, "workspaces"))
			if err != nil || len(left) != 0 {
				t.Fatalf("private contexts/results not cleaned: entries=%d, err=%v", len(left), err)
			}
		})
	}
}
