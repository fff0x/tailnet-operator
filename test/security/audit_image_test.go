package security

// These are behavioral, fully offline tests. Every Git, registry, scanner and
// signer invocation runs this test executable as a mock, never a real CLI.
import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const (
	auditRepo   = "registry.invalid/tailnet/operator"
	auditSecret = "AUDIT-SECRET-DO-NOT-PRINT"
	auditRID    = "rad:z46fGxuhyvDV57psA8s6Q6PdHJrsX"
)

var (
	auditCommit  = strings.Repeat("d", 40)
	auditIndex   = "sha256:" + strings.Repeat("a", 64)
	auditAMD     = "sha256:" + strings.Repeat("b", 64)
	auditARM     = "sha256:" + strings.Repeat("c", 64)
	auditBuilder = "registry.invalid/radicle/ci-broker@sha256:" + strings.Repeat("e", 64)
)

type auditCall struct {
	Tool string   `json:"tool"`
	Args []string `json:"args"`
	Temp string   `json:"temp"`
}

type auditFixture struct {
	root, script, result string
	env                  []string
	input                map[string]any
}

func newAuditFixture(t *testing.T, scenario string) *auditFixture {
	t.Helper()
	for _, tool := range []string{"bash", "jq", "timeout"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("offline audit tests require %s: %v", tool, err)
		}
	}
	_, source, _, _ := runtime.Caller(0)
	f := &auditFixture{
		root: t.TempDir(), script: filepath.Join(filepath.Dir(source), "../../hack/audit-image.sh"),
		input: map[string]any{"schemaVersion": 1, "commit": auditCommit, "releaseTag": "", "images": []any{
			map[string]any{"repository": auditRepo, "digest": auditIndex},
		}},
	}
	bin := filepath.Join(f.root, "bin")
	for _, dir := range []string{bin, filepath.Join(f.root, "tmp"), filepath.Join(f.root, "evidence")} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"git", "crane", "syft", "trivy", "cosign-legacy"} {
		writeAuditFile(t, filepath.Join(bin, name), []byte("#!/usr/bin/env bash\nexec \"$AUDIT_TEST_BINARY\" '-test.run=^TestAuditToolProcess$' -- \"$0\" \"$@\"\n"), 0700)
	}
	key := filepath.Join(f.root, "synthetic.key")
	writeAuditFile(t, key, []byte(auditSecret+"-NOT-A-REAL-KEY"), 0600)
	f.result = filepath.Join(f.root, "result.json")
	// Whitelist inputs rather than inheriting credentials, BASH_ENV or exported
	// shell functions. Race detection stays enabled in mock children; only its
	// default one-second exit delay is removed for the many short-lived tools.
	f.env = append(f.env, "LANG=C.UTF-8", "GORACE=atexit_sleep_ms=0",
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "TMPDIR="+filepath.Join(f.root, "tmp"),
		"REGISTRY=registry.invalid", "CI_BUILDER_IMAGE="+auditBuilder, "COSIGN_KEY="+key, "COSIGN_PASSWORD="+auditSecret,
		"DOCKER_CONFIG="+filepath.Join(f.root, "nonexistent-docker-config"), "AUDIT_TEST_BINARY="+testBinary,
		"AUDIT_MOCK=1", "AUDIT_FIXTURE="+f.root, "AUDIT_SCENARIO="+scenario)
	return f
}

func writeAuditFile(t *testing.T, path string, b []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, b, mode); err != nil {
		t.Fatal(err)
	}
}

func (f *auditFixture) setenv(name, value string) {
	for i, entry := range f.env {
		if strings.HasPrefix(entry, name+"=") {
			f.env[i] = name + "=" + value
			return
		}
	}
	f.env = append(f.env, name+"="+value)
}

func (f *auditFixture) run(t *testing.T, checkOnly bool, raw []byte) (string, []auditCall, error) {
	t.Helper()
	if raw == nil {
		var err error
		raw, err = json.Marshal(f.input)
		if err != nil {
			t.Fatal(err)
		}
	}
	writeAuditFile(t, f.result, raw, 0600)
	args := []string{f.script, "--result", f.result}
	if checkOnly {
		args = []string{f.script, "--check-tools"}
	}
	cmd := exec.Command("bash", args...)
	cmd.Env = f.env
	cmd.Dir = f.root // No fixture repository or Git commits.
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), auditSecret) || strings.Contains(string(out), f.root) || strings.Contains(string(out), "registry.invalid") {
		t.Fatalf("audit leaked private input/diagnostics: %q", out)
	}
	entries, readErr := os.ReadDir(filepath.Join(f.root, "tmp"))
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("private artifacts not cleaned: %v, %v", entries, readErr)
	}
	var calls []auditCall
	b, readErr := os.ReadFile(filepath.Join(f.root, "calls.jsonl"))
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var call auditCall
		if err := json.Unmarshal([]byte(line), &call); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, call)
	}
	assertImmutableAuditCalls(t, calls)
	return string(out), calls, err
}

func assertImmutableAuditCalls(t *testing.T, calls []auditCall) {
	t.Helper()
	for _, call := range calls {
		if len(call.Args) == 0 {
			t.Fatalf("empty tool call: %+v", call)
		}
		var ref string
		switch {
		case call.Tool == "crane" && call.Args[0] != "version":
			ref = call.Args[len(call.Args)-1]
		case call.Tool == "trivy" && call.Args[0] == "image":
			ref = call.Args[len(call.Args)-1]
		case call.Tool == "cosign" && (call.Args[0] == "verify" || call.Args[0] == "attest" || call.Args[0] == "verify-attestation"):
			ref = call.Args[len(call.Args)-1]
		case call.Tool == "syft" && call.Args[0] != "version":
			for _, arg := range call.Args {
				if strings.HasPrefix(arg, "registry:") {
					ref = strings.TrimPrefix(arg, "registry:")
				}
			}
			if ref == "" {
				t.Fatal("Syft did not use explicit registry source")
			}
		}
		if ref != "" && ref != auditRepo+"@"+auditIndex && ref != auditRepo+"@"+auditAMD && ref != auditRepo+"@"+auditARM {
			t.Fatalf("mutable or unexpected registry reference: %+v", call)
		}
		if (call.Tool == "syft" && call.Args[0] != "version") || (call.Tool == "trivy" && call.Args[0] == "image") {
			if ref == auditRepo+"@"+auditIndex {
				t.Fatal("scanner selected index/host platform instead of explicit child")
			}
		}
	}
}

func auditAttests(calls []auditCall) []auditCall {
	var result []auditCall
	for _, c := range calls {
		if c.Tool == "cosign" && c.Args[0] == "attest" {
			result = append(result, c)
		}
	}
	return result
}

func TestAuditTwoPlatforms(t *testing.T) {
	for _, tagged := range []bool{false, true} {
		t.Run(fmt.Sprintf("tagged=%v", tagged), func(t *testing.T) {
			f := newAuditFixture(t, "success")
			if tagged {
				f.input["releaseTag"] = "v1.2.3"
			}
			out, calls, err := f.run(t, false, nil)
			if err != nil || !strings.Contains(out, "accepted (both platforms") {
				t.Fatalf("successful audit failed: %v, %s; calls: %+v", err, out, calls)
			}
			attests := auditAttests(calls)
			if len(attests) != 3 {
				t.Fatalf("want two child SBOMs and index provenance: %+v", attests)
			}
			scans := map[string]int{}
			for _, c := range calls {
				if c.Tool == "trivy" && c.Args[0] == "image" {
					scans["trivy:"+c.Args[len(c.Args)-1]]++
				}
				if c.Tool == "syft" && c.Args[0] != "version" {
					for _, arg := range c.Args {
						if strings.HasPrefix(arg, "registry:") {
							scans["syft:"+strings.TrimPrefix(arg, "registry:")]++
						}
					}
				}
				if c.Tool == "cosign" && c.Args[0] == "attest" && len(scans) != 4 {
					t.Fatal("attested before all platform scans completed")
				}
			}
			if !reflect.DeepEqual(scans, map[string]int{
				"trivy:" + auditRepo + "@" + auditAMD: 1, "trivy:" + auditRepo + "@" + auditARM: 1,
				"syft:" + auditRepo + "@" + auditAMD: 1, "syft:" + auditRepo + "@" + auditARM: 1,
			}) {
				t.Fatalf("wrong platform scans: %+v", scans)
			}
			for i, digest := range []string{auditAMD, auditARM, auditIndex} {
				if attests[i].Args[len(attests[i].Args)-1] != auditRepo+"@"+digest {
					t.Fatalf("wrong attestation subject: %+v", attests[i])
				}
				if digest != auditIndex {
					b, err := os.ReadFile(auditEvidencePath(f.root, "spdxjson", auditRepo+"@"+digest))
					if err != nil || !strings.Contains(string(b), auditRepo+"@"+digest) {
						t.Fatalf("SBOM was not produced from its own child: %s, %v", b, err)
					}
				}
			}
			var predicate struct {
				BuildDefinition struct {
					BuildType            string
					ResolvedDependencies []struct {
						URI    string
						Digest map[string]string
					}
				}
				RunDetails struct {
					Builder struct {
						ID      string
						Version map[string]string
					}
					Metadata   map[string]any
					Byproducts []struct{ Content string }
				}
			}
			b, err := os.ReadFile(auditEvidencePath(f.root, "slsaprovenance1", auditRepo+"@"+auditIndex))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(b, &predicate); err != nil {
				t.Fatal(err)
			}
			deps := predicate.BuildDefinition.ResolvedDependencies
			if len(deps) != 1 || deps[0].URI != auditRID || deps[0].Digest["gitCommit"] != auditCommit ||
				predicate.RunDetails.Builder.ID != "oci://"+auditBuilder || predicate.RunDetails.Builder.Version["trivy"] != "0.75.0" ||
				!strings.Contains(predicate.BuildDefinition.BuildType, "radicle-bundle") {
				t.Fatalf("untruthful/incomplete provenance: %s", b)
			}
			if predicate.RunDetails.Metadata == nil || len(predicate.RunDetails.Metadata) != 0 {
				t.Fatalf("provenance must explicitly provide empty metadata: %s", b)
			}
			for _, invented := range []string{"startedOn", "finishedOn", "invocationId", "slsaLevel"} {
				if strings.Contains(string(b), invented) {
					t.Fatalf("invented metadata: %s", b)
				}
			}
			if len(predicate.RunDetails.Byproducts) != 1 {
				t.Fatal("missing audit byproduct")
			}
			summary, err := base64.StdEncoding.DecodeString(predicate.RunDetails.Byproducts[0].Content)
			if err != nil || !strings.Contains(string(summary), auditAMD) || !strings.Contains(string(summary), auditARM) {
				t.Fatalf("incomplete platform summary: %q, %v", summary, err)
			}
		})
	}
}

func TestAuditGoPackageEvidence(t *testing.T) {
	for _, scenario := range []string{"success", "main-empty-version", "versioned-packages"} {
		t.Run(scenario, func(t *testing.T) {
			f := newAuditFixture(t, scenario)
			out, calls, err := f.run(t, false, nil)
			if err != nil || !strings.Contains(out, "accepted (both platforms") || len(auditAttests(calls)) != 3 {
				t.Fatalf("valid Go packages/provenance rejected: %v, %s; mock attestations: %d", err, out, len(auditAttests(calls)))
			}
		})
	}
	for _, invalid := range []string{
		"no-stdlib", "no-dependency", "only-main", "missing-binary", "duplicate-binary",
		"unknown-unversioned", "unknown-empty-version", "unversioned-stdlib", "empty-stdlib-version",
		"null-main-version", "numeric-main-version", "numeric-dependency-version", "missing-name", "empty-name", "numeric-name",
	} {
		for _, binary := range []string{"agent", "operator"} {
			scenario := "packages/" + invalid + "/" + binary
			t.Run(scenario, func(t *testing.T) {
				f := newAuditFixture(t, scenario)
				out, calls, err := f.run(t, false, nil)
				if err == nil || !strings.Contains(out, "failed (vulnerabilities)") || len(auditAttests(calls)) != 0 {
					t.Fatalf("incomplete Go evidence accepted or attested: %v, %s, %+v", err, out, calls)
				}
			})
		}
	}
}

func TestAuditFindingsPolicy(t *testing.T) {
	for _, tagged := range []bool{false, true} {
		t.Run(fmt.Sprintf("tagged=%v", tagged), func(t *testing.T) {
			f := newAuditFixture(t, "findings")
			if tagged {
				f.input["releaseTag"] = "v1.2.3"
			}
			out, calls, err := f.run(t, false, nil)
			if tagged {
				if err == nil || len(auditAttests(calls)) != 0 || strings.Contains(out, "warning") {
					t.Fatalf("tag findings must fail without any new attestations: %v, %s, %+v", err, out, calls)
				}
			} else if err != nil || strings.Count(out, "warning") != 2 || !strings.Contains(out, "HIGH=1, CRITICAL=1") || len(auditAttests(calls)) != 3 {
				t.Fatalf("main findings should warn with bounded counts: %v, %s", err, out)
			}
		})
	}
}

func TestAuditRejectsIncompleteOrUntrustedEvidence(t *testing.T) {
	for _, scenario := range []string{
		"missing-platform", "duplicate-platform", "duplicate-digest", "extra-platform", "bad-index", "index-urls", "unsupported-descriptor", "foreign-artifact-type",
		"config-mismatch", "layer-urls", "nested-index", "signature-error", "signature-mismatch", "signature-empty",
		"malformed-spdx", "empty-spdx", "missing-spdx", "invalid-spdx",
		"scan-error", "second-scan-error", "scan-timeout", "malformed-trivy", "empty-trivy", "missing-trivy", "missing-binary",
		"nested-binary", "empty-packages", "wrong-binary-type", "scan-reported-error", "invalid-vulnerability", "boolean-vulnerabilities", "boolean-errors", "findings-exit-zero", "clean-exit-42",
	} {
		t.Run(scenario, func(t *testing.T) {
			f := newAuditFixture(t, scenario)
			out, calls, err := f.run(t, false, nil)
			if err == nil || !strings.Contains(out, "publication is not accepted") || len(auditAttests(calls)) != 0 {
				t.Fatalf("bad evidence accepted or attested: %v, %s, %+v", err, out, calls)
			}
		})
	}
}

func TestAuditAttestationFailures(t *testing.T) {
	for _, scenario := range []string{"attest-error", "verify-error", "attestation-subject", "attestation-predicate", "attestation-type", "attestation-empty", "attestation-base64", "late-failure", "index-predicate"} {
		for _, tagged := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tagged=%v", scenario, tagged), func(t *testing.T) {
				f := newAuditFixture(t, scenario)
				if tagged {
					f.input["releaseTag"] = "v1.2.3"
				}
				out, calls, err := f.run(t, false, nil)
				if err == nil || !strings.Contains(out, "publication is not accepted") {
					t.Fatalf("attestation failure accepted: %v, %s", err, out)
				}
				if (scenario == "late-failure" || scenario == "index-predicate") && len(auditAttests(calls)) != 3 {
					t.Fatalf("expected failure after publication of all attestations: %+v", calls)
				}
				for _, c := range calls {
					if c.Tool == "crane" && c.Args[0] != "version" && c.Args[0] != "manifest" && c.Args[0] != "config" {
						t.Fatal("audit attempted registry cleanup/overwrite")
					}
				}
			})
		}
	}
}

func TestAuditResultContract(t *testing.T) {
	valid := string(auditJSON(newAuditFixture(t, "success").input))
	cases := []struct {
		name   string
		mutate func(*auditFixture)
		raw    []byte
	}{
		{name: "malformed", raw: []byte("{\"" + auditSecret)},
		{name: "empty", raw: []byte("{}")},
		{name: "multiple", raw: []byte("{} {}")},
		{name: "multiple-valid", raw: []byte(valid + "\n" + valid)},
		{name: "trailing-malformed", raw: []byte(valid + "\n{")},
		{name: "duplicate-key", raw: []byte(fmt.Sprintf(`{"schemaVersion":1,"schemaVersion":1,"commit":%q,"releaseTag":"","images":[{"repository":%q,"digest":%q}]}`, auditCommit, auditRepo, auditIndex))},
		{name: "public-file", mutate: func(f *auditFixture) {
			writeAuditFile(t, f.result, []byte("{}"), 0600)
			if err := os.Chmod(f.result, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unknown-field", mutate: func(f *auditFixture) { f.input["password"] = auditSecret }},
		{name: "schema", mutate: func(f *auditFixture) { f.input["schemaVersion"] = 2 }},
		{name: "short-commit", mutate: func(f *auditFixture) { f.input["commit"] = "ddddddd" }},
		{name: "wrong-commit", mutate: func(f *auditFixture) { f.input["commit"] = strings.Repeat("f", 40) }},
		{name: "bad-tag", mutate: func(f *auditFixture) { f.input["releaseTag"] = "v1.2.3-rc1" }},
		{name: "missing-tag", mutate: func(f *auditFixture) { delete(f.input, "releaseTag") }},
		{name: "empty-images", mutate: func(f *auditFixture) { f.input["images"] = []any{} }},
		{name: "two-images", mutate: func(f *auditFixture) {
			f.input["images"] = append(f.input["images"].([]any), f.input["images"].([]any)[0])
		}},
		{name: "unknown-image-field", mutate: func(f *auditFixture) { f.input["images"].([]any)[0].(map[string]any)["extra"] = 1 }},
		{name: "repo-mismatch", mutate: func(f *auditFixture) {
			f.input["images"].([]any)[0].(map[string]any)["repository"] = "registry.invalid/unrelated"
		}},
		{name: "credentials-ref", mutate: func(f *auditFixture) {
			f.input["images"].([]any)[0].(map[string]any)["repository"] = "user:" + auditSecret + "@registry.invalid/tailnet/operator"
		}},
		{name: "mutable", mutate: func(f *auditFixture) { f.input["images"].([]any)[0].(map[string]any)["digest"] = "latest" }},
		{name: "short-digest", mutate: func(f *auditFixture) { f.input["images"].([]any)[0].(map[string]any)["digest"] = "sha256:aaa" }},
		{name: "registry-env", mutate: func(f *auditFixture) { f.setenv("REGISTRY", "https://user:"+auditSecret+"@registry.invalid") }},
		{name: "builder-tag", mutate: func(f *auditFixture) { f.setenv("CI_BUILDER_IMAGE", "registry.invalid/broker:latest") }},
		{name: "builder-credentials", mutate: func(f *auditFixture) { f.setenv("CI_BUILDER_IMAGE", "user:"+auditSecret+"@"+auditBuilder) }},
		{name: "missing-key", mutate: func(f *auditFixture) { f.setenv("COSIGN_KEY", filepath.Join(f.root, "missing")) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuditFixture(t, "success")
			if tc.mutate != nil {
				tc.mutate(f)
			}
			out, calls, err := f.run(t, false, tc.raw)
			if err == nil || !strings.Contains(out, "publication is not accepted") {
				t.Fatalf("bad contract accepted: %v, %s", err, out)
			}
			for _, c := range calls {
				if (c.Tool == "crane" && c.Args[0] != "version") || len(auditAttests([]auditCall{c})) > 0 {
					t.Fatalf("registry used before contract validation: %+v", c)
				}
			}
		})
	}
}

func TestAuditFixtureDoesNotInheritHostEnvironment(t *testing.T) {
	poison := filepath.Join(t.TempDir(), "bash-env")
	writeAuditFile(t, poison, []byte("exit 93\n"), 0600)
	t.Setenv("BASH_ENV", poison)
	t.Setenv("UNRELATED_CREDENTIAL", auditSecret)
	f := newAuditFixture(t, "success")
	if out, _, err := f.run(t, true, nil); err != nil {
		t.Fatalf("host environment contaminated mock tools: %v, %s", err, out)
	}
}

func TestAuditPreflightAndAmbientConfiguration(t *testing.T) {
	for _, scenario := range []string{"success", "wrong-syft-version", "wrong-trivy-version", "wrong-cosign-version", "bad-key"} {
		t.Run(scenario, func(t *testing.T) {
			f := newAuditFixture(t, scenario)
			out, calls, err := f.run(t, true, nil)
			if (err == nil) != (scenario == "success") {
				t.Fatalf("preflight result: %v, %s", err, out)
			}
			for _, c := range calls {
				if c.Args[0] != "version" && !(c.Tool == "cosign" && c.Args[0] == "public-key") {
					t.Fatalf("preflight performed a registry/Git/scan operation: %+v", c)
				}
			}
		})
	}
	f := newAuditFixture(t, "ambient")
	for _, name := range []string{"SYFT_CONFIG", "SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY", "TRIVY_SKIP_DB_UPDATE", "TRIVY_SKIP_FILES", "TRIVY_INSECURE", "TRIVY_CONFIG", "COSIGN_REPOSITORY", "SIGSTORE_ROOT_FILE"} {
		f.setenv(name, auditSecret)
	}
	// An ambient ignore/config file must not even be discovered through the cwd.
	writeAuditFile(t, filepath.Join(f.root, "trivy.yaml"), []byte("skip-files: ['**']\n"), 0600)
	writeAuditFile(t, filepath.Join(f.root, ".trivyignore"), []byte("*\n"), 0600)
	out, _, err := f.run(t, false, nil)
	if err != nil {
		t.Fatalf("ambient settings were not isolated: %v, %s", err, out)
	}
}

// TestAuditToolProcess is entered only through the mock executable shims.
func TestAuditToolProcess(t *testing.T) {
	if os.Getenv("AUDIT_MOCK") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Exit(auditMockTool(strings.TrimSuffix(filepath.Base(os.Args[i+1]), "-legacy"), os.Args[i+2:]))
		}
	}
	os.Exit(99)
}

func auditArg(args []string, name string) string {
	for i, arg := range args {
		if arg == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func auditHas(args []string, value string) bool {
	for _, arg := range args {
		if arg == value {
			return true
		}
	}
	return false
}

func auditJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func auditEmit(v any) int {
	fmt.Println(string(auditJSON(v)))
	return 0
}

func auditEvidencePath(root, kind, ref string) string {
	_, digest, _ := strings.Cut(ref, "@sha256:")
	return filepath.Join(root, "evidence", kind+"-"+digest+".json")
}

func auditMockTool(tool string, args []string) int {
	root, scenario := os.Getenv("AUDIT_FIXTURE"), os.Getenv("AUDIT_SCENARIO")
	// Every external tool deliberately emits sensitive-looking errors. Even on a
	// successful command these must remain private and be deleted after the run.
	fmt.Fprintln(os.Stderr, auditSecret+" raw registry/scanner/signer diagnostic")
	log, err := os.OpenFile(filepath.Join(root, "calls.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return 98
	}
	_ = json.NewEncoder(log).Encode(auditCall{Tool: tool, Args: args, Temp: os.Getenv("TMPDIR")})
	_ = log.Close()
	if len(args) == 0 || os.Getenv("COSIGN_PASSWORD") != auditSecret || os.Getenv("UNRELATED_CREDENTIAL") != "" {
		return 97
	}
	for _, name := range []string{"SYFT_CONFIG", "SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY", "TRIVY_SKIP_DB_UPDATE", "TRIVY_SKIP_FILES", "TRIVY_INSECURE", "TRIVY_CONFIG", "COSIGN_REPOSITORY", "SIGSTORE_ROOT_FILE"} {
		if os.Getenv(name) != "" {
			return 96
		}
	}
	// All private directories and scanner/signer files are owner-only.
	for _, dir := range []string{os.Getenv("TMPDIR"), os.Getenv("HOME"), os.Getenv("XDG_CACHE_HOME")} {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || !strings.HasPrefix(dir, filepath.Join(root, "tmp")+"/") {
			return 95
		}
	}
	if tool == "git" {
		if !reflect.DeepEqual(args, []string{"rev-parse", "--verify", "HEAD"}) {
			return 94
		}
		fmt.Println(auditCommit)
		return 0
	}
	if args[0] == "version" {
		switch tool {
		case "syft":
			version := "1.54.1"
			if scenario == "wrong-syft-version" {
				version = "1.1.0"
			}
			return auditEmit(map[string]string{"version": version})
		case "trivy":
			version := "0.75.0"
			if scenario == "wrong-trivy-version" {
				version = "0.1.0"
			}
			return auditEmit(map[string]string{"Version": version})
		case "cosign":
			version := "v2.5.0"
			if scenario == "wrong-cosign-version" {
				version = "v3.0.0"
			}
			return auditEmit(map[string]string{"gitVersion": version})
		case "crane":
			fmt.Println("v0.20.3")
			return 0
		}
	}
	ref := args[len(args)-1]
	digest := auditAMD
	arch := "amd64"
	if strings.HasSuffix(ref, auditARM) {
		digest, arch = auditARM, "arm64"
	} else if strings.HasSuffix(ref, auditIndex) {
		digest = auditIndex
	}
	switch tool {
	case "crane":
		if len(args) != 2 {
			return 93
		}
		if args[0] == "config" {
			if scenario == "config-mismatch" {
				arch = "386"
			}
			return auditEmit(map[string]string{"architecture": arch, "os": "linux"})
		}
		if args[0] != "manifest" {
			return 92
		}
		if digest == auditIndex {
			// Broker v1.4.1 (crane 0.22 / buildah) writes artifactType and empty base annotations
			// into every descriptor; the audit must accept exactly that shape and nothing wider.
			base := map[string]string{"org.opencontainers.image.base.digest": "", "org.opencontainers.image.base.name": ""}
			amd := map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 123, "digest": auditAMD, "platform": map[string]string{"os": "linux", "architecture": "amd64"}, "artifactType": "application/vnd.oci.image.config.v1+json", "annotations": base}
			arm := map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 123, "digest": auditARM, "platform": map[string]string{"os": "linux", "architecture": "arm64", "variant": "v8"}}
			manifests := []any{amd, arm}
			switch scenario {
			case "foreign-artifact-type":
				amd["artifactType"] = "application/vnd.example.sbom+json"
			case "missing-platform":
				manifests = manifests[:1]
			case "duplicate-platform":
				arm["platform"] = amd["platform"]
			case "duplicate-digest":
				arm["digest"] = auditAMD
			case "extra-platform":
				manifests = append(manifests, amd)
			case "index-urls":
				amd["urls"] = []string{"https://" + auditSecret + "@example.invalid/layer"}
			case "unsupported-descriptor":
				amd["mediaType"] = "application/vnd.oci.image.index.v1+json"
			case "bad-index":
				fmt.Println("not json " + auditSecret)
				return 0
			}
			return auditEmit(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": manifests})
		}
		layer := map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "size": 999, "digest": "sha256:" + strings.Repeat("f", 64)}
		if scenario == "layer-urls" {
			layer["urls"] = []string{"https://example.invalid/layer"}
		}
		mediaType := "application/vnd.oci.image.manifest.v1+json"
		if scenario == "nested-index" {
			mediaType = "application/vnd.oci.image.index.v1+json"
		}
		return auditEmit(map[string]any{"schemaVersion": 2, "mediaType": mediaType,
			"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "size": 99, "digest": auditIndex}, "layers": []any{layer}})
	case "syft":
		source := ""
		for _, arg := range args {
			if strings.HasPrefix(arg, "registry:") {
				source = strings.TrimPrefix(arg, "registry:")
			}
		}
		if strings.HasSuffix(source, auditARM) {
			arch = "arm64"
		}
		if auditArg(args, "--platform") != "linux/"+arch {
			return 91
		}
		if auditArg(args, "--scope") != "squashed" || !strings.HasPrefix(auditArg(args, "--platform"), "linux/") || os.Getenv("SYFT_CHECK_FOR_APP_UPDATE") != "false" {
			return 91
		}
		if b, err := os.ReadFile(auditArg(args, "--config")); err != nil || strings.TrimSpace(string(b)) != "{}" {
			return 90
		}
		path := strings.TrimPrefix(auditArg(args, "--output"), "spdx-json=")
		if scenario == "missing-spdx" {
			return 0
		}
		sbom := map[string]any{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "dataLicense": "CC0-1.0", "name": "test image " + source,
			"documentNamespace": "https://example.invalid/sbom/123", "creationInfo": map[string]any{"created": "2026-01-01T00:00:00Z", "creators": []string{"Tool: syft-1.54.1"}},
			"packages": []any{map[string]string{"SPDXID": "SPDXRef-tailnet-agent", "name": "tailnet-agent"}}}
		if scenario == "empty-spdx" {
			sbom["packages"] = []any{}
		} else if scenario == "invalid-spdx" {
			delete(sbom, "SPDXID")
		}
		b := auditJSON(sbom)
		if scenario == "malformed-spdx" {
			b = []byte(auditSecret + " invalid JSON")
		}
		if err := os.WriteFile(path, b, 0600); err != nil {
			return 89
		}
		return 0
	case "trivy":
		if args[0] != "image" || auditArg(args, "--image-src") != "remote" || auditArg(args, "--scanners") != "vuln" ||
			auditArg(args, "--severity") != "HIGH,CRITICAL" || auditArg(args, "--exit-code") != "42" || auditArg(args, "--format") != "json" ||
			!auditHas(args, "--disable-telemetry") || !auditHas(args, "--list-all-pkgs") || !auditHas(args, "--skip-db-update=false") || !auditHas(args, "--skip-java-db-update=false") ||
			!auditHas(args, "--offline-scan=false") || !auditHas(args, "--ignore-unfixed=false") || !auditHas(args, "--insecure=false") ||
			os.Getenv("TRIVY_SKIP_VERSION_CHECK") != "true" {
			return 88
		}
		cwd, _ := os.Getwd()
		if !strings.HasPrefix(cwd, filepath.Join(root, "tmp")+"/") || !strings.HasPrefix(auditArg(args, "--cache-dir"), cwd+"/") {
			return 87
		}
		if b, err := os.ReadFile(auditArg(args, "--config")); err != nil || strings.TrimSpace(string(b)) != "{}" {
			return 86
		}
		if b, err := os.ReadFile(auditArg(args, "--ignorefile")); err != nil || len(b) != 0 {
			return 85
		}
		if scenario == "scan-error" || (scenario == "second-scan-error" && arch == "arm64") {
			return 1
		}
		if scenario == "scan-timeout" {
			return 124
		}
		if scenario == "missing-trivy" {
			return 0
		}
		packages := func() []any {
			main := map[string]any{"Name": "tsunaro.io/tailnet-operator"}
			if scenario == "main-empty-version" {
				main["Version"] = ""
			} else if scenario == "versioned-packages" {
				main["Version"] = "v0.0.0"
			}
			return []any{
				map[string]any{"Name": "stdlib", "Version": "1.26.7"},
				main,
				map[string]any{"Name": "tailscale.com", "Version": "v1.94.1"},
			}
		}
		agent := map[string]any{"Target": "tailnet-agent", "Class": "lang-pkgs", "Type": "gobinary", "Packages": packages()}
		operator := map[string]any{"Target": "/tailnet-operator", "Class": "lang-pkgs", "Type": "gobinary", "Packages": packages()}
		results := []any{agent, operator}
		if parts := strings.Split(scenario, "/"); len(parts) == 3 && parts[0] == "packages" {
			binary := agent
			if parts[2] == "operator" {
				binary = operator
			}
			pkgs := binary["Packages"].([]any)
			stdlib, main, dependency := pkgs[0].(map[string]any), pkgs[1].(map[string]any), pkgs[2].(map[string]any)
			switch parts[1] {
			case "no-stdlib":
				pkgs = pkgs[1:]
			case "no-dependency":
				pkgs = pkgs[:2]
			case "only-main":
				pkgs = pkgs[1:2]
			case "missing-binary":
				binary["Target"] = "/unrelated"
			case "duplicate-binary":
				results = append(results, binary)
			case "unknown-unversioned":
				delete(dependency, "Version")
			case "unknown-empty-version":
				dependency["Version"] = ""
			case "unversioned-stdlib":
				delete(stdlib, "Version")
			case "empty-stdlib-version":
				stdlib["Version"] = ""
			case "null-main-version":
				main["Version"] = nil
			case "numeric-main-version":
				main["Version"] = 123
			case "numeric-dependency-version":
				dependency["Version"] = 123
			case "missing-name":
				delete(main, "Name")
			case "empty-name":
				main["Name"] = ""
			case "numeric-name":
				main["Name"] = 123
			}
			binary["Packages"] = pkgs
		}
		code := 0
		switch scenario {
		case "empty-trivy":
			results = []any{}
		case "missing-binary":
			results = results[:1]
		case "nested-binary":
			operator["Target"] = "/unrelated/tailnet-operator"
		case "empty-packages":
			operator["Packages"] = []any{}
		case "wrong-binary-type":
			operator["Type"] = "gomod"
		case "scan-reported-error":
			operator["Errors"] = []string{auditSecret}
		case "boolean-errors":
			operator["Errors"] = false
		case "boolean-vulnerabilities":
			operator["Vulnerabilities"] = false
		case "findings", "findings-exit-zero", "invalid-vulnerability":
			agent["Vulnerabilities"] = []any{
				map[string]string{"VulnerabilityID": auditSecret + "-CVE-1", "PkgName": "stdlib", "Severity": "HIGH"},
				map[string]string{"VulnerabilityID": auditSecret + "-CVE-2", "PkgName": "stdlib", "Severity": "CRITICAL"},
			}
			code = 42
			if scenario == "findings-exit-zero" {
				code = 0
			} else if scenario == "invalid-vulnerability" {
				agent["Vulnerabilities"] = []any{map[string]string{"Severity": "HIGH"}}
			}
		case "clean-exit-42":
			code = 42
		}
		b := auditJSON(map[string]any{"SchemaVersion": 2, "ArtifactName": ref, "ArtifactType": "container_image", "Results": results})
		if scenario == "malformed-trivy" {
			b = []byte(auditSecret)
		}
		if err := os.WriteFile(auditArg(args, "--output"), b, 0600); err != nil {
			return 84
		}
		return code
	case "cosign":
		if args[0] == "public-key" {
			if scenario == "bad-key" {
				return 1
			}
			fmt.Println("SYNTHETIC PUBLIC KEY")
			return 0
		}
		if args[0] == "verify" || args[0] == "verify-attestation" {
			b, err := os.ReadFile(auditArg(args, "--key"))
			// Transparency-log evidence is part of the audit: no flag may skip it.
			if err != nil || string(b) != "SYNTHETIC PUBLIC KEY\n" || auditHas(args, "--insecure-ignore-tlog=true") || auditHas(args, "--insecure-ignore-tlog") {
				return 83
			}
		}
		if args[0] == "verify" {
			if scenario == "signature-error" {
				return 1
			}
			if scenario == "signature-empty" {
				return auditEmit([]any{})
			}
			if scenario == "signature-mismatch" {
				digest = auditARM
			}
			return auditEmit([]any{map[string]any{"critical": map[string]any{"identity": map[string]string{"docker-reference": auditRepo}, "image": map[string]string{"docker-manifest-digest": digest}}}})
		}
		kind := auditArg(args, "--type")
		if kind != "spdxjson" && kind != "slsaprovenance1" {
			return 82
		}
		if args[0] == "attest" {
			if !auditHas(args, "--yes") || auditHas(args, "--tlog-upload=false") || auditArg(args, "--key") != filepath.Join(root, "synthetic.key") {
				return 81
			}
			if scenario == "attest-error" && digest == auditARM {
				return 1
			}
			path := auditArg(args, "--predicate")
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm()&0077 != 0 {
				return 80
			}
			b, err := os.ReadFile(path)
			if err != nil || !json.Valid(b) {
				return 79
			}
			if err := os.WriteFile(auditEvidencePath(root, kind, ref), b, 0600); err != nil {
				return 78
			}
			return 0
		}
		if args[0] != "verify-attestation" {
			return 77
		}
		if scenario == "verify-error" || (scenario == "late-failure" && digest == auditIndex) {
			return 1
		}
		if scenario == "attestation-empty" {
			return auditEmit([]any{})
		}
		b, err := os.ReadFile(auditEvidencePath(root, kind, ref))
		if err != nil {
			return 76
		}
		predicateType := "https://spdx.dev/Document"
		if kind == "slsaprovenance1" {
			predicateType = "https://slsa.dev/provenance/v1"
			// Cosign v2.5.0 GenerateStatement round-trips through the SLSA
			// struct, whose runDetails.metadata serializes as {} when omitted.
			// Normalize before deliberate mismatches, not the saved input.
			var predicate map[string]any
			if err := json.Unmarshal(b, &predicate); err != nil {
				return 76
			}
			runDetails := predicate["runDetails"].(map[string]any)
			if runDetails["metadata"] == nil {
				runDetails["metadata"] = map[string]any{}
			}
			b = auditJSON(predicate)
		}
		if scenario == "attestation-type" {
			predicateType = "https://invalid.example/predicate"
		}
		if scenario == "attestation-subject" {
			digest = auditIndex
		}
		if scenario == "attestation-predicate" || (scenario == "index-predicate" && digest == auditIndex) {
			b = []byte(`{"different":true}`)
		}
		payload := base64.StdEncoding.EncodeToString(auditJSON(map[string]any{
			"_type": "https://in-toto.io/Statement/v0.1", "predicateType": predicateType,
			"subject":   []any{map[string]any{"name": auditRepo, "digest": map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")}}},
			"predicate": json.RawMessage(b),
		}))
		if scenario == "attestation-base64" {
			payload = "not base64!!"
		}
		return auditEmit(map[string]string{"payloadType": "application/vnd.in-toto+json", "payload": payload})
	}
	return 75 // An unrecognized operation must never escape to a real tool.
}
