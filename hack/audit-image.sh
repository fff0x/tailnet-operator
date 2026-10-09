#!/usr/bin/env bash
# Post-publication acceptance gate. Failure never removes already-published artifacts.
# This hand-built evidence is not a claim of SLSA level or reproducible builds.
set +x
set -Eeuo pipefail
umask 077
exec 3>&2
stage=preflight
work=
fail() {
  printf 'image audit: failed (%s); publication is not accepted\n' "$stage" >&3
  # Bounded diagnostic on failure: trivy/cosign/jq errors are the only unknown. Keep it
  # to a few lines so no CVE/package/signer identifiers reach CI; the full private.log
  # is still discarded on cleanup. No-op on preflight (private.log not yet opened).
  if [[ -n "${work:-}" && -s "$work/private.log" ]]; then
    tail -n 20 "$work/private.log" 2>/dev/null \
      | grep -E 'error|Error|FATAL|FAILED|cannot|refused|timeout|unauthorized|exit (status )?[1-9]' \
      | head -n 5 >&3 || true
  fi
  exit 1
}
cleanup() { [[ -z "$work" ]] || rm -rf -- "$work" >/dev/null 2>&1; }
trap cleanup EXIT
trap fail ERR
trap 'stage=interrupted; fail' HUP INT TERM

# No command output, reference, credential or scanner diagnostic reaches CI logs.
# All external operations, including local key derivation, have a hard deadline.
run() { timeout --kill-after=10s 12m "$@"; }
for tool in bash jq git crane syft trivy cosign-legacy timeout mktemp mkdir cp mv rm stat realpath; do
  command -v "$tool" >/dev/null 2>&1 || fail
done
if ! work=$(mktemp -d "${TMPDIR:-/tmp}/audit-image.XXXXXXXX" 2>/dev/null); then fail; fi
exec >"$work/private.log" 2>&1

mode=
result=
case "$#:${1:-}" in
  1:--check-tools) mode=check ;;
  2:--result) mode=audit; result=$2 ;;
  *) fail ;;
esac
# Restrictive OCI repository grammar: no schemes, userinfo, tags, query or fragments.
host='[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]+)?'
component='[a-z0-9]+([._-][a-z0-9]+)*'
repository="${host}(/${component})+"
[[ ${REGISTRY:-} =~ ^${host}(/${component})*$ ]] || fail
[[ ${CI_BUILDER_IMAGE:-} =~ ^${repository}@sha256:[a-f0-9]{64}$ ]] || fail
[[ -n ${COSIGN_KEY:-} && -f $COSIGN_KEY && -r $COSIGN_KEY ]] || fail
[[ ${COSIGN_PASSWORD+x} ]] || fail
COSIGN_KEY=$(realpath -e -- "$COSIGN_KEY")
expected="${REGISTRY}/tailnet/operator"

# Discard all ambient scanner/signer switches, including skip/insecure settings
# and COSIGN_REPOSITORY. Registry authentication still uses the Docker keychain.
for var in ${!SYFT_@} ${!TRIVY_@} ${!COSIGN_@} ${!SIGSTORE_@}; do
  case "$var" in COSIGN_KEY|COSIGN_PASSWORD) ;; *) unset "$var" ;; esac
done
export COSIGN_PASSWORD
export DOCKER_CONFIG
DOCKER_CONFIG=$(realpath -m -- "${DOCKER_CONFIG:-${HOME:-/nonexistent}/.docker}")
mkdir -p "$work/home" "$work/config" "$work/cache" "$work/data" "$work/state" "$work/tmp"
export HOME="$work/home" XDG_CONFIG_HOME="$work/config" XDG_CACHE_HOME="$work/cache" TMPDIR="$work/tmp"
export XDG_DATA_HOME="$work/data" XDG_STATE_HOME="$work/state"
export SYFT_CHECK_FOR_APP_UPDATE=false TRIVY_SKIP_VERSION_CHECK=true
printf '{}\n' >"$work/syft.yaml"
printf '{}\n' >"$work/trivy.yaml"
: >"$work/empty.ignore"

run syft version -o json >"$work/syft-version.json"
run trivy version --format json >"$work/trivy-version.json"
# The broker ships cosign v3 (OCI referrers bundles) beside cosign-legacy v2.5.0 and dual-signs
# with both; zot and Kyverno read only the legacy tag form, so this audit stays on that binary.
run cosign-legacy version --json >"$work/cosign-version.json"
run crane version >"$work/crane-version"
jq -e '.version == "1.54.1"' "$work/syft-version.json" >/dev/null
jq -e '.Version == "0.75.0"' "$work/trivy-version.json" >/dev/null
jq -e '.gitVersion == "v2.5.0"' "$work/cosign-version.json" >/dev/null
crane_version=$(<"$work/crane-version")
[[ $crane_version =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail
# Local, fixed key only. No ambient keyless identity or trust-on-first-use.
run cosign-legacy public-key --key "$COSIGN_KEY" >"$work/broker.pub"
[[ -s "$work/broker.pub" ]] || fail
if [[ $mode == check ]]; then
  printf 'image audit: tools and configuration checked (no registry operations)\n' >&3
  exit 0
fi

stage=result
[[ -f $result && -r $result && -O $result && ! -L $result ]] || fail
permissions=$(stat -c %a -- "$result")
[[ $permissions =~ ^[0-7]{3,4}$ ]] || fail
(( (8#$permissions & 077) == 0 )) || fail
cp -- "$result" "$work/result.json"
result="$work/result.json"
# Reject duplicate keys before jq collapses them. Separate streaming and slurping:
# jq 1.6 (Debian TEST) can emit an extra empty result when both flags are combined.
jq -c --stream 'select(length == 2) | .[0]' "$result" |
  jq -e -s 'sort ==
    [["commit"],["images",0,"digest"],["images",0,"repository"],["releaseTag"],["schemaVersion"]]
  ' >/dev/null
# Slurping also rejects concatenated JSON documents. Exact key sets are intentional.
jq -e -s --arg repo "$expected" '
  length == 1 and (.[0] |
    type == "object" and keys == ["commit","images","releaseTag","schemaVersion"] and
    .schemaVersion == 1 and
    (.commit | type == "string" and test("^([a-f0-9]{40}|[a-f0-9]{64})$")) and
    (.releaseTag | type == "string" and test("^(|v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*))$")) and
    (.images | type == "array" and length == 1 and (.[0] |
      type == "object" and keys == ["digest","repository"] and .repository == $repo and
      (.digest | type == "string" and test("^sha256:[a-f0-9]{64}$")))))
' "$result" >/dev/null
commit=$(jq -r .commit "$result")
release=$(jq -r .releaseTag "$result")
index=$(jq -r '.images[0].digest' "$result")
head=$(run git rev-parse --verify HEAD)
[[ $head == "$commit" ]] || fail
# Never let repository-local scanner configuration or ignore files affect the gate.
cd "$work"
ref="$expected@$index"

stage=index
run crane manifest "$ref" >index.json
jq -e -s '
  def digest: type == "string" and test("^sha256:[a-f0-9]{64}$");
  length == 1 and (.[0] | .schemaVersion == 2 and
    (.mediaType == "application/vnd.oci.image.index.v1+json" or
     .mediaType == "application/vnd.docker.distribution.manifest.list.v2+json") and
    (.manifests | type == "array" and length == 2 and
      all(.[];
        (keys - ["mediaType","digest","size","platform","annotations"] | length == 0) and
        (.mediaType == "application/vnd.oci.image.manifest.v1+json" or
         .mediaType == "application/vnd.docker.distribution.manifest.v2+json") and
        (.digest | digest) and (.size | type == "number" and . > 0 and floor == .) and
        (.platform | type == "object" and
          (keys - ["os","architecture","variant"] | length == 0) and .os == "linux" and
          (.architecture == "amd64" or .architecture == "arm64") and
          ((.variant // "") == "" or (.architecture == "arm64" and .variant == "v8")))) and
      ([.[].platform.architecture] | sort == ["amd64","arm64"]) and
      ([.[].digest] | unique | length == 2)))
' index.json >/dev/null

stage=signature
# The publisher signs the index; its descriptors bind both child digests. Fixed-key
# verification intentionally does not claim public Rekor transparency-log evidence.
run cosign-legacy verify --key "$work/broker.pub" --insecure-ignore-tlog=true "$ref" >signature.json
jq -e -s --arg digest "$index" --arg repo "$expected" '
  [ .[] | if type == "array" then .[] else . end ] |
  any(.[]; .critical.image["docker-manifest-digest"] == $digest and
    .critical.identity["docker-reference"] == $repo)
' signature.json >/dev/null

printf '[]\n' >summaries.json
for arch in amd64 arm64; do
  stage=platform
  child=$(jq -r --arg arch "$arch" '.manifests[] | select(.platform.architecture == $arch) | .digest' index.json)
  child_ref="$expected@$child"
  run crane manifest "$child_ref" >"$arch-manifest.json"
  # Reject foreign/nondistributable layers, embedded data and remote URL descriptors.
  jq -e -s '
    def descriptor: type == "object" and
      (keys - ["mediaType","digest","size","annotations"] | length == 0) and
      (.digest | type == "string" and test("^sha256:[a-f0-9]{64}$")) and
      (.size | type == "number" and . > 0 and floor == .);
    length == 1 and (.[0] | .schemaVersion == 2 and
      (.mediaType == "application/vnd.oci.image.manifest.v1+json" or
       .mediaType == "application/vnd.docker.distribution.manifest.v2+json") and
      (.config | descriptor and
        (.mediaType == "application/vnd.oci.image.config.v1+json" or
         .mediaType == "application/vnd.docker.container.image.v1+json")) and
      (.layers | type == "array" and length > 0 and all(.[]; descriptor and
        (.mediaType == "application/vnd.oci.image.layer.v1.tar" or
         .mediaType == "application/vnd.oci.image.layer.v1.tar+gzip" or
         .mediaType == "application/vnd.oci.image.layer.v1.tar+zstd" or
         .mediaType == "application/vnd.docker.image.rootfs.diff.tar.gzip"))))
  ' "$arch-manifest.json" >/dev/null
  run crane config "$child_ref" >"$arch-config.json"
  jq -e -s --arg arch "$arch" 'length == 1 and (.[0] | .os == "linux" and .architecture == $arch)' "$arch-config.json" >/dev/null

  stage=sbom
  run syft --config "$work/syft.yaml" "registry:$child_ref" --scope squashed \
    --platform "linux/$arch" --output "spdx-json=$work/$arch-spdx.json"
  jq -e -s '
    def text: type == "string" and length > 0;
    length == 1 and (.[0] | type == "object" and
      (.spdxVersion == "SPDX-2.2" or .spdxVersion == "SPDX-2.3") and
      .SPDXID == "SPDXRef-DOCUMENT" and .dataLicense == "CC0-1.0" and (.name | text) and
      (.documentNamespace | text and test("^[A-Za-z][A-Za-z0-9+.-]*:")) and
      (.creationInfo | type == "object" and (.created | text) and
        (.creators | type == "array" and length > 0 and all(.[]; text))) and
      (.packages | type == "array" and length > 0 and all(.[];
        type == "object" and (.SPDXID | text and startswith("SPDXRef-")) and (.name | text))))
  ' "$arch-spdx.json" >/dev/null

  stage=vulnerabilities
  scan_status=0
  # Fresh per-run DB cache; DB updates enabled, telemetry/version phone-home disabled. No
  # Docker/containerd fallback, ignored unfixed findings, user ignorefile or config.
  run trivy image --config "$work/trivy.yaml" --cache-dir "$work/cache/trivy" \
    --image-src remote --scanners vuln --severity HIGH,CRITICAL --format json \
    --output "$work/$arch-trivy.json" --exit-code 42 --timeout 10m \
    --skip-db-update=false --skip-java-db-update=false --offline-scan=false \
    --ignore-unfixed=false --ignorefile "$work/empty.ignore" --insecure=false \
    --disable-telemetry --list-all-pkgs "$child_ref" || scan_status=$?
  [[ $scan_status == 0 || $scan_status == 42 ]] || fail
  jq -e -s --arg ref "$child_ref" '
    def text: type == "string" and length > 0;
    def noerrors: .Errors == null or .Errors == [];
    length == 1 and (.[0] | type == "object" and .SchemaVersion == 2 and
      .ArtifactName == $ref and .ArtifactType == "container_image" and noerrors and
      (.Results | type == "array" and length > 0 and
        all(.[]; type == "object" and (.Target | text) and noerrors and
          (.Vulnerabilities | . == null or (type == "array" and all(.[];
            type == "object" and (.VulnerabilityID | text) and (.PkgName | text) and
            (.Severity == "HIGH" or .Severity == "CRITICAL")))))))
  ' "$arch-trivy.json" >/dev/null
  # Trivy sometimes omits the leading slash. Only the two root executables count;
  # unrelated packages or a nested binary with the same basename do not suffice.
  # Source builds can omit the main module version, but stdlib and dependency
  # versions must still be present for each executable.
  jq -e '
    def text: type == "string" and length > 0;
    def main: .Name == "tsunaro.io/tailnet-operator";
    .Results as $results | all("tailnet-agent", "tailnet-operator"; . as $binary |
      [$results[] | select(.Class == "lang-pkgs" and .Type == "gobinary" and
        (.Target | ltrimstr("/")) == $binary)] |
      length == 1 and (.[0].Packages | type == "array" and length > 0 and
        all(.[]; type == "object" and (.Name | text) and
          ((.Version | text) or (main and (has("Version") | not)) or (main and .Version == ""))) and
        any(.[]; .Name == "stdlib" and (.Version | text)) and
        any(.[]; (main | not) and .Name != "stdlib" and (.Version | text))))
  ' "$arch-trivy.json" >/dev/null
  high=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$arch-trivy.json")
  critical=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$arch-trivy.json")
  if (( high + critical > 0 )); then
    [[ $scan_status == 42 ]] || fail
  else
    [[ $scan_status == 0 ]] || fail
  fi
  jq --arg arch "$arch" --arg digest "$child" --argjson high "$high" --argjson critical "$critical" \
    '. + [{platform:("linux/" + $arch),digest:$digest,high:$high,critical:$critical,goBinaries:["/tailnet-agent","/tailnet-operator"]}]' \
    summaries.json >summaries.next
  mv summaries.next summaries.json
done

stage=policy
findings=$(jq '[.[] | .high + .critical] | add' summaries.json)
if (( findings > 0 )); then
  [[ -z $release ]] || fail
  # Bounded output: counts only, never package identifiers, CVEs or scanner text.
  for arch in amd64 arm64; do
    jq -r --arg arch "$arch" '.[] | select(.platform == ("linux/" + $arch)) |
      "image audit: warning (linux/" + $arch + "): HIGH=\(.high), CRITICAL=\(.critical)"' summaries.json >&3
  done
fi

verify_attestation() {
  local target=$1 digest=$2 kind=$3 predicate=$4 uri=$5
  run cosign-legacy verify-attestation --key "$work/broker.pub" --insecure-ignore-tlog=true \
    --type "$kind" "$target" >verified.json
  # Exit zero alone is insufficient: require a verified DSSE envelope containing
  # this exact predicate and subject, not an older attestation of the same type.
  jq -e -s --arg digest "${digest#sha256:}" --arg repo "$expected" --arg uri "$uri" \
    --slurpfile predicate "$predicate" '
    [ .[] | if type == "array" then .[] else . end ] |
    any(.[]; .payloadType == "application/vnd.in-toto+json" and
      (.payload | @base64d | fromjson |
        (._type == "https://in-toto.io/Statement/v0.1" or ._type == "https://in-toto.io/Statement/v1") and
        .predicateType == $uri and .predicate == $predicate[0] and
        (.subject | type == "array" and length == 1 and
          .[0].name == $repo and .[0].digest == {sha256:$digest})))
  ' verified.json >/dev/null
}

# No new attestations until *both* platforms passed every scan and tag policy.
# Subsequent failure may leave some attestations; publication is non-transactional.
for arch in amd64 arm64; do
  stage=sbom-attestation
  child=$(jq -r --arg arch "$arch" '.[] | select(.platform == ("linux/" + $arch)) | .digest' summaries.json)
  run cosign-legacy attest --yes --key "$COSIGN_KEY" --tlog-upload=false --type spdxjson \
    --predicate "$work/$arch-spdx.json" "$expected@$child"
  verify_attestation "$expected@$child" "$child" spdxjson "$work/$arch-spdx.json" https://spdx.dev/Document
done

stage=provenance
# SLSA builder.id is a TypeURI, not a bare OCI image reference.
jq -n --arg source rad:z46fGxuhyvDV57psA8s6Q6PdHJrsX --arg commit "$commit" --arg release "$release" \
  --arg builder "$CI_BUILDER_IMAGE" --arg crane "$crane_version" --slurpfile scans summaries.json '{
  buildDefinition: {
    buildType: "https://tsunaro.io/tailnet-operator/buildtypes/radicle-bundle/v1",
    externalParameters: {source:$source,commit:$commit,releaseTag:$release},
    resolvedDependencies: [{uri:$source,digest:{gitCommit:$commit}}]
  },
  runDetails: {
    metadata: {},
    builder: {id:("oci://" + $builder),version:{syft:"1.54.1",trivy:"0.75.0",cosign:"2.5.0",crane:$crane}},
    byproducts: [{name:"post-publication-audit",mediaType:"application/json",content:({
      platforms:$scans[0],scanners:["vuln"],severities:["HIGH","CRITICAL"],
      databasePolicy:"fresh per-run cache; updates enabled",
      findingsPolicy:(if $release == "" then "main: warn" else "release: reject" end),
      limitations:"Hand-built post-publication evidence; builder identity is deployment-configured, not self-measured. No SLSA level, completeness or reproducibility claim."
    } | tojson | @base64)}]
  }
}' >provenance.json
run cosign-legacy attest --yes --key "$COSIGN_KEY" --tlog-upload=false --type slsaprovenance1 \
  --predicate "$work/provenance.json" "$ref"
verify_attestation "$ref" "$index" slsaprovenance1 "$work/provenance.json" https://slsa.dev/provenance/v1
printf 'image audit: accepted (both platforms; verified SBOM and provenance attestations)\n' >&3
