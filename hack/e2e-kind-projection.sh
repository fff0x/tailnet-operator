#!/usr/bin/env bash
# Source-only fixture image; a separate delegated user scope must already exist.
# Only fixed test selections are optional; no reuse, route repair,
# context/image overrides, or sudo fallback.
set +x
set -Eeuo pipefail
umask 077
exec 3>&1
exec >/dev/null 2>&1
reject() { printf 'projection: stage=preflight result=rejected\n' >&3; exit 2; }
test_pattern='^Test(FixtureCAProjection|PodNetworkGate|HeadscaleHTTPS|AgentHTTPSPeer|IngressHTTP|IngressL4)$'
test_timeout=26m
kernel_only=false
gateway_only=false
if [[ $# == 1 && $1 == --http-only ]]; then
    test_pattern='^TestIngressHTTP$'
    # 22m, not 18m: the virtual-host phase now also relabels the base-name expose, which rolls the
    # agent through the fixture gate a third time and reissues the certificate.
    test_timeout=22m
elif [[ $# == 1 && $1 == --l4-only ]]; then
    test_pattern='^TestIngressL4$'
    test_timeout=10m
elif [[ $# == 1 && $1 == --rest-only ]]; then
    # The remaining P1.4 gates share one bootstrap; each builds its own namespace, control
    # plane and peer, so the budget is the sum of four fixtures, not of four clusters.
    test_pattern='^Test(EgressReach|RestartNoFlap|MagicDNSRename|IngressIdentityPersists)$'
    test_timeout=26m
elif [[ $# == 1 && $1 == --gateway-preflight-only ]]; then
    test_pattern='^TestGatewayKernelPrerequisites$'
    test_timeout=10m
    kernel_only=true
elif [[ $# == 1 && $1 == --gateway-fresh-only ]]; then
    test_pattern='^TestGatewayFreshPod$'
    test_timeout=10m
    gateway_only=true
elif [[ $# != 0 ]]; then
    reject
fi
[[ $(id -u) != 0 && $(uname -s) == Linux ]] || reject
for name in CONTAINER_HOST CONTAINER_CONNECTION CONTAINER_SSHKEY DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH PODMAN_REMOTE \
    PODMAN_CONNECTIONS_CONF CONTAINERS_CONF CONTAINERS_CONF_OVERRIDE CONTAINERS_CONF_MODULES \
    CONTAINERS_STORAGE_CONF CONTAINERS_REGISTRIES_CONF CONTAINERS_REGISTRIES_CONF_DIR; do
    [[ ! -v $name ]] || reject
done
src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P) || reject
fixture=$src/test/e2e-kind
# Only executable paths are discovered in the caller's PATH. No shell functions,
# aliases, BASH_ENV, proxy, cloud, registry or kube credentials reach child tools.
declare -A bins
for name in bash env podman kind kubectl helm go python3 systemctl timeout file stat; do
    bins[$name]=$(type -P "$name") || reject
    [[ ${bins[$name]} == /* ]] || reject
done
uid=$(id -u)
runtime=${XDG_RUNTIME_DIR:-}
[[ $runtime == /* && -d $runtime && ! -L $runtime ]] || reject
[[ $(stat -c '%u:%a' "$runtime") == "$uid:700" ]] || reject
state=${XDG_STATE_HOME:-${HOME:?}/.local/state}
data=${XDG_DATA_HOME:-$HOME/.local/share}
modules=${GOMODCACHE:-$state/go/pkg/mod}
case $(uname -m) in
    x86_64) hs_arch=amd64; hs_sha=7477c374949eea6fb7cf3cbff14dbef49e4d118d9a33557d6764a77ece617e53 ;;
    aarch64) hs_arch=arm64; hs_sha=7b3c792ebe10e1a81a0c8d9674aee8eb540e7dbb7ccb80a98b71024da4c72a48 ;;
    *) reject ;;
esac
cm_cache=${XDG_CACHE_HOME:-$HOME/.cache}/tailnet-operator-e2e/cert-manager/v1.21.2/immutable-ref/linux-$hs_arch
gateway_cache=${XDG_CACHE_HOME:-$HOME/.cache}/tailnet-operator-e2e/gateway/v1.104.4-coredns1.15.0/immutable-ref/linux-$hs_arch
headscale=${XDG_CACHE_HOME:-$HOME/.cache}/tailnet-operator-e2e/headscale/0.29.6/headscale-linux-$hs_arch
[[ -f $headscale && $(sha256sum "$headscale") == "$hs_sha  $headscale" ]] || reject
[[ $state == /* && $data == /* && $modules == /* && $modules != *:* ]] || reject
# Resolve parents before choosing an evidence location; never write under source.
state=$(realpath -m -- "$state") || reject
evidence_root=$(realpath -m -- "$state/tailnet-operator/evidence") || reject
tmp=$(realpath -m -- "${TMPDIR:-/tmp}") || reject
case $evidence_root/ in "$src/"*) reject ;; esac
case $tmp/ in "$src/"*) reject ;; esac
modules=$(realpath -m -- "$modules") || reject
case $modules/ in "$src/"*) reject ;; esac
[[ -d $modules ]] || reject
[[ $state != *$'\n'* && ${#state} -le 1024 ]] || reject
[[ ! -L $state/tailnet-operator && ! -L $state/tailnet-operator/evidence ]] || reject
work=$(mktemp -d "$tmp/tn-projection-XXXXXXXXXX") || reject
[[ $work == /* && ! -L $work ]] || reject
out=
stage=preflight
runtime_ready=false
network_attempted=false
cluster_attempted=false
image_attempted=false
shared_ready=false
source_recorded=false

# Until private evidence exists there are no runtime side effects.
bootstrap_cleanup() {
    local rc=$?
    trap - EXIT
    rm -rf -- "$work" || rc=1
    [[ ! -e $work && ! -L $work ]] || rc=1
    printf 'projection: stage=preflight result=rejected\n' >&3
    [[ -z $out ]] || printf 'evidence: %s\n' "$out" >&3
    exit "$rc"
}
trap bootstrap_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p -- "$state/tailnet-operator/evidence"
[[ ! -L $state/tailnet-operator && ! -L $state/tailnet-operator/evidence ]]
chmod 0700 "$state/tailnet-operator" "$state/tailnet-operator/evidence"
out=$(mktemp -d "$state/tailnet-operator/evidence/projection-XXXXXXXXXX")
chmod 0700 "$work" "$out"
# All tool output remains private. Only the final bounded result uses fd 3.
exec >>"$out/runner.log" 2>&1
mkdir -m 700 "$work/bin" "$work/home" "$work/config" "$work/cache" "$work/docker" "$work/context"
printf '{"auths":{}}\n' > "$work/auth.json"
printf '{"auths":{}}\n' > "$work/docker/config.json"
printf '[containers]\nvolumes=[]\n[engine]\nremote=false\n' > "$work/containers.conf"
printf 'unqualified-search-registries=[]\n' > "$work/registries.conf"
mkdir -m 700 "$work/registries.d"
# Include runtime helper executables, not arbitrary caller PATH entries. Podman's
# compiled helper locations remain usable; shared rootless storage is retained.
for name in bash env podman kind kubectl helm go python3 systemctl timeout file stat \
    sh cat cp mv rm mkdir mount umount sleep tar uname hostname ip iptables ip6tables \
    nft conmon crun runc netavark aardvark-dns pasta slirp4netns newuidmap newgidmap \
    fuse-overlayfs fusermount3 gzip pigz; do
    path=$(type -P "$name" || true)
    [[ -z $path ]] || ln -s -- "$path" "$work/bin/$name"
done
rm -- "$work/bin/podman"
# kind invokes podman itself; force local mode even when invoked indirectly.
printf '#!%s\nexec %q --remote=false "$@"\n' "${bins[bash]}" "${bins[podman]}" > "$work/bin/podman"
chmod 0755 "$work/bin/podman"
base=("PATH=$work/bin" "HOME=$work/home" "TMPDIR=$work" "LANG=C.UTF-8" "LC_ALL=C" \
    "XDG_CONFIG_HOME=$work/config" "XDG_CACHE_HOME=$work/cache" "XDG_DATA_HOME=$data" \
    "XDG_RUNTIME_DIR=$runtime" "REGISTRY_AUTH_FILE=$work/auth.json" "DOCKER_CONFIG=$work/docker" \
    "CONTAINERS_CONF=$work/containers.conf" "CONTAINERS_REGISTRIES_CONF=$work/registries.conf" \
    "CONTAINERS_REGISTRIES_CONF_DIR=$work/registries.d" "PYTHONDONTWRITEBYTECODE=1" \
    "GOENV=off" "GOFLAGS=-mod=readonly -buildvcs=false" "GOWORK=off" "GOTOOLCHAIN=local" \
    "CGO_ENABLED=0" "GOPROXY=off" "GOSUMDB=off" "GOTELEMETRY=off" \
    "GOMODCACHE=$modules" "GOPATH=$work/go" "GOCACHE=$work/cache/go" "GOMAXPROCS=4" "TS_NO_LOGS_NO_SUPPORT=1")
run() { "${bins[env]}" -i "${base[@]}" "$@" 3>&-; }
py() { run "${bins[python3]}" -B -I "$fixture/network-gate.py" "$@"; }
p() { run "${bins[timeout]}" 60 "$work/bin/podman" "$@"; }
# Uniform random lowercase name, not a lowercased mixed-case temp basename.
cluster=$(run "${bins[python3]}" -I -c 'import secrets,string; print("tn-kind-"+"".join(secrets.choice(string.ascii_lowercase) for _ in range(10)))')
network=$cluster-net
image=localhost/tn-source-netprobe:$cluster
agent_image=localhost/tailnet-operator-e2e:$cluster
node=$cluster-control-plane
ctx=kind-$cluster
pin=docker.io/kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
base+=("KIND_EXPERIMENTAL_PROVIDER=podman" "KIND_EXPERIMENTAL_PODMAN_NETWORK=$network" "KUBECONFIG=$work/kubeconfig")
k() { run "${bins[kubectl]}" --kubeconfig "$work/kubeconfig" --context "$ctx" --request-timeout=15s "$@"; }
# An exists command returning 125 (or any unexpected status) is not absence.
absent() { local rc=0; p "$@" || rc=$?; [[ $rc == 1 ]]; }
source_manifest() {
    (cd "$src"; sha256sum go.mod go.sum hack/e2e-kind-projection.sh test/e2e-kind/kind-http.yaml \
        test/e2e-kind/network-gate.py test/e2e-kind/Dockerfile.fixture test/e2e-kind/netprobe-pod.json test/e2e-kind/headscale-http.json \
        test/e2e-kind/cmd/{netprobe,fixture,projection,proofverify,hold,netgate,controlprobe,httppeer,kernelcheck,gatewayprobe,egressprobe}/*.go \
        test/internal/{netproof,kindfixture,kernelcheck,gatewayprobe}/*.go test/e2e-kind/*.go test/e2e-kind/Dockerfile \
        test/e2e-kind/cert-manager-images.json test/e2e-kind/cert-manager-assets*.py \
        test/e2e-kind/gateway-images.json test/e2e-kind/gateway-assets*.py;
        find api cmd internal -type f -name '*.go' -print0 | sort -z | xargs -0 sha256sum;
        find charts/tailnet-operator deploy/crds -type f -print0 | sort -z | xargs -0 sha256sum)
}
cleanup() {
    local result=$? bad=0 ids id rc which owned_image
    trap - EXIT INT TERM
    set +e
    printf '%s\n' "$stage" > "$out/last-stage.txt"
    if [[ $runtime_ready == true ]]; then
        if [[ $cluster_attempted == true ]]; then
            # Do not let kind's name selection broaden the deletion boundary.
            # Validate every exact-label match, then remove by full container ID.
            if p ps -a --filter "label=io.x-k8s.kind.cluster=$cluster" --format json > "$out/cleanup-containers.json" &&
                ids=$(py cleanup-containers "$out/cleanup-containers.json" "$cluster"); then
                while IFS= read -r id; do
                    [[ -z $id ]] || p rm --force --volumes "$id" >> "$out/cleanup.log" 2>&1 || bad=1
                done <<< "$ids"
            else bad=1; fi
        fi
        if [[ $network_attempted == true ]]; then
            rc=0; p network exists "$network" || rc=$?
            if [[ $rc == 0 ]]; then
                if p network inspect "$network" > "$out/cleanup-network.json" &&
                    py cleanup-network "$out/cleanup-network.json" "$cluster" "$network"; then
                    p network rm "$network" >> "$out/cleanup.log" 2>&1 || bad=1
                else bad=1; fi
            elif [[ $rc != 1 ]]; then bad=1; fi
        fi
        if [[ $image_attempted == true ]]; then
            for which in image agent-image; do
                owned_image=$image; [[ $which != agent-image ]] || owned_image=$agent_image
                rc=0; p image exists "$owned_image" || rc=$?
                if [[ $rc == 0 ]]; then
                    if p image inspect "$owned_image" > "$out/cleanup-$which.json" &&
                        py "cleanup-$which" "$out/cleanup-$which.json" "$cluster" "$owned_image"; then
                        p image rm --no-prune "$owned_image" >> "$out/cleanup.log" 2>&1 || bad=1
                    else bad=1; fi
                elif [[ $rc != 1 ]]; then bad=1; fi
            done
        fi
        p ps -a --filter "label=io.x-k8s.kind.cluster=$cluster" --format json > "$out/absence-cluster.json" || bad=1
        p ps -a --filter "name=^${node}$" --format json > "$out/absence-node.json" || bad=1
        p network ls --filter "label=netproof-owner=$cluster" --format json > "$out/absence-network.json" || bad=1
        p images --filter "label=netproof-owner=$cluster" --format json > "$out/absence-image.json" || bad=1
        py empty "$out/absence-cluster.json" "$out/absence-node.json" "$out/absence-network.json" "$out/absence-image.json" || bad=1
        absent network exists "$network" || bad=1
        absent image exists "$image" || bad=1
        absent image exists "$agent_image" || bad=1
        if [[ $shared_ready == true ]]; then p image exists "$pin" || bad=1; fi
    fi
    if [[ $source_recorded == true ]]; then
        source_manifest > "$out/source-after.sha256" || bad=1
        cmp -s "$out/source-before.sha256" "$out/source-after.sha256" || bad=1
    fi
    rm -rf -- "$work" || bad=1
    [[ ! -e $work && ! -L $work ]] || bad=1
    printf '%s\n' "$bad" > "$out/cleanup-exit-code.txt"
    if [[ $bad != 0 ]]; then result=1; stage=cleanup-rejected; fi
    printf '%s\n' "$result" > "$out/run-exit-code.txt"
    if [[ $result == 0 ]]; then rc=passed; else rc=failed; fi
    printf 'projection: stage=%s result=%s\nevidence: %s\n' "$stage" "$rc" "$out" >&3
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

stage=delegation-preflight
run "${bins[python3]}" -B -I -c 'import json,sys; json.dump(dict(zip(("work","cluster","network","image","agent_image"),sys.argv[2:])),open(sys.argv[1],"w"))' \
    "$out/owned.json" "$work" "$cluster" "$network" "$image" "$agent_image"
scope=$(py scope)
run "${bins[systemctl]}" --user show "$scope" --property=Delegate --property=Transient --property=ControlGroup > "$out/delegation.txt"
py delegation "$out/delegation.txt"
[[ $(p info --format '{{.Host.Security.Rootless}}') == true ]]
[[ $(run "${bins[kind]}" version) == 'kind v0.33.0 '* ]]
p ps -a --filter "label=io.x-k8s.kind.cluster=$cluster" --format json > "$out/initial-cluster.json"
p ps -a --filter "name=^${node}$" --format json > "$out/initial-node.json"
py empty "$out/initial-cluster.json" "$out/initial-node.json"
absent network exists "$network"
absent image exists "$image"
absent image exists "$agent_image"
runtime_ready=true

stage=build-source-offline
source_manifest > "$out/source-before.sha256"
source_recorded=true
# Dependency caches must already be populated. No module/auth/network fallback.
for binary in netprobe fixture projection hold proofverify netgate controlprobe httppeer kernelcheck gatewayprobe egressprobe; do
    target=$work/context/$binary
    [[ $binary != proofverify ]] || target=$work/proofverify
    (cd "$src"; run "${bins[go]}" build -trimpath -o "$target" "./test/e2e-kind/cmd/$binary") > "$out/$binary-build.log" 2>&1
    chmod 0755 "$target"
    run "${bins[file]}" "$target" >> "$out/static-binaries.txt"
done
cp -- "$headscale" "$work/context/headscale"
chmod 0755 "$work/context/headscale"
[[ $(sha256sum "$work/context/headscale") == "$hs_sha  $work/context/headscale" ]]
run "${bins[file]}" "$work/context/headscale" >> "$out/static-binaries.txt"
printf '%s  headscale-linux-%s\n' "$hs_sha" "$hs_arch" > "$out/headscale-provenance.sha256"
(cd "$src"; run "${bins[go]}" test -c -tags=e2e_kind -o "$work/projection.test" ./test/e2e-kind) > "$out/projection-build.log" 2>&1
chmod 0755 "$work/projection.test"
run "${bins[file]}" "$work/projection.test" >> "$out/static-binaries.txt"
run "${bins[python3]}" -B -I -c 'import pathlib,sys; s=pathlib.Path(sys.argv[1]).read_text(); sys.exit(0 if len(s.splitlines())==13 and s.count("statically linked")==13 else 2)' "$out/static-binaries.txt"
cp -- "$fixture/Dockerfile.fixture" "$work/context/Dockerfile"
py render "$fixture/netprobe-pod.json" "$work/pod.json" "$cluster"
# Keep private provenance hashes, not a second copy of source or tool state.
sha256sum "$work/context/"{netprobe,fixture,projection,hold,netgate,controlprobe,headscale,httppeer,kernelcheck,gatewayprobe,egressprobe} "$work/proofverify" "$work/projection.test" > "$out/binaries.sha256"

mkdir -m 700 "$work/agent-image"
for program in operator agent; do
    (cd "$src"; run "${bins[go]}" build -trimpath -ldflags='-s -w' -o "$work/agent-image/tailnet-$program" "./cmd/$program") > "$out/$program-production-build.log" 2>&1
    chmod 0755 "$work/agent-image/tailnet-$program"
    run "${bins[file]}" "$work/agent-image/tailnet-$program" >> "$out/production-static-binaries.txt"
done
run "${bins[python3]}" -B -I -c 'import pathlib,sys; s=pathlib.Path(sys.argv[1]).read_text(); sys.exit(0 if len(s.splitlines())==2 and s.count("statically linked")==2 else 2)' "$out/production-static-binaries.txt"
cp -- /etc/ssl/certs/ca-certificates.crt "$work/agent-image/ca-certificates.crt"
chmod 0644 "$work/agent-image/ca-certificates.crt"
cp -- "$fixture/Dockerfile" "$work/agent-image/Dockerfile"
sha256sum "$work/agent-image/"{tailnet-operator,tailnet-agent,ca-certificates.crt,Dockerfile} > "$out/production-image-inputs.sha256"

stage=cert-manager-asset-preparation
run "${bins[helm]}" version --short > "$out/helm-version.txt"
grep -Eq '^v4\.[0-9]+\.[0-9]+' "$out/helm-version.txt"
run "${bins[python3]}" -B -I "$fixture/cert-manager-assets.py" "$cm_cache" "$hs_arch" > "$out/cert-manager-cache.json"
mkdir -m 700 "$work/cert-manager"
for component in controller cainjector webhook startupapicheck; do cp -- "$cm_cache/$component.tar" "$work/cert-manager/$component.tar"; done
cp -- "$cm_cache/chart.tgz" "$work/cert-manager/chart.tgz"
run "${bins[python3]}" -B -I "$fixture/cert-manager-assets.py" "$work/cert-manager" "$hs_arch" > "$out/cert-manager-assets.json"
cmp "$out/cert-manager-cache.json" "$out/cert-manager-assets.json"
if [[ $gateway_only == true ]]; then
    stage=gateway-asset-preparation
    run "${bins[python3]}" -B -I "$fixture/gateway-assets.py" "$gateway_cache" "$hs_arch" > "$out/gateway-cache.json"
    mkdir -m 700 "$work/gateway"
    for component in tailscale coredns; do cp -- "$gateway_cache/$component.tar" "$work/gateway/$component.tar"; done
    run "${bins[python3]}" -B -I "$fixture/gateway-assets.py" "$work/gateway" "$hs_arch" > "$out/gateway-assets.json"
    cmp "$out/gateway-cache.json" "$out/gateway-assets.json"
fi

stage=public-image-preparation
run "${bins[timeout]}" 300 "$work/bin/podman" pull --authfile "$work/auth.json" "$pin" > "$out/node-pull.log" 2>&1
shared_ready=true
image_attempted=true
run "${bins[timeout]}" 120 "$work/bin/podman" build --network=none --pull=never --layers=false --rm --force-rm \
    --authfile "$work/auth.json" --label "netproof-owner=$cluster" --tag "$image" \
    --file "$work/context/Dockerfile" "$work/context" > "$out/probe-build.log" 2>&1
p build --pull=never --network=none --http-proxy=false --authfile "$work/auth.json" --label "netproof-owner=$cluster" --tag "$agent_image" "$work/agent-image" > "$out/agent-image-build.log" 2>&1
p image inspect "$agent_image" > "$out/agent-image.json"
p save --format docker-archive --output "$work/agent.tar" "$agent_image" > "$out/agent-save.log" 2>&1
p image inspect "$image" > "$out/probe-image.json"
p save --format docker-archive --output "$work/probe.tar" "$image" > "$out/probe-save.log" 2>&1

stage=internal-network
network_attempted=true
p network create --driver bridge --internal --disable-dns --opt isolate=true --label "netproof-owner=$cluster" "$network" > "$out/network-create.log"
p network inspect "$network" > "$out/network-before.json"
py network "$out/network-before.json" "$cluster" "$network"

stage=bootstrap
cluster_attempted=true
run "${bins[timeout]}" 300 "${bins[kind]}" create cluster --name "$cluster" --kubeconfig "$work/kubeconfig" \
    --config "$fixture/kind-http.yaml" --wait 120s --retain > "$out/kind-create.log" 2>&1
chmod 0600 "$work/kubeconfig"
k config view -o json > "$out/kubeconfig-binding.json"
py kube "$out/kubeconfig-binding.json" "$cluster"
k get namespace kube-system -o jsonpath='{.metadata.uid}' > "$out/cluster-uid.txt"

stage=coredns-no-forward-restart
k -n kube-system get configmap coredns -o json > "$out/coredns-before.json"
py patch "$out/coredns-before.json" "$work/coredns-patch.json"
k -n kube-system patch configmap coredns --type merge --patch-file "$work/coredns-patch.json" > "$out/coredns-patch.log"
k -n kube-system rollout restart deployment/coredns > "$out/coredns-restart.log"
if ! k -n kube-system rollout status deployment/coredns --timeout=90s > "$out/coredns-rollout.log" 2>&1; then
    # Read only the bootstrap DNS workload through this owned cluster's API.
    # Keep the original failure; observations do not authorize later stages.
    k -n kube-system get deployment coredns -o json > "$out/coredns-failed-deployment.private.json" 2> "$out/coredns-failed-deployment.private.stderr" || true
    k -n kube-system get pods -l k8s-app=kube-dns -o json > "$out/coredns-failed-pods.private.json" 2> "$out/coredns-failed-pods.private.stderr" || true
    k -n kube-system logs deployment/coredns --all-pods=true --all-containers=true --tail=50 --limit-bytes=16384 > "$out/coredns-failed.private.log" 2> "$out/coredns-failed.private.stderr" || true
    exit 1
fi
k -n kube-system get configmap coredns -o json > "$out/coredns-after.json"

stage=preload
run "${bins[timeout]}" 120 "${bins[kind]}" load image-archive "$work/probe.tar" --name "$cluster" > "$out/probe-load.log" 2>&1
p exec "$node" crictl inspecti "$image" > "$out/probe-cri-image.json"
run "${bins[timeout]}" 120 "${bins[kind]}" load image-archive "$work/agent.tar" --name "$cluster" > "$out/agent-load.log" 2>&1
p exec "$node" crictl inspecti "$agent_image" > "$out/agent-cri-image.json"
p exec "$node" ctr version > "$out/containerd-version.txt"
p exec "$node" containerd config dump > "$out/containerd-config.private.toml"
snapshotter=$(run "${bins[python3]}" -B -I "$fixture/cert-manager-assets.py" --snapshotter "$out/containerd-config.private.toml")
for component in controller cainjector webhook startupapicheck; do
    ref=$(run "${bins[python3]}" -B -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["images"][sys.argv[2]]["reference"])' "$out/cert-manager-assets.json" "$component")
    repo=${ref%@*}
    # Same owned-node import as Kind, with a fully qualified base for generated
    # index aliases. Containerd transfer mode otherwise creates an unqualified
    # alias which CRI normalizes to a different, nonexistent literal image name.
    run "${bins[timeout]}" 120 "$work/bin/podman" exec -i "$node" ctr --namespace=k8s.io images import --all-platforms --digests "--snapshotter=$snapshotter" "--base-name=$repo" - < "$work/cert-manager/$component.tar" > "$out/cm-$component-load.log" 2>&1
    p exec "$node" crictl images --output json > "$out/cm-$component-image-inventory.json"
    p exec "$node" ctr --namespace k8s.io images list --quiet > "$out/cm-$component-containerd-images.txt"
    p exec "$node" crictl inspecti "$ref" > "$out/cm-$component-cri-image.json"
    run "${bins[python3]}" -B -I "$fixture/cert-manager-assets.py" --check-import "$out/cert-manager-assets.json" "$component" "$out/cm-$component-cri-image.json" "$out/cm-$component-containerd-images.txt" > "$out/cm-$component-import-verified.json"
done
if [[ $gateway_only == true ]]; then
    for component in tailscale coredns; do
        ref=$(run "${bins[python3]}" -B -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["images"][sys.argv[2]]["reference"])' "$out/gateway-assets.json" "$component")
        repo=${ref%@*}
        run "${bins[timeout]}" 120 "$work/bin/podman" exec -i "$node" ctr --namespace=k8s.io images import --all-platforms --digests "--snapshotter=$snapshotter" "--base-name=$repo" - < "$work/gateway/$component.tar" > "$out/gateway-$component-load.log" 2>&1
        p exec "$node" ctr --namespace k8s.io images list --quiet > "$out/gateway-$component-containerd-images.txt"
        p exec "$node" crictl inspecti "$ref" > "$out/gateway-$component-cri-image.json"
        run "${bins[python3]}" -B -I "$fixture/gateway-assets.py" --check-import "$out/gateway-assets.json" "$component" "$out/gateway-$component-cri-image.json" "$out/gateway-$component-containerd-images.txt" > "$out/gateway-$component-import-verified.json"
    done
fi
p cp "$work/context/netprobe" "$node:/tmp/owned-source-netprobe" > "$out/node-copy.log" 2>&1
if [[ $kernel_only == true ]]; then
    p cp "$work/context/kernelcheck" "$node:/tmp/owned-source-kernelcheck" > "$out/kernelcheck-node-copy.log" 2>&1
fi
stage=holder-pod
k create -f "$work/pod.json" > "$out/pod-create.log"
k wait --for=condition=Ready pod/owned-netproof --timeout=60s > "$out/pod-ready.log" 2>&1
sleep 5

stage=capture
end=$((SECONDS+30)); attempt=0; ok=false
while (( SECONDS < end )); do
    attempt=$((attempt+1)); a=$out/attempt-$attempt; mkdir -m 700 "$a"
    k get nodes -o json > "$out/nodes-before.json"
    k get pod owned-netproof -o json > "$out/pod-before.json"
    p inspect "$node" > "$out/node-container-before.json"
    start=$(date +%s)
    nr=0; pr=0
    run "${bins[timeout]}" 7 "$work/bin/podman" exec --user 65534:65534 "$node" /tmp/owned-source-netprobe \
        --capture=node --fixture=p1.8-layered-isolation > "$a/node.json" 2> "$a/node.stderr" || nr=$?
    run "${bins[timeout]}" 7 "${bins[kubectl]}" --kubeconfig "$work/kubeconfig" --context "$ctx" --request-timeout=6s \
        exec owned-netproof -- /netprobe --capture=pod --fixture=p1.8-layered-isolation > "$a/pod.json" 2> "$a/pod.stderr" || pr=$?
    finish=$(date +%s)
    printf '{"nodeExit":%s,"podExit":%s,"start":%s,"end":%s}\n' "$nr" "$pr" "$start" "$finish" > "$a/result.json"
    cp -- "$out/nodes-before.json" "$out/pod-before.json" "$out/node-container-before.json" "$a/"
    if [[ $nr != 0 || $pr != 0 ]]; then sleep 1; continue; fi
    cp -- "$a/node.json" "$out/node-capture.json"; cp -- "$a/pod.json" "$out/pod-capture.json"
    printf '{"start":%s,"end":%s}\n' "$start" "$finish" > "$out/capture-times.json"
    k get nodes -o json > "$out/nodes-after.json"
    k get pod owned-netproof -o json > "$out/pod-after.json"
    p inspect "$node" > "$out/node-container-after.json"
    if ! py stable "$out" > "$a/stable.log" 2>&1; then sleep 1; continue; fi
    ok=true; break
done
printf '%s\n' "$attempt" > "$out/capture-attempts.txt"
[[ $ok == true ]]

stage=caller-binding-gate
k get pods -A -o json > "$out/cluster-pods.json"
for resource in deployments daemonsets statefulsets jobs cronjobs; do k get "$resource" -A -o json > "$out/$resource.json"; done
p network inspect "$network" > "$out/network-after.json"
p ps -a --filter "label=io.x-k8s.kind.cluster=$cluster" --format json > "$out/owned-containers.json"
k get namespace kube-system -o jsonpath='{.metadata.uid}' > "$out/cluster-uid-after.txt"
py check "$out" "$cluster" "$network" "$image" > "$out/caller-gate.json" 2> "$out/caller-gate.stderr"
stage=source-classifier
run "$work/proofverify" "$out/binding.json" "$out/node-capture.json" "$out/pod-capture.json" > "$out/classifier.json" 2> "$out/classifier.stderr"

# Fixed, private observation commands for the test's per-Pod startup proof.
# They inherit the same closed runtime environment; no arbitrary command mode.
{
    # shellcheck disable=SC2016 # Preserve positional parameters for the generated observer.
    printf '#!%s\nset -eu\n[[ $# == 1 ]] || exit 2\ncase "$1" in\n' "${bins[bash]}"
    modes=(capture inspect network)
    [[ $kernel_only != true ]] || modes+=(kernel)
    for mode in "${modes[@]}"; do
        case $mode in
            kernel) action=(exec --user 65534:65534 "$node" /tmp/owned-source-kernelcheck --capture=node --fixture=p2.1-kernel-prerequisites) ;;
            capture) action=(exec --user 65534:65534 "$node" /tmp/owned-source-netprobe --capture=node --fixture=p1.8-layered-isolation) ;;
            inspect) action=(inspect "$node") ;;
            network) action=(network inspect "$network") ;;
        esac
        printf '%s) exec ' "$mode"
        printf '%q ' "${bins[env]}" -i "${base[@]}" "${bins[timeout]}" 7 "$work/bin/podman" "${action[@]}"
        printf ';;\n'
    done
    printf '*) exit 2;;\nesac\n'
} > "$work/node-observation"
chmod 0700 "$work/node-observation"
stage=real-admission-and-projection
printf '%s\n' "$test_pattern" > "$out/test-selection.txt"
printf '%s\n' "$test_timeout" > "$out/test-timeout.txt"
system_uid=$(< "$out/cluster-uid.txt")
# Compiled test binaries do not inherit `go test`'s package working directory.
(cd "$fixture"; run "${bins[env]}" "E2E_KIND_WORK=$work" "E2E_KIND_CLUSTER=$cluster" "E2E_KIND_CONTEXT=$ctx" \
    "E2E_KIND_FIXTURE_IMAGE=$image" "E2E_KIND_AGENT_IMAGE=$agent_image" "E2E_KIND_SYSTEM_UID=$system_uid" "E2E_KIND_HTTP_NETWORK_GATE=passed" "E2E_KIND_NET_EVIDENCE=$out" \
    "$work/projection.test" -test.run "$test_pattern" -test.count=1 -test.timeout="$test_timeout" -test.v) > "$out/projection-test.log" 2>&1
stage=projection-passed
