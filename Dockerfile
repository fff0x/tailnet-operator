# syntax=docker/dockerfile:1
# tailnet-operator — published as a signed multi-arch bundle via ci-build's `build_bundle`.
# ci-build builds this ONCE on the native (arm64) broker, `crane export`s the rootfs, and packs each
# /bundle/<app>/<os>/<arch>/ group into its own platform-annotated FROM-scratch image, then folds
# them into a signed multi-arch index `${CAT}/<app>` (= tailnet/operator). No QEMU: Go cross-compiles
# amd64+arm64 from the native builder (CGO off). See ~/projects/src/radicle/ci-broker/ci-build.
#
# The PUBLISHED image is scratch (the base below is discarded): no ENTRYPOINT, no shell, no
# /etc/passwd, no CA bundle. Consequences, all handled in the pod specs / this file:
#   * binaries sit flat at / — pod specs use absolute commands (/tailnet-operator, /tailnet-agent).
#   * the agent (tsnet -> https control URL) needs ca-certificates.crt (bundled) + SSL_CERT_FILE.
#   * both containers must set an explicit numeric runAsUser (scratch has no USER directive).

##
## TEST — native architecture only; never published or used as the bundle carrier.
## Debian supplies the glibc userspace required by official Headscale/envtest assets.
## Only tools and module downloads are cached. CI executes hack/ci-test.sh with
## `buildah run` in a fresh working container, NOT a cacheable Dockerfile RUN.
##
# renovate: datasource=docker depName=golang versioning=docker
FROM docker.io/library/golang:1.26.11-bookworm AS TEST

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl jq sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Helm release checksums verified against get.helm.sh; no floating install script.
RUN set -eux; \
    case "$(dpkg --print-architecture)" in \
      amd64) arch=amd64; checksum=d1c0278d46beab79582d7e50f5b3dc206944ba8e577cde618513fd07daa53983 ;; \
      arm64) arch=arm64; checksum=df31cb61680ef728f82c770e5280dd565617bee6b039d37e85c677288be4bbb0 ;; \
      *) echo 'TEST supports native Linux amd64/arm64 only' >&2; exit 1 ;; \
    esac; \
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
      --connect-timeout 10 --max-time 180 --retry 2 \
      "https://get.helm.sh/helm-v4.3.2-linux-${arch}.tar.gz" -o /tmp/helm.tar.gz; \
    printf '%s  /tmp/helm.tar.gz\n' "$checksum" | sha256sum -c -; \
    tar -xzf /tmp/helm.tar.gz -C /tmp; \
    install -m 0755 "/tmp/linux-${arch}/helm" /usr/local/bin/helm; \
    rm -rf /tmp/helm.tar.gz "/tmp/linux-${arch}"

# Go's module checksum database verifies this version-pinned scanner and its dependencies.
RUN GOTOOLCHAIN=local GOBIN=/usr/local/bin go install golang.org/x/vuln/cmd/govulncheck@v1.8.0

WORKDIR /src
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
# Native CI supplies a tracked-source-only context without the production .dockerignore
# (which excludes deploy/). Do not pass credentials, host homes or runtime sockets.
COPY cmd ./cmd
COPY internal ./internal
COPY api ./api
COPY test ./test
COPY charts ./charts
COPY deploy ./deploy
COPY hack ./hack
COPY docs/OPERATIONS.md ./docs/OPERATIONS.md
COPY docs/reference/rbac.md ./docs/reference/rbac.md
COPY docs/reference/crds.md ./docs/reference/crds.md
COPY .radicle/native.yaml ./.radicle/native.yaml

##
## BUILD — both binaries, static (CGO off), cross-compiled for every target arch.
##
# renovate: datasource=docker depName=golang versioning=docker
FROM docker.io/library/golang:1.26-alpine AS build

# ca-certificates supplies the root CA bundle the (scratch) agent needs for its HTTPS control URL.
RUN apk add --no-cache ca-certificates

WORKDIR /src

# Module graph first, for layer caching.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Static, stripped. tsnet needs no cgo. Cross-compile both binaries for each target arch into the
# /bundle/<app>/<os>/<arch>/ layout build_bundle consumes; drop the CA bundle beside them so the
# scratch image carries it at /ca-certificates.crt.
ENV CGO_ENABLED=0
RUN set -eux; \
    for arch in amd64 arm64; do \
      d="/bundle/operator/linux/$arch"; mkdir -p "$d"; \
      GOOS=linux GOARCH="$arch" go build -trimpath -ldflags="-s -w" -o "$d/tailnet-operator" ./cmd/operator; \
      GOOS=linux GOARCH="$arch" go build -trimpath -ldflags="-s -w" -o "$d/tailnet-agent"    ./cmd/agent; \
      cp /etc/ssl/certs/ca-certificates.crt "$d/ca-certificates.crt"; \
    done

##
## MAIN — FROM scratch carrying only /bundle. build_bundle repacks each (os,arch) group into its own
## platform-annotated scratch image and folds them into a signed multi-arch index.
##
FROM scratch

# Opt-in for ci-build's generic build_bundle mode.
ARG BUNDLE=1
ARG CAT=tailnet
ARG APP=operator

COPY --from=build /bundle /bundle
