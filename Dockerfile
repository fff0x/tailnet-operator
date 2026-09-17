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
