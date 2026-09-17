# syntax=docker/dockerfile:1
# tailnet-operator — one combined image carrying both static binaries:
#   * tailnet-operator  (control plane)  — pod command: ["tailnet-operator"]  (ENTRYPOINT)
#   * tailnet-agent     (data plane)     — pod command: ["tailnet-agent"]
# A single image keeps the radicle `ci-build` one-Dockerfile model (build + push + sign) intact.

##
## BUILD — both binaries, static (CGO off), reproducible
##
# renovate: datasource=docker depName=golang versioning=docker
FROM docker.io/library/golang:1.26-alpine AS build

WORKDIR /src

# Module graph first, for layer caching.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Static, stripped. tsnet needs no cgo.
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/tailnet-operator ./cmd/operator && \
    go build -trimpath -ldflags="-s -w" -o /out/tailnet-agent    ./cmd/agent

##
## MAIN — distroless static, nonroot
##
# renovate: datasource=docker depName=gcr.io/distroless/static-debian12
FROM gcr.io/distroless/static-debian12:nonroot

ARG CAT=tailnet
ARG APP=operator
# Fallback for a direct `docker build`; `task image` / ci-build injects the real version.
ARG APP_VERSION=0.0.0
ARG APP_DESCRIPTION="tailnet-operator — per-namespace tailnet egress via CRD"

LABEL \
  org.opencontainers.image.vendor="this-is-fine" \
  org.opencontainers.image.url="https://this-is-fine.io" \
  org.opencontainers.image.authors="Max 'ff0x' Reineke <ff0x@this-is-fine.io>" \
  org.opencontainers.image.title="${CAT}-${APP}" \
  org.opencontainers.image.version="${APP_VERSION}" \
  org.opencontainers.image.description="$APP_DESCRIPTION" \
  org.opencontainers.image.licenses="MIT"

COPY --from=build /out/tailnet-operator /usr/bin/tailnet-operator
COPY --from=build /out/tailnet-agent    /usr/bin/tailnet-agent

# distroless nonroot is uid 65532; pod specs set the exact command per container.
USER 65532:65532

ENTRYPOINT ["tailnet-operator"]
