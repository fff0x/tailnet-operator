# Runnable local equivalent of one /bundle/operator/linux/<arch> repack.
# Binaries are statically built from the same checkout by hack/e2e-kind.sh.
FROM scratch
COPY tailnet-operator /tailnet-operator
COPY tailnet-agent /tailnet-agent
COPY ca-certificates.crt /ca-certificates.crt
ENV SSL_CERT_FILE=/ca-certificates.crt
USER 65532:65532
