{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  name = "tailnet-operator";

  packages = with pkgs; [
    # Go toolchain
    go
    gopls
    gotools # goimports

    # Kubernetes + local testing
    kubectl
    kustomize
    go-task
    kubernetes-helm
    helm-docs
    kubeconform
    jq # Portable dashboard JSON validation (also available in the CI broker)
    curl
    sqlite # Offline route fixtures for the real Headscale integration tests
    govulncheck # hack/ci-test.sh (task e2e-full) runs the same scanner the CI image pins
  ];

  # tsnet phones home to log.tailscale.com by default; keep the dev shell quiet too.
  TS_NO_LOGS_NO_SUPPORT = "1";

  shellHook = ''
    echo "tailnet-operator dev shell — $(go version 2>/dev/null | cut -d' ' -f3)"
  '';
}
