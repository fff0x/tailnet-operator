{
  pkgs ? import <nixpkgs> { },
}:

let
  # hack/e2e-kind.sh and hack/e2e-kind-projection.sh require exactly this release: kind.yaml pins
  # its verified default node image. nixpkgs has moved on, so build the pinned sources with the
  # current recipe plus the upstream fix nixpkgs carried for this release. Move the version, both
  # hashes and the scripts' version check together.
  kind = pkgs.kind.overrideAttrs (old: {
    version = "0.32.0";
    src = old.src.override { hash = "sha256-ii0VhS1Nib+r2ZFIIkRvkcGY1fLxev6WnhbqvaZW7j8="; };
    vendorHash = "sha256-tRpylYpEGF6XqtBl7ESYlXKEEAt+Jws4x4VlUVW8SNI=";
    patches = old.patches ++ [
      # apiserver connection loss after the envoy load-balancer container restarts
      (pkgs.fetchpatch {
        url = "https://github.com/kubernetes-sigs/kind/commit/9a24e6c1ae3d59f8de052ee5c3842820450a369a.patch";
        hash = "sha256-BP2Ub8b1GA7V0CGvhcoGuHRm7u+IMRTmN3mDc2rePnY=";
      })
    ];
  });

  # hack/e2e-kind-projection.sh requires Helm 3, and the CI test image (Dockerfile, stage TEST) pins
  # this release; nixpkgs ships Helm 4. Take the same official archive. Move the version and both
  # checksums together with the Dockerfile.
  helm =
    let
      release =
        {
          x86_64-linux = {
            arch = "amd64";
            sha256 = "a7f81ce08007091b86d8bd696eb4d86b8d0f2e1b9f6c714be62f82f96a594496";
          };
          aarch64-linux = {
            arch = "arm64";
            sha256 = "440cf7add0aee27ebc93fada965523c1dc2e0ab340d4348da2215737fc0d76ad";
          };
        }
        .${pkgs.stdenv.hostPlatform.system};
    in
    pkgs.runCommand "helm-3.19.0"
      {
        src = pkgs.fetchurl {
          url = "https://get.helm.sh/helm-v3.19.0-linux-${release.arch}.tar.gz";
          inherit (release) sha256;
        };
      }
      ''
        mkdir -p $out/bin
        tar -xzf $src -C $out/bin --strip-components=1 linux-${release.arch}/helm
      '';
in
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
    kind # pinned above; task e2e-kind / e2e-full
    go-task
    helm # pinned above; the chart tasks and the kind runners
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
