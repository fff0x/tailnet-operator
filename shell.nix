{
  pkgs ? import <nixpkgs> { },
}:

let
  # hack/e2e-kind.sh and hack/e2e-kind-projection.sh require exactly this release: kind.yaml pins
  # its verified default node image. Build the pinned sources with the current nixpkgs recipe. Move
  # the version, both hashes and the scripts' version check together.
  kind = pkgs.kind.overrideAttrs (old: {
    version = "0.33.0";
    src = old.src.override { hash = "sha256-exqO/KERw/SOv3dywcrm/DSHY37dfTOhQezg6Nroew0="; };
    vendorHash = "sha256-tRpylYpEGF6XqtBl7ESYlXKEEAt+Jws4x4VlUVW8SNI=";
  });

  # hack/e2e-kind-projection.sh requires Helm 4, and the CI test image (Dockerfile, stage TEST) pins
  # this release. Take the same official archive instead of the nixpkgs build. Move the version and
  # both checksums together with the Dockerfile.
  helm =
    let
      release =
        {
          x86_64-linux = {
            arch = "amd64";
            sha256 = "d1c0278d46beab79582d7e50f5b3dc206944ba8e577cde618513fd07daa53983";
          };
          aarch64-linux = {
            arch = "arm64";
            sha256 = "df31cb61680ef728f82c770e5280dd565617bee6b039d37e85c677288be4bbb0";
          };
        }
        .${pkgs.stdenv.hostPlatform.system};
    in
    pkgs.runCommand "helm-4.3.2"
      {
        src = pkgs.fetchurl {
          url = "https://get.helm.sh/helm-v4.3.2-linux-${release.arch}.tar.gz";
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
