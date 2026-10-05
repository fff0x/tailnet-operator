#!/usr/bin/env python3
"""Synthetic offline tests: python3 -B -I gateway-assets-test.py."""

import contextlib
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


def sibling_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


assets = sibling_module("gateway_assets", "gateway-assets.py")
builders = sibling_module("cert_manager_asset_builders", "cert-manager-assets-test.py")
encoded, sha = builders.encoded, builders.sha


class ArchiveFixture(builders.ArchiveFixture):
    def __init__(self, arch="amd64", role="tailscale"):
        self.role = role
        super().__init__(arch)
        self.repository = assets.REPOSITORIES[role]
        self.finish()

    def finish(self):
        super().finish()
        self.image["version"] = assets.VERSIONS[self.role]


class GatewayAssetsTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="gateway-assets-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.lock_path = self.directory / "lock.json"
        self.prepare()

    def prepare(self, arch="amd64"):
        self.fixtures = {role: ArchiveFixture(arch, role) for role in assets.ROLES}
        self.lock = {"images": {role: copy.deepcopy(fixture.image)
                                for role, fixture in self.fixtures.items()}}
        self.lock_path.write_bytes(encoded(self.lock))
        for role, fixture in self.fixtures.items():
            fixture.write(self.directory / (role + ".tar"))

    def validate(self, arch="amd64"):
        return assets.validate_assets(self.directory, arch, self.lock_path)

    def reject_fixture(self, fixture, extra=()):
        self.prepare()
        role = fixture.role
        fixture.write(self.directory / (role + ".tar"), extra)
        self.lock["images"][role] = fixture.image
        self.lock_path.write_bytes(encoded(self.lock))
        with self.assertRaises(assets.Rejected):
            self.validate()

    def cli(self, arguments, code=0):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(assets.main(arguments), code)
        self.assertEqual(stderr.getvalue(), "" if code == 0 else "gateway assets rejected\n")
        if code:
            self.assertEqual(stdout.getvalue(), "")
            return None
        return json.loads(stdout.getvalue())

    def binding(self):
        report = self.validate()
        image = report["images"]["tailscale"]
        alias = image["tag"]
        status = {"id": image["configDigest"], "repoDigests": [image["reference"]],
                  "repoTags": [alias]}
        return report, status, [image["reference"], alias]

    def test_complete_report_both_architectures(self):
        for arch in assets.ARCHES:
            with self.subTest(arch=arch):
                self.prepare(arch)
                report = self.validate(arch)
                self.assertEqual(set(report), {"architecture", "images"})
                self.assertEqual(report["architecture"], arch)
                self.assertEqual(set(report["images"]), set(assets.ROLES))
                for role, fixture in self.fixtures.items():
                    digest = fixture.image["platforms"][arch]
                    self.assertEqual(report["images"][role], {
                        "reference": fixture.repository + "@" + digest,
                        "manifestDigest": digest, "configDigest": sha(fixture.config),
                        "tag": fixture.repository + ":" + assets.VERSIONS[role],
                        "archiveSHA256": hashlib.sha256(
                            (self.directory / (role + ".tar")).read_bytes()).hexdigest(),
                    })

    def test_shared_helpers_and_globals_unchanged(self):
        for name in ("_archive", "bounded_read", "_json", "_keys", "_digest",
                     "_open_regular", "imported_binding"):
            self.assertIs(getattr(assets, name), getattr(assets.shared, name))
        self.validate()
        self.assertEqual(assets.shared.VERSION, "v1.21.2")
        self.assertEqual(builders.assets.VERSION, "v1.21.2")
        self.assertEqual(builders.ArchiveFixture().repository,
                         "quay.io/jetstack/cert-manager-controller")

    def test_production_lock_pins(self):
        lock = assets.load_lock(assets.LOCK_PATH)
        pins = {
            "tailscale": (
                "2667499ed87ae29218f292556ba062918402dd5e92e93637af14867e4df12dd3",
                "9482efa70e5e37180a74ad17e01fb0a43ec4b629cdde1a28a9fb79597bca63e2",
                "5789311e4ab3bcf6cfb88020def1ce6c8cfebacfd6a369f06b103a8feee0eedc"),
            "coredns": (
                "900f9c109f7a33545d3c811516e8376df9019147b750f5ce3e254468769176ea",
                "1ba6f47265602e2e50a9c4669e3a955e4298a0d30dc82f39293d4bf1a851e0ff",
                "d5cc132a34e034ecfd2d4c73c5bf341e5d8af9a0ba46bd7619d9448beb27e7a2"),
        }
        for role, (index, amd64, arm64) in pins.items():
            self.assertEqual(lock["images"][role], {
                "repository": assets.REPOSITORIES[role], "version": assets.VERSIONS[role],
                "indexDigest": "sha256:" + index,
                "platforms": {"amd64": "sha256:" + amd64, "arm64": "sha256:" + arm64},
            })

    def test_lock_schema(self):
        mutations = [
            lambda x: x.update(extra=True),
            lambda x: x.pop("images"),
            lambda x: x.update(images=[]),
            lambda x: x["images"].pop("coredns"),
            lambda x: x["images"].update(extra={}),
        ]
        for mutate in mutations:
            lock = copy.deepcopy(self.lock)
            mutate(lock)
            with self.assertRaises(assets.Rejected):
                assets._validate_lock(lock)
        for role in assets.ROLES:
            for key, value in (("repository", "untrusted.invalid/image"),
                               ("version", "latest"), ("version", True),
                               ("indexDigest", "sha256:bad"), ("indexDigest", None),
                               ("platforms", []), ("extra", True)):
                with self.subTest(role=role, key=key, value=value):
                    lock = copy.deepcopy(self.lock)
                    lock["images"][role][key] = value
                    with self.assertRaises(assets.Rejected):
                        assets._validate_lock(lock)
            for key in self.lock["images"][role]:
                lock = copy.deepcopy(self.lock)
                del lock["images"][role][key]
                with self.assertRaises(assets.Rejected):
                    assets._validate_lock(lock)
            for platforms in ({"amd64": sha(b"a")},
                              dict(self.lock["images"][role]["platforms"], s390x=sha(b"b")),
                              {"amd64": "SHA256:" + "a" * 64, "arm64": sha(b"b")},
                              {"amd64": sha(b"a") + "\n", "arm64": sha(b"b")}):
                lock = copy.deepcopy(self.lock)
                lock["images"][role]["platforms"] = platforms
                with self.assertRaises(assets.Rejected):
                    assets._validate_lock(lock)

    def test_lock_json_and_size(self):
        for data in (b'{"images":{},"images":{}}', b'{', b'[]', b'\xff',
                     b'{"images":NaN}', b' ' * (assets.shared.MAX_LOCK + 1)):
            self.lock_path.write_bytes(data)
            with self.assertRaises(assets.Rejected):
                self.validate()

    def test_wrong_manifest_pin(self):
        for role in assets.ROLES:
            self.prepare()
            self.lock["images"][role]["platforms"]["amd64"] = sha(b"wrong")
            self.lock_path.write_bytes(encoded(self.lock))
            with self.assertRaises(assets.Rejected):
                self.validate()

    def test_wrong_architecture(self):
        for arch in ("arm64", "x86_64", "../amd64"):
            with self.assertRaises(assets.Rejected):
                self.validate(arch)

    def test_bad_ref_and_platform(self):
        for role in assets.ROLES:
            for ref in ("tag", "repository", "digest", "missing"):
                fixture = ArchiveFixture(role=role)
                descriptor = fixture.index["manifests"][0]
                annotation = descriptor["annotations"]
                key = "org.opencontainers.image.ref.name"
                if ref == "tag":
                    annotation[key] = fixture.repository + ":" + fixture.image["version"]
                elif ref == "repository":
                    annotation[key] = "untrusted.invalid/image@" + fixture.image["platforms"]["amd64"]
                elif ref == "digest":
                    annotation[key] = fixture.repository + "@" + sha(b"wrong")
                else:
                    del annotation[key]
                fixture.update_index()
                self.reject_fixture(fixture)
            for platform in ({"os": "linux", "architecture": "arm64"},
                             {"os": "windows", "architecture": "amd64"},
                             {"os": "linux", "architecture": "amd64", "variant": "v8"}):
                fixture = ArchiveFixture(role=role)
                fixture.index["manifests"][0]["platform"] = platform
                fixture.update_index()
                self.reject_fixture(fixture)

    def test_missing_tampered_and_extra_blobs(self):
        for role in assets.ROLES:
            for target in ("config", "layer"):
                for operation in ("missing", "tampered"):
                    fixture = ArchiveFixture(role=role)
                    path = "blobs/sha256/" + sha(getattr(fixture, target))[7:]
                    if operation == "missing":
                        del fixture.files[path]
                    else:
                        fixture.files[path] = b"tampered"
                    self.reject_fixture(fixture)
            fixture = ArchiveFixture(role=role)
            fixture.files["blobs/sha256/" + sha(b"extra")[7:]] = b"extra"
            self.reject_fixture(fixture)

    def test_bad_manifest_and_config(self):
        for data in (b'{', b'[]', encoded({"os": "windows", "architecture": "amd64"}),
                     encoded({"os": "linux", "architecture": "arm64"})):
            fixture = ArchiveFixture()
            fixture.config = data
            fixture.manifest["config"] = fixture.descriptor(
                data, "application/vnd.docker.container.image.v1+json")
            fixture.finish()
            self.reject_fixture(fixture)
        for field, value in (("size", 1), ("size", True), ("digest", sha(b"absent")),
                             ("mediaType", "unknown"), ("urls", ["https://invalid/layer"])):
            fixture = ArchiveFixture()
            fixture.manifest["layers"][0][field] = value
            fixture.finish()
            self.reject_fixture(fixture)

    def test_malformed_index(self):
        for data in (b'{', b'{"schemaVersion":2,"schemaVersion":2}', b'[]',
                     b'{"x":NaN}', b'\xff', b'[' * 2000):
            fixture = ArchiveFixture()
            fixture.files["index.json"] = data
            self.reject_fixture(fixture)
        for field, value in (("schemaVersion", True), ("manifests", []),
                             ("mediaType", "unknown")):
            fixture = ArchiveFixture()
            fixture.index[field] = value
            fixture.update_index()
            self.reject_fixture(fixture)

    def test_unsafe_archive_members(self):
        for name in ("../escape", "/escape", "./index.json", "unexpected", "index.json"):
            self.reject_fixture(ArchiveFixture(), [(tarfile.TarInfo(name), b"")])
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE,
                     tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_SPARSE):
            member = tarfile.TarInfo("unsafe")
            member.type = kind
            member.linkname = "index.json"
            self.reject_fixture(ArchiveFixture(), [(member, b"")])

    def test_truncated_compressed_and_trailing_archive(self):
        path = self.directory / "tailscale.tar"
        original = path.read_bytes()
        for data in (original[:100], original[:512], original + b"payload",
                     gzip.compress(original)):
            path.write_bytes(data)
            with self.assertRaises(assets.Rejected):
                self.validate()

    def test_symlink_nonregular_and_missing_files(self):
        original = self.directory / "tailscale.tar"
        saved = self.directory / "saved.tar"
        original.rename(saved)
        original.symlink_to(saved)
        with self.assertRaises(OSError):
            self.validate()
        original.unlink()
        os.mkfifo(original)
        with self.assertRaises(assets.Rejected):
            self.validate()
        original.unlink()
        with self.assertRaises(OSError):
            self.validate()
        saved.rename(original)
        parent = self.directory / "linked"
        parent.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(OSError):
            assets.validate_assets(parent, "amd64", self.lock_path)
        self.lock_path.unlink()
        self.lock_path.symlink_to(original)
        with self.assertRaises(OSError):
            self.validate()

    def test_repository_cache_rejected(self):
        with self.assertRaises(assets.Rejected):
            assets.validate_assets(assets.REPO_ROOT / "not-created", "amd64", self.lock_path)
        link = self.directory / "repository"
        link.symlink_to(assets.REPO_ROOT, target_is_directory=True)
        with self.assertRaises(assets.Rejected):
            assets.validate_assets(link, "amd64", self.lock_path)

    def test_import_valid_both_roles_and_architectures(self):
        for arch in assets.ARCHES:
            self.prepare(arch)
            report = self.validate(arch)
            for role, image in report["images"].items():
                status = {"id": image["configDigest"], "repoDigests": [image["reference"]],
                          "repoTags": [image["tag"]]}
                result = assets.check_import(report, role, status,
                                             [image["reference"], image["tag"]], self.lock)
                self.assertEqual(result, {"pinnedConfigAndReference": True,
                                          "allCRIReferencesExistLiterally": True})

    def test_import_requires_exact_config_digest_and_aliases(self):
        report, status, names = self.binding()
        for mutate in (
            lambda x: x.update(id=sha(b"wrong")),
            lambda x: x.update(repoDigests=[]),
            lambda x: x.update(repoDigests=["untrusted@" + sha(b"wrong")]),
            lambda x: x.update(repoTags=["docker.io/library/import-alias:latest"]),
            lambda x: x.update(repoTags="not a list"),
            lambda x: x.update(repoTags=[None]),
        ):
            bad = copy.deepcopy(status)
            mutate(bad)
            with self.assertRaises(assets.Rejected):
                assets.check_import(report, "tailscale", bad, names, self.lock)
        for bad_names in ([], [names[0]], [names[1]], [names[0] + " ", names[1]],
                          names[0], [None]):
            with self.assertRaises(assets.Rejected):
                assets.check_import(report, "tailscale", status, bad_names, self.lock)
        alias = "docker.io/library/import-alias@" + sha(b"alias")
        status["repoDigests"].append(alias)
        with self.assertRaises(assets.Rejected):
            assets.check_import(report, "tailscale", status,
                                names + [alias.removeprefix("docker.io/library/")], self.lock)
        assets.check_import(report, "tailscale", status, names + [alias], self.lock)

    def test_import_report_must_match_lock(self):
        report, status, names = self.binding()
        for role in assets.ROLES:
            for field, value in (("reference", "untrusted@" + sha(b"bad")),
                                 ("manifestDigest", sha(b"bad")),
                                 ("configDigest", "sha256:bad"), ("tag", "latest"),
                                 ("archiveSHA256", "bad"), ("archiveSHA256", None)):
                bad = copy.deepcopy(report)
                bad["images"][role][field] = value
                with self.assertRaises(assets.Rejected):
                    assets.check_import(bad, "tailscale", status, names, self.lock)
        # A self-consistent forged reference/config binding is not a lock pin.
        bad = copy.deepcopy(report)
        image = bad["images"]["tailscale"]
        image["manifestDigest"] = sha(b"forged")
        image["reference"] = assets.REPOSITORIES["tailscale"] + "@" + image["manifestDigest"]
        status["repoDigests"] = [image["reference"]]
        with self.assertRaises(assets.Rejected):
            assets.check_import(bad, "tailscale", status, names + [image["reference"]], self.lock)

    def test_import_report_shape(self):
        report, status, names = self.binding()
        for mutate in (lambda x: x.update(architecture="x86_64"),
                       lambda x: x.update(extra=True),
                       lambda x: x["images"].pop("coredns"),
                       lambda x: x["images"].update(extra={}),
                       lambda x: x["images"]["tailscale"].pop("configDigest")):
            bad = copy.deepcopy(report)
            mutate(bad)
            with self.assertRaises(assets.Rejected):
                assets.check_import(bad, "tailscale", status, names, self.lock)
        with self.assertRaises(assets.Rejected):
            assets.check_import(report, "controller", status, names, self.lock)

    def test_cli_success_and_import(self):
        report, status, names = self.binding()
        report_path = self.directory / "report.json"
        cri_path = self.directory / "cri.json"
        names_path = self.directory / "names.txt"
        report_path.write_bytes(encoded(report))
        cri_path.write_bytes(encoded({"status": status}))
        names_path.write_text("\n".join(names) + "\n")
        args = ["--check-import", str(report_path), "tailscale", str(cri_path), str(names_path)]
        with patch.object(assets, "LOCK_PATH", self.lock_path):
            self.assertEqual(self.cli([str(self.directory), "amd64"]), report)
            self.assertTrue(self.cli(args)["pinnedConfigAndReference"])
            cri_path.write_bytes(b'{"status":{},"status":{}}')
            self.cli(args, 2)
            cri_path.write_bytes(encoded({"status": status}))
            names_path.write_bytes(b'\xff')
            self.cli(args, 2)
        # Synthetic manifest pins must not pass the production CLI lock.
        names_path.write_text("\n".join(names))
        self.cli(args, 2)

    def test_production_import_cli(self):
        report, _, _ = self.binding()
        lock = assets.load_lock(assets.LOCK_PATH)
        for role, image in report["images"].items():
            image["manifestDigest"] = lock["images"][role]["platforms"]["amd64"]
            image["reference"] = lock["images"][role]["repository"] + "@" + image["manifestDigest"]
        image = report["images"]["coredns"]
        status = {"id": image["configDigest"], "repoDigests": [image["reference"]],
                  "repoTags": [image["tag"]]}
        report_path, cri_path, names_path = [self.directory / name for name in
                                           ("report.json", "cri.json", "names.txt")]
        report_path.write_bytes(encoded(report))
        cri_path.write_bytes(encoded({"status": status}))
        names_path.write_text(image["reference"] + "\n" + image["tag"] + "\n")
        result = subprocess.run(
            [sys.executable, "-B", "-I", str(Path(assets.__file__).resolve()),
             "--check-import", str(report_path), "coredns", str(cri_path), str(names_path)],
            cwd=self.directory, capture_output=True, text=True, check=False, timeout=10)
        self.assertEqual((result.returncode, result.stderr), (0, ""))
        self.assertEqual(json.loads(result.stdout), {
            "pinnedConfigAndReference": True, "allCRIReferencesExistLiterally": True})

    def test_cli_redaction_and_isolation(self):
        for args in ([], ["private-path"], ["private-path", "bad-arch"],
                     ["private-path", "amd64", "extra"],
                     ["--check-import", "private-path", "tailscale", "private-cri", "private-names"]):
            self.cli(args, 2)
        with patch.object(assets, "validate_assets", side_effect=OSError("private contents")):
            self.cli(["private-path", "amd64"], 2)
        result = subprocess.run(
            [sys.executable, "-B", "-I", str(Path(assets.__file__).resolve()),
             "private-path", "amd64"], cwd=self.directory, capture_output=True, text=True,
            check=False, timeout=10)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (2, "", "gateway assets rejected\n"))


if __name__ == "__main__":
    unittest.main()
