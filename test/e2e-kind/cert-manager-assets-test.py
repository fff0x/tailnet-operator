#!/usr/bin/env python3
"""Synthetic, offline tests. Run with python3 -B -I cert-manager-assets-test.py."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "cert_manager_assets", Path(__file__).with_name("cert-manager-assets.py"))
assets = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assets)


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class ArchiveFixture:
    """Complete OCI layout with one config, layer and pinned Docker manifest."""

    def __init__(self, arch="amd64", role="controller"):
        self.repository = assets.REPOSITORIES[role]
        self.config = encoded({"architecture": arch, "os": "linux", "config": {}})
        self.layer = b"opaque layer bytes: never decompress or execute"
        self.manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": self.descriptor(self.config, "application/vnd.docker.container.image.v1+json"),
            "layers": [self.descriptor(self.layer, "application/vnd.docker.image.rootfs.diff.tar.gzip")],
        }
        self.finish()

    @staticmethod
    def descriptor(data, media):
        return {"mediaType": media, "digest": sha(data), "size": len(data)}

    def finish(self):
        manifest_bytes = encoded(self.manifest)
        self.image = {"repository": self.repository, "indexDigest": "sha256:" + "f" * 64,
                      "platforms": {arch: sha(manifest_bytes) for arch in assets.ARCHES}}
        self.index = {
            "schemaVersion": 2, "mediaType": assets.INDEX_MEDIA,
            "manifests": [dict(self.descriptor(manifest_bytes, self.manifest["mediaType"]),
                               annotations={"org.opencontainers.image.ref.name":
                                            self.repository + "@" + sha(manifest_bytes)})],
        }
        self.files = {"blobs/sha256/" + sha(data)[7:]: data
                      for data in (self.config, self.layer, manifest_bytes)}
        self.files["oci-layout"] = encoded({"imageLayoutVersion": "1.0.0"})
        self.update_index()

    def update_index(self):
        self.files["index.json"] = encoded(self.index)

    def write(self, path, extra=()):
        with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
            for directory in ("blobs", "blobs/sha256"):
                member = tarfile.TarInfo(directory)
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            for name, data in self.files.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            for member, data in extra:
                archive.addfile(member, io.BytesIO(data))


class AssetsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cert-manager-assets-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.path = self.directory / "image.tar"
        self.fixture = ArchiveFixture()

    def validate(self, arch="amd64", extra=()):
        self.fixture.write(self.path, extra)
        return assets._archive(self.path, arch, self.fixture.image)

    def lock(self):
        return {"version": assets.VERSION, "chartSHA256": assets.CHART_SHA256,
                "images": {role: dict(copy.deepcopy(self.fixture.image),
                                      repository=assets.REPOSITORIES[role])
                           for role in assets.ROLES}}

    def test_complete_archive_report(self):
        result = self.validate()
        digest = self.fixture.image["platforms"]["amd64"]
        self.assertEqual(result, {
            "reference": self.fixture.repository + "@" + digest,
            "tag": self.fixture.repository + ":v1.21.2",
            "manifestDigest": digest, "configDigest": sha(self.fixture.config),
            "archiveSHA256": hashlib.sha256(self.path.read_bytes()).hexdigest(),
        })

    def test_arm64_archive(self):
        self.fixture = ArchiveFixture("arm64")
        self.assertEqual(self.validate("arm64")["configDigest"], sha(self.fixture.config))

    def test_oci_media(self):
        self.fixture.manifest["mediaType"] = "application/vnd.oci.image.manifest.v1+json"
        self.fixture.manifest["config"]["mediaType"] = "application/vnd.oci.image.config.v1+json"
        self.fixture.manifest["layers"][0]["mediaType"] = "application/vnd.oci.image.layer.v1.tar+gzip"
        self.fixture.finish()
        self.validate()

    def test_wrong_architecture(self):
        with self.assertRaises(assets.Rejected):
            self.validate("arm64")
        with self.assertRaises(assets.Rejected):
            self.validate("x86_64")

    def test_wrong_manifest_digest(self):
        self.fixture.image["platforms"]["amd64"] = "sha256:" + "0" * 64
        with self.assertRaises(assets.Rejected):
            self.validate()

    def test_wrong_blob_hash(self):
        self.fixture.files["blobs/sha256/" + sha(self.fixture.layer)[7:]] = b"tampered"
        with self.assertRaises(assets.Rejected):
            self.validate()

    def test_missing_config(self):
        del self.fixture.files["blobs/sha256/" + sha(self.fixture.config)[7:]]
        with self.assertRaises(assets.Rejected):
            self.validate()

    def test_missing_layer(self):
        del self.fixture.files["blobs/sha256/" + sha(self.fixture.layer)[7:]]
        with self.assertRaises(assets.Rejected):
            self.validate()

    def test_extra_blob(self):
        data = b"unreferenced"
        self.fixture.files["blobs/sha256/" + sha(data)[7:]] = data
        with self.assertRaises(assets.Rejected):
            self.validate()

    def test_size_mismatch(self):
        self.fixture.manifest["config"]["size"] += 1
        self.fixture.finish()
        with self.assertRaises(assets.Rejected):
            self.validate()

    def test_foreign_descriptor_url(self):
        self.fixture.manifest["layers"][0]["urls"] = ["https://unrelated.invalid/layer"]
        self.fixture.finish()
        with self.assertRaises(assets.Rejected):
            self.validate()

    def test_snapshotter_uses_actual_config_version(self):
        self.assertEqual(assets.snapshotter(b'version=2\n[plugins."io.containerd.grpc.v1.cri".containerd]\nsnapshotter="overlayfs"\n'), "overlayfs")
        for version in (3, 4):
            self.assertEqual(assets.snapshotter(('version=%d\n[plugins."io.containerd.cri.v1.images"]\nsnapshotter="native"\n' % version).encode()), "native")
        for bad in (b'version=5', b'version=true', b'version=3', b'version=3\n[plugins."io.containerd.cri.v1.images"]\nsnapshotter="../unsafe"'):
            with self.assertRaises((assets.Rejected, KeyError)):
                assets.snapshotter(bad)

    def test_imported_reference_normalization_mismatch(self):
        expected = {"configDigest": "sha256:" + "a" * 64, "reference": self.fixture.repository + "@sha256:" + "b" * 64}
        stable_alias = self.fixture.repository + "@sha256:" + "c" * 64
        status = {"id": expected["configDigest"], "repoDigests": [expected["reference"], stable_alias], "repoTags": []}
        assets.imported_binding(expected, status, [expected["reference"], stable_alias])
        status["repoDigests"][1] = "docker.io/library/import-2026-10-01@sha256:" + "c" * 64
        with self.assertRaises(assets.Rejected):
            assets.imported_binding(expected, status, [expected["reference"], "import-2026-10-01@sha256:" + "c" * 64])
        status["repoDigests"] = [expected["reference"]]
        status["id"] = "sha256:" + "d" * 64
        with self.assertRaises(assets.Rejected):
            assets.imported_binding(expected, status, [expected["reference"]])

    def test_mutable_tag_does_not_supply_digest_binding(self):
        self.fixture.index["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"] = (
            self.fixture.repository + ":" + assets.VERSION)
        self.fixture.update_index()
        with self.assertRaises(assets.Rejected):
            self.validate()

    def test_unrelated_repository(self):
        self.fixture.index["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"] = (
            "remote.invalid/unrelated:v1.21.2")
        self.fixture.update_index()
        with self.assertRaises(assets.Rejected):
            self.validate()
        lock = self.lock()
        lock["images"]["controller"]["repository"] = "remote.invalid/unrelated"
        with self.assertRaises(assets.Rejected):
            assets._validate_lock(lock)

    def test_index_shape(self):
        original = copy.deepcopy(self.fixture.index)
        for key, value in (("schemaVersion", True), ("schemaVersion", 1),
                           ("manifests", []), ("manifests", original["manifests"] * 2),
                           ("mediaType", "unknown")):
            with self.subTest(key=key, value=value):
                self.fixture.index = dict(original, **{key: value})
                self.fixture.update_index()
                with self.assertRaises(assets.Rejected):
                    self.validate()

    def test_index_platform(self):
        self.fixture.index["manifests"][0]["platform"] = {"os": "linux", "architecture": "arm64"}
        self.fixture.update_index()
        with self.assertRaises(assets.Rejected):
            self.validate()

    def test_invalid_layout(self):
        self.fixture.files["oci-layout"] = encoded({"imageLayoutVersion": "2.0.0"})
        with self.assertRaises(assets.Rejected):
            self.validate()

    def test_unsafe_paths(self):
        for name in ("../escape", "/escape", "blobs/../escape", "./index.json",
                     "blobs//sha256/" + "0" * 64, "unexpected", "blobs\\escape"):
            with self.subTest(name=name):
                member = tarfile.TarInfo(name)
                with self.assertRaises(assets.Rejected):
                    self.validate(extra=[(member, b"")])

    def test_links_and_special_members(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE,
                     tarfile.BLKTYPE, tarfile.FIFOTYPE, tarfile.XHDTYPE,
                     tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_SPARSE):
            with self.subTest(kind=kind):
                member = tarfile.TarInfo("unsafe")
                member.type = kind
                member.linkname = "index.json"
                with self.assertRaises(assets.Rejected):
                    self.validate(extra=[(member, b"")])

    def test_duplicate_member(self):
        for name in ("index.json", "blobs", "blobs/"):
            with self.subTest(name=name):
                member = tarfile.TarInfo(name)
                if name.startswith("blobs"):
                    member.type = tarfile.DIRTYPE
                with self.assertRaises(assets.Rejected):
                    self.validate(extra=[(member, b"")])

    def test_oversize_header(self):
        member = tarfile.TarInfo("blobs/sha256/" + "0" * 64)
        member.size = assets.MAX_BLOB + 1
        self.path.write_bytes(member.tobuf(format=tarfile.USTAR_FORMAT) + bytes(1024))
        with self.assertRaises(assets.Rejected):
            assets._archive(self.path, "amd64", self.fixture.image)

    def test_archive_metadata_and_count_limits(self):
        for constant, limit in (("MAX_ARCHIVE", 1024), ("MAX_METADATA", 20),
                                ("MAX_MEMBERS", 2), ("MAX_BLOB", 20)):
            with self.subTest(constant=constant), patch.object(assets, constant, limit):
                with self.assertRaises(assets.Rejected):
                    self.validate()

    def test_truncated_archive_and_trailing_data(self):
        self.fixture.write(self.path)
        original = self.path.read_bytes()
        for data in (original[:100], original[:-512] + b"x" * 512,
                     original + b"not another archive", original[:512]):
            self.path.write_bytes(data)
            with self.assertRaises(assets.Rejected):
                assets._archive(self.path, "amd64", self.fixture.image)

    def test_compressed_outer_archive(self):
        import gzip
        self.fixture.write(self.path)
        self.path.write_bytes(gzip.compress(self.path.read_bytes()))
        with self.assertRaises(assets.Rejected):
            assets._archive(self.path, "amd64", self.fixture.image)

    def test_bad_json(self):
        cases = (b'{"schemaVersion":2,"schemaVersion":2}', b'{', b'{}{}',
                 b'{"x":NaN}', b'{"x":Infinity}', b'\xff', b'[' * 2000)
        for number, data in enumerate(cases):
            with self.subTest(case=number):
                self.fixture.files["index.json"] = data
                with self.assertRaises(assets.Rejected):
                    self.validate()

    def test_invalid_config_and_manifest(self):
        for number, data in enumerate((b'{', encoded({"os": "windows", "architecture": "amd64"}),
                                       encoded({"os": "linux"}), b'[]')):
            with self.subTest(case=number):
                self.fixture = ArchiveFixture()
                self.fixture.config = data
                self.fixture.manifest["config"] = self.fixture.descriptor(
                    data, "application/vnd.docker.container.image.v1+json")
                self.fixture.finish()
                with self.assertRaises(assets.Rejected):
                    self.validate()
        self.fixture = ArchiveFixture()
        self.fixture.manifest["schemaVersion"] = True
        self.fixture.finish()
        with self.assertRaises(assets.Rejected):
            self.validate()

    def test_large_config_metadata(self):
        self.fixture.config = encoded({"os": "linux", "architecture": "amd64",
                                       "padding": "x" * 4096})
        self.fixture.manifest["config"] = self.fixture.descriptor(
            self.fixture.config, "application/vnd.docker.container.image.v1+json")
        self.fixture.finish()
        with patch.object(assets, "MAX_METADATA", 1024):
            with self.assertRaises(assets.Rejected):
                self.validate()

    def test_lock_schema(self):
        self.assertEqual(assets._validate_lock(self.lock()), self.lock())
        mutations = [
            lambda x: x.update(version="v1.21.1"),
            lambda x: x.update(chartSHA256="0" * 64),
            lambda x: x.update(extra=True),
            lambda x: x["images"].pop("webhook"),
            lambda x: x["images"].update(extra=x["images"]["controller"]),
            lambda x: x["images"]["controller"].update(indexDigest="sha256:bad"),
            lambda x: x["images"]["controller"]["platforms"].update(amd64="SHA256:" + "0" * 64),
            lambda x: x["images"]["controller"]["platforms"].pop("arm64"),
            lambda x: x["images"]["controller"]["platforms"].update(s390x="sha256:" + "0" * 64),
        ]
        for mutate in mutations:
            lock = self.lock()
            mutate(lock)
            with self.assertRaises(assets.Rejected):
                assets._validate_lock(lock)
        with self.assertRaises(assets.Rejected):
            assets._json(b'{"version":"v1.21.2","version":"v1.21.2"}')

    def test_symlinks_and_nonregular_files(self):
        self.fixture.write(self.path)
        link = self.directory / "link.tar"
        link.symlink_to(self.path)
        with self.assertRaises(OSError):
            assets._archive(link, "amd64", self.fixture.image)
        parent_link = self.directory / "link-directory"
        parent_link.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(OSError):
            assets._archive(parent_link / "image.tar", "amd64", self.fixture.image)
        fifo = self.directory / "fifo"
        os.mkfifo(fifo)
        for path in (fifo, self.directory):
            with self.assertRaises(assets.Rejected):
                assets._archive(path, "amd64", self.fixture.image)

    def test_repository_cache_rejected(self):
        with self.assertRaises(assets.Rejected):
            assets.validate_assets(assets.REPO_ROOT / "not-created", "amd64",
                                   self.directory / "not-created.json")

    def test_chart_mismatch(self):
        lock_path = self.directory / "lock.json"
        lock_path.write_bytes(encoded(self.lock()))
        (self.directory / "chart.tgz").write_bytes(b"not the pinned chart")
        with self.assertRaises(assets.Rejected):
            assets.validate_assets(self.directory, "amd64", lock_path)
        # The production chart pin is never replaced for a synthetic success.
        self.assertEqual(assets.CHART_SHA256,
                         "73a56e1728edd6c99f1f31082618c3259d279a76b7ebd3d4bdc5475c2442d34a")

    def test_cli_rejections_are_redacted(self):
        for arguments in ([], ["private-path"], ["private-path", "bad-architecture"],
                          ["private-path", "amd64", "extra"]):
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(assets.main(arguments), 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "cert-manager assets rejected\n")
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(assets, "validate_assets", side_effect=OSError("private contents")):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(assets.main(["private-path", "amd64"]), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "cert-manager assets rejected\n")


if __name__ == "__main__":
    unittest.main()
