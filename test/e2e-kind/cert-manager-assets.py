#!/usr/bin/env python3
"""Offline, read-only validation of pinned cert-manager assets.

Archive hashes measure local bytes, not an upstream signature. OCI archives must
be uncompressed tar; compressed image layers remain opaque, hashed blobs. No
archive member is extracted or executed. GNU/PAX extensions are not accepted.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tomllib

VERSION = "v1.21.2"
CHART_SHA256 = "73a56e1728edd6c99f1f31082618c3259d279a76b7ebd3d4bdc5475c2442d34a"
ROLES = ("controller", "cainjector", "webhook", "startupapicheck")
ARCHES = ("amd64", "arm64")
REPOSITORIES = {role: "quay.io/jetstack/cert-manager-" + role for role in ROLES}
REPO_ROOT = Path(__file__).resolve().parents[2]
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_BLOB = 256 * 1024 * 1024
MAX_METADATA = 2 * 1024 * 1024
MAX_CHART = 64 * 1024 * 1024
MAX_LOCK = 64 * 1024
MAX_MEMBERS = 4096
CHUNK = 1024 * 1024
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
BLOB_PATH = re.compile(r"blobs/sha256/([0-9a-f]{64})\Z")
INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"
MANIFEST_MEDIA = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
CONFIG_MEDIA = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
LAYER_MEDIA = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.docker.image.rootfs.diff.tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}


class Rejected(ValueError):
    def __init__(self):
        super().__init__("cert-manager assets rejected")


def _require(condition):
    if not condition:
        raise Rejected()


def _keys(value, required, optional=()):
    _require(type(value) is dict)
    _require(set(required) <= value.keys() <= set(required) | set(optional))


def _digest(value):
    _require(type(value) is str and DIGEST.fullmatch(value) is not None)
    return value


def _json(data):
    _require(len(data) <= MAX_METADATA)

    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result)
            result[key] = value
        return result

    def constant(_):
        raise Rejected()

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected() from None


def _open_regular(path, limit):
    """Use no-follow opens for every component, including the final file."""
    parts = Path(path).absolute().parts
    _require(".." not in parts)
    directory = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY)
    fd = None
    try:
        for part in parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit)
        result = os.fdopen(fd, "rb")
        fd = None
        return result
    finally:
        os.close(directory)
        if fd is not None:
            os.close(fd)


def _validate_lock(lock):
    _keys(lock, {"version", "chartSHA256", "images"})
    _require(lock["version"] == VERSION and lock["chartSHA256"] == CHART_SHA256)
    _keys(lock["images"], ROLES)
    for role, image in lock["images"].items():
        _keys(image, {"repository", "indexDigest", "platforms"})
        _require(image["repository"] == REPOSITORIES[role])
        _digest(image["indexDigest"])
        _keys(image["platforms"], ARCHES)
        for digest in image["platforms"].values():
            _digest(digest)
    return lock


def _descriptor(value, blobs, media):
    _keys(value, {"mediaType", "digest", "size"}, {"annotations", "platform"})
    _require(type(value["mediaType"]) is str and value["mediaType"] in media)
    digest = _digest(value["digest"])
    _require(type(value["size"]) is int and 0 <= value["size"] <= MAX_BLOB)
    _require(digest in blobs and blobs[digest][0] == value["size"])
    if "annotations" in value:
        _require(type(value["annotations"]) is dict)
        _require(all(type(k) is str and type(v) is str
                     for k, v in value["annotations"].items()))
    return digest


def _archive(path, arch, image):
    """Validate one OCI archive against an already-validated image lock entry."""
    _require(arch in ARCHES)
    expected = image["platforms"][arch]
    tag = image["repository"] + ":" + VERSION
    blobs = {}
    metadata = {}
    seen = set()
    archive_hash = hashlib.sha256()
    total = 0
    payload = 0
    with _open_regular(path, MAX_ARCHIVE) as stream:
        def read(size):
            nonlocal total
            data = stream.read(size)
            total += len(data)
            _require(total <= MAX_ARCHIVE)
            archive_hash.update(data)
            return data

        while True:
            header = read(512)
            _require(len(header) == 512)
            if header == bytes(512):
                _require(read(512) == bytes(512))
                while True:
                    trailing = read(CHUNK)
                    if not trailing:
                        break
                    _require(not any(trailing))
                _require(total % 512 == 0)
                break
            try:
                member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            except (tarfile.TarError, ValueError, UnicodeError):
                raise Rejected() from None
            # Parse a single header only: never process extended headers, links,
            # sparse files or compression via tarfile's higher-level readers.
            _require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE))
            name = member.name
            _require(name not in seen and len(seen) < MAX_MEMBERS)
            seen.add(name)
            _require(0 <= member.size <= MAX_BLOB)
            if member.isdir():
                _require(name in {"blobs", "blobs/sha256"} and member.size == 0)
                continue
            match = BLOB_PATH.fullmatch(name)
            _require(match is not None or name in {"index.json", "oci-layout"})
            if match is None:
                _require(member.size <= MAX_METADATA)
            payload += member.size
            _require(payload <= MAX_ARCHIVE)
            offset = stream.tell()
            digest = hashlib.sha256()
            remaining = member.size
            chunks = []
            while remaining:
                data = read(min(CHUNK, remaining))
                _require(bool(data))
                remaining -= len(data)
                digest.update(data)
                if match is None:
                    chunks.append(data)
            padding = (-member.size) % 512
            _require(read(padding) == bytes(padding))
            if match:
                _require(digest.hexdigest() == match.group(1))
                blobs["sha256:" + match.group(1)] = (member.size, offset)
            else:
                metadata[name] = _json(b"".join(chunks))

        _require(set(metadata) == {"index.json", "oci-layout"})
        _require(metadata["oci-layout"] == {"imageLayoutVersion": "1.0.0"})
        index = metadata["index.json"]
        _keys(index, {"schemaVersion", "mediaType", "manifests"})
        _require(type(index["schemaVersion"]) is int and index["schemaVersion"] == 2)
        _require(index["mediaType"] == INDEX_MEDIA)
        _require(type(index["manifests"]) is list and len(index["manifests"]) == 1)
        descriptor = index["manifests"][0]
        _require(_descriptor(descriptor, blobs, MANIFEST_MEDIA) == expected)
        _require(descriptor.get("annotations", {}).get(
            "org.opencontainers.image.ref.name") == image["repository"] + "@" + expected)
        if "platform" in descriptor:
            platform = descriptor["platform"]
            _keys(platform, {"os", "architecture"})
            _require(platform == {"os": "linux", "architecture": arch})

        def read_blob(digest):
            size, offset = blobs[digest]
            _require(size <= MAX_METADATA)
            stream.seek(offset)
            data = stream.read(size)
            # Re-hash metadata after seeking to detect concurrent modifications.
            _require(len(data) == size and "sha256:" + hashlib.sha256(data).hexdigest() == digest)
            return _json(data)

        manifest = read_blob(expected)
        _keys(manifest, {"schemaVersion", "mediaType", "config", "layers"}, {"annotations"})
        _require(type(manifest["schemaVersion"]) is int and manifest["schemaVersion"] == 2)
        _require(manifest["mediaType"] == descriptor["mediaType"])
        config_digest = _descriptor(manifest["config"], blobs, CONFIG_MEDIA)
        referenced = {expected, config_digest}
        _require(type(manifest["layers"]) is list and len(manifest["layers"]) <= MAX_MEMBERS)
        for layer in manifest["layers"]:
            referenced.add(_descriptor(layer, blobs, LAYER_MEDIA))
        _require(set(blobs) == referenced)
        config = read_blob(config_digest)
        _require(type(config) is dict and config.get("os") == "linux"
                 and config.get("architecture") == arch)
    return {"reference": image["repository"] + "@" + expected, "tag": tag,
            "manifestDigest": expected, "configDigest": config_digest,
            "archiveSHA256": archive_hash.hexdigest()}


def validate_assets(cache: Path, arch: str, lock_path: Path) -> dict:
    """Validate all assets without network access, extraction or side effects."""
    _require(arch in ARCHES)
    cache = Path(cache)
    _require(not cache.resolve().is_relative_to(REPO_ROOT))
    with _open_regular(lock_path, MAX_LOCK) as stream:
        data = stream.read(MAX_LOCK + 1)
        _require(len(data) <= MAX_LOCK)
        lock = _validate_lock(_json(data))
    chart_hash = hashlib.sha256()
    with _open_regular(cache / "chart.tgz", MAX_CHART) as stream:
        size = 0
        while True:
            chunk = stream.read(CHUNK)
            if not chunk:
                break
            size += len(chunk)
            _require(size <= MAX_CHART)
            chart_hash.update(chunk)
    _require(chart_hash.hexdigest() == CHART_SHA256)
    images = {role: _archive(cache / (role + ".tar"), arch, lock["images"][role])
              for role in ROLES}
    return {"version": VERSION, "architecture": arch,
            "chartSHA256": CHART_SHA256, "images": images}


def snapshotter(data):
    _require(len(data) <= MAX_METADATA)
    config = tomllib.loads(data.decode("utf-8"))
    version = config.get("version")
    _require(type(version) is int)
    if version == 2:
        value = config["plugins"]["io.containerd.grpc.v1.cri"]["containerd"]["snapshotter"]
    elif version in (3, 4):
        value = config["plugins"]["io.containerd.cri.v1.images"]["snapshotter"]
    else:
        raise Rejected()
    _require(type(value) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", value) is not None)
    return value


def imported_binding(expected, status, names):
    _require(type(status) is dict and type(names) is list and 0 < len(names) <= MAX_MEMBERS)
    _require(all(type(name) is str and 0 < len(name) <= 1024 for name in names))
    _require(status.get("id") == _digest(expected["configDigest"]))
    digests, tags = status.get("repoDigests"), status.get("repoTags")
    _require(type(digests) is list and type(tags) is list and 0 < len(digests) + len(tags) <= 32)
    _require(expected["reference"] in digests)
    _require(all(type(ref) is str and ref in names for ref in digests + tags))


def bounded_read(path):
    with _open_regular(path, MAX_METADATA) as stream:
        data = stream.read(MAX_METADATA + 1)
        _require(len(data) <= MAX_METADATA)
        return data


def main(argv):
    try:
        if len(argv) == 2 and argv[0] == "--snapshotter":
            output = snapshotter(bounded_read(argv[1]))
        elif len(argv) == 5 and argv[0] == "--check-import":
            report = _json(bounded_read(argv[1]))
            role = argv[2]
            _require(role in ROLES and report["version"] == VERSION and report["architecture"] in ARCHES)
            image = report["images"][role]
            _require(image["reference"] == REPOSITORIES[role] + "@" + _digest(image["manifestDigest"]))
            status = _json(bounded_read(argv[3]))["status"]
            names = bounded_read(argv[4]).decode("utf-8").splitlines()
            imported_binding(image, status, names)
            output = json.dumps({"pinnedConfigAndReference": True, "allCRIReferencesExistLiterally": True})
        else:
            _require(len(argv) == 2)
            report = validate_assets(Path(argv[0]), argv[1],
                                     Path(__file__).with_name("cert-manager-images.json"))
            output = json.dumps(report, sort_keys=True)
    except Exception:
        print("cert-manager assets rejected", file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
