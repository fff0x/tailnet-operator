#!/usr/bin/env python3
"""Offline, read-only validation of pinned gateway OCI archives.

Reuse the cert-manager validator's bounded, no-extraction archive parser and
literal CRI binding checks. Archive hashes measure local bytes, not signatures.
"""

import importlib.util
import json
from pathlib import Path
import sys

SPEC = importlib.util.spec_from_file_location(
    "gateway_cert_manager_assets", Path(__file__).with_name("cert-manager-assets.py"))
shared = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shared)

_archive = shared._archive
bounded_read = shared.bounded_read
_json = shared._json
_keys = shared._keys
_digest = shared._digest
_open_regular = shared._open_regular
imported_binding = shared.imported_binding
_require = shared._require
Rejected = shared.Rejected
ARCHES = shared.ARCHES
REPO_ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = Path(__file__).with_name("gateway-images.json")
ROLES = ("tailscale", "coredns")
REPOSITORIES = {"tailscale": "ghcr.io/tailscale/tailscale",
                "coredns": "docker.io/coredns/coredns"}
VERSIONS = {"tailscale": "v1.104.4", "coredns": "1.15.0"}


def _validate_lock(lock):
    _keys(lock, {"images"})
    _keys(lock["images"], ROLES)
    for role, image in lock["images"].items():
        _keys(image, {"repository", "version", "indexDigest", "platforms"})
        _require(image["repository"] == REPOSITORIES[role])
        _require(image["version"] == VERSIONS[role])
        _digest(image["indexDigest"])
        _keys(image["platforms"], ARCHES)
        for digest in image["platforms"].values():
            _digest(digest)
    return lock


def load_lock(path):
    with _open_regular(path, shared.MAX_LOCK) as stream:
        data = stream.read(shared.MAX_LOCK + 1)
        _require(len(data) <= shared.MAX_LOCK)
    return _validate_lock(_json(data))


def validate_assets(cache: Path, arch: str, lock_path: Path) -> dict:
    _require(arch in ARCHES)
    cache = Path(cache)
    _require(not cache.resolve().is_relative_to(REPO_ROOT))
    lock = load_lock(lock_path)
    images = {}
    for role in ROLES:
        image = lock["images"][role]
        result = _archive(cache / (role + ".tar"), arch, image)
        # The shared parser's tag uses the cert-manager version. Only the
        # digest reference participates in archive validation; replace the tag.
        result["tag"] = image["repository"] + ":" + image["version"]
        images[role] = result
    return {"architecture": arch, "images": images}


def check_import(report, role, status, names, lock):
    lock = _validate_lock(lock)
    _keys(report, {"architecture", "images"})
    arch = report["architecture"]
    _require(arch in ARCHES and role in ROLES)
    _keys(report["images"], ROLES)
    for name, image in report["images"].items():
        _keys(image, {"reference", "manifestDigest", "configDigest", "archiveSHA256", "tag"})
        pinned = lock["images"][name]
        _require(_digest(image["manifestDigest"]) == pinned["platforms"][arch])
        _require(image["reference"] == pinned["repository"] + "@" + image["manifestDigest"])
        _require(image["tag"] == pinned["repository"] + ":" + pinned["version"])
        _digest(image["configDigest"])
        _require(type(image["archiveSHA256"]) is str)
        _digest("sha256:" + image["archiveSHA256"])
    imported_binding(report["images"][role], status, names)
    return {"pinnedConfigAndReference": True, "allCRIReferencesExistLiterally": True}


def main(argv):
    try:
        if len(argv) == 5 and argv[0] == "--check-import":
            report = _json(bounded_read(argv[1]))
            status = _json(bounded_read(argv[3]))["status"]
            names = bounded_read(argv[4]).decode("utf-8").splitlines()
            output = check_import(report, argv[2], status, names, load_lock(LOCK_PATH))
        else:
            _require(len(argv) == 2)
            output = validate_assets(Path(argv[0]), argv[1], LOCK_PATH)
        output = json.dumps(output, sort_keys=True)
    except Exception:
        print("gateway assets rejected", file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
