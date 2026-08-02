"""Normative Control runtime policy parser and exact contract."""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any


MAX_POLICY_BYTES = 16 * 1024
EXPECTED_POLICY = {
    "architecture": "x86_64",
    "distribution": {
        "id": "ubuntu",
        "os_release_path": "/usr/lib/os-release",
        "version_id": "24.04",
    },
    "libc": {
        "family": "glibc",
        "minimum_version": "2.39",
    },
    "name": "control-runtime-v1",
    "node": {
        "archive_member": "node-v22.22.0-linux-x64/bin/node",
        "archive_name": "node-v22.22.0-linux-x64.tar.xz",
        "archive_sha256": (
            "9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37"
        ),
        "archive_size_bytes": 30_779_824,
        "binary_sha256": (
            "1bec56ef7cfa9a76f3e0b7c0a87f220eb73f23102b9c0b4c7529a3f7c3ce7c31"
        ),
        "binary_size_bytes": 123_405_064,
        "executable": (
            "/opt/tratto-control/toolchains/"
            "node-v22.22.0-linux-x64/bin/node"
        ),
        "provisioning": "root-owned-out-of-band",
        "runtime_user": "tratto-control-web",
        "source_url": (
            "https://nodejs.org/dist/v22.22.0/"
            "node-v22.22.0-linux-x64.tar.xz"
        ),
        "version": "v22.22.0",
    },
    "operating_system": "Linux",
    "python": {
        "abi": "cp312",
        "build_version": "3.12.13",
        "cache_tag": "cpython-312",
        "executable": "/usr/bin/python3.12",
        "implementation": "CPython",
        "major_minor": "3.12",
        "patch_compatibility": "same-major-minor",
        "py_debug": False,
        "runtime_users": [
            "tratto-control-api",
            "tratto-control-executor",
            "tratto-control-fleet-migrator",
            "tratto-control-migrator",
            "tratto-control-proxy",
            "tratto-control-web",
        ],
        "soabi": "cpython-312-x86_64-linux-gnu",
    },
    "root_validation": {
        "artifact_interpreter_execution": False,
        "installed_policy_path": "/etc/tratto-control/runtime-policy.json",
        "setpriv_executable": "/usr/bin/setpriv",
        "trusted_runtime_metadata_only": True,
    },
    "schema_version": 1,
}
class RuntimePolicyError(ValueError):
    """The runtime policy or its binding is invalid."""


def reject(message: str) -> None:
    raise RuntimePolicyError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            reject(f"runtime policy contains duplicate key: {key}")
        value[key] = item
    return value


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


EXPECTED_POLICY_SHA256 = hashlib.sha256(
    canonical_bytes(EXPECTED_POLICY)
).hexdigest()


def validate_value(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value != EXPECTED_POLICY:
        reject("runtime policy diverges from the reviewed exact contract")
    return value


def validate_bytes(raw: bytes) -> tuple[dict[str, Any], str]:
    if not 0 < len(raw) <= MAX_POLICY_BYTES:
        reject("runtime policy size is invalid")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda item: reject(
                f"runtime policy contains non-finite number: {item}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject("runtime policy is not valid UTF-8 JSON")
    if not isinstance(value, dict) or raw != canonical_bytes(value):
        reject("runtime policy must be canonical JSON")
    validate_value(value)
    return value, hashlib.sha256(raw).hexdigest()


def stat_snapshot(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def load(
    path: Path,
    *,
    required_uid: int | None = None,
    required_gid: int | None = None,
    allowed_modes: set[int] | None = None,
) -> tuple[dict[str, Any], str]:
    safe_modes = {0o400, 0o444, 0o600, 0o644}
    effective_modes = safe_modes if allowed_modes is None else allowed_modes
    if not effective_modes or not effective_modes <= safe_modes:
        reject("runtime policy allowed modes are invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        reject("runtime policy cannot be opened safely")
    try:
        info = os.fstat(descriptor)
        validate_file_metadata(
            info,
            required_uid=required_uid,
            required_gid=required_gid,
            allowed_modes=effective_modes,
        )
        raw = os.read(descriptor, MAX_POLICY_BYTES + 1)
        if (
            len(raw) != info.st_size
            or stat_snapshot(os.fstat(descriptor)) != stat_snapshot(info)
        ):
            reject("runtime policy changed while being read")
    finally:
        os.close(descriptor)
    return validate_bytes(raw)


def validate_file_metadata(
    info: os.stat_result,
    *,
    required_uid: int | None,
    required_gid: int | None,
    allowed_modes: set[int],
) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) not in allowed_modes
        or (required_uid is not None and info.st_uid != required_uid)
        or (required_gid is not None and info.st_gid != required_gid)
        or not 0 < info.st_size <= MAX_POLICY_BYTES
    ):
        reject(
            "runtime policy must be a bounded owned single-link file "
            f"with one of modes {sorted(oct(mode) for mode in allowed_modes)}"
        )


def reference(digest: str) -> dict[str, str]:
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        reject("runtime policy digest is invalid")
    return {"name": EXPECTED_POLICY["name"], "sha256": digest}


def validate_reference(value: Any, digest: str) -> None:
    if value != reference(digest):
        reject("component manifest does not bind the reviewed runtime policy")


def validate_embedded(raw: bytes | None, digest: str) -> None:
    expected_raw = canonical_bytes(EXPECTED_POLICY)
    if (
        raw is None
        or raw != expected_raw
        or hashlib.sha256(raw).hexdigest() != digest
        or digest != EXPECTED_POLICY_SHA256
    ):
        reject(
            "embedded runtime policy differs from the reviewed exact contract"
        )
