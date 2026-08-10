#!/usr/bin/env python3
"""Independent exact-byte contract for security-critical product sources.

The controller owns this verifier and the reviewed contract.  The product
repository cannot satisfy it by merely retaining strings that look like a
feature: every listed source must match the exact reviewed bytes in both the
immutable checkout and the prepared runtime tree.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import stat
import sys
from pathlib import Path
from typing import Any


sys.dont_write_bytecode = True


HASH_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[a-z0-9][a-z0-9_]{2,63}$")
MAX_CONTRACT_BYTES = 64 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_FILES = 64
EXPECTED_KEYS = {
    "artifact_kind",
    "contract",
    "files",
    "migration_head",
    "schema_version",
}


class ProductSourceContractError(ValueError):
    """The reviewed source contract or observed product tree is invalid."""


def reject(message: str) -> None:
    raise ProductSourceContractError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            reject(f"source contract contains duplicate key: {key}")
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


def _snapshot(info: os.stat_result) -> tuple[int, ...]:
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


def _read_regular(path: Path, *, label: str, maximum: int) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError:
        reject(f"{label} is unavailable or unsafe")
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_mode & 0o022
            or not 0 < info.st_size <= maximum
        ):
            reject(f"{label} is not a bounded immutable regular file")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                reject(f"{label} changed while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if _snapshot(os.fstat(descriptor)) != _snapshot(info):
            reject(f"{label} changed while being read")
        return raw
    except OSError:
        reject(f"{label} cannot be read safely")
    finally:
        os.close(descriptor)


def _canonical_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith(("/", "-"))
        or "\x00" in value
        or "\\" in value
    ):
        reject("source contract path is invalid")
    normalized = posixpath.normpath(value)
    if (
        normalized in {"", ".", ".."}
        or normalized.startswith("../")
        or normalized != value
    ):
        reject("source contract path is not canonical")
    return value


def parse(raw: bytes) -> dict[str, Any]:
    if not 0 < len(raw) <= MAX_CONTRACT_BYTES:
        reject("source contract size is invalid")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda item: reject(
                f"source contract contains non-finite number: {item}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject("source contract is not valid UTF-8 JSON")
    if not isinstance(value, dict) or raw != canonical_bytes(value):
        reject("source contract must be canonical JSON")
    if (
        set(value) != EXPECTED_KEYS
        or value["schema_version"] != 1
        or value["contract"] != "tratto-product-source-exact-bytes"
        or value["artifact_kind"] != "api"
        or not isinstance(value["migration_head"], str)
        or REVISION_RE.fullmatch(value["migration_head"]) is None
        or not isinstance(value["files"], dict)
        or not 1 <= len(value["files"]) <= MAX_FILES
    ):
        reject("source contract shape is invalid")
    normalized_files: dict[str, str] = {}
    for path, digest in value["files"].items():
        canonical = _canonical_path(path)
        if (
            not isinstance(digest, str)
            or HASH_RE.fullmatch(digest) is None
        ):
            reject(f"source contract digest is invalid: {canonical}")
        normalized_files[canonical] = digest
    if list(value["files"]) != sorted(
        value["files"], key=lambda item: item.encode("utf-8")
    ):
        reject("source contract files are not bytewise ordered")
    return value


def load(path: Path) -> tuple[dict[str, Any], str]:
    raw = _read_regular(
        path,
        label="product source contract",
        maximum=MAX_CONTRACT_BYTES,
    )
    return parse(raw), hashlib.sha256(raw).hexdigest()


def _root(path: Path, *, label: str) -> Path:
    absolute = path.absolute()
    try:
        resolved = absolute.resolve(strict=True)
    except OSError:
        reject(f"{label} root is unavailable")
    if resolved != absolute or absolute.is_symlink() or not absolute.is_dir():
        reject(f"{label} root is unsafe")
    return absolute


def verify(
    contract: dict[str, Any],
    *,
    repository_root: Path,
    bundle_root: Path,
    expected_migration_head: str,
    required_files: frozenset[str] = frozenset(),
) -> dict[str, str]:
    """Verify exact reviewed bytes in source and packaged runtime roots."""

    if contract.get("migration_head") != expected_migration_head:
        reject("source contract migration head diverges from approval")
    normalized_required = {_canonical_path(path) for path in required_files}
    missing = normalized_required - set(contract["files"])
    if missing:
        reject(
            "source contract omits required security-critical source: "
            f"{min(missing, key=lambda item: item.encode('utf-8'))}"
        )
    repository = _root(repository_root, label="repository")
    bundle = _root(bundle_root, label="bundle")
    observed: dict[str, str] = {}
    for relative, expected in contract["files"].items():
        source_raw = _read_regular(
            repository / relative,
            label=f"repository source {relative}",
            maximum=MAX_SOURCE_BYTES,
        )
        runtime_raw = _read_regular(
            bundle / relative,
            label=f"runtime source {relative}",
            maximum=MAX_SOURCE_BYTES,
        )
        source_digest = hashlib.sha256(source_raw).hexdigest()
        runtime_digest = hashlib.sha256(runtime_raw).hexdigest()
        if source_digest != expected or runtime_digest != expected:
            reject(f"security-critical source diverges: {relative}")
        if source_raw != runtime_raw:
            reject(f"runtime source bytes diverge from checkout: {relative}")
        observed[relative] = expected
    return observed
