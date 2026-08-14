"""Normative schema-v4 Control component-manifest validation."""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

import runtime_policy as RUNTIME


HASH_RE = re.compile(r"^[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REVISION_RE = re.compile(r"^[a-z0-9][a-z0-9_]{2,63}$")
MAX_MANIFEST_BYTES = 64 * 1024
MIGRATION_LEGACY_KEYS = {
    "base_revision",
    "database_scope",
    "fleet_preflight_sha256",
    "head_revision",
    "mode",
    "tenant_catalog_count",
    "tenant_catalog_sha256",
    "tenant_fleet_base_revision",
}
MIGRATION_VERSIONED_KEYS = {
    "control_base_revisions",
    "control_schema_revision",
    "database_scope",
    "fleet_preflight_sha256",
    "head_revision",
    "mode",
    "schema_version",
    "tenant_catalog_count",
    "tenant_catalog_sha256",
    "tenant_fleet_base_revisions",
    "tenant_schema_revision",
}
APPROVED_LEGACY_MIGRATION_HEADS = {
    "f29controlexec",
    "f42customerlink",
}
APPROVED_VERSIONED_MIGRATIONS = {
    5: {
        "control_base_revisions": ["z2card181nf"],
        "control_schema_revision": "f51legalpublish",
        "head_revision": "f51legalpublish",
        "tenant_fleet_base_revisions": ["z2card181nf"],
        "tenant_schema_revision": "f49legalauth",
    },
    6: {
        "control_base_revisions": ["z2card181nf"],
        "control_schema_revision": "f52provisionactivate",
        "head_revision": "f52provisionactivate",
        "tenant_fleet_base_revisions": ["z2card181nf"],
        "tenant_schema_revision": "f52provisionactivate",
    },
}


class ComponentManifestError(ValueError):
    """A component manifest diverges from the signed runtime contract."""


def reject(message: str) -> None:
    raise ComponentManifestError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            reject(f"component manifest contains duplicate key: {key}")
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


def parse(raw: bytes, label: str) -> dict[str, Any]:
    if not 0 < len(raw) <= MAX_MANIFEST_BYTES:
        reject(f"{label} size is invalid")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda item: reject(
                f"{label} contains non-finite number: {item}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject(f"{label} is not valid UTF-8 JSON")
    if not isinstance(value, dict) or raw != canonical_bytes(value):
        reject(f"{label} must be canonical JSON")
    return value


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


def load(path: Path, label: str) -> tuple[bytes, dict[str, Any], str]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        reject(f"{label} cannot be opened safely")
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o022
            or not 0 < info.st_size <= MAX_MANIFEST_BYTES
        ):
            reject(f"{label} must be a bounded non-writable single-link file")
        raw = os.read(descriptor, MAX_MANIFEST_BYTES + 1)
        if (
            len(raw) != info.st_size
            or stat_snapshot(os.fstat(descriptor)) != stat_snapshot(info)
        ):
            reject(f"{label} changed while being read")
    finally:
        os.close(descriptor)
    return raw, parse(raw, label), hashlib.sha256(raw).hexdigest()


def validate_migration(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        reject("component migration contract must be an object")
    keys = set(value)
    if keys == MIGRATION_LEGACY_KEYS:
        _validate_legacy_migration(value)
    elif keys == MIGRATION_VERSIONED_KEYS:
        _validate_versioned_migration(value)
    else:
        reject("component migration contract has invalid keys")
    return value


def _validate_common_migration(value: dict[str, Any]) -> None:
    count = value["tenant_catalog_count"]
    if (
        value["database_scope"] != "control-and-tenant-fleet"
        or value["mode"] != "expand-only"
        or type(count) is not int
        or not 1 <= count <= 512
    ):
        reject("component migration contract is outside the approved chain")
    for key in ("tenant_catalog_sha256", "fleet_preflight_sha256"):
        if (
            not isinstance(value[key], str)
            or HASH_RE.fullmatch(value[key]) is None
        ):
            reject(f"component migration digest is invalid: {key}")


def _validate_legacy_migration(value: dict[str, Any]) -> None:
    _validate_common_migration(value)
    if (
        value["base_revision"] != "j1transpcod"
        or value["tenant_fleet_base_revision"] != "j1transpcod"
        or value["head_revision"] not in APPROVED_LEGACY_MIGRATION_HEADS
    ):
        reject("component migration contract is outside the approved chain")
    for key in ("base_revision", "tenant_fleet_base_revision", "head_revision"):
        if (
            not isinstance(value[key], str)
            or REVISION_RE.fullmatch(value[key]) is None
        ):
            reject(f"component migration revision is invalid: {key}")


def _validate_versioned_migration(value: dict[str, Any]) -> None:
    _validate_common_migration(value)
    schema_version = value.get("schema_version")
    if type(schema_version) is not int:
        reject("component migration schema_version must be an integer")
    expected = APPROVED_VERSIONED_MIGRATIONS.get(schema_version)
    if expected is None:
        reject("component migration schema_version is not supported")
    actual = {key: value.get(key) for key in expected}
    if actual != expected:
        reject("component migration contract is outside the approved chain")
    for key in (
        "control_schema_revision",
        "tenant_schema_revision",
        "head_revision",
    ):
        if (
            not isinstance(value[key], str)
            or REVISION_RE.fullmatch(value[key]) is None
        ):
            reject(f"component migration revision is invalid: {key}")


def validate(
    value: Any,
    *,
    kind: str,
    release_sha: str,
    approval_manifest_sha256: str,
    migration: dict[str, Any],
    runtime_policy_digest: str,
    requirements_lock_sha256: str | None = None,
) -> dict[str, Any]:
    if kind not in {"api", "ops", "web"}:
        reject("component kind is invalid")
    expected_keys = {
        "approval_manifest_sha256",
        "artifact_kind",
        "build",
        "migration",
        "release_sha",
        "runtime_policy",
        "schema_version",
    }
    if kind == "web":
        expected_keys.add("public_build")
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value["schema_version"] != 4
        or value["artifact_kind"] != f"tratto-control-{kind}"
        or value["release_sha"] != release_sha
        or value["approval_manifest_sha256"] != approval_manifest_sha256
        or value["migration"] != migration
    ):
        reject(f"{kind} component manifest diverges from signed identity")
    if SHA_RE.fullmatch(release_sha) is None:
        reject(f"{kind} release SHA is invalid")
    if HASH_RE.fullmatch(approval_manifest_sha256) is None:
        reject("approval manifest digest is invalid")
    validate_migration(value["migration"])
    try:
        RUNTIME.validate_reference(
            value["runtime_policy"],
            runtime_policy_digest,
        )
    except RUNTIME.RuntimePolicyError as error:
        reject(str(error))
    policy = RUNTIME.EXPECTED_POLICY
    build = value["build"]
    if kind == "api":
        if (
            not isinstance(build, dict)
            or set(build)
            != {"arch", "os", "python", "requirements_lock_sha256"}
            or build["arch"] != policy["architecture"]
            or build["os"] != policy["operating_system"]
            or build["python"] != policy["python"]["build_version"]
            or not isinstance(build["requirements_lock_sha256"], str)
            or HASH_RE.fullmatch(build["requirements_lock_sha256"]) is None
            or (
                requirements_lock_sha256 is not None
                and build["requirements_lock_sha256"]
                != requirements_lock_sha256
            )
        ):
            reject("API build/runtime policy diverges")
    elif kind == "ops":
        if (
            not isinstance(build, dict)
            or set(build)
            != {
                "arch",
                "os",
                "python",
                "shell",
                "tree_digest_algorithm",
            }
            or build["arch"] != policy["architecture"]
            or build["os"] != policy["operating_system"]
            or build["python"] != policy["python"]["build_version"]
            or build["shell"] != "bash"
            or build["tree_digest_algorithm"] != "tratto-tree-v1"
        ):
            reject("Ops build/runtime policy diverges")
    else:
        if (
            not isinstance(build, dict)
            or set(build) != {"arch", "node", "os"}
            or build["arch"] != policy["architecture"]
            or build["os"] != policy["operating_system"]
            or build["node"] != policy["node"]["version"]
            or value["public_build"]
            != {
                "NEXT_PUBLIC_API_URL": "/api",
                "NEXT_PUBLIC_APP_SURFACE": "control",
            }
        ):
            reject("Web build/runtime policy diverges")
    return value


def validate_set(
    manifests: dict[str, dict[str, Any]],
    *,
    api_sha: str,
    web_sha: str,
    approval_manifest_sha256: str,
    migration: dict[str, Any],
    runtime_policy_digest: str,
    requirements_lock_sha256: str,
) -> None:
    if set(manifests) != {"api", "ops", "web"}:
        reject("component manifest set must contain API, Ops, and Web")
    for kind in ("api", "ops", "web"):
        validate(
            manifests[kind],
            kind=kind,
            release_sha=api_sha if kind in {"api", "ops"} else web_sha,
            approval_manifest_sha256=approval_manifest_sha256,
            migration=migration,
            runtime_policy_digest=runtime_policy_digest,
            requirements_lock_sha256=(
                requirements_lock_sha256 if kind == "api" else None
            ),
        )
    if (
        manifests["api"]["runtime_policy"]
        != manifests["ops"]["runtime_policy"]
        or manifests["api"]["runtime_policy"]
        != manifests["web"]["runtime_policy"]
        or manifests["api"]["migration"] != manifests["ops"]["migration"]
        or manifests["api"]["migration"] != manifests["web"]["migration"]
    ):
        reject("component manifests do not share one runtime/fleet contract")
