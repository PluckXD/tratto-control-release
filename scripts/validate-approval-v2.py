#!/usr/bin/env python3
"""Fail-closed validation for a Control production-v2 authorization.

This validator is intentionally self-contained.  It validates the canonical
authorization document and its immutable-controller and append-only-ledger
bindings without importing mutable controller code or performing network I/O.
External verifiers remain responsible for proving the referenced GitHub and
Git objects before a signer consumes the validated authorization.
"""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import base64
import binascii
import datetime as dt
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping


SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RELEASE_ID_RE = re.compile(
    r"^ctl-([0-9]{8}T[0-9]{6}Z)-([a-z0-9][a-z0-9-]{2,31})$"
)
REVISION_RE = re.compile(r"^[a-z0-9][a-z0-9_]{2,63}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22,86}$")
TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-(0[1-9]|1[0-2])-"
    r"(0[1-9]|[12][0-9]|3[01])T"
    r"([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
CONTROLLER_TAG_RE = re.compile(
    r"^refs/tags/control-controller-v6\."
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)

EXPECTED_REPOSITORIES = {
    "api": "PluckXD/tratto-api",
    "ops": "PluckXD/tratto-api",
    "web": "PluckXD/tratto-web",
}
EXPECTED_REF = "refs/heads/main"
EXPECTED_CONTROLLER_REPOSITORY = "PluckXD/tratto-control-release"
EXPECTED_LEDGER_REPOSITORY = "PluckXD/tratto-control-release-ledger"
EXPECTED_WORKFLOW_PATH = ".github/workflows/control-release.yml"
EXPECTED_POLICY_PATH = "policies/control-production-v2.json"
EXPECTED_POLICY_NAME = "control-production-v2"

TOP_KEYS = {
    "api",
    "controller",
    "expires_at",
    "issued_at",
    "ledger",
    "migration",
    "nonce",
    "ops",
    "policy",
    "release_id",
    "schema_version",
    "web",
}
COMPONENT_KEYS = {
    "approved_ref",
    "commit_sha",
    "repository",
    "required_ancestors",
}
CONTROLLER_KEYS = {
    "commit_sha",
    "immutable_release_id",
    "repository",
    "repository_id",
    "signer_verifier_sha256",
    "tag_object_sha",
    "tag_ref",
    "workflow_path",
    "workflow_sha256",
}
LEDGER_KEYS = {
    "genesis_sha",
    "parent_commit_sha",
    "previous_manifest_sha256",
    "ref",
    "repository",
    "repository_id",
    "sequence",
}
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
POLICY_KEYS = {"digest_sha256", "name", "path", "repository"}

ZERO_SHA256 = "0" * 64
MAX_FILE_BYTES = 64 * 1024
MAX_VALIDITY = dt.timedelta(hours=24)
MAX_FUTURE_SKEW = dt.timedelta(minutes=5)
MAX_LEDGER_SEQUENCE = 100_000


class ApprovalV2Error(ValueError):
    """The v2 authorization is ambiguous or violates release policy."""


def reject(message: str) -> None:
    raise ApprovalV2Error(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            reject(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def parse_canonical_json(raw: bytes) -> dict[str, Any]:
    if not 0 < len(raw) <= MAX_FILE_BYTES:
        reject("authorization has an invalid size")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        reject("authorization must be UTF-8")
    try:
        value = json.loads(
            decoded,
            object_pairs_hook=unique_object,
            parse_constant=lambda constant: reject(
                f"non-finite number is forbidden: {constant}"
            ),
        )
    except json.JSONDecodeError as error:
        reject(
            "authorization has invalid JSON at "
            f"line {error.lineno}, column {error.colno}"
        )
    if not isinstance(value, dict):
        reject("authorization root must be an object")
    if raw != canonical_bytes(value):
        reject("authorization must be canonical JSON")
    return value


def exact_keys(
    value: Any,
    expected: set[str],
    label: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        reject(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        reject(
            f"{label} keys diverge; "
            f"missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        reject(f"{label} must be a string")
    return value


def require_pattern(
    value: Any,
    pattern: re.Pattern[str],
    label: str,
) -> str:
    text = require_string(value, label)
    if pattern.fullmatch(text) is None:
        reject(f"{label} has invalid format")
    return text


def require_positive_integer(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        reject(f"{label} must be a positive integer")
    return value


def parse_utc(value: Any, label: str) -> dt.datetime:
    text = require_string(value, label)
    if TIMESTAMP_RE.fullmatch(text) is None:
        reject(f"{label} must be whole-second RFC3339 UTC")
    try:
        parsed = dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        reject(f"{label} is not a real calendar timestamp")
    return parsed.replace(tzinfo=dt.timezone.utc)


def validate_nonce(value: Any) -> str:
    nonce = require_pattern(value, NONCE_RE, "nonce")
    padding = "=" * (-len(nonce) % 4)
    try:
        decoded = base64.b64decode(
            nonce + padding,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error):
        reject("nonce is not canonical base64url")
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != nonce or len(decoded) < 16:
        reject("nonce must encode at least 128 bits as canonical base64url")
    return nonce


def validate_component(name: str, value: Any) -> None:
    component = exact_keys(value, COMPONENT_KEYS, name)
    if component["repository"] != EXPECTED_REPOSITORIES[name]:
        reject(f"{name}.repository is not allowed")
    if component["approved_ref"] != EXPECTED_REF:
        reject(f"{name}.approved_ref must be refs/heads/main")
    commit = require_pattern(
        component["commit_sha"],
        SHA1_RE,
        f"{name}.commit_sha",
    )
    ancestors = component["required_ancestors"]
    if (
        not isinstance(ancestors, list)
        or isinstance(ancestors, (str, bytes))
        or not 1 <= len(ancestors) <= 32
    ):
        reject(f"{name}.required_ancestors must contain 1..32 SHAs")
    checked = [
        require_pattern(item, SHA1_RE, f"{name}.required_ancestors[{index}]")
        for index, item in enumerate(ancestors)
    ]
    if len(checked) != len(set(checked)):
        reject(f"{name}.required_ancestors contains duplicates")
    if commit in checked:
        reject(f"{name}.commit_sha cannot duplicate a required ancestor")


def validate_controller(value: Any) -> None:
    controller = exact_keys(value, CONTROLLER_KEYS, "controller")
    if controller["repository"] != EXPECTED_CONTROLLER_REPOSITORY:
        reject("controller.repository is not allowed")
    require_positive_integer(
        controller["repository_id"],
        "controller.repository_id",
    )
    require_pattern(controller["tag_ref"], CONTROLLER_TAG_RE, "controller.tag_ref")
    require_pattern(
        controller["tag_object_sha"],
        SHA1_RE,
        "controller.tag_object_sha",
    )
    require_pattern(
        controller["commit_sha"],
        SHA1_RE,
        "controller.commit_sha",
    )
    require_positive_integer(
        controller["immutable_release_id"],
        "controller.immutable_release_id",
    )
    if controller["workflow_path"] != EXPECTED_WORKFLOW_PATH:
        reject("controller.workflow_path is not allowed")
    require_pattern(
        controller["workflow_sha256"],
        SHA256_RE,
        "controller.workflow_sha256",
    )
    require_pattern(
        controller["signer_verifier_sha256"],
        SHA256_RE,
        "controller.signer_verifier_sha256",
    )


def validate_ledger(value: Any) -> None:
    ledger = exact_keys(value, LEDGER_KEYS, "ledger")
    if ledger["repository"] != EXPECTED_LEDGER_REPOSITORY:
        reject("ledger.repository is not allowed")
    require_positive_integer(ledger["repository_id"], "ledger.repository_id")
    if ledger["ref"] != EXPECTED_REF:
        reject("ledger.ref must be refs/heads/main")
    genesis = require_pattern(
        ledger["genesis_sha"],
        SHA1_RE,
        "ledger.genesis_sha",
    )
    parent = require_pattern(
        ledger["parent_commit_sha"],
        SHA1_RE,
        "ledger.parent_commit_sha",
    )
    previous = require_pattern(
        ledger["previous_manifest_sha256"],
        SHA256_RE,
        "ledger.previous_manifest_sha256",
    )
    sequence = require_positive_integer(ledger["sequence"], "ledger.sequence")
    if sequence > MAX_LEDGER_SEQUENCE:
        reject(f"ledger.sequence cannot exceed {MAX_LEDGER_SEQUENCE}")
    if sequence == 1:
        if parent != genesis:
            reject("ledger sequence 1 must have genesis as its parent")
        if previous != ZERO_SHA256:
            reject("ledger sequence 1 must use the zero previous manifest hash")
    else:
        if parent == genesis:
            reject("ledger sequence greater than 1 cannot directly follow genesis")
        if previous == ZERO_SHA256:
            reject(
                "ledger sequence greater than 1 must bind a previous manifest"
            )


def validate_migration(value: Any) -> None:
    if not isinstance(value, dict):
        reject("migration must be an object")
    keys = set(value)
    if keys == MIGRATION_LEGACY_KEYS:
        _validate_legacy_migration(value)
        return
    if keys == MIGRATION_VERSIONED_KEYS:
        _validate_versioned_migration(value)
        return
    reject("migration keys diverge from supported contracts")


def _validate_common_migration(migration: dict[str, Any]) -> None:
    if migration["database_scope"] != "control-and-tenant-fleet":
        reject("migration.database_scope must be control-and-tenant-fleet")
    if migration["mode"] != "expand-only":
        reject("migration.mode must be expand-only")
    require_pattern(
        migration["tenant_catalog_sha256"],
        SHA256_RE,
        "migration.tenant_catalog_sha256",
    )
    require_pattern(
        migration["fleet_preflight_sha256"],
        SHA256_RE,
        "migration.fleet_preflight_sha256",
    )
    count = migration["tenant_catalog_count"]
    if type(count) is not int or not 1 <= count <= 512:
        reject("migration tenant catalog count is invalid")


def _validate_legacy_migration(migration: dict[str, Any]) -> None:
    _validate_common_migration(migration)
    base = require_pattern(
        migration["base_revision"],
        REVISION_RE,
        "migration.base_revision",
    )
    head = require_pattern(
        migration["head_revision"],
        REVISION_RE,
        "migration.head_revision",
    )
    tenant_base = require_pattern(
        migration["tenant_fleet_base_revision"],
        REVISION_RE,
        "migration.tenant_fleet_base_revision",
    )
    if (
        base != "j1transpcod"
        or tenant_base != "j1transpcod"
        or head != "f29controlexec"
    ):
        reject("migration revision chain is not approved")


def _validate_versioned_migration(migration: dict[str, Any]) -> None:
    _validate_common_migration(migration)
    schema_version = migration.get("schema_version")
    if type(schema_version) is not int:
        reject("migration.schema_version must be an integer")
    expected = APPROVED_VERSIONED_MIGRATIONS.get(schema_version)
    if expected is None:
        reject("migration.schema_version is not supported")
    actual = {key: migration.get(key) for key in expected}
    if actual != expected:
        reject("migration revision chain is not approved")
    for key in (
        "control_schema_revision",
        "tenant_schema_revision",
        "head_revision",
    ):
        require_pattern(migration[key], REVISION_RE, f"migration.{key}")


def validate_policy(value: Any) -> None:
    policy = exact_keys(value, POLICY_KEYS, "policy")
    if policy["repository"] != EXPECTED_CONTROLLER_REPOSITORY:
        reject("policy.repository is not allowed")
    if policy["path"] != EXPECTED_POLICY_PATH:
        reject("policy.path is not allowed")
    if policy["name"] != EXPECTED_POLICY_NAME:
        reject("policy.name is not allowed")
    require_pattern(
        policy["digest_sha256"],
        SHA256_RE,
        "policy.digest_sha256",
    )


def validate_shape(
    value: Mapping[str, Any],
    *,
    now: dt.datetime,
    historical: bool = False,
) -> dict[str, Any]:
    authorization = exact_keys(value, TOP_KEYS, "authorization")
    if (
        type(authorization["schema_version"]) is not int
        or authorization["schema_version"] != 2
    ):
        reject("schema_version must be integer 2")
    release_id = require_pattern(
        authorization["release_id"],
        RELEASE_ID_RE,
        "release_id",
    )
    validate_nonce(authorization["nonce"])
    issued_at = parse_utc(authorization["issued_at"], "issued_at")
    expires_at = parse_utc(authorization["expires_at"], "expires_at")
    if expires_at <= issued_at or expires_at - issued_at > MAX_VALIDITY:
        reject("authorization validity must be between 1 second and 24 hours")
    match = RELEASE_ID_RE.fullmatch(release_id)
    assert match is not None
    if match.group(1) != issued_at.strftime("%Y%m%dT%H%M%SZ"):
        reject("release_id timestamp must equal issued_at")
    if type(historical) is not bool:
        reject("historical validation mode must be boolean")
    if now.tzinfo != dt.timezone.utc:
        reject("validator clock must be timezone-aware UTC")
    if not historical:
        if issued_at > now + MAX_FUTURE_SKEW:
            reject("authorization issued_at is too far in the future")
        if expires_at <= now:
            reject("authorization is expired")

    validate_component("api", authorization["api"])
    validate_component("web", authorization["web"])
    validate_component("ops", authorization["ops"])
    api = authorization["api"]
    ops = authorization["ops"]
    assert isinstance(api, Mapping) and isinstance(ops, Mapping)
    if (
        api["repository"] == ops["repository"]
        and api["commit_sha"] != ops["commit_sha"]
    ):
        reject("api and ops must pin the same commit in their shared repository")
    validate_controller(authorization["controller"])
    validate_ledger(authorization["ledger"])
    validate_migration(authorization["migration"])
    validate_policy(authorization["policy"])
    return dict(authorization)


def validate_bytes(
    raw: bytes,
    *,
    now: dt.datetime | None = None,
    historical: bool = False,
) -> dict[str, Any]:
    """Validate canonical authorization bytes using a trusted UTC clock."""

    current = (
        dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        if now is None
        else now
    )
    value = parse_canonical_json(raw)
    return validate_shape(value, now=current, historical=historical)


def read_approval(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    absolute = path.absolute()
    try:
        if absolute.resolve(strict=True) != absolute:
            reject("authorization path must not traverse symlinks")
        before = absolute.lstat()
        descriptor = os.open(absolute, flags)
    except ApprovalV2Error:
        raise
    except OSError as error:
        reject(f"cannot open authorization safely: {error.strerror}")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o644
            or metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            reject(
                "authorization must be a single-link 0644 regular file "
                "owned by the runner"
            )
        if not 0 < metadata.st_size <= MAX_FILE_BYTES:
            reject("authorization has an invalid size")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(65536, MAX_FILE_BYTES + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                reject("authorization exceeds maximum size")
        after = os.fstat(descriptor)
        if (
            total != metadata.st_size
            or (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            != (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
        ):
            reject("authorization changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def validate_file(
    path: Path,
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    return validate_bytes(read_approval(path), now=now)


class FailClosedParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        reject(f"invalid command line: {message}")


def main(arguments: list[str] | None = None) -> int:
    parser = FailClosedParser()
    parser.add_argument("approval", type=Path)
    try:
        args = parser.parse_args(arguments)
        value = validate_file(args.approval)
    except ApprovalV2Error as error:
        print(f"release authorization v2 rejected: {error}", file=sys.stderr)
        return 78
    print(
        json.dumps(
            {
                "api_sha": value["api"]["commit_sha"],
                "controller_commit_sha": value["controller"]["commit_sha"],
                "controller_tag_ref": value["controller"]["tag_ref"],
                "ledger_parent_commit_sha": value["ledger"][
                    "parent_commit_sha"
                ],
                "ledger_sequence": value["ledger"]["sequence"],
                "ops_sha": value["ops"]["commit_sha"],
                "policy_sha256": value["policy"]["digest_sha256"],
                "release_id": value["release_id"],
                "web_sha": value["web"]["commit_sha"],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
