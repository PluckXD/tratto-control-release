#!/usr/bin/env python3
"""Validate the exact, fail-closed Control production policy v2.

The checked-in policy is an intentionally unavailable template: every
environment-specific trust pin is empty or zero.  Production activation
requires two deliberate changes reviewed together:

* replace every placeholder in ``control-production-v2.json``; and
* replace ``PRODUCTION_AUDITED_PINS`` below with the independently audited
  values.

The CLI never accepts pins from arguments or the environment.  The pure
``validate_bytes`` API accepts an explicit, typed ``AuditedPins`` value so
offline tests and reviewers can validate a prospective configured document
without weakening the production command.

The controller commit SHA, concrete tag ref, annotated-tag object SHA and
immutable release ID are intentionally absent.  A policy stored inside the
controller commit cannot non-circularly pin those future identities; approval
and envelope documents must bind them to independently verified GitHub
evidence instead.
"""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_POLICY_BYTES = 64 * 1024
CONTROLLER_REPOSITORY = "PluckXD/tratto-control-release"
CONTROLLER_TAG_PREFIX = "refs/tags/control-controller-v6."
CONTROLLER_TAG_PATTERN = (
    r"^refs/tags/control-controller-v6\."
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
CONTROLLER_WORKFLOW_PATH = ".github/workflows/control-release.yml"
LEDGER_REPOSITORY = "PluckXD/tratto-control-release-ledger"
LEDGER_REF = "refs/heads/main"
RUNTIME_POLICY_SHA256 = (
    "c34e2b5655ed2df968b4f976db223bb9653a58e4aacce65f28300cb06b5dc5ae"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")

TOP_KEYS = {
    "approval_max_seconds",
    "approval_path_prefix",
    "approval_schema_version",
    "artifact_transport",
    "carrier_authorizes_release",
    "carrier_repository",
    "carrier_trust",
    "controller",
    "controller_repository",
    "ledger",
    "migration_database_scope",
    "product_repositories",
    "required_ref",
    "runtime_policy",
    "schema_version",
    "signer_allows_product_credentials",
    "signer_allows_source_checkout",
}
CONTROLLER_KEYS = {
    "immutable_release_required",
    "repository",
    "repository_id",
    "require_owner_enforcement",
    "signed_annotated_tag_required",
    "tag_ref_pattern",
    "tag_ref_prefix",
    "tag_signature_claim_authorizes_release",
    "tag_signature_trust_root_sha256",
    "tag_signature_verification_mode",
    "tag_signature_verifier_sha256",
    "workflow_path",
    "workflow_sha256",
}
LEDGER_KEYS = {
    "append_only",
    "approval_schema_version",
    "genesis_sha",
    "linear_single_parent",
    "ref",
    "repository",
    "repository_id",
    "require_unchanged_head_at_signature",
    "signer_revalidation_timing",
}
RUNTIME_POLICY_KEYS = {"digest_sha256", "name", "path"}


class ProductionPolicyError(ValueError):
    """The policy is ambiguous, unavailable, or diverges from reviewed pins."""


def reject(message: str) -> None:
    raise ProductionPolicyError(message)


@dataclass(frozen=True)
class AuditedPins:
    controller_repository_id: int
    controller_workflow_sha256: str
    controller_tag_trust_root_sha256: str
    controller_tag_verifier_sha256: str
    ledger_repository_id: int
    ledger_genesis_sha: str


UNCONFIGURED_PINS = AuditedPins(
    controller_repository_id=0,
    controller_workflow_sha256="",
    controller_tag_trust_root_sha256="",
    controller_tag_verifier_sha256="",
    ledger_repository_id=0,
    ledger_genesis_sha="",
)

# Deliberately unavailable until all values are independently audited.
PRODUCTION_AUDITED_PINS = UNCONFIGURED_PINS


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            reject(f"duplicate JSON key: {key}")
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


def expected_policy(pins: AuditedPins) -> dict[str, Any]:
    """Build the sole policy value allowed for a given set of audited pins."""

    if type(pins) is not AuditedPins:
        reject("audited pins must use the typed contract")
    return {
        "approval_max_seconds": 86400,
        "approval_path_prefix": "approvals/",
        "approval_schema_version": 2,
        "artifact_transport": "private-untrusted-carrier",
        "carrier_authorizes_release": False,
        "carrier_repository": "PluckXD/tratto-control-release-carrier",
        "carrier_trust": "transport-only",
        "controller": {
            "immutable_release_required": True,
            "repository": CONTROLLER_REPOSITORY,
            "repository_id": pins.controller_repository_id,
            "require_owner_enforcement": True,
            "signed_annotated_tag_required": True,
            "tag_ref_pattern": CONTROLLER_TAG_PATTERN,
            "tag_ref_prefix": CONTROLLER_TAG_PREFIX,
            "tag_signature_claim_authorizes_release": False,
            "tag_signature_trust_root_sha256": (
                pins.controller_tag_trust_root_sha256
            ),
            "tag_signature_verification_mode": (
                "local-cryptographic-annotated-tag-object"
            ),
            "tag_signature_verifier_sha256": (
                pins.controller_tag_verifier_sha256
            ),
            "workflow_path": CONTROLLER_WORKFLOW_PATH,
            "workflow_sha256": pins.controller_workflow_sha256,
        },
        "controller_repository": CONTROLLER_REPOSITORY,
        "ledger": {
            "append_only": True,
            "approval_schema_version": 2,
            "genesis_sha": pins.ledger_genesis_sha,
            "linear_single_parent": True,
            "ref": LEDGER_REF,
            "repository": LEDGER_REPOSITORY,
            "repository_id": pins.ledger_repository_id,
            "require_unchanged_head_at_signature": True,
            "signer_revalidation_timing": (
                "immediately-before-signature"
            ),
        },
        "migration_database_scope": "control-and-tenant-fleet",
        "product_repositories": [
            "PluckXD/tratto-api",
            "PluckXD/tratto-web",
        ],
        "required_ref": "refs/heads/main",
        "runtime_policy": {
            "digest_sha256": RUNTIME_POLICY_SHA256,
            "name": "control-runtime-v1",
            "path": "policies/control-runtime-v1.json",
        },
        "schema_version": 2,
        "signer_allows_product_credentials": False,
        "signer_allows_source_checkout": False,
    }


def parse_canonical(raw: bytes) -> dict[str, Any]:
    if not 0 < len(raw) <= MAX_POLICY_BYTES:
        reject("production policy has an invalid size")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda item: reject(
                f"non-finite number is forbidden: {item}"
            ),
        )
    except UnicodeDecodeError:
        reject("production policy must be UTF-8")
    except json.JSONDecodeError as error:
        reject(
            "production policy has invalid JSON at "
            f"line {error.lineno}, column {error.colno}"
        )
    if not isinstance(value, dict):
        reject("production policy root must be an object")
    if raw != canonical_bytes(value):
        reject("production policy must be canonical JSON")
    return value


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        reject(f"{label} keys diverge")
    return value


def valid_sha(value: Any, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def configured_bindings(value: dict[str, Any]) -> bool:
    controller = value["controller"]
    ledger = value["ledger"]
    return (
        type(controller["repository_id"]) is int
        and controller["repository_id"] > 0
        and valid_sha(controller["workflow_sha256"], SHA256_RE)
        and valid_sha(
            controller["tag_signature_trust_root_sha256"],
            SHA256_RE,
        )
        and valid_sha(
            controller["tag_signature_verifier_sha256"],
            SHA256_RE,
        )
        and type(ledger["repository_id"]) is int
        and ledger["repository_id"] > 0
        and valid_sha(ledger["genesis_sha"], SHA1_RE)
    )


def unconfigured_bindings(value: dict[str, Any]) -> bool:
    controller = value["controller"]
    ledger = value["ledger"]
    return (
        type(controller["repository_id"]) is int
        and controller["repository_id"] == 0
        and controller["workflow_sha256"] == ""
        and controller["tag_signature_trust_root_sha256"] == ""
        and controller["tag_signature_verifier_sha256"] == ""
        and type(ledger["repository_id"]) is int
        and ledger["repository_id"] == 0
        and ledger["genesis_sha"] == ""
    )


def validate_shape(value: Any) -> dict[str, Any]:
    policy = exact_keys(value, TOP_KEYS, "production policy")
    controller = exact_keys(
        policy["controller"],
        CONTROLLER_KEYS,
        "controller policy",
    )
    ledger = exact_keys(policy["ledger"], LEDGER_KEYS, "ledger policy")
    exact_keys(
        policy["runtime_policy"],
        RUNTIME_POLICY_KEYS,
        "runtime policy reference",
    )

    static_expected = expected_policy(UNCONFIGURED_PINS)
    dynamic_controller = {
        "repository_id",
        "tag_signature_trust_root_sha256",
        "tag_signature_verifier_sha256",
        "workflow_sha256",
    }
    dynamic_ledger = {"genesis_sha", "repository_id"}
    for key in TOP_KEYS - {"controller", "ledger"}:
        if policy[key] != static_expected[key]:
            reject(f"production policy fixed field diverges: {key}")
    for key in CONTROLLER_KEYS - dynamic_controller:
        if controller[key] != static_expected["controller"][key]:
            reject(f"controller policy fixed field diverges: {key}")
    for key in LEDGER_KEYS - dynamic_ledger:
        if ledger[key] != static_expected["ledger"][key]:
            reject(f"ledger policy fixed field diverges: {key}")

    if not (
        unconfigured_bindings(policy)
        or configured_bindings(policy)
    ):
        reject(
            "production trust bindings must be either wholly unavailable "
            "or wholly configured"
        )
    return policy


def validate_audited_pins(pins: AuditedPins) -> AuditedPins:
    if type(pins) is not AuditedPins:
        reject("audited pins must use the typed contract")
    candidate = expected_policy(pins)
    if not configured_bindings(candidate):
        reject("audited production pins are unavailable or invalid")
    return pins


def validate_value(
    value: Any,
    *,
    audited_pins: AuditedPins,
) -> dict[str, Any]:
    policy = validate_shape(value)
    pins = validate_audited_pins(audited_pins)
    if policy != expected_policy(pins):
        reject("production policy does not match the audited pins")
    return policy


def validate_bytes(
    raw: bytes,
    *,
    audited_pins: AuditedPins,
) -> tuple[dict[str, Any], str]:
    value = parse_canonical(raw)
    validate_value(value, audited_pins=audited_pins)
    return value, hashlib.sha256(raw).hexdigest()


def validate_template_bytes(raw: bytes) -> tuple[dict[str, Any], str]:
    """Validate the canonical unavailable template without authorizing it."""

    value = validate_shape(parse_canonical(raw))
    if value != expected_policy(UNCONFIGURED_PINS):
        reject("checked-in policy is not the unavailable template")
    return value, hashlib.sha256(raw).hexdigest()


def metadata_snapshot(info: os.stat_result) -> tuple[int, ...]:
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


def load_policy_bytes(path: Path) -> bytes:
    """Read a policy through one stable, non-symlinked file descriptor."""

    absolute = path.absolute()
    try:
        if absolute.resolve(strict=True) != absolute:
            reject("production policy path must not traverse symlinks")
        before = absolute.lstat()
        descriptor = os.open(
            absolute,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except ProductionPolicyError:
        raise
    except OSError:
        reject("production policy is unavailable")
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode)
            not in {0o400, 0o444, 0o600, 0o644}
            or not 0 < info.st_size <= MAX_POLICY_BYTES
            or (info.st_dev, info.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            reject(
                "production policy must be a bounded, owned, "
                "single-link regular file with a safe mode"
            )
        chunks: list[bytes] = []
        remaining = MAX_POLICY_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    except ProductionPolicyError:
        raise
    except OSError:
        reject("production policy failed closed while being read")
    finally:
        os.close(descriptor)
    if (
        metadata_snapshot(after) != metadata_snapshot(info)
        or len(raw) != info.st_size
    ):
        reject("production policy changed while being read")
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the exact Control production policy v2",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=(
            Path(__file__).resolve().parents[1]
            / "policies"
            / "control-production-v2.json"
        ),
    )
    args = parser.parse_args(argv)
    try:
        raw = load_policy_bytes(args.policy)
        value = parse_canonical(raw)
        validate_shape(value)
        validate_value(
            value,
            audited_pins=PRODUCTION_AUDITED_PINS,
        )
    except ProductionPolicyError as error:
        print(f"production policy rejected: {error}", file=sys.stderr)
        return 78
    print(
        json.dumps(
            {
                "policy_sha256": hashlib.sha256(raw).hexdigest(),
                "schema_version": value["schema_version"],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
