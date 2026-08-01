#!/usr/bin/env python3
"""Fail-closed validation for a candidate Control release envelope v6.

The carrier transports artifacts but never authorizes a release.  Authorization
comes from a complete canonical approval-v2 manifest recorded in an independent
append-only ledger.  This validator checks the signed envelope's internal
bindings without claiming that the embedded external attestations prove
themselves.
"""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "control_release_approval_v2_validator",
    HERE / "validate-approval-v2.py",
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("approval-v2 validator unavailable")
APPROVAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APPROVAL)

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CONTROLLER_TAG_RE = re.compile(
    r"^refs/tags/control-controller-v6\."
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)

CONTROLLER_REPOSITORY = "PluckXD/tratto-control-release"
LEDGER_REPOSITORY = "PluckXD/tratto-control-release-ledger"
CARRIER_REPOSITORY = "PluckXD/tratto-control-release-carrier"
WORKFLOW_PATH = ".github/workflows/control-release.yml"
MAX_FILE_BYTES = 1024 * 1024

TOP_KEYS = {
    "approval",
    "artifacts",
    "behavioral_verification",
    "carrier",
    "controller",
    "ledger",
    "migration",
    "schema_version",
    "signer_freshness",
    "supplemental_inventory",
}
PRODUCT_KEYS = {
    "ancestor_verified",
    "approved_ref",
    "artifact_id",
    "artifact_name",
    "build_job",
    "carrier_repository",
    "commit_sha",
    "component_manifest_sha256",
    "repository",
    "runner_arch",
    "runner_environment",
    "runner_os",
    "service_digest",
    "sha256",
    "size_bytes",
    "tree_sha",
}
CONTROLLER_KEYS = {
    "commit_sha",
    "event_name",
    "github_sha",
    "immutable_release_id",
    "owner_enforced",
    "repository",
    "repository_id",
    "run_attempt",
    "run_id",
    "runner_arch",
    "runner_environment",
    "runner_os",
    "signer_verifier_sha256",
    "source_ref",
    "tag_object_sha",
    "tag_ref",
    "workflow_path",
    "workflow_ref",
    "workflow_sha",
    "workflow_sha256",
}
LEDGER_KEYS = {
    "genesis_sha",
    "head_sha",
    "manifest_sha256",
    "parent_commit_sha",
    "previous_manifest_sha256",
    "record_count",
    "ref",
    "repository",
    "repository_id",
    "sequence",
}
SIGNER_FRESHNESS_KEYS = {
    "controller_tag_attestation_sha256",
    "github_controls_attestation_sha256",
    "ledger_attestation_sha256",
    "ledger_head_sha",
    "revalidated_immediately_before_signature",
}
BEHAVIOR_KEYS = {
    "artifacts",
    "api_sha",
    "browser_report_sha256",
    "contracts",
    "observations",
    "schema_version",
    "verdict",
    "web_sha",
}
BEHAVIOR_ARTIFACT_KEYS = {
    "artifact_id",
    "component_manifest_sha256",
    "service_digest",
    "sha256",
}
REQUIRED_CONTRACTS = {
    "api_auth_surface_http",
    "api_business_denylist_http",
    "api_p2t_password_ack_http",
    "api_reset_endpoint_http",
    "edge_reset_url_redaction_http",
    "ops_tree_digest_verified",
    "web_exact_hostname_http",
    "web_reset_fragment_browser",
    "web_surface_denylist_http",
}
EXPECTED_OBSERVATIONS = {
    "api_anonymous_me": {401, 403},
    "api_business_deny": {404},
    "api_health": {200},
    "api_internal_deny": {404},
    "api_p2t_password_ack_exists": {401, 403},
    "api_reset_exact": {400, 401, 403, 422},
    "api_reset_legacy": {404},
    "edge_reset_legacy": {404},
    "edge_reset_query": {404},
    "web_business_deny": {404},
    "web_login": {200},
    "web_reset_exact": {200},
    "web_reset_legacy": {404},
    "web_wrong_host": {421},
}


class EnvelopeV6Error(ValueError):
    """The v6 envelope is ambiguous or violates release policy."""


def reject(message: str) -> None:
    raise EnvelopeV6Error(message)


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


def require_pattern(
    value: Any,
    pattern: re.Pattern[str],
    label: str,
) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        reject(f"{label} has invalid format")
    return value


def require_positive_integer(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        reject(f"{label} must be a positive integer")
    return value


def parse_canonical_json(raw: bytes) -> dict[str, Any]:
    if not 0 < len(raw) <= MAX_FILE_BYTES:
        reject("envelope has an invalid size")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        reject("envelope must be UTF-8")
    try:
        value = json.loads(
            decoded,
            object_pairs_hook=unique_object,
            parse_constant=lambda item: reject(
                f"non-finite number is forbidden: {item}"
            ),
        )
    except json.JSONDecodeError as error:
        reject(
            "envelope has invalid JSON at "
            f"line {error.lineno}, column {error.colno}"
        )
    if not isinstance(value, dict):
        reject("envelope root must be an object")
    if raw != canonical_bytes(value):
        reject("envelope must be canonical JSON")
    return value


def read_envelope(path: Path) -> bytes:
    """Read one stable, non-symlink, single-link regular file."""

    absolute = path.absolute()
    try:
        if absolute.resolve(strict=True) != absolute:
            reject("envelope path must not traverse symlinks")
        before_path = absolute.lstat()
    except EnvelopeV6Error:
        raise
    except OSError as error:
        reject(f"cannot inspect envelope safely: {error.strerror}")
    if (
        not stat.S_ISREG(before_path.st_mode)
        or stat.S_ISLNK(before_path.st_mode)
        or before_path.st_nlink != 1
    ):
        reject("envelope must be a single-link non-symlink regular file")

    flags = os.O_RDONLY | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        reject(f"cannot open envelope safely: {error.strerror}")
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino)
            != (before_path.st_dev, before_path.st_ino)
            or not 0 < before.st_size <= MAX_FILE_BYTES
        ):
            reject("envelope must be a bounded single-link regular file")
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
                reject("envelope exceeds maximum size")
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if total != before.st_size or any(
            getattr(before, field) != getattr(after, field)
            for field in stable_fields
        ):
            reject("envelope changed while being read")
        try:
            after_path = absolute.lstat()
        except OSError:
            reject("envelope pathname changed while being read")
        if (
            stat.S_ISLNK(after_path.st_mode)
            or after_path.st_nlink != 1
            or any(
                getattr(before, field) != getattr(after_path, field)
                for field in stable_fields
            )
        ):
            reject("envelope pathname changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def validate_product(
    value: Any,
    *,
    label: str,
    repository: str,
    commit_sha: str,
) -> Mapping[str, Any]:
    artifact = exact_keys(value, PRODUCT_KEYS, f"artifacts.{label}")
    if (
        artifact["repository"] != repository
        or artifact["carrier_repository"] != CARRIER_REPOSITORY
        or artifact["commit_sha"] != commit_sha
        or artifact["approved_ref"] != "refs/heads/main"
        or artifact["ancestor_verified"] is not True
        or artifact["build_job"] != f"build_{label}"
        or artifact["runner_os"] != "Linux"
        or artifact["runner_arch"] != "X64"
        or artifact["runner_environment"] != "github-hosted"
        or not isinstance(artifact["artifact_name"], str)
        or artifact["artifact_name"]
        != f"tratto-control-{label}-{commit_sha}.tar.gz"
    ):
        reject(f"artifacts.{label} provenance diverges")
    require_positive_integer(
        artifact["artifact_id"],
        f"artifacts.{label}.artifact_id",
    )
    require_positive_integer(
        artifact["size_bytes"],
        f"artifacts.{label}.size_bytes",
    )
    require_pattern(
        artifact["tree_sha"],
        SHA1_RE,
        f"artifacts.{label}.tree_sha",
    )
    for key in ("sha256", "component_manifest_sha256", "service_digest"):
        require_pattern(
            artifact[key],
            SHA256_RE,
            f"artifacts.{label}.{key}",
        )
    return artifact


def validate_controller(
    value: Any,
    approval_controller: Mapping[str, Any],
) -> Mapping[str, Any]:
    controller = exact_keys(value, CONTROLLER_KEYS, "controller")
    tag_ref = require_pattern(
        approval_controller["tag_ref"],
        CONTROLLER_TAG_RE,
        "approval.controller.tag_ref",
    )
    expected_workflow_ref = (
        f"{CONTROLLER_REPOSITORY}/{WORKFLOW_PATH}@{tag_ref}"
    )
    expected = {
        "commit_sha": approval_controller["commit_sha"],
        "immutable_release_id": approval_controller["immutable_release_id"],
        "repository": approval_controller["repository"],
        "repository_id": approval_controller["repository_id"],
        "signer_verifier_sha256": approval_controller[
            "signer_verifier_sha256"
        ],
        "tag_object_sha": approval_controller["tag_object_sha"],
        "tag_ref": tag_ref,
        "workflow_path": approval_controller["workflow_path"],
        "workflow_sha256": approval_controller["workflow_sha256"],
    }
    for key, expected_value in expected.items():
        if controller[key] != expected_value:
            reject(f"controller.{key} diverges from approval")
    if (
        controller["repository"] != CONTROLLER_REPOSITORY
        or controller["workflow_path"] != WORKFLOW_PATH
        or controller["workflow_ref"] != expected_workflow_ref
        or controller["source_ref"] != tag_ref
        or controller["event_name"] != "workflow_dispatch"
        or controller["runner_os"] != "Linux"
        or controller["runner_arch"] != "X64"
        or controller["runner_environment"] != "github-hosted"
        or controller["owner_enforced"] is not True
    ):
        reject("controller execution identity diverges")
    require_positive_integer(controller["run_id"], "controller.run_id")
    require_positive_integer(
        controller["run_attempt"],
        "controller.run_attempt",
    )
    require_positive_integer(
        controller["repository_id"],
        "controller.repository_id",
    )
    require_positive_integer(
        controller["immutable_release_id"],
        "controller.immutable_release_id",
    )
    for key in (
        "commit_sha",
        "github_sha",
        "tag_object_sha",
        "workflow_sha",
    ):
        require_pattern(controller[key], SHA1_RE, f"controller.{key}")
    for key in ("signer_verifier_sha256", "workflow_sha256"):
        require_pattern(controller[key], SHA256_RE, f"controller.{key}")
    if (
        controller["github_sha"] != controller["commit_sha"]
        or controller["workflow_sha"] != controller["commit_sha"]
    ):
        reject(
            "GitHub workflow SHA and commit must equal the approved tag commit"
        )
    return controller


def validate_ledger(
    value: Any,
    approval_ledger: Mapping[str, Any],
    manifest_sha256: str,
) -> Mapping[str, Any]:
    ledger = exact_keys(value, LEDGER_KEYS, "ledger")
    for key in (
        "repository",
        "repository_id",
        "ref",
        "genesis_sha",
        "parent_commit_sha",
        "sequence",
        "previous_manifest_sha256",
    ):
        if ledger[key] != approval_ledger[key]:
            reject(f"ledger.{key} diverges from approval")
    if (
        ledger["repository"] != LEDGER_REPOSITORY
        or ledger["ref"] != "refs/heads/main"
    ):
        reject("ledger identity diverges")
    require_positive_integer(ledger["repository_id"], "ledger.repository_id")
    sequence = require_positive_integer(ledger["sequence"], "ledger.sequence")
    record_count = require_positive_integer(
        ledger["record_count"],
        "ledger.record_count",
    )
    if record_count != sequence:
        reject("ledger.record_count must equal ledger.sequence")
    for key in ("genesis_sha", "head_sha", "parent_commit_sha"):
        require_pattern(ledger[key], SHA1_RE, f"ledger.{key}")
    for key in ("manifest_sha256", "previous_manifest_sha256"):
        require_pattern(ledger[key], SHA256_RE, f"ledger.{key}")
    if ledger["manifest_sha256"] != manifest_sha256:
        reject("ledger manifest digest diverges from canonical approval")
    if ledger["head_sha"] in {
        ledger["parent_commit_sha"],
        ledger["genesis_sha"],
    }:
        reject("ledger head must be distinct from parent and genesis")
    return ledger


def validate_signer_freshness(
    value: Any,
    ledger_head_sha: str,
) -> Mapping[str, Any]:
    freshness = exact_keys(
        value,
        SIGNER_FRESHNESS_KEYS,
        "signer_freshness",
    )
    if freshness["ledger_head_sha"] != ledger_head_sha:
        reject("signer freshness is not bound to the validated ledger head")
    require_pattern(
        freshness["ledger_head_sha"],
        SHA1_RE,
        "signer_freshness.ledger_head_sha",
    )
    digest_keys = (
        "ledger_attestation_sha256",
        "controller_tag_attestation_sha256",
        "github_controls_attestation_sha256",
    )
    digests = [
        require_pattern(
            freshness[key],
            SHA256_RE,
            f"signer_freshness.{key}",
        )
        for key in digest_keys
    ]
    if len(set(digests)) != len(digests):
        reject("signer freshness attestations must use distinct digests")
    if freshness["revalidated_immediately_before_signature"] is not True:
        reject("signer did not revalidate immediately before signature")
    return freshness


def validate_behavior(
    value: Any,
    *,
    api: Mapping[str, Any],
    ops: Mapping[str, Any],
    web: Mapping[str, Any],
) -> None:
    behavior = exact_keys(
        value,
        BEHAVIOR_KEYS,
        "behavioral_verification",
    )
    contracts = exact_keys(
        behavior["contracts"],
        REQUIRED_CONTRACTS,
        "behavioral_verification.contracts",
    )
    observations = exact_keys(
        behavior["observations"],
        set(EXPECTED_OBSERVATIONS),
        "behavioral_verification.observations",
    )
    if (
        type(behavior["schema_version"]) is not int
        or behavior["schema_version"] != 3
        or behavior["verdict"] != "pass"
        or behavior["api_sha"] != api["commit_sha"]
        or behavior["web_sha"] != web["commit_sha"]
        or any(item is not True for item in contracts.values())
        or any(
            type(observations[label]) is not int
            or observations[label] not in allowed
            for label, allowed in EXPECTED_OBSERVATIONS.items()
        )
    ):
        reject("independent runtime verification did not pass")
    require_pattern(
        behavior["browser_report_sha256"],
        SHA256_RE,
        "behavioral_verification.browser_report_sha256",
    )
    bindings = exact_keys(
        behavior["artifacts"],
        {"api", "ops", "web"},
        "behavioral_verification.artifacts",
    )
    for label, artifact in (("api", api), ("ops", ops), ("web", web)):
        binding = exact_keys(
            bindings[label],
            BEHAVIOR_ARTIFACT_KEYS,
            f"behavioral_verification.artifacts.{label}",
        )
        if dict(binding) != {
            "artifact_id": artifact["artifact_id"],
            "component_manifest_sha256": artifact[
                "component_manifest_sha256"
            ],
            "service_digest": artifact["service_digest"],
            "sha256": artifact["sha256"],
        }:
            reject(
                f"behavioral verification is not bound to artifacts.{label}"
            )


def validate(value: Mapping[str, Any]) -> dict[str, Any]:
    envelope = exact_keys(value, TOP_KEYS, "envelope")
    if (
        type(envelope["schema_version"]) is not int
        or envelope["schema_version"] != 6
    ):
        reject("envelope schema_version must be integer 6")

    carrier = exact_keys(
        envelope["carrier"],
        {"authorizes_release", "repository", "trust"},
        "carrier",
    )
    if dict(carrier) != {
        "authorizes_release": False,
        "repository": CARRIER_REPOSITORY,
        "trust": "transport-only",
    }:
        reject("carrier must remain non-authoritative transport")
    supplemental = exact_keys(
        envelope["supplemental_inventory"],
        {"supplemental_only"},
        "supplemental_inventory",
    )
    if dict(supplemental) != {"supplemental_only": True}:
        reject("supplemental inventory must remain non-authoritative")

    approval_wrapper = exact_keys(
        envelope["approval"],
        {"manifest", "manifest_sha256", "mode"},
        "approval",
    )
    if approval_wrapper["mode"] != "protected-independent-ledger":
        reject("approval mode is not protected-independent-ledger")
    manifest = approval_wrapper["manifest"]
    if not isinstance(manifest, Mapping):
        reject("approval manifest must be an object")
    try:
        validated_manifest = APPROVAL.validate_shape(
            manifest,
            now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0),
            historical=True,
        )
    except APPROVAL.ApprovalV2Error as error:
        reject(f"approval manifest rejected: {error}")
    manifest_sha256 = hashlib.sha256(
        APPROVAL.canonical_bytes(validated_manifest)
    ).hexdigest()
    if approval_wrapper["manifest_sha256"] != manifest_sha256:
        reject("approval manifest digest diverges")
    require_pattern(
        approval_wrapper["manifest_sha256"],
        SHA256_RE,
        "approval.manifest_sha256",
    )

    approval_controller = validated_manifest["controller"]
    approval_ledger = validated_manifest["ledger"]
    assert isinstance(approval_controller, Mapping)
    assert isinstance(approval_ledger, Mapping)
    validate_controller(envelope["controller"], approval_controller)
    ledger = validate_ledger(
        envelope["ledger"],
        approval_ledger,
        manifest_sha256,
    )
    validate_signer_freshness(
        envelope["signer_freshness"],
        ledger["head_sha"],
    )

    artifacts = exact_keys(
        envelope["artifacts"],
        {"api", "ops", "web"},
        "artifacts",
    )
    api = validate_product(
        artifacts["api"],
        label="api",
        repository="PluckXD/tratto-api",
        commit_sha=validated_manifest["api"]["commit_sha"],
    )
    ops = validate_product(
        artifacts["ops"],
        label="ops",
        repository="PluckXD/tratto-api",
        commit_sha=validated_manifest["ops"]["commit_sha"],
    )
    web = validate_product(
        artifacts["web"],
        label="web",
        repository="PluckXD/tratto-web",
        commit_sha=validated_manifest["web"]["commit_sha"],
    )
    if api["commit_sha"] != ops["commit_sha"]:
        reject("Ops and API must be built from the same approved commit")
    if len(
        {
            api["artifact_id"],
            ops["artifact_id"],
            web["artifact_id"],
        }
    ) != 3:
        reject("API, Ops, and Web must use distinct carrier assets")
    if envelope["migration"] != validated_manifest["migration"]:
        reject("migration contract diverges from approval")
    validate_behavior(
        envelope["behavioral_verification"],
        api=api,
        ops=ops,
        web=web,
    )
    return dict(envelope)


def validate_bytes(raw: bytes) -> dict[str, Any]:
    return validate(parse_canonical_json(raw))


def validate_file(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = read_envelope(path)
    return raw, validate_bytes(raw)


class FailClosedParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        reject(f"invalid command line: {message}")


def main(arguments: list[str] | None = None) -> int:
    parser = FailClosedParser()
    parser.add_argument("envelope", type=Path)
    try:
        args = parser.parse_args(arguments)
        raw, value = validate_file(args.envelope)
    except (EnvelopeV6Error, APPROVAL.ApprovalV2Error) as error:
        print(f"release envelope v6 rejected: {error}", file=sys.stderr)
        return 78
    print(
        json.dumps(
            {
                "controller_tag_ref": value["controller"]["tag_ref"],
                "envelope_sha256": hashlib.sha256(raw).hexdigest(),
                "ledger_head_sha": value["ledger"]["head_sha"],
                "release_id": value["approval"]["manifest"]["release_id"],
                "schema_version": value["schema_version"],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
