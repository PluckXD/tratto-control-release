#!/usr/bin/env python3
"""Validate the candidate v5 envelope without trusting the carrier."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "control_release_validator",
    HERE / "validate-approval.py",
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("approval validator unavailable")
APPROVAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APPROVAL)

HASH_RE = re.compile(r"^[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CONTROLLER_REPOSITORY = "PluckXD/tratto-control-release"
CARRIER_REPOSITORY = "PluckXD/tratto-control-release-carrier"
TOP_KEYS = {
    "approval",
    "artifacts",
    "behavioral_verification",
    "carrier",
    "controller",
    "migration",
    "schema_version",
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


class EnvelopeError(ValueError):
    pass


def reject(message: str) -> None:
    raise EnvelopeError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            reject(f"duplicate key: {key}")
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


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        reject(f"{label} keys diverge")
    return value


def require_pattern(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        reject(f"{label} has invalid format")
    return value


def load(path: Path) -> tuple[bytes, dict[str, Any]]:
    try:
        info = path.lstat()
        raw = path.read_bytes()
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda item: reject(
                f"non-finite number is forbidden: {item}"
            ),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        reject(f"envelope is unreadable: {type(error).__name__}")
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or not 0 < len(raw) <= 1024 * 1024
    ):
        reject("envelope must be a bounded single-link regular file")
    if not isinstance(value, dict):
        reject("envelope root must be an object")
    if raw != canonical_bytes(value):
        reject("envelope must be canonical JSON")
    return raw, value


def validate_product(
    value: Any,
    *,
    label: str,
    repository: str,
    commit_sha: str,
) -> dict[str, Any]:
    block = exact_keys(value, PRODUCT_KEYS, f"artifacts.{label}")
    if (
        block["repository"] != repository
        or block["carrier_repository"] != CARRIER_REPOSITORY
        or block["commit_sha"] != commit_sha
        or block["approved_ref"] != "refs/heads/main"
        or block["ancestor_verified"] is not True
        or block["build_job"] != f"build_{label}"
        or block["runner_os"] != "Linux"
        or block["runner_arch"] != "X64"
        or block["runner_environment"] != "github-hosted"
        or type(block["size_bytes"]) is not int
        or block["size_bytes"] <= 0
        or type(block["artifact_id"]) is not int
        or block["artifact_id"] <= 0
        or not isinstance(block["artifact_name"], str)
        or block["artifact_name"]
        != f"tratto-control-{label}-{commit_sha}.tar.gz"
    ):
        reject(f"artifacts.{label} provenance diverges")
    require_pattern(block["tree_sha"], SHA_RE, f"{label}.tree_sha")
    for key in (
        "sha256",
        "component_manifest_sha256",
        "service_digest",
    ):
        require_pattern(block[key], HASH_RE, f"{label}.{key}")
    return block


def validate(value: dict[str, Any]) -> dict[str, Any]:
    exact_keys(value, TOP_KEYS, "envelope")
    if type(value["schema_version"]) is not int or value["schema_version"] != 5:
        reject("envelope schema must be integer 5")

    carrier = exact_keys(
        value["carrier"],
        {"authorizes_release", "repository", "trust"},
        "carrier",
    )
    if carrier != {
        "authorizes_release": False,
        "repository": CARRIER_REPOSITORY,
        "trust": "transport-only",
    }:
        reject("carrier must remain non-authoritative")

    controller = exact_keys(
        value["controller"],
        {
            "commit_sha",
            "event_name",
            "repository",
            "runner_arch",
            "runner_environment",
            "runner_os",
            "run_attempt",
            "run_id",
            "source_ref",
            "verifier_sha256",
            "workflow",
            "workflow_ref",
        },
        "controller",
    )
    if (
        controller["repository"] != CONTROLLER_REPOSITORY
        or controller["workflow"] != ".github/workflows/control-release.yml"
        or controller["workflow_ref"]
        != (
            "PluckXD/tratto-control-release/"
            ".github/workflows/control-release.yml@refs/heads/main"
        )
        or controller["source_ref"] != "refs/heads/main"
        or controller["event_name"] != "workflow_dispatch"
        or controller["runner_os"] != "Linux"
        or controller["runner_arch"] != "X64"
        or controller["runner_environment"] != "github-hosted"
        or type(controller["run_id"]) is not int
        or controller["run_id"] <= 0
        or type(controller["run_attempt"]) is not int
        or controller["run_attempt"] <= 0
    ):
        reject("controller identity diverges")
    require_pattern(
        controller["commit_sha"],
        SHA_RE,
        "controller.commit_sha",
    )
    require_pattern(
        controller["verifier_sha256"],
        HASH_RE,
        "controller.verifier_sha256",
    )
    if value["supplemental_inventory"] != {"supplemental_only": True}:
        reject("supplemental inventory must remain non-authoritative")

    approval = exact_keys(
        value["approval"],
        {"manifest", "manifest_sha256", "mode"},
        "approval",
    )
    if approval["mode"] != "protected-public-controller":
        reject("approval mode is not allowed")
    manifest = approval["manifest"]
    if not isinstance(manifest, dict):
        reject("approval manifest must be an object")
    try:
        APPROVAL.validate_shape(manifest, now=None, historical=True)
    except APPROVAL.ApprovalError as error:
        reject(f"approval manifest rejected: {error}")
    manifest_hash = hashlib.sha256(
        APPROVAL.canonical_bytes(manifest)
    ).hexdigest()
    if approval["manifest_sha256"] != manifest_hash:
        reject("approval manifest digest diverges")
    if controller["commit_sha"] == manifest["controller"]["base_sha"]:
        reject("controller run must be the append-only approval commit")

    artifacts = exact_keys(
        value["artifacts"],
        {"api", "ops", "web"},
        "artifacts",
    )
    api = validate_product(
        artifacts["api"],
        label="api",
        repository="PluckXD/tratto-api",
        commit_sha=manifest["api"]["commit_sha"],
    )
    web = validate_product(
        artifacts["web"],
        label="web",
        repository="PluckXD/tratto-web",
        commit_sha=manifest["web"]["commit_sha"],
    )
    ops = validate_product(
        artifacts["ops"],
        label="ops",
        repository="PluckXD/tratto-api",
        commit_sha=manifest["ops"]["commit_sha"],
    )
    if ops["commit_sha"] != api["commit_sha"]:
        reject("Ops and API must be built from the same approved commit")
    asset_ids = {
        api["artifact_id"],
        ops["artifact_id"],
        web["artifact_id"],
    }
    if len(asset_ids) != 3:
        reject("API, Ops, and Web must use distinct carrier assets")

    if value["migration"] != manifest["migration"]:
        reject("migration contract diverges from approval")
    behavior = exact_keys(
        value["behavioral_verification"],
        {
            "artifacts",
            "api_sha",
            "browser_report_sha256",
            "contracts",
            "observations",
            "schema_version",
            "verdict",
            "web_sha",
        },
        "behavioral_verification",
    )
    required_contracts = {
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
    if (
        type(behavior["schema_version"]) is not int
        or behavior["schema_version"] != 3
        or behavior["verdict"] != "pass"
        or behavior["api_sha"] != api["commit_sha"]
        or behavior["web_sha"] != web["commit_sha"]
        or not isinstance(behavior["contracts"], dict)
        or set(behavior["contracts"]) != required_contracts
        or any(item is not True for item in behavior["contracts"].values())
        or not isinstance(behavior["observations"], dict)
        or set(behavior["observations"]) != set(EXPECTED_OBSERVATIONS)
        or any(
            type(behavior["observations"][label]) is not int
            or behavior["observations"][label] not in allowed
            for label, allowed in EXPECTED_OBSERVATIONS.items()
        )
    ):
        reject("independent runtime verification did not pass")
    require_pattern(
        behavior["browser_report_sha256"],
        HASH_RE,
        "behavioral_verification.browser_report_sha256",
    )
    behavior_artifacts = exact_keys(
        behavior["artifacts"],
        {"api", "ops", "web"},
        "behavioral_verification.artifacts",
    )
    for label, artifact in (("api", api), ("ops", ops), ("web", web)):
        if behavior_artifacts[label] != {
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
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("envelope", type=Path)
    args = parser.parse_args()
    try:
        raw, value = load(args.envelope)
        validate(value)
    except (EnvelopeError, APPROVAL.ApprovalError) as error:
        print(f"release envelope rejected: {error}", file=sys.stderr)
        return 78
    print(
        json.dumps(
            {
                "envelope_sha256": hashlib.sha256(raw).hexdigest(),
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
