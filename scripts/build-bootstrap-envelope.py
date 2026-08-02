#!/usr/bin/env python3
"""Create the canonical, one-shot Control bootstrap release envelope.

This is intentionally narrower than the permanent release controller.  It
only combines already-built component summaries, a canonical approval, and an
independent behavioral report.  Signing is performed later by a checkout-free
OIDC job in the private bootstrap carrier.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any


sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
APPROVAL_SPEC = importlib.util.spec_from_file_location(
    "control_bootstrap_envelope_approval",
    HERE / "validate-approval.py",
)
if APPROVAL_SPEC is None or APPROVAL_SPEC.loader is None:
    raise RuntimeError("approval validator unavailable")
APPROVAL = importlib.util.module_from_spec(APPROVAL_SPEC)
APPROVAL_SPEC.loader.exec_module(APPROVAL)

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
REPOSITORIES = {
    "api": "PluckXD/tratto-api",
    "ops": "PluckXD/tratto-api",
    "web": "PluckXD/tratto-web",
}
SUMMARY_KEYS = {
    "artifact_name",
    "component_manifest_sha256",
    "runtime_policy_sha256",
    "service_digest",
    "sha256",
    "size_bytes",
    "tree_sha",
}
BEHAVIOR_KEYS = {
    "api_sha",
    "artifacts",
    "browser_report_sha256",
    "contracts",
    "observations",
    "schema_version",
    "verdict",
    "web_sha",
}
BEHAVIOR_CONTRACTS = {
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


class BootstrapEnvelopeError(ValueError):
    """Bootstrap evidence is incomplete, ambiguous, or inconsistent."""


def reject(message: str) -> None:
    raise BootstrapEnvelopeError(message)


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


def read_json(path: Path, label: str) -> tuple[bytes, dict[str, Any]]:
    try:
        info = path.lstat()
        raw = path.read_bytes()
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda item: reject(
                f"{label} contains non-finite number: {item}"
            ),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        reject(f"{label} is invalid")
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o022
        or not 0 < len(raw) <= 1024 * 1024
        or not isinstance(value, dict)
        or raw != canonical_bytes(value)
    ):
        reject(f"{label} must be canonical and non-writable")
    return raw, value


def read_approval(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw, value = read_json(path, "bootstrap approval")
    try:
        APPROVAL.validate_shape(value, now=None, historical=True)
    except APPROVAL.ApprovalError as error:
        reject(f"bootstrap approval is invalid: {error}")
    return raw, value


def validate_summary(
    value: dict[str, Any],
    *,
    label: str,
    release_sha: str,
) -> None:
    if set(value) != SUMMARY_KEYS:
        reject(f"{label} summary has invalid keys")
    expected_name = f"tratto-control-{label}-{release_sha}.tar.gz"
    if (
        value["artifact_name"] != expected_name
        or SHA_RE.fullmatch(str(value["tree_sha"])) is None
        or type(value["size_bytes"]) is not int
        or value["size_bytes"] <= 0
    ):
        reject(f"{label} summary identity is invalid")
    for key in (
        "component_manifest_sha256",
        "runtime_policy_sha256",
        "service_digest",
        "sha256",
    ):
        if HASH_RE.fullmatch(str(value[key])) is None:
            reject(f"{label} summary digest is invalid: {key}")


def artifact_binding(
    summary: dict[str, Any],
    *,
    label: str,
    release_sha: str,
    artifact_id: int,
) -> dict[str, Any]:
    return {
        "ancestor_verified": True,
        "approved_ref": "refs/heads/main",
        "artifact_id": artifact_id,
        "artifact_name": summary["artifact_name"],
        "build_job": f"build_{label}",
        "carrier_repository": (
            "PluckXD/tratto-control-release-carrier"
        ),
        "commit_sha": release_sha,
        "component_manifest_sha256": summary[
            "component_manifest_sha256"
        ],
        "repository": REPOSITORIES[label],
        "runner_arch": "X64",
        "runner_environment": "github-hosted",
        "runner_os": "Linux",
        "service_digest": summary["service_digest"],
        "sha256": summary["sha256"],
        "size_bytes": summary["size_bytes"],
        "tree_sha": summary["tree_sha"],
    }


def validate_behavior(
    value: dict[str, Any],
    *,
    api_sha: str,
    web_sha: str,
    artifacts: dict[str, dict[str, Any]],
) -> None:
    if (
        set(value) != BEHAVIOR_KEYS
        or value["schema_version"] != 3
        or value["verdict"] != "pass"
        or value["api_sha"] != api_sha
        or value["web_sha"] != web_sha
        or not isinstance(value["contracts"], dict)
        or set(value["contracts"]) != BEHAVIOR_CONTRACTS
        or any(result is not True for result in value["contracts"].values())
        or not isinstance(value["observations"], dict)
        or HASH_RE.fullmatch(
            str(value["browser_report_sha256"])
        )
        is None
    ):
        reject("behavioral report is invalid")
    bindings = value["artifacts"]
    if not isinstance(bindings, dict) or set(bindings) != {
        "api",
        "ops",
        "web",
    }:
        reject("behavioral artifact bindings are invalid")
    for label, artifact in artifacts.items():
        expected = {
            "artifact_id": artifact["artifact_id"],
            "component_manifest_sha256": artifact[
                "component_manifest_sha256"
            ],
            "service_digest": artifact["service_digest"],
            "sha256": artifact["sha256"],
        }
        if bindings[label] != expected:
            reject(f"behavioral report does not bind {label}")


def write_exclusive(path: Path, payload: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                reject("envelope output was interrupted")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--approval", required=True, type=Path)
    parser.add_argument("--api-summary", required=True, type=Path)
    parser.add_argument("--ops-summary", required=True, type=Path)
    parser.add_argument("--web-summary", required=True, type=Path)
    parser.add_argument("--behavior", required=True, type=Path)
    parser.add_argument("--api-artifact-id", required=True, type=int)
    parser.add_argument("--ops-artifact-id", required=True, type=int)
    parser.add_argument("--web-artifact-id", required=True, type=int)
    parser.add_argument("--carrier-sha", required=True)
    parser.add_argument("--controller-sha", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--run-attempt", required=True, type=int)
    parser.add_argument("--verifier-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        for value, label in (
            (args.carrier_sha, "carrier"),
            (args.controller_sha, "controller"),
        ):
            if SHA_RE.fullmatch(value) is None:
                reject(f"{label} SHA is invalid")
        if (
            args.run_id <= 0
            or args.run_attempt <= 0
            or HASH_RE.fullmatch(args.verifier_sha256) is None
        ):
            reject("bootstrap run identity is invalid")
        ids = {
            args.api_artifact_id,
            args.ops_artifact_id,
            args.web_artifact_id,
        }
        if len(ids) != 3 or any(value <= 0 for value in ids):
            reject("bootstrap artifacts require distinct positive IDs")

        approval_raw, approval = read_approval(args.approval)
        api_sha = approval["api"]["commit_sha"]
        web_sha = approval["web"]["commit_sha"]
        if approval["ops"]["commit_sha"] != api_sha:
            reject("API and Ops approval SHAs differ")
        summaries: dict[str, dict[str, Any]] = {}
        for label, path, release_sha in (
            ("api", args.api_summary, api_sha),
            ("ops", args.ops_summary, api_sha),
            ("web", args.web_summary, web_sha),
        ):
            _, summary = read_json(path, f"{label} build summary")
            validate_summary(
                summary,
                label=label,
                release_sha=release_sha,
            )
            summaries[label] = summary
        runtime_digests = {
            summary["runtime_policy_sha256"]
            for summary in summaries.values()
        }
        if len(runtime_digests) != 1:
            reject("component runtime policies differ")
        artifacts = {
            "api": artifact_binding(
                summaries["api"],
                label="api",
                release_sha=api_sha,
                artifact_id=args.api_artifact_id,
            ),
            "ops": artifact_binding(
                summaries["ops"],
                label="ops",
                release_sha=api_sha,
                artifact_id=args.ops_artifact_id,
            ),
            "web": artifact_binding(
                summaries["web"],
                label="web",
                release_sha=web_sha,
                artifact_id=args.web_artifact_id,
            ),
        }
        _, behavior = read_json(
            args.behavior,
            "behavioral verification",
        )
        validate_behavior(
            behavior,
            api_sha=api_sha,
            web_sha=web_sha,
            artifacts=artifacts,
        )
        approval_hash = hashlib.sha256(approval_raw).hexdigest()
        document = {
            "approval": {
                "manifest": approval,
                "manifest_sha256": approval_hash,
                "mode": "single-operator-bootstrap",
            },
            "artifacts": artifacts,
            "behavioral_verification": behavior,
            "carrier": {
                "authorizes_release": False,
                "repository": (
                    "PluckXD/tratto-control-release-carrier"
                ),
                "trust": "transport-only",
            },
            "controller": {
                "commit_sha": args.carrier_sha,
                "event_name": "workflow_dispatch",
                "run_attempt": args.run_attempt,
                "run_id": args.run_id,
                "runner_arch": "X64",
                "runner_environment": "github-hosted",
                "runner_os": "Linux",
                "source_ref": "refs/heads/main",
                "verifier_sha256": args.verifier_sha256,
                "workflow": (
                    ".github/workflows/control-bootstrap-v1.yml"
                ),
                "workflow_ref": (
                    "PluckXD/tratto-control-release-carrier/"
                    ".github/workflows/control-bootstrap-v1.yml@"
                    "refs/heads/main"
                ),
                "repository": (
                    "PluckXD/tratto-control-release-carrier"
                ),
            },
            "migration": approval["migration"],
            "schema_version": 5,
            "supplemental_inventory": {
                "supplemental_only": True,
            },
        }
        # The reviewed public controller SHA remains explicit in the approval.
        if approval["controller"]["base_sha"] != args.controller_sha:
            reject("approval does not bind the reviewed controller SHA")
        write_exclusive(args.output, canonical_bytes(document))
        print(
            json.dumps(
                {
                    "approval_manifest_sha256": approval_hash,
                    "attestation_sha256": hashlib.sha256(
                        canonical_bytes(document)
                    ).hexdigest(),
                    "runtime_policy_sha256": next(
                        iter(runtime_digests)
                    ),
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        APPROVAL.ApprovalError,
        BootstrapEnvelopeError,
    ) as error:
        print(f"Bootstrap envelope rejected: {error}", file=sys.stderr)
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
