#!/usr/bin/env python3
"""Fail-closed readiness gate for every Control release job."""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import json
import os
from pathlib import Path
from typing import Any


EXPECTED_KEYS = {
    "blockers",
    "required_envelope_schema",
    "required_ops_install_mode",
    "schema_version",
    "state",
}
PHASES = {
    "authorize",
    "build_api",
    "build_ops",
    "build_web",
    "verify",
    "sign_release",
}
EXPECTED_CONTEXT = {
    "GITHUB_ACTIONS": "true",
    "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_REPOSITORY": "PluckXD/tratto-control-release",
    "GITHUB_SERVER_URL": "https://github.com",
    "RUNNER_ENVIRONMENT": "github-hosted",
}


class GateError(ValueError):
    pass


def reject(message: str) -> None:
    raise GateError(message)


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


def load_readiness(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda item: reject(
                f"non-finite number is forbidden: {item}"
            ),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        reject(f"readiness document is unavailable: {type(error).__name__}")
    if not isinstance(value, dict) or set(value) != EXPECTED_KEYS:
        reject("readiness document has an invalid schema")
    if raw != canonical_bytes(value):
        reject("readiness document must be canonical JSON")
    blockers = value["blockers"]
    if not isinstance(blockers, list):
        reject("readiness blockers must be a list")
    seen: set[str] = set()
    for blocker in blockers:
        if (
            not isinstance(blocker, dict)
            or set(blocker) != {"id", "resolution"}
            or not isinstance(blocker["id"], str)
            or not isinstance(blocker["resolution"], str)
            or not blocker["id"]
            or not blocker["resolution"]
            or blocker["id"] in seen
        ):
            reject("readiness blocker is invalid or duplicated")
        seen.add(blocker["id"])
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or type(value["required_envelope_schema"]) is not int
        or value["required_envelope_schema"] != 5
        or value["required_ops_install_mode"] != "atomic-quiesced"
        or value["state"] not in {"unavailable", "ready"}
    ):
        reject("readiness contract is incompatible")
    if value["state"] == "ready" and blockers:
        reject("ready state cannot retain blockers")
    return value


def validate_context(phase: str, environment: dict[str, str]) -> None:
    if phase not in PHASES:
        reject("unknown release phase")
    for name, expected in EXPECTED_CONTEXT.items():
        if environment.get(name) != expected:
            reject(f"trusted GitHub context is invalid: {name}")
    oidc_url = environment.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    oidc_token = environment.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    product_tokens = (
        environment.get("CONTROL_API_READ_TOKEN", ""),
        environment.get("CONTROL_WEB_READ_TOKEN", ""),
    )
    if phase == "sign_release":
        if not oidc_url or not oidc_token:
            reject("signer OIDC context is unavailable")
        if any(product_tokens):
            reject("signer must not receive product credentials")
        if environment.get("CONTROL_SIGNER_SOURCE_CHECKOUT", ""):
            reject("signer must not receive a source checkout")
    else:
        if oidc_url or oidc_token:
            reject(f"{phase} must not receive an OIDC token")
        if phase == "verify" and any(product_tokens):
            reject("independent verifier must not receive product credentials")
        if phase in {"build_api", "build_ops"} and product_tokens[1]:
            reject(f"{phase} must not receive the Web credential")
        if phase == "build_web" and product_tokens[0]:
            reject("Web builder must not receive the API credential")


def gate(path: Path, phase: str, environment: dict[str, str]) -> None:
    readiness = load_readiness(path)
    validate_context(phase, environment)
    if readiness["state"] != "ready":
        ids = ",".join(item["id"] for item in readiness["blockers"])
        reject(f"RELEASE_POLICY_UNAVAILABLE ({ids})")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--readiness", required=True, type=Path)
    parser.add_argument("--phase", required=True, choices=sorted(PHASES))
    args = parser.parse_args()
    try:
        gate(args.readiness, args.phase, dict(os.environ))
    except GateError as error:
        print(f"release gate rejected: {error}", file=sys.stderr)
        return 78
    print(f"release gate ready: {args.phase}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
