#!/usr/bin/env python3
"""Fail-closed readiness and execution-context gate for Control v6.

The command-line interface deliberately uses only the checked-in v2
readiness and production-policy documents and the separately audited pins in
``validate-policy-v2.py``.  It accepts no trust pins or document paths from
arguments or environment variables.

The pure API accepts explicit canonical policy bytes and typed audited pins so
tests and reviewers can exercise a prospective fully configured policy without
turning the checked-in unavailable template into an authorization source.
"""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
READINESS_PATH = ROOT / "release-readiness-v2.json"
PRODUCTION_POLICY_PATH = ROOT / "policies" / "control-production-v2.json"
MAX_READINESS_BYTES = 64 * 1024

READINESS_KEYS = {
    "blockers",
    "required_approval_schema",
    "required_envelope_schema",
    "required_ops_install_mode",
    "required_policy_schema",
    "schema_version",
    "state",
}
BLOCKER_KEYS = {"id", "resolution"}
BLOCKER_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")

PHASES = {
    "authorize",
    "build_api",
    "build_ops",
    "build_web",
    "verify",
    "sign_release",
}
STATIC_CONTEXT = {
    "GITHUB_ACTIONS": "true",
    "GITHUB_API_URL": "https://api.github.com",
    "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REF_TYPE": "tag",
    "RUNNER_ENVIRONMENT": "github-hosted",
    "RUNNER_OS": "Linux",
    "RUNNER_ARCH": "X64",
}
REQUIRED_CONTEXT_KEYS = {
    *STATIC_CONTEXT,
    "GITHUB_REF",
    "GITHUB_REPOSITORY",
    "GITHUB_REPOSITORY_ID",
    "GITHUB_SHA",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_WORKFLOW_SHA",
}
PRODUCT_CREDENTIALS = {
    "CONTROL_API_READ_TOKEN",
    "CONTROL_WEB_READ_TOKEN",
}
ALLOWED_PRODUCT_CREDENTIALS = {
    "authorize": set(),
    "build_api": {"CONTROL_API_READ_TOKEN"},
    "build_ops": {"CONTROL_API_READ_TOKEN"},
    "build_web": {"CONTROL_WEB_READ_TOKEN"},
    "verify": set(),
    "sign_release": set(),
}


class GateV2Error(ValueError):
    """Readiness, audited policy, or execution context failed closed."""


def reject(message: str) -> None:
    raise GateV2Error(message)


def _load_policy_module():
    path = Path(__file__).with_name("validate-policy-v2.py")
    name = "control_release_policy_v2_for_gate"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        reject("production policy validator is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        reject("production policy validator is unavailable")
    return module


POLICY = _load_policy_module()


@dataclass(frozen=True)
class GateV2Attestation:
    """Minimal typed result for downstream in-process consumers."""

    controller_commit_sha: str
    controller_ref: str
    phase: str
    policy_sha256: str
    readiness_sha256: str

    def as_dict(self) -> dict[str, str]:
        return {
            "controller_commit_sha": self.controller_commit_sha,
            "controller_ref": self.controller_ref,
            "phase": self.phase,
            "policy_sha256": self.policy_sha256,
            "readiness_sha256": self.readiness_sha256,
        }


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


def load_readiness_bytes(path: Path) -> bytes:
    """Read one stable, owned, non-symlinked readiness document."""

    absolute = path.absolute()
    try:
        if absolute.resolve(strict=True) != absolute:
            reject("readiness path must not traverse symlinks")
        before = absolute.lstat()
        descriptor = os.open(
            absolute,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except GateV2Error:
        raise
    except OSError:
        reject("readiness document is unavailable")
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode)
            not in {0o400, 0o444, 0o600, 0o644}
            or not 0 < info.st_size <= MAX_READINESS_BYTES
            or (info.st_dev, info.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            reject(
                "readiness must be a bounded, owned, single-link regular "
                "file with a safe mode"
            )
        chunks: list[bytes] = []
        remaining = MAX_READINESS_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    except GateV2Error:
        raise
    except OSError:
        reject("readiness failed closed while being read")
    finally:
        os.close(descriptor)
    if (
        metadata_snapshot(after) != metadata_snapshot(info)
        or len(raw) != info.st_size
    ):
        reject("readiness changed while being read")
    return raw


def validate_readiness_bytes(
    raw: bytes,
) -> tuple[dict[str, Any], str]:
    if not 0 < len(raw) <= MAX_READINESS_BYTES:
        reject("readiness document has an invalid size")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda item: reject(
                f"non-finite number is forbidden: {item}"
            ),
        )
    except UnicodeDecodeError:
        reject("readiness document must be UTF-8")
    except json.JSONDecodeError as error:
        reject(
            "readiness document has invalid JSON at "
            f"line {error.lineno}, column {error.colno}"
        )
    if not isinstance(value, dict) or set(value) != READINESS_KEYS:
        reject("readiness document keys diverge")
    if raw != canonical_bytes(value):
        reject("readiness document must be canonical JSON")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 2
        or type(value["required_envelope_schema"]) is not int
        or value["required_envelope_schema"] != 6
        or type(value["required_approval_schema"]) is not int
        or value["required_approval_schema"] != 2
        or type(value["required_policy_schema"]) is not int
        or value["required_policy_schema"] != 2
        or value["required_ops_install_mode"] != "atomic-quiesced"
        or value["state"] not in {"unavailable", "ready"}
    ):
        reject("readiness contract is incompatible")

    blockers = value["blockers"]
    if not isinstance(blockers, list):
        reject("readiness blockers must be a list")
    seen: set[str] = set()
    ordered_ids: list[str] = []
    for blocker in blockers:
        if not isinstance(blocker, dict) or set(blocker) != BLOCKER_KEYS:
            reject("readiness blocker keys diverge")
        blocker_id = blocker["id"]
        resolution = blocker["resolution"]
        if (
            not isinstance(blocker_id, str)
            or BLOCKER_ID_RE.fullmatch(blocker_id) is None
            or blocker_id in seen
            or not isinstance(resolution, str)
            or not resolution
            or resolution != resolution.strip()
            or len(resolution.encode("utf-8")) > 1024
        ):
            reject("readiness blocker is invalid or duplicated")
        seen.add(blocker_id)
        ordered_ids.append(blocker_id)
    if ordered_ids != sorted(ordered_ids):
        reject("readiness blockers must be sorted by id")
    if value["state"] == "ready" and blockers:
        reject("ready state cannot retain blockers")
    if value["state"] == "unavailable" and not blockers:
        reject("unavailable state must identify blockers")
    return value, hashlib.sha256(raw).hexdigest()


def _required_string(
    environment: Mapping[str, str],
    name: str,
) -> str:
    value = environment.get(name)
    if not isinstance(value, str) or not value:
        reject(f"trusted GitHub context is invalid: {name}")
    return value


def _present(environment: Mapping[str, str], name: str) -> bool:
    value = environment.get(name)
    return isinstance(value, str) and bool(value)


def validate_execution_context(
    phase: str,
    environment: Mapping[str, str],
    policy: Mapping[str, Any],
) -> tuple[str, str]:
    """Validate one direct, tagged, GitHub-hosted controller execution."""

    if phase not in PHASES:
        reject("unknown release phase")
    if not isinstance(environment, Mapping):
        reject("execution environment must be a mapping")
    for name in REQUIRED_CONTEXT_KEYS:
        _required_string(environment, name)
    for name, expected in STATIC_CONTEXT.items():
        if environment.get(name) != expected:
            reject(f"trusted GitHub context is invalid: {name}")

    controller = policy["controller"]
    repository = controller["repository"]
    repository_id = controller["repository_id"]
    if environment.get("GITHUB_REPOSITORY") != repository:
        reject("trusted GitHub context is invalid: GITHUB_REPOSITORY")
    if environment.get("GITHUB_REPOSITORY_ID") != str(repository_id):
        reject("trusted GitHub context is invalid: GITHUB_REPOSITORY_ID")

    ref = _required_string(environment, "GITHUB_REF")
    try:
        tag_pattern = re.compile(controller["tag_ref_pattern"])
    except (TypeError, re.error):
        reject("controller tag pattern is invalid")
    if (
        not ref.startswith(controller["tag_ref_prefix"])
        or tag_pattern.fullmatch(ref) is None
    ):
        reject("controller must execute from an exact v6 semantic tag")

    expected_workflow_ref = (
        f"{repository}/{controller['workflow_path']}@{ref}"
    )
    if environment.get("GITHUB_WORKFLOW_REF") != expected_workflow_ref:
        reject("trusted GitHub context is invalid: GITHUB_WORKFLOW_REF")
    commit_sha = _required_string(environment, "GITHUB_SHA")
    if SHA1_RE.fullmatch(commit_sha) is None:
        reject("trusted GitHub context is invalid: GITHUB_SHA")
    if environment.get("GITHUB_WORKFLOW_SHA") != commit_sha:
        reject("trusted GitHub context is invalid: GITHUB_WORKFLOW_SHA")

    oidc_url = environment.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    oidc_token = environment.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    oidc_url_present = isinstance(oidc_url, str) and bool(oidc_url.strip())
    oidc_token_present = (
        isinstance(oidc_token, str) and bool(oidc_token.strip())
    )
    if phase == "sign_release":
        if not oidc_url_present or not oidc_token_present:
            reject("signer OIDC context is unavailable")
        if any(_present(environment, name) for name in PRODUCT_CREDENTIALS):
            reject("signer must not receive product credentials")
        if _present(environment, "CONTROL_SIGNER_SOURCE_CHECKOUT"):
            reject("signer must not receive a source checkout")
    else:
        if oidc_url_present or oidc_token_present:
            reject(f"{phase} must not receive an OIDC token")
        allowed = ALLOWED_PRODUCT_CREDENTIALS[phase]
        for name in PRODUCT_CREDENTIALS - allowed:
            if _present(environment, name):
                reject(f"{phase} must not receive {name}")
    return ref, commit_sha


def validate_release_gate(
    *,
    readiness_raw: bytes,
    policy_raw: bytes,
    audited_pins: Any,
    phase: str,
    environment: Mapping[str, str],
) -> GateV2Attestation:
    """Pure validation API; all trust inputs are explicit."""

    readiness, readiness_digest = validate_readiness_bytes(readiness_raw)
    try:
        policy, policy_digest = POLICY.validate_bytes(
            policy_raw,
            audited_pins=audited_pins,
        )
    except POLICY.ProductionPolicyError as error:
        reject(f"production policy rejected: {error}")
    if (
        readiness["required_policy_schema"] != policy["schema_version"]
        or readiness["required_approval_schema"]
        != policy["approval_schema_version"]
    ):
        reject("readiness and production policy schemas diverge")
    ref, commit_sha = validate_execution_context(
        phase,
        environment,
        policy,
    )
    if readiness["state"] != "ready":
        blocker_ids = ",".join(
            blocker["id"] for blocker in readiness["blockers"]
        )
        reject(f"RELEASE_POLICY_UNAVAILABLE ({blocker_ids})")
    return GateV2Attestation(
        controller_commit_sha=commit_sha,
        controller_ref=ref,
        phase=phase,
        policy_sha256=policy_digest,
        readiness_sha256=readiness_digest,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the fail-closed Control v6 policy gate",
    )
    parser.add_argument("--phase", required=True, choices=sorted(PHASES))
    args = parser.parse_args(argv)
    try:
        readiness_raw = load_readiness_bytes(READINESS_PATH)
        policy_raw = POLICY.load_policy_bytes(PRODUCTION_POLICY_PATH)
        result = validate_release_gate(
            readiness_raw=readiness_raw,
            policy_raw=policy_raw,
            audited_pins=POLICY.PRODUCTION_AUDITED_PINS,
            phase=args.phase,
            environment=dict(os.environ),
        )
    except GateV2Error as error:
        print(f"release gate v2 rejected: {error}", file=sys.stderr)
        return 78
    except POLICY.ProductionPolicyError as error:
        print(
            f"release gate v2 rejected: production policy rejected: {error}",
            file=sys.stderr,
        )
        return 78
    print(
        json.dumps(
            result.as_dict(),
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
