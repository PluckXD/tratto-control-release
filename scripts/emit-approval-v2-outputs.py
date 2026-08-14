#!/usr/bin/env python3
"""Emit only validated production-v2 authorization values to GITHUB_OUTPUT.

The ledger summary is evidence produced by the independent ledger validator,
not an authority by itself.  This module binds that evidence to a current
canonical approval, the separately audited production policy and trust epoch,
the exact reviewed workflow and controller-tag verifier bytes, and the exact
canonical source-free signer-freshness verifier manifest bytes before exposing
a deliberately small set of single-line GitHub outputs.

The command-line interface never accepts trust pins from arguments or the
environment.  Production remains unavailable while
``validate-policy-v2.py::PRODUCTION_AUDITED_TRUST_EPOCH`` is unconfigured.  The
pure ``validate_inputs`` API accepts an explicit typed ``AuditedTrustEpoch`` for
offline tests and independent review.
"""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Iterable, Mapping


HERE = Path(__file__).resolve().parent


def load_fixed_module(name: str, filename: str) -> Any:
    specification = importlib.util.spec_from_file_location(
        name,
        HERE / filename,
    )
    if specification is None or specification.loader is None:
        raise RuntimeError(f"fixed validator is unavailable: {filename}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


APPROVAL_V2 = load_fixed_module(
    "control_release_emit_approval_v2_validator",
    "validate-approval-v2.py",
)
POLICY_V2 = load_fixed_module(
    "control_release_emit_policy_v2_validator",
    "validate-policy-v2.py",
)
AuditedTrustEpoch = POLICY_V2.AuditedTrustEpoch

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RELEASE_ID_RE = APPROVAL_V2.RELEASE_ID_RE
CONTROLLER_TAG_RE = APPROVAL_V2.CONTROLLER_TAG_RE

MAX_APPROVAL_BYTES = APPROVAL_V2.MAX_FILE_BYTES
MAX_POLICY_BYTES = POLICY_V2.MAX_POLICY_BYTES
MAX_LEDGER_SUMMARY_BYTES = 4096
MAX_REVIEWED_SOURCE_BYTES = 1024 * 1024
MAX_GITHUB_OUTPUT_BYTES = 1024 * 1024
MAX_GITHUB_RELEASE_ID = 9_223_372_036_854_775_807

LEDGER_SUMMARY_KEYS = {
    "genesis_sha",
    "head_sha",
    "manifest_sha256",
    "record_count",
    "release_id",
}
OUTPUT_KEYS = (
    "api_sha",
    "ops_sha",
    "web_sha",
    "release_id",
    "approval_sha256",
    "policy_sha256",
    "ledger_head_sha",
    "controller_commit_sha",
    "controller_tag_signature_verifier_sha256",
    "controller_tag_ref",
    "controller_tag_object_sha",
    "controller_release_id",
    "signer_freshness_verifier_sha256",
    "trust_epoch",
)
OUTPUT_PATTERNS = {
    "api_sha": SHA1_RE,
    "ops_sha": SHA1_RE,
    "web_sha": SHA1_RE,
    "release_id": RELEASE_ID_RE,
    "approval_sha256": SHA256_RE,
    "policy_sha256": SHA256_RE,
    "ledger_head_sha": SHA1_RE,
    "controller_commit_sha": SHA1_RE,
    "controller_tag_signature_verifier_sha256": SHA256_RE,
    "controller_tag_ref": CONTROLLER_TAG_RE,
    "controller_tag_object_sha": SHA1_RE,
    "controller_release_id": re.compile(r"^[1-9][0-9]{0,18}$"),
    "signer_freshness_verifier_sha256": SHA256_RE,
    "trust_epoch": re.compile(r"^[1-9][0-9]*$"),
}


class ApprovalV2OutputsError(ValueError):
    """An output input or filesystem target violates the fail-closed contract."""


def reject(message: str) -> None:
    raise ApprovalV2OutputsError(message)


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


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            reject(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def parse_ledger_summary(raw: bytes) -> dict[str, Any]:
    if not 0 < len(raw) <= MAX_LEDGER_SUMMARY_BYTES:
        reject("ledger summary has an invalid size")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda item: reject(
                f"non-finite ledger summary value is forbidden: {item}"
            ),
        )
    except UnicodeDecodeError:
        reject("ledger summary must be UTF-8")
    except json.JSONDecodeError as error:
        reject(
            "ledger summary has invalid JSON at "
            f"line {error.lineno}, column {error.colno}"
        )
    except ApprovalV2OutputsError:
        raise
    except (RecursionError, ValueError):
        reject("ledger summary JSON exceeds safe parser limits")
    if not isinstance(value, dict) or set(value) != LEDGER_SUMMARY_KEYS:
        reject("ledger summary keys diverge")
    if raw != canonical_bytes(value):
        reject("ledger summary must be canonical JSON")
    for key in ("genesis_sha", "head_sha"):
        if (
            not isinstance(value[key], str)
            or SHA1_RE.fullmatch(value[key]) is None
        ):
            reject(f"ledger summary {key} has invalid format")
    if (
        not isinstance(value["manifest_sha256"], str)
        or SHA256_RE.fullmatch(value["manifest_sha256"]) is None
    ):
        reject("ledger summary manifest_sha256 has invalid format")
    if (
        not isinstance(value["release_id"], str)
        or RELEASE_ID_RE.fullmatch(value["release_id"]) is None
    ):
        reject("ledger summary release_id has invalid format")
    if (
        type(value["record_count"]) is not int
        or not 1
        <= value["record_count"]
        <= APPROVAL_V2.MAX_LEDGER_SEQUENCE
    ):
        reject("ledger summary record_count is invalid")
    return value


def validate_policy_bindings(
    approval: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> None:
    approval_controller = approval["controller"]
    policy_controller = policy["controller"]
    controller_bindings = {
        "controller_tag_signature_verifier_sha256": (
            "controller_tag_signature_verifier_sha256"
        ),
        "repository": "repository",
        "repository_id": "repository_id",
        "signer_freshness_verifier_sha256": (
            "signer_freshness_verifier_sha256"
        ),
        "workflow_path": "workflow_path",
        "workflow_sha256": "workflow_sha256",
    }
    for approval_key, policy_key in controller_bindings.items():
        if (
            approval_controller[approval_key]
            != policy_controller[policy_key]
        ):
            reject(
                "approval controller binding diverges from audited policy: "
                f"{approval_key}"
            )
    if approval["policy"]["trust_epoch"] != policy["trust_epoch"]:
        reject(
            "approval trust epoch diverges from audited policy"
        )

    approval_ledger = approval["ledger"]
    policy_ledger = policy["ledger"]
    for key in ("repository", "repository_id", "ref", "genesis_sha"):
        if approval_ledger[key] != policy_ledger[key]:
            reject(
                "approval ledger binding diverges from audited policy: "
                f"{key}"
            )


def validate_inputs(
    *,
    approval_raw: bytes,
    ledger_summary_raw: bytes,
    policy_raw: bytes,
    workflow_raw: bytes,
    controller_tag_signature_verifier_raw: bytes,
    signer_freshness_verifier_manifest_raw: bytes,
    audited_trust_epoch: AuditedTrustEpoch,
    now: dt.datetime | None = None,
) -> dict[str, str]:
    """Validate immutable input bytes and return the sole allowed outputs.

    This function performs no filesystem, environment, subprocess, network, or
    output operations.  Callers must provide the typed ``AuditedTrustEpoch``
    contract defined by the fixed production-policy validator.
    """

    for raw, maximum, label in (
        (approval_raw, MAX_APPROVAL_BYTES, "approval"),
        (
            ledger_summary_raw,
            MAX_LEDGER_SUMMARY_BYTES,
            "ledger summary",
        ),
        (policy_raw, MAX_POLICY_BYTES, "production policy"),
        (
            workflow_raw,
            MAX_REVIEWED_SOURCE_BYTES,
            "controller workflow",
        ),
        (
            controller_tag_signature_verifier_raw,
            MAX_REVIEWED_SOURCE_BYTES,
            "controller tag signature verifier",
        ),
        (
            signer_freshness_verifier_manifest_raw,
            MAX_REVIEWED_SOURCE_BYTES,
            "signer freshness verifier manifest",
        ),
    ):
        if type(raw) is not bytes or not 0 < len(raw) <= maximum:
            reject(f"{label} bytes have an invalid size")
    if (
        controller_tag_signature_verifier_raw
        == signer_freshness_verifier_manifest_raw
    ):
        reject(
            "controller tag signature verifier and signer freshness verifier "
            "manifest must use distinct bytes"
        )

    try:
        approval = APPROVAL_V2.validate_bytes(
            approval_raw,
            now=now,
            historical=False,
        )
    except APPROVAL_V2.ApprovalV2Error as error:
        reject(f"approval rejected: {error}")
    except (RecursionError, TypeError, ValueError):
        reject("approval rejected: parser safety limit exceeded")
    try:
        policy, policy_sha256 = POLICY_V2.validate_bytes(
            policy_raw,
            audited_trust_epoch=audited_trust_epoch,
        )
    except POLICY_V2.ProductionPolicyError as error:
        reject(f"production policy rejected: {error}")
    except (RecursionError, TypeError, ValueError):
        reject("production policy rejected: parser safety limit exceeded")

    summary = parse_ledger_summary(ledger_summary_raw)
    approval_sha256 = hashlib.sha256(approval_raw).hexdigest()
    workflow_sha256 = hashlib.sha256(workflow_raw).hexdigest()
    controller_tag_signature_verifier_sha256 = hashlib.sha256(
        controller_tag_signature_verifier_raw
    ).hexdigest()
    signer_freshness_verifier_sha256 = hashlib.sha256(
        signer_freshness_verifier_manifest_raw
    ).hexdigest()
    if (
        controller_tag_signature_verifier_sha256
        == signer_freshness_verifier_sha256
    ):
        reject(
            "controller tag signature verifier and signer freshness verifier "
            "manifest must use distinct SHA-256 digests"
        )

    if approval["policy"]["digest_sha256"] != policy_sha256:
        reject("approval policy digest diverges from exact policy bytes")

    controller = approval["controller"]
    if controller["workflow_sha256"] != workflow_sha256:
        reject("approval workflow digest diverges from exact workflow bytes")
    if (
        controller["controller_tag_signature_verifier_sha256"]
        != controller_tag_signature_verifier_sha256
    ):
        reject(
            "approval controller tag signature verifier digest diverges from "
            "exact verifier bytes"
        )
    if (
        controller["signer_freshness_verifier_sha256"]
        != signer_freshness_verifier_sha256
    ):
        reject(
            "approval signer freshness verifier digest diverges from exact "
            "source-free manifest bytes"
        )
    validate_policy_bindings(approval, policy)

    ledger = approval["ledger"]
    if summary["genesis_sha"] != ledger["genesis_sha"]:
        reject("ledger summary genesis diverges from approval")
    if summary["release_id"] != approval["release_id"]:
        reject("ledger summary release_id diverges from approval")
    if summary["record_count"] != ledger["sequence"]:
        reject("ledger summary record_count must equal approval sequence")
    if summary["manifest_sha256"] != approval_sha256:
        reject("ledger summary manifest digest diverges from approval")
    if summary["head_sha"] in {
        ledger["parent_commit_sha"],
        ledger["genesis_sha"],
    }:
        reject("ledger head must be distinct from parent and genesis")

    release_number = controller["immutable_release_id"]
    if (
        type(release_number) is not int
        or release_number <= 0
        or release_number > MAX_GITHUB_RELEASE_ID
    ):
        reject("controller immutable release ID exceeds the output contract")

    outputs = {
        "api_sha": approval["api"]["commit_sha"],
        "ops_sha": approval["ops"]["commit_sha"],
        "web_sha": approval["web"]["commit_sha"],
        "release_id": approval["release_id"],
        "approval_sha256": approval_sha256,
        "policy_sha256": policy_sha256,
        "ledger_head_sha": summary["head_sha"],
        "controller_commit_sha": controller["commit_sha"],
        "controller_tag_signature_verifier_sha256": (
            controller_tag_signature_verifier_sha256
        ),
        "controller_tag_ref": controller["tag_ref"],
        "controller_tag_object_sha": controller["tag_object_sha"],
        "controller_release_id": str(release_number),
        "signer_freshness_verifier_sha256": (
            signer_freshness_verifier_sha256
        ),
        "trust_epoch": str(approval["policy"]["trust_epoch"]),
    }
    validate_output_values(outputs)
    return outputs


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


def safe_input_mode(info: os.stat_result) -> bool:
    permissions = stat.S_IMODE(info.st_mode)
    special = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
    return (
        info.st_uid == os.geteuid()
        and permissions & 0o400 != 0
        and permissions & 0o022 == 0
        and info.st_mode & special == 0
    )


def safe_output_mode(info: os.stat_result) -> bool:
    permissions = stat.S_IMODE(info.st_mode)
    special = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
    return (
        info.st_uid == os.geteuid()
        and permissions & 0o200 != 0
        and permissions & 0o022 == 0
        and info.st_mode & special == 0
    )


def read_stable_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
) -> tuple[bytes, tuple[int, int]]:
    """Read a bounded owned file through one stable, non-symlinked FD."""

    absolute = path.absolute()
    try:
        if absolute.resolve(strict=True) != absolute:
            reject(f"{label} path must not traverse symlinks")
        before_path = absolute.lstat()
    except ApprovalV2OutputsError:
        raise
    except OSError:
        reject(f"{label} is unavailable")
    if (
        not stat.S_ISREG(before_path.st_mode)
        or stat.S_ISLNK(before_path.st_mode)
        or before_path.st_nlink != 1
        or not safe_input_mode(before_path)
        or not 0 < before_path.st_size <= max_bytes
    ):
        reject(
            f"{label} must be a bounded, owned, single-link, "
            "non-writable-by-others regular file"
        )

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError:
        reject(f"{label} cannot be opened safely")
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not safe_input_mode(before)
            or not 0 < before.st_size <= max_bytes
            or (before.st_dev, before.st_ino)
            != (before_path.st_dev, before_path.st_ino)
        ):
            reject(f"{label} changed before it was opened")
        chunks: list[bytes] = []
        total = 0
        while True:
            try:
                chunk = os.read(
                    descriptor,
                    min(65536, max_bytes + 1 - total),
                )
            except OSError:
                reject(f"{label} failed closed while being read")
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                reject(f"{label} exceeds its size bound")
        after = os.fstat(descriptor)
        if (
            total != before.st_size
            or metadata_snapshot(after) != metadata_snapshot(before)
        ):
            reject(f"{label} changed while being read")
        try:
            after_path = absolute.lstat()
        except OSError:
            reject(f"{label} pathname changed while being read")
        if metadata_snapshot(after_path) != metadata_snapshot(before):
            reject(f"{label} pathname changed while being read")
        return b"".join(chunks), (before.st_dev, before.st_ino)
    except ApprovalV2OutputsError:
        raise
    except OSError:
        reject(f"{label} failed closed during stable read")
    finally:
        os.close(descriptor)


def validate_output_values(values: Mapping[str, str]) -> None:
    if not isinstance(values, Mapping) or set(values) != set(OUTPUT_KEYS):
        reject("GitHub output keys diverge")
    for key in OUTPUT_KEYS:
        value = values[key]
        if (
            type(value) is not str
            or len(value) > 128
            or OUTPUT_PATTERNS[key].fullmatch(value) is None
            or any(
                character in value
                for character in ("\r", "\n", "=", "%", "\0")
            )
        ):
            reject(f"GitHub output value is unsafe: {key}")


def append_github_outputs(
    path: Path,
    values: Mapping[str, str],
    *,
    input_identities: Iterable[tuple[int, int]] = (),
) -> None:
    """Append all values with one O_APPEND write to a stable GitHub file."""

    validate_output_values(values)
    payload = "".join(
        f"{key}={values[key]}\n"
        for key in OUTPUT_KEYS
    ).encode("ascii")
    absolute = path.absolute()
    try:
        if absolute.resolve(strict=True) != absolute:
            reject("GITHUB_OUTPUT path must not traverse symlinks")
        before_path = absolute.lstat()
    except ApprovalV2OutputsError:
        raise
    except OSError:
        reject("GITHUB_OUTPUT is unavailable")
    identity = (before_path.st_dev, before_path.st_ino)
    if identity in set(input_identities):
        reject("GITHUB_OUTPUT must not alias a validated input")
    if (
        not stat.S_ISREG(before_path.st_mode)
        or stat.S_ISLNK(before_path.st_mode)
        or before_path.st_nlink != 1
        or not safe_output_mode(before_path)
        or before_path.st_size < 0
        or before_path.st_size + len(payload) > MAX_GITHUB_OUTPUT_BYTES
    ):
        reject(
            "GITHUB_OUTPUT must be a bounded, owned, single-link, "
            "non-writable-by-others regular file"
        )

    flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError:
        reject("GITHUB_OUTPUT cannot be opened safely")
    locked = False
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not safe_output_mode(before)
            or metadata_snapshot(before) != metadata_snapshot(before_path)
            or before.st_size + len(payload) > MAX_GITHUB_OUTPUT_BYTES
        ):
            reject("GITHUB_OUTPUT changed before it was opened")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            locked = True
            locked_before = os.fstat(descriptor)
            if metadata_snapshot(locked_before) != metadata_snapshot(before):
                reject("GITHUB_OUTPUT changed before append")
            written = os.write(descriptor, payload)
            if written != len(payload):
                reject("GITHUB_OUTPUT append was incomplete")
            os.fsync(descriptor)
            after = os.fstat(descriptor)
        except ApprovalV2OutputsError:
            raise
        except OSError:
            reject("GITHUB_OUTPUT append failed closed")
        if (
            (after.st_dev, after.st_ino) != identity
            or after.st_nlink != 1
            or not safe_output_mode(after)
            or after.st_size != before.st_size + len(payload)
        ):
            reject("GITHUB_OUTPUT changed during append")
        try:
            after_path = absolute.lstat()
        except OSError:
            reject("GITHUB_OUTPUT pathname changed during append")
        if (
            (after_path.st_dev, after_path.st_ino) != identity
            or metadata_snapshot(after_path) != metadata_snapshot(after)
        ):
            reject("GITHUB_OUTPUT pathname changed during append")
    except ApprovalV2OutputsError:
        raise
    except OSError:
        reject("GITHUB_OUTPUT append failed closed")
    finally:
        if locked:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(descriptor)


def validate_files(
    *,
    approval_path: Path,
    ledger_summary_path: Path,
    policy_path: Path,
    workflow_path: Path,
    controller_tag_signature_verifier_path: Path,
    signer_freshness_verifier_manifest_path: Path,
    audited_trust_epoch: AuditedTrustEpoch,
    now: dt.datetime | None = None,
) -> tuple[dict[str, str], tuple[tuple[int, int], ...]]:
    inputs = (
        ("approval", approval_path, MAX_APPROVAL_BYTES),
        (
            "ledger summary",
            ledger_summary_path,
            MAX_LEDGER_SUMMARY_BYTES,
        ),
        ("production policy", policy_path, MAX_POLICY_BYTES),
        (
            "controller workflow",
            workflow_path,
            MAX_REVIEWED_SOURCE_BYTES,
        ),
        (
            "controller tag signature verifier",
            controller_tag_signature_verifier_path,
            MAX_REVIEWED_SOURCE_BYTES,
        ),
        (
            "signer freshness verifier manifest",
            signer_freshness_verifier_manifest_path,
            MAX_REVIEWED_SOURCE_BYTES,
        ),
    )
    raw_values: list[bytes] = []
    identities: list[tuple[int, int]] = []
    for label, path, maximum in inputs:
        raw, identity = read_stable_file(
            path,
            label,
            max_bytes=maximum,
        )
        raw_values.append(raw)
        identities.append(identity)
    if len(identities) != len(set(identities)):
        reject("validated input files must have distinct identities")
    outputs = validate_inputs(
        approval_raw=raw_values[0],
        ledger_summary_raw=raw_values[1],
        policy_raw=raw_values[2],
        workflow_raw=raw_values[3],
        controller_tag_signature_verifier_raw=raw_values[4],
        signer_freshness_verifier_manifest_raw=raw_values[5],
        audited_trust_epoch=audited_trust_epoch,
        now=now,
    )
    return outputs, tuple(identities)


class FailClosedParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        reject(f"invalid command line: {message}")


def main(arguments: list[str] | None = None) -> int:
    parser = FailClosedParser()
    parser.add_argument("--approval", required=True, type=Path)
    parser.add_argument("--ledger-summary", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--workflow", required=True, type=Path)
    parser.add_argument(
        "--controller-tag-signature-verifier",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--signer-freshness-verifier-manifest",
        required=True,
        type=Path,
    )
    parser.add_argument("--github-output", required=True, type=Path)
    try:
        args = parser.parse_args(arguments)
        outputs, identities = validate_files(
            approval_path=args.approval,
            ledger_summary_path=args.ledger_summary,
            policy_path=args.policy,
            workflow_path=args.workflow,
            controller_tag_signature_verifier_path=(
                args.controller_tag_signature_verifier
            ),
            signer_freshness_verifier_manifest_path=(
                args.signer_freshness_verifier_manifest
            ),
            audited_trust_epoch=POLICY_V2.PRODUCTION_AUDITED_TRUST_EPOCH,
        )
        append_github_outputs(
            args.github_output,
            outputs,
            input_identities=identities,
        )
    except ApprovalV2OutputsError as error:
        print(f"approval v2 outputs rejected: {error}", file=sys.stderr)
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
