from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import datetime as dt
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "emit-approval-v2-outputs.py"
SPEC = importlib.util.spec_from_file_location(
    "control_release_emit_approval_v2_outputs",
    SCRIPT,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

NOW = dt.datetime(2026, 8, 1, 12, 30, tzinfo=dt.timezone.utc)
WORKFLOW_RAW = b"name: immutable-control-release\non: workflow_dispatch\n"
VERIFIER_RAW = b"#!/usr/bin/env python3\n# fixed local tag verifier\n"
WORKFLOW_SHA256 = hashlib.sha256(WORKFLOW_RAW).hexdigest()
VERIFIER_SHA256 = hashlib.sha256(VERIFIER_RAW).hexdigest()
PINS = MODULE.POLICY_V2.AuditedPins(
    controller_repository_id=123456789,
    controller_workflow_sha256=WORKFLOW_SHA256,
    controller_tag_trust_root_sha256="c" * 64,
    controller_tag_verifier_sha256=VERIFIER_SHA256,
    ledger_repository_id=234567890,
    ledger_genesis_sha="a" * 40,
)


def canonical(value: dict) -> bytes:
    return MODULE.canonical_bytes(value)


def approval_value(
    *,
    policy_sha256: str,
    workflow_sha256: str = WORKFLOW_SHA256,
    verifier_sha256: str = VERIFIER_SHA256,
    issued_at: dt.datetime | None = None,
) -> dict:
    issued = (
        dt.datetime(2026, 8, 1, 12, 0, tzinfo=dt.timezone.utc)
        if issued_at is None
        else issued_at
    ).replace(microsecond=0)
    expires = issued + dt.timedelta(hours=1)
    release_id = (
        f"ctl-{issued.strftime('%Y%m%dT%H%M%SZ')}-outputs"
    )
    return {
        "api": {
            "approved_ref": "refs/heads/main",
            "commit_sha": "1" * 40,
            "repository": "PluckXD/tratto-api",
            "required_ancestors": ["2" * 40],
        },
        "controller": {
            "commit_sha": "5" * 40,
            "immutable_release_id": 12001,
            "repository": "PluckXD/tratto-control-release",
            "repository_id": PINS.controller_repository_id,
            "signer_verifier_sha256": verifier_sha256,
            "tag_object_sha": "6" * 40,
            "tag_ref": "refs/tags/control-controller-v6.0.0",
            "workflow_path": ".github/workflows/control-release.yml",
            "workflow_sha256": workflow_sha256,
        },
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ledger": {
            "genesis_sha": PINS.ledger_genesis_sha,
            "parent_commit_sha": "7" * 40,
            "previous_manifest_sha256": "8" * 64,
            "ref": "refs/heads/main",
            "repository": "PluckXD/tratto-control-release-ledger",
            "repository_id": PINS.ledger_repository_id,
            "sequence": 2,
        },
        "migration": {
            "base_revision": "j1transpcod",
            "database_scope": "control-and-tenant-fleet",
            "fleet_preflight_sha256": "9" * 64,
            "head_revision": "f29controlexec",
            "mode": "expand-only",
            "tenant_catalog_count": 1,
            "tenant_catalog_sha256": "d" * 64,
            "tenant_fleet_base_revision": "j1transpcod",
        },
        "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
        "ops": {
            "approved_ref": "refs/heads/main",
            "commit_sha": "1" * 40,
            "repository": "PluckXD/tratto-api",
            "required_ancestors": ["3" * 40],
        },
        "policy": {
            "digest_sha256": policy_sha256,
            "name": "control-production-v2",
            "path": "policies/control-production-v2.json",
            "repository": "PluckXD/tratto-control-release",
        },
        "release_id": release_id,
        "schema_version": 2,
        "web": {
            "approved_ref": "refs/heads/main",
            "commit_sha": "4" * 40,
            "repository": "PluckXD/tratto-web",
            "required_ancestors": ["e" * 40],
        },
    }


def materials(
    *,
    workflow_raw: bytes = WORKFLOW_RAW,
    verifier_raw: bytes = VERIFIER_RAW,
    issued_at: dt.datetime | None = None,
) -> dict:
    pins = MODULE.POLICY_V2.AuditedPins(
        **{
            **PINS.__dict__,
            "controller_workflow_sha256": hashlib.sha256(
                workflow_raw
            ).hexdigest(),
            "controller_tag_verifier_sha256": hashlib.sha256(
                verifier_raw
            ).hexdigest(),
        }
    )
    policy = MODULE.POLICY_V2.expected_policy(pins)
    policy_raw = MODULE.POLICY_V2.canonical_bytes(policy)
    approval = approval_value(
        policy_sha256=hashlib.sha256(policy_raw).hexdigest(),
        workflow_sha256=hashlib.sha256(workflow_raw).hexdigest(),
        verifier_sha256=hashlib.sha256(verifier_raw).hexdigest(),
        issued_at=issued_at,
    )
    approval["controller"]["repository_id"] = pins.controller_repository_id
    approval["ledger"]["repository_id"] = pins.ledger_repository_id
    approval["ledger"]["genesis_sha"] = pins.ledger_genesis_sha
    approval_raw = canonical(approval)
    summary = {
        "genesis_sha": approval["ledger"]["genesis_sha"],
        "head_sha": "b" * 40,
        "manifest_sha256": hashlib.sha256(approval_raw).hexdigest(),
        "record_count": approval["ledger"]["sequence"],
        "release_id": approval["release_id"],
    }
    return {
        "approval": approval,
        "approval_raw": approval_raw,
        "ledger_summary": summary,
        "ledger_summary_raw": canonical(summary),
        "pins": pins,
        "policy": policy,
        "policy_raw": policy_raw,
        "signer_verifier_raw": verifier_raw,
        "workflow_raw": workflow_raw,
    }


def validate(bundle: dict, *, now: dt.datetime = NOW) -> dict[str, str]:
    return MODULE.validate_inputs(
        approval_raw=bundle["approval_raw"],
        ledger_summary_raw=bundle["ledger_summary_raw"],
        policy_raw=bundle["policy_raw"],
        workflow_raw=bundle["workflow_raw"],
        signer_verifier_raw=bundle["signer_verifier_raw"],
        audited_pins=bundle["pins"],
        now=now,
    )


def recanonicalize_approval(bundle: dict) -> None:
    bundle["approval_raw"] = canonical(bundle["approval"])


def recanonicalize_summary(bundle: dict) -> None:
    bundle["ledger_summary_raw"] = canonical(bundle["ledger_summary"])


def expected_outputs(bundle: dict) -> dict[str, str]:
    approval = bundle["approval"]
    return {
        "api_sha": "1" * 40,
        "ops_sha": "1" * 40,
        "web_sha": "4" * 40,
        "release_id": approval["release_id"],
        "approval_sha256": hashlib.sha256(
            bundle["approval_raw"]
        ).hexdigest(),
        "ledger_head_sha": "b" * 40,
        "controller_commit_sha": "5" * 40,
        "controller_tag_ref": "refs/tags/control-controller-v6.0.0",
        "controller_tag_object_sha": "6" * 40,
        "controller_release_id": "12001",
    }


def test_pure_api_accepts_exact_current_cross_bound_inputs() -> None:
    bundle = materials()
    assert validate(bundle) == expected_outputs(bundle)


def test_pure_api_performs_no_file_or_environment_access(monkeypatch) -> None:
    bundle = materials()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("pure validation attempted external access")

    monkeypatch.setattr(MODULE.os, "open", forbidden)
    monkeypatch.setattr(MODULE.os, "getenv", forbidden)
    assert validate(bundle) == expected_outputs(bundle)


def test_workflow_and_verifier_are_hashed_as_bytes_not_imported_or_executed() -> None:
    bundle = materials(
        workflow_raw=b"\0this is not YAML or executable code\n",
        verifier_raw=b"raise RuntimeError('must never execute')\n",
    )
    assert validate(bundle)["controller_commit_sha"] == "5" * 40


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda bundle: bundle["ledger_summary"].update(
                {"genesis_sha": "c" * 40}
            ),
            "genesis",
        ),
        (
            lambda bundle: bundle["ledger_summary"].update(
                {"release_id": "ctl-20260801T120000Z-other"}
            ),
            "release_id",
        ),
        (
            lambda bundle: bundle["ledger_summary"].update(
                {"record_count": 1}
            ),
            "record_count",
        ),
        (
            lambda bundle: bundle["ledger_summary"].update(
                {"manifest_sha256": "f" * 64}
            ),
            "manifest digest",
        ),
        (
            lambda bundle: bundle["ledger_summary"].update(
                {
                    "head_sha": bundle["approval"]["ledger"][
                        "parent_commit_sha"
                    ]
                }
            ),
            "distinct",
        ),
        (
            lambda bundle: bundle["ledger_summary"].update(
                {
                    "head_sha": bundle["approval"]["ledger"][
                        "genesis_sha"
                    ]
                }
            ),
            "distinct",
        ),
    ],
)
def test_rejects_ledger_summary_cross_binding_drift(
    mutate,
    message: str,
) -> None:
    bundle = materials()
    mutate(bundle)
    recanonicalize_summary(bundle)
    with pytest.raises(MODULE.ApprovalV2OutputsError, match=message):
        validate(bundle)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: value.update({"extra": True}),
            "keys diverge",
        ),
        (
            lambda value: value.pop("release_id"),
            "keys diverge",
        ),
        (
            lambda value: value.update({"record_count": True}),
            "record_count",
        ),
        (
            lambda value: value.update({"record_count": 0}),
            "record_count",
        ),
        (
            lambda value: value.update({"head_sha": "B" * 40}),
            "head_sha",
        ),
        (
            lambda value: value.update({"manifest_sha256": "f" * 63}),
            "manifest_sha256",
        ),
        (
            lambda value: value.update({"release_id": "unsafe\nvalue"}),
            "release_id",
        ),
    ],
)
def test_rejects_invalid_ledger_summary_shape(mutate, message: str) -> None:
    bundle = materials()
    mutate(bundle["ledger_summary"])
    recanonicalize_summary(bundle)
    with pytest.raises(MODULE.ApprovalV2OutputsError, match=message):
        validate(bundle)


@pytest.mark.parametrize(
    "raw_transform",
    [
        lambda raw: json.dumps(
            json.loads(raw),
            indent=2,
        ).encode("utf-8")
        + b"\n",
        lambda raw: raw.rstrip(b"\n"),
        lambda raw: raw.replace(
            b'{"genesis_sha":',
            b'{"genesis_sha":"' + b"a" * 40 + b'","genesis_sha":',
            1,
        ),
    ],
)
def test_rejects_noncanonical_or_duplicate_ledger_summary(
    raw_transform,
) -> None:
    bundle = materials()
    bundle["ledger_summary_raw"] = raw_transform(
        bundle["ledger_summary_raw"]
    )
    with pytest.raises(MODULE.ApprovalV2OutputsError):
        validate(bundle)


def test_rejects_expired_approval_instead_of_historical_acceptance() -> None:
    bundle = materials()
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="expired",
    ):
        validate(
            bundle,
            now=dt.datetime(
                2026,
                8,
                1,
                13,
                0,
                1,
                tzinfo=dt.timezone.utc,
            ),
        )


def test_rejects_noncanonical_approval() -> None:
    bundle = materials()
    bundle["approval_raw"] = json.dumps(
        bundle["approval"],
        indent=2,
    ).encode("utf-8")
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="canonical",
    ):
        validate(bundle)


@pytest.mark.parametrize(
    ("target", "replacement", "message"),
    [
        (
            ("policy", "digest_sha256"),
            "0" * 64,
            "policy digest",
        ),
        (
            ("controller", "workflow_sha256"),
            "0" * 64,
            "workflow digest",
        ),
        (
            ("controller", "signer_verifier_sha256"),
            "0" * 64,
            "signer verifier digest",
        ),
        (
            ("controller", "repository_id"),
            PINS.controller_repository_id + 1,
            "controller binding",
        ),
        (
            ("ledger", "repository_id"),
            PINS.ledger_repository_id + 1,
            "ledger binding",
        ),
    ],
)
def test_rejects_exact_policy_workflow_and_verifier_binding_drift(
    target: tuple[str, str],
    replacement: object,
    message: str,
) -> None:
    bundle = materials()
    bundle["approval"][target[0]][target[1]] = replacement
    recanonicalize_approval(bundle)
    if target != ("policy", "digest_sha256"):
        bundle["ledger_summary"]["manifest_sha256"] = hashlib.sha256(
            bundle["approval_raw"]
        ).hexdigest()
        recanonicalize_summary(bundle)
    with pytest.raises(MODULE.ApprovalV2OutputsError, match=message):
        validate(bundle)


def test_rejects_exact_workflow_bytes_changed_after_approval() -> None:
    bundle = materials()
    bundle["workflow_raw"] += b"# post-approval mutation\n"
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="workflow digest",
    ):
        validate(bundle)


def test_rejects_exact_verifier_bytes_changed_after_approval() -> None:
    bundle = materials()
    bundle["signer_verifier_raw"] += b"# post-approval mutation\n"
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="signer verifier digest",
    ):
        validate(bundle)


def test_rejects_verifier_that_matches_approval_but_not_audited_policy() -> None:
    bundle = materials()
    replacement = b"#!/bin/false\n"
    bundle["signer_verifier_raw"] = replacement
    bundle["approval"]["controller"]["signer_verifier_sha256"] = (
        hashlib.sha256(replacement).hexdigest()
    )
    recanonicalize_approval(bundle)
    bundle["ledger_summary"]["manifest_sha256"] = hashlib.sha256(
        bundle["approval_raw"]
    ).hexdigest()
    recanonicalize_summary(bundle)
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="audited policy",
    ):
        validate(bundle)


def test_rejects_policy_that_does_not_match_explicit_audited_pins() -> None:
    bundle = materials()
    changed_pins = MODULE.POLICY_V2.AuditedPins(
        **{
            **bundle["pins"].__dict__,
            "ledger_repository_id": bundle["pins"].ledger_repository_id + 1,
        }
    )
    bundle["pins"] = changed_pins
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="audited pins",
    ):
        validate(bundle)


def test_rejects_release_identifier_outside_bounded_output_contract() -> None:
    bundle = materials()
    bundle["approval"]["controller"]["immutable_release_id"] = (
        MODULE.MAX_GITHUB_RELEASE_ID + 1
    )
    recanonicalize_approval(bundle)
    bundle["ledger_summary"]["manifest_sha256"] = hashlib.sha256(
        bundle["approval_raw"]
    ).hexdigest()
    recanonicalize_summary(bundle)
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="release ID",
    ):
        validate(bundle)


def write_file(path: Path, raw: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def prepared_files(
    tmp_path: Path,
    *,
    bundle: dict | None = None,
) -> tuple[dict, dict[str, Path]]:
    selected = materials() if bundle is None else bundle
    paths = {
        "approval": write_file(
            tmp_path / "approval.json",
            selected["approval_raw"],
        ),
        "ledger_summary": write_file(
            tmp_path / "ledger-summary.json",
            selected["ledger_summary_raw"],
        ),
        "policy": write_file(
            tmp_path / "policy.json",
            selected["policy_raw"],
        ),
        "workflow": write_file(
            tmp_path / "control-release.yml",
            selected["workflow_raw"],
        ),
        "signer_verifier": write_file(
            tmp_path / "signer-verifier.py",
            selected["signer_verifier_raw"],
            0o700,
        ),
        "github_output": write_file(
            tmp_path / "github-output",
            b"existing=safe\n",
        ),
    }
    return selected, paths


def validate_files(
    bundle: dict,
    paths: dict[str, Path],
) -> tuple[dict[str, str], tuple[tuple[int, int], ...]]:
    return MODULE.validate_files(
        approval_path=paths["approval"],
        ledger_summary_path=paths["ledger_summary"],
        policy_path=paths["policy"],
        workflow_path=paths["workflow"],
        signer_verifier_path=paths["signer_verifier"],
        audited_pins=bundle["pins"],
        now=NOW,
    )


def test_stable_file_api_and_atomic_append_emit_only_allowlisted_lines(
    tmp_path: Path,
) -> None:
    bundle, paths = prepared_files(tmp_path)
    outputs, identities = validate_files(bundle, paths)
    MODULE.append_github_outputs(
        paths["github_output"],
        outputs,
        input_identities=identities,
    )
    expected_lines = ["existing=safe"]
    expected_lines.extend(
        f"{key}={outputs[key]}"
        for key in MODULE.OUTPUT_KEYS
    )
    raw = paths["github_output"].read_bytes()
    assert raw == ("\n".join(expected_lines) + "\n").encode("ascii")
    assert b"nonce" not in raw
    assert b"token" not in raw
    assert b"{" not in raw
    assert b"}" not in raw


@pytest.mark.parametrize(
    "input_name",
    [
        "approval",
        "ledger_summary",
        "policy",
        "workflow",
        "signer_verifier",
    ],
)
def test_rejects_symlinked_input_files(
    tmp_path: Path,
    input_name: str,
) -> None:
    bundle, paths = prepared_files(tmp_path)
    alias = tmp_path / f"{input_name}-symlink"
    alias.symlink_to(paths[input_name])
    paths[input_name] = alias
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="symlink",
    ):
        validate_files(bundle, paths)


@pytest.mark.parametrize(
    "input_name",
    [
        "approval",
        "ledger_summary",
        "policy",
        "workflow",
        "signer_verifier",
    ],
)
def test_rejects_hardlinked_input_files(
    tmp_path: Path,
    input_name: str,
) -> None:
    bundle, paths = prepared_files(tmp_path)
    alias = tmp_path / f"{input_name}-hardlink"
    os.link(paths[input_name], alias)
    paths[input_name] = alias
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="single-link",
    ):
        validate_files(bundle, paths)


@pytest.mark.parametrize(
    "input_name",
    [
        "approval",
        "ledger_summary",
        "policy",
        "workflow",
        "signer_verifier",
    ],
)
def test_rejects_input_files_writable_by_other_accounts(
    tmp_path: Path,
    input_name: str,
) -> None:
    bundle, paths = prepared_files(tmp_path)
    paths[input_name].chmod(0o666)
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="non-writable-by-others",
    ):
        validate_files(bundle, paths)


def test_rejects_same_single_link_file_reused_for_two_input_roles(
    tmp_path: Path,
) -> None:
    shared = b"shared reviewed bytes\n"
    bundle = materials(workflow_raw=shared, verifier_raw=shared)
    bundle, paths = prepared_files(tmp_path, bundle=bundle)
    paths["signer_verifier"].unlink()
    paths["signer_verifier"] = paths["workflow"]
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="distinct identities",
    ):
        validate_files(bundle, paths)


def test_rejects_empty_and_oversized_reviewed_sources(
    tmp_path: Path,
) -> None:
    bundle, paths = prepared_files(tmp_path)
    paths["workflow"].write_bytes(b"")
    with pytest.raises(MODULE.ApprovalV2OutputsError, match="bounded"):
        validate_files(bundle, paths)

    paths["workflow"].write_bytes(
        b"x" * (MODULE.MAX_REVIEWED_SOURCE_BYTES + 1)
    )
    with pytest.raises(MODULE.ApprovalV2OutputsError, match="bounded"):
        validate_files(bundle, paths)


def test_rejects_input_mutation_while_stable_fd_is_read(
    monkeypatch,
    tmp_path: Path,
) -> None:
    bundle, paths = prepared_files(tmp_path)
    target = paths["workflow"].stat()
    original_read = MODULE.os.read
    mutated = False

    def racing_read(descriptor: int, count: int) -> bytes:
        nonlocal mutated
        chunk = original_read(descriptor, count)
        info = os.fstat(descriptor)
        if (
            not mutated
            and (info.st_dev, info.st_ino)
            == (target.st_dev, target.st_ino)
        ):
            mutated = True
            with paths["workflow"].open("ab") as stream:
                stream.write(b"race")
        return chunk

    monkeypatch.setattr(MODULE.os, "read", racing_read)
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="changed while being read",
    ):
        validate_files(bundle, paths)


def test_rejects_input_path_replacement_while_fd_is_read(
    monkeypatch,
    tmp_path: Path,
) -> None:
    bundle, paths = prepared_files(tmp_path)
    target = paths["workflow"].stat()
    original_read = MODULE.os.read
    replaced = False

    def racing_read(descriptor: int, count: int) -> bytes:
        nonlocal replaced
        chunk = original_read(descriptor, count)
        info = os.fstat(descriptor)
        if (
            not replaced
            and (info.st_dev, info.st_ino)
            == (target.st_dev, target.st_ino)
        ):
            replaced = True
            paths["workflow"].rename(tmp_path / "old-workflow")
            write_file(paths["workflow"], WORKFLOW_RAW)
        return chunk

    monkeypatch.setattr(MODULE.os, "read", racing_read)
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="changed",
    ):
        validate_files(bundle, paths)


@pytest.mark.parametrize(
    "attack",
    ["symlink", "hardlink", "unsafe-mode", "oversized"],
)
def test_rejects_unsafe_github_output_targets(
    tmp_path: Path,
    attack: str,
) -> None:
    bundle, paths = prepared_files(tmp_path)
    outputs, identities = validate_files(bundle, paths)
    target = paths["github_output"]
    if attack == "symlink":
        real = tmp_path / "real-output"
        target.rename(real)
        target.symlink_to(real)
    elif attack == "hardlink":
        os.link(target, tmp_path / "output-alias")
    elif attack == "unsafe-mode":
        target.chmod(0o666)
    else:
        target.write_bytes(b"x" * MODULE.MAX_GITHUB_OUTPUT_BYTES)
    with pytest.raises(MODULE.ApprovalV2OutputsError):
        MODULE.append_github_outputs(
            target,
            outputs,
            input_identities=identities,
        )


def test_rejects_github_output_that_aliases_a_validated_input(
    tmp_path: Path,
) -> None:
    bundle, paths = prepared_files(tmp_path)
    outputs, identities = validate_files(bundle, paths)
    before = paths["approval"].read_bytes()
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="alias",
    ):
        MODULE.append_github_outputs(
            paths["approval"],
            outputs,
            input_identities=identities,
        )
    assert paths["approval"].read_bytes() == before


@pytest.mark.parametrize(
    ("key", "bad"),
    [
        ("release_id", "safe\ninjected=value"),
        ("controller_tag_ref", "refs/tags/safe%0Aevil"),
        ("controller_release_id", "1=evil"),
        ("approval_sha256", "A" * 64),
    ],
)
def test_rejects_output_injection_and_noncanonical_values_before_write(
    tmp_path: Path,
    key: str,
    bad: str,
) -> None:
    bundle, paths = prepared_files(tmp_path)
    outputs, identities = validate_files(bundle, paths)
    outputs[key] = bad
    before = paths["github_output"].read_bytes()
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="unsafe",
    ):
        MODULE.append_github_outputs(
            paths["github_output"],
            outputs,
            input_identities=identities,
        )
    assert paths["github_output"].read_bytes() == before


def test_append_uses_one_o_append_write_and_fsync(
    monkeypatch,
    tmp_path: Path,
) -> None:
    bundle, paths = prepared_files(tmp_path)
    outputs, identities = validate_files(bundle, paths)
    original_open = MODULE.os.open
    original_write = MODULE.os.write
    original_fsync = MODULE.os.fsync
    seen_flags: list[int] = []
    writes: list[int] = []
    syncs: list[int] = []

    def observed_open(path, flags, *args):
        seen_flags.append(flags)
        return original_open(path, flags, *args)

    def observed_write(descriptor: int, payload: bytes) -> int:
        writes.append(len(payload))
        return original_write(descriptor, payload)

    def observed_fsync(descriptor: int) -> None:
        syncs.append(descriptor)
        original_fsync(descriptor)

    monkeypatch.setattr(MODULE.os, "open", observed_open)
    monkeypatch.setattr(MODULE.os, "write", observed_write)
    monkeypatch.setattr(MODULE.os, "fsync", observed_fsync)
    MODULE.append_github_outputs(
        paths["github_output"],
        outputs,
        input_identities=identities,
    )
    assert len(seen_flags) == 1
    assert seen_flags[0] & os.O_APPEND
    assert seen_flags[0] & getattr(os, "O_NOFOLLOW", 0)
    assert len(writes) == 1
    assert len(syncs) == 1


def test_rejects_short_append_write(
    monkeypatch,
    tmp_path: Path,
) -> None:
    bundle, paths = prepared_files(tmp_path)
    outputs, identities = validate_files(bundle, paths)
    original_write = MODULE.os.write

    def short_write(descriptor: int, payload: bytes) -> int:
        return original_write(descriptor, payload[:-1])

    monkeypatch.setattr(MODULE.os, "write", short_write)
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="incomplete",
    ):
        MODULE.append_github_outputs(
            paths["github_output"],
            outputs,
            input_identities=identities,
        )


def test_rejects_output_path_replacement_during_append(
    monkeypatch,
    tmp_path: Path,
) -> None:
    bundle, paths = prepared_files(tmp_path)
    outputs, identities = validate_files(bundle, paths)
    original_write = MODULE.os.write

    def replacing_write(descriptor: int, payload: bytes) -> int:
        written = original_write(descriptor, payload)
        paths["github_output"].rename(tmp_path / "detached-output")
        write_file(paths["github_output"], b"attacker=safe-looking\n")
        return written

    monkeypatch.setattr(MODULE.os, "write", replacing_write)
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="changed during append",
    ):
        MODULE.append_github_outputs(
            paths["github_output"],
            outputs,
            input_identities=identities,
        )


def test_rejects_fsync_failure(
    monkeypatch,
    tmp_path: Path,
) -> None:
    bundle, paths = prepared_files(tmp_path)
    outputs, identities = validate_files(bundle, paths)

    def failed_fsync(_descriptor: int) -> None:
        raise OSError("simulated storage failure")

    monkeypatch.setattr(MODULE.os, "fsync", failed_fsync)
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="failed closed",
    ):
        MODULE.append_github_outputs(
            paths["github_output"],
            outputs,
            input_identities=identities,
        )


def test_cli_returns_78_for_missing_required_fixed_inputs() -> None:
    result = subprocess.run(
        [sys.executable, "-B", str(SCRIPT)],
        cwd=ROOT,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    assert result.returncode == 78
    assert "invalid command line" in result.stderr
    assert result.stdout == ""


def test_cli_ignores_environment_pins_and_fails_closed_until_compiled_pins(
    tmp_path: Path,
) -> None:
    current = dt.datetime.now(dt.timezone.utc).replace(
        microsecond=0,
    ) - dt.timedelta(minutes=1)
    bundle = materials(issued_at=current)
    _, paths = prepared_files(tmp_path, bundle=bundle)
    before = paths["github_output"].read_bytes()
    command = [
        sys.executable,
        "-B",
        str(SCRIPT),
        "--approval",
        str(paths["approval"]),
        "--ledger-summary",
        str(paths["ledger_summary"]),
        "--policy",
        str(paths["policy"]),
        "--workflow",
        str(paths["workflow"]),
        "--signer-verifier",
        str(paths["signer_verifier"]),
        "--github-output",
        str(paths["github_output"]),
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        env={
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PRODUCTION_AUDITED_PINS": json.dumps(
                bundle["pins"].__dict__,
            ),
            "CONTROL_POLICY_PINS": "attacker-controlled",
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    assert result.returncode == 78
    assert "audited production pins are unavailable" in result.stderr
    assert result.stdout == ""
    assert paths["github_output"].read_bytes() == before


def test_source_is_executable_and_disables_bytecode_before_imports() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert stat.S_IMODE(SCRIPT.stat().st_mode) == 0o755
    assert source.startswith("#!/usr/bin/env python3\n")
    flag = source.index("sys.dont_write_bytecode = True")
    importlib_use = source.index("importlib.util.spec_from_file_location")
    assert flag < importlib_use
    assert "PRODUCTION_AUDITED_PINS" in source
    assert "os.environ" not in source
