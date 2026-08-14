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
CONTROLLER_TAG_SIGNATURE_VERIFIER_RAW = (
    b"#!/usr/bin/env python3\n# fixed local controller-tag verifier\n"
)
SIGNER_FRESHNESS_VERIFIER_MANIFEST_RAW = (
    b'{"bundle_name":"control-release-verifier-v6",'
    b'"format":"tratto-control-source-free-verifier-bundle-v1",'
    b'"schema_version":1}\n'
)
WORKFLOW_SHA256 = hashlib.sha256(WORKFLOW_RAW).hexdigest()
CONTROLLER_TAG_SIGNATURE_VERIFIER_SHA256 = hashlib.sha256(
    CONTROLLER_TAG_SIGNATURE_VERIFIER_RAW
).hexdigest()
SIGNER_FRESHNESS_VERIFIER_SHA256 = hashlib.sha256(
    SIGNER_FRESHNESS_VERIFIER_MANIFEST_RAW
).hexdigest()
TRUST_EPOCH = 7
TRUST = MODULE.POLICY_V2.AuditedTrustEpoch(
    trust_epoch=TRUST_EPOCH,
    controller_repository_id=123456789,
    controller_workflow_sha256=WORKFLOW_SHA256,
    controller_tag_signature_trust_root_sha256="c" * 64,
    controller_tag_signature_verifier_sha256=(
        CONTROLLER_TAG_SIGNATURE_VERIFIER_SHA256
    ),
    signer_freshness_verifier_sha256=SIGNER_FRESHNESS_VERIFIER_SHA256,
    ledger_repository_id=234567890,
    ledger_genesis_sha="a" * 40,
)


def canonical(value: dict) -> bytes:
    return MODULE.canonical_bytes(value)


def approval_value(
    *,
    policy_sha256: str,
    workflow_sha256: str = WORKFLOW_SHA256,
    controller_tag_signature_verifier_sha256: str = (
        CONTROLLER_TAG_SIGNATURE_VERIFIER_SHA256
    ),
    signer_freshness_verifier_sha256: str = (
        SIGNER_FRESHNESS_VERIFIER_SHA256
    ),
    trust_epoch: int = TRUST_EPOCH,
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
            "controller_tag_signature_verifier_sha256": (
                controller_tag_signature_verifier_sha256
            ),
            "immutable_release_id": 12001,
            "repository": "PluckXD/tratto-control-release",
            "repository_id": TRUST.controller_repository_id,
            "signer_freshness_verifier_sha256": (
                signer_freshness_verifier_sha256
            ),
            "tag_object_sha": "6" * 40,
            "tag_ref": "refs/tags/control-controller-v6.0.0",
            "workflow_path": ".github/workflows/control-release.yml",
            "workflow_sha256": workflow_sha256,
        },
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ledger": {
            "genesis_sha": TRUST.ledger_genesis_sha,
            "parent_commit_sha": "7" * 40,
            "previous_manifest_sha256": "8" * 64,
            "ref": "refs/heads/main",
            "repository": "PluckXD/tratto-control-release-ledger",
            "repository_id": TRUST.ledger_repository_id,
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
            "trust_epoch": trust_epoch,
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
    controller_tag_signature_verifier_raw: bytes = (
        CONTROLLER_TAG_SIGNATURE_VERIFIER_RAW
    ),
    signer_freshness_verifier_manifest_raw: bytes = (
        SIGNER_FRESHNESS_VERIFIER_MANIFEST_RAW
    ),
    issued_at: dt.datetime | None = None,
) -> dict:
    trust = MODULE.POLICY_V2.AuditedTrustEpoch(
        **{
            **TRUST.__dict__,
            "controller_workflow_sha256": hashlib.sha256(
                workflow_raw
            ).hexdigest(),
            "controller_tag_signature_verifier_sha256": hashlib.sha256(
                controller_tag_signature_verifier_raw
            ).hexdigest(),
            "signer_freshness_verifier_sha256": hashlib.sha256(
                signer_freshness_verifier_manifest_raw
            ).hexdigest(),
        }
    )
    policy = MODULE.POLICY_V2.expected_policy(trust)
    policy_raw = MODULE.POLICY_V2.canonical_bytes(policy)
    approval = approval_value(
        policy_sha256=hashlib.sha256(policy_raw).hexdigest(),
        workflow_sha256=hashlib.sha256(workflow_raw).hexdigest(),
        controller_tag_signature_verifier_sha256=hashlib.sha256(
            controller_tag_signature_verifier_raw
        ).hexdigest(),
        signer_freshness_verifier_sha256=hashlib.sha256(
            signer_freshness_verifier_manifest_raw
        ).hexdigest(),
        trust_epoch=trust.trust_epoch,
        issued_at=issued_at,
    )
    approval["controller"]["repository_id"] = trust.controller_repository_id
    approval["ledger"]["repository_id"] = trust.ledger_repository_id
    approval["ledger"]["genesis_sha"] = trust.ledger_genesis_sha
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
        "trust": trust,
        "policy": policy,
        "policy_raw": policy_raw,
        "controller_tag_signature_verifier_raw": (
            controller_tag_signature_verifier_raw
        ),
        "signer_freshness_verifier_manifest_raw": (
            signer_freshness_verifier_manifest_raw
        ),
        "workflow_raw": workflow_raw,
    }


def validate(bundle: dict, *, now: dt.datetime = NOW) -> dict[str, str]:
    return MODULE.validate_inputs(
        approval_raw=bundle["approval_raw"],
        ledger_summary_raw=bundle["ledger_summary_raw"],
        policy_raw=bundle["policy_raw"],
        workflow_raw=bundle["workflow_raw"],
        controller_tag_signature_verifier_raw=(
            bundle["controller_tag_signature_verifier_raw"]
        ),
        signer_freshness_verifier_manifest_raw=(
            bundle["signer_freshness_verifier_manifest_raw"]
        ),
        audited_trust_epoch=bundle["trust"],
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
        "policy_sha256": hashlib.sha256(
            bundle["policy_raw"]
        ).hexdigest(),
        "ledger_head_sha": "b" * 40,
        "controller_commit_sha": "5" * 40,
        "controller_tag_signature_verifier_sha256": (
            CONTROLLER_TAG_SIGNATURE_VERIFIER_SHA256
        ),
        "controller_tag_ref": "refs/tags/control-controller-v6.0.0",
        "controller_tag_object_sha": "6" * 40,
        "controller_release_id": "12001",
        "signer_freshness_verifier_sha256": (
            SIGNER_FRESHNESS_VERIFIER_SHA256
        ),
        "trust_epoch": str(approval["policy"]["trust_epoch"]),
    }


def test_pure_api_accepts_exact_current_cross_bound_inputs() -> None:
    bundle = materials()
    assert validate(bundle) == expected_outputs(bundle)


def test_pure_api_rejects_identical_verifier_role_bytes() -> None:
    shared = b'{"artifact":"must-have-one-role-only"}\n'
    bundle = materials(
        controller_tag_signature_verifier_raw=shared,
        signer_freshness_verifier_manifest_raw=shared,
    )
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="must use distinct bytes",
    ):
        validate(bundle)


def test_pure_api_rejects_identical_verifier_role_digests(monkeypatch) -> None:
    bundle = materials()
    real_sha256 = MODULE.hashlib.sha256
    role_bytes = {
        bundle["controller_tag_signature_verifier_raw"],
        bundle["signer_freshness_verifier_manifest_raw"],
    }

    class CollidingDigest:
        def hexdigest(self) -> str:
            return "f" * 64

    def colliding_sha256(raw: bytes):
        if raw in role_bytes:
            return CollidingDigest()
        return real_sha256(raw)

    monkeypatch.setattr(MODULE.hashlib, "sha256", colliding_sha256)
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="must use distinct SHA-256 digests",
    ):
        validate(bundle)


def test_pure_api_performs_no_file_or_environment_access(monkeypatch) -> None:
    bundle = materials()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("pure validation attempted external access")

    monkeypatch.setattr(MODULE.os, "open", forbidden)
    monkeypatch.setattr(MODULE.os, "getenv", forbidden)
    assert validate(bundle) == expected_outputs(bundle)


def test_reviewed_artifacts_are_hashed_as_bytes_not_imported_or_executed() -> None:
    bundle = materials(
        workflow_raw=b"\0this is not YAML or executable code\n",
        controller_tag_signature_verifier_raw=(
            b"raise RuntimeError('must never execute')\n"
        ),
        signer_freshness_verifier_manifest_raw=(
            b'{"payload":"must never execute"}\n'
        ),
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
            ("controller", "controller_tag_signature_verifier_sha256"),
            "0" * 64,
            "controller tag signature verifier digest",
        ),
        (
            ("controller", "signer_freshness_verifier_sha256"),
            "0" * 64,
            "signer freshness verifier digest",
        ),
        (
            ("policy", "trust_epoch"),
            TRUST_EPOCH + 1,
            "trust epoch",
        ),
        (
            ("controller", "repository_id"),
            TRUST.controller_repository_id + 1,
            "controller binding",
        ),
        (
            ("ledger", "repository_id"),
            TRUST.ledger_repository_id + 1,
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


def test_rejects_exact_controller_tag_verifier_bytes_changed_after_approval() -> None:
    bundle = materials()
    bundle["controller_tag_signature_verifier_raw"] += (
        b"# post-approval mutation\n"
    )
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="controller tag signature verifier digest",
    ):
        validate(bundle)


def test_rejects_exact_signer_manifest_bytes_changed_after_approval() -> None:
    bundle = materials()
    bundle["signer_freshness_verifier_manifest_raw"] += b" "
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="signer freshness verifier digest",
    ):
        validate(bundle)


@pytest.mark.parametrize(
    ("raw_key", "approval_key", "replacement"),
    [
        (
            "controller_tag_signature_verifier_raw",
            "controller_tag_signature_verifier_sha256",
            b"#!/bin/false\n",
        ),
        (
            "signer_freshness_verifier_manifest_raw",
            "signer_freshness_verifier_sha256",
            b'{"bundle_name":"attacker"}\n',
        ),
    ],
)
def test_rejects_verifier_that_matches_approval_but_not_audited_policy(
    raw_key: str,
    approval_key: str,
    replacement: bytes,
) -> None:
    bundle = materials()
    bundle[raw_key] = replacement
    bundle["approval"]["controller"][approval_key] = (
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


def test_rejects_policy_that_does_not_match_explicit_audited_epoch() -> None:
    bundle = materials()
    changed_trust = MODULE.POLICY_V2.AuditedTrustEpoch(
        **{
            **bundle["trust"].__dict__,
            "ledger_repository_id": (
                bundle["trust"].ledger_repository_id + 1
            ),
        }
    )
    bundle["trust"] = changed_trust
    with pytest.raises(
        MODULE.ApprovalV2OutputsError,
        match="audited trust epoch",
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
        "controller_tag_signature_verifier": write_file(
            tmp_path / "controller-tag-signature-verifier.py",
            selected["controller_tag_signature_verifier_raw"],
            0o700,
        ),
        "signer_freshness_verifier_manifest": write_file(
            tmp_path / "signer-freshness-verifier-manifest.json",
            selected["signer_freshness_verifier_manifest_raw"],
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
        controller_tag_signature_verifier_path=(
            paths["controller_tag_signature_verifier"]
        ),
        signer_freshness_verifier_manifest_path=(
            paths["signer_freshness_verifier_manifest"]
        ),
        audited_trust_epoch=bundle["trust"],
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
        "controller_tag_signature_verifier",
        "signer_freshness_verifier_manifest",
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
        "controller_tag_signature_verifier",
        "signer_freshness_verifier_manifest",
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
        "controller_tag_signature_verifier",
        "signer_freshness_verifier_manifest",
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


@pytest.mark.parametrize(
    ("first_role", "second_role"),
    [
        ("workflow", "controller_tag_signature_verifier"),
        (
            "controller_tag_signature_verifier",
            "signer_freshness_verifier_manifest",
        ),
    ],
)
def test_rejects_same_single_link_file_reused_for_two_input_roles(
    tmp_path: Path,
    first_role: str,
    second_role: str,
) -> None:
    bundle, paths = prepared_files(tmp_path)
    paths[second_role].unlink()
    paths[second_role] = paths[first_role]
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


def test_cli_rejects_legacy_signer_verifier_alias(capsys) -> None:
    assert MODULE.main(["--signer-verifier", "legacy.py"]) == 78
    captured = capsys.readouterr()
    assert "invalid command line" in captured.err


def test_cli_rejects_distinct_files_with_identical_verifier_role_bytes(
    monkeypatch,
    capsys,
    tmp_path: Path,
) -> None:
    current = dt.datetime.now(dt.timezone.utc).replace(
        microsecond=0,
    ) - dt.timedelta(minutes=1)
    shared = b'{"artifact":"must-have-one-role-only"}\n'
    bundle = materials(
        controller_tag_signature_verifier_raw=shared,
        signer_freshness_verifier_manifest_raw=shared,
        issued_at=current,
    )
    _, paths = prepared_files(tmp_path, bundle=bundle)
    controller_identity = paths["controller_tag_signature_verifier"].stat()
    signer_identity = paths["signer_freshness_verifier_manifest"].stat()
    assert (controller_identity.st_dev, controller_identity.st_ino) != (
        signer_identity.st_dev,
        signer_identity.st_ino,
    )
    monkeypatch.setattr(
        MODULE.POLICY_V2,
        "PRODUCTION_AUDITED_TRUST_EPOCH",
        bundle["trust"],
    )
    before = paths["github_output"].read_bytes()
    result = MODULE.main(
        [
            "--approval",
            str(paths["approval"]),
            "--ledger-summary",
            str(paths["ledger_summary"]),
            "--policy",
            str(paths["policy"]),
            "--workflow",
            str(paths["workflow"]),
            "--controller-tag-signature-verifier",
            str(paths["controller_tag_signature_verifier"]),
            "--signer-freshness-verifier-manifest",
            str(paths["signer_freshness_verifier_manifest"]),
            "--github-output",
            str(paths["github_output"]),
        ]
    )
    assert result == 78
    captured = capsys.readouterr()
    assert "must use distinct bytes" in captured.err
    assert paths["github_output"].read_bytes() == before


def test_cli_ignores_environment_epoch_and_fails_until_compiled_epoch(
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
        "--controller-tag-signature-verifier",
        str(paths["controller_tag_signature_verifier"]),
        "--signer-freshness-verifier-manifest",
        str(paths["signer_freshness_verifier_manifest"]),
        "--github-output",
        str(paths["github_output"]),
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        env={
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PRODUCTION_AUDITED_TRUST_EPOCH": json.dumps(
                bundle["trust"].__dict__,
            ),
            "CONTROL_TRUST_EPOCH": "attacker-controlled",
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    assert result.returncode == 78
    assert "audited production trust epoch is unavailable" in result.stderr
    assert result.stdout == ""
    assert paths["github_output"].read_bytes() == before


def test_source_is_executable_and_disables_bytecode_before_imports() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert stat.S_IMODE(SCRIPT.stat().st_mode) == 0o755
    assert source.startswith("#!/usr/bin/env python3\n")
    flag = source.index("sys.dont_write_bytecode = True")
    importlib_use = source.index("importlib.util.spec_from_file_location")
    assert flag < importlib_use
    assert "PRODUCTION_AUDITED_TRUST_EPOCH" in source
    assert 'add_argument("--signer-verifier"' not in source
    assert "os.environ" not in source
