from __future__ import annotations

import copy
import datetime as dt
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-approval-v2.py"
SCHEMA = ROOT / "schemas" / "approval-v2.schema.json"
SPEC = importlib.util.spec_from_file_location("validate_approval_v2", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
NOW = dt.datetime(2026, 8, 1, 12, 0, tzinfo=dt.timezone.utc)


def approval(*, sequence: int = 1) -> dict:
    genesis = "a" * 40
    parent = genesis if sequence == 1 else "b" * 40
    previous = "0" * 64 if sequence == 1 else "c" * 64
    return {
        "api": {
            "approved_ref": "refs/heads/main",
            "commit_sha": "1" * 40,
            "repository": "PluckXD/tratto-api",
            "required_ancestors": ["2" * 40],
        },
        "controller": {
            "commit_sha": "3" * 40,
            "immutable_release_id": 12001,
            "repository": "PluckXD/tratto-control-release",
            "repository_id": 22001,
            "signer_verifier_sha256": "4" * 64,
            "tag_object_sha": "5" * 40,
            "tag_ref": "refs/tags/control-controller-v6.0.0",
            "workflow_path": ".github/workflows/control-release.yml",
            "workflow_sha256": "6" * 64,
        },
        "expires_at": "2026-08-01T13:00:00Z",
        "issued_at": "2026-08-01T12:00:00Z",
        "ledger": {
            "genesis_sha": genesis,
            "parent_commit_sha": parent,
            "previous_manifest_sha256": previous,
            "ref": "refs/heads/main",
            "repository": "PluckXD/tratto-control-release-ledger",
            "repository_id": 32001,
            "sequence": sequence,
        },
        "migration": {
            "base_revision": "j1transpcod",
            "database_scope": "control-and-tenant-fleet",
            "fleet_preflight_sha256": "7" * 64,
            "head_revision": "f29controlexec",
            "mode": "expand-only",
            "tenant_catalog_count": 1,
            "tenant_catalog_sha256": "8" * 64,
            "tenant_fleet_base_revision": "j1transpcod",
        },
        "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
        "ops": {
            "approved_ref": "refs/heads/main",
            "commit_sha": "1" * 40,
            "repository": "PluckXD/tratto-api",
            "required_ancestors": ["9" * 40],
        },
        "policy": {
            "digest_sha256": "e" * 64,
            "name": "control-production-v2",
            "path": "policies/control-production-v2.json",
            "repository": "PluckXD/tratto-control-release",
        },
        "release_id": "ctl-20260801T120000Z-tests",
        "schema_version": 2,
        "web": {
            "approved_ref": "refs/heads/main",
            "commit_sha": "f" * 40,
            "repository": "PluckXD/tratto-web",
            "required_ancestors": ["0" * 40],
        },
    }


def versioned_migration(schema_version: int) -> dict:
    if schema_version == 5:
        control = "f51legalpublish"
        tenant = "f49legalauth"
    elif schema_version == 6:
        control = tenant = "f52provisionactivate"
    else:
        raise AssertionError("test requested an unsupported migration version")
    return {
        "control_base_revisions": ["z2card181nf"],
        "control_schema_revision": control,
        "database_scope": "control-and-tenant-fleet",
        "fleet_preflight_sha256": "7" * 64,
        "head_revision": control,
        "mode": "expand-only",
        "schema_version": schema_version,
        "tenant_catalog_count": 1,
        "tenant_catalog_sha256": "8" * 64,
        "tenant_fleet_base_revisions": ["z2card181nf"],
        "tenant_schema_revision": tenant,
    }


def validate(value: dict, *, now: dt.datetime = NOW) -> dict:
    return MODULE.validate_bytes(MODULE.canonical_bytes(value), now=now)


def test_accepts_complete_sequence_one_authorization() -> None:
    value = approval()
    assert validate(value) == value


def test_accepts_complete_later_ledger_authorization() -> None:
    value = approval(sequence=2)
    assert validate(value)["ledger"]["sequence"] == 2


@pytest.mark.parametrize("schema_version", (5, 6))
def test_accepts_exact_versioned_product_migration_contract(
    schema_version: int,
) -> None:
    value = approval()
    value["migration"] = versioned_migration(schema_version)
    assert validate(value)["migration"] == value["migration"]


@pytest.mark.parametrize(
    ("schema_version", "field", "replacement"),
    [
        (5, "tenant_schema_revision", "f52provisionactivate"),
        (5, "control_schema_revision", "f52provisionactivate"),
        (5, "head_revision", "f52provisionactivate"),
        (6, "tenant_schema_revision", "f49legalauth"),
        (6, "control_schema_revision", "f51legalpublish"),
        (6, "head_revision", "f51legalpublish"),
        (6, "control_base_revisions", ["f51legalpublish"]),
        (6, "tenant_fleet_base_revisions", ["f49legalauth"]),
    ],
)
def test_rejects_mixed_versioned_product_migration_contract(
    schema_version: int,
    field: str,
    replacement,
) -> None:
    value = approval()
    value["migration"] = versioned_migration(schema_version)
    value["migration"][field] = replacement
    with pytest.raises(MODULE.ApprovalV2Error, match="revision chain"):
        validate(value)


def test_rejects_unsupported_or_non_integer_versioned_migration() -> None:
    for schema_version in (4, 7, True, 6.0):
        value = approval()
        value["migration"] = versioned_migration(6)
        value["migration"]["schema_version"] = schema_version
        with pytest.raises(
            MODULE.ApprovalV2Error,
            match="schema_version",
        ):
            validate(value)


def test_controller_tag_object_and_commit_may_share_the_same_sha() -> None:
    value = approval()
    value["controller"]["tag_object_sha"] = value["controller"]["commit_sha"]
    assert validate(value)["controller"]["commit_sha"] == "3" * 40


def test_schema_is_valid_json_and_closes_all_object_shapes() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == 2
    for name in ("component", "controller", "ledger", "policy"):
        assert schema["$defs"][name]["additionalProperties"] is False
    assert schema["$defs"]["migration"]["oneOf"] == [
        {"$ref": "#/$defs/migrationLegacy"},
        {"$ref": "#/$defs/migrationDemoPlatformV5"},
        {"$ref": "#/$defs/migrationDemoPlatformV6"},
    ]
    for name in (
        "migrationLegacy",
        "migrationDemoPlatformV5",
        "migrationDemoPlatformV6",
    ):
        assert schema["$defs"][name]["additionalProperties"] is False


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"extra": True}), "keys diverge"),
        (
            lambda value: value.update({"schema_version": 2.0}),
            "integer 2",
        ),
        (
            lambda value: value["api"].update({"repository": "evil/api"}),
            "repository is not allowed",
        ),
        (
            lambda value: value["web"].update({"approved_ref": "refs/heads/dev"}),
            "refs/heads/main",
        ),
        (
            lambda value: value["ops"].update({"commit_sha": "a" * 40}),
            "same commit",
        ),
        (
            lambda value: value["api"].update(
                {"required_ancestors": ["2" * 40, "2" * 40]}
            ),
            "contains duplicates",
        ),
        (
            lambda value: value["api"].update(
                {"required_ancestors": ["1" * 40]}
            ),
            "cannot duplicate",
        ),
        (
            lambda value: value["migration"].update(
                {"head_revision": "j1transpcod"}
            ),
            "revision chain",
        ),
        (
            lambda value: value["migration"].update(
                {"tenant_catalog_count": True}
            ),
            "catalog count",
        ),
        (
            lambda value: value["policy"].update(
                {"name": "control-production-v1"}
            ),
            "policy.name",
        ),
        (
            lambda value: value["policy"].update(
                {"path": "policies/control-production-v1.json"}
            ),
            "policy.path",
        ),
        (
            lambda value: value.update({"nonce": "too-short"}),
            "nonce",
        ),
    ],
)
def test_rejects_preserved_v1_contract_drift(mutation, message: str) -> None:
    value = approval()
    mutation(value)
    with pytest.raises(MODULE.ApprovalV2Error, match=message):
        validate(value)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["controller"].update(
                {"repository": "attacker/controller"}
            ),
            "controller.repository",
        ),
        (
            lambda value: value["controller"].update({"repository_id": True}),
            "positive integer",
        ),
        (
            lambda value: value["controller"].update({"repository_id": 0}),
            "positive integer",
        ),
        (
            lambda value: value["controller"].update(
                {"tag_ref": "refs/heads/control-controller-v6.0.0"}
            ),
            "tag_ref",
        ),
        (
            lambda value: value["controller"].update(
                {"tag_ref": "refs/tags/control-controller-v6.01.0"}
            ),
            "tag_ref",
        ),
        (
            lambda value: value["controller"].update(
                {"tag_ref": "refs/tags/control-controller-v7.0.0"}
            ),
            "tag_ref",
        ),
        (
            lambda value: value["controller"].update(
                {"tag_object_sha": "A" * 40}
            ),
            "tag_object_sha",
        ),
        (
            lambda value: value["controller"].update({"commit_sha": "3" * 39}),
            "commit_sha",
        ),
        (
            lambda value: value["controller"].update(
                {"immutable_release_id": 0}
            ),
            "positive integer",
        ),
        (
            lambda value: value["controller"].update(
                {"workflow_path": ".github/workflows/other.yml"}
            ),
            "workflow_path",
        ),
        (
            lambda value: value["controller"].update(
                {"workflow_sha256": "6" * 63}
            ),
            "workflow_sha256",
        ),
        (
            lambda value: value["controller"].update(
                {"signer_verifier_sha256": "4" * 63}
            ),
            "signer_verifier_sha256",
        ),
        (
            lambda value: value["controller"].update({"extra": "field"}),
            "keys diverge",
        ),
    ],
)
def test_rejects_controller_binding_drift(mutation, message: str) -> None:
    value = approval()
    mutation(value)
    with pytest.raises(MODULE.ApprovalV2Error, match=message):
        validate(value)


@pytest.mark.parametrize(
    ("sequence", "mutation", "message"),
    [
        (
            1,
            lambda value: value["ledger"].update(
                {"repository": "attacker/ledger"}
            ),
            "ledger.repository",
        ),
        (
            1,
            lambda value: value["ledger"].update({"repository_id": False}),
            "positive integer",
        ),
        (
            1,
            lambda value: value["ledger"].update({"ref": "refs/heads/dev"}),
            "refs/heads/main",
        ),
        (
            1,
            lambda value: value["ledger"].update({"genesis_sha": "a" * 39}),
            "genesis_sha",
        ),
        (
            1,
            lambda value: value["ledger"].update(
                {"parent_commit_sha": "b" * 40}
            ),
            "genesis as its parent",
        ),
        (
            1,
            lambda value: value["ledger"].update(
                {"previous_manifest_sha256": "1" * 64}
            ),
            "zero previous",
        ),
        (
            1,
            lambda value: value["ledger"].update({"sequence": 0}),
            "positive integer",
        ),
        (
            1,
            lambda value: value["ledger"].update({"sequence": True}),
            "positive integer",
        ),
        (
            2,
            lambda value: value["ledger"].update(
                {"parent_commit_sha": "a" * 40}
            ),
            "cannot directly follow genesis",
        ),
        (
            2,
            lambda value: value["ledger"].update(
                {"previous_manifest_sha256": "0" * 64}
            ),
            "must bind a previous",
        ),
        (
            2,
            lambda value: value["ledger"].update(
                {"sequence": MODULE.MAX_LEDGER_SEQUENCE + 1}
            ),
            "cannot exceed",
        ),
        (
            1,
            lambda value: value["ledger"].update({"extra": "field"}),
            "keys diverge",
        ),
    ],
)
def test_rejects_ledger_chain_drift(
    sequence: int,
    mutation,
    message: str,
) -> None:
    value = approval(sequence=sequence)
    mutation(value)
    with pytest.raises(MODULE.ApprovalV2Error, match=message):
        validate(value)


@pytest.mark.parametrize(
    ("mutation", "now", "message"),
    [
        (
            lambda value: value.update(
                {"expires_at": "2026-08-01T12:00:00Z"}
            ),
            NOW,
            "between 1 second",
        ),
        (
            lambda value: value.update(
                {"expires_at": "2026-08-02T12:00:01Z"}
            ),
            NOW,
            "between 1 second",
        ),
        (
            lambda value: value.update(
                {"issued_at": "2026-08-01T12:00:01Z"}
            ),
            NOW,
            "timestamp must equal",
        ),
        (
            lambda value: None,
            dt.datetime(2026, 8, 1, 13, 0, tzinfo=dt.timezone.utc),
            "expired",
        ),
        (
            lambda value: None,
            dt.datetime(2026, 8, 1, 11, 54, 59, tzinfo=dt.timezone.utc),
            "too far in the future",
        ),
        (
            lambda value: None,
            dt.datetime(2026, 8, 1, 12, 0),
            "timezone-aware UTC",
        ),
    ],
)
def test_rejects_temporal_drift(mutation, now: dt.datetime, message: str) -> None:
    value = approval()
    mutation(value)
    with pytest.raises(MODULE.ApprovalV2Error, match=message):
        validate(value, now=now)


def test_historical_mode_allows_expiry_but_preserves_time_shape() -> None:
    value = approval()
    much_later = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
    assert MODULE.validate_bytes(
        MODULE.canonical_bytes(value),
        now=much_later,
        historical=True,
    ) == value
    value["expires_at"] = value["issued_at"]
    with pytest.raises(MODULE.ApprovalV2Error, match="between 1 second"):
        MODULE.validate_bytes(
            MODULE.canonical_bytes(value),
            now=much_later,
            historical=True,
        )


def test_rejects_noncanonical_json() -> None:
    value = approval()
    raw = json.dumps(value, indent=2, sort_keys=True).encode("utf-8")
    with pytest.raises(MODULE.ApprovalV2Error, match="canonical JSON"):
        MODULE.validate_bytes(raw, now=NOW)


def test_rejects_duplicate_json_keys() -> None:
    raw = MODULE.canonical_bytes(approval()).decode("utf-8")
    raw = raw.replace('"schema_version":2', '"schema_version":2,"schema_version":2')
    with pytest.raises(MODULE.ApprovalV2Error, match="duplicate JSON key"):
        MODULE.validate_bytes(raw.encode("utf-8"), now=NOW)


def test_rejects_non_utf8_and_non_finite_json() -> None:
    with pytest.raises(MODULE.ApprovalV2Error, match="UTF-8"):
        MODULE.validate_bytes(b"\xff", now=NOW)
    raw = MODULE.canonical_bytes(approval()).replace(
        b'"schema_version":2',
        b'"schema_version":NaN',
    )
    with pytest.raises(MODULE.ApprovalV2Error, match="non-finite"):
        MODULE.validate_bytes(raw, now=NOW)


def test_rejects_symlink_hardlink_and_unsafe_mode(tmp_path: Path) -> None:
    target = tmp_path / "approval.json"
    target.write_bytes(MODULE.canonical_bytes(approval()))
    target.chmod(0o644)
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(target)
    with pytest.raises(MODULE.ApprovalV2Error, match="traverse symlinks"):
        MODULE.validate_file(symlink, now=NOW)
    hardlink = tmp_path / "hardlink.json"
    os.link(target, hardlink)
    with pytest.raises(MODULE.ApprovalV2Error, match="single-link"):
        MODULE.validate_file(target, now=NOW)
    hardlink.unlink()
    target.chmod(0o600)
    with pytest.raises(MODULE.ApprovalV2Error, match="0644"):
        MODULE.validate_file(target, now=NOW)


def test_rejects_authorization_below_symlinked_parent(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    target = real / "approval.json"
    target.write_bytes(MODULE.canonical_bytes(approval()))
    target.chmod(0o644)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(MODULE.ApprovalV2Error, match="traverse symlinks"):
        MODULE.validate_file(alias / "approval.json", now=NOW)


def test_cli_returns_78_for_invalid_input_and_arguments(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_bytes(b"{}\n")
    invalid.chmod(0o644)
    result = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), str(invalid)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    assert result.returncode == 78
    assert "rejected" in result.stderr
    arguments = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), "--unknown"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    assert arguments.returncode == 78
    assert "invalid command line" in arguments.stderr


def test_cli_accepts_valid_current_authorization(tmp_path: Path) -> None:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    value = approval()
    value["issued_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    value["expires_at"] = (now + dt.timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    value["release_id"] = f"ctl-{now.strftime('%Y%m%dT%H%M%SZ')}-cli"
    path = tmp_path / "approval.json"
    path.write_bytes(MODULE.canonical_bytes(value))
    path.chmod(0o644)
    result = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), str(path)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert output["release_id"] == value["release_id"]
    assert output["ledger_sequence"] == 1
    assert output["ledger_parent_commit_sha"] == value["ledger"][
        "parent_commit_sha"
    ]
