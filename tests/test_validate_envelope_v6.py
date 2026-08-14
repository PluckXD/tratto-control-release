from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-envelope-v6.py"
SCHEMA = ROOT / "schemas" / "release-envelope-v6.schema.json"
SPEC = importlib.util.spec_from_file_location("validate_envelope_v6", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def approval(*, sequence: int = 2) -> dict:
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
        raise AssertionError("unsupported test migration schema")
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


def artifact(label: str, commit_sha: str, asset_id: int) -> dict:
    repository = (
        "PluckXD/tratto-web"
        if label == "web"
        else "PluckXD/tratto-api"
    )
    characters = {
        1: ("a", "b", "c", "d"),
        2: ("e", "f", "1", "2"),
        3: ("3", "4", "5", "6"),
    }
    component, service, archive, tree = characters[asset_id]
    return {
        "ancestor_verified": True,
        "approved_ref": "refs/heads/main",
        "artifact_id": asset_id,
        "artifact_name": f"tratto-control-{label}-{commit_sha}.tar.gz",
        "build_job": f"build_{label}",
        "carrier_repository": "PluckXD/tratto-control-release-carrier",
        "commit_sha": commit_sha,
        "component_manifest_sha256": component * 64,
        "repository": repository,
        "runner_arch": "X64",
        "runner_environment": "github-hosted",
        "runner_os": "Linux",
        "service_digest": service * 64,
        "sha256": archive * 64,
        "size_bytes": 100 + asset_id,
        "tree_sha": tree * 40,
    }


def envelope(*, sequence: int = 2) -> dict:
    manifest = approval(sequence=sequence)
    manifest_sha256 = hashlib.sha256(
        MODULE.APPROVAL.canonical_bytes(manifest)
    ).hexdigest()
    api = artifact("api", manifest["api"]["commit_sha"], 1)
    ops = artifact("ops", manifest["ops"]["commit_sha"], 2)
    web = artifact("web", manifest["web"]["commit_sha"], 3)
    bindings = {
        label: {
            "artifact_id": value["artifact_id"],
            "component_manifest_sha256": value[
                "component_manifest_sha256"
            ],
            "service_digest": value["service_digest"],
            "sha256": value["sha256"],
        }
        for label, value in (("api", api), ("ops", ops), ("web", web))
    }
    controller_approval = manifest["controller"]
    tag_ref = controller_approval["tag_ref"]
    head_sha = "d" * 40
    return {
        "approval": {
            "manifest": manifest,
            "manifest_sha256": manifest_sha256,
            "mode": "protected-independent-ledger",
        },
        "artifacts": {"api": api, "ops": ops, "web": web},
        "behavioral_verification": {
            "artifacts": bindings,
            "api_sha": manifest["api"]["commit_sha"],
            "browser_report_sha256": "f" * 64,
            "contracts": {
                "api_auth_surface_http": True,
                "api_business_denylist_http": True,
                "api_p2t_password_ack_http": True,
                "api_reset_endpoint_http": True,
                "edge_reset_url_redaction_http": True,
                "ops_tree_digest_verified": True,
                "web_exact_hostname_http": True,
                "web_reset_fragment_browser": True,
                "web_surface_denylist_http": True,
            },
            "observations": {
                label: min(allowed)
                for label, allowed in MODULE.EXPECTED_OBSERVATIONS.items()
            },
            "schema_version": 3,
            "verdict": "pass",
            "web_sha": manifest["web"]["commit_sha"],
        },
        "carrier": {
            "authorizes_release": False,
            "repository": "PluckXD/tratto-control-release-carrier",
            "trust": "transport-only",
        },
        "controller": {
            "commit_sha": controller_approval["commit_sha"],
            "event_name": "workflow_dispatch",
            "github_sha": controller_approval["commit_sha"],
            "immutable_release_id": controller_approval[
                "immutable_release_id"
            ],
            "owner_enforced": True,
            "repository": controller_approval["repository"],
            "repository_id": controller_approval["repository_id"],
            "run_attempt": 1,
            "run_id": 123,
            "runner_arch": "X64",
            "runner_environment": "github-hosted",
            "runner_os": "Linux",
            "signer_verifier_sha256": controller_approval[
                "signer_verifier_sha256"
            ],
            "source_ref": tag_ref,
            "tag_object_sha": controller_approval["tag_object_sha"],
            "tag_ref": tag_ref,
            "workflow_path": controller_approval["workflow_path"],
            "workflow_ref": (
                "PluckXD/tratto-control-release/"
                f".github/workflows/control-release.yml@{tag_ref}"
            ),
            "workflow_sha": controller_approval["commit_sha"],
            "workflow_sha256": controller_approval["workflow_sha256"],
        },
        "ledger": {
            **manifest["ledger"],
            "head_sha": head_sha,
            "manifest_sha256": manifest_sha256,
            "record_count": sequence,
        },
        "migration": copy.deepcopy(manifest["migration"]),
        "schema_version": 6,
        "signer_freshness": {
            "controller_tag_attestation_sha256": "1" * 64,
            "github_controls_attestation_sha256": "2" * 64,
            "ledger_attestation_sha256": "3" * 64,
            "ledger_head_sha": head_sha,
            "revalidated_immediately_before_signature": True,
        },
        "supplemental_inventory": {"supplemental_only": True},
    }


def validate(value: dict) -> dict:
    return MODULE.validate_bytes(MODULE.canonical_bytes(value))


def test_accepts_complete_v6_envelope_with_later_ledger_record() -> None:
    value = envelope(sequence=2)
    assert validate(value) == value


def test_accepts_first_ledger_record_without_circular_commit_binding() -> None:
    value = envelope(sequence=1)
    assert "commit_sha" not in value["approval"]["manifest"]["ledger"]
    assert value["ledger"]["head_sha"] == "d" * 40
    assert value["ledger"]["head_sha"] != value["ledger"]["genesis_sha"]
    assert validate(value)["ledger"]["sequence"] == 1


@pytest.mark.parametrize("schema_version", (5, 6))
def test_v6_envelope_preserves_exact_versioned_product_migration(
    schema_version: int,
) -> None:
    value = envelope(sequence=2)
    migration = versioned_migration(schema_version)
    value["approval"]["manifest"]["migration"] = copy.deepcopy(migration)
    value["approval"]["manifest_sha256"] = hashlib.sha256(
        MODULE.APPROVAL.canonical_bytes(value["approval"]["manifest"])
    ).hexdigest()
    value["ledger"]["manifest_sha256"] = value["approval"][
        "manifest_sha256"
    ]
    value["migration"] = copy.deepcopy(migration)
    assert validate(value)["migration"] == migration


def test_v6_envelope_rejects_crossed_v5_v6_migration_identity() -> None:
    value = envelope(sequence=2)
    migration = versioned_migration(6)
    migration["tenant_schema_revision"] = "f49legalauth"
    value["approval"]["manifest"]["migration"] = copy.deepcopy(migration)
    value["approval"]["manifest_sha256"] = hashlib.sha256(
        MODULE.APPROVAL.canonical_bytes(value["approval"]["manifest"])
    ).hexdigest()
    value["ledger"]["manifest_sha256"] = value["approval"][
        "manifest_sha256"
    ]
    value["migration"] = copy.deepcopy(migration)
    with pytest.raises(MODULE.EnvelopeV6Error, match="revision chain"):
        validate(value)


def test_approval_is_validated_historically() -> None:
    value = envelope()
    value["approval"]["manifest"]["issued_at"] = "2024-01-01T00:00:00Z"
    value["approval"]["manifest"]["expires_at"] = "2024-01-01T00:00:01Z"
    value["approval"]["manifest"]["release_id"] = (
        "ctl-20240101T000000Z-tests"
    )
    digest = hashlib.sha256(
        MODULE.APPROVAL.canonical_bytes(value["approval"]["manifest"])
    ).hexdigest()
    value["approval"]["manifest_sha256"] = digest
    value["ledger"]["manifest_sha256"] = digest
    assert validate(value)["approval"]["manifest"]["expires_at"].startswith(
        "2024-"
    )


def test_schema_is_valid_json_and_closes_every_inline_object() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"] == {
        "const": 6,
        "type": "integer",
    }
    assert schema["properties"]["approval"]["properties"]["manifest"] == {
        "$ref": "approval-v2.schema.json"
    }
    for name in (
        "approval",
        "artifacts",
        "behavioral_verification",
        "carrier",
        "controller",
        "ledger",
        "signer_freshness",
        "supplemental_inventory",
    ):
        assert schema["properties"][name]["additionalProperties"] is False
    for name in ("artifactBinding", "productArtifact"):
        assert schema["$defs"][name]["additionalProperties"] is False


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"extra": True}), "keys diverge"),
        (
            lambda value: value.update({"schema_version": 6.0}),
            "integer 6",
        ),
        (
            lambda value: value["approval"].update({"mode": "legacy"}),
            "protected-independent-ledger",
        ),
        (
            lambda value: value["approval"].update(
                {"manifest_sha256": "0" * 64}
            ),
            "approval manifest digest",
        ),
        (
            lambda value: value["approval"]["manifest"].update(
                {"schema_version": 1}
            ),
            "approval manifest rejected",
        ),
        (
            lambda value: value["carrier"].update(
                {"authorizes_release": True}
            ),
            "non-authoritative",
        ),
        (
            lambda value: value["supplemental_inventory"].update(
                {"supplemental_only": False}
            ),
            "non-authoritative",
        ),
        (
            lambda value: value["migration"].update(
                {"head_revision": "other_head"}
            ),
            "migration contract",
        ),
    ],
)
def test_rejects_envelope_authority_or_approval_drift(
    mutation,
    message: str,
) -> None:
    value = envelope()
    mutation(value)
    with pytest.raises(MODULE.EnvelopeV6Error, match=message):
        validate(value)


@pytest.mark.parametrize(
    ("key", "replacement"),
    [
        ("repository", "attacker/ledger"),
        ("repository_id", 99999),
        ("ref", "refs/heads/dev"),
        ("genesis_sha", "1" * 40),
        ("parent_commit_sha", "2" * 40),
        ("sequence", 3),
        ("previous_manifest_sha256", "9" * 64),
    ],
)
def test_rejects_every_ledger_approval_binding(
    key: str,
    replacement,
) -> None:
    value = envelope()
    value["ledger"][key] = replacement
    with pytest.raises(
        MODULE.EnvelopeV6Error,
        match=rf"ledger\.{key} diverges",
    ):
        validate(value)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["ledger"].update(
                {"head_sha": value["ledger"]["parent_commit_sha"]}
            ),
            "distinct",
        ),
        (
            lambda value: value["ledger"].update(
                {"head_sha": value["ledger"]["genesis_sha"]}
            ),
            "distinct",
        ),
        (
            lambda value: value["ledger"].update({"record_count": 1}),
            "record_count",
        ),
        (
            lambda value: value["ledger"].update({"record_count": True}),
            "positive integer",
        ),
        (
            lambda value: value["ledger"].update(
                {"manifest_sha256": "9" * 64}
            ),
            "canonical approval",
        ),
        (
            lambda value: value["ledger"].update({"head_sha": "D" * 40}),
            "invalid format",
        ),
    ],
)
def test_rejects_invalid_external_ledger_evidence(
    mutation,
    message: str,
) -> None:
    value = envelope()
    mutation(value)
    with pytest.raises(MODULE.EnvelopeV6Error, match=message):
        validate(value)


@pytest.mark.parametrize(
    ("key", "replacement"),
    [
        ("commit_sha", "7" * 40),
        ("repository", "attacker/controller"),
        ("repository_id", 99999),
        ("immutable_release_id", 99999),
        ("tag_object_sha", "7" * 40),
        ("tag_ref", "refs/tags/control-controller-v6.0.1"),
        ("workflow_path", ".github/workflows/evil.yml"),
        ("workflow_sha256", "7" * 64),
        ("signer_verifier_sha256", "8" * 64),
    ],
)
def test_rejects_every_controller_approval_binding(
    key: str,
    replacement: str | int,
) -> None:
    value = envelope()
    value["controller"][key] = replacement
    with pytest.raises(
        MODULE.EnvelopeV6Error,
        match=rf"controller\.{key} diverges",
    ):
        validate(value)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["controller"].update(
                {"source_ref": "refs/heads/main"}
            ),
            "execution identity",
        ),
        (
            lambda value: value["controller"].update(
                {
                    "workflow_ref": (
                        "PluckXD/tratto-control-release/"
                        ".github/workflows/control-release.yml@refs/heads/main"
                    )
                }
            ),
            "execution identity",
        ),
        (
            lambda value: value["controller"].update(
                {"github_sha": "8" * 40}
            ),
            "GitHub workflow SHA",
        ),
        (
            lambda value: value["controller"].update(
                {"workflow_sha": "8" * 40}
            ),
            "GitHub workflow SHA",
        ),
        (
            lambda value: value["controller"].update(
                {"owner_enforced": False}
            ),
            "execution identity",
        ),
        (
            lambda value: value["controller"].update({"run_id": True}),
            "positive integer",
        ),
        (
            lambda value: value["controller"].update(
                {"event_name": "push"}
            ),
            "execution identity",
        ),
    ],
)
def test_rejects_non_tag_or_non_owner_controller_context(
    mutation,
    message: str,
) -> None:
    value = envelope()
    mutation(value)
    with pytest.raises(MODULE.EnvelopeV6Error, match=message):
        validate(value)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["signer_freshness"].update(
                {"ledger_head_sha": "e" * 40}
            ),
            "validated ledger head",
        ),
        (
            lambda value: value["signer_freshness"].update(
                {"ledger_attestation_sha256": "A" * 64}
            ),
            "invalid format",
        ),
        (
            lambda value: value["signer_freshness"].update(
                {
                    "github_controls_attestation_sha256": value[
                        "signer_freshness"
                    ]["ledger_attestation_sha256"]
                }
            ),
            "distinct digests",
        ),
        (
            lambda value: value["signer_freshness"].update(
                {"revalidated_immediately_before_signature": False}
            ),
            "immediately",
        ),
        (
            lambda value: value["signer_freshness"].update(
                {"unexpected": "1" * 64}
            ),
            "keys diverge",
        ),
    ],
)
def test_rejects_stale_or_ambiguous_signer_freshness(
    mutation,
    message: str,
) -> None:
    value = envelope()
    mutation(value)
    with pytest.raises(MODULE.EnvelopeV6Error, match=message):
        validate(value)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["artifacts"].pop("ops"),
            "artifacts keys",
        ),
        (
            lambda value: value["artifacts"]["api"].update(
                {"commit_sha": "8" * 40}
            ),
            "provenance",
        ),
        (
            lambda value: value["artifacts"]["ops"].update(
                {
                    "artifact_id": value["artifacts"]["api"][
                        "artifact_id"
                    ]
                }
            ),
            "distinct carrier assets",
        ),
        (
            lambda value: value["behavioral_verification"]["artifacts"][
                "web"
            ].update({"sha256": "9" * 64}),
            "not bound",
        ),
        (
            lambda value: value["behavioral_verification"][
                "contracts"
            ].update({"api_health_http": True}),
            "keys diverge",
        ),
        (
            lambda value: value["behavioral_verification"][
                "contracts"
            ].update({"api_auth_surface_http": False}),
            "did not pass",
        ),
        (
            lambda value: value["behavioral_verification"][
                "observations"
            ].update({"web_wrong_host": 200}),
            "did not pass",
        ),
    ],
)
def test_preserves_v5_artifact_and_behavioral_bindings(
    mutation,
    message: str,
) -> None:
    value = envelope()
    mutation(value)
    with pytest.raises(MODULE.EnvelopeV6Error, match=message):
        validate(value)


def test_rejects_noncanonical_and_duplicate_json() -> None:
    value = envelope()
    noncanonical = json.dumps(value, indent=2).encode("utf-8")
    with pytest.raises(MODULE.EnvelopeV6Error, match="canonical"):
        MODULE.validate_bytes(noncanonical)
    duplicate = b'{"schema_version":6,"schema_version":6}\n'
    with pytest.raises(MODULE.EnvelopeV6Error, match="duplicate JSON key"):
        MODULE.validate_bytes(duplicate)


def test_safe_reader_rejects_symlink_and_hardlink(tmp_path: Path) -> None:
    target = tmp_path / "envelope.json"
    target.write_bytes(MODULE.canonical_bytes(envelope()))
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(target)
    with pytest.raises(MODULE.EnvelopeV6Error, match="traverse symlinks"):
        MODULE.read_envelope(symlink)
    hardlink = tmp_path / "hardlink.json"
    os.link(target, hardlink)
    with pytest.raises(MODULE.EnvelopeV6Error, match="single-link"):
        MODULE.read_envelope(target)


def test_safe_reader_rejects_symlinked_parent_directory(
    tmp_path: Path,
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    target = real / "envelope.json"
    target.write_bytes(MODULE.canonical_bytes(envelope()))
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(MODULE.EnvelopeV6Error, match="traverse symlinks"):
        MODULE.read_envelope(alias / "envelope.json")


def test_safe_reader_rejects_oversized_file(tmp_path: Path) -> None:
    path = tmp_path / "oversized.json"
    path.write_bytes(b"x" * (MODULE.MAX_FILE_BYTES + 1))
    with pytest.raises(MODULE.EnvelopeV6Error, match="bounded"):
        MODULE.read_envelope(path)


def test_safe_reader_detects_metadata_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "envelope.json"
    path.write_bytes(MODULE.canonical_bytes(envelope()))
    real_fstat = MODULE.os.fstat
    calls = 0

    def changed_fstat(descriptor: int):
        nonlocal calls
        calls += 1
        value = real_fstat(descriptor)
        if calls != 2:
            return value
        return SimpleNamespace(
            st_dev=value.st_dev,
            st_ino=value.st_ino,
            st_mode=value.st_mode,
            st_nlink=value.st_nlink,
            st_size=value.st_size,
            st_mtime_ns=value.st_mtime_ns + 1,
            st_ctime_ns=value.st_ctime_ns,
        )

    monkeypatch.setattr(MODULE.os, "fstat", changed_fstat)
    with pytest.raises(MODULE.EnvelopeV6Error, match="changed"):
        MODULE.read_envelope(path)


def test_cli_returns_78_for_rejection_and_canonical_summary_for_success(
    tmp_path: Path,
) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{}\n", encoding="utf-8")
    rejected = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), str(invalid)],
        capture_output=True,
        check=False,
        text=True,
    )
    assert rejected.returncode == 78
    assert "release envelope v6 rejected:" in rejected.stderr

    valid = tmp_path / "valid.json"
    value = envelope()
    raw = MODULE.canonical_bytes(value)
    valid.write_bytes(raw)
    accepted = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), str(valid)],
        capture_output=True,
        check=False,
        text=True,
    )
    assert accepted.returncode == 0
    assert accepted.stderr == ""
    assert json.loads(accepted.stdout) == {
        "controller_tag_ref": value["controller"]["tag_ref"],
        "envelope_sha256": hashlib.sha256(raw).hexdigest(),
        "ledger_head_sha": value["ledger"]["head_sha"],
        "release_id": value["approval"]["manifest"]["release_id"],
        "schema_version": 6,
    }
