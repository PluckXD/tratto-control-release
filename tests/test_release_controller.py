from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


APPROVAL = load_module(
    "release_controller_approval",
    ROOT / "scripts" / "validate-approval.py",
)
ENVELOPE = load_module(
    "release_controller_envelope",
    ROOT / "scripts" / "validate-envelope.py",
)
GATE = load_module(
    "release_controller_gate",
    ROOT / "scripts" / "policy-gate.py",
)
CONTROLS = load_module(
    "release_controller_controls",
    ROOT / "scripts" / "verify-github-controls.py",
)
TREE = load_module(
    "release_controller_ops_tree",
    ROOT / "scripts" / "control_ops_tree.py",
)


def approval_value(api_sha: str = "1" * 40) -> dict:
    return {
        "api": {
            "approved_ref": "refs/heads/main",
            "commit_sha": api_sha,
            "repository": "PluckXD/tratto-api",
            "required_ancestors": ["2" * 40],
        },
        "controller": {
            "approved_ref": "refs/heads/main",
            "base_sha": "3" * 40,
            "repository": "PluckXD/tratto-control-release",
            "workflow_path": ".github/workflows/control-release.yml",
            "workflow_sha256": "4" * 64,
        },
        "expires_at": "2026-08-01T13:00:00Z",
        "issued_at": "2026-08-01T12:00:00Z",
        "migration": {
            "base_revision": "j1transpcod",
            "database_scope": "control-and-tenant-fleet",
            "fleet_preflight_sha256": "5" * 64,
            "head_revision": "f29controlexec",
            "mode": "expand-only",
            "tenant_catalog_count": 1,
            "tenant_catalog_sha256": "6" * 64,
            "tenant_fleet_base_revision": "j1transpcod",
        },
        "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
        "ops": {
            "approved_ref": "refs/heads/main",
            "commit_sha": api_sha,
            "repository": "PluckXD/tratto-api",
            "required_ancestors": ["7" * 40],
        },
        "policy": {
            "digest_sha256": "8" * 64,
            "name": "control-production-v1",
            "path": "policies/control-production-v1.json",
            "repository": "PluckXD/tratto-control-release",
        },
        "release_id": "ctl-20260801T120000Z-tests",
        "schema_version": 1,
        "web": {
            "approved_ref": "refs/heads/main",
            "commit_sha": "9" * 40,
            "repository": "PluckXD/tratto-web",
            "required_ancestors": ["a" * 40],
        },
    }


def artifact(label: str, commit_sha: str, asset_id: int) -> dict:
    repository = (
        "PluckXD/tratto-web"
        if label == "web"
        else "PluckXD/tratto-api"
    )
    component_char = {1: "b", 2: "c", 3: "d"}[asset_id]
    service_char = {1: "e", 2: "f", 3: "a"}[asset_id]
    archive_char = {1: "1", 2: "2", 3: "3"}[asset_id]
    tree_char = {1: "4", 2: "5", 3: "6"}[asset_id]
    return {
        "ancestor_verified": True,
        "approved_ref": "refs/heads/main",
        "artifact_id": asset_id,
        "artifact_name": f"tratto-control-{label}-{commit_sha}.tar.gz",
        "build_job": f"build_{label}",
        "carrier_repository": "PluckXD/tratto-control-release-carrier",
        "commit_sha": commit_sha,
        "component_manifest_sha256": component_char * 64,
        "repository": repository,
        "runner_arch": "X64",
        "runner_environment": "github-hosted",
        "runner_os": "Linux",
        "service_digest": service_char * 64,
        "sha256": archive_char * 64,
        "size_bytes": 100 + asset_id,
        "tree_sha": tree_char * 40,
    }


def envelope_value() -> dict:
    manifest = approval_value()
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
    return {
        "approval": {
            "manifest": manifest,
            "manifest_sha256": hashlib.sha256(
                APPROVAL.canonical_bytes(manifest)
            ).hexdigest(),
            "mode": "protected-public-controller",
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
                for label, allowed in ENVELOPE.EXPECTED_OBSERVATIONS.items()
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
            "commit_sha": "b" * 40,
            "event_name": "workflow_dispatch",
            "repository": "PluckXD/tratto-control-release",
            "runner_arch": "X64",
            "runner_environment": "github-hosted",
            "runner_os": "Linux",
            "run_attempt": 1,
            "run_id": 123,
            "source_ref": "refs/heads/main",
            "verifier_sha256": "c" * 64,
            "workflow": ".github/workflows/control-release.yml",
            "workflow_ref": (
                "PluckXD/tratto-control-release/"
                ".github/workflows/control-release.yml@refs/heads/main"
            ),
        },
        "migration": manifest["migration"],
        "schema_version": 5,
        "supplemental_inventory": {"supplemental_only": True},
    }


def test_release_readiness_is_canonical_and_unavailable() -> None:
    value = GATE.load_readiness(ROOT / "release-readiness.json")
    assert value["state"] == "unavailable"
    assert value["blockers"]
    assert value["required_envelope_schema"] == 5


def test_example_matches_canonical_policy_and_current_fleet_contract() -> None:
    path = ROOT / "examples" / "approval.example.json"
    raw = path.read_bytes()
    value = APPROVAL.parse_json(raw, "example")
    APPROVAL.require_canonical(raw, value, "example")
    APPROVAL.validate_shape(value, now=None, historical=True)
    assert value["policy"]["digest_sha256"] == hashlib.sha256(
        (ROOT / "policies" / "control-production-v1.json").read_bytes()
    ).hexdigest()
    assert value["migration"]["head_revision"] == "f29controlexec"


def test_policy_gate_returns_78_while_external_proofs_are_missing() -> None:
    environment = {
        **GATE.EXPECTED_CONTEXT,
    }
    with pytest.raises(GATE.GateError, match="RELEASE_POLICY_UNAVAILABLE"):
        GATE.gate(
            ROOT / "release-readiness.json",
            "authorize",
            environment,
        )


def test_external_control_validator_rejects_observed_bypass_and_open_actions() -> None:
    with pytest.raises(CONTROLS.ControlsError, match="bypass"):
        CONTROLS.validate_environment(
            {
                "can_admins_bypass": True,
                "protection_rules": [
                    {
                        "type": "required_reviewers",
                        "prevent_self_review": True,
                        "reviewers": [{"type": "User"}],
                    }
                ],
            }
        )
    with pytest.raises(CONTROLS.ControlsError, match="restricted"):
        CONTROLS.validate_actions(
            {
                "allowed_actions": "all",
                "enabled": True,
                "sha_pinning_required": False,
            }
        )


def test_external_control_validator_rejects_review_bypass_and_open_conversations() -> None:
    protected = {
        "allow_deletions": {"enabled": False},
        "allow_force_pushes": {"enabled": False},
        "enforce_admins": {"enabled": True},
        "required_conversation_resolution": {"enabled": True},
        "required_linear_history": {"enabled": True},
        "required_pull_request_reviews": {
            "bypass_pull_request_allowances": {
                "apps": [{"slug": "release-bot"}],
                "teams": [],
                "users": [],
            },
            "dismiss_stale_reviews": True,
            "require_code_owner_reviews": True,
            "require_last_push_approval": True,
            "required_approving_review_count": 1,
        },
    }
    with pytest.raises(CONTROLS.ControlsError, match="review bypass"):
        CONTROLS.validate_branch(protected)

    protected["required_pull_request_reviews"][
        "bypass_pull_request_allowances"
    ] = {"apps": [], "teams": [], "users": []}
    protected["required_conversation_resolution"] = {"enabled": False}
    with pytest.raises(CONTROLS.ControlsError, match="release root"):
        CONTROLS.validate_branch(protected)


def test_external_control_validator_rejects_broad_selected_actions() -> None:
    with pytest.raises(CONTROLS.ControlsError, match="allowlist"):
        CONTROLS.validate_selected_actions(
            {
                "github_owned_allowed": True,
                "patterns_allowed": ["actions/checkout@*"],
                "verified_allowed": False,
            }
        )


def test_external_control_validator_accepts_fail_closed_shapes() -> None:
    CONTROLS.validate_branch(
        {
            "allow_deletions": {"enabled": False},
            "allow_force_pushes": {"enabled": False},
            "enforce_admins": {"enabled": True},
            "required_conversation_resolution": {"enabled": True},
            "required_linear_history": {"enabled": True},
            "required_pull_request_reviews": {
                "bypass_pull_request_allowances": {
                    "apps": [],
                    "teams": [],
                    "users": [],
                },
                "dismiss_stale_reviews": True,
                "require_code_owner_reviews": True,
                "require_last_push_approval": True,
                "required_approving_review_count": 1,
            },
        }
    )
    CONTROLS.validate_environment(
        {
            "can_admins_bypass": False,
            "protection_rules": [
                {
                    "prevent_self_review": True,
                    "reviewers": [{"type": "User"}],
                    "type": "required_reviewers",
                }
            ],
        }
    )
    CONTROLS.validate_actions(
        {
            "allowed_actions": "selected",
            "enabled": True,
            "sha_pinning_required": True,
        }
    )
    CONTROLS.validate_selected_actions(
        {
            "github_owned_allowed": False,
            "patterns_allowed": list(CONTROLS.ALLOWED_ACTIONS),
            "verified_allowed": False,
        }
    )
    CONTROLS.validate_signatures({"enabled": True})


def test_envelope_binds_distinct_api_ops_web_artifacts() -> None:
    value = envelope_value()
    assert ENVELOPE.validate(value)["schema_version"] == 5


def test_canonical_v5_fixture_matches_normative_validator() -> None:
    raw, value = ENVELOPE.load(
        ROOT / "examples" / "release-envelope-v5.example.json"
    )
    assert raw == ENVELOPE.canonical_bytes(value)
    assert ENVELOPE.validate(value)["schema_version"] == 5


def test_envelope_rejects_missing_ops_artifact() -> None:
    value = envelope_value()
    del value["artifacts"]["ops"]
    with pytest.raises(ENVELOPE.EnvelopeError, match="artifacts keys"):
        ENVELOPE.validate(value)


def test_envelope_rejects_ops_commit_different_from_api() -> None:
    value = envelope_value()
    value["artifacts"]["ops"]["commit_sha"] = "c" * 40
    with pytest.raises(ENVELOPE.EnvelopeError, match="provenance"):
        ENVELOPE.validate(value)


def test_envelope_rejects_behavior_not_bound_to_ops_bytes() -> None:
    value = envelope_value()
    value["behavioral_verification"]["artifacts"]["ops"]["sha256"] = "d" * 64
    with pytest.raises(ENVELOPE.EnvelopeError, match="not bound"):
        ENVELOPE.validate(value)


def test_envelope_rejects_authoritative_carrier() -> None:
    value = envelope_value()
    value["carrier"]["authorizes_release"] = True
    with pytest.raises(ENVELOPE.EnvelopeError, match="non-authoritative"):
        ENVELOPE.validate(value)


def test_workflow_uses_only_full_sha_actions_and_isolates_signer() -> None:
    workflow = (
        ROOT / ".github" / "workflows" / "control-release.yml"
    ).read_text(encoding="utf-8")
    uses = re.findall(r"^\s*uses:\s*([^\s]+)\s*$", workflow, re.MULTILINE)
    assert uses
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", item) for item in uses)
    assert set(uses) == set(CONTROLS.ALLOWED_ACTIONS)
    assert workflow.count("python-version: '3.12.13'") == 5
    assert "APPROVAL_PATH: ${{ inputs.approval_path }}" in workflow
    assert '"${{ inputs.approval_path }}"' not in workflow
    for job in ("build_api:", "build_ops:", "build_web:", "verify:"):
        assert f"\n  {job}" in workflow
    signer = workflow.split("\n  sign_release:", 1)[1]
    assert "actions/checkout" not in signer
    assert "secrets." not in signer
    assert "id-token: write" in signer
    assert "environment: control-release" in signer
    assert "exit 78" in signer


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        },
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def test_ops_artifact_round_trip_uses_canonical_modes_and_digest(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    git(source, "init", "-b", "main")
    git(source, "config", "user.name", "Release Test")
    git(source, "config", "user.email", "release@example.invalid")
    for relative in sorted(TREE.REQUIRED_FILES):
        path = source / "ops" / "control" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{relative}\n", encoding="utf-8")
        if relative.endswith(".sh"):
            path.chmod(0o755)
    git(source, "add", ".")
    git(source, "commit", "-m", "ops fixture")
    release_sha = git(source, "rev-parse", "HEAD")

    approval = approval_value(release_sha)
    approval_path = tmp_path / "approval.json"
    approval_path.write_bytes(APPROVAL.canonical_bytes(approval))
    archive = tmp_path / f"tratto-control-ops-{release_sha}.tar.gz"
    build = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "build-ops-artifact.py"),
            "--repository-root",
            str(source),
            "--approval",
            str(approval_path),
            "--release-sha",
            release_sha,
            "--output",
            str(archive),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stderr
    summary = json.loads(build.stdout)
    assert re.fullmatch(r"3\.12\.[0-9]+", summary["python"])
    validate = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "validate-ops-artifact.py"),
            "--archive",
            str(archive),
            "--approval",
            str(approval_path),
            "--release-sha",
            release_sha,
            "--expected-sha256",
            summary["sha256"],
            "--expected-manifest-sha256",
            summary["component_manifest_sha256"],
            "--expected-service-digest",
            summary["service_digest"],
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert validate.returncode == 0, validate.stderr
    with tarfile.open(archive, "r:gz") as handle:
        members = handle.getmembers()
    assert all(
        member.mode == 0o555
        for member in members
        if member.isdir()
    )
    assert all(
        member.mode in {0o444, 0o555}
        for member in members
        if member.isfile()
    )
    assert not any(member.islnk() for member in members)


def test_ops_inventory_serialization_vector() -> None:
    records = [
        (
            "scripts/a.sh",
            TREE.inventory_record(
                kind="file",
                mode=0o555,
                content_sha256=hashlib.sha256(b"a\n").hexdigest(),
                path="scripts/a.sh",
            ),
        ),
        (
            "config/z.env.template",
            TREE.inventory_record(
                kind="file",
                mode=0o444,
                content_sha256=hashlib.sha256(b"z\n").hexdigest(),
                path="config/z.env.template",
            ),
        ),
    ]
    assert TREE.service_digest(records) == (
        "5e25049f42dec6136d54531c65cded1f31d0973863d8f9a1cec58b128f54dd4a"
    )


def test_ops_inventory_rejects_links() -> None:
    with pytest.raises(TREE.OpsTreeError, match="type"):
        TREE.inventory_record(
            kind="symlink",
            mode=0o777,
            content_sha256="1" * 64,
            path="scripts/link",
        )
