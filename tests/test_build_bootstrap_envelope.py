from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build-bootstrap-envelope.py"


def canonical(value: dict) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()


def put(path: Path, value: dict) -> None:
    path.write_bytes(canonical(value))
    path.chmod(0o644)


def approval() -> dict:
    value = json.loads(
        (
            ROOT / "examples" / "approval.example.json"
        ).read_text()
    )
    value["api"]["commit_sha"] = "1" * 40
    value["ops"]["commit_sha"] = "1" * 40
    value["web"]["commit_sha"] = "2" * 40
    value["controller"]["base_sha"] = "3" * 40
    return value


def summary(label: str, release_sha: str) -> dict:
    return {
        "artifact_name": (
            f"tratto-control-{label}-{release_sha}.tar.gz"
        ),
        "component_manifest_sha256": "4" * 64,
        "runtime_policy_sha256": "5" * 64,
        "service_digest": "6" * 64,
        "sha256": "7" * 64,
        "size_bytes": 123,
        "tree_sha": "8" * 40,
    }


def behavior(ids: dict[str, int]) -> dict:
    return {
        "api_sha": "1" * 40,
        "artifacts": {
            label: {
                "artifact_id": artifact_id,
                "component_manifest_sha256": "4" * 64,
                "service_digest": "6" * 64,
                "sha256": "7" * 64,
            }
            for label, artifact_id in ids.items()
        },
        "browser_report_sha256": "9" * 64,
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
        "observations": {"tests": 1},
        "schema_version": 3,
        "verdict": "pass",
        "web_sha": "2" * 40,
    }


def run_builder(
    tmp_path: Path,
    *,
    ids: dict[str, int] | None = None,
) -> subprocess.CompletedProcess[str]:
    artifact_ids = ids or {"api": 11, "ops": 12, "web": 13}
    approval_path = tmp_path / "approval.json"
    put(approval_path, approval())
    summary_paths: dict[str, Path] = {}
    for label, release_sha in (
        ("api", "1" * 40),
        ("ops", "1" * 40),
        ("web", "2" * 40),
    ):
        path = tmp_path / f"{label}.json"
        put(path, summary(label, release_sha))
        summary_paths[label] = path
    behavior_path = tmp_path / "behavior.json"
    put(behavior_path, behavior(artifact_ids))
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--approval",
            str(approval_path),
            "--api-summary",
            str(summary_paths["api"]),
            "--ops-summary",
            str(summary_paths["ops"]),
            "--web-summary",
            str(summary_paths["web"]),
            "--behavior",
            str(behavior_path),
            "--api-artifact-id",
            str(artifact_ids["api"]),
            "--ops-artifact-id",
            str(artifact_ids["ops"]),
            "--web-artifact-id",
            str(artifact_ids["web"]),
            "--carrier-sha",
            "a" * 40,
            "--controller-sha",
            "3" * 40,
            "--run-id",
            "42",
            "--run-attempt",
            "1",
            "--verifier-sha256",
            "b" * 64,
            "--output",
            str(tmp_path / "attestation.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_builds_canonical_single_operator_envelope(
    tmp_path: Path,
) -> None:
    result = run_builder(tmp_path)

    assert result.returncode == 0, result.stderr
    attestation_path = tmp_path / "attestation.json"
    raw = attestation_path.read_bytes()
    value = json.loads(raw)
    assert raw == canonical(value)
    assert value["schema_version"] == 5
    assert value["approval"]["mode"] == "single-operator-bootstrap"
    assert value["controller"]["repository"].endswith(
        "tratto-control-release-carrier"
    )
    assert value["approval"]["manifest"]["controller"]["base_sha"] == (
        "3" * 40
    )
    summary_value = json.loads(result.stdout)
    assert summary_value["attestation_sha256"] == hashlib.sha256(
        raw
    ).hexdigest()


def test_rejects_reused_artifact_id(tmp_path: Path) -> None:
    result = run_builder(
        tmp_path,
        ids={"api": 11, "ops": 11, "web": 13},
    )

    assert result.returncode == 78
    assert "distinct positive IDs" in result.stderr
    assert not (tmp_path / "attestation.json").exists()
