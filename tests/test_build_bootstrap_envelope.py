from __future__ import annotations

import hashlib
import datetime as dt
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build-bootstrap-envelope.py"
SPEC = importlib.util.spec_from_file_location(
    "bootstrap_envelope_builder_under_test",
    SCRIPT,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


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


def approval(*, expired: bool = False) -> dict:
    value = json.loads(
        (
            ROOT / "examples" / "approval.example.json"
        ).read_text()
    )
    value["api"]["commit_sha"] = "1" * 40
    value["ops"]["commit_sha"] = "1" * 40
    value["web"]["commit_sha"] = "2" * 40
    value["controller"]["base_sha"] = "3" * 40
    issued_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    if expired:
        issued_at -= dt.timedelta(days=2)
    expires_at = issued_at + dt.timedelta(hours=1)
    stamp = issued_at.strftime("%Y%m%dT%H%M%SZ")
    value["release_id"] = f"ctl-{stamp}-bootstrap"
    value["issued_at"] = issued_at.isoformat().replace("+00:00", "Z")
    value["expires_at"] = expires_at.isoformat().replace("+00:00", "Z")
    return value


def summary(label: str, release_sha: str) -> dict:
    value = {
        "artifact_name": (
            f"tratto-control-{label}-{release_sha}.tar.gz"
        ),
        "component_manifest_sha256": "4" * 64,
        "runtime_policy_sha256": (
            MODULE.RUNTIME.EXPECTED_POLICY_SHA256
        ),
        "service_digest": "6" * 64,
        "sha256": "7" * 64,
        "size_bytes": 123,
        "tree_sha": "8" * 40,
    }
    if label == "ops":
        value["python"] = MODULE.RUNTIME.EXPECTED_POLICY[
            "python"
        ]["build_version"]
    return value


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
    expired: bool = False,
    helper_receipt: dict | None = None,
    helper_receipt_raw: bytes | None = None,
    summaries: dict[str, dict] | None = None,
) -> subprocess.CompletedProcess[str]:
    artifact_ids = ids or {"api": 11, "ops": 12, "web": 13}
    approval_path = tmp_path / "approval.json"
    put(approval_path, approval(expired=expired))
    summary_paths: dict[str, Path] = {}
    for label, release_sha in (
        ("api", "1" * 40),
        ("ops", "1" * 40),
        ("web", "2" * 40),
    ):
        path = tmp_path / f"{label}.json"
        value = (
            summaries[label]
            if summaries is not None and label in summaries
            else summary(label, release_sha)
        )
        put(path, value)
        summary_paths[label] = path
    behavior_path = tmp_path / "behavior.json"
    put(behavior_path, behavior(artifact_ids))
    receipt_path = tmp_path / "bootstrap-source-helper.json"
    put(
        receipt_path,
        helper_receipt
        if helper_receipt is not None
        else {
            "controller_sha": "3" * 40,
            "name": "install-bootstrap-source-kit.py",
            "sha256": "c" * 64,
            "size_bytes": 456,
        },
    )
    if helper_receipt_raw is not None:
        receipt_path.write_bytes(helper_receipt_raw)
        receipt_path.chmod(0o644)
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
            "--bootstrap-source-helper",
            str(receipt_path),
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
    assert value["schema_version"] == 6
    assert value["bootstrap_source_helper"] == {
        "controller_sha": "3" * 40,
        "name": "install-bootstrap-source-kit.py",
        "sha256": "c" * 64,
        "size_bytes": 456,
    }
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


def test_rejects_ops_summary_without_python(tmp_path: Path) -> None:
    value = summary("ops", "1" * 40)
    del value["python"]

    result = run_builder(tmp_path, summaries={"ops": value})

    assert result.returncode == 78
    assert "ops summary has invalid keys" in result.stderr
    assert not (tmp_path / "attestation.json").exists()


def test_rejects_ops_summary_with_wrong_python(tmp_path: Path) -> None:
    value = summary("ops", "1" * 40)
    value["python"] = "3.12.12"

    result = run_builder(tmp_path, summaries={"ops": value})

    assert result.returncode == 78
    assert "ops summary Python diverges" in result.stderr
    assert not (tmp_path / "attestation.json").exists()


@pytest.mark.parametrize("label,release_sha", [
    ("api", "1" * 40),
    ("web", "2" * 40),
])
def test_rejects_python_in_non_ops_summary(
    tmp_path: Path,
    label: str,
    release_sha: str,
) -> None:
    value = summary(label, release_sha)
    value["python"] = MODULE.RUNTIME.EXPECTED_POLICY[
        "python"
    ]["build_version"]

    result = run_builder(tmp_path, summaries={label: value})

    assert result.returncode == 78
    assert f"{label} summary has invalid keys" in result.stderr
    assert not (tmp_path / "attestation.json").exists()


@pytest.mark.parametrize("label,release_sha", [
    ("api", "1" * 40),
    ("ops", "1" * 40),
    ("web", "2" * 40),
])
def test_rejects_extra_summary_key(
    tmp_path: Path,
    label: str,
    release_sha: str,
) -> None:
    value = summary(label, release_sha)
    value["extra"] = "forbidden"

    result = run_builder(tmp_path, summaries={label: value})

    assert result.returncode == 78
    assert f"{label} summary has invalid keys" in result.stderr
    assert not (tmp_path / "attestation.json").exists()


def test_rejects_runtime_policy_outside_compiled_contract(
    tmp_path: Path,
) -> None:
    value = summary("api", "1" * 40)
    value["runtime_policy_sha256"] = "5" * 64

    result = run_builder(tmp_path, summaries={"api": value})

    assert result.returncode == 78
    assert "runtime policy is not the reviewed contract" in result.stderr
    assert not (tmp_path / "attestation.json").exists()


def test_rejects_reused_artifact_id(tmp_path: Path) -> None:
    result = run_builder(
        tmp_path,
        ids={"api": 11, "ops": 11, "web": 13},
    )

    assert result.returncode == 78
    assert "distinct positive IDs" in result.stderr
    assert not (tmp_path / "attestation.json").exists()


def test_rejects_expired_bootstrap_approval(tmp_path: Path) -> None:
    result = run_builder(tmp_path, expired=True)

    assert result.returncode == 78
    assert "expired" in result.stderr
    assert not (tmp_path / "attestation.json").exists()


def test_rejects_helper_receipt_not_bound_to_controller(
    tmp_path: Path,
) -> None:
    result = run_builder(
        tmp_path,
        helper_receipt={
            "controller_sha": "d" * 40,
            "name": "install-bootstrap-source-kit.py",
            "sha256": "c" * 64,
            "size_bytes": 456,
        },
    )

    assert result.returncode == 78
    assert "helper receipt is invalid" in result.stderr
    assert not (tmp_path / "attestation.json").exists()


def test_rejects_non_exact_helper_receipt(tmp_path: Path) -> None:
    result = run_builder(
        tmp_path,
        helper_receipt={
            "controller_sha": "3" * 40,
            "name": "install-bootstrap-source-kit.py",
            "sha256": "c" * 64,
            "size_bytes": 456,
            "schema_version": 1,
        },
    )

    assert result.returncode == 78
    assert "helper receipt is invalid" in result.stderr
    assert not (tmp_path / "attestation.json").exists()


def test_rejects_non_string_helper_digest(tmp_path: Path) -> None:
    result = run_builder(
        tmp_path,
        helper_receipt={
            "controller_sha": "3" * 40,
            "name": "install-bootstrap-source-kit.py",
            "sha256": int("1" * 64),
            "size_bytes": 456,
        },
    )

    assert result.returncode == 78
    assert "helper receipt is invalid" in result.stderr
    assert not (tmp_path / "attestation.json").exists()


def test_rejects_noncanonical_helper_receipt(tmp_path: Path) -> None:
    result = run_builder(
        tmp_path,
        helper_receipt_raw=json.dumps(
            {
                "controller_sha": "3" * 40,
                "name": "install-bootstrap-source-kit.py",
                "sha256": "c" * 64,
                "size_bytes": 456,
            },
            indent=2,
        ).encode(),
    )

    assert result.returncode == 78
    assert "canonical" in result.stderr
    assert not (tmp_path / "attestation.json").exists()


def test_read_json_uses_one_stable_nofollow_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "input.json"
    put(source, {"value": 1})

    def forbid_path_reopen(_path: Path) -> bytes:
        raise AssertionError("Path.read_bytes must not be used")

    monkeypatch.setattr(Path, "read_bytes", forbid_path_reopen)
    raw, value = MODULE.read_json(source, "test input")

    assert raw == canonical({"value": 1})
    assert value == {"value": 1}


def test_read_json_rejects_symlink(tmp_path: Path) -> None:
    source = tmp_path / "input.json"
    put(source, {"value": 1})
    link = tmp_path / "link.json"
    link.symlink_to(source)

    with pytest.raises(MODULE.BootstrapEnvelopeError):
        MODULE.read_json(link, "test input")
