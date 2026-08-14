from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))


def load(name: str, filename: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PRODUCT = load("release_v2_product_builder", "build-product-artifact.py")
OPS = load("release_v2_ops_builder", "build-ops-artifact.py")
SOURCE = load("release_v2_source_revision", "verify-source-revision-v2.py")
EVIDENCE = load("release_v2_github_evidence", "collect-github-evidence-v2.py")
CARRIER = load("release_v2_carrier", "carrier-artifact-v2.py")


def canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def approval_v2(
    *,
    api_sha: str = "1" * 40,
    api_ancestor: str = "2" * 40,
    expired: bool = False,
) -> dict[str, Any]:
    issued = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    if expired:
        issued -= dt.timedelta(days=2)
    expires = issued + dt.timedelta(hours=1)
    stamp = issued.strftime("%Y%m%dT%H%M%SZ")
    component = {
        "approved_ref": "refs/heads/main",
        "commit_sha": api_sha,
        "repository": "PluckXD/tratto-api",
        "required_ancestors": [api_ancestor],
    }
    return {
        "api": component,
        "controller": {
            "commit_sha": "3" * 40,
            "controller_tag_signature_verifier_sha256": "4" * 64,
            "immutable_release_id": 12001,
            "repository": "PluckXD/tratto-control-release",
            "repository_id": 1317521588,
            "signer_freshness_verifier_sha256": "d" * 64,
            "tag_object_sha": "5" * 40,
            "tag_ref": "refs/tags/control-controller-v6.0.0",
            "workflow_path": ".github/workflows/control-release.yml",
            "workflow_sha256": "6" * 64,
        },
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
        "issued_at": issued.isoformat().replace("+00:00", "Z"),
        "ledger": {
            "genesis_sha": "a" * 40,
            "parent_commit_sha": "b" * 40,
            "previous_manifest_sha256": "c" * 64,
            "ref": "refs/heads/main",
            "repository": "PluckXD/tratto-control-release-ledger",
            "repository_id": 1319756090,
            "sequence": 2,
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
        "ops": dict(component),
        "policy": {
            "digest_sha256": "e" * 64,
            "name": "control-production-v2",
            "path": "policies/control-production-v2.json",
            "repository": "PluckXD/tratto-control-release",
            "trust_epoch": 1,
        },
        "release_id": f"ctl-{stamp}-tests",
        "schema_version": 2,
        "web": {
            "approved_ref": "refs/heads/main",
            "commit_sha": "f" * 40,
            "repository": "PluckXD/tratto-web",
            "required_ancestors": ["0" * 40],
        },
    }


def write_approval(path: Path, value: dict[str, Any]) -> None:
    path.write_bytes(canonical(value))
    path.chmod(0o644)


def test_deterministic_packagers_accept_current_approval_v2(tmp_path: Path) -> None:
    path = tmp_path / "approval.json"
    value = approval_v2()
    write_approval(path, value)

    product, product_raw = PRODUCT.load_approval(
        path,
        kind="api",
        release_sha=value["api"]["commit_sha"],
    )
    ops, ops_raw = OPS.load_approval(path, value["ops"]["commit_sha"])

    assert product == value == ops
    assert product_raw == ops_raw == canonical(value)


def test_deterministic_packagers_reject_expired_approval_v2(tmp_path: Path) -> None:
    path = tmp_path / "approval.json"
    value = approval_v2(expired=True)
    write_approval(path, value)

    with pytest.raises(PRODUCT.ProductArtifactError, match="expired"):
        PRODUCT.load_approval(
            path,
            kind="api",
            release_sha=value["api"]["commit_sha"],
        )
    with pytest.raises(OPS.TREE.OpsTreeError, match="expired"):
        OPS.load_approval(path, value["ops"]["commit_sha"])


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return result.stdout.strip()


def source_repository(tmp_path: Path) -> tuple[Path, str, str]:
    root = tmp_path / "api"
    root.mkdir()
    git(root, "init", "-b", "main")
    git(root, "config", "user.name", "Release Test")
    git(root, "config", "user.email", "release@example.invalid")
    (root / "source.txt").write_text("first\n", encoding="utf-8")
    git(root, "add", "source.txt")
    git(root, "commit", "-m", "first")
    ancestor = git(root, "rev-parse", "HEAD")
    (root / "source.txt").write_text("second\n", encoding="utf-8")
    git(root, "commit", "-am", "second")
    approved = git(root, "rev-parse", "HEAD")
    git(root, "remote", "add", "origin", "https://github.com/PluckXD/tratto-api.git")
    git(root, "update-ref", "refs/remotes/origin/main", approved)
    return root, ancestor, approved


def test_source_revision_v2_binds_exact_fetched_main_and_ancestry(tmp_path: Path) -> None:
    root, ancestor, approved = source_repository(tmp_path)
    value = approval_v2(api_sha=approved, api_ancestor=ancestor)
    result = SOURCE.verify(root, "api", value)

    assert result["commit_sha"] == approved
    assert result["remote_main_sha"] == approved
    assert result["repository"] == "PluckXD/tratto-api"

    git(root, "update-ref", "refs/remotes/origin/main", ancestor)
    with pytest.raises(SOURCE.SourceRevisionV2Error, match="exact fetched main"):
        SOURCE.verify(root, "api", value)


class FakeReader:
    def __init__(self, values: dict[str, Any]) -> None:
        self.values = values
        self.paths: list[str] = []

    def get(self, path: str) -> Any:
        self.paths.append(path)
        return self.values[path]


def github_values() -> dict[str, Any]:
    branch = {
        "allow_deletions": {"enabled": False},
        "allow_force_pushes": {"enabled": False},
        "enforce_admins": {"enabled": True},
        "required_linear_history": {"enabled": True},
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": True,
            "require_code_owner_reviews": True,
            "require_last_push_approval": True,
            "required_approving_review_count": 2,
        },
    }
    return {
        f"/repos/{EVIDENCE.CONTROLLER}/immutable-releases": {
            "enabled": True,
            "enforced_by_owner": False,
        },
        f"/repos/{EVIDENCE.CONTROLLER}/actions/permissions": {
            "allowed_actions": "selected",
            "enabled": True,
            "sha_pinning_required": True,
        },
        f"/repos/{EVIDENCE.CONTROLLER}/branches/main/protection": branch,
        f"/repos/{EVIDENCE.CONTROLLER}/environments/{EVIDENCE.ENVIRONMENT}": {"name": EVIDENCE.ENVIRONMENT},
        f"/repos/{EVIDENCE.CONTROLLER}": {
            "full_name": EVIDENCE.CONTROLLER,
            "id": 1317521588,
            "private": False,
            "visibility": "public",
        },
        f"/repos/{EVIDENCE.CONTROLLER}/actions/permissions/selected-actions": {"patterns_allowed": []},
        f"/repos/{EVIDENCE.CONTROLLER}/branches/main/protection/required_signatures": {"enabled": True},
        f"/repos/{EVIDENCE.LEDGER}/branches/main/protection": branch,
        f"/repos/{EVIDENCE.LEDGER}/rulesets": [{"id": 11}],
        f"/repos/{EVIDENCE.LEDGER}/rulesets/11": {"id": 11},
        f"/repos/{EVIDENCE.LEDGER}": {
            "full_name": EVIDENCE.LEDGER,
            "id": 1319756090,
            "private": False,
            "visibility": "public",
        },
        f"/repos/{EVIDENCE.LEDGER}/branches/main/protection/required_signatures": {"enabled": True},
    }


def test_github_collector_only_projects_fixed_read_endpoints() -> None:
    reader = FakeReader(github_values())
    controller, ledger = EVIDENCE.collect_control_documents(reader)

    assert controller["repository"]["id"] == 1317521588
    assert controller["immutable_releases"]["enforced_by_owner"] is False
    assert controller["branch_protection"][
        "required_pull_request_reviews"
    ]["bypass_pull_request_allowances"] == {
        "apps": [],
        "teams": [],
        "users": [],
    }
    assert ledger["repository"]["id"] == 1319756090
    assert ledger["main_rulesets"] == [{"id": 11}]
    assert all(path.startswith("/repos/PluckXD/") for path in reader.paths)
    assert all("?" not in path for path in reader.paths)


def test_github_collector_writes_private_canonical_once(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    value = {"enabled": True}
    EVIDENCE.write_once(tmp_path, "evidence.json", value)
    path = tmp_path / "evidence.json"
    assert path.read_bytes() == canonical(value)
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(EVIDENCE.GitHubEvidenceV2Error, match="cannot publish"):
        EVIDENCE.write_once(tmp_path, "evidence.json", value)


def test_github_collector_appends_only_bounded_controller_outputs(
    tmp_path: Path,
) -> None:
    output = tmp_path / "github-output"
    output.write_bytes(b"existing=value\n")
    output.chmod(0o600)
    values = {
        "commit_sha": "1" * 40,
        "release_id": "12001",
        "repository_id": "1317521588",
        "tag": "control-controller-v6.0.0",
        "tag_object_sha": "2" * 40,
    }
    EVIDENCE.append_outputs(output, values)
    assert output.read_bytes() == b"existing=value\n" + b"".join(
        f"{key}={values[key]}\n".encode("ascii")
        for key in EVIDENCE.OUTPUT_KEYS
    )

    bad = dict(values)
    bad["tag"] = "control-controller-v6.0.0%0Aforged=value"
    with pytest.raises(EVIDENCE.GitHubEvidenceV2Error, match="invalid"):
        EVIDENCE.append_outputs(output, bad)


def test_carrier_local_binding_and_redirect_policy_are_fail_closed(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.tar.gz"
    payload = b"bound carrier bytes\n"
    artifact.write_bytes(payload)
    artifact.chmod(0o600)
    digest = hashlib.sha256(payload).hexdigest()

    source, info = CARRIER.stable_input(artifact, len(payload), digest)
    try:
        assert source.read() == payload
        assert info.st_size == len(payload)
    finally:
        source.close()

    assert CARRIER.allowed_redirect(
        "https://objects.githubusercontent.com/release/file?sig=x"
    ) == (
        "objects.githubusercontent.com",
        "/release/file?sig=x",
    )
    with pytest.raises(CARRIER.CarrierArtifactV2Error, match="outside approved"):
        CARRIER.allowed_redirect("https://attacker.invalid/release/file")
    artifact.chmod(0o644)
    with pytest.raises(CARRIER.CarrierArtifactV2Error, match="private"):
        CARRIER.stable_input(artifact, len(payload), digest)


class FakeUploadResponse:
    status = 201

    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def read(self, maximum: int) -> bytes:
        assert len(self.payload) <= maximum
        return self.payload


class FakeUploadConnection:
    instances: list["FakeUploadConnection"] = []

    def __init__(self, host: str, **_kwargs: Any) -> None:
        self.host = host
        self.target = ""
        self.headers: dict[str, str] = {}
        self.body = bytearray()
        self.instances.append(self)

    def putrequest(self, method: str, target: str, **_kwargs: Any) -> None:
        assert method == "POST"
        self.target = target

    def putheader(self, name: str, value: str) -> None:
        self.headers[name] = value

    def endheaders(self) -> None:
        return None

    def send(self, payload: bytes) -> None:
        self.body.extend(payload)

    def getresponse(self) -> FakeUploadResponse:
        name = "tratto-control-api-" + "1" * 40 + ".tar.gz"
        return FakeUploadResponse(
            canonical(
                {
                    "id": 9001,
                    "name": name,
                    "size": len(self.body),
                    "state": "uploaded",
                }
            )
        )

    def close(self) -> None:
        return None


def test_carrier_upload_streams_exact_bytes_and_returns_non_authority_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"exact upload bytes\n"
    artifact = tmp_path / ("tratto-control-api-" + "1" * 40 + ".tar.gz")
    artifact.write_bytes(payload)
    artifact.chmod(0o600)
    digest = hashlib.sha256(payload).hexdigest()
    FakeUploadConnection.instances.clear()
    monkeypatch.setattr(
        CARRIER.http.client,
        "HTTPSConnection",
        FakeUploadConnection,
    )

    receipt = CARRIER.upload(
        token="read-write-carrier-token",
        release_id=7001,
        path=artifact,
        name=artifact.name,
        expected_size=len(payload),
        expected_sha256=digest,
    )

    assert receipt == {
        "artifact_id": 9001,
        "artifact_name": artifact.name,
        "carrier_repository": CARRIER.REPOSITORY,
        "sha256": digest,
        "size_bytes": len(payload),
    }
    connection = FakeUploadConnection.instances[-1]
    assert connection.host == CARRIER.UPLOAD_HOST
    assert bytes(connection.body) == payload
    assert connection.headers["Content-Length"] == str(len(payload))
    assert connection.target.startswith(
        f"/repos/{CARRIER.REPOSITORY}/releases/7001/assets?"
    )


class FakeDownloadResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.offset = 0

    def read(self, maximum: int) -> bytes:
        chunk = self.payload[self.offset : self.offset + maximum]
        self.offset += len(chunk)
        return chunk


def test_carrier_download_removes_output_when_digest_binding_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"downloaded bytes\n"
    name = "tratto-control-web-" + "2" * 40 + ".tar.gz"
    monkeypatch.setattr(
        CARRIER,
        "asset_metadata",
        lambda _token, artifact_id: {
            "id": artifact_id,
            "name": name,
            "size": len(payload),
            "state": "uploaded",
        },
    )
    monkeypatch.setattr(
        CARRIER,
        "open_download",
        lambda _token, _artifact_id: FakeDownloadResponse(payload),
    )
    monkeypatch.setattr(CARRIER, "close_response", lambda _response: None)
    output = tmp_path / name

    with pytest.raises(CARRIER.CarrierArtifactV2Error, match="diverge"):
        CARRIER.download(
            token="read-only-carrier-token",
            artifact_id=8001,
            output=output,
            name=name,
            expected_size=len(payload),
            expected_sha256="0" * 64,
        )
    assert not output.exists()


def test_carrier_client_cannot_create_edit_or_delete_releases() -> None:
    source = (SCRIPTS / "carrier-artifact-v2.py").read_text(encoding="utf-8")
    assert "create-release" not in source
    assert 'connection.request("PATCH"' not in source
    assert 'connection.request("DELETE"' not in source
    assert "/releases/latest" not in source
    assert "/releases/tags/" not in source
