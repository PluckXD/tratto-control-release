from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

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
RUNTIME = load_module(
    "release_controller_runtime_policy",
    ROOT / "scripts" / "runtime_policy.py",
)
COMPONENT = load_module(
    "release_controller_component_manifest",
    ROOT / "scripts" / "component_manifest.py",
)
HOST_RUNTIME = load_module(
    "release_controller_host_runtime",
    ROOT / "scripts" / "attest-host-runtime.py",
)
RUNTIME_VERIFY = load_module(
    "release_controller_runtime_verify",
    ROOT / "scripts" / "verify-runtime-contract.py",
)
NODE_EXTRACT = load_module(
    "release_controller_node_extract",
    ROOT / "scripts" / "extract-reviewed-node.py",
)
OPS_BUILDER = load_module(
    "release_controller_ops_builder",
    ROOT / "scripts" / "build-ops-artifact.py",
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


def test_all_runtime_policy_schema_and_approval_digests_are_cross_bound() -> None:
    runtime_digest = RUNTIME.EXPECTED_POLICY_SHA256
    component_schema = json.loads(
        (
            ROOT / "schemas" / "component-manifest.schema.json"
        ).read_text(encoding="utf-8")
    )
    host_schema = json.loads(
        (
            ROOT / "schemas" / "host-runtime-attestation.schema.json"
        ).read_text(encoding="utf-8")
    )
    production_raw = (
        ROOT / "policies" / "control-production-v1.json"
    ).read_bytes()
    production = json.loads(production_raw)
    approval = json.loads(
        (ROOT / "examples" / "approval.example.json").read_bytes()
    )
    assert (
        component_schema["properties"]["runtime_policy"]["properties"][
            "sha256"
        ]["const"]
        == runtime_digest
    )
    assert (
        host_schema["properties"]["runtime_policy_sha256"]["const"]
        == runtime_digest
    )
    assert (
        production["runtime_policy"]["digest_sha256"]
        == runtime_digest
    )
    assert approval["policy"]["digest_sha256"] == hashlib.sha256(
        production_raw
    ).hexdigest()


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


def test_runtime_policy_is_canonical_exact_and_separates_build_from_host() -> None:
    path = ROOT / "policies" / "control-runtime-v1.json"
    raw = path.read_bytes()
    value, digest = RUNTIME.validate_bytes(raw)
    assert digest == RUNTIME.EXPECTED_POLICY_SHA256
    assert value["python"]["build_version"] == "3.12.13"
    assert value["python"]["major_minor"] == "3.12"
    assert value["python"]["cache_tag"] == "cpython-312"
    assert value["python"]["executable"] == "/usr/bin/python3.12"
    assert value["node"]["version"] == "v22.22.0"
    assert (
        value["node"]["archive_member"]
        == "node-v22.22.0-linux-x64/bin/node"
    )
    assert value["node"]["executable"].startswith(
        "/opt/tratto-control/toolchains/"
    )
    assert value["root_validation"]["artifact_interpreter_execution"] is False


def fake_stat(
    kind: int,
    mode: int,
    *,
    inode: int,
    links: int = 1,
    uid: int = 0,
) -> SimpleNamespace:
    return SimpleNamespace(
        st_ctime_ns=10,
        st_dev=1,
        st_gid=0,
        st_ino=inode,
        st_mode=kind | mode,
        st_mtime_ns=10,
        st_nlink=links,
        st_size=1024,
        st_uid=uid,
    )


def test_runtime_verifier_binds_all_approval_component_shas() -> None:
    approval = approval_value()
    RUNTIME_VERIFY.validate_approval_component_shas(
        approval,
        api_sha=approval["api"]["commit_sha"],
        web_sha=approval["web"]["commit_sha"],
    )
    for component in ("api", "ops", "web"):
        changed = approval_value()
        changed[component]["commit_sha"] = "f" * 40
        with pytest.raises(SystemExit, match="not authorized"):
            RUNTIME_VERIFY.validate_approval_component_shas(
                changed,
                api_sha=approval["api"]["commit_sha"],
                web_sha=approval["web"]["commit_sha"],
            )


def test_runtime_verifier_fd_json_rejects_symlink_and_snapshot_change(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "approval.json"
    path.write_bytes(APPROVAL.canonical_bytes(approval_value()))
    path.chmod(0o600)
    link = tmp_path / "approval-link.json"
    link.symlink_to(path)
    with pytest.raises(SystemExit, match="unavailable or invalid"):
        RUNTIME_VERIFY.regular_json(link, "approval")

    real_fstat = RUNTIME_VERIFY.os.fstat
    calls = 0

    def changed_fstat(descriptor: int):
        nonlocal calls
        info = real_fstat(descriptor)
        calls += 1
        if calls == 2:
            values = {
                name: getattr(info, name)
                for name in (
                    "st_ctime_ns",
                    "st_dev",
                    "st_gid",
                    "st_ino",
                    "st_mode",
                    "st_mtime_ns",
                    "st_nlink",
                    "st_size",
                    "st_uid",
                )
            }
            values["st_ino"] = info.st_ino + 1
            return SimpleNamespace(**values)
        return info

    monkeypatch.setattr(RUNTIME_VERIFY.os, "fstat", changed_fstat)
    with pytest.raises(SystemExit, match="changed while being read"):
        RUNTIME_VERIFY.regular_json(path, "approval")


def test_runtime_verifier_fd_digest_rejects_symlink_and_snapshot_change(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "requirements.lock"
    path.write_bytes(b"locked\n")
    path.chmod(0o444)
    link = tmp_path / "requirements-link.lock"
    link.symlink_to(path)
    with pytest.raises(SystemExit, match="unavailable"):
        RUNTIME_VERIFY.bounded_digest(link, "lock", 1024)

    real_fstat = RUNTIME_VERIFY.os.fstat
    calls = 0

    def changed_fstat(descriptor: int):
        nonlocal calls
        info = real_fstat(descriptor)
        calls += 1
        if calls == 2:
            values = {
                name: getattr(info, name)
                for name in (
                    "st_ctime_ns",
                    "st_dev",
                    "st_gid",
                    "st_ino",
                    "st_mode",
                    "st_mtime_ns",
                    "st_nlink",
                    "st_size",
                    "st_uid",
                )
            }
            values["st_mtime_ns"] = info.st_mtime_ns + 1
            return SimpleNamespace(**values)
        return info

    monkeypatch.setattr(RUNTIME_VERIFY.os, "fstat", changed_fstat)
    with pytest.raises(SystemExit, match="changed while being hashed"):
        RUNTIME_VERIFY.bounded_digest(path, "lock", 1024)


def test_runtime_verifier_observes_redirect_instead_of_following_404() -> None:
    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/forbidden":
                self.send_response(302)
                self.send_header("Location", "/generic-not-found")
            else:
                self.send_response(404)
            self.end_headers()

        def log_message(self, *args) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        status = RUNTIME_VERIFY.request(
            f"http://127.0.0.1:{server.server_port}",
            "/forbidden",
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
    assert status == 302
    with pytest.raises(SystemExit, match="returned HTTP 302"):
        RUNTIME_VERIFY.expect(status, {404}, "forbidden endpoint")


def test_ops_builder_rejects_false_platform_provenance() -> None:
    policy = RUNTIME.EXPECTED_POLICY
    OPS_BUILDER.validate_builder_platform(
        policy,
        system="Linux",
        architecture="x86_64",
        implementation="CPython",
        python_version="3.12.13",
    )
    for field, wrong in (
        ("system", "Darwin"),
        ("architecture", "arm64"),
        ("implementation", "PyPy"),
        ("python_version", "3.12.3"),
    ):
        values = {
            "system": "Linux",
            "architecture": "x86_64",
            "implementation": "CPython",
            "python_version": "3.12.13",
        }
        values[field] = wrong
        with pytest.raises(
            OPS_BUILDER.TREE.OpsTreeError,
            match="builder host/runtime",
        ):
            OPS_BUILDER.validate_builder_platform(policy, **values)


def test_embedded_runtime_policy_must_match_exact_signed_bytes() -> None:
    raw = RUNTIME.canonical_bytes(RUNTIME.EXPECTED_POLICY)
    digest = hashlib.sha256(raw).hexdigest()
    RUNTIME.validate_embedded(raw, digest)
    with pytest.raises(RUNTIME.RuntimePolicyError, match="embedded"):
        RUNTIME.validate_embedded(raw + b" ", digest)
    with pytest.raises(RUNTIME.RuntimePolicyError, match="embedded"):
        RUNTIME.validate_embedded(raw, "0" * 64)
    with pytest.raises(RUNTIME.RuntimePolicyError, match="embedded"):
        RUNTIME.validate_embedded(None, digest)


@pytest.mark.parametrize(
    ("kind", "mode", "links", "size"),
    [
        (stat.S_IFLNK, 0o444, 1, 30_779_824),
        (stat.S_IFREG, 0o444, 2, 30_779_824),
        (stat.S_IFREG, 0o666, 1, 30_779_824),
        (stat.S_IFREG, 0o444, 1, 30_779_823),
    ],
)
def test_node_archive_rejects_unsafe_metadata(
    kind: int,
    mode: int,
    links: int,
    size: int,
) -> None:
    info = fake_stat(kind, mode, inode=1, links=links)
    info.st_size = size
    with pytest.raises(NODE_EXTRACT.NodeArchiveError, match="metadata/size"):
        NODE_EXTRACT.validate_archive_metadata(
            info,
            expected_size=30_779_824,
        )


def test_node_archive_hash_and_snapshot_are_bound(
    tmp_path: Path,
    monkeypatch,
) -> None:
    archive = tmp_path / "node.tar.xz"
    archive.write_bytes(b"reviewed archive fixture")
    archive.chmod(0o400)
    descriptor = os.open(archive, os.O_RDONLY)
    try:
        info = os.fstat(descriptor)
        NODE_EXTRACT.validate_archive_metadata(
            info,
            expected_size=info.st_size,
        )
        assert NODE_EXTRACT.digest_descriptor(
            descriptor,
            info,
            "Node archive",
        ) == hashlib.sha256(archive.read_bytes()).hexdigest()

        changed = SimpleNamespace(
            st_ctime_ns=info.st_ctime_ns,
            st_dev=info.st_dev,
            st_gid=info.st_gid,
            st_ino=info.st_ino + 1,
            st_mode=info.st_mode,
            st_mtime_ns=info.st_mtime_ns,
            st_nlink=info.st_nlink,
            st_size=info.st_size,
            st_uid=info.st_uid,
        )
        monkeypatch.setattr(NODE_EXTRACT.os, "fstat", lambda _: changed)
        with pytest.raises(NODE_EXTRACT.NodeArchiveError, match="changed"):
            NODE_EXTRACT.digest_descriptor(
                descriptor,
                info,
                "Node archive",
            )
    finally:
        os.close(descriptor)


def test_node_archive_requires_one_literal_policy_member() -> None:
    expected = RUNTIME.EXPECTED_POLICY["node"]["archive_member"]
    member = tarfile.TarInfo(expected)
    absent = SimpleNamespace(pax_headers={}, getmembers=lambda: [])
    duplicate = SimpleNamespace(
        pax_headers={},
        getmembers=lambda: [member, member],
    )
    with pytest.raises(NODE_EXTRACT.NodeArchiveError, match="unique"):
        NODE_EXTRACT.select_unique_member(absent, expected)
    with pytest.raises(NODE_EXTRACT.NodeArchiveError, match="unique"):
        NODE_EXTRACT.select_unique_member(duplicate, expected)
    assert (
        NODE_EXTRACT.select_unique_member(
            SimpleNamespace(pax_headers={}, getmembers=lambda: [member]),
            expected,
        )
        is member
    )
    with pytest.raises(NODE_EXTRACT.NodeArchiveError, match="global PAX"):
        NODE_EXTRACT.select_unique_member(
            SimpleNamespace(
                pax_headers={"comment": "forbidden"},
                getmembers=lambda: [member],
            ),
            expected,
        )


@pytest.mark.parametrize(
    ("member_type", "mode", "size"),
    [
        (tarfile.SYMTYPE, 0o755, 4),
        (tarfile.LNKTYPE, 0o755, 4),
        (tarfile.REGTYPE, 0o775, 4),
        (tarfile.REGTYPE, 0o755, 5),
    ],
)
def test_node_member_rejects_link_mode_and_size(
    tmp_path: Path,
    member_type: bytes,
    mode: int,
    size: int,
) -> None:
    member = tarfile.TarInfo(
        RUNTIME.EXPECTED_POLICY["node"]["archive_member"]
    )
    member.type = member_type
    member.mode = mode
    member.size = size
    archive = SimpleNamespace(extractfile=lambda _: io.BytesIO(b"node"))
    with pytest.raises(NODE_EXTRACT.NodeArchiveError, match="exact bounded"):
        NODE_EXTRACT.write_member(
            archive,
            member,
            tmp_path / "node",
            expected_size=4,
            expected_digest=hashlib.sha256(b"node").hexdigest(),
        )


@pytest.mark.parametrize("metadata", ("pax", "sparse"))
def test_node_member_rejects_pax_and_sparse_metadata(
    tmp_path: Path,
    metadata: str,
) -> None:
    archive, member = node_member_fixture(b"node")
    if metadata == "pax":
        member.pax_headers = {"comment": "forbidden"}
    else:
        member.sparse = [(0, 4)]
    with pytest.raises(NODE_EXTRACT.NodeArchiveError, match="exact bounded"):
        NODE_EXTRACT.write_member(
            archive,
            member,
            tmp_path / "node",
            expected_size=4,
            expected_digest=hashlib.sha256(b"node").hexdigest(),
        )


def node_member_fixture(payload: bytes) -> tuple[SimpleNamespace, tarfile.TarInfo]:
    member = tarfile.TarInfo(
        RUNTIME.EXPECTED_POLICY["node"]["archive_member"]
    )
    member.type = tarfile.REGTYPE
    member.mode = 0o755
    member.size = len(payload)
    archive = SimpleNamespace(
        extractfile=lambda _: io.BytesIO(payload),
    )
    return archive, member


def test_node_member_streams_to_exclusive_root_only_output(
    tmp_path: Path,
) -> None:
    payload = b"reviewed-node"
    archive, member = node_member_fixture(payload)
    output = tmp_path / "node"
    NODE_EXTRACT.write_member(
        archive,
        member,
        output,
        expected_size=len(payload),
        expected_digest=hashlib.sha256(payload).hexdigest(),
    )
    assert output.read_bytes() == payload
    assert stat.S_IMODE(output.stat().st_mode) == 0o400
    with pytest.raises(OSError):
        NODE_EXTRACT.write_member(
            archive,
            member,
            output,
            expected_size=len(payload),
            expected_digest=hashlib.sha256(payload).hexdigest(),
        )
    assert output.read_bytes() == payload


def test_node_member_rejects_symlink_output_without_touching_target(
    tmp_path: Path,
) -> None:
    payload = b"reviewed-node"
    archive, member = node_member_fixture(payload)
    target = tmp_path / "target"
    target.write_bytes(b"preserve")
    output = tmp_path / "node"
    output.symlink_to(target)
    with pytest.raises(OSError):
        NODE_EXTRACT.write_member(
            archive,
            member,
            output,
            expected_size=len(payload),
            expected_digest=hashlib.sha256(payload).hexdigest(),
        )
    assert target.read_bytes() == b"preserve"
    assert output.is_symlink()


def test_node_member_digest_failure_cleans_only_created_output(
    tmp_path: Path,
) -> None:
    payload = b"reviewed-node"
    archive, member = node_member_fixture(payload)
    output = tmp_path / "node"
    with pytest.raises(NODE_EXTRACT.NodeArchiveError, match="SHA-256"):
        NODE_EXTRACT.write_member(
            archive,
            member,
            output,
            expected_size=len(payload),
            expected_digest="0" * 64,
        )
    assert not output.exists()


@pytest.mark.parametrize("failure", ("zero", "enospc"))
def test_node_member_write_failure_is_bounded_and_cleaned(
    tmp_path: Path,
    monkeypatch,
    failure: str,
) -> None:
    payload = b"reviewed-node"
    archive, member = node_member_fixture(payload)
    output = tmp_path / "node"

    if failure == "zero":
        monkeypatch.setattr(NODE_EXTRACT.os, "write", lambda *_: 0)
        expected_error = NODE_EXTRACT.NodeArchiveError
    else:
        def no_space(*_):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(NODE_EXTRACT.os, "write", no_space)
        expected_error = OSError
    with pytest.raises(expected_error):
        NODE_EXTRACT.write_member(
            archive,
            member,
            output,
            expected_size=len(payload),
            expected_digest=hashlib.sha256(payload).hexdigest(),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        (
            [
                (Path("/trusted"), fake_stat(stat.S_IFDIR, 0o755, inode=1)),
                (Path("/trusted/node"), fake_stat(stat.S_IFLNK, 0o777, inode=2)),
            ],
            "symlink",
        ),
        (
            [
                (Path("/trusted"), fake_stat(stat.S_IFDIR, 0o777, inode=1)),
                (Path("/trusted/node"), fake_stat(stat.S_IFREG, 0o555, inode=2)),
            ],
            "protected",
        ),
        (
            [
                (Path("/trusted"), fake_stat(stat.S_IFDIR, 0o700, inode=1)),
                (Path("/trusted/node"), fake_stat(stat.S_IFREG, 0o555, inode=2)),
            ],
            "world-traversable",
        ),
        (
            [
                (Path("/trusted"), fake_stat(stat.S_IFDIR, 0o755, inode=1)),
                (
                    Path("/trusted/node"),
                    fake_stat(stat.S_IFREG, 0o555, inode=2, links=2),
                ),
            ],
            "leaf metadata",
        ),
        (
            [
                (Path("/trusted"), fake_stat(stat.S_IFDIR, 0o755, inode=1)),
                (Path("/trusted/node"), fake_stat(stat.S_IFREG, 0o755, inode=2)),
            ],
            "leaf metadata",
        ),
    ],
)
def test_host_runtime_rejects_unsafe_path_metadata(entries, message) -> None:
    with pytest.raises(HOST_RUNTIME.HostRuntimeError, match=message):
        HOST_RUNTIME.validate_chain_metadata(
            entries,
            "runtime",
            leaf_modes={0o555},
        )


def test_host_runtime_rejects_inode_snapshot_change(monkeypatch) -> None:
    expected = fake_stat(stat.S_IFREG, 0o555, inode=1)
    changed = fake_stat(stat.S_IFREG, 0o555, inode=2)
    monkeypatch.setattr(HOST_RUNTIME.os, "fstat", lambda _: changed)
    with pytest.raises(HOST_RUNTIME.HostRuntimeError, match="changed"):
        HOST_RUNTIME.require_unchanged(7, expected, "runtime")


def test_host_runtime_rejects_missing_or_root_runtime_user(monkeypatch) -> None:
    def missing(_: str):
        raise KeyError

    monkeypatch.setattr(HOST_RUNTIME.pwd, "getpwnam", missing)
    with pytest.raises(HOST_RUNTIME.HostRuntimeError, match="unavailable"):
        HOST_RUNTIME.run_as(
            setpriv_descriptor=5,
            binary_descriptor=6,
            arguments=["--version"],
            user="missing",
            label="runtime",
        )
    monkeypatch.setattr(
        HOST_RUNTIME.pwd,
        "getpwnam",
        lambda _: SimpleNamespace(pw_uid=0, pw_gid=0),
    )
    with pytest.raises(HOST_RUNTIME.HostRuntimeError, match="unprivileged"):
        HOST_RUNTIME.run_as(
            setpriv_descriptor=5,
            binary_descriptor=6,
            arguments=["--version"],
            user="root",
            label="runtime",
        )


def valid_python_metadata() -> dict:
    return {
        "cache_tag": "cpython-312",
        "implementation": "CPython",
        "libc_family": "glibc",
        "libc_version": "2.39",
        "major_minor": "3.12",
        "observed_version": "3.12.3",
        "py_debug": False,
        "soabi": "cpython-312-x86_64-linux-gnu",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("soabi", "cpython-312d-x86_64-linux-gnu"),
        ("py_debug", True),
        ("libc_version", "2.38"),
    ],
)
def test_host_runtime_rejects_divergent_python_metadata(
    field: str,
    value,
) -> None:
    HOST_RUNTIME.validate_python_metadata(
        valid_python_metadata(),
        RUNTIME.EXPECTED_POLICY,
    )
    divergent = valid_python_metadata()
    divergent[field] = value
    with pytest.raises(HOST_RUNTIME.HostRuntimeError, match="cp312 ABI"):
        HOST_RUNTIME.validate_python_metadata(
            divergent,
            RUNTIME.EXPECTED_POLICY,
        )


def test_host_runtime_checks_python_as_all_six_users(monkeypatch) -> None:
    info = fake_stat(stat.S_IFREG, 0o755, inode=1)
    users: list[str] = []
    monkeypatch.setattr(
        HOST_RUNTIME,
        "open_verified",
        lambda *args, **kwargs: (9, info),
    )
    monkeypatch.setattr(
        HOST_RUNTIME,
        "digest_binary",
        lambda *args, **kwargs: "f" * 64,
    )
    monkeypatch.setattr(
        HOST_RUNTIME,
        "require_unchanged",
        lambda *args, **kwargs: None,
    )

    def observed(**kwargs):
        users.append(kwargs["user"])
        return json.dumps(
            valid_python_metadata(),
            separators=(",", ":"),
            sort_keys=True,
        )

    monkeypatch.setattr(HOST_RUNTIME, "run_as", observed)
    monkeypatch.setattr(HOST_RUNTIME.os, "close", lambda _: None)
    report, _ = HOST_RUNTIME.attest_python(
        RUNTIME.EXPECTED_POLICY,
        setpriv_descriptor=8,
    )
    assert users == RUNTIME.EXPECTED_POLICY["python"]["runtime_users"]
    assert report["runtime_users_verified"] == users
    assert len(users) == 6


def test_host_runtime_rejects_wrong_node_hash(monkeypatch) -> None:
    info = fake_stat(stat.S_IFREG, 0o555, inode=1)
    info.st_size = RUNTIME.EXPECTED_POLICY["node"]["binary_size_bytes"]
    monkeypatch.setattr(
        HOST_RUNTIME,
        "open_verified",
        lambda *args, **kwargs: (9, info),
    )
    monkeypatch.setattr(
        HOST_RUNTIME,
        "digest_binary",
        lambda *args, **kwargs: "0" * 64,
    )
    monkeypatch.setattr(HOST_RUNTIME.os, "close", lambda _: None)
    with pytest.raises(HOST_RUNTIME.HostRuntimeError, match="digest"):
        HOST_RUNTIME.attest_node(
            RUNTIME.EXPECTED_POLICY,
            setpriv_descriptor=8,
        )


def test_host_runtime_rejects_wrong_node_version(monkeypatch) -> None:
    info = fake_stat(stat.S_IFREG, 0o555, inode=1)
    info.st_size = RUNTIME.EXPECTED_POLICY["node"]["binary_size_bytes"]
    monkeypatch.setattr(
        HOST_RUNTIME,
        "open_verified",
        lambda *args, **kwargs: (9, info),
    )
    monkeypatch.setattr(
        HOST_RUNTIME,
        "digest_binary",
        lambda *args, **kwargs: RUNTIME.EXPECTED_POLICY["node"][
            "binary_sha256"
        ],
    )
    monkeypatch.setattr(
        HOST_RUNTIME,
        "run_as",
        lambda **kwargs: "v20.20.2",
    )
    monkeypatch.setattr(
        HOST_RUNTIME,
        "require_unchanged",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(HOST_RUNTIME.os, "close", lambda _: None)
    with pytest.raises(HOST_RUNTIME.HostRuntimeError, match="version"):
        HOST_RUNTIME.attest_node(
            RUNTIME.EXPECTED_POLICY,
            setpriv_descriptor=8,
        )


def test_host_runtime_output_is_exclusive(tmp_path: Path) -> None:
    output = tmp_path / "host-runtime.json"
    output.write_bytes(b"existing\n")
    with pytest.raises(HOST_RUNTIME.HostRuntimeError, match="already exists"):
        HOST_RUNTIME.write_exclusive(output, b"replacement\n")
    assert output.read_bytes() == b"existing\n"


def host_runtime_report() -> dict:
    policy = RUNTIME.EXPECTED_POLICY
    return {
        "distribution": policy["distribution"],
        "libc": {
            "family": "glibc",
            "minimum_version": "2.39",
            "observed_version": "2.39",
        },
        "node": {
            "binary_sha256": policy["node"]["binary_sha256"],
            "executable": policy["node"]["executable"],
            "runtime_user_verified": policy["node"]["runtime_user"],
            "version": policy["node"]["version"],
        },
        "python": {
            "binary_sha256": "f" * 64,
            "cache_tag": policy["python"]["cache_tag"],
            "executable": policy["python"]["executable"],
            "implementation": policy["python"]["implementation"],
            "major_minor": policy["python"]["major_minor"],
            "observed_version": "3.12.3",
            "py_debug": policy["python"]["py_debug"],
            "runtime_users_verified": policy["python"]["runtime_users"],
            "soabi": policy["python"]["soabi"],
        },
        "root_validation": policy["root_validation"],
        "runtime_policy_sha256": RUNTIME.EXPECTED_POLICY_SHA256,
        "schema_version": 1,
        "verdict": "pass",
    }


def test_host_runtime_report_has_normative_exact_schema() -> None:
    value = host_runtime_report()
    HOST_RUNTIME.validate_report(
        value,
        policy=RUNTIME.EXPECTED_POLICY,
        policy_digest=RUNTIME.EXPECTED_POLICY_SHA256,
    )
    encoded = HOST_RUNTIME.canonical_bytes(value)
    assert encoded.endswith(b"\n")
    assert json.loads(encoded) == value
    wrong_distribution = host_runtime_report()
    wrong_distribution["distribution"] = {
        **wrong_distribution["distribution"],
        "version_id": "22.04",
    }
    with pytest.raises(HOST_RUNTIME.HostRuntimeError, match="top-level"):
        HOST_RUNTIME.validate_report(
            wrong_distribution,
            policy=RUNTIME.EXPECTED_POLICY,
            policy_digest=RUNTIME.EXPECTED_POLICY_SHA256,
        )
    del value["python"]["runtime_users_verified"]
    with pytest.raises(HOST_RUNTIME.HostRuntimeError, match="Python"):
        HOST_RUNTIME.validate_report(
            value,
            policy=RUNTIME.EXPECTED_POLICY,
            policy_digest=RUNTIME.EXPECTED_POLICY_SHA256,
        )


def test_runtime_policy_loader_supports_stage_and_installed_modes(
    tmp_path: Path,
) -> None:
    raw = (ROOT / "policies" / "control-runtime-v1.json").read_bytes()
    for mode in (0o400, 0o444, 0o600, 0o644):
        path = tmp_path / f"policy-{mode:o}.json"
        path.write_bytes(raw)
        path.chmod(mode)
        _, digest = RUNTIME.load(path)
        assert digest == RUNTIME.EXPECTED_POLICY_SHA256


@pytest.mark.parametrize("loader_kind", ("runtime-policy", "manifest"))
def test_runtime_policy_and_manifest_loaders_reject_snapshot_change(
    tmp_path: Path,
    monkeypatch,
    loader_kind: str,
) -> None:
    if loader_kind == "runtime-policy":
        module = RUNTIME
        path = tmp_path / "runtime-policy.json"
        path.write_bytes(
            (ROOT / "policies" / "control-runtime-v1.json").read_bytes()
        )
        error = RUNTIME.RuntimePolicyError
        call = lambda: RUNTIME.load(path)
    else:
        module = COMPONENT
        path = tmp_path / "component-manifest.json"
        path.write_bytes(b"{}\n")
        error = COMPONENT.ComponentManifestError
        call = lambda: COMPONENT.load(path, "component manifest")
    path.chmod(0o400)
    real_fstat = module.os.fstat
    calls = 0

    def changed_fstat(descriptor: int):
        nonlocal calls
        info = real_fstat(descriptor)
        calls += 1
        if calls == 2:
            values = {
                name: getattr(info, name)
                for name in (
                    "st_ctime_ns",
                    "st_dev",
                    "st_gid",
                    "st_ino",
                    "st_mode",
                    "st_mtime_ns",
                    "st_nlink",
                    "st_size",
                    "st_uid",
                )
            }
            values["st_ctime_ns"] = info.st_ctime_ns + 1
            return SimpleNamespace(**values)
        return info

    monkeypatch.setattr(module.os, "fstat", changed_fstat)
    with pytest.raises(error, match="changed while being read"):
        call()


def test_host_runtime_policy_metadata_is_strict() -> None:
    info = fake_stat(stat.S_IFREG, 0o644, inode=1)
    with pytest.raises(RUNTIME.RuntimePolicyError, match="owned"):
        RUNTIME.validate_file_metadata(
            info,
            required_uid=0,
            required_gid=0,
            allowed_modes={0o444},
        )
    wrong_group = fake_stat(stat.S_IFREG, 0o444, inode=1)
    wrong_group.st_gid = 123
    with pytest.raises(RUNTIME.RuntimePolicyError, match="owned"):
        RUNTIME.validate_file_metadata(
            wrong_group,
            required_uid=0,
            required_gid=0,
            allowed_modes={0o444},
        )


def test_component_manifest_v4_rejects_host_patch_as_build_version() -> None:
    approval = approval_value()
    runtime_digest = RUNTIME.EXPECTED_POLICY_SHA256
    common = {
        "approval_manifest_sha256": hashlib.sha256(
            APPROVAL.canonical_bytes(approval)
        ).hexdigest(),
        "migration": approval["migration"],
        "runtime_policy": RUNTIME.reference(runtime_digest),
        "schema_version": 4,
    }
    manifests = {
        "api": {
            **common,
            "artifact_kind": "tratto-control-api",
            "build": {
                "arch": "x86_64",
                "os": "Linux",
                "python": "3.12.13",
                "requirements_lock_sha256": "d" * 64,
            },
            "release_sha": approval["api"]["commit_sha"],
        },
        "ops": {
            **common,
            "artifact_kind": "tratto-control-ops",
            "build": {
                "arch": "x86_64",
                "os": "Linux",
                "python": "3.12.13",
                "shell": "bash",
                "tree_digest_algorithm": "tratto-tree-v1",
            },
            "release_sha": approval["ops"]["commit_sha"],
        },
        "web": {
            **common,
            "artifact_kind": "tratto-control-web",
            "build": {
                "arch": "x86_64",
                "node": "v22.22.0",
                "os": "Linux",
            },
            "public_build": {
                "NEXT_PUBLIC_API_URL": "/api",
                "NEXT_PUBLIC_APP_SURFACE": "control",
            },
            "release_sha": approval["web"]["commit_sha"],
        },
    }
    COMPONENT.validate_set(
        manifests,
        api_sha=approval["api"]["commit_sha"],
        web_sha=approval["web"]["commit_sha"],
        approval_manifest_sha256=common["approval_manifest_sha256"],
        migration=approval["migration"],
        runtime_policy_digest=runtime_digest,
        requirements_lock_sha256="d" * 64,
    )
    manifests["ops"]["build"]["python"] = "3.12.3"
    with pytest.raises(
        COMPONENT.ComponentManifestError,
        match="Ops build/runtime",
    ):
        COMPONENT.validate_set(
            manifests,
            api_sha=approval["api"]["commit_sha"],
            web_sha=approval["web"]["commit_sha"],
            approval_manifest_sha256=common["approval_manifest_sha256"],
            migration=approval["migration"],
            runtime_policy_digest=runtime_digest,
            requirements_lock_sha256="d" * 64,
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
    monkeypatch,
    capsys,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    git(source, "init", "-b", "main")
    git(source, "config", "user.name", "Release Test")
    git(source, "config", "user.email", "release@example.invalid")
    for relative in sorted(TREE.REQUIRED_FILES):
        path = source / "ops" / "control" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative == "release-root/policies/control-runtime-v1.json":
            path.write_bytes(
                (ROOT / "policies" / "control-runtime-v1.json").read_bytes()
            )
        else:
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
    monkeypatch.setattr(OPS_BUILDER.platform, "system", lambda: "Linux")
    monkeypatch.setattr(OPS_BUILDER.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(
        OPS_BUILDER.platform,
        "python_implementation",
        lambda: "CPython",
    )
    monkeypatch.setattr(
        OPS_BUILDER.platform,
        "python_version",
        lambda: "3.12.13",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "build-ops-artifact.py",
            "--repository-root",
            str(source),
            "--approval",
            str(approval_path),
            "--runtime-policy",
            str(ROOT / "policies" / "control-runtime-v1.json"),
            "--release-sha",
            release_sha,
            "--output",
            str(archive),
        ],
    )
    assert OPS_BUILDER.main() == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["python"] == "3.12.13"
    assert (
        summary["runtime_policy_sha256"]
        == RUNTIME.EXPECTED_POLICY_SHA256
    )
    validate = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "validate-ops-artifact.py"),
            "--archive",
            str(archive),
            "--approval",
            str(approval_path),
            "--runtime-policy",
            str(ROOT / "policies" / "control-runtime-v1.json"),
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
        manifest_member = handle.getmember("artifact-manifest.json")
        manifest_handle = handle.extractfile(manifest_member)
        assert manifest_handle is not None
        manifest = json.loads(manifest_handle.read())
    assert manifest["schema_version"] == 4
    assert manifest["runtime_policy"] == RUNTIME.reference(
        RUNTIME.EXPECTED_POLICY_SHA256
    )
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


def test_ops_builder_process_rejects_unreviewed_host_platform(
    tmp_path: Path,
) -> None:
    if (
        platform.system() == RUNTIME.EXPECTED_POLICY["operating_system"]
        and platform.machine() == RUNTIME.EXPECTED_POLICY["architecture"]
        and platform.python_implementation()
        == RUNTIME.EXPECTED_POLICY["python"]["implementation"]
        and platform.python_version()
        == RUNTIME.EXPECTED_POLICY["python"]["build_version"]
    ):
        pytest.skip("current process is the reviewed Ops builder platform")
    release_sha = "1" * 40
    approval_path = tmp_path / "approval.json"
    approval_path.write_bytes(
        APPROVAL.canonical_bytes(approval_value(release_sha))
    )
    source = tmp_path / "source"
    source.mkdir()
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "build-ops-artifact.py"),
            "--repository-root",
            str(source),
            "--approval",
            str(approval_path),
            "--runtime-policy",
            str(ROOT / "policies" / "control-runtime-v1.json"),
            "--release-sha",
            release_sha,
            "--output",
            str(
                tmp_path
                / f"tratto-control-ops-{release_sha}.tar.gz"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 78
    assert "builder host/runtime" in result.stderr


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
