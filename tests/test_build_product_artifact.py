from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build-product-artifact.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location(
    "control_build_product_artifact",
    SCRIPT,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def write(path: Path, payload: bytes = b"x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def api_tree(root: Path) -> None:
    directories = ("app", "alembic", "scripts", "runtime")
    for name in directories:
        (root / name).mkdir(parents=True, exist_ok=True)
    files = MODULE.API_REQUIRED - set(directories)
    for name in files:
        write(root / name)


def web_tree(root: Path) -> None:
    (root / ".next").mkdir(parents=True)
    (root / "node_modules").mkdir()
    write(root / "package.json", b"{}\n")
    write(root / "server.js", b"'use strict';\n")


def test_api_tree_is_bounded_and_digest_is_deterministic(
    tmp_path: Path,
) -> None:
    root = tmp_path / "api"
    root.mkdir()
    api_tree(root)

    first, first_digest = MODULE.scan_tree(root, kind="api")
    second, second_digest = MODULE.scan_tree(root, kind="api")

    assert first == second
    assert first_digest == second_digest
    assert len(first_digest) == 64
    assert first_digest == hashlib.sha256(
        (
            b"TRATTO-CONTROL-PRODUCT-TREE-V1\0"
            + b"".join(
                MODULE.tree_record(
                    path=path,
                    kind=kind,
                    mode=mode,
                    payload_hash=(
                        hashlib.sha256(payload or b"").hexdigest()
                        if kind != "symlink"
                        else hashlib.sha256(target.encode()).hexdigest()
                    ),
                    target=target,
                )
                for path, kind, mode, payload, target in first
            )
        )
    ).hexdigest()


def test_web_cache_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "web"
    root.mkdir()
    web_tree(root)
    (root / ".next" / "cache").mkdir()

    with pytest.raises(
        MODULE.ProductArtifactError,
        match="cache",
    ):
        MODULE.scan_tree(root, kind="web")


def test_escaping_symlink_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "web"
    root.mkdir()
    web_tree(root)
    os.symlink("../../outside", root / "node_modules" / "escape")

    with pytest.raises(
        MODULE.ProductArtifactError,
        match="escaping symlink",
    ):
        MODULE.scan_tree(root, kind="web")


@pytest.mark.parametrize(
    "name",
    [
        ".env",
        ".env.production",
        "id_ed25519",
        "tenant.key",
        "certificate.p12",
    ],
)
def test_secret_bearing_names_are_rejected(
    tmp_path: Path,
    name: str,
) -> None:
    root = tmp_path / "api"
    root.mkdir()
    api_tree(root)
    write(root / "runtime" / name, b"not-a-secret")

    with pytest.raises(
        MODULE.ProductArtifactError,
        match="secret-bearing",
    ):
        MODULE.scan_tree(root, kind="api")


def test_private_key_pem_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "api"
    root.mkdir()
    api_tree(root)
    write(
        root / "runtime" / "certificate.pem",
        b"-----BEGIN PRIVATE KEY-----\n",
    )

    with pytest.raises(
        MODULE.ProductArtifactError,
        match="private key material",
    ):
        MODULE.scan_tree(root, kind="api")


def test_missing_runtime_contract_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "api"
    root.mkdir()
    api_tree(root)
    (root / "app" / "core" / "control_runtime_db.py").unlink()

    with pytest.raises(
        MODULE.ProductArtifactError,
        match="incomplete",
    ):
        MODULE.scan_tree(root, kind="api")


def test_archive_is_exclusive_and_contains_canonical_markers(
    tmp_path: Path,
) -> None:
    root = tmp_path / "web"
    root.mkdir()
    web_tree(root)
    entries, _ = MODULE.scan_tree(root, kind="web")
    output = tmp_path / "artifact.tar.gz"
    manifest = MODULE.canonical_bytes({"schema_version": 4})

    digest, size = MODULE.write_archive(
        output,
        entries=entries,
        release_sha="1" * 40,
        manifest_raw=manifest,
    )

    assert output.stat().st_mode & 0o777 == 0o600
    assert digest == hashlib.sha256(output.read_bytes()).hexdigest()
    assert size == output.stat().st_size
    with pytest.raises(FileExistsError):
        MODULE.write_archive(
            output,
            entries=entries,
            release_sha="1" * 40,
            manifest_raw=manifest,
        )


def test_product_builder_rejects_expired_approval(
    tmp_path: Path,
) -> None:
    value = json.loads(
        (ROOT / "examples" / "approval.example.json").read_text()
    )
    issued_at = dt.datetime.now(dt.timezone.utc).replace(
        microsecond=0
    ) - dt.timedelta(days=2)
    expires_at = issued_at + dt.timedelta(hours=1)
    value["release_id"] = (
        f"ctl-{issued_at.strftime('%Y%m%dT%H%M%SZ')}-bootstrap"
    )
    value["issued_at"] = issued_at.isoformat().replace("+00:00", "Z")
    value["expires_at"] = expires_at.isoformat().replace("+00:00", "Z")
    value["api"]["commit_sha"] = "1" * 40
    approval_path = tmp_path / "approval.json"
    approval_path.write_bytes(MODULE.canonical_bytes(value))

    with pytest.raises(
        MODULE.ProductArtifactError,
        match="expired",
    ):
        MODULE.load_approval(
            approval_path,
            kind="api",
            release_sha="1" * 40,
        )
