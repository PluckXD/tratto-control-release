from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "product-source-contract.py"
SPEC = importlib.util.spec_from_file_location(
    "control_product_source_contract",
    SCRIPT,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o440)


def _contract(files: dict[str, bytes]) -> bytes:
    value = {
        "artifact_kind": "api",
        "contract": "tratto-product-source-exact-bytes",
        "files": {
            path: hashlib.sha256(payload).hexdigest()
            for path, payload in sorted(
                files.items(), key=lambda item: item[0].encode("utf-8")
            )
        },
        "migration_head": "f42customerlink",
        "schema_version": 1,
    }
    return MODULE.canonical_bytes(value)


def test_exact_contract_binds_checkout_and_runtime_bytes(tmp_path: Path) -> None:
    files = {
        "alembic/versions/f42.py": b"revision = 'f42customerlink'\n",
        "app/services/pagamento.py": b"def reconcile():\n    return 'safe'\n",
    }
    repository = tmp_path / "repository"
    bundle = tmp_path / "bundle"
    repository.mkdir()
    bundle.mkdir()
    for relative, payload in files.items():
        _write(repository / relative, payload)
        _write(bundle / relative, payload)
    contract_path = tmp_path / "contract.json"
    contract_path.write_bytes(_contract(files))
    contract_path.chmod(0o440)

    contract, digest = MODULE.load(contract_path)
    observed = MODULE.verify(
        contract,
        repository_root=repository,
        bundle_root=bundle,
        expected_migration_head="f42customerlink",
    )

    assert digest == hashlib.sha256(contract_path.read_bytes()).hexdigest()
    assert observed == contract["files"]


def test_needles_cannot_fake_reviewed_behavior(tmp_path: Path) -> None:
    relative = "app/services/pagamento.py"
    reviewed = b"def reconcile():\n    return 'safe'\n"
    fake = (
        b"# def reconcile():\n"
        b"# return 'safe'\n"
        b"def reconcile():\n    return 'unsafe-post'\n"
    )
    repository = tmp_path / "repository"
    bundle = tmp_path / "bundle"
    repository.mkdir()
    bundle.mkdir()
    _write(repository / relative, fake)
    _write(bundle / relative, fake)
    contract = MODULE.parse(_contract({relative: reviewed}))

    with pytest.raises(
        MODULE.ProductSourceContractError,
        match="security-critical source diverges",
    ):
        MODULE.verify(
            contract,
            repository_root=repository,
            bundle_root=bundle,
            expected_migration_head="f42customerlink",
        )


@pytest.mark.parametrize(
    "mutator",
    [
        lambda raw: raw.rstrip(b"\n"),
        lambda raw: raw.replace(b'"schema_version":1', b'"schema_version":2'),
        lambda raw: raw.replace(
            b'"migration_head":"f42customerlink"',
            b'"migration_head":"../f42"',
        ),
        lambda raw: raw.replace(
            b'"app/source.py"', b'"../app/source.py"'
        ),
    ],
)
def test_contract_shape_is_fail_closed(mutator) -> None:
    raw = _contract({"app/source.py": b"safe\n"})
    with pytest.raises(MODULE.ProductSourceContractError):
        MODULE.parse(mutator(raw))


def test_duplicate_json_keys_are_rejected() -> None:
    raw = _contract({"app/source.py": b"safe\n"})
    value = json.loads(raw)
    malformed = (
        b'{"artifact_kind":"api","artifact_kind":"api",'
        + MODULE.canonical_bytes(
            {key: item for key, item in value.items() if key != "artifact_kind"}
        )[1:]
    )
    with pytest.raises(
        MODULE.ProductSourceContractError,
        match="duplicate key",
    ):
        MODULE.parse(malformed)


def test_runtime_copy_must_match_reviewed_checkout(tmp_path: Path) -> None:
    relative = "app/source.py"
    reviewed = b"safe\n"
    repository = tmp_path / "repository"
    bundle = tmp_path / "bundle"
    repository.mkdir()
    bundle.mkdir()
    _write(repository / relative, reviewed)
    _write(bundle / relative, b"changed\n")
    contract = MODULE.parse(_contract({relative: reviewed}))

    with pytest.raises(
        MODULE.ProductSourceContractError,
        match="security-critical source diverges",
    ):
        MODULE.verify(
            contract,
            repository_root=repository,
            bundle_root=bundle,
            expected_migration_head="f42customerlink",
        )
