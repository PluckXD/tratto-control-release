from __future__ import annotations

import gzip
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "install-bootstrap-source-kit.py"
README = ROOT / "README.md"
SPEC = importlib.util.spec_from_file_location(
    "bootstrap_source_kit_under_test",
    SCRIPT,
)
assert SPEC is not None and SPEC.loader is not None
KIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = KIT
SPEC.loader.exec_module(KIT)


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


def tar_info(
    name: str,
    *,
    mode: int,
    kind: bytes,
    size: int = 0,
) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.mode = mode
    info.type = kind
    info.size = size
    return info


def build_archive(
    path: Path,
    api_sha: str,
    *,
    extra: tuple[str, bytes, int] | None = None,
    link: bool = False,
    omit: str | None = None,
    quiescence_kind: bytes = tarfile.REGTYPE,
    quiescence_mode: int = 0o555,
) -> None:
    approval = {
        "api": {"commit_sha": api_sha},
        "controller": {"base_sha": "c" * 40},
        "ops": {"commit_sha": api_sha},
    }
    manifest = canonical(
        {
            "approval_manifest_sha256": hashlib.sha256(
                canonical(approval)
            ).hexdigest(),
            "artifact_kind": "tratto-control-ops",
            "build": {
                "arch": "x86_64",
                "os": "Linux",
                "python": "3.12.13",
                "shell": "bash",
                "tree_digest_algorithm": "tratto-tree-v1",
            },
            "migration": {},
            "release_sha": api_sha,
            "runtime_policy": {
                "name": "control-runtime-v1",
                "sha256": "9" * 64,
            },
            "schema_version": 4,
        }
    )
    files = {
        "RELEASE_SHA": (f"{api_sha}\n".encode(), 0o444),
        "artifact-manifest.json": (manifest, 0o444),
        "scripts/provision-node-runtime.py": (b"provision\n", 0o555),
        "scripts/publish-bootstrap-tree.py": (b"publisher\n", 0o555),
        "scripts/verify-control-stack-quiescent.py": (
            b"quiescence\n",
            quiescence_mode,
        ),
        "scripts/with-deploy-lock.py": (b"lock\n", 0o555),
    }
    if extra is not None:
        files[extra[0]] = (extra[1], extra[2])
    if omit is not None:
        files.pop(omit)
    with path.open("wb") as raw:
        with gzip.GzipFile(
            filename="",
            fileobj=raw,
            mode="wb",
            mtime=0,
        ) as compressed:
            with tarfile.open(
                fileobj=compressed,
                mode="w",
                format=tarfile.USTAR_FORMAT,
            ) as archive:
                archive.addfile(
                    tar_info(
                        "scripts",
                        mode=0o555,
                        kind=tarfile.DIRTYPE,
                    )
                )
                for name in ("RELEASE_SHA", "artifact-manifest.json"):
                    payload, mode = files.pop(name)
                    archive.addfile(
                        tar_info(
                            name,
                            mode=mode,
                            kind=tarfile.REGTYPE,
                            size=len(payload),
                        ),
                        io.BytesIO(payload),
                    )
                for name in sorted(files):
                    payload, mode = files[name]
                    special_kind = (
                        quiescence_kind
                        if name
                        == "scripts/verify-control-stack-quiescent.py"
                        else tarfile.REGTYPE
                    )
                    if (
                        (link and name == "scripts/with-deploy-lock.py")
                        or special_kind == tarfile.SYMTYPE
                    ):
                        info = tar_info(
                            name,
                            mode=mode,
                            kind=tarfile.SYMTYPE,
                        )
                        info.linkname = "publish-bootstrap-tree.py"
                        archive.addfile(info)
                    else:
                        archive.addfile(
                            tar_info(
                                name,
                                mode=mode,
                                kind=tarfile.REGTYPE,
                                size=len(payload),
                            ),
                            io.BytesIO(payload),
                        )


def attestation(
    *,
    api_sha: str,
    carrier_sha: str,
    controller_sha: str,
    archive_hash: str,
    archive_size: int,
    helper_hash: str,
    helper_size: int,
) -> bytes:
    approval = {
        "api": {"commit_sha": api_sha},
        "controller": {"base_sha": controller_sha},
        "ops": {"commit_sha": api_sha},
    }
    def artifact(
        *,
        kind: str,
        commit_sha: str,
        repository: str,
        artifact_hash: str = "1" * 64,
        size_bytes: int = 123,
    ) -> dict:
        return {
            "ancestor_verified": True,
            "approved_ref": "refs/heads/main",
            "artifact_id": {
                "api": 11,
                "ops": 12,
                "web": 13,
            }[kind],
            "artifact_name": (
                f"tratto-control-{kind}-{commit_sha}.tar.gz"
            ),
            "build_job": f"build_{kind}",
            "carrier_repository": (
                "PluckXD/tratto-control-release-carrier"
            ),
            "commit_sha": commit_sha,
            "component_manifest_sha256": "2" * 64,
            "repository": repository,
            "runner_arch": "X64",
            "runner_environment": "github-hosted",
            "runner_os": "Linux",
            "service_digest": "3" * 64,
            "sha256": artifact_hash,
            "size_bytes": size_bytes,
            "tree_sha": "4" * 40,
        }

    value = {
        "approval": {
            "manifest": approval,
            "manifest_sha256": hashlib.sha256(
                canonical(approval)
            ).hexdigest(),
            "mode": "single-operator-bootstrap",
        },
        "artifacts": {
            "api": artifact(
                kind="api",
                commit_sha=api_sha,
                repository="PluckXD/tratto-api",
            ),
            "ops": artifact(
                kind="ops",
                commit_sha=api_sha,
                repository="PluckXD/tratto-api",
                artifact_hash=archive_hash,
                size_bytes=archive_size,
            ),
            "web": artifact(
                kind="web",
                commit_sha="f" * 40,
                repository="PluckXD/tratto-web",
            ),
        },
        "behavioral_verification": {},
        "bootstrap_source_helper": {
            "controller_sha": controller_sha,
            "name": KIT.HELPER_NAME,
            "sha256": helper_hash,
            "size_bytes": helper_size,
        },
        "carrier": {
            "authorizes_release": False,
            "repository": (
                "PluckXD/tratto-control-release-carrier"
            ),
            "trust": "transport-only",
        },
        "controller": {
            "commit_sha": carrier_sha,
            "event_name": "workflow_dispatch",
            "repository": (
                "PluckXD/tratto-control-release-carrier"
            ),
            "run_attempt": 1,
            "run_id": 42,
            "runner_arch": "X64",
            "runner_environment": "github-hosted",
            "runner_os": "Linux",
            "source_ref": "refs/heads/main",
            "verifier_sha256": "d" * 64,
            "workflow": (
                ".github/workflows/control-bootstrap-v1.yml"
            ),
            "workflow_ref": (
                "PluckXD/tratto-control-release-carrier/"
                ".github/workflows/control-bootstrap-v1.yml@"
                "refs/heads/main"
            ),
        },
        "migration": {},
        "schema_version": 6,
        "supplemental_inventory": {"supplemental_only": True},
    }
    return canonical(value)


def chmod_tree(root: Path) -> None:
    for path in sorted(
        root.rglob("*"),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        path.chmod(0o555 if path.is_dir() or path.suffix == ".py" else 0o444)
    root.chmod(0o555)


def fake_runtime() -> object:
    def noreplace(
        old_parent: int,
        old_name: str,
        new_parent: int,
        new_name: str,
    ) -> None:
        try:
            os.stat(new_name, dir_fd=new_parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(new_name)
        os.rename(
            old_name,
            new_name,
            src_dir_fd=old_parent,
            dst_dir_fd=new_parent,
        )

    def exchange(
        old_parent: int,
        old_name: str,
        new_parent: int,
        new_name: str,
    ) -> None:
        temporary = ".test.exchange"
        os.rename(
            old_name,
            temporary,
            src_dir_fd=old_parent,
            dst_dir_fd=old_parent,
        )
        os.rename(
            new_name,
            old_name,
            src_dir_fd=new_parent,
            dst_dir_fd=old_parent,
        )
        os.rename(
            temporary,
            new_name,
            src_dir_fd=old_parent,
            dst_dir_fd=new_parent,
        )

    return KIT.Runtime(exchange=exchange, noreplace=noreplace)


@pytest.fixture
def secure_tmp_path() -> Iterator[Path]:
    anchor = ROOT / ".pytest-secure"
    anchor.mkdir(mode=0o700, exist_ok=True)
    if anchor.is_symlink() or not anchor.is_dir():
        raise AssertionError("secure test anchor is not a real directory")
    anchor.chmod(0o700)
    path = Path(tempfile.mkdtemp(prefix="source-kit-", dir=anchor))
    try:
        yield path
    finally:
        for directory, _children, _files in os.walk(
            path,
            topdown=True,
            followlinks=False,
        ):
            Path(directory).chmod(0o700)
        shutil.rmtree(path)
        try:
            anchor.rmdir()
        except OSError:
            pass


def fixture(tmp_path: Path) -> tuple[Path, Path, list[str]]:
    uid = os.getuid()
    gid = os.getgid()
    state = tmp_path / "state"
    incoming = state / "incoming"
    source = state / "bootstrap-source"
    state.mkdir(mode=0o755)
    incoming.mkdir(mode=0o700)
    source.mkdir(mode=0o700)
    (source / "old.txt").write_bytes(b"old source\n")
    (source / "old.txt").chmod(0o444)
    source.chmod(0o555)

    helper = SCRIPT.read_bytes()
    helper_path = incoming / KIT.HELPER_NAME
    helper_path.write_bytes(helper)
    api_sha = "a" * 40
    carrier_sha = "b" * 40
    controller_sha = "c" * 40
    archive_name = f"tratto-control-ops-{api_sha}.tar.gz"
    archive_path = incoming / archive_name
    build_archive(archive_path, api_sha)
    archive_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    (incoming / KIT.ATTESTATION_NAME).write_bytes(
        attestation(
            api_sha=api_sha,
            carrier_sha=carrier_sha,
            controller_sha=controller_sha,
            archive_hash=archive_hash,
            archive_size=archive_path.stat().st_size,
            helper_hash=hashlib.sha256(helper).hexdigest(),
            helper_size=len(helper),
        )
    )
    for name in (
        KIT.HELPER_BUNDLE_NAME,
        KIT.ATTESTATION_BUNDLE_NAME,
        KIT.OPS_BUNDLE_NAME,
    ):
        (incoming / name).write_bytes(b"sigstore bundle\n")
    for path in incoming.iterdir():
        path.chmod(0o400)
    incoming.chmod(0o700)
    state.chmod(0o755)
    calls: list[str] = []
    assert state.stat().st_uid == uid
    assert state.stat().st_gid == gid
    return incoming, state, calls


def expectations(incoming: Path) -> object:
    return KIT.BootstrapExpectations(
        helper_sha256=hashlib.sha256(
            (incoming / KIT.HELPER_NAME).read_bytes()
        ).hexdigest(),
        attestation_sha256=hashlib.sha256(
            (incoming / KIT.ATTESTATION_NAME).read_bytes()
        ).hexdigest(),
        carrier_sha="b" * 40,
        controller_sha="c" * 40,
    )


def install(
    incoming: Path,
    state: Path,
    calls: list[str],
    *,
    fault=lambda _event: None,
) -> str:
    def verifier(
        _cosign: int,
        _target: int,
        _bundle: int,
        carrier_sha: str,
    ) -> None:
        assert carrier_sha == "b" * 40
        calls.append("signature")

    def publisher(_source: int, _lock: int) -> str:
        calls.append("publisher")
        return "upgraded"

    helper_path = incoming / KIT.HELPER_NAME
    execution_descriptor = os.open(helper_path, os.O_RDONLY)
    try:
        return KIT.install_source(
            incoming=incoming,
            state_root=state,
            uid=os.getuid(),
            gid=os.getgid(),
            execution_descriptor=execution_descriptor,
            expectations=expectations(incoming),
            runtime=fake_runtime(),
            signature_verifier=verifier,
            publisher=publisher,
            lock_descriptor=99,
            fault=fault,
        )
    finally:
        os.close(execution_descriptor)


def test_installs_signed_tree_retains_old_and_is_idempotent(
    secure_tmp_path: Path,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)

    assert install(incoming, state, calls) == "installed"
    assert calls == ["signature", "signature", "signature", "publisher"]
    assert (state / "bootstrap-source" / "RELEASE_SHA").read_text() == (
        "a" * 40 + "\n"
    )
    previous = list(state.glob("bootstrap-source.previous.*"))
    assert len(previous) == 1
    assert (previous[0] / "old.txt").read_text() == "old source\n"

    calls.clear()
    assert install(incoming, state, calls) == "already-installed"
    assert calls == ["signature", "signature", "signature"]


@pytest.mark.parametrize(
    "event",
    [
        "after_intent",
        "after_candidate",
        "after_exchange",
        "after_retention_rename",
        "after_publisher",
    ],
)
def test_recovers_each_persistent_crash_boundary(
    secure_tmp_path: Path,
    event: str,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    fired = False

    def fault(observed: str) -> None:
        nonlocal fired
        if not fired and observed == event:
            fired = True
            raise RuntimeError("simulated SIGKILL boundary")

    with pytest.raises(RuntimeError, match="simulated"):
        install(incoming, state, calls, fault=fault)
    calls.clear()
    assert install(incoming, state, calls) == "installed"
    assert (state / "bootstrap-source" / "RELEASE_SHA").is_file()
    assert len(list(state.glob("bootstrap-source.previous.*"))) == 1
    assert calls[-1] == "publisher"


@pytest.mark.parametrize("immutable_complete", [False, True])
def test_recovers_partial_candidate_and_partial_intent_record(
    secure_tmp_path: Path,
    immutable_complete: bool,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    binding = KIT.validate_attestation(
        (incoming / KIT.ATTESTATION_NAME).read_bytes(),
        helper_sha256=hashlib.sha256(
            (incoming / KIT.HELPER_NAME).read_bytes()
        ).hexdigest(),
        helper_size_bytes=(
            incoming / KIT.HELPER_NAME
        ).stat().st_size,
        expected_carrier_sha="b" * 40,
        expected_controller_sha="c" * 40,
    )
    archive = incoming / binding.ops_name
    descriptor = os.open(archive, os.O_RDONLY)
    try:
        inventory = KIT.validate_ops_archive(
            descriptor,
            os.fstat(descriptor),
            binding,
        )
    finally:
        os.close(descriptor)
    kit_id = KIT.kit_identity(binding, inventory)
    candidate = state / f"{KIT.CANDIDATE_PREFIX}{kit_id}"
    candidate.mkdir(mode=0o700)
    (candidate / "partial").write_bytes(b"part")
    (candidate / "partial").chmod(0o600)
    old_fd = os.open(state / "bootstrap-source", os.O_RDONLY)
    try:
        old_digest = KIT.tree_digest(
            KIT.scan_tree(
                old_fd,
                uid=os.getuid(),
                gid=os.getgid(),
            )
        )
    finally:
        os.close(old_fd)
    intent = KIT.intent_payload(
        binding,
        inventory,
        kit_id,
        old_digest,
    )
    partial = (
        state
        / f"bootstrap-source-kit.intent.{kit_id}.installing"
    )
    partial.write_bytes(intent if immutable_complete else intent[:31])
    partial.chmod(0o444 if immutable_complete else 0o600)

    assert install(incoming, state, calls) == "installed"
    assert not candidate.exists()
    assert (state / KIT.INTENT_NAME).read_bytes() == intent


def test_rejects_different_kit_after_intent(
    secure_tmp_path: Path,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)

    def stop(event: str) -> None:
        if event == "after_intent":
            raise RuntimeError("stop")

    with pytest.raises(RuntimeError):
        install(incoming, state, calls, fault=stop)
    helper = incoming / KIT.HELPER_NAME
    helper.chmod(0o600)
    helper.write_bytes(helper.read_bytes() + b"# different\n")
    helper.chmod(0o400)
    raw = json.loads((incoming / KIT.ATTESTATION_NAME).read_text())
    attestation_path = incoming / KIT.ATTESTATION_NAME
    attestation_path.chmod(0o600)
    attestation_path.write_bytes(canonical(raw))
    attestation_path.chmod(0o400)

    with pytest.raises(
        KIT.BootstrapSourceError,
        match="binding|diferente|outro",
    ):
        install(incoming, state, [])


def test_archive_rejects_links_before_any_mutation(
    secure_tmp_path: Path,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    archive = next(incoming.glob("tratto-control-ops-*.tar.gz"))
    archive.chmod(0o600)
    build_archive(archive, "a" * 40, link=True)
    archive.chmod(0o400)
    raw = json.loads((incoming / KIT.ATTESTATION_NAME).read_text())
    raw["artifacts"]["ops"]["sha256"] = hashlib.sha256(
        archive.read_bytes()
    ).hexdigest()
    raw["artifacts"]["ops"]["size_bytes"] = archive.stat().st_size
    attestation_path = incoming / KIT.ATTESTATION_NAME
    attestation_path.chmod(0o600)
    attestation_path.write_bytes(canonical(raw))
    attestation_path.chmod(0o400)

    with pytest.raises(KIT.BootstrapSourceError, match="proibido"):
        install(incoming, state, calls)
    assert not (state / KIT.INTENT_NAME).exists()


@pytest.mark.parametrize(
    ("tamper", "options", "message"),
    (
        (
            "missing",
            {
                "omit": (
                    "scripts/verify-control-stack-quiescent.py"
                )
            },
            "inventário bootstrap mínimo",
        ),
        (
            "type",
            {"quiescence_kind": tarfile.SYMTYPE},
            "tipo, modo ou tamanho proibido",
        ),
        (
            "mode",
            {"quiescence_mode": 0o444},
            "inventário bootstrap mínimo",
        ),
    ),
)
def test_archive_rejects_invalid_quiescence_helper_before_source_exchange(
    secure_tmp_path: Path,
    tamper: str,
    options: dict[str, object],
    message: str,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    archive = next(incoming.glob("tratto-control-ops-*.tar.gz"))
    archive.chmod(0o600)
    build_archive(archive, "a" * 40, **options)
    archive.chmod(0o400)
    raw = json.loads((incoming / KIT.ATTESTATION_NAME).read_text())
    raw["artifacts"]["ops"]["sha256"] = hashlib.sha256(
        archive.read_bytes()
    ).hexdigest()
    raw["artifacts"]["ops"]["size_bytes"] = archive.stat().st_size
    attestation_path = incoming / KIT.ATTESTATION_NAME
    attestation_path.chmod(0o600)
    attestation_path.write_bytes(canonical(raw))
    attestation_path.chmod(0o400)

    with pytest.raises(KIT.BootstrapSourceError, match=message):
        install(incoming, state, calls)
    assert (state / "bootstrap-source" / "old.txt").read_bytes() == (
        b"old source\n"
    )
    assert not (state / KIT.INTENT_NAME).exists(), tamper


@pytest.mark.parametrize("tamper", ["traversal", "concatenated-gzip"])
def test_archive_rejects_noncanonical_container_or_path(
    secure_tmp_path: Path,
    tamper: str,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    archive = next(incoming.glob("tratto-control-ops-*.tar.gz"))
    archive.chmod(0o600)
    if tamper == "traversal":
        build_archive(
            archive,
            "a" * 40,
            extra=("../escape", b"escape\n", 0o444),
        )
    else:
        with archive.open("ab") as output:
            output.write(gzip.compress(b"hidden\n", mtime=0))
    archive.chmod(0o400)
    raw = json.loads((incoming / KIT.ATTESTATION_NAME).read_text())
    raw["artifacts"]["ops"]["sha256"] = hashlib.sha256(
        archive.read_bytes()
    ).hexdigest()
    raw["artifacts"]["ops"]["size_bytes"] = archive.stat().st_size
    attestation_path = incoming / KIT.ATTESTATION_NAME
    attestation_path.chmod(0o600)
    attestation_path.write_bytes(canonical(raw))
    attestation_path.chmod(0o400)

    with pytest.raises(KIT.BootstrapSourceError):
        install(incoming, state, calls)
    assert not (state / KIT.INTENT_NAME).exists()


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("helper_sha256", "0" * 64, "helper"),
        ("attestation_sha256", "0" * 64, "attestation"),
        ("carrier_sha", "0" * 40, "carrier"),
        ("controller_sha", "0" * 40, "controller"),
    ],
)
def test_rejects_every_external_binding_before_signature_or_mutation(
    secure_tmp_path: Path,
    field: str,
    replacement: str,
    message: str,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    expected = expectations(incoming)
    values = {
        "helper_sha256": expected.helper_sha256,
        "attestation_sha256": expected.attestation_sha256,
        "carrier_sha": expected.carrier_sha,
        "controller_sha": expected.controller_sha,
    }
    values[field] = replacement
    execution = os.open(incoming / KIT.HELPER_NAME, os.O_RDONLY)
    try:
        with pytest.raises(KIT.BootstrapSourceError, match=message):
            KIT.open_and_validate_inputs(
                incoming,
                uid=os.getuid(),
                gid=os.getgid(),
                execution_descriptor=execution,
                expectations=KIT.BootstrapExpectations(**values),
                signature_verifier=lambda *_args: calls.append("signature"),
            )
    finally:
        os.close(execution)

    assert calls == []
    assert not (state / KIT.INTENT_NAME).exists()


def test_rejects_execution_fd_not_bound_to_fixed_helper(
    secure_tmp_path: Path,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    other = secure_tmp_path / "other-helper.py"
    other.write_bytes((incoming / KIT.HELPER_NAME).read_bytes())
    other.chmod(0o400)
    execution = os.open(other, os.O_RDONLY)
    try:
        with pytest.raises(
            KIT.BootstrapSourceError,
            match="helper fixo",
        ):
            KIT.open_and_validate_inputs(
                incoming,
                uid=os.getuid(),
                gid=os.getgid(),
                execution_descriptor=execution,
                expectations=expectations(incoming),
                signature_verifier=lambda *_args: calls.append("signature"),
            )
    finally:
        os.close(execution)

    assert calls == []
    assert not (state / KIT.INTENT_NAME).exists()


def test_rejects_writable_execution_fd(
    secure_tmp_path: Path,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    helper = incoming / KIT.HELPER_NAME
    helper.chmod(0o600)
    execution = os.open(helper, os.O_RDWR)
    helper.chmod(0o400)
    try:
        with pytest.raises(
            KIT.BootstrapSourceError,
            match="somente leitura",
        ):
            KIT.open_and_validate_inputs(
                incoming,
                uid=os.getuid(),
                gid=os.getgid(),
                execution_descriptor=execution,
                expectations=expectations(incoming),
                signature_verifier=lambda *_args: calls.append("signature"),
            )
    finally:
        os.close(execution)

    assert calls == []
    assert not (state / KIT.INTENT_NAME).exists()


def test_rejects_helper_block_size_drift_before_signature(
    secure_tmp_path: Path,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    attestation_path = incoming / KIT.ATTESTATION_NAME
    value = json.loads(attestation_path.read_text())
    value["bootstrap_source_helper"]["size_bytes"] += 1
    attestation_path.chmod(0o600)
    attestation_path.write_bytes(canonical(value))
    attestation_path.chmod(0o400)

    with pytest.raises(
        KIT.BootstrapSourceError,
        match="helper binding",
    ):
        install(incoming, state, calls)

    assert calls == []
    assert not (state / KIT.INTENT_NAME).exists()


@pytest.mark.parametrize("tamper", ["schema-5", "extra-helper-key"])
def test_rejects_legacy_or_non_exact_helper_envelope_before_signature(
    secure_tmp_path: Path,
    tamper: str,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    attestation_path = incoming / KIT.ATTESTATION_NAME
    value = json.loads(attestation_path.read_text())
    if tamper == "schema-5":
        value["schema_version"] = 5
    else:
        value["bootstrap_source_helper"]["schema_version"] = 1
    attestation_path.chmod(0o600)
    attestation_path.write_bytes(canonical(value))
    attestation_path.chmod(0o400)

    with pytest.raises(KIT.BootstrapSourceError):
        install(incoming, state, calls)

    assert calls == []
    assert not (state / KIT.INTENT_NAME).exists()


def test_cli_requires_fd_and_all_external_bindings() -> None:
    parsed = KIT.parse_cli(
        [
            "--helper-fd",
            "0",
            "--expected-helper-sha256",
            "1" * 64,
            "--expected-attestation-sha256",
            "2" * 64,
            "--expected-carrier-sha",
            "3" * 40,
            "--expected-controller-sha",
            "4" * 40,
        ]
    )

    assert parsed.helper_fd == 0
    with pytest.raises(KIT.BootstrapSourceError, match="CLI"):
        KIT.parse_cli(
            [
                "--helper-fd",
                "0",
                "--expected-helper-sha256",
                "1" * 64,
            ]
        )
    with pytest.raises(KIT.BootstrapSourceError, match="CLI"):
        KIT.parse_cli(
            [
                "--helper-fd",
                "0",
                "--expected-helper-sha256",
                "1" * 64,
                "--expected-attestation-sha256",
                "2" * 64,
                "--expected-carrier-sha",
                "3" * 40,
                "--expected-controller-sha",
                "4" * 40,
                "--unexpected",
                "value",
            ]
        )
    with pytest.raises(KIT.BootstrapSourceError, match="exatamente"):
        KIT.parse_cli(
            [
                "--helper-fd",
                "0",
                "--helper-fd",
                "1",
                "--expected-helper-sha256",
                "1" * 64,
                "--expected-attestation-sha256",
                "2" * 64,
                "--expected-carrier-sha",
                "3" * 40,
                "--expected-controller-sha",
                "4" * 40,
            ]
        )


def test_readme_verifies_same_helper_fd_before_lock_wrapper() -> None:
    text = README.read_text(encoding="utf-8")
    clean_environment = text.index("/usr/bin/env -i")
    clean_shell = text.index("/usr/bin/bash --noprofile --norc")
    opened = text.index('exec {helper_fd}<"$helper"')
    metadata = text.index(
        "/usr/bin/stat -Lc '%F:%a:%u:%g:%h' \"$helper_fd_path\""
    )
    signature = text.index("/usr/local/bin/cosign verify-blob")
    wrapper = text.index(
        "/opt/tratto-control/bootstrap/scripts/with-deploy-lock.py"
    )

    assert (
        clean_environment
        < clean_shell
        < opened
        < metadata
        < signature
        < wrapper
    )
    assert '"$helper_fd_path"' in text[signature:wrapper]
    before_signature = text[clean_environment:signature]
    for utility in (
        "/usr/bin/env",
        "/usr/bin/bash",
        "/usr/bin/test",
        "/usr/bin/stat",
        "/usr/bin/sha256sum",
        "/usr/bin/awk",
    ):
        assert utility in before_signature
    assert "PATH=/usr/bin:/bin" in before_signature
    assert "BASH_ENV" not in before_signature
    assert "/usr/bin/python3.12 -I -B /proc/self/fd/0" in text
    assert '--helper-fd 0' in text
    assert '<&"$helper_fd"' in text
    for option in (
        "--expected-helper-sha256",
        "--expected-attestation-sha256",
        "--expected-carrier-sha",
        "--expected-controller-sha",
    ):
        assert option in text[wrapper:]
    assert (
        "/usr/bin/python3.12 -I -B \\\n"
        "  /var/lib/tratto-control/incoming/"
        "install-bootstrap-source-kit.py"
    ) not in text


def test_execution_entrypoint_fails_closed_without_linux_procfs(
    tmp_path: Path,
) -> None:
    with pytest.raises(KIT.BootstrapSourceError, match="Linux"):
        KIT.validate_execution_entrypoint(
            0,
            script_path="/proc/self/fd/0",
            platform="darwin",
        )
    with pytest.raises(KIT.BootstrapSourceError, match="proc"):
        KIT.validate_execution_entrypoint(
            0,
            script_path=str(tmp_path / "missing" / "0"),
            platform="linux",
            proc_fd_root=tmp_path / "missing",
        )


@pytest.mark.skipif(
    sys.platform != "linux" or not Path("/proc/self/fd").is_dir(),
    reason="requires Linux procfs FD execution",
)
def test_wrapper_preserves_fd0_into_proc_entrypoint_and_main(
    tmp_path: Path,
) -> None:
    wrapper = tmp_path / "with-deploy-lock.py"
    wrapper.write_text(
        "import subprocess\n"
        "import sys\n"
        "raise SystemExit(\n"
        "    subprocess.run(sys.argv[1:], check=False).returncode\n"
        ")\n",
        encoding="utf-8",
    )
    probe = tmp_path / "install-bootstrap-source-kit.py"
    probe.write_text(
        "import importlib.util\n"
        "import os\n"
        "import sys\n"
        "from pathlib import Path\n"
        f"helper_path = {str(SCRIPT)!r}\n"
        "spec = importlib.util.spec_from_file_location(\n"
        "    'bootstrap_fd_main_harness', helper_path\n"
        ")\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "sys.modules[spec.name] = module\n"
        "spec.loader.exec_module(module)\n"
        "module.__file__ = __file__\n"
        "module.EXPECTED_UID = os.geteuid()\n"
        "module.EXPECTED_GID = os.getegid()\n"
        f"module.INCOMING = Path({str(probe.parent)!r})\n"
        f"module.HELPER_NAME = {probe.name!r}\n"
        f"module.STATE_ROOT = Path({str(probe.parent)!r})\n"
        "module.verify_inherited_lock = lambda **_kwargs: 91\n"
        "module.production_runtime = lambda: object()\n"
        "def install_source(**kwargs):\n"
        "    assert kwargs['execution_descriptor'] == 0\n"
        "    executed = os.fstat(0)\n"
        "    fixed = os.stat(\n"
        "        module.INCOMING / module.HELPER_NAME\n"
        "    )\n"
        "    assert (executed.st_dev, executed.st_ino) == (\n"
        "        fixed.st_dev, fixed.st_ino\n"
        "    )\n"
        "    assert kwargs['expectations'].carrier_sha == '3' * 40\n"
        "    return 'installed'\n"
        "module.install_source = install_source\n"
        "raise SystemExit(module.main())\n",
        encoding="utf-8",
    )
    probe.chmod(0o400)
    with probe.open("rb") as verified_helper:
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(wrapper),
                sys.executable,
                "-I",
                "-B",
                "/proc/self/fd/0",
                "--helper-fd",
                "0",
                "--expected-helper-sha256",
                "1" * 64,
                "--expected-attestation-sha256",
                "2" * 64,
                "--expected-carrier-sha",
                "3" * 40,
                "--expected-controller-sha",
                "4" * 40,
            ],
            stdin=verified_helper,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "installed\n"


def test_requires_the_inherited_inode_to_be_actually_locked(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_directory = secure_tmp_path / "run"
    lock_directory.mkdir(mode=0o700)
    lock_path = lock_directory / KIT.LOCK_NAME
    lock_path.write_bytes(b"")
    lock_path.chmod(0o600)
    inherited = os.open(lock_path, os.O_RDWR)
    try:
        monkeypatch.setenv(KIT.LOCK_FD_ENV, str(inherited))
        monkeypatch.setenv(KIT.LOCK_HELD_ENV, "1")
        with pytest.raises(
            KIT.BootstrapSourceError,
            match="efetivamente",
        ):
            KIT.verify_inherited_lock(
                uid=os.getuid(),
                gid=os.getgid(),
                lock_directory=lock_directory,
            )

        fcntl.flock(inherited, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert KIT.verify_inherited_lock(
            uid=os.getuid(),
            gid=os.getgid(),
            lock_directory=lock_directory,
        ) == inherited
    finally:
        os.close(inherited)


def test_open_path_chain_rejects_world_writable_parent(
    secure_tmp_path: Path,
) -> None:
    untrusted_parent = secure_tmp_path / "untrusted"
    untrusted_parent.mkdir(mode=0o700)
    protected_leaf = untrusted_parent / "leaf"
    protected_leaf.mkdir(mode=0o700)
    untrusted_parent.chmod(0o1777)
    assert stat.S_IMODE(untrusted_parent.stat().st_mode) == 0o1777

    try:
        with pytest.raises(
            KIT.BootstrapSourceError,
            match="pai não protegido",
        ):
            KIT.open_path_chain(
                protected_leaf,
                uid=os.getuid(),
                gid=os.getgid(),
                final_modes={0o700},
            )
    finally:
        untrusted_parent.chmod(0o700)


def test_cosign_claims_are_exact() -> None:
    args = KIT.cosign_arguments(
        bundle_path="/proc/self/fd/3",
        target_path="/proc/self/fd/4",
        carrier_sha="e" * 40,
    )

    assert args == [
        "verify-blob",
        "--bundle",
        "/proc/self/fd/3",
        "--certificate-identity",
        (
            "https://github.com/PluckXD/"
            "tratto-control-release-carrier/.github/workflows/"
            "control-bootstrap-v1.yml@refs/heads/main"
        ),
        "--certificate-oidc-issuer",
        "https://token.actions.githubusercontent.com",
        "--certificate-github-workflow-sha",
        "e" * 40,
        "--certificate-github-workflow-ref",
        "refs/heads/main",
        "--certificate-github-workflow-repository",
        "PluckXD/tratto-control-release-carrier",
        "--certificate-github-workflow-trigger",
        "workflow_dispatch",
        "/proc/self/fd/4",
    ]
