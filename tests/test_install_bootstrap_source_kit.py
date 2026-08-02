from __future__ import annotations

import gzip
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import signal
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
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


def immutable_tree_snapshot(root: Path) -> dict[str, tuple[object, ...]]:
    observed: dict[str, tuple[object, ...]] = {}

    def visit(path: Path, relative: str) -> None:
        info = path.lstat()
        content: object = None
        if stat.S_ISREG(info.st_mode):
            content = hashlib.sha256(path.read_bytes()).hexdigest()
        elif stat.S_ISLNK(info.st_mode):
            content = os.readlink(path)
        observed[relative] = (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_uid,
            info.st_gid,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
            content,
        )
        if stat.S_ISDIR(info.st_mode):
            for child in sorted(path.iterdir(), key=lambda item: item.name):
                child_relative = (
                    child.name
                    if relative == "."
                    else f"{relative}/{child.name}"
                )
                visit(child, child_relative)

    visit(root, ".")
    return observed


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
    required_ancestors: tuple[str, ...] = ("0" * 40,),
    extra: tuple[str, bytes, int] | None = None,
    link: bool = False,
    omit: str | None = None,
    quiescence_kind: bytes = tarfile.REGTYPE,
    quiescence_mode: int = 0o555,
    quiescence_payload: bytes = b"quiescence\n",
) -> None:
    approval = {
        "api": {
            "commit_sha": api_sha,
            "required_ancestors": list(required_ancestors),
        },
        "controller": {"base_sha": "c" * 40},
        "ops": {
            "commit_sha": api_sha,
            "required_ancestors": list(required_ancestors),
        },
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
            quiescence_payload,
            quiescence_mode,
        ),
        "scripts/with-deploy-lock.py": (b"lock\n", 0o555),
        "systemd/tratto-control.slice": (
            b"[Unit]\nDescription=Tratto Control\n",
            0o444,
        ),
        "systemd/tratto-control-recovery.service": (
            b"[Unit]\nDescription=Tratto Control recovery\n",
            0o444,
        ),
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
                for directory in ("scripts", "systemd"):
                    archive.addfile(
                        tar_info(
                            directory,
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
    required_ancestors: tuple[str, ...] = ("0" * 40,),
) -> bytes:
    approval = {
        "api": {
            "commit_sha": api_sha,
            "required_ancestors": list(required_ancestors),
        },
        "controller": {"base_sha": controller_sha},
        "ops": {
            "commit_sha": api_sha,
            "required_ancestors": list(required_ancestors),
        },
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
        try:
            os.rename(
                old_name,
                new_name,
                src_dir_fd=old_parent,
                dst_dir_fd=new_parent,
            )
        except PermissionError:
            # Production executes as root. The test process emulates that
            # bounded rename while retaining the protected parent modes.
            old_mode = stat.S_IMODE(os.fstat(old_parent).st_mode)
            new_mode = stat.S_IMODE(os.fstat(new_parent).st_mode)
            moved = os.open(
                old_name,
                os.O_RDONLY | os.O_DIRECTORY,
                dir_fd=old_parent,
            )
            moved_mode = stat.S_IMODE(os.fstat(moved).st_mode)
            os.fchmod(old_parent, old_mode | 0o700)
            os.fchmod(new_parent, new_mode | 0o700)
            os.fchmod(moved, moved_mode | 0o700)
            try:
                os.rename(
                    old_name,
                    new_name,
                    src_dir_fd=old_parent,
                    dst_dir_fd=new_parent,
                )
            finally:
                os.fchmod(moved, moved_mode)
                os.close(moved)
                os.fchmod(new_parent, new_mode)
                os.fchmod(old_parent, old_mode)

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
    predecessor: tuple[str, str, str] | None = None,
    post_predecessor: (
        tuple[str, str, str, str, str, str] | None
    ) = None,
    post_stage: tuple[str, str] | None = None,
    publisher_callback=None,
    quiescence_callback=None,
) -> str:
    def verifier(
        _cosign: int,
        _target: int,
        _bundle: int,
        carrier_sha: str,
    ) -> None:
        assert carrier_sha == "b" * 40
        calls.append("signature")

    def publisher(
        _source: int,
        _lock: int,
        authorization: bytes | None,
    ) -> str:
        if predecessor is None:
            assert authorization is None
        else:
            assert authorization is not None
            calls.append(authorization.decode("utf-8"))
        calls.append("publisher")
        if publisher_callback is not None:
            publisher_callback()
        return "upgraded"

    def quiescence(
        _archive: int,
        _archive_info: os.stat_result,
        _inventory: object,
        _archive_sha256: str,
        lock_descriptor: int,
        current_bootstrap_digest: str,
    ) -> None:
        assert lock_descriptor == 99
        assert len(current_bootstrap_digest) == 64
        calls.append("quiescence")
        if quiescence_callback is not None:
            quiescence_callback(current_bootstrap_digest)

    helper_path = incoming / KIT.HELPER_NAME
    execution_descriptor = os.open(helper_path, os.O_RDONLY)
    try:
        return KIT.install_source(
            incoming=incoming,
            state_root=state,
            uid=os.getuid(),
            gid=os.getgid(),
            execution_descriptor=execution_descriptor,
            expectations=KIT.BootstrapExpectations(
                helper_sha256=expectations(incoming).helper_sha256,
                attestation_sha256=(
                    expectations(incoming).attestation_sha256
                ),
                carrier_sha=expectations(incoming).carrier_sha,
                controller_sha=expectations(incoming).controller_sha,
                predecessor_kit_id=(
                    predecessor[0] if predecessor else None
                ),
                predecessor_controller_sha=(
                    predecessor[1] if predecessor else None
                ),
                predecessor_publisher_intent_sha256=(
                    predecessor[2] if predecessor else None
                ),
                post_publisher_predecessor_kit_id=(
                    post_predecessor[0] if post_predecessor else None
                ),
                post_publisher_predecessor_controller_sha=(
                    post_predecessor[1] if post_predecessor else None
                ),
                post_publisher_source_intent_sha256=(
                    post_predecessor[2] if post_predecessor else None
                ),
                post_publisher_source_used_sha256=(
                    post_predecessor[3] if post_predecessor else None
                ),
                post_publisher_publisher_intent_sha256=(
                    post_predecessor[4] if post_predecessor else None
                ),
                post_publisher_publisher_used_sha256=(
                    post_predecessor[5] if post_predecessor else None
                ),
                post_publisher_staged_bundle_id=(
                    post_stage[0] if post_stage else None
                ),
                post_publisher_staged_bundle_tree_sha256=(
                    post_stage[1] if post_stage else None
                ),
            ),
            runtime=fake_runtime(),
            signature_verifier=verifier,
            publisher=publisher,
            lock_descriptor=99,
            quiescence=quiescence,
            fault=fault,
        )
    finally:
        os.close(execution_descriptor)


def inspect_post_stage(
    incoming: Path,
    state: Path,
    bindings: tuple[str, str, str, str, str, str],
    bundle_id: str,
    calls: list[str],
) -> bytes:
    def verifier(
        _cosign: int,
        _target: int,
        _bundle: int,
        carrier_sha: str,
    ) -> None:
        assert carrier_sha == "b" * 40
        calls.append("signature")

    helper_path = incoming / KIT.HELPER_NAME
    execution_descriptor = os.open(helper_path, os.O_RDONLY)
    try:
        return KIT.inspect_post_stage(
            incoming=incoming,
            state_root=state,
            uid=os.getuid(),
            gid=os.getgid(),
            execution_descriptor=execution_descriptor,
            expectations=KIT.BootstrapExpectations(
                helper_sha256=expectations(incoming).helper_sha256,
                attestation_sha256=(
                    expectations(incoming).attestation_sha256
                ),
                carrier_sha=expectations(incoming).carrier_sha,
                controller_sha=expectations(incoming).controller_sha,
                post_publisher_predecessor_kit_id=bindings[0],
                post_publisher_predecessor_controller_sha=bindings[1],
                post_publisher_source_intent_sha256=bindings[2],
                post_publisher_source_used_sha256=bindings[3],
                post_publisher_publisher_intent_sha256=bindings[4],
                post_publisher_publisher_used_sha256=bindings[5],
                post_publisher_staged_bundle_id=bundle_id,
            ),
            signature_verifier=verifier,
            lock_descriptor=99,
            quiescence=lambda *_args: calls.append("quiescence"),
        )
    finally:
        os.close(execution_descriptor)


def replace_signed_release(
    incoming: Path,
    *,
    api_sha: str,
    required_ancestors: tuple[str, ...],
) -> None:
    helper = (incoming / KIT.HELPER_NAME).read_bytes()
    archive = incoming / f"tratto-control-ops-{api_sha}.tar.gz"
    build_archive(
        archive,
        api_sha,
        required_ancestors=required_ancestors,
    )
    archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    attestation_path = incoming / KIT.ATTESTATION_NAME
    attestation_path.chmod(0o600)
    attestation_path.write_bytes(
        attestation(
            api_sha=api_sha,
            carrier_sha="b" * 40,
            controller_sha="c" * 40,
            archive_hash=archive_hash,
            archive_size=archive.stat().st_size,
            helper_hash=hashlib.sha256(helper).hexdigest(),
            helper_size=len(helper),
            required_ancestors=required_ancestors,
        )
    )
    archive.chmod(0o400)
    attestation_path.chmod(0o400)


def signed_release_kit_id(incoming: Path) -> str:
    execution = os.open(incoming / KIT.HELPER_NAME, os.O_RDONLY)
    inputs = KIT.open_and_validate_inputs(
        incoming,
        uid=os.getuid(),
        gid=os.getgid(),
        execution_descriptor=execution,
        expectations=expectations(incoming),
        signature_verifier=lambda *_args: None,
    )
    try:
        inventory = KIT.validate_ops_archive(
            inputs.archive_descriptor,
            inputs.archive_info,
            inputs.binding,
        )
        return KIT.kit_identity(inputs.binding, inventory)
    finally:
        inputs.close()
        os.close(execution)


def prepare_pre_publisher_source_state(
    incoming: Path,
    state: Path,
    calls: list[str],
) -> dict:
    def stop(event: str) -> None:
        if event == "before_publisher":
            raise RuntimeError("predecessor publisher failed")

    with pytest.raises(RuntimeError, match="publisher failed"):
        install(incoming, state, calls, fault=stop)
    return json.loads((state / KIT.INTENT_NAME).read_text())


def prepare_clean_noop_source_state(
    incoming: Path,
    state: Path,
    calls: list[str],
) -> dict:
    assert install(incoming, state, calls) == "installed"
    intent = json.loads((state / KIT.INTENT_NAME).read_text())
    for path in list(state.iterdir()):
        if path.name in {incoming.name, KIT.SOURCE_NAME}:
            continue
        if path.is_dir():
            for directory, _children, files in os.walk(
                path,
                topdown=True,
                followlinks=False,
            ):
                Path(directory).chmod(0o700)
                for name in files:
                    (Path(directory) / name).chmod(0o600)
            shutil.rmtree(path)
        else:
            path.chmod(0o600)
            path.unlink()
    calls.clear()
    return intent


def prepare_fixed_publisher_state(
    root: Path,
) -> tuple[Path, str]:
    control = root / "tratto-control"
    staging = control / ".staging"
    final = control / "bootstrap"
    candidate = staging / KIT.PUBLISHER_CANDIDATE_NAME
    staging.mkdir(parents=True, mode=0o700)
    final.mkdir(mode=0o700)
    candidate.mkdir(mode=0o700)
    (final / ".complete").write_bytes(b"BOOTSTRAP_READY=1\n")
    (candidate / ".complete").write_bytes(b"BOOTSTRAP_READY=1\n")
    (final / "version").write_bytes(b"old\n")
    (candidate / "version").write_bytes(b"failed\n")
    for directory in (final, candidate):
        for child in directory.iterdir():
            child.chmod(0o444)
        directory.chmod(0o555)
    final_fd = os.open(final, os.O_RDONLY | os.O_DIRECTORY)
    candidate_fd = os.open(candidate, os.O_RDONLY | os.O_DIRECTORY)
    try:
        old_digest = KIT.protected_bootstrap_tree_digest(
            final_fd,
            uid=os.getuid(),
            gid=os.getgid(),
        )
        new_digest = KIT.protected_bootstrap_tree_digest(
            candidate_fd,
            uid=os.getuid(),
            gid=os.getgid(),
        )
    finally:
        os.close(candidate_fd)
        os.close(final_fd)
    intent = canonical(
        {
            "new_tree_sha256": new_digest,
            "old_tree_sha256": old_digest,
            "phase": "intent",
            "previous_name": (
                KIT.PUBLISHER_PREVIOUS_PREFIX + old_digest[:32]
            ),
            "schema_version": 1,
        }
    )
    intent_path = staging / KIT.PUBLISHER_INTENT_NAME
    intent_path.write_bytes(intent)
    intent_path.chmod(0o400)
    staging.chmod(0o700)
    control.chmod(0o711)
    return control, hashlib.sha256(intent).hexdigest()


def protected_bootstrap_tree(path: Path, version: bytes) -> str:
    path.mkdir(mode=0o700)
    (path / ".complete").write_bytes(b"BOOTSTRAP_READY=1\n")
    (path / "version").write_bytes(version)
    for child in path.iterdir():
        child.chmod(0o444)
    path.chmod(0o555)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return KIT.protected_bootstrap_tree_digest(
            descriptor,
            uid=os.getuid(),
            gid=os.getgid(),
        )
    finally:
        os.close(descriptor)


def prepare_terminal_publisher_state(
    root: Path,
) -> tuple[Path, dict[str, object]]:
    control = root / "tratto-control"
    staging = control / ".staging"
    bundles = control / KIT.BUNDLES_NAME
    staging.mkdir(parents=True, mode=0o700)
    bundles.mkdir(mode=0o711)
    provisional_previous = staging / ".publisher-old"
    old_digest = protected_bootstrap_tree(
        provisional_previous,
        b"old\n",
    )
    final = control / "bootstrap"
    new_digest = protected_bootstrap_tree(final, b"published\n")
    previous_name = KIT.PUBLISHER_PREVIOUS_PREFIX + old_digest[:32]
    provisional_previous.rename(staging / previous_name)
    intent_value = {
        "new_tree_sha256": new_digest,
        "old_tree_sha256": old_digest,
        "phase": "intent",
        "previous_name": previous_name,
        "schema_version": 1,
    }
    used_value = dict(intent_value)
    used_value["phase"] = "used"
    intent_raw = canonical(intent_value)
    used_raw = canonical(used_value)
    (staging / KIT.PUBLISHER_INTENT_NAME).write_bytes(intent_raw)
    (staging / KIT.PUBLISHER_USED_NAME).write_bytes(used_raw)
    (staging / KIT.PUBLISHER_INTENT_NAME).chmod(0o400)
    (staging / KIT.PUBLISHER_USED_NAME).chmod(0o400)
    control.chmod(0o711)
    return control, {
        "intent_sha256": hashlib.sha256(intent_raw).hexdigest(),
        "used_sha256": hashlib.sha256(used_raw).hexdigest(),
        "old_digest": old_digest,
        "new_digest": new_digest,
        "previous_name": previous_name,
    }


def configure_post_publisher_paths(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
    control: Path,
) -> None:
    monkeypatch.setattr(KIT, "CONTROL_ROOT", control)
    monkeypatch.setattr(
        KIT,
        "BOOTSTRAP_RELEASE_MARKER",
        root / "etc" / "bootstrap-release.env",
    )
    monkeypatch.setattr(
        KIT,
        "RELEASE_STATE_MARKER",
        root / "etc" / "release-state.env",
    )
    monkeypatch.setattr(
        KIT,
        "ACTIVATION_JOURNAL",
        root / "etc" / "activation.env",
    )
    monkeypatch.setattr(
        KIT,
        "ACTIVATION_EPOCH_MARKER",
        root / "etc" / "activation-epoch.env",
    )


def prepare_post_publisher_fixture(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    Path,
    Path,
    list[str],
    tuple[str, str, str, str, str, str],
    Path,
]:
    incoming, state, calls = fixture(root)
    assert install(incoming, state, calls) == "installed"
    source_intent = (state / KIT.INTENT_NAME).read_bytes()
    source_used = (state / KIT.USED_NAME).read_bytes()
    source = KIT.validate_source_intent(source_intent)
    control, publisher = prepare_terminal_publisher_state(root)
    configure_post_publisher_paths(monkeypatch, root, control)
    successor_api_sha = "d" * 40
    replace_signed_release(
        incoming,
        api_sha=successor_api_sha,
        required_ancestors=(source.api_sha,),
    )
    calls.clear()
    bindings = (
        source.kit_id,
        source.controller_sha,
        hashlib.sha256(source_intent).hexdigest(),
        hashlib.sha256(source_used).hexdigest(),
        str(publisher["intent_sha256"]),
        str(publisher["used_sha256"]),
    )
    return incoming, state, calls, bindings, control


def stage_predecessor_schema6_bundle(
    incoming: Path,
    state: Path,
    control: Path,
    *,
    required_ancestors: tuple[str, ...] = ("0" * 40,),
) -> tuple[str, str]:
    source_intent = json.loads((state / KIT.INTENT_NAME).read_text())
    bundle_id = str(source_intent["attestation_sha256"])
    api_sha = str(source_intent["api_sha"])
    old_archive = (
        incoming / f"tratto-control-ops-{api_sha}.tar.gz"
    )
    old_raw = attestation(
        api_sha=api_sha,
        carrier_sha="b" * 40,
        controller_sha="c" * 40,
        archive_hash=hashlib.sha256(old_archive.read_bytes()).hexdigest(),
        archive_size=old_archive.stat().st_size,
        helper_hash=hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
        helper_size=SCRIPT.stat().st_size,
        required_ancestors=required_ancestors,
    )
    assert hashlib.sha256(old_raw).hexdigest() == bundle_id
    target = control / KIT.BUNDLES_NAME / bundle_id
    target.mkdir(mode=0o700)
    attestation_path = target / KIT.ATTESTATION_NAME
    attestation_path.write_bytes(old_raw)
    attestation_path.chmod(0o444)
    empty_marker = target / "empty-package-marker"
    empty_marker.write_bytes(b"")
    empty_marker.chmod(0o444)
    target.chmod(0o555)
    descriptor = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try:
        tree_digest = KIT.staged_bundle_tree_digest(
            descriptor,
            uid=os.getuid(),
        )
    finally:
        os.close(descriptor)
    return bundle_id, tree_digest


def publish_fake_successor_bootstrap(control: Path) -> None:
    staging = control / ".staging"
    final = control / "bootstrap"
    final_descriptor = os.open(final, os.O_RDONLY | os.O_DIRECTORY)
    try:
        old_digest = KIT.protected_bootstrap_tree_digest(
            final_descriptor,
            uid=os.getuid(),
            gid=os.getgid(),
        )
    finally:
        os.close(final_descriptor)
    candidate = staging / ".publisher-successor"
    new_digest = protected_bootstrap_tree(candidate, b"successor\n")
    previous_name = KIT.PUBLISHER_PREVIOUS_PREFIX + old_digest[:32]
    control.chmod(0o700)
    final.chmod(0o700)
    candidate.chmod(0o700)
    final.rename(staging / previous_name)
    candidate.rename(final)
    (staging / previous_name).chmod(0o555)
    final.chmod(0o555)
    control.chmod(0o711)
    intent = {
        "new_tree_sha256": new_digest,
        "old_tree_sha256": old_digest,
        "phase": "intent",
        "previous_name": previous_name,
        "schema_version": 1,
    }
    used = dict(intent)
    used["phase"] = "used"
    (staging / KIT.PUBLISHER_INTENT_NAME).write_bytes(canonical(intent))
    (staging / KIT.PUBLISHER_USED_NAME).write_bytes(canonical(used))
    (staging / KIT.PUBLISHER_INTENT_NAME).chmod(0o400)
    (staging / KIT.PUBLISHER_USED_NAME).chmod(0o400)


def publish_fake_superseding_bootstrap(
    control: Path,
    authorization: dict[str, object],
) -> None:
    staging = control / ".staging"
    final = control / "bootstrap"
    predecessor_intent_path = staging / KIT.PUBLISHER_INTENT_NAME
    predecessor_intent_raw = predecessor_intent_path.read_bytes()
    predecessor_intent = json.loads(predecessor_intent_raw)
    predecessor_candidate = staging / KIT.PUBLISHER_CANDIDATE_NAME
    predecessor_candidate_fd = os.open(
        predecessor_candidate,
        os.O_RDONLY | os.O_DIRECTORY,
    )
    try:
        predecessor_candidate_digest = (
            KIT.protected_bootstrap_tree_digest(
                predecessor_candidate_fd,
                uid=os.getuid(),
                gid=os.getgid(),
            )
        )
    finally:
        os.close(predecessor_candidate_fd)
    assert (
        predecessor_candidate_digest
        == predecessor_intent["new_tree_sha256"]
    )
    successor_candidate = staging / ".publisher-successor"
    successor_digest = protected_bootstrap_tree(
        successor_candidate,
        b"superseding-successor\n",
    )
    predecessor_intent_sha256 = hashlib.sha256(
        predecessor_intent_raw
    ).hexdigest()
    retained_intent_name = (
        "bootstrap-upgrade.intent.superseded."
        f"{predecessor_intent_sha256}.json"
    )
    retained_candidate_name = (
        "bootstrap.upgrading.superseded."
        f"{predecessor_candidate_digest}"
    )
    supersede = {
        "contract": KIT.PUBLISHER_SUPERSEDE_CONTRACT,
        "phase": "superseded",
        "predecessor_intent_sha256": predecessor_intent_sha256,
        "predecessor_new_tree_sha256": predecessor_candidate_digest,
        "predecessor_old_tree_sha256": predecessor_intent[
            "old_tree_sha256"
        ],
        "predecessor_previous_name": predecessor_intent[
            "previous_name"
        ],
        "retained_candidate_name": retained_candidate_name,
        "retained_intent_name": retained_intent_name,
        "schema_version": 1,
        "source_predecessor_kit_id": authorization[
            "predecessor_source_kit_id"
        ],
        "source_predecessor_tree_sha256": authorization[
            "predecessor_source_tree_sha256"
        ],
        "source_successor_kit_id": authorization[
            "successor_source_kit_id"
        ],
        "source_successor_tree_sha256": authorization[
            "successor_source_tree_sha256"
        ],
        "successor_new_tree_sha256": successor_digest,
    }
    supersede_path = staging / KIT.PUBLISHER_SUPERSEDE_NAME
    supersede_path.write_bytes(canonical(supersede))
    supersede_path.chmod(0o400)
    predecessor_candidate.rename(staging / retained_candidate_name)
    predecessor_intent_path.rename(staging / retained_intent_name)

    old_digest = str(predecessor_intent["old_tree_sha256"])
    previous_name = KIT.PUBLISHER_PREVIOUS_PREFIX + old_digest[:32]
    control.chmod(0o700)
    final.chmod(0o700)
    successor_candidate.chmod(0o700)
    final.rename(staging / previous_name)
    successor_candidate.rename(final)
    (staging / previous_name).chmod(0o555)
    final.chmod(0o555)
    control.chmod(0o711)
    intent = {
        "new_tree_sha256": successor_digest,
        "old_tree_sha256": old_digest,
        "phase": "intent",
        "previous_name": previous_name,
        "schema_version": 1,
    }
    used = dict(intent)
    used["phase"] = "used"
    (staging / KIT.PUBLISHER_INTENT_NAME).write_bytes(canonical(intent))
    (staging / KIT.PUBLISHER_USED_NAME).write_bytes(canonical(used))
    (staging / KIT.PUBLISHER_INTENT_NAME).chmod(0o400)
    (staging / KIT.PUBLISHER_USED_NAME).chmod(0o400)


def prepare_nested_post_publisher_fixture(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    Path,
    Path,
    list[str],
    tuple[str, str, str, str, str, str],
    Path,
]:
    incoming, state, calls = fixture(root)
    predecessor_intent = prepare_pre_publisher_source_state(
        incoming,
        state,
        calls,
    )
    control, publisher_intent_sha256 = prepare_fixed_publisher_state(root)
    (control / KIT.BUNDLES_NAME).mkdir(mode=0o711)
    configure_post_publisher_paths(monkeypatch, root, control)
    replace_signed_release(
        incoming,
        api_sha="d" * 40,
        required_ancestors=(str(predecessor_intent["api_sha"]),),
    )
    calls.clear()

    def publish_superseding() -> None:
        authorization = json.loads(calls[-2])
        publish_fake_superseding_bootstrap(control, authorization)

    assert (
        install(
            incoming,
            state,
            calls,
            predecessor=(
                str(predecessor_intent["kit_id"]),
                str(predecessor_intent["controller_sha"]),
                publisher_intent_sha256,
            ),
            publisher_callback=publish_superseding,
        )
        == "installed"
    )
    current_source_intent = (state / KIT.INTENT_NAME).read_bytes()
    current_source_used = (state / KIT.USED_NAME).read_bytes()
    current_source = KIT.validate_source_intent(current_source_intent)
    publisher_intent = (
        control / ".staging" / KIT.PUBLISHER_INTENT_NAME
    ).read_bytes()
    publisher_used = (
        control / ".staging" / KIT.PUBLISHER_USED_NAME
    ).read_bytes()
    replace_signed_release(
        incoming,
        api_sha="e" * 40,
        required_ancestors=(current_source.api_sha,),
    )
    calls.clear()
    return (
        incoming,
        state,
        calls,
        (
            current_source.kit_id,
            current_source.controller_sha,
            hashlib.sha256(current_source_intent).hexdigest(),
            hashlib.sha256(current_source_used).hexdigest(),
            hashlib.sha256(publisher_intent).hexdigest(),
            hashlib.sha256(publisher_used).hexdigest(),
        ),
        control,
    )


def add_foreign_source_reserved_entry(
    state: Path,
    kind: str,
) -> None:
    if kind == "journal":
        foreign = state / "bootstrap-source-kit.foreign.json"
        foreign.write_bytes(b"foreign\n")
        foreign.chmod(0o444)
        return
    prefix = (
        KIT.CANDIDATE_PREFIX
        if kind == "candidate"
        else KIT.PREVIOUS_PREFIX
    )
    foreign = state / f"{prefix}{'9' * 64}"
    foreign.mkdir(mode=0o755)
    evidence = foreign / "evidence"
    evidence.write_bytes(b"foreign\n")
    evidence.chmod(0o444)
    foreign.chmod(0o555)


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


def test_installs_and_replays_noop_source_without_exchange_evidence(
    secure_tmp_path: Path,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    expected = prepare_clean_noop_source_state(incoming, state, calls)

    assert install(incoming, state, calls) == "installed"
    intent_raw = (state / KIT.INTENT_NAME).read_bytes()
    intent = json.loads(intent_raw)
    assert intent["old_source_tree_sha256"] == expected[
        "new_source_tree_sha256"
    ]
    assert intent["new_source_tree_sha256"] == expected[
        "new_source_tree_sha256"
    ]
    parsed = KIT.validate_source_intent(intent_raw, allow_noop=True)
    assert parsed.old_digest == parsed.new_digest
    with pytest.raises(KIT.BootstrapSourceError):
        KIT.validate_source_intent(intent_raw)
    assert (state / KIT.RETAINED_NAME).is_file()
    assert (state / KIT.USED_NAME).is_file()
    assert not (state / KIT.PREPARED_NAME).exists()
    assert not (state / KIT.EXCHANGED_NAME).exists()
    assert not list(state.glob(f"{KIT.CANDIDATE_PREFIX}*"))
    assert not list(state.glob(f"{KIT.PREVIOUS_PREFIX}*"))
    assert calls == ["signature", "signature", "signature", "publisher"]

    calls.clear()
    assert install(incoming, state, calls) == "already-installed"
    assert calls == ["signature", "signature", "signature"]


@pytest.mark.parametrize(
    "event",
    ("after_intent", "before_publisher", "after_publisher"),
)
def test_noop_recovers_each_simulated_crash_boundary(
    secure_tmp_path: Path,
    event: str,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    prepare_clean_noop_source_state(incoming, state, calls)
    fired = False

    def fault(observed: str) -> None:
        nonlocal fired
        if not fired and observed == event:
            fired = True
            raise RuntimeError("simulated no-op crash")

    with pytest.raises(RuntimeError, match="simulated no-op"):
        install(incoming, state, calls, fault=fault)
    assert not (state / KIT.PREPARED_NAME).exists()
    assert not (state / KIT.EXCHANGED_NAME).exists()
    assert not list(state.glob(f"{KIT.CANDIDATE_PREFIX}*"))
    assert not list(state.glob(f"{KIT.PREVIOUS_PREFIX}*"))

    calls.clear()
    assert install(incoming, state, calls) == "installed"
    assert (state / KIT.RETAINED_NAME).is_file()
    assert (state / KIT.USED_NAME).is_file()


@pytest.mark.skipif(
    not hasattr(os, "fork"),
    reason="fault harness exige fork",
)
@pytest.mark.parametrize(
    "event",
    ("after_intent", "before_publisher", "after_publisher"),
)
def test_noop_replays_after_real_sigkill(
    secure_tmp_path: Path,
    event: str,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    prepare_clean_noop_source_state(incoming, state, calls)
    child = os.fork()
    if child == 0:
        def kill_at(observed: str) -> None:
            if observed == event:
                os.kill(os.getpid(), 9)

        try:
            install(incoming, state, [], fault=kill_at)
        except BaseException:
            os._exit(92)
        os._exit(91)
    _, status = os.waitpid(child, 0)
    assert os.WIFSIGNALED(status)
    assert os.WTERMSIG(status) == 9
    assert install(incoming, state, []) == "installed"
    assert (state / KIT.RETAINED_NAME).is_file()
    assert (state / KIT.USED_NAME).is_file()
    assert not (state / KIT.PREPARED_NAME).exists()
    assert not (state / KIT.EXCHANGED_NAME).exists()


@pytest.mark.parametrize(
    ("phase", "boundary"),
    (
        ("intent", "after_intent"),
        ("retained", "before_publisher"),
        ("used", None),
    ),
)
def test_noop_recovers_each_partial_record(
    secure_tmp_path: Path,
    phase: str,
    boundary: str | None,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    expected = prepare_clean_noop_source_state(incoming, state, calls)
    if boundary is None:
        assert install(incoming, state, calls) == "installed"
    else:
        def stop(event: str) -> None:
            if event == boundary:
                raise RuntimeError("stop at no-op record boundary")

        with pytest.raises(RuntimeError, match="no-op record boundary"):
            install(incoming, state, calls, fault=stop)
    final_name = {
        "intent": KIT.INTENT_NAME,
        "retained": KIT.RETAINED_NAME,
        "used": KIT.USED_NAME,
    }[phase]
    partial = state / (
        f"bootstrap-source-kit.{phase}."
        f"{expected['kit_id']}.installing"
    )
    (state / final_name).rename(partial)

    calls.clear()
    assert install(incoming, state, calls) == "installed"
    assert (state / final_name).is_file()
    assert not partial.exists()
    assert not (state / KIT.PREPARED_NAME).exists()
    assert not (state / KIT.EXCHANGED_NAME).exists()


@pytest.mark.parametrize(
    "impossible",
    (
        "prepared",
        "exchanged",
        "prepared-partial",
        "candidate",
        "previous",
        "retained-without-intent",
        "used-without-retained",
    ),
)
def test_noop_rejects_impossible_state_without_mutation(
    secure_tmp_path: Path,
    impossible: str,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    expected = prepare_clean_noop_source_state(incoming, state, calls)
    kit_id = expected["kit_id"]
    digest = expected["new_source_tree_sha256"]
    if impossible != "retained-without-intent":
        def stop_after_intent(event: str) -> None:
            if event == "after_intent":
                raise RuntimeError("stop after no-op intent")

        with pytest.raises(RuntimeError, match="stop after no-op intent"):
            install(incoming, state, calls, fault=stop_after_intent)
    if impossible in {"prepared", "exchanged", "used-without-retained"}:
        phase = (
            "used"
            if impossible == "used-without-retained"
            else impossible
        )
        name = {
            "prepared": KIT.PREPARED_NAME,
            "exchanged": KIT.EXCHANGED_NAME,
            "used": KIT.USED_NAME,
        }[phase]
        path = state / name
        path.write_bytes(
            KIT.marker_payload(
                kit_id=kit_id,
                phase=phase,
                old_digest=digest,
                new_digest=digest,
            )
        )
        path.chmod(0o444)
    elif impossible == "prepared-partial":
        partial = state / (
            f"bootstrap-source-kit.prepared.{kit_id}.installing"
        )
        partial.write_bytes(b"")
        partial.chmod(0o600)
    elif impossible == "candidate":
        (state / f"{KIT.CANDIDATE_PREFIX}{kit_id}").mkdir(mode=0o700)
    elif impossible == "previous":
        shutil.copytree(
            state / KIT.SOURCE_NAME,
            state / f"{KIT.PREVIOUS_PREFIX}{kit_id}",
        )
    else:
        retained = state / KIT.RETAINED_NAME
        retained.write_bytes(
            KIT.marker_payload(
                kit_id=kit_id,
                phase="retained",
                old_digest=digest,
                new_digest=digest,
            )
        )
        retained.chmod(0o444)
    before = immutable_tree_snapshot(state)

    with pytest.raises(KIT.BootstrapSourceError):
        install(incoming, state, calls)

    assert immutable_tree_snapshot(state) == before


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


def test_authorized_successor_supersedes_only_exact_pre_publisher_state(
    secure_tmp_path: Path,
    monkeypatch,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    predecessor_intent = prepare_pre_publisher_source_state(
        incoming,
        state,
        calls,
    )
    publisher_intent_sha256 = "7" * 64
    monkeypatch.setattr(
        KIT,
        "validate_fixed_predecessor_publisher_state",
        lambda **_kwargs: publisher_intent_sha256,
    )
    replace_signed_release(
        incoming,
        api_sha="e" * 40,
        required_ancestors=("a" * 40,),
    )
    calls.clear()
    predecessor = (
        predecessor_intent["kit_id"],
        predecessor_intent["controller_sha"],
        publisher_intent_sha256,
    )
    assert (
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
        )
        == "installed"
    )
    supersede = json.loads((state / KIT.SUPERSEDE_NAME).read_text())
    assert supersede["predecessor_kit_id"] == predecessor[0]
    assert (
        supersede["predecessor_publisher_intent_sha256"]
        == publisher_intent_sha256
    )
    for phase in ("intent", "prepared", "exchanged", "retained"):
        archived = state / (
            f"bootstrap-source-kit.{phase}.superseded."
            f"{predecessor[0]}.json"
        )
        assert archived.is_file()
    authorization = json.loads(calls[-2])
    assert authorization["predecessor_source_kit_id"] == predecessor[0]
    assert (
        authorization["predecessor_publisher_intent_sha256"]
        == publisher_intent_sha256
    )
    assert calls[-1] == "publisher"
    calls.clear()
    assert (
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
        )
        == "already-installed"
    )


@pytest.mark.parametrize(
    "boundary",
    (
        "after_source_supersede",
        "after_source_supersede_intent",
        "after_source_supersede_prepared",
        "after_source_supersede_exchanged",
        "after_source_supersede_retained",
    ),
)
def test_successor_recovers_every_supersede_crash_boundary(
    secure_tmp_path: Path,
    monkeypatch,
    boundary: str,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    predecessor_intent = prepare_pre_publisher_source_state(
        incoming,
        state,
        calls,
    )
    publisher_intent_sha256 = "7" * 64
    monkeypatch.setattr(
        KIT,
        "validate_fixed_predecessor_publisher_state",
        lambda **_kwargs: publisher_intent_sha256,
    )
    replace_signed_release(
        incoming,
        api_sha="e" * 40,
        required_ancestors=("a" * 40,),
    )
    predecessor = (
        predecessor_intent["kit_id"],
        predecessor_intent["controller_sha"],
        publisher_intent_sha256,
    )
    fired = False

    def fail_once(event: str) -> None:
        nonlocal fired
        if not fired and event == boundary:
            fired = True
            raise RuntimeError("simulated successor crash")

    with pytest.raises(RuntimeError, match="simulated successor"):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
            fault=fail_once,
        )
    calls.clear()
    assert (
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
        )
        == "installed"
    )


@pytest.mark.parametrize("replay", [False, True])
@pytest.mark.parametrize("foreign_kind", ["journal", "candidate", "previous"])
def test_successor_rejects_foreign_reserved_namespace_without_mutation(
    secure_tmp_path: Path,
    monkeypatch,
    replay: bool,
    foreign_kind: str,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    predecessor_intent = prepare_pre_publisher_source_state(
        incoming,
        state,
        calls,
    )
    publisher_intent_sha256 = "7" * 64
    monkeypatch.setattr(
        KIT,
        "validate_fixed_predecessor_publisher_state",
        lambda **_kwargs: publisher_intent_sha256,
    )
    replace_signed_release(
        incoming,
        api_sha="e" * 40,
        required_ancestors=("a" * 40,),
    )
    predecessor = (
        predecessor_intent["kit_id"],
        predecessor_intent["controller_sha"],
        publisher_intent_sha256,
    )
    if replay:
        def stop_after_supersede(event: str) -> None:
            if event == "after_source_supersede":
                raise RuntimeError("stop after source supersede")

        with pytest.raises(RuntimeError, match="stop after source"):
            install(
                incoming,
                state,
                calls,
                predecessor=predecessor,
                fault=stop_after_supersede,
            )
    add_foreign_source_reserved_entry(state, foreign_kind)
    before = immutable_tree_snapshot(state)

    with pytest.raises(
        KIT.BootstrapSourceError,
        match="namespace reservado",
    ):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
        )

    assert immutable_tree_snapshot(state) == before
    if replay:
        assert (state / KIT.SUPERSEDE_NAME).is_file()
    else:
        assert not (state / KIT.SUPERSEDE_NAME).exists()
    assert not list(state.glob("bootstrap-source-kit.*.superseded.*"))


def test_successor_replay_rejects_predecessor_used_without_mutation(
    secure_tmp_path: Path,
    monkeypatch,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    predecessor_intent = prepare_pre_publisher_source_state(
        incoming,
        state,
        calls,
    )
    publisher_intent_sha256 = "7" * 64
    monkeypatch.setattr(
        KIT,
        "validate_fixed_predecessor_publisher_state",
        lambda **_kwargs: publisher_intent_sha256,
    )
    replace_signed_release(
        incoming,
        api_sha="e" * 40,
        required_ancestors=("a" * 40,),
    )
    predecessor = (
        predecessor_intent["kit_id"],
        predecessor_intent["controller_sha"],
        publisher_intent_sha256,
    )

    def stop_after_supersede(event: str) -> None:
        if event == "after_source_supersede":
            raise RuntimeError("stop after source supersede")

    with pytest.raises(RuntimeError, match="stop after source"):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
            fault=stop_after_supersede,
        )
    used = state / KIT.USED_NAME
    used.write_bytes(
        KIT.marker_payload(
            kit_id=predecessor_intent["kit_id"],
            phase="used",
            old_digest=predecessor_intent[
                "old_source_tree_sha256"
            ],
            new_digest=predecessor_intent[
                "new_source_tree_sha256"
            ],
        )
    )
    used.chmod(0o444)
    before = immutable_tree_snapshot(state)

    with pytest.raises(KIT.BootstrapSourceError, match="used source"):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
        )

    assert immutable_tree_snapshot(state) == before
    assert not list(state.glob("bootstrap-source-kit.*.superseded.*"))


def test_successor_replay_rejects_foreign_partial_without_mutation(
    secure_tmp_path: Path,
    monkeypatch,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    predecessor_intent = prepare_pre_publisher_source_state(
        incoming,
        state,
        calls,
    )
    publisher_intent_sha256 = "7" * 64
    monkeypatch.setattr(
        KIT,
        "validate_fixed_predecessor_publisher_state",
        lambda **_kwargs: publisher_intent_sha256,
    )
    replace_signed_release(
        incoming,
        api_sha="e" * 40,
        required_ancestors=("a" * 40,),
    )
    predecessor = (
        predecessor_intent["kit_id"],
        predecessor_intent["controller_sha"],
        publisher_intent_sha256,
    )

    def stop_after_archives(event: str) -> None:
        if event == "after_source_supersede_retained":
            raise RuntimeError("stop after source archives")

    with pytest.raises(RuntimeError, match="stop after source"):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
            fault=stop_after_archives,
        )
    successor = json.loads((state / KIT.SUPERSEDE_NAME).read_text())
    partial = state / (
        f"bootstrap-source-kit.used."
        f"{successor['successor_kit_id']}.installing"
    )
    partial.write_bytes(b"foreign partial\n")
    partial.chmod(0o444)
    before = immutable_tree_snapshot(state)

    with pytest.raises(
        KIT.BootstrapSourceError,
        match="prefixo do journal sucessor",
    ):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
        )

    assert immutable_tree_snapshot(state) == before
    assert not (state / KIT.INTENT_NAME).exists()


def test_normal_mode_rejects_post_publisher_partial_with_typed_error(
    secure_tmp_path: Path,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)

    def stop_after_intent(event: str) -> None:
        if event == "after_intent":
            raise RuntimeError("stop after intent")

    with pytest.raises(RuntimeError, match="stop after intent"):
        install(
            incoming,
            state,
            calls,
            fault=stop_after_intent,
        )
    successor = json.loads((state / KIT.INTENT_NAME).read_text())
    partial = state / (
        "bootstrap-source-kit.post-publisher-supersede."
        f"{successor['kit_id']}.installing"
    )
    partial.write_bytes(b"foreign partial\n")
    partial.chmod(0o444)
    before = immutable_tree_snapshot(state)

    with pytest.raises(
        KIT.BootstrapSourceError,
        match="namespace reservado",
    ):
        install(incoming, state, calls)

    assert immutable_tree_snapshot(state) == before


def prepare_successor_after_predecessor_archives(
    incoming: Path,
    state: Path,
    calls: list[str],
    monkeypatch,
) -> tuple[tuple[str, str, str], dict]:
    predecessor_intent = prepare_pre_publisher_source_state(
        incoming,
        state,
        calls,
    )
    publisher_intent_sha256 = "7" * 64
    monkeypatch.setattr(
        KIT,
        "validate_fixed_predecessor_publisher_state",
        lambda **_kwargs: publisher_intent_sha256,
    )
    replace_signed_release(
        incoming,
        api_sha="e" * 40,
        required_ancestors=("a" * 40,),
    )
    predecessor = (
        predecessor_intent["kit_id"],
        predecessor_intent["controller_sha"],
        publisher_intent_sha256,
    )

    def stop_after_archives(event: str) -> None:
        if event == "after_source_supersede_retained":
            raise RuntimeError("stop after source archives")

    with pytest.raises(RuntimeError, match="stop after source archives"):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
            fault=stop_after_archives,
        )
    return predecessor, json.loads((state / KIT.SUPERSEDE_NAME).read_text())


@pytest.mark.parametrize(
    "archived_phases",
    [
        pytest.param(("retained",), id="retained-only"),
        pytest.param(("intent", "exchanged"), id="intermediate-gap"),
    ],
)
def test_successor_rejects_nonprefix_predecessor_history_without_mutation(
    secure_tmp_path: Path,
    monkeypatch,
    archived_phases: tuple[str, ...],
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    predecessor_intent = prepare_pre_publisher_source_state(
        incoming,
        state,
        calls,
    )
    publisher_intent_sha256 = "7" * 64
    monkeypatch.setattr(
        KIT,
        "validate_fixed_predecessor_publisher_state",
        lambda **_kwargs: publisher_intent_sha256,
    )
    replace_signed_release(
        incoming,
        api_sha="e" * 40,
        required_ancestors=("a" * 40,),
    )
    predecessor = (
        predecessor_intent["kit_id"],
        predecessor_intent["controller_sha"],
        publisher_intent_sha256,
    )

    def stop_after_supersede(event: str) -> None:
        if event == "after_source_supersede":
            raise RuntimeError("stop after source supersede")

    with pytest.raises(RuntimeError, match="stop after source supersede"):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
            fault=stop_after_supersede,
        )
    for phase in archived_phases:
        (state / KIT.SOURCE_PHASE_NAMES[phase]).rename(
            state
            / (
                f"bootstrap-source-kit.{phase}.superseded."
                f"{predecessor[0]}.json"
            )
        )
    before = immutable_tree_snapshot(state)

    with pytest.raises(
        KIT.BootstrapSourceError,
        match="histórico predecessor não forma prefixo",
    ):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
        )

    assert immutable_tree_snapshot(state) == before


def test_successor_rejects_candidate_before_intent_without_mutation(
    secure_tmp_path: Path,
    monkeypatch,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    predecessor, supersede = prepare_successor_after_predecessor_archives(
        incoming,
        state,
        calls,
        monkeypatch,
    )
    candidate = state / (
        KIT.CANDIDATE_PREFIX + supersede["successor_kit_id"]
    )
    candidate.mkdir(mode=0o700)
    (candidate / "partial").write_bytes(b"unbound candidate\n")
    (candidate / "partial").chmod(0o600)
    before = immutable_tree_snapshot(state)

    with pytest.raises(
        KIT.BootstrapSourceError,
        match="candidate sucessor existe antes do intent",
    ):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
        )

    assert immutable_tree_snapshot(state) == before
    assert not (state / KIT.INTENT_NAME).exists()


def test_successor_rejects_candidate_with_partial_intent_without_mutation(
    secure_tmp_path: Path,
    monkeypatch,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    predecessor, supersede = prepare_successor_after_predecessor_archives(
        incoming,
        state,
        calls,
        monkeypatch,
    )
    successor_kit_id = supersede["successor_kit_id"]
    partial = state / (
        f"bootstrap-source-kit.intent.{successor_kit_id}.installing"
    )
    partial.write_bytes(b"")
    partial.chmod(0o600)
    candidate = state / (KIT.CANDIDATE_PREFIX + successor_kit_id)
    candidate.mkdir(mode=0o700)
    (candidate / "partial").write_bytes(b"unbound candidate\n")
    (candidate / "partial").chmod(0o600)
    before = immutable_tree_snapshot(state)

    with pytest.raises(
        KIT.BootstrapSourceError,
        match="candidate sucessor existe antes do intent ativo",
    ):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
        )

    assert immutable_tree_snapshot(state) == before
    assert not (state / KIT.INTENT_NAME).exists()


def test_successor_rejects_previous_before_exchange_without_mutation(
    secure_tmp_path: Path,
    monkeypatch,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    predecessor, supersede = prepare_successor_after_predecessor_archives(
        incoming,
        state,
        calls,
        monkeypatch,
    )

    def stop_after_intent(event: str) -> None:
        if event == "after_intent":
            raise RuntimeError("stop after successor intent")

    with pytest.raises(RuntimeError, match="stop after successor intent"):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
            fault=stop_after_intent,
        )
    previous = state / (
        KIT.PREVIOUS_PREFIX + supersede["successor_kit_id"]
    )
    shutil.copytree(state / KIT.SOURCE_NAME, previous)
    before = immutable_tree_snapshot(state)

    with pytest.raises(
        KIT.BootstrapSourceError,
        match="retenção sucessora existe fora do estágio",
    ):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
        )

    assert immutable_tree_snapshot(state) == before


def test_successor_rejects_used_partial_before_exchange_without_mutation(
    secure_tmp_path: Path,
    monkeypatch,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    predecessor, supersede = prepare_successor_after_predecessor_archives(
        incoming,
        state,
        calls,
        monkeypatch,
    )
    partial = state / (
        f"bootstrap-source-kit.used."
        f"{supersede['successor_kit_id']}.installing"
    )
    partial.write_bytes(b"")
    partial.chmod(0o600)
    before = immutable_tree_snapshot(state)

    with pytest.raises(
        KIT.BootstrapSourceError,
        match="fase pós-exchange existe antes da troca",
    ):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
        )

    assert immutable_tree_snapshot(state) == before
    assert not (state / KIT.INTENT_NAME).exists()


def test_successor_used_rejects_corrupt_previous_without_mutation(
    secure_tmp_path: Path,
    monkeypatch,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    predecessor_intent = prepare_pre_publisher_source_state(
        incoming,
        state,
        calls,
    )
    publisher_intent_sha256 = "7" * 64
    monkeypatch.setattr(
        KIT,
        "validate_fixed_predecessor_publisher_state",
        lambda **_kwargs: publisher_intent_sha256,
    )
    replace_signed_release(
        incoming,
        api_sha="e" * 40,
        required_ancestors=("a" * 40,),
    )
    predecessor = (
        predecessor_intent["kit_id"],
        predecessor_intent["controller_sha"],
        publisher_intent_sha256,
    )
    assert (
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
        )
        == "installed"
    )
    successor_intent = json.loads((state / KIT.INTENT_NAME).read_text())
    previous = state / (
        KIT.PREVIOUS_PREFIX + successor_intent["kit_id"]
    )
    release = previous / "RELEASE_SHA"
    previous.chmod(0o755)
    release.chmod(0o644)
    release.write_bytes(b"corrupt previous\n")
    release.chmod(0o444)
    previous.chmod(0o555)
    before = immutable_tree_snapshot(state)

    with pytest.raises(
        KIT.BootstrapSourceError,
        match="anterior retida diverge",
    ):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
        )

    assert immutable_tree_snapshot(state) == before


@pytest.mark.skipif(
    not hasattr(os, "fork"),
    reason="fault harness exige fork",
)
@pytest.mark.parametrize(
    "boundary",
    (
        "after_source_supersede",
        "after_source_supersede_intent",
        "after_source_supersede_retained",
    ),
)
def test_successor_replays_after_real_sigkill(
    secure_tmp_path: Path,
    monkeypatch,
    boundary: str,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    predecessor_intent = prepare_pre_publisher_source_state(
        incoming,
        state,
        calls,
    )
    publisher_intent_sha256 = "7" * 64
    monkeypatch.setattr(
        KIT,
        "validate_fixed_predecessor_publisher_state",
        lambda **_kwargs: publisher_intent_sha256,
    )
    replace_signed_release(
        incoming,
        api_sha="e" * 40,
        required_ancestors=("a" * 40,),
    )
    predecessor = (
        predecessor_intent["kit_id"],
        predecessor_intent["controller_sha"],
        publisher_intent_sha256,
    )
    child = os.fork()
    if child == 0:
        def kill_at(event: str) -> None:
            if event == boundary:
                os.kill(os.getpid(), 9)

        try:
            install(
                incoming,
                state,
                [],
                predecessor=predecessor,
                fault=kill_at,
            )
        except BaseException:
            os._exit(92)
        os._exit(91)
    _, status = os.waitpid(child, 0)
    assert os.WIFSIGNALED(status)
    assert os.WTERMSIG(status) == 9
    assert (
        install(
            incoming,
            state,
            [],
            predecessor=predecessor,
        )
        == "installed"
    )


@pytest.mark.parametrize(
    "tamper",
    (
        "missing-required-ancestor",
        "wrong-controller",
        "wrong-publisher-intent",
        "predecessor-used",
        "rollback",
    ),
)
def test_successor_rejects_unbound_or_non_pre_publisher_predecessor(
    secure_tmp_path: Path,
    monkeypatch,
    tamper: str,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    predecessor_intent = prepare_pre_publisher_source_state(
        incoming,
        state,
        calls,
    )
    publisher_intent_sha256 = "7" * 64
    monkeypatch.setattr(
        KIT,
        "validate_fixed_predecessor_publisher_state",
        lambda **_kwargs: publisher_intent_sha256,
    )
    ancestors = (
        ("0" * 40,)
        if tamper == "missing-required-ancestor"
        else ("a" * 40,)
    )
    replace_signed_release(
        incoming,
        api_sha="e" * 40,
        required_ancestors=ancestors,
    )
    predecessor = [
        predecessor_intent["kit_id"],
        predecessor_intent["controller_sha"],
        publisher_intent_sha256,
    ]
    if tamper == "wrong-controller":
        predecessor[1] = "9" * 40
    elif tamper == "wrong-publisher-intent":
        predecessor[2] = "9" * 64
    elif tamper == "predecessor-used":
        (state / KIT.USED_NAME).write_bytes(
            KIT.marker_payload(
                kit_id=predecessor_intent["kit_id"],
                phase="used",
                old_digest=predecessor_intent[
                    "old_source_tree_sha256"
                ],
                new_digest=predecessor_intent[
                    "new_source_tree_sha256"
                ],
            )
        )
        (state / KIT.USED_NAME).chmod(0o444)
    elif tamper == "rollback":
        previous = state / (
            KIT.PREVIOUS_PREFIX + predecessor_intent["kit_id"]
        )
        previous.chmod(0o755)
        old = previous / "old.txt"
        old.chmod(0o644)
        old.write_bytes(b"tampered rollback\n")
        old.chmod(0o444)
        previous.chmod(0o555)
    with pytest.raises(KIT.BootstrapSourceError):
        install(
            incoming,
            state,
            calls,
            predecessor=tuple(predecessor),
        )
    assert not (state / KIT.SUPERSEDE_NAME).exists()
    assert (state / KIT.INTENT_NAME).is_file()


@pytest.mark.parametrize(
    "publisher_state",
    ("used", "previous", "exchanged", "partial"),
)
def test_successor_prevalidates_exact_publisher_state_before_source_mutation(
    secure_tmp_path: Path,
    monkeypatch,
    publisher_state: str,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    predecessor_intent = prepare_pre_publisher_source_state(
        incoming,
        state,
        calls,
    )
    control, publisher_intent_sha256 = prepare_fixed_publisher_state(
        secure_tmp_path / "publisher"
    )
    monkeypatch.setattr(KIT, "CONTROL_ROOT", control)
    staging = control / ".staging"
    intent = json.loads(
        (staging / KIT.PUBLISHER_INTENT_NAME).read_text()
    )
    if publisher_state == "used":
        used = dict(intent)
        used["phase"] = "used"
        path = staging / KIT.PUBLISHER_USED_NAME
        path.write_bytes(canonical(used))
        path.chmod(0o400)
    elif publisher_state == "previous":
        previous = staging / intent["previous_name"]
        previous.mkdir(mode=0o555)
    elif publisher_state == "exchanged":
        temporary = staging / "test.exchange"
        final = control / "bootstrap"
        candidate = staging / KIT.PUBLISHER_CANDIDATE_NAME
        final.chmod(0o755)
        candidate.chmod(0o755)
        final.rename(temporary)
        candidate.rename(final)
        temporary.rename(candidate)
        final.chmod(0o555)
        candidate.chmod(0o555)
    else:
        partial = staging / f"{KIT.PUBLISHER_USED_NAME}.installing"
        partial.write_bytes(b"partial\n")
        partial.chmod(0o400)
    replace_signed_release(
        incoming,
        api_sha="e" * 40,
        required_ancestors=("a" * 40,),
    )
    predecessor = (
        predecessor_intent["kit_id"],
        predecessor_intent["controller_sha"],
        publisher_intent_sha256,
    )
    with pytest.raises(KIT.BootstrapSourceError):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
        )
    assert (
        state / KIT.SOURCE_NAME / "RELEASE_SHA"
    ).read_text() == "a" * 40 + "\n"
    assert not (state / KIT.SUPERSEDE_NAME).exists()
    assert (state / KIT.INTENT_NAME).is_file()


def test_successor_revalidates_publisher_after_supersede_crash_before_archive(
    secure_tmp_path: Path,
    monkeypatch,
) -> None:
    incoming, state, calls = fixture(secure_tmp_path)
    predecessor_intent = prepare_pre_publisher_source_state(
        incoming,
        state,
        calls,
    )
    control, publisher_intent_sha256 = prepare_fixed_publisher_state(
        secure_tmp_path / "publisher"
    )
    monkeypatch.setattr(KIT, "CONTROL_ROOT", control)
    replace_signed_release(
        incoming,
        api_sha="e" * 40,
        required_ancestors=("a" * 40,),
    )
    predecessor = (
        predecessor_intent["kit_id"],
        predecessor_intent["controller_sha"],
        publisher_intent_sha256,
    )

    def stop_after_supersede(event: str) -> None:
        if event == "after_source_supersede":
            raise RuntimeError("stop after source supersede")

    with pytest.raises(RuntimeError, match="stop after source"):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
            fault=stop_after_supersede,
        )
    publisher_intent = json.loads(
        (
            control / ".staging" / KIT.PUBLISHER_INTENT_NAME
        ).read_text()
    )
    publisher_used = dict(publisher_intent)
    publisher_used["phase"] = "used"
    used_path = control / ".staging" / KIT.PUBLISHER_USED_NAME
    used_path.write_bytes(canonical(publisher_used))
    used_path.chmod(0o400)
    with pytest.raises(KIT.BootstrapSourceError):
        install(
            incoming,
            state,
            calls,
            predecessor=predecessor,
        )
    assert (
        state / KIT.SOURCE_NAME / "RELEASE_SHA"
    ).read_text() == "a" * 40 + "\n"
    assert (state / KIT.INTENT_NAME).is_file()
    assert not (
        state
        / (
            "bootstrap-source-kit.intent.superseded."
            f"{predecessor[0]}.json"
        )
    ).exists()


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


def test_post_publisher_successor_archives_terminal_evidence_and_replays(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_post_publisher_fixture(secure_tmp_path, monkeypatch)
    )
    observed_bootstrap_digests: list[str] = []
    predecessor = os.open(
        control / "bootstrap",
        os.O_RDONLY | os.O_DIRECTORY,
    )
    try:
        predecessor_digest = KIT.protected_bootstrap_tree_digest(
            predecessor,
            uid=os.getuid(),
            gid=os.getgid(),
        )
    finally:
        os.close(predecessor)

    assert (
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            publisher_callback=lambda: publish_fake_successor_bootstrap(
                control
            ),
            quiescence_callback=observed_bootstrap_digests.append,
        )
        == "installed"
    )
    assert calls == [
        "signature",
        "signature",
        "signature",
        "quiescence",
        "publisher",
    ]
    predecessor_kit = bindings[0]
    assert (state / KIT.POST_PUBLISHER_SUPERSEDE_NAME).is_file()
    assert (state / KIT.SUPERSEDE_NAME).is_file()
    assert (
        state
        / f"bootstrap-source-kit.used.superseded."
        f"{predecessor_kit}.json"
    ).is_file()
    for kind in ("used", "intent", "previous"):
        assert (
            control
            / ".staging"
            / KIT.post_publisher_archive_name(kind, predecessor_kit)
        ).exists()
    assert (state / KIT.USED_NAME).is_file()
    successor = os.open(
        control / "bootstrap",
        os.O_RDONLY | os.O_DIRECTORY,
    )
    try:
        successor_digest = KIT.protected_bootstrap_tree_digest(
            successor,
            uid=os.getuid(),
            gid=os.getgid(),
        )
    finally:
        os.close(successor)
    assert observed_bootstrap_digests == [predecessor_digest]

    calls.clear()
    assert (
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            quiescence_callback=observed_bootstrap_digests.append,
        )
        == "already-installed"
    )
    assert calls == [
        "signature",
        "signature",
        "signature",
        "quiescence",
    ]
    assert observed_bootstrap_digests == [
        predecessor_digest,
        successor_digest,
    ]


def test_post_stage_successor_quarantines_exact_schema6_bundle_and_replays(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_post_publisher_fixture(secure_tmp_path, monkeypatch)
    )
    post_stage = stage_predecessor_schema6_bundle(
        incoming,
        state,
        control,
    )

    assert (
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            post_stage=post_stage,
            publisher_callback=lambda: publish_fake_successor_bootstrap(
                control
            ),
        )
        == "installed"
    )
    assert not any((control / KIT.BUNDLES_NAME).iterdir())
    archive = (
        control
        / ".staging"
        / KIT.post_stage_bundle_archive_name(post_stage[0])
    )
    assert archive.is_dir()
    journal = json.loads(
        (state / KIT.POST_PUBLISHER_SUPERSEDE_NAME).read_text()
    )
    assert journal["schema_version"] == 3
    assert journal["staged_bundle_id"] == post_stage[0]
    assert journal["staged_bundle_tree_sha256"] == post_stage[1]

    before = immutable_tree_snapshot(control)
    calls.clear()
    assert (
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            post_stage=post_stage,
        )
        == "already-installed"
    )
    assert immutable_tree_snapshot(control) == before


def test_post_stage_signed_inspection_is_canonical_and_read_only(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_post_publisher_fixture(secure_tmp_path, monkeypatch)
    )
    bundle_id, tree_digest = stage_predecessor_schema6_bundle(
        incoming,
        state,
        control,
    )
    state_before = immutable_tree_snapshot(state)
    control_before = immutable_tree_snapshot(control)
    raw = inspect_post_stage(
        incoming,
        state,
        bindings,
        bundle_id,
        calls,
    )
    value = json.loads(raw)

    assert raw == canonical(value)
    assert value["bundle_id"] == bundle_id
    assert value["bundle_tree_sha256"] == tree_digest
    assert calls == [
        "signature",
        "signature",
        "signature",
        "quiescence",
    ]
    assert immutable_tree_snapshot(state) == state_before
    assert immutable_tree_snapshot(control) == control_before


def test_post_stage_signed_inspection_rejects_tamper_without_mutation(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_post_publisher_fixture(secure_tmp_path, monkeypatch)
    )
    bundle_id, _tree_digest = stage_predecessor_schema6_bundle(
        incoming,
        state,
        control,
    )
    target = (
        control
        / KIT.BUNDLES_NAME
        / bundle_id
        / KIT.ATTESTATION_NAME
    )
    target.chmod(0o600)
    target.write_bytes(target.read_bytes() + b" ")
    target.chmod(0o444)
    state_before = immutable_tree_snapshot(state)
    control_before = immutable_tree_snapshot(control)

    with pytest.raises(
        KIT.BootstrapSourceError,
        match="atestado post-stage diverge",
    ):
        inspect_post_stage(
            incoming,
            state,
            bindings,
            bundle_id,
            calls,
        )
    assert immutable_tree_snapshot(state) == state_before
    assert immutable_tree_snapshot(control) == control_before


def test_post_stage_successor_recovers_sigkill_after_bundle_quarantine(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_post_publisher_fixture(secure_tmp_path, monkeypatch)
    )
    post_stage = stage_predecessor_schema6_bundle(
        incoming,
        state,
        control,
    )

    def stop(event: str) -> None:
        if event == "after_post_publisher_staged_bundle_archive":
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            post_stage=post_stage,
            fault=stop,
        )
    assert not any((control / KIT.BUNDLES_NAME).iterdir())

    calls.clear()
    assert (
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            post_stage=post_stage,
            publisher_callback=lambda: publish_fake_successor_bootstrap(
                control
            ),
        )
        == "installed"
    )


def test_post_stage_rejects_wrong_tree_binding_without_mutation(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_post_publisher_fixture(secure_tmp_path, monkeypatch)
    )
    bundle_id, _tree_digest = stage_predecessor_schema6_bundle(
        incoming,
        state,
        control,
    )
    state_before = immutable_tree_snapshot(state)
    control_before = immutable_tree_snapshot(control)

    with pytest.raises(
        KIT.BootstrapSourceError,
        match="árvore do bundle post-stage diverge",
    ):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            post_stage=(bundle_id, "9" * 64),
        )
    assert immutable_tree_snapshot(state) == state_before
    assert immutable_tree_snapshot(control) == control_before


def test_post_stage_rejects_hardlink_race_between_lstat_and_open(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_post_publisher_fixture(secure_tmp_path, monkeypatch)
    )
    post_stage = stage_predecessor_schema6_bundle(
        incoming,
        state,
        control,
    )
    target = (
        control
        / KIT.BUNDLES_NAME
        / post_stage[0]
        / "empty-package-marker"
    )
    target_inode = target.stat().st_ino
    real_fstat = os.fstat

    def raced_fstat(descriptor: int) -> os.stat_result:
        observed = real_fstat(descriptor)
        if observed.st_ino != target_inode:
            return observed
        fields = list(observed)
        fields[3] = 2
        return os.stat_result(fields)

    state_before = immutable_tree_snapshot(state)
    control_before = immutable_tree_snapshot(control)
    monkeypatch.setattr(KIT.os, "fstat", raced_fstat)
    with pytest.raises(
        KIT.BootstrapSourceError,
        match="arquivo regular protegido",
    ):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            post_stage=post_stage,
        )
    assert immutable_tree_snapshot(state) == state_before
    assert immutable_tree_snapshot(control) == control_before


@pytest.mark.parametrize(
    "residue",
    (
        "active-and-archive",
        "extra-bundle",
        "unknown-quarantine",
    ),
)
def test_post_stage_rejects_collision_or_foreign_state_without_mutation(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    residue: str,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_post_publisher_fixture(secure_tmp_path, monkeypatch)
    )
    post_stage = stage_predecessor_schema6_bundle(
        incoming,
        state,
        control,
    )
    active = control / KIT.BUNDLES_NAME / post_stage[0]
    archive = (
        control
        / ".staging"
        / KIT.post_stage_bundle_archive_name(post_stage[0])
    )
    if residue in {"active-and-archive", "unknown-quarantine"}:
        shutil.copytree(active, archive, symlinks=True)
        if residue == "unknown-quarantine":
            active.chmod(0o700)
            shutil.rmtree(active)
    else:
        bundles = control / KIT.BUNDLES_NAME
        bundles.chmod(0o700)
        foreign = bundles / ("9" * 64)
        foreign.mkdir(mode=0o555)
        bundles.chmod(0o711)
    state_before = immutable_tree_snapshot(state)
    control_before = immutable_tree_snapshot(control)

    with pytest.raises(KIT.BootstrapSourceError):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            post_stage=(
                None if residue == "unknown-quarantine" else post_stage
            ),
        )
    assert immutable_tree_snapshot(state) == state_before
    assert immutable_tree_snapshot(control) == control_before


def test_post_stage_rejects_bundle_id_not_bound_by_source_intent(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_post_publisher_fixture(secure_tmp_path, monkeypatch)
    )
    _bundle_id, tree_digest = stage_predecessor_schema6_bundle(
        incoming,
        state,
        control,
    )
    state_before = immutable_tree_snapshot(state)
    control_before = immutable_tree_snapshot(control)
    with pytest.raises(
        KIT.BootstrapSourceError,
        match="não pertence ao source predecessor",
    ):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            post_stage=("9" * 64, tree_digest),
        )
    assert immutable_tree_snapshot(state) == state_before
    assert immutable_tree_snapshot(control) == control_before


def test_nested_post_stage_journal_binds_both_histories_and_bundle(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_nested_post_publisher_fixture(
            secure_tmp_path,
            monkeypatch,
        )
    )
    post_stage = stage_predecessor_schema6_bundle(
        incoming,
        state,
        control,
        required_ancestors=("a" * 40,),
    )

    assert (
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            post_stage=post_stage,
            publisher_callback=lambda: publish_fake_successor_bootstrap(
                control
            ),
        )
        == "installed"
    )
    journal = json.loads(
        (state / KIT.POST_PUBLISHER_SUPERSEDE_NAME).read_text()
    )
    assert journal["schema_version"] == 4
    assert journal["staged_bundle_id"] == post_stage[0]
    assert "nested_source_supersede_sha256" in journal
    assert "nested_publisher_supersede_sha256" in journal
    before = immutable_tree_snapshot(control)
    calls.clear()
    assert (
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            post_stage=post_stage,
        )
        == "already-installed"
    )
    assert immutable_tree_snapshot(control) == before


@pytest.mark.skipif(
    not hasattr(os, "fork"),
    reason="fault harness exige fork",
)
def test_nested_post_stage_recovers_sigkill_after_quarantine(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, _calls, bindings, control = (
        prepare_nested_post_publisher_fixture(
            secure_tmp_path,
            monkeypatch,
        )
    )
    post_stage = stage_predecessor_schema6_bundle(
        incoming,
        state,
        control,
        required_ancestors=("a" * 40,),
    )
    child = os.fork()
    if child == 0:
        def kill_at(event: str) -> None:
            if event == "after_post_publisher_staged_bundle_archive":
                os.kill(os.getpid(), signal.SIGKILL)

        try:
            install(
                incoming,
                state,
                [],
                post_predecessor=bindings,
                post_stage=post_stage,
                fault=kill_at,
            )
        except BaseException:
            os._exit(92)
        os._exit(91)
    _, status = os.waitpid(child, 0)
    assert os.WIFSIGNALED(status)
    assert os.WTERMSIG(status) == signal.SIGKILL
    assert not any((control / KIT.BUNDLES_NAME).iterdir())

    assert (
        install(
            incoming,
            state,
            [],
            post_predecessor=bindings,
            post_stage=post_stage,
            publisher_callback=lambda: publish_fake_successor_bootstrap(
                control
            ),
        )
        == "installed"
    )


def test_post_publisher_successor_preserves_nested_supersede_and_replays(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_nested_post_publisher_fixture(
            secure_tmp_path,
            monkeypatch,
        )
    )
    source_supersede = json.loads(
        (state / KIT.SUPERSEDE_NAME).read_text()
    )
    nested_source_kit = source_supersede["predecessor_kit_id"]
    publisher_supersede = json.loads(
        (
            control / ".staging" / KIT.PUBLISHER_SUPERSEDE_NAME
        ).read_text()
    )

    assert (
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            publisher_callback=lambda: publish_fake_successor_bootstrap(
                control
            ),
        )
        == "installed"
    )

    current_source_kit = bindings[0]
    for name in (
        KIT.nested_source_archive_name(
            "supersede",
            current_source_kit,
        ),
        *(
            KIT.nested_source_archive_name(
                phase,
                current_source_kit,
            )
            for phase in ("intent", "prepared", "exchanged", "retained")
        ),
        KIT.nested_source_archive_name(
            "previous",
            current_source_kit,
        ),
    ):
        assert (state / name).exists()
    assert not (
        state / f"{KIT.PREVIOUS_PREFIX}{nested_source_kit}"
    ).exists()
    for kind in ("supersede", "intent", "candidate"):
        assert (
            control
            / ".staging"
            / KIT.nested_publisher_archive_name(
                kind,
                current_source_kit,
            )
        ).exists()
    assert not (
        control
        / ".staging"
        / publisher_supersede["retained_intent_name"]
    ).exists()
    assert not (
        control
        / ".staging"
        / publisher_supersede["retained_candidate_name"]
    ).exists()

    state_before = immutable_tree_snapshot(state)
    control_before = immutable_tree_snapshot(control)
    calls.clear()
    assert (
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
        )
        == "already-installed"
    )
    assert immutable_tree_snapshot(state) == state_before
    assert immutable_tree_snapshot(control) == control_before


def test_nested_post_publisher_resumes_valid_partial_recovery_journal(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_nested_post_publisher_fixture(
            secure_tmp_path,
            monkeypatch,
        )
    )
    partial = (
        state
        / "bootstrap-source-kit.post-publisher-supersede."
        f"{signed_release_kit_id(incoming)}.installing"
    )
    partial.write_bytes(b'{"contract":')
    partial.chmod(0o600)

    assert (
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            publisher_callback=lambda: publish_fake_successor_bootstrap(
                control
            ),
        )
        == "installed"
    )
    assert not partial.exists()


def test_nested_post_publisher_replay_rejects_another_signed_successor(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, calls, bindings, _control = (
        prepare_nested_post_publisher_fixture(
            secure_tmp_path,
            monkeypatch,
        )
    )

    def stop(event: str) -> None:
        if event == "after_post_publisher_supersede":
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            fault=stop,
        )
    replace_signed_release(
        incoming,
        api_sha="f" * 40,
        required_ancestors=("d" * 40,),
    )
    state_before = immutable_tree_snapshot(state)
    with pytest.raises(
        KIT.BootstrapSourceError,
        match="autoriza|successor|sucessor",
    ):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
        )
    assert immutable_tree_snapshot(state) == state_before


@pytest.mark.parametrize(
    "event",
    (
        "after_nested_source_supersede_archive",
        "after_nested_source_intent_archive",
        "after_nested_source_prepared_archive",
        "after_nested_source_exchanged_archive",
        "after_nested_source_retained_archive",
        "after_nested_source_previous_archive",
        "after_nested_publisher_supersede_archive",
        "after_nested_publisher_candidate_archive",
        "after_nested_publisher_intent_archive",
    ),
)
@pytest.mark.skipif(
    not hasattr(os, "fork"),
    reason="fault harness exige fork",
)
def test_nested_post_publisher_recovers_every_sigkill_boundary(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event: str,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_nested_post_publisher_fixture(
            secure_tmp_path,
            monkeypatch,
        )
    )

    def publish_successor_once() -> None:
        if not (
            control / ".staging" / KIT.PUBLISHER_USED_NAME
        ).exists():
            publish_fake_successor_bootstrap(control)

    child = os.fork()
    if child == 0:
        def kill_at(observed: str) -> None:
            if observed == event:
                os.kill(os.getpid(), signal.SIGKILL)

        try:
            install(
                incoming,
                state,
                [],
                post_predecessor=bindings,
                publisher_callback=publish_successor_once,
                fault=kill_at,
            )
        except BaseException:
            os._exit(92)
        os._exit(91)
    _, status = os.waitpid(child, 0)
    assert os.WIFSIGNALED(status)
    assert os.WTERMSIG(status) == signal.SIGKILL

    calls.clear()
    assert (
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            publisher_callback=publish_successor_once,
        )
        == "installed"
    )


@pytest.mark.parametrize(
    "tamper",
    (
        "source-supersede-noncanonical",
        "source-other-successor",
        "source-phase-content",
        "source-phase-mode",
        "source-previous-content",
        "source-previous-mode",
        "publisher-supersede-noncanonical",
        "publisher-cross-binding",
        "publisher-intent-content",
        "publisher-intent-mode",
        "publisher-candidate-content",
        "publisher-candidate-mode",
        "extra-source-history",
        "extra-publisher-history",
        "missing-source-phase",
        "missing-publisher-intent",
        "missing-publisher-candidate",
        "coexisting-source-archive",
        "coexisting-publisher-archive",
        "partial-journal",
    ),
)
def test_nested_post_publisher_rejects_tamper_without_mutation(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_nested_post_publisher_fixture(
            secure_tmp_path,
            monkeypatch,
        )
    )
    staging = control / ".staging"
    source_supersede_path = state / KIT.SUPERSEDE_NAME
    source_supersede = json.loads(source_supersede_path.read_text())
    nested_source_kit = str(source_supersede["predecessor_kit_id"])
    source_phase = (
        state
        / f"bootstrap-source-kit.retained.superseded."
        f"{nested_source_kit}.json"
    )
    source_previous = (
        state / f"{KIT.PREVIOUS_PREFIX}{nested_source_kit}"
    )
    publisher_supersede_path = (
        staging / KIT.PUBLISHER_SUPERSEDE_NAME
    )
    publisher_supersede = json.loads(
        publisher_supersede_path.read_text()
    )
    publisher_intent = (
        staging / str(publisher_supersede["retained_intent_name"])
    )
    publisher_candidate = (
        staging
        / str(publisher_supersede["retained_candidate_name"])
    )

    def rewrite(path: Path, raw: bytes, mode: int) -> None:
        path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(mode)

    if tamper == "source-supersede-noncanonical":
        rewrite(
            source_supersede_path,
            source_supersede_path.read_bytes().rstrip(b"\n") + b" \n",
            0o444,
        )
    elif tamper == "source-other-successor":
        source_supersede["successor_kit_id"] = "9" * 64
        rewrite(
            source_supersede_path,
            canonical(source_supersede),
            0o444,
        )
    elif tamper == "source-phase-content":
        value = json.loads(source_phase.read_text())
        value["old_source_tree_sha256"] = "9" * 64
        rewrite(source_phase, canonical(value), 0o444)
    elif tamper == "source-phase-mode":
        source_phase.chmod(0o400)
    elif tamper == "source-previous-content":
        source_previous.chmod(0o700)
        child = next(source_previous.iterdir())
        child.chmod(0o600)
        child.write_bytes(b"tampered source rollback\n")
        child.chmod(0o444)
        source_previous.chmod(0o555)
    elif tamper == "source-previous-mode":
        source_previous.chmod(0o700)
    elif tamper == "publisher-supersede-noncanonical":
        rewrite(
            publisher_supersede_path,
            publisher_supersede_path.read_bytes().rstrip(b"\n")
            + b" \n",
            0o400,
        )
    elif tamper == "publisher-cross-binding":
        publisher_supersede["source_successor_kit_id"] = "9" * 64
        rewrite(
            publisher_supersede_path,
            canonical(publisher_supersede),
            0o400,
        )
    elif tamper == "publisher-intent-content":
        value = json.loads(publisher_intent.read_text())
        value["new_tree_sha256"] = "9" * 64
        rewrite(publisher_intent, canonical(value), 0o400)
    elif tamper == "publisher-intent-mode":
        publisher_intent.chmod(0o444)
    elif tamper == "publisher-candidate-content":
        publisher_candidate.chmod(0o700)
        child = publisher_candidate / "version"
        child.chmod(0o600)
        child.write_bytes(b"tampered publisher candidate\n")
        child.chmod(0o444)
        publisher_candidate.chmod(0o555)
    elif tamper == "publisher-candidate-mode":
        publisher_candidate.chmod(0o700)
    elif tamper == "extra-source-history":
        extra = state / (
            "bootstrap-source-kit.intent.superseded."
            f"{'9' * 64}.json"
        )
        extra.write_bytes(b"foreign\n")
        extra.chmod(0o444)
    elif tamper == "extra-publisher-history":
        extra = staging / (
            "bootstrap-upgrade.intent.superseded."
            f"{'9' * 64}.json"
        )
        extra.write_bytes(b"foreign\n")
        extra.chmod(0o400)
    elif tamper == "missing-source-phase":
        source_phase.unlink()
    elif tamper == "missing-publisher-intent":
        publisher_intent.unlink()
    elif tamper == "missing-publisher-candidate":
        publisher_candidate.chmod(0o700)
        for child in publisher_candidate.iterdir():
            child.chmod(0o600)
        shutil.rmtree(publisher_candidate)
    elif tamper == "coexisting-source-archive":
        archive = state / KIT.nested_source_archive_name(
            "supersede",
            bindings[0],
        )
        archive.write_bytes(source_supersede_path.read_bytes())
        archive.chmod(0o444)
    elif tamper == "coexisting-publisher-archive":
        archive = staging / KIT.nested_publisher_archive_name(
            "supersede",
            bindings[0],
        )
        archive.write_bytes(publisher_supersede_path.read_bytes())
        archive.chmod(0o400)
    else:
        successor_kit_id = signed_release_kit_id(incoming)
        partial = (
            state
            / "bootstrap-source-kit.post-publisher-supersede."
            f"{successor_kit_id}.installing"
        )
        partial.write_bytes(b'{"corrupt":')
        partial.chmod(0o600)

    state_before = immutable_tree_snapshot(state)
    control_before = immutable_tree_snapshot(control)
    with pytest.raises(KIT.BootstrapSourceError):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
        )
    assert immutable_tree_snapshot(state) == state_before
    assert immutable_tree_snapshot(control) == control_before


def test_nested_post_publisher_rejects_wrong_owner_without_mutation(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_nested_post_publisher_fixture(
            secure_tmp_path,
            monkeypatch,
        )
    )
    target = (
        control / ".staging" / KIT.PUBLISHER_SUPERSEDE_NAME
    )
    target_inode = target.stat().st_ino
    real_fstat = os.fstat

    def wrong_owner(descriptor: int) -> os.stat_result:
        observed = real_fstat(descriptor)
        if observed.st_ino != target_inode:
            return observed
        fields = list(observed)
        fields[4] = observed.st_uid + 1
        return os.stat_result(fields)

    state_before = immutable_tree_snapshot(state)
    control_before = immutable_tree_snapshot(control)
    monkeypatch.setattr(KIT.os, "fstat", wrong_owner)
    with pytest.raises(
        KIT.BootstrapSourceError,
        match="protegido",
    ):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
        )
    assert immutable_tree_snapshot(state) == state_before
    assert immutable_tree_snapshot(control) == control_before


@pytest.mark.parametrize(
    ("event", "tamper"),
    (
        (
            "after_post_publisher_previous_archive",
            "archive-collision",
        ),
        (
            "after_post_publisher_source_used_archive",
            "out-of-order",
        ),
        (
            "after_nested_source_supersede_archive",
            "source-coexistence",
        ),
        (
            "after_nested_publisher_supersede_archive",
            "publisher-coexistence",
        ),
        (
            "after_post_publisher_supersede",
            "journal-binding",
        ),
    ),
)
def test_nested_post_publisher_replay_rejects_collision_or_coexistence(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event: str,
    tamper: str,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_nested_post_publisher_fixture(
            secure_tmp_path,
            monkeypatch,
        )
    )

    def stop(observed: str) -> None:
        if observed == event:
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            fault=stop,
        )

    if tamper == "archive-collision":
        collision = state / KIT.nested_source_archive_name(
            "supersede",
            bindings[0],
        )
        collision.write_bytes(b'{"foreign":true}\n')
        collision.chmod(0o444)
    elif tamper == "out-of-order":
        (state / KIT.SUPERSEDE_NAME).rename(
            state
            / KIT.nested_source_archive_name(
                "supersede",
                bindings[0],
            )
        )
    elif tamper == "source-coexistence":
        archived = state / KIT.nested_source_archive_name(
            "supersede",
            bindings[0],
        )
        duplicate = state / KIT.SUPERSEDE_NAME
        duplicate.write_bytes(archived.read_bytes())
        duplicate.chmod(0o444)
    elif tamper == "publisher-coexistence":
        staging = control / ".staging"
        archived = staging / KIT.nested_publisher_archive_name(
            "supersede",
            bindings[0],
        )
        duplicate = staging / KIT.PUBLISHER_SUPERSEDE_NAME
        duplicate.write_bytes(archived.read_bytes())
        duplicate.chmod(0o400)
    else:
        journal = state / KIT.POST_PUBLISHER_SUPERSEDE_NAME
        value = json.loads(journal.read_text())
        value["nested_publisher_supersede_sha256"] = "9" * 64
        journal.chmod(0o600)
        journal.write_bytes(canonical(value))
        journal.chmod(0o444)

    state_before = immutable_tree_snapshot(state)
    control_before = immutable_tree_snapshot(control)
    with pytest.raises(KIT.BootstrapSourceError):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
        )
    assert immutable_tree_snapshot(state) == state_before
    assert immutable_tree_snapshot(control) == control_before


def test_nested_replay_rejects_different_active_intent_after_archive(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_nested_post_publisher_fixture(
            secure_tmp_path,
            monkeypatch,
        )
    )

    def stop(event: str) -> None:
        if event == "after_nested_source_intent_archive":
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            fault=stop,
        )

    nested_supersede = json.loads(
        (
            state
            / KIT.nested_source_archive_name(
                "supersede",
                bindings[0],
            )
        ).read_text()
    )
    active_intent = state / (
        "bootstrap-source-kit.intent.superseded."
        f"{nested_supersede['predecessor_kit_id']}.json"
    )
    active_intent.write_bytes(b'{"different":true}\n')
    active_intent.chmod(0o444)

    state_before = immutable_tree_snapshot(state)
    control_before = immutable_tree_snapshot(control)
    with pytest.raises(
        KIT.BootstrapSourceError,
        match="coexiste",
    ):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
        )
    assert immutable_tree_snapshot(state) == state_before
    assert immutable_tree_snapshot(control) == control_before


@pytest.mark.parametrize(
    "event",
    (
        "after_post_publisher_supersede",
        "after_post_publisher_source_used_archive",
        "after_post_publisher_used_archive",
        "after_post_publisher_intent_archive",
        "after_post_publisher_previous_archive",
        "after_post_publisher_standard_supersede",
        "after_source_supersede_intent",
        "after_source_supersede_prepared",
        "after_source_supersede_exchanged",
        "after_source_supersede_retained",
        "after_intent",
        "after_candidate",
        "after_exchange",
        "after_retention_rename",
        "before_publisher",
        "after_publisher",
    ),
)
@pytest.mark.skipif(
    not hasattr(os, "fork"),
    reason="fault harness exige fork",
)
def test_post_publisher_successor_recovers_every_sigkill_boundary(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event: str,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_post_publisher_fixture(secure_tmp_path, monkeypatch)
    )

    def publish_successor_once() -> None:
        if not (
            control / ".staging" / KIT.PUBLISHER_USED_NAME
        ).exists():
            publish_fake_successor_bootstrap(control)

    child = os.fork()
    if child == 0:
        def kill_at(observed: str) -> None:
            if observed == event:
                os.kill(os.getpid(), signal.SIGKILL)

        try:
            install(
                incoming,
                state,
                [],
                post_predecessor=bindings,
                publisher_callback=publish_successor_once,
                fault=kill_at,
            )
        except BaseException:
            os._exit(92)
        os._exit(91)
    _, status = os.waitpid(child, 0)
    assert os.WIFSIGNALED(status)
    assert os.WTERMSIG(status) == signal.SIGKILL
    calls.clear()
    assert (
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            publisher_callback=publish_successor_once,
        )
        == "installed"
    )


@pytest.mark.parametrize(
    "residue",
    (
        "current",
        "bundle",
        "bootstrap-release",
        "release-state",
        "activation",
        "activation-epoch",
        "consumed",
    ),
)
def test_post_publisher_rejects_any_pre_stage_residue_without_mutation(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    residue: str,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_post_publisher_fixture(secure_tmp_path, monkeypatch)
    )
    if residue == "current":
        (control / "current").symlink_to("bootstrap")
    elif residue == "bundle":
        (control / KIT.BUNDLES_NAME / ("f" * 64)).mkdir()
    elif residue == "consumed":
        (state / KIT.BOOTSTRAP_CONSUMED_NAME).write_bytes(b"used\n")
    else:
        paths = {
            "bootstrap-release": KIT.BOOTSTRAP_RELEASE_MARKER,
            "release-state": KIT.RELEASE_STATE_MARKER,
            "activation": KIT.ACTIVATION_JOURNAL,
            "activation-epoch": KIT.ACTIVATION_EPOCH_MARKER,
        }
        path = paths[residue]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"foreign\n")
    before = immutable_tree_snapshot(state)
    with pytest.raises(
        KIT.BootstrapSourceError,
        match="pré-stage|current|bundle|marker|activation|consumption",
    ):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
        )
    assert immutable_tree_snapshot(state) == before


@pytest.mark.parametrize("binding_index", range(6))
def test_post_publisher_rejects_mixed_external_binding_without_mutation(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    binding_index: int,
) -> None:
    incoming, state, calls, bindings, _control = (
        prepare_post_publisher_fixture(secure_tmp_path, monkeypatch)
    )
    tampered = list(bindings)
    tampered[binding_index] = (
        "9" * 40 if binding_index == 1 else "9" * 64
    )
    before = immutable_tree_snapshot(state)
    with pytest.raises(KIT.BootstrapSourceError):
        install(
            incoming,
            state,
            calls,
            post_predecessor=tuple(tampered),
        )
    assert immutable_tree_snapshot(state) == before


def test_post_publisher_rejects_duplicate_predecessor_used_after_archive(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, calls, bindings, _control = (
        prepare_post_publisher_fixture(secure_tmp_path, monkeypatch)
    )

    def stop(event: str) -> None:
        if event == "after_post_publisher_source_used_archive":
            raise RuntimeError("SIGKILL")

    with pytest.raises(RuntimeError, match="SIGKILL"):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            fault=stop,
        )
    archived = (
        state
        / f"bootstrap-source-kit.used.superseded."
        f"{bindings[0]}.json"
    )
    duplicate = state / KIT.USED_NAME
    duplicate.write_bytes(archived.read_bytes())
    duplicate.chmod(0o444)
    before = immutable_tree_snapshot(state)
    with pytest.raises(KIT.BootstrapSourceError, match="coexiste"):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
        )
    assert immutable_tree_snapshot(state) == before


def test_post_publisher_replay_rejects_unknown_signed_successor(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, calls, bindings, _control = (
        prepare_post_publisher_fixture(secure_tmp_path, monkeypatch)
    )

    def stop(event: str) -> None:
        if event == "after_post_publisher_supersede":
            raise RuntimeError("SIGKILL")

    with pytest.raises(RuntimeError, match="SIGKILL"):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            fault=stop,
        )
    replace_signed_release(
        incoming,
        api_sha="e" * 40,
        required_ancestors=("a" * 40,),
    )
    before = immutable_tree_snapshot(state)
    with pytest.raises(
        KIT.BootstrapSourceError,
        match="autoriza|successor|sucessor",
    ):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
        )
    assert immutable_tree_snapshot(state) == before


def test_post_publisher_terminal_replay_rejects_another_signed_successor(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_post_publisher_fixture(secure_tmp_path, monkeypatch)
    )
    assert (
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            publisher_callback=lambda: publish_fake_successor_bootstrap(
                control
            ),
        )
        == "installed"
    )
    replace_signed_release(
        incoming,
        api_sha="e" * 40,
        required_ancestors=("a" * 40,),
    )
    state_before = immutable_tree_snapshot(state)
    control_before = immutable_tree_snapshot(control)
    with pytest.raises(
        KIT.BootstrapSourceError,
        match="autoriza|successor|sucessor",
    ):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
        )
    assert immutable_tree_snapshot(state) == state_before
    assert immutable_tree_snapshot(control) == control_before


@pytest.mark.parametrize(
    "event",
    (
        "after_post_publisher_supersede",
        "after_post_publisher_source_used_archive",
        "after_post_publisher_used_archive",
        "after_post_publisher_intent_archive",
        "after_post_publisher_previous_archive",
        "after_post_publisher_standard_supersede",
    ),
)
@pytest.mark.parametrize("binding_index", range(6))
def test_post_publisher_partial_retry_rejects_every_mixed_binding(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event: str,
    binding_index: int,
) -> None:
    incoming, state, calls, bindings, control = (
        prepare_post_publisher_fixture(secure_tmp_path, monkeypatch)
    )

    def stop(observed: str) -> None:
        if observed == event:
            raise RuntimeError(f"SIGKILL:{event}")

    with pytest.raises(RuntimeError, match="SIGKILL"):
        install(
            incoming,
            state,
            calls,
            post_predecessor=bindings,
            fault=stop,
        )
    tampered = list(bindings)
    tampered[binding_index] = (
        "9" * 40 if binding_index == 1 else "9" * 64
    )
    state_before = immutable_tree_snapshot(state)
    control_before = immutable_tree_snapshot(control)
    with pytest.raises(KIT.BootstrapSourceError):
        install(
            incoming,
            state,
            calls,
            post_predecessor=tuple(tampered),
        )
    assert immutable_tree_snapshot(state) == state_before
    assert immutable_tree_snapshot(control) == control_before


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


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "memfd_create"),
    reason="requires Linux sealed memfd",
)
@pytest.mark.parametrize("outcome", ("success", "unknown-unit"))
def test_post_publisher_runs_only_signed_incoming_quiescence_memfd(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
) -> None:
    incoming, _state, _calls = fixture(secure_tmp_path)
    archive = next(incoming.glob("tratto-control-ops-*.tar.gz"))
    archive.chmod(0o600)
    if outcome == "success":
        verifier = (
            b"print('stack Control totalmente parada e sem "
            b"concorrencia systemd'.replace('concorrencia', "
            b"'concorr\\u00eancia'))\n"
        )
    else:
        verifier = (
            b"raise SystemExit('preflight bootstrap Control recusado: "
            b"unit Fleet futura desconhecida')\n"
        )
    build_archive(
        archive,
        "a" * 40,
        quiescence_payload=verifier,
    )
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
    execution = os.open(incoming / KIT.HELPER_NAME, os.O_RDONLY)
    inputs = KIT.open_and_validate_inputs(
        incoming,
        uid=os.getuid(),
        gid=os.getgid(),
        execution_descriptor=execution,
        expectations=expectations(incoming),
        signature_verifier=lambda *_args: None,
    )
    lock_descriptor = -1
    try:
        inventory = KIT.validate_ops_archive(
            inputs.archive_descriptor,
            inputs.archive_info,
            inputs.binding,
        )
        monkeypatch.setattr(KIT, "EXPECTED_UID", os.getuid())
        monkeypatch.setattr(KIT, "EXPECTED_GID", os.getgid())
        monkeypatch.setattr(KIT, "PYTHON", Path(sys.executable))
        monkeypatch.setattr(KIT, "SYSTEMCTL", Path("/usr/bin/true"))
        monkeypatch.setattr(
            KIT,
            "STATE_ROOT",
            secure_tmp_path / "forbidden-predecessor",
        )
        control = secure_tmp_path / "quiescence-control"
        current_digest = published_unit_catalog_tree(
            control,
            {
                "tratto-control.slice": b"published slice\n",
                "tratto-control-recovery.service": (
                    b"published recovery\n"
                ),
            },
        )
        monkeypatch.setattr(KIT, "CONTROL_ROOT", control)
        lock_path = secure_tmp_path / "quiescence.lock"
        lock_path.write_bytes(b"")
        lock_path.chmod(0o600)
        lock_descriptor = os.open(lock_path, os.O_RDWR)
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if outcome == "success":
            KIT.run_quiescence_verifier(
                inputs.archive_descriptor,
                inputs.archive_info,
                inventory,
                inputs.binding.ops_sha256,
                lock_descriptor,
                current_digest,
            )
        else:
            with pytest.raises(
                KIT.BootstrapSourceError,
                match="não foi provada",
            ):
                KIT.run_quiescence_verifier(
                    inputs.archive_descriptor,
                    inputs.archive_info,
                    inventory,
                    inputs.binding.ops_sha256,
                    lock_descriptor,
                    current_digest,
                )
    finally:
        if lock_descriptor >= 0:
            os.close(lock_descriptor)
        inputs.close()
        os.close(execution)


def test_quiescence_protocol_is_pre_reload_then_final_with_same_fds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        calls.append((command, kwargs))
        output = (
            b""
            if command[0] == str(KIT.SYSTEMCTL)
            else KIT.QUIESCENCE_SUCCESS
        )
        return subprocess.CompletedProcess(command, 0, output, b"")

    monkeypatch.setattr(KIT.subprocess, "run", run)
    KIT.run_quiescence_protocol(41, 42, 43)

    assert [call[0] for call in calls] == [
        [
            str(KIT.PYTHON),
            "-I",
            "-B",
            "/proc/self/fd/41",
            "--sealed-packaged-unit-catalog-pre-reload-fd",
            "42",
        ],
        [
            str(KIT.SYSTEMCTL),
            "--no-ask-password",
            "daemon-reload",
        ],
        [
            str(KIT.PYTHON),
            "-I",
            "-B",
            "/proc/self/fd/41",
            "--sealed-packaged-unit-catalog-fd",
            "42",
        ],
    ]
    assert calls[0][1]["pass_fds"] == (41, 42, 43)
    assert calls[1][1]["pass_fds"] == (43,)
    assert calls[2][1]["pass_fds"] == (41, 42, 43)
    for _command, arguments in calls:
        environment = arguments["env"]
        assert isinstance(environment, dict)
        assert environment[KIT.LOCK_FD_ENV] == "43"
        assert environment[KIT.LOCK_HELD_ENV] == "1"


@pytest.mark.parametrize(
    ("failure", "expected_calls", "message"),
    (
        ("pre", 1, "pré-reload"),
        ("reload", 2, "daemon-reload"),
    ),
)
def test_quiescence_protocol_short_circuits_before_final_on_failure(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    expected_calls: int,
    message: str,
) -> None:
    calls: list[list[str]] = []

    def run(
        command: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        is_reload = command[0] == str(KIT.SYSTEMCTL)
        should_fail = (
            failure == "pre" and len(calls) == 1
        ) or (failure == "reload" and is_reload)
        return subprocess.CompletedProcess(
            command,
            78 if should_fail else 0,
            b"" if is_reload else KIT.QUIESCENCE_SUCCESS,
            b"controlled failure\n" if should_fail else b"",
        )

    monkeypatch.setattr(KIT.subprocess, "run", run)
    with pytest.raises(KIT.BootstrapSourceError, match=message):
        KIT.run_quiescence_protocol(51, 52, 53)
    assert len(calls) == expected_calls
    assert not any(
        "--sealed-packaged-unit-catalog-fd" in command
        for command in calls
    )


def test_fork_guardian_retains_same_lock_after_parent_sigkill(
    secure_tmp_path: Path,
) -> None:
    lock_directory = secure_tmp_path / "guardian-lock"
    lock_directory.mkdir(mode=0o700)
    lock_path = lock_directory / KIT.LOCK_NAME
    lock_path.write_bytes(b"")
    lock_path.chmod(0o600)
    ready_reader, ready_writer = os.pipe()
    release_reader, release_writer = os.pipe()
    parent = os.fork()
    if parent == 0:
        os.close(ready_reader)
        os.close(release_writer)
        try:
            lock = KIT.acquire_fixed_deploy_lock(
                uid=os.getuid(),
                gid=os.getgid(),
                lock_directory=lock_directory,
            )

            def held_action() -> None:
                os.write(ready_writer, b"ready\n")
                if os.read(release_reader, 1) != b"x":
                    raise RuntimeError("release inválido")

            KIT.run_fork_guardian(lock, held_action)
        except BaseException:
            os._exit(78)
        os._exit(0)
    os.close(ready_writer)
    os.close(release_reader)
    acquired = -1
    try:
        assert os.read(ready_reader, len(b"ready\n")) == b"ready\n"
        os.kill(parent, signal.SIGKILL)
        waited, status = os.waitpid(parent, 0)
        assert waited == parent
        assert os.WIFSIGNALED(status)
        assert os.WTERMSIG(status) == signal.SIGKILL
        with pytest.raises(
            KIT.BootstrapSourceError,
            match="já está ocupado",
        ):
            KIT.acquire_fixed_deploy_lock(
                uid=os.getuid(),
                gid=os.getgid(),
                lock_directory=lock_directory,
            )
        os.write(release_writer, b"x")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                acquired = KIT.acquire_fixed_deploy_lock(
                    uid=os.getuid(),
                    gid=os.getgid(),
                    lock_directory=lock_directory,
                )
                break
            except KIT.BootstrapSourceError:
                time.sleep(0.01)
        assert acquired >= 0
    finally:
        if acquired >= 0:
            os.close(acquired)
        os.close(release_writer)
        os.close(ready_reader)


def inventory_entry(
    path: str,
    *,
    kind: str = "file",
    mode: int = 0o444,
    size: int = 1,
) -> object:
    payload = b"x" * size
    return KIT.TreeEntry(
        path=path,
        kind=kind,
        mode=mode,
        size=size,
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def published_unit_catalog_tree(
    control: Path,
    units: dict[str, bytes],
) -> str:
    bootstrap = control / "bootstrap"
    systemd = bootstrap / "systemd"
    systemd.mkdir(parents=True, mode=0o700)
    for name, payload in units.items():
        path = systemd / name
        path.write_bytes(payload)
        path.chmod(0o444)
    systemd.chmod(0o555)
    bootstrap.chmod(0o555)
    control.chmod(0o711)
    descriptor = os.open(bootstrap, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return KIT.protected_bootstrap_tree_digest(
            descriptor,
            uid=os.getuid(),
            gid=os.getgid(),
        )
    finally:
        os.close(descriptor)


def test_packaged_unit_names_are_exact_sorted_and_accept_templates() -> None:
    entries = {
        path: inventory_entry(path)
        for path in (
            "systemd/tratto-control.slice",
            "systemd/tratto-control-recovery.service",
            "systemd/tratto-control-web.service",
            "systemd/tratto-control-migrate@.service",
            "scripts/tratto-control-not-a-unit.service",
            "systemd/vendor-unrelated.service",
        )
    }
    inventory = KIT.ArchiveInventory(entries=entries, tree_sha256="0" * 64)

    assert KIT.packaged_unit_names(inventory) == (
        "tratto-control-migrate@.service",
        "tratto-control-recovery.service",
        "tratto-control-web.service",
        "tratto-control.slice",
    )


def test_packaged_units_catalog_hashes_authenticated_published_units(
    secure_tmp_path: Path,
) -> None:
    units = {
        "tratto-control.slice": b"published slice\n",
        "tratto-control-recovery.service": b"published recovery\n",
        "tratto-control-web.service": b"published web\n",
        "vendor-unrelated.service": b"ignored but authenticated\n",
    }
    control = secure_tmp_path / "catalog-control"
    digest = published_unit_catalog_tree(control, units)
    entries = {
        f"systemd/{name}": inventory_entry(f"systemd/{name}")
        for name in (
            "tratto-control.slice",
            "tratto-control-recovery.service",
            "tratto-control-web.service",
        )
    }
    inventory = KIT.ArchiveInventory(entries=entries, tree_sha256="0" * 64)

    assert KIT.packaged_units_catalog(
        inventory,
        digest,
        uid=os.getuid(),
        gid=os.getgid(),
        control_root=control,
    ) == b"".join(
        (
            name.encode("ascii")
            + b" "
            + hashlib.sha256(units[name]).hexdigest().encode("ascii")
            + b"\n"
        )
        for name in (
            "tratto-control-recovery.service",
            "tratto-control-web.service",
            "tratto-control.slice",
        )
    )


@pytest.mark.parametrize(
    ("tamper", "message"),
    (
        ("digest", "journal autenticado"),
        ("name", "divergem do sucessor"),
        ("mode", "arquivo regular protegido"),
    ),
)
def test_packaged_units_catalog_rejects_untrusted_published_state(
    secure_tmp_path: Path,
    tamper: str,
    message: str,
) -> None:
    units = {
        "tratto-control.slice": b"published slice\n",
        "tratto-control-recovery.service": b"published recovery\n",
    }
    control = secure_tmp_path / f"catalog-control-{tamper}"
    digest = published_unit_catalog_tree(control, units)
    if tamper == "name":
        systemd = control / "bootstrap" / "systemd"
        systemd.chmod(0o755)
        extra = systemd / "tratto-control-extra.service"
        extra.write_bytes(b"extra\n")
        extra.chmod(0o444)
        systemd.chmod(0o555)
        descriptor = os.open(
            control / "bootstrap",
            os.O_RDONLY | os.O_DIRECTORY,
        )
        try:
            digest = KIT.protected_bootstrap_tree_digest(
                descriptor,
                uid=os.getuid(),
                gid=os.getgid(),
            )
        finally:
            os.close(descriptor)
    elif tamper == "mode":
        (control / "bootstrap" / "systemd" / "tratto-control.slice").chmod(
            0o555
        )
        descriptor = os.open(
            control / "bootstrap",
            os.O_RDONLY | os.O_DIRECTORY,
        )
        try:
            digest = KIT.protected_bootstrap_tree_digest(
                descriptor,
                uid=os.getuid(),
                gid=os.getgid(),
            )
        finally:
            os.close(descriptor)
    else:
        digest = "f" * 64
    entries = {
        f"systemd/{name}": inventory_entry(f"systemd/{name}")
        for name in units
    }
    inventory = KIT.ArchiveInventory(entries=entries, tree_sha256="0" * 64)

    with pytest.raises(KIT.BootstrapSourceError, match=message):
        KIT.packaged_units_catalog(
            inventory,
            digest,
            uid=os.getuid(),
            gid=os.getgid(),
            control_root=control,
        )


@pytest.mark.parametrize(
    ("entries", "message"),
    (
        (
            {
                "systemd/tratto-control-web.service": inventory_entry(
                    "systemd/tratto-control-web.service"
                ),
                "systemd/tratto-control-recovery.service": inventory_entry(
                    "systemd/tratto-control-recovery.service"
                ),
            },
            "incompleto",
        ),
        (
            {
                "systemd/tratto-control.slice": inventory_entry(
                    "systemd/tratto-control.slice",
                    mode=0o555,
                ),
                "systemd/tratto-control-recovery.service": inventory_entry(
                    "systemd/tratto-control-recovery.service"
                ),
            },
            "tipo, modo ou nome",
        ),
        (
            {
                "systemd/tratto-control.slice": inventory_entry(
                    "systemd/tratto-control.slice",
                    size=KIT.MAX_PACKAGED_UNIT_BYTES + 1,
                ),
                "systemd/tratto-control-recovery.service": inventory_entry(
                    "systemd/tratto-control-recovery.service"
                ),
            },
            "tipo, modo ou nome",
        ),
        (
            {
                "systemd/tratto-control.slice": inventory_entry(
                    "systemd/tratto-control.slice",
                    size=0,
                ),
                "systemd/tratto-control-recovery.service": inventory_entry(
                    "systemd/tratto-control-recovery.service"
                ),
            },
            "tipo, modo ou nome",
        ),
        (
            {
                "systemd/tratto-control.slice": inventory_entry(
                    "systemd/tratto-control.slice",
                    kind="directory",
                ),
                "systemd/tratto-control-recovery.service": inventory_entry(
                    "systemd/tratto-control-recovery.service"
                ),
            },
            "tipo, modo ou nome",
        ),
        (
            {
                "systemd/tratto-control.slice": inventory_entry(
                    "systemd/tratto-control.slice"
                ),
                "systemd/tratto-control-recovery.service": inventory_entry(
                    "systemd/tratto-control-recovery.service"
                ),
                "systemd/tratto-control.invalid": inventory_entry(
                    "systemd/tratto-control.invalid"
                ),
            },
            "tipo, modo ou nome",
        ),
    ),
)
def test_packaged_units_catalog_rejects_incomplete_or_ambiguous_inventory(
    entries: dict[str, object],
    message: str,
) -> None:
    inventory = KIT.ArchiveInventory(entries=entries, tree_sha256="0" * 64)

    with pytest.raises(KIT.BootstrapSourceError, match=message):
        KIT.packaged_unit_names(inventory)


def test_packaged_units_catalog_rejects_oversize_payload() -> None:
    entries = {
        "systemd/tratto-control.slice": inventory_entry(
            "systemd/tratto-control.slice"
        ),
        "systemd/tratto-control-recovery.service": inventory_entry(
            "systemd/tratto-control-recovery.service"
        ),
    }
    for index in range(800):
        name = (
            f"tratto-control-{index:04d}-"
            + ("x" * 64)
            + ".service"
        )
        path = f"systemd/{name}"
        entries[path] = inventory_entry(path)
    inventory = KIT.ArchiveInventory(entries=entries, tree_sha256="0" * 64)

    with pytest.raises(KIT.BootstrapSourceError, match="excede o limite"):
        KIT.packaged_unit_names(inventory)


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
    successor = KIT.parse_cli(
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
            "--expected-predecessor-kit-id",
            "5" * 64,
            "--expected-predecessor-controller-sha",
            "6" * 40,
            "--expected-predecessor-publisher-intent-sha256",
            "7" * 64,
        ]
    )
    assert successor.expected_predecessor_kit_id == "5" * 64
    post_publisher = KIT.parse_cli(
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
            "--expected-post-publisher-predecessor-kit-id",
            "5" * 64,
            "--expected-post-publisher-predecessor-controller-sha",
            "6" * 40,
            "--expected-post-publisher-source-intent-sha256",
            "7" * 64,
            "--expected-post-publisher-source-used-sha256",
            "8" * 64,
            "--expected-post-publisher-publisher-intent-sha256",
            "9" * 64,
            "--expected-post-publisher-publisher-used-sha256",
            "a" * 64,
        ]
    )
    assert (
        post_publisher.expected_post_publisher_predecessor_kit_id
        == "5" * 64
    )
    post_stage = KIT.parse_cli(
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
            "--expected-post-publisher-predecessor-kit-id",
            "5" * 64,
            "--expected-post-publisher-predecessor-controller-sha",
            "6" * 40,
            "--expected-post-publisher-source-intent-sha256",
            "7" * 64,
            "--expected-post-publisher-source-used-sha256",
            "8" * 64,
            "--expected-post-publisher-publisher-intent-sha256",
            "9" * 64,
            "--expected-post-publisher-publisher-used-sha256",
            "a" * 64,
            "--expected-post-publisher-staged-bundle-id",
            "b" * 64,
            "--expected-post-publisher-staged-bundle-tree-sha256",
            "c" * 64,
        ]
    )
    assert post_stage.expected_post_publisher_staged_bundle_id == "b" * 64
    inspection = KIT.parse_cli(
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
            "--expected-post-publisher-predecessor-kit-id",
            "5" * 64,
            "--expected-post-publisher-predecessor-controller-sha",
            "6" * 40,
            "--expected-post-publisher-source-intent-sha256",
            "7" * 64,
            "--expected-post-publisher-source-used-sha256",
            "8" * 64,
            "--expected-post-publisher-publisher-intent-sha256",
            "9" * 64,
            "--expected-post-publisher-publisher-used-sha256",
            "a" * 64,
            "--expected-post-publisher-staged-bundle-id",
            "b" * 64,
            "--inspect-post-publisher-staged-bundle-tree",
        ]
    )
    assert inspection.inspect_post_publisher_staged_bundle_tree is True
    assert (
        inspection.expected_post_publisher_staged_bundle_tree_sha256
        is None
    )
    with pytest.raises(
        KIT.BootstrapSourceError,
        match="exatamente",
    ):
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
                "--expected-post-publisher-staged-bundle-id",
                "b" * 64,
            ]
        )
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
    with pytest.raises(KIT.BootstrapSourceError, match="exatamente"):
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
                "--expected-predecessor-kit-id",
                "5" * 64,
            ]
        )
    with pytest.raises(KIT.BootstrapSourceError, match="exatamente"):
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
                "--expected-post-publisher-predecessor-kit-id",
                "5" * 64,
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
    for option in (
        "--expected-predecessor-kit-id",
        "--expected-predecessor-controller-sha",
        "--expected-predecessor-publisher-intent-sha256",
    ):
        assert option in text
    assert (
        "/usr/bin/python3.12 -I -B \\\n"
        "  /var/lib/tratto-control/incoming/"
        "install-bootstrap-source-kit.py"
    ) not in text


def test_readme_post_publisher_bridge_uses_verified_fd_without_bad_wrapper(
) -> None:
    text = README.read_text(encoding="utf-8")
    start = text.index("### One-use post-publisher/pre-stage recovery")
    end = text.index("## Stable controller v2", start)
    section = text[start:end]
    opened = section.index('exec {helper_fd}<"$helper"')
    signature = section.index("/usr/local/bin/cosign verify-blob")
    direct = section.index(
        '/usr/bin/python3.12 -I -B "$helper_fd_path"'
    )
    assert opened < signature < direct
    assert (
        "/opt/tratto-control/bootstrap/scripts/with-deploy-lock.py"
        not in section
    )
    assert "/run/tratto-control/deploy.lock" in section
    assert "non-blocking" in section
    assert "sealed anonymous Linux `memfd`" in section
    assert (
        "--sealed-packaged-unit-catalog-pre-reload-fd"
        in section
    )
    assert "--sealed-packaged-unit-catalog-fd" in section
    assert (
        "/usr/bin/systemctl --no-ask-password daemon-reload"
        in section
    )
    assert "journal-authenticated" in section
    assert "guardian" in section
    assert "same open-file-description lock" in section
    assert "SIGKILL" in section
    assert "authoritative `UnitPath`" in section
    assert "drop-ins" in section
    assert "aliases" in section
    assert "templates with no runtime instance" in section
    for option in (
        "--expected-post-publisher-predecessor-kit-id",
        "--expected-post-publisher-predecessor-controller-sha",
        "--expected-post-publisher-source-intent-sha256",
        "--expected-post-publisher-source-used-sha256",
        "--expected-post-publisher-publisher-intent-sha256",
        "--expected-post-publisher-publisher-used-sha256",
    ):
        assert option in section[direct:]


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


def test_post_publisher_bridge_acquires_exact_global_lock_exclusively(
    secure_tmp_path: Path,
) -> None:
    lock_directory = secure_tmp_path / "run-post"
    lock_directory.mkdir(mode=0o700)
    lock_path = lock_directory / KIT.LOCK_NAME
    lock_path.write_bytes(b"")
    lock_path.chmod(0o600)

    acquired = KIT.acquire_fixed_deploy_lock(
        uid=os.getuid(),
        gid=os.getgid(),
        lock_directory=lock_directory,
    )
    try:
        with pytest.raises(
            KIT.BootstrapSourceError,
            match="ocupado",
        ):
            KIT.acquire_fixed_deploy_lock(
                uid=os.getuid(),
                gid=os.getgid(),
                lock_directory=lock_directory,
            )
        observed = os.open(lock_path, os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(
                    observed,
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
        finally:
            os.close(observed)
    finally:
        os.close(acquired)

    retried = KIT.acquire_fixed_deploy_lock(
        uid=os.getuid(),
        gid=os.getgid(),
        lock_directory=lock_directory,
    )
    os.close(retried)


def _post_publisher_main_args(helper_fd: int):
    return KIT.parse_cli(
        [
            "--helper-fd",
            str(helper_fd),
            "--expected-helper-sha256",
            "1" * 64,
            "--expected-attestation-sha256",
            "2" * 64,
            "--expected-carrier-sha",
            "3" * 40,
            "--expected-controller-sha",
            "4" * 40,
            "--expected-post-publisher-predecessor-kit-id",
            "5" * 64,
            "--expected-post-publisher-predecessor-controller-sha",
            "6" * 40,
            "--expected-post-publisher-source-intent-sha256",
            "7" * 64,
            "--expected-post-publisher-source-used-sha256",
            "8" * 64,
            "--expected-post-publisher-publisher-intent-sha256",
            "9" * 64,
            "--expected-post-publisher-publisher-used-sha256",
            "a" * 64,
        ]
    )


def test_post_publisher_main_rejects_any_inherited_lock_environment(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper_fd = os.open(SCRIPT, os.O_RDONLY)
    args = _post_publisher_main_args(helper_fd)
    acquired = False

    def unexpected_acquire(**_kwargs):
        nonlocal acquired
        acquired = True
        raise AssertionError("post-publisher must reject before acquisition")

    monkeypatch.setattr(KIT, "parse_cli", lambda _argv: args)
    monkeypatch.setattr(
        KIT,
        "validate_execution_entrypoint",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(KIT, "EXPECTED_UID", os.geteuid())
    monkeypatch.setattr(KIT, "EXPECTED_GID", os.getegid())
    monkeypatch.setattr(KIT, "acquire_fixed_deploy_lock", unexpected_acquire)
    monkeypatch.setattr(
        KIT,
        "verify_inherited_lock",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("inherited verifier must not run")
        ),
    )
    monkeypatch.setenv(KIT.LOCK_FD_ENV, "91")
    try:
        with pytest.raises(
            KIT.BootstrapSourceError,
            match="recusa lock herdado",
        ):
            KIT.main()
    finally:
        os.close(helper_fd)

    assert acquired is False


def test_post_stage_inspection_main_uses_direct_lock_and_never_installs(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    helper_fd = os.open(SCRIPT, os.O_RDONLY)
    args = KIT.parse_cli(
        [
            "--helper-fd",
            str(helper_fd),
            "--expected-helper-sha256",
            "1" * 64,
            "--expected-attestation-sha256",
            "2" * 64,
            "--expected-carrier-sha",
            "3" * 40,
            "--expected-controller-sha",
            "4" * 40,
            "--expected-post-publisher-predecessor-kit-id",
            "5" * 64,
            "--expected-post-publisher-predecessor-controller-sha",
            "6" * 40,
            "--expected-post-publisher-source-intent-sha256",
            "7" * 64,
            "--expected-post-publisher-source-used-sha256",
            "8" * 64,
            "--expected-post-publisher-publisher-intent-sha256",
            "9" * 64,
            "--expected-post-publisher-publisher-used-sha256",
            "a" * 64,
            "--expected-post-publisher-staged-bundle-id",
            "b" * 64,
            "--inspect-post-publisher-staged-bundle-tree",
        ]
    )
    observed_locks: list[int] = []
    payload = canonical(
        {
            "bundle_id": "b" * 64,
            "bundle_tree_sha256": "c" * 64,
        }
    )

    monkeypatch.setattr(KIT, "parse_cli", lambda _argv: args)
    monkeypatch.setattr(
        KIT,
        "validate_execution_entrypoint",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(KIT, "EXPECTED_UID", os.geteuid())
    monkeypatch.setattr(KIT, "EXPECTED_GID", os.getegid())
    monkeypatch.delenv(KIT.LOCK_FD_ENV, raising=False)
    monkeypatch.delenv(KIT.LOCK_HELD_ENV, raising=False)
    monkeypatch.setattr(
        KIT,
        "acquire_fixed_deploy_lock",
        lambda **_kwargs: os.dup(helper_fd),
    )
    monkeypatch.setattr(
        KIT,
        "inspect_post_stage",
        lambda **kwargs: (
            observed_locks.append(kwargs["lock_descriptor"]) or payload
        ),
    )
    monkeypatch.setattr(
        KIT,
        "install_source",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("inspection must not install")
        ),
    )
    try:
        assert KIT.main() == 0
    finally:
        os.close(helper_fd)

    assert capsysbinary.readouterr().out == payload
    assert len(observed_locks) == 1
    with pytest.raises(OSError):
        os.fstat(observed_locks[0])


@pytest.mark.parametrize("install_fails", (False, True))
def test_post_publisher_main_holds_and_closes_exact_direct_lock(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    install_fails: bool,
) -> None:
    lock_directory = secure_tmp_path / "run-main-post"
    lock_directory.mkdir(mode=0o700)
    lock_path = lock_directory / KIT.LOCK_NAME
    lock_path.write_bytes(b"")
    lock_path.chmod(0o600)
    helper_fd = os.open(SCRIPT, os.O_RDONLY)
    args = _post_publisher_main_args(helper_fd)
    real_acquire = KIT.acquire_fixed_deploy_lock
    acquired_fds: list[int] = []
    publisher_fds: list[int] = []

    def acquire(**kwargs) -> int:
        assert kwargs == {"uid": os.geteuid(), "gid": os.getegid()}
        descriptor = real_acquire(
            uid=os.geteuid(),
            gid=os.getegid(),
            lock_directory=lock_directory,
        )
        acquired_fds.append(descriptor)
        return descriptor

    def assert_lock_is_held(descriptor: int) -> None:
        fixed = os.stat(lock_path, follow_symlinks=False)
        observed = os.fstat(descriptor)
        assert (observed.st_dev, observed.st_ino) == (
            fixed.st_dev,
            fixed.st_ino,
        )
        with pytest.raises(KIT.BootstrapSourceError, match="ocupado"):
            real_acquire(
                uid=os.geteuid(),
                gid=os.getegid(),
                lock_directory=lock_directory,
            )

    def publisher(
        _source_descriptor: int,
        lock_descriptor: int,
        _authorization: bytes | None,
    ) -> str:
        assert lock_descriptor == acquired_fds[0]
        assert_lock_is_held(lock_descriptor)
        publisher_fds.append(lock_descriptor)
        return "upgraded"

    def install_source(**kwargs) -> str:
        descriptor = kwargs["lock_descriptor"]
        assert descriptor == acquired_fds[0]
        assert_lock_is_held(descriptor)
        assert kwargs["publisher"] is publisher
        assert kwargs["publisher"](123, descriptor, b"authorization") == (
            "upgraded"
        )
        if install_fails:
            raise KIT.BootstrapSourceError("simulated install failure")
        return "installed"

    monkeypatch.delenv(KIT.LOCK_FD_ENV, raising=False)
    monkeypatch.delenv(KIT.LOCK_HELD_ENV, raising=False)
    monkeypatch.setattr(KIT, "parse_cli", lambda _argv: args)
    monkeypatch.setattr(
        KIT,
        "validate_execution_entrypoint",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(KIT, "EXPECTED_UID", os.geteuid())
    monkeypatch.setattr(KIT, "EXPECTED_GID", os.getegid())
    monkeypatch.setattr(KIT, "acquire_fixed_deploy_lock", acquire)
    monkeypatch.setattr(
        KIT,
        "verify_inherited_lock",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("inherited verifier must not run")
        ),
    )
    monkeypatch.setattr(KIT, "production_runtime", lambda: object())
    monkeypatch.setattr(KIT, "run_publisher", publisher)
    monkeypatch.setattr(KIT, "install_source", install_source)

    try:
        if install_fails:
            with pytest.raises(
                KIT.BootstrapSourceError,
                match="simulated install failure",
            ):
                KIT.main()
        else:
            assert KIT.main() == 0
    finally:
        os.close(helper_fd)

    assert len(acquired_fds) == 1
    assert publisher_fds == acquired_fds
    with pytest.raises(OSError):
        os.fstat(acquired_fds[0])
    reacquired = real_acquire(
        uid=os.geteuid(),
        gid=os.getegid(),
        lock_directory=lock_directory,
    )
    os.close(reacquired)


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
