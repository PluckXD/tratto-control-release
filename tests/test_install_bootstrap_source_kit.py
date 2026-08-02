from __future__ import annotations

import gzip
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import sys
import tarfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "install-bootstrap-source-kit.py"
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
        "scripts/with-deploy-lock.py": (b"lock\n", 0o555),
    }
    if extra is not None:
        files[extra[0]] = (extra[1], extra[2])
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
                    if link and name == "scripts/with-deploy-lock.py":
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
        "schema_version": 5,
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
    (incoming / KIT.HELPER_NAME).write_bytes(helper)
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

    return KIT.install_source(
        incoming=incoming,
        state_root=state,
        uid=os.getuid(),
        gid=os.getgid(),
        runtime=fake_runtime(),
        signature_verifier=verifier,
        publisher=publisher,
        lock_descriptor=99,
        fault=fault,
    )


def test_installs_signed_tree_retains_old_and_is_idempotent(
    tmp_path: Path,
) -> None:
    incoming, state, calls = fixture(tmp_path)

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
    tmp_path: Path,
    event: str,
) -> None:
    incoming, state, calls = fixture(tmp_path)
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
    tmp_path: Path,
    immutable_complete: bool,
) -> None:
    incoming, state, calls = fixture(tmp_path)
    binding = KIT.validate_attestation(
        (incoming / KIT.ATTESTATION_NAME).read_bytes(),
        helper_sha256=hashlib.sha256(
            (incoming / KIT.HELPER_NAME).read_bytes()
        ).hexdigest(),
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
    tmp_path: Path,
) -> None:
    incoming, state, calls = fixture(tmp_path)

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
        match="diferente|outro",
    ):
        install(incoming, state, [])


def test_archive_rejects_links_before_any_mutation(
    tmp_path: Path,
) -> None:
    incoming, state, calls = fixture(tmp_path)
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


@pytest.mark.parametrize("tamper", ["traversal", "concatenated-gzip"])
def test_archive_rejects_noncanonical_container_or_path(
    tmp_path: Path,
    tamper: str,
) -> None:
    incoming, state, calls = fixture(tmp_path)
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


def test_requires_the_inherited_inode_to_be_actually_locked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_directory = tmp_path / "run"
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
