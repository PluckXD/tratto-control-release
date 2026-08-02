#!/usr/bin/python3.12
"""Install one signed Operations tree as the fixed bootstrap source.

This program is deliberately self-contained.  It is transported as data,
signed independently, placed with the other release inputs, and invoked by
the already-installed ``with-deploy-lock.py`` through the same read-only file
descriptor verified before execution.  No checkout, network download, shell,
or mutable Python import participates in the host update.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import tarfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping


CONTRACT = "tratto-control-bootstrap-source-v1"
EXPECTED_UID = 0
EXPECTED_GID = 0
INCOMING = Path("/var/lib/tratto-control/incoming")
STATE_ROOT = Path("/var/lib/tratto-control")
SOURCE_NAME = "bootstrap-source"
CANDIDATE_PREFIX = "bootstrap-source.candidate."
PREVIOUS_PREFIX = "bootstrap-source.previous."
INTENT_NAME = "bootstrap-source-kit.intent.json"
PREPARED_NAME = "bootstrap-source-kit.prepared.json"
EXCHANGED_NAME = "bootstrap-source-kit.exchanged.json"
RETAINED_NAME = "bootstrap-source-kit.retained.json"
USED_NAME = "bootstrap-source-kit.used.json"
HELPER_NAME = "install-bootstrap-source-kit.py"
HELPER_BUNDLE_NAME = "bootstrap-source-kit.sigstore.json"
ATTESTATION_NAME = "release-attestation.json"
ATTESTATION_BUNDLE_NAME = "release.sigstore.json"
OPS_BUNDLE_NAME = "ops.sigstore.json"
COSIGN = Path("/usr/local/bin/cosign")
COSIGN_CACHE = Path("/var/cache/tratto-control/cosign")
PYTHON = Path("/usr/bin/python3.12")
LOCK_DIRECTORY = Path("/run/tratto-control")
LOCK_NAME = "deploy.lock"
LOCK_FD_ENV = "TRATTO_CONTROL_LOCK_FD"
LOCK_HELD_ENV = "TRATTO_CONTROL_LOCK_HELD"

CARRIER_REPOSITORY = "PluckXD/tratto-control-release-carrier"
CARRIER_WORKFLOW = ".github/workflows/control-bootstrap-v1.yml"
CARRIER_REF = "refs/heads/main"
CARRIER_TRIGGER = "workflow_dispatch"
CARRIER_IDENTITY = (
    "https://github.com/"
    f"{CARRIER_REPOSITORY}/{CARRIER_WORKFLOW}@{CARRIER_REF}"
)
GITHUB_ISSUER = "https://token.actions.githubusercontent.com"

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
ARCHIVE_NAME_RE = re.compile(
    r"^tratto-control-ops-([0-9a-f]{40})\.tar\.gz$"
)
STATE_TEMP_RE = re.compile(
    r"^bootstrap-source-kit\.(intent|prepared|exchanged|retained|used)"
    r"\.([0-9a-f]{64})\.installing$"
)

MAX_HELPER_BYTES = 2 * 1024 * 1024
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_MEMBERS = 2048
MAX_PATH_BYTES = 240
MAX_TREE_ENTRIES = 2048
MAX_TREE_BYTES = 64 * 1024 * 1024

REQUIRED_FILES = {
    "RELEASE_SHA": 0o444,
    "artifact-manifest.json": 0o444,
    "scripts/provision-node-runtime.py": 0o555,
    "scripts/publish-bootstrap-tree.py": 0o555,
    "scripts/with-deploy-lock.py": 0o555,
}

RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
AT_EMPTY_PATH = 0x1000
AT_SYMLINK_NOFOLLOW = 0x100
STATX_MNT_ID = 0x1000
STATX_BUFFER_SIZE = 256
STATX_MNT_ID_OFFSET = 144


class BootstrapSourceError(ValueError):
    """The signed source kit or the host state is not safe to use."""


def reject(message: str) -> None:
    raise BootstrapSourceError(message)


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            reject(f"JSON contém chave duplicada: {key}")
        value[key] = item
    return value


def parse_canonical_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda item: reject(
                f"{label} contém número não-finito: {item}"
            ),
        )
    except BootstrapSourceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        reject(f"{label} não é JSON UTF-8 válido")
    if type(value) is not dict or raw != canonical_bytes(value):
        reject(f"{label} precisa ser um objeto JSON canônico")
    return value


def exact_object(
    value: Any,
    keys: set[str],
    label: str,
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        reject(f"{label} possui formato divergente")
    return value


def require_hash(value: Any, label: str) -> str:
    if type(value) is not str or HASH_RE.fullmatch(value) is None:
        reject(f"{label} não é SHA-256 canônico")
    return value


def require_sha(value: Any, label: str) -> str:
    if type(value) is not str or SHA_RE.fullmatch(value) is None:
        reject(f"{label} não é commit SHA canônico")
    return value


def write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            reject("escrita interrompida")
        view = view[written:]


def read_all(
    descriptor: int,
    info: os.stat_result,
    *,
    maximum: int,
    label: str,
) -> bytes:
    if not 0 < info.st_size <= maximum:
        reject(f"{label} excede o tamanho permitido")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = info.st_size
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            reject(f"{label} terminou antes do tamanho declarado")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        reject(f"{label} cresceu durante a leitura")
    after = os.fstat(descriptor)
    stable = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_uid",
        "st_gid",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(getattr(info, field) != getattr(after, field) for field in stable):
        reject(f"{label} mudou durante a leitura")
    return b"".join(chunks)


def digest_fd(descriptor: int, info: os.stat_result, label: str) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = info.st_size
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            reject(f"{label} terminou antes do tamanho declarado")
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        reject(f"{label} cresceu durante o hash")
    after = os.fstat(descriptor)
    stable = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_uid",
        "st_gid",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(getattr(info, field) != getattr(after, field) for field in stable):
        reject(f"{label} mudou durante o hash")
    return digest.hexdigest()


def validate_directory(
    info: os.stat_result,
    label: str,
    *,
    uid: int,
    gid: int,
    modes: set[int],
) -> None:
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != uid
        or info.st_gid != gid
        or stat.S_IMODE(info.st_mode) not in modes
    ):
        reject(f"{label} não é diretório protegido com modo exato")


def validate_regular(
    info: os.stat_result,
    label: str,
    *,
    uid: int,
    gid: int,
    modes: set[int],
    maximum: int,
    allow_empty: bool = False,
) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != uid
        or info.st_gid != gid
        or stat.S_IMODE(info.st_mode) not in modes
        or info.st_size > maximum
        or (info.st_size <= 0 and not allow_empty)
    ):
        reject(f"{label} não é arquivo regular protegido e limitado")


def mount_identity(descriptor: int) -> tuple[str, int]:
    libc = ctypes.CDLL(None, use_errno=True)
    statx = getattr(libc, "statx", None)
    if statx is not None:
        statx.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_uint,
            ctypes.c_void_p,
        ]
        statx.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(STATX_BUFFER_SIZE)
        result = statx(
            descriptor,
            b"",
            AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
            STATX_MNT_ID,
            buffer,
        )
        if result == 0:
            mask = int.from_bytes(buffer.raw[0:4], "little")
            if mask & STATX_MNT_ID:
                value = int.from_bytes(
                    buffer.raw[
                        STATX_MNT_ID_OFFSET : STATX_MNT_ID_OFFSET + 8
                    ],
                    "little",
                )
                return ("mnt", value)
        elif ctypes.get_errno() not in {
            errno.ENOSYS,
            errno.EINVAL,
            errno.EOPNOTSUPP,
        }:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    return ("dev", os.fstat(descriptor).st_dev)


def require_same_mount(parent: int, child: int, label: str) -> None:
    if mount_identity(parent) != mount_identity(child):
        reject(f"{label} está em mount separado")


def open_path_chain(
    path: Path,
    *,
    uid: int,
    gid: int,
    final_modes: set[int],
) -> int:
    if not path.is_absolute():
        reject("caminho fixo não é absoluto")
    descriptor = os.open(
        "/",
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        root = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(root.st_mode)
            or root.st_uid not in {0, uid}
            or (root.st_uid == uid and root.st_gid != gid)
            or stat.S_IMODE(root.st_mode) & 0o022
        ):
            reject("/ não é uma raiz protegida")
        for index, part in enumerate(path.parts[1:], start=1):
            child = os.open(
                part,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            info = os.fstat(child)
            if index == len(path.parts) - 1:
                validate_directory(
                    info,
                    str(path),
                    uid=uid,
                    gid=gid,
                    modes=final_modes,
                )
            elif (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid not in {0, uid}
                or (info.st_uid == uid and info.st_gid != gid)
                or stat.S_IMODE(info.st_mode) & 0o022
                or stat.S_IMODE(info.st_mode) & 0o500 != 0o500
            ):
                reject(f"pai não protegido no caminho {path}")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def open_input(
    incoming_descriptor: int,
    name: str,
    *,
    uid: int,
    gid: int,
    maximum: int,
) -> tuple[int, os.stat_result]:
    if (
        not name
        or "/" in name
        or name in {".", ".."}
        or "\x00" in name
    ):
        reject("nome de input não canônico")
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=incoming_descriptor,
    )
    try:
        info = os.fstat(descriptor)
        validate_regular(
            info,
            f"input {name}",
            uid=uid,
            gid=gid,
            modes={0o400},
            maximum=maximum,
        )
        return descriptor, info
    except Exception:
        os.close(descriptor)
        raise


@dataclass(frozen=True)
class BootstrapExpectations:
    helper_sha256: str
    attestation_sha256: str
    carrier_sha: str
    controller_sha: str


def validate_expectations(
    expectations: BootstrapExpectations,
) -> None:
    require_hash(
        expectations.helper_sha256,
        "helper hash esperado",
    )
    require_hash(
        expectations.attestation_sha256,
        "attestation hash esperado",
    )
    require_sha(
        expectations.carrier_sha,
        "carrier SHA esperado",
    )
    require_sha(
        expectations.controller_sha,
        "controller SHA esperado",
    )


@dataclass(frozen=True)
class AttestationBinding:
    raw_sha256: str
    carrier_sha: str
    controller_sha: str
    api_sha: str
    ops_name: str
    ops_sha256: str
    ops_size: int
    helper_sha256: str
    approval_sha256: str
    migration: Mapping[str, Any]


def validate_attestation(
    raw: bytes,
    *,
    helper_sha256: str,
    helper_size_bytes: int,
    expected_carrier_sha: str,
    expected_controller_sha: str,
) -> AttestationBinding:
    require_hash(helper_sha256, "helper hash")
    if type(helper_size_bytes) is not int or not (
        0 < helper_size_bytes <= MAX_HELPER_BYTES
    ):
        reject("tamanho do helper é inválido")
    require_sha(expected_carrier_sha, "carrier SHA esperado")
    require_sha(expected_controller_sha, "controller SHA esperado")
    value = parse_canonical_json(raw, "release attestation")
    exact_object(
        value,
        {
            "approval",
            "artifacts",
            "behavioral_verification",
            "bootstrap_source_helper",
            "carrier",
            "controller",
            "migration",
            "schema_version",
            "supplemental_inventory",
        },
        "release attestation",
    )
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 6
    ):
        reject("release attestation não usa schema 6")
    helper = exact_object(
        value["bootstrap_source_helper"],
        {"controller_sha", "name", "sha256", "size_bytes"},
        "bootstrap source helper binding",
    )
    if (
        helper["name"] != HELPER_NAME
        or helper["sha256"] != helper_sha256
        or type(helper["size_bytes"]) is not int
        or helper["size_bytes"] != helper_size_bytes
    ):
        reject("bootstrap source helper binding diverge")
    if helper["controller_sha"] != expected_controller_sha:
        reject("controller SHA esperado diverge do helper assinado")
    carrier = exact_object(
        value["carrier"],
        {"authorizes_release", "repository", "trust"},
        "carrier binding",
    )
    if carrier != {
        "authorizes_release": False,
        "repository": CARRIER_REPOSITORY,
        "trust": "transport-only",
    }:
        reject("carrier binding diverge")
    if (
        type(value["migration"]) is not dict
        or value["supplemental_inventory"]
        != {"supplemental_only": True}
    ):
        reject("migration ou supplemental inventory diverge")
    controller = exact_object(
        value["controller"],
        {
            "commit_sha",
            "event_name",
            "repository",
            "run_attempt",
            "run_id",
            "runner_arch",
            "runner_environment",
            "runner_os",
            "source_ref",
            "verifier_sha256",
            "workflow",
            "workflow_ref",
        },
        "controller carrier",
    )
    carrier_sha = require_sha(
        controller["commit_sha"],
        "carrier commit",
    )
    if (
        carrier_sha != expected_carrier_sha
        or controller["event_name"] != CARRIER_TRIGGER
        or controller["repository"] != CARRIER_REPOSITORY
        or controller["source_ref"] != CARRIER_REF
        or controller["workflow"] != CARRIER_WORKFLOW
        or controller["workflow_ref"]
        != f"{CARRIER_REPOSITORY}/{CARRIER_WORKFLOW}@{CARRIER_REF}"
        or controller["runner_arch"] != "X64"
        or controller["runner_environment"] != "github-hosted"
        or controller["runner_os"] != "Linux"
        or type(controller["run_attempt"]) is not int
        or controller["run_attempt"] <= 0
        or type(controller["run_id"]) is not int
        or controller["run_id"] <= 0
        or HASH_RE.fullmatch(str(controller["verifier_sha256"])) is None
    ):
        reject("identidade do workflow carrier diverge")

    approval = exact_object(
        value["approval"],
        {"manifest", "manifest_sha256", "mode"},
        "approval binding",
    )
    if (
        approval["mode"] != "single-operator-bootstrap"
        or HASH_RE.fullmatch(str(approval["manifest_sha256"])) is None
        or type(approval["manifest"]) is not dict
    ):
        reject("approval binding diverge")
    approval_raw = canonical_bytes(approval["manifest"])
    if hashlib.sha256(approval_raw).hexdigest() != approval["manifest_sha256"]:
        reject("hash do approval diverge")
    manifest = approval["manifest"]
    controller_approval = manifest.get("controller")
    api_approval = manifest.get("api")
    ops_approval = manifest.get("ops")
    if not all(
        type(item) is dict
        for item in (controller_approval, api_approval, ops_approval)
    ):
        reject("approval não vincula controller/API/Ops")
    controller_sha = require_sha(
        controller_approval.get("base_sha"),
        "controller SHA aprovado",
    )
    if (
        controller_sha != expected_controller_sha
        or controller_sha != helper["controller_sha"]
    ):
        reject("controller SHA diverge do helper assinado")
    api_sha = require_sha(
        api_approval.get("commit_sha"),
        "API SHA aprovado",
    )
    if require_sha(
        ops_approval.get("commit_sha"),
        "Ops SHA aprovado",
    ) != api_sha:
        reject("API e Ops aprovados divergem")

    artifacts = exact_object(
        value["artifacts"],
        {"api", "ops", "web"},
        "artifact bindings",
    )
    artifact_keys = {
        "ancestor_verified",
        "approved_ref",
        "artifact_id",
        "artifact_name",
        "build_job",
        "carrier_repository",
        "commit_sha",
        "component_manifest_sha256",
        "repository",
        "runner_arch",
        "runner_environment",
        "runner_os",
        "service_digest",
        "sha256",
        "size_bytes",
        "tree_sha",
    }
    api_artifact = exact_object(
        artifacts["api"],
        artifact_keys,
        "API artifact binding",
    )
    ops_artifact = exact_object(
        artifacts["ops"],
        artifact_keys,
        "Ops artifact binding",
    )
    exact_object(
        artifacts["web"],
        artifact_keys,
        "Web artifact binding",
    )
    if (
        api_artifact.get("commit_sha") != api_sha
        or api_artifact.get("repository") != "PluckXD/tratto-api"
        or ops_artifact.get("commit_sha") != api_sha
        or ops_artifact.get("repository") != "PluckXD/tratto-api"
        or ops_artifact.get("carrier_repository") != CARRIER_REPOSITORY
        or ops_artifact.get("approved_ref") != CARRIER_REF
        or ops_artifact.get("build_job") != "build_ops"
        or api_artifact.get("ancestor_verified") is not True
        or ops_artifact.get("ancestor_verified") is not True
        or api_artifact.get("runner_arch") != "X64"
        or ops_artifact.get("runner_arch") != "X64"
        or api_artifact.get("runner_environment") != "github-hosted"
        or ops_artifact.get("runner_environment") != "github-hosted"
        or api_artifact.get("runner_os") != "Linux"
        or ops_artifact.get("runner_os") != "Linux"
        or type(api_artifact.get("artifact_id")) is not int
        or api_artifact["artifact_id"] <= 0
        or type(ops_artifact.get("artifact_id")) is not int
        or ops_artifact["artifact_id"] <= 0
        or type(ops_artifact.get("size_bytes")) is not int
        or ops_artifact["size_bytes"] <= 0
    ):
        reject("bindings de API/Ops divergem do approval")
    for artifact, label in (
        (api_artifact, "API"),
        (ops_artifact, "Ops"),
    ):
        require_hash(
            artifact.get("component_manifest_sha256"),
            f"{label} component manifest hash",
        )
        require_hash(
            artifact.get("service_digest"),
            f"{label} service digest",
        )
        require_sha(
            artifact.get("tree_sha"),
            f"{label} tree SHA",
        )
    ops_name = ops_artifact.get("artifact_name")
    if (
        type(ops_name) is not str
        or ARCHIVE_NAME_RE.fullmatch(ops_name) is None
        or ARCHIVE_NAME_RE.fullmatch(ops_name).group(1) != api_sha
    ):
        reject("nome do archive Ops diverge do SHA aprovado")
    ops_hash = require_hash(
        ops_artifact.get("sha256"),
        "Ops archive hash",
    )
    return AttestationBinding(
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        carrier_sha=carrier_sha,
        controller_sha=controller_sha,
        api_sha=api_sha,
        ops_name=ops_name,
        ops_sha256=ops_hash,
        ops_size=ops_artifact["size_bytes"],
        helper_sha256=helper_sha256,
        approval_sha256=approval["manifest_sha256"],
        migration=value["migration"],
    )


def cosign_arguments(
    *,
    bundle_path: str,
    target_path: str,
    carrier_sha: str,
) -> list[str]:
    return [
        "verify-blob",
        "--bundle",
        bundle_path,
        "--certificate-identity",
        CARRIER_IDENTITY,
        "--certificate-oidc-issuer",
        GITHUB_ISSUER,
        "--certificate-github-workflow-sha",
        carrier_sha,
        "--certificate-github-workflow-ref",
        CARRIER_REF,
        "--certificate-github-workflow-repository",
        CARRIER_REPOSITORY,
        "--certificate-github-workflow-trigger",
        CARRIER_TRIGGER,
        target_path,
    ]


def verify_cosign_blob(
    cosign_descriptor: int,
    target_descriptor: int,
    bundle_descriptor: int,
    carrier_sha: str,
) -> None:
    descriptors = (
        cosign_descriptor,
        target_descriptor,
        bundle_descriptor,
    )
    paths = [f"/proc/self/fd/{item}" for item in descriptors]
    result = subprocess.run(
        [
            paths[0],
            *cosign_arguments(
                bundle_path=paths[2],
                target_path=paths[1],
                carrier_sha=carrier_sha,
            ),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "NO_COLOR": "1",
            "XDG_CACHE_HOME": str(COSIGN_CACHE),
        },
        pass_fds=descriptors,
        check=False,
        timeout=90,
    )
    if result.returncode != 0:
        reject("assinatura Sigstore foi recusada")


def open_cosign(*, uid: int, gid: int) -> int:
    cache = open_path_chain(
        COSIGN_CACHE,
        uid=uid,
        gid=gid,
        final_modes={0o700},
    )
    os.close(cache)
    parent = open_path_chain(
        COSIGN.parent,
        uid=uid,
        gid=gid,
        final_modes={0o755, 0o555},
    )
    try:
        descriptor = os.open(
            COSIGN.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
    finally:
        os.close(parent)
    try:
        info = os.fstat(descriptor)
        validate_regular(
            info,
            str(COSIGN),
            uid=uid,
            gid=gid,
            modes={0o555, 0o755},
            maximum=256 * 1024 * 1024,
        )
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def canonical_member_path(value: str) -> str:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        reject("tar contém path não UTF-8")
    pure = PurePosixPath(value)
    if (
        not value
        or value.startswith(("/", "-"))
        or "\\" in value
        or "\x00" in value
        or len(encoded) > MAX_PATH_BYTES
        or unicodedata.normalize("NFC", value) != value
        or any(part in {"", ".", ".."} for part in pure.parts)
        or pure.as_posix() != value
    ):
        reject("tar contém path não canônico")
    return value


@dataclass(frozen=True)
class TreeEntry:
    path: str
    kind: str
    mode: int
    size: int
    sha256: str

    def record(self) -> bytes:
        return (
            self.kind.encode("ascii")
            + b"\0"
            + f"{self.mode:04o}".encode("ascii")
            + b"\0"
            + str(self.size).encode("ascii")
            + b"\0"
            + self.sha256.encode("ascii")
            + b"\0"
            + self.path.encode("utf-8")
            + b"\0"
        )


@dataclass(frozen=True)
class ArchiveInventory:
    entries: Mapping[str, TreeEntry]
    tree_sha256: str


def tree_digest(entries: Mapping[str, TreeEntry]) -> str:
    digest = hashlib.sha256()
    for path in sorted(entries, key=lambda item: item.encode("utf-8")):
        digest.update(entries[path].record())
    return digest.hexdigest()


def _tar_from_fd(descriptor: int) -> tuple[Any, tarfile.TarFile]:
    duplicate = os.dup(descriptor)
    os.lseek(duplicate, 0, os.SEEK_SET)
    handle = os.fdopen(duplicate, "rb", closefd=True)
    try:
        archive = tarfile.open(fileobj=handle, mode="r:gz")
    except (OSError, tarfile.TarError):
        handle.close()
        reject("archive Ops não é gzip/tar válido")
    return handle, archive


def validate_ops_archive(
    descriptor: int,
    info: os.stat_result,
    binding: AttestationBinding,
) -> ArchiveInventory:
    if info.st_size != binding.ops_size:
        reject("tamanho do archive Ops diverge da attestation")
    if digest_fd(descriptor, info, "archive Ops") != binding.ops_sha256:
        reject("hash do archive Ops diverge da attestation")
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.read(descriptor, 10) != bytes.fromhex(
        "1f8b08000000000002ff"
    ):
        reject("header gzip do archive Ops não é canônico")
    handle, archive = _tar_from_fd(descriptor)
    entries: dict[str, TreeEntry] = {}
    payloads: dict[str, bytes] = {}
    observed_order: list[str] = []
    total = 0
    directories: set[str] = set()
    try:
        if archive.pax_headers:
            reject("tar Ops contém PAX global")
        members = archive.getmembers()
        if not 1 <= len(members) <= MAX_MEMBERS:
            reject("quantidade de membros do tar Ops é inválida")
        for member in members:
            if member.pax_headers:
                reject("tar Ops contém PAX por membro")
            name = canonical_member_path(member.name)
            if name in entries:
                reject("tar Ops contém paths duplicados")
            if (
                member.uid != 0
                or member.gid != 0
                or member.uname != ""
                or member.gname != ""
                or member.mtime != 0
                or member.devmajor != 0
                or member.devminor != 0
            ):
                reject(f"metadados não canônicos no tar: {name}")
            observed_order.append(name)
            if member.isdir():
                if member.mode != 0o555 or member.size != 0:
                    reject(f"diretório não canônico no tar: {name}")
                entry = TreeEntry(
                    path=name,
                    kind="directory",
                    mode=0o555,
                    size=0,
                    sha256=hashlib.sha256(b"").hexdigest(),
                )
                directories.add(name)
                entries[name] = entry
                continue
            if (
                not member.isfile()
                or member.islnk()
                or member.issym()
                or member.mode not in {0o444, 0o555}
                or not 0 <= member.size <= MAX_MEMBER_BYTES
            ):
                reject(f"tipo, modo ou tamanho proibido no tar: {name}")
            total += member.size
            if total > MAX_UNCOMPRESSED_BYTES:
                reject("tar Ops excede limite descompactado")
            extracted = archive.extractfile(member)
            if extracted is None:
                reject(f"membro não pôde ser lido: {name}")
            payload = extracted.read(member.size + 1)
            if len(payload) != member.size:
                reject(f"tamanho do membro diverge: {name}")
            payloads[name] = payload
            entries[name] = TreeEntry(
                path=name,
                kind="file",
                mode=member.mode,
                size=member.size,
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        expected_order = (
            sorted(directories, key=lambda item: item.encode("utf-8"))
            + ["RELEASE_SHA", "artifact-manifest.json"]
            + sorted(
                set(entries)
                - directories
                - {"RELEASE_SHA", "artifact-manifest.json"},
                key=lambda item: item.encode("utf-8"),
            )
        )
        if observed_order != expected_order:
            reject("ordem do tar Ops não é canônica")
        expected_tar_size = (
            (archive.offset + 1024 + 10239) // 10240
        ) * 10240
        if expected_tar_size > (
            MAX_UNCOMPRESSED_BYTES
            + (MAX_MEMBERS * 512)
            + 10240
        ):
            reject("container tar Ops excede o limite")
        archive.fileobj.seek(archive.offset)
        tail = archive.fileobj.read(
            expected_tar_size - archive.offset + 1
        )
        if (
            len(tail) != expected_tar_size - archive.offset
            or any(tail)
            or archive.fileobj.read(1)
        ):
            reject("padding ou stream gzip/tar Ops não é canônico")
        for path, entry in entries.items():
            parent = str(PurePosixPath(path).parent)
            while parent not in {"", "."}:
                if parent not in directories:
                    reject(f"diretório pai ausente no tar: {parent}")
                parent = str(PurePosixPath(parent).parent)
        for path, mode in REQUIRED_FILES.items():
            entry = entries.get(path)
            if (
                entry is None
                or entry.kind != "file"
                or entry.mode != mode
            ):
                reject(f"inventário bootstrap mínimo ausente: {path}")
        if payloads["RELEASE_SHA"] != (
            binding.api_sha + "\n"
        ).encode("ascii"):
            reject("RELEASE_SHA do tar diverge")
        manifest_raw = payloads["artifact-manifest.json"]
        manifest = parse_canonical_json(
            manifest_raw,
            "manifesto Ops",
        )
        exact_object(
            manifest,
            {
                "approval_manifest_sha256",
                "artifact_kind",
                "build",
                "migration",
                "release_sha",
                "runtime_policy",
                "schema_version",
            },
            "manifesto Ops",
        )
        build = exact_object(
            manifest["build"],
            {
                "arch",
                "os",
                "python",
                "shell",
                "tree_digest_algorithm",
            },
            "build do manifesto Ops",
        )
        runtime_policy = exact_object(
            manifest["runtime_policy"],
            {"name", "sha256"},
            "runtime policy do manifesto Ops",
        )
        if (
            manifest.get("schema_version") != 4
            or manifest.get("artifact_kind") != "tratto-control-ops"
            or manifest.get("release_sha") != binding.api_sha
            or manifest.get("approval_manifest_sha256")
            != binding.approval_sha256
            or manifest.get("migration") != binding.migration
            or build
            != {
                "arch": "x86_64",
                "os": "Linux",
                "python": "3.12.13",
                "shell": "bash",
                "tree_digest_algorithm": "tratto-tree-v1",
            }
            or runtime_policy.get("name") != "control-runtime-v1"
            or HASH_RE.fullmatch(
                str(runtime_policy.get("sha256"))
            )
            is None
        ):
            reject("manifesto Ops diverge da attestation")
        return ArchiveInventory(
            entries=entries,
            tree_sha256=tree_digest(entries),
        )
    finally:
        archive.close()
        handle.close()
        if digest_fd(descriptor, info, "archive Ops") != binding.ops_sha256:
            reject("archive Ops mudou após a validação")


def open_relative_directory(
    root_descriptor: int,
    relative: str,
    *,
    uid: int,
    gid: int,
    modes: set[int],
) -> int:
    descriptor = os.dup(root_descriptor)
    try:
        if relative in {"", "."}:
            validate_directory(
                os.fstat(descriptor),
                "raiz relativa",
                uid=uid,
                gid=gid,
                modes=modes,
            )
            return descriptor
        for part in PurePosixPath(relative).parts:
            child = os.open(
                part,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            validate_directory(
                os.fstat(child),
                relative,
                uid=uid,
                gid=gid,
                modes=modes,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def scan_tree(
    descriptor: int,
    *,
    uid: int,
    gid: int,
    root_modes: set[int] = {0o555},
    directory_modes: set[int] = {0o555},
    file_modes: set[int] = {0o444, 0o555},
) -> dict[str, TreeEntry]:
    validate_directory(
        os.fstat(descriptor),
        "raiz da fonte bootstrap",
        uid=uid,
        gid=gid,
        modes=root_modes,
    )
    entries: dict[str, TreeEntry] = {}
    total = 0

    def visit(current: int, relative: str) -> None:
        nonlocal total
        try:
            names = os.listdir(current)
        except OSError:
            reject("fonte bootstrap não pôde ser enumerada")
        for name in sorted(names, key=lambda item: item.encode("utf-8")):
            path = name if not relative else f"{relative}/{name}"
            canonical_member_path(path)
            if len(entries) >= MAX_TREE_ENTRIES:
                reject("fonte bootstrap possui entradas demais")
            info = os.stat(name, dir_fd=current, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                validate_directory(
                    info,
                    path,
                    uid=uid,
                    gid=gid,
                    modes=directory_modes,
                )
                child = os.open(
                    name,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    dir_fd=current,
                )
                try:
                    require_same_mount(descriptor, child, path)
                    entries[path] = TreeEntry(
                        path=path,
                        kind="directory",
                        mode=stat.S_IMODE(info.st_mode),
                        size=0,
                        sha256=hashlib.sha256(b"").hexdigest(),
                    )
                    visit(child, path)
                finally:
                    os.close(child)
                continue
            validate_regular(
                info,
                path,
                uid=uid,
                gid=gid,
                modes=file_modes,
                maximum=MAX_MEMBER_BYTES,
                allow_empty=True,
            )
            child = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current,
            )
            try:
                opened = os.fstat(child)
                validate_regular(
                    opened,
                    path,
                    uid=uid,
                    gid=gid,
                    modes=file_modes,
                    maximum=MAX_MEMBER_BYTES,
                    allow_empty=True,
                )
                total += opened.st_size
                if total > MAX_TREE_BYTES:
                    reject("fonte bootstrap excede o limite")
                digest = digest_fd(child, opened, path)
            finally:
                os.close(child)
            entries[path] = TreeEntry(
                path=path,
                kind="file",
                mode=stat.S_IMODE(info.st_mode),
                size=info.st_size,
                sha256=digest,
            )

    visit(descriptor, "")
    return entries


def validate_exact_tree(
    descriptor: int,
    inventory: ArchiveInventory,
    *,
    uid: int,
    gid: int,
) -> None:
    observed = scan_tree(descriptor, uid=uid, gid=gid)
    if observed != dict(inventory.entries):
        reject("fonte bootstrap publicada diverge do archive assinado")


def _open_named_directory(
    parent: int,
    name: str,
    *,
    uid: int,
    gid: int,
    modes: set[int],
) -> int | None:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            dir_fd=parent,
        )
    except FileNotFoundError:
        return None
    try:
        validate_directory(
            os.fstat(descriptor),
            name,
            uid=uid,
            gid=gid,
            modes=modes,
        )
        require_same_mount(parent, descriptor, name)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def create_candidate(
    state_descriptor: int,
    candidate_name: str,
    archive_descriptor: int,
    archive_info: os.stat_result,
    inventory: ArchiveInventory,
    *,
    uid: int,
    gid: int,
) -> int:
    os.mkdir(candidate_name, 0o700, dir_fd=state_descriptor)
    os.fsync(state_descriptor)
    candidate = _open_named_directory(
        state_descriptor,
        candidate_name,
        uid=uid,
        gid=gid,
        modes={0o700},
    )
    if candidate is None:
        reject("candidate desapareceu após criação")
    try:
        directories = sorted(
            (
                path
                for path, entry in inventory.entries.items()
                if entry.kind == "directory"
            ),
            key=lambda item: (
                len(PurePosixPath(item).parts),
                item.encode("utf-8"),
            ),
        )
        for relative in directories:
            parent_name = str(PurePosixPath(relative).parent)
            parent = open_relative_directory(
                candidate,
                parent_name,
                uid=uid,
                gid=gid,
                modes={0o700},
            )
            try:
                os.mkdir(
                    PurePosixPath(relative).name,
                    0o700,
                    dir_fd=parent,
                )
                os.fsync(parent)
            finally:
                os.close(parent)

        handle, archive = _tar_from_fd(archive_descriptor)
        try:
            for member in archive.getmembers():
                entry = inventory.entries[member.name]
                if entry.kind != "file":
                    continue
                parent_name = str(PurePosixPath(entry.path).parent)
                parent = open_relative_directory(
                    candidate,
                    parent_name,
                    uid=uid,
                    gid=gid,
                    modes={0o700},
                )
                try:
                    target = os.open(
                        PurePosixPath(entry.path).name,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_CLOEXEC
                        | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=parent,
                    )
                    try:
                        source = archive.extractfile(member)
                        if source is None:
                            reject("payload do tar desapareceu")
                        digest = hashlib.sha256()
                        remaining = entry.size
                        while remaining:
                            chunk = source.read(min(1024 * 1024, remaining))
                            if not chunk:
                                reject("payload do tar terminou cedo")
                            digest.update(chunk)
                            write_all(target, chunk)
                            remaining -= len(chunk)
                        if source.read(1):
                            reject("payload do tar excedeu o tamanho")
                        if digest.hexdigest() != entry.sha256:
                            reject("payload do tar diverge do inventário")
                        os.fchown(target, uid, gid)
                        os.fchmod(target, entry.mode)
                        os.fsync(target)
                    finally:
                        os.close(target)
                    os.fsync(parent)
                finally:
                    os.close(parent)
        finally:
            archive.close()
            handle.close()

        for relative in sorted(
            directories,
            key=lambda item: (
                -len(PurePosixPath(item).parts),
                item.encode("utf-8"),
            ),
        ):
            directory = open_relative_directory(
                candidate,
                relative,
                uid=uid,
                gid=gid,
                modes={0o700},
            )
            try:
                os.fchmod(directory, 0o555)
                os.fsync(directory)
            finally:
                os.close(directory)
        os.fchown(candidate, uid, gid)
        os.fchmod(candidate, 0o555)
        os.fsync(candidate)
        os.fsync(state_descriptor)
        validate_exact_tree(
            candidate,
            inventory,
            uid=uid,
            gid=gid,
        )
        digest_fd(
            archive_descriptor,
            archive_info,
            "archive Ops",
        )
        return candidate
    except Exception:
        os.close(candidate)
        raise


def remove_safe_tree(
    parent: int,
    name: str,
    *,
    uid: int,
    gid: int,
) -> None:
    root = _open_named_directory(
        parent,
        name,
        uid=uid,
        gid=gid,
        modes={0o700, 0o555},
    )
    if root is None:
        return

    def remove_contents(descriptor: int) -> None:
        for child_name in os.listdir(descriptor):
            if (
                not child_name
                or "/" in child_name
                or child_name in {".", ".."}
            ):
                reject("candidate parcial contém nome inválido")
            info = os.stat(
                child_name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
            if stat.S_ISDIR(info.st_mode):
                validate_directory(
                    info,
                    child_name,
                    uid=uid,
                    gid=gid,
                    modes={0o700, 0o555},
                )
                child = os.open(
                    child_name,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                try:
                    remove_contents(child)
                finally:
                    os.close(child)
                os.rmdir(child_name, dir_fd=descriptor)
            else:
                validate_regular(
                    info,
                    child_name,
                    uid=uid,
                    gid=gid,
                    modes={0o600, 0o400, 0o444, 0o555},
                    maximum=MAX_MEMBER_BYTES,
                    allow_empty=True,
                )
                os.unlink(child_name, dir_fd=descriptor)
        os.fsync(descriptor)

    try:
        remove_contents(root)
    finally:
        os.close(root)
    os.rmdir(name, dir_fd=parent)
    os.fsync(parent)


def libc_rename(
    old_parent: int,
    old_name: str,
    new_parent: int,
    new_name: str,
    flags: int,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        reject("renameat2 é obrigatório")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        old_parent,
        os.fsencode(old_name),
        new_parent,
        os.fsencode(new_name),
        flags,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


@dataclass(frozen=True)
class Runtime:
    exchange: Callable[[int, str, int, str], None]
    noreplace: Callable[[int, str, int, str], None]


def production_runtime() -> Runtime:
    return Runtime(
        exchange=lambda a, b, c, d: libc_rename(
            a,
            b,
            c,
            d,
            RENAME_EXCHANGE,
        ),
        noreplace=lambda a, b, c, d: libc_rename(
            a,
            b,
            c,
            d,
            RENAME_NOREPLACE,
        ),
    )


def marker_payload(
    *,
    kit_id: str,
    phase: str,
    old_digest: str,
    new_digest: str,
) -> bytes:
    return canonical_bytes(
        {
            "contract": CONTRACT,
            "kit_id": kit_id,
            "new_source_tree_sha256": new_digest,
            "old_source_tree_sha256": old_digest,
            "phase": phase,
            "schema_version": 1,
        }
    )


def publish_record(
    parent: int,
    final_name: str,
    payload: bytes,
    *,
    kit_id: str,
    uid: int,
    gid: int,
    runtime: Runtime,
) -> None:
    phase = final_name.removeprefix("bootstrap-source-kit.").removesuffix(
        ".json"
    )
    temporary = f"bootstrap-source-kit.{phase}.{kit_id}.installing"
    try:
        final = os.open(
            final_name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
    except FileNotFoundError:
        final = -1
    if final >= 0:
        try:
            info = os.fstat(final)
            validate_regular(
                info,
                final_name,
                uid=uid,
                gid=gid,
                modes={0o444},
                maximum=MAX_JSON_BYTES,
            )
            if read_all(
                final,
                info,
                maximum=MAX_JSON_BYTES,
                label=final_name,
            ) != payload:
                reject(f"record append-only diverge: {final_name}")
        finally:
            os.close(final)
        try:
            os.unlink(temporary, dir_fd=parent)
            os.fsync(parent)
        except FileNotFoundError:
            pass
        return

    temporary_fd = -1
    immutable_complete = False
    try:
        temporary_fd = os.open(
            temporary,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
    except FileExistsError:
        observed = os.open(
            temporary,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        try:
            observed_info = os.fstat(observed)
            validate_regular(
                observed_info,
                temporary,
                uid=uid,
                gid=gid,
                modes={0o600, 0o444},
                maximum=MAX_JSON_BYTES,
                allow_empty=True,
            )
            partial = (
                read_all(
                    observed,
                    observed_info,
                    maximum=MAX_JSON_BYTES,
                    label=temporary,
                )
                if observed_info.st_size
                else b""
            )
        finally:
            os.close(observed)
        if not payload.startswith(partial):
            reject(f"record parcial diverge: {temporary}")
        if stat.S_IMODE(observed_info.st_mode) == 0o444:
            if partial != payload:
                reject(
                    f"record parcial imutável está incompleto: {temporary}"
                )
            immutable_complete = True
        else:
            temporary_fd = os.open(
                temporary,
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent,
            )
            reopened = os.fstat(temporary_fd)
            if (
                reopened.st_dev,
                reopened.st_ino,
                reopened.st_mode,
                reopened.st_size,
                reopened.st_mtime_ns,
                reopened.st_ctime_ns,
            ) != (
                observed_info.st_dev,
                observed_info.st_ino,
                observed_info.st_mode,
                observed_info.st_size,
                observed_info.st_mtime_ns,
                observed_info.st_ctime_ns,
            ):
                os.close(temporary_fd)
                temporary_fd = -1
                reject("record parcial mudou antes da retomada")
    if not immutable_complete:
        assert temporary_fd >= 0
        try:
            info = os.fstat(temporary_fd)
            validate_regular(
                info,
                temporary,
                uid=uid,
                gid=gid,
                modes={0o600, 0o444},
                maximum=MAX_JSON_BYTES,
                allow_empty=True,
            )
            partial = (
                read_all(
                    temporary_fd,
                    info,
                    maximum=MAX_JSON_BYTES,
                    label=temporary,
                )
                if info.st_size
                else b""
            )
            if not payload.startswith(partial):
                reject(f"record parcial diverge: {temporary}")
            if partial != payload:
                if stat.S_IMODE(info.st_mode) == 0o444:
                    reject(
                        "record parcial imutável está incompleto: "
                        f"{temporary}"
                    )
                os.lseek(temporary_fd, len(partial), os.SEEK_SET)
                write_all(temporary_fd, payload[len(partial) :])
                os.fsync(temporary_fd)
            os.fchmod(temporary_fd, 0o444)
            os.fsync(temporary_fd)
        finally:
            os.close(temporary_fd)
    try:
        runtime.noreplace(parent, temporary, parent, final_name)
    except FileExistsError:
        pass
    os.fsync(parent)
    final = os.open(
        final_name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=parent,
    )
    try:
        info = os.fstat(final)
        validate_regular(
            info,
            final_name,
            uid=uid,
            gid=gid,
            modes={0o444},
            maximum=MAX_JSON_BYTES,
        )
        if read_all(
            final,
            info,
            maximum=MAX_JSON_BYTES,
            label=final_name,
        ) != payload:
            reject(f"record final diverge: {final_name}")
    finally:
        os.close(final)
    try:
        os.unlink(temporary, dir_fd=parent)
        os.fsync(parent)
    except FileNotFoundError:
        pass


def reject_foreign_state(
    state_descriptor: int,
    kit_id: str,
    *,
    uid: int,
    gid: int,
) -> None:
    allowed = {
        SOURCE_NAME,
        f"{CANDIDATE_PREFIX}{kit_id}",
        f"{PREVIOUS_PREFIX}{kit_id}",
        INTENT_NAME,
        PREPARED_NAME,
        EXCHANGED_NAME,
        RETAINED_NAME,
        USED_NAME,
    }
    for name in os.listdir(state_descriptor):
        match = STATE_TEMP_RE.fullmatch(name)
        if match:
            if match.group(2) != kit_id:
                reject("há record parcial de outro bootstrap source kit")
            allowed.add(name)
        if (
            name.startswith(CANDIDATE_PREFIX)
            or name.startswith(PREVIOUS_PREFIX)
        ) and name not in allowed:
            reject("há source kit anterior ou concorrente não reconciliado")
    for name in (
        INTENT_NAME,
        PREPARED_NAME,
        EXCHANGED_NAME,
        RETAINED_NAME,
        USED_NAME,
    ):
        raw = read_record_if_present(
            state_descriptor,
            name,
            uid=uid,
            gid=gid,
        )
        if raw is None:
            continue
        value = parse_canonical_json(raw, name)
        if (
            value.get("contract") != CONTRACT
            or value.get("kit_id") != kit_id
        ):
            reject("record append-only pertence a outro source kit")


def read_record_if_present(
    parent: int,
    name: str,
    *,
    uid: int,
    gid: int,
) -> bytes | None:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(descriptor)
        validate_regular(
            info,
            name,
            uid=uid,
            gid=gid,
            modes={0o444},
            maximum=MAX_JSON_BYTES,
        )
        return read_all(
            descriptor,
            info,
            maximum=MAX_JSON_BYTES,
            label=name,
        )
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class InstallInputs:
    incoming_descriptor: int
    helper_descriptor: int
    helper_info: os.stat_result
    helper_bundle_descriptor: int
    attestation_descriptor: int
    attestation_info: os.stat_result
    attestation_bundle_descriptor: int
    archive_descriptor: int
    archive_info: os.stat_result
    archive_bundle_descriptor: int
    binding: AttestationBinding

    def close(self) -> None:
        for descriptor in (
            self.helper_descriptor,
            self.helper_bundle_descriptor,
            self.attestation_descriptor,
            self.attestation_bundle_descriptor,
            self.archive_descriptor,
            self.archive_bundle_descriptor,
            self.incoming_descriptor,
        ):
            os.close(descriptor)


def open_and_validate_inputs(
    incoming: Path,
    *,
    uid: int,
    gid: int,
    execution_descriptor: int,
    expectations: BootstrapExpectations,
    signature_verifier: (
        Callable[[int, int, int, str], None] | None
    ) = None,
) -> InstallInputs:
    validate_expectations(expectations)
    try:
        execution_info = os.fstat(execution_descriptor)
        execution_flags = fcntl.fcntl(
            execution_descriptor,
            fcntl.F_GETFL,
        )
    except OSError:
        reject("FD de execução do helper está fechado")
    if (execution_flags & os.O_ACCMODE) != os.O_RDONLY:
        reject("FD de execução do helper precisa ser somente leitura")
    validate_regular(
        execution_info,
        "FD de execução do helper",
        uid=uid,
        gid=gid,
        modes={0o400},
        maximum=MAX_HELPER_BYTES,
    )
    incoming_descriptor = open_path_chain(
        incoming,
        uid=uid,
        gid=gid,
        final_modes={0o700},
    )
    opened: list[int] = []
    try:
        helper, helper_info = open_input(
            incoming_descriptor,
            HELPER_NAME,
            uid=uid,
            gid=gid,
            maximum=MAX_HELPER_BYTES,
        )
        opened.append(helper)
        stable_identity = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(execution_info, field)
            != getattr(helper_info, field)
            for field in stable_identity
        ):
            reject(
                "FD de execução não aponta para o helper fixo protegido"
            )
        execution_hash = digest_fd(
            execution_descriptor,
            execution_info,
            "FD de execução do helper",
        )
        helper_hash = digest_fd(
            helper,
            helper_info,
            "bootstrap source helper",
        )
        if (
            execution_hash != expectations.helper_sha256
            or helper_hash != expectations.helper_sha256
        ):
            reject("hash esperado do helper diverge")
        helper_bundle, _ = open_input(
            incoming_descriptor,
            HELPER_BUNDLE_NAME,
            uid=uid,
            gid=gid,
            maximum=MAX_BUNDLE_BYTES,
        )
        opened.append(helper_bundle)
        attestation, attestation_info = open_input(
            incoming_descriptor,
            ATTESTATION_NAME,
            uid=uid,
            gid=gid,
            maximum=MAX_JSON_BYTES,
        )
        opened.append(attestation)
        attestation_bundle, _ = open_input(
            incoming_descriptor,
            ATTESTATION_BUNDLE_NAME,
            uid=uid,
            gid=gid,
            maximum=MAX_BUNDLE_BYTES,
        )
        opened.append(attestation_bundle)
        attestation_raw = read_all(
            attestation,
            attestation_info,
            maximum=MAX_JSON_BYTES,
            label="release attestation",
        )
        if (
            hashlib.sha256(attestation_raw).hexdigest()
            != expectations.attestation_sha256
        ):
            reject("hash esperado da release attestation diverge")
        binding = validate_attestation(
            attestation_raw,
            helper_sha256=helper_hash,
            helper_size_bytes=helper_info.st_size,
            expected_carrier_sha=expectations.carrier_sha,
            expected_controller_sha=expectations.controller_sha,
        )
        archive, archive_info = open_input(
            incoming_descriptor,
            binding.ops_name,
            uid=uid,
            gid=gid,
            maximum=MAX_ARCHIVE_BYTES,
        )
        opened.append(archive)
        archive_bundle, _ = open_input(
            incoming_descriptor,
            OPS_BUNDLE_NAME,
            uid=uid,
            gid=gid,
            maximum=MAX_BUNDLE_BYTES,
        )
        opened.append(archive_bundle)
        identities = {
            (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
            for descriptor in opened
        }
        if len(identities) != len(opened):
            reject("inputs do source kit compartilham inode")
        verifier = signature_verifier
        cosign_descriptor = -1
        if verifier is None:
            cosign_descriptor = open_cosign(uid=uid, gid=gid)
            verifier = verify_cosign_blob
        try:
            verifier(
                cosign_descriptor,
                helper,
                helper_bundle,
                expectations.carrier_sha,
            )
            verifier(
                cosign_descriptor,
                attestation,
                attestation_bundle,
                expectations.carrier_sha,
            )
            verifier(
                cosign_descriptor,
                archive,
                archive_bundle,
                expectations.carrier_sha,
            )
        finally:
            if cosign_descriptor >= 0:
                os.close(cosign_descriptor)
        return InstallInputs(
            incoming_descriptor=incoming_descriptor,
            helper_descriptor=helper,
            helper_info=helper_info,
            helper_bundle_descriptor=helper_bundle,
            attestation_descriptor=attestation,
            attestation_info=attestation_info,
            attestation_bundle_descriptor=attestation_bundle,
            archive_descriptor=archive,
            archive_info=archive_info,
            archive_bundle_descriptor=archive_bundle,
            binding=binding,
        )
    except Exception:
        for descriptor in reversed(opened):
            os.close(descriptor)
        os.close(incoming_descriptor)
        raise


def kit_identity(
    binding: AttestationBinding,
    inventory: ArchiveInventory,
) -> str:
    return hashlib.sha256(
        canonical_bytes(
            {
                "api_sha": binding.api_sha,
                "attestation_sha256": binding.raw_sha256,
                "carrier_sha": binding.carrier_sha,
                "contract": CONTRACT,
                "controller_sha": binding.controller_sha,
                "helper_sha256": binding.helper_sha256,
                "ops_sha256": binding.ops_sha256,
                "source_tree_sha256": inventory.tree_sha256,
            }
        )
    ).hexdigest()


def intent_payload(
    binding: AttestationBinding,
    inventory: ArchiveInventory,
    kit_id: str,
    old_digest: str,
) -> bytes:
    return canonical_bytes(
        {
            "api_sha": binding.api_sha,
            "archive_name": binding.ops_name,
            "attestation_sha256": binding.raw_sha256,
            "carrier_sha": binding.carrier_sha,
            "contract": CONTRACT,
            "controller_sha": binding.controller_sha,
            "helper_sha256": binding.helper_sha256,
            "kit_id": kit_id,
            "new_source_tree_sha256": inventory.tree_sha256,
            "old_source_tree_sha256": old_digest,
            "ops_sha256": binding.ops_sha256,
            "schema_version": 1,
        }
    )


def verify_inherited_lock(
    *,
    uid: int,
    gid: int,
    lock_directory: Path = LOCK_DIRECTORY,
) -> int:
    raw = os.environ.get(LOCK_FD_ENV, "")
    if (
        not raw.isdigit()
        or os.environ.get(LOCK_HELD_ENV) != "1"
    ):
        reject("deploy.lock herdado está ausente")
    inherited = int(raw)
    try:
        inherited_info = os.fstat(inherited)
    except OSError:
        reject("deploy.lock herdado está fechado")
    directory = open_path_chain(
        lock_directory,
        uid=uid,
        gid=gid,
        final_modes={0o700},
    )
    try:
        check = os.open(
            LOCK_NAME,
            os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory,
        )
    finally:
        os.close(directory)
    try:
        check_info = os.fstat(check)
        validate_regular(
            check_info,
            "deploy.lock",
            uid=uid,
            gid=gid,
            modes={0o600},
            maximum=1024,
            allow_empty=True,
        )
        if (
            inherited_info.st_dev,
            inherited_info.st_ino,
        ) != (
            check_info.st_dev,
            check_info.st_ino,
        ):
            reject("deploy.lock herdado aponta para outro inode")
        try:
            fcntl.flock(check, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return inherited
        reject("deploy.lock herdado não está efetivamente bloqueado")
    finally:
        os.close(check)


def run_publisher(
    source_descriptor: int,
    lock_descriptor: int,
) -> str:
    fixed_publisher = (
        STATE_ROOT
        / SOURCE_NAME
        / "scripts"
        / "publish-bootstrap-tree.py"
    )
    scripts = open_relative_directory(
        source_descriptor,
        "scripts",
        uid=EXPECTED_UID,
        gid=EXPECTED_GID,
        modes={0o555},
    )
    try:
        publisher = os.open(
            "publish-bootstrap-tree.py",
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=scripts,
        )
    finally:
        os.close(scripts)
    try:
        info = os.fstat(publisher)
        validate_regular(
            info,
            "publisher bootstrap",
            uid=EXPECTED_UID,
            gid=EXPECTED_GID,
            modes={0o555},
            maximum=MAX_MEMBER_BYTES,
        )
        fixed_info = os.stat(
            fixed_publisher,
            follow_symlinks=False,
        )
        if (
            fixed_info.st_dev,
            fixed_info.st_ino,
            fixed_info.st_mode,
            fixed_info.st_uid,
            fixed_info.st_gid,
        ) != (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_gid,
        ):
            reject("publisher fixo diverge do snapshot validado")
        result = subprocess.run(
            [
                str(PYTHON),
                "-I",
                "-B",
                str(fixed_publisher),
                "upgrade",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                LOCK_FD_ENV: str(lock_descriptor),
                LOCK_HELD_ENV: "1",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
            pass_fds=(lock_descriptor,),
            check=False,
            timeout=300,
        )
    finally:
        os.close(publisher)
    if result.returncode != 0:
        reject("publisher da árvore bootstrap recusou o upgrade")
    try:
        output = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError:
        reject("publisher bootstrap retornou saída inválida")
    if output not in {"upgraded", "already-upgraded"}:
        reject("publisher bootstrap retornou resultado inesperado")
    return output


def install_source(
    *,
    incoming: Path,
    state_root: Path,
    uid: int,
    gid: int,
    execution_descriptor: int,
    expectations: BootstrapExpectations,
    runtime: Runtime,
    signature_verifier: (
        Callable[[int, int, int, str], None] | None
    ),
    publisher: Callable[[int, int], str],
    lock_descriptor: int,
    fault: Callable[[str], None] = lambda _event: None,
) -> str:
    inputs = open_and_validate_inputs(
        incoming,
        uid=uid,
        gid=gid,
        execution_descriptor=execution_descriptor,
        expectations=expectations,
        signature_verifier=signature_verifier,
    )
    try:
        inventory = validate_ops_archive(
            inputs.archive_descriptor,
            inputs.archive_info,
            inputs.binding,
        )
        kit_id = kit_identity(inputs.binding, inventory)
        state = open_path_chain(
            state_root,
            uid=uid,
            gid=gid,
            final_modes={0o555, 0o755},
        )
        try:
            reject_foreign_state(
                state,
                kit_id,
                uid=uid,
                gid=gid,
            )
            source = _open_named_directory(
                state,
                SOURCE_NAME,
                uid=uid,
                gid=gid,
                modes={0o555},
            )
            if source is None:
                reject("fonte bootstrap anterior está ausente")
            try:
                old_entries = scan_tree(source, uid=uid, gid=gid)
                observed_digest = tree_digest(old_entries)
            finally:
                os.close(source)

            existing_intent = read_record_if_present(
                state,
                INTENT_NAME,
                uid=uid,
                gid=gid,
            )
            if existing_intent is None:
                old_digest = observed_digest
            else:
                intent = parse_canonical_json(
                    existing_intent,
                    "bootstrap source intent",
                )
                if (
                    intent.get("contract") != CONTRACT
                    or intent.get("kit_id") != kit_id
                ):
                    reject("source kit diferente já foi iniciado")
                old_digest = require_hash(
                    intent.get("old_source_tree_sha256"),
                    "old source digest",
                )
            intent_raw = intent_payload(
                inputs.binding,
                inventory,
                kit_id,
                old_digest,
            )
            publish_record(
                state,
                INTENT_NAME,
                intent_raw,
                kit_id=kit_id,
                uid=uid,
                gid=gid,
                runtime=runtime,
            )
            fault("after_intent")

            used = read_record_if_present(
                state,
                USED_NAME,
                uid=uid,
                gid=gid,
            )
            if used is not None:
                expected_used = marker_payload(
                    kit_id=kit_id,
                    phase="used",
                    old_digest=old_digest,
                    new_digest=inventory.tree_sha256,
                )
                if used != expected_used:
                    reject("used marker diverge do source kit")
                final = _open_named_directory(
                    state,
                    SOURCE_NAME,
                    uid=uid,
                    gid=gid,
                    modes={0o555},
                )
                if final is None:
                    reject("fonte usada desapareceu")
                try:
                    validate_exact_tree(
                        final,
                        inventory,
                        uid=uid,
                        gid=gid,
                    )
                finally:
                    os.close(final)
                return "already-installed"

            candidate_name = f"{CANDIDATE_PREFIX}{kit_id}"
            previous_name = f"{PREVIOUS_PREFIX}{kit_id}"
            final = _open_named_directory(
                state,
                SOURCE_NAME,
                uid=uid,
                gid=gid,
                modes={0o555},
            )
            if final is None:
                reject("fonte bootstrap desapareceu")
            try:
                final_entries = scan_tree(final, uid=uid, gid=gid)
                final_digest = tree_digest(final_entries)
                final_is_new = final_entries == dict(inventory.entries)
            finally:
                os.close(final)

            previous = _open_named_directory(
                state,
                previous_name,
                uid=uid,
                gid=gid,
                modes={0o555},
            )
            if previous is not None:
                try:
                    previous_digest = tree_digest(
                        scan_tree(previous, uid=uid, gid=gid)
                    )
                finally:
                    os.close(previous)
                if previous_digest != old_digest:
                    reject("fonte bootstrap anterior retida diverge")

            if final_is_new:
                if old_digest != inventory.tree_sha256:
                    publish_record(
                        state,
                        EXCHANGED_NAME,
                        marker_payload(
                            kit_id=kit_id,
                            phase="exchanged",
                            old_digest=old_digest,
                            new_digest=inventory.tree_sha256,
                        ),
                        kit_id=kit_id,
                        uid=uid,
                        gid=gid,
                        runtime=runtime,
                    )
                if old_digest != inventory.tree_sha256 and previous is None:
                    candidate = _open_named_directory(
                        state,
                        candidate_name,
                        uid=uid,
                        gid=gid,
                        modes={0o555},
                    )
                    if candidate is None:
                        reject("exchange ocorreu sem fonte anterior recuperável")
                    try:
                        candidate_digest = tree_digest(
                            scan_tree(candidate, uid=uid, gid=gid)
                        )
                    finally:
                        os.close(candidate)
                    if candidate_digest != old_digest:
                        reject("candidate pós-exchange não é a fonte anterior")
                    try:
                        runtime.noreplace(
                            state,
                            candidate_name,
                            state,
                            previous_name,
                        )
                    except FileExistsError:
                        reject("retenção concorrente do bootstrap foi recusada")
                    os.fsync(state)
                    fault("after_retention_rename")
                publish_record(
                    state,
                    RETAINED_NAME,
                    marker_payload(
                        kit_id=kit_id,
                        phase="retained",
                        old_digest=old_digest,
                        new_digest=inventory.tree_sha256,
                    ),
                    kit_id=kit_id,
                    uid=uid,
                    gid=gid,
                    runtime=runtime,
                )
            else:
                if final_digest != old_digest:
                    reject("fonte fixa não corresponde ao estado pré-upgrade")
                candidate = _open_named_directory(
                    state,
                    candidate_name,
                    uid=uid,
                    gid=gid,
                    modes={0o555, 0o700},
                )
                if candidate is not None:
                    try:
                        candidate_exact = False
                        if stat.S_IMODE(os.fstat(candidate).st_mode) == 0o555:
                            candidate_exact = (
                                scan_tree(candidate, uid=uid, gid=gid)
                                == dict(inventory.entries)
                            )
                    finally:
                        os.close(candidate)
                    if not candidate_exact:
                        remove_safe_tree(
                            state,
                            candidate_name,
                            uid=uid,
                            gid=gid,
                        )
                        candidate = None
                if candidate is None:
                    candidate = create_candidate(
                        state,
                        candidate_name,
                        inputs.archive_descriptor,
                        inputs.archive_info,
                        inventory,
                        uid=uid,
                        gid=gid,
                    )
                    os.close(candidate)
                publish_record(
                    state,
                    PREPARED_NAME,
                    marker_payload(
                        kit_id=kit_id,
                        phase="prepared",
                        old_digest=old_digest,
                        new_digest=inventory.tree_sha256,
                    ),
                    kit_id=kit_id,
                    uid=uid,
                    gid=gid,
                    runtime=runtime,
                )
                fault("after_candidate")
                runtime.exchange(
                    state,
                    SOURCE_NAME,
                    state,
                    candidate_name,
                )
                os.fsync(state)
                fault("after_exchange")
                published = _open_named_directory(
                    state,
                    SOURCE_NAME,
                    uid=uid,
                    gid=gid,
                    modes={0o555},
                )
                if published is None:
                    reject("rename exchange removeu a fonte fixa")
                valid = False
                try:
                    validate_exact_tree(
                        published,
                        inventory,
                        uid=uid,
                        gid=gid,
                    )
                    valid = True
                except BootstrapSourceError:
                    valid = False
                finally:
                    os.close(published)
                if not valid:
                    runtime.exchange(
                        state,
                        SOURCE_NAME,
                        state,
                        candidate_name,
                    )
                    os.fsync(state)
                    restored = _open_named_directory(
                        state,
                        SOURCE_NAME,
                        uid=uid,
                        gid=gid,
                        modes={0o555},
                    )
                    if restored is None:
                        reject("rollback atômico perdeu a fonte anterior")
                    try:
                        restored_digest = tree_digest(
                            scan_tree(restored, uid=uid, gid=gid)
                        )
                    finally:
                        os.close(restored)
                    if restored_digest != old_digest:
                        reject("rollback atômico não restaurou a fonte")
                    reject("nova fonte falhou revalidação e foi revertida")
                publish_record(
                    state,
                    EXCHANGED_NAME,
                    marker_payload(
                        kit_id=kit_id,
                        phase="exchanged",
                        old_digest=old_digest,
                        new_digest=inventory.tree_sha256,
                    ),
                    kit_id=kit_id,
                    uid=uid,
                    gid=gid,
                    runtime=runtime,
                )
                candidate = _open_named_directory(
                    state,
                    candidate_name,
                    uid=uid,
                    gid=gid,
                    modes={0o555},
                )
                if candidate is None:
                    reject("fonte anterior sumiu após exchange")
                try:
                    candidate_digest = tree_digest(
                        scan_tree(candidate, uid=uid, gid=gid)
                    )
                finally:
                    os.close(candidate)
                if candidate_digest != old_digest:
                    reject("fonte anterior pós-exchange diverge")
                runtime.noreplace(
                    state,
                    candidate_name,
                    state,
                    previous_name,
                )
                os.fsync(state)
                fault("after_retention_rename")
                publish_record(
                    state,
                    RETAINED_NAME,
                    marker_payload(
                        kit_id=kit_id,
                        phase="retained",
                        old_digest=old_digest,
                        new_digest=inventory.tree_sha256,
                    ),
                    kit_id=kit_id,
                    uid=uid,
                    gid=gid,
                    runtime=runtime,
                )
            fault("before_publisher")
            source = _open_named_directory(
                state,
                SOURCE_NAME,
                uid=uid,
                gid=gid,
                modes={0o555},
            )
            if source is None:
                reject("nova fonte sumiu antes do publisher")
            try:
                validate_exact_tree(
                    source,
                    inventory,
                    uid=uid,
                    gid=gid,
                )
                publisher_result = publisher(source, lock_descriptor)
            finally:
                os.close(source)
            if publisher_result not in {"upgraded", "already-upgraded"}:
                reject("publisher callback retornou resultado inválido")
            fault("after_publisher")
            publish_record(
                state,
                USED_NAME,
                marker_payload(
                    kit_id=kit_id,
                    phase="used",
                    old_digest=old_digest,
                    new_digest=inventory.tree_sha256,
                ),
                kit_id=kit_id,
                uid=uid,
                gid=gid,
                runtime=runtime,
            )
            return "installed"
        finally:
            os.close(state)
    finally:
        inputs.close()


class FailClosedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        reject(f"CLI do helper é inválida: {message}")


def parse_cli(argv: list[str]) -> argparse.Namespace:
    parser = FailClosedArgumentParser(
        allow_abbrev=False,
        add_help=False,
    )
    parser.add_argument("--helper-fd", required=True, type=int)
    parser.add_argument("--expected-helper-sha256", required=True)
    parser.add_argument("--expected-attestation-sha256", required=True)
    parser.add_argument("--expected-carrier-sha", required=True)
    parser.add_argument("--expected-controller-sha", required=True)
    required_options = (
        "--helper-fd",
        "--expected-helper-sha256",
        "--expected-attestation-sha256",
        "--expected-carrier-sha",
        "--expected-controller-sha",
    )
    if len(argv) != 2 * len(required_options) or any(
        argv.count(option) != 1 for option in required_options
    ):
        reject("CLI do helper exige cada binding exatamente uma vez")
    args = parser.parse_args(argv)
    if args.helper_fd < 0:
        reject("FD de execução do helper é inválido")
    return args


def validate_execution_entrypoint(
    helper_fd: int,
    *,
    script_path: str,
    platform: str,
    proc_fd_root: Path = Path("/proc/self/fd"),
) -> None:
    if platform != "linux":
        reject("helper exige Linux com procfs")
    try:
        proc_info = proc_fd_root.stat()
        os.fstat(helper_fd)
    except OSError:
        reject("helper exige /proc/self/fd e FD aberto")
    if (
        not stat.S_ISDIR(proc_info.st_mode)
        or script_path != str(proc_fd_root / str(helper_fd))
    ):
        reject("helper exige execução por /proc/self/fd")


def main() -> int:
    args = parse_cli(sys.argv[1:])
    validate_execution_entrypoint(
        args.helper_fd,
        script_path=__file__,
        platform=sys.platform,
    )
    if (
        os.geteuid() != EXPECTED_UID
        or os.getegid() != EXPECTED_GID
    ):
        reject(
            "helper exige root:root e execução pelo FD explicitamente "
            "validado"
        )
    expectations = BootstrapExpectations(
        helper_sha256=args.expected_helper_sha256,
        attestation_sha256=args.expected_attestation_sha256,
        carrier_sha=args.expected_carrier_sha,
        controller_sha=args.expected_controller_sha,
    )
    validate_expectations(expectations)
    previous_umask = os.umask(0o077)
    try:
        lock_descriptor = verify_inherited_lock(
            uid=EXPECTED_UID,
            gid=EXPECTED_GID,
        )
        result = install_source(
            incoming=INCOMING,
            state_root=STATE_ROOT,
            uid=EXPECTED_UID,
            gid=EXPECTED_GID,
            execution_descriptor=args.helper_fd,
            expectations=expectations,
            runtime=production_runtime(),
            signature_verifier=None,
            publisher=run_publisher,
            lock_descriptor=lock_descriptor,
        )
        print(result)
        return 0
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        BootstrapSourceError,
        OSError,
        subprocess.SubprocessError,
        tarfile.TarError,
    ) as error:
        print(f"bootstrap source kit rejected: {error}", file=sys.stderr)
        raise SystemExit(78)
