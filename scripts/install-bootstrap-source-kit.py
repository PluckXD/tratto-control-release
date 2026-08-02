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
from dataclasses import dataclass, replace
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
SUPERSEDE_NAME = "bootstrap-source-kit.supersede.json"
POST_PUBLISHER_SUPERSEDE_NAME = (
    "bootstrap-source-kit.post-publisher-supersede.json"
)
SUPERSEDED_RECORD_PREFIX = "bootstrap-source-kit."
HELPER_NAME = "install-bootstrap-source-kit.py"
HELPER_BUNDLE_NAME = "bootstrap-source-kit.sigstore.json"
ATTESTATION_NAME = "release-attestation.json"
ATTESTATION_BUNDLE_NAME = "release.sigstore.json"
OPS_BUNDLE_NAME = "ops.sigstore.json"
COSIGN = Path("/usr/local/bin/cosign")
COSIGN_CACHE = Path("/var/cache/tratto-control/cosign")
PYTHON = Path("/usr/bin/python3.12")
SYSTEMCTL = Path("/usr/bin/systemctl")
LOCK_DIRECTORY = Path("/run/tratto-control")
LOCK_NAME = "deploy.lock"
LOCK_FD_ENV = "TRATTO_CONTROL_LOCK_FD"
LOCK_HELD_ENV = "TRATTO_CONTROL_LOCK_HELD"
CONTROL_STAGING = Path("/opt/tratto-control/.staging")
CONTROL_ROOT = Path("/opt/tratto-control")
PUBLISHER_INTENT_NAME = "bootstrap-upgrade.intent.json"
PUBLISHER_USED_NAME = "bootstrap-upgrade.used.json"
PUBLISHER_SUPERSEDE_NAME = "bootstrap-upgrade.supersede.json"
PUBLISHER_CANDIDATE_NAME = "bootstrap.upgrading"
PUBLISHER_PREVIOUS_PREFIX = "bootstrap.previous."
PUBLISHER_SUPERSEDE_FD_ENV = "TRATTO_CONTROL_BOOTSTRAP_SUPERSEDE_FD"
PUBLISHER_SUPERSEDE_CONTRACT = (
    "tratto-control-bootstrap-publisher-supersede-v1"
)
POST_PUBLISHER_SUPERSEDE_CONTRACT = (
    "tratto-control-bootstrap-post-publisher-supersede-v1"
)
POST_PUBLISHER_ARCHIVE_PREFIX = ".bootstrap-post-publisher."
NESTED_POST_PUBLISHER_ARCHIVE_PREFIX = (
    ".bootstrap-post-publisher.nested-"
)
POST_STAGE_BUNDLE_ARCHIVE_PREFIX = ".bootstrap-post-stage.bundle."
BOOTSTRAP_RELEASE_MARKER = Path(
    "/etc/tratto-control/bootstrap-release.env"
)
RELEASE_STATE_MARKER = Path("/etc/tratto-control/release-state.env")
ACTIVATION_JOURNAL = Path("/etc/tratto-control/activation.env")
ACTIVATION_EPOCH_MARKER = Path(
    "/etc/tratto-control/activation-epoch.env"
)
BOOTSTRAP_CONSUMED_NAME = "bootstrap-consumed"
BUNDLES_NAME = "bundles"

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
SYSTEMD_UNIT_RE = re.compile(
    r"^tratto-control[A-Za-z0-9_.:@-]*"
    r"\.(?:service|timer|slice|socket|path|target)$"
)
ARCHIVE_NAME_RE = re.compile(
    r"^tratto-control-ops-([0-9a-f]{40})\.tar\.gz$"
)
STATE_TEMP_RE = re.compile(
    r"^bootstrap-source-kit\."
    r"(intent|prepared|exchanged|retained|used|supersede"
    r"|post-publisher-supersede)"
    r"\.([0-9a-f]{64})\.installing$"
)
SUPERSEDED_RECORD_RE = re.compile(
    r"^bootstrap-source-kit\."
    r"(intent|prepared|exchanged|retained|used)"
    r"\.superseded\.([0-9a-f]{64})\.json$"
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
MAX_PACKAGED_UNITS_BYTES = 64 * 1024
MAX_PACKAGED_UNIT_BYTES = 1024 * 1024
MAX_GUARDIAN_REPORT_BYTES = 4096
MAX_STAGED_BUNDLE_ENTRIES = 32768
MAX_STAGED_BUNDLE_BYTES = 512 * 1024 * 1024
MAX_STAGED_BUNDLE_MEMBER_BYTES = 32 * 1024 * 1024
QUIESCENCE_SUCCESS = (
    b"stack Control totalmente parada e sem concorr\xc3\xaancia systemd\n"
)

REQUIRED_FILES = {
    "RELEASE_SHA": 0o444,
    "artifact-manifest.json": 0o444,
    "scripts/provision-node-runtime.py": 0o555,
    "scripts/publish-bootstrap-tree.py": 0o555,
    "scripts/verify-control-stack-quiescent.py": 0o555,
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


def require_sha_list(value: Any, label: str) -> tuple[str, ...]:
    if type(value) is not list or not value:
        reject(f"{label} precisa ser lista não vazia de commits")
    result = tuple(
        require_sha(item, f"{label}[{index}]")
        for index, item in enumerate(value)
    )
    if len(set(result)) != len(result):
        reject(f"{label} contém commit duplicado")
    return result


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
    predecessor_kit_id: str | None = None
    predecessor_controller_sha: str | None = None
    predecessor_publisher_intent_sha256: str | None = None
    post_publisher_predecessor_kit_id: str | None = None
    post_publisher_predecessor_controller_sha: str | None = None
    post_publisher_source_intent_sha256: str | None = None
    post_publisher_source_used_sha256: str | None = None
    post_publisher_publisher_intent_sha256: str | None = None
    post_publisher_publisher_used_sha256: str | None = None
    post_publisher_staged_bundle_id: str | None = None
    post_publisher_staged_bundle_tree_sha256: str | None = None


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
    predecessor_values = (
        expectations.predecessor_kit_id,
        expectations.predecessor_controller_sha,
        expectations.predecessor_publisher_intent_sha256,
    )
    if any(item is not None for item in predecessor_values):
        if not all(item is not None for item in predecessor_values):
            reject("bindings do predecessor precisam ser informados juntos")
        require_hash(
            expectations.predecessor_kit_id,
            "kit ID predecessor esperado",
        )
        require_sha(
            expectations.predecessor_controller_sha,
            "controller predecessor esperado",
        )
        require_hash(
            expectations.predecessor_publisher_intent_sha256,
            "publisher intent predecessor esperado",
        )
    post_publisher_values = (
        expectations.post_publisher_predecessor_kit_id,
        expectations.post_publisher_predecessor_controller_sha,
        expectations.post_publisher_source_intent_sha256,
        expectations.post_publisher_source_used_sha256,
        expectations.post_publisher_publisher_intent_sha256,
        expectations.post_publisher_publisher_used_sha256,
    )
    if any(item is not None for item in post_publisher_values):
        if not all(item is not None for item in post_publisher_values):
            reject(
                "bindings post-publisher precisam ser informados juntos"
            )
        if any(item is not None for item in predecessor_values):
            reject(
                "recuperações pre-publisher e post-publisher são exclusivas"
            )
        require_hash(
            expectations.post_publisher_predecessor_kit_id,
            "kit ID post-publisher esperado",
        )
        require_sha(
            expectations.post_publisher_predecessor_controller_sha,
            "controller post-publisher esperado",
        )
        require_hash(
            expectations.post_publisher_source_intent_sha256,
            "source intent post-publisher esperado",
        )
        require_hash(
            expectations.post_publisher_source_used_sha256,
            "source used post-publisher esperado",
        )
        require_hash(
            expectations.post_publisher_publisher_intent_sha256,
            "publisher intent post-publisher esperado",
        )
        require_hash(
            expectations.post_publisher_publisher_used_sha256,
            "publisher used post-publisher esperado",
        )
    post_stage_values = (
        expectations.post_publisher_staged_bundle_id,
        expectations.post_publisher_staged_bundle_tree_sha256,
    )
    if any(item is not None for item in post_stage_values):
        if not all(item is not None for item in post_stage_values):
            reject("bindings do bundle post-stage precisam vir juntos")
        if not all(item is not None for item in post_publisher_values):
            reject("bundle post-stage exige recovery post-publisher completo")
        require_hash(
            expectations.post_publisher_staged_bundle_id,
            "bundle ID post-stage esperado",
        )
        require_hash(
            expectations.post_publisher_staged_bundle_tree_sha256,
            "árvore do bundle post-stage esperada",
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
    api_required_ancestors: tuple[str, ...]
    ops_required_ancestors: tuple[str, ...]
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
    api_required_ancestors = require_sha_list(
        api_approval.get("required_ancestors"),
        "required ancestors da API",
    )
    ops_required_ancestors = require_sha_list(
        ops_approval.get("required_ancestors"),
        "required ancestors de Ops",
    )

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
        api_required_ancestors=api_required_ancestors,
        ops_required_ancestors=ops_required_ancestors,
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


def protected_bootstrap_tree_digest(
    descriptor: int,
    *,
    uid: int,
    gid: int,
) -> str:
    entries = scan_tree(
        descriptor,
        uid=uid,
        gid=gid,
        root_modes={0o555},
        directory_modes={0o555},
        file_modes={0o444, 0o555},
    )
    children: dict[str, set[str]] = {".": set()}
    for path, entry in entries.items():
        parent = str(PurePosixPath(path).parent)
        children.setdefault(parent, set()).add(PurePosixPath(path).name)
        if entry.kind == "directory":
            children.setdefault(path, set())
    records: list[bytes] = []

    def visit(relative: str) -> None:
        records.append(
            b"D\0"
            + relative.encode("utf-8")
            + b"\0"
            + b"0555\n"
        )
        for name in sorted(children[relative]):
            child = name if relative == "." else f"{relative}/{name}"
            entry = entries[child]
            if entry.kind == "directory":
                visit(child)
                continue
            records.append(
                b"F\0"
                + child.encode("utf-8")
                + b"\0"
                + f"{entry.mode:04o}".encode("ascii")
                + b"\0"
                + str(entry.size).encode("ascii")
                + b"\0"
                + entry.sha256.encode("ascii")
                + b"\n"
            )

    visit(".")
    digest = hashlib.sha256()
    for record in records:
        digest.update(record)
    return digest.hexdigest()


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


SOURCE_PHASE_NAMES = {
    "intent": INTENT_NAME,
    "prepared": PREPARED_NAME,
    "exchanged": EXCHANGED_NAME,
    "retained": RETAINED_NAME,
}
POST_PUBLISHER_SOURCE_PHASE_NAMES = {
    **SOURCE_PHASE_NAMES,
    "used": USED_NAME,
}


@dataclass(frozen=True)
class SupersededSourceTransaction:
    kit_id: str
    api_sha: str
    controller_sha: str
    old_digest: str
    new_digest: str
    intent_raw: bytes
    publisher_intent_sha256: str
    publisher_authorization_required: bool = True

    def archived_name(self, phase: str) -> str:
        if phase not in POST_PUBLISHER_SOURCE_PHASE_NAMES:
            reject("fase inválida no histórico do source kit")
        return (
            f"{SUPERSEDED_RECORD_PREFIX}{phase}.superseded."
            f"{self.kit_id}.json"
        )


def validate_source_intent(
    raw: bytes,
    *,
    allow_noop: bool = False,
) -> SupersededSourceTransaction:
    value = parse_canonical_json(raw, "bootstrap source intent predecessor")
    exact_object(
        value,
        {
            "api_sha",
            "archive_name",
            "attestation_sha256",
            "carrier_sha",
            "contract",
            "controller_sha",
            "helper_sha256",
            "kit_id",
            "new_source_tree_sha256",
            "old_source_tree_sha256",
            "ops_sha256",
            "schema_version",
        },
        "bootstrap source intent predecessor",
    )
    api_sha = require_sha(value["api_sha"], "API SHA predecessor")
    carrier_sha = require_sha(
        value["carrier_sha"],
        "carrier SHA predecessor",
    )
    controller_sha = require_sha(
        value["controller_sha"],
        "controller SHA predecessor",
    )
    attestation_sha256 = require_hash(
        value["attestation_sha256"],
        "attestation predecessor",
    )
    helper_sha256 = require_hash(
        value["helper_sha256"],
        "helper predecessor",
    )
    ops_sha256 = require_hash(
        value["ops_sha256"],
        "Ops predecessor",
    )
    old_digest = require_hash(
        value["old_source_tree_sha256"],
        "árvore source antiga predecessor",
    )
    new_digest = require_hash(
        value["new_source_tree_sha256"],
        "árvore source nova predecessor",
    )
    kit_id = require_hash(value["kit_id"], "kit ID predecessor")
    archive_name = value["archive_name"]
    archive_match = (
        ARCHIVE_NAME_RE.fullmatch(archive_name)
        if type(archive_name) is str
        else None
    )
    if (
        value["contract"] != CONTRACT
        or value["schema_version"] != 1
        or archive_match is None
        or archive_match.group(1) != api_sha
    ):
        reject("intent predecessor não pertence a um source kit válido")
    computed_kit_id = hashlib.sha256(
        canonical_bytes(
            {
                "api_sha": api_sha,
                "attestation_sha256": attestation_sha256,
                "carrier_sha": carrier_sha,
                "contract": CONTRACT,
                "controller_sha": controller_sha,
                "helper_sha256": helper_sha256,
                "ops_sha256": ops_sha256,
                "source_tree_sha256": new_digest,
            }
        )
    ).hexdigest()
    if (
        kit_id != computed_kit_id
        or (old_digest == new_digest and not allow_noop)
    ):
        reject("identidade do source kit predecessor diverge do intent")
    return SupersededSourceTransaction(
        kit_id=kit_id,
        api_sha=api_sha,
        controller_sha=controller_sha,
        old_digest=old_digest,
        new_digest=new_digest,
        intent_raw=raw,
        publisher_intent_sha256="",
    )


def source_supersede_payload(
    predecessor: SupersededSourceTransaction,
    *,
    successor_kit_id: str,
    successor_new_digest: str,
) -> bytes:
    require_hash(successor_kit_id, "kit ID sucessor")
    require_hash(successor_new_digest, "árvore source sucessora")
    return canonical_bytes(
        {
            "contract": CONTRACT,
            "phase": "supersede",
            "predecessor_api_sha": predecessor.api_sha,
            "predecessor_controller_sha": predecessor.controller_sha,
            "predecessor_intent_sha256": hashlib.sha256(
                predecessor.intent_raw
            ).hexdigest(),
            "predecessor_kit_id": predecessor.kit_id,
            "predecessor_new_source_tree_sha256": predecessor.new_digest,
            "predecessor_old_source_tree_sha256": predecessor.old_digest,
            "predecessor_publisher_intent_sha256": (
                predecessor.publisher_intent_sha256
            ),
            "schema_version": 1,
            "successor_kit_id": successor_kit_id,
            "successor_new_source_tree_sha256": successor_new_digest,
        }
    )


def validate_source_supersede(
    raw: bytes,
    *,
    successor_kit_id: str,
    successor_new_digest: str,
) -> SupersededSourceTransaction:
    value = parse_canonical_json(raw, "bootstrap source supersede")
    exact_object(
        value,
        {
            "contract",
            "phase",
            "predecessor_api_sha",
            "predecessor_controller_sha",
            "predecessor_intent_sha256",
            "predecessor_kit_id",
            "predecessor_new_source_tree_sha256",
            "predecessor_old_source_tree_sha256",
            "predecessor_publisher_intent_sha256",
            "schema_version",
            "successor_kit_id",
            "successor_new_source_tree_sha256",
        },
        "bootstrap source supersede",
    )
    if (
        value["contract"] != CONTRACT
        or value["phase"] != "supersede"
        or value["schema_version"] != 1
        or value["successor_kit_id"] != successor_kit_id
        or value["successor_new_source_tree_sha256"]
        != successor_new_digest
    ):
        reject("source supersede não autoriza este kit sucessor")
    predecessor = SupersededSourceTransaction(
        kit_id=require_hash(
            value["predecessor_kit_id"],
            "kit ID predecessor no supersede",
        ),
        api_sha=require_sha(
            value["predecessor_api_sha"],
            "API predecessor no supersede",
        ),
        controller_sha=require_sha(
            value["predecessor_controller_sha"],
            "controller predecessor no supersede",
        ),
        old_digest=require_hash(
            value["predecessor_old_source_tree_sha256"],
            "árvore antiga predecessor no supersede",
        ),
        new_digest=require_hash(
            value["predecessor_new_source_tree_sha256"],
            "árvore nova predecessor no supersede",
        ),
        intent_raw=b"",
        publisher_intent_sha256=require_hash(
            value["predecessor_publisher_intent_sha256"],
            "publisher intent predecessor no supersede",
        ),
    )
    require_hash(
        value["predecessor_intent_sha256"],
        "intent predecessor no supersede",
    )
    if (
        predecessor.kit_id == successor_kit_id
        or predecessor.new_digest == successor_new_digest
        or predecessor.old_digest == predecessor.new_digest
    ):
        reject("source supersede não representa uma sucessão distinta")
    return predecessor


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
    predecessor: SupersededSourceTransaction | None = None,
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
        SUPERSEDE_NAME,
    }
    if predecessor is not None:
        allowed.add(f"{PREVIOUS_PREFIX}{predecessor.kit_id}")
        allowed.update(
            predecessor.archived_name(phase)
            for phase in SOURCE_PHASE_NAMES
        )
        if not predecessor.publisher_authorization_required:
            allowed.add(POST_PUBLISHER_SUPERSEDE_NAME)
            allowed.add(predecessor.archived_name("used"))
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
        archived = SUPERSEDED_RECORD_RE.fullmatch(name)
        if archived is not None and name not in allowed:
            reject("há histórico source superseded não reconhecido")
        if (
            name.startswith("bootstrap-source-kit.")
            and name not in allowed
        ):
            reject("há journal source kit concorrente não reconhecido")
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


def validate_fixed_predecessor_publisher_state(
    *,
    uid: int,
    gid: int,
) -> str:
    control = open_path_chain(
        CONTROL_ROOT,
        uid=uid,
        gid=gid,
        final_modes={0o711},
    )
    try:
        staging = _open_named_directory(
            control,
            ".staging",
            uid=uid,
            gid=gid,
            modes={0o700},
        )
        if staging is None:
            reject("staging do publisher predecessor está ausente")
        descriptor = os.open(
            PUBLISHER_INTENT_NAME,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=staging,
        )
        info = os.fstat(descriptor)
        try:
            validate_regular(
                info,
                PUBLISHER_INTENT_NAME,
                uid=uid,
                gid=gid,
                modes={0o400},
                maximum=1024,
            )
            raw = read_all(
                descriptor,
                info,
                maximum=1024,
                label=PUBLISHER_INTENT_NAME,
            )
        finally:
            os.close(descriptor)
        value = parse_canonical_json(raw, PUBLISHER_INTENT_NAME)
        exact_object(
            value,
            {
                "new_tree_sha256",
                "old_tree_sha256",
                "phase",
                "previous_name",
                "schema_version",
            },
            PUBLISHER_INTENT_NAME,
        )
        old_digest = require_hash(
            value["old_tree_sha256"],
            "bootstrap antigo do publisher predecessor",
        )
        new_digest = require_hash(
            value["new_tree_sha256"],
            "bootstrap novo do publisher predecessor",
        )
        if (
            value["phase"] != "intent"
            or value["schema_version"] != 1
            or value["previous_name"]
            != PUBLISHER_PREVIOUS_PREFIX + old_digest[:32]
            or old_digest == new_digest
        ):
            reject("publisher intent predecessor diverge do contrato")
        allowed = {
            PUBLISHER_INTENT_NAME,
            PUBLISHER_CANDIDATE_NAME,
        }
        for name in os.listdir(staging):
            if (
                name == PUBLISHER_USED_NAME
                or name == PUBLISHER_SUPERSEDE_NAME
                or name.startswith(PUBLISHER_PREVIOUS_PREFIX)
                or name.startswith("bootstrap-upgrade.intent.superseded.")
                or name.startswith("bootstrap.upgrading.superseded.")
                or (
                    name.startswith("bootstrap-upgrade.")
                    and name not in allowed
                )
                or (
                    name.startswith("bootstrap.upgrading")
                    and name not in allowed
                )
            ):
                reject("publisher predecessor não está pré-exchange limpo")
        try:
            os.stat(
                "current",
                dir_fd=control,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            reject("runtime current já existe antes do bootstrap")
        final = _open_named_directory(
            control,
            "bootstrap",
            uid=uid,
            gid=gid,
            modes={0o555},
        )
        if final is None:
            reject("bootstrap predecessor publicado está ausente")
        try:
            if (
                protected_bootstrap_tree_digest(
                    final,
                    uid=uid,
                    gid=gid,
                )
                != old_digest
            ):
                reject("bootstrap publicado diverge do publisher intent")
        finally:
            os.close(final)
        candidate = _open_named_directory(
            staging,
            PUBLISHER_CANDIDATE_NAME,
            uid=uid,
            gid=gid,
            modes={0o555},
        )
        if candidate is None:
            reject("candidate predecessor do publisher está ausente")
        try:
            if (
                protected_bootstrap_tree_digest(
                    candidate,
                    uid=uid,
                    gid=gid,
                )
                != new_digest
            ):
                reject("candidate predecessor diverge do publisher intent")
        finally:
            os.close(candidate)
        return hashlib.sha256(raw).hexdigest()
    finally:
        if "staging" in locals() and staging is not None:
            os.close(staging)
        os.close(control)


@dataclass(frozen=True)
class PublisherUpgradeTransaction:
    old_digest: str
    new_digest: str
    previous_name: str
    intent_raw: bytes
    used_raw: bytes


@dataclass(frozen=True)
class NestedSupersedeHistory:
    source_predecessor: SupersededSourceTransaction
    source_supersede_raw: bytes
    publisher_supersede_raw: bytes
    publisher_predecessor_intent_raw: bytes
    publisher_predecessor_new_digest: str
    publisher_retained_intent_name: str
    publisher_retained_candidate_name: str
    archive_statuses: tuple[bool, ...]


@dataclass(frozen=True)
class PostPublisherRecovery:
    predecessor: SupersededSourceTransaction
    source_intent_sha256: str
    source_used_sha256: str
    publisher_intent_sha256: str
    publisher_used_sha256: str
    publisher_old_digest: str
    publisher_new_digest: str
    publisher_previous_name: str
    successor_kit_id: str
    successor_new_digest: str
    staged_bundle_id: str | None = None
    staged_bundle_tree_sha256: str | None = None
    nested_source_supersede_sha256: str | None = None
    nested_publisher_supersede_sha256: str | None = None
    nested_history: NestedSupersedeHistory | None = None


def post_publisher_archive_name(kind: str, kit_id: str) -> str:
    require_hash(kit_id, "kit ID do arquivo post-publisher")
    if kind not in {"intent", "used", "previous"}:
        reject("tipo de arquivo post-publisher inválido")
    suffix = ".json" if kind in {"intent", "used"} else ""
    return f"{POST_PUBLISHER_ARCHIVE_PREFIX}{kind}.{kit_id}{suffix}"


def post_stage_bundle_archive_name(bundle_id: str) -> str:
    require_hash(bundle_id, "bundle ID do arquivo post-stage")
    return f"{POST_STAGE_BUNDLE_ARCHIVE_PREFIX}{bundle_id}"


def nested_source_archive_name(kind: str, kit_id: str) -> str:
    require_hash(kit_id, "kit ID do histórico source aninhado")
    if kind not in {
        "supersede",
        "intent",
        "prepared",
        "exchanged",
        "retained",
        "previous",
    }:
        reject("tipo de histórico source aninhado inválido")
    suffix = "" if kind == "previous" else ".json"
    return (
        f"{NESTED_POST_PUBLISHER_ARCHIVE_PREFIX}"
        f"source-{kind}.{kit_id}{suffix}"
    )


def nested_publisher_archive_name(kind: str, kit_id: str) -> str:
    require_hash(kit_id, "kit ID do histórico publisher aninhado")
    if kind not in {"supersede", "intent", "candidate"}:
        reject("tipo de histórico publisher aninhado inválido")
    suffix = "" if kind == "candidate" else ".json"
    return (
        f"{NESTED_POST_PUBLISHER_ARCHIVE_PREFIX}"
        f"publisher-{kind}.{kit_id}{suffix}"
    )


def read_publisher_record_if_present(
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
            modes={0o400},
            maximum=1024,
        )
        return read_all(
            descriptor,
            info,
            maximum=1024,
            label=name,
        )
    finally:
        os.close(descriptor)


def read_publisher_history_record_if_present(
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
            modes={0o400},
            maximum=4096,
        )
        return read_all(
            descriptor,
            info,
            maximum=4096,
            label=name,
        )
    finally:
        os.close(descriptor)


def validate_publisher_upgrade_record(
    raw: bytes,
    *,
    phase: str,
    label: str,
) -> dict[str, Any]:
    value = parse_canonical_json(raw, label)
    exact_object(
        value,
        {
            "new_tree_sha256",
            "old_tree_sha256",
            "phase",
            "previous_name",
            "schema_version",
        },
        label,
    )
    old_digest = require_hash(
        value["old_tree_sha256"],
        f"{label} old tree",
    )
    new_digest = require_hash(
        value["new_tree_sha256"],
        f"{label} new tree",
    )
    if (
        value["phase"] != phase
        or value["schema_version"] != 1
        or old_digest == new_digest
        or value["previous_name"]
        != PUBLISHER_PREVIOUS_PREFIX + old_digest[:32]
    ):
        reject(f"{label} diverge do contrato")
    return value


def validate_publisher_upgrade_transaction(
    intent_raw: bytes,
    used_raw: bytes,
) -> PublisherUpgradeTransaction:
    intent = validate_publisher_upgrade_record(
        intent_raw,
        phase="intent",
        label="publisher intent post-publisher",
    )
    used = validate_publisher_upgrade_record(
        used_raw,
        phase="used",
        label="publisher used post-publisher",
    )
    expected_used = dict(intent)
    expected_used["phase"] = "used"
    if used != expected_used:
        reject("publisher used diverge do intent post-publisher")
    return PublisherUpgradeTransaction(
        old_digest=str(intent["old_tree_sha256"]),
        new_digest=str(intent["new_tree_sha256"]),
        previous_name=str(intent["previous_name"]),
        intent_raw=intent_raw,
        used_raw=used_raw,
    )


def validate_publisher_supersede_history(
    raw: bytes,
) -> dict[str, Any]:
    value = parse_canonical_json(
        raw,
        "publisher supersede aninhado",
    )
    keys = {
        "contract",
        "phase",
        "predecessor_intent_sha256",
        "predecessor_new_tree_sha256",
        "predecessor_old_tree_sha256",
        "predecessor_previous_name",
        "retained_candidate_name",
        "retained_intent_name",
        "schema_version",
        "source_predecessor_kit_id",
        "source_predecessor_tree_sha256",
        "source_successor_kit_id",
        "source_successor_tree_sha256",
        "successor_new_tree_sha256",
    }
    exact_object(value, keys, "publisher supersede aninhado")
    if (
        value["contract"] != PUBLISHER_SUPERSEDE_CONTRACT
        or value["phase"] != "superseded"
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        reject("publisher supersede aninhado diverge do contrato")
    digest_keys = keys - {
        "contract",
        "phase",
        "predecessor_previous_name",
        "retained_candidate_name",
        "retained_intent_name",
        "schema_version",
    }
    for key in digest_keys:
        require_hash(value[key], key)
    predecessor_old = str(value["predecessor_old_tree_sha256"])
    predecessor_new = str(value["predecessor_new_tree_sha256"])
    predecessor_intent = str(value["predecessor_intent_sha256"])
    if (
        value["predecessor_previous_name"]
        != PUBLISHER_PREVIOUS_PREFIX + predecessor_old[:32]
        or value["retained_intent_name"]
        != (
            "bootstrap-upgrade.intent.superseded."
            f"{predecessor_intent}.json"
        )
        or value["retained_candidate_name"]
        != (
            "bootstrap.upgrading.superseded."
            f"{predecessor_new}"
        )
        or value["source_predecessor_kit_id"]
        == value["source_successor_kit_id"]
        or value["source_predecessor_tree_sha256"]
        == value["source_successor_tree_sha256"]
        or predecessor_new == value["successor_new_tree_sha256"]
    ):
        reject("publisher supersede aninhado não é sucessão exata")
    return value


def _nested_record(
    parent: int,
    *,
    active_name: str,
    archived_name: str,
    expected: bytes,
    publisher: bool,
    uid: int,
    gid: int,
) -> tuple[bool, set[str]]:
    reader = (
        read_publisher_history_record_if_present
        if publisher
        else read_record_if_present
    )
    active = reader(parent, active_name, uid=uid, gid=gid)
    archived = reader(parent, archived_name, uid=uid, gid=gid)
    if archived is not None:
        if archived != expected:
            reject(f"histórico aninhado diverge: {archived_name}")
        if active is not None:
            reject(f"histórico aninhado coexiste: {active_name}")
        return True, {archived_name}
    if active != expected:
        reject(f"histórico aninhado está ausente: {active_name}")
    return False, {active_name}


def _nested_tree(
    parent: int,
    *,
    active_name: str,
    archived_name: str,
    expected_digest: str,
    publisher: bool,
    uid: int,
    gid: int,
) -> tuple[bool, set[str]]:
    modes = {0o555}
    active = _open_named_directory(
        parent,
        active_name,
        uid=uid,
        gid=gid,
        modes=modes,
    )
    archived = _open_named_directory(
        parent,
        archived_name,
        uid=uid,
        gid=gid,
        modes=modes,
    )

    def observed_digest(descriptor: int) -> str:
        if publisher:
            return protected_bootstrap_tree_digest(
                descriptor,
                uid=uid,
                gid=gid,
            )
        return tree_digest(scan_tree(descriptor, uid=uid, gid=gid))

    try:
        if archived is not None:
            if observed_digest(archived) != expected_digest:
                reject(f"histórico aninhado diverge: {archived_name}")
            if active is not None:
                reject(f"histórico aninhado coexiste: {active_name}")
            return True, {archived_name}
        if active is None or observed_digest(active) != expected_digest:
            reject(f"histórico aninhado está ausente: {active_name}")
        return False, {active_name}
    finally:
        if active is not None:
            os.close(active)
        if archived is not None:
            os.close(archived)


def validate_nested_supersede_history(
    state_descriptor: int,
    staging: int,
    *,
    current_source: SupersededSourceTransaction,
    current_publisher: PublisherUpgradeTransaction,
    expected_source_supersede_sha256: str | None,
    expected_publisher_supersede_sha256: str | None,
    uid: int,
    gid: int,
) -> tuple[
    NestedSupersedeHistory | None,
    set[str],
    set[str],
]:
    if (
        expected_source_supersede_sha256 is None
    ) != (expected_publisher_supersede_sha256 is None):
        reject("bindings do histórico aninhado estão incompletos")
    source_archive = nested_source_archive_name(
        "supersede",
        current_source.kit_id,
    )
    active_source_raw = read_record_if_present(
        state_descriptor,
        SUPERSEDE_NAME,
        uid=uid,
        gid=gid,
    )
    archived_source_raw = read_record_if_present(
        state_descriptor,
        source_archive,
        uid=uid,
        gid=gid,
    )
    source_archived = False
    if expected_source_supersede_sha256 is None:
        if active_source_raw is None:
            if archived_source_raw is not None:
                reject("histórico source aninhado existe sem recovery")
            for name in os.listdir(state_descriptor):
                if name.startswith(NESTED_POST_PUBLISHER_ARCHIVE_PREFIX):
                    reject("arquivo source aninhado existe sem recovery")
            return None, set(), set()
        if archived_source_raw is not None:
            reject("histórico source aninhado parcial existe sem recovery")
        source_supersede_raw = active_source_raw
    else:
        require_hash(
            expected_source_supersede_sha256,
            "hash source supersede aninhado",
        )
        if (
            archived_source_raw is not None
            and hashlib.sha256(archived_source_raw).hexdigest()
            == expected_source_supersede_sha256
        ):
            source_supersede_raw = archived_source_raw
            source_archived = True
            if (
                active_source_raw is not None
                and hashlib.sha256(active_source_raw).hexdigest()
                == expected_source_supersede_sha256
            ):
                reject("source supersede aninhado coexiste com arquivo")
        elif (
            archived_source_raw is None
            and active_source_raw is not None
            and hashlib.sha256(active_source_raw).hexdigest()
            == expected_source_supersede_sha256
        ):
            source_supersede_raw = active_source_raw
        else:
            reject("source supersede aninhado não está recuperável")
    source_predecessor = validate_source_supersede(
        source_supersede_raw,
        successor_kit_id=current_source.kit_id,
        successor_new_digest=current_source.new_digest,
    )
    source_value = parse_canonical_json(
        source_supersede_raw,
        "source supersede aninhado",
    )
    source_allowed = {
        source_archive if source_archived else SUPERSEDE_NAME
    }
    source_statuses = [source_archived]
    source_intent_name = source_predecessor.archived_name("intent")
    nested_intent_name = nested_source_archive_name(
        "intent",
        current_source.kit_id,
    )
    source_intent_active = read_record_if_present(
        state_descriptor,
        source_intent_name,
        uid=uid,
        gid=gid,
    )
    source_intent_archived = read_record_if_present(
        state_descriptor,
        nested_intent_name,
        uid=uid,
        gid=gid,
    )
    source_intent_raw = (
        source_intent_archived
        if source_intent_archived is not None
        else source_intent_active
    )
    if (
        source_intent_raw is None
        or hashlib.sha256(source_intent_raw).hexdigest()
        != source_value["predecessor_intent_sha256"]
    ):
        reject("intent source aninhado diverge do supersede")
    parsed_source_predecessor = validate_source_intent(
        source_intent_raw
    )
    if (
        parsed_source_predecessor.kit_id
        != source_predecessor.kit_id
        or parsed_source_predecessor.api_sha
        != source_predecessor.api_sha
        or parsed_source_predecessor.controller_sha
        != source_predecessor.controller_sha
        or parsed_source_predecessor.old_digest
        != source_predecessor.old_digest
        or parsed_source_predecessor.new_digest
        != source_predecessor.new_digest
    ):
        reject("intent source aninhado mudou de identidade")
    if current_source.old_digest != source_predecessor.new_digest:
        reject("source supersede aninhado não encadeia o sucessor")
    source_predecessor = SupersededSourceTransaction(
        kit_id=parsed_source_predecessor.kit_id,
        api_sha=parsed_source_predecessor.api_sha,
        controller_sha=parsed_source_predecessor.controller_sha,
        old_digest=parsed_source_predecessor.old_digest,
        new_digest=parsed_source_predecessor.new_digest,
        intent_raw=source_intent_raw,
        publisher_intent_sha256=(
            source_predecessor.publisher_intent_sha256
        ),
    )
    for phase in ("intent", "prepared", "exchanged", "retained"):
        archived, allowed = _nested_record(
            state_descriptor,
            active_name=source_predecessor.archived_name(phase),
            archived_name=nested_source_archive_name(
                phase,
                current_source.kit_id,
            ),
            expected=_expected_source_phase(
                source_predecessor,
                phase,
            ),
            publisher=False,
            uid=uid,
            gid=gid,
        )
        source_statuses.append(archived)
        source_allowed.update(allowed)
    previous_archived, previous_allowed = _nested_tree(
        state_descriptor,
        active_name=(
            f"{PREVIOUS_PREFIX}{source_predecessor.kit_id}"
        ),
        archived_name=nested_source_archive_name(
            "previous",
            current_source.kit_id,
        ),
        expected_digest=source_predecessor.old_digest,
        publisher=False,
        uid=uid,
        gid=gid,
    )
    source_statuses.append(previous_archived)
    source_allowed.update(previous_allowed)

    publisher_archive = nested_publisher_archive_name(
        "supersede",
        current_source.kit_id,
    )
    active_publisher_raw = read_publisher_history_record_if_present(
        staging,
        PUBLISHER_SUPERSEDE_NAME,
        uid=uid,
        gid=gid,
    )
    archived_publisher_raw = read_publisher_history_record_if_present(
        staging,
        publisher_archive,
        uid=uid,
        gid=gid,
    )
    publisher_archived = False
    if expected_publisher_supersede_sha256 is None:
        if (
            active_publisher_raw is None
            or archived_publisher_raw is not None
        ):
            reject("publisher supersede aninhado não está íntegro")
        publisher_supersede_raw = active_publisher_raw
    else:
        require_hash(
            expected_publisher_supersede_sha256,
            "hash publisher supersede aninhado",
        )
        if (
            archived_publisher_raw is not None
            and hashlib.sha256(archived_publisher_raw).hexdigest()
            == expected_publisher_supersede_sha256
        ):
            publisher_supersede_raw = archived_publisher_raw
            publisher_archived = True
            if (
                active_publisher_raw is not None
                and hashlib.sha256(active_publisher_raw).hexdigest()
                == expected_publisher_supersede_sha256
            ):
                reject(
                    "publisher supersede aninhado coexiste com arquivo"
                )
        elif (
            archived_publisher_raw is None
            and active_publisher_raw is not None
            and hashlib.sha256(active_publisher_raw).hexdigest()
            == expected_publisher_supersede_sha256
        ):
            publisher_supersede_raw = active_publisher_raw
        else:
            reject("publisher supersede aninhado não está recuperável")
    publisher_value = validate_publisher_supersede_history(
        publisher_supersede_raw
    )
    if (
        publisher_value["predecessor_intent_sha256"]
        != source_predecessor.publisher_intent_sha256
        or publisher_value["source_predecessor_kit_id"]
        != source_predecessor.kit_id
        or publisher_value["source_predecessor_tree_sha256"]
        != source_predecessor.new_digest
        or publisher_value["source_successor_kit_id"]
        != current_source.kit_id
        or publisher_value["source_successor_tree_sha256"]
        != current_source.new_digest
        or publisher_value["predecessor_old_tree_sha256"]
        != current_publisher.old_digest
        or publisher_value["successor_new_tree_sha256"]
        != current_publisher.new_digest
        or publisher_value["predecessor_previous_name"]
        != current_publisher.previous_name
    ):
        reject("publisher supersede aninhado diverge da cadeia source")
    publisher_allowed = {
        (
            publisher_archive
            if publisher_archived
            else PUBLISHER_SUPERSEDE_NAME
        )
    }
    publisher_statuses = [publisher_archived]
    publisher_intent_name = str(
        publisher_value["retained_intent_name"]
    )
    publisher_intent_archive = nested_publisher_archive_name(
        "intent",
        current_source.kit_id,
    )
    active_publisher_intent = read_publisher_record_if_present(
        staging,
        publisher_intent_name,
        uid=uid,
        gid=gid,
    )
    archived_publisher_intent = read_publisher_record_if_present(
        staging,
        publisher_intent_archive,
        uid=uid,
        gid=gid,
    )
    predecessor_publisher_intent_raw = (
        archived_publisher_intent
        if archived_publisher_intent is not None
        else active_publisher_intent
    )
    if (
        predecessor_publisher_intent_raw is None
        or hashlib.sha256(
            predecessor_publisher_intent_raw
        ).hexdigest()
        != publisher_value["predecessor_intent_sha256"]
    ):
        reject("intent publisher aninhado diverge do supersede")
    parsed_publisher_intent = validate_publisher_upgrade_record(
        predecessor_publisher_intent_raw,
        phase="intent",
        label="intent publisher aninhado",
    )
    if (
        parsed_publisher_intent["old_tree_sha256"]
        != publisher_value["predecessor_old_tree_sha256"]
        or parsed_publisher_intent["new_tree_sha256"]
        != publisher_value["predecessor_new_tree_sha256"]
        or parsed_publisher_intent["previous_name"]
        != publisher_value["predecessor_previous_name"]
    ):
        reject("intent publisher aninhado mudou de contrato")
    intent_archived, intent_allowed = _nested_record(
        staging,
        active_name=publisher_intent_name,
        archived_name=publisher_intent_archive,
        expected=predecessor_publisher_intent_raw,
        publisher=True,
        uid=uid,
        gid=gid,
    )
    candidate_archived, candidate_allowed = _nested_tree(
        staging,
        active_name=str(
            publisher_value["retained_candidate_name"]
        ),
        archived_name=nested_publisher_archive_name(
            "candidate",
            current_source.kit_id,
        ),
        expected_digest=str(
            publisher_value["predecessor_new_tree_sha256"]
        ),
        publisher=True,
        uid=uid,
        gid=gid,
    )
    publisher_statuses.extend(
        (candidate_archived, intent_archived)
    )
    publisher_allowed.update(candidate_allowed)
    publisher_allowed.update(intent_allowed)

    statuses = tuple(source_statuses + publisher_statuses)
    archived_count = sum(statuses)
    if statuses != (True,) * archived_count + (False,) * (
        len(statuses) - archived_count
    ):
        reject("histórico aninhado não forma prefixo transacional")
    for parent, allowed in (
        (state_descriptor, source_allowed),
        (staging, publisher_allowed),
    ):
        for name in os.listdir(parent):
            if (
                name.startswith(
                    NESTED_POST_PUBLISHER_ARCHIVE_PREFIX
                )
                and name not in allowed
            ):
                reject("namespace do histórico aninhado não é exato")
    history = NestedSupersedeHistory(
        source_predecessor=source_predecessor,
        source_supersede_raw=source_supersede_raw,
        publisher_supersede_raw=publisher_supersede_raw,
        publisher_predecessor_intent_raw=(
            predecessor_publisher_intent_raw
        ),
        publisher_predecessor_new_digest=str(
            publisher_value["predecessor_new_tree_sha256"]
        ),
        publisher_retained_intent_name=publisher_intent_name,
        publisher_retained_candidate_name=str(
            publisher_value["retained_candidate_name"]
        ),
        archive_statuses=statuses,
    )
    return history, source_allowed, publisher_allowed


def post_publisher_supersede_payload(
    recovery: PostPublisherRecovery,
) -> bytes:
    predecessor = recovery.predecessor
    value: dict[str, Any] = {
        "contract": POST_PUBLISHER_SUPERSEDE_CONTRACT,
        "phase": "post-publisher-supersede",
        "predecessor_api_sha": predecessor.api_sha,
        "predecessor_controller_sha": predecessor.controller_sha,
        "predecessor_intent_sha256": (
            recovery.source_intent_sha256
        ),
        "predecessor_kit_id": predecessor.kit_id,
        "predecessor_new_source_tree_sha256": (
            predecessor.new_digest
        ),
        "predecessor_old_source_tree_sha256": (
            predecessor.old_digest
        ),
        "predecessor_publisher_intent_sha256": (
            recovery.publisher_intent_sha256
        ),
        "predecessor_publisher_new_tree_sha256": (
            recovery.publisher_new_digest
        ),
        "predecessor_publisher_old_tree_sha256": (
            recovery.publisher_old_digest
        ),
        "predecessor_publisher_previous_name": (
            recovery.publisher_previous_name
        ),
        "predecessor_publisher_used_sha256": (
            recovery.publisher_used_sha256
        ),
        "predecessor_source_used_sha256": (
            recovery.source_used_sha256
        ),
        "schema_version": 1,
        "successor_kit_id": recovery.successor_kit_id,
        "successor_new_source_tree_sha256": (
            recovery.successor_new_digest
        ),
    }
    nested_hashes = (
        recovery.nested_source_supersede_sha256,
        recovery.nested_publisher_supersede_sha256,
    )
    staged_hashes = (
        recovery.staged_bundle_id,
        recovery.staged_bundle_tree_sha256,
    )
    if any(item is not None for item in nested_hashes):
        if not all(item is not None for item in nested_hashes):
            reject("bindings do histórico aninhado estão incompletos")
        value["schema_version"] = 2
        value["nested_source_supersede_sha256"] = (
            recovery.nested_source_supersede_sha256
        )
        value["nested_publisher_supersede_sha256"] = (
            recovery.nested_publisher_supersede_sha256
        )
    if any(item is not None for item in staged_hashes):
        if not all(item is not None for item in staged_hashes):
            reject("bindings do bundle post-stage estão incompletos")
        value["schema_version"] = 4 if value["schema_version"] == 2 else 3
        value["staged_bundle_id"] = recovery.staged_bundle_id
        value["staged_bundle_tree_sha256"] = (
            recovery.staged_bundle_tree_sha256
        )
    return canonical_bytes(value)


def validate_post_publisher_supersede(
    raw: bytes,
    *,
    successor_kit_id: str,
    successor_new_digest: str,
) -> PostPublisherRecovery:
    value = parse_canonical_json(
        raw,
        "bootstrap source post-publisher supersede",
    )
    base_keys = {
        "contract",
        "phase",
        "predecessor_api_sha",
        "predecessor_controller_sha",
        "predecessor_intent_sha256",
        "predecessor_kit_id",
        "predecessor_new_source_tree_sha256",
        "predecessor_old_source_tree_sha256",
        "predecessor_publisher_intent_sha256",
        "predecessor_publisher_new_tree_sha256",
        "predecessor_publisher_old_tree_sha256",
        "predecessor_publisher_previous_name",
        "predecessor_publisher_used_sha256",
        "predecessor_source_used_sha256",
        "schema_version",
        "successor_kit_id",
        "successor_new_source_tree_sha256",
    }
    schema_version = value.get("schema_version")
    if type(schema_version) is not int:
        reject("post-publisher supersede possui schema inválido")
    staged = schema_version in {3, 4}
    nested = schema_version in {2, 4}
    if schema_version == 1:
        expected_keys = base_keys
    elif schema_version == 2:
        expected_keys = base_keys | {
            "nested_source_supersede_sha256",
            "nested_publisher_supersede_sha256",
        }
    elif schema_version == 3:
        expected_keys = base_keys | {
            "staged_bundle_id",
            "staged_bundle_tree_sha256",
        }
    elif schema_version == 4:
        expected_keys = base_keys | {
            "nested_source_supersede_sha256",
            "nested_publisher_supersede_sha256",
            "staged_bundle_id",
            "staged_bundle_tree_sha256",
        }
    else:
        reject("post-publisher supersede possui schema inválido")
    exact_object(
        value,
        expected_keys,
        "bootstrap source post-publisher supersede",
    )
    if (
        value["contract"] != POST_PUBLISHER_SUPERSEDE_CONTRACT
        or value["phase"] != "post-publisher-supersede"
        or value["successor_kit_id"] != successor_kit_id
        or value["successor_new_source_tree_sha256"]
        != successor_new_digest
    ):
        reject("post-publisher supersede não autoriza este sucessor")
    predecessor = SupersededSourceTransaction(
        kit_id=require_hash(
            value["predecessor_kit_id"],
            "kit ID predecessor post-publisher",
        ),
        api_sha=require_sha(
            value["predecessor_api_sha"],
            "API predecessor post-publisher",
        ),
        controller_sha=require_sha(
            value["predecessor_controller_sha"],
            "controller predecessor post-publisher",
        ),
        old_digest=require_hash(
            value["predecessor_old_source_tree_sha256"],
            "source antigo predecessor post-publisher",
        ),
        new_digest=require_hash(
            value["predecessor_new_source_tree_sha256"],
            "source novo predecessor post-publisher",
        ),
        intent_raw=b"",
        publisher_intent_sha256=require_hash(
            value["predecessor_publisher_intent_sha256"],
            "publisher intent predecessor post-publisher",
        ),
        publisher_authorization_required=False,
    )
    source_intent_sha256 = require_hash(
        value["predecessor_intent_sha256"],
        "source intent predecessor post-publisher",
    )
    source_used_sha256 = require_hash(
        value["predecessor_source_used_sha256"],
        "source used predecessor post-publisher",
    )
    publisher_used_sha256 = require_hash(
        value["predecessor_publisher_used_sha256"],
        "publisher used predecessor post-publisher",
    )
    publisher_old_digest = require_hash(
        value["predecessor_publisher_old_tree_sha256"],
        "publisher old tree predecessor post-publisher",
    )
    publisher_new_digest = require_hash(
        value["predecessor_publisher_new_tree_sha256"],
        "publisher new tree predecessor post-publisher",
    )
    publisher_previous_name = value[
        "predecessor_publisher_previous_name"
    ]
    if (
        type(publisher_previous_name) is not str
        or publisher_previous_name
        != PUBLISHER_PREVIOUS_PREFIX + publisher_old_digest[:32]
        or publisher_old_digest == publisher_new_digest
        or predecessor.old_digest == predecessor.new_digest
        or predecessor.kit_id == successor_kit_id
        or predecessor.new_digest == successor_new_digest
    ):
        reject("post-publisher supersede não descreve sucessão distinta")
    nested_source_supersede_sha256 = (
        require_hash(
            value["nested_source_supersede_sha256"],
            "source supersede aninhado no recovery",
        )
        if nested
        else None
    )
    nested_publisher_supersede_sha256 = (
        require_hash(
            value["nested_publisher_supersede_sha256"],
            "publisher supersede aninhado no recovery",
        )
        if nested
        else None
    )
    staged_bundle_id = (
        require_hash(
            value["staged_bundle_id"],
            "bundle ID post-stage no recovery",
        )
        if staged
        else None
    )
    staged_bundle_tree_sha256 = (
        require_hash(
            value["staged_bundle_tree_sha256"],
            "árvore do bundle post-stage no recovery",
        )
        if staged
        else None
    )
    return PostPublisherRecovery(
        predecessor=predecessor,
        source_intent_sha256=source_intent_sha256,
        source_used_sha256=source_used_sha256,
        publisher_intent_sha256=predecessor.publisher_intent_sha256,
        publisher_used_sha256=publisher_used_sha256,
        publisher_old_digest=publisher_old_digest,
        publisher_new_digest=publisher_new_digest,
        publisher_previous_name=publisher_previous_name,
        successor_kit_id=successor_kit_id,
        successor_new_digest=successor_new_digest,
        staged_bundle_id=staged_bundle_id,
        staged_bundle_tree_sha256=staged_bundle_tree_sha256,
        nested_source_supersede_sha256=(
            nested_source_supersede_sha256
        ),
        nested_publisher_supersede_sha256=(
            nested_publisher_supersede_sha256
        ),
    )


def require_absent_path(path: Path, label: str) -> None:
    try:
        os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return
    reject(f"{label} precisa estar ausente no estado pré-stage")


def staged_bundle_tree_digest(
    descriptor: int,
    *,
    uid: int,
) -> str:
    """Hash one already-published, inert stage tree without following links."""

    digest = hashlib.sha256()
    digest.update(b"tratto-control-staged-bundle-tree-v1\0")
    entries = 0
    total_bytes = 0

    def record(
        *,
        kind: str,
        relative: str,
        info: os.stat_result,
        content_sha256: str,
    ) -> None:
        nonlocal entries
        entries += 1
        if entries > MAX_STAGED_BUNDLE_ENTRIES:
            reject("bundle post-stage excede o limite de entradas")
        digest.update(
            (
                f"{kind}\0{stat.S_IMODE(info.st_mode):04o}\0"
                f"{info.st_uid}\0{info.st_gid}\0{info.st_size}\0"
                f"{content_sha256}\0{relative}\0"
            ).encode("utf-8")
        )

    def visit(current: int, relative: str) -> None:
        nonlocal total_bytes
        before = os.fstat(current)
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != uid
            or stat.S_IMODE(before.st_mode) not in {0o550, 0o555}
        ):
            reject("diretório do bundle post-stage possui metadata insegura")
        record(
            kind="directory",
            relative=relative or ".",
            info=before,
            content_sha256="-",
        )
        try:
            names = sorted(
                os.listdir(current),
                key=lambda item: item.encode("utf-8"),
            )
        except (OSError, UnicodeError):
            reject("bundle post-stage não pôde ser inventariado")
        for name in names:
            path = f"{relative}/{name}" if relative else name
            if (
                canonical_member_path(path) != path
                or len(path.encode("utf-8")) > MAX_PATH_BYTES
            ):
                reject("bundle post-stage contém caminho não canônico")
            try:
                info = os.stat(
                    name,
                    dir_fd=current,
                    follow_symlinks=False,
                )
            except OSError:
                reject("entrada do bundle post-stage sumiu")
            mode = stat.S_IMODE(info.st_mode)
            if info.st_uid != uid:
                reject("entrada do bundle post-stage não pertence a root")
            if stat.S_ISDIR(info.st_mode):
                try:
                    child = os.open(
                        name,
                        os.O_RDONLY
                        | os.O_DIRECTORY
                        | os.O_CLOEXEC
                        | os.O_NOFOLLOW,
                        dir_fd=current,
                    )
                except OSError:
                    reject("diretório post-stage não pôde ser aberto")
                try:
                    require_same_mount(
                        current,
                        child,
                        f"diretório post-stage {path}",
                    )
                    visit(child, path)
                finally:
                    os.close(child)
                continue
            if stat.S_ISREG(info.st_mode):
                validate_regular(
                    info,
                    f"arquivo post-stage {path}",
                    uid=uid,
                    gid=info.st_gid,
                    modes={0o440, 0o444, 0o550, 0o555},
                    maximum=MAX_STAGED_BUNDLE_MEMBER_BYTES,
                    allow_empty=True,
                )
                try:
                    file_descriptor = os.open(
                        name,
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=current,
                    )
                except OSError:
                    reject("arquivo post-stage não pôde ser aberto")
                try:
                    opened = os.fstat(file_descriptor)
                    validate_regular(
                        opened,
                        f"arquivo post-stage aberto {path}",
                        uid=uid,
                        gid=info.st_gid,
                        modes={0o440, 0o444, 0o550, 0o555},
                        maximum=MAX_STAGED_BUNDLE_MEMBER_BYTES,
                        allow_empty=True,
                    )
                    require_same_mount(
                        current,
                        file_descriptor,
                        f"arquivo post-stage {path}",
                    )
                    if (
                        opened.st_dev,
                        opened.st_ino,
                        opened.st_mode,
                        opened.st_uid,
                        opened.st_gid,
                        opened.st_size,
                        opened.st_nlink,
                        opened.st_mtime_ns,
                        opened.st_ctime_ns,
                    ) != (
                        info.st_dev,
                        info.st_ino,
                        info.st_mode,
                        info.st_uid,
                        info.st_gid,
                        info.st_size,
                        info.st_nlink,
                        info.st_mtime_ns,
                        info.st_ctime_ns,
                    ):
                        reject("arquivo post-stage mudou antes da leitura")
                    content_sha256 = digest_fd(
                        file_descriptor,
                        opened,
                        f"arquivo post-stage {path}",
                    )
                finally:
                    os.close(file_descriptor)
                total_bytes += opened.st_size
                if total_bytes > MAX_STAGED_BUNDLE_BYTES:
                    reject("bundle post-stage excede o limite de bytes")
                record(
                    kind="file",
                    relative=path,
                    info=opened,
                    content_sha256=content_sha256,
                )
                continue
            if stat.S_ISLNK(info.st_mode):
                if (
                    path != "web/.next/cache"
                    or mode != 0o777
                    or info.st_nlink != 1
                ):
                    reject("bundle post-stage contém link não autorizado")
                if not hasattr(os, "O_PATH"):
                    reject("mount do link post-stage não é verificável")
                try:
                    link_descriptor = os.open(
                        name,
                        os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=current,
                    )
                except OSError:
                    reject("link post-stage não pôde ser aberto")
                try:
                    require_same_mount(
                        current,
                        link_descriptor,
                        f"link post-stage {path}",
                    )
                    target = os.readlink(name, dir_fd=current)
                    after = os.stat(
                        name,
                        dir_fd=current,
                        follow_symlinks=False,
                    )
                except OSError:
                    reject("link post-stage não pôde ser lido")
                finally:
                    os.close(link_descriptor)
                if (
                    target != "/var/cache/tratto-control/web"
                    or (
                        info.st_dev,
                        info.st_ino,
                        info.st_mode,
                        info.st_uid,
                        info.st_gid,
                        info.st_size,
                        info.st_mtime_ns,
                        info.st_ctime_ns,
                    )
                    != (
                        after.st_dev,
                        after.st_ino,
                        after.st_mode,
                        after.st_uid,
                        after.st_gid,
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    )
                ):
                    reject("link post-stage diverge do cache fixo")
                record(
                    kind="symlink",
                    relative=path,
                    info=info,
                    content_sha256=hashlib.sha256(
                        target.encode("utf-8")
                    ).hexdigest(),
                )
                continue
            reject("bundle post-stage contém entrada especial")
        after = os.fstat(current)
        stable = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(before, field) != getattr(after, field)
            for field in stable
        ):
            reject("diretório do bundle post-stage mudou durante o hash")

    visit(descriptor, "")
    return digest.hexdigest()


def validate_staged_bundle_attestation(
    bundle: int,
    *,
    bundle_id: str,
    uid: int,
    gid: int,
) -> None:
    try:
        descriptor = os.open(
            "release-attestation.json",
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=bundle,
        )
    except OSError:
        reject("atestado do bundle post-stage não pôde ser aberto")
    try:
        info = os.fstat(descriptor)
        validate_regular(
            info,
            "atestado do bundle post-stage",
            uid=uid,
            gid=gid,
            modes={0o444},
            maximum=MAX_JSON_BYTES,
        )
        raw = read_all(
            descriptor,
            info,
            maximum=MAX_JSON_BYTES,
            label="atestado do bundle post-stage",
        )
    finally:
        os.close(descriptor)
    if hashlib.sha256(raw).hexdigest() != bundle_id:
        reject("atestado post-stage diverge do bundle ID")
    value = parse_canonical_json(raw, "atestado do bundle post-stage")
    if (
        value.get("schema_version") != 6
        or set(value)
        != {
            "approval",
            "artifacts",
            "behavioral_verification",
            "bootstrap_source_helper",
            "carrier",
            "controller",
            "migration",
            "schema_version",
            "supplemental_inventory",
        }
    ):
        reject("recovery post-stage exige o atestado schema 6 exato")


def source_intent_attestation_sha256(raw: bytes) -> str:
    value = parse_canonical_json(raw, "source intent do bundle post-stage")
    return require_hash(
        value.get("attestation_sha256"),
        "atestado no source intent post-stage",
    )


def validate_post_publisher_pre_stage(
    state_descriptor: int,
    *,
    recovery: PostPublisherRecovery | None = None,
    uid: int,
    gid: int,
) -> bool:
    bundle_archived = False
    control = open_path_chain(
        CONTROL_ROOT,
        uid=uid,
        gid=gid,
        final_modes={0o711},
    )
    try:
        try:
            os.stat(
                "current",
                dir_fd=control,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            reject("runtime current já existe no recovery post-publisher")
        bundles = _open_named_directory(
            control,
            BUNDLES_NAME,
            uid=uid,
            gid=gid,
            modes={0o711},
        )
        if bundles is None:
            reject("diretório de bundles pré-stage está ausente")
        try:
            expected_id = (
                recovery.staged_bundle_id
                if recovery is not None
                else None
            )
            expected_tree = (
                recovery.staged_bundle_tree_sha256
                if recovery is not None
                else None
            )
            if (expected_id is None) != (expected_tree is None):
                reject("journal post-stage possui bindings incompletos")
            names = set(os.listdir(bundles))
            staging = _open_named_directory(
                control,
                ".staging",
                uid=uid,
                gid=gid,
                modes={0o700},
            )
            if staging is None:
                reject("staging post-stage está ausente")
            try:
                archive_name = (
                    post_stage_bundle_archive_name(expected_id)
                    if expected_id is not None
                    else None
                )
                archived = (
                    _open_named_directory(
                        staging,
                        archive_name,
                        uid=uid,
                        gid=gid,
                        modes={0o555},
                    )
                    if archive_name is not None
                    else None
                )
                active = (
                    _open_named_directory(
                        bundles,
                        expected_id,
                        uid=uid,
                        gid=gid,
                        modes={0o555},
                    )
                    if expected_id is not None
                    else None
                )
                try:
                    if expected_id is None:
                        if names or any(
                            name.startswith(
                                POST_STAGE_BUNDLE_ARCHIVE_PREFIX
                            )
                            for name in os.listdir(staging)
                        ):
                            reject(
                                "recovery post-publisher encontrou "
                                "bundle staged"
                            )
                    else:
                        if active is not None and archived is not None:
                            reject(
                                "bundle post-stage coexiste com sua "
                                "quarentena"
                            )
                        if active is None and archived is None:
                            reject(
                                "bundle post-stage autorizado está ausente"
                            )
                        if names not in ({expected_id}, set()):
                            reject(
                                "diretório de bundles contém release estranho"
                            )
                        selected = (
                            archived if archived is not None else active
                        )
                        assert (
                            selected is not None
                            and expected_tree is not None
                        )
                        validate_staged_bundle_attestation(
                            selected,
                            bundle_id=expected_id,
                            uid=uid,
                            gid=gid,
                        )
                        observed_tree = staged_bundle_tree_digest(
                            selected,
                            uid=uid,
                        )
                        if observed_tree != expected_tree:
                            reject("árvore do bundle post-stage diverge")
                        bundle_archived = archived is not None
                finally:
                    if active is not None:
                        os.close(active)
                    if archived is not None:
                        os.close(archived)
            finally:
                os.close(staging)
        finally:
            os.close(bundles)
    finally:
        os.close(control)
    for path, label in (
        (BOOTSTRAP_RELEASE_MARKER, "bootstrap release marker"),
        (RELEASE_STATE_MARKER, "release-state"),
        (ACTIVATION_JOURNAL, "activation journal"),
        (ACTIVATION_EPOCH_MARKER, "activation epoch"),
    ):
        require_absent_path(path, label)
    try:
        os.stat(
            BOOTSTRAP_CONSUMED_NAME,
            dir_fd=state_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        pass
    else:
        reject("bootstrap consumption marker já existe")
    return bundle_archived


def validate_fixed_post_publisher_state(
    state_descriptor: int,
    *,
    current_source: SupersededSourceTransaction,
    expected_intent_sha256: str,
    expected_used_sha256: str,
    uid: int,
    gid: int,
) -> tuple[
    PublisherUpgradeTransaction,
    NestedSupersedeHistory | None,
    set[str],
    set[str],
]:
    require_hash(
        expected_intent_sha256,
        "publisher intent post-publisher esperado",
    )
    require_hash(
        expected_used_sha256,
        "publisher used post-publisher esperado",
    )
    control = open_path_chain(
        CONTROL_ROOT,
        uid=uid,
        gid=gid,
        final_modes={0o711},
    )
    staging: int | None = None
    try:
        staging = _open_named_directory(
            control,
            ".staging",
            uid=uid,
            gid=gid,
            modes={0o700},
        )
        if staging is None:
            reject("staging do publisher post-publisher está ausente")
        intent_raw = read_publisher_record_if_present(
            staging,
            PUBLISHER_INTENT_NAME,
            uid=uid,
            gid=gid,
        )
        used_raw = read_publisher_record_if_present(
            staging,
            PUBLISHER_USED_NAME,
            uid=uid,
            gid=gid,
        )
        if intent_raw is None or used_raw is None:
            reject("publisher post-publisher não está terminal")
        transaction = validate_publisher_upgrade_transaction(
            intent_raw,
            used_raw,
        )
        if (
            hashlib.sha256(intent_raw).hexdigest()
            != expected_intent_sha256
            or hashlib.sha256(used_raw).hexdigest()
            != expected_used_sha256
        ):
            reject("publisher terminal diverge dos bindings externos")
        (
            nested_history,
            nested_source_allowed,
            nested_publisher_allowed,
        ) = validate_nested_supersede_history(
            state_descriptor,
            staging,
            current_source=current_source,
            current_publisher=transaction,
            expected_source_supersede_sha256=None,
            expected_publisher_supersede_sha256=None,
            uid=uid,
            gid=gid,
        )
        allowed = {
            PUBLISHER_INTENT_NAME,
            PUBLISHER_USED_NAME,
            transaction.previous_name,
        }
        allowed.update(nested_publisher_allowed)
        if set(os.listdir(staging)) != allowed:
            reject("namespace terminal do publisher não é exato")
        previous = _open_named_directory(
            staging,
            transaction.previous_name,
            uid=uid,
            gid=gid,
            modes={0o555},
        )
        if previous is None:
            reject("rollback terminal do publisher está ausente")
        try:
            if (
                protected_bootstrap_tree_digest(
                    previous,
                    uid=uid,
                    gid=gid,
                )
                != transaction.old_digest
            ):
                reject("rollback terminal do publisher diverge")
        finally:
            os.close(previous)
        final = _open_named_directory(
            control,
            "bootstrap",
            uid=uid,
            gid=gid,
            modes={0o555},
        )
        if final is None:
            reject("bootstrap terminal do publisher está ausente")
        try:
            if (
                protected_bootstrap_tree_digest(
                    final,
                    uid=uid,
                    gid=gid,
                )
                != transaction.new_digest
            ):
                reject("bootstrap terminal diverge do publisher used")
        finally:
            os.close(final)
        return (
            transaction,
            nested_history,
            nested_source_allowed,
            nested_publisher_allowed,
        )
    finally:
        if staging is not None:
            os.close(staging)
        os.close(control)


def build_initial_post_publisher_recovery(
    state_descriptor: int,
    *,
    observed_source_digest: str,
    binding: AttestationBinding,
    successor_kit_id: str,
    successor_new_digest: str,
    expectations: BootstrapExpectations,
    uid: int,
    gid: int,
) -> PostPublisherRecovery:
    intent_raw = read_record_if_present(
        state_descriptor,
        INTENT_NAME,
        uid=uid,
        gid=gid,
    )
    used_raw = read_record_if_present(
        state_descriptor,
        USED_NAME,
        uid=uid,
        gid=gid,
    )
    if intent_raw is None or used_raw is None:
        reject("source predecessor post-publisher não está terminal")
    predecessor = validate_source_intent(intent_raw)
    if (
        predecessor.kit_id
        != expectations.post_publisher_predecessor_kit_id
        or predecessor.controller_sha
        != expectations.post_publisher_predecessor_controller_sha
        or hashlib.sha256(intent_raw).hexdigest()
        != expectations.post_publisher_source_intent_sha256
        or hashlib.sha256(used_raw).hexdigest()
        != expectations.post_publisher_source_used_sha256
        or predecessor.api_sha not in binding.api_required_ancestors
        or predecessor.api_sha not in binding.ops_required_ancestors
        or predecessor.kit_id == successor_kit_id
        or predecessor.new_digest == successor_new_digest
        or observed_source_digest != predecessor.new_digest
    ):
        reject("bindings externos não autorizam o source terminal")
    for phase in ("prepared", "exchanged", "retained", "used"):
        observed = read_record_if_present(
            state_descriptor,
            POST_PUBLISHER_SOURCE_PHASE_NAMES[phase],
            uid=uid,
            gid=gid,
        )
        if observed != _expected_source_phase(predecessor, phase):
            reject(f"fase source terminal ausente ou divergente: {phase}")
    _validate_predecessor_rollback(
        state_descriptor,
        predecessor,
        uid=uid,
        gid=gid,
    )
    allowed = {
        INTENT_NAME,
        PREPARED_NAME,
        EXCHANGED_NAME,
        RETAINED_NAME,
        USED_NAME,
        f"{PREVIOUS_PREFIX}{predecessor.kit_id}",
        (
            "bootstrap-source-kit.post-publisher-supersede."
            f"{successor_kit_id}.installing"
        ),
    }
    (
        publisher,
        nested_history,
        nested_source_allowed,
        _nested_publisher_allowed,
    ) = validate_fixed_post_publisher_state(
        state_descriptor,
        current_source=predecessor,
        expected_intent_sha256=(
            expectations.post_publisher_publisher_intent_sha256
        ),
        expected_used_sha256=(
            expectations.post_publisher_publisher_used_sha256
        ),
        uid=uid,
        gid=gid,
    )
    allowed.update(nested_source_allowed)
    for name in os.listdir(state_descriptor):
        if not (
            name.startswith("bootstrap-source-kit.")
            or name.startswith(CANDIDATE_PREFIX)
            or name.startswith(PREVIOUS_PREFIX)
            or name.startswith(
                NESTED_POST_PUBLISHER_ARCHIVE_PREFIX
            )
        ):
            continue
        if name not in allowed:
            reject("namespace source terminal contém journal estrangeiro")
    predecessor = SupersededSourceTransaction(
        kit_id=predecessor.kit_id,
        api_sha=predecessor.api_sha,
        controller_sha=predecessor.controller_sha,
        old_digest=predecessor.old_digest,
        new_digest=predecessor.new_digest,
        intent_raw=intent_raw,
        publisher_intent_sha256=hashlib.sha256(
            publisher.intent_raw
        ).hexdigest(),
        publisher_authorization_required=False,
    )
    staged_bundle_id = expectations.post_publisher_staged_bundle_id
    staged_bundle_tree_sha256 = (
        expectations.post_publisher_staged_bundle_tree_sha256
    )
    if (
        staged_bundle_id is not None
        and staged_bundle_id
        != source_intent_attestation_sha256(intent_raw)
    ):
        reject("bundle post-stage não pertence ao source predecessor")
    recovery = PostPublisherRecovery(
        predecessor=predecessor,
        source_intent_sha256=hashlib.sha256(intent_raw).hexdigest(),
        source_used_sha256=hashlib.sha256(used_raw).hexdigest(),
        publisher_intent_sha256=hashlib.sha256(
            publisher.intent_raw
        ).hexdigest(),
        publisher_used_sha256=hashlib.sha256(
            publisher.used_raw
        ).hexdigest(),
        publisher_old_digest=publisher.old_digest,
        publisher_new_digest=publisher.new_digest,
        publisher_previous_name=publisher.previous_name,
        successor_kit_id=successor_kit_id,
        successor_new_digest=successor_new_digest,
        staged_bundle_id=staged_bundle_id,
        staged_bundle_tree_sha256=staged_bundle_tree_sha256,
        nested_source_supersede_sha256=(
            hashlib.sha256(
                nested_history.source_supersede_raw
            ).hexdigest()
            if nested_history is not None
            else None
        ),
        nested_publisher_supersede_sha256=(
            hashlib.sha256(
                nested_history.publisher_supersede_raw
            ).hexdigest()
            if nested_history is not None
            else None
        ),
        nested_history=nested_history,
    )
    validate_post_publisher_pre_stage(
        state_descriptor,
        recovery=recovery,
        uid=uid,
        gid=gid,
    )
    return recovery


def _expected_source_phase(
    predecessor: SupersededSourceTransaction,
    phase: str,
) -> bytes:
    if phase == "intent":
        return predecessor.intent_raw
    return marker_payload(
        kit_id=predecessor.kit_id,
        phase=phase,
        old_digest=predecessor.old_digest,
        new_digest=predecessor.new_digest,
    )


def _archive_source_record(
    state_descriptor: int,
    predecessor: SupersededSourceTransaction,
    phase: str,
    *,
    uid: int,
    gid: int,
    runtime: Runtime,
) -> None:
    source_name = POST_PUBLISHER_SOURCE_PHASE_NAMES[phase]
    archived_name = predecessor.archived_name(phase)
    expected = _expected_source_phase(predecessor, phase)
    source_raw = read_record_if_present(
        state_descriptor,
        source_name,
        uid=uid,
        gid=gid,
    )
    archived_raw = read_record_if_present(
        state_descriptor,
        archived_name,
        uid=uid,
        gid=gid,
    )
    if archived_raw is not None:
        if archived_raw != expected:
            reject(f"histórico predecessor diverge: {archived_name}")
        if source_raw == expected:
            reject(f"record predecessor coexistente: {source_name}")
        return
    if source_raw != expected:
        reject(f"record predecessor não recuperável: {source_name}")
    try:
        runtime.noreplace(
            state_descriptor,
            source_name,
            state_descriptor,
            archived_name,
        )
    except FileExistsError:
        archived_raw = read_record_if_present(
            state_descriptor,
            archived_name,
            uid=uid,
            gid=gid,
        )
        if archived_raw != expected:
            raise
    os.fsync(state_descriptor)
    if read_record_if_present(
        state_descriptor,
        archived_name,
        uid=uid,
        gid=gid,
    ) != expected:
        reject(f"record predecessor não foi arquivado: {source_name}")


def _validate_predecessor_rollback(
    state_descriptor: int,
    predecessor: SupersededSourceTransaction,
    *,
    uid: int,
    gid: int,
) -> None:
    candidate = _open_named_directory(
        state_descriptor,
        f"{CANDIDATE_PREFIX}{predecessor.kit_id}",
        uid=uid,
        gid=gid,
        modes={0o555, 0o700},
    )
    if candidate is not None:
        os.close(candidate)
        reject("candidate predecessor coexistente após retenção")
    previous = _open_named_directory(
        state_descriptor,
        f"{PREVIOUS_PREFIX}{predecessor.kit_id}",
        uid=uid,
        gid=gid,
        modes={0o555},
    )
    if previous is None:
        reject("rollback predecessor retido está ausente")
    try:
        observed = tree_digest(scan_tree(previous, uid=uid, gid=gid))
    finally:
        os.close(previous)
    if observed != predecessor.old_digest:
        reject("rollback predecessor retido diverge do intent")


def _post_publisher_recovery_from_record(
    state_descriptor: int,
    raw: bytes,
    *,
    binding: AttestationBinding,
    successor_kit_id: str,
    successor_new_digest: str,
    expectations: BootstrapExpectations,
    uid: int,
    gid: int,
) -> PostPublisherRecovery:
    recovery = validate_post_publisher_supersede(
        raw,
        successor_kit_id=successor_kit_id,
        successor_new_digest=successor_new_digest,
    )
    predecessor = recovery.predecessor
    if (
        predecessor.kit_id
        != expectations.post_publisher_predecessor_kit_id
        or predecessor.controller_sha
        != expectations.post_publisher_predecessor_controller_sha
        or recovery.source_intent_sha256
        != expectations.post_publisher_source_intent_sha256
        or recovery.source_used_sha256
        != expectations.post_publisher_source_used_sha256
        or recovery.publisher_intent_sha256
        != expectations.post_publisher_publisher_intent_sha256
        or recovery.publisher_used_sha256
        != expectations.post_publisher_publisher_used_sha256
        or recovery.staged_bundle_id
        != expectations.post_publisher_staged_bundle_id
        or recovery.staged_bundle_tree_sha256
        != expectations.post_publisher_staged_bundle_tree_sha256
        or predecessor.api_sha not in binding.api_required_ancestors
        or predecessor.api_sha not in binding.ops_required_ancestors
    ):
        reject("bindings externos divergem do recovery post-publisher")
    intent_raw = read_record_if_present(
        state_descriptor,
        predecessor.archived_name("intent"),
        uid=uid,
        gid=gid,
    )
    if intent_raw is None:
        intent_raw = read_record_if_present(
            state_descriptor,
            INTENT_NAME,
            uid=uid,
            gid=gid,
        )
    if (
        intent_raw is None
        or hashlib.sha256(intent_raw).hexdigest()
        != recovery.source_intent_sha256
    ):
        reject("source intent post-publisher não está recuperável")
    if (
        recovery.staged_bundle_id is not None
        and recovery.staged_bundle_id
        != source_intent_attestation_sha256(intent_raw)
    ):
        reject("bundle post-stage diverge do source predecessor")
    parsed = validate_source_intent(intent_raw)
    if (
        parsed.kit_id != predecessor.kit_id
        or parsed.api_sha != predecessor.api_sha
        or parsed.controller_sha != predecessor.controller_sha
        or parsed.old_digest != predecessor.old_digest
        or parsed.new_digest != predecessor.new_digest
    ):
        reject("source intent diverge do journal post-publisher")
    predecessor = SupersededSourceTransaction(
        kit_id=parsed.kit_id,
        api_sha=parsed.api_sha,
        controller_sha=parsed.controller_sha,
        old_digest=parsed.old_digest,
        new_digest=parsed.new_digest,
        intent_raw=intent_raw,
        publisher_intent_sha256=recovery.publisher_intent_sha256,
        publisher_authorization_required=False,
    )
    nested_history: NestedSupersedeHistory | None = None
    if recovery.nested_source_supersede_sha256 is not None:
        publisher_intent_value = {
            "new_tree_sha256": recovery.publisher_new_digest,
            "old_tree_sha256": recovery.publisher_old_digest,
            "phase": "intent",
            "previous_name": recovery.publisher_previous_name,
            "schema_version": 1,
        }
        publisher_used_value = dict(publisher_intent_value)
        publisher_used_value["phase"] = "used"
        current_publisher = PublisherUpgradeTransaction(
            old_digest=recovery.publisher_old_digest,
            new_digest=recovery.publisher_new_digest,
            previous_name=recovery.publisher_previous_name,
            intent_raw=canonical_bytes(publisher_intent_value),
            used_raw=canonical_bytes(publisher_used_value),
        )
        control, staging = _open_post_publisher_staging(
            uid=uid,
            gid=gid,
        )
        try:
            nested_history, _source_allowed, _publisher_allowed = (
                validate_nested_supersede_history(
                    state_descriptor,
                    staging,
                    current_source=predecessor,
                    current_publisher=current_publisher,
                    expected_source_supersede_sha256=(
                        recovery.nested_source_supersede_sha256
                    ),
                    expected_publisher_supersede_sha256=(
                        recovery.nested_publisher_supersede_sha256
                    ),
                    uid=uid,
                    gid=gid,
                )
            )
        finally:
            os.close(staging)
            os.close(control)
        if nested_history is None:
            reject("recovery exige histórico aninhado ausente")
    return PostPublisherRecovery(
        predecessor=predecessor,
        source_intent_sha256=recovery.source_intent_sha256,
        source_used_sha256=recovery.source_used_sha256,
        publisher_intent_sha256=recovery.publisher_intent_sha256,
        publisher_used_sha256=recovery.publisher_used_sha256,
        publisher_old_digest=recovery.publisher_old_digest,
        publisher_new_digest=recovery.publisher_new_digest,
        publisher_previous_name=recovery.publisher_previous_name,
        successor_kit_id=recovery.successor_kit_id,
        successor_new_digest=recovery.successor_new_digest,
        staged_bundle_id=recovery.staged_bundle_id,
        staged_bundle_tree_sha256=(
            recovery.staged_bundle_tree_sha256
        ),
        nested_source_supersede_sha256=(
            recovery.nested_source_supersede_sha256
        ),
        nested_publisher_supersede_sha256=(
            recovery.nested_publisher_supersede_sha256
        ),
        nested_history=nested_history,
    )


def _validate_post_source_used_evidence(
    state_descriptor: int,
    recovery: PostPublisherRecovery,
    *,
    uid: int,
    gid: int,
) -> bool:
    expected = _expected_source_phase(recovery.predecessor, "used")
    active = read_record_if_present(
        state_descriptor,
        USED_NAME,
        uid=uid,
        gid=gid,
    )
    archived = read_record_if_present(
        state_descriptor,
        recovery.predecessor.archived_name("used"),
        uid=uid,
        gid=gid,
    )
    if archived is None:
        if active is None:
            reject("source used predecessor não está recuperável")
        if (
            active != expected
            or hashlib.sha256(active).hexdigest()
            != recovery.source_used_sha256
        ):
            reject("source used predecessor diverge")
        return False
    if (
        archived != expected
        or hashlib.sha256(archived).hexdigest()
        != recovery.source_used_sha256
    ):
        reject("source used predecessor arquivado diverge")
    if active == expected:
        reject("source used predecessor coexiste com seu arquivo")
    return True


def _publisher_archive_status(
    staging: int,
    recovery: PostPublisherRecovery,
    *,
    uid: int,
    gid: int,
) -> tuple[bool, bool, bool]:
    expected_intent = canonical_bytes(
        {
            "new_tree_sha256": recovery.publisher_new_digest,
            "old_tree_sha256": recovery.publisher_old_digest,
            "phase": "intent",
            "previous_name": recovery.publisher_previous_name,
            "schema_version": 1,
        }
    )
    expected_used_value = parse_canonical_json(
        expected_intent,
        "publisher intent predecessor esperado",
    )
    expected_used_value["phase"] = "used"
    expected_used = canonical_bytes(expected_used_value)
    statuses: list[bool] = []
    for active_name, archived_name, expected, expected_hash in (
        (
            PUBLISHER_USED_NAME,
            post_publisher_archive_name(
                "used",
                recovery.predecessor.kit_id,
            ),
            expected_used,
            recovery.publisher_used_sha256,
        ),
        (
            PUBLISHER_INTENT_NAME,
            post_publisher_archive_name(
                "intent",
                recovery.predecessor.kit_id,
            ),
            expected_intent,
            recovery.publisher_intent_sha256,
        ),
    ):
        active = read_publisher_record_if_present(
            staging,
            active_name,
            uid=uid,
            gid=gid,
        )
        archived = read_publisher_record_if_present(
            staging,
            archived_name,
            uid=uid,
            gid=gid,
        )
        observed = archived if archived is not None else active
        if (
            observed != expected
            or hashlib.sha256(observed).hexdigest() != expected_hash
        ):
            reject(f"{active_name} predecessor não está recuperável")
        if archived is not None and active == expected:
            reject(f"{active_name} predecessor coexiste com seu arquivo")
        statuses.append(archived is not None)
    active_previous = _open_named_directory(
        staging,
        recovery.publisher_previous_name,
        uid=uid,
        gid=gid,
        modes={0o555},
    )
    archived_previous_name = post_publisher_archive_name(
        "previous",
        recovery.predecessor.kit_id,
    )
    archived_previous = _open_named_directory(
        staging,
        archived_previous_name,
        uid=uid,
        gid=gid,
        modes={0o555},
    )
    if active_previous is not None and archived_previous is not None:
        os.close(active_previous)
        os.close(archived_previous)
        reject("rollback publisher coexiste com seu arquivo")
    previous = (
        archived_previous
        if archived_previous is not None
        else active_previous
    )
    if previous is None:
        reject("rollback publisher predecessor não está recuperável")
    try:
        if (
            protected_bootstrap_tree_digest(
                previous,
                uid=uid,
                gid=gid,
            )
            != recovery.publisher_old_digest
        ):
            reject("rollback publisher predecessor diverge")
    finally:
        os.close(previous)
    statuses.append(archived_previous is not None)
    expected_prefix = (True,) * sum(statuses) + (False,) * (
        len(statuses) - sum(statuses)
    )
    if tuple(statuses) != expected_prefix:
        reject("arquivos publisher post-publisher estão fora de ordem")
    return tuple(statuses)  # type: ignore[return-value]


def validate_partial_publisher_record(
    staging: int,
    name: str,
    expected: bytes,
    *,
    uid: int,
    gid: int,
) -> bool:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=staging,
        )
    except FileNotFoundError:
        return False
    try:
        info = os.fstat(descriptor)
        validate_regular(
            info,
            name,
            uid=uid,
            gid=gid,
            modes={0o400, 0o600},
            maximum=len(expected),
            allow_empty=True,
        )
        observed = (
            read_all(
                descriptor,
                info,
                maximum=len(expected),
                label=name,
            )
            if info.st_size
            else b""
        )
    finally:
        os.close(descriptor)
    if not expected.startswith(observed):
        reject(f"{name} não é prefixo do publisher sucessor")
    if stat.S_IMODE(info.st_mode) == 0o400 and observed != expected:
        reject(f"{name} imutável está incompleto")
    return True


def _validate_successor_publisher_state(
    control: int,
    staging: int,
    recovery: PostPublisherRecovery,
    *,
    allow_successor: bool,
    uid: int,
    gid: int,
) -> tuple[set[str], str]:
    final = _open_named_directory(
        control,
        "bootstrap",
        uid=uid,
        gid=gid,
        modes={0o555},
    )
    if final is None:
        reject("bootstrap publicado sumiu no recovery post-publisher")
    try:
        final_digest = protected_bootstrap_tree_digest(
            final,
            uid=uid,
            gid=gid,
        )
    finally:
        os.close(final)
    intent_raw = read_publisher_record_if_present(
        staging,
        PUBLISHER_INTENT_NAME,
        uid=uid,
        gid=gid,
    )
    used_raw = read_publisher_record_if_present(
        staging,
        PUBLISHER_USED_NAME,
        uid=uid,
        gid=gid,
    )
    candidate = _open_named_directory(
        staging,
        PUBLISHER_CANDIDATE_NAME,
        uid=uid,
        gid=gid,
        modes={0o555, 0o700},
    )
    candidate_digest: str | None = None
    candidate_mode: int | None = None
    if candidate is not None:
        try:
            candidate_mode = stat.S_IMODE(os.fstat(candidate).st_mode)
            candidate_entries = scan_tree(
                candidate,
                uid=uid,
                gid=gid,
                root_modes={0o555, 0o700},
                directory_modes={0o555, 0o700},
                file_modes={0o444, 0o555, 0o600},
            )
            if candidate_mode == 0o555:
                candidate_digest = protected_bootstrap_tree_digest(
                    candidate,
                    uid=uid,
                    gid=gid,
                )
        finally:
            os.close(candidate)
    allowed: set[str] = set()
    if intent_raw is None:
        if used_raw is not None:
            reject("publisher sucessor possui used sem intent")
        if not allow_successor and candidate is not None:
            reject("publisher sucessor começou antes do source retido")
        if final_digest != recovery.publisher_new_digest:
            reject("bootstrap mudou sem intent publisher sucessor")
        if candidate is not None:
            allowed.add(PUBLISHER_CANDIDATE_NAME)
        if candidate_mode == 0o555 and candidate_digest is not None:
            successor_intent = canonical_bytes(
                {
                    "new_tree_sha256": candidate_digest,
                    "old_tree_sha256": recovery.publisher_new_digest,
                    "phase": "intent",
                    "previous_name": (
                        PUBLISHER_PREVIOUS_PREFIX
                        + recovery.publisher_new_digest[:32]
                    ),
                    "schema_version": 1,
                }
            )
            if validate_partial_publisher_record(
                staging,
                f"{PUBLISHER_INTENT_NAME}.installing",
                successor_intent,
                uid=uid,
                gid=gid,
            ):
                if not allow_successor:
                    reject("publisher intent parcial começou cedo")
                allowed.add(f"{PUBLISHER_INTENT_NAME}.installing")
        elif (
            f"{PUBLISHER_INTENT_NAME}.installing"
            in os.listdir(staging)
        ):
            reject("publisher intent parcial não possui candidate completo")
        if f"{PUBLISHER_USED_NAME}.installing" in os.listdir(staging):
            reject("publisher used parcial existe antes do intent")
        return allowed, final_digest
    if not allow_successor:
        reject("publisher sucessor começou antes do source retido")
    intent = validate_publisher_upgrade_record(
        intent_raw,
        phase="intent",
        label="publisher intent sucessor",
    )
    if intent["old_tree_sha256"] != recovery.publisher_new_digest:
        reject("publisher sucessor não parte do bootstrap predecessor")
    successor_new = str(intent["new_tree_sha256"])
    successor_previous = str(intent["previous_name"])
    allowed.add(PUBLISHER_INTENT_NAME)
    previous = _open_named_directory(
        staging,
        successor_previous,
        uid=uid,
        gid=gid,
        modes={0o555},
    )
    previous_valid = False
    if previous is not None:
        try:
            previous_valid = (
                protected_bootstrap_tree_digest(
                    previous,
                    uid=uid,
                    gid=gid,
                )
                == recovery.publisher_new_digest
            )
        finally:
            os.close(previous)
        if not previous_valid:
            reject("rollback publisher sucessor diverge")
        allowed.add(successor_previous)
    if final_digest == recovery.publisher_new_digest:
        if (
            candidate_mode != 0o555
            or candidate_digest != successor_new
            or previous is not None
            or used_raw is not None
        ):
            reject("publisher sucessor pré-exchange está inconsistente")
        allowed.add(PUBLISHER_CANDIDATE_NAME)
    elif final_digest == successor_new:
        candidate_is_old = (
            candidate_mode == 0o555
            and candidate_digest == recovery.publisher_new_digest
        )
        if not candidate_is_old and not previous_valid:
            reject("publisher sucessor perdeu o lado anterior")
        if candidate_is_old:
            if previous is not None:
                reject("candidate e rollback publisher coexistem")
            allowed.add(PUBLISHER_CANDIDATE_NAME)
    else:
        reject("bootstrap não pertence ao publisher sucessor")
    expected_used_value = dict(intent)
    expected_used_value["phase"] = "used"
    expected_used = canonical_bytes(expected_used_value)
    if validate_partial_publisher_record(
        staging,
        f"{PUBLISHER_USED_NAME}.installing",
        expected_used,
        uid=uid,
        gid=gid,
    ):
        if (
            final_digest != successor_new
            or not previous_valid
            or candidate is not None
            or used_raw is not None
        ):
            reject("publisher used parcial está fora de estágio")
        allowed.add(f"{PUBLISHER_USED_NAME}.installing")
    if used_raw is not None:
        used = validate_publisher_upgrade_record(
            used_raw,
            phase="used",
            label="publisher used sucessor",
        )
        if (
            used != expected_used_value
            or final_digest != successor_new
            or not previous_valid
            or candidate is not None
        ):
            reject("publisher used sucessor não está íntegro")
        allowed.add(PUBLISHER_USED_NAME)
    if f"{PUBLISHER_INTENT_NAME}.installing" in os.listdir(staging):
        reject("publisher intent parcial coexiste com intent final")
    return allowed, final_digest


def validate_partial_source_record(
    state_descriptor: int,
    name: str,
    expected: bytes,
    *,
    uid: int,
    gid: int,
) -> None:
    """Valida um journal parcial sem completá-lo nem removê-lo."""

    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=state_descriptor,
    )
    try:
        info = os.fstat(descriptor)
        validate_regular(
            info,
            name,
            uid=uid,
            gid=gid,
            modes={0o600, 0o444},
            maximum=len(expected),
            allow_empty=True,
        )
        observed = (
            read_all(
                descriptor,
                info,
                maximum=len(expected),
                label=name,
            )
            if info.st_size
            else b""
        )
    finally:
        os.close(descriptor)
    if not expected.startswith(observed):
        reject(f"{name} não é prefixo do journal sucessor")
    if stat.S_IMODE(info.st_mode) == 0o444 and observed != expected:
        reject(f"{name} imutável está incompleto")


def _validate_post_recovery_source_before_supersede(
    state_descriptor: int,
    recovery: PostPublisherRecovery,
    *,
    observed_source_digest: str,
    uid: int,
    gid: int,
) -> None:
    predecessor = recovery.predecessor
    if observed_source_digest != predecessor.new_digest:
        reject("source mudou antes do supersede post-publisher")
    _validate_predecessor_rollback(
        state_descriptor,
        predecessor,
        uid=uid,
        gid=gid,
    )
    for phase in SOURCE_PHASE_NAMES:
        active = read_record_if_present(
            state_descriptor,
            SOURCE_PHASE_NAMES[phase],
            uid=uid,
            gid=gid,
        )
        archived = read_record_if_present(
            state_descriptor,
            predecessor.archived_name(phase),
            uid=uid,
            gid=gid,
        )
        if active != _expected_source_phase(predecessor, phase):
            reject(f"source predecessor perdeu a fase {phase}")
        if archived is not None:
            reject(f"source predecessor arquivou {phase} cedo demais")


def _open_post_publisher_staging(
    *,
    uid: int,
    gid: int,
) -> tuple[int, int]:
    control = open_path_chain(
        CONTROL_ROOT,
        uid=uid,
        gid=gid,
        final_modes={0o711},
    )
    staging = _open_named_directory(
        control,
        ".staging",
        uid=uid,
        gid=gid,
        modes={0o700},
    )
    if staging is None:
        os.close(control)
        reject("staging publisher sumiu no recovery post-publisher")
    return control, staging


def validate_existing_post_publisher_recovery(
    state_descriptor: int,
    recovery: PostPublisherRecovery,
    *,
    observed_source_digest: str,
    uid: int,
    gid: int,
) -> str:
    staged_bundle_archived = validate_post_publisher_pre_stage(
        state_descriptor,
        recovery=recovery,
        uid=uid,
        gid=gid,
    )
    source_used_archived = _validate_post_source_used_evidence(
        state_descriptor,
        recovery,
        uid=uid,
        gid=gid,
    )
    control, staging = _open_post_publisher_staging(
        uid=uid,
        gid=gid,
    )
    try:
        nested_publisher_allowed: set[str] = set()
        nested_history: NestedSupersedeHistory | None = None
        if recovery.nested_source_supersede_sha256 is not None:
            publisher_intent_value = {
                "new_tree_sha256": recovery.publisher_new_digest,
                "old_tree_sha256": recovery.publisher_old_digest,
                "phase": "intent",
                "previous_name": recovery.publisher_previous_name,
                "schema_version": 1,
            }
            publisher_used_value = dict(publisher_intent_value)
            publisher_used_value["phase"] = "used"
            (
                nested_history,
                _nested_source_allowed,
                nested_publisher_allowed,
            ) = validate_nested_supersede_history(
                state_descriptor,
                staging,
                current_source=recovery.predecessor,
                current_publisher=PublisherUpgradeTransaction(
                    old_digest=recovery.publisher_old_digest,
                    new_digest=recovery.publisher_new_digest,
                    previous_name=recovery.publisher_previous_name,
                    intent_raw=canonical_bytes(
                        publisher_intent_value
                    ),
                    used_raw=canonical_bytes(publisher_used_value),
                ),
                expected_source_supersede_sha256=(
                    recovery.nested_source_supersede_sha256
                ),
                expected_publisher_supersede_sha256=(
                    recovery.nested_publisher_supersede_sha256
                ),
                uid=uid,
                gid=gid,
            )
            if nested_history is None:
                reject("histórico aninhado sumiu durante recovery")
        else:
            for parent in (state_descriptor, staging):
                if any(
                    name.startswith(
                        NESTED_POST_PUBLISHER_ARCHIVE_PREFIX
                    )
                    for name in os.listdir(parent)
                ):
                    reject("recovery sem binding contém histórico aninhado")
        publisher_archived = _publisher_archive_status(
            staging,
            recovery,
            uid=uid,
            gid=gid,
        )
        archive_steps = (
            (
                (staged_bundle_archived,)
                if recovery.staged_bundle_id is not None
                else ()
            )
            + (source_used_archived, *publisher_archived)
        )
        archive_count = sum(archive_steps)
        if archive_steps != (True,) * archive_count + (False,) * (
            len(archive_steps) - archive_count
        ):
            reject("recovery post-publisher não forma prefixo transacional")
        all_archived = all(archive_steps)
        nested_archive_started = (
            nested_history is not None
            and any(nested_history.archive_statuses)
        )
        nested_all_archived = (
            nested_history is None
            or all(nested_history.archive_statuses)
        )
        if nested_archive_started and not all_archived:
            reject(
                "histórico aninhado começou antes dos arquivos atuais"
            )

        standard_raw = read_record_if_present(
            state_descriptor,
            SUPERSEDE_NAME,
            uid=uid,
            gid=gid,
        )
        nested_standard_occupies_name = (
            standard_raw is not None
            and recovery.nested_source_supersede_sha256 is not None
            and hashlib.sha256(standard_raw).hexdigest()
            == recovery.nested_source_supersede_sha256
        )
        if nested_standard_occupies_name:
            standard_raw = None
        expected_standard = source_supersede_payload(
            recovery.predecessor,
            successor_kit_id=recovery.successor_kit_id,
            successor_new_digest=recovery.successor_new_digest,
        )
        standard_partial_name = (
            f"bootstrap-source-kit.supersede."
            f"{recovery.successor_kit_id}.installing"
        )
        standard_partial = False
        if standard_raw is not None:
            if standard_raw != expected_standard:
                reject("source supersede padrão diverge do recovery")
        else:
            try:
                os.stat(
                    standard_partial_name,
                    dir_fd=state_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                validate_partial_source_record(
                    state_descriptor,
                    standard_partial_name,
                    expected_standard,
                    uid=uid,
                    gid=gid,
                )
                standard_partial = True
        if (standard_raw is not None or standard_partial) and not all_archived:
            reject("source supersede começou antes dos arquivos predecessor")
        if (
            standard_raw is not None or standard_partial
        ) and not nested_all_archived:
            reject(
                "source supersede começou antes do histórico aninhado"
            )
        if standard_raw is None:
            _validate_post_recovery_source_before_supersede(
                state_descriptor,
                recovery,
                observed_source_digest=observed_source_digest,
                uid=uid,
                gid=gid,
            )

        successor_retained = marker_payload(
            kit_id=recovery.successor_kit_id,
            phase="retained",
            old_digest=recovery.predecessor.new_digest,
            new_digest=recovery.successor_new_digest,
        )
        successor_used = marker_payload(
            kit_id=recovery.successor_kit_id,
            phase="used",
            old_digest=recovery.predecessor.new_digest,
            new_digest=recovery.successor_new_digest,
        )
        allow_successor_publisher = (
            standard_raw is not None
            and (
                read_record_if_present(
                    state_descriptor,
                    RETAINED_NAME,
                    uid=uid,
                    gid=gid,
                )
                == successor_retained
                or read_record_if_present(
                    state_descriptor,
                    USED_NAME,
                    uid=uid,
                    gid=gid,
                )
                == successor_used
            )
        )
        allowed_staging = {
            post_publisher_archive_name(
                kind,
                recovery.predecessor.kit_id,
            )
            for kind, archived in zip(
                ("used", "intent", "previous"),
                publisher_archived,
                strict=True,
            )
            if archived
        }
        if (
            recovery.staged_bundle_id is not None
            and staged_bundle_archived
        ):
            allowed_staging.add(
                post_stage_bundle_archive_name(
                    recovery.staged_bundle_id
                )
            )
        allowed_staging.update(nested_publisher_allowed)
        for kind, active_name, archived in (
            ("used", PUBLISHER_USED_NAME, publisher_archived[0]),
            ("intent", PUBLISHER_INTENT_NAME, publisher_archived[1]),
            (
                "previous",
                recovery.publisher_previous_name,
                publisher_archived[2],
            ),
        ):
            if not archived:
                allowed_staging.add(active_name)
        if all(publisher_archived):
            successor_staging, current_bootstrap_digest = (
                _validate_successor_publisher_state(
                    control,
                    staging,
                    recovery,
                    allow_successor=allow_successor_publisher,
                    uid=uid,
                    gid=gid,
                )
            )
            allowed_staging.update(successor_staging)
        else:
            final = _open_named_directory(
                control,
                "bootstrap",
                uid=uid,
                gid=gid,
                modes={0o555},
            )
            if final is None:
                reject("bootstrap predecessor sumiu durante os arquivos")
            try:
                current_bootstrap_digest = (
                    protected_bootstrap_tree_digest(
                        final,
                        uid=uid,
                        gid=gid,
                    )
                )
                if current_bootstrap_digest != recovery.publisher_new_digest:
                    reject("bootstrap mudou durante os arquivos predecessor")
            finally:
                os.close(final)
        if set(os.listdir(staging)) != allowed_staging:
            reject("namespace publisher post-publisher contém estado estranho")
        return current_bootstrap_digest
    finally:
        os.close(staging)
        os.close(control)


def prepare_post_publisher_recovery(
    state_descriptor: int,
    *,
    observed_source_digest: str,
    binding: AttestationBinding,
    successor_kit_id: str,
    successor_new_digest: str,
    expectations: BootstrapExpectations,
    uid: int,
    gid: int,
) -> tuple[PostPublisherRecovery, str]:
    raw = read_record_if_present(
        state_descriptor,
        POST_PUBLISHER_SUPERSEDE_NAME,
        uid=uid,
        gid=gid,
    )
    if raw is None:
        recovery = build_initial_post_publisher_recovery(
            state_descriptor,
            observed_source_digest=observed_source_digest,
            binding=binding,
            successor_kit_id=successor_kit_id,
            successor_new_digest=successor_new_digest,
            expectations=expectations,
            uid=uid,
            gid=gid,
        )
        partial_name = (
            "bootstrap-source-kit.post-publisher-supersede."
            f"{successor_kit_id}.installing"
        )
        try:
            os.stat(
                partial_name,
                dir_fd=state_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            validate_partial_source_record(
                state_descriptor,
                partial_name,
                post_publisher_supersede_payload(recovery),
                uid=uid,
                gid=gid,
            )
        return recovery, recovery.publisher_new_digest
    recovery = _post_publisher_recovery_from_record(
        state_descriptor,
        raw,
        binding=binding,
        successor_kit_id=successor_kit_id,
        successor_new_digest=successor_new_digest,
        expectations=expectations,
        uid=uid,
        gid=gid,
    )
    current_bootstrap_digest = validate_existing_post_publisher_recovery(
        state_descriptor,
        recovery,
        observed_source_digest=observed_source_digest,
        uid=uid,
        gid=gid,
    )
    return recovery, current_bootstrap_digest


def _archive_publisher_record(
    staging: int,
    *,
    source_name: str,
    archived_name: str,
    expected: bytes,
    uid: int,
    gid: int,
    runtime: Runtime,
) -> None:
    active = read_publisher_record_if_present(
        staging,
        source_name,
        uid=uid,
        gid=gid,
    )
    archived = read_publisher_record_if_present(
        staging,
        archived_name,
        uid=uid,
        gid=gid,
    )
    if archived is not None:
        if archived != expected or active == expected:
            reject(f"arquivo publisher diverge: {archived_name}")
        return
    if active != expected:
        reject(f"publisher predecessor não recuperável: {source_name}")
    runtime.noreplace(
        staging,
        source_name,
        staging,
        archived_name,
    )
    os.fsync(staging)
    if (
        read_publisher_record_if_present(
            staging,
            archived_name,
            uid=uid,
            gid=gid,
        )
        != expected
    ):
        reject(f"publisher predecessor não foi arquivado: {source_name}")


def _archive_publisher_previous(
    staging: int,
    recovery: PostPublisherRecovery,
    *,
    uid: int,
    gid: int,
    runtime: Runtime,
) -> None:
    source_name = recovery.publisher_previous_name
    archived_name = post_publisher_archive_name(
        "previous",
        recovery.predecessor.kit_id,
    )
    active = _open_named_directory(
        staging,
        source_name,
        uid=uid,
        gid=gid,
        modes={0o555},
    )
    archived = _open_named_directory(
        staging,
        archived_name,
        uid=uid,
        gid=gid,
        modes={0o555},
    )
    if archived is not None:
        try:
            if (
                protected_bootstrap_tree_digest(
                    archived,
                    uid=uid,
                    gid=gid,
                )
                != recovery.publisher_old_digest
                or active is not None
            ):
                reject("rollback publisher arquivado diverge")
        finally:
            os.close(archived)
            if active is not None:
                os.close(active)
        return
    if active is None:
        reject("rollback publisher predecessor está ausente")
    try:
        if (
            protected_bootstrap_tree_digest(
                active,
                uid=uid,
                gid=gid,
            )
            != recovery.publisher_old_digest
        ):
            reject("rollback publisher predecessor diverge")
    finally:
        os.close(active)
    runtime.noreplace(
        staging,
        source_name,
        staging,
        archived_name,
    )
    os.fsync(staging)


def _archive_nested_record(
    parent: int,
    *,
    active_name: str,
    archived_name: str,
    expected: bytes,
    publisher: bool,
    uid: int,
    gid: int,
    runtime: Runtime,
) -> None:
    archived, _allowed = _nested_record(
        parent,
        active_name=active_name,
        archived_name=archived_name,
        expected=expected,
        publisher=publisher,
        uid=uid,
        gid=gid,
    )
    if archived:
        return
    runtime.noreplace(
        parent,
        active_name,
        parent,
        archived_name,
    )
    os.fsync(parent)
    archived, _allowed = _nested_record(
        parent,
        active_name=active_name,
        archived_name=archived_name,
        expected=expected,
        publisher=publisher,
        uid=uid,
        gid=gid,
    )
    if not archived:
        reject(f"histórico aninhado não foi arquivado: {active_name}")


def _archive_nested_source_supersede(
    state_descriptor: int,
    *,
    archived_name: str,
    expected: bytes,
    uid: int,
    gid: int,
    runtime: Runtime,
) -> None:
    active = read_record_if_present(
        state_descriptor,
        SUPERSEDE_NAME,
        uid=uid,
        gid=gid,
    )
    archived = read_record_if_present(
        state_descriptor,
        archived_name,
        uid=uid,
        gid=gid,
    )
    if archived is not None:
        if archived != expected or active == expected:
            reject("source supersede aninhado arquivado diverge")
        return
    if active != expected:
        reject("source supersede aninhado não está recuperável")
    runtime.noreplace(
        state_descriptor,
        SUPERSEDE_NAME,
        state_descriptor,
        archived_name,
    )
    os.fsync(state_descriptor)
    if (
        read_record_if_present(
            state_descriptor,
            archived_name,
            uid=uid,
            gid=gid,
        )
        != expected
    ):
        reject("source supersede aninhado não foi arquivado")


def _archive_nested_tree(
    parent: int,
    *,
    active_name: str,
    archived_name: str,
    expected_digest: str,
    publisher: bool,
    uid: int,
    gid: int,
    runtime: Runtime,
) -> None:
    archived, _allowed = _nested_tree(
        parent,
        active_name=active_name,
        archived_name=archived_name,
        expected_digest=expected_digest,
        publisher=publisher,
        uid=uid,
        gid=gid,
    )
    if archived:
        return
    runtime.noreplace(
        parent,
        active_name,
        parent,
        archived_name,
    )
    os.fsync(parent)
    archived, _allowed = _nested_tree(
        parent,
        active_name=active_name,
        archived_name=archived_name,
        expected_digest=expected_digest,
        publisher=publisher,
        uid=uid,
        gid=gid,
    )
    if not archived:
        reject(f"histórico aninhado não foi arquivado: {active_name}")


def archive_nested_supersede_history(
    state_descriptor: int,
    recovery: PostPublisherRecovery,
    *,
    uid: int,
    gid: int,
    runtime: Runtime,
    fault: Callable[[str], None],
) -> None:
    history = recovery.nested_history
    if history is None:
        return
    current_kit_id = recovery.predecessor.kit_id
    source_predecessor = history.source_predecessor
    _archive_nested_source_supersede(
        state_descriptor,
        archived_name=nested_source_archive_name(
            "supersede",
            current_kit_id,
        ),
        expected=history.source_supersede_raw,
        uid=uid,
        gid=gid,
        runtime=runtime,
    )
    fault("after_nested_source_supersede_archive")
    for phase in ("intent", "prepared", "exchanged", "retained"):
        _archive_nested_record(
            state_descriptor,
            active_name=source_predecessor.archived_name(phase),
            archived_name=nested_source_archive_name(
                phase,
                current_kit_id,
            ),
            expected=_expected_source_phase(
                source_predecessor,
                phase,
            ),
            publisher=False,
            uid=uid,
            gid=gid,
            runtime=runtime,
        )
        fault(f"after_nested_source_{phase}_archive")
    _archive_nested_tree(
        state_descriptor,
        active_name=f"{PREVIOUS_PREFIX}{source_predecessor.kit_id}",
        archived_name=nested_source_archive_name(
            "previous",
            current_kit_id,
        ),
        expected_digest=source_predecessor.old_digest,
        publisher=False,
        uid=uid,
        gid=gid,
        runtime=runtime,
    )
    fault("after_nested_source_previous_archive")

    control, staging = _open_post_publisher_staging(
        uid=uid,
        gid=gid,
    )
    try:
        _archive_nested_record(
            staging,
            active_name=PUBLISHER_SUPERSEDE_NAME,
            archived_name=nested_publisher_archive_name(
                "supersede",
                current_kit_id,
            ),
            expected=history.publisher_supersede_raw,
            publisher=True,
            uid=uid,
            gid=gid,
            runtime=runtime,
        )
        fault("after_nested_publisher_supersede_archive")
        _archive_nested_tree(
            staging,
            active_name=history.publisher_retained_candidate_name,
            archived_name=nested_publisher_archive_name(
                "candidate",
                current_kit_id,
            ),
            expected_digest=history.publisher_predecessor_new_digest,
            publisher=True,
            uid=uid,
            gid=gid,
            runtime=runtime,
        )
        fault("after_nested_publisher_candidate_archive")
        _archive_nested_record(
            staging,
            active_name=history.publisher_retained_intent_name,
            archived_name=nested_publisher_archive_name(
                "intent",
                current_kit_id,
            ),
            expected=history.publisher_predecessor_intent_raw,
            publisher=True,
            uid=uid,
            gid=gid,
            runtime=runtime,
        )
        fault("after_nested_publisher_intent_archive")
    finally:
        os.close(staging)
        os.close(control)


def archive_post_stage_bundle(
    state_descriptor: int,
    recovery: PostPublisherRecovery,
    *,
    uid: int,
    gid: int,
    runtime: Runtime,
) -> None:
    if recovery.staged_bundle_id is None:
        return
    if recovery.staged_bundle_tree_sha256 is None:
        reject("recovery post-stage perdeu o hash da árvore")
    if validate_post_publisher_pre_stage(
        state_descriptor,
        recovery=recovery,
        uid=uid,
        gid=gid,
    ):
        return
    control = open_path_chain(
        CONTROL_ROOT,
        uid=uid,
        gid=gid,
        final_modes={0o711},
    )
    bundles: int | None = None
    staging: int | None = None
    try:
        bundles = _open_named_directory(
            control,
            BUNDLES_NAME,
            uid=uid,
            gid=gid,
            modes={0o711},
        )
        staging = _open_named_directory(
            control,
            ".staging",
            uid=uid,
            gid=gid,
            modes={0o700},
        )
        if bundles is None or staging is None:
            reject("raízes do bundle post-stage estão ausentes")
        require_same_mount(
            bundles,
            staging,
            "quarentena do bundle post-stage",
        )
        bundle = _open_named_directory(
            bundles,
            recovery.staged_bundle_id,
            uid=uid,
            gid=gid,
            modes={0o555},
        )
        if bundle is None:
            reject("bundle post-stage sumiu antes da quarentena")
        try:
            validated_info = os.fstat(bundle)
            validate_staged_bundle_attestation(
                bundle,
                bundle_id=recovery.staged_bundle_id,
                uid=uid,
                gid=gid,
            )
            if (
                staged_bundle_tree_digest(bundle, uid=uid)
                != recovery.staged_bundle_tree_sha256
            ):
                reject("bundle post-stage mudou antes da quarentena")
            archive_name = post_stage_bundle_archive_name(
                recovery.staged_bundle_id
            )
            try:
                runtime.noreplace(
                    bundles,
                    recovery.staged_bundle_id,
                    staging,
                    archive_name,
                )
            except FileExistsError:
                reject("quarentena post-stage concorrente foi recusada")
            archived = _open_named_directory(
                staging,
                archive_name,
                uid=uid,
                gid=gid,
                modes={0o555},
            )
            if archived is None:
                reject("quarentena post-stage não foi publicada")
            try:
                archived_info = os.fstat(archived)
                stable_identity = (
                    "st_dev",
                    "st_ino",
                    "st_mode",
                    "st_uid",
                    "st_gid",
                    "st_size",
                )
                if any(
                    getattr(validated_info, field)
                    != getattr(archived_info, field)
                    for field in stable_identity
                ):
                    reject(
                        "inode post-stage trocado durante a quarentena"
                    )
                if (
                    staged_bundle_tree_digest(archived, uid=uid)
                    != recovery.staged_bundle_tree_sha256
                ):
                    reject(
                        "bundle post-stage mudou durante a quarentena"
                    )
            finally:
                os.close(archived)
            os.fsync(bundles)
            os.fsync(staging)
        finally:
            os.close(bundle)
    finally:
        if staging is not None:
            os.close(staging)
        if bundles is not None:
            os.close(bundles)
        os.close(control)
    if not validate_post_publisher_pre_stage(
        state_descriptor,
        recovery=recovery,
        uid=uid,
        gid=gid,
    ):
        reject("bundle post-stage não convergiu para a quarentena")


def reconcile_post_publisher_prelude(
    state_descriptor: int,
    recovery: PostPublisherRecovery,
    *,
    observed_source_digest: str,
    uid: int,
    gid: int,
    runtime: Runtime,
    fault: Callable[[str], None],
) -> SupersededSourceTransaction:
    publish_record(
        state_descriptor,
        POST_PUBLISHER_SUPERSEDE_NAME,
        post_publisher_supersede_payload(recovery),
        kit_id=recovery.successor_kit_id,
        uid=uid,
        gid=gid,
        runtime=runtime,
    )
    fault("after_post_publisher_supersede")
    validate_existing_post_publisher_recovery(
        state_descriptor,
        recovery,
        observed_source_digest=observed_source_digest,
        uid=uid,
        gid=gid,
    )
    archive_post_stage_bundle(
        state_descriptor,
        recovery,
        uid=uid,
        gid=gid,
        runtime=runtime,
    )
    if recovery.staged_bundle_id is not None:
        fault("after_post_publisher_staged_bundle_archive")
    validate_existing_post_publisher_recovery(
        state_descriptor,
        recovery,
        observed_source_digest=observed_source_digest,
        uid=uid,
        gid=gid,
    )
    _archive_source_record(
        state_descriptor,
        recovery.predecessor,
        "used",
        uid=uid,
        gid=gid,
        runtime=runtime,
    )
    fault("after_post_publisher_source_used_archive")
    control, staging = _open_post_publisher_staging(
        uid=uid,
        gid=gid,
    )
    try:
        intent_value = {
            "new_tree_sha256": recovery.publisher_new_digest,
            "old_tree_sha256": recovery.publisher_old_digest,
            "phase": "intent",
            "previous_name": recovery.publisher_previous_name,
            "schema_version": 1,
        }
        used_value = dict(intent_value)
        used_value["phase"] = "used"
        _archive_publisher_record(
            staging,
            source_name=PUBLISHER_USED_NAME,
            archived_name=post_publisher_archive_name(
                "used",
                recovery.predecessor.kit_id,
            ),
            expected=canonical_bytes(used_value),
            uid=uid,
            gid=gid,
            runtime=runtime,
        )
        fault("after_post_publisher_used_archive")
        _archive_publisher_record(
            staging,
            source_name=PUBLISHER_INTENT_NAME,
            archived_name=post_publisher_archive_name(
                "intent",
                recovery.predecessor.kit_id,
            ),
            expected=canonical_bytes(intent_value),
            uid=uid,
            gid=gid,
            runtime=runtime,
        )
        fault("after_post_publisher_intent_archive")
        _archive_publisher_previous(
            staging,
            recovery,
            uid=uid,
            gid=gid,
            runtime=runtime,
        )
        fault("after_post_publisher_previous_archive")
    finally:
        os.close(staging)
        os.close(control)
    archive_nested_supersede_history(
        state_descriptor,
        recovery,
        uid=uid,
        gid=gid,
        runtime=runtime,
        fault=fault,
    )
    publish_record(
        state_descriptor,
        SUPERSEDE_NAME,
        source_supersede_payload(
            recovery.predecessor,
            successor_kit_id=recovery.successor_kit_id,
            successor_new_digest=recovery.successor_new_digest,
        ),
        kit_id=recovery.successor_kit_id,
        uid=uid,
        gid=gid,
        runtime=runtime,
    )
    fault("after_post_publisher_standard_supersede")
    return recovery.predecessor


def validate_reserved_source_namespace(
    state_descriptor: int,
    *,
    binding: AttestationBinding,
    inventory: ArchiveInventory,
    successor_kit_id: str,
    successor_new_digest: str,
    observed_source_digest: str,
    predecessor_expected: bool,
    post_recovery: PostPublisherRecovery | None = None,
    uid: int,
    gid: int,
) -> None:
    allowed = {
        INTENT_NAME,
        PREPARED_NAME,
        EXCHANGED_NAME,
        RETAINED_NAME,
        USED_NAME,
        SUPERSEDE_NAME,
    }
    if post_recovery is not None:
        allowed.add(POST_PUBLISHER_SUPERSEDE_NAME)
        allowed.add(
            post_recovery.predecessor.archived_name("used")
        )
    supersede_raw = read_record_if_present(
        state_descriptor,
        SUPERSEDE_NAME,
        uid=uid,
        gid=gid,
    )
    predecessor: SupersededSourceTransaction | None = None
    if supersede_raw is not None:
        predecessor = validate_source_supersede(
            supersede_raw,
            successor_kit_id=successor_kit_id,
            successor_new_digest=successor_new_digest,
        )
        allowed.update(
            predecessor.archived_name(phase)
            for phase in SOURCE_PHASE_NAMES
        )

    intent_raw = read_record_if_present(
        state_descriptor,
        INTENT_NAME,
        uid=uid,
        gid=gid,
    )
    intent = (
        validate_source_intent(
            intent_raw,
            allow_noop=not predecessor_expected,
        )
        if intent_raw is not None
        else None
    )
    active_records = {
        phase: (
            intent_raw
            if phase == "intent"
            else read_record_if_present(
                state_descriptor,
                SOURCE_PHASE_NAMES[phase],
                uid=uid,
                gid=gid,
            )
        )
        for phase in SOURCE_PHASE_NAMES
    }
    all_predecessor_archived = False
    if predecessor is not None:
        archived_records = {
            phase: read_record_if_present(
                state_descriptor,
                predecessor.archived_name(phase),
                uid=uid,
                gid=gid,
            )
            for phase in SOURCE_PHASE_NAMES
        }
        predecessor_intent_raw = (
            archived_records["intent"]
            if archived_records["intent"] is not None
            else intent_raw
        )
        if predecessor_intent_raw is None:
            reject("intent predecessor não está recuperável no preflight")
        parsed_predecessor = validate_source_intent(
            predecessor_intent_raw
        )
        supersede_value = parse_canonical_json(
            supersede_raw,
            "bootstrap source supersede",
        )
        if (
            parsed_predecessor.kit_id != predecessor.kit_id
            or parsed_predecessor.api_sha != predecessor.api_sha
            or parsed_predecessor.controller_sha
            != predecessor.controller_sha
            or parsed_predecessor.old_digest != predecessor.old_digest
            or parsed_predecessor.new_digest != predecessor.new_digest
            or hashlib.sha256(predecessor_intent_raw).hexdigest()
            != supersede_value["predecessor_intent_sha256"]
        ):
            reject("intent predecessor diverge no preflight source")
        predecessor = SupersededSourceTransaction(
            kit_id=predecessor.kit_id,
            api_sha=predecessor.api_sha,
            controller_sha=predecessor.controller_sha,
            old_digest=predecessor.old_digest,
            new_digest=predecessor.new_digest,
            intent_raw=predecessor_intent_raw,
            publisher_intent_sha256=(
                predecessor.publisher_intent_sha256
            ),
            publisher_authorization_required=(
                post_recovery is None
            ),
        )
        if post_recovery is not None and (
            predecessor.kit_id
            != post_recovery.predecessor.kit_id
            or predecessor.publisher_intent_sha256
            != post_recovery.publisher_intent_sha256
        ):
            reject("source supersede diverge do recovery post-publisher")
        for phase in SOURCE_PHASE_NAMES:
            archived = archived_records[phase]
            if (
                archived is not None
                and archived != _expected_source_phase(
                    predecessor,
                    phase,
                )
            ):
                reject(f"histórico predecessor diverge: {phase}")
        archived_presence = tuple(
            archived_records[phase] is not None
            for phase in SOURCE_PHASE_NAMES
        )
        archived_count = sum(archived_presence)
        if archived_presence != (
            (True,) * archived_count
            + (False,) * (len(SOURCE_PHASE_NAMES) - archived_count)
        ):
            reject("histórico predecessor não forma prefixo transacional")
        all_predecessor_archived = all(
            raw is not None for raw in archived_records.values()
        )
        if all_predecessor_archived:
            successor_intent = intent_payload(
                binding,
                inventory,
                successor_kit_id,
                predecessor.new_digest,
            )
            for phase, active in active_records.items():
                expected_successor = (
                    successor_intent
                    if phase == "intent"
                    else marker_payload(
                        kit_id=successor_kit_id,
                        phase=phase,
                        old_digest=predecessor.new_digest,
                        new_digest=successor_new_digest,
                    )
                )
                if active is not None and active != expected_successor:
                    reject(f"fase ativa sucessora diverge: {phase}")
        else:
            for phase, active in active_records.items():
                archived = archived_records[phase]
                if archived is None:
                    if active != _expected_source_phase(
                        predecessor,
                        phase,
                    ):
                        reject(
                            f"fase predecessor não recuperável: {phase}"
                        )
                elif active is not None:
                    reject(
                        f"fase predecessor coexiste com arquivo: {phase}"
                    )
    used_raw = read_record_if_present(
        state_descriptor,
        USED_NAME,
        uid=uid,
        gid=gid,
    )
    if used_raw is not None and predecessor_expected and predecessor is None:
        reject("source predecessor já foi marcado como usado")
    predecessor_kit_id = (
        predecessor.kit_id
        if predecessor is not None
        else (
            intent.kit_id
            if predecessor_expected
            and intent is not None
            and intent.kit_id != successor_kit_id
            else None
        )
    )
    if predecessor_kit_id is not None:
        allowed.add(f"{PREVIOUS_PREFIX}{predecessor_kit_id}")

    successor_stage = (
        not predecessor_expected
        or predecessor is not None
        and all_predecessor_archived
    )
    successor_old_digest = (
        predecessor.new_digest
        if predecessor is not None
        else (
            intent.old_digest
            if intent is not None and intent.kit_id == successor_kit_id
            else observed_source_digest
        )
    )
    successor_intent_raw = intent_payload(
        binding,
        inventory,
        successor_kit_id,
        successor_old_digest,
    )
    expected_successor_records = {
        "intent": successor_intent_raw,
        **{
            phase: marker_payload(
                kit_id=successor_kit_id,
                phase=phase,
                old_digest=successor_old_digest,
                new_digest=successor_new_digest,
            )
            for phase in ("prepared", "exchanged", "retained", "used")
        },
    }
    successor_is_noop = (
        successor_stage
        and successor_old_digest == successor_new_digest
    )
    if successor_is_noop and predecessor_expected:
        reject("sucessão com predecessor não pode ser no-op")
    if used_raw is not None and predecessor_expected and not successor_stage:
        reject("used source predecessor não pode ser superado")
    if successor_stage:
        for phase, raw in active_records.items():
            if raw is not None and raw != expected_successor_records[phase]:
                reject(f"fase ativa sucessora diverge: {phase}")
        if used_raw is not None and used_raw != expected_successor_records["used"]:
            reject("used source não pertence ao sucessor íntegro")

    names = os.listdir(state_descriptor)
    successor_partials: set[str] = set()
    for name in names:
        temporary = STATE_TEMP_RE.fullmatch(name)
        if (
            temporary is None
            or temporary.group(2) != successor_kit_id
            or temporary.group(1) in {
                "supersede",
                "post-publisher-supersede",
            }
        ):
            continue
        phase = temporary.group(1)
        if not successor_stage:
            reject("journal parcial sucessor existe antes do seu estágio")
        validate_partial_source_record(
            state_descriptor,
            name,
            expected_successor_records[phase],
            uid=uid,
            gid=gid,
        )
        successor_partials.add(phase)

    present = {
        phase: active_records[phase] is not None
        for phase in SOURCE_PHASE_NAMES
    }
    present["used"] = used_raw is not None
    for phase in successor_partials:
        if present[phase]:
            reject(f"fase sucessora {phase} coexiste com record parcial")
    if successor_stage:
        ordered = (
            ("intent", "retained", "used")
            if successor_is_noop
            else ("intent", "prepared", "exchanged", "retained", "used")
        )
        for index, phase in enumerate(ordered[1:], start=1):
            if present[phase] and not all(
                present[prior] for prior in ordered[:index]
            ):
                reject(f"fase sucessora {phase} está fora de ordem")
        if successor_is_noop and (
            present["prepared"]
            or present["exchanged"]
            or "prepared" in successor_partials
            or "exchanged" in successor_partials
        ):
            reject("source kit no-op contém evidência de exchange")

    candidate_name = f"{CANDIDATE_PREFIX}{successor_kit_id}"
    previous_name = f"{PREVIOUS_PREFIX}{successor_kit_id}"
    final_is_successor = observed_source_digest == successor_new_digest
    candidate_exists = candidate_name in names
    candidate_is_complete_new = False
    candidate_is_complete_old = False
    if candidate_exists:
        if successor_is_noop:
            reject("source kit no-op contém candidate")
        candidate_has_intent = present["intent"] or (
            not predecessor_expected
            and "intent" in successor_partials
        )
        if not successor_stage or not candidate_has_intent:
            reject("candidate sucessor existe antes do intent ativo")
        candidate = _open_named_directory(
            state_descriptor,
            candidate_name,
            uid=uid,
            gid=gid,
            modes={0o555, 0o700},
        )
        if candidate is None:
            reject("candidate sucessor desapareceu durante o preflight")
        try:
            candidate_mode = stat.S_IMODE(os.fstat(candidate).st_mode)
            if candidate_mode == 0o555:
                candidate_entries = scan_tree(candidate, uid=uid, gid=gid)
                candidate_digest = tree_digest(candidate_entries)
                candidate_is_complete_new = (
                    candidate_entries == dict(inventory.entries)
                )
                candidate_is_complete_old = (
                    candidate_digest == successor_old_digest
                )
        finally:
            os.close(candidate)
        if final_is_successor:
            if not candidate_is_complete_old:
                reject("candidate pós-exchange não é a fonte anterior")
        elif candidate_mode == 0o555 and not candidate_is_complete_new:
            reject("candidate preparado diverge do kit sucessor")
        allowed.add(candidate_name)

    previous_exists = previous_name in names
    previous_is_valid = False
    if previous_exists:
        if successor_is_noop:
            reject("source kit no-op contém retenção anterior")
        if (
            not successor_stage
            or not final_is_successor
            or not present["exchanged"]
            or candidate_exists
        ):
            reject("retenção sucessora existe fora do estágio pós-exchange")
        previous = _open_named_directory(
            state_descriptor,
            previous_name,
            uid=uid,
            gid=gid,
            modes={0o555},
        )
        if previous is None:
            reject("retenção sucessora desapareceu durante o preflight")
        try:
            previous_is_valid = (
                tree_digest(scan_tree(previous, uid=uid, gid=gid))
                == successor_old_digest
            )
        finally:
            os.close(previous)
        if not previous_is_valid:
            reject("fonte bootstrap anterior retida diverge")
        allowed.add(previous_name)

    if successor_is_noop:
        if not final_is_successor:
            reject("fonte do source kit no-op diverge do kit")
        if "intent" in successor_partials and (
            any(present.values())
            or successor_partials != {"intent"}
        ):
            reject("intent parcial no-op está fora de estágio")
        if "retained" in successor_partials and (
            not present["intent"]
            or present["retained"]
            or present["used"]
            or successor_partials != {"retained"}
        ):
            reject("retained parcial no-op está fora de estágio")
        if "used" in successor_partials and (
            not present["intent"]
            or not present["retained"]
            or present["used"]
            or successor_partials != {"used"}
        ):
            reject("used parcial no-op está fora de estágio")
        if used_raw is not None and (
            not present["intent"]
            or not present["retained"]
        ):
            reject("used source no-op está fora de estágio")
    elif successor_stage:
        successor_artifact_exists = (
            any(present.values())
            or bool(successor_partials)
            or candidate_exists
            or previous_exists
        )
        if (
            not final_is_successor
            and present["prepared"]
            and not candidate_is_complete_new
        ):
            reject("prepared sucessor existe sem candidate íntegro")
        if (
            final_is_successor
            and successor_artifact_exists
            and (
                not present["intent"]
                or not present["prepared"]
                or (
                    successor_old_digest != successor_new_digest
                    and not candidate_is_complete_old
                    and not previous_is_valid
                )
            )
        ):
            reject("fonte sucessora está sem evidência recuperável da troca")
        if not final_is_successor and (
            present["exchanged"]
            or present["retained"]
            or present["used"]
            or "exchanged" in successor_partials
            or "retained" in successor_partials
            or "used" in successor_partials
        ):
            reject("fase pós-exchange existe antes da troca da fonte")
        if "prepared" in successor_partials and (
            not present["intent"]
            or not candidate_is_complete_new
            or final_is_successor
            or previous_exists
        ):
            reject("prepared parcial sucessor está fora de estágio")
        if "exchanged" in successor_partials and (
            not present["prepared"]
            or not final_is_successor
            or not candidate_is_complete_old
            or previous_exists
        ):
            reject("exchanged parcial sucessor está fora de estágio")
        if "retained" in successor_partials and (
            not present["exchanged"]
            or not final_is_successor
            or not previous_is_valid
            or candidate_exists
        ):
            reject("retained parcial sucessor está fora de estágio")
        if "used" in successor_partials and (
            not present["retained"]
            or not final_is_successor
            or not previous_is_valid
            or candidate_exists
        ):
            reject("used parcial sucessor está fora de estágio")
        if used_raw is not None and (
            not final_is_successor
            or not present["intent"]
            or not present["prepared"]
            or not present["exchanged"]
            or not present["retained"]
            or (
                successor_old_digest != successor_new_digest
                and not previous_is_valid
            )
            or candidate_exists
        ):
            reject("used source não pertence ao sucessor íntegro")

    for name in names:
        if not (
            name.startswith("bootstrap-source-kit.")
            or name.startswith(CANDIDATE_PREFIX)
            or name.startswith(PREVIOUS_PREFIX)
        ):
            continue
        if name in allowed:
            continue
        temporary = STATE_TEMP_RE.fullmatch(name)
        if (
            temporary is not None
            and temporary.group(2) == successor_kit_id
            and (
                (
                    temporary.group(1) == "supersede"
                    and supersede_raw is None
                    and predecessor_expected
                    and intent is not None
                    and intent.kit_id != successor_kit_id
                )
                or (
                    temporary.group(1) != "supersede"
                    and temporary.group(1) in successor_partials
                )
            )
        ):
            continue
        reject("namespace reservado do source kit contém journal estrangeiro")


def reconcile_superseded_source_transaction(
    state_descriptor: int,
    *,
    observed_source_digest: str,
    binding: AttestationBinding,
    inventory: ArchiveInventory,
    successor_kit_id: str,
    expectations: BootstrapExpectations,
    post_recovery: PostPublisherRecovery | None = None,
    uid: int,
    gid: int,
    runtime: Runtime,
    fault: Callable[[str], None],
) -> SupersededSourceTransaction | None:
    supersede_raw = read_record_if_present(
        state_descriptor,
        SUPERSEDE_NAME,
        uid=uid,
        gid=gid,
    )
    predecessor: SupersededSourceTransaction | None = None
    if supersede_raw is None:
        legacy_intent = read_record_if_present(
            state_descriptor,
            INTENT_NAME,
            uid=uid,
            gid=gid,
        )
        if legacy_intent is None:
            if expectations.predecessor_kit_id is not None:
                reject("predecessor esperado não está presente")
            return None
        if expectations.predecessor_kit_id is None:
            return None
        predecessor = validate_source_intent(legacy_intent)
        if (
            predecessor.kit_id != expectations.predecessor_kit_id
            or predecessor.controller_sha
            != expectations.predecessor_controller_sha
            or predecessor.api_sha not in binding.api_required_ancestors
            or predecessor.api_sha not in binding.ops_required_ancestors
        ):
            reject("aprovação sucessora não autoriza o predecessor")
        publisher_intent_sha256 = validate_fixed_predecessor_publisher_state(
            uid=uid,
            gid=gid,
        )
        if (
            publisher_intent_sha256
            != expectations.predecessor_publisher_intent_sha256
        ):
            reject("publisher intent predecessor diverge do binding externo")
        predecessor = SupersededSourceTransaction(
            kit_id=predecessor.kit_id,
            api_sha=predecessor.api_sha,
            controller_sha=predecessor.controller_sha,
            old_digest=predecessor.old_digest,
            new_digest=predecessor.new_digest,
            intent_raw=predecessor.intent_raw,
            publisher_intent_sha256=publisher_intent_sha256,
        )
        if (
            predecessor.kit_id == successor_kit_id
            or predecessor.new_digest == inventory.tree_sha256
            or observed_source_digest != predecessor.new_digest
        ):
            reject("source predecessor não está no estado pré-publisher")
        for phase in ("prepared", "exchanged", "retained"):
            observed = read_record_if_present(
                state_descriptor,
                SOURCE_PHASE_NAMES[phase],
                uid=uid,
                gid=gid,
            )
            if observed != _expected_source_phase(predecessor, phase):
                reject(f"fase predecessor ausente ou divergente: {phase}")
        if read_record_if_present(
            state_descriptor,
            USED_NAME,
            uid=uid,
            gid=gid,
        ) is not None:
            reject("source predecessor já foi marcado como usado")
        for name in os.listdir(state_descriptor):
            match = STATE_TEMP_RE.fullmatch(name)
            if match is not None and (
                match.group(1) != "supersede"
                or match.group(2) != successor_kit_id
            ):
                reject("source predecessor possui record parcial")
        _validate_predecessor_rollback(
            state_descriptor,
            predecessor,
            uid=uid,
            gid=gid,
        )
        supersede_raw = source_supersede_payload(
            predecessor,
            successor_kit_id=successor_kit_id,
            successor_new_digest=inventory.tree_sha256,
        )
        publish_record(
            state_descriptor,
            SUPERSEDE_NAME,
            supersede_raw,
            kit_id=successor_kit_id,
            uid=uid,
            gid=gid,
            runtime=runtime,
        )
        fault("after_source_supersede")
    else:
        predecessor = validate_source_supersede(
            supersede_raw,
            successor_kit_id=successor_kit_id,
            successor_new_digest=inventory.tree_sha256,
        )
        expected_predecessor_kit_id = (
            post_recovery.predecessor.kit_id
            if post_recovery is not None
            else expectations.predecessor_kit_id
        )
        expected_predecessor_controller_sha = (
            post_recovery.predecessor.controller_sha
            if post_recovery is not None
            else expectations.predecessor_controller_sha
        )
        expected_publisher_intent_sha256 = (
            post_recovery.publisher_intent_sha256
            if post_recovery is not None
            else expectations.predecessor_publisher_intent_sha256
        )
        if (
            expected_predecessor_kit_id != predecessor.kit_id
            or expected_predecessor_controller_sha
            != predecessor.controller_sha
            or expected_publisher_intent_sha256
            != predecessor.publisher_intent_sha256
            or predecessor.api_sha not in binding.api_required_ancestors
            or predecessor.api_sha not in binding.ops_required_ancestors
        ):
            reject("bindings sucessores divergem do source supersede")
        intent_raw = read_record_if_present(
            state_descriptor,
            predecessor.archived_name("intent"),
            uid=uid,
            gid=gid,
        )
        if intent_raw is None:
            intent_raw = read_record_if_present(
                state_descriptor,
                INTENT_NAME,
                uid=uid,
                gid=gid,
            )
        if intent_raw is None:
            reject("intent predecessor sumiu durante supersede")
        parsed = validate_source_intent(intent_raw)
        if (
            parsed.kit_id != predecessor.kit_id
            or parsed.api_sha != predecessor.api_sha
            or parsed.controller_sha != predecessor.controller_sha
            or parsed.old_digest != predecessor.old_digest
            or parsed.new_digest != predecessor.new_digest
            or hashlib.sha256(intent_raw).hexdigest()
            != parse_canonical_json(
                supersede_raw,
                "bootstrap source supersede",
            )["predecessor_intent_sha256"]
        ):
            reject("intent predecessor diverge do source supersede")
        predecessor = SupersededSourceTransaction(
            kit_id=parsed.kit_id,
            api_sha=parsed.api_sha,
            controller_sha=parsed.controller_sha,
            old_digest=parsed.old_digest,
            new_digest=parsed.new_digest,
            intent_raw=intent_raw,
            publisher_intent_sha256=(
                predecessor.publisher_intent_sha256
            ),
            publisher_authorization_required=(
                post_recovery is None
            ),
        )
        if (
            post_recovery is None
            and observed_source_digest == predecessor.new_digest
        ):
            revalidated_publisher_intent_sha256 = (
                validate_fixed_predecessor_publisher_state(
                    uid=uid,
                    gid=gid,
                )
            )
            if (
                revalidated_publisher_intent_sha256
                != predecessor.publisher_intent_sha256
            ):
                reject(
                    "publisher predecessor mudou durante source supersede"
                )
        elif post_recovery is not None and (
            predecessor.kit_id
            != post_recovery.predecessor.kit_id
            or predecessor.new_digest
            != post_recovery.predecessor.new_digest
            or predecessor.old_digest
            != post_recovery.predecessor.old_digest
        ):
            reject("predecessor padrão diverge do recovery post-publisher")

    assert predecessor is not None
    _validate_predecessor_rollback(
        state_descriptor,
        predecessor,
        uid=uid,
        gid=gid,
    )
    if observed_source_digest not in {
        predecessor.new_digest,
        inventory.tree_sha256,
    }:
        reject("árvore source não pertence à sucessão autorizada")
    for phase in ("intent", "prepared", "exchanged", "retained"):
        _archive_source_record(
            state_descriptor,
            predecessor,
            phase,
            uid=uid,
            gid=gid,
            runtime=runtime,
        )
        fault(f"after_source_supersede_{phase}")
    successor_intent_raw = read_record_if_present(
        state_descriptor,
        INTENT_NAME,
        uid=uid,
        gid=gid,
    )
    if successor_intent_raw is not None:
        successor_intent = validate_source_intent(successor_intent_raw)
        if (
            successor_intent.kit_id != successor_kit_id
            or successor_intent.old_digest != predecessor.new_digest
            or successor_intent.new_digest != inventory.tree_sha256
        ):
            reject("intent source sucessor diverge da cadeia autorizada")
    elif observed_source_digest == inventory.tree_sha256:
        reject("source sucessor publicado está sem intent recuperável")
    legacy_used = read_record_if_present(
        state_descriptor,
        USED_NAME,
        uid=uid,
        gid=gid,
    )
    if legacy_used is not None:
        parsed_used = parse_canonical_json(
            legacy_used,
            USED_NAME,
        )
        if parsed_used.get("kit_id") == predecessor.kit_id:
            reject("source predecessor usado não pode ser superado")
    return predecessor


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


def acquire_fixed_deploy_lock(
    *,
    uid: int,
    gid: int,
    lock_directory: Path = LOCK_DIRECTORY,
) -> int:
    directory = open_path_chain(
        lock_directory,
        uid=uid,
        gid=gid,
        final_modes={0o700},
    )
    try:
        descriptor = os.open(
            LOCK_NAME,
            os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory,
        )
    finally:
        os.close(directory)
    try:
        info = os.fstat(descriptor)
        validate_regular(
            info,
            "deploy.lock post-publisher",
            uid=uid,
            gid=gid,
            modes={0o600},
            maximum=1024,
            allow_empty=True,
        )
        try:
            fcntl.flock(
                descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError:
            reject("deploy.lock post-publisher já está ocupado")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def open_sealed_archive_member(
    archive_descriptor: int,
    archive_info: os.stat_result,
    inventory: ArchiveInventory,
    relative: str,
    *,
    expected_archive_sha256: str,
) -> int:
    require_hash(expected_archive_sha256, "hash do archive Ops")
    entry = inventory.entries.get(relative)
    if (
        entry is None
        or entry.kind != "file"
        or entry.mode != 0o555
        or not 0 < entry.size <= MAX_MEMBER_BYTES
    ):
        reject("verificador de quiescência não pertence ao inventário")
    if not hasattr(os, "memfd_create") or not all(
        hasattr(fcntl, name)
        for name in (
            "F_ADD_SEALS",
            "F_GET_SEALS",
            "F_SEAL_GROW",
            "F_SEAL_SEAL",
            "F_SEAL_SHRINK",
            "F_SEAL_WRITE",
        )
    ):
        reject("recovery post-publisher exige memfd selável no Linux")
    handle, archive = _tar_from_fd(archive_descriptor)
    try:
        try:
            member = archive.getmember(relative)
        except KeyError:
            reject("verificador de quiescência sumiu do archive")
        source = archive.extractfile(member)
        if source is None:
            reject("payload do verificador de quiescência está ausente")
        payload = source.read(entry.size + 1)
        if (
            len(payload) != entry.size
            or source.read(1)
            or hashlib.sha256(payload).hexdigest() != entry.sha256
        ):
            reject("bytes do verificador divergem do inventário assinado")
    finally:
        archive.close()
        handle.close()
    if (
        digest_fd(
            archive_descriptor,
            archive_info,
            "archive Ops após extrair quiescência",
        )
        != expected_archive_sha256
    ):
        reject("archive Ops mudou ao extrair quiescência")
    return open_sealed_memfd(
        payload,
        label="verificador de quiescência",
        mode=0o555,
        expected_sha256=entry.sha256,
    )


def open_sealed_memfd(
    payload: bytes,
    *,
    label: str,
    mode: int,
    expected_sha256: str,
) -> int:
    require_hash(expected_sha256, f"hash de {label}")
    if (
        not payload
        or len(payload) > MAX_MEMBER_BYTES
        or hashlib.sha256(payload).hexdigest() != expected_sha256
        or mode not in {0o400, 0o555}
    ):
        reject(f"payload do memfd de {label} é inválido")
    if not hasattr(os, "memfd_create") or not all(
        hasattr(fcntl, name)
        for name in (
            "F_ADD_SEALS",
            "F_GET_SEALS",
            "F_SEAL_GROW",
            "F_SEAL_SEAL",
            "F_SEAL_SHRINK",
            "F_SEAL_WRITE",
        )
    ):
        reject("recovery post-publisher exige memfd selável no Linux")
    flags = int(getattr(os, "MFD_CLOEXEC", 0x0001)) | int(
        getattr(os, "MFD_ALLOW_SEALING", 0x0002)
    )
    writer = os.memfd_create(
        "tratto-control-" + label.replace(" ", "-")[:64],
        flags,
    )
    reader = -1
    try:
        write_all(writer, payload)
        os.fchmod(writer, mode)
        os.fsync(writer)
        seals = (
            fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_WRITE
        )
        fcntl.fcntl(writer, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(writer, fcntl.F_GET_SEALS) != seals:
            reject(f"memfd de {label} não ficou integralmente selado")
        reader = os.open(
            f"/proc/self/fd/{writer}",
            os.O_RDONLY | os.O_CLOEXEC,
        )
        writer_info = os.fstat(writer)
        info = os.fstat(reader)
        reader_flags = fcntl.fcntl(reader, fcntl.F_GETFL)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 0
            or info.st_uid != EXPECTED_UID
            or info.st_gid != EXPECTED_GID
            or stat.S_IMODE(info.st_mode) != mode
            or info.st_size != len(payload)
            or (reader_flags & os.O_ACCMODE) != os.O_RDONLY
            or (info.st_dev, info.st_ino)
            != (writer_info.st_dev, writer_info.st_ino)
            or fcntl.fcntl(reader, fcntl.F_GET_SEALS) != seals
            or digest_fd(
                reader,
                info,
                f"memfd de {label}",
            )
            != expected_sha256
        ):
            reject(f"memfd de {label} diverge do payload")
        os.close(writer)
        writer = -1
        return reader
    except Exception:
        if reader >= 0:
            os.close(reader)
        if writer >= 0:
            os.close(writer)
        raise


def packaged_unit_names(inventory: ArchiveInventory) -> tuple[str, ...]:
    units: list[str] = []
    for path, entry in inventory.entries.items():
        pure = PurePosixPath(path)
        if len(pure.parts) != 2 or pure.parts[0] != "systemd":
            continue
        name = pure.parts[1]
        if not name.startswith("tratto-control"):
            continue
        if (
            entry.kind != "file"
            or entry.mode != 0o444
            or entry.size <= 0
            or entry.size > MAX_PACKAGED_UNIT_BYTES
            or SYSTEMD_UNIT_RE.fullmatch(name) is None
        ):
            reject("unit Control assinada possui tipo, modo ou nome inválido")
        units.append(name)
    ordered = sorted(units, key=lambda name: name.encode("ascii"))
    if (
        not ordered
        or len(set(ordered)) != len(ordered)
        or "tratto-control.slice" not in ordered
        or "tratto-control-recovery.service" not in ordered
    ):
        reject("catálogo assinado de units Control está incompleto")
    if (
        sum(len(name.encode("ascii")) + 66 for name in ordered)
        > MAX_PACKAGED_UNITS_BYTES
    ):
        reject("catálogo assinado de units Control excede o limite")
    return tuple(ordered)


def packaged_units_catalog(
    inventory: ArchiveInventory,
    current_authenticated_bootstrap_digest: str,
    *,
    uid: int,
    gid: int,
    control_root: Path | None = None,
) -> bytes:
    require_hash(
        current_authenticated_bootstrap_digest,
        "digest autenticado do bootstrap publicado",
    )
    expected_names = packaged_unit_names(inventory)
    root = open_path_chain(
        CONTROL_ROOT if control_root is None else control_root,
        uid=uid,
        gid=gid,
        final_modes={0o711},
    )
    bootstrap = -1
    systemd = -1
    try:
        bootstrap = _open_named_directory(
            root,
            "bootstrap",
            uid=uid,
            gid=gid,
            modes={0o555},
        )
        if bootstrap is None:
            reject("bootstrap publicado está ausente")
        before = protected_bootstrap_tree_digest(
            bootstrap,
            uid=uid,
            gid=gid,
        )
        if before != current_authenticated_bootstrap_digest:
            reject("bootstrap publicado diverge do journal autenticado")
        systemd = _open_named_directory(
            bootstrap,
            "systemd",
            uid=uid,
            gid=gid,
            modes={0o555},
        )
        if systemd is None:
            reject("diretório systemd do bootstrap está ausente")
        observed: list[str] = []
        for name in os.listdir(systemd):
            if not name.startswith("tratto-control"):
                continue
            try:
                name.encode("ascii")
            except UnicodeEncodeError:
                reject("nome de unit Control publicado não é ASCII")
            if SYSTEMD_UNIT_RE.fullmatch(name) is None:
                reject("nome de unit Control publicado é inválido")
            observed.append(name)
        observed_names = tuple(
            sorted(observed, key=lambda name: name.encode("ascii"))
        )
        if observed_names != expected_names:
            reject(
                "units Control publicadas divergem do sucessor assinado"
            )
        records: list[bytes] = []
        for name in expected_names:
            if SYSTEMD_UNIT_RE.fullmatch(name) is None:
                reject("nome de unit Control publicado é inválido")
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=systemd,
            )
            try:
                info = os.fstat(descriptor)
                validate_regular(
                    info,
                    f"unit Control publicada {name}",
                    uid=uid,
                    gid=gid,
                    modes={0o444},
                    maximum=MAX_PACKAGED_UNIT_BYTES,
                )
                digest = digest_fd(
                    descriptor,
                    info,
                    f"unit Control publicada {name}",
                )
            finally:
                os.close(descriptor)
            records.append(
                name.encode("ascii")
                + b" "
                + digest.encode("ascii")
                + b"\n"
            )
        after = protected_bootstrap_tree_digest(
            bootstrap,
            uid=uid,
            gid=gid,
        )
        if after != before:
            reject("bootstrap publicado mudou durante o catálogo")
    finally:
        if systemd >= 0:
            os.close(systemd)
        if bootstrap >= 0:
            os.close(bootstrap)
        os.close(root)
    payload = b"".join(records)
    if len(payload) > MAX_PACKAGED_UNITS_BYTES:
        reject("catálogo assinado de units Control excede o limite")
    return payload


def sanitized_diagnostic(raw: bytes) -> str:
    diagnostic = raw[:2048].decode("utf-8", errors="replace")
    return " ".join(
        item
        for item in diagnostic.replace("\x00", "").split()
        if item.isprintable()
    )[:512]


def validate_quiescence_result(
    result: subprocess.CompletedProcess[bytes],
    *,
    phase: str,
) -> None:
    if result.returncode != 0:
        diagnostic = sanitized_diagnostic(result.stderr)
        suffix = f": {diagnostic}" if diagnostic else ""
        reject(
            f"quiescência post-publisher {phase} não foi provada"
            + suffix
        )
    if result.stdout != QUIESCENCE_SUCCESS:
        reject(
            f"verificador de quiescência {phase} retornou contrato inesperado"
        )


def run_quiescence_protocol(
    verifier: int,
    catalog: int,
    lock_descriptor: int,
) -> None:
    inherited = tuple(sorted({verifier, catalog, lock_descriptor}))
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "SYSTEMD_COLORS": "0",
        "SYSTEMD_PAGER": "",
        LOCK_FD_ENV: str(lock_descriptor),
        LOCK_HELD_ENV: "1",
    }
    for option, phase in (
        (
            "--sealed-packaged-unit-catalog-pre-reload-fd",
            "pré-reload",
        ),
        ("--sealed-packaged-unit-catalog-fd", "final"),
    ):
        if phase == "final":
            reload_result = subprocess.run(
                [
                    str(SYSTEMCTL),
                    "--no-ask-password",
                    "daemon-reload",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                pass_fds=(lock_descriptor,),
                check=False,
                timeout=300,
            )
            if reload_result.returncode != 0:
                diagnostic = sanitized_diagnostic(reload_result.stderr)
                suffix = f": {diagnostic}" if diagnostic else ""
                reject("systemd daemon-reload falhou" + suffix)
        result = subprocess.run(
            [
                str(PYTHON),
                "-I",
                "-B",
                f"/proc/self/fd/{verifier}",
                option,
                str(catalog),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            pass_fds=inherited,
            check=False,
            timeout=300,
        )
        validate_quiescence_result(result, phase=phase)


def run_fork_guardian(
    lock_descriptor: int,
    action: Callable[[], None],
) -> None:
    if not hasattr(os, "fork"):
        reject("guardião de quiescência exige fork")
    try:
        os.fstat(lock_descriptor)
    except OSError:
        reject("guardião recebeu deploy.lock fechado")
    if hasattr(os, "pipe2"):
        reader, writer = os.pipe2(os.O_CLOEXEC)
    else:
        reader, writer = os.pipe()
    try:
        child = os.fork()
    except BaseException:
        os.close(writer)
        os.close(reader)
        raise
    if child == 0:
        os.close(reader)
        outcome = b"ok\n"
        status = 0
        try:
            action()
        except BaseException as error:
            detail = sanitized_diagnostic(
                f"{type(error).__name__}: {error}".encode(
                    "utf-8",
                    errors="replace",
                )
            )
            outcome = ("error:" + detail + "\n").encode("utf-8")
            status = 78
        try:
            if len(outcome) > MAX_GUARDIAN_REPORT_BYTES:
                outcome = b"error:relatorio do guardiao excedeu limite\n"
                status = 78
            write_all(writer, outcome)
        except BaseException:
            pass
        finally:
            os.close(writer)
        os._exit(status)
    os.close(writer)
    report = bytearray()
    oversized = False
    try:
        while True:
            chunk = os.read(reader, 1024)
            if not chunk:
                break
            if len(report) <= MAX_GUARDIAN_REPORT_BYTES:
                report.extend(chunk)
                if len(report) > MAX_GUARDIAN_REPORT_BYTES:
                    oversized = True
    finally:
        os.close(reader)
    while True:
        try:
            waited, status = os.waitpid(child, 0)
            break
        except InterruptedError:
            continue
    if oversized:
        reject("relatório do guardião excedeu o limite")
    if (
        waited != child
        or not os.WIFEXITED(status)
        or os.WEXITSTATUS(status) != 0
        or bytes(report) != b"ok\n"
    ):
        detail = sanitized_diagnostic(bytes(report))
        suffix = f": {detail}" if detail else ""
        reject("guardião de quiescência recusou a operação" + suffix)


def run_quiescence_verifier(
    archive_descriptor: int,
    archive_info: os.stat_result,
    inventory: ArchiveInventory,
    expected_archive_sha256: str,
    lock_descriptor: int,
    current_authenticated_bootstrap_digest: str,
) -> None:
    verifier = open_sealed_archive_member(
        archive_descriptor,
        archive_info,
        inventory,
        "scripts/verify-control-stack-quiescent.py",
        expected_archive_sha256=expected_archive_sha256,
    )
    catalog_payload = packaged_units_catalog(
        inventory,
        current_authenticated_bootstrap_digest,
        uid=EXPECTED_UID,
        gid=EXPECTED_GID,
    )
    catalog = open_sealed_memfd(
        catalog_payload,
        label="catálogo de units",
        mode=0o400,
        expected_sha256=hashlib.sha256(catalog_payload).hexdigest(),
    )
    try:
        run_fork_guardian(
            lock_descriptor,
            lambda: run_quiescence_protocol(
                verifier,
                catalog,
                lock_descriptor,
            ),
        )
    finally:
        os.close(catalog)
        os.close(verifier)


def publisher_supersede_authorization(
    predecessor: SupersededSourceTransaction,
    *,
    successor_kit_id: str,
    successor_source_digest: str,
) -> bytes:
    require_hash(successor_kit_id, "kit ID sucessor do publisher")
    require_hash(
        successor_source_digest,
        "árvore source sucessora do publisher",
    )
    return canonical_bytes(
        {
            "contract": PUBLISHER_SUPERSEDE_CONTRACT,
            "predecessor_publisher_intent_sha256": (
                predecessor.publisher_intent_sha256
            ),
            "predecessor_source_kit_id": predecessor.kit_id,
            "predecessor_source_tree_sha256": predecessor.new_digest,
            "schema_version": 1,
            "successor_source_kit_id": successor_kit_id,
            "successor_source_tree_sha256": successor_source_digest,
        }
    )


def run_publisher(
    source_descriptor: int,
    lock_descriptor: int,
    supersede_authorization: bytes | None,
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
        environment = {
            LOCK_FD_ENV: str(lock_descriptor),
            LOCK_HELD_ENV: "1",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }
        pass_descriptors = [lock_descriptor]
        authorization_reader = -1
        if supersede_authorization is not None:
            if not 0 < len(supersede_authorization) <= 4096:
                reject("autorização do publisher excede o limite")
            authorization_reader, authorization_writer = os.pipe2(
                os.O_CLOEXEC
            )
            try:
                write_all(authorization_writer, supersede_authorization)
            finally:
                os.close(authorization_writer)
            environment[PUBLISHER_SUPERSEDE_FD_ENV] = str(
                authorization_reader
            )
            pass_descriptors.append(authorization_reader)
        try:
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
                env=environment,
                pass_fds=tuple(pass_descriptors),
                check=False,
                timeout=300,
            )
        finally:
            if authorization_reader >= 0:
                os.close(authorization_reader)
    finally:
        os.close(publisher)
    if result.returncode != 0:
        diagnostic = result.stderr[:2048].decode(
            "utf-8",
            errors="replace",
        )
        diagnostic = " ".join(
            item
            for item in diagnostic.replace("\x00", "").split()
            if item.isprintable()
        )[:512]
        suffix = f": {diagnostic}" if diagnostic else ""
        reject(
            "publisher da árvore bootstrap recusou o upgrade"
            + suffix
        )
    try:
        output = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError:
        reject("publisher bootstrap retornou saída inválida")
    if output not in {"upgraded", "already-upgraded"}:
        reject("publisher bootstrap retornou resultado inesperado")
    return output


def observe_active_post_stage_bundle(
    bundle_id: str,
    *,
    uid: int,
    gid: int,
) -> str:
    require_hash(bundle_id, "bundle ID observado post-stage")
    control = open_path_chain(
        CONTROL_ROOT,
        uid=uid,
        gid=gid,
        final_modes={0o711},
    )
    bundles: int | None = None
    staging: int | None = None
    bundle: int | None = None
    try:
        bundles = _open_named_directory(
            control,
            BUNDLES_NAME,
            uid=uid,
            gid=gid,
            modes={0o711},
        )
        staging = _open_named_directory(
            control,
            ".staging",
            uid=uid,
            gid=gid,
            modes={0o700},
        )
        if bundles is None or staging is None:
            reject("raízes post-stage observadas estão ausentes")
        if set(os.listdir(bundles)) != {bundle_id}:
            reject("observação post-stage exige somente o bundle esperado")
        archive_name = post_stage_bundle_archive_name(bundle_id)
        try:
            os.stat(
                archive_name,
                dir_fd=staging,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            reject("observação post-stage encontrou quarentena existente")
        bundle = _open_named_directory(
            bundles,
            bundle_id,
            uid=uid,
            gid=gid,
            modes={0o555},
        )
        if bundle is None:
            reject("bundle post-stage observado está ausente")
        validate_staged_bundle_attestation(
            bundle,
            bundle_id=bundle_id,
            uid=uid,
            gid=gid,
        )
        return staged_bundle_tree_digest(bundle, uid=uid)
    finally:
        if bundle is not None:
            os.close(bundle)
        if staging is not None:
            os.close(staging)
        if bundles is not None:
            os.close(bundles)
        os.close(control)


def inspect_post_stage(
    *,
    incoming: Path,
    state_root: Path,
    uid: int,
    gid: int,
    execution_descriptor: int,
    expectations: BootstrapExpectations,
    signature_verifier: (
        Callable[[int, int, int, str], None] | None
    ),
    lock_descriptor: int,
    quiescence: Callable[
        [
            int,
            os.stat_result,
            ArchiveInventory,
            str,
            int,
            str,
        ],
        None,
    ],
) -> bytes:
    bundle_id = expectations.post_publisher_staged_bundle_id
    if (
        bundle_id is None
        or expectations.post_publisher_staged_bundle_tree_sha256 is not None
    ):
        reject("observação post-stage exige ID sem tree hash prévio")
    base_expectations = replace(
        expectations,
        post_publisher_staged_bundle_id=None,
        post_publisher_staged_bundle_tree_sha256=None,
    )
    validate_expectations(base_expectations)
    require_hash(bundle_id, "bundle ID observado post-stage")
    inputs = open_and_validate_inputs(
        incoming,
        uid=uid,
        gid=gid,
        execution_descriptor=execution_descriptor,
        expectations=base_expectations,
        signature_verifier=signature_verifier,
    )
    try:
        inventory = validate_ops_archive(
            inputs.archive_descriptor,
            inputs.archive_info,
            inputs.binding,
        )
        successor_kit_id = kit_identity(inputs.binding, inventory)
        state = open_path_chain(
            state_root,
            uid=uid,
            gid=gid,
            final_modes={0o555, 0o755},
        )
        try:
            source = _open_named_directory(
                state,
                SOURCE_NAME,
                uid=uid,
                gid=gid,
                modes={0o555},
            )
            if source is None:
                reject("source post-stage observado está ausente")
            try:
                observed_source_digest = tree_digest(
                    scan_tree(source, uid=uid, gid=gid)
                )
            finally:
                os.close(source)
            observed_tree = observe_active_post_stage_bundle(
                bundle_id,
                uid=uid,
                gid=gid,
            )
            bound = replace(
                expectations,
                post_publisher_staged_bundle_tree_sha256=observed_tree,
            )
            recovery = build_initial_post_publisher_recovery(
                state,
                observed_source_digest=observed_source_digest,
                binding=inputs.binding,
                successor_kit_id=successor_kit_id,
                successor_new_digest=inventory.tree_sha256,
                expectations=bound,
                uid=uid,
                gid=gid,
            )
            quiescence(
                inputs.archive_descriptor,
                inputs.archive_info,
                inventory,
                inputs.binding.ops_sha256,
                lock_descriptor,
                recovery.publisher_new_digest,
            )
            source_after = _open_named_directory(
                state,
                SOURCE_NAME,
                uid=uid,
                gid=gid,
                modes={0o555},
            )
            if source_after is None:
                reject("source sumiu durante a observação post-stage")
            try:
                if (
                    tree_digest(
                        scan_tree(source_after, uid=uid, gid=gid)
                    )
                    != observed_source_digest
                ):
                    reject("source mudou durante a observação post-stage")
            finally:
                os.close(source_after)
            if (
                observe_active_post_stage_bundle(
                    bundle_id,
                    uid=uid,
                    gid=gid,
                )
                != observed_tree
            ):
                reject("bundle mudou durante a observação post-stage")
            repeated = build_initial_post_publisher_recovery(
                state,
                observed_source_digest=observed_source_digest,
                binding=inputs.binding,
                successor_kit_id=successor_kit_id,
                successor_new_digest=inventory.tree_sha256,
                expectations=bound,
                uid=uid,
                gid=gid,
            )
            if repeated != recovery:
                reject("bindings mudaram durante a observação post-stage")
            return canonical_bytes(
                {
                    "bundle_id": bundle_id,
                    "bundle_tree_sha256": observed_tree,
                    "contract": (
                        "tratto-control-bootstrap-post-stage-observation-v1"
                    ),
                    "predecessor_source_intent_sha256": (
                        recovery.source_intent_sha256
                    ),
                    "schema_version": 1,
                    "successor_controller_sha": (
                        inputs.binding.controller_sha
                    ),
                    "successor_kit_id": successor_kit_id,
                }
            )
        finally:
            os.close(state)
    finally:
        inputs.close()


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
    publisher: Callable[[int, int, bytes | None], str],
    lock_descriptor: int,
    quiescence: (
        Callable[
            [
                int,
                os.stat_result,
                ArchiveInventory,
                str,
                int,
                str,
            ],
            None,
        ]
        | None
    ) = None,
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
            post_recovery: PostPublisherRecovery | None = None
            post_publisher_mode = (
                expectations.post_publisher_predecessor_kit_id
                is not None
            )
            if post_publisher_mode:
                (
                    post_recovery,
                    current_bootstrap_digest,
                ) = prepare_post_publisher_recovery(
                    state,
                    observed_source_digest=observed_digest,
                    binding=inputs.binding,
                    successor_kit_id=kit_id,
                    successor_new_digest=inventory.tree_sha256,
                    expectations=expectations,
                    uid=uid,
                    gid=gid,
                )
                if quiescence is None:
                    reject(
                        "recovery post-publisher exige prova de quiescência"
                    )
                quiescence(
                    inputs.archive_descriptor,
                    inputs.archive_info,
                    inventory,
                    inputs.binding.ops_sha256,
                    lock_descriptor,
                    current_bootstrap_digest,
                )
                source_after = _open_named_directory(
                    state,
                    SOURCE_NAME,
                    uid=uid,
                    gid=gid,
                    modes={0o555},
                )
                if source_after is None:
                    reject("source sumiu após a prova de quiescência")
                try:
                    digest_after = tree_digest(
                        scan_tree(source_after, uid=uid, gid=gid)
                    )
                finally:
                    os.close(source_after)
                if digest_after != observed_digest:
                    reject("source mudou durante a prova de quiescência")
                (
                    post_recovery,
                    _current_bootstrap_digest_after,
                ) = prepare_post_publisher_recovery(
                    state,
                    observed_source_digest=observed_digest,
                    binding=inputs.binding,
                    successor_kit_id=kit_id,
                    successor_new_digest=inventory.tree_sha256,
                    expectations=expectations,
                    uid=uid,
                    gid=gid,
                )
                if (
                    _current_bootstrap_digest_after
                    != current_bootstrap_digest
                ):
                    reject(
                        "bootstrap mudou durante a prova de quiescência"
                    )
                reconcile_post_publisher_prelude(
                    state,
                    post_recovery,
                    observed_source_digest=observed_digest,
                    uid=uid,
                    gid=gid,
                    runtime=runtime,
                    fault=fault,
                )
            validate_reserved_source_namespace(
                state,
                binding=inputs.binding,
                inventory=inventory,
                successor_kit_id=kit_id,
                successor_new_digest=inventory.tree_sha256,
                observed_source_digest=observed_digest,
                predecessor_expected=(
                    expectations.predecessor_kit_id is not None
                    or post_publisher_mode
                ),
                post_recovery=post_recovery,
                uid=uid,
                gid=gid,
            )
            predecessor = reconcile_superseded_source_transaction(
                state,
                observed_source_digest=observed_digest,
                binding=inputs.binding,
                inventory=inventory,
                successor_kit_id=kit_id,
                expectations=expectations,
                post_recovery=post_recovery,
                uid=uid,
                gid=gid,
                runtime=runtime,
                fault=fault,
            )
            reject_foreign_state(
                state,
                kit_id,
                uid=uid,
                gid=gid,
                predecessor=predecessor,
            )

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
                publisher_authorization = (
                    publisher_supersede_authorization(
                        predecessor,
                        successor_kit_id=kit_id,
                        successor_source_digest=inventory.tree_sha256,
                    )
                    if (
                        predecessor is not None
                        and predecessor.publisher_authorization_required
                    )
                    else None
                )
                publisher_result = publisher(
                    source,
                    lock_descriptor,
                    publisher_authorization,
                )
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
    parser.add_argument("--expected-predecessor-kit-id")
    parser.add_argument("--expected-predecessor-controller-sha")
    parser.add_argument("--expected-predecessor-publisher-intent-sha256")
    parser.add_argument("--expected-post-publisher-predecessor-kit-id")
    parser.add_argument(
        "--expected-post-publisher-predecessor-controller-sha"
    )
    parser.add_argument("--expected-post-publisher-source-intent-sha256")
    parser.add_argument("--expected-post-publisher-source-used-sha256")
    parser.add_argument("--expected-post-publisher-publisher-intent-sha256")
    parser.add_argument("--expected-post-publisher-publisher-used-sha256")
    parser.add_argument("--expected-post-publisher-staged-bundle-id")
    parser.add_argument(
        "--expected-post-publisher-staged-bundle-tree-sha256"
    )
    parser.add_argument(
        "--inspect-post-publisher-staged-bundle-tree",
        action="store_true",
    )
    required_options = (
        "--helper-fd",
        "--expected-helper-sha256",
        "--expected-attestation-sha256",
        "--expected-carrier-sha",
        "--expected-controller-sha",
    )
    predecessor_options = (
        "--expected-predecessor-kit-id",
        "--expected-predecessor-controller-sha",
        "--expected-predecessor-publisher-intent-sha256",
    )
    post_publisher_options = (
        "--expected-post-publisher-predecessor-kit-id",
        "--expected-post-publisher-predecessor-controller-sha",
        "--expected-post-publisher-source-intent-sha256",
        "--expected-post-publisher-source-used-sha256",
        "--expected-post-publisher-publisher-intent-sha256",
        "--expected-post-publisher-publisher-used-sha256",
    )
    post_stage_options = (
        "--expected-post-publisher-staged-bundle-id",
        "--expected-post-publisher-staged-bundle-tree-sha256",
    )
    predecessor_present = [
        option for option in predecessor_options if option in argv
    ]
    post_publisher_present = [
        option for option in post_publisher_options if option in argv
    ]
    post_stage_present = [
        option for option in post_stage_options if option in argv
    ]
    inspect_option = "--inspect-post-publisher-staged-bundle-tree"
    inspect_present = inspect_option in argv
    if inspect_present:
        expected_length = 2 * (
            len(required_options)
            + len(post_publisher_options)
            + 1
        ) + 1
    else:
        expected_length = 2 * (
            len(required_options)
            + (len(predecessor_options) if predecessor_present else 0)
            + (
                len(post_publisher_options)
                if post_publisher_present
                else 0
            )
            + (len(post_stage_options) if post_stage_present else 0)
        )
    if (
        len(argv) != expected_length
        or any(
        argv.count(option) != 1 for option in required_options
        )
        or (
            predecessor_present
            and any(argv.count(option) != 1 for option in predecessor_options)
        )
        or (
            post_publisher_present
            and any(
                argv.count(option) != 1
                for option in post_publisher_options
            )
        )
        or (
            post_stage_present
            and (
                not post_publisher_present
                or (
                    inspect_present
                    and (
                        argv.count(post_stage_options[0]) != 1
                        or post_stage_options[1] in argv
                    )
                )
                or (
                    not inspect_present
                    and any(
                        argv.count(option) != 1
                        for option in post_stage_options
                    )
                )
            )
        )
        or (
            inspect_present
            and (
                argv.count(inspect_option) != 1
                or predecessor_present
                or len(post_publisher_present)
                != len(post_publisher_options)
                or post_stage_present != [post_stage_options[0]]
            )
        )
        or (predecessor_present and post_publisher_present)
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
        predecessor_kit_id=args.expected_predecessor_kit_id,
        predecessor_controller_sha=(
            args.expected_predecessor_controller_sha
        ),
        predecessor_publisher_intent_sha256=(
            args.expected_predecessor_publisher_intent_sha256
        ),
        post_publisher_predecessor_kit_id=(
            args.expected_post_publisher_predecessor_kit_id
        ),
        post_publisher_predecessor_controller_sha=(
            args.expected_post_publisher_predecessor_controller_sha
        ),
        post_publisher_source_intent_sha256=(
            args.expected_post_publisher_source_intent_sha256
        ),
        post_publisher_source_used_sha256=(
            args.expected_post_publisher_source_used_sha256
        ),
        post_publisher_publisher_intent_sha256=(
            args.expected_post_publisher_publisher_intent_sha256
        ),
        post_publisher_publisher_used_sha256=(
            args.expected_post_publisher_publisher_used_sha256
        ),
        post_publisher_staged_bundle_id=(
            args.expected_post_publisher_staged_bundle_id
        ),
        post_publisher_staged_bundle_tree_sha256=(
            args.expected_post_publisher_staged_bundle_tree_sha256
        ),
    )
    if not args.inspect_post_publisher_staged_bundle_tree:
        validate_expectations(expectations)
    previous_umask = os.umask(0o077)
    acquired_lock = False
    lock_descriptor = -1
    try:
        if expectations.post_publisher_predecessor_kit_id is not None:
            if (
                LOCK_FD_ENV in os.environ
                or LOCK_HELD_ENV in os.environ
            ):
                reject(
                    "ponte post-publisher recusa lock herdado ambíguo"
                )
            lock_descriptor = acquire_fixed_deploy_lock(
                uid=EXPECTED_UID,
                gid=EXPECTED_GID,
            )
            acquired_lock = True
        else:
            lock_descriptor = verify_inherited_lock(
                uid=EXPECTED_UID,
                gid=EXPECTED_GID,
            )
        if args.inspect_post_publisher_staged_bundle_tree:
            observation = inspect_post_stage(
                incoming=INCOMING,
                state_root=STATE_ROOT,
                uid=EXPECTED_UID,
                gid=EXPECTED_GID,
                execution_descriptor=args.helper_fd,
                expectations=expectations,
                signature_verifier=None,
                lock_descriptor=lock_descriptor,
                quiescence=run_quiescence_verifier,
            )
            sys.stdout.buffer.write(observation)
            return 0
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
            quiescence=run_quiescence_verifier,
        )
        print(result)
        return 0
    finally:
        if acquired_lock and lock_descriptor >= 0:
            os.close(lock_descriptor)
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
