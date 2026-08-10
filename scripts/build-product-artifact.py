#!/usr/bin/env python3
"""Build a bounded Control API or Web artifact from a prepared runtime tree.

The builder deliberately does not install dependencies or run product build
scripts.  A fresh, isolated job prepares ``bundle-root`` and this program
validates and packages only those bytes.  This keeps the packaging authority
small and makes the resulting archive independently reproducible/verifiable.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import importlib.util
import io
import json
import os
import platform
import posixpath
import re
import stat
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


sys.dont_write_bytecode = True

import component_manifest as COMPONENT
import runtime_policy as RUNTIME


HERE = Path(__file__).resolve().parent
APPROVAL_SPEC = importlib.util.spec_from_file_location(
    "control_release_product_approval",
    HERE / "validate-approval.py",
)
if APPROVAL_SPEC is None or APPROVAL_SPEC.loader is None:
    raise SystemExit("approval validator unavailable")
APPROVAL = importlib.util.module_from_spec(APPROVAL_SPEC)
APPROVAL_SPEC.loader.exec_module(APPROVAL)
APPROVAL_V2_SPEC = importlib.util.spec_from_file_location(
    "control_release_product_approval_v2",
    HERE / "validate-approval-v2.py",
)
if APPROVAL_V2_SPEC is None or APPROVAL_V2_SPEC.loader is None:
    raise SystemExit("approval-v2 validator unavailable")
APPROVAL_V2 = importlib.util.module_from_spec(APPROVAL_V2_SPEC)
APPROVAL_V2_SPEC.loader.exec_module(APPROVAL_V2)
SOURCE_CONTRACT_SPEC = importlib.util.spec_from_file_location(
    "control_release_product_source_contract",
    HERE / "product-source-contract.py",
)
if SOURCE_CONTRACT_SPEC is None or SOURCE_CONTRACT_SPEC.loader is None:
    raise SystemExit("product source contract verifier unavailable")
SOURCE_CONTRACT = importlib.util.module_from_spec(SOURCE_CONTRACT_SPEC)
SOURCE_CONTRACT_SPEC.loader.exec_module(SOURCE_CONTRACT)
SOURCE_CONTRACT_ROOT = HERE.parent / "contracts" / "product-source"
LEGACY_SOURCE_CONTRACT_EXEMPT_HEADS = {"j1transpcod", "f29controlexec"}
PAYMENT_SOURCE_CONTRACT_REQUIRED_PATHS = frozenset(
    {
        "alembic/env.py",
        "alembic/versions/f39paymentfence_cobranca_external_unica.py",
        (
            "alembic/versions/"
            "f40asaasfence_preflight_parcelamento_asaas.py"
        ),
        "alembic/versions/f41paymentintent_intent_state_machine.py",
        (
            "alembic/versions/"
            "f42customerlink_pagamento_cliente_vinculo.py"
        ),
        "app/core/config.py",
        "app/main.py",
        "app/models/__init__.py",
        "app/models/pagamento.py",
        "app/pagamento/asaas.py",
        "app/pagamento/base.py",
        "app/pagamento/registry.py",
        "app/routers/loja.py",
        "app/routers/loja_admin.py",
        "app/routers/pagamentos.py",
        "app/services/erp_worker.py",
        "app/services/pagamento.py",
        "app/services/pagamento_intent_worker.py",
        "ops/control/scripts/run-control-fleet-migration.py",
        "ops/control/scripts/validate-artifact.py",
        "ops/control/scripts/validate-bundle.py",
        "ops/control/scripts/verify-control-stack-quiescent.py",
        "scripts/migrate_all_tenants.py",
    }
)

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_MEMBERS = 350_000
MAX_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024
FORBIDDEN_BASENAMES = {
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials.json",
    "id_ed25519",
    "id_rsa",
}
FORBIDDEN_SUFFIXES = {".key", ".p12", ".pfx"}
MARKERS = {"RELEASE_SHA", "artifact-manifest.json"}
API_REQUIRED = {
    "alembic",
    "alembic.ini",
    "alembic/env.py",
    "app",
    "app/main.py",
    "app/core/config.py",
    "app/core/control_runtime_db.py",
    "app/core/tenant_executor_contract.py",
    "app/services/control_db_rpc.py",
    "app/services/control_executor_backend.py",
    "app/services/control_executor_client.py",
    "app/services/control_executor_protocol.py",
    "app/services/control_executor_server.py",
    "app/services/control_fleet_attestation.py",
    "requirements.lock",
    "runtime",
    "scripts",
    "scripts/control_executor.py",
    "scripts/migrate_control_mfa_key.py",
    (
        "alembic/versions/"
        "j1transpcod_transportadora_external_id.py"
    ),
    (
        "alembic/versions/"
        "f26authchallenge_user_2fa_challenge_ledger.py"
    ),
    (
        "alembic/versions/"
        "f27mfakeyversion_user_2fa_mfa_envelope.py"
    ),
    (
        "alembic/versions/"
        "f28controlrpc_control_runtime_rpc_boundary.py"
    ),
    (
        "alembic/versions/"
        "f29controlexec_control_executor_ledger.py"
    ),
}
WEB_REQUIRED = {
    ".next",
    "node_modules",
    "package.json",
    "server.js",
}


class ProductArtifactError(ValueError):
    """The prepared product tree is not safe or does not match approval."""


def reject(message: str) -> None:
    raise ProductArtifactError(message)


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def git(root: Path, arguments: list[str]) -> str:
    result = subprocess.run(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            *arguments,
        ],
        cwd=root,
        env={
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", ""),
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if result.returncode:
        reject("immutable source Git lookup failed")
    return result.stdout.decode("utf-8", errors="strict").strip()


def load_approval(
    path: Path,
    *,
    kind: str,
    release_sha: str,
) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        dispatch = json.loads(raw)
        if isinstance(dispatch, dict) and dispatch.get("schema_version") == 2:
            value = APPROVAL_V2.parse_canonical_json(raw)
            APPROVAL_V2.validate_shape(
                value,
                now=dt.datetime.now(dt.timezone.utc),
                historical=False,
            )
        else:
            value = APPROVAL.parse_json(raw, "approval")
            APPROVAL.require_canonical(raw, value, "approval")
            APPROVAL.validate_shape(
                value,
                now=dt.datetime.now(dt.timezone.utc),
                historical=False,
            )
    except (
        OSError,
        json.JSONDecodeError,
        APPROVAL.ApprovalError,
        APPROVAL_V2.ApprovalV2Error,
    ) as error:
        reject(f"approval is invalid: {error}")
    approved = value["api" if kind == "api" else "web"]["commit_sha"]
    if approved != release_sha:
        reject(f"{kind} source SHA does not match approval")
    return value, raw


def validate_source(root: Path, release_sha: str) -> str:
    absolute = root.absolute()
    if absolute.resolve(strict=True) != absolute:
        reject("source repository root must not contain symlinks")
    if git(absolute, ["rev-parse", "--verify", "HEAD^{commit}"]) != release_sha:
        reject("source checkout HEAD differs from approved SHA")
    if git(absolute, ["status", "--porcelain=v1", "--untracked-files=no"]):
        reject("tracked source checkout is dirty")
    tree_sha = git(absolute, ["rev-parse", f"{release_sha}^{{tree}}"])
    if SHA_RE.fullmatch(tree_sha) is None:
        reject("source tree SHA is invalid")
    return tree_sha


def validate_exact_product_sources(
    *,
    kind: str,
    approval: dict[str, Any],
    repository_root: Path,
    bundle_root: Path,
) -> str | None:
    """Apply the controller-owned contract to guarded migration heads.

    Selection is derived exclusively from the approved migration head.  A
    workflow input therefore cannot substitute a contract that blesses
    attacker-chosen source bytes.
    """

    if kind != "api":
        return None
    migration = approval.get("migration")
    if not isinstance(migration, dict):
        reject("approval migration contract is invalid")
    migration_head = migration.get("head_revision")
    if not isinstance(migration_head, str):
        reject("approval migration head is invalid")
    if migration_head in LEGACY_SOURCE_CONTRACT_EXEMPT_HEADS:
        return None
    contract_path = SOURCE_CONTRACT_ROOT / f"{migration_head}.json"
    if not contract_path.is_file():
        reject(
            "guarded API migration head requires its controller-owned "
            "exact source contract"
        )
    contract, digest = SOURCE_CONTRACT.load(contract_path)
    SOURCE_CONTRACT.verify(
        contract,
        repository_root=repository_root,
        bundle_root=bundle_root,
        expected_migration_head=migration_head,
        required_files=PAYMENT_SOURCE_CONTRACT_REQUIRED_PATHS,
    )
    return digest


def canonical_path(value: str) -> str:
    if (
        not value
        or value.startswith("/")
        or "\x00" in value
        or "\\" in value
    ):
        reject("runtime path is invalid")
    normalized = posixpath.normpath(value)
    if (
        normalized in {"", ".", ".."}
        or normalized.startswith("../")
        or normalized != value
        or value.startswith("-")
    ):
        reject("runtime path is not canonical")
    return normalized


def link_stays_inside(path: str, target: str) -> bool:
    if not target or target.startswith("/") or "\x00" in target:
        return False
    resolved = posixpath.normpath(
        posixpath.join(posixpath.dirname(path), target)
    )
    return (
        resolved not in {"", ".", ".."}
        and not resolved.startswith("../")
    )


def reject_secret(path: str, payload: bytes | None) -> None:
    name = PurePosixPath(path).name.lower()
    suffix = PurePosixPath(name).suffix
    if (
        name in FORBIDDEN_BASENAMES
        or name.startswith(".env.")
        or suffix in FORBIDDEN_SUFFIXES
    ):
        reject("secret-bearing filename in prepared runtime")
    if suffix == ".pem" and payload is not None:
        if len(payload) > 4 * 1024 * 1024:
            reject("PEM file is excessively large")
        if b"PRIVATE KEY" in payload.upper():
            reject("private key material in prepared runtime")


def normalized_mode(info: os.stat_result, *, directory: bool) -> int:
    if directory:
        return 0o550
    return 0o550 if info.st_mode & 0o111 else 0o440


def tree_record(
    *,
    path: str,
    kind: str,
    mode: int,
    payload_hash: str,
    target: str,
) -> bytes:
    return (
        f"{kind}\0{mode:04o}\0{payload_hash}\0{target}\0{path}\n"
    ).encode("utf-8")


def scan_tree(
    root: Path,
    *,
    kind: str,
) -> tuple[list[tuple[str, str, int, bytes | None, str]], str]:
    absolute = root.absolute()
    if absolute.resolve(strict=True) != absolute or absolute.is_symlink():
        reject("prepared runtime root must not contain symlinks")
    if MARKERS & {entry.name for entry in absolute.iterdir()}:
        reject("prepared runtime collides with release markers")
    if kind == "web" and (absolute / ".next" / "cache").exists():
        reject("Web build cache must not enter the immutable artifact")

    entries: list[tuple[str, str, int, bytes | None, str]] = []
    records: list[bytes] = []
    total = 0
    for index, path in enumerate(
        sorted(
            absolute.rglob("*"),
            key=lambda item: item.relative_to(absolute).as_posix().encode(
                "utf-8"
            ),
        ),
        start=1,
    ):
        if index > MAX_MEMBERS:
            reject("prepared runtime has too many members")
        relative = canonical_path(path.relative_to(absolute).as_posix())
        try:
            info = path.lstat()
        except OSError:
            reject("prepared runtime changed during inspection")
        if info.st_mode & 0o6000:
            reject("prepared runtime contains setuid/setgid entry")
        if stat.S_ISDIR(info.st_mode):
            mode = normalized_mode(info, directory=True)
            entries.append((relative, "directory", mode, None, ""))
            records.append(
                tree_record(
                    path=relative,
                    kind="directory",
                    mode=mode,
                    payload_hash=hashlib.sha256(b"").hexdigest(),
                    target="",
                )
            )
            continue
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            if not link_stays_inside(relative, target):
                reject("prepared runtime contains escaping symlink")
            reject_secret(relative, None)
            mode = 0o440
            entries.append((relative, "symlink", mode, None, target))
            records.append(
                tree_record(
                    path=relative,
                    kind="symlink",
                    mode=mode,
                    payload_hash=hashlib.sha256(
                        target.encode("utf-8")
                    ).hexdigest(),
                    target=target,
                )
            )
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            reject("prepared runtime contains a special or linked file")
        payload = path.read_bytes()
        if len(payload) != info.st_size:
            reject("prepared runtime changed while being read")
        total += len(payload)
        if total > MAX_UNCOMPRESSED_BYTES:
            reject("prepared runtime exceeds size limit")
        reject_secret(relative, payload)
        mode = normalized_mode(info, directory=False)
        payload_hash = hashlib.sha256(payload).hexdigest()
        entries.append((relative, "file", mode, payload, ""))
        records.append(
            tree_record(
                path=relative,
                kind="file",
                mode=mode,
                payload_hash=payload_hash,
                target="",
            )
        )

    names = {entry[0] for entry in entries}
    required = API_REQUIRED if kind == "api" else WEB_REQUIRED
    missing = sorted(required - names)
    if missing:
        reject(f"prepared {kind} runtime is incomplete: {missing[0]}")
    for directory in (
        {"app", "alembic", "scripts", "runtime"}
        if kind == "api"
        else {".next", "node_modules"}
    ):
        entry = next((item for item in entries if item[0] == directory), None)
        if entry is None or entry[1] != "directory":
            reject(f"required {kind} directory is invalid: {directory}")
    service_digest = hashlib.sha256(
        b"TRATTO-CONTROL-PRODUCT-TREE-V1\0" + b"".join(records)
    ).hexdigest()
    return entries, service_digest


def tar_info(
    path: str,
    *,
    mode: int,
    tar_type: bytes,
    size: int = 0,
    target: str = "",
) -> tarfile.TarInfo:
    info = tarfile.TarInfo(path)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.mode = mode
    info.type = tar_type
    info.size = size
    info.linkname = target
    return info


def write_archive(
    path: Path,
    *,
    entries: list[tuple[str, str, int, bytes | None, str]],
    release_sha: str,
    manifest_raw: bytes,
) -> tuple[str, int]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=output,
                mtime=0,
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed,
                    mode="w",
                    format=tarfile.PAX_FORMAT,
                ) as archive:
                    for name, payload in (
                        ("RELEASE_SHA", f"{release_sha}\n".encode("ascii")),
                        ("artifact-manifest.json", manifest_raw),
                    ):
                        info = tar_info(
                            name,
                            mode=0o440,
                            tar_type=tarfile.REGTYPE,
                            size=len(payload),
                        )
                        archive.addfile(info, io.BytesIO(payload))
                    for name, entry_kind, mode, payload, target in entries:
                        if entry_kind == "directory":
                            info = tar_info(
                                name,
                                mode=mode,
                                tar_type=tarfile.DIRTYPE,
                            )
                            archive.addfile(info)
                        elif entry_kind == "symlink":
                            info = tar_info(
                                name,
                                mode=mode,
                                tar_type=tarfile.SYMTYPE,
                                target=target,
                            )
                            archive.addfile(info)
                        else:
                            assert payload is not None
                            info = tar_info(
                                name,
                                mode=mode,
                                tar_type=tarfile.REGTYPE,
                                size=len(payload),
                            )
                            archive.addfile(info, io.BytesIO(payload))
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    archive_hash = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            archive_hash.update(chunk)
            size += len(chunk)
    return archive_hash.hexdigest(), size


def node_version() -> str:
    result = subprocess.run(
        ["node", "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            "PATH": os.environ.get("PATH", ""),
            "LANG": "C",
            "LC_ALL": "C",
        },
    )
    if result.returncode:
        reject("Node runtime is unavailable")
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", required=True, choices=("api", "web"))
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--bundle-root", required=True, type=Path)
    parser.add_argument("--approval", required=True, type=Path)
    parser.add_argument("--runtime-policy", required=True, type=Path)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if SHA_RE.fullmatch(args.release_sha) is None:
            reject("approved product SHA is invalid")
        expected_name = (
            f"tratto-control-{args.kind}-{args.release_sha}.tar.gz"
        )
        if args.output.name != expected_name:
            reject(f"product artifact name must be {expected_name}")
        approval, approval_raw = load_approval(
            args.approval,
            kind=args.kind,
            release_sha=args.release_sha,
        )
        tree_sha = validate_source(args.repository_root, args.release_sha)
        validate_exact_product_sources(
            kind=args.kind,
            approval=approval,
            repository_root=args.repository_root,
            bundle_root=args.bundle_root,
        )
        runtime_policy, runtime_policy_digest = RUNTIME.load(
            args.runtime_policy
        )
        if (
            platform.system() != runtime_policy["operating_system"]
            or platform.machine() != runtime_policy["architecture"]
        ):
            reject("product builder platform diverges from runtime policy")
        if args.kind == "api":
            if (
                platform.python_implementation()
                != runtime_policy["python"]["implementation"]
                or platform.python_version()
                != runtime_policy["python"]["build_version"]
            ):
                reject("API builder Python diverges from runtime policy")
        else:
            if node_version() != runtime_policy["node"]["version"]:
                reject("Web builder Node diverges from runtime policy")

        entries, service_digest = scan_tree(
            args.bundle_root,
            kind=args.kind,
        )
        approval_hash = hashlib.sha256(approval_raw).hexdigest()
        build: dict[str, str]
        if args.kind == "api":
            requirements = args.bundle_root / "requirements.lock"
            requirements_hash = hashlib.sha256(
                requirements.read_bytes()
            ).hexdigest()
            build = {
                "arch": "x86_64",
                "os": "Linux",
                "python": platform.python_version(),
                "requirements_lock_sha256": requirements_hash,
            }
        else:
            build = {
                "arch": "x86_64",
                "node": node_version(),
                "os": "Linux",
            }
        manifest: dict[str, Any] = {
            "approval_manifest_sha256": approval_hash,
            "artifact_kind": f"tratto-control-{args.kind}",
            "build": build,
            "migration": approval["migration"],
            "release_sha": args.release_sha,
            "runtime_policy": RUNTIME.reference(runtime_policy_digest),
            "schema_version": 4,
        }
        if args.kind == "web":
            manifest["public_build"] = {
                "NEXT_PUBLIC_API_URL": "/api",
                "NEXT_PUBLIC_APP_SURFACE": "control",
            }
        COMPONENT.validate(
            manifest,
            kind=args.kind,
            release_sha=args.release_sha,
            approval_manifest_sha256=approval_hash,
            migration=approval["migration"],
            runtime_policy_digest=runtime_policy_digest,
            requirements_lock_sha256=(
                build.get("requirements_lock_sha256")
                if args.kind == "api"
                else None
            ),
        )
        manifest_raw = canonical_bytes(manifest)
        archive_hash, archive_size = write_archive(
            args.output,
            entries=entries,
            release_sha=args.release_sha,
            manifest_raw=manifest_raw,
        )
        print(
            json.dumps(
                {
                    "artifact_name": expected_name,
                    "component_manifest_sha256": hashlib.sha256(
                        manifest_raw
                    ).hexdigest(),
                    "runtime_policy_sha256": runtime_policy_digest,
                    "service_digest": service_digest,
                    "sha256": archive_hash,
                    "size_bytes": archive_size,
                    "tree_sha": tree_sha,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    except (
        OSError,
        UnicodeDecodeError,
        subprocess.SubprocessError,
        APPROVAL.ApprovalError,
        APPROVAL_V2.ApprovalV2Error,
        COMPONENT.ComponentManifestError,
        SOURCE_CONTRACT.ProductSourceContractError,
        RUNTIME.RuntimePolicyError,
        ProductArtifactError,
    ) as error:
        print(
            f"Product artifact build rejected: {error}",
            file=sys.stderr,
        )
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
