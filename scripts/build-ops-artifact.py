#!/usr/bin/env python3
"""Build a deterministic, separately signed artifact from ops/control."""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
import platform
import re
import subprocess
import tarfile
from pathlib import Path, PurePosixPath

import component_manifest as COMPONENT
import control_ops_tree as TREE
import runtime_policy as RUNTIME


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "control_release_validator",
    HERE / "validate-approval.py",
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("approval validator unavailable")
APPROVAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APPROVAL)
APPROVAL_V2_SPEC = importlib.util.spec_from_file_location(
    "control_release_ops_approval_v2",
    HERE / "validate-approval-v2.py",
)
if APPROVAL_V2_SPEC is None or APPROVAL_V2_SPEC.loader is None:
    raise SystemExit("approval-v2 validator unavailable")
APPROVAL_V2 = importlib.util.module_from_spec(APPROVAL_V2_SPEC)
APPROVAL_V2_SPEC.loader.exec_module(APPROVAL_V2)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def reject(message: str) -> None:
    raise TREE.OpsTreeError(message)


def validate_builder_platform(
    runtime_policy: dict,
    *,
    system: str,
    architecture: str,
    implementation: str,
    python_version: str,
) -> None:
    if (
        system != runtime_policy["operating_system"]
        or architecture != runtime_policy["architecture"]
        or implementation != runtime_policy["python"]["implementation"]
        or python_version != runtime_policy["python"]["build_version"]
    ):
        reject(
            "Ops builder host/runtime diverges from reviewed "
            "Linux x86_64 CPython 3.12.13"
        )


def git(root: Path, arguments: list[str], *, binary: bool = False) -> bytes | str:
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
    if binary:
        return result.stdout
    return result.stdout.decode("utf-8", errors="strict").strip()


def load_approval(path: Path, release_sha: str) -> tuple[dict, bytes]:
    try:
        raw = path.read_bytes()
        dispatch = json.loads(raw)
        if isinstance(dispatch, dict) and dispatch.get("schema_version") == 2:
            value = APPROVAL_V2.validate_bytes(raw, historical=False)
        else:
            value = APPROVAL.parse_json(raw, "approval")
            APPROVAL.require_canonical(raw, value, "approval")
            APPROVAL.validate_shape(value, now=None, historical=True)
    except (
        OSError,
        json.JSONDecodeError,
        APPROVAL.ApprovalError,
        APPROVAL_V2.ApprovalV2Error,
    ) as error:
        reject(f"approval is invalid: {error}")
    if (
        value["api"]["commit_sha"] != release_sha
        or value["ops"]["commit_sha"] != release_sha
    ):
        reject("Ops source SHA does not match API/Operations approval")
    return value, raw


def git_entries(root: Path, release_sha: str) -> list[tuple[str, str, bytes]]:
    head = git(root, ["rev-parse", "--verify", "HEAD^{commit}"])
    if head != release_sha:
        reject("source checkout HEAD differs from approved Ops SHA")
    if git(root, ["status", "--porcelain=v1", "--untracked-files=no"]):
        reject("tracked source checkout is dirty")
    raw = git(
        root,
        [
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            release_sha,
            "--",
            "ops/control",
        ],
        binary=True,
    )
    assert isinstance(raw, bytes)
    entries: list[tuple[str, str, bytes]] = []
    total = 0
    for record in [item for item in raw.split(b"\0") if item]:
        try:
            metadata, encoded_path = record.split(b"\t", 1)
            mode, object_type, object_sha = metadata.split(b" ", 2)
            source_path = encoded_path.decode("utf-8")
            sha = object_sha.decode("ascii")
        except (ValueError, UnicodeDecodeError):
            reject("invalid Ops Git tree record")
        prefix = "ops/control/"
        if (
            object_type != b"blob"
            or not source_path.startswith(prefix)
            or SHA_RE.fullmatch(sha) is None
        ):
            reject("Ops tree contains a non-blob or ambiguous entry")
        relative = TREE.canonical_path(source_path[len(prefix) :])
        if relative in TREE.MARKERS:
            reject("Ops source collides with release markers")
        if mode not in {b"100644", b"100755"}:
            reject("Ops Git mode is not supported")
        payload = git(root, ["cat-file", "blob", sha], binary=True)
        assert isinstance(payload, bytes)
        total += len(payload)
        if total > TREE.MAX_UNCOMPRESSED_BYTES:
            reject("Ops tree exceeds the uncompressed size limit")
        kind = "file"
        if (
            relative.lower().endswith(".pem")
            and b"PRIVATE KEY" in payload.upper()
        ):
            reject("private key material in Ops source")
        entries.append((relative, kind, payload))
    if not entries or len(entries) > TREE.MAX_MEMBERS:
        reject("Ops tree member count is invalid")
    if len({item[0] for item in entries}) != len(entries):
        reject("Ops tree contains duplicate paths")
    TREE.validate_required_inventory({item[0] for item in entries})
    return entries


def tar_info(path: str, *, mode: int, kind: bytes, size: int = 0) -> tarfile.TarInfo:
    info = tarfile.TarInfo(path)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.mode = mode
    info.type = kind
    info.size = size
    return info


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--approval", required=True, type=Path)
    parser.add_argument("--runtime-policy", required=True, type=Path)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if SHA_RE.fullmatch(args.release_sha) is None:
            reject("approved Ops SHA is invalid")
        expected_name = f"tratto-control-ops-{args.release_sha}.tar.gz"
        if args.output.name != expected_name:
            reject(f"Ops artifact name must be {expected_name}")
        root = args.repository_root.absolute()
        if root.resolve(strict=True) != root:
            reject("source repository root must not contain symlinks")
        approval, approval_raw = load_approval(
            args.approval,
            args.release_sha,
        )
        runtime_policy, runtime_policy_digest = RUNTIME.load(
            args.runtime_policy
        )
        python_version = platform.python_version()
        validate_builder_platform(
            runtime_policy,
            system=platform.system(),
            architecture=platform.machine(),
            implementation=platform.python_implementation(),
            python_version=python_version,
        )
        entries = git_entries(root, args.release_sha)
        TREE.validate_quiescence_helper_contract(
            next(
                (
                    payload
                    for path, kind, payload in entries
                    if (
                        kind == "file"
                        and path == TREE.QUIESCENCE_HELPER_PATH
                    )
                ),
                None,
            )
        )
        embedded_runtime_policy = next(
            (
                payload
                for path, kind, payload in entries
                if (
                    kind == "file"
                    and path
                    == "release-root/policies/control-runtime-v1.json"
                )
            ),
            None,
        )
        RUNTIME.validate_embedded(
            embedded_runtime_policy,
            runtime_policy_digest,
        )
        tree_sha = git(root, ["rev-parse", f"{args.release_sha}^{{tree}}"])
        assert isinstance(tree_sha, str)

        records: list[tuple[str, bytes]] = []
        normalized: list[tuple[str, str, int, bytes, str | None]] = []
        file_modes: dict[str, int] = {}
        directories: set[str] = set()
        for path, kind, payload in entries:
            parent = PurePosixPath(path).parent
            while str(parent) not in {"", "."}:
                directories.add(str(parent))
                parent = parent.parent
            source_mode = git(
                root,
                [
                    "ls-tree",
                    args.release_sha,
                    "--",
                    f"ops/control/{path}",
                ],
            )
            assert isinstance(source_mode, str)
            executable = source_mode.startswith("100755 ")
            mode = TREE.normalized_file_mode(executable=executable)
            file_modes[path] = mode
            content_hash = hashlib.sha256(payload).hexdigest()
            normalized.append((path, kind, mode, payload, None))
            records.append(
                (
                    path,
                    TREE.inventory_record(
                        kind=kind,
                        mode=mode,
                        content_sha256=content_hash,
                        path=path,
                    ),
                )
            )
        TREE.validate_bootstrap_required_file_modes(file_modes)
        service_digest = TREE.service_digest(records)
        manifest = {
            "approval_manifest_sha256": hashlib.sha256(
                approval_raw
            ).hexdigest(),
            "artifact_kind": "tratto-control-ops",
            "build": {
                "arch": "x86_64",
                "os": "Linux",
                "python": python_version,
                "shell": "bash",
                "tree_digest_algorithm": "tratto-tree-v1",
            },
            "migration": approval["migration"],
            "release_sha": args.release_sha,
            "runtime_policy": RUNTIME.reference(runtime_policy_digest),
            "schema_version": 4,
        }
        COMPONENT.validate(
            manifest,
            kind="ops",
            release_sha=args.release_sha,
            approval_manifest_sha256=hashlib.sha256(
                approval_raw
            ).hexdigest(),
            migration=approval["migration"],
            runtime_policy_digest=runtime_policy_digest,
        )
        manifest_raw = APPROVAL.canonical_bytes(manifest)
        release_raw = f"{args.release_sha}\n".encode("ascii")

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open(args.output, flags, 0o600)
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
                        format=tarfile.USTAR_FORMAT,
                    ) as archive:
                        for directory in sorted(
                            directories,
                            key=lambda item: item.encode("utf-8"),
                        ):
                            info = tar_info(
                                directory,
                                mode=0o555,
                                kind=tarfile.DIRTYPE,
                            )
                            archive.addfile(info)
                        for name, payload in (
                            ("RELEASE_SHA", release_raw),
                            ("artifact-manifest.json", manifest_raw),
                        ):
                            info = tar_info(
                                name,
                                mode=0o444,
                                kind=tarfile.REGTYPE,
                                size=len(payload),
                            )
                            archive.addfile(info, io.BytesIO(payload))
                        for path, kind, mode, payload, target in sorted(
                            normalized,
                            key=lambda item: item[0].encode("utf-8"),
                        ):
                            assert kind == "file" and target is None
                            info = tar_info(
                                path,
                                mode=mode,
                                kind=tarfile.REGTYPE,
                                size=len(payload),
                            )
                            archive.addfile(info, io.BytesIO(payload))
                output.flush()
                os.fsync(output.fileno())
        except Exception:
            try:
                args.output.unlink()
            except OSError:
                pass
            raise
        archive_raw = args.output.read_bytes()
        print(
            json.dumps(
                {
                    "artifact_name": expected_name,
                    "component_manifest_sha256": hashlib.sha256(
                        manifest_raw
                    ).hexdigest(),
                    "python": python_version,
                    "runtime_policy_sha256": runtime_policy_digest,
                    "service_digest": service_digest,
                    "sha256": hashlib.sha256(archive_raw).hexdigest(),
                    "size_bytes": len(archive_raw),
                    "tree_sha": tree_sha,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    except (
        OSError,
        UnicodeDecodeError,
        COMPONENT.ComponentManifestError,
        RUNTIME.RuntimePolicyError,
        TREE.OpsTreeError,
    ) as error:
        print(f"Ops artifact build rejected: {error}", file=sys.stderr)
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
