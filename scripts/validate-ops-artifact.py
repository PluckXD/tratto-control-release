#!/usr/bin/env python3
"""Independently validate the signed Operations archive before extraction."""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import importlib.util
import json
import re
import stat
import tarfile
from pathlib import Path

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
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def reject(message: str) -> None:
    raise TREE.OpsTreeError(message)


def digest_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def member_bytes(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    *,
    maximum: int,
) -> bytes:
    if not member.isfile() or member.size > maximum:
        reject(f"Ops member is not a bounded regular file: {member.name}")
    handle = archive.extractfile(member)
    if handle is None:
        reject(f"Ops member cannot be read: {member.name}")
    payload = handle.read(maximum + 1)
    if len(payload) != member.size or len(payload) > maximum:
        reject(f"Ops member size diverges: {member.name}")
    return payload


def load_approval(path: Path, release_sha: str) -> tuple[dict, bytes]:
    try:
        raw = path.read_bytes()
        value = APPROVAL.parse_json(raw, "approval")
        APPROVAL.require_canonical(raw, value, "approval")
        APPROVAL.validate_shape(value, now=None, historical=True)
    except (OSError, APPROVAL.ApprovalError) as error:
        reject(f"approval is invalid: {error}")
    if (
        value["api"]["commit_sha"] != release_sha
        or value["ops"]["commit_sha"] != release_sha
    ):
        reject("Ops archive SHA is not the approved API/Operations commit")
    return value, raw


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--approval", required=True, type=Path)
    parser.add_argument("--runtime-policy", required=True, type=Path)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-service-digest", required=True)
    args = parser.parse_args()
    try:
        if SHA_RE.fullmatch(args.release_sha) is None:
            reject("expected Ops release SHA is invalid")
        for value, label in (
            (args.expected_sha256, "archive"),
            (args.expected_manifest_sha256, "component manifest"),
            (args.expected_service_digest, "service tree"),
        ):
            if HASH_RE.fullmatch(value) is None:
                reject(f"expected {label} digest is invalid")
        expected_name = f"tratto-control-ops-{args.release_sha}.tar.gz"
        if args.archive.name != expected_name:
            reject(f"Ops archive name must be {expected_name}")
        info = args.archive.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_nlink != 1
            or not 0 < info.st_size <= 512 * 1024 * 1024
        ):
            reject("Ops archive must be a bounded single-link regular file")
        if digest_file(args.archive) != args.expected_sha256:
            reject("Ops archive SHA-256 diverges")
        approval, approval_raw = load_approval(
            args.approval,
            args.release_sha,
        )
        runtime_policy, runtime_policy_digest = RUNTIME.load(
            args.runtime_policy
        )
        try:
            archive = tarfile.open(args.archive, mode="r:gz")
        except (OSError, tarfile.TarError):
            reject("Ops archive is not a valid gzip tar")

        seen: set[str] = set()
        directories: set[str] = set()
        payload_paths: set[str] = set()
        payload_modes: dict[str, int] = {}
        records: list[tuple[str, bytes]] = []
        markers: dict[str, bytes] = {}
        embedded_runtime_policy: bytes | None = None
        quiescence_helper: bytes | None = None
        total = 0
        with archive:
            if archive.pax_headers:
                reject("Ops archive global PAX headers are forbidden")
            members = archive.getmembers()
            if not 1 <= len(members) <= TREE.MAX_MEMBERS:
                reject("Ops archive member count is invalid")
            for member in members:
                if member.pax_headers:
                    reject("Ops archive member PAX headers are forbidden")
                name = TREE.canonical_path(member.name)
                if name in seen:
                    reject("Ops archive contains duplicate paths")
                seen.add(name)
                if member.uid != 0 or member.gid != 0 or member.mtime != 0:
                    reject(f"Ops member metadata is not canonical: {name}")
                if member.isdir():
                    if member.mode != 0o555:
                        reject(f"Ops directory mode must be 0555: {name}")
                    directories.add(name)
                    continue
                if member.islnk():
                    reject("Ops hardlinks are forbidden")
                if member.issym():
                    reject("Ops symlinks are forbidden")
                if not member.isfile():
                    reject(f"Ops member type is forbidden: {name}")
                if member.mode not in {0o444, 0o555}:
                    reject(f"Ops file mode is not canonical: {name}")
                total += member.size
                if total > TREE.MAX_UNCOMPRESSED_BYTES:
                    reject("Ops archive exceeds uncompressed size limit")
                payload = member_bytes(
                    archive,
                    member,
                    maximum=TREE.MAX_UNCOMPRESSED_BYTES,
                )
                if name in TREE.MARKERS:
                    if member.mode != 0o444:
                        reject(f"Ops marker mode must be 0444: {name}")
                    markers[name] = payload
                    continue
                if name.lower().endswith(".pem") and b"PRIVATE KEY" in payload.upper():
                    reject("private key material in Ops archive")
                records.append(
                    (
                        name,
                        TREE.inventory_record(
                            kind="file",
                            mode=member.mode,
                            content_sha256=hashlib.sha256(payload).hexdigest(),
                            path=name,
                        ),
                    )
                )
                payload_paths.add(name)
                payload_modes[name] = member.mode
                if (
                    name
                    == "release-root/policies/control-runtime-v1.json"
                ):
                    embedded_runtime_policy = payload
                if name == TREE.QUIESCENCE_HELPER_PATH:
                    quiescence_helper = payload

        if set(markers) != TREE.MARKERS:
            reject("Ops archive markers are missing or ambiguous")
        TREE.validate_required_inventory(payload_paths)
        TREE.validate_bootstrap_required_file_modes(payload_modes)
        TREE.validate_quiescence_helper_contract(quiescence_helper)
        for path in payload_paths:
            parent = str(Path(path).parent).replace("\\", "/")
            while parent not in {"", "."}:
                if parent not in directories:
                    reject(f"Ops parent directory entry is missing: {parent}")
                parent = str(Path(parent).parent).replace("\\", "/")
        observed_service_digest = TREE.service_digest(records)
        if observed_service_digest != args.expected_service_digest:
            reject("Ops canonical service tree digest diverges")
        if markers["RELEASE_SHA"] != f"{args.release_sha}\n".encode("ascii"):
            reject("Ops RELEASE_SHA marker diverges")
        manifest_raw = markers["artifact-manifest.json"]
        if hashlib.sha256(manifest_raw).hexdigest() != (
            args.expected_manifest_sha256
        ):
            reject("Ops component manifest digest diverges")
        manifest = APPROVAL.parse_json(manifest_raw, "Ops component manifest")
        APPROVAL.require_canonical(
            manifest_raw,
            manifest,
            "Ops component manifest",
        )
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
        RUNTIME.validate_embedded(
            embedded_runtime_policy,
            manifest["runtime_policy"]["sha256"],
        )
        print(
            json.dumps(
                {
                    "component_manifest_sha256": (
                        args.expected_manifest_sha256
                    ),
                    "service_digest": observed_service_digest,
                    "sha256": args.expected_sha256,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    except (
        OSError,
        UnicodeDecodeError,
        APPROVAL.ApprovalError,
        COMPONENT.ComponentManifestError,
        RUNTIME.RuntimePolicyError,
        TREE.OpsTreeError,
    ) as error:
        print(f"Ops artifact rejected: {error}", file=sys.stderr)
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
