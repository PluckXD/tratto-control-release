#!/usr/bin/env python3
"""Offline validation/extraction of the single reviewed Node binary."""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import json
import os
import stat
import tarfile
from pathlib import Path

import runtime_policy as RUNTIME


class NodeArchiveError(ValueError):
    """The local Node archive diverges from the reviewed policy."""


def reject(message: str) -> None:
    raise NodeArchiveError(message)


def snapshot(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def validate_archive_metadata(
    info: os.stat_result,
    *,
    expected_size: int,
) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_size != expected_size
    ):
        reject("Node archive metadata/size diverges before hashing")


def require_unchanged(
    descriptor: int,
    expected: os.stat_result,
    label: str,
) -> None:
    if snapshot(os.fstat(descriptor)) != snapshot(expected):
        reject(f"{label} changed while being processed")


def digest_descriptor(
    descriptor: int,
    expected: os.stat_result,
    label: str,
) -> str:
    digest = hashlib.sha256()
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError:
        reject(f"{label} cannot be hashed")
    require_unchanged(descriptor, expected, label)
    return digest.hexdigest()


def write_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    output: Path,
    *,
    expected_size: int,
    expected_digest: str,
) -> None:
    if (
        not member.isfile()
        or member.issym()
        or member.islnk()
        or bool(member.pax_headers)
        or member.sparse not in (None, [])
        or member.size != expected_size
        or stat.S_IMODE(member.mode) != 0o755
    ):
        reject("reviewed Node member is not the exact bounded regular binary")
    source = archive.extractfile(member)
    if source is None:
        reject("reviewed Node member cannot be streamed")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    created = False
    try:
        descriptor = os.open(output, flags, 0o400)
        created = True
        digest = hashlib.sha256()
        total = 0
        try:
            while total < expected_size:
                chunk = source.read(min(1024 * 1024, expected_size - total))
                if not chunk:
                    reject("reviewed Node member ended before its pinned size")
                view = memoryview(chunk)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        reject("reviewed Node binary cannot be written")
                    view = view[written:]
                digest.update(chunk)
                total += len(chunk)
            if source.read(1) or total != expected_size:
                reject("reviewed Node member exceeds its pinned size")
            if digest.hexdigest() != expected_digest:
                reject("reviewed Node binary SHA-256 diverges")
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except Exception:
        if created:
            try:
                output.unlink()
            except OSError:
                pass
        raise


def select_unique_member(
    archive: tarfile.TarFile,
    expected_name: str,
) -> tarfile.TarInfo:
    if archive.pax_headers:
        reject("reviewed Node archive has forbidden global PAX metadata")
    members = [
        member
        for member in archive.getmembers()
        if member.name == expected_name
    ]
    if len(members) != 1:
        reject("reviewed Node archive has no unique binary")
    return members[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-policy", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        policy, policy_digest = RUNTIME.load(args.runtime_policy)
        node = policy["node"]
        if args.archive.name != node["archive_name"]:
            reject("Node archive filename diverges from reviewed policy")
        try:
            descriptor = os.open(
                args.archive,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except OSError:
            reject("Node archive cannot be opened safely")
        try:
            archive_info = os.fstat(descriptor)
            validate_archive_metadata(
                archive_info,
                expected_size=node["archive_size_bytes"],
            )
            if (
                digest_descriptor(descriptor, archive_info, "Node archive")
                != node["archive_sha256"]
            ):
                reject("Node archive SHA-256 diverges before decompression")
            try:
                duplicate = os.dup(descriptor)
                with os.fdopen(duplicate, "rb", closefd=True) as source:
                    with tarfile.open(fileobj=source, mode="r:xz") as archive:
                        write_member(
                            archive,
                            select_unique_member(
                                archive,
                                node["archive_member"],
                            ),
                            args.output,
                            expected_size=node["binary_size_bytes"],
                            expected_digest=node["binary_sha256"],
                        )
            except (OSError, tarfile.TarError):
                reject("Node archive cannot be decoded safely")
            require_unchanged(descriptor, archive_info, "Node archive")
        finally:
            os.close(descriptor)
        print(
            json.dumps(
                {
                    "archive_sha256": node["archive_sha256"],
                    "archive_size_bytes": node["archive_size_bytes"],
                    "binary_sha256": node["binary_sha256"],
                    "binary_size_bytes": node["binary_size_bytes"],
                    "output_mode": "0400",
                    "runtime_policy_sha256": policy_digest,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    except (NodeArchiveError, RUNTIME.RuntimePolicyError) as error:
        print(f"Node archive rejected: {error}", file=sys.stderr)
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
