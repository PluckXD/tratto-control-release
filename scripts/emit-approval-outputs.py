#!/usr/bin/env python3
"""Write only validated, injection-safe approval values to GITHUB_OUTPUT."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
RELEASE_RE = re.compile(
    r"^ctl-[0-9]{8}T[0-9]{6}Z-[a-z0-9][a-z0-9-]{2,31}$"
)
EXPECTED_KEYS = {
    "api_sha",
    "controller_base_sha",
    "ops_sha",
    "policy_sha256",
    "release_id",
    "web_sha",
}


def fail(message: str) -> None:
    raise SystemExit(f"approval outputs rejected: {message}")


def regular(path: Path, label: str, *, max_bytes: int) -> bytes:
    try:
        info = path.lstat()
    except OSError:
        fail(f"{label} is unavailable")
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or not 0 < info.st_size <= max_bytes
    ):
        fail(f"{label} must be a bounded regular file")
    return path.read_bytes()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--approval", required=True, type=Path)
    parser.add_argument("--github-output", required=True, type=Path)
    args = parser.parse_args()
    try:
        summary = json.loads(
            regular(args.summary, "validator summary", max_bytes=4096).decode(
                "utf-8"
            )
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("validator summary is invalid JSON")
    if not isinstance(summary, dict) or set(summary) != EXPECTED_KEYS:
        fail("validator summary schema diverges")
    for key in ("api_sha", "controller_base_sha", "ops_sha", "web_sha"):
        if not isinstance(summary[key], str) or SHA_RE.fullmatch(
            summary[key]
        ) is None:
            fail(f"{key} is invalid")
    if summary["api_sha"] != summary["ops_sha"]:
        fail("API and Ops must use the same source commit")
    if (
        not isinstance(summary["policy_sha256"], str)
        or HASH_RE.fullmatch(summary["policy_sha256"]) is None
        or not isinstance(summary["release_id"], str)
        or RELEASE_RE.fullmatch(summary["release_id"]) is None
    ):
        fail("policy digest or release ID is invalid")
    approval_raw = regular(
        args.approval,
        "approval manifest",
        max_bytes=64 * 1024,
    )
    values = {
        **summary,
        "approval_sha256": hashlib.sha256(approval_raw).hexdigest(),
    }
    lines = "".join(f"{key}={values[key]}\n" for key in sorted(values))
    flags = os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(args.github_output, flags)
    except OSError:
        fail("GITHUB_OUTPUT cannot be opened safely")
    try:
        os.write(descriptor, lines.encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    main()
