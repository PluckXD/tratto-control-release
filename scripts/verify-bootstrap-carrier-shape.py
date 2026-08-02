#!/usr/bin/env python3
"""Fail closed when the private one-shot carrier loses its trust shape.

The carrier intentionally has no third-party YAML dependency.  This verifier
therefore checks a small, indentation-bounded subset of its reviewed workflow
as text.  Product validation remains independent; this gate only protects the
separation between verifier and checkout-free OIDC signer.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import os
import re
import stat
from pathlib import Path


CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
DOWNLOAD = (
    "actions/download-artifact@"
    "d3f86a106a0bac45b974a628896c90dbdf5c8093"
)
UPLOAD = (
    "actions/upload-artifact@"
    "ea165f8d65b6e75b540449e92b4886f43607fa02"
)
COSIGN_INSTALLER = (
    "sigstore/cosign-installer@"
    "6f9f17788090df1f26f669e9d70d6ae9567deba6"
)
SETUP_PYTHON = (
    "actions/setup-python@"
    "83679a892e2d95755f2dac6acb0bfd1e9ac5d548"
)
SETUP_NODE = (
    "actions/setup-node@"
    "49933ea5288caeca8642d1e84afbd3f7d6820020"
)
ALLOWED_ACTIONS = {
    CHECKOUT,
    DOWNLOAD,
    UPLOAD,
    COSIGN_INSTALLER,
    SETUP_PYTHON,
    SETUP_NODE,
}
MAX_WORKFLOW_BYTES = 512 * 1024


class CarrierShapeError(ValueError):
    pass


def reject(message: str) -> None:
    raise CarrierShapeError(message)


def job_block(raw: str, name: str) -> str:
    pattern = re.compile(
        rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [a-zA-Z0-9_]+:\n|\Z)"
    )
    matches = pattern.findall(raw)
    if len(matches) != 1:
        reject(f"job {name} is missing or duplicated")
    return f"  {name}:\n{matches[0]}"


def require_once(raw: str, needle: str, label: str) -> None:
    if raw.count(needle) != 1:
        reject(f"{label} must occur exactly once")


def validate(raw: str) -> None:
    if "\r" in raw or "\t" in raw or "\x00" in raw:
        reject("workflow text is not canonical LF/space YAML")
    if not raw.startswith("name: Control bootstrap v1\n"):
        reject("workflow identity diverges")
    require_once(raw, "\npermissions: {}\n", "top-level empty permissions")
    if len(re.findall(r"(?m)^permissions:", raw)) != 1:
        reject("top-level permissions are duplicated or broadened")
    for job in (
        "authorize",
        "build_api",
        "build_ops",
        "build_web",
        "verify",
        "sign_release",
    ):
        job_block(raw, job)

    uses = re.findall(r"(?m)^\s+-?\s*uses:\s*(\S+)\s*$", raw)
    if not uses or any(action not in ALLOWED_ACTIONS for action in uses):
        reject("workflow contains an unreviewed or unpinned action")
    if any(re.fullmatch(r"[^@]+@[0-9a-f]{40}", item) is None for item in uses):
        reject("workflow action is not pinned to a full commit")

    verifier = job_block(raw, "verify")
    required_verifier = {
        "CONTROLLER_SHA: ${{ inputs.controller_sha }}",
        'test "$(git -C controller rev-parse HEAD)" = "$CONTROLLER_SHA"',
        "scripts/install-bootstrap-source-kit.py",
        "git -C controller ls-tree",
        "git -C controller rev-parse",
        'test "$(git hash-object "$helper_source")" = "$helper_blob"',
        "install -m 0400",
        "bootstrap-source-helper.json",
        '"helper_sha256": os.environ["HELPER_SHA256"]',
        '"controller_sha": os.environ["CONTROLLER_SHA"]',
        ".helper_sha256 bootstrap-source-helper.json",
        ".controller_sha",
        "install-bootstrap-source-kit.py",
    }
    if any(item not in verifier for item in required_verifier):
        reject("verify job does not prove the exact controller helper")
    if "--bootstrap-source-helper" in verifier:
        reject("legacy envelope mutation is forbidden")

    signer = job_block(raw, "sign_release")
    exact_permissions = (
        "    permissions:\n"
        "      actions: read\n"
        "      contents: none\n"
        "      id-token: write\n"
    )
    if (
        signer.count(exact_permissions) != 1
        or signer.count("\n    permissions:\n") != 1
        or signer.count("\n    environment: control-bootstrap\n") != 1
        or "id-token: write" not in signer
        or "contents: none" not in signer
        or "actions: read" not in signer
        or CHECKOUT in signer
        or "ssh-key:" in signer
        or "secrets." in signer
        or "repository:" in signer
    ):
        reject("signer isolation or authority diverges")
    signer_uses = re.findall(
        r"(?m)^\s+-?\s*uses:\s*(\S+)\s*$",
        signer,
    )
    if signer_uses != [DOWNLOAD, DOWNLOAD, COSIGN_INSTALLER, UPLOAD]:
        reject("signer action sequence diverges")
    for required in (
        "verified/install-bootstrap-source-kit.py",
        "bootstrap-source-kit.sigstore.json",
        "verified/bootstrap-source-helper.json",
        ".helper_sha256",
        ".approval.manifest.controller.base_sha",
        "cosign sign-blob",
        "cosign verify-blob",
        "--certificate-github-workflow-sha \"$GITHUB_SHA\"",
        "--certificate-github-workflow-ref refs/heads/main",
        (
            "--certificate-github-workflow-repository "
            '"$GITHUB_REPOSITORY"'
        ),
        "--certificate-github-workflow-trigger workflow_dispatch",
    ):
        if required not in signer:
            reject(f"signer is missing helper contract: {required}")
    if signer.count("--bundle bootstrap-source-kit.sigstore.json") != 2:
        reject("helper must be signed and independently verified once")
    if signer.count('"$helper"') < 3:
        reject("helper digest, signature, and verification are not bound")


def read_workflow(path: Path) -> str:
    try:
        info = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError:
        reject("workflow is unavailable")
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
            or not 0 < opened.st_size <= MAX_WORKFLOW_BYTES
            or stat.S_IMODE(opened.st_mode) & 0o022
        ):
            reject("workflow must be bounded, single-link, and non-writable")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                reject("workflow ended early")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            reject("workflow grew while being read")
        after = os.fstat(descriptor)
        if (
            after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
        ):
            reject("workflow changed while being read")
    finally:
        os.close(descriptor)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError:
        reject("workflow is not UTF-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow", required=True, type=Path)
    args = parser.parse_args()
    try:
        validate(read_workflow(args.workflow))
    except (CarrierShapeError, OSError) as error:
        print(f"bootstrap carrier shape rejected: {error}", file=sys.stderr)
        return 78
    print("bootstrap carrier shape verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
