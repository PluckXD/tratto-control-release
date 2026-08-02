#!/usr/bin/env python3
"""Fail closed when the private one-shot carrier loses its trust shape.

The carrier intentionally has no third-party YAML dependency.  This verifier
therefore checks a small, indentation-bounded subset of its reviewed workflow
as text and pins the complete one-shot workflow bytes to a compile-time
SHA-256.  Product validation remains independent; this gate only protects the
separation between verifier and checkout-free OIDC signer.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import hashlib
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
# Recompute only from the reviewed LF/UTF-8 carrier workflow with:
# sha256sum .github/workflows/control-bootstrap-v1.yml
EXPECTED_WORKFLOW_SHA256 = (
    "d993f5c926546e6e448090bac3fefa2405be5898e8285fafd57c7bd471974a91"
)
EXPECTED_JOBS = (
    "authorize",
    "build_api",
    "build_ops",
    "build_web",
    "verify",
    "sign_release",
)


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


def require_job_permissions(
    raw: str,
    name: str,
    expected: str,
) -> None:
    block = job_block(raw, name)
    matches = re.findall(
        r"(?m)^    permissions:\n(?:^      [a-z-]+: [a-z]+\n)+",
        block,
    )
    if matches != [expected]:
        reject(f"job {name} permissions diverge")


def require_once(raw: str, needle: str, label: str) -> None:
    if raw.count(needle) != 1:
        reject(f"{label} must occur exactly once")


def require_order(raw: str, needles: tuple[str, ...], label: str) -> None:
    positions: list[int] = []
    for needle in needles:
        if raw.count(needle) != 1:
            reject(f"{label} element is missing or duplicated: {needle}")
        positions.append(raw.index(needle))
    if positions != sorted(positions):
        reject(f"{label} order diverges")


def run_blocks(raw: str) -> list[str]:
    lines = raw.splitlines(keepends=True)
    blocks: list[str] = []
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)(?:-\s+)?run:\s*(.*)$", line)
        if match is None:
            continue
        indentation = len(match.group(1))
        block = [match.group(2)]
        cursor = index + 1
        while cursor < len(lines):
            candidate = lines[cursor]
            if candidate.strip():
                candidate_indent = len(candidate) - len(
                    candidate.lstrip(" ")
                )
                if candidate_indent <= indentation:
                    break
            block.append(candidate)
            cursor += 1
        blocks.append("".join(block))
    return blocks


def step_blocks(raw: str) -> list[str]:
    return re.findall(
        r"(?ms)^      - .*?(?=^      - |^  [a-zA-Z0-9_]+:\n|\Z)",
        raw,
    )


def validate_structure(raw: str) -> None:
    if "\r" in raw or "\t" in raw or "\x00" in raw:
        reject("workflow text is not canonical LF/space YAML")
    if not raw.startswith("name: Control bootstrap v1\n"):
        reject("workflow identity diverges")
    require_once(raw, "\npermissions: {}\n", "top-level empty permissions")
    if len(re.findall(r"(?m)^permissions:", raw)) != 1:
        reject("top-level permissions are duplicated or broadened")
    jobs_at = raw.find("\njobs:\n")
    if jobs_at < 0:
        reject("jobs mapping is missing")
    observed_jobs = tuple(
        re.findall(
            r"(?m)^  ([a-zA-Z_][a-zA-Z0-9_-]*):\n",
            raw[jobs_at + len("\njobs:\n"):],
        )
    )
    if observed_jobs != EXPECTED_JOBS:
        reject("workflow jobs or job order diverge")
    for job in EXPECTED_JOBS:
        job_block(raw, job)
    oidc_grants = re.findall(
        r"(?m)^\s+id-token\s*:\s*write\s*$",
        raw,
    )
    if len(oidc_grants) != 1 or raw.count("id-token: write") != 1:
        reject("OIDC write authority must exist exactly once")
    read_contents = (
        "    permissions:\n"
        "      contents: read\n"
    )
    for job in ("authorize", "build_api", "build_ops", "build_web"):
        require_job_permissions(raw, job, read_contents)
    require_job_permissions(
        raw,
        "verify",
        (
            "    permissions:\n"
            "      actions: read\n"
            "      contents: read\n"
        ),
    )
    uses = re.findall(r"(?m)^\s+-?\s*uses:\s*(\S+)\s*$", raw)
    if not uses or any(action not in ALLOWED_ACTIONS for action in uses):
        reject("workflow contains an unreviewed or unpinned action")
    if any(re.fullmatch(r"[^@]+@[0-9a-f]{40}", item) is None for item in uses):
        reject("workflow action is not pinned to a full commit")
    if any(
        re.search(r"\$\{\{\s*inputs\.", block)
        for block in run_blocks(raw)
    ):
        reject("workflow inputs may not be interpolated into run content")
    approval_steps = [
        block
        for block in step_blocks(raw)
        if (
            re.search(r"\$(?:\{)?APPROVAL_PATH(?:\})?", block)
            or re.search(
                r"os\.environ\[[\"']APPROVAL_PATH[\"']\]",
                block,
            )
        )
    ]
    if not approval_steps or any(
        "APPROVAL_PATH: ${{ inputs.approval_path }}" not in block
        for block in approval_steps
    ):
        reject("approval_path must enter every run step only through env")

    verifier = job_block(raw, "verify")
    required_verifier = {
        "CONTROLLER_SHA: ${{ inputs.controller_sha }}",
        "APPROVAL_PATH: ${{ inputs.approval_path }}",
        'test "$(git -C controller rev-parse HEAD)" = "$CONTROLLER_SHA"',
        "scripts/install-bootstrap-source-kit.py",
        "git -C controller ls-tree",
        "git -C controller rev-parse",
        'test "$(git hash-object "$helper_source")" = "$helper_blob"',
        "install -m 0400",
        "bootstrap-source-helper.json",
        '"name": "install-bootstrap-source-kit.py"',
        '"sha256": os.environ["HELPER_SHA256"]',
        '"size_bytes": int(',
        '"controller_sha": os.environ["CONTROLLER_SHA"]',
        "--bootstrap-source-helper",
        "(.schema_version == 6)",
        "(($receipt | length) == 1)",
        ".bootstrap_source_helper == $receipt[0]",
        '["controller_sha", "name", "sha256", "size_bytes"]',
        ".bootstrap_source_helper.sha256",
        ".bootstrap_source_helper.size_bytes",
        ".bootstrap_source_helper.controller_sha",
        "install-bootstrap-source-kit.py",
    }
    if any(item not in verifier for item in required_verifier):
        reject("verify job does not prove the exact controller helper")
    authorize = job_block(raw, "authorize")
    authorization_order = (
        "Checkout exact private carrier main",
        "Preflight untrusted approval and controller inputs",
        "Checkout reviewed public controller",
        "Verify the carrier trust shape",
        "Validate the bounded one-shot approval",
        "Verify controller checkout and workflow identity",
    )
    require_order(
        authorize,
        authorization_order,
        "authorize trust-boundary",
    )
    if authorize.count(
        "- id: preflight\n"
        "        name: Preflight untrusted approval and controller inputs"
    ) != 1:
        reject("trusted preflight output identity diverges")
    preflight_at = authorize.index(authorization_order[1])
    before_preflight = authorize[:preflight_at]
    if (
        "repository: PluckXD/tratto-control-release" in before_preflight
        or "ref: ${{ inputs.controller_sha }}" in before_preflight
        or "controller/" in before_preflight
    ):
        reject("controller input is consumed before trusted preflight")
    required_preflight = {
        're.fullmatch(r"[0-9a-f]{40}", controller_sha)',
        "object_pairs_hook=unique_object",
        "raw != canonical_bytes(value)",
        "os.O_NOFOLLOW",
        "path.as_posix()",
        'f"approvals/{release_id}.json"',
        'value.get("schema_version") != 1',
        'issued.strftime("%Y%m%dT%H%M%SZ")',
        "release_match.group(1)",
        'controller.get("base_sha") != controller_sha',
        "hashlib.sha256(raw).hexdigest()",
        'os.environ["GITHUB_OUTPUT"]',
        "approval_sha256=",
        "approval path, filename, or release_id is invalid",
    }
    preflight_end = authorize.index(authorization_order[2])
    preflight = authorize[preflight_at:preflight_end]
    if any(item not in preflight for item in required_preflight):
        reject("trusted approval/controller preflight is incomplete")
    if (
        "module.validate_shape(" not in authorize[preflight_end:]
        or "historical=False" not in authorize[preflight_end:]
        or (
            "PREFLIGHT_APPROVAL_SHA256: "
            "${{ steps.preflight.outputs.approval_sha256 }}"
        )
        not in authorize[preflight_end:]
        or '"PREFLIGHT_APPROVAL_SHA256"'
        not in authorize[preflight_end:]
        or "expected_approval_hash" not in authorize[preflight_end:]
        or "hashlib.sha256(raw).hexdigest()" not in authorize[preflight_end:]
        or "approval diverged from trusted preflight"
        not in authorize[preflight_end:]
    ):
        reject("reviewed full approval validation is missing")
    if (
        "path.name != f'{value[\"release_id\"]}.json'" not in authorize
        or "approval filename does not match canonical release_id"
        not in authorize
    ):
        reject("approval filename is not bound to canonical release_id")

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
        ".bootstrap_source_helper == $receipt[0]",
        "(($receipt | length) == 1)",
        '["controller_sha", "name", "sha256", "size_bytes"]',
        ".bootstrap_source_helper.name",
        "= install-bootstrap-source-kit.py",
        ".bootstrap_source_helper.sha256",
        ".bootstrap_source_helper.size_bytes",
        ".bootstrap_source_helper.controller_sha",
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
    if (
        signer.count("cosign sign-blob") != 3
        or signer.count("cosign verify-blob") != 3
        or signer.count("--bundle release.sigstore.json") != 2
        or signer.count("--bundle ops.sigstore.json") != 2
    ):
        reject("release, Ops, and helper signatures must remain separate")
    if signer.count('"$helper"') < 3:
        reject("helper digest, signature, and verification are not bound")


def validate(raw: str) -> None:
    observed = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    if observed != EXPECTED_WORKFLOW_SHA256:
        reject("workflow digest diverges from compile-time review")
    validate_structure(raw)


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
