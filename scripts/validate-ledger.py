#!/usr/bin/env python3
"""Validate the independent append-only Control approval ledger.

The ledger checkout is treated as untrusted input.  A valid checkout is the
exact verified remote ``main`` of the fixed public ledger repository, has full
history, and contains a linear sequence of single-parent commits after a
separately pinned genesis commit.  Every post-genesis commit adds exactly one
canonical approval-v2 manifest and changes nothing else.

Each ledger entry is a complete production-v2 authorization.  Its canonical
shape and business bindings are delegated to the co-located, fixed-path
``validate-approval-v2.py`` validator in historical mode; this module adds
only the Git-ledger replay and remote-head guarantees.

The production CLI deliberately remains unavailable until
``PINNED_GENESIS_SHA`` is replaced by the reviewed ledger genesis commit.
Unit tests and offline reviewers use :func:`validate` with an explicit genesis
and already verified remote-main SHA; that API never performs network access.
"""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


HERE = Path(__file__).resolve().parent
APPROVAL_V2_SPEC = importlib.util.spec_from_file_location(
    "control_release_approval_v2",
    HERE / "validate-approval-v2.py",
)
if APPROVAL_V2_SPEC is None or APPROVAL_V2_SPEC.loader is None:
    raise RuntimeError("fixed approval-v2 validator is unavailable")
APPROVAL_V2 = importlib.util.module_from_spec(APPROVAL_V2_SPEC)
APPROVAL_V2_SPEC.loader.exec_module(APPROVAL_V2)


EXPECTED_REPOSITORY = "PluckXD/tratto-control-release-ledger"
EXPECTED_ORIGIN = (
    "https://github.com/PluckXD/tratto-control-release-ledger.git"
)
EXPECTED_REF = "refs/heads/main"
PINNED_GENESIS_SHA = "20ad87d361f31fd08ed2721a2d2acbb855addd6b"

SHA1_RE = APPROVAL_V2.SHA1_RE
SHA256_RE = APPROVAL_V2.SHA256_RE
RELEASE_ID_RE = APPROVAL_V2.RELEASE_ID_RE
ZERO_SHA256 = APPROVAL_V2.ZERO_SHA256
MAX_APPROVAL_BYTES = APPROVAL_V2.MAX_FILE_BYTES
MAX_LEDGER_RECORDS = APPROVAL_V2.MAX_LEDGER_SEQUENCE


class LedgerError(ValueError):
    """The ledger is unavailable, ambiguous, or violates its trust contract."""


def reject(message: str) -> None:
    raise LedgerError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            reject(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return APPROVAL_V2.canonical_bytes(value)


def parse_approval(raw: bytes, label: str) -> dict[str, Any]:
    try:
        return APPROVAL_V2.validate_bytes(
            raw,
            historical=True,
        )
    except APPROVAL_V2.ApprovalV2Error as error:
        reject(f"{label} is invalid: {error}")


def git(
    root: Path,
    arguments: list[str],
    *,
    binary: bool = False,
    allow_failure: bool = False,
) -> bytes | str:
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
    }
    try:
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
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        reject("local Git verification failed")
    if result.returncode and not allow_failure:
        detail = result.stderr.decode("utf-8", errors="replace").strip()[:300]
        reject(f"Git verification rejected: {detail}")
    if binary:
        return result.stdout
    try:
        return result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        reject("Git returned non-UTF-8 metadata")


def git_succeeds(root: Path, arguments: list[str]) -> bool:
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
    }
    try:
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
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        reject("local Git verification failed")
    return result.returncode == 0


def approval_path(path: str) -> PurePosixPath:
    pure = PurePosixPath(path)
    if (
        pure.is_absolute()
        or len(pure.parts) != 2
        or pure.parent != PurePosixPath("approvals")
        or pure.name in {"", ".", ".."}
        or not pure.name.endswith(".json")
    ):
        reject("approval path must be approvals/<release_id>.json")
    filename = pure.name.removesuffix(".json")
    if RELEASE_ID_RE.fullmatch(filename) is None:
        reject("approval filename has invalid release_id format")
    return pure


def tree_blob(root: Path, revision: str, path: str) -> bytes:
    entry = git(
        root,
        ["ls-tree", "-z", revision, "--", path],
        binary=True,
    )
    assert isinstance(entry, bytes)
    records = [record for record in entry.split(b"\0") if record]
    if len(records) != 1:
        reject(f"approval tree entry is absent or ambiguous: {path}")
    try:
        metadata, encoded_path = records[0].split(b"\t", 1)
        mode, object_type, object_sha = metadata.split(b" ", 2)
        decoded_path = encoded_path.decode("utf-8")
        sha = object_sha.decode("ascii")
    except (ValueError, UnicodeDecodeError):
        reject(f"approval tree entry is invalid: {path}")
    if (
        mode != b"100644"
        or object_type != b"blob"
        or decoded_path != path
        or SHA1_RE.fullmatch(sha) is None
    ):
        reject(f"approval must be a regular 100644 Git blob: {path}")
    size_text = git(root, ["cat-file", "-s", sha])
    assert isinstance(size_text, str)
    try:
        size = int(size_text, 10)
    except ValueError:
        reject(f"approval blob size is invalid: {path}")
    if not 0 < size <= MAX_APPROVAL_BYTES:
        reject(f"approval blob size is invalid: {path}")
    raw = git(root, ["cat-file", "blob", sha], binary=True)
    assert isinstance(raw, bytes)
    if len(raw) != size:
        reject(f"approval blob changed while being read: {path}")
    return raw


def commit_parent(root: Path, commit: str) -> str:
    line = git(root, ["rev-list", "--parents", "-n", "1", commit])
    assert isinstance(line, str)
    parts = line.split()
    if len(parts) != 2 or parts[0] != commit:
        reject(f"ledger commit must have exactly one parent: {commit}")
    if SHA1_RE.fullmatch(parts[1]) is None:
        reject(f"ledger commit parent is invalid: {commit}")
    return parts[1]


def added_path(root: Path, parent: str, commit: str) -> str:
    raw = git(
        root,
        ["diff", "--name-status", "-z", parent, commit, "--"],
        binary=True,
    )
    assert isinstance(raw, bytes)
    fields = raw.split(b"\0")
    if len(fields) != 3 or fields[0] != b"A" or fields[2] != b"":
        reject(
            "each post-genesis commit must add exactly one approval "
            "without changing prior content"
        )
    try:
        path = fields[1].decode("utf-8")
    except UnicodeDecodeError:
        reject("approval path must be UTF-8")
    approval_path(path)
    return path


def verify_checkout(
    root: Path,
    *,
    genesis_sha: str,
    remote_main_sha: str,
) -> str:
    if SHA1_RE.fullmatch(genesis_sha) is None:
        reject("ledger genesis SHA is not pinned")
    if SHA1_RE.fullmatch(remote_main_sha) is None:
        reject("verified ledger remote-main SHA is invalid")
    actual_root = git(root, ["rev-parse", "--show-toplevel"])
    assert isinstance(actual_root, str)
    if Path(actual_root).absolute() != root:
        reject("ledger root argument is not the Git top-level directory")
    if git(root, ["rev-parse", "--is-shallow-repository"]) != "false":
        reject("ledger checkout must contain full ancestry")
    symbolic = git(
        root,
        ["symbolic-ref", "-q", "HEAD"],
        allow_failure=True,
    )
    if symbolic != EXPECTED_REF:
        reject("ledger HEAD must be attached to local main")
    origin = git(root, ["remote", "get-url", "origin"])
    if origin != EXPECTED_ORIGIN:
        reject("ledger origin does not match the fixed repository")
    head = git(root, ["rev-parse", "--verify", "HEAD^{commit}"])
    local_main = git(
        root,
        ["rev-parse", "--verify", "refs/heads/main^{commit}"],
    )
    tracked_main = git(
        root,
        ["rev-parse", "--verify", "refs/remotes/origin/main^{commit}"],
    )
    assert isinstance(head, str)
    if (
        head != local_main
        or head != tracked_main
        or head != remote_main_sha
    ):
        reject("ledger checkout is not the verified remote main head")
    if git(root, ["cat-file", "-t", genesis_sha]) != "commit":
        reject("ledger genesis object is not a commit")
    if not git_succeeds(
        root,
        ["merge-base", "--is-ancestor", genesis_sha, head],
    ):
        reject("ledger genesis is not an ancestor of remote main")
    dirty = git(
        root,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        binary=True,
    )
    assert isinstance(dirty, bytes)
    if dirty:
        reject("ledger checkout must be clean")
    genesis_entries = git(
        root,
        ["ls-tree", "-rz", genesis_sha, "--", "approvals"],
        binary=True,
    )
    assert isinstance(genesis_entries, bytes)
    if genesis_entries:
        reject("ledger genesis must not contain approval entries")
    return head


def replay(
    root: Path,
    *,
    genesis_sha: str,
    head_sha: str,
) -> list[dict[str, Any]]:
    output = git(
        root,
        [
            "rev-list",
            "--reverse",
            "--topo-order",
            f"--max-count={MAX_LEDGER_RECORDS + 1}",
            f"{genesis_sha}..{head_sha}",
        ],
    )
    assert isinstance(output, str)
    commits = output.splitlines() if output else []
    if not commits:
        reject("ledger has no post-genesis approval")
    if len(commits) > MAX_LEDGER_RECORDS:
        reject("ledger exceeds the bounded record count")
    previous_commit = genesis_sha
    previous_manifest_sha256 = ZERO_SHA256
    release_ids: set[str] = set()
    nonces: set[str] = set()
    records: list[dict[str, Any]] = []
    for expected_sequence, commit in enumerate(commits, start=1):
        if SHA1_RE.fullmatch(commit) is None:
            reject("ledger history contains an invalid commit ID")
        parent = commit_parent(root, commit)
        if parent != previous_commit:
            reject("ledger history is not a single linear chain")
        path = added_path(root, parent, commit)
        raw = tree_blob(root, commit, path)
        value = parse_approval(raw, f"approval {path}")
        release_id = value["release_id"]
        nonce = value["nonce"]
        if release_id in release_ids:
            reject(f"release_id is not unique: {release_id}")
        if nonce in nonces:
            reject("approval nonce is not unique")
        release_ids.add(release_id)
        nonces.add(nonce)
        if path != f"approvals/{release_id}.json":
            reject(f"approval filename does not match release_id: {path}")
        ledger = value["ledger"]
        if (
            ledger["genesis_sha"] != genesis_sha
            or ledger["parent_commit_sha"] != parent
            or ledger["sequence"] != expected_sequence
            or ledger["previous_manifest_sha256"]
            != previous_manifest_sha256
        ):
            reject(f"approval ledger link diverges at sequence {expected_sequence}")
        records.append(
            {
                "commit_sha": commit,
                "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                "path": path,
                "value": value,
            }
        )
        previous_commit = commit
        previous_manifest_sha256 = records[-1]["manifest_sha256"]
    if previous_commit != head_sha:
        reject("ledger replay did not terminate at verified remote main")
    return records


def validate(
    root: Path,
    expected_approval: str,
    *,
    genesis_sha: str,
    remote_main_sha: str,
) -> dict[str, Any]:
    """Validate an offline checkout against already trusted immutable SHAs."""

    root = root.absolute()
    try:
        if root.resolve(strict=True) != root or not root.is_dir():
            reject("ledger root must be a real directory without symlinks")
    except OSError:
        reject("ledger root is unavailable")
    expected_path = approval_path(expected_approval).as_posix()
    head = verify_checkout(
        root,
        genesis_sha=genesis_sha,
        remote_main_sha=remote_main_sha,
    )
    records = replay(root, genesis_sha=genesis_sha, head_sha=head)
    current = records[-1]
    if current["path"] != expected_path:
        reject("requested approval is not the record added by ledger HEAD")
    return {
        "approval": current["value"],
        "genesis_sha": genesis_sha,
        "head_sha": head,
        "manifest_sha256": current["manifest_sha256"],
        "record_count": len(records),
    }


def parse_github_ref(raw: bytes) -> str:
    if not 0 < len(raw) <= MAX_APPROVAL_BYTES:
        reject("GitHub ledger main-head response has invalid size")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda item: reject(
                f"GitHub response contains a non-finite number: {item}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject("GitHub ledger main-head response is invalid")
    if not isinstance(value, dict):
        reject("GitHub ledger main-head response contract is invalid")
    target = value.get("object")
    if (
        value.get("ref") != EXPECTED_REF
        or not isinstance(target, dict)
        or target.get("type") != "commit"
        or not isinstance(target.get("sha"), str)
        or SHA1_RE.fullmatch(target["sha"]) is None
    ):
        reject("GitHub ledger main-head response contract is invalid")
    return target["sha"]


def github_main_head(token: str) -> str:
    if not token or any(character.isspace() for character in token):
        reject("read-only GitHub ledger token is unavailable")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{EXPECTED_REPOSITORY}/git/ref/heads/main",
        method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "tratto-control-ledger-validator/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=10) as response:
            if response.status != 200:
                reject("GitHub ledger main-head lookup was rejected")
            raw = response.read(MAX_APPROVAL_BYTES + 1)
    except (OSError, urllib.error.HTTPError, urllib.error.URLError):
        reject("GitHub ledger main-head lookup failed closed")
    return parse_github_ref(raw)


def trusted_remote_main_head() -> str:
    expected_environment = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_REF": EXPECTED_REF,
        "GITHUB_REPOSITORY": EXPECTED_REPOSITORY,
        "GITHUB_SERVER_URL": "https://github.com",
        "RUNNER_ENVIRONMENT": "github-hosted",
    }
    for name, expected in expected_environment.items():
        if os.environ.get(name) != expected:
            reject(f"trusted ledger GitHub context is invalid: {name}")
    remote_main = github_main_head(os.environ.get("GITHUB_TOKEN", ""))
    if os.environ.get("GITHUB_SHA") != remote_main:
        reject("GITHUB_SHA is not the verified ledger remote main head")
    return remote_main


def production_genesis_sha() -> str:
    if SHA1_RE.fullmatch(PINNED_GENESIS_SHA) is None:
        reject("production ledger genesis SHA is not pinned")
    return PINNED_GENESIS_SHA


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "approval",
        help="repository-relative approvals/<release_id>.json at ledger HEAD",
    )
    parser.add_argument(
        "--repository-root",
        required=True,
        type=Path,
        help="checked-out public approval-ledger repository",
    )
    args = parser.parse_args()
    try:
        genesis_sha = production_genesis_sha()
        remote_main_sha = trusted_remote_main_head()
        result = validate(
            args.repository_root,
            args.approval,
            genesis_sha=genesis_sha,
            remote_main_sha=remote_main_sha,
        )
    except LedgerError as error:
        print(f"release ledger rejected: {error}", file=sys.stderr)
        return 78
    print(
        json.dumps(
            {
                "genesis_sha": result["genesis_sha"],
                "head_sha": result["head_sha"],
                "manifest_sha256": result["manifest_sha256"],
                "record_count": result["record_count"],
                "release_id": result["approval"]["release_id"],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
