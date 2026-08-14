#!/usr/bin/env python3
"""Verify a prepared product checkout against one canonical approval-v2.

The checkout must have been made from ``main`` by the reviewed checkout
action before product code runs.  This verifier is intentionally offline: it
accepts no token and treats the exact ``HEAD`` plus the fetched
``refs/remotes/origin/main`` as one inseparable observation.
"""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import datetime as dt
import importlib.util
import json
import os
import subprocess
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "control_release_source_approval_v2",
    HERE / "validate-approval-v2.py",
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("approval-v2 validator unavailable")
APPROVAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APPROVAL)


class SourceRevisionV2Error(ValueError):
    """The source checkout is not the exact authorized main revision."""


def reject(message: str) -> None:
    raise SourceRevisionV2Error(message)


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
    except (OSError, subprocess.TimeoutExpired):
        reject("source Git observation failed")
    if result.returncode != 0:
        reject("source Git observation failed")
    try:
        return result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        reject("source Git output is not UTF-8")


def load_approval(path: Path) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = APPROVAL.read_approval(path)
        value = APPROVAL.validate_bytes(
            raw,
            now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0),
            historical=False,
        )
    except (OSError, APPROVAL.ApprovalV2Error) as error:
        reject(f"approval-v2 is invalid: {error}")
    return raw, value


def verify(
    checkout: Path,
    component: str,
    approval: dict[str, Any],
) -> dict[str, Any]:
    expected = approval[component]
    root = checkout.absolute()
    try:
        if root.resolve(strict=True) != root or not root.is_dir():
            reject("source checkout must be a real directory without symlinks")
    except OSError:
        reject("source checkout is unavailable")
    top = Path(git(root, ["rev-parse", "--show-toplevel"])).absolute()
    if top != root:
        reject("source checkout is not its Git top-level")
    if git(root, ["rev-parse", "--is-shallow-repository"]) != "false":
        reject("source checkout must contain full ancestry")
    allowed_origins = {
        f"git@github.com:{expected['repository']}.git",
        f"https://github.com/{expected['repository']}.git",
    }
    if git(root, ["remote", "get-url", "origin"]) not in allowed_origins:
        reject("source origin does not match approval-v2")
    if git(root, ["status", "--porcelain=v1", "--untracked-files=all"]):
        reject("source checkout is dirty")

    approved_sha = expected["commit_sha"]
    head = git(root, ["rev-parse", "--verify", "HEAD^{commit}"])
    remote_main = git(
        root,
        ["rev-parse", "--verify", "refs/remotes/origin/main^{commit}"],
    )
    if head != approved_sha or remote_main != approved_sha:
        reject("approval-v2 is not the exact fetched main head")
    if git(root, ["cat-file", "-t", approved_sha]) != "commit":
        reject("approved source object is not a commit")
    for ancestor in expected["required_ancestors"]:
        try:
            result = subprocess.run(
                [
                    "git",
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "merge-base",
                    "--is-ancestor",
                    ancestor,
                    approved_sha,
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
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            reject("required source ancestry observation failed")
        if result.returncode != 0:
            reject("required source ancestor is absent")
    tree_sha = git(root, ["rev-parse", f"{approved_sha}^{{tree}}"])
    APPROVAL.require_pattern(tree_sha, APPROVAL.SHA1_RE, "source tree SHA")
    return {
        "approved_ref": expected["approved_ref"],
        "commit_sha": approved_sha,
        "component": component,
        "remote_main_sha": remote_main,
        "repository": expected["repository"],
        "tree_sha": tree_sha,
    }


class FailClosedParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        reject(f"invalid command line: {message}")


def main(arguments: list[str] | None = None) -> int:
    parser = FailClosedParser()
    parser.add_argument("--approval", required=True, type=Path)
    parser.add_argument(
        "--component",
        required=True,
        choices=("api", "ops", "web"),
    )
    parser.add_argument("--checkout", required=True, type=Path)
    try:
        args = parser.parse_args(arguments)
        _, approval = load_approval(args.approval)
        attestation = verify(args.checkout, args.component, approval)
    except (SourceRevisionV2Error, APPROVAL.ApprovalV2Error) as error:
        print(f"source revision v2 rejected: {error}", file=sys.stderr)
        return 78
    sys.stdout.buffer.write(canonical_bytes(attestation))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
