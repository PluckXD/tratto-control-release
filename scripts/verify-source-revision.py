#!/usr/bin/env python3
"""Verify that an approved product revision is the exact private main head."""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import os
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "control_release_validator",
    HERE / "validate-approval.py",
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("source revision verifier unavailable")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


def run_git(root: Path, arguments: list[str], *, allow_failure: bool = False) -> str:
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
        VALIDATOR.reject("source Git verification failed")
    if result.returncode and not allow_failure:
        VALIDATOR.reject("source revision is absent or not an ancestor")
    return result.stdout.decode("utf-8", errors="strict").strip()


def verify(
    checkout: Path,
    component: str,
    value: dict,
    *,
    remote_main_sha: str,
) -> None:
    expected = value[component]
    expected_repository = VALIDATOR.EXPECTED_REPOSITORIES[component]
    root = checkout.absolute()
    try:
        if root.resolve(strict=True) != root or not root.is_dir():
            VALIDATOR.reject(
                "source checkout must be a real directory without symlinks"
            )
    except OSError:
        VALIDATOR.reject("source checkout is unavailable")
    top = run_git(root, ["rev-parse", "--show-toplevel"])
    if Path(top).absolute() != root:
        VALIDATOR.reject("source checkout is not its Git top-level")
    if run_git(root, ["rev-parse", "--is-shallow-repository"]) != "false":
        VALIDATOR.reject("source checkout must contain full ancestry")
    origin = run_git(root, ["remote", "get-url", "origin"])
    allowed_origins = {
        f"git@github.com:{expected_repository}.git",
        f"https://github.com/{expected_repository}.git",
    }
    if origin not in allowed_origins:
        VALIDATOR.reject("source origin does not match the approved repository")
    if run_git(root, ["status", "--porcelain=v1", "--untracked-files=all"]):
        VALIDATOR.reject("source checkout is dirty")
    if run_git(root, ["rev-parse", "HEAD^{commit}"]) != expected["commit_sha"]:
        VALIDATOR.reject("source HEAD does not match the approved commit")
    main = run_git(
        root,
        ["rev-parse", "refs/remotes/origin/main^{commit}"],
    )
    VALIDATOR.require_pattern(
        remote_main_sha,
        VALIDATOR.SHA1_RE,
        "verified source main sha",
    )
    if (
        main != expected["commit_sha"]
        or remote_main_sha != expected["commit_sha"]
    ):
        VALIDATOR.reject("approved commit is not the exact fetched main head")
    if run_git(root, ["cat-file", "-t", expected["commit_sha"]]) != "commit":
        VALIDATOR.reject("approved source object is not a commit")
    for ancestor in expected["required_ancestors"]:
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
                expected["commit_sha"],
            ],
            cwd=root,
            env={
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
                "PATH": os.environ.get("PATH", ""),
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )
        if result.returncode != 0:
            VALIDATOR.reject(
                f"{component} required ancestor is absent from approved commit"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--approval",
        required=True,
        help="repository-relative approvals/*.json",
    )
    parser.add_argument(
        "--controller-root",
        required=True,
        type=Path,
    )
    parser.add_argument("--component", required=True, choices=("api", "ops", "web"))
    parser.add_argument("--checkout", required=True, type=Path)
    args = parser.parse_args()
    try:
        value = VALIDATOR.validate(
            args.controller_root.absolute(),
            args.approval,
            now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0),
            remote_main_sha=VALIDATOR.trusted_controller_main_head(),
        )
        source_remote_main = VALIDATOR.github_main_head(
            VALIDATOR.EXPECTED_REPOSITORIES[args.component],
            os.environ.get("CONTROL_SOURCE_READ_TOKEN", ""),
        )
        verify(
            args.checkout,
            args.component,
            value,
            remote_main_sha=source_remote_main,
        )
    except (OSError, VALIDATOR.ApprovalError) as error:
        print(f"source revision rejected: {error}", file=sys.stderr)
        return 78
    print(
        f"{args.component} source revision verified: "
        f"{value[args.component]['commit_sha']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
