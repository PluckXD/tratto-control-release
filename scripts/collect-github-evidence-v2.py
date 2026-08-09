#!/usr/bin/env python3
"""Collect bounded read-only GitHub evidence for the v6 offline verifiers.

This collector has no authorization semantics.  It performs only fixed GET
requests, projects the responses into the exact offline evidence documents,
and writes canonical private files.  The independent validators still decide
whether those observations satisfy release policy.
"""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import fcntl
import json
import os
import re
import stat
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping


API_ROOT = "https://api.github.com"
CONTROLLER = "PluckXD/tratto-control-release"
LEDGER = "PluckXD/tratto-control-release-ledger"
ENVIRONMENT = "control-release"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
TAG_RE = re.compile(
    r"^control-controller-v6\.(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)$"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CONTEXT_KEYS = {
    "GITHUB_ACTIONS",
    "GITHUB_API_URL",
    "GITHUB_EVENT_NAME",
    "GITHUB_REF",
    "GITHUB_REF_TYPE",
    "GITHUB_REPOSITORY",
    "GITHUB_REPOSITORY_ID",
    "GITHUB_SERVER_URL",
    "GITHUB_SHA",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_WORKFLOW_SHA",
    "RUNNER_ENVIRONMENT",
}
OUTPUT_KEYS = (
    "commit_sha",
    "release_id",
    "repository_id",
    "tag",
    "tag_object_sha",
)


class GitHubEvidenceV2Error(ValueError):
    """The read-only observation was incomplete, ambiguous, or unsafe."""


def reject(message: str) -> None:
    raise GitHubEvidenceV2Error(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            reject(f"duplicate JSON key in GitHub response: {key}")
        value[key] = item
    return value


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


class GitHubReader:
    """Small fixed-host JSON reader; injectable in unit tests."""

    def __init__(self, token: str) -> None:
        if (
            not token
            or len(token.encode("utf-8")) > 4096
            or any(ord(character) < 33 for character in token)
        ):
            reject("read-only GitHub audit token is unavailable or invalid")
        self._token = token
        self._opener = urllib.request.build_opener(NoRedirect())

    def get(self, path: str) -> Any:
        if (
            not path.startswith("/")
            or "?" in path
            or "#" in path
            or "\\" in path
            or "//" in path
        ):
            reject("GitHub evidence path is not canonical")
        url = API_ROOT + urllib.parse.quote(path, safe="/-._~")
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "tratto-control-release-evidence-v2",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with self._opener.open(request, timeout=20) as response:
                if response.status != 200 or response.geturl() != url:
                    reject("GitHub evidence request was redirected or rejected")
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except GitHubEvidenceV2Error:
            raise
        except (OSError, urllib.error.URLError, urllib.error.HTTPError):
            reject("GitHub evidence request failed closed")
        if not 0 < len(raw) <= MAX_RESPONSE_BYTES:
            reject("GitHub evidence response is empty or oversized")
        try:
            return json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=unique_object,
                parse_constant=lambda item: reject(
                    f"non-finite GitHub JSON number: {item}"
                ),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            reject("GitHub evidence response is not valid UTF-8 JSON")


def exact_object(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        reject(f"{label} GitHub response must be an object")
    return value


def exact_array(value: Any, label: str) -> list[Any]:
    if type(value) is not list:
        reject(f"{label} GitHub response must be an array")
    return value


def repository_projection(value: Any, expected: str) -> dict[str, Any]:
    repository = exact_object(value, f"{expected} repository")
    projected = {
        "full_name": repository.get("full_name"),
        "id": repository.get("id"),
        "private": repository.get("private"),
        "visibility": repository.get("visibility"),
    }
    if projected["full_name"] != expected:
        reject(f"{expected} repository response diverges")
    return projected


def branch_projection(value: Any, repository: str) -> dict[str, Any]:
    branch = exact_object(value, f"{repository} main protection")
    reviews = exact_object(
        branch.get("required_pull_request_reviews"),
        f"{repository} pull-request reviews",
    )
    raw_bypass = reviews.get("bypass_pull_request_allowances")
    if raw_bypass is None:
        bypass: dict[str, Any] = {"apps": [], "teams": [], "users": []}
    else:
        observed = exact_object(
            raw_bypass,
            f"{repository} review bypass allowances",
        )
        bypass = {
            bucket: exact_array(
                observed.get(bucket),
                f"{repository} review bypass {bucket}",
            )
            for bucket in ("apps", "teams", "users")
        }
    return {
        "allow_deletions": branch.get("allow_deletions"),
        "allow_force_pushes": branch.get("allow_force_pushes"),
        "enforce_admins": branch.get("enforce_admins"),
        "required_linear_history": branch.get("required_linear_history"),
        "required_pull_request_reviews": {
            "bypass_pull_request_allowances": bypass,
            "dismiss_stale_reviews": reviews.get("dismiss_stale_reviews"),
            "require_code_owner_reviews": reviews.get(
                "require_code_owner_reviews"
            ),
            "require_last_push_approval": reviews.get(
                "require_last_push_approval"
            ),
            "required_approving_review_count": reviews.get(
                "required_approving_review_count"
            ),
        },
    }


def collect_rulesets(reader: GitHubReader, repository: str) -> list[Any]:
    summaries = exact_array(
        reader.get(f"/repos/{repository}/rulesets"),
        f"{repository} rulesets",
    )
    details: list[Any] = []
    seen: set[int] = set()
    for summary_value in summaries:
        summary = exact_object(summary_value, f"{repository} ruleset summary")
        ruleset_id = summary.get("id")
        if type(ruleset_id) is not int or ruleset_id <= 0 or ruleset_id in seen:
            reject(f"{repository} ruleset id is invalid or duplicated")
        seen.add(ruleset_id)
        details.append(
            reader.get(f"/repos/{repository}/rulesets/{ruleset_id}")
        )
    return details


def collect_control_documents(reader: GitHubReader) -> tuple[dict[str, Any], dict[str, Any]]:
    immutable = exact_object(
        reader.get(f"/repos/{CONTROLLER}/immutable-releases"),
        "controller immutable releases",
    )
    controller = {
        "actions": reader.get(f"/repos/{CONTROLLER}/actions/permissions"),
        "branch_protection": branch_projection(
            reader.get(f"/repos/{CONTROLLER}/branches/main/protection"),
            CONTROLLER,
        ),
        "environment": reader.get(
            f"/repos/{CONTROLLER}/environments/{ENVIRONMENT}"
        ),
        "immutable_releases": immutable,
        "repository": repository_projection(
            reader.get(f"/repos/{CONTROLLER}"),
            CONTROLLER,
        ),
        "selected_actions": reader.get(
            f"/repos/{CONTROLLER}/actions/permissions/selected-actions"
        ),
        "signatures": reader.get(
            f"/repos/{CONTROLLER}/branches/main/protection/required_signatures"
        ),
    }
    ledger = {
        "branch_protection": branch_projection(
            reader.get(f"/repos/{LEDGER}/branches/main/protection"),
            LEDGER,
        ),
        "main_rulesets": collect_rulesets(reader, LEDGER),
        "repository": repository_projection(
            reader.get(f"/repos/{LEDGER}"),
            LEDGER,
        ),
        "signatures": reader.get(
            f"/repos/{LEDGER}/branches/main/protection/required_signatures"
        ),
    }
    return controller, ledger


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
        reject("local controller tag observation failed")
    if result.returncode != 0:
        reject("local controller tag observation failed")
    try:
        return result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        reject("local controller tag output is not UTF-8")


def collect_tag_documents(
    reader: GitHubReader,
    root: Path,
    environment: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    context = {name: environment.get(name, "") for name in CONTEXT_KEYS}
    if any(not value for value in context.values()):
        reject("GitHub workflow context is incomplete")
    ref = context["GITHUB_REF"]
    prefix = "refs/tags/"
    if not ref.startswith(prefix):
        reject("controller execution is not on a direct tag")
    tag = ref[len(prefix):]
    if TAG_RE.fullmatch(tag) is None:
        reject("controller tag is not canonical v6")
    absolute = root.absolute()
    try:
        if absolute.resolve(strict=True) != absolute:
            reject("controller checkout must not traverse symlinks")
    except OSError:
        reject("controller checkout is unavailable")
    object_sha = git(absolute, ["rev-parse", "--verify", f"{ref}^{{tag}}"])
    commit_sha = git(absolute, ["rev-parse", "--verify", f"{ref}^{{commit}}"])
    if SHA_RE.fullmatch(object_sha) is None or SHA_RE.fullmatch(commit_sha) is None:
        reject("local controller tag object identity is invalid")
    local_tag = {
        "commit_sha": commit_sha,
        "object_sha": object_sha,
        "object_type": git(absolute, ["cat-file", "-t", object_sha]),
        "ref": ref,
    }
    release = reader.get(f"/repos/{CONTROLLER}/releases/tags/{tag}")
    immutable = reader.get(f"/repos/{CONTROLLER}/immutable-releases")
    return {
        "controller-context.json": context,
        "controller-immutable-releases.json": exact_object(
            immutable,
            "controller immutable releases",
        ),
        "controller-local-tag.json": local_tag,
        "controller-release.json": exact_object(
            release,
            "controller release",
        ),
    }


def safe_output_directory(path: Path) -> Path:
    absolute = path.absolute()
    try:
        if absolute.resolve(strict=True) != absolute:
            reject("evidence output directory must not traverse symlinks")
        info = absolute.lstat()
    except GitHubEvidenceV2Error:
        raise
    except OSError:
        reject("evidence output directory is unavailable")
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        reject("evidence output directory must be owned and private")
    return absolute


def write_once(directory: Path, name: str, value: Any) -> None:
    if Path(name).name != name or not name.endswith(".json"):
        reject("evidence output name is invalid")
    path = directory / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    payload = canonical_bytes(value)
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except OSError:
        reject(f"cannot publish evidence file safely: {name}")


def metadata_snapshot(info: os.stat_result) -> tuple[int, ...]:
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


def append_outputs(path: Path, values: Mapping[str, str]) -> None:
    if set(values) != set(OUTPUT_KEYS):
        reject("controller evidence output keys diverge")
    if (
        SHA_RE.fullmatch(values["commit_sha"]) is None
        or SHA_RE.fullmatch(values["tag_object_sha"]) is None
        or TAG_RE.fullmatch(values["tag"]) is None
        or re.fullmatch(r"[1-9][0-9]*", values["release_id"]) is None
        or re.fullmatch(r"[1-9][0-9]*", values["repository_id"]) is None
    ):
        reject("controller evidence output value is invalid")
    payload = "".join(
        f"{key}={values[key]}\n" for key in OUTPUT_KEYS
    ).encode("ascii")
    absolute = path.absolute()
    descriptor = -1
    locked = False
    try:
        if absolute.resolve(strict=True) != absolute:
            reject("GITHUB_OUTPUT path must not traverse symlinks")
        before_path = absolute.lstat()
        if (
            not stat.S_ISREG(before_path.st_mode)
            or before_path.st_nlink != 1
            or before_path.st_uid != os.geteuid()
            or stat.S_IMODE(before_path.st_mode) & 0o022
            or not stat.S_IMODE(before_path.st_mode) & 0o200
            or before_path.st_size + len(payload) > 1024 * 1024
        ):
            reject("GITHUB_OUTPUT is not one bounded private writable file")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(absolute, flags)
        before = os.fstat(descriptor)
        if metadata_snapshot(before) != metadata_snapshot(before_path):
            reject("GITHUB_OUTPUT changed before append")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = True
        if metadata_snapshot(os.fstat(descriptor)) != metadata_snapshot(before):
            reject("GITHUB_OUTPUT changed while acquiring append lock")
        if os.write(descriptor, payload) != len(payload):
            reject("GITHUB_OUTPUT append was incomplete")
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if (
            after.st_size != before.st_size + len(payload)
            or (after.st_dev, after.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            reject("GITHUB_OUTPUT changed during append")
        try:
            after_path = absolute.lstat()
        except OSError:
            reject("GITHUB_OUTPUT pathname changed during append")
        if metadata_snapshot(after_path) != metadata_snapshot(after):
            reject("GITHUB_OUTPUT pathname changed during append")
    except GitHubEvidenceV2Error:
        raise
    except OSError:
        reject("GITHUB_OUTPUT append failed closed")
    finally:
        if descriptor >= 0:
            if locked:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
            os.close(descriptor)


class FailClosedParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        reject(f"invalid command line: {message}")


def main(arguments: list[str] | None = None) -> int:
    parser = FailClosedParser()
    parser.add_argument("--controller-root", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--github-output", required=True, type=Path)
    try:
        args = parser.parse_args(arguments)
        reader = GitHubReader(
            os.environ.get("CONTROL_CONTROLLER_AUDIT_TOKEN", "")
        )
        output = safe_output_directory(args.output_directory)
        controller, ledger = collect_control_documents(reader)
        tag_documents = collect_tag_documents(
            reader,
            args.controller_root,
            os.environ,
        )
        documents = {
            "controller-controls-v2.json": controller,
            "ledger-controls-v2.json": ledger,
            **tag_documents,
        }
        for name in sorted(documents):
            write_once(output, name, documents[name])
        release = tag_documents["controller-release.json"]
        local_tag = tag_documents["controller-local-tag.json"]
        repository = controller["repository"]
        if (
            type(release.get("id")) is not int
            or type(repository.get("id")) is not int
        ):
            reject("controller release or repository numeric identity is absent")
        append_outputs(
            args.github_output,
            {
                "commit_sha": local_tag["commit_sha"],
                "release_id": str(release["id"]),
                "repository_id": str(repository["id"]),
                "tag": local_tag["ref"].removeprefix("refs/tags/"),
                "tag_object_sha": local_tag["object_sha"],
            },
        )
    except GitHubEvidenceV2Error as error:
        print(f"GitHub evidence v2 rejected: {error}", file=sys.stderr)
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
