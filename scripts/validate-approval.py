#!/usr/bin/env python3
"""Validate one append-only Control release authorization.

The candidate must be the only file added by the current, single-parent Git
commit. Replay history is read from the immutable parent tree, never from a
caller-selected directory or a symlinkable working-tree path.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any


SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RELEASE_ID_RE = re.compile(
    r"^ctl-([0-9]{8}T[0-9]{6}Z)-([a-z0-9][a-z0-9-]{2,31})$"
)
POLICY_NAME_RE = re.compile(r"^control-[a-z0-9][a-z0-9-]{2,63}$")
REVISION_RE = re.compile(r"^[a-z0-9][a-z0-9_]{2,63}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22,86}$")
TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-(0[1-9]|1[0-2])-"
    r"(0[1-9]|[12][0-9]|3[01])T"
    r"([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
TOP_KEYS = {
    "api",
    "controller",
    "expires_at",
    "issued_at",
    "migration",
    "nonce",
    "ops",
    "policy",
    "release_id",
    "schema_version",
    "web",
}
COMPONENT_KEYS = {
    "approved_ref",
    "commit_sha",
    "repository",
    "required_ancestors",
}
CONTROLLER_KEYS = {
    "approved_ref",
    "base_sha",
    "repository",
    "workflow_path",
    "workflow_sha256",
}
MIGRATION_KEYS = {
    "base_revision",
    "database_scope",
    "fleet_preflight_sha256",
    "head_revision",
    "mode",
    "tenant_catalog_count",
    "tenant_catalog_sha256",
    "tenant_fleet_base_revision",
}
POLICY_KEYS = {"digest_sha256", "name", "path", "repository"}
POLICY_DOCUMENT_KEYS = {
    "approval_max_seconds",
    "approval_path_prefix",
    "artifact_transport",
    "carrier_authorizes_release",
    "carrier_repository",
    "carrier_trust",
    "controller_repository",
    "migration_database_scope",
    "product_repositories",
    "required_ref",
    "schema_version",
    "signer_allows_product_credentials",
    "signer_allows_source_checkout",
}
EXPECTED_REPOSITORIES = {
    "api": "PluckXD/tratto-api",
    "ops": "PluckXD/tratto-api",
    "web": "PluckXD/tratto-web",
}
EXPECTED_CONTROLLER_REPOSITORY = "PluckXD/tratto-control-release"
EXPECTED_CARRIER_REPOSITORY = "PluckXD/tratto-control-release-carrier"
EXPECTED_CONTROLLER_ORIGIN = (
    "https://github.com/PluckXD/tratto-control-release.git"
)
EXPECTED_REF = "refs/heads/main"
EXPECTED_WORKFLOW_PATH = ".github/workflows/control-release.yml"
EXPECTED_POLICY_PATH = "policies/control-production-v1.json"
MAX_FILE_BYTES = 64 * 1024
MAX_VALIDITY = dt.timedelta(hours=24)
MAX_FUTURE_SKEW = dt.timedelta(minutes=5)


class ApprovalError(ValueError):
    """The authorization is ambiguous or violates release policy."""


def reject(message: str) -> None:
    raise ApprovalError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            reject(f"duplicate key: {key}")
        value[key] = item
    return value


def parse_json(raw: bytes, label: str) -> dict[str, Any]:
    if len(raw) > MAX_FILE_BYTES:
        reject(f"{label} exceeds {MAX_FILE_BYTES} bytes")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        reject(f"{label} must be UTF-8")
    try:
        value = json.loads(
            decoded,
            object_pairs_hook=unique_object,
            parse_constant=lambda constant: reject(
                f"non-finite number is forbidden: {constant}"
            ),
        )
    except json.JSONDecodeError as error:
        reject(
            f"{label} has invalid JSON at line {error.lineno}, "
            f"column {error.colno}"
        )
    if not isinstance(value, dict):
        reject(f"{label} root must be an object")
    return value


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


def require_canonical(raw: bytes, value: dict[str, Any], label: str) -> None:
    if raw != canonical_bytes(value):
        reject(f"{label} must be canonical JSON")


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        reject(
            f"{label} keys diverge; "
            f"missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        reject(f"{label} must be a string")
    return value


def require_pattern(value: Any, pattern: re.Pattern[str], label: str) -> str:
    text = require_string(value, label)
    if pattern.fullmatch(text) is None:
        reject(f"{label} has invalid format")
    return text


def parse_utc(value: Any, label: str) -> dt.datetime:
    text = require_string(value, label)
    if TIMESTAMP_RE.fullmatch(text) is None:
        reject(f"{label} must be whole-second RFC3339 UTC")
    try:
        parsed = dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        reject(f"{label} is not a real calendar timestamp")
    return parsed.replace(tzinfo=dt.timezone.utc)


def validate_nonce(value: Any, label: str = "nonce") -> str:
    nonce = require_pattern(value, NONCE_RE, label)
    padding = "=" * (-len(nonce) % 4)
    try:
        decoded = base64.b64decode(
            nonce + padding,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error):
        reject(f"{label} is not canonical base64url")
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != nonce or len(decoded) < 16:
        reject(f"{label} must encode at least 128 bits as canonical base64url")
    return nonce


def read_candidate(root: Path, relative: str) -> bytes:
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or len(pure.parts) != 2
        or pure.parts[0] != "approvals"
        or pure.parts[1] in {"", ".", ".."}
        or not pure.parts[1].endswith(".json")
    ):
        reject("approval path must be approvals/<release-id>.json")
    flags = os.O_RDONLY | os.O_CLOEXEC
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(root / "approvals", flags)
    except OSError as error:
        reject(f"cannot open approvals directory safely: {error.strerror}")
    try:
        directory_metadata = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(directory_metadata.st_mode) not in {0o700, 0o750, 0o755}
        ):
            reject("approvals directory ownership or mode is unsafe")
        file_flags = os.O_RDONLY | os.O_CLOEXEC
        file_flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(
                pure.parts[1],
                file_flags,
                dir_fd=directory_fd,
            )
        except OSError as error:
            reject(f"cannot open approval safely: {error.strerror}")
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o644
                or metadata.st_nlink != 1
            ):
                reject(
                    "approval must be a single-link 0644 regular file "
                    "owned by the runner"
                )
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(65536, MAX_FILE_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_FILE_BYTES:
                    reject("approval exceeds maximum size")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_fd)


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
        reject(
            "Git verification rejected: "
            + result.stderr.decode("utf-8", errors="replace").strip()[:300]
        )
    if binary:
        return result.stdout
    return result.stdout.decode("utf-8", errors="strict").strip()


def git_blob(root: Path, revision: str, path: str) -> bytes:
    entry = git(root, ["ls-tree", "-z", revision, "--", path], binary=True)
    assert isinstance(entry, bytes)
    records = [item for item in entry.split(b"\0") if item]
    if len(records) != 1:
        reject(f"required controller blob is absent or ambiguous: {path}")
    try:
        metadata, encoded_path = records[0].split(b"\t", 1)
        mode, object_type, object_sha = metadata.split(b" ", 2)
        decoded_path = encoded_path.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        reject(f"invalid Git tree record for {path}")
    if (
        mode != b"100644"
        or object_type != b"blob"
        or decoded_path != path
        or SHA1_RE.fullmatch(object_sha.decode("ascii", errors="ignore")) is None
    ):
        reject(f"controller blob must be a regular 0644 file: {path}")
    payload = git(root, ["cat-file", "blob", object_sha.decode("ascii")], binary=True)
    assert isinstance(payload, bytes)
    if len(payload) > MAX_FILE_BYTES:
        reject(f"controller blob exceeds maximum size: {path}")
    return payload


def github_main_head(repository: str, token: str) -> str:
    if repository not in {
        EXPECTED_CONTROLLER_REPOSITORY,
        *EXPECTED_REPOSITORIES.values(),
    }:
        reject("GitHub repository is outside the release allowlist")
    if not token or any(character.isspace() for character in token):
        reject("read-only GitHub token is unavailable")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/git/ref/heads/main",
        method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "tratto-control-release-validator/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=10) as response:
            if response.status != 200:
                reject("GitHub main-head lookup was rejected")
            raw = response.read(MAX_FILE_BYTES + 1)
    except (OSError, urllib.error.HTTPError, urllib.error.URLError):
        reject("GitHub main-head lookup failed closed")
    if len(raw) > MAX_FILE_BYTES:
        reject("GitHub main-head response is oversized")
    value = parse_json(raw, "GitHub main-head response")
    object_value = value.get("object")
    if (
        value.get("ref") != "refs/heads/main"
        or not isinstance(object_value, dict)
        or object_value.get("type") != "commit"
    ):
        reject("GitHub main-head response has an invalid contract")
    return require_pattern(
        object_value.get("sha"),
        SHA1_RE,
        "GitHub main-head sha",
    )


def trusted_controller_main_head() -> str:
    expected_environment = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": EXPECTED_CONTROLLER_REPOSITORY,
        "GITHUB_SERVER_URL": "https://github.com",
        "RUNNER_ENVIRONMENT": "github-hosted",
    }
    for name, expected in expected_environment.items():
        if os.environ.get(name) != expected:
            reject(f"trusted GitHub context is invalid: {name}")
    remote_main_sha = github_main_head(
        EXPECTED_CONTROLLER_REPOSITORY,
        os.environ.get("GITHUB_TOKEN", ""),
    )
    if os.environ.get("GITHUB_SHA") != remote_main_sha:
        reject("GITHUB_SHA is not the verified remote main head")
    return remote_main_sha


def validate_component(name: str, value: Any) -> None:
    if not isinstance(value, dict):
        reject(f"{name} must be an object")
    exact_keys(value, COMPONENT_KEYS, name)
    if value["repository"] != EXPECTED_REPOSITORIES[name]:
        reject(f"{name}.repository is not allowed")
    if value["approved_ref"] != EXPECTED_REF:
        reject(f"{name}.approved_ref must be refs/heads/main")
    commit = require_pattern(value["commit_sha"], SHA1_RE, f"{name}.commit_sha")
    ancestors = value["required_ancestors"]
    if (
        not isinstance(ancestors, list)
        or isinstance(ancestors, (str, bytes))
        or not 1 <= len(ancestors) <= 32
    ):
        reject(f"{name}.required_ancestors must contain 1..32 SHAs")
    checked = [
        require_pattern(item, SHA1_RE, f"{name}.required_ancestors[{index}]")
        for index, item in enumerate(ancestors)
    ]
    if len(checked) != len(set(checked)):
        reject(f"{name}.required_ancestors contains duplicates")
    if commit in checked:
        reject(f"{name}.commit_sha cannot duplicate a required ancestor")


def validate_controller(value: Any) -> None:
    if not isinstance(value, dict):
        reject("controller must be an object")
    exact_keys(value, CONTROLLER_KEYS, "controller")
    if value["repository"] != EXPECTED_CONTROLLER_REPOSITORY:
        reject("controller.repository is not allowed")
    if value["approved_ref"] != EXPECTED_REF:
        reject("controller.approved_ref must be refs/heads/main")
    require_pattern(value["base_sha"], SHA1_RE, "controller.base_sha")
    if value["workflow_path"] != EXPECTED_WORKFLOW_PATH:
        reject("controller.workflow_path is not allowed")
    require_pattern(
        value["workflow_sha256"],
        SHA256_RE,
        "controller.workflow_sha256",
    )


def validate_migration(value: Any) -> None:
    if not isinstance(value, dict):
        reject("migration must be an object")
    exact_keys(value, MIGRATION_KEYS, "migration")
    if value["database_scope"] != "control-and-tenant-fleet":
        reject(
            "migration.database_scope must be control-and-tenant-fleet"
        )
    if value["mode"] != "expand-only":
        reject("migration.mode must be expand-only")
    base = require_pattern(
        value["base_revision"], REVISION_RE, "migration.base_revision"
    )
    head = require_pattern(
        value["head_revision"], REVISION_RE, "migration.head_revision"
    )
    tenant_base = require_pattern(
        value["tenant_fleet_base_revision"],
        REVISION_RE,
        "migration.tenant_fleet_base_revision",
    )
    if (
        base != "j1transpcod"
        or tenant_base != "j1transpcod"
        or head != "f29controlexec"
    ):
        reject("migration revision chain is not approved")
    require_pattern(
        value["tenant_catalog_sha256"],
        SHA256_RE,
        "migration.tenant_catalog_sha256",
    )
    require_pattern(
        value["fleet_preflight_sha256"],
        SHA256_RE,
        "migration.fleet_preflight_sha256",
    )
    count = value["tenant_catalog_count"]
    if type(count) is not int or not 1 <= count <= 512:
        reject("migration tenant catalog count is invalid")


def validate_policy(value: Any) -> None:
    if not isinstance(value, dict):
        reject("policy must be an object")
    exact_keys(value, POLICY_KEYS, "policy")
    if value["repository"] != EXPECTED_CONTROLLER_REPOSITORY:
        reject("policy.repository is not allowed")
    if value["path"] != EXPECTED_POLICY_PATH:
        reject("policy.path is not allowed")
    name = require_pattern(value["name"], POLICY_NAME_RE, "policy.name")
    if name != "control-production-v1":
        reject("policy.name is not allowed")
    require_pattern(value["digest_sha256"], SHA256_RE, "policy.digest_sha256")


def validate_shape(
    value: dict[str, Any],
    *,
    now: dt.datetime | None,
    historical: bool,
) -> tuple[str, str]:
    exact_keys(value, TOP_KEYS, "authorization")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        reject("schema_version must be integer 1")
    release_id = require_pattern(
        value["release_id"], RELEASE_ID_RE, "release_id"
    )
    nonce = validate_nonce(value["nonce"])
    issued_at = parse_utc(value["issued_at"], "issued_at")
    expires_at = parse_utc(value["expires_at"], "expires_at")
    if expires_at <= issued_at or expires_at - issued_at > MAX_VALIDITY:
        reject("authorization validity must be between 1 second and 24 hours")
    match = RELEASE_ID_RE.fullmatch(release_id)
    assert match is not None
    expected_stamp = issued_at.strftime("%Y%m%dT%H%M%SZ")
    if match.group(1) != expected_stamp:
        reject("release_id timestamp must equal issued_at")
    if not historical:
        if now is None or now.tzinfo != dt.timezone.utc:
            reject("validator clock must be timezone-aware UTC")
        if issued_at > now + MAX_FUTURE_SKEW:
            reject("authorization issued_at is too far in the future")
        if expires_at <= now:
            reject("authorization is expired")
    validate_component("api", value["api"])
    validate_component("web", value["web"])
    validate_component("ops", value["ops"])
    if (
        value["api"]["repository"] == value["ops"]["repository"]
        and value["api"]["commit_sha"] != value["ops"]["commit_sha"]
    ):
        reject("api and ops must pin the same commit in their shared repository")
    validate_controller(value["controller"])
    validate_migration(value["migration"])
    validate_policy(value["policy"])
    return release_id, nonce


def validate_policy_blob(raw: bytes, expected_digest: str) -> None:
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        reject("policy digest does not match the controller base blob")
    value = parse_json(raw, "policy")
    require_canonical(raw, value, "policy")
    exact_keys(value, POLICY_DOCUMENT_KEYS, "policy")
    expected = {
        "approval_max_seconds": 86400,
        "approval_path_prefix": "approvals/",
        "artifact_transport": "private-untrusted-carrier",
        "carrier_authorizes_release": False,
        "carrier_repository": EXPECTED_CARRIER_REPOSITORY,
        "carrier_trust": "transport-only",
        "controller_repository": EXPECTED_CONTROLLER_REPOSITORY,
        "migration_database_scope": "control-and-tenant-fleet",
        "product_repositories": [
            "PluckXD/tratto-api",
            "PluckXD/tratto-web",
        ],
        "required_ref": EXPECTED_REF,
        "schema_version": 1,
        "signer_allows_product_credentials": False,
        "signer_allows_source_checkout": False,
    }
    if (
        type(value["schema_version"]) is not int
        or type(value["approval_max_seconds"]) is not int
        or type(value["carrier_authorizes_release"]) is not bool
        or type(value["signer_allows_product_credentials"]) is not bool
        or type(value["signer_allows_source_checkout"]) is not bool
        or not isinstance(value["product_repositories"], list)
        or not all(
            isinstance(repository, str)
            for repository in value["product_repositories"]
        )
    ):
        reject("policy document field types diverge from the enforced contract")
    if value != expected:
        reject("policy document values diverge from the enforced contract")


def historical_authorizations(
    root: Path,
    base_sha: str,
) -> set[tuple[str, str]]:
    output = git(
        root,
        ["ls-tree", "-rz", base_sha, "--", "approvals"],
        binary=True,
    )
    assert isinstance(output, bytes)
    pairs: set[tuple[str, str]] = set()
    release_ids: set[str] = set()
    nonces: set[str] = set()
    for record in [item for item in output.split(b"\0") if item]:
        try:
            metadata, encoded_path = record.split(b"\t", 1)
            mode, object_type, object_sha = metadata.split(b" ", 2)
            path = encoded_path.decode("utf-8")
            sha = object_sha.decode("ascii")
        except (ValueError, UnicodeDecodeError):
            reject("invalid approval history tree record")
        if (
            mode != b"100644"
            or object_type != b"blob"
            or SHA1_RE.fullmatch(sha) is None
            or not path.startswith("approvals/")
            or PurePosixPath(path).parent != PurePosixPath("approvals")
            or not path.endswith(".json")
        ):
            reject(f"approval history contains a forbidden entry: {path}")
        raw = git(root, ["cat-file", "blob", sha], binary=True)
        assert isinstance(raw, bytes)
        value = parse_json(raw, f"history {path}")
        require_canonical(raw, value, f"history {path}")
        release_id, nonce = validate_shape(value, now=None, historical=True)
        if path != f"approvals/{release_id}.json":
            reject(f"history filename does not match release_id: {path}")
        if release_id in release_ids:
            reject(f"duplicate historical release_id: {release_id}")
        if nonce in nonces:
            reject("duplicate historical nonce")
        pair = (release_id, nonce)
        if pair in pairs:
            reject(f"duplicate historical authorization: {release_id}")
        release_ids.add(release_id)
        nonces.add(nonce)
        pairs.add(pair)
    return pairs


def verify_controller_commit(
    root: Path,
    relative: str,
    value: dict[str, Any],
    candidate_raw: bytes,
    remote_main_sha: str,
) -> None:
    base_sha = value["controller"]["base_sha"]
    head = git(root, ["rev-parse", "--verify", "HEAD^{commit}"])
    assert isinstance(head, str)
    main_head = git(
        root,
        ["rev-parse", "--verify", "refs/heads/main^{commit}"],
    )
    assert isinstance(main_head, str)
    if head != main_head:
        reject("approval commit must be the checked-out local main head")
    if git(root, ["rev-parse", "--is-shallow-repository"]) != "false":
        reject("controller checkout must contain full ancestry")
    origin = git(root, ["remote", "get-url", "origin"])
    assert isinstance(origin, str)
    if origin != EXPECTED_CONTROLLER_ORIGIN:
        reject("controller origin does not match the declared repository")
    tracked_main = git(
        root,
        ["rev-parse", "--verify", "refs/remotes/origin/main^{commit}"],
    )
    assert isinstance(tracked_main, str)
    if head != tracked_main or head != remote_main_sha:
        reject("controller checkout is not the verified remote main head")
    parents = git(root, ["rev-list", "--parents", "-n", "1", head])
    assert isinstance(parents, str)
    parts = parents.split()
    if len(parts) != 2 or parts != [head, base_sha]:
        reject("approval commit must have controller.base_sha as its only parent")
    diff = git(
        root,
        ["diff", "--name-status", "-z", base_sha, head, "--"],
        binary=True,
    )
    assert isinstance(diff, bytes)
    fields = diff.split(b"\0")
    expected = [b"A", relative.encode("utf-8"), b""]
    if fields != expected:
        reject("approval commit may only add its own authorization file")
    status = git(
        root,
        ["status", "--porcelain=v1", "--untracked-files=all"],
    )
    assert isinstance(status, str)
    if status:
        reject("controller checkout must be clean")
    committed_candidate = git_blob(root, head, relative)
    if committed_candidate != candidate_raw:
        reject("working-tree authorization differs from committed authorization")
    workflow = git_blob(root, base_sha, value["controller"]["workflow_path"])
    if (
        hashlib.sha256(workflow).hexdigest()
        != value["controller"]["workflow_sha256"]
    ):
        reject("workflow digest does not match the controller base blob")
    policy = git_blob(root, base_sha, value["policy"]["path"])
    validate_policy_blob(policy, value["policy"]["digest_sha256"])


def validate(
    root: Path,
    relative: str,
    *,
    now: dt.datetime,
    remote_main_sha: str,
) -> dict[str, Any]:
    root = root.absolute()
    try:
        if root.resolve(strict=True) != root or not root.is_dir():
            reject("repository root must be a real directory without symlinks")
    except OSError:
        reject("repository root is unavailable")
    actual_root = git(root, ["rev-parse", "--show-toplevel"])
    assert isinstance(actual_root, str)
    if Path(actual_root).absolute() != root:
        reject("repository root argument is not the Git top-level directory")
    raw = read_candidate(root, relative)
    value = parse_json(raw, "authorization")
    require_canonical(raw, value, "authorization")
    release_id, nonce = validate_shape(value, now=now, historical=False)
    if relative != f"approvals/{release_id}.json":
        reject("approval filename must equal release_id")
    history = historical_authorizations(root, value["controller"]["base_sha"])
    if any(existing_id == release_id for existing_id, _ in history):
        reject(f"release_id already used: {release_id}")
    if any(existing_nonce == nonce for _, existing_nonce in history):
        reject("nonce already used")
    require_pattern(remote_main_sha, SHA1_RE, "verified controller main sha")
    verify_controller_commit(
        root,
        relative,
        value,
        raw,
        remote_main_sha,
    )
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("approval", help="repository-relative approvals/*.json")
    parser.add_argument(
        "--repository-root",
        required=True,
        type=Path,
        help="checked-out public controller Git repository",
    )
    args = parser.parse_args()
    try:
        remote_main_sha = trusted_controller_main_head()
        value = validate(
            args.repository_root,
            args.approval,
            now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0),
            remote_main_sha=remote_main_sha,
        )
    except ApprovalError as error:
        print(f"release authorization rejected: {error}", file=sys.stderr)
        return 78
    print(
        json.dumps(
            {
                "api_sha": value["api"]["commit_sha"],
                "controller_base_sha": value["controller"]["base_sha"],
                "ops_sha": value["ops"]["commit_sha"],
                "policy_sha256": value["policy"]["digest_sha256"],
                "release_id": value["release_id"],
                "web_sha": value["web"]["commit_sha"],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
