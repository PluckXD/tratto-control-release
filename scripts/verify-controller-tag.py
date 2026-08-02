#!/usr/bin/env python3
"""Verify one immutable v6 controller tag from offline evidence.

The verifier deliberately has no network client.  Callers must obtain the
GitHub REST responses separately and pass their canonical JSON bytes here.
Signature verification is an injected trust boundary: the pure API accepts a
callback and requires its return value to be a typed ``SignatureVerification``.
"""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import json
import os
import re
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping


REPOSITORY = "PluckXD/tratto-control-release"
WORKFLOW_PATH = ".github/workflows/control-release.yml"
TAG_RE = re.compile(
    r"^control-controller-v6\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_JSON_BYTES = 1024 * 1024
PINNED_TAG_SIGNATURE_VERIFIER_IDENTITY = ""
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
LOCAL_TAG_KEYS = {"commit_sha", "object_sha", "object_type", "ref"}
IMMUTABLE_RELEASE_KEYS = {"enabled", "enforced_by_owner"}
RELEASE_REQUIRED_KEYS = {
    "draft",
    "id",
    "immutable",
    "prerelease",
    "tag_name",
    "target_commitish",
    "url",
}


class ControllerTagError(ValueError):
    """The controller tag or its immutable-release evidence is invalid."""


def reject(message: str) -> None:
    raise ControllerTagError(message)


class SignatureStatus(Enum):
    VERIFIED = "verified"


@dataclass(frozen=True)
class ControllerTagPolicy:
    """Values fixed by reviewed policy or explicit, bounded CLI arguments."""

    tag: str
    tag_object_sha: str
    commit_sha: str
    release_id: int
    repository_id: int
    repository: str = REPOSITORY


@dataclass(frozen=True)
class LocalGitTag:
    """Typed evidence produced by a local Git tag inspection."""

    ref: str
    object_type: str
    object_sha: str
    commit_sha: str


@dataclass(frozen=True)
class SignatureVerification:
    """Typed result returned by the caller's signature-verification boundary."""

    tag_object_sha: str
    status: SignatureStatus


@dataclass(frozen=True)
class ControllerTagAttestation:
    repository: str
    tag: str
    tag_object_sha: str
    commit_sha: str
    release_id: int
    repository_id: int
    owner_enforced: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "commit_sha": self.commit_sha,
            "owner_enforced": self.owner_enforced,
            "release_id": self.release_id,
            "repository": self.repository,
            "repository_id": self.repository_id,
            "tag": self.tag,
            "tag_object_sha": self.tag_object_sha,
        }


SignatureVerifier = Callable[[LocalGitTag], SignatureVerification]


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            reject(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def load_canonical_json(path: Path, label: str) -> dict[str, Any]:
    """Read one bounded, canonical, single-link regular JSON evidence file."""

    absolute = path.absolute()
    try:
        if absolute.resolve(strict=True) != absolute:
            reject(f"{label} path must not traverse symlinks")
        before = absolute.lstat()
        descriptor = os.open(
            absolute,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except ControllerTagError:
        raise
    except OSError:
        reject(f"{label} is unavailable")
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > MAX_JSON_BYTES
            or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)
        ):
            reject(f"{label} must be a bounded single-link regular file")
        chunks: list[bytes] = []
        remaining = MAX_JSON_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    except ControllerTagError:
        raise
    except OSError:
        reject(f"{label} failed closed while being read")
    finally:
        os.close(descriptor)
    if (
        (after.st_dev, after.st_ino, after.st_size)
        != (info.st_dev, info.st_ino, info.st_size)
        or len(raw) != info.st_size
        or not 0 < len(raw) <= MAX_JSON_BYTES
    ):
        reject(f"{label} changed while being read or is oversized")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda constant: reject(
                f"{label} contains non-finite number: {constant}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject(f"{label} is not valid UTF-8 JSON")
    if not isinstance(value, dict):
        reject(f"{label} root must be an object")
    if raw != canonical_bytes(value):
        reject(f"{label} must be canonical JSON")
    return value


def exact_keys(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        reject(f"{label} keys diverge")
    return value


def require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        reject(f"{label} must be a lowercase 40-character Git SHA")
    return value


def validate_policy(policy: ControllerTagPolicy) -> None:
    if type(policy) is not ControllerTagPolicy:
        reject("controller tag policy must be typed")
    if policy.repository != REPOSITORY:
        reject("controller repository is not the fixed trust root")
    if not isinstance(policy.tag, str) or TAG_RE.fullmatch(policy.tag) is None:
        reject("controller tag must match control-controller-v6.<minor>.<patch>")
    require_sha(policy.tag_object_sha, "policy tag object")
    require_sha(policy.commit_sha, "policy commit")
    if (
        type(policy.release_id) is not int
        or policy.release_id <= 0
        or type(policy.repository_id) is not int
        or policy.repository_id <= 0
    ):
        reject("controller release policy has invalid typed values")


def parse_local_tag(value: Mapping[str, Any]) -> LocalGitTag:
    block = exact_keys(value, LOCAL_TAG_KEYS, "local Git tag evidence")
    if not isinstance(block["ref"], str) or not isinstance(
        block["object_type"],
        str,
    ):
        reject("local Git tag ref and object type must be strings")
    return LocalGitTag(
        ref=block["ref"],
        object_type=block["object_type"],
        object_sha=require_sha(block["object_sha"], "local tag object"),
        commit_sha=require_sha(block["commit_sha"], "local tag commit"),
    )


def validate_github_context(
    value: Mapping[str, Any],
    policy: ControllerTagPolicy,
) -> None:
    context = exact_keys(value, CONTEXT_KEYS, "GitHub controller context")
    expected_ref = f"refs/tags/{policy.tag}"
    expected_workflow_ref = (
        f"{REPOSITORY}/{WORKFLOW_PATH}@{expected_ref}"
    )
    if context["GITHUB_REPOSITORY"] != REPOSITORY:
        reject("GitHub repository is not the fixed controller trust root")
    if (
        context["GITHUB_ACTIONS"] != "true"
        or context["GITHUB_API_URL"] != "https://api.github.com"
        or context["GITHUB_SERVER_URL"] != "https://github.com"
        or context["GITHUB_EVENT_NAME"] != "workflow_dispatch"
        or context["RUNNER_ENVIRONMENT"] != "github-hosted"
        or context["GITHUB_REPOSITORY_ID"] != str(policy.repository_id)
    ):
        reject("GitHub controller execution context diverges from policy")
    if context["GITHUB_REF_TYPE"] != "tag":
        reject("GitHub controller ref type is not tag")
    if context["GITHUB_REF"] != expected_ref:
        reject("GitHub controller ref is not the fixed v6 tag")
    if context["GITHUB_WORKFLOW_REF"] != expected_workflow_ref:
        reject("GitHub workflow ref is not the controller workflow at the tag")
    github_sha = require_sha(context["GITHUB_SHA"], "GITHUB_SHA")
    workflow_sha = require_sha(
        context["GITHUB_WORKFLOW_SHA"],
        "GITHUB_WORKFLOW_SHA",
    )
    if github_sha != policy.commit_sha or workflow_sha != policy.commit_sha:
        reject("GitHub commit and workflow SHAs do not match the tagged commit")


def validate_local_tag(
    value: LocalGitTag,
    policy: ControllerTagPolicy,
    signature_verifier: SignatureVerifier,
) -> None:
    if type(value) is not LocalGitTag:
        reject("local Git tag evidence must be typed")
    expected_ref = f"refs/tags/{policy.tag}"
    if value.ref != expected_ref:
        reject("local Git tag ref diverges from policy")
    if value.object_type != "tag":
        reject("controller tag must be an annotated Git tag object")
    if value.object_sha != policy.tag_object_sha:
        reject("local annotated tag object SHA diverges from policy")
    if value.commit_sha != policy.commit_sha:
        reject("local annotated tag peeled commit diverges from policy")
    try:
        signature = signature_verifier(value)
    except ControllerTagError:
        raise
    except Exception:
        reject("local annotated tag signature verifier failed closed")
    if type(signature) is not SignatureVerification:
        reject("signature verifier did not return a typed result")
    if (
        signature.status is not SignatureStatus.VERIFIED
        or signature.tag_object_sha != policy.tag_object_sha
    ):
        reject("local annotated tag signature verification diverges")


def validate_release(
    value: Mapping[str, Any],
    policy: ControllerTagPolicy,
) -> None:
    if not isinstance(value, Mapping):
        reject("GitHub release payload must be an object")
    if not RELEASE_REQUIRED_KEYS.issubset(value):
        reject("GitHub release payload lacks required fields")
    expected_url = (
        f"https://api.github.com/repos/{REPOSITORY}/releases/"
        f"{policy.release_id}"
    )
    if (
        type(value["id"]) is not int
        or value["id"] != policy.release_id
        or value["url"] != expected_url
        or value["tag_name"] != policy.tag
        or value["target_commitish"] != policy.commit_sha
        or value["immutable"] is not True
        or value["draft"] is not False
        or value["prerelease"] is not False
    ):
        reject("GitHub immutable release does not match controller policy")


def validate_immutable_releases(
    value: Mapping[str, Any],
) -> bool:
    settings = exact_keys(
        value,
        IMMUTABLE_RELEASE_KEYS,
        "repository immutable-releases response",
    )
    if (
        type(settings["enabled"]) is not bool
        or settings["enabled"] is not True
        or type(settings["enforced_by_owner"]) is not bool
    ):
        reject("repository immutable releases are not proven enabled")
    owner_enforced = settings["enforced_by_owner"]
    if owner_enforced is not True:
        reject("repository immutable releases are not enforced by owner")
    return owner_enforced


def validate_controller_tag(
    *,
    policy: ControllerTagPolicy,
    github_context: Mapping[str, Any],
    local_tag: LocalGitTag,
    signature_verifier: SignatureVerifier,
    release: Mapping[str, Any],
    immutable_releases: Mapping[str, Any],
) -> ControllerTagAttestation:
    """Validate all v6 bindings without filesystem, child-process, or network I/O."""

    validate_policy(policy)
    validate_github_context(github_context, policy)
    validate_local_tag(local_tag, policy, signature_verifier)
    validate_release(release, policy)
    owner_enforced = validate_immutable_releases(
        immutable_releases,
    )
    return ControllerTagAttestation(
        repository=REPOSITORY,
        tag=policy.tag,
        tag_object_sha=policy.tag_object_sha,
        commit_sha=policy.commit_sha,
        release_id=policy.release_id,
        repository_id=policy.repository_id,
        owner_enforced=owner_enforced,
    )


def positive_decimal(value: str) -> int:
    if re.fullmatch(r"[1-9][0-9]*", value) is None:
        raise argparse.ArgumentTypeError(
            "ID must be a canonical positive decimal integer"
        )
    return int(value)


def cli_signature_verifier(_tag: LocalGitTag) -> SignatureVerification:
    """Fail closed until a reviewed cryptographic verifier is pinned."""

    if PINNED_TAG_SIGNATURE_VERIFIER_IDENTITY == "":
        reject("cryptographic tag signature verifier identity is not pinned")
    reject("cryptographic tag signature verifier implementation is unavailable")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify an immutable controller v6 tag from offline JSON",
    )
    parser.add_argument("--controller-tag", required=True)
    parser.add_argument("--tag-object-sha", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--release-id", required=True, type=positive_decimal)
    parser.add_argument("--repository-id", required=True, type=positive_decimal)
    parser.add_argument("--github-context", required=True, type=Path)
    parser.add_argument("--local-git-tag", required=True, type=Path)
    parser.add_argument("--release-response", required=True, type=Path)
    parser.add_argument(
        "--immutable-releases-response",
        required=True,
        type=Path,
    )
    args = parser.parse_args(argv)
    try:
        policy = ControllerTagPolicy(
            tag=args.controller_tag,
            tag_object_sha=args.tag_object_sha,
            commit_sha=args.commit_sha,
            release_id=args.release_id,
            repository_id=args.repository_id,
        )
        context = load_canonical_json(
            args.github_context,
            "GitHub context",
        )
        local_tag = parse_local_tag(
            load_canonical_json(args.local_git_tag, "local Git tag"),
        )
        release = load_canonical_json(
            args.release_response,
            "GitHub release response",
        )
        immutable_releases = load_canonical_json(
            args.immutable_releases_response,
            "immutable-releases response",
        )
        attestation = validate_controller_tag(
            policy=policy,
            github_context=context,
            local_tag=local_tag,
            signature_verifier=cli_signature_verifier,
            release=release,
            immutable_releases=immutable_releases,
        )
    except (OSError, ControllerTagError) as error:
        print(f"immutable controller tag rejected: {error}", file=sys.stderr)
        return 78
    sys.stdout.buffer.write(canonical_bytes(attestation.as_dict()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
