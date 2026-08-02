#!/usr/bin/env python3
"""Verify the v6 GitHub control plane from canonical offline evidence.

This module deliberately has no network client.  The pure :func:`validate`
API receives canonicalized GitHub REST response objects plus repository IDs
that were audited out of band.  Repository names and other textual response
fields never substitute for those numeric trust pins.

The production CLI remains fail-closed until both repository ID constants are
replaced with reviewed values.  Evidence files are bounded, canonical JSON,
single-link regular files and are read through stable file descriptors without
following symlinks.
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
from pathlib import Path
from typing import Any, Mapping


CONTROLLER_REPOSITORY = "PluckXD/tratto-control-release"
LEDGER_REPOSITORY = "PluckXD/tratto-control-release-ledger"
MAIN_REF = "refs/heads/main"
ENVIRONMENT = "control-release"

# Numeric repository identities audited directly from the GitHub API after
# both public trust repositories were provisioned. Names remain part of the
# contract, but can never substitute for these immutable numeric identities.
PINNED_CONTROLLER_REPOSITORY_ID = 1317521588
PINNED_LEDGER_REPOSITORY_ID = 1319756090

CHECKOUT_ACTION = (
    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
)
SETUP_PYTHON_ACTION = (
    "actions/setup-python@83679a892e2d95755f2dac6acb0bfd1e9ac5d548"
)
ALLOWED_ACTIONS = frozenset({CHECKOUT_ACTION, SETUP_PYTHON_ACTION})
ACTION_PATTERN_RE = re.compile(
    r"^actions/(?:checkout|setup-python)@[0-9a-f]{40}$"
)

MAX_JSON_BYTES = 1024 * 1024
CONTROLLER_EVIDENCE_KEYS = {
    "actions",
    "branch_protection",
    "environment",
    "immutable_releases",
    "repository",
    "selected_actions",
    "signatures",
}
LEDGER_EVIDENCE_KEYS = {
    "branch_protection",
    "main_rulesets",
    "repository",
    "signatures",
}
DESTRUCTIVE_LEDGER_RULES = {
    "creation",
    "deletion",
    "non_fast_forward",
}


class GitHubControlsV2Error(ValueError):
    """GitHub control evidence is unavailable, ambiguous, or insufficient."""


def reject(message: str) -> None:
    raise GitHubControlsV2Error(message)


@dataclass(frozen=True)
class GitHubControlsV2Attestation:
    controller_repository: str
    controller_repository_id: int
    ledger_repository: str
    ledger_repository_id: int
    environment: str
    minimum_pull_request_approvals: int
    environment_reviewer_count: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "controller_repository": self.controller_repository,
            "controller_repository_id": self.controller_repository_id,
            "environment": self.environment,
            "environment_reviewer_count": self.environment_reviewer_count,
            "ledger_repository": self.ledger_repository,
            "ledger_repository_id": self.ledger_repository_id,
            "minimum_pull_request_approvals": (
                self.minimum_pull_request_approvals
            ),
        }


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
    """Read one bounded canonical JSON file without following links."""

    absolute = path.absolute()
    descriptor = -1
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
        opened = os.fstat(descriptor)
    except GitHubControlsV2Error:
        raise
    except OSError:
        reject(f"{label} is unavailable")

    try:
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size <= 0
            or opened.st_size > MAX_JSON_BYTES
            or (opened.st_dev, opened.st_ino)
            != (before.st_dev, before.st_ino)
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
    except GitHubControlsV2Error:
        raise
    except OSError:
        reject(f"{label} failed closed while being read")
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        any(getattr(after, field) != getattr(opened, field) for field in stable_fields)
        or len(raw) != opened.st_size
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
    except GitHubControlsV2Error:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        reject(f"{label} is not valid UTF-8 JSON")
    if type(value) is not dict:
        reject(f"{label} root must be an object")
    if raw != canonical_bytes(value):
        reject(f"{label} must be canonical JSON")
    return value


def exact_dict(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        reject(f"{label} must be an object")
    return value


def exact_list(value: Any, label: str) -> list[Any]:
    if type(value) is not list:
        reject(f"{label} must be an array")
    return value


def positive_int(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        reject(f"{label} must be a positive integer")
    return value


def fixed_evidence_shape(
    value: Any,
    keys: set[str],
    label: str,
) -> dict[str, Any]:
    block = exact_dict(value, label)
    if set(block) != keys:
        reject(f"{label} keys diverge")
    return block


def validate_repository(
    value: Any,
    *,
    expected_name: str,
    expected_id: int,
    label: str,
) -> None:
    repository = exact_dict(value, f"{label} repository")
    if type(expected_id) is not int or expected_id <= 0:
        reject(f"{label} audited repository ID is unavailable")
    if type(repository.get("id")) is not int:
        reject(f"{label} repository id has the wrong type")
    if repository["id"] != expected_id:
        reject(f"{label} repository id does not match the audited pin")
    if (
        type(repository.get("full_name")) is not str
        or repository["full_name"] != expected_name
    ):
        reject(f"{label} repository name diverges")
    if repository.get("private") is not False:
        reject(f"{label} repository is not public")
    if (
        type(repository.get("visibility")) is not str
        or repository["visibility"] != "public"
    ):
        reject(f"{label} repository visibility is not public")


def validate_actions(value: Any) -> None:
    actions = exact_dict(value, "controller Actions permissions")
    if (
        actions.get("enabled") is not True
        or type(actions.get("allowed_actions")) is not str
        or actions["allowed_actions"] != "selected"
        or actions.get("sha_pinning_required") is not True
    ):
        reject(
            "controller Actions must be enabled, selected-only, and full-SHA"
        )


def validate_selected_actions(value: Any) -> None:
    selected = exact_dict(value, "controller selected Actions policy")
    patterns = exact_list(
        selected.get("patterns_allowed"),
        "controller selected Actions patterns",
    )
    if (
        selected.get("github_owned_allowed") is not False
        or selected.get("verified_allowed") is not False
        or len(patterns) != len(ALLOWED_ACTIONS)
        or any(type(pattern) is not str for pattern in patterns)
        or any(ACTION_PATTERN_RE.fullmatch(pattern) is None for pattern in patterns)
        or set(patterns) != ALLOWED_ACTIONS
    ):
        reject(
            "controller selected Actions policy is broader than the two "
            "reviewed full-SHA actions"
        )


def enabled_flag(value: Any, label: str, expected: bool) -> None:
    block = exact_dict(value, label)
    if block.get("enabled") is not expected:
        reject(f"{label} must have enabled={str(expected).lower()}")


def validate_no_pull_request_bypass(value: Any, label: str) -> None:
    bypass = exact_dict(value, f"{label} pull-request bypass allowances")
    for bucket in ("apps", "teams", "users"):
        entries = exact_list(
            bypass.get(bucket),
            f"{label} pull-request bypass {bucket}",
        )
        if entries:
            reject(f"{label} permits pull-request review bypass")


def validate_branch(value: Any, label: str) -> int:
    branch = exact_dict(value, f"{label} main protection")
    reviews = exact_dict(
        branch.get("required_pull_request_reviews"),
        f"{label} pull-request reviews",
    )
    validate_no_pull_request_bypass(
        reviews.get("bypass_pull_request_allowances"),
        label,
    )
    count = reviews.get("required_approving_review_count")
    if (
        reviews.get("dismiss_stale_reviews") is not True
        or reviews.get("require_code_owner_reviews") is not True
        or reviews.get("require_last_push_approval") is not True
        or type(count) is not int
        or count < 2
    ):
        reject(
            f"{label} main must require stale/code-owner/last-push review "
            "controls and at least two approvals"
        )
    enabled_flag(
        branch.get("required_linear_history"),
        f"{label} linear history",
        True,
    )
    enabled_flag(branch.get("enforce_admins"), f"{label} admin enforcement", True)
    enabled_flag(
        branch.get("allow_force_pushes"),
        f"{label} force pushes",
        False,
    )
    enabled_flag(branch.get("allow_deletions"), f"{label} deletions", False)
    return count


def validate_signatures(value: Any, label: str) -> None:
    enabled_flag(value, f"{label} signed commits", True)


def validate_environment(value: Any) -> int:
    environment = exact_dict(value, "control-release environment")
    positive_int(environment.get("id"), "control-release environment id")
    if (
        type(environment.get("name")) is not str
        or environment["name"] != ENVIRONMENT
    ):
        reject("control-release environment name diverges")
    if environment.get("can_admins_bypass") is not False:
        reject("control-release environment permits admin bypass")
    rules = exact_list(
        environment.get("protection_rules"),
        "control-release protection rules",
    )
    reviewer_rules = [
        rule
        for rule in rules
        if type(rule) is dict and rule.get("type") == "required_reviewers"
    ]
    if len(reviewer_rules) != 1:
        reject(
            "control-release must have exactly one required-reviewers rule"
        )
    reviewer_rule = reviewer_rules[0]
    positive_int(
        reviewer_rule.get("id"),
        "control-release required-reviewers rule id",
    )
    if reviewer_rule.get("prevent_self_review") is not True:
        reject("control-release permits self-review")
    reviewers = exact_list(
        reviewer_rule.get("reviewers"),
        "control-release reviewers",
    )
    identities: set[tuple[str, int]] = set()
    for index, entry_value in enumerate(reviewers):
        entry = exact_dict(
            entry_value,
            f"control-release reviewer {index}",
        )
        reviewer_type = entry.get("type")
        if type(reviewer_type) is not str or reviewer_type not in {"User", "Team"}:
            reject("control-release reviewer type is invalid")
        reviewer = exact_dict(
            entry.get("reviewer"),
            f"control-release reviewer {index} identity",
        )
        reviewer_id = positive_int(
            reviewer.get("id"),
            f"control-release reviewer {index} id",
        )
        identities.add((reviewer_type, reviewer_id))
    if len(reviewers) < 2 or len(identities) != len(reviewers):
        reject(
            "control-release requires at least two distinct numeric reviewers"
        )
    return len(identities)


def validate_immutable_releases(value: Any) -> None:
    immutable = exact_dict(value, "controller immutable releases")
    if (
        immutable.get("enabled") is not True
        or immutable.get("enforced_by_owner") is not True
    ):
        reject(
            "controller immutable releases must be enabled and owner-enforced"
        )


def validate_ledger_rulesets(value: Any) -> None:
    rulesets = exact_list(value, "ledger main rulesets")
    protected_rule_types: set[str] = set()
    applicable_rulesets = 0
    ruleset_ids: set[int] = set()
    for index, ruleset_value in enumerate(rulesets):
        ruleset = exact_dict(ruleset_value, f"ledger main ruleset {index}")
        if (
            type(ruleset.get("target")) is not str
            or ruleset["target"] != "branch"
            or type(ruleset.get("enforcement")) is not str
            or ruleset["enforcement"] != "active"
        ):
            continue
        bypass = exact_list(
            ruleset.get("bypass_actors"),
            f"ledger main ruleset {index} bypass actors",
        )
        if bypass:
            continue
        conditions = exact_dict(
            ruleset.get("conditions"),
            f"ledger main ruleset {index} conditions",
        )
        ref_name = exact_dict(
            conditions.get("ref_name"),
            f"ledger main ruleset {index} ref condition",
        )
        include = exact_list(
            ref_name.get("include"),
            f"ledger main ruleset {index} included refs",
        )
        exclude = exact_list(
            ref_name.get("exclude"),
            f"ledger main ruleset {index} excluded refs",
        )
        if (
            include != [MAIN_REF]
            or exclude
            or any(type(item) is not str for item in include + exclude)
        ):
            continue
        ruleset_id = positive_int(
            ruleset.get("id"),
            f"ledger main ruleset {index} id",
        )
        if ruleset_id in ruleset_ids:
            reject("ledger main ruleset IDs must be distinct")
        ruleset_ids.add(ruleset_id)
        rules = exact_list(
            ruleset.get("rules"),
            f"ledger main ruleset {index} rules",
        )
        applicable_rulesets += 1
        for rule_index, rule_value in enumerate(rules):
            rule = exact_dict(
                rule_value,
                f"ledger main ruleset {index} rule {rule_index}",
            )
            rule_type = rule.get("type")
            if type(rule_type) is not str:
                reject("ledger main ruleset rule type is invalid")
            protected_rule_types.add(rule_type)
    missing = DESTRUCTIVE_LEDGER_RULES - protected_rule_types
    if not applicable_rulesets or missing:
        reject(
            "ledger main lacks no-bypass creation/deletion/non-fast-forward "
            "rules"
        )


def validate(
    controller_evidence: Mapping[str, Any],
    ledger_evidence: Mapping[str, Any],
    *,
    controller_repository_id: int,
    ledger_repository_id: int,
) -> GitHubControlsV2Attestation:
    """Validate v6 controls using only caller-supplied offline evidence."""

    if (
        type(controller_repository_id) is not int
        or controller_repository_id <= 0
        or type(ledger_repository_id) is not int
        or ledger_repository_id <= 0
        or controller_repository_id == ledger_repository_id
    ):
        reject("audited repository IDs must be distinct positive integers")

    controller = fixed_evidence_shape(
        controller_evidence,
        CONTROLLER_EVIDENCE_KEYS,
        "controller evidence",
    )
    ledger = fixed_evidence_shape(
        ledger_evidence,
        LEDGER_EVIDENCE_KEYS,
        "ledger evidence",
    )

    validate_repository(
        controller["repository"],
        expected_name=CONTROLLER_REPOSITORY,
        expected_id=controller_repository_id,
        label="controller",
    )
    validate_actions(controller["actions"])
    validate_selected_actions(controller["selected_actions"])
    controller_approvals = validate_branch(
        controller["branch_protection"],
        "controller",
    )
    validate_signatures(controller["signatures"], "controller")
    reviewer_count = validate_environment(controller["environment"])
    validate_immutable_releases(controller["immutable_releases"])

    validate_repository(
        ledger["repository"],
        expected_name=LEDGER_REPOSITORY,
        expected_id=ledger_repository_id,
        label="ledger",
    )
    ledger_approvals = validate_branch(
        ledger["branch_protection"],
        "ledger",
    )
    validate_signatures(ledger["signatures"], "ledger")
    validate_ledger_rulesets(ledger["main_rulesets"])

    return GitHubControlsV2Attestation(
        controller_repository=CONTROLLER_REPOSITORY,
        controller_repository_id=controller_repository_id,
        ledger_repository=LEDGER_REPOSITORY,
        ledger_repository_id=ledger_repository_id,
        environment=ENVIRONMENT,
        minimum_pull_request_approvals=min(
            controller_approvals,
            ledger_approvals,
        ),
        environment_reviewer_count=reviewer_count,
    )


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(
        description="Verify canonical offline GitHub v6 control evidence.",
    )
    argument_parser.add_argument(
        "--controller-evidence",
        required=True,
        type=Path,
    )
    argument_parser.add_argument(
        "--ledger-evidence",
        required=True,
        type=Path,
    )
    return argument_parser


def main(arguments: list[str] | None = None) -> int:
    try:
        options = parser().parse_args(arguments)
        if (
            type(PINNED_CONTROLLER_REPOSITORY_ID) is not int
            or PINNED_CONTROLLER_REPOSITORY_ID <= 0
            or type(PINNED_LEDGER_REPOSITORY_ID) is not int
            or PINNED_LEDGER_REPOSITORY_ID <= 0
        ):
            reject("reviewed repository ID pins are not configured")
        controller = load_canonical_json(
            options.controller_evidence,
            "controller evidence",
        )
        ledger = load_canonical_json(
            options.ledger_evidence,
            "ledger evidence",
        )
        attestation = validate(
            controller,
            ledger,
            controller_repository_id=PINNED_CONTROLLER_REPOSITORY_ID,
            ledger_repository_id=PINNED_LEDGER_REPOSITORY_ID,
        )
    except GitHubControlsV2Error as error:
        print(f"GitHub controls v2 rejected: {error}", file=sys.stderr)
        return 78
    print(
        json.dumps(
            attestation.as_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
