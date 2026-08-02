#!/usr/bin/env python3
"""Read-only proof that external controller protections are fail-closed."""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import json
import os
import urllib.error
import urllib.request
from typing import Any


REPOSITORY = "PluckXD/tratto-control-release"
API = "https://api.github.com"
CHECKOUT_ACTION = (
    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
)
SETUP_PYTHON_ACTION = (
    "actions/setup-python@83679a892e2d95755f2dac6acb0bfd1e9ac5d548"
)
ALLOWED_ACTIONS = (CHECKOUT_ACTION, SETUP_PYTHON_ACTION)


class ControlsError(ValueError):
    pass


def reject(message: str) -> None:
    raise ControlsError(message)


def fetch(path: str, token: str) -> dict[str, Any]:
    if not token or any(character.isspace() for character in token):
        reject("CONTROL_CONTROLLER_AUDIT_TOKEN is unavailable")
    request = urllib.request.Request(
        f"{API}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "tratto-control-release-auditor/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=10) as response:
            if response.status != 200:
                reject(f"GitHub control lookup rejected: {path}")
            raw = response.read(1024 * 1024 + 1)
    except (OSError, urllib.error.HTTPError, urllib.error.URLError):
        reject(f"GitHub control lookup failed closed: {path}")
    if len(raw) > 1024 * 1024:
        reject("GitHub control response is oversized")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject("GitHub control response is invalid")
    if not isinstance(value, dict):
        reject("GitHub control response must be an object")
    return value


def validate_branch(value: dict[str, Any]) -> None:
    reviews = value.get("required_pull_request_reviews")
    bypass = (
        reviews.get("bypass_pull_request_allowances")
        if isinstance(reviews, dict)
        else None
    )
    if bypass is not None:
        if (
            not isinstance(bypass, dict)
            or set(bypass) - {"apps", "teams", "users"}
            or any(
                not isinstance(bypass.get(bucket, []), list)
                or bypass.get(bucket, [])
                for bucket in ("apps", "teams", "users")
            )
        ):
            reject("protected main permits pull-request review bypass")
    if (
        not isinstance(reviews, dict)
        or reviews.get("dismiss_stale_reviews") is not True
        or reviews.get("require_code_owner_reviews") is not True
        or reviews.get("require_last_push_approval") is not True
        or type(reviews.get("required_approving_review_count")) is not int
        or reviews["required_approving_review_count"] < 1
        or value.get("enforce_admins", {}).get("enabled") is not True
        or value.get("required_linear_history", {}).get("enabled") is not True
        or value.get("required_conversation_resolution", {}).get("enabled")
        is not True
        or value.get("allow_force_pushes", {}).get("enabled") is not False
        or value.get("allow_deletions", {}).get("enabled") is not False
    ):
        reject("protected main does not enforce the reviewed release root")


def validate_environment(value: dict[str, Any]) -> None:
    rules = value.get("protection_rules")
    if (
        value.get("can_admins_bypass") is not False
        or not isinstance(rules, list)
    ):
        reject("control-release environment permits bypass")
    reviewers = [
        rule
        for rule in rules
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    if (
        len(reviewers) != 1
        or reviewers[0].get("prevent_self_review") is not True
        or not isinstance(reviewers[0].get("reviewers"), list)
        or not reviewers[0]["reviewers"]
    ):
        reject("control-release environment lacks an independent reviewer")


def validate_actions(value: dict[str, Any]) -> None:
    if (
        value.get("enabled") is not True
        or value.get("allowed_actions") != "selected"
        or value.get("sha_pinning_required") is not True
    ):
        reject("repository Actions policy is not restricted/full-SHA")


def validate_selected_actions(value: dict[str, Any]) -> None:
    patterns = value.get("patterns_allowed")
    if (
        value.get("github_owned_allowed") is not False
        or value.get("verified_allowed") is not False
        or not isinstance(patterns, list)
        or len(patterns) != len(ALLOWED_ACTIONS)
        or any(not isinstance(pattern, str) for pattern in patterns)
        or set(patterns) != set(ALLOWED_ACTIONS)
    ):
        reject("repository Actions allowlist is broader than the reviewed action")


def validate_signatures(value: dict[str, Any]) -> None:
    if value.get("enabled") is not True:
        reject("protected main does not require signed commits")


def main() -> int:
    try:
        if (
            os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        ):
            reject("GitHub controller context is invalid")
        token = os.environ.get("CONTROL_CONTROLLER_AUDIT_TOKEN", "")
        validate_branch(
            fetch(
                f"/repos/{REPOSITORY}/branches/main/protection",
                token,
            )
        )
        validate_environment(
            fetch(
                f"/repos/{REPOSITORY}/environments/control-release",
                token,
            )
        )
        validate_signatures(
            fetch(
                (
                    f"/repos/{REPOSITORY}/branches/main/"
                    "protection/required_signatures"
                ),
                token,
            )
        )
        validate_actions(
            fetch(f"/repos/{REPOSITORY}/actions/permissions", token)
        )
        validate_selected_actions(
            fetch(
                (
                    f"/repos/{REPOSITORY}/actions/permissions/"
                    "selected-actions"
                ),
                token,
            )
        )
    except ControlsError as error:
        print(f"controller controls rejected: {error}", file=sys.stderr)
        return 78
    print("controller branch, environment, and Actions controls verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
