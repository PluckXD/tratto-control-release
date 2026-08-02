from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import copy
import importlib.util
import json
import os
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_github_controls_v2",
    ROOT / "scripts" / "verify-github-controls-v2.py",
)
assert SPEC is not None and SPEC.loader is not None
CONTROLS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CONTROLS
SPEC.loader.exec_module(CONTROLS)

CONTROLLER_ID = 111111
LEDGER_ID = 222222


def branch() -> dict[str, Any]:
    return {
        "allow_deletions": {"enabled": False},
        "allow_force_pushes": {"enabled": False},
        "enforce_admins": {"enabled": True},
        "required_linear_history": {"enabled": True},
        "required_pull_request_reviews": {
            "bypass_pull_request_allowances": {
                "apps": [],
                "teams": [],
                "users": [],
            },
            "dismiss_stale_reviews": True,
            "require_code_owner_reviews": True,
            "require_last_push_approval": True,
            "required_approving_review_count": 2,
        },
    }


def controller_evidence() -> dict[str, Any]:
    return {
        "actions": {
            "allowed_actions": "selected",
            "enabled": True,
            "sha_pinning_required": True,
        },
        "branch_protection": branch(),
        "environment": {
            "can_admins_bypass": False,
            "description": "untrusted-extra-text-is-not-authority",
            "id": 303,
            "name": CONTROLS.ENVIRONMENT,
            "protection_rules": [
                {
                    "id": 9,
                    "prevent_self_review": True,
                    "reviewers": [
                        {
                            "reviewer": {
                                "id": 101,
                                "login": "untrusted-display-name",
                            },
                            "type": "User",
                        },
                        {
                            "reviewer": {
                                "id": 202,
                                "slug": "untrusted-team-slug",
                            },
                            "type": "Team",
                        },
                    ],
                    "type": "required_reviewers",
                },
                {"type": "branch_policy"},
            ],
        },
        "immutable_releases": {
            "enabled": True,
            "enforced_by_owner": True,
        },
        "repository": {
            "full_name": CONTROLS.CONTROLLER_REPOSITORY,
            "id": CONTROLLER_ID,
            "private": False,
            "visibility": "public",
        },
        "selected_actions": {
            "github_owned_allowed": False,
            "patterns_allowed": [
                CONTROLS.CHECKOUT_ACTION,
                CONTROLS.SETUP_PYTHON_ACTION,
            ],
            "verified_allowed": False,
        },
        "signatures": {"enabled": True},
    }


def ledger_evidence() -> dict[str, Any]:
    return {
        "branch_protection": branch(),
        "main_rulesets": [
            {
                "bypass_actors": [],
                "conditions": {
                    "ref_name": {
                        "exclude": [],
                        "include": [CONTROLS.MAIN_REF],
                    },
                },
                "enforcement": "active",
                "id": 404,
                "name": "untrusted-display-name",
                "rules": [
                    {"type": "creation"},
                    {"type": "deletion"},
                    {"type": "non_fast_forward"},
                    {"type": "required_signatures"},
                ],
                "target": "branch",
            },
        ],
        "repository": {
            "full_name": CONTROLS.LEDGER_REPOSITORY,
            "id": LEDGER_ID,
            "private": False,
            "visibility": "public",
        },
        "signatures": {"enabled": True},
    }


def validate(
    controller: dict[str, Any] | None = None,
    ledger: dict[str, Any] | None = None,
    *,
    controller_id: Any = CONTROLLER_ID,
    ledger_id: Any = LEDGER_ID,
) -> Any:
    return CONTROLS.validate(
        controller if controller is not None else controller_evidence(),
        ledger if ledger is not None else ledger_evidence(),
        controller_repository_id=controller_id,
        ledger_repository_id=ledger_id,
    )


def write_canonical(path: Path, value: dict[str, Any]) -> None:
    path.write_bytes(CONTROLS.canonical_bytes(value))


def test_accepts_complete_offline_v6_controls() -> None:
    attestation = validate()
    assert attestation.as_dict() == {
        "controller_repository": CONTROLS.CONTROLLER_REPOSITORY,
        "controller_repository_id": CONTROLLER_ID,
        "environment": "control-release",
        "environment_reviewer_count": 2,
        "ledger_repository": CONTROLS.LEDGER_REPOSITORY,
        "ledger_repository_id": LEDGER_ID,
        "minimum_pull_request_approvals": 2,
    }


@pytest.mark.parametrize(
    ("controller_id", "ledger_id"),
    [
        (0, LEDGER_ID),
        (True, LEDGER_ID),
        ("111111", LEDGER_ID),
        (CONTROLLER_ID, -1),
        (CONTROLLER_ID, CONTROLLER_ID),
    ],
)
def test_rejects_unavailable_or_mistyped_audited_repository_ids(
    controller_id: Any,
    ledger_id: Any,
) -> None:
    with pytest.raises(
        CONTROLS.GitHubControlsV2Error,
        match="distinct positive integers",
    ):
        validate(controller_id=controller_id, ledger_id=ledger_id)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", LEDGER_ID),
        ("id", True),
        ("full_name", "attacker/controller"),
        ("private", True),
        ("private", 0),
        ("visibility", "internal"),
    ],
)
def test_rejects_wrong_or_non_public_controller_repository(
    field: str,
    value: Any,
) -> None:
    evidence = controller_evidence()
    evidence["repository"][field] = value
    with pytest.raises(CONTROLS.GitHubControlsV2Error):
        validate(controller=evidence)


def test_rejects_wrong_ledger_repository_identity() -> None:
    evidence = ledger_evidence()
    evidence["repository"]["full_name"] = CONTROLS.CONTROLLER_REPOSITORY
    evidence["repository"]["id"] = CONTROLLER_ID
    with pytest.raises(CONTROLS.GitHubControlsV2Error):
        validate(ledger=evidence)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("enabled", False),
        ("enabled", 1),
        ("allowed_actions", "all"),
        ("sha_pinning_required", False),
        ("sha_pinning_required", 1),
    ],
)
def test_rejects_weak_or_mistyped_actions_policy(
    field: str,
    value: Any,
) -> None:
    evidence = controller_evidence()
    evidence["actions"][field] = value
    with pytest.raises(CONTROLS.GitHubControlsV2Error, match="Actions"):
        validate(controller=evidence)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("github_owned_allowed", True),
        ("verified_allowed", True),
        ("patterns_allowed", [CONTROLS.CHECKOUT_ACTION]),
        (
            "patterns_allowed",
            [CONTROLS.CHECKOUT_ACTION, "actions/setup-python@v6"],
        ),
        (
            "patterns_allowed",
            [CONTROLS.CHECKOUT_ACTION, "owner/extra@" + "a" * 40],
        ),
        (
            "patterns_allowed",
            [CONTROLS.CHECKOUT_ACTION, CONTROLS.CHECKOUT_ACTION],
        ),
    ],
)
def test_rejects_broader_or_unpinned_selected_actions(
    field: str,
    value: Any,
) -> None:
    evidence = controller_evidence()
    evidence["selected_actions"][field] = value
    with pytest.raises(CONTROLS.GitHubControlsV2Error, match="two reviewed"):
        validate(controller=evidence)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("required_linear_history", "enabled"), False),
        (("enforce_admins", "enabled"), False),
        (("allow_force_pushes", "enabled"), True),
        (("allow_deletions", "enabled"), True),
        (
            ("required_pull_request_reviews", "dismiss_stale_reviews"),
            False,
        ),
        (
            (
                "required_pull_request_reviews",
                "require_code_owner_reviews",
            ),
            False,
        ),
        (
            (
                "required_pull_request_reviews",
                "require_last_push_approval",
            ),
            False,
        ),
        (
            (
                "required_pull_request_reviews",
                "required_approving_review_count",
            ),
            1,
        ),
        (
            (
                "required_pull_request_reviews",
                "required_approving_review_count",
            ),
            True,
        ),
    ],
)
@pytest.mark.parametrize("target", ["controller", "ledger"])
def test_rejects_weak_main_protection(
    path: tuple[str, str],
    value: Any,
    target: str,
) -> None:
    controller = controller_evidence()
    ledger = ledger_evidence()
    selected = (
        controller["branch_protection"]
        if target == "controller"
        else ledger["branch_protection"]
    )
    selected[path[0]][path[1]] = value
    with pytest.raises(CONTROLS.GitHubControlsV2Error):
        validate(controller=controller, ledger=ledger)


@pytest.mark.parametrize("target", ["controller", "ledger"])
def test_rejects_unsigned_main(target: str) -> None:
    controller = controller_evidence()
    ledger = ledger_evidence()
    selected = controller if target == "controller" else ledger
    selected["signatures"]["enabled"] = False
    with pytest.raises(CONTROLS.GitHubControlsV2Error, match="signed"):
        validate(controller=controller, ledger=ledger)


@pytest.mark.parametrize("bucket", ["apps", "teams", "users"])
def test_rejects_pull_request_bypass(bucket: str) -> None:
    evidence = controller_evidence()
    bypass = evidence["branch_protection"][
        "required_pull_request_reviews"
    ]["bypass_pull_request_allowances"]
    bypass[bucket] = [{"id": 99}]
    with pytest.raises(CONTROLS.GitHubControlsV2Error, match="bypass"):
        validate(controller=evidence)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (("can_admins_bypass", True), "admin bypass"),
        (("prevent_self_review", False), "self-review"),
        (("reviewers", "one"), "reviewers"),
    ],
)
def test_rejects_weak_environment_controls(
    mutation: tuple[str, Any],
    message: str,
) -> None:
    evidence = controller_evidence()
    key, value = mutation
    if key == "can_admins_bypass":
        evidence["environment"][key] = value
    else:
        evidence["environment"]["protection_rules"][0][key] = value
    with pytest.raises(CONTROLS.GitHubControlsV2Error, match=message):
        validate(controller=evidence)


def test_rejects_one_environment_reviewer() -> None:
    evidence = controller_evidence()
    reviewers = evidence["environment"]["protection_rules"][0]["reviewers"]
    evidence["environment"]["protection_rules"][0]["reviewers"] = reviewers[:1]
    with pytest.raises(CONTROLS.GitHubControlsV2Error, match="two distinct"):
        validate(controller=evidence)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", 0),
        ("id", True),
        ("name", "production"),
    ],
)
def test_rejects_wrong_environment_identity(field: str, value: Any) -> None:
    evidence = controller_evidence()
    evidence["environment"][field] = value
    with pytest.raises(CONTROLS.GitHubControlsV2Error, match="environment"):
        validate(controller=evidence)


def test_rejects_duplicate_environment_reviewer_ids() -> None:
    evidence = controller_evidence()
    reviewers = evidence["environment"]["protection_rules"][0]["reviewers"]
    reviewers[1] = copy.deepcopy(reviewers[0])
    with pytest.raises(CONTROLS.GitHubControlsV2Error, match="two distinct"):
        validate(controller=evidence)


@pytest.mark.parametrize("field", ["enabled", "enforced_by_owner"])
def test_rejects_non_immutable_controller_releases(field: str) -> None:
    evidence = controller_evidence()
    evidence["immutable_releases"][field] = False
    with pytest.raises(CONTROLS.GitHubControlsV2Error, match="immutable"):
        validate(controller=evidence)


@pytest.mark.parametrize(
    "mutation",
    [
        "bypass",
        "inactive",
        "wrong_ref",
        "excluded_main",
        "missing_creation",
        "missing_deletion",
        "missing_non_fast_forward",
    ],
)
def test_rejects_ledger_without_no_bypass_destructive_protection(
    mutation: str,
) -> None:
    evidence = ledger_evidence()
    ruleset = evidence["main_rulesets"][0]
    if mutation == "bypass":
        ruleset["bypass_actors"] = [
            {
                "actor_id": 1,
                "actor_type": "OrganizationAdmin",
                "bypass_mode": "always",
            },
        ]
    elif mutation == "inactive":
        ruleset["enforcement"] = "evaluate"
    elif mutation == "wrong_ref":
        ruleset["conditions"]["ref_name"]["include"] = [
            "refs/heads/release"
        ]
    elif mutation == "excluded_main":
        ruleset["conditions"]["ref_name"]["exclude"] = [CONTROLS.MAIN_REF]
    else:
        missing = mutation.removeprefix("missing_")
        ruleset["rules"] = [
            rule for rule in ruleset["rules"] if rule["type"] != missing
        ]
    with pytest.raises(CONTROLS.GitHubControlsV2Error, match="ledger main"):
        validate(ledger=evidence)


def test_accepts_destructive_rules_layered_across_no_bypass_rulesets() -> None:
    evidence = ledger_evidence()
    original = evidence["main_rulesets"][0]
    evidence["main_rulesets"] = []
    for index, rule in enumerate(original["rules"][:3]):
        split = copy.deepcopy(original)
        split["id"] += index
        split["rules"] = [rule]
        evidence["main_rulesets"].append(split)
    validate(ledger=evidence)


@pytest.mark.parametrize("value", [0, True, "404"])
def test_rejects_mistyped_ledger_ruleset_id(value: Any) -> None:
    evidence = ledger_evidence()
    evidence["main_rulesets"][0]["id"] = value
    with pytest.raises(CONTROLS.GitHubControlsV2Error, match="ruleset"):
        validate(ledger=evidence)


def test_rejects_the_documented_weak_current_state() -> None:
    evidence = controller_evidence()
    evidence["actions"]["allowed_actions"] = "all"
    evidence["actions"]["sha_pinning_required"] = False
    evidence["environment"]["can_admins_bypass"] = True
    evidence["environment"]["protection_rules"][0]["reviewers"] = (
        evidence["environment"]["protection_rules"][0]["reviewers"][:1]
    )
    evidence["immutable_releases"]["enabled"] = False
    evidence["immutable_releases"]["enforced_by_owner"] = False
    with pytest.raises(CONTROLS.GitHubControlsV2Error):
        validate(controller=evidence)


def test_rejects_unknown_top_level_evidence_field() -> None:
    evidence = controller_evidence()
    evidence["operator_note"] = "this text cannot grant authority"
    with pytest.raises(CONTROLS.GitHubControlsV2Error, match="keys diverge"):
        validate(controller=evidence)


def test_untrusted_extra_text_cannot_replace_numeric_identity() -> None:
    evidence = controller_evidence()
    evidence["repository"]["id"] = 999999
    evidence["repository"]["description"] = (
        f"trusted repository id is {CONTROLLER_ID}"
    )
    with pytest.raises(CONTROLS.GitHubControlsV2Error, match="audited pin"):
        validate(controller=evidence)


def test_loads_stable_canonical_single_link_evidence(tmp_path: Path) -> None:
    path = tmp_path / "controller.json"
    evidence = controller_evidence()
    write_canonical(path, evidence)
    assert CONTROLS.load_canonical_json(path, "controller") == evidence


@pytest.mark.parametrize(
    "raw",
    [
        b'{"z":1, "a":2}\n',
        b'{"a":1,"a":1}\n',
        b'{"value":NaN}\n',
        b'[]\n',
        b"\xff\n",
        b"",
    ],
)
def test_loader_rejects_noncanonical_or_invalid_json(
    tmp_path: Path,
    raw: bytes,
) -> None:
    path = tmp_path / "evidence.json"
    path.write_bytes(raw)
    with pytest.raises(CONTROLS.GitHubControlsV2Error):
        CONTROLS.load_canonical_json(path, "evidence")


def test_loader_rejects_symlink_and_hardlink(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    write_canonical(target, controller_evidence())
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(target)
    hardlink = tmp_path / "hardlink.json"
    os.link(target, hardlink)
    for path in (symlink, hardlink):
        with pytest.raises(CONTROLS.GitHubControlsV2Error):
            CONTROLS.load_canonical_json(path, "evidence")


def test_cli_uses_the_audited_repository_ids(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    controller_path = tmp_path / "controller.json"
    ledger_path = tmp_path / "ledger.json"
    controller = controller_evidence()
    ledger = ledger_evidence()
    controller["repository"]["id"] = (
        CONTROLS.PINNED_CONTROLLER_REPOSITORY_ID
    )
    ledger["repository"]["id"] = CONTROLS.PINNED_LEDGER_REPOSITORY_ID
    write_canonical(controller_path, controller)
    write_canonical(ledger_path, ledger)
    assert (
        CONTROLS.main(
            [
                "--controller-evidence",
                str(controller_path),
                "--ledger-evidence",
                str(ledger_path),
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["controller_repository_id"] == 1317521588
    assert output["ledger_repository_id"] == 1319756090


def test_cli_reads_canonical_evidence_when_reviewed_pins_are_injected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    controller_path = tmp_path / "controller.json"
    ledger_path = tmp_path / "ledger.json"
    write_canonical(controller_path, controller_evidence())
    write_canonical(ledger_path, ledger_evidence())
    monkeypatch.setattr(
        CONTROLS,
        "PINNED_CONTROLLER_REPOSITORY_ID",
        CONTROLLER_ID,
    )
    monkeypatch.setattr(
        CONTROLS,
        "PINNED_LEDGER_REPOSITORY_ID",
        LEDGER_ID,
    )
    assert (
        CONTROLS.main(
            [
                "--controller-evidence",
                str(controller_path),
                "--ledger-evidence",
                str(ledger_path),
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["controller_repository_id"] == CONTROLLER_ID
    assert output["ledger_repository_id"] == LEDGER_ID
