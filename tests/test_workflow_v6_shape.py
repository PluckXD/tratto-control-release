from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / "workflow-v6-shape.yml"
CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
SETUP_PYTHON = (
    "actions/setup-python@83679a892e2d95755f2dac6acb0bfd1e9ac5d548"
)
JOBS = {
    "authorize",
    "build_api",
    "build_ops",
    "build_web",
    "verify",
    "sign_release",
}
BUILDERS = {
    "build_api": "CONTROL_API_READ_TOKEN",
    "build_ops": "CONTROL_API_READ_TOKEN",
    "build_web": "CONTROL_WEB_READ_TOKEN",
}
PRODUCT_CREDENTIALS = {
    "CONTROL_API_READ_TOKEN",
    "CONTROL_WEB_READ_TOKEN",
}


class UniqueSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that also rejects duplicate mapping keys."""


def construct_unique_mapping(
    loader: UniqueSafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


def load_workflow() -> tuple[str, dict[str, Any]]:
    raw = WORKFLOW_PATH.read_text(encoding="utf-8")
    parsed = yaml.load(raw, Loader=UniqueSafeLoader)
    assert isinstance(parsed, dict)
    return raw, parsed


def steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    value = job["steps"]
    assert isinstance(value, list) and value
    assert all(isinstance(step, dict) for step in value)
    return value


def run_text(job: dict[str, Any]) -> str:
    return "\n".join(
        str(step.get("run", "")) for step in steps(job)
    )


def uses(job: dict[str, Any]) -> list[str]:
    return [
        str(step["uses"])
        for step in steps(job)
        if "uses" in step
    ]


def secret_names(job: dict[str, Any]) -> set[str]:
    text = repr(job)
    return set(re.findall(r"secrets\.([A-Z0-9_]+)", text))


def test_review_shape_is_not_an_active_workflow_and_parses_safely() -> None:
    raw, workflow = load_workflow()

    assert WORKFLOW_PATH.parent == ROOT
    assert not WORKFLOW_PATH.is_relative_to(ROOT / ".github" / "workflows")
    assert "Review-only shape" in raw
    assert workflow["permissions"] == {}
    assert set(workflow["jobs"]) == JOBS


def test_dispatch_tag_and_concurrency_contract_are_fail_closed() -> None:
    _, workflow = load_workflow()

    trigger = workflow["on"]
    assert set(trigger) == {"workflow_dispatch"}
    dispatch = trigger["workflow_dispatch"]
    assert set(dispatch["inputs"]) == {"approval_path"}
    approval = dispatch["inputs"]["approval_path"]
    assert approval["required"] is True
    assert approval["type"] == "string"

    concurrency = workflow["concurrency"]
    assert concurrency["cancel-in-progress"] is False
    group = concurrency["group"]
    assert "${{ github.ref }}" in group
    assert "${{ inputs.approval_path }}" in group

    authorize = workflow["jobs"]["authorize"]
    text = run_text(authorize)
    assert r"^refs/tags/control-controller-v6\." in text
    assert r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$" in text
    assert "raise SystemExit(78)" in text
    assert "policy-gate-v2.py --phase authorize" in text


def test_every_job_uses_the_pinned_runner_python_and_actions() -> None:
    _, workflow = load_workflow()

    all_uses: list[str] = []
    for name, job in workflow["jobs"].items():
        assert job["runs-on"] == "ubuntu-24.04", name
        job_uses = uses(job)
        all_uses.extend(job_uses)
        setup_steps = [
            step for step in steps(job)
            if step.get("uses") == SETUP_PYTHON
        ]
        assert len(setup_steps) == 1, name
        assert setup_steps[0]["with"] == {
            "architecture": "x64",
            "check-latest": False,
            "python-version": "3.12.13",
        }

    assert set(all_uses) == {CHECKOUT, SETUP_PYTHON}
    assert all(
        re.fullmatch(r"[^@]+@[0-9a-f]{40}", action)
        for action in all_uses
    )

    raw = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert re.search(r"\bpython3 (?!-B)", raw) is None


def test_authorize_has_exact_checkouts_and_all_v2_validations() -> None:
    _, workflow = load_workflow()
    authorize = workflow["jobs"]["authorize"]

    assert authorize["permissions"] == {"contents": "read"}
    assert "id-token" not in authorize["permissions"]
    assert secret_names(authorize).isdisjoint(PRODUCT_CREDENTIALS)

    checkout_steps = [
        step for step in steps(authorize)
        if step.get("uses") == CHECKOUT
    ]
    assert len(checkout_steps) == 2
    controller, ledger = checkout_steps
    assert controller["with"] == {
        "fetch-depth": 0,
        "path": "controller",
        "persist-credentials": False,
        "ref": "${{ github.ref }}",
    }
    assert ledger["with"] == {
        "fetch-depth": 0,
        "path": "approval-ledger",
        "persist-credentials": False,
        "ref": "refs/heads/main",
        "repository": "PluckXD/tratto-control-release-ledger",
    }
    assert controller["with"]["path"] != ledger["with"]["path"]

    text = run_text(authorize)
    required_commands = {
        "scripts/policy-gate-v2.py --phase authorize",
        "scripts/validate-policy-v2.py",
        "scripts/verify-controller-tag.py",
        "scripts/verify-github-controls-v2.py",
        "scripts/validate-ledger.py",
        "scripts/validate-approval-v2.py",
        "scripts/emit-approval-v2-outputs.py",
    }
    assert all(command in text for command in required_commands)
    assert "FUTURE BLOCKER" in repr(authorize)
    assert text.count("exit 78") >= 2
    assert 'APPROVAL_PATH: "${{ inputs.approval_path }}"' not in repr(authorize)


def test_builders_are_isolated_to_one_product_credential_and_fail_before_work() -> None:
    _, workflow = load_workflow()

    for name, allowed_credential in BUILDERS.items():
        job = workflow["jobs"][name]
        assert job["needs"] == "authorize"
        assert job["permissions"] == {"contents": "read"}
        assert "id-token" not in job["permissions"]
        assert secret_names(job) == {allowed_credential}
        assert uses(job).count(CHECKOUT) == 1
        checkout = next(
            step for step in steps(job)
            if step.get("uses") == CHECKOUT
        )
        assert checkout["with"] == {
            "fetch-depth": 0,
            "path": "controller",
            "persist-credentials": False,
            "ref": "${{ github.ref }}",
        }

        text = run_text(job)
        assert f"policy-gate-v2.py --phase {name}" in text
        assert "ACTIONS_ID_TOKEN_REQUEST_URL" in text
        assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" in text
        assert "FUTURE BLOCKER" in repr(job)
        assert "exit 78" in text
        assert not re.search(
            r"\b(?:docker|podman|buildah|oras|cosign|scp|ssh|rsync)\b",
            text,
            re.IGNORECASE,
        )


def test_verify_has_no_product_or_oidc_authority_and_fails_closed() -> None:
    _, workflow = load_workflow()
    verify = workflow["jobs"]["verify"]

    assert verify["needs"] == [
        "authorize",
        "build_api",
        "build_ops",
        "build_web",
    ]
    assert verify["permissions"] == {"contents": "read"}
    assert "id-token" not in verify["permissions"]
    assert secret_names(verify).isdisjoint(PRODUCT_CREDENTIALS)
    assert uses(verify).count(CHECKOUT) == 1
    text = run_text(verify)
    assert "policy-gate-v2.py --phase verify" in text
    assert "runtime verifier/carrier identity is not provisioned" in text
    assert "exit 78" in text
    for name in PRODUCT_CREDENTIALS:
        assert f'test -z "${{{name}:-}}"' in text


def test_signer_is_source_free_and_revalidates_immediately_before_cosign() -> None:
    raw, workflow = load_workflow()
    signer = workflow["jobs"]["sign_release"]

    assert signer["needs"] == ["authorize", "verify"]
    assert signer["runs-on"] == "ubuntu-24.04"
    assert signer["environment"] == "control-release"
    assert signer["permissions"] == {
        "actions": "read",
        "contents": "none",
        "id-token": "write",
    }
    assert CHECKOUT not in uses(signer)
    assert secret_names(signer) == set()

    text = run_text(signer)
    assert "policy-gate-v2.py" in text
    assert "--phase sign_release" in text
    tag_at = text.index("verify-controller-tag.py")
    ledger_at = text.index("validate-ledger.py")
    controls_at = text.index("verify-github-controls-v2.py")
    freshness_at = text.index("validate-signer-freshness-v2.py")
    closed_at = text.index(
        "reviewed Cosign verifier/identity is not provisioned"
    )
    assert tag_at < ledger_at < controls_at < freshness_at < closed_at
    assert "exit 78" in text[closed_at:]
    assert "cosign sign" not in text.lower()
    assert "actions/checkout" not in repr(signer)
    assert not re.search(r"\b(?:git\s+checkout|git\s+clone|scp|ssh|rsync)\b", text)
    for name in PRODUCT_CREDENTIALS:
        assert f'test -z "${{{name}:-}}"' in text

    signer_raw = raw.split("\n  sign_release:", 1)[1]
    assert "secrets." not in signer_raw


def test_every_placeholder_is_an_explicit_exit_78_gate() -> None:
    _, workflow = load_workflow()

    blockers: list[dict[str, Any]] = []
    for job in workflow["jobs"].values():
        blockers.extend(
            step
            for step in steps(job)
            if "FUTURE BLOCKER" in str(step.get("name", ""))
        )
    assert len(blockers) == 8
    for blocker in blockers:
        assert "exit 78" in str(blocker.get("run", ""))
        assert blocker.get("continue-on-error") is not True


def test_shape_has_no_release_side_effect_or_plaintext_secret() -> None:
    raw, _ = load_workflow()
    lowered = raw.lower()

    assert "password:" not in lowered
    assert "private_key" not in lowered
    assert "begin private key" not in lowered
    assert not re.search(r"\b(?:ssh|scp|rsync)\b", lowered)
    assert not re.search(r"\b(?:kubectl|helm)\b", lowered)
    assert "cosign sign" not in lowered
    assert "/deploy" not in lowered


def test_python_script_references_are_existing_or_the_named_future_blocker() -> None:
    raw, _ = load_workflow()
    references = set(
        re.findall(
            r"(?:/opt/control-release-verifier-v6/)?"
            r"scripts/([a-z0-9-]+\.py)",
            raw,
        )
    )
    existing = {
        path.name
        for path in (ROOT / "scripts").glob("*.py")
    }

    assert references <= existing
