from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / "workflow-v6-shape.yml"
EMITTER_PATH = ROOT / "scripts" / "emit-approval-v2-outputs.py"
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


def emitter_output_keys() -> set[str]:
    tree = ast.parse(EMITTER_PATH.read_bytes(), filename=str(EMITTER_PATH))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "OUTPUT_KEYS"
            for target in node.targets
        ):
            continue
        value = ast.literal_eval(node.value)
        assert isinstance(value, tuple)
        assert all(isinstance(key, str) for key in value)
        return set(value)
    raise AssertionError("emitter OUTPUT_KEYS assignment is missing")


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
        "scripts/collect-github-evidence-v2.py",
        "scripts/policy-gate-v2.py --phase authorize",
        "scripts/validate-policy-v2.py",
        "scripts/verify-controller-tag.py",
        "scripts/verify-github-controls-v2.py",
        "scripts/validate-ledger.py",
        "scripts/validate-approval-v2.py",
        "scripts/emit-approval-v2-outputs.py",
    }
    assert all(command in text for command in required_commands)
    assert "--controller-tag-signature-verifier" in text
    assert "scripts/verify-controller-tag.py" in text
    assert "--signer-freshness-verifier-manifest" in text
    assert "/opt/control-release-verifier-v6/identity.json" in text
    assert "--signer-verifier" not in text
    outputs = authorize["outputs"]
    emitted = emitter_output_keys()
    assert set(outputs) == emitted | {"controller_repository_id"}
    for key in emitted:
        assert outputs[key] == f"${{{{ steps.intent.outputs.{key} }}}}"
    assert outputs["controller_repository_id"] == (
        "${{ steps.controller_evidence.outputs.repository_id }}"
    )
    assert "FUTURE BLOCKER" not in repr(authorize)
    assert secret_names(authorize) == {"CONTROL_CONTROLLER_AUDIT_TOKEN"}
    assert "$RUNNER_TEMP/control-evidence-v2" in text
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

    preflight = next(
        step
        for step in steps(signer)
        if "source-free verifier bundle identity" in step.get("name", "")
    )
    assert preflight["env"] == {
        "CONTROLLER_TAG_SIGNATURE_VERIFIER_SHA256": (
            "${{ needs.authorize.outputs."
            "controller_tag_signature_verifier_sha256 }}"
        ),
        "POLICY_SHA256": "${{ needs.authorize.outputs.policy_sha256 }}",
        "RUNNER_ENVIRONMENT": "${{ runner.environment }}",
        "SIGNER_FRESHNESS_VERIFIER_SHA256": (
            "${{ needs.authorize.outputs."
            "signer_freshness_verifier_sha256 }}"
        ),
        "TRUST_EPOCH": "${{ needs.authorize.outputs.trust_epoch }}",
    }
    text = run_text(signer)
    assert "policy-gate-v2.py" not in text
    assert "validate-policy-v2.py" not in text
    assert "--phase sign_release" in text
    preflight_at = text.index("verify-control-release-verifier-v1")
    assert "--expected-sha256" in text
    assert (
        "--policy /opt/control-release-policy-v2/"
        "control-production-v2.json" in text
    )
    assert "/opt/control-release-verifier-v6/policies/" not in text
    assert "--expected-policy-sha256" in text
    assert "--expected-trust-epoch" in text
    assert '--runner-environment "$RUNNER_ENVIRONMENT"' in text
    assert "--expected-controller-tag-signature-verifier-sha256" in text
    assert '--expected-sha256 "$SIGNER_FRESHNESS_VERIFIER_SHA256"' in text
    assert '--expected-policy-sha256 "$POLICY_SHA256"' in text
    assert '--expected-trust-epoch "$TRUST_EPOCH"' in text
    assert re.search(
        r'--expected-controller-tag-signature-verifier-sha256 \\\n'
        r'\s+"\$CONTROLLER_TAG_SIGNATURE_VERIFIER_SHA256"',
        text,
    )
    assert "CONTROLLER_TAG_SIGNATURE_VERIFIER_SHA256" in text
    assert "POLICY_SHA256" in text
    assert "SIGNER_FRESHNESS_VERIFIER_SHA256" in text
    assert "TRUST_EPOCH" in text
    assert "${{ needs.authorize.outputs.policy_sha256 }}" in repr(signer)
    assert "${{ needs.authorize.outputs.trust_epoch }}" in repr(signer)
    tag_at = text.index("verify-controller-tag.py")
    ledger_at = text.index("validate-ledger.py")
    controls_at = text.index("verify-github-controls-v2.py")
    freshness_at = text.index("validate-signer-freshness-v2.py")
    closed_at = text.index(
        "reviewed Cosign verifier/identity is not provisioned"
    )
    assert preflight_at < tag_at < ledger_at < controls_at < freshness_at
    assert freshness_at < closed_at
    assert "authenticated fresh-evidence collector is not provisioned" in text
    assert (
        'test "$CONTROLLER_WORKFLOW_REPOSITORY_ID" != '
        '"$CONTROLLER_AUTHORIZED_REPOSITORY_ID"' in text
    )
    assert "signer repository identity diverges" in text
    assert (
        '--workflow-repository-id "$CONTROLLER_WORKFLOW_REPOSITORY_ID"'
        in text
    )
    assert '--workflow-run-id "$CONTROLLER_WORKFLOW_RUN_ID"' in text
    assert '--workflow-run-attempt "$CONTROLLER_WORKFLOW_RUN_ATTEMPT"' in text
    assert "${{ github.run_id }}" in repr(signer)
    assert "${{ github.run_attempt }}" in repr(signer)
    assert "${{ github.repository_id }}" in repr(signer)
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
    assert len(blockers) == 6
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
