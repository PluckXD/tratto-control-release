from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "policy-gate-v2.py"
READINESS_PATH = ROOT / "release-readiness-v2.json"
POLICY_PATH = ROOT / "policies" / "control-production-v2.json"
SPEC = importlib.util.spec_from_file_location(
    "control_release_policy_gate_v2",
    SCRIPT,
)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)


PINS = GATE.POLICY.AuditedPins(
    controller_repository_id=123456789,
    controller_workflow_sha256="3" * 64,
    controller_tag_trust_root_sha256="6" * 64,
    controller_tag_verifier_sha256="4" * 64,
    ledger_repository_id=234567890,
    ledger_genesis_sha="5" * 40,
)
COMMIT_SHA = "b" * 40
TAG_REF = "refs/tags/control-controller-v6.0.0"


def canonical(value: dict) -> bytes:
    return GATE.canonical_bytes(value)


def configured_policy() -> dict:
    return GATE.POLICY.expected_policy(PINS)


def ready_readiness() -> dict:
    return {
        "blockers": [],
        "required_approval_schema": 2,
        "required_envelope_schema": 6,
        "required_ops_install_mode": "atomic-quiesced",
        "required_policy_schema": 2,
        "schema_version": 2,
        "state": "ready",
    }


def github_context(phase: str = "authorize") -> dict[str, str]:
    repository = configured_policy()["controller"]["repository"]
    workflow_path = configured_policy()["controller"]["workflow_path"]
    value = {
        **GATE.STATIC_CONTEXT,
        "GITHUB_REF": TAG_REF,
        "GITHUB_REPOSITORY": repository,
        "GITHUB_REPOSITORY_ID": str(PINS.controller_repository_id),
        "GITHUB_SHA": COMMIT_SHA,
        "GITHUB_WORKFLOW_REF": (
            f"{repository}/{workflow_path}@{TAG_REF}"
        ),
        "GITHUB_WORKFLOW_SHA": COMMIT_SHA,
    }
    if phase == "sign_release":
        value.update(
            {
                "ACTIONS_ID_TOKEN_REQUEST_URL": (
                    "https://oidc.example.invalid/token"
                ),
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "opaque-oidc-token",
            }
        )
    return value


def validate(
    phase: str = "authorize",
    *,
    readiness: dict | None = None,
    policy: dict | None = None,
    pins=PINS,
    environment: dict[str, str] | None = None,
):
    return GATE.validate_release_gate(
        readiness_raw=canonical(readiness or ready_readiness()),
        policy_raw=GATE.POLICY.canonical_bytes(
            policy or configured_policy()
        ),
        audited_pins=pins,
        phase=phase,
        environment=environment or github_context(phase),
    )


EXPECTED_BLOCKERS = {
    "actions-policy",
    "builder-identities-images",
    "carrier-identities",
    "cryptographic-tag-verifier",
    "hml-ubuntu-kill-resume",
    "immutable-controller-releases",
    "ledger-controls",
    "protected-environment",
    "signer-oidc-freshness",
    "workflow-v6",
}


def test_checked_in_readiness_v2_is_canonical_and_unavailable() -> None:
    raw = READINESS_PATH.read_bytes()
    value, digest = GATE.validate_readiness_bytes(raw)

    assert raw == canonical(value)
    assert digest == hashlib.sha256(raw).hexdigest()
    assert value["schema_version"] == 2
    assert value["state"] == "unavailable"
    assert value["required_envelope_schema"] == 6
    assert value["required_approval_schema"] == 2
    assert value["required_policy_schema"] == 2
    assert value["required_ops_install_mode"] == "atomic-quiesced"
    assert {item["id"] for item in value["blockers"]} == EXPECTED_BLOCKERS
    joined = " ".join(item["resolution"] for item in value["blockers"])
    for required in (
        "full commit SHA",
        "builder images pinned by digest",
        "carrier read and write identities",
        "owner-controlled",
        "cryptographic annotated-tag verifier",
        "ledger repository",
        "administrator bypass",
        "second independent reviewer",
        "OIDC signer",
        "immediately before signing",
        "v6 controller workflow",
        "Ubuntu HML",
        "kill-and-resume",
    ):
        assert required in joined


@pytest.mark.parametrize("phase", sorted(GATE.PHASES))
def test_pure_api_accepts_every_phase_with_explicit_configured_policy(
    phase: str,
) -> None:
    result = validate(phase)
    assert result.as_dict() == {
        "controller_commit_sha": COMMIT_SHA,
        "controller_ref": TAG_REF,
        "phase": phase,
        "policy_sha256": hashlib.sha256(
            GATE.POLICY.canonical_bytes(configured_policy())
        ).hexdigest(),
        "readiness_sha256": hashlib.sha256(
            canonical(ready_readiness())
        ).hexdigest(),
    }


def test_unavailable_readiness_rejects_with_all_blocker_ids() -> None:
    value, _ = GATE.validate_readiness_bytes(READINESS_PATH.read_bytes())
    with pytest.raises(
        GATE.GateV2Error,
        match="RELEASE_POLICY_UNAVAILABLE",
    ) as captured:
        validate(readiness=value)
    for blocker in EXPECTED_BLOCKERS:
        assert blocker in str(captured.value)


@pytest.mark.parametrize(
    ("path", "bad"),
    [
        (("schema_version",), 1),
        (("schema_version",), True),
        (("required_envelope_schema",), 5),
        (("required_approval_schema",), 1),
        (("required_policy_schema",), 1),
        (("required_ops_install_mode",), "copy"),
        (("state",), "enabled"),
        (("blockers",), {}),
    ],
)
def test_readiness_rejects_incompatible_contract(
    path: tuple[str, ...],
    bad: object,
) -> None:
    value = ready_readiness()
    value[path[0]] = bad
    with pytest.raises(GATE.GateV2Error):
        GATE.validate_readiness_bytes(canonical(value))


def test_readiness_rejects_noncanonical_duplicate_unknown_and_state_lies() -> None:
    value = ready_readiness()
    pretty = json.dumps(value, indent=2).encode("utf-8") + b"\n"
    with pytest.raises(GATE.GateV2Error, match="canonical"):
        GATE.validate_readiness_bytes(pretty)

    duplicate = canonical(value).replace(
        b'{"blockers":[],',
        b'{"blockers":[],"blockers":[],',
        1,
    )
    with pytest.raises(GATE.GateV2Error, match="duplicate JSON key"):
        GATE.validate_readiness_bytes(duplicate)

    extra = copy.deepcopy(value)
    extra["authorization"] = "allow"
    with pytest.raises(GATE.GateV2Error, match="keys diverge"):
        GATE.validate_readiness_bytes(canonical(extra))

    lying_ready = copy.deepcopy(value)
    lying_ready["blockers"] = [
        {"id": "still-blocked", "resolution": "Finish the proof."}
    ]
    with pytest.raises(GATE.GateV2Error, match="cannot retain blockers"):
        GATE.validate_readiness_bytes(canonical(lying_ready))

    empty_unavailable = copy.deepcopy(value)
    empty_unavailable["state"] = "unavailable"
    with pytest.raises(GATE.GateV2Error, match="identify blockers"):
        GATE.validate_readiness_bytes(canonical(empty_unavailable))


@pytest.mark.parametrize(
    "blockers",
    [
        [
            {"id": "z-last", "resolution": "Later."},
            {"id": "a-first", "resolution": "First."},
        ],
        [
            {"id": "same", "resolution": "One."},
            {"id": "same", "resolution": "Two."},
        ],
        [{"id": "Bad_ID", "resolution": "Invalid id."}],
        [{"id": "valid", "resolution": " surrounding "}],
        [{"id": "valid", "resolution": ""}],
        [{"id": "valid", "resolution": "Valid.", "extra": True}],
    ],
)
def test_readiness_rejects_ambiguous_blockers(blockers: list[dict]) -> None:
    value = ready_readiness()
    value["state"] = "unavailable"
    value["blockers"] = blockers
    with pytest.raises(GATE.GateV2Error):
        GATE.validate_readiness_bytes(canonical(value))


def test_readiness_file_loader_rejects_symlink_and_hardlink(
    tmp_path: Path,
) -> None:
    target = tmp_path / "readiness.json"
    target.write_bytes(canonical(ready_readiness()))
    target.chmod(0o600)
    symlink = tmp_path / "readiness-link.json"
    symlink.symlink_to(target)
    with pytest.raises(GATE.GateV2Error, match="symlinks"):
        GATE.load_readiness_bytes(symlink)

    hardlink = tmp_path / "readiness-hard.json"
    os.link(target, hardlink)
    with pytest.raises(GATE.GateV2Error, match="single-link"):
        GATE.load_readiness_bytes(target)


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("GITHUB_ACTIONS", "false"),
        ("GITHUB_API_URL", "https://github.example/api"),
        ("GITHUB_SERVER_URL", "https://github.example"),
        ("GITHUB_EVENT_NAME", "push"),
        ("GITHUB_REF_TYPE", "branch"),
        ("GITHUB_REPOSITORY", "PluckXD/tratto-api"),
        ("GITHUB_REPOSITORY_ID", str(PINS.controller_repository_id + 1)),
        ("GITHUB_REPOSITORY_ID", f"0{PINS.controller_repository_id}"),
        ("RUNNER_ENVIRONMENT", "self-hosted"),
        ("RUNNER_OS", "Windows"),
        ("RUNNER_ARCH", "ARM64"),
        ("GITHUB_SHA", "B" * 40),
        ("GITHUB_SHA", "b" * 39),
        ("GITHUB_WORKFLOW_SHA", "c" * 40),
        (
            "GITHUB_WORKFLOW_REF",
            (
                "PluckXD/tratto-control-release/"
                ".github/workflows/other.yml@"
                f"{TAG_REF}"
            ),
        ),
    ],
)
def test_execution_context_rejects_every_mutated_binding(
    field: str,
    bad: str,
) -> None:
    value = github_context()
    value[field] = bad
    with pytest.raises(GATE.GateV2Error):
        validate(environment=value)


@pytest.mark.parametrize(
    "field",
    sorted(GATE.REQUIRED_CONTEXT_KEYS),
)
def test_execution_context_rejects_every_missing_binding(field: str) -> None:
    value = github_context()
    value.pop(field)
    with pytest.raises(
        GATE.GateV2Error,
        match=f"trusted GitHub context is invalid: {field}",
    ):
        validate(environment=value)


@pytest.mark.parametrize(
    "ref",
    [
        "refs/heads/main",
        "refs/tags/control-controller-v5.0.0",
        "refs/tags/control-controller-v6.0",
        "refs/tags/control-controller-v6.00.0",
        "refs/tags/control-controller-v6.0.00",
        "refs/tags/control-controller-v6.x.0",
        "refs/tags/control-controller-v6.0.0/other",
        "refs/tags/CONTROL-CONTROLLER-V6.0.0",
    ],
)
def test_execution_context_rejects_noncanonical_controller_tag(
    ref: str,
) -> None:
    value = github_context()
    value["GITHUB_REF"] = ref
    repository = value["GITHUB_REPOSITORY"]
    workflow_path = configured_policy()["controller"]["workflow_path"]
    value["GITHUB_WORKFLOW_REF"] = (
        f"{repository}/{workflow_path}@{ref}"
    )
    with pytest.raises(GATE.GateV2Error, match="semantic tag"):
        validate(environment=value)


@pytest.mark.parametrize(
    "phase",
    sorted(GATE.PHASES - {"sign_release"}),
)
@pytest.mark.parametrize(
    "oidc_field",
    [
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    ],
)
def test_non_signer_phases_reject_oidc(
    phase: str,
    oidc_field: str,
) -> None:
    value = github_context(phase)
    value[oidc_field] = "unexpected"
    with pytest.raises(GATE.GateV2Error, match="must not receive an OIDC"):
        validate(phase, environment=value)


@pytest.mark.parametrize(
    "missing",
    [
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    ],
)
def test_signer_requires_both_oidc_values(missing: str) -> None:
    value = github_context("sign_release")
    value.pop(missing)
    with pytest.raises(GATE.GateV2Error, match="OIDC context"):
        validate("sign_release", environment=value)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("CONTROL_API_READ_TOKEN", "secret", "product credentials"),
        ("CONTROL_WEB_READ_TOKEN", "secret", "product credentials"),
        ("CONTROL_SIGNER_SOURCE_CHECKOUT", "/workspace", "source checkout"),
    ],
)
def test_signer_rejects_product_credentials_and_source_checkout(
    field: str,
    value: str,
    message: str,
) -> None:
    environment = github_context("sign_release")
    environment[field] = value
    with pytest.raises(GATE.GateV2Error, match=message):
        validate("sign_release", environment=environment)


@pytest.mark.parametrize(
    ("phase", "credential"),
    [
        ("authorize", "CONTROL_API_READ_TOKEN"),
        ("authorize", "CONTROL_WEB_READ_TOKEN"),
        ("verify", "CONTROL_API_READ_TOKEN"),
        ("verify", "CONTROL_WEB_READ_TOKEN"),
        ("build_api", "CONTROL_WEB_READ_TOKEN"),
        ("build_ops", "CONTROL_WEB_READ_TOKEN"),
        ("build_web", "CONTROL_API_READ_TOKEN"),
    ],
)
def test_other_phases_reject_cross_boundary_product_credentials(
    phase: str,
    credential: str,
) -> None:
    environment = github_context(phase)
    environment[credential] = "secret"
    with pytest.raises(GATE.GateV2Error, match=credential):
        validate(phase, environment=environment)


@pytest.mark.parametrize(
    ("phase", "credential"),
    [
        ("build_api", "CONTROL_API_READ_TOKEN"),
        ("build_ops", "CONTROL_API_READ_TOKEN"),
        ("build_web", "CONTROL_WEB_READ_TOKEN"),
    ],
)
def test_builder_may_receive_only_its_explicit_source_credential(
    phase: str,
    credential: str,
) -> None:
    environment = github_context(phase)
    environment[credential] = "source-read-only"
    validate(phase, environment=environment)


def test_policy_must_be_configured_and_match_explicit_audited_pins() -> None:
    template_raw = POLICY_PATH.read_bytes()
    with pytest.raises(
        GATE.GateV2Error,
        match="audited production pins are unavailable",
    ):
        GATE.validate_release_gate(
            readiness_raw=canonical(ready_readiness()),
            policy_raw=template_raw,
            audited_pins=GATE.POLICY.PRODUCTION_AUDITED_PINS,
            phase="authorize",
            environment=github_context(),
        )

    wrong_pins = GATE.POLICY.AuditedPins(
        **{
            **PINS.__dict__,
            "controller_repository_id": (
                PINS.controller_repository_id + 1
            ),
        }
    )
    with pytest.raises(GATE.GateV2Error, match="audited pins"):
        validate(pins=wrong_pins)


def test_readiness_and_policy_schema_bindings_must_match() -> None:
    value = ready_readiness()
    value["required_approval_schema"] = 3
    raw = canonical(value)
    with pytest.raises(GATE.GateV2Error, match="readiness contract"):
        GATE.validate_readiness_bytes(raw)


def test_unknown_phase_is_rejected_by_pure_api() -> None:
    with pytest.raises(GATE.GateV2Error, match="unknown release phase"):
        validate("publish")


def test_cli_uses_only_checked_in_unavailable_policy_and_returns_78() -> None:
    environment = {
        **os.environ,
        **github_context(),
        "CONTROL_CONTROLLER_REPOSITORY_ID": str(
            PINS.controller_repository_id
        ),
        "CONTROL_LEDGER_GENESIS_SHA": PINS.ledger_genesis_sha,
        "CONTROL_POLICY_PINS_JSON": json.dumps(PINS.__dict__),
    }
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(SCRIPT),
            "--phase",
            "authorize",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 78
    assert "audited production pins are unavailable" in completed.stderr
    assert not completed.stdout


@pytest.mark.parametrize(
    "forbidden_arguments",
    [
        ["--readiness", "/tmp/ready.json"],
        ["--policy", "/tmp/policy.json"],
        ["--repository-id", str(PINS.controller_repository_id)],
        ["--ledger-genesis-sha", PINS.ledger_genesis_sha],
    ],
)
def test_cli_accepts_no_document_or_trust_pin_overrides(
    forbidden_arguments: list[str],
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(SCRIPT),
            "--phase",
            "authorize",
            *forbidden_arguments,
        ],
        cwd=ROOT,
        env={**os.environ, **github_context()},
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert "unrecognized arguments" in completed.stderr
