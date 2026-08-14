from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest


sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-signer-freshness-v2.py"
FIXTURE_SOURCE = ROOT / "tests" / "test_validate_envelope_v6.py"

SPEC = importlib.util.spec_from_file_location(
    "validate_signer_freshness_v2",
    SCRIPT,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "signer_freshness_envelope_fixtures",
    FIXTURE_SOURCE,
)
assert FIXTURE_SPEC is not None and FIXTURE_SPEC.loader is not None
FIXTURES = importlib.util.module_from_spec(FIXTURE_SPEC)
sys.modules[FIXTURE_SPEC.name] = FIXTURES
FIXTURE_SPEC.loader.exec_module(FIXTURES)

NOW = dt.datetime(2026, 8, 1, 12, 30, tzinfo=dt.timezone.utc)
RUNTIME_IDENTITY = "tratto-signer-runtime/v2@test"
DEFAULT_WORKFLOW_RUN = MODULE.WorkflowRunScope(
    repository_id=22001,
    run_id=123,
    run_attempt=1,
)


def canonical(value: dict[str, Any]) -> bytes:
    return MODULE.canonical_bytes(value)


def base_documents() -> tuple[dict[str, Any], dict[str, Any]]:
    envelope = FIXTURES.envelope(sequence=2)
    return copy.deepcopy(envelope["approval"]["manifest"]), envelope


def ledger_attestation(
    approval: dict[str, Any],
    envelope: dict[str, Any],
) -> dict[str, Any]:
    return {
        "genesis_sha": approval["ledger"]["genesis_sha"],
        "head_sha": envelope["ledger"]["head_sha"],
        "manifest_sha256": envelope["ledger"]["manifest_sha256"],
        "record_count": envelope["ledger"]["record_count"],
        "release_id": approval["release_id"],
    }


def controller_attestation(approval: dict[str, Any]) -> dict[str, Any]:
    controller = approval["controller"]
    return {
        "commit_sha": controller["commit_sha"],
        "owner_enforced": True,
        "release_id": controller["immutable_release_id"],
        "repository": controller["repository"],
        "repository_id": controller["repository_id"],
        "tag": controller["tag_ref"].removeprefix("refs/tags/"),
        "tag_object_sha": controller["tag_object_sha"],
    }


def controls_attestation(approval: dict[str, Any]) -> dict[str, Any]:
    return {
        "controller_repository": approval["controller"]["repository"],
        "controller_repository_id": approval["controller"]["repository_id"],
        "environment": "control-release",
        "environment_reviewer_count": 2,
        "ledger_repository": approval["ledger"]["repository"],
        "ledger_repository_id": approval["ledger"]["repository_id"],
        "minimum_pull_request_approvals": 2,
    }


def authenticated(
    kind: MODULE.AttestationKind,
    value: dict[str, Any],
    sequence: int,
    *,
    identity: str = RUNTIME_IDENTITY,
    workflow_run: MODULE.WorkflowRunScope = DEFAULT_WORKFLOW_RUN,
    authentication_overrides: dict[str, Any] | None = None,
) -> MODULE.AuthenticatedAttestation:
    raw = canonical(value)

    def authenticate(
        received_kind: MODULE.AttestationKind,
        received_raw: bytes,
    ) -> MODULE.AttestationAuthentication:
        fields: dict[str, Any] = {
            "authenticated": True,
            "digest_sha256": hashlib.sha256(received_raw).hexdigest(),
            "kind": received_kind,
            "observation_sequence": sequence,
            "signer_runtime_identity": identity,
            "workflow_run": workflow_run,
        }
        fields.update(authentication_overrides or {})
        return MODULE.AttestationAuthentication(**fields)

    return MODULE.authenticate_attestation(kind, raw, authenticate)


def case(
    *,
    initial_ledger_value: dict[str, Any] | None = None,
    fresh_ledger_value: dict[str, Any] | None = None,
    initial_controller_value: dict[str, Any] | None = None,
    fresh_controller_value: dict[str, Any] | None = None,
    initial_controls_value: dict[str, Any] | None = None,
    fresh_controls_value: dict[str, Any] | None = None,
    fresh_sequences: tuple[int, int, int] = (2, 2, 2),
    fresh_identity: str = RUNTIME_IDENTITY,
    candidate_override: dict[str, Any] | None = None,
    observation_scope_overrides: (
        dict[str, MODULE.WorkflowRunScope] | None
    ) = None,
    runtime_scope: MODULE.WorkflowRunScope | None = None,
) -> dict[str, Any]:
    approval, envelope = base_documents()
    ledger = ledger_attestation(approval, envelope)
    controller = controller_attestation(approval)
    controls = controls_attestation(approval)
    workflow_run = MODULE.WorkflowRunScope(
        repository_id=envelope["controller"]["repository_id"],
        run_id=envelope["controller"]["run_id"],
        run_attempt=envelope["controller"]["run_attempt"],
    )
    scopes = observation_scope_overrides or {}

    initial_ledger = authenticated(
        MODULE.AttestationKind.LEDGER,
        initial_ledger_value or ledger,
        1,
        workflow_run=scopes.get("initial_ledger", workflow_run),
    )
    fresh_ledger = authenticated(
        MODULE.AttestationKind.LEDGER,
        fresh_ledger_value or ledger,
        fresh_sequences[0],
        identity=fresh_identity,
        workflow_run=scopes.get("fresh_ledger", workflow_run),
    )
    initial_controller = authenticated(
        MODULE.AttestationKind.CONTROLLER_TAG,
        initial_controller_value or controller,
        1,
        workflow_run=scopes.get("initial_controller_tag", workflow_run),
    )
    fresh_controller = authenticated(
        MODULE.AttestationKind.CONTROLLER_TAG,
        fresh_controller_value or controller,
        fresh_sequences[1],
        identity=fresh_identity,
        workflow_run=scopes.get("fresh_controller_tag", workflow_run),
    )
    initial_controls = authenticated(
        MODULE.AttestationKind.GITHUB_CONTROLS,
        initial_controls_value or controls,
        1,
        workflow_run=scopes.get("initial_github_controls", workflow_run),
    )
    fresh_controls = authenticated(
        MODULE.AttestationKind.GITHUB_CONTROLS,
        fresh_controls_value or controls,
        fresh_sequences[2],
        identity=fresh_identity,
        workflow_run=scopes.get("fresh_github_controls", workflow_run),
    )

    # The envelope declares the current run.  Build that independently from
    # the supplied observations so negative tests can model replayed evidence
    # from a different run without making the envelope itself malformed.
    summary_ledger = authenticated(
        MODULE.AttestationKind.LEDGER,
        ledger,
        2,
        workflow_run=workflow_run,
    )
    summary_controller = authenticated(
        MODULE.AttestationKind.CONTROLLER_TAG,
        controller,
        2,
        workflow_run=workflow_run,
    )
    summary_controls = authenticated(
        MODULE.AttestationKind.GITHUB_CONTROLS,
        controls,
        2,
        workflow_run=workflow_run,
    )
    derived_block = MODULE.build_signer_freshness_block(
        fresh_ledger=summary_ledger,
        fresh_controller_tag=summary_controller,
        fresh_github_controls=summary_controls,
    )
    # A candidate envelope is independently valid only when its declared
    # ledger head remains the envelope's validated head.  The signer validator
    # must still detect a different freshly observed head before signing.
    derived_block["ledger_head_sha"] = envelope["ledger"]["head_sha"]
    envelope["signer_freshness"] = candidate_override or derived_block
    return {
        "approval": MODULE.validate_approval_v2_bytes(
            MODULE.APPROVAL.canonical_bytes(approval),
            now=NOW,
        ),
        "envelope_candidate": MODULE.validate_envelope_v6_bytes(
            MODULE.ENVELOPE.canonical_bytes(envelope)
        ),
        "fresh_controller_tag": fresh_controller,
        "fresh_github_controls": fresh_controls,
        "fresh_ledger": fresh_ledger,
        "initial_controller_tag": initial_controller,
        "initial_github_controls": initial_controls,
        "initial_ledger": initial_ledger,
        "signer_runtime": MODULE.SignerRuntimeIdentity(
            RUNTIME_IDENTITY,
            runtime_scope or workflow_run,
        ),
    }


def validate(values: dict[str, Any]) -> dict[str, Any]:
    return MODULE.validate_signer_freshness(**values)


def test_accepts_unchanged_fresh_authorities_and_returns_exact_block() -> None:
    values = case()
    expected = MODULE.build_signer_freshness_block(
        fresh_ledger=values["fresh_ledger"],
        fresh_controller_tag=values["fresh_controller_tag"],
        fresh_github_controls=values["fresh_github_controls"],
    )
    assert validate(values) == expected
    assert expected["ledger_head_sha"] == "d" * 40
    assert expected["evidence_model"] == "workflow-signed-summary-v1"
    assert expected["revalidated_immediately_before_signature"] is True
    assert expected["workflow_run"] == {
        "repository_id": 22001,
        "run_attempt": 1,
        "run_id": 123,
    }
    assert len(
        {
            expected["ledger_attestation_sha256"],
            expected["controller_tag_attestation_sha256"],
            expected["github_controls_attestation_sha256"],
        }
    ) == 3


def test_freshness_digests_are_of_exact_fresh_canonical_bytes() -> None:
    values = case()
    result = validate(values)
    mappings = {
        "ledger_attestation_sha256": values["fresh_ledger"],
        "controller_tag_attestation_sha256": values[
            "fresh_controller_tag"
        ],
        "github_controls_attestation_sha256": values[
            "fresh_github_controls"
        ],
    }
    for key, attestation in mappings.items():
        assert result[key] == hashlib.sha256(
            attestation.canonical
        ).hexdigest()


@pytest.mark.parametrize(
    ("kind", "value_factory", "mutation", "message"),
    [
        (
            MODULE.AttestationKind.LEDGER,
            lambda approval, envelope: ledger_attestation(
                approval,
                envelope,
            ),
            lambda value: value.update({"extra": True}),
            "keys diverge",
        ),
        (
            MODULE.AttestationKind.LEDGER,
            lambda approval, envelope: ledger_attestation(
                approval,
                envelope,
            ),
            lambda value: value.update({"record_count": True}),
            "bounded positive integer",
        ),
        (
            MODULE.AttestationKind.CONTROLLER_TAG,
            lambda approval, _envelope: controller_attestation(approval),
            lambda value: value.update({"owner_enforced": 1}),
            "must be boolean",
        ),
        (
            MODULE.AttestationKind.CONTROLLER_TAG,
            lambda approval, _envelope: controller_attestation(approval),
            lambda value: value.update({"repository_id": True}),
            "bounded positive integer",
        ),
        (
            MODULE.AttestationKind.GITHUB_CONTROLS,
            lambda approval, _envelope: controls_attestation(approval),
            lambda value: value.update(
                {"minimum_pull_request_approvals": True}
            ),
            "bounded positive integer",
        ),
        (
            MODULE.AttestationKind.GITHUB_CONTROLS,
            lambda approval, _envelope: controls_attestation(approval),
            lambda value: value.update({"unexpected": "value"}),
            "keys diverge",
        ),
    ],
)
def test_attestation_schemas_are_exact_and_reject_bool_as_int(
    kind,
    value_factory,
    mutation,
    message: str,
) -> None:
    approval, envelope = base_documents()
    value = value_factory(approval, envelope)
    mutation(value)
    with pytest.raises(MODULE.SignerFreshnessV2Error, match=message):
        authenticated(kind, value, 1)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1, "b":2}\n',
        b'{"a":1,"a":2}\n',
        b'{"a":NaN}\n',
        b"[]\n",
        b"\xff",
        b"",
    ],
)
def test_attestation_parser_rejects_noncanonical_or_ambiguous_json(
    raw: bytes,
) -> None:
    with pytest.raises(MODULE.SignerFreshnessV2Error):
        MODULE.parse_canonical_attestation(raw)


def test_attestation_parser_is_bounded() -> None:
    with pytest.raises(MODULE.SignerFreshnessV2Error, match="invalid size"):
        MODULE.parse_canonical_attestation(
            b"x" * (MODULE.MAX_ATTESTATION_BYTES + 1)
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("repository_id", True),
        ("run_id", True),
        ("run_attempt", True),
        ("repository_id", 0),
        ("run_id", 0),
        ("run_attempt", 0),
        ("repository_id", MODULE.MAX_OBSERVATION_SEQUENCE + 1),
        ("run_id", MODULE.MAX_OBSERVATION_SEQUENCE + 1),
        ("run_attempt", MODULE.MAX_OBSERVATION_SEQUENCE + 1),
    ],
)
def test_workflow_run_scope_requires_strict_positive_integers(
    field: str,
    replacement: int | bool,
) -> None:
    values = DEFAULT_WORKFLOW_RUN.as_dict()
    values[field] = replacement
    with pytest.raises(
        MODULE.SignerFreshnessV2Error,
        match=rf"workflow run {field} must be a bounded positive integer",
    ):
        MODULE.WorkflowRunScope(
            repository_id=values["repository_id"],
            run_id=values["run_id"],
            run_attempt=values["run_attempt"],
        )


def test_workflow_run_scope_accepts_exact_signed_63_bit_maximum() -> None:
    maximum = MODULE.MAX_OBSERVATION_SEQUENCE
    scope = MODULE.WorkflowRunScope(
        repository_id=maximum,
        run_id=maximum,
        run_attempt=maximum,
    )
    assert scope.as_dict() == {
        "repository_id": maximum,
        "run_attempt": maximum,
        "run_id": maximum,
    }


@pytest.mark.parametrize(
    "value",
    [
        {"repository_id": 22001, "run_id": 123},
        {
            "repository_id": 22001,
            "run_attempt": 1,
            "run_id": 123,
            "unknown": 1,
        },
        [],
    ],
)
def test_workflow_run_wire_scope_requires_exact_object_shape(
    value: Any,
) -> None:
    with pytest.raises(MODULE.SignerFreshnessV2Error):
        MODULE.workflow_run_scope(value, "test workflow run")


def test_signer_runtime_requires_typed_workflow_run_scope() -> None:
    with pytest.raises(MODULE.SignerFreshnessV2Error, match="must be typed"):
        MODULE.SignerRuntimeIdentity(
            RUNTIME_IDENTITY,
            DEFAULT_WORKFLOW_RUN.as_dict(),
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"authenticated": 1}, "marker must be boolean"),
        ({"authenticated": False}, "was not authenticated"),
        ({"digest_sha256": "0" * 64}, "digest diverges"),
        ({"kind": MODULE.AttestationKind.CONTROLLER_TAG}, "kind diverges"),
        ({"observation_sequence": True}, "bounded positive integer"),
        ({"signer_runtime_identity": "bad"}, "invalid format"),
        (
            {"workflow_run": DEFAULT_WORKFLOW_RUN.as_dict()},
            "scope must be typed",
        ),
    ],
)
def test_authenticator_result_is_strictly_typed_and_bound(
    overrides: dict[str, Any],
    message: str,
) -> None:
    approval, envelope = base_documents()
    with pytest.raises(MODULE.SignerFreshnessV2Error, match=message):
        authenticated(
            MODULE.AttestationKind.LEDGER,
            ledger_attestation(approval, envelope),
            1,
            authentication_overrides=overrides,
        )


def test_authenticator_cannot_return_a_self_declared_dict() -> None:
    approval, envelope = base_documents()
    raw = canonical(ledger_attestation(approval, envelope))
    with pytest.raises(MODULE.SignerFreshnessV2Error, match="untyped"):
        MODULE.authenticate_attestation(
            MODULE.AttestationKind.LEDGER,
            raw,
            lambda _kind, _raw: {
                "authenticated": True,
                "digest_sha256": hashlib.sha256(raw).hexdigest(),
            },
        )


@pytest.mark.parametrize(
    ("sequences", "message"),
    [
        ((1, 2, 2), "fresh ledger observation is stale"),
        ((2, 1, 2), "fresh controller-tag observation is stale"),
        ((2, 2, 1), "fresh github-controls observation is stale"),
    ],
)
def test_rejects_stale_fresh_observation_sequences(
    sequences: tuple[int, int, int],
    message: str,
) -> None:
    values = case(fresh_sequences=sequences)
    with pytest.raises(MODULE.SignerFreshnessV2Error, match=message):
        validate(values)


def test_rejects_reuse_of_initial_observation_object() -> None:
    values = case()
    values["fresh_ledger"] = values["initial_ledger"]
    with pytest.raises(MODULE.SignerFreshnessV2Error, match="reused"):
        validate(values)


def test_rejects_fresh_observation_from_another_signer_runtime() -> None:
    values = case(fresh_identity="different-signer-runtime/v2@test")
    with pytest.raises(
        MODULE.SignerFreshnessV2Error,
        match="runtime identity diverges",
    ):
        validate(values)


OBSERVATION_FIELDS = (
    "initial_ledger",
    "fresh_ledger",
    "initial_controller_tag",
    "fresh_controller_tag",
    "initial_github_controls",
    "fresh_github_controls",
)


@pytest.mark.parametrize("field", OBSERVATION_FIELDS)
@pytest.mark.parametrize(
    "foreign_scope",
    [
        MODULE.WorkflowRunScope(
            repository_id=22002,
            run_id=123,
            run_attempt=1,
        ),
        MODULE.WorkflowRunScope(
            repository_id=22001,
            run_id=124,
            run_attempt=1,
        ),
        MODULE.WorkflowRunScope(
            repository_id=22001,
            run_id=123,
            run_attempt=2,
        ),
    ],
)
def test_rejects_every_observation_from_another_workflow_scope(
    field: str,
    foreign_scope: MODULE.WorkflowRunScope,
) -> None:
    values = case(
        observation_scope_overrides={field: foreign_scope},
    )
    with pytest.raises(
        MODULE.SignerFreshnessV2Error,
        match="workflow run scope diverges",
    ):
        validate(values)


def test_rejects_complete_cross_attempt_evidence_replay() -> None:
    foreign_attempt = MODULE.WorkflowRunScope(
        repository_id=22001,
        run_id=123,
        run_attempt=2,
    )
    values = case(
        observation_scope_overrides={
            field: foreign_attempt for field in OBSERVATION_FIELDS
        },
    )
    with pytest.raises(
        MODULE.SignerFreshnessV2Error,
        match="workflow run scope diverges",
    ):
        validate(values)


def test_freshness_builder_rejects_divergent_fresh_run_scopes() -> None:
    values = case()
    approval, envelope = base_documents()
    foreign_ledger = authenticated(
        MODULE.AttestationKind.LEDGER,
        ledger_attestation(approval, envelope),
        2,
        workflow_run=MODULE.WorkflowRunScope(22001, 123, 2),
    )
    with pytest.raises(
        MODULE.SignerFreshnessV2Error,
        match="divergent workflow run scopes",
    ):
        MODULE.build_signer_freshness_block(
            fresh_ledger=foreign_ledger,
            fresh_controller_tag=values["fresh_controller_tag"],
            fresh_github_controls=values["fresh_github_controls"],
        )


@pytest.mark.parametrize(
    "runtime_scope",
    [
        MODULE.WorkflowRunScope(22002, 123, 1),
        MODULE.WorkflowRunScope(22001, 124, 1),
        MODULE.WorkflowRunScope(22001, 123, 2),
    ],
)
def test_rejects_signer_runtime_scope_divergent_from_envelope(
    runtime_scope: MODULE.WorkflowRunScope,
) -> None:
    values = case(runtime_scope=runtime_scope)
    with pytest.raises(
        MODULE.SignerFreshnessV2Error,
        match="signer runtime workflow run scope diverges from envelope",
    ):
        validate(values)


@pytest.mark.parametrize(
    ("authority", "mutation", "message"),
    [
        (
            "ledger",
            lambda value: value.update({"head_sha": "e" * 40}),
            "ledger changed",
        ),
        (
            "controller",
            lambda value: value.update({"commit_sha": "e" * 40}),
            "controller-tag changed",
        ),
        (
            "controls",
            lambda value: value.update({"environment_reviewer_count": 3}),
            "github-controls changed",
        ),
    ],
)
def test_rejects_authority_that_changed_between_observations(
    authority: str,
    mutation,
    message: str,
) -> None:
    approval, envelope = base_documents()
    initial = {
        "ledger": ledger_attestation(approval, envelope),
        "controller": controller_attestation(approval),
        "controls": controls_attestation(approval),
    }
    fresh = copy.deepcopy(initial)
    mutation(fresh[authority])
    values = case(
        initial_ledger_value=initial["ledger"],
        fresh_ledger_value=fresh["ledger"],
        initial_controller_value=initial["controller"],
        fresh_controller_value=fresh["controller"],
        initial_controls_value=initial["controls"],
        fresh_controls_value=fresh["controls"],
    )
    with pytest.raises(MODULE.SignerFreshnessV2Error, match=message):
        validate(values)


@pytest.mark.parametrize(
    ("authority", "mutation", "message"),
    [
        (
            "ledger",
            lambda value: value.update({"head_sha": "e" * 40}),
            "ledger attestation diverges",
        ),
        (
            "controller",
            lambda value: value.update({"commit_sha": "e" * 40}),
            "controller-tag attestation diverges",
        ),
        (
            "controls",
            lambda value: value.update(
                {"ledger_repository_id": value["ledger_repository_id"] + 1}
            ),
            "ledger_repository_id diverges",
        ),
    ],
)
def test_rejects_fresh_but_wrong_authority_binding(
    authority: str,
    mutation,
    message: str,
) -> None:
    approval, envelope = base_documents()
    values_by_authority = {
        "ledger": ledger_attestation(approval, envelope),
        "controller": controller_attestation(approval),
        "controls": controls_attestation(approval),
    }
    mutation(values_by_authority[authority])
    values = case(
        initial_ledger_value=values_by_authority["ledger"],
        fresh_ledger_value=values_by_authority["ledger"],
        initial_controller_value=values_by_authority["controller"],
        fresh_controller_value=values_by_authority["controller"],
        initial_controls_value=values_by_authority["controls"],
        fresh_controls_value=values_by_authority["controls"],
    )
    with pytest.raises(MODULE.SignerFreshnessV2Error, match=message):
        validate(values)


def test_rejects_validated_approval_different_from_envelope_approval() -> None:
    values = case()
    approval, _envelope = base_documents()
    approval["nonce"] = "AQEBAQEBAQEBAQEBAQEBAQ"
    values["approval"] = MODULE.validate_approval_v2_bytes(
        MODULE.APPROVAL.canonical_bytes(approval),
        now=NOW,
    )
    with pytest.raises(
        MODULE.SignerFreshnessV2Error,
        match="envelope approval diverges",
    ):
        validate(values)


def test_rejects_candidate_freshness_block_not_derived_from_fresh_bytes() -> None:
    wrong = {
        "controller_tag_attestation_sha256": "1" * 64,
        "evidence_model": "workflow-signed-summary-v1",
        "github_controls_attestation_sha256": "2" * 64,
        "ledger_attestation_sha256": "3" * 64,
        "ledger_head_sha": "d" * 40,
        "revalidated_immediately_before_signature": True,
        "workflow_run": DEFAULT_WORKFLOW_RUN.as_dict(),
    }
    values = case(candidate_override=wrong)
    with pytest.raises(
        MODULE.SignerFreshnessV2Error,
        match="signer_freshness diverges",
    ):
        validate(values)


def test_rejects_digest_reuse_across_attestation_types(monkeypatch) -> None:
    values = case()
    monkeypatch.setattr(MODULE, "sha256_hex", lambda _raw: "a" * 64)
    with pytest.raises(MODULE.SignerFreshnessV2Error, match="distinct"):
        MODULE.build_signer_freshness_block(
            fresh_ledger=values["fresh_ledger"],
            fresh_controller_tag=values["fresh_controller_tag"],
            fresh_github_controls=values["fresh_github_controls"],
        )


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("approval", {}, "typed validated approval"),
        ("envelope_candidate", {}, "typed validated envelope"),
        ("signer_runtime", {}, "identity must be typed"),
        ("fresh_ledger", {}, "typed authenticated evidence"),
    ],
)
def test_pure_api_rejects_raw_dicts_as_authority(
    field: str,
    replacement: dict[str, Any],
    message: str,
) -> None:
    values = case()
    values[field] = replacement
    with pytest.raises(MODULE.SignerFreshnessV2Error, match=message):
        validate(values)


def test_stable_reader_accepts_private_file_and_rejects_links_and_writes(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private.json"
    private.write_bytes(b"{}\n")
    private.chmod(0o600)
    assert MODULE.read_stable_file(
        private,
        label="test",
        maximum=100,
    ) == b"{}\n"

    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(private)
    with pytest.raises(MODULE.SignerFreshnessV2Error):
        MODULE.read_stable_file(symlink, label="test", maximum=100)

    hardlink = tmp_path / "hardlink.json"
    os.link(private, hardlink)
    for path in (private, hardlink):
        with pytest.raises(MODULE.SignerFreshnessV2Error):
            MODULE.read_stable_file(path, label="test", maximum=100)

    writable = tmp_path / "writable.json"
    writable.write_bytes(b"{}\n")
    writable.chmod(0o666)
    with pytest.raises(MODULE.SignerFreshnessV2Error):
        MODULE.read_stable_file(writable, label="test", maximum=100)


def current_documents() -> tuple[dict[str, Any], dict[str, Any]]:
    approval, envelope = base_documents()
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    issued = now - dt.timedelta(minutes=1)
    expires = now + dt.timedelta(hours=1)
    approval["issued_at"] = issued.strftime("%Y-%m-%dT%H:%M:%SZ")
    approval["expires_at"] = expires.strftime("%Y-%m-%dT%H:%M:%SZ")
    approval["release_id"] = (
        f"ctl-{issued.strftime('%Y%m%dT%H%M%SZ')}-tests"
    )
    manifest_digest = hashlib.sha256(
        MODULE.APPROVAL.canonical_bytes(approval)
    ).hexdigest()
    envelope["approval"]["manifest"] = copy.deepcopy(approval)
    envelope["approval"]["manifest_sha256"] = manifest_digest
    envelope["ledger"]["manifest_sha256"] = manifest_digest
    return approval, envelope


def write_private(path: Path, raw: bytes) -> None:
    path.write_bytes(raw)
    path.chmod(0o600)


def test_cli_validates_files_but_fails_closed_without_pins(
    tmp_path: Path,
) -> None:
    assert MODULE.PINNED_SIGNER_RUNTIME_IDENTITY == ""
    assert MODULE.PINNED_ATTESTATION_AUTHENTICATOR_IDENTITY == ""
    approval, envelope = current_documents()
    documents = {
        "approval": MODULE.APPROVAL.canonical_bytes(approval),
        "envelope": MODULE.ENVELOPE.canonical_bytes(envelope),
        "ledger": canonical(ledger_attestation(approval, envelope)),
        "controller-tag": canonical(controller_attestation(approval)),
        "github-controls": canonical(controls_attestation(approval)),
    }
    for name, raw in documents.items():
        write_private(tmp_path / f"{name}.json", raw)

    command = [
        sys.executable,
        "-B",
        str(SCRIPT),
        "--approval",
        str(tmp_path / "approval.json"),
        "--envelope",
        str(tmp_path / "envelope.json"),
        "--workflow-repository-id",
        "22001",
        "--workflow-run-id",
        "123",
        "--workflow-run-attempt",
        "1",
    ]
    for phase in ("initial", "fresh"):
        for kind in ("ledger", "controller-tag", "github-controls"):
            command.extend(
                [
                    f"--{phase}-{kind}-attestation",
                    str(tmp_path / f"{kind}.json"),
                ]
            )
    result = subprocess.run(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )
    assert result.returncode == 78
    assert result.stdout == b""
    assert b"signer runtime identity is not pinned" in result.stderr


def test_cli_rejects_symlink_before_pin_check(tmp_path: Path) -> None:
    approval, envelope = current_documents()
    write_private(
        tmp_path / "approval-real.json",
        MODULE.APPROVAL.canonical_bytes(approval),
    )
    (tmp_path / "approval.json").symlink_to(
        tmp_path / "approval-real.json"
    )
    write_private(
        tmp_path / "envelope.json",
        MODULE.ENVELOPE.canonical_bytes(envelope),
    )
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            str(SCRIPT),
            "--approval",
            str(tmp_path / "approval.json"),
            "--envelope",
            str(tmp_path / "envelope.json"),
            "--workflow-repository-id",
            "22001",
            "--workflow-run-id",
            "123",
            "--workflow-run-attempt",
            "1",
            "--initial-ledger-attestation",
            str(tmp_path / "missing"),
            "--fresh-ledger-attestation",
            str(tmp_path / "missing"),
            "--initial-controller-tag-attestation",
            str(tmp_path / "missing"),
            "--fresh-controller-tag-attestation",
            str(tmp_path / "missing"),
            "--initial-github-controls-attestation",
            str(tmp_path / "missing"),
            "--fresh-github-controls-attestation",
            str(tmp_path / "missing"),
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15,
    )
    assert result.returncode == 78
    assert b"must not traverse symlinks" in result.stderr


def test_cli_arguments_fail_closed_with_exit_78() -> None:
    result = subprocess.run(
        [sys.executable, "-B", str(SCRIPT)],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15,
    )
    assert result.returncode == 78
    assert result.stdout == b""


def test_cli_parser_requires_the_exact_current_workflow_scope() -> None:
    actions = {action.dest for action in MODULE.parser()._actions}
    assert {
        "workflow_repository_id",
        "workflow_run_id",
        "workflow_run_attempt",
    } <= actions


def test_source_is_offline_no_bytecode_and_production_unavailable() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    bytecode_guard = source.index("sys.dont_write_bytecode = True")
    assert bytecode_guard < source.index("import argparse")
    assert "urllib" not in source
    assert "requests" not in source
    assert "socket" not in source
    assert "subprocess" not in source
    assert 'PINNED_SIGNER_RUNTIME_IDENTITY = ""' in source
    assert 'PINNED_ATTESTATION_AUTHENTICATOR_IDENTITY = ""' in source
    assert SCRIPT.stat().st_mode & 0o777 == 0o755
