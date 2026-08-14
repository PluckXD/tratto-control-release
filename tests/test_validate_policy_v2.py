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
SCRIPT = ROOT / "scripts" / "validate-policy-v2.py"
POLICY_PATH = ROOT / "policies" / "control-production-v2.json"
SCHEMA_PATH = ROOT / "schemas" / "production-policy-v2.schema.json"
SPEC = importlib.util.spec_from_file_location(
    "control_release_production_policy_v2",
    SCRIPT,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


TRUST_EPOCH = MODULE.AuditedTrustEpoch(
    trust_epoch=7,
    controller_repository_id=123456789,
    controller_workflow_sha256="3" * 64,
    controller_tag_signature_trust_root_sha256="6" * 64,
    controller_tag_signature_verifier_sha256="4" * 64,
    signer_freshness_verifier_sha256="7" * 64,
    ledger_repository_id=234567890,
    ledger_genesis_sha="5" * 40,
)


def configured_value() -> dict:
    return MODULE.expected_policy(TRUST_EPOCH)


def changed_trust_epoch(**changes):
    return MODULE.AuditedTrustEpoch(
        **{
            **TRUST_EPOCH.__dict__,
            **changes,
        }
    )


def canonical(value: dict) -> bytes:
    return MODULE.canonical_bytes(value)


def test_checked_in_policy_is_canonical_exact_unavailable_template() -> None:
    raw = POLICY_PATH.read_bytes()
    value, digest = MODULE.validate_template_bytes(raw)
    assert value == MODULE.expected_policy(MODULE.UNCONFIGURED_TRUST_EPOCH)
    assert value["trust_epoch"] == 0
    assert digest == hashlib.sha256(raw).hexdigest()
    assert value["controller"]["repository_id"] == 0
    assert value["ledger"]["repository_id"] == 0
    assert value["ledger"]["genesis_sha"] == ""
    with pytest.raises(
        MODULE.ProductionPolicyError,
        match="audited production trust epoch is unavailable",
    ):
        MODULE.validate_bytes(
            raw,
            audited_trust_epoch=MODULE.PRODUCTION_AUDITED_TRUST_EPOCH,
        )


def test_offline_api_accepts_only_exact_audited_trust_epoch() -> None:
    raw = canonical(configured_value())
    value, digest = MODULE.validate_bytes(
        raw,
        audited_trust_epoch=TRUST_EPOCH,
    )
    assert value == configured_value()
    assert digest == hashlib.sha256(raw).hexdigest()
    assert value["trust_epoch"] == TRUST_EPOCH.trust_epoch
    assert value["controller"]["tag_ref_pattern"] == (
        MODULE.CONTROLLER_TAG_PATTERN
    )
    assert value["ledger"]["signer_revalidation_timing"] == (
        "immediately-before-signature"
    )
    assert value["ledger"]["require_unchanged_head_at_signature"] is True
    assert (
        value["controller"]["tag_signature_verification_mode"]
        == "local-cryptographic-annotated-tag-object"
    )
    assert (
        value["controller"]["tag_signature_claim_authorizes_release"]
        is False
    )


@pytest.mark.parametrize("epoch", [1, MODULE.MAX_TRUST_EPOCH])
def test_accepts_inclusive_configured_trust_epoch_bounds(epoch: int) -> None:
    audited = changed_trust_epoch(trust_epoch=epoch)
    raw = canonical(MODULE.expected_policy(audited))
    value, _ = MODULE.validate_bytes(
        raw,
        audited_trust_epoch=audited,
    )
    assert value["trust_epoch"] == epoch


def test_v2_preserves_every_v1_restriction_and_runtime_binding() -> None:
    previous = json.loads(
        (ROOT / "policies" / "control-production-v1.json").read_bytes()
    )
    current = configured_value()
    preserved = {
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
        "runtime_policy",
        "signer_allows_product_credentials",
        "signer_allows_source_checkout",
    }
    for key in preserved:
        assert current[key] == previous[key]
    assert current["runtime_policy"]["digest_sha256"] == hashlib.sha256(
        (ROOT / "policies" / "control-runtime-v1.json").read_bytes()
    ).hexdigest()
    assert current["approval_schema_version"] == 2
    assert current["ledger"]["approval_schema_version"] == 2


def test_schema_encodes_fail_closed_bindings_and_exact_trust_roots() -> None:
    schema = json.loads(SCHEMA_PATH.read_bytes())
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == 2
    assert (
        schema["properties"]["controller_repository"]["const"]
        == MODULE.CONTROLLER_REPOSITORY
    )
    assert (
        schema["$defs"]["controller"]["properties"]["tag_ref_prefix"]["const"]
        == MODULE.CONTROLLER_TAG_PREFIX
    )
    assert (
        schema["$defs"]["controller"]["properties"]["tag_ref_pattern"]["const"]
        == MODULE.CONTROLLER_TAG_PATTERN
    )
    assert (
        schema["$defs"]["ledger"]["properties"]["repository"]["const"]
        == MODULE.LEDGER_REPOSITORY
    )
    assert (
        schema["$defs"]["ledger"]["properties"][
            "signer_revalidation_timing"
        ]["const"]
        == "immediately-before-signature"
    )
    assert len(schema["allOf"][0]["oneOf"]) == 2
    assert schema["properties"]["trust_epoch"] == {
        "maximum": MODULE.MAX_TRUST_EPOCH,
        "minimum": 0,
        "type": "integer",
    }
    configured = schema["$defs"]["configuredBindings"]
    assert configured["properties"]["trust_epoch"] == {
        "maximum": MODULE.MAX_TRUST_EPOCH,
        "minimum": 1,
        "type": "integer",
    }
    assert schema["$defs"]["unconfiguredBindings"]["properties"][
        "trust_epoch"
    ] == {"const": 0}
    controller_properties = schema["$defs"]["controller"]["properties"]
    for field in (
        "controller_tag_signature_trust_root_sha256",
        "controller_tag_signature_verifier_sha256",
        "signer_freshness_verifier_sha256",
    ):
        assert field in controller_properties
    for legacy_alias in (
        "tag_signature_trust_root_sha256",
        "tag_signature_verifier_sha256",
        "signer_verifier_sha256",
    ):
        assert legacy_alias not in controller_properties


@pytest.mark.parametrize(
    ("path", "bad"),
    [
        (("controller", "repository"), "PluckXD/other"),
        (("controller_repository",), "PluckXD/other"),
        (("controller", "repository_id"), 0),
        (("controller", "repository_id"), True),
        (
            ("controller", "tag_ref_prefix"),
            "refs/tags/control-controller-v5.",
        ),
        (
            ("controller", "tag_ref_pattern"),
            "^refs/tags/control-controller-v6.*$",
        ),
        (("controller", "immutable_release_required"), False),
        (("controller", "require_owner_enforcement"), False),
        (("controller", "signed_annotated_tag_required"), False),
        (
            ("controller", "workflow_path"),
            ".github/workflows/other.yml",
        ),
        (("controller", "workflow_sha256"), "A" * 64),
        (
            ("controller", "controller_tag_signature_verifier_sha256"),
            "4" * 63,
        ),
        (
            ("controller", "controller_tag_signature_trust_root_sha256"),
            "6" * 63,
        ),
        (("controller", "signer_freshness_verifier_sha256"), "7" * 63),
        (
            ("controller", "tag_signature_verification_mode"),
            "json-declared-verified",
        ),
        (
            ("controller", "tag_signature_claim_authorizes_release"),
            True,
        ),
        (("ledger", "repository"), "PluckXD/other-ledger"),
        (("ledger", "repository_id"), 0),
        (("ledger", "repository_id"), True),
        (("ledger", "ref"), "refs/heads/develop"),
        (("ledger", "genesis_sha"), "A" * 40),
        (("ledger", "append_only"), False),
        (("ledger", "linear_single_parent"), False),
        (("ledger", "approval_schema_version"), 1),
        (
            ("ledger", "signer_revalidation_timing"),
            "after-signature",
        ),
        (
            ("ledger", "require_unchanged_head_at_signature"),
            False,
        ),
        (("schema_version",), 1),
        (("approval_schema_version",), 1),
        (("carrier_authorizes_release",), True),
        (("carrier_trust",), "authority"),
        (("signer_allows_product_credentials",), True),
        (("signer_allows_source_checkout",), True),
        (("trust_epoch",), 0),
        (("trust_epoch",), True),
        (("trust_epoch",), -1),
        (("trust_epoch",), MODULE.MAX_TRUST_EPOCH + 1),
        (
            ("runtime_policy", "digest_sha256"),
            "6" * 64,
        ),
    ],
)
def test_rejects_mutated_repository_ids_tags_refs_genesis_and_flags(
    path: tuple[str, ...],
    bad: object,
) -> None:
    value = configured_value()
    target = value
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = bad
    with pytest.raises(MODULE.ProductionPolicyError):
        MODULE.validate_bytes(
            canonical(value),
            audited_trust_epoch=TRUST_EPOCH,
        )


@pytest.mark.parametrize(
    "trust_epoch",
    [
        changed_trust_epoch(trust_epoch=0),
        changed_trust_epoch(trust_epoch=True),
        changed_trust_epoch(trust_epoch=MODULE.MAX_TRUST_EPOCH + 1),
        changed_trust_epoch(controller_repository_id=0),
        changed_trust_epoch(controller_workflow_sha256=""),
        changed_trust_epoch(
            controller_tag_signature_trust_root_sha256=""
        ),
        changed_trust_epoch(controller_tag_signature_verifier_sha256=""),
        changed_trust_epoch(signer_freshness_verifier_sha256=""),
        changed_trust_epoch(
            signer_freshness_verifier_sha256=(
                TRUST_EPOCH.controller_tag_signature_verifier_sha256
            )
        ),
        changed_trust_epoch(
            controller_tag_signature_verifier_sha256=(
                TRUST_EPOCH.controller_tag_signature_trust_root_sha256
            )
        ),
        changed_trust_epoch(
            signer_freshness_verifier_sha256=(
                TRUST_EPOCH.controller_tag_signature_trust_root_sha256
            )
        ),
        changed_trust_epoch(ledger_repository_id=0),
        changed_trust_epoch(ledger_genesis_sha=""),
    ],
)
def test_rejects_unavailable_or_invalid_explicit_trust_epoch(
    trust_epoch,
) -> None:
    with pytest.raises(
        MODULE.ProductionPolicyError,
        match="audited production trust epoch is unavailable or invalid",
    ):
        MODULE.validate_bytes(
            canonical(configured_value()),
            audited_trust_epoch=trust_epoch,
        )


def test_rejects_document_that_does_not_match_audited_trust_epoch() -> None:
    changed = changed_trust_epoch(
        controller_repository_id=TRUST_EPOCH.controller_repository_id + 1,
    )
    with pytest.raises(
        MODULE.ProductionPolicyError,
        match="does not match the audited trust epoch",
    ):
        MODULE.validate_bytes(
            canonical(configured_value()),
            audited_trust_epoch=changed,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(extra="forbidden"),
        lambda value: value["controller"].update(extra="forbidden"),
        lambda value: value["ledger"].update(extra="forbidden"),
        lambda value: value["runtime_policy"].update(extra="forbidden"),
        lambda value: value.pop("required_ref"),
        lambda value: value.pop("trust_epoch"),
        lambda value: value["controller"].pop("tag_ref_pattern"),
        lambda value: value["controller"].pop(
            "controller_tag_signature_trust_root_sha256"
        ),
        lambda value: value["controller"].pop(
            "controller_tag_signature_verifier_sha256"
        ),
        lambda value: value["controller"].pop(
            "signer_freshness_verifier_sha256"
        ),
        lambda value: value["controller"].update(
            tag_signature_trust_root_sha256="6" * 64
        ),
        lambda value: value["controller"].update(
            tag_signature_verifier_sha256="4" * 64
        ),
        lambda value: value["controller"].update(
            signer_verifier_sha256="7" * 64
        ),
        lambda value: value["ledger"].pop("genesis_sha"),
    ],
)
def test_rejects_unknown_and_missing_keys(mutation) -> None:
    value = configured_value()
    mutation(value)
    with pytest.raises(MODULE.ProductionPolicyError, match="keys diverge"):
        MODULE.validate_bytes(
            canonical(value),
            audited_trust_epoch=TRUST_EPOCH,
        )


def test_rejects_noncanonical_json_duplicate_keys_and_nonfinite_values() -> None:
    raw = canonical(configured_value())
    pretty = json.dumps(configured_value(), indent=2).encode() + b"\n"
    with pytest.raises(
        MODULE.ProductionPolicyError,
        match="canonical JSON",
    ):
        MODULE.validate_bytes(pretty, audited_trust_epoch=TRUST_EPOCH)

    duplicate = raw.replace(
        b'{"approval_max_seconds":86400,',
        b'{"approval_max_seconds":86400,"approval_max_seconds":86400,',
        1,
    )
    with pytest.raises(
        MODULE.ProductionPolicyError,
        match="duplicate JSON key",
    ):
        MODULE.validate_bytes(duplicate, audited_trust_epoch=TRUST_EPOCH)

    nonfinite = raw.replace(b"86400", b"NaN", 1)
    with pytest.raises(
        MODULE.ProductionPolicyError,
        match="non-finite",
    ):
        MODULE.validate_bytes(nonfinite, audited_trust_epoch=TRUST_EPOCH)


def test_rejects_partially_configured_policy() -> None:
    value = MODULE.expected_policy(MODULE.UNCONFIGURED_TRUST_EPOCH)
    value["trust_epoch"] = 1
    with pytest.raises(
        MODULE.ProductionPolicyError,
        match="either wholly unavailable or wholly configured",
    ):
        MODULE.validate_shape(value)


@pytest.mark.parametrize(
    "forbidden",
    [
        "commit_sha",
        "tag_ref",
        "tag_object_sha",
        "immutable_release_id",
    ],
)
def test_policy_forbids_circular_controller_identity_fields(
    forbidden: str,
) -> None:
    value = configured_value()
    value["controller"][forbidden] = (
        123 if forbidden == "immutable_release_id" else "1" * 40
    )
    with pytest.raises(
        MODULE.ProductionPolicyError,
        match="controller policy keys diverge",
    ):
        MODULE.validate_bytes(
            canonical(value),
            audited_trust_epoch=TRUST_EPOCH,
        )
    assert forbidden not in MODULE.expected_policy(TRUST_EPOCH)["controller"]


def test_policy_loader_rejects_symlink_and_hardlink(tmp_path: Path) -> None:
    original = tmp_path / "policy.json"
    original.write_bytes(POLICY_PATH.read_bytes())
    original.chmod(0o644)
    symlink = tmp_path / "policy-link.json"
    symlink.symlink_to(original)
    with pytest.raises(
        MODULE.ProductionPolicyError,
        match="symlink",
    ):
        MODULE.load_policy_bytes(symlink)

    hardlink = tmp_path / "policy-hardlink.json"
    os.link(original, hardlink)
    with pytest.raises(
        MODULE.ProductionPolicyError,
        match="single-link",
    ):
        MODULE.load_policy_bytes(original)


def test_cli_is_unavailable_and_returns_78_without_audited_epoch() -> None:
    result = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), "--policy", str(POLICY_PATH)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 78
    assert result.stdout == ""
    assert "audited production trust epoch is unavailable" in result.stderr


def test_cli_checks_canonical_shape_before_reporting_missing_epoch(
    tmp_path: Path,
) -> None:
    value = copy.deepcopy(
        MODULE.expected_policy(MODULE.UNCONFIGURED_TRUST_EPOCH)
    )
    value["unknown"] = True
    path = tmp_path / "bad-policy.json"
    path.write_bytes(canonical(value))
    path.chmod(0o644)
    result = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), "--policy", str(path)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 78
    assert "production policy keys diverge" in result.stderr
    assert "audited production trust epoch" not in result.stderr
