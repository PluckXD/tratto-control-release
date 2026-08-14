#!/usr/bin/env python3
"""Revalidate v6 release authority immediately before signing.

This module is intentionally offline.  It binds a previously validated
approval-v2 document and a previously validated envelope-v6 candidate to two
authenticated observations of each external authority: the approval ledger,
the immutable controller tag, and the GitHub control plane.  Every observation
is scoped to the exact repository, workflow run, and run attempt being signed.

Raw JSON is never authority.  The pure API accepts attestations only after an
injected authenticator returns a typed :class:`AttestationAuthentication`.
The production CLI remains unavailable until both the signer runtime identity
and a reviewed authenticated-attestation mechanism are pinned.
"""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping


HERE = Path(__file__).resolve().parent


def _load_fixed_module(name: str, filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise SystemExit(f"fixed validator unavailable: {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


APPROVAL = _load_fixed_module(
    "control_release_signer_approval_v2",
    "validate-approval-v2.py",
)
ENVELOPE = _load_fixed_module(
    "control_release_signer_envelope_v6",
    "validate-envelope-v6.py",
)

PINNED_SIGNER_RUNTIME_IDENTITY = ""
PINNED_ATTESTATION_AUTHENTICATOR_IDENTITY = ""

CONTROLLER_REPOSITORY = "PluckXD/tratto-control-release"
LEDGER_REPOSITORY = "PluckXD/tratto-control-release-ledger"
LEDGER_REF = "refs/heads/main"
CONTROL_ENVIRONMENT = "control-release"

MAX_ATTESTATION_BYTES = 16 * 1024
MAX_OBSERVATION_SEQUENCE = 2**63 - 1
MAX_CONTROL_COUNT = 100

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RELEASE_ID_RE = APPROVAL.RELEASE_ID_RE
CONTROLLER_TAG_RE = re.compile(
    r"^control-controller-v6\."
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{7,255}$")

LEDGER_KEYS = {
    "genesis_sha",
    "head_sha",
    "manifest_sha256",
    "record_count",
    "release_id",
}
CONTROLLER_TAG_KEYS = {
    "commit_sha",
    "owner_enforced",
    "release_id",
    "repository",
    "repository_id",
    "tag",
    "tag_object_sha",
}
GITHUB_CONTROLS_KEYS = {
    "controller_repository",
    "controller_repository_id",
    "environment",
    "environment_reviewer_count",
    "ledger_repository",
    "ledger_repository_id",
    "minimum_pull_request_approvals",
}
SIGNER_FRESHNESS_KEYS = {
    "controller_tag_attestation_sha256",
    "evidence_model",
    "github_controls_attestation_sha256",
    "ledger_attestation_sha256",
    "ledger_head_sha",
    "revalidated_immediately_before_signature",
    "workflow_run",
}
WORKFLOW_RUN_KEYS = {"repository_id", "run_attempt", "run_id"}
EVIDENCE_MODEL = "workflow-signed-summary-v1"


class SignerFreshnessV2Error(ValueError):
    """The immediately-before-signature proof is invalid or unavailable."""


def reject(message: str) -> None:
    raise SignerFreshnessV2Error(message)


class AttestationKind(Enum):
    LEDGER = "ledger"
    CONTROLLER_TAG = "controller-tag"
    GITHUB_CONTROLS = "github-controls"


@dataclass(frozen=True)
class WorkflowRunScope:
    """Exact GitHub workflow invocation that authenticated the evidence."""

    repository_id: int
    run_id: int
    run_attempt: int

    def __post_init__(self) -> None:
        for label, value in (
            ("repository_id", self.repository_id),
            ("run_id", self.run_id),
            ("run_attempt", self.run_attempt),
        ):
            if (
                type(value) is not int
                or not 1 <= value <= MAX_OBSERVATION_SEQUENCE
            ):
                reject(
                    f"workflow run {label} must be a bounded "
                    "positive integer"
                )

    def as_dict(self) -> dict[str, int]:
        return {
            "repository_id": self.repository_id,
            "run_attempt": self.run_attempt,
            "run_id": self.run_id,
        }


@dataclass(frozen=True)
class SignerRuntimeIdentity:
    """Reviewed identity and invocation of the isolated signer runtime."""

    value: str
    workflow_run: WorkflowRunScope

    def __post_init__(self) -> None:
        if (
            type(self.value) is not str
            or IDENTITY_RE.fullmatch(self.value) is None
        ):
            reject("signer runtime identity has invalid format")
        if type(self.workflow_run) is not WorkflowRunScope:
            reject("signer runtime workflow run scope must be typed")


@dataclass(frozen=True)
class AttestationAuthentication:
    """Typed result returned by an authenticated observation boundary."""

    kind: AttestationKind
    digest_sha256: str
    signer_runtime_identity: str
    observation_sequence: int
    workflow_run: WorkflowRunScope
    authenticated: bool


_CONSTRUCTION_TOKEN = object()


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True, init=False)
class ValidatedApprovalV2:
    """An approval created only by the fixed approval-v2 validator."""

    value: Mapping[str, Any]
    canonical: bytes

    def __init__(
        self,
        token: object,
        value: Mapping[str, Any],
        canonical: bytes,
    ) -> None:
        if token is not _CONSTRUCTION_TOKEN:
            raise TypeError("use validate_approval_v2_bytes")
        object.__setattr__(self, "value", _freeze(value))
        object.__setattr__(self, "canonical", canonical)


@dataclass(frozen=True, init=False)
class ValidatedEnvelopeV6:
    """An envelope candidate created only by the fixed v6 validator."""

    value: Mapping[str, Any]
    canonical: bytes

    def __init__(
        self,
        token: object,
        value: Mapping[str, Any],
        canonical: bytes,
    ) -> None:
        if token is not _CONSTRUCTION_TOKEN:
            raise TypeError("use validate_envelope_v6_bytes")
        object.__setattr__(self, "value", _freeze(value))
        object.__setattr__(self, "canonical", canonical)


@dataclass(frozen=True, init=False)
class AuthenticatedAttestation:
    """Canonical attestation plus typed authentication metadata."""

    kind: AttestationKind
    value: Mapping[str, Any]
    canonical: bytes
    authentication: AttestationAuthentication

    def __init__(
        self,
        token: object,
        kind: AttestationKind,
        value: Mapping[str, Any],
        canonical: bytes,
        authentication: AttestationAuthentication,
    ) -> None:
        if token is not _CONSTRUCTION_TOKEN:
            raise TypeError("use authenticate_attestation")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "value", _freeze(value))
        object.__setattr__(self, "canonical", canonical)
        object.__setattr__(self, "authentication", authentication)


AttestationAuthenticator = Callable[
    [AttestationKind, bytes],
    AttestationAuthentication,
]


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


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def exact_keys(
    value: Any,
    expected: set[str],
    label: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        reject(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        reject(
            f"{label} keys diverge; "
            f"missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )
    return value


def require_pattern(
    value: Any,
    pattern: re.Pattern[str],
    label: str,
) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        reject(f"{label} has invalid format")
    return value


def require_positive_integer(
    value: Any,
    label: str,
    *,
    maximum: int,
) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        reject(f"{label} must be a bounded positive integer")
    return value


def workflow_run_scope(value: Any, label: str) -> WorkflowRunScope:
    run = exact_keys(value, WORKFLOW_RUN_KEYS, label)
    return WorkflowRunScope(
        repository_id=require_positive_integer(
            run["repository_id"],
            f"{label}.repository_id",
            maximum=MAX_OBSERVATION_SEQUENCE,
        ),
        run_id=require_positive_integer(
            run["run_id"],
            f"{label}.run_id",
            maximum=MAX_OBSERVATION_SEQUENCE,
        ),
        run_attempt=require_positive_integer(
            run["run_attempt"],
            f"{label}.run_attempt",
            maximum=MAX_OBSERVATION_SEQUENCE,
        ),
    )


def parse_canonical_attestation(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_ATTESTATION_BYTES:
        reject("attestation has an invalid size")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        reject("attestation must be UTF-8")
    try:
        value = json.loads(
            decoded,
            object_pairs_hook=unique_object,
            parse_constant=lambda item: reject(
                f"non-finite number is forbidden: {item}"
            ),
        )
    except json.JSONDecodeError as error:
        reject(
            "attestation has invalid JSON at "
            f"line {error.lineno}, column {error.colno}"
        )
    if not isinstance(value, dict):
        reject("attestation root must be an object")
    if raw != canonical_bytes(value):
        reject("attestation must be canonical JSON")
    return value


def validate_ledger_attestation(value: Any) -> Mapping[str, Any]:
    ledger = exact_keys(value, LEDGER_KEYS, "ledger attestation")
    genesis = require_pattern(
        ledger["genesis_sha"],
        SHA1_RE,
        "ledger attestation genesis_sha",
    )
    head = require_pattern(
        ledger["head_sha"],
        SHA1_RE,
        "ledger attestation head_sha",
    )
    if head == genesis:
        reject("ledger attestation head must be post-genesis")
    require_pattern(
        ledger["manifest_sha256"],
        SHA256_RE,
        "ledger attestation manifest_sha256",
    )
    require_positive_integer(
        ledger["record_count"],
        "ledger attestation record_count",
        maximum=APPROVAL.MAX_LEDGER_SEQUENCE,
    )
    require_pattern(
        ledger["release_id"],
        RELEASE_ID_RE,
        "ledger attestation release_id",
    )
    return ledger


def validate_controller_tag_attestation(
    value: Any,
) -> Mapping[str, Any]:
    controller = exact_keys(
        value,
        CONTROLLER_TAG_KEYS,
        "controller-tag attestation",
    )
    if controller["repository"] != CONTROLLER_REPOSITORY:
        reject("controller-tag attestation repository diverges")
    require_positive_integer(
        controller["repository_id"],
        "controller-tag attestation repository_id",
        maximum=MAX_OBSERVATION_SEQUENCE,
    )
    require_pattern(
        controller["tag"],
        CONTROLLER_TAG_RE,
        "controller-tag attestation tag",
    )
    for key in ("tag_object_sha", "commit_sha"):
        require_pattern(
            controller[key],
            SHA1_RE,
            f"controller-tag attestation {key}",
        )
    require_positive_integer(
        controller["release_id"],
        "controller-tag attestation release_id",
        maximum=MAX_OBSERVATION_SEQUENCE,
    )
    if type(controller["owner_enforced"]) is not bool:
        reject("controller-tag attestation owner_enforced must be boolean")
    if controller["owner_enforced"] is not True:
        reject("controller-tag attestation is not owner-enforced")
    return controller


def validate_github_controls_attestation(
    value: Any,
) -> Mapping[str, Any]:
    controls = exact_keys(
        value,
        GITHUB_CONTROLS_KEYS,
        "GitHub-controls attestation",
    )
    if (
        controls["controller_repository"] != CONTROLLER_REPOSITORY
        or controls["ledger_repository"] != LEDGER_REPOSITORY
        or controls["environment"] != CONTROL_ENVIRONMENT
    ):
        reject("GitHub-controls attestation identity diverges")
    controller_id = require_positive_integer(
        controls["controller_repository_id"],
        "GitHub-controls controller_repository_id",
        maximum=MAX_OBSERVATION_SEQUENCE,
    )
    ledger_id = require_positive_integer(
        controls["ledger_repository_id"],
        "GitHub-controls ledger_repository_id",
        maximum=MAX_OBSERVATION_SEQUENCE,
    )
    if controller_id == ledger_id:
        reject("GitHub-controls repository IDs must be distinct")
    approvals = require_positive_integer(
        controls["minimum_pull_request_approvals"],
        "GitHub-controls minimum_pull_request_approvals",
        maximum=MAX_CONTROL_COUNT,
    )
    reviewers = require_positive_integer(
        controls["environment_reviewer_count"],
        "GitHub-controls environment_reviewer_count",
        maximum=MAX_CONTROL_COUNT,
    )
    if approvals < 2 or reviewers < 1:
        reject("GitHub-controls attestation is below production policy")
    return controls


ATTESTATION_VALIDATORS = {
    AttestationKind.LEDGER: validate_ledger_attestation,
    AttestationKind.CONTROLLER_TAG: validate_controller_tag_attestation,
    AttestationKind.GITHUB_CONTROLS: validate_github_controls_attestation,
}


def validate_approval_v2_bytes(
    raw: bytes,
    *,
    now: dt.datetime | None = None,
) -> ValidatedApprovalV2:
    try:
        value = APPROVAL.validate_bytes(raw, now=now)
    except APPROVAL.ApprovalV2Error as error:
        reject(f"approval-v2 rejected: {error}")
    canonical = APPROVAL.canonical_bytes(value)
    return ValidatedApprovalV2(_CONSTRUCTION_TOKEN, value, canonical)


def validate_envelope_v6_bytes(raw: bytes) -> ValidatedEnvelopeV6:
    try:
        value = ENVELOPE.validate_bytes(raw)
    except (ENVELOPE.EnvelopeV6Error, APPROVAL.ApprovalV2Error) as error:
        reject(f"envelope-v6 rejected: {error}")
    canonical = ENVELOPE.canonical_bytes(value)
    return ValidatedEnvelopeV6(_CONSTRUCTION_TOKEN, value, canonical)


def authenticate_attestation(
    kind: AttestationKind,
    raw: bytes,
    authenticator: AttestationAuthenticator,
) -> AuthenticatedAttestation:
    """Validate exact JSON and require a typed authenticated observation."""

    if type(kind) is not AttestationKind:
        reject("attestation kind must be typed")
    value = parse_canonical_attestation(raw)
    validator = ATTESTATION_VALIDATORS[kind]
    validator(value)
    if not callable(authenticator):
        reject("attestation authenticator is unavailable")
    try:
        authentication = authenticator(kind, raw)
    except SignerFreshnessV2Error:
        raise
    except Exception:
        reject("attestation authenticator failed closed")
    if type(authentication) is not AttestationAuthentication:
        reject("attestation authenticator returned an untyped result")
    if type(authentication.kind) is not AttestationKind:
        reject("authenticated attestation kind must be typed")
    if authentication.kind is not kind:
        reject("authenticated attestation kind diverges")
    digest = require_pattern(
        authentication.digest_sha256,
        SHA256_RE,
        "authenticated attestation digest",
    )
    if digest != sha256_hex(raw):
        reject("authenticated attestation digest diverges")
    require_pattern(
        authentication.signer_runtime_identity,
        IDENTITY_RE,
        "authenticated signer runtime identity",
    )
    require_positive_integer(
        authentication.observation_sequence,
        "authenticated observation sequence",
        maximum=MAX_OBSERVATION_SEQUENCE,
    )
    if type(authentication.workflow_run) is not WorkflowRunScope:
        reject("authenticated workflow run scope must be typed")
    if type(authentication.authenticated) is not bool:
        reject("authenticated marker must be boolean")
    if authentication.authenticated is not True:
        reject("attestation was not authenticated")
    return AuthenticatedAttestation(
        _CONSTRUCTION_TOKEN,
        kind,
        value,
        raw,
        authentication,
    )


def _typed_evidence(
    value: Any,
    kind: AttestationKind,
    label: str,
) -> AuthenticatedAttestation:
    if type(value) is not AuthenticatedAttestation:
        reject(f"{label} must be typed authenticated evidence")
    if value.kind is not kind:
        reject(f"{label} has the wrong attestation kind")
    return value


def _validate_fresh_pair(
    *,
    initial: Any,
    fresh: Any,
    kind: AttestationKind,
    runtime: SignerRuntimeIdentity,
) -> tuple[AuthenticatedAttestation, AuthenticatedAttestation]:
    first = _typed_evidence(initial, kind, f"initial {kind.value}")
    second = _typed_evidence(fresh, kind, f"fresh {kind.value}")
    if first is second:
        reject(f"fresh {kind.value} reused the initial observation object")
    for label, evidence in (("initial", first), ("fresh", second)):
        authentication = evidence.authentication
        if authentication.signer_runtime_identity != runtime.value:
            reject(f"{label} {kind.value} signer runtime identity diverges")
        if authentication.workflow_run != runtime.workflow_run:
            reject(f"{label} {kind.value} workflow run scope diverges")
    if (
        second.authentication.observation_sequence
        <= first.authentication.observation_sequence
    ):
        reject(f"fresh {kind.value} observation is stale")
    if first.canonical != second.canonical:
        reject(f"{kind.value} changed before signature")
    return first, second


def build_signer_freshness_block(
    *,
    fresh_ledger: AuthenticatedAttestation,
    fresh_controller_tag: AuthenticatedAttestation,
    fresh_github_controls: AuthenticatedAttestation,
) -> dict[str, Any]:
    ledger = _typed_evidence(
        fresh_ledger,
        AttestationKind.LEDGER,
        "fresh ledger",
    )
    controller = _typed_evidence(
        fresh_controller_tag,
        AttestationKind.CONTROLLER_TAG,
        "fresh controller-tag",
    )
    controls = _typed_evidence(
        fresh_github_controls,
        AttestationKind.GITHUB_CONTROLS,
        "fresh GitHub-controls",
    )
    workflow_runs = tuple(
        evidence.authentication.workflow_run
        for evidence in (ledger, controller, controls)
    )
    if any(type(run) is not WorkflowRunScope for run in workflow_runs):
        reject("fresh attestation workflow run scope must be typed")
    scopes = set(workflow_runs)
    if len(scopes) != 1:
        reject("fresh attestations have divergent workflow run scopes")
    workflow_run = next(iter(scopes))
    digests = {
        "ledger_attestation_sha256": sha256_hex(ledger.canonical),
        "controller_tag_attestation_sha256": sha256_hex(
            controller.canonical
        ),
        "github_controls_attestation_sha256": sha256_hex(
            controls.canonical
        ),
    }
    if len(set(digests.values())) != 3:
        reject("attestation digests must be distinct across authority types")
    head = require_pattern(
        ledger.value["head_sha"],
        SHA1_RE,
        "fresh ledger head_sha",
    )
    return {
        "controller_tag_attestation_sha256": digests[
            "controller_tag_attestation_sha256"
        ],
        "evidence_model": EVIDENCE_MODEL,
        "github_controls_attestation_sha256": digests[
            "github_controls_attestation_sha256"
        ],
        "ledger_attestation_sha256": digests[
            "ledger_attestation_sha256"
        ],
        "ledger_head_sha": head,
        "revalidated_immediately_before_signature": True,
        "workflow_run": workflow_run.as_dict(),
    }


def _bind_approval_and_envelope(
    approval: ValidatedApprovalV2,
    envelope: ValidatedEnvelopeV6,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    embedded = envelope.value["approval"]["manifest"]
    embedded_bytes = APPROVAL.canonical_bytes(_plain(embedded))
    if embedded_bytes != approval.canonical:
        reject("envelope approval diverges from validated approval-v2")
    manifest_digest = sha256_hex(approval.canonical)
    if (
        envelope.value["approval"]["manifest_sha256"] != manifest_digest
        or envelope.value["ledger"]["manifest_sha256"] != manifest_digest
    ):
        reject("envelope manifest digest diverges from validated approval-v2")
    return approval.value, envelope.value


def _bind_ledger(
    attestation: Mapping[str, Any],
    approval: Mapping[str, Any],
    envelope: Mapping[str, Any],
) -> None:
    approved_ledger = approval["ledger"]
    envelope_ledger = envelope["ledger"]
    expected = {
        "genesis_sha": approved_ledger["genesis_sha"],
        "head_sha": envelope_ledger["head_sha"],
        "manifest_sha256": envelope_ledger["manifest_sha256"],
        "record_count": approved_ledger["sequence"],
        "release_id": approval["release_id"],
    }
    if dict(attestation) != expected:
        reject("fresh ledger attestation diverges from approval or envelope")
    if envelope_ledger["record_count"] != attestation["record_count"]:
        reject("envelope ledger count diverges from fresh ledger")
    if envelope_ledger["repository"] != LEDGER_REPOSITORY:
        reject("envelope ledger repository diverges")
    if (
        envelope_ledger["repository_id"]
        != approved_ledger["repository_id"]
        or envelope_ledger["ref"] != LEDGER_REF
    ):
        reject("envelope ledger identity diverges")


def _bind_controller(
    attestation: Mapping[str, Any],
    approval: Mapping[str, Any],
    envelope: Mapping[str, Any],
) -> None:
    approved = approval["controller"]
    executed = envelope["controller"]
    expected = {
        "commit_sha": approved["commit_sha"],
        "owner_enforced": True,
        "release_id": approved["immutable_release_id"],
        "repository": approved["repository"],
        "repository_id": approved["repository_id"],
        "tag": approved["tag_ref"].removeprefix("refs/tags/"),
        "tag_object_sha": approved["tag_object_sha"],
    }
    if dict(attestation) != expected:
        reject(
            "fresh controller-tag attestation diverges from approval "
            "or envelope"
        )
    envelope_expected = {
        "commit_sha": attestation["commit_sha"],
        "immutable_release_id": attestation["release_id"],
        "repository": attestation["repository"],
        "repository_id": attestation["repository_id"],
        "tag_object_sha": attestation["tag_object_sha"],
        "tag_ref": f"refs/tags/{attestation['tag']}",
    }
    for key, expected_value in envelope_expected.items():
        if executed[key] != expected_value:
            reject(f"envelope controller {key} diverges from fresh tag")
    if executed["owner_enforced"] is not True:
        reject("envelope controller is not owner-enforced")


def _bind_controls(
    attestation: Mapping[str, Any],
    approval: Mapping[str, Any],
    envelope: Mapping[str, Any],
) -> None:
    expected = {
        "controller_repository": approval["controller"]["repository"],
        "controller_repository_id": approval["controller"]["repository_id"],
        "ledger_repository": approval["ledger"]["repository"],
        "ledger_repository_id": approval["ledger"]["repository_id"],
    }
    for key, expected_value in expected.items():
        if attestation[key] != expected_value:
            reject(f"fresh GitHub-controls {key} diverges")
    if (
        envelope["controller"]["repository_id"]
        != attestation["controller_repository_id"]
        or envelope["ledger"]["repository_id"]
        != attestation["ledger_repository_id"]
    ):
        reject("envelope repository IDs diverge from fresh GitHub controls")


def validate_signer_freshness(
    *,
    approval: ValidatedApprovalV2,
    envelope_candidate: ValidatedEnvelopeV6,
    signer_runtime: SignerRuntimeIdentity,
    initial_ledger: AuthenticatedAttestation,
    fresh_ledger: AuthenticatedAttestation,
    initial_controller_tag: AuthenticatedAttestation,
    fresh_controller_tag: AuthenticatedAttestation,
    initial_github_controls: AuthenticatedAttestation,
    fresh_github_controls: AuthenticatedAttestation,
) -> dict[str, Any]:
    """Return the exact v6 signer-freshness block or fail closed."""

    if type(approval) is not ValidatedApprovalV2:
        reject("approval must be a typed validated approval-v2")
    if type(envelope_candidate) is not ValidatedEnvelopeV6:
        reject("envelope must be a typed validated envelope-v6")
    if type(signer_runtime) is not SignerRuntimeIdentity:
        reject("signer runtime identity must be typed")

    approved, envelope = _bind_approval_and_envelope(
        approval,
        envelope_candidate,
    )
    controller = envelope["controller"]
    envelope_scope = WorkflowRunScope(
        repository_id=controller["repository_id"],
        run_id=controller["run_id"],
        run_attempt=controller["run_attempt"],
    )
    if signer_runtime.workflow_run != envelope_scope:
        reject("signer runtime workflow run scope diverges from envelope")

    candidate = exact_keys(
        envelope["signer_freshness"],
        SIGNER_FRESHNESS_KEYS,
        "envelope signer_freshness",
    )
    if candidate["evidence_model"] != EVIDENCE_MODEL:
        reject("envelope signer freshness evidence model diverges")
    candidate_scope = workflow_run_scope(
        candidate["workflow_run"],
        "envelope signer_freshness.workflow_run",
    )
    if candidate_scope != envelope_scope:
        reject("envelope signer freshness workflow run scope diverges")

    _, latest_ledger = _validate_fresh_pair(
        initial=initial_ledger,
        fresh=fresh_ledger,
        kind=AttestationKind.LEDGER,
        runtime=signer_runtime,
    )
    _, latest_controller = _validate_fresh_pair(
        initial=initial_controller_tag,
        fresh=fresh_controller_tag,
        kind=AttestationKind.CONTROLLER_TAG,
        runtime=signer_runtime,
    )
    _, latest_controls = _validate_fresh_pair(
        initial=initial_github_controls,
        fresh=fresh_github_controls,
        kind=AttestationKind.GITHUB_CONTROLS,
        runtime=signer_runtime,
    )

    _bind_ledger(latest_ledger.value, approved, envelope)
    _bind_controller(latest_controller.value, approved, envelope)
    _bind_controls(latest_controls.value, approved, envelope)

    result = build_signer_freshness_block(
        fresh_ledger=latest_ledger,
        fresh_controller_tag=latest_controller,
        fresh_github_controls=latest_controls,
    )
    if _plain(candidate) != result:
        reject("envelope signer_freshness diverges from fresh attestations")
    return result


def read_stable_file(
    path: Path,
    *,
    label: str,
    maximum: int,
) -> bytes:
    """Read a bounded, owned, stable, non-linked regular file."""

    absolute = path.absolute()
    descriptor = -1
    try:
        if absolute.resolve(strict=True) != absolute:
            reject(f"{label} path must not traverse symlinks")
        before_path = absolute.lstat()
        descriptor = os.open(
            absolute,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
    except SignerFreshnessV2Error:
        raise
    except OSError:
        reject(f"{label} is unavailable")
    try:
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before_path.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > maximum
            or stat.S_IMODE(before.st_mode) & 0o022
            or (before.st_dev, before.st_ino)
            != (before_path.st_dev, before_path.st_ino)
        ):
            reject(f"{label} must be a bounded private regular file")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        try:
            after_path = absolute.lstat()
        except OSError:
            reject(f"{label} pathname changed while being read")
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if (
            len(raw) != before.st_size
            or any(
                getattr(before, field) != getattr(after, field)
                for field in stable_fields
            )
            or any(
                getattr(before, field) != getattr(after_path, field)
                for field in stable_fields
            )
        ):
            reject(f"{label} changed while being read")
        return raw
    except SignerFreshnessV2Error:
        raise
    except OSError:
        reject(f"{label} failed closed while being read")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


class FailClosedParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        reject(f"invalid command line: {message}")


def parser() -> argparse.ArgumentParser:
    argument_parser = FailClosedParser(
        description="Revalidate v6 authority immediately before signing",
    )
    argument_parser.add_argument("--approval", required=True, type=Path)
    argument_parser.add_argument("--envelope", required=True, type=Path)
    argument_parser.add_argument(
        "--workflow-repository-id",
        required=True,
        type=int,
    )
    argument_parser.add_argument("--workflow-run-id", required=True, type=int)
    argument_parser.add_argument(
        "--workflow-run-attempt",
        required=True,
        type=int,
    )
    for phase in ("initial", "fresh"):
        for kind in ("ledger", "controller-tag", "github-controls"):
            argument_parser.add_argument(
                f"--{phase}-{kind}-attestation",
                required=True,
                type=Path,
            )
    return argument_parser


def main(arguments: list[str] | None = None) -> int:
    try:
        options = parser().parse_args(arguments)
        current_workflow_run = WorkflowRunScope(
            repository_id=options.workflow_repository_id,
            run_id=options.workflow_run_id,
            run_attempt=options.workflow_run_attempt,
        )
        approval_raw = read_stable_file(
            options.approval,
            label="approval-v2",
            maximum=APPROVAL.MAX_FILE_BYTES,
        )
        envelope_raw = read_stable_file(
            options.envelope,
            label="envelope-v6",
            maximum=ENVELOPE.MAX_FILE_BYTES,
        )
        validate_approval_v2_bytes(approval_raw)
        validated_envelope = validate_envelope_v6_bytes(envelope_raw)
        envelope_workflow_run = workflow_run_scope(
            validated_envelope.value["signer_freshness"]["workflow_run"],
            "envelope signer_freshness.workflow_run",
        )
        if current_workflow_run != envelope_workflow_run:
            reject("current workflow run scope diverges from envelope")

        raw_attestations: list[tuple[AttestationKind, bytes]] = []
        for phase in ("initial", "fresh"):
            for argument, kind in (
                ("ledger", AttestationKind.LEDGER),
                ("controller_tag", AttestationKind.CONTROLLER_TAG),
                ("github_controls", AttestationKind.GITHUB_CONTROLS),
            ):
                path = getattr(options, f"{phase}_{argument}_attestation")
                raw = read_stable_file(
                    path,
                    label=f"{phase} {kind.value} attestation",
                    maximum=MAX_ATTESTATION_BYTES,
                )
                ATTESTATION_VALIDATORS[kind](
                    parse_canonical_attestation(raw)
                )
                raw_attestations.append((kind, raw))

        if PINNED_SIGNER_RUNTIME_IDENTITY == "":
            reject("signer runtime identity is not pinned")
        if PINNED_ATTESTATION_AUTHENTICATOR_IDENTITY == "":
            reject("authenticated-attestation mechanism is not pinned")
        if not raw_attestations:
            reject("authenticated attestations are unavailable")
        reject("authenticated-attestation implementation is unavailable")
    except (
        SignerFreshnessV2Error,
        APPROVAL.ApprovalV2Error,
        ENVELOPE.EnvelopeV6Error,
    ) as error:
        print(f"signer freshness v2 rejected: {error}", file=sys.stderr)
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
