from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify-bootstrap-carrier-shape.py"
SPEC = importlib.util.spec_from_file_location(
    "bootstrap_carrier_shape_under_test",
    SCRIPT,
)
assert SPEC is not None and SPEC.loader is not None
SHAPE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SHAPE
SPEC.loader.exec_module(SHAPE)


def valid_shape() -> str:
    return """name: Control bootstrap v1

on:
  workflow_dispatch:

permissions: {}

jobs:
  authorize:
    permissions:
      contents: read
    steps:
      - name: Checkout exact private carrier main
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
      - id: preflight
        name: Preflight untrusted approval and controller inputs
        env:
          APPROVAL_PATH: ${{ inputs.approval_path }}
          CONTROLLER_SHA: ${{ inputs.controller_sha }}
        run: |
          controller_sha = os.environ["CONTROLLER_SHA"]
          re.fullmatch(r"[0-9a-f]{40}", controller_sha)
          path = PurePosixPath("$APPROVAL_PATH")
          object_pairs_hook=unique_object
          raw != canonical_bytes(value)
          os.O_NOFOLLOW
          path.as_posix()
          f"approvals/{release_id}.json"
          value.get("schema_version") != 1
          issued.strftime("%Y%m%dT%H%M%SZ")
          release_match.group(1)
          controller.get("base_sha") != controller_sha
          hashlib.sha256(raw).hexdigest()
          os.environ["GITHUB_OUTPUT"]
          approval_sha256=
          approval path, filename, or release_id is invalid
      - name: Checkout reviewed public controller
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          repository: PluckXD/tratto-control-release
          ref: ${{ inputs.controller_sha }}
      - name: Verify the carrier trust shape
        run: verify shape
      - name: Validate the bounded one-shot approval
        env:
          APPROVAL_PATH: ${{ inputs.approval_path }}
          PREFLIGHT_APPROVAL_SHA256: ${{ steps.preflight.outputs.approval_sha256 }}
        run: |
          path = os.environ["APPROVAL_PATH"]
          expected_approval_hash = os.environ[
            "PREFLIGHT_APPROVAL_SHA256"
          ]
          hashlib.sha256(raw).hexdigest()
          approval diverged from trusted preflight
          module.validate_shape(
          historical=False
          path.name != f'{value["release_id"]}.json'
          approval filename does not match canonical release_id
      - name: Verify controller checkout and workflow identity
        run: verify identity
  build_api:
    permissions:
      contents: read
    steps:
      - run: api
  build_ops:
    permissions:
      contents: read
    steps:
      - run: ops
  build_web:
    permissions:
      contents: read
    steps:
      - run: web
  verify:
    permissions:
      actions: read
      contents: read
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
      - env:
          APPROVAL_PATH: ${{ inputs.approval_path }}
          CONTROLLER_SHA: ${{ inputs.controller_sha }}
        run: |
          test "$(git -C controller rev-parse HEAD)" = "$CONTROLLER_SHA"
          approval="carrier/$APPROVAL_PATH"
          helper_source=controller/scripts/install-bootstrap-source-kit.py
          git -C controller ls-tree
          git -C controller rev-parse
          test "$(git hash-object "$helper_source")" = "$helper_blob"
          install -m 0400 "$helper_source" install-bootstrap-source-kit.py
          HELPER_SHA256=value
          HELPER_SIZE_BYTES=value
          "name": "install-bootstrap-source-kit.py"
          "sha256": os.environ["HELPER_SHA256"]
          "size_bytes": int(
          "controller_sha": os.environ["CONTROLLER_SHA"]
          bootstrap-source-helper.json
          --bootstrap-source-helper bootstrap-source-helper.json
          (.schema_version == 6)
          (($receipt | length) == 1)
          .bootstrap_source_helper == $receipt[0]
          ["controller_sha", "name", "sha256", "size_bytes"]
          jq -r .bootstrap_source_helper.sha256
          jq -r .bootstrap_source_helper.size_bytes
          jq -r .bootstrap_source_helper.controller_sha
  sign_release:
    environment: control-bootstrap
    permissions:
      actions: read
      contents: none
      id-token: write
    steps:
      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
      - uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6
      - run: |
          attestation=verified/release-attestation.json
          receipt=verified/bootstrap-source-helper.json
          helper=verified/install-bootstrap-source-kit.py
          (($receipt | length) == 1)
          .bootstrap_source_helper == $receipt[0]
          ["controller_sha", "name", "sha256", "size_bytes"]
          jq -r .bootstrap_source_helper.name = install-bootstrap-source-kit.py
          jq -r .bootstrap_source_helper.sha256 "$attestation"
          jq -r .bootstrap_source_helper.size_bytes "$attestation"
          jq -r .bootstrap_source_helper.controller_sha "$attestation"
          jq -r .approval.manifest.controller.base_sha
          test "$(sha256sum "$helper")"
          cosign sign-blob --bundle release.sigstore.json "$attestation"
          cosign sign-blob --bundle ops.sigstore.json "$ops_archive"
          cosign sign-blob --bundle bootstrap-source-kit.sigstore.json "$helper"
          cosign verify-blob --bundle release.sigstore.json "$attestation"
          cosign verify-blob --bundle ops.sigstore.json "$ops_archive"
          cosign verify-blob --bundle bootstrap-source-kit.sigstore.json \\
            --certificate-github-workflow-sha "$GITHUB_SHA" \\
            --certificate-github-workflow-ref refs/heads/main \\
            --certificate-github-workflow-repository "$GITHUB_REPOSITORY" \\
            --certificate-github-workflow-trigger workflow_dispatch "$helper"
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
"""


def test_accepts_exact_checkout_to_isolated_signer_shape() -> None:
    SHAPE.validate_structure(valid_shape())


def test_full_gate_requires_exact_compile_time_workflow_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = valid_shape()
    reviewed = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    monkeypatch.setattr(
        SHAPE,
        "EXPECTED_WORKFLOW_SHA256",
        reviewed,
    )

    SHAPE.validate(raw)
    with pytest.raises(
        SHAPE.CarrierShapeError,
        match="digest",
    ):
        SHAPE.validate(raw + "\n# inert text is still drift\n")
    with pytest.raises(
        SHAPE.CarrierShapeError,
        match="digest",
    ):
        SHAPE.validate(
            raw.replace(
                "          attestation=verified/release-attestation.json",
                "          : # inert command\n"
                "          attestation=verified/release-attestation.json",
                1,
            )
        )


def test_rejects_extra_job_or_second_oidc_authority() -> None:
    extra_job = valid_shape() + (
        "  extra_authority:\n"
        "    permissions:\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - run: true\n"
    )
    with pytest.raises(
        SHAPE.CarrierShapeError,
        match="jobs",
    ):
        SHAPE.validate_structure(extra_job)

    second_oidc = valid_shape().replace(
        "  build_api:\n"
        "    permissions:\n"
        "      contents: read\n",
        "  build_api:\n"
        "    permissions:\n"
        "      contents: read\n"
        "      id-token: write\n",
        1,
    )
    with pytest.raises(
        SHAPE.CarrierShapeError,
        match="OIDC",
    ):
        SHAPE.validate_structure(second_oidc)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            "contents: read",
            "contents: write",
        ),
        (
            "contents: none",
            "contents: read",
        ),
        (
            (
                "sigstore/cosign-installer@"
                "6f9f17788090df1f26f669e9d70d6ae9567deba6"
            ),
            "sigstore/cosign-installer@main",
        ),
        (
            "install -m 0400",
            "cp",
        ),
        (
            "--certificate-github-workflow-trigger workflow_dispatch",
            "--certificate-github-workflow-trigger push",
        ),
        (
            "--bundle bootstrap-source-kit.sigstore.json",
            "--bundle shared.sigstore.json",
        ),
        (
            "(.schema_version == 6)",
            "(.schema_version == 5)",
        ),
        (
            '["controller_sha", "name", "sha256", "size_bytes"]',
            '["controller_sha", "name", "sha256"]',
        ),
        (
            "--bootstrap-source-helper bootstrap-source-helper.json",
            "bootstrap-source-helper.json",
        ),
    ],
)
def test_rejects_authority_origin_or_signature_drift(
    old: str,
    new: str,
) -> None:
    with pytest.raises(SHAPE.CarrierShapeError):
        SHAPE.validate_structure(valid_shape().replace(old, new, 1))


def test_rejects_checkout_in_signer() -> None:
    raw = valid_shape().replace(
        "    steps:\n"
        "      - uses: actions/download-artifact@",
        "    steps:\n"
        "      - uses: actions/checkout@"
        "11d5960a326750d5838078e36cf38b85af677262\n"
        "      - uses: actions/download-artifact@",
        1,
    )

    with pytest.raises(
        SHAPE.CarrierShapeError,
        match="signer isolation",
    ):
        SHAPE.validate_structure(raw)


def test_rejects_coalesced_or_missing_blob_signature() -> None:
    raw = valid_shape().replace(
        'cosign sign-blob --bundle ops.sigstore.json "$ops_archive"',
        'cp release.sigstore.json ops.sigstore.json',
        1,
    )

    with pytest.raises(
        SHAPE.CarrierShapeError,
        match="signatures",
    ):
        SHAPE.validate_structure(raw)


def test_rejects_direct_input_interpolation_inside_run() -> None:
    raw = valid_shape().replace(
        'approval="carrier/$APPROVAL_PATH"',
        'approval="carrier/${{ inputs.approval_path }}"',
        1,
    )

    with pytest.raises(
        SHAPE.CarrierShapeError,
        match="interpolated",
    ):
        SHAPE.validate_structure(raw)


def test_rejects_approval_path_without_step_env() -> None:
    raw = valid_shape().replace(
        "          APPROVAL_PATH: ${{ inputs.approval_path }}\n",
        "",
        1,
    )

    with pytest.raises(
        SHAPE.CarrierShapeError,
        match="only through env",
    ):
        SHAPE.validate_structure(raw)


def test_rejects_approval_filename_not_bound_to_release_id() -> None:
    raw = valid_shape().replace(
        """          path.name != f'{value["release_id"]}.json'\n""",
        "          path.name.endswith('.json')\n",
        1,
    )

    with pytest.raises(
        SHAPE.CarrierShapeError,
        match="filename",
    ):
        SHAPE.validate_structure(raw)


def test_rejects_controller_checkout_before_inline_preflight() -> None:
    raw = valid_shape().replace(
        "Preflight untrusted approval and controller inputs",
        "ORDER_PLACEHOLDER",
        1,
    ).replace(
        "Checkout reviewed public controller",
        "Preflight untrusted approval and controller inputs",
        1,
    ).replace(
        "ORDER_PLACEHOLDER",
        "Checkout reviewed public controller",
        1,
    )

    with pytest.raises(
        SHAPE.CarrierShapeError,
        match="order",
    ):
        SHAPE.validate_structure(raw)


def test_rejects_preflight_without_exact_controller_binding() -> None:
    raw = valid_shape().replace(
        'controller.get("base_sha") != controller_sha',
        'controller.get("base_sha")',
        1,
    )

    with pytest.raises(
        SHAPE.CarrierShapeError,
        match="preflight",
    ):
        SHAPE.validate_structure(raw)


def test_rejects_missing_preflight_digest_continuity() -> None:
    raw = valid_shape().replace(
        "          approval diverged from trusted preflight\n",
        "",
        1,
    )

    with pytest.raises(
        SHAPE.CarrierShapeError,
        match="validation",
    ):
        SHAPE.validate_structure(raw)
