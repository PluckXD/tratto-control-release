from __future__ import annotations

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
    steps:
      - run: authorize
  build_api:
    steps:
      - run: api
  build_ops:
    steps:
      - run: ops
  build_web:
    steps:
      - run: web
  verify:
    env:
      CONTROLLER_SHA: ${{ inputs.controller_sha }}
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
      - run: |
          test "$(git -C controller rev-parse HEAD)" = "$CONTROLLER_SHA"
          helper_source=controller/scripts/install-bootstrap-source-kit.py
          git -C controller ls-tree
          git -C controller rev-parse
          test "$(git hash-object "$helper_source")" = "$helper_blob"
          install -m 0400 "$helper_source" install-bootstrap-source-kit.py
          HELPER_SHA256=value
          "helper_sha256": os.environ["HELPER_SHA256"]
          "controller_sha": os.environ["CONTROLLER_SHA"]
          bootstrap-source-helper.json
          jq -r .helper_sha256 bootstrap-source-helper.json
          jq -r .controller_sha bootstrap-source-helper.json
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
          helper=verified/install-bootstrap-source-kit.py
          jq -r .helper_sha256 verified/bootstrap-source-helper.json
          jq -r .approval.manifest.controller.base_sha
          test "$(sha256sum "$helper")"
          cosign sign-blob --bundle bootstrap-source-kit.sigstore.json "$helper"
          cosign verify-blob --bundle bootstrap-source-kit.sigstore.json \\
            --certificate-github-workflow-sha "$GITHUB_SHA" \\
            --certificate-github-workflow-ref refs/heads/main \\
            --certificate-github-workflow-repository "$GITHUB_REPOSITORY" \\
            --certificate-github-workflow-trigger workflow_dispatch "$helper"
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
"""


def test_accepts_exact_checkout_to_isolated_signer_shape() -> None:
    SHAPE.validate(valid_shape())


@pytest.mark.parametrize(
    ("old", "new"),
    [
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
    ],
)
def test_rejects_authority_origin_or_signature_drift(
    old: str,
    new: str,
) -> None:
    with pytest.raises(SHAPE.CarrierShapeError):
        SHAPE.validate(valid_shape().replace(old, new, 1))


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
        SHAPE.validate(raw)
