"""Canonical Operations artifact inventory shared by builder and verifier."""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import ast
import hashlib
import posixpath
import re
import unicodedata
from collections.abc import Mapping
from pathlib import PurePosixPath


HASH_RE = re.compile(r"^[0-9a-f]{64}$")
MARKERS = {"RELEASE_SHA", "artifact-manifest.json"}
MAX_MEMBERS = 10_000
MAX_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
QUIESCENCE_HELPER_PATH = "scripts/verify-control-stack-quiescent.py"
QUIESCENCE_CONTRACT_VERSION = 2
QUIESCENCE_HELPER_SHA256 = (
    "2f745c4dd99e811eb2e50f2800a31ca99f97c41579c9a0ca96ac728df55f35c8"
)
MAX_QUIESCENCE_HELPER_BYTES = 256 * 1024
BOOTSTRAP_REQUIRED_FILE_MODES = {
    "scripts/provision-node-runtime.py": 0o555,
    "scripts/publish-bootstrap-tree.py": 0o555,
    "scripts/verify-control-stack-quiescent.py": 0o555,
    "scripts/with-deploy-lock.py": 0o555,
}
REQUIRED_FILES = {
    "config/provenance-policy.env",
    "nginx/tratto-control.conf",
    "release-root/policies/control-runtime-v1.json",
    "release-root/README.md",
    "release-root/schemas/component-manifest.schema.json",
    "release-root/schemas/host-runtime-attestation.schema.json",
    "release-root/schemas/runtime-policy.schema.json",
    "release-root/scripts/attest-host-runtime.py",
    "release-root/scripts/component_manifest.py",
    "release-root/scripts/extract-reviewed-node.py",
    "release-root/scripts/runtime_policy.py",
    "release-root/scripts/verify-runtime-contract.py",
    "scripts/activate-release.sh",
    "scripts/attest-host-runtime.py",
    "scripts/install-host.sh",
    "scripts/lib/control_ops_tree.py",
    "scripts/link-bootstrap-contract.sh",
    "scripts/link-runtime-contract.sh",
    "scripts/provision-node-runtime.py",
    "scripts/publish-bootstrap-tree.py",
    "scripts/publish-host-policies.py",
    "scripts/record-bootstrap-release.py",
    "scripts/recover-interrupted.sh",
    "scripts/rollback-release.sh",
    "scripts/stage-release.sh",
    "scripts/validate-artifact.py",
    "scripts/validate-bundle.py",
    "scripts/verify-bootstrap-provenance.py",
    "scripts/verify-ci-provenance.py",
    "systemd/tratto-control-api.service",
    "systemd/tratto-control-recovery.service",
    "systemd/tratto-control-web.service",
} | set(BOOTSTRAP_REQUIRED_FILE_MODES)
FORBIDDEN_BASENAMES = {
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials.json",
    "id_ed25519",
    "id_rsa",
}
FORBIDDEN_SUFFIXES = {".key", ".p12", ".pfx"}


class OpsTreeError(ValueError):
    pass


def reject(message: str) -> None:
    raise OpsTreeError(message)


def canonical_path(path: str) -> str:
    try:
        encoded = path.encode("utf-8")
    except UnicodeEncodeError:
        reject("Ops path is not valid UTF-8")
    if (
        not path
        or path.startswith("/")
        or path.startswith("-")
        or "\x00" in path
        or unicodedata.normalize("NFC", path) != path
    ):
        reject("Ops path is not canonical UTF-8")
    normalized = posixpath.normpath(path)
    pure = PurePosixPath(path)
    if (
        normalized != path
        or normalized in {"", ".", ".."}
        or normalized.startswith("../")
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        reject("Ops path traversal or normalization drift")
    if encoded.decode("utf-8") != path:
        reject("Ops path UTF-8 round trip diverges")
    basename = pure.name.lower()
    if (
        basename in FORBIDDEN_BASENAMES
        or basename.startswith(".env.")
        or pure.suffix.lower() in FORBIDDEN_SUFFIXES
    ):
        reject("secret-bearing filename in Ops artifact")
    return path


def normalized_file_mode(*, executable: bool) -> int:
    return 0o555 if executable else 0o444


def inventory_record(
    *,
    kind: str,
    mode: int,
    content_sha256: str,
    path: str,
) -> bytes:
    if kind != "file":
        reject("Ops inventory type is invalid")
    if mode not in {0o444, 0o555}:
        reject("Ops inventory mode is not canonical")
    if HASH_RE.fullmatch(content_sha256) is None:
        reject("Ops inventory content digest is invalid")
    canonical_path(path)
    return (
        kind.encode("ascii")
        + b"\0"
        + f"{mode:04o}".encode("ascii")
        + b"\0"
        + content_sha256.encode("ascii")
        + b"\0"
        + path.encode("utf-8")
        + b"\0"
    )


def service_digest(records: list[tuple[str, bytes]]) -> str:
    paths = [path.encode("utf-8") for path, _ in records]
    if len(paths) != len(set(paths)):
        reject("Ops inventory contains duplicate paths")
    digest = hashlib.sha256()
    for _, record in sorted(records, key=lambda item: item[0].encode("utf-8")):
        digest.update(record)
    return digest.hexdigest()


def validate_required_inventory(paths: set[str]) -> None:
    missing = REQUIRED_FILES - paths
    if missing:
        reject(f"Ops required inventory is incomplete: {sorted(missing)}")


def validate_bootstrap_required_file_modes(
    modes: Mapping[str, int],
) -> None:
    missing = set(BOOTSTRAP_REQUIRED_FILE_MODES) - set(modes)
    if missing:
        reject(
            "Ops bootstrap executable inventory is incomplete: "
            f"{sorted(missing)}"
        )
    mismatched = {
        path: (BOOTSTRAP_REQUIRED_FILE_MODES[path], modes[path])
        for path in BOOTSTRAP_REQUIRED_FILE_MODES
        if modes[path] != BOOTSTRAP_REQUIRED_FILE_MODES[path]
    }
    if mismatched:
        reject(
            "Ops bootstrap executable mode contract diverges: "
            f"{mismatched}"
        )


def validate_quiescence_helper_contract(payload: bytes | None) -> None:
    if (
        payload is None
        or not payload
        or len(payload) > MAX_QUIESCENCE_HELPER_BYTES
    ):
        reject("Ops quiescence helper is missing or exceeds its size limit")
    try:
        source = payload.decode("utf-8")
    except UnicodeDecodeError:
        reject("Ops quiescence helper is not UTF-8")
    if "\x00" in source or "\r" in source:
        reject("Ops quiescence helper source is not canonical")
    if hashlib.sha256(payload).hexdigest() != QUIESCENCE_HELPER_SHA256:
        reject("Ops quiescence helper digest diverges")
    try:
        module = ast.parse(source, filename=QUIESCENCE_HELPER_PATH)
    except (SyntaxError, ValueError):
        reject("Ops quiescence helper is not valid Python")
    assignments: list[tuple[ast.AST, ast.Name, ast.AST]] = []
    for node in module.body:
        if isinstance(node, ast.Assign):
            matching = [
                target
                for target in node.targets
                if (
                    isinstance(target, ast.Name)
                    and target.id == "QUIESCENCE_CONTRACT_VERSION"
                )
            ]
            if matching:
                if len(node.targets) != 1 or len(matching) != 1:
                    reject("Ops quiescence helper contract is ambiguous")
                assignments.append((node, matching[0], node.value))
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "QUIESCENCE_CONTRACT_VERSION"
        ):
            if node.value is None:
                reject("Ops quiescence helper contract is not literal")
            assignments.append((node, node.target, node.value))
    if len(assignments) != 1:
        reject("Ops quiescence helper contract version diverges")
    try:
        version = ast.literal_eval(assignments[0][2])
    except (ValueError, TypeError):
        reject("Ops quiescence helper contract is not literal")
    if (
        type(version) is not int
        or version != QUIESCENCE_CONTRACT_VERSION
    ):
        reject("Ops quiescence helper contract version diverges")
    approved_target = assignments[0][1]
    for node in ast.walk(module):
        if (
            isinstance(node, ast.Name)
            and node.id == "QUIESCENCE_CONTRACT_VERSION"
            and not isinstance(node.ctx, ast.Load)
            and node is not approved_target
        ):
            reject("Ops quiescence helper contract is rebound")
        if (
            isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
            )
            and node.name == "QUIESCENCE_CONTRACT_VERSION"
        ):
            reject("Ops quiescence helper contract is rebound")
        if (
            isinstance(node, ast.arg)
            and node.arg == "QUIESCENCE_CONTRACT_VERSION"
        ):
            reject("Ops quiescence helper contract is rebound")
        if (
            isinstance(node, (ast.Global, ast.Nonlocal))
            and "QUIESCENCE_CONTRACT_VERSION" in node.names
        ):
            reject("Ops quiescence helper contract is rebound")
        if (
            isinstance(node, ast.ExceptHandler)
            and node.name == "QUIESCENCE_CONTRACT_VERSION"
        ):
            reject("Ops quiescence helper contract is rebound")
        if isinstance(node, ast.alias):
            bound = node.asname or node.name.split(".", 1)[0]
            if bound == "QUIESCENCE_CONTRACT_VERSION":
                reject("Ops quiescence helper contract is rebound")
