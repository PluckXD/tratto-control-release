#!/usr/bin/env python3
"""Independent HTTP/runtime verifier for exact API, Ops, and Web artifacts."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import component_manifest as COMPONENT
import runtime_policy as RUNTIME


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
BINDING_KEYS = {
    "artifact_id",
    "component_manifest_sha256",
    "service_digest",
    "sha256",
}
HERE = Path(__file__).resolve().parent
APPROVAL_SPEC = importlib.util.spec_from_file_location(
    "control_release_runtime_approval",
    HERE / "validate-approval.py",
)
if APPROVAL_SPEC is None or APPROVAL_SPEC.loader is None:
    raise RuntimeError("approval validator is unavailable")
APPROVAL = importlib.util.module_from_spec(APPROVAL_SPEC)
APPROVAL_SPEC.loader.exec_module(APPROVAL)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Expose the original 3xx response instead of following its Location."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def fail(message: str) -> None:
    raise SystemExit(f"runtime contract rejected: {message}")


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def stat_snapshot(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def regular_json(path: Path, label: str) -> tuple[bytes, dict[str, Any]]:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError:
        fail(f"{label} is unavailable or invalid")
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or not 0 < info.st_size <= 64 * 1024
        ):
            fail(f"{label} must be canonical isolated output mode 0600")
        raw = os.read(descriptor, 64 * 1024 + 1)
        if (
            len(raw) != info.st_size
            or stat_snapshot(os.fstat(descriptor)) != stat_snapshot(info)
        ):
            fail(f"{label} changed while being read")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{label} is unavailable or invalid")
    if not isinstance(value, dict) or raw != canonical_bytes(value):
        fail(f"{label} must be canonical isolated output mode 0600")
    return raw, value


def validate_bindings(path: Path) -> dict[str, dict[str, Any]]:
    _, value = regular_json(path, "artifact bindings")
    if set(value) != {"api", "ops", "web"}:
        fail("artifact bindings must contain API, Ops, and Web")
    ids: set[int] = set()
    for label, block in value.items():
        if (
            not isinstance(block, dict)
            or set(block) != BINDING_KEYS
            or type(block["artifact_id"]) is not int
            or block["artifact_id"] <= 0
        ):
            fail(f"artifact binding is invalid: {label}")
        ids.add(block["artifact_id"])
        for key in (
            "component_manifest_sha256",
            "service_digest",
            "sha256",
        ):
            if (
                not isinstance(block[key], str)
                or HASH_RE.fullmatch(block[key]) is None
            ):
                fail(f"artifact binding digest is invalid: {label}/{key}")
    if len(ids) != 3:
        fail("artifact bindings must use distinct carrier asset IDs")
    return value


def validate_ops_verification(
    path: Path,
    binding: dict[str, Any],
) -> None:
    _, value = regular_json(path, "Ops verification")
    expected = {
        "component_manifest_sha256": binding[
            "component_manifest_sha256"
        ],
        "service_digest": binding["service_digest"],
        "sha256": binding["sha256"],
    }
    if value != expected:
        fail("Ops archive/tree verification does not match signed binding")


def bounded_digest(path: Path, label: str, maximum: int) -> str:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError:
        fail(f"{label} is unavailable")
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o022
            or not 0 < info.st_size <= maximum
        ):
            fail(f"{label} must be a bounded non-writable single-link file")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        if stat_snapshot(os.fstat(descriptor)) != stat_snapshot(info):
            fail(f"{label} changed while being hashed")
    except OSError:
        fail(f"{label} cannot be read")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def validate_approval_component_shas(
    approval: dict[str, Any],
    *,
    api_sha: str,
    web_sha: str,
) -> None:
    if (
        approval["api"]["commit_sha"] != api_sha
        or approval["ops"]["commit_sha"] != api_sha
        or approval["web"]["commit_sha"] != web_sha
    ):
        fail("runtime component SHAs are not authorized by the approval")


def validate_component_manifests(
    *,
    approval_path: Path,
    runtime_policy_path: Path,
    api_manifest_path: Path,
    ops_manifest_path: Path,
    web_manifest_path: Path,
    api_requirements_lock: Path,
    bindings: dict[str, dict[str, Any]],
    api_sha: str,
    web_sha: str,
) -> None:
    approval_raw, approval = regular_json(approval_path, "approval")
    try:
        APPROVAL.validate_shape(approval, now=None, historical=True)
        validate_approval_component_shas(
            approval,
            api_sha=api_sha,
            web_sha=web_sha,
        )
        _, runtime_policy_digest = RUNTIME.load(runtime_policy_path)
        manifests: dict[str, dict[str, Any]] = {}
        for label, path in (
            ("api", api_manifest_path),
            ("ops", ops_manifest_path),
            ("web", web_manifest_path),
        ):
            _, manifest, digest = COMPONENT.load(
                path,
                f"{label} component manifest",
            )
            if digest != bindings[label]["component_manifest_sha256"]:
                fail(f"{label} component manifest is not bound to the artifact")
            manifests[label] = manifest
        requirements_digest = bounded_digest(
            api_requirements_lock,
            "API requirements lock",
            16 * 1024 * 1024,
        )
        COMPONENT.validate_set(
            manifests,
            api_sha=api_sha,
            web_sha=web_sha,
            approval_manifest_sha256=hashlib.sha256(
                approval_raw
            ).hexdigest(),
            migration=approval["migration"],
            runtime_policy_digest=runtime_policy_digest,
            requirements_lock_sha256=requirements_digest,
        )
    except (
        APPROVAL.ApprovalError,
        COMPONENT.ComponentManifestError,
        RUNTIME.RuntimePolicyError,
    ) as error:
        fail(f"component runtime policy is invalid: {error}")


def request(
    base: str,
    path: str,
    *,
    method: str = "GET",
    host: str = "control.usetratto.com.br",
    body: bytes | None = None,
) -> int:
    target = base.rstrip("/") + path
    headers = {"Host": host}
    if body is not None:
        headers["Content-Type"] = "application/json"
    value = urllib.request.Request(
        target,
        method=method,
        data=body,
        headers=headers,
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirect(),
    )
    try:
        with opener.open(value, timeout=5) as response:
            response.read(1)
            return response.status
    except urllib.error.HTTPError as error:
        error.read(1)
        return error.code
    except (OSError, urllib.error.URLError):
        fail(f"endpoint is unavailable: {path}")


def expect(actual: int, allowed: set[int], label: str) -> None:
    if actual not in allowed:
        fail(f"{label} returned HTTP {actual}, expected {sorted(allowed)}")


def browser_report(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw, value = regular_json(path, "browser report")
    expected = {
        "schema_version",
        "fragment_removed_before_submit",
        "legacy_path_status",
        "request_method",
        "request_path",
        "request_body_keys",
        "request_token_sha256",
        "token_observed_in_url",
    }
    if (
        set(value) != expected
        or value["schema_version"] != 1
        or value["fragment_removed_before_submit"] is not True
        or value["legacy_path_status"] != 404
        or value["request_method"] != "POST"
        or value["request_path"] != "/api/auth/redefinir-senha"
        or value["request_body_keys"] != ["senha_nova", "token"]
        or not isinstance(value["request_token_sha256"], str)
        or HASH_RE.fullmatch(value["request_token_sha256"]) is None
        or value["token_observed_in_url"] is not False
    ):
        fail("browser did not prove fragment/body-only reset")
    return raw, value


def write_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError:
        fail("runtime report output already exists or is unsafe")
    try:
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--web-url", required=True)
    parser.add_argument("--edge-url", required=True)
    parser.add_argument("--browser-report", required=True, type=Path)
    parser.add_argument("--artifact-bindings", required=True, type=Path)
    parser.add_argument("--ops-verification", required=True, type=Path)
    parser.add_argument("--approval", required=True, type=Path)
    parser.add_argument("--runtime-policy", required=True, type=Path)
    parser.add_argument("--api-manifest", required=True, type=Path)
    parser.add_argument("--ops-manifest", required=True, type=Path)
    parser.add_argument("--web-manifest", required=True, type=Path)
    parser.add_argument("--api-requirements-lock", required=True, type=Path)
    parser.add_argument("--api-sha", required=True)
    parser.add_argument("--web-sha", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if (
        SHA_RE.fullmatch(args.api_sha) is None
        or SHA_RE.fullmatch(args.web_sha) is None
    ):
        fail("component SHA is invalid")
    bindings = validate_bindings(args.artifact_bindings)
    validate_ops_verification(args.ops_verification, bindings["ops"])
    validate_component_manifests(
        approval_path=args.approval,
        runtime_policy_path=args.runtime_policy,
        api_manifest_path=args.api_manifest,
        ops_manifest_path=args.ops_manifest,
        web_manifest_path=args.web_manifest,
        api_requirements_lock=args.api_requirements_lock,
        bindings=bindings,
        api_sha=args.api_sha,
        web_sha=args.web_sha,
    )

    observations: dict[str, int] = {}
    checks = (
        ("api_health", args.api_url, "/healthz", "GET", {200}, None),
        ("api_anonymous_me", args.api_url, "/me", "GET", {401, 403}, None),
        ("api_business_deny", args.api_url, "/clientes", "GET", {404}, None),
        ("api_internal_deny", args.api_url, "/internal/p2t", "GET", {404}, None),
        (
            "api_reset_exact",
            args.api_url,
            "/auth/redefinir-senha",
            "POST",
            {400, 401, 403, 422},
            b'{"token":"invalid","senha_nova":"Contract1!"}',
        ),
        (
            "api_reset_legacy",
            args.api_url,
            "/auth/redefinir-senha/token-in-url",
            "POST",
            {404},
            b"{}",
        ),
        (
            "api_p2t_password_ack_exists",
            args.api_url,
            (
                "/superadmin/p2t/environments/"
                "00000000-0000-4000-8000-000000000000/password-ack"
            ),
            "POST",
            {401, 403},
            b"{}",
        ),
        ("web_login", args.web_url, "/login", "GET", {200}, None),
        ("web_business_deny", args.web_url, "/pedidos", "GET", {404}, None),
        ("web_reset_exact", args.web_url, "/redefinir-senha", "GET", {200}, None),
        (
            "web_reset_legacy",
            args.web_url,
            "/redefinir-senha/token-in-url",
            "GET",
            {404},
            None,
        ),
        (
            "web_wrong_host",
            args.web_url,
            "/login",
            "GET",
            {421},
            None,
            "app.usetratto.com.br",
        ),
        (
            "edge_reset_query",
            args.edge_url,
            "/redefinir-senha?token=query-token",
            "GET",
            {404},
            None,
        ),
        (
            "edge_reset_legacy",
            args.edge_url,
            "/redefinir-senha/token-in-url",
            "GET",
            {404},
            None,
        ),
    )
    for check in checks:
        label, base, path, method, allowed, body, *optional_host = check
        status = request(
            base,
            path,
            method=method,
            body=body,
            host=(
                optional_host[0]
                if optional_host
                else "control.usetratto.com.br"
            ),
        )
        expect(status, allowed, label)
        observations[label] = status

    browser_raw, _ = browser_report(args.browser_report)
    report = {
        "api_sha": args.api_sha,
        "artifacts": bindings,
        "browser_report_sha256": hashlib.sha256(browser_raw).hexdigest(),
        "contracts": {
            "api_auth_surface_http": True,
            "api_business_denylist_http": True,
            "api_p2t_password_ack_http": True,
            "api_reset_endpoint_http": True,
            "edge_reset_url_redaction_http": True,
            "ops_tree_digest_verified": True,
            "web_exact_hostname_http": True,
            "web_reset_fragment_browser": True,
            "web_surface_denylist_http": True,
        },
        "observations": observations,
        "schema_version": 3,
        "verdict": "pass",
        "web_sha": args.web_sha,
    }
    write_exclusive(args.output, canonical_bytes(report))
    print("real artifacts passed the independent runtime contract")


if __name__ == "__main__":
    main()
