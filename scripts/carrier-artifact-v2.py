#!/usr/bin/env python3
"""Upload or retrieve a digest-bound asset from the untrusted carrier.

The carrier is transport only.  Every operation is pinned to a numeric release
or asset id and exact bytes; names and GitHub Release state never authorize a
Control release.  This client deliberately cannot create, edit, or delete a
release.
"""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import http.client
import json
import os
import re
import ssl
import stat
import urllib.parse
from pathlib import Path
from typing import Any, BinaryIO


REPOSITORY = "PluckXD/tratto-control-release-carrier"
API_HOST = "api.github.com"
UPLOAD_HOST = "uploads.github.com"
MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024
MAX_JSON_BYTES = 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ASSET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
RECEIPT_KEYS = {
    "artifact_id",
    "artifact_name",
    "carrier_repository",
    "sha256",
    "size_bytes",
}


class CarrierArtifactV2Error(ValueError):
    """The transport operation or exact byte binding failed closed."""


def reject(message: str) -> None:
    raise CarrierArtifactV2Error(message)


def positive_decimal(value: str) -> int:
    if re.fullmatch(r"[1-9][0-9]*", value) is None:
        raise argparse.ArgumentTypeError("id must be a positive decimal")
    parsed = int(value)
    if parsed > 2**63 - 1:
        raise argparse.ArgumentTypeError("id exceeds supported range")
    return parsed


def bounded_size(value: str) -> int:
    parsed = positive_decimal(value)
    if parsed > MAX_FILE_BYTES:
        raise argparse.ArgumentTypeError("size exceeds artifact limit")
    return parsed


def sha256_value(value: str) -> str:
    if SHA256_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("SHA-256 must be lowercase hex")
    return value


def asset_name(value: str) -> str:
    if ASSET_NAME_RE.fullmatch(value) is None or value in {".", ".."}:
        raise argparse.ArgumentTypeError("asset name is not canonical")
    return value


def token_from_environment() -> str:
    token = os.environ.get("CONTROL_CARRIER_TOKEN", "")
    if (
        not token
        or len(token.encode("utf-8")) > 4096
        or any(ord(character) < 33 for character in token)
    ):
        reject("least-privilege carrier token is unavailable or invalid")
    return token


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            reject(f"duplicate JSON key in carrier response: {key}")
        value[key] = item
    return value


def parse_json(raw: bytes, label: str) -> Any:
    if not 0 < len(raw) <= MAX_JSON_BYTES:
        reject(f"{label} response is empty or oversized")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda item: reject(
                f"non-finite carrier JSON number: {item}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        reject(f"{label} response is not valid UTF-8 JSON")


def common_headers(token: str, accept: str) -> dict[str, str]:
    return {
        "Accept": accept,
        "Authorization": f"Bearer {token}",
        "User-Agent": "tratto-control-release-carrier-v2",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def stable_input(path: Path, expected_size: int, expected_sha256: str) -> tuple[BinaryIO, os.stat_result]:
    absolute = path.absolute()
    descriptor = -1
    try:
        if absolute.resolve(strict=True) != absolute:
            reject("artifact path must not traverse symlinks")
        before_path = absolute.lstat()
        descriptor = os.open(
            absolute,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        info = os.fstat(descriptor)
    except CarrierArtifactV2Error:
        raise
    except OSError:
        reject("artifact is unavailable")
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
        or info.st_size != expected_size
        or not 0 < info.st_size <= MAX_FILE_BYTES
        or (info.st_dev, info.st_ino)
        != (before_path.st_dev, before_path.st_ino)
    ):
        os.close(descriptor)
        reject("artifact is not one exact private single-link regular file")
    digest = hashlib.sha256()
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError:
        os.close(descriptor)
        reject("artifact changed or failed while being hashed")
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        any(getattr(after, field) != getattr(info, field) for field in fields)
        or digest.hexdigest() != expected_sha256
    ):
        os.close(descriptor)
        reject("artifact bytes diverge from the expected binding")
    return os.fdopen(descriptor, "rb", closefd=True), info


def response_bytes(response: http.client.HTTPResponse, label: str) -> bytes:
    raw = response.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        reject(f"{label} response is oversized")
    return raw


def write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            reject("carrier output write was incomplete")
        view = view[written:]


def upload(
    *,
    token: str,
    release_id: int,
    path: Path,
    name: str,
    expected_size: int,
    expected_sha256: str,
) -> dict[str, Any]:
    source, opened = stable_input(path, expected_size, expected_sha256)
    query = urllib.parse.urlencode({"name": name}, quote_via=urllib.parse.quote)
    target = f"/repos/{REPOSITORY}/releases/{release_id}/assets?{query}"
    connection = http.client.HTTPSConnection(
        UPLOAD_HOST,
        timeout=60,
        context=ssl.create_default_context(),
    )
    try:
        connection.putrequest("POST", target, skip_accept_encoding=True)
        for header, value in common_headers(
            token,
            "application/vnd.github+json",
        ).items():
            connection.putheader(header, value)
        connection.putheader("Content-Type", "application/octet-stream")
        connection.putheader("Content-Length", str(expected_size))
        connection.endheaders()
        sent = 0
        sent_digest = hashlib.sha256()
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            connection.send(chunk)
            sent += len(chunk)
            sent_digest.update(chunk)
        if (
            sent != expected_size
            or source.tell() != expected_size
            or sent_digest.hexdigest() != expected_sha256
        ):
            reject("artifact changed or ended during carrier upload")
        after = os.fstat(source.fileno())
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(after, field) != getattr(opened, field) for field in fields):
            reject("artifact metadata changed during carrier upload")
        response = connection.getresponse()
        raw = response_bytes(response, "carrier upload")
        if response.status != 201:
            reject("carrier upload was rejected")
    except CarrierArtifactV2Error:
        raise
    except (OSError, http.client.HTTPException):
        reject("carrier upload failed closed")
    finally:
        source.close()
        connection.close()
    value = parse_json(raw, "carrier upload")
    if type(value) is not dict:
        reject("carrier upload response must be an object")
    if (
        type(value.get("id")) is not int
        or value["id"] <= 0
        or value.get("name") != name
        or value.get("size") != expected_size
        or value.get("state") != "uploaded"
    ):
        reject("carrier upload response diverges from the exact artifact")
    return {
        "artifact_id": value["id"],
        "artifact_name": name,
        "carrier_repository": REPOSITORY,
        "sha256": expected_sha256,
        "size_bytes": expected_size,
    }


def api_request(token: str, target: str, accept: str) -> http.client.HTTPResponse:
    connection = http.client.HTTPSConnection(
        API_HOST,
        timeout=30,
        context=ssl.create_default_context(),
    )
    try:
        connection.request(
            "GET",
            target,
            headers=common_headers(token, accept),
        )
        response = connection.getresponse()
        response._tratto_connection = connection  # type: ignore[attr-defined]
        return response
    except (OSError, http.client.HTTPException):
        connection.close()
        reject("carrier API request failed closed")


def close_response(response: http.client.HTTPResponse) -> None:
    connection = getattr(response, "_tratto_connection", None)
    response.close()
    if connection is not None:
        connection.close()


def asset_metadata(token: str, artifact_id: int) -> dict[str, Any]:
    target = f"/repos/{REPOSITORY}/releases/assets/{artifact_id}"
    response = api_request(token, target, "application/vnd.github+json")
    try:
        raw = response_bytes(response, "carrier metadata")
        if response.status != 200:
            reject("carrier asset metadata was rejected")
    finally:
        close_response(response)
    value = parse_json(raw, "carrier metadata")
    if type(value) is not dict or value.get("id") != artifact_id:
        reject("carrier asset metadata identity diverges")
    return value


def allowed_redirect(location: str) -> tuple[str, str]:
    parsed = urllib.parse.urlsplit(location)
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or not host
        or (
            host != "objects.githubusercontent.com"
            and not host.endswith(".githubusercontent.com")
            and not host.endswith(".amazonaws.com")
        )
        or parsed.fragment
    ):
        reject("carrier download redirect is outside approved HTTPS storage")
    target = urllib.parse.urlunsplit(("", "", parsed.path, parsed.query, ""))
    if not target.startswith("/"):
        reject("carrier download redirect path is invalid")
    return host, target


def open_download(token: str, artifact_id: int) -> http.client.HTTPResponse:
    target = f"/repos/{REPOSITORY}/releases/assets/{artifact_id}"
    response = api_request(token, target, "application/octet-stream")
    if response.status == 200:
        return response
    if response.status not in {301, 302, 303, 307, 308}:
        close_response(response)
        reject("carrier asset download was rejected")
    location = response.getheader("Location", "")
    close_response(response)
    host, redirected_target = allowed_redirect(location)
    connection = http.client.HTTPSConnection(
        host,
        timeout=60,
        context=ssl.create_default_context(),
    )
    try:
        connection.request("GET", redirected_target, headers={"User-Agent": "tratto-control-release-carrier-v2"})
        redirected = connection.getresponse()
        redirected._tratto_connection = connection  # type: ignore[attr-defined]
    except (OSError, http.client.HTTPException):
        connection.close()
        reject("carrier storage download failed closed")
    if redirected.status != 200:
        close_response(redirected)
        reject("carrier storage download was rejected")
    return redirected


def download(
    *,
    token: str,
    artifact_id: int,
    output: Path,
    name: str,
    expected_size: int,
    expected_sha256: str,
) -> dict[str, Any]:
    metadata = asset_metadata(token, artifact_id)
    if (
        metadata.get("name") != name
        or metadata.get("size") != expected_size
        or metadata.get("state") != "uploaded"
    ):
        reject("carrier metadata diverges from the approved byte binding")
    absolute = output.absolute()
    try:
        if absolute.parent.resolve(strict=True) != absolute.parent:
            reject("carrier output parent must not traverse symlinks")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(absolute, flags, 0o600)
    except CarrierArtifactV2Error:
        raise
    except OSError:
        reject("carrier output cannot be created safely")
    response: http.client.HTTPResponse | None = None
    digest = hashlib.sha256()
    total = 0
    try:
        response = open_download(token, artifact_id)
        while True:
            chunk = response.read(min(1024 * 1024, expected_size + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > expected_size:
                reject("carrier asset exceeds its approved size")
            digest.update(chunk)
            write_all(descriptor, chunk)
        os.fsync(descriptor)
        if total != expected_size or digest.hexdigest() != expected_sha256:
            reject("carrier bytes diverge from the approved digest or size")
    except BaseException:
        os.close(descriptor)
        if response is not None:
            close_response(response)
        try:
            absolute.unlink()
        except OSError:
            pass
        raise
    os.close(descriptor)
    assert response is not None
    close_response(response)
    return {
        "artifact_id": artifact_id,
        "artifact_name": name,
        "carrier_repository": REPOSITORY,
        "sha256": expected_sha256,
        "size_bytes": expected_size,
    }


def write_receipt(path: Path, value: dict[str, Any]) -> None:
    if set(value) != RECEIPT_KEYS:
        reject("carrier receipt keys diverge")
    absolute = path.absolute()
    try:
        if absolute.parent.resolve(strict=True) != absolute.parent:
            reject("carrier receipt parent must not traverse symlinks")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(absolute, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(canonical_bytes(value))
            output.flush()
            os.fsync(output.fileno())
    except CarrierArtifactV2Error:
        raise
    except OSError:
        reject("carrier receipt cannot be written safely")


class FailClosedParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        reject(f"invalid command line: {message}")


def parser() -> argparse.ArgumentParser:
    root = FailClosedParser()
    commands = root.add_subparsers(dest="command", required=True)
    upload_command = commands.add_parser("upload")
    upload_command.add_argument("--release-id", required=True, type=positive_decimal)
    upload_command.add_argument("--artifact", required=True, type=Path)
    upload_command.add_argument("--asset-name", required=True, type=asset_name)
    upload_command.add_argument("--expected-size", required=True, type=bounded_size)
    upload_command.add_argument("--expected-sha256", required=True, type=sha256_value)
    upload_command.add_argument("--receipt", required=True, type=Path)
    download_command = commands.add_parser("download")
    download_command.add_argument("--artifact-id", required=True, type=positive_decimal)
    download_command.add_argument("--output", required=True, type=Path)
    download_command.add_argument("--asset-name", required=True, type=asset_name)
    download_command.add_argument("--expected-size", required=True, type=bounded_size)
    download_command.add_argument("--expected-sha256", required=True, type=sha256_value)
    download_command.add_argument("--receipt", required=True, type=Path)
    return root


def main(arguments: list[str] | None = None) -> int:
    try:
        options = parser().parse_args(arguments)
        token = token_from_environment()
        if options.command == "upload":
            receipt = upload(
                token=token,
                release_id=options.release_id,
                path=options.artifact,
                name=options.asset_name,
                expected_size=options.expected_size,
                expected_sha256=options.expected_sha256,
            )
        else:
            receipt = download(
                token=token,
                artifact_id=options.artifact_id,
                output=options.output,
                name=options.asset_name,
                expected_size=options.expected_size,
                expected_sha256=options.expected_sha256,
            )
        write_receipt(options.receipt, receipt)
    except CarrierArtifactV2Error as error:
        print(f"carrier artifact v2 rejected: {error}", file=sys.stderr)
        return 78
    sys.stdout.buffer.write(canonical_bytes(receipt))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
