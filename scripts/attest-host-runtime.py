#!/usr/bin/env python3
"""Attest only reviewed root-owned host interpreters; never artifact code."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import pwd
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import runtime_policy as RUNTIME


MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_OS_RELEASE_BYTES = 64 * 1024
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
PYTHON_VERSION_RE = re.compile(r"^3\.12\.[0-9]+$")


class HostRuntimeError(ValueError):
    """The host does not satisfy the reviewed runtime boundary."""


def reject(message: str) -> None:
    raise HostRuntimeError(message)


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


def validate_path_chain(
    path: Path,
    label: str,
    *,
    leaf_modes: set[int],
) -> os.stat_result:
    if not path.is_absolute() or ".." in path.parts:
        reject(f"{label} path is not absolute canonical infrastructure")
    current = Path("/")
    entries: list[tuple[Path, os.stat_result]] = []
    for index, component in enumerate(path.parts[1:], start=1):
        current /= component
        try:
            info = current.lstat()
        except OSError:
            reject(f"{label} path is unavailable")
        entries.append((current, info))
    return validate_chain_metadata(
        entries,
        label,
        leaf_modes=leaf_modes,
    )


def validate_chain_metadata(
    entries: list[tuple[Path, os.stat_result]],
    label: str,
    *,
    leaf_modes: set[int],
) -> os.stat_result:
    if not entries:
        reject(f"{label} path has no reviewed leaf")
    for index, (_, info) in enumerate(entries):
        leaf = index == len(entries) - 1
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode):
            reject(f"{label} path contains an unreviewed symlink")
        if info.st_uid != 0 or mode & 0o022:
            reject(f"{label} path is not root-owned protected infrastructure")
        if leaf:
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or mode not in leaf_modes
            ):
                reject(f"{label} leaf metadata diverges")
        elif not stat.S_ISDIR(info.st_mode) or mode & 0o001 == 0:
            reject(f"{label} ancestor is not world-traversable infrastructure")
    return entries[-1][1]


def open_verified(
    path: Path,
    label: str,
    *,
    leaf_modes: set[int],
    maximum: int,
) -> tuple[int, os.stat_result]:
    path_info = validate_path_chain(path, label, leaf_modes=leaf_modes)
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError:
        reject(f"{label} cannot be opened without following links")
    info = os.fstat(descriptor)
    if (
        (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)
        or not 0 < info.st_size <= maximum
    ):
        os.close(descriptor)
        reject(f"{label} changed before it was opened")
    return descriptor, info


def stable_snapshot(info: os.stat_result) -> tuple[int, ...]:
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


def require_unchanged(
    descriptor: int,
    expected: os.stat_result,
    label: str,
) -> None:
    if stable_snapshot(os.fstat(descriptor)) != stable_snapshot(expected):
        reject(f"{label} changed during attestation")


def digest_binary(
    descriptor: int,
    expected: os.stat_result,
    label: str,
) -> str:
    digest = hashlib.sha256()
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError:
        reject(f"{label} cannot be hashed")
    require_unchanged(descriptor, expected, label)
    return digest.hexdigest()


def run_as(
    *,
    setpriv_descriptor: int,
    binary_descriptor: int,
    arguments: list[str],
    user: str,
    label: str,
) -> str:
    try:
        identity = pwd.getpwnam(user)
    except KeyError:
        reject(f"{label} runtime identity is unavailable")
    if identity.pw_uid == 0 or identity.pw_gid == 0:
        reject(f"{label} runtime identity must be unprivileged")
    command = [
        f"/proc/self/fd/{setpriv_descriptor}",
        f"--reuid={identity.pw_uid}",
        f"--regid={identity.pw_gid}",
        "--clear-groups",
        "--no-new-privs",
        f"/proc/self/fd/{binary_descriptor}",
        *arguments,
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            cwd="/",
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "NO_COLOR": "1",
                "PATH": "/usr/bin:/bin",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            pass_fds=(setpriv_descriptor, binary_descriptor),
        )
    except (OSError, subprocess.SubprocessError):
        reject(f"{label} metadata command failed")
    output = completed.stdout.strip()
    if completed.returncode != 0 or not output or completed.stderr:
        reject(f"{label} metadata command was not clean")
    return output


def version_tuple(value: str, label: str) -> tuple[int, ...]:
    try:
        parts = tuple(int(part) for part in value.split("."))
    except ValueError:
        reject(f"{label} version is invalid")
    if len(parts) < 2 or any(part < 0 for part in parts):
        reject(f"{label} version is invalid")
    return parts


def validate_python_metadata(
    observed: Any,
    policy: dict[str, Any],
) -> None:
    if (
        not isinstance(observed, dict)
        or set(observed)
        != {
            "cache_tag",
            "implementation",
            "libc_family",
            "libc_version",
            "major_minor",
            "observed_version",
            "py_debug",
            "soabi",
        }
        or observed["cache_tag"] != policy["python"]["cache_tag"]
        or observed["implementation"] != policy["python"]["implementation"]
        or observed["major_minor"] != policy["python"]["major_minor"]
        or observed["py_debug"] is not policy["python"]["py_debug"]
        or observed["soabi"] != policy["python"]["soabi"]
        or observed["libc_family"] != policy["libc"]["family"]
        or not isinstance(observed["libc_version"], str)
        or version_tuple(
            observed["libc_version"],
            "trusted system libc",
        )
        < version_tuple(policy["libc"]["minimum_version"], "policy libc")
        or not isinstance(observed["observed_version"], str)
        or PYTHON_VERSION_RE.fullmatch(observed["observed_version"]) is None
    ):
        reject("trusted system Python is outside the reviewed Ubuntu/cp312 ABI")


def attest_python(
    policy: dict[str, Any],
    *,
    setpriv_descriptor: int,
) -> tuple[dict[str, Any], dict[str, str]]:
    configured = Path(policy["python"]["executable"])
    descriptor, info = open_verified(
        configured,
        "trusted system Python",
        leaf_modes={0o555, 0o755},
        maximum=MAX_BINARY_BYTES,
    )
    program = (
        "import json,platform,sys,sysconfig;"
        "libc=platform.libc_ver();"
        "print(json.dumps({"
        "'cache_tag':sys.implementation.cache_tag,"
        "'implementation':platform.python_implementation(),"
        "'libc_family':libc[0],"
        "'libc_version':libc[1],"
        "'major_minor':f'{sys.version_info.major}.{sys.version_info.minor}',"
        "'observed_version':platform.python_version(),"
        "'py_debug':bool(sysconfig.get_config_var('Py_DEBUG')),"
        "'soabi':sysconfig.get_config_var('SOABI')"
        "},separators=(',',':'),sort_keys=True))"
    )
    digest = digest_binary(descriptor, info, "trusted system Python")
    observed_by_user: dict[str, dict[str, Any]] = {}
    try:
        for user in policy["python"]["runtime_users"]:
            raw = run_as(
                setpriv_descriptor=setpriv_descriptor,
                binary_descriptor=descriptor,
                arguments=["-I", "-S", "-c", program],
                user=user,
                label=f"trusted system Python/{user}",
            )
            try:
                observed = json.loads(raw)
            except json.JSONDecodeError:
                reject("trusted system Python metadata is invalid")
            observed_by_user[user] = observed
        require_unchanged(descriptor, info, "trusted system Python")
    finally:
        os.close(descriptor)
    if not observed_by_user or len(
        {canonical_bytes(value) for value in observed_by_user.values()}
    ) != 1:
        reject("trusted system Python metadata diverges across runtime users")
    observed = next(iter(observed_by_user.values()))
    validate_python_metadata(observed, policy)
    python_report = {
        "binary_sha256": digest,
        "cache_tag": observed["cache_tag"],
        "executable": str(configured),
        "implementation": observed["implementation"],
        "major_minor": observed["major_minor"],
        "observed_version": observed["observed_version"],
        "py_debug": observed["py_debug"],
        "runtime_users_verified": policy["python"]["runtime_users"],
        "soabi": observed["soabi"],
    }
    libc_report = {
        "family": observed["libc_family"],
        "minimum_version": policy["libc"]["minimum_version"],
        "observed_version": observed["libc_version"],
    }
    return python_report, libc_report


def attest_node(
    policy: dict[str, Any],
    *,
    setpriv_descriptor: int,
) -> dict[str, Any]:
    configured = Path(policy["node"]["executable"])
    descriptor, info = open_verified(
        configured,
        "dedicated Node runtime",
        leaf_modes={0o555},
        maximum=MAX_BINARY_BYTES,
    )
    if info.st_size != policy["node"]["binary_size_bytes"]:
        os.close(descriptor)
        reject("dedicated Node binary size diverges from reviewed policy")
    observed_digest = digest_binary(
        descriptor,
        info,
        "dedicated Node runtime",
    )
    try:
        if observed_digest != policy["node"]["binary_sha256"]:
            reject("dedicated Node binary digest diverges from reviewed policy")
        version = run_as(
            setpriv_descriptor=setpriv_descriptor,
            binary_descriptor=descriptor,
            arguments=["--version"],
            user=policy["node"]["runtime_user"],
            label="dedicated Node runtime",
        )
        require_unchanged(descriptor, info, "dedicated Node runtime")
        if version != policy["node"]["version"]:
            reject("dedicated Node version diverges from reviewed policy")
    finally:
        os.close(descriptor)
    return {
        "binary_sha256": observed_digest,
        "executable": str(configured),
        "runtime_user_verified": policy["node"]["runtime_user"],
        "version": version,
    }


def attest_distribution(policy: dict[str, Any]) -> dict[str, str]:
    configured = Path(policy["distribution"]["os_release_path"])
    descriptor, info = open_verified(
        configured,
        "OS release identity",
        leaf_modes={0o444, 0o644},
        maximum=MAX_OS_RELEASE_BYTES,
    )
    try:
        raw = os.read(descriptor, MAX_OS_RELEASE_BYTES + 1)
        require_unchanged(descriptor, info, "OS release identity")
    finally:
        os.close(descriptor)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        reject("OS release identity is not UTF-8")
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"ID", "VERSION_ID"}:
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            values[key] = value
    if (
        values.get("ID") != policy["distribution"]["id"]
        or values.get("VERSION_ID") != policy["distribution"]["version_id"]
    ):
        reject("host distribution diverges from reviewed Ubuntu baseline")
    return {
        "id": values["ID"],
        "os_release_path": str(configured),
        "version_id": values["VERSION_ID"],
    }


def validate_report(
    value: Any,
    *,
    policy: dict[str, Any],
    policy_digest: str,
) -> None:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "distribution",
            "libc",
            "node",
            "python",
            "root_validation",
            "runtime_policy_sha256",
            "schema_version",
            "verdict",
        }
        or value["schema_version"] != 1
        or value["verdict"] != "pass"
        or value["runtime_policy_sha256"] != policy_digest
        or value["root_validation"] != policy["root_validation"]
        or value["distribution"] != policy["distribution"]
    ):
        reject("host runtime report top-level contract diverges")
    libc = value["libc"]
    if (
        not isinstance(libc, dict)
        or set(libc) != {"family", "minimum_version", "observed_version"}
        or libc["family"] != policy["libc"]["family"]
        or libc["minimum_version"] != policy["libc"]["minimum_version"]
        or not isinstance(libc["observed_version"], str)
        or version_tuple(libc["observed_version"], "report libc")
        < version_tuple(policy["libc"]["minimum_version"], "policy libc")
    ):
        reject("host runtime report libc contract diverges")
    node = value["node"]
    if (
        not isinstance(node, dict)
        or set(node)
        != {
            "binary_sha256",
            "executable",
            "runtime_user_verified",
            "version",
        }
        or node["binary_sha256"] != policy["node"]["binary_sha256"]
        or node["executable"] != policy["node"]["executable"]
        or node["runtime_user_verified"] != policy["node"]["runtime_user"]
        or node["version"] != policy["node"]["version"]
    ):
        reject("host runtime report Node contract diverges")
    python = value["python"]
    if (
        not isinstance(python, dict)
        or set(python)
        != {
            "binary_sha256",
            "cache_tag",
            "executable",
            "implementation",
            "major_minor",
            "observed_version",
            "py_debug",
            "runtime_users_verified",
            "soabi",
        }
        or not isinstance(python["binary_sha256"], str)
        or HASH_RE.fullmatch(python["binary_sha256"]) is None
        or python["cache_tag"] != policy["python"]["cache_tag"]
        or python["executable"] != policy["python"]["executable"]
        or python["implementation"] != policy["python"]["implementation"]
        or python["major_minor"] != policy["python"]["major_minor"]
        or not isinstance(python["observed_version"], str)
        or PYTHON_VERSION_RE.fullmatch(python["observed_version"]) is None
        or python["py_debug"] is not policy["python"]["py_debug"]
        or python["runtime_users_verified"] != policy["python"]["runtime_users"]
        or python["soabi"] != policy["python"]["soabi"]
    ):
        reject("host runtime report Python contract diverges")


def write_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError:
        reject("host runtime attestation output is unsafe or already exists")
    try:
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-policy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        policy, policy_digest = RUNTIME.load(
            args.runtime_policy,
            required_uid=0,
            required_gid=0,
            allowed_modes={0o444},
        )
        if args.runtime_policy != Path(
            policy["root_validation"]["installed_policy_path"]
        ):
            reject("host runtime policy is not loaded from its fixed path")
        if os.geteuid() != 0:
            reject("host runtime attestation must start as root")
        if (
            platform.system() != policy["operating_system"]
            or platform.machine() != policy["architecture"]
        ):
            reject("host OS/architecture diverges from runtime policy")
        setpriv_descriptor, setpriv_info = open_verified(
            Path(policy["root_validation"]["setpriv_executable"]),
            "setpriv privilege dropper",
            leaf_modes={0o555, 0o755},
            maximum=MAX_BINARY_BYTES,
        )
        try:
            distribution = attest_distribution(policy)
            python_report, libc_report = attest_python(
                policy,
                setpriv_descriptor=setpriv_descriptor,
            )
            node_report = attest_node(
                policy,
                setpriv_descriptor=setpriv_descriptor,
            )
            require_unchanged(
                setpriv_descriptor,
                setpriv_info,
                "setpriv privilege dropper",
            )
            report = {
                "distribution": distribution,
                "libc": libc_report,
                "node": node_report,
                "python": python_report,
                "root_validation": policy["root_validation"],
                "runtime_policy_sha256": policy_digest,
                "schema_version": 1,
                "verdict": "pass",
            }
            validate_report(
                report,
                policy=policy,
                policy_digest=policy_digest,
            )
        finally:
            os.close(setpriv_descriptor)
        write_exclusive(args.output, canonical_bytes(report))
    except (HostRuntimeError, RUNTIME.RuntimePolicyError) as error:
        print(f"host runtime rejected: {error}", file=sys.stderr)
        return 78
    print("trusted host runtime contract verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
