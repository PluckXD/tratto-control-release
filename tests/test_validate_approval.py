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

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-approval.py"
SPEC = importlib.util.spec_from_file_location("validate_approval", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SOURCE_SCRIPT = ROOT / "scripts" / "verify-source-revision.py"
SOURCE_SPEC = importlib.util.spec_from_file_location(
    "verify_source_revision",
    SOURCE_SCRIPT,
)
assert SOURCE_SPEC is not None and SOURCE_SPEC.loader is not None
SOURCE_MODULE = importlib.util.module_from_spec(SOURCE_SPEC)
SOURCE_SPEC.loader.exec_module(SOURCE_MODULE)
NOW = dt.datetime(2026, 7, 30, 12, 0, tzinfo=dt.timezone.utc)
WORKFLOW = b"name: control-release\n"
POLICY = (ROOT / "policies" / "control-production-v1.json").read_bytes()


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        text=True,
    )
    return result.stdout.strip()


def init_repository(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "controller"
    root.mkdir()
    git(root, "init", "-b", "main")
    git(root, "config", "user.name", "Release Test")
    git(root, "config", "user.email", "release-test@example.invalid")
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "control-release.yml").write_bytes(
        WORKFLOW
    )
    (root / "policies").mkdir()
    (root / "policies" / "control-production-v1.json").write_bytes(POLICY)
    git(root, "add", ".")
    git(root, "commit", "-m", "bootstrap controller")
    head = git(root, "rev-parse", "HEAD")
    git(
        root,
        "remote",
        "add",
        "origin",
        "https://github.com/PluckXD/tratto-control-release.git",
    )
    git(root, "update-ref", "refs/remotes/origin/main", head)
    return root, head


def approval(base_sha: str, *, suffix: str = "tests") -> dict:
    return {
        "api": {
            "approved_ref": "refs/heads/main",
            "commit_sha": "1" * 40,
            "repository": "PluckXD/tratto-api",
            "required_ancestors": ["2" * 40],
        },
        "controller": {
            "approved_ref": "refs/heads/main",
            "base_sha": base_sha,
            "repository": "PluckXD/tratto-control-release",
            "workflow_path": ".github/workflows/control-release.yml",
            "workflow_sha256": hashlib.sha256(WORKFLOW).hexdigest(),
        },
        "expires_at": "2026-07-30T13:00:00Z",
        "issued_at": "2026-07-30T12:00:00Z",
        "migration": {
            "base_revision": "f25p2tauth",
            "database_scope": "control",
            "head_revision": "f28controlrpc",
            "mode": "expand-only",
        },
        "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
        "ops": {
            "approved_ref": "refs/heads/main",
            "commit_sha": "1" * 40,
            "repository": "PluckXD/tratto-api",
            "required_ancestors": ["5" * 40],
        },
        "policy": {
            "digest_sha256": hashlib.sha256(POLICY).hexdigest(),
            "name": "control-production-v1",
            "path": "policies/control-production-v1.json",
            "repository": "PluckXD/tratto-control-release",
        },
        "release_id": f"ctl-20260730T120000Z-{suffix}",
        "schema_version": 1,
        "web": {
            "approved_ref": "refs/heads/main",
            "commit_sha": "7" * 40,
            "repository": "PluckXD/tratto-web",
            "required_ancestors": ["8" * 40],
        },
    }


def commit_approval(root: Path, value: dict) -> str:
    approvals = root / "approvals"
    approvals.mkdir(exist_ok=True)
    relative = f"approvals/{value['release_id']}.json"
    (root / relative).write_bytes(MODULE.canonical_bytes(value))
    git(root, "add", relative)
    git(root, "commit", "-m", f"approve {value['release_id']}")
    git(
        root,
        "update-ref",
        "refs/remotes/origin/main",
        git(root, "rev-parse", "HEAD"),
    )
    return relative


def prepared(tmp_path: Path) -> tuple[Path, str, dict]:
    root, base = init_repository(tmp_path)
    value = approval(base)
    relative = commit_approval(root, value)
    return root, relative, value


def source_repository(
    tmp_path: Path,
    repository: str,
) -> tuple[Path, str, str]:
    root = tmp_path / "source"
    root.mkdir()
    git(root, "init", "-b", "main")
    git(root, "config", "user.name", "Source Test")
    git(root, "config", "user.email", "source-test@example.invalid")
    (root / "source.txt").write_text("ancestor\n", encoding="utf-8")
    git(root, "add", "source.txt")
    git(root, "commit", "-m", "ancestor")
    ancestor = git(root, "rev-parse", "HEAD")
    (root / "source.txt").write_text("head\n", encoding="utf-8")
    git(root, "commit", "-am", "head")
    head = git(root, "rev-parse", "HEAD")
    git(root, "remote", "add", "origin", f"git@github.com:{repository}.git")
    git(root, "update-ref", "refs/remotes/origin/main", head)
    return root, ancestor, head


def validate(root: Path, relative: str) -> dict:
    return MODULE.validate(
        root,
        relative,
        now=NOW,
        remote_main_sha=git(root, "rev-parse", "HEAD"),
    )


def test_accepts_single_append_only_authorization(tmp_path: Path) -> None:
    root, relative, _ = prepared(tmp_path)
    assert validate(root, relative)["schema_version"] == 1


def test_rejects_candidate_symlink(tmp_path: Path) -> None:
    root, base = init_repository(tmp_path)
    value = approval(base)
    outside = root / "outside.json"
    outside.write_bytes(MODULE.canonical_bytes(value))
    approvals = root / "approvals"
    approvals.mkdir()
    relative = f"approvals/{value['release_id']}.json"
    (root / relative).symlink_to(outside)
    git(root, "add", relative)
    git(root, "commit", "-m", "malicious symlink")
    with pytest.raises(MODULE.ApprovalError, match="open approval safely"):
        validate(root, relative)


def test_rejects_historical_symlink(tmp_path: Path) -> None:
    root, bootstrap = init_repository(tmp_path)
    old = approval(bootstrap, suffix="old")
    external = root / "outside.json"
    external.write_bytes(MODULE.canonical_bytes(old))
    (root / "approvals").mkdir()
    old_relative = f"approvals/{old['release_id']}.json"
    (root / old_relative).symlink_to(external)
    git(root, "add", old_relative)
    git(root, "commit", "-m", "historical symlink")
    base = git(root, "rev-parse", "HEAD")
    current = approval(base, suffix="new")
    current["issued_at"] = "2026-07-30T12:01:00Z"
    current["expires_at"] = "2026-07-30T13:01:00Z"
    current["release_id"] = "ctl-20260730T120100Z-new"
    current["nonce"] = "AQEBAQEBAQEBAQEBAQEBAQ"
    relative = commit_approval(root, current)
    with pytest.raises(MODULE.ApprovalError, match="forbidden entry"):
        validate(root, relative)


def test_rejects_reused_release_id(tmp_path: Path) -> None:
    root, bootstrap = init_repository(tmp_path)
    first = approval(bootstrap)
    commit_approval(root, first)
    base = git(root, "rev-parse", "HEAD")
    second = approval(base)
    second["nonce"] = "AQEBAQEBAQEBAQEBAQEBAQ"
    relative = commit_approval(root, second)
    with pytest.raises(MODULE.ApprovalError, match="release_id already used"):
        validate(root, relative)


def test_rejects_reused_nonce(tmp_path: Path) -> None:
    root, bootstrap = init_repository(tmp_path)
    first = approval(bootstrap)
    commit_approval(root, first)
    base = git(root, "rev-parse", "HEAD")
    second = approval(base, suffix="second")
    relative = commit_approval(root, second)
    with pytest.raises(MODULE.ApprovalError, match="nonce already used"):
        validate(root, relative)


def test_rejects_deleted_history(tmp_path: Path) -> None:
    root, bootstrap = init_repository(tmp_path)
    first = approval(bootstrap)
    first_path = commit_approval(root, first)
    base = git(root, "rev-parse", "HEAD")
    os.unlink(root / first_path)
    second = approval(base, suffix="second")
    second["nonce"] = "AQEBAQEBAQEBAQEBAQEBAQ"
    second["issued_at"] = "2026-07-30T12:01:00Z"
    second["expires_at"] = "2026-07-30T13:01:00Z"
    second["release_id"] = "ctl-20260730T120100Z-second"
    (root / "approvals" / f"{second['release_id']}.json").write_bytes(
        MODULE.canonical_bytes(second)
    )
    git(root, "add", "-A")
    git(root, "commit", "-m", "delete history and add candidate")
    git(
        root,
        "update-ref",
        "refs/remotes/origin/main",
        git(root, "rev-parse", "HEAD"),
    )
    relative = f"approvals/{second['release_id']}.json"
    with pytest.raises(MODULE.ApprovalError, match="may only add"):
        validate(root, relative)


def test_rejects_merge_commit(tmp_path: Path) -> None:
    root, relative, _ = prepared(tmp_path)
    git(root, "checkout", "-b", "side", "HEAD~1")
    (root / "side.txt").write_text("side\n", encoding="utf-8")
    git(root, "add", "side.txt")
    git(root, "commit", "-m", "side")
    git(root, "checkout", "main")
    git(root, "merge", "--no-ff", "side", "-m", "merge")
    git(
        root,
        "update-ref",
        "refs/remotes/origin/main",
        git(root, "rev-parse", "HEAD"),
    )
    with pytest.raises(MODULE.ApprovalError, match="only parent"):
        validate(root, relative)


def test_rejects_authorization_outside_main(tmp_path: Path) -> None:
    root, base = init_repository(tmp_path)
    git(root, "checkout", "-b", "untrusted")
    value = approval(base)
    relative = commit_approval(root, value)
    with pytest.raises(MODULE.ApprovalError, match="local main head"):
        validate(root, relative)


def test_rejects_dirty_controller_checkout(tmp_path: Path) -> None:
    root, relative, _ = prepared(tmp_path)
    (root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(MODULE.ApprovalError, match="checkout must be clean"):
        validate(root, relative)


def test_rejects_executable_authorization_blob(tmp_path: Path) -> None:
    root, base = init_repository(tmp_path)
    value = approval(base)
    relative = commit_approval(root, value)
    os.chmod(root / relative, 0o755)
    git(root, "add", relative)
    git(root, "commit", "--amend", "--no-edit")
    git(
        root,
        "update-ref",
        "refs/remotes/origin/main",
        git(root, "rev-parse", "HEAD"),
    )
    with pytest.raises(MODULE.ApprovalError, match="0644 regular"):
        validate(root, relative)


def test_rejects_symlinked_repository_root(tmp_path: Path) -> None:
    root, relative, _ = prepared(tmp_path)
    linked = tmp_path / "controller-link"
    linked.symlink_to(root, target_is_directory=True)
    with pytest.raises(MODULE.ApprovalError, match="without symlinks"):
        validate(linked, relative)


def test_rejects_hardlinked_authorization(tmp_path: Path) -> None:
    root, relative, _ = prepared(tmp_path)
    os.link(root / relative, root / "second-link.json")
    with pytest.raises(MODULE.ApprovalError, match="single-link"):
        validate(root, relative)


def test_rejects_world_writable_approvals_directory(tmp_path: Path) -> None:
    root, relative, _ = prepared(tmp_path)
    os.chmod(root / "approvals", 0o777)
    with pytest.raises(MODULE.ApprovalError, match="directory ownership or mode"):
        validate(root, relative)


def test_rejects_controller_origin_drift(tmp_path: Path) -> None:
    root, relative, _ = prepared(tmp_path)
    git(root, "remote", "set-url", "origin", "https://github.com/attacker/repo.git")
    with pytest.raises(MODULE.ApprovalError, match="controller origin"):
        validate(root, relative)


def test_rejects_unverified_remote_main(tmp_path: Path) -> None:
    root, relative, value = prepared(tmp_path)
    with pytest.raises(MODULE.ApprovalError, match="verified remote main"):
        MODULE.validate(
            root,
            relative,
            now=NOW,
            remote_main_sha=value["controller"]["base_sha"],
        )


def test_rejects_policy_numeric_boolean_alias(tmp_path: Path) -> None:
    root, _ = init_repository(tmp_path)
    policy_path = root / "policies" / "control-production-v1.json"
    policy_value = json.loads(policy_path.read_text(encoding="utf-8"))
    policy_value["signer_allows_source_checkout"] = 0
    policy_path.write_bytes(MODULE.canonical_bytes(policy_value))
    git(root, "add", str(policy_path.relative_to(root)))
    git(root, "commit", "-m", "malicious policy type")
    base = git(root, "rev-parse", "HEAD")
    value = approval(base)
    value["policy"]["digest_sha256"] = hashlib.sha256(
        policy_path.read_bytes()
    ).hexdigest()
    relative = commit_approval(root, value)
    with pytest.raises(MODULE.ApprovalError, match="field types"):
        validate(root, relative)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"unknown": True}), "keys diverge"),
        (
            lambda value: value.update({"schema_version": 1.0}),
            "integer 1",
        ),
        (
            lambda value: value["api"].update({"approved_ref": "refs/heads/dev"}),
            "refs/heads/main",
        ),
        (
            lambda value: value["web"].update(
                {"repository": "attacker/product"}
            ),
            "repository is not allowed",
        ),
        (
            lambda value: value["ops"].update({"commit_sha": "9" * 40}),
            "same commit",
        ),
        (
            lambda value: value["controller"].update({"base_sha": "main"}),
            "invalid format",
        ),
        (
            lambda value: value["migration"].update(
                {"head_revision": "f25p2tauth"}
            ),
            "base and head",
        ),
        (
            lambda value: value["policy"].update({"digest_sha256": "6" * 64}),
            "policy digest",
        ),
        (
            lambda value: value.update({"nonce": "too-short"}),
            "invalid format",
        ),
        (
            lambda value: value.update(
                {"expires_at": "2026-07-31T12:00:01Z"}
            ),
            "between 1 second and 24 hours",
        ),
        (
            lambda value: value.update(
                {"issued_at": "2026-07-30T12:00:01Z"}
            ),
            "timestamp must equal",
        ),
    ],
)
def test_rejects_contract_drift(
    tmp_path: Path,
    mutation,
    message: str,
) -> None:
    root, base = init_repository(tmp_path)
    value = approval(base)
    mutation(value)
    relative = commit_approval(root, value)
    with pytest.raises(MODULE.ApprovalError, match=message):
        validate(root, relative)


def test_rejects_duplicate_json_key(tmp_path: Path) -> None:
    root, base = init_repository(tmp_path)
    value = approval(base)
    approvals = root / "approvals"
    approvals.mkdir()
    relative = f"approvals/{value['release_id']}.json"
    raw = MODULE.canonical_bytes(value).decode("utf-8")
    (root / relative).write_text(
        raw.replace(
            '"schema_version":1',
            '"schema_version":1,"schema_version":1',
        ),
        encoding="utf-8",
    )
    git(root, "add", relative)
    git(root, "commit", "-m", "duplicate key")
    with pytest.raises(MODULE.ApprovalError, match="duplicate key"):
        validate(root, relative)


def test_cli_has_no_clock_override() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "approvals/example.json",
            "--repository-root",
            ".",
            "--now",
            "2099-01-01T00:00:00Z",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    assert result.returncode == 2
    assert "unrecognized arguments: --now" in result.stderr


def test_source_revision_requires_exact_private_main(tmp_path: Path) -> None:
    source, ancestor, head = source_repository(
        tmp_path,
        "PluckXD/tratto-api",
    )
    controller, base = init_repository(tmp_path)
    value = approval(base)
    for component in ("api", "ops"):
        value[component]["commit_sha"] = head
        value[component]["required_ancestors"] = [ancestor]
    relative = commit_approval(controller, value)
    loaded = validate(controller, relative)
    SOURCE_MODULE.verify(source, "api", loaded, remote_main_sha=head)
    SOURCE_MODULE.verify(source, "ops", loaded, remote_main_sha=head)


def test_source_revision_rejects_non_main_commit(tmp_path: Path) -> None:
    source, ancestor, head = source_repository(
        tmp_path,
        "PluckXD/tratto-api",
    )
    value = approval("3" * 40)
    for component in ("api", "ops"):
        value[component]["commit_sha"] = ancestor
        value[component]["required_ancestors"] = ["9" * 40]
    with pytest.raises(
        SOURCE_MODULE.VALIDATOR.ApprovalError,
        match="source HEAD",
    ):
        SOURCE_MODULE.verify(
            source,
            "api",
            value,
            remote_main_sha=head,
        )
    assert head != ancestor
