from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-ledger.py"
SPEC = importlib.util.spec_from_file_location("validate_ledger", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        text=True,
    )
    return result.stdout.strip()


def init_repository(
    tmp_path: Path,
    *,
    genesis_has_approval: bool = False,
) -> tuple[Path, str]:
    root = tmp_path / "ledger"
    root.mkdir()
    git(root, "init", "-b", "main")
    git(root, "config", "user.name", "Ledger Test")
    git(root, "config", "user.email", "ledger-test@example.invalid")
    (root / "README.md").write_text("ledger genesis\n", encoding="utf-8")
    git(root, "add", "README.md")
    if genesis_has_approval:
        (root / "approvals").mkdir()
        (root / "approvals" / "preexisting.json").write_text(
            "{}\n",
            encoding="utf-8",
        )
        git(root, "add", "approvals/preexisting.json")
    git(root, "commit", "-m", "ledger genesis")
    genesis = git(root, "rev-parse", "HEAD")
    git(root, "remote", "add", "origin", MODULE.EXPECTED_ORIGIN)
    git(root, "update-ref", "refs/remotes/origin/main", genesis)
    return root, genesis


def approval(
    parent: str,
    *,
    genesis: str | None = None,
    sequence: int = 1,
    previous_manifest_sha256: str = MODULE.ZERO_SHA256,
    suffix: str = "tests",
    nonce: str = "AAAAAAAAAAAAAAAAAAAAAA",
) -> dict:
    genesis_sha = parent if genesis is None else genesis
    return {
        "api": {
            "approved_ref": "refs/heads/main",
            "commit_sha": "1" * 40,
            "repository": "PluckXD/tratto-api",
            "required_ancestors": ["2" * 40],
        },
        "controller": {
            "commit_sha": "3" * 40,
            "immutable_release_id": 12001,
            "repository": "PluckXD/tratto-control-release",
            "repository_id": 22001,
            "signer_verifier_sha256": "4" * 64,
            "tag_object_sha": "5" * 40,
            "tag_ref": "refs/tags/control-controller-v6.0.0",
            "workflow_path": ".github/workflows/control-release.yml",
            "workflow_sha256": "6" * 64,
        },
        "expires_at": "2026-08-01T13:00:00Z",
        "issued_at": "2026-08-01T12:00:00Z",
        "ledger": {
            "genesis_sha": genesis_sha,
            "parent_commit_sha": parent,
            "previous_manifest_sha256": previous_manifest_sha256,
            "ref": "refs/heads/main",
            "repository": "PluckXD/tratto-control-release-ledger",
            "repository_id": 32001,
            "sequence": sequence,
        },
        "migration": {
            "base_revision": "j1transpcod",
            "database_scope": "control-and-tenant-fleet",
            "fleet_preflight_sha256": "7" * 64,
            "head_revision": "f29controlexec",
            "mode": "expand-only",
            "tenant_catalog_count": 1,
            "tenant_catalog_sha256": "8" * 64,
            "tenant_fleet_base_revision": "j1transpcod",
        },
        "nonce": nonce,
        "ops": {
            "approved_ref": "refs/heads/main",
            "commit_sha": "1" * 40,
            "repository": "PluckXD/tratto-api",
            "required_ancestors": ["9" * 40],
        },
        "policy": {
            "digest_sha256": "e" * 64,
            "name": "control-production-v2",
            "path": "policies/control-production-v2.json",
            "repository": "PluckXD/tratto-control-release",
        },
        "release_id": f"ctl-20260801T120000Z-{suffix}",
        "schema_version": 2,
        "web": {
            "approved_ref": "refs/heads/main",
            "commit_sha": "f" * 40,
            "repository": "PluckXD/tratto-web",
            "required_ancestors": ["0" * 40],
        },
    }


def commit_approval(
    root: Path,
    value: dict,
    *,
    raw: bytes | None = None,
    path: str | None = None,
    update_remote: bool = True,
) -> tuple[str, str, bytes]:
    relative = path or f"approvals/{value['release_id']}.json"
    (root / relative).parent.mkdir(parents=True, exist_ok=True)
    payload = MODULE.canonical_bytes(value) if raw is None else raw
    (root / relative).write_bytes(payload)
    git(root, "add", relative)
    git(root, "commit", "-m", f"append {relative}")
    head = git(root, "rev-parse", "HEAD")
    if update_remote:
        git(root, "update-ref", "refs/remotes/origin/main", head)
    return relative, head, payload


def prepared(tmp_path: Path, *, records: int = 2):
    root, genesis = init_repository(tmp_path)
    first = approval(genesis)
    first_path, first_head, first_raw = commit_approval(root, first)
    if records == 1:
        return root, genesis, first_path, first_head, first_raw
    second = approval(
        first_head,
        genesis=genesis,
        sequence=2,
        previous_manifest_sha256=hashlib.sha256(first_raw).hexdigest(),
        suffix="second",
        nonce="AQEBAQEBAQEBAQEBAQEBAQ",
    )
    second_path, second_head, second_raw = commit_approval(root, second)
    return root, genesis, second_path, second_head, second_raw


def validate(root: Path, genesis: str, relative: str) -> dict:
    return MODULE.validate(
        root,
        relative,
        genesis_sha=genesis,
        remote_main_sha=git(root, "rev-parse", "HEAD"),
    )


def test_accepts_two_record_linear_append_only_ledger(tmp_path: Path) -> None:
    root, genesis, relative, head, raw = prepared(tmp_path)
    result = validate(root, genesis, relative)
    assert result == {
        "approval": MODULE.parse_approval(raw, "expected"),
        "genesis_sha": genesis,
        "head_sha": head,
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "record_count": 2,
    }


def test_manifest_has_no_circular_commit_field_and_result_binds_git_head(
    tmp_path: Path,
) -> None:
    root, genesis, relative, head, raw = prepared(tmp_path, records=1)
    result = validate(root, genesis, relative)
    assert "commit_sha" not in result["approval"]["ledger"]
    assert result["approval"]["ledger"]["parent_commit_sha"] == genesis
    assert result["head_sha"] == head
    assert result["manifest_sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["head_sha"] not in result["approval"]["ledger"].values()


def test_api_validation_is_offline(monkeypatch, tmp_path: Path) -> None:
    root, genesis, relative, _, _ = prepared(tmp_path, records=1)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("network access is forbidden")

    monkeypatch.setattr(MODULE.urllib.request, "build_opener", forbidden)
    assert validate(root, genesis, relative)["record_count"] == 1


def test_cli_uses_pinned_genesis_and_still_requires_trusted_github_context(
    tmp_path: Path,
) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            str(SCRIPT),
            "approvals/ctl-20260801T120000Z-tests.json",
            "--repository-root",
            str(tmp_path),
        ],
        env={
            **os.environ,
            "GITHUB_TOKEN": "must-not-be-used",
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    assert result.returncode == 78
    assert "trusted ledger GitHub context is invalid:" in result.stderr
    assert "Traceback" not in result.stderr


def test_rejects_noncanonical_and_duplicate_json_keys() -> None:
    value = approval("1" * 40)
    pretty = (json.dumps(value, indent=2) + "\n").encode()
    with pytest.raises(MODULE.LedgerError, match="canonical JSON"):
        MODULE.parse_approval(pretty, "candidate")
    duplicate = MODULE.canonical_bytes(value).replace(
        b'"schema_version":2',
        b'"schema_version":2,"schema_version":2',
    )
    with pytest.raises(MODULE.LedgerError, match="duplicate JSON key"):
        MODULE.parse_approval(duplicate, "candidate")


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda value: value.update(schema_version=True),
            "schema_version must be integer 2",
        ),
        (
            lambda value: value["ledger"].update(sequence=True),
            "ledger.sequence must be a positive integer",
        ),
        (
            lambda value: value.update(nonce="not-base64"),
            "nonce has invalid format",
        ),
        (
            lambda value: value.update(extra="forbidden"),
            "authorization keys diverge",
        ),
        (
            lambda value: value["ledger"].update(extra="forbidden"),
            "ledger keys diverge",
        ),
    ],
)
def test_rejects_invalid_complete_approval_v2_shape(
    mutator,
    message: str,
) -> None:
    value = approval("1" * 40)
    mutator(value)
    with pytest.raises(MODULE.LedgerError, match=message):
        MODULE.parse_approval(MODULE.canonical_bytes(value), "candidate")


def test_rejects_wrong_origin(tmp_path: Path) -> None:
    root, genesis, relative, _, _ = prepared(tmp_path, records=1)
    git(root, "remote", "set-url", "origin", "git@example.invalid:other.git")
    with pytest.raises(MODULE.LedgerError, match="origin"):
        validate(root, genesis, relative)


def test_rejects_dirty_checkout_including_untracked_files(
    tmp_path: Path,
) -> None:
    root, genesis, relative, _, _ = prepared(tmp_path, records=1)
    (root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(MODULE.LedgerError, match="clean"):
        validate(root, genesis, relative)


def test_rejects_detached_head(tmp_path: Path) -> None:
    root, genesis, relative, head, _ = prepared(tmp_path, records=1)
    git(root, "checkout", "--detach", head)
    with pytest.raises(MODULE.LedgerError, match="attached"):
        validate(root, genesis, relative)


def test_rejects_local_or_tracked_main_not_verified_remote(
    tmp_path: Path,
) -> None:
    root, genesis, relative, head, _ = prepared(tmp_path, records=1)
    with pytest.raises(MODULE.LedgerError, match="verified remote main"):
        MODULE.validate(
            root,
            relative,
            genesis_sha=genesis,
            remote_main_sha="f" * 40,
        )
    git(root, "update-ref", "refs/remotes/origin/main", genesis)
    with pytest.raises(MODULE.LedgerError, match="verified remote main"):
        MODULE.validate(
            root,
            relative,
            genesis_sha=genesis,
            remote_main_sha=head,
        )


def test_rejects_shallow_checkout(tmp_path: Path) -> None:
    root, genesis, relative, head, _ = prepared(tmp_path, records=1)
    (root / ".git" / "shallow").write_text(f"{genesis}\n", encoding="ascii")
    with pytest.raises(MODULE.LedgerError, match="full ancestry"):
        MODULE.validate(
            root,
            relative,
            genesis_sha=genesis,
            remote_main_sha=head,
        )


def test_rejects_unpinned_or_nonancestor_genesis(tmp_path: Path) -> None:
    root, genesis, relative, _, _ = prepared(tmp_path, records=1)
    with pytest.raises(MODULE.LedgerError, match="genesis SHA is not pinned"):
        MODULE.validate(
            root,
            relative,
            genesis_sha="",
            remote_main_sha=git(root, "rev-parse", "HEAD"),
        )
    orphan = tmp_path / "orphan"
    orphan.mkdir()
    git(orphan, "init", "-b", "main")
    git(orphan, "config", "user.name", "Ledger Test")
    git(orphan, "config", "user.email", "ledger-test@example.invalid")
    (orphan / "other").write_text("other\n", encoding="utf-8")
    git(orphan, "add", "other")
    git(orphan, "commit", "-m", "unrelated")
    unrelated = git(orphan, "rev-parse", "HEAD")
    git(
        root,
        "fetch",
        str(orphan),
        f"{unrelated}:refs/untrusted/unrelated",
    )
    with pytest.raises(MODULE.LedgerError, match="not an ancestor"):
        MODULE.validate(
            root,
            relative,
            genesis_sha=unrelated,
            remote_main_sha=git(root, "rev-parse", "HEAD"),
        )
    assert genesis != unrelated


def test_rejects_approval_entries_present_at_genesis(tmp_path: Path) -> None:
    root, genesis = init_repository(tmp_path, genesis_has_approval=True)
    value = approval(genesis)
    relative, head, _ = commit_approval(root, value)
    with pytest.raises(MODULE.LedgerError, match="genesis must not contain"):
        MODULE.validate(
            root,
            relative,
            genesis_sha=genesis,
            remote_main_sha=head,
        )


def test_rejects_history_commit_that_modifies_prior_approval(
    tmp_path: Path,
) -> None:
    root, genesis, first_path, first_head, first_raw = prepared(
        tmp_path,
        records=1,
    )
    second = approval(
        first_head,
        genesis=genesis,
        sequence=2,
        previous_manifest_sha256=hashlib.sha256(first_raw).hexdigest(),
        suffix="second",
        nonce="AQEBAQEBAQEBAQEBAQEBAQ",
    )
    (root / first_path).write_bytes(first_raw + b"\n")
    second_path = f"approvals/{second['release_id']}.json"
    (root / second_path).write_bytes(MODULE.canonical_bytes(second))
    git(root, "add", first_path, second_path)
    git(root, "commit", "-m", "modify old approval and append another")
    head = git(root, "rev-parse", "HEAD")
    git(root, "update-ref", "refs/remotes/origin/main", head)
    with pytest.raises(MODULE.LedgerError, match="exactly one approval"):
        MODULE.validate(
            root,
            second_path,
            genesis_sha=genesis,
            remote_main_sha=head,
        )


def test_rejects_commit_that_adds_multiple_files(tmp_path: Path) -> None:
    root, genesis = init_repository(tmp_path)
    value = approval(genesis)
    relative = f"approvals/{value['release_id']}.json"
    (root / "approvals").mkdir()
    (root / relative).write_bytes(MODULE.canonical_bytes(value))
    (root / "extra.txt").write_text("not an approval\n", encoding="utf-8")
    git(root, "add", relative, "extra.txt")
    git(root, "commit", "-m", "ambiguous append")
    head = git(root, "rev-parse", "HEAD")
    git(root, "update-ref", "refs/remotes/origin/main", head)
    with pytest.raises(MODULE.LedgerError, match="exactly one approval"):
        MODULE.validate(
            root,
            relative,
            genesis_sha=genesis,
            remote_main_sha=head,
        )


def test_rejects_executable_approval_blob(tmp_path: Path) -> None:
    root, genesis = init_repository(tmp_path)
    value = approval(genesis)
    relative = f"approvals/{value['release_id']}.json"
    (root / "approvals").mkdir()
    (root / relative).write_bytes(MODULE.canonical_bytes(value))
    git(root, "add", relative)
    git(root, "update-index", "--chmod=+x", relative)
    (root / relative).chmod(0o755)
    git(root, "commit", "-m", "append executable approval")
    head = git(root, "rev-parse", "HEAD")
    git(root, "update-ref", "refs/remotes/origin/main", head)
    with pytest.raises(MODULE.LedgerError, match="regular 100644 Git blob"):
        MODULE.validate(
            root,
            relative,
            genesis_sha=genesis,
            remote_main_sha=head,
        )


def test_parses_verified_github_main_contract_without_network() -> None:
    sha = "a" * 40
    raw = json.dumps(
        {
            "object": {"sha": sha, "type": "commit"},
            "ref": MODULE.EXPECTED_REF,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    assert MODULE.parse_github_ref(raw) == sha
    with pytest.raises(MODULE.LedgerError, match="contract"):
        MODULE.parse_github_ref(b"[]")


def test_rejects_manifest_with_different_self_consistent_genesis(
    tmp_path: Path,
) -> None:
    root, genesis = init_repository(tmp_path)
    value = approval("f" * 40, genesis="f" * 40)
    relative, head, _ = commit_approval(root, value)
    with pytest.raises(MODULE.LedgerError, match="ledger link diverges"):
        MODULE.validate(
            root,
            relative,
            genesis_sha=genesis,
            remote_main_sha=head,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("sequence", 3),
        ("previous_manifest_sha256", "f" * 64),
    ],
)
def test_rejects_broken_later_ledger_link(
    tmp_path: Path,
    field: str,
    replacement,
) -> None:
    root, genesis, _, first_head, first_raw = prepared(tmp_path, records=1)
    second = approval(
        first_head,
        genesis=genesis,
        sequence=2,
        previous_manifest_sha256=hashlib.sha256(first_raw).hexdigest(),
        suffix="second",
        nonce="AQEBAQEBAQEBAQEBAQEBAQ",
    )
    second["ledger"][field] = replacement
    relative, head, _ = commit_approval(root, second)
    with pytest.raises(MODULE.LedgerError, match="ledger link diverges"):
        MODULE.validate(
            root,
            relative,
            genesis_sha=genesis,
            remote_main_sha=head,
        )


def test_rejects_reused_nonce(tmp_path: Path) -> None:
    root, genesis, _, first_head, first_raw = prepared(tmp_path, records=1)
    second = approval(
        first_head,
        genesis=genesis,
        sequence=2,
        previous_manifest_sha256=hashlib.sha256(first_raw).hexdigest(),
        suffix="second",
    )
    relative, head, _ = commit_approval(root, second)
    with pytest.raises(MODULE.LedgerError, match="nonce is not unique"):
        MODULE.validate(
            root,
            relative,
            genesis_sha=genesis,
            remote_main_sha=head,
        )


def test_rejects_reused_release_id_before_filename_alias(
    tmp_path: Path,
) -> None:
    root, genesis, _, first_head, first_raw = prepared(tmp_path, records=1)
    duplicate = approval(
        first_head,
        genesis=genesis,
        sequence=2,
        previous_manifest_sha256=hashlib.sha256(first_raw).hexdigest(),
        nonce="AQEBAQEBAQEBAQEBAQEBAQ",
    )
    alias = "approvals/ctl-20260801T120000Z-alias.json"
    _, head, _ = commit_approval(root, duplicate, path=alias)
    with pytest.raises(MODULE.LedgerError, match="release_id is not unique"):
        MODULE.validate(
            root,
            alias,
            genesis_sha=genesis,
            remote_main_sha=head,
        )


def test_rejects_merge_history(tmp_path: Path) -> None:
    root, genesis = init_repository(tmp_path)
    main_value = approval(genesis, suffix="main")
    main_path, _, _ = commit_approval(
        root,
        main_value,
        update_remote=False,
    )
    git(root, "checkout", "-b", "side", genesis)
    side_value = approval(
        genesis,
        suffix="side",
        nonce="AQEBAQEBAQEBAQEBAQEBAQ",
    )
    commit_approval(root, side_value, update_remote=False)
    git(root, "checkout", "main")
    git(root, "merge", "--no-ff", "--no-edit", "side")
    head = git(root, "rev-parse", "HEAD")
    git(root, "update-ref", "refs/remotes/origin/main", head)
    with pytest.raises(
        MODULE.LedgerError,
        match="single linear chain|exactly one parent",
    ):
        MODULE.validate(
            root,
            main_path,
            genesis_sha=genesis,
            remote_main_sha=head,
        )


def test_rejects_non_head_requested_approval(tmp_path: Path) -> None:
    root, genesis, _, _, _ = prepared(tmp_path)
    first = "approvals/ctl-20260801T120000Z-tests.json"
    with pytest.raises(MODULE.LedgerError, match="record added by ledger HEAD"):
        validate(root, genesis, first)


def test_source_disables_bytecode_before_local_execution() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    future = source.index("from __future__ import annotations")
    disable = source.index("sys.dont_write_bytecode = True")
    argparse_import = source.index("import argparse")
    assert future < disable < argparse_import
    assert (
        'PINNED_GENESIS_SHA = "20ad87d361f31fd08ed2721a2d2acbb855addd6b"'
        in source
    )
    assert 'HERE / "validate-approval-v2.py"' in source
