from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify-controller-tag.py"
SPEC = importlib.util.spec_from_file_location(
    "control_release_controller_tag",
    SCRIPT,
)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFIER
SPEC.loader.exec_module(VERIFIER)

TAG = "control-controller-v6.0.0"
TAG_OBJECT_SHA = "a" * 40
COMMIT_SHA = "b" * 40
RELEASE_ID = 987654
REPOSITORY_ID = 123456789


def policy() -> VERIFIER.ControllerTagPolicy:
    return VERIFIER.ControllerTagPolicy(
        tag=TAG,
        tag_object_sha=TAG_OBJECT_SHA,
        commit_sha=COMMIT_SHA,
        release_id=RELEASE_ID,
        repository_id=REPOSITORY_ID,
    )


def github_context() -> dict:
    ref = f"refs/tags/{TAG}"
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": ref,
        "GITHUB_REF_TYPE": "tag",
        "GITHUB_REPOSITORY": VERIFIER.REPOSITORY,
        "GITHUB_REPOSITORY_ID": str(REPOSITORY_ID),
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_SHA": COMMIT_SHA,
        "GITHUB_WORKFLOW_REF": (
            f"{VERIFIER.REPOSITORY}/{VERIFIER.WORKFLOW_PATH}@{ref}"
        ),
        "GITHUB_WORKFLOW_SHA": COMMIT_SHA,
        "RUNNER_ENVIRONMENT": "github-hosted",
    }


def local_tag() -> VERIFIER.LocalGitTag:
    return VERIFIER.LocalGitTag(
        ref=f"refs/tags/{TAG}",
        object_type="tag",
        object_sha=TAG_OBJECT_SHA,
        commit_sha=COMMIT_SHA,
    )


def local_tag_json() -> dict:
    value = local_tag()
    return {
        "commit_sha": value.commit_sha,
        "object_sha": value.object_sha,
        "object_type": value.object_type,
        "ref": value.ref,
    }


def signature() -> VERIFIER.SignatureVerification:
    return VERIFIER.SignatureVerification(
        tag_object_sha=TAG_OBJECT_SHA,
        status=VERIFIER.SignatureStatus.VERIFIED,
    )


def release() -> dict:
    return {
        "assets": [],
        "draft": False,
        "id": RELEASE_ID,
        "immutable": True,
        "name": TAG,
        "prerelease": False,
        "tag_name": TAG,
        "target_commitish": COMMIT_SHA,
        "url": (
            f"https://api.github.com/repos/{VERIFIER.REPOSITORY}/releases/"
            f"{RELEASE_ID}"
        ),
    }


def immutable_releases(*, enforced: bool = True) -> dict:
    return {"enabled": True, "enforced_by_owner": enforced}


def validate(**overrides):
    values = {
        "policy": policy(),
        "github_context": github_context(),
        "local_tag": local_tag(),
        "signature_verifier": lambda _tag: signature(),
        "release": release(),
        "immutable_releases": immutable_releases(),
    }
    values.update(overrides)
    return VERIFIER.validate_controller_tag(**values)


def write_canonical(path: Path, value: dict) -> None:
    path.write_bytes(VERIFIER.canonical_bytes(value))


def cli_arguments(tmp_path: Path) -> list[str]:
    documents = {
        "context.json": github_context(),
        "local-tag.json": local_tag_json(),
        "release.json": release(),
        "immutable.json": immutable_releases(),
    }
    for name, value in documents.items():
        write_canonical(tmp_path / name, value)
    return [
        sys.executable,
        "-B",
        str(SCRIPT),
        "--controller-tag",
        TAG,
        "--tag-object-sha",
        TAG_OBJECT_SHA,
        "--commit-sha",
        COMMIT_SHA,
        "--release-id",
        str(RELEASE_ID),
        "--repository-id",
        str(REPOSITORY_ID),
        "--github-context",
        str(tmp_path / "context.json"),
        "--local-git-tag",
        str(tmp_path / "local-tag.json"),
        "--release-response",
        str(tmp_path / "release.json"),
        "--immutable-releases-response",
        str(tmp_path / "immutable.json"),
    ]


def test_pure_api_accepts_exact_immutable_annotated_tag() -> None:
    seen: list[VERIFIER.LocalGitTag] = []

    def verify(value):
        seen.append(value)
        return signature()

    attestation = validate(signature_verifier=verify)

    assert seen == [local_tag()]
    assert attestation.as_dict() == {
        "commit_sha": COMMIT_SHA,
        "owner_enforced": True,
        "release_id": RELEASE_ID,
        "repository": VERIFIER.REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "tag": TAG,
        "tag_object_sha": TAG_OBJECT_SHA,
    }


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("GITHUB_ACTIONS", "false"),
        ("GITHUB_API_URL", "https://github.example/api"),
        ("GITHUB_EVENT_NAME", "push"),
        ("GITHUB_REPOSITORY", "PluckXD/tratto-api"),
        ("GITHUB_REPOSITORY_ID", str(REPOSITORY_ID + 1)),
        ("GITHUB_REPOSITORY_ID", REPOSITORY_ID),
        ("GITHUB_SERVER_URL", "https://github.example"),
        ("RUNNER_ENVIRONMENT", "self-hosted"),
        ("GITHUB_REF_TYPE", "branch"),
        ("GITHUB_REF", f"refs/heads/{TAG}"),
        ("GITHUB_REF", f"refs/tags/{TAG}/caller"),
        (
            "GITHUB_WORKFLOW_REF",
            (
                f"{VERIFIER.REPOSITORY}/.github/workflows/other.yml"
                f"@refs/tags/{TAG}"
            ),
        ),
        (
            "GITHUB_WORKFLOW_REF",
            (
                f"other/repo/{VERIFIER.WORKFLOW_PATH}"
                f"@refs/tags/{TAG}"
            ),
        ),
        ("GITHUB_SHA", "c" * 40),
        ("GITHUB_WORKFLOW_SHA", "c" * 40),
    ],
)
def test_github_context_is_exactly_bound(field: str, bad: object) -> None:
    value = github_context()
    value[field] = bad
    with pytest.raises(VERIFIER.ControllerTagError):
        validate(github_context=value)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.pop("GITHUB_REF"),
        lambda value: value.update({"CALLER_WORKFLOW": "other.yml"}),
    ],
)
def test_github_context_rejects_missing_or_extra_keys(mutate) -> None:
    value = github_context()
    mutate(value)
    with pytest.raises(VERIFIER.ControllerTagError):
        validate(github_context=value)


@pytest.mark.parametrize(
    "bad_tag",
    [
        "control-controller-v5.0.0",
        "control-controller-v6.0",
        "control-controller-v6.01.0",
        "control-controller-v6.0.01",
        "control-controller-v6.x",
        "control-controller-v6.0.0/other",
        "CONTROL-CONTROLLER-V6.0.0",
        "refs/tags/control-controller-v6.0.0",
    ],
)
def test_policy_rejects_noncanonical_v6_tags(bad_tag: str) -> None:
    bad = VERIFIER.ControllerTagPolicy(
        tag=bad_tag,
        tag_object_sha=TAG_OBJECT_SHA,
        commit_sha=COMMIT_SHA,
        release_id=RELEASE_ID,
        repository_id=REPOSITORY_ID,
    )
    with pytest.raises(VERIFIER.ControllerTagError):
        validate(policy=bad)


@pytest.mark.parametrize(
    "bad",
    [
        VERIFIER.ControllerTagPolicy(
            tag=TAG,
            tag_object_sha=TAG_OBJECT_SHA,
            commit_sha=COMMIT_SHA,
            release_id=RELEASE_ID,
            repository_id=REPOSITORY_ID,
            repository="PluckXD/other",
        ),
        VERIFIER.ControllerTagPolicy(
            tag=TAG,
            tag_object_sha="A" * 40,
            commit_sha=COMMIT_SHA,
            release_id=RELEASE_ID,
            repository_id=REPOSITORY_ID,
        ),
        VERIFIER.ControllerTagPolicy(
            tag=TAG,
            tag_object_sha=TAG_OBJECT_SHA,
            commit_sha="not-a-sha",
            release_id=RELEASE_ID,
            repository_id=REPOSITORY_ID,
        ),
        VERIFIER.ControllerTagPolicy(
            tag=TAG,
            tag_object_sha=TAG_OBJECT_SHA,
            commit_sha=COMMIT_SHA,
            release_id=0,
            repository_id=REPOSITORY_ID,
        ),
        VERIFIER.ControllerTagPolicy(
            tag=TAG,
            tag_object_sha=TAG_OBJECT_SHA,
            commit_sha=COMMIT_SHA,
            release_id=True,
            repository_id=REPOSITORY_ID,
        ),
        VERIFIER.ControllerTagPolicy(
            tag=TAG,
            tag_object_sha=TAG_OBJECT_SHA,
            commit_sha=COMMIT_SHA,
            release_id=RELEASE_ID,
            repository_id=0,
        ),
        VERIFIER.ControllerTagPolicy(
            tag=TAG,
            tag_object_sha=TAG_OBJECT_SHA,
            commit_sha=COMMIT_SHA,
            release_id=RELEASE_ID,
            repository_id=True,
        ),
    ],
)
def test_policy_values_are_fixed_and_typed(bad) -> None:
    with pytest.raises(VERIFIER.ControllerTagError):
        validate(policy=bad)


@pytest.mark.parametrize(
    "bad",
    [
        VERIFIER.LocalGitTag(
            ref=f"refs/tags/{TAG}",
            object_type="commit",
            object_sha=TAG_OBJECT_SHA,
            commit_sha=COMMIT_SHA,
        ),
        VERIFIER.LocalGitTag(
            ref=f"refs/tags/{TAG}/caller",
            object_type="tag",
            object_sha=TAG_OBJECT_SHA,
            commit_sha=COMMIT_SHA,
        ),
        VERIFIER.LocalGitTag(
            ref=f"refs/tags/{TAG}",
            object_type="tag",
            object_sha="c" * 40,
            commit_sha=COMMIT_SHA,
        ),
        VERIFIER.LocalGitTag(
            ref=f"refs/tags/{TAG}",
            object_type="tag",
            object_sha=TAG_OBJECT_SHA,
            commit_sha="c" * 40,
        ),
    ],
)
def test_local_git_tag_must_be_exact_and_annotated(bad) -> None:
    called = False

    def verifier(_value):
        nonlocal called
        called = True
        return signature()

    with pytest.raises(VERIFIER.ControllerTagError):
        validate(local_tag=bad, signature_verifier=verifier)
    assert called is False


def test_signature_verifier_must_return_exact_typed_verified_result() -> None:
    bad_results = [
        True,
        {"status": "verified", "tag_object_sha": TAG_OBJECT_SHA},
        VERIFIER.SignatureVerification(
            tag_object_sha="c" * 40,
            status=VERIFIER.SignatureStatus.VERIFIED,
        ),
        VERIFIER.SignatureVerification(
            tag_object_sha=TAG_OBJECT_SHA,
            status="verified",
        ),
    ]
    for result in bad_results:
        with pytest.raises(VERIFIER.ControllerTagError):
            validate(signature_verifier=lambda _tag, result=result: result)


def test_signature_verifier_exception_fails_closed() -> None:
    def fail(_tag):
        raise RuntimeError("tool failed")

    with pytest.raises(
        VERIFIER.ControllerTagError,
        match="failed closed",
    ):
        validate(signature_verifier=fail)


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("id", RELEASE_ID + 1),
        ("id", True),
        ("url", "https://api.github.com/repos/other/repo/releases/987654"),
        ("tag_name", "control-controller-v6.0.1"),
        ("target_commitish", "c" * 40),
        ("immutable", False),
        ("immutable", 1),
        ("draft", True),
        ("draft", 0),
        ("prerelease", True),
        ("prerelease", 0),
    ],
)
def test_release_payload_is_exactly_bound(field: str, bad: object) -> None:
    value = release()
    value[field] = bad
    with pytest.raises(VERIFIER.ControllerTagError):
        validate(release=value)


def test_release_allows_untrusted_supplemental_rest_fields() -> None:
    value = release()
    value["author"] = {"login": "octocat"}
    value["body"] = "not used as authority"
    validate(release=value)


def test_release_rejects_absent_required_field() -> None:
    value = release()
    value.pop("target_commitish")
    with pytest.raises(VERIFIER.ControllerTagError):
        validate(release=value)


@pytest.mark.parametrize(
    "value",
    [
        {"enabled": False, "enforced_by_owner": True},
        {"enabled": 1, "enforced_by_owner": True},
        {"enabled": True, "enforced_by_owner": False},
        {"enabled": True, "enforced_by_owner": 1},
        {"enabled": True},
        {
            "enabled": True,
            "enforced_by_owner": True,
            "repository": VERIFIER.REPOSITORY,
        },
    ],
)
def test_immutable_releases_endpoint_must_prove_enabled(value: dict) -> None:
    with pytest.raises(VERIFIER.ControllerTagError):
        validate(immutable_releases=value)


def test_production_always_requires_owner_enforcement() -> None:
    with pytest.raises(VERIFIER.ControllerTagError):
        validate(immutable_releases=immutable_releases(enforced=False))

    assert "require_owner_enforcement" not in (
        VERIFIER.ControllerTagPolicy.__dataclass_fields__
    )


def test_local_tag_parser_rejects_confused_values() -> None:
    bad_local = local_tag_json()
    bad_local["ref"] = 123
    with pytest.raises(VERIFIER.ControllerTagError):
        VERIFIER.parse_local_tag(bad_local)


def test_canonical_json_loader_accepts_exact_document(tmp_path: Path) -> None:
    path = tmp_path / "value.json"
    write_canonical(path, github_context())
    assert VERIFIER.load_canonical_json(path, "value") == github_context()


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1, "b":2}\n',
        b'{"a":1,"a":1}\n',
        b'{"a":NaN}\n',
        b'[]\n',
        b"\xff",
        b"",
    ],
)
def test_canonical_json_loader_rejects_ambiguous_bytes(
    tmp_path: Path,
    raw: bytes,
) -> None:
    path = tmp_path / "value.json"
    path.write_bytes(raw)
    with pytest.raises(VERIFIER.ControllerTagError):
        VERIFIER.load_canonical_json(path, "value")


def test_canonical_json_loader_rejects_symlink_and_hardlink(
    tmp_path: Path,
) -> None:
    original = tmp_path / "original.json"
    write_canonical(original, github_context())
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(original)
    hardlink = tmp_path / "hardlink.json"
    os.link(original, hardlink)
    for path in (symlink, hardlink, original):
        with pytest.raises(VERIFIER.ControllerTagError):
            VERIFIER.load_canonical_json(path, "value")


def test_canonical_json_loader_rejects_oversized_document(
    tmp_path: Path,
) -> None:
    path = tmp_path / "large.json"
    path.write_bytes(b"x" * (VERIFIER.MAX_JSON_BYTES + 1))
    with pytest.raises(VERIFIER.ControllerTagError):
        VERIFIER.load_canonical_json(path, "value")


def test_cli_fails_closed_until_real_crypto_identity_is_pinned(
    tmp_path: Path,
) -> None:
    assert VERIFIER.PINNED_TAG_SIGNATURE_VERIFIER_IDENTITY == ""
    command = cli_arguments(tmp_path)
    result = subprocess.run(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )
    assert result.returncode == 78
    assert result.stdout == b""
    assert b"cryptographic tag signature verifier identity is not pinned" in (
        result.stderr
    )


def test_cli_rejects_noncanonical_or_unfixed_input(
    tmp_path: Path,
) -> None:
    command = cli_arguments(tmp_path)
    (tmp_path / "context.json").write_text(
        json.dumps(github_context(), indent=2),
        encoding="utf-8",
    )
    result = subprocess.run(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )
    assert result.returncode == 78
    assert result.stdout == b""
    assert b"must be canonical JSON" in result.stderr

    command = cli_arguments(tmp_path)
    command[command.index("--release-id") + 1] = "01"
    result = subprocess.run(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )
    assert result.returncode == 2


def test_verifier_source_is_offline_and_disables_bytecode_early() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    guard = source.index("sys.dont_write_bytecode = True")
    assert guard < source.index("from dataclasses import dataclass")
    assert "urllib" not in source
    assert "requests" not in source
    assert "socket" not in source
    assert "subprocess" not in source
    assert 'add_argument("--repository"' not in source
    assert 'add_argument("--workflow' not in source
    assert 'add_argument("--signature-result"' not in source
    assert 'PINNED_TAG_SIGNATURE_VERIFIER_IDENTITY = ""' in source
