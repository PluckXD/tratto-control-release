from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "controller-ci.yml"
REQUIREMENTS_PATH = ROOT / "requirements-ci.txt"
CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
SETUP_PYTHON = (
    "actions/setup-python@83679a892e2d95755f2dac6acb0bfd1e9ac5d548"
)


class UniqueSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueSafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _workflow() -> dict[str, Any]:
    parsed = yaml.load(
        WORKFLOW_PATH.read_text(encoding="utf-8"),
        Loader=UniqueSafeLoader,
    )
    assert isinstance(parsed, dict)
    return parsed


def test_ci_has_no_write_or_oidc_authority() -> None:
    workflow = _workflow()
    assert set(workflow["on"]) == {"pull_request", "push"}
    assert workflow["permissions"] == {}
    assert set(workflow["jobs"]) == {"controller-tests"}

    job = workflow["jobs"]["controller-tests"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["timeout-minutes"] == 10
    assert job["permissions"] == {"contents": "read"}
    assert "secrets." not in repr(job)
    assert "id-token" not in repr(job)


def test_ci_uses_only_exact_reviewed_action_commits() -> None:
    job = _workflow()["jobs"]["controller-tests"]
    actions = [step["uses"] for step in job["steps"] if "uses" in step]
    assert actions == [CHECKOUT, SETUP_PYTHON]
    assert all(
        re.fullmatch(r"[^@]+@[0-9a-f]{40}", action)
        for action in actions
    )

    checkout = job["steps"][0]
    assert checkout["with"] == {
        "fetch-depth": 1,
        "persist-credentials": False,
    }
    setup = job["steps"][1]
    assert setup["with"] == {
        "architecture": "x64",
        "check-latest": False,
        "python-version": "3.12.13",
    }


def test_ci_installs_only_hash_pinned_binary_dependencies() -> None:
    job = _workflow()["jobs"]["controller-tests"]
    install = job["steps"][2]["run"]
    for required in (
        "--no-deps",
        "--only-binary=:all:",
        "--require-hashes",
        "--index-url https://pypi.org/simple",
        "--requirement requirements-ci.txt",
    ):
        assert required in install
    assert job["env"]["PIP_CONFIG_FILE"] == "/dev/null"

    requirements = REQUIREMENTS_PATH.read_text(encoding="ascii")
    records = [
        record.strip()
        for record in requirements.splitlines()
        if record and not record.startswith(" ")
    ]
    assert len(records) == 6
    assert all(re.fullmatch(r"[A-Za-z]+==[0-9.]+ \\", row) for row in records)
    hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", requirements)
    assert len(hashes) == len(records)
    assert len(set(hashes)) == len(hashes)


def test_ci_runs_the_complete_suite_without_bytecode() -> None:
    job = _workflow()["jobs"]["controller-tests"]
    assert job["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
    assert job["steps"][-1]["run"] == "python3 -B -m pytest -q"
