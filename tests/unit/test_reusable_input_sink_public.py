"""Precision regressions for reusable-workflow executable sinks."""

from __future__ import annotations

import pytest

from taintly.engine import scan_file
from taintly.rules.registry import get_rule_by_id


def _findings(content: str):
    rule = get_rule_by_id("TAINT-GH-006")
    assert rule is not None
    return scan_file(".github/workflows/reusable.yml", [rule], _content=content)


@pytest.mark.parametrize(
    "step",
    [
        "      - run: ${{ inputs.after_build }}\n",
        (
            "      - uses: nick-fields/retry@v3\n"
            "        with:\n"
            "          command: npm test -- ${{ inputs.pattern }}\n"
        ),
        (
            "      - uses: actions/github-script@v7\n"
            "        with:\n"
            "          script: console.log('${{ inputs.message }}')\n"
        ),
    ],
)
def test_reports_reviewed_executable_sink_shapes(step: str) -> None:
    content = "on: workflow_call\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n" + step
    findings = _findings(content)
    assert len(findings) == 1
    assert findings[0].rule_id == "TAINT-GH-006"


@pytest.mark.parametrize(
    "step",
    [
        ("      - uses: actions/checkout@v4\n        with:\n          ref: ${{ inputs.ref }}\n"),
        (
            "      - uses: actions/upload-artifact@v4\n"
            "        with:\n"
            "          name: ${{ inputs.artifact_name }}\n"
        ),
        (
            "      - uses: local/action@v1\n"
            "        with:\n"
            "          working-directory: ${{ inputs.directory }}\n"
        ),
        ("      - env:\n          TARGET: ${{ inputs.target }}\n        run: ./fixed-command\n"),
    ],
)
def test_ignores_reviewed_structured_data_shapes(step: str) -> None:
    content = "on: workflow_call\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n" + step
    assert _findings(content) == []


def test_same_input_reference_is_ignored_outside_reusable_workflow() -> None:
    content = (
        "on: workflow_dispatch\n"
        "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo ${{ inputs.message }}\n"
    )
    assert _findings(content) == []


def test_typed_non_string_input_cannot_inject_script_text() -> None:
    content = (
        "on:\n"
        "  workflow_call:\n"
        "    inputs:\n"
        "      attempts:\n"
        "        type: number\n"
        "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: retry --count ${{ inputs.attempts }}\n"
    )
    assert _findings(content) == []


def test_follows_input_into_local_reusable_workflow(tmp_path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "callee.yml").write_text(
        "on:\n"
        "  workflow_call:\n"
        "    inputs:\n"
        "      command:\n"
        "        type: string\n"
        "jobs:\n  execute:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: ${{ inputs.command }}\n",
        encoding="utf-8",
    )
    caller = workflows / "caller.yml"
    caller.write_text(
        "on:\n"
        "  workflow_call:\n"
        "    inputs:\n"
        "      before:\n"
        "        type: string\n"
        "jobs:\n  call:\n    uses: ./.github/workflows/callee.yml\n"
        "    with:\n      command: ${{ inputs.before }}\n",
        encoding="utf-8",
    )
    rule = get_rule_by_id("TAINT-GH-006")
    assert rule is not None
    findings = scan_file(str(caller), [rule])
    assert len(findings) == 1
    assert findings[0].line == 10


def test_local_reusable_workflow_structured_input_is_not_a_sink(tmp_path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "callee.yml").write_text(
        "on:\n"
        "  workflow_call:\n"
        "    inputs:\n"
        "      ref:\n"
        "        type: string\n"
        "jobs:\n  checkout:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ inputs.ref }}\n",
        encoding="utf-8",
    )
    caller = workflows / "caller.yml"
    caller.write_text(
        "on:\n"
        "  workflow_call:\n"
        "    inputs:\n"
        "      ref:\n"
        "        type: string\n"
        "jobs:\n  call:\n    uses: ./.github/workflows/callee.yml\n"
        "    with:\n      ref: ${{ inputs.ref }}\n",
        encoding="utf-8",
    )
    rule = get_rule_by_id("TAINT-GH-006")
    assert rule is not None
    assert scan_file(str(caller), [rule]) == []
