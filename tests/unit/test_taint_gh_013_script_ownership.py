"""Precision controls for TAINT-GH-013's executable script binding."""

from __future__ import annotations

import pytest

from taintly.engine import scan_file
from taintly.models import Severity
from taintly.rules.registry import get_rule_by_id


def _findings(content: str):
    rule = get_rule_by_id("TAINT-GH-013")
    assert rule is not None
    return scan_file(".github/workflows/script.yml", [rule], _content=content)


@pytest.mark.parametrize(
    "step_fields",
    [
        (
            "      - uses: actions/github-script@v7\n"
            "        env:\n"
            "          PR_TITLE: ${{ github.event.pull_request.title }}\n"
            "        with:\n"
            "          script: |\n"
            "            const title = process.env.PR_TITLE;\n"
        ),
        (
            "      - uses: actions/github-script@v7\n"
            "        env:\n"
            "          RELEASE_NOTE: ${{ inputs.release_note }}\n"
            "        with:\n"
            "          script: >-\n"
            "            core.info(process.env.RELEASE_NOTE);\n"
        ),
    ],
)
def test_step_environment_expression_is_not_javascript_source(step_fields: str) -> None:
    content = "jobs:\n  inspect:\n    steps:\n" + step_fields
    assert _findings(content) == []


def test_expression_in_another_step_does_not_belong_to_github_script() -> None:
    content = (
        "jobs:\n  inspect:\n    steps:\n"
        "      - uses: actions/github-script@v7\n"
        "        with:\n"
        "          script: console.log('static');\n"
        "      - env:\n"
        "          TITLE: ${{ github.event.pull_request.title }}\n"
        "        run: printf '%s\\n' \"$TITLE\"\n"
    )
    assert _findings(content) == []


@pytest.mark.parametrize(
    "content",
    [
        (
            "jobs:\n  inspect:\n    steps:\n"
            "      - uses: actions/github-script@v7\n"
            "        with:\n"
            "          script: |\n"
            "            const title = '${{ github.event.pull_request.title }}';\n"
        ),
        (
            "jobs:\n  inspect:\n    steps:\n"
            "      - uses: actions/github-script@v7\n"
            "        with:\n"
            "          script: >-\n"
            "            const body = `${{ github.event.comment.body }}`;\n"
        ),
        (
            "jobs: {inspect: {steps: [{uses: 'actions/github-script@v7', "
            "with: {script: \"const branch = '${{ github.head_ref }}';\"}}]}}\n"
        ),
    ],
)
def test_expression_in_executable_script_scalar_is_reported(content: str) -> None:
    findings = _findings(content)
    assert len(findings) == 1
    assert findings[0].rule_id == "TAINT-GH-013"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].review_needed is True
    assert findings[0].confidence == "medium"


def test_expression_in_github_script_header_input_is_not_script_source() -> None:
    content = (
        "jobs:\n  inspect:\n    steps:\n"
        "      - uses: actions/github-script@v7\n"
        "        with:\n"
        "          github-token: ${{ secrets.GITHUB_TOKEN }}\n"
        "          script: |\n"
        "            core.info(context.repo.owner);\n"
    )
    assert _findings(content) == []
