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


_ISSUE_NUMBER = "const issue_number = ${{ github.event.issue.number }};"
_TEXT = "const display = '${{ github.event.issue.title }}';"


def _issue_script(*lines: str, trigger: str = "on: issues\n") -> str:
    return (
        trigger + "jobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/github-script@v7\n"
        "        with:\n"
        "          script: |\n" + "".join(f"            {line}\n" for line in lines)
    )


def test_issue_number_keeps_the_exact_location_as_an_observation() -> None:
    (finding,) = _findings(_issue_script("const scope = 'local';", _ISSUE_NUMBER))
    assert finding.severity is Severity.INFO
    assert finding.line == 10
    assert finding.snippet == _ISSUE_NUMBER
    assert "issue number" in finding.title.lower()
    assert "arbitrary JS" not in finding.description
    assert "decimal integer" in finding.threat_narrative.lower()
    assert not finding.incidents


def test_numeric_use_leaves_independent_text_review_visible() -> None:
    number, text = _findings(_issue_script(_ISSUE_NUMBER, _TEXT))
    assert number.severity is Severity.INFO
    assert text.severity is Severity.HIGH
    assert text.snippet == _TEXT


@pytest.mark.parametrize(
    "source",
    [
        _issue_script(_ISSUE_NUMBER + " " + _TEXT),
        _issue_script(_ISSUE_NUMBER, trigger="on: [issues, workflow_call]\n"),
        _issue_script(_ISSUE_NUMBER, trigger="on: issues\non: workflow_call\n"),
        _issue_script(_ISSUE_NUMBER.replace("issue.number", "issue.number || inputs.number")),
        _issue_script(_ISSUE_NUMBER.replace("github.event.issue.number", "inputs.number")),
        _issue_script("/* open comment", _ISSUE_NUMBER, "*/"),
        _issue_script("function initialize() {", _ISSUE_NUMBER, "}"),
    ],
)
def test_numeric_proof_requires_supported_source_and_position(source: str) -> None:
    (finding,) = _findings(source)
    assert finding.severity is Severity.HIGH
    assert finding.review_needed
