"""Whole-report contracts for platform-neutral script-injection summaries."""

from __future__ import annotations

import hashlib
import json

import pytest

from taintly.engine import scan_file
from taintly.models import AuditReport, Platform
from taintly.reporters.html_report import format_html
from taintly.reporters.json_report import format_json
from taintly.reporters.text import format_text
from taintly.rules.registry import load_rules_for_platform


_GITLAB_CASES = {
    "data": (
        "workflow:\n"
        "  rules:\n"
        "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
        "variables:\n"
        "  TITLE: $CI_MERGE_REQUEST_TITLE\n"
        "check:\n"
        "  image: alpine:3.21\n"
        "  script:\n"
        "    - printf '%s\\n' $TITLE\n"
    ),
    "unknown": (
        "workflow:\n"
        "  rules:\n"
        "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
        "variables:\n"
        "  TITLE: $CI_MERGE_REQUEST_TITLE\n"
        "check:\n"
        "  image: alpine:3.21\n"
        "  script:\n"
        '    - eval "$TITLE" extra\n'
    ),
    "code": (
        "workflow:\n"
        "  rules:\n"
        "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
        "variables:\n"
        "  TITLE: $CI_MERGE_REQUEST_TITLE\n"
        "check:\n"
        "  image: alpine:3.21\n"
        "  script:\n"
        '    - eval "$TITLE"\n'
    ),
}
_GITLAB_SHA256 = {
    "data": "ac0e0204041f132f69b27bdff01b5915828092e1ea3172e24d4d3f334f61e340",
    "code": "584fc8ce407b6cb667fa7f98da08bef0c07e3c08a61b5bbcb6bf76206f5889a9",
}
_GITHUB_RUN = (
    "name: title check\n"
    "on: pull_request\n"
    "jobs:\n"
    "  check:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    '      - run: echo "${{ github.event.pull_request.title }}"\n'
)
_SUMMARY_INTRO = "Untrusted input may become code when a shell or interpreter parses it as source."


def _render(platform: Platform, rule_id: str, content: str):
    rule = next(
        rule
        for rule in load_rules_for_platform(platform)
        if rule.id == rule_id
    )
    filename = ".gitlab-ci.yml" if platform is Platform.GITLAB else ".github/workflows/title.yml"
    findings = scan_file(filename, [rule], _content=content)
    assert not [finding for finding in findings if finding.rule_id == "ENGINE-ERR"]
    report = AuditReport(
        repo_path="/fixture",
        platform=platform.value,
        files_scanned=1,
        rules_loaded=1,
        findings=findings,
    )
    report.summarize()
    return findings, report, format_json(report), format_text(report, use_color=False), format_html(report)


@pytest.mark.parametrize("role", ["data", "unknown", "code"])
def test_gitlab_script_injection_family_summary_does_not_overclaim(role: str) -> None:
    content = _GITLAB_CASES[role]
    if role in _GITLAB_SHA256:
        assert hashlib.sha256(content.encode("utf-8")).hexdigest() == _GITLAB_SHA256[role]

    findings, _report, json_text, text, html = _render(
        Platform.GITLAB, "TAINT-GL-001", content
    )
    data = json.loads(json_text)
    family = next(item for item in data["families"] if item["family_id"] == "script_injection")

    assert len(findings) == 1
    assert family["finding_count"] == 1
    assert family["rule_ids"] == ["TAINT-GL-001"]
    finding = findings[0]
    serialized_finding = finding.to_dict()
    if role == "data":
        assert serialized_finding["context_tags"] == ["gitlab-shell-role-data"]
        assert finding.severity.value in {"LOW", "MEDIUM"}
        assert finding.confidence in {"low", "medium"}
        assert finding.review_needed is True
        assert "ordinary printf argument" in finding.description
    elif role == "unknown":
        assert serialized_finding["context_tags"] == ["gitlab-shell-role-unknown"]
        assert finding.severity.value in {"LOW", "MEDIUM"}
        assert finding.confidence in {"low", "medium"}
        assert finding.review_needed is True
        assert "UNKNOWN" in finding.description
    else:
        assert role == "code"
        assert serialized_finding["context_tags"] == ["gitlab-shell-role-code"]
        assert finding.severity.value in {"HIGH", "CRITICAL"}
        assert finding.confidence == "high"
        assert finding.review_needed is True
        assert "conditional POSIX profile" in finding.description
    family_why = family["why"].lower()
    assert "arbitrary code execution" not in family_why
    assert "full permissions" not in family_why
    assert "does not execute the value by itself" in family_why
    assert "does not recursively parse" in family_why
    assert family["title"] == "Untrusted input handling in CI scripts"
    assert _SUMMARY_INTRO.lower() in family_why
    # Text places review-needed families in a compact list, while JSON and
    # HTML carry the full family rationale.
    assert family["title"].lower() in text.lower()
    assert "arbitrary code execution" not in text.lower()
    assert "full permissions" not in text.lower()
    assert family["title"].lower() in html.lower()
    assert family_why in html.lower()
    assert "review" in html.lower()


def test_github_script_injection_summary_keeps_shell_context() -> None:
    findings, _report, json_text, text, html = _render(
        Platform.GITHUB, "SEC4-GH-004", _GITHUB_RUN
    )
    data = json.loads(json_text)
    family = next(item for item in data["families"] if item["family_id"] == "script_injection")
    why = family["why"].lower()

    assert [finding.rule_id for finding in findings] == ["SEC4-GH-004"]
    assert family["finding_count"] == 1
    assert family["rule_ids"] == ["SEC4-GH-004"]
    assert "shell" in why and "code" in why
    assert "github_output" in why
    assert "does not execute the value by itself" in why
    assert _SUMMARY_INTRO.lower() in why
    for rendered in (text.lower(), html.lower()):
        assert _SUMMARY_INTRO.lower() in rendered
    assert "github_output" in html.lower()
    assert "does not execute the value by itself" in html.lower()
    assert "arbitrary code execution with the workflow's full permissions" not in family["why"].lower()
