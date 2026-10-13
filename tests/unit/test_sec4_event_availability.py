"""Event-aware availability regression guards for GitHub context sources.

Only a complete, explicit ``push`` trigger proves ``github.event.issue``
absent. Unknown and incomplete trigger declarations remain candidates for
review; event unions and independent fallback sources retain their findings.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform


@pytest.fixture(scope="module")
def github_rules():
    return _github_rules()


def _github_rules():
    return load_rules_for_platform(Platform.GITHUB)


def _scan(tmp_path: Path, content: str, name: str = "workflow.yml"):
    target = tmp_path / ".github" / "workflows" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8", newline="")
    return scan_file(str(target), _github_rules())


def _scan_complete(tmp_path: Path, content: str, name: str = "workflow.yml"):
    findings = _scan(tmp_path, content, name)
    assert not [finding for finding in findings if finding.rule_id == "ENGINE-ERR"]
    return findings


def _ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}


def _run_line(content: str) -> int:
    return next(index for index, line in enumerate(content.splitlines(), 1) if "- run:" in line)


def _workflow(trigger: str, run: str) -> str:
    return (
        "name: event availability\n"
        f"{trigger}"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  check:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - run: {run}\n"
    )


@pytest.mark.parametrize(
    "trigger",
    [
        "on: push\n",
        "on: [push]\n",
        "on:\n  - push\n",
        "on: {push: {}}\n",
        "on:\n  push: {}\n",
    ],
    ids=["scalar", "flow-list", "block-list", "flow-map", "block-map"],
)
def test_push_only_issue_title_and_body_are_unavailable(tmp_path, trigger):
    content = (
        "name: push only\n" + trigger + "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  check:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        '      - run: echo "${{ github.event.issue.title }}"\n'
        '      - run: echo "${{ github.event.issue.body }}"\n'
    )

    findings = _scan_complete(tmp_path, content)

    assert "SEC4-GH-004" not in _ids(findings)


@pytest.mark.parametrize(
    "trigger",
    [
        "on:\n  - push\n  - {}\n",
        "event_name: &ev push\non:\n  - *ev\n",
    ],
    ids=["empty-collection-item", "aliased-trigger-item"],
)
def test_incomplete_or_indirect_trigger_items_keep_candidate(tmp_path, trigger):
    content = _workflow(trigger, 'echo "${{ github.event.issue.title }}"')

    matches = [
        finding for finding in _scan_complete(tmp_path, content) if finding.rule_id == "SEC4-GH-004"
    ]

    assert len(matches) == 1
    assert matches[0].line == _run_line(content)


def test_push_only_bracket_case_spelling_has_same_absence(tmp_path):
    content = _workflow(
        "on: push\n",
        "echo \"${{ GITHUB['event']['issue']['title'] }}\"",
    )

    findings = _scan_complete(tmp_path, content)

    assert "SEC4-GH-004" not in _ids(findings)


def test_issues_trigger_retains_issue_title_at_source_line(tmp_path):
    content = _workflow("on: issues\n", 'echo "${{ github.event.issue.title }}"')

    matches = [
        finding for finding in _scan_complete(tmp_path, content) if finding.rule_id == "SEC4-GH-004"
    ]

    assert len(matches) == 1
    assert matches[0].line == _run_line(content)
    assert "github.event.issue.title" in matches[0].snippet


def test_push_and_issues_union_retains_issue_source(tmp_path):
    content = _workflow(
        "on: [push, issues]\n",
        'echo "${{ github.event.issue.title }}"',
    )

    matches = [
        finding for finding in _scan_complete(tmp_path, content) if finding.rule_id == "SEC4-GH-004"
    ]

    assert len(matches) == 1
    assert matches[0].line == _run_line(content)


def test_push_issue_fallback_retains_independent_head_commit_source(tmp_path):
    content = _workflow(
        "on: push\n",
        'echo "${{ github.event.issue.title || github.event.head_commit.message }}"',
    )

    matches = [
        finding for finding in _scan_complete(tmp_path, content) if finding.rule_id == "SEC4-GH-004"
    ]

    assert len(matches) == 1
    assert matches[0].line == _run_line(content)
    assert "github.event.head_commit.message" in matches[0].snippet


@pytest.mark.parametrize(
    "trigger",
    [
        "",  # No event declaration is not proof that the property is absent.
        "on: repository_dispatch\n",  # Unmodeled event availability stays unknown.
        "on: workflow_call\n",  # Reusable caller context is outside this fact table.
    ],
    ids=["missing-on", "unmodeled-event", "workflow-call"],
)
def test_unknown_or_missing_trigger_keeps_candidate(tmp_path, trigger):
    content = _workflow(trigger, 'echo "${{ github.event.issue.title }}"')

    matches = [
        finding for finding in _scan_complete(tmp_path, content) if finding.rule_id == "SEC4-GH-004"
    ]

    assert len(matches) == 1
    assert matches[0].line == _run_line(
        _workflow(trigger, 'echo "${{ github.event.issue.title }}"')
    )


@pytest.mark.parametrize(
    ("trigger", "kind"),
    [
        ("on: push\non: issues\n", "candidate"),
        (
            "triggers: &events\n  push: {}\non:\n  <<: *events\n",
            "candidate",
        ),
        ("on: [push\n", "cutoff"),
    ],
    ids=["duplicate-on", "merged-on", "malformed-on"],
)
def test_ambiguous_or_malformed_trigger_never_becomes_a_clean_negative(tmp_path, trigger, kind):
    findings = _scan(
        tmp_path,
        _workflow(trigger, 'echo "${{ github.event.issue.title }}"'),
    )
    matches = [finding for finding in findings if finding.rule_id == "SEC4-GH-004"]

    if kind == "candidate":
        assert len(matches) == 1, _ids(findings)
        assert matches[0].line == _run_line(
            _workflow(trigger, 'echo "${{ github.event.issue.title }}"')
        )
        assert not [finding for finding in findings if finding.rule_id == "ENGINE-ERR"]
        return

    errors = [finding for finding in findings if finding.rule_id == "ENGINE-ERR"]
    assert not matches
    expected = [
        ("Structural coverage degraded:", 9, "unsupported YAML construct"),
        (
            "Rule LOTP-GH-006 returned incomplete pattern results for ",
            0,
            "Structural run ownership was incomplete",
        ),
        (
            "Rule SEC10-GH-002 returned incomplete pattern results for ",
            0,
            "structural YAML parsing reported an error or cutoff",
        ),
        (
            "Rule SEC3-GH-006 returned incomplete pattern results for ",
            0,
            "structural YAML parsing reported an error or cutoff",
        ),
    ]
    assert len(errors) == len(expected)
    for error, (title, line, reason) in zip(errors, expected, strict=True):
        assert error.title.startswith(title), error.title
        assert error.line == line
        assert reason in error.description
    expected_file = str((tmp_path / ".github" / "workflows" / "workflow.yml").resolve())
    assert {error.file for error in errors} == {expected_file}


def test_fragment_self_test_remains_conservative_without_trigger_context(github_rules):
    rule = next(rule for rule in github_rules if rule.id == "SEC4-GH-004")
    fragment = '        run: echo "${{ github.event.issue.title }}"'

    assert rule.pattern.check(fragment, fragment.splitlines())


@pytest.mark.parametrize(
    ("event", "field", "expected"),
    [
        ("push", "title", False),
        ("issues", "title", True),
        ("push", "body", False),
        ("issues", "body", True),
    ],
    ids=["push-title", "issues-title", "push-body", "issues-body"],
)
def test_github_script_issue_context_is_event_sensitive(tmp_path, event, field, expected):
    content = (
        "name: github script event availability\n"
        + "on: "
        + event
        + "\npermissions:\n  contents: read\njobs:\n  check:\n"
        + "    runs-on: ubuntu-latest\n    steps:\n"
        + "      - uses: actions/github-script@v7\n        with:\n"
        + "          script: |\n"
        + f"            const value = '${{{{ github.event.issue.{field} }}}}';\n"
    )
    findings = _scan_complete(tmp_path, content, f"{event}-{field}.yml")
    script_matches = [finding for finding in findings if finding.rule_id == "SEC4-GH-025"]

    assert len(script_matches) == int(expected), (event, field, _ids(findings))
    assert "TAINT-GH-013" in _ids(findings)
    if script_matches:
        interpolation_line = next(
            index for index, line in enumerate(content.splitlines(), 1) if "const value" in line
        )
        assert script_matches[0].line == interpolation_line
        assert f"github.event.issue.{field}" in script_matches[0].snippet


def test_dispatch_inputs_remain_owned_by_sec4_gh_008(tmp_path):
    content = (
        "name: dispatch input\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "    inputs:\n"
        "      environment:\n"
        "        type: string\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n"
        '      - run: echo "${{ github.event.inputs.environment }}"\n'
    )

    fired = _ids(_scan_complete(tmp_path, content))

    assert "SEC4-GH-008" in fired
    assert "SEC4-GH-004" not in fired


def test_step_output_github_script_path_remains_sec4_gh_024(tmp_path):
    content = (
        "name: script step output\n"
        "on: push\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n"
        '      - id: source\n        run: echo value=ok >> "$GITHUB_OUTPUT"\n'
        "      - uses: actions/github-script@v7\n        with:\n"
        "          script: |\n"
        "            console.log('${{ steps.source.outputs.value }}');\n"
    )

    fired = _ids(_scan_complete(tmp_path, content))

    assert "SEC4-GH-024" in fired
