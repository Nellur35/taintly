"""GitLab shallow CODE eligibility at variable-binding boundaries.

The parameter rows are related controls for one bounded source/sink profile,
not independent threats or detection-accuracy observations.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from taintly.engine import scan_file, scan_repo
from taintly.gitlab_taint import TaintPath, analyze
from taintly.models import Platform
from taintly.rules.gitlab.shell_role import (
    GitLabShellRole,
    classify_gitlab_shallow_use,
    validate_gitlab_shallow_use,
)
from taintly.rules.registry import load_rules_for_platform


def _base(root_rules: str = "") -> str:
    return (
        "workflow:\n"
        "  rules:\n"
        + root_rules
        + "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
        + "variables:\n"
        + "  TITLE: $CI_MERGE_REQUEST_TITLE\n"
    )


def _job(job_prelude: str, script: str, after_script: str = "") -> str:
    return (
        "check:\n"
        + job_prelude
        + "  id_tokens:\n"
        + "    CLOUD_TOKEN:\n"
        + "      aud: https://cloud.example\n"
        + script
        + after_script
    )


def _cases() -> dict[str, str]:
    root = _base()
    return {
        "inherit_false": root
        + _job("  inherit:\n    variables: false\n", '  script:\n    - eval "$TITLE"\n'),
        "inherit_allowlist_excludes_title": root
        + _job(
            "  inherit:\n    variables:\n      - OTHER\n",
            '  script:\n    - eval "$TITLE"\n',
        ),
        "workflow_rule_variables_override": _base(
            "    - when: always\n"
            "      variables:\n"
            "        TITLE: fixed\n"
        )
        + _job("", '  script:\n    - eval "$TITLE"\n'),
        "job_rule_variables_override": root
        + _job(
            "  rules:\n"
            "    - when: always\n"
            "      variables:\n"
            "        TITLE: fixed\n",
            '  script:\n    - eval "$TITLE"\n',
        ),
        "parallel_matrix_override": root
        + _job(
            "  parallel:\n"
            "    matrix:\n"
            "      - TITLE: [fixed]\n",
            '  script:\n    - eval "$TITLE"\n',
        ),
        "prior_assignment": root
        + _job(
            "",
            "  script:\n"
            "    - TITLE=fixed\n"
            '    - eval "$TITLE"\n',
        ),
        "prior_export_assignment": root
        + _job(
            "",
            "  script:\n"
            "    - export TITLE=fixed\n"
            '    - eval "$TITLE"\n',
        ),
        "prior_eval_assignment": root
        + _job(
            "",
            '  script:\n    - eval "TITLE=fixed"\n'
            '    - eval "$TITLE"\n',
        ),
        "prior_unset": root
        + _job(
            "",
            "  script:\n"
            "    - unset -v TITLE\n"
            '    - eval "$TITLE"\n',
        ),
        "prior_read": root
        + _job(
            "",
            "  script:\n"
            "    - read -r TITLE\n"
            '    - eval "$TITLE"\n',
        ),
        "before_script_is_prior_even_below_script": root
        + _job(
            "",
            '  script:\n    - eval "$TITLE"\n',
            "  before_script:\n"
            "    - TITLE=fixed\n",
        ),
        "global_before_script_is_prior": root
        + "before_script:\n"
        + "  - TITLE=fixed\n"
        + _job("", '  script:\n    - eval "$TITLE"\n'),
        "after_script_starts_fresh_shell": root
        + _job(
            "",
            "  script:\n"
            "    - TITLE=fixed\n",
            '  after_script:\n    - eval "$TITLE"\n',
        ),
        "plain_export_preserves_value": root
        + _job(
            "",
            "  script:\n"
            "    - export TITLE\n"
            '    - eval "$TITLE"\n',
        ),
        "job_variable_survives_disabled_inheritance": root
        + _job(
            "  inherit:\n"
            "    variables: false\n"
            "  variables:\n"
            "    TITLE: $CI_MERGE_REQUEST_TITLE\n",
            '  script:\n    - eval "$TITLE"\n',
        ),
    }


def _shallow_eval_path(content: str) -> TaintPath:
    paths = analyze(content, content.splitlines())
    matching = [
        path
        for path in paths
        if path.kind == "shallow"
        and path.sink_kind == "script"
        and path.source_var == "CI_MERGE_REQUEST_TITLE"
        and path.laundered_var == "TITLE"
        and path.sink_snippet.strip() == 'eval "$TITLE"'
    ]
    assert len(matching) == 1, "fixture must expose one real shallow eval path"
    return matching[0]


def _findings(tmp_path: Path, content: str):
    config = tmp_path / ".gitlab-ci.yml"
    config.write_text(content, encoding="utf-8")
    reports = scan_repo(
        str(tmp_path), load_rules_for_platform(Platform.GITLAB), Platform.GITLAB
    )
    assert reports
    assert all(report.engine_errors() == [] for report in reports)
    return [finding for report in reports for finding in report.findings]


@pytest.mark.parametrize(
    "case",
    [
        "inherit_false",
        "inherit_allowlist_excludes_title",
        "workflow_rule_variables_override",
        "job_rule_variables_override",
        "parallel_matrix_override",
        "prior_assignment",
        "prior_export_assignment",
        "prior_eval_assignment",
        "prior_unset",
        "prior_read",
        "before_script_is_prior_even_below_script",
        "global_before_script_is_prior",
    ],
    ids=[
        "inherit-false",
        "inherit-allowlist",
        "workflow-rule-override",
        "job-rule-override",
        "parallel-matrix-override",
        "prior-shell-assignment",
        "prior-export-assignment",
        "prior-eval-assignment",
        "prior-unset-v",
        "prior-read-r",
        "before-script-order",
        "global-before-script-order",
    ],
)
def test_binding_replacements_keep_shallow_eval_unknown_without_chain(
    tmp_path: Path, case: str
) -> None:
    content = _cases()[case]
    path = _shallow_eval_path(content)
    assert path.sink_line > 0
    witness = classify_gitlab_shallow_use(content, ".gitlab-ci.yml", path)
    assert witness.role is GitLabShellRole.UNKNOWN
    assert validate_gitlab_shallow_use(
        witness, content, ".gitlab-ci.yml", path.sink_line
    )

    rule = next(
        rule
        for rule in load_rules_for_platform(Platform.GITLAB)
        if rule.id == "TAINT-GL-001"
    )
    atomic = [
        finding
        for finding in scan_file(".gitlab-ci.yml", [rule], _content=content)
        if finding.rule_id == "TAINT-GL-001"
    ]
    assert len(atomic) == 1
    assert atomic[0].line == path.sink_line
    assert atomic[0].severity.value == "MEDIUM"
    assert atomic[0].confidence == "low"
    assert atomic[0].review_needed is True
    assert "gitlab-shell-role-unknown" in atomic[0].context_tags

    findings = _findings(tmp_path, content)
    assert any(finding.rule_id == "TAINT-GL-001" for finding in findings)
    assert not any(finding.rule_id == "CHAIN-GL-103" for finding in findings)


@pytest.mark.parametrize(
    ("case", "expected_section", "expected_item", "expected_source_path"),
    [
        (
            "after_script_starts_fresh_shell",
            "after_script",
            0,
            ("variables", "TITLE"),
        ),
        ("plain_export_preserves_value", "script", 1, ("variables", "TITLE")),
        (
            "job_variable_survives_disabled_inheritance",
            "script",
            0,
            ("check", "variables", "TITLE"),
        ),
    ],
    ids=[
        "after-script-fresh-shell",
        "plain-export-keeps-root-value",
        "job-variable-without-inheritance",
    ],
)
def test_binding_preserving_shell_context_retains_code_and_chain(
    tmp_path: Path,
    case: str,
    expected_section: str,
    expected_item: int,
    expected_source_path: tuple[str, ...],
) -> None:
    content = _cases()[case]
    path = _shallow_eval_path(content)
    witness = classify_gitlab_shallow_use(content, ".gitlab-ci.yml", path)
    assert witness.role is GitLabShellRole.CODE
    assert witness.filepath == ".gitlab-ci.yml"
    assert witness.source_var == "CI_MERGE_REQUEST_TITLE"
    assert witness.source_path == expected_source_path
    assert witness.owner_path == ("check", expected_section, expected_item)
    assert validate_gitlab_shallow_use(
        witness, content, ".gitlab-ci.yml", path.sink_line
    )

    findings = _findings(tmp_path, content)
    atomic = [finding for finding in findings if finding.rule_id == "TAINT-GL-001"]
    chain = [finding for finding in findings if finding.rule_id == "CHAIN-GL-103"]
    assert len(atomic) == 1
    assert atomic[0].severity.value == "CRITICAL"
    assert atomic[0].confidence == "high"
    assert atomic[0].review_needed is True
    assert len(chain) == 1
    rendered = json.dumps(chain[0].to_dict(), sort_keys=True).lower()
    assert chain[0].review_needed is True
    assert "conditional posix" in rendered
    assert "ci_merge_request_title" in chain[0].snippet.lower()
    assert "title" in chain[0].snippet.lower()
    assert "unverified" in rendered
