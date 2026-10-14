"""Full-engine calibration for the safely quoted TAINT-GH-012 lint."""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform, Severity
from taintly.rules.registry import load_all_rules
from taintly.scorer import compute_score


@pytest.fixture(scope="module")
def taint_rules():
    ids = {"TAINT-GH-001", "TAINT-GH-012"}
    return [rule for rule in load_all_rules() if rule.id in ids]


def _scan(content: str, tmp_path: Path, taint_rules):
    return scan_file(str(tmp_path / ".github" / "workflows" / "lint.yml"), taint_rules, _content=content)


SAFE_QUOTED_WORKFLOWS = [
    pytest.param(
        """name: step environment on privileged PR
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: write
jobs:
  inspect:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.pull_request.title }}
        run: echo "$TITLE"
""",
        id="pull-request-target-step-env-echo",
    ),
    pytest.param(
        """name: job environment on issue comment
on:
  issue_comment:
    types: [created]
permissions:
  issues: write
jobs:
  inspect:
    runs-on: ubuntu-latest
    env:
      COMMENT_BODY: ${{ github.event.comment.body }}
    steps:
      - run: printf '%s\\n' "$COMMENT_BODY"
""",
        id="issue-comment-job-env-printf",
    ),
    pytest.param(
        """name: step environment on privileged PR ref
on:
  pull_request_target:
    types: [synchronize]
permissions:
  contents: write
jobs:
  inspect:
    runs-on: ubuntu-latest
    steps:
      - env:
          HEAD_REF: ${{ github.head_ref }}
        run: git fetch origin "$HEAD_REF"
""",
        id="pull-request-target-step-env-command-argument",
    ),
    pytest.param(
        """name: step environment on review comment
on:
  pull_request_review_comment:
    types: [created]
permissions:
  issues: write
jobs:
  inspect:
    runs-on: ubuntu-latest
    steps:
      - env:
          REVIEW_TEXT: ${{ github.event.comment.body }}
        run: printf '%s\\n' "$REVIEW_TEXT"
""",
        id="review-comment-step-env-printf",
    ),
]


@pytest.mark.parametrize("content", SAFE_QUOTED_WORKFLOWS)
def test_safe_quoted_taint_stays_low_confidence_review_needed(content, tmp_path, taint_rules):
    findings = _scan(content, tmp_path, taint_rules)
    lint = [finding for finding in findings if finding.rule_id == "TAINT-GH-012"]

    assert len(lint) == 1
    assert lint[0].confidence == "low"
    assert lint[0].review_needed is True
    assert lint[0].exploitability != "high"
    assert lint[0].severity == Severity.MEDIUM
    assert not any(finding.rule_id == "TAINT-GH-001" for finding in findings)

    score = compute_score([lint[0]], files_scanned=1, platforms_scanned={Platform.GITHUB})
    assert score.deductions["CLUSTERS"] == 0.0
    assert score.review_needed == 1
    assert score.distinct_risks == 0


def test_workflow_level_env_remains_outside_shallow_taint_scope(tmp_path, taint_rules):
    content = """name: workflow environment boundary
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: write
env:
  TITLE: ${{ github.event.pull_request.title }}
jobs:
  inspect:
    runs-on: ubuntu-latest
    steps:
      - run: printf '%s\\n' "$TITLE"
"""

    findings = _scan(content, tmp_path, taint_rules)

    assert not any(finding.rule_id in {"TAINT-GH-001", "TAINT-GH-012"} for finding in findings)


@pytest.mark.parametrize(
    ("run_line", "code_bearing"),
    [
        ("run: echo $TITLE", False),
        ('run: eval "$TITLE"', True),
    ],
    ids=["unquoted-shell-reference", "eval-reparser"],
)
def test_taint_metadata_distinguishes_unresolved_argument_from_code(
    run_line, code_bearing, tmp_path, taint_rules
):
    content = f"""name: unsafe taint control
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: write
jobs:
  inspect:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{{{ github.event.pull_request.title }}}}
        {run_line}
"""

    findings = _scan(content, tmp_path, taint_rules)
    injection = [finding for finding in findings if finding.rule_id == "TAINT-GH-001"]

    assert len(injection) == 1
    if code_bearing:
        assert injection[0].exploitability == "high"
        assert injection[0].confidence == "high"
        assert injection[0].review_needed is False
        assert injection[0].severity is Severity.CRITICAL
    else:
        assert injection[0].exploitability != "high"
        assert injection[0].confidence == "low"
        assert injection[0].review_needed is True
        assert injection[0].severity is Severity.MEDIUM
        assert "shell-use-unknown" in injection[0].context_tags
    assert not any(finding.rule_id == "TAINT-GH-012" for finding in findings)


def test_safe_lint_does_not_make_a_real_injection_family_review_only(tmp_path, taint_rules):
    content = """name: both safe lint and unsafe sink
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: write
jobs:
  inspect:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.pull_request.title }}
        run: echo "$TITLE"
      - env:
          TITLE: ${{ github.event.pull_request.title }}
        run: eval "$TITLE"
"""

    findings = _scan(content, tmp_path, taint_rules)
    lint = next(finding for finding in findings if finding.rule_id == "TAINT-GH-012")
    injection = next(finding for finding in findings if finding.rule_id == "TAINT-GH-001")
    score = compute_score(findings, files_scanned=1, platforms_scanned={Platform.GITHUB})

    assert lint.review_needed is True
    assert lint.exploitability == "medium"
    assert injection.review_needed is False
    assert injection.exploitability == "high"
    assert score.review_needed == 0
    assert score.distinct_risks == 1
    assert score.deductions["CLUSTERS"] < 0.0
