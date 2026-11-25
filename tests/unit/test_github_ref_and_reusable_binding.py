"""Scanner-level checks for GitHub ref splices and reusable input ownership."""
from pathlib import Path

from taintly.engine import scan_repo
from taintly.models import Platform, Severity
from taintly.rules.registry import load_rules_for_platform


def _scan(root: Path, workflow: str, rule_id: str):
    path = root / ".github" / "workflows" / "ci.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(workflow, encoding="utf-8")
    reports = scan_repo(str(root), load_rules_for_platform(Platform.GITHUB), Platform.GITHUB)
    return [finding for finding in reports[0].findings if finding.rule_id == rule_id]


def test_ref_template_and_environment_argument_are_distinct(tmp_path: Path):
    workflow = """on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          printf '%s' "${{ github.ref_name }}"
      - env:
          REF: ${{ github.ref_name }}
        run: printf '%s' "$REF"
      - if: github.ref_name == 'main'
        run: printf fixed
"""
    findings = _scan(tmp_path, workflow, "SEC4-GH-030")
    assert [(f.line, f.severity, f.review_needed) for f in findings] == [
        (7, Severity.INFO, True)
    ]


def test_external_workflow_report_binds_only_the_owned_input(tmp_path: Path):
    workflow = """on: workflow_dispatch
jobs:
  call:
    uses: example/tools/.github/workflows/help.yml@main
    if: github.event.inputs.enabled
    with:
      label: ${{ github.event.inputs.label }}
      number: ${{ github.event.pull_request.number }}
  other:
    runs-on: ubuntu-latest
    steps:
      - run: printf '%s' "${{ github.event.inputs.label }}"
"""
    findings = _scan(tmp_path, workflow, "SEC4-GH-016")
    assert [(f.line, f.review_needed) for f in findings] == [(7, True)]
    assert "called implementation at its effective revision" in findings[0].description
    assert "explicit secrets mapping or secrets: inherit" in findings[0].remediation
    assert "all secrets" not in findings[0].description


def test_local_call_guard_does_not_become_an_input_binding(tmp_path: Path):
    workflow = """on: issue_comment
jobs:
  call:
    uses: ./.github/workflows/help.yml
    if: github.event.comment.body != ''
    with:
      label: ${{ github.event.comment.body }}
"""
    findings = _scan(tmp_path, workflow, "TAINT-GH-007")
    assert [(f.line, f.severity, f.review_needed) for f in findings] == [
        (7, Severity.MEDIUM, True)
    ]
