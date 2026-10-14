"""Configured OIDC candidates cannot certify effective cloud authority."""

from pathlib import Path

from taintly.engine import scan_repo
from taintly.guides import get_guide
from taintly.models import Platform, Severity
from taintly.rules.registry import get_rule_by_id


def _candidate_workflow(*, separate_job: bool = False) -> str:
    if separate_job:
        return """name: Review without cloud connection
on: issues
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: anthropics/claude-code-action@v1
  signing:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: printf '%s\\n' prepare
"""
    return """name: Review with token request declaration
on: issues
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedTools Read
"""


def test_file_scope_candidate_requires_review_without_cloud_trust_proof(tmp_path: Path):
    rule = get_rule_by_id("PSE-GH-001")
    assert rule is not None
    assert rule.severity == Severity.HIGH
    assert rule.review_needed
    for separate_job in (False, True):
        workflow = _candidate_workflow(separate_job=separate_job)
        # The existing broad matcher is preserved. Its result must explicitly
        # remain a file-level candidate when the capability is in another job.
        assert rule.pattern.check(workflow, workflow.splitlines())
        repo = tmp_path / str(separate_job)
        file = repo / ".github" / "workflows" / "review.yml"
        file.parent.mkdir(parents=True)
        file.write_text(workflow, encoding="utf-8")
        findings = [
            f for report in scan_repo(str(repo), [rule], Platform.GITHUB)
            for f in report.findings if f.rule_id == rule.id
        ]
        assert len(findings) == 1
        finding = findings[0]
        assert finding.review_needed
        assert "candidate" in finding.title.lower()
        assert "file-level" in finding.description
        assert "does not establish" in finding.description
        assert "cloud trust" in finding.description
        assert "holds a valid" not in finding.description


def test_pse_advice_preserves_required_auth_and_does_not_certify_tools():
    rule = get_rule_by_id("PSE-GH-001")
    assert rule is not None
    advice = rule.remediation
    assert "automatic approval" in advice
    assert "tool availability" in advice
    assert "exact" in advice and "MCP" in advice
    assert "authentication" in advice
    assert "forbid shell" not in advice
    assert "token is useless" not in advice


def test_pse_guide_does_not_grant_authority_from_cooccurrence_or_success():
    guide = get_guide("PSE-GH-001")
    assert guide is not None
    assert "file-level candidate" in guide
    assert "cloud trust" in guide
    assert "automatic approval" in guide
    assert "tool availability" in guide
    assert "success alone" in guide
    assert "refusal" in guide
    assert "holds a valid cloud-credential grant" not in guide
    assert "denies the agent the ability" not in guide
    assert "ROADMAP NOTE" not in guide
