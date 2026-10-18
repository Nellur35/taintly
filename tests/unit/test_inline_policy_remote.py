"""Remote and batch scans must apply inline-suppression policy in the engine."""

from __future__ import annotations

import json
import sys

import pytest

import taintly.__main__ as cli
import taintly.batch as batch
from taintly.models import Platform, RegexPattern, Rule, Severity


def _rule(platform: Platform) -> Rule:
    return Rule(
        id="TEST-CI-REMOTE-001",
        title="Remote suppression test",
        severity=Severity.HIGH,
        platform=platform,
        owasp_cicd="CICD-SEC-3",
        description="Test-only finding used to exercise the real scan engine.",
        pattern=RegexPattern(match=r"dangerous-marker"),
        remediation="Remove the dangerous marker.",
        reference="https://example.invalid/test",
    )


def _run_remote_cli(monkeypatch, capsys, *, platform: Platform, suppressions_disabled: bool):
    """Run the actual CLI/scan_file path while stubbing only remote I/O."""
    rule = _rule(platform)
    monkeypatch.setattr(cli, "load_rules_for_platform", lambda _platform: [rule])
    monkeypatch.setattr(cli, "load_all_rules", lambda: [rule])
    monkeypatch.setattr(cli._rule_registry, "_IMPORT_FAILURES", [])

    if platform is Platform.GITHUB:
        import taintly.ingestion.github_api as api
        import taintly.platform.github_checks as checks

        content = """name: remote
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo dangerous-marker # taintly: ignore[TEST-CI-REMOTE-001]
"""
        monkeypatch.setenv("GITHUB_TOKEN", "test-token")
        monkeypatch.setattr(
            api,
            "fetch_org_workflows",
            lambda _org, _token: [("repo/.github/workflows/ci.yml", content)],
        )
        monkeypatch.setattr(api, "list_org_repos", lambda _org, _token: [])
        monkeypatch.setattr(checks, "run_all_checks", lambda _repo, _client: [])
        monkeypatch.setattr(checks, "run_account_checks", lambda _org, _client: [])
        argv = ["taintly", "--github-org", "example-org", "--platform", "github"]
    else:
        import taintly.ingestion.gitlab_api as api
        import taintly.platform.gitlab_checks as checks

        content = """test-job:
  script:
    - echo dangerous-marker # taintly: ignore[TEST-CI-REMOTE-001]
"""
        monkeypatch.setenv("GITLAB_TOKEN", "test-token")
        monkeypatch.setattr(
            api,
            "fetch_group_pipelines",
            lambda _group, _token: [("project/.gitlab-ci.yml", content)],
        )
        monkeypatch.setattr(api, "list_group_projects", lambda _group, _token: [])
        monkeypatch.setattr(checks, "run_all_checks", lambda _project, _client: [])
        monkeypatch.setattr(checks, "run_group_checks", lambda _group, _client: [])
        argv = ["taintly", "--gitlab-group", "example-group", "--platform", "gitlab"]

    argv.extend(["--no-config", "--format", "json", "--no-color"])
    if suppressions_disabled:
        argv.append("--no-inline-suppressions")
    monkeypatch.setattr(sys, "argv", argv)

    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code
    else:
        exit_code = 0
    payload = json.loads(capsys.readouterr().out)
    findings = [finding for finding in payload["findings"] if finding["rule_id"] == rule.id]
    return findings, exit_code


@pytest.mark.parametrize("platform", [Platform.GITHUB, Platform.GITLAB])
def test_remote_cli_opt_out_keeps_real_suppressed_rule_finding(monkeypatch, capsys, platform):
    # The remote fetch and posture calls are mocked; main(), its remote branch,
    # scan_file(), RegexPattern.check(), and inline suppression handling are real.
    findings, exit_code = _run_remote_cli(
        monkeypatch, capsys, platform=platform, suppressions_disabled=True
    )
    assert exit_code == 1
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    expected_line = 7 if platform is Platform.GITHUB else 3
    assert findings[0]["line"] == expected_line


@pytest.mark.parametrize("platform", [Platform.GITHUB, Platform.GITLAB])
def test_remote_cli_default_still_honors_inline_suppression(monkeypatch, capsys, platform):
    findings, exit_code = _run_remote_cli(
        monkeypatch, capsys, platform=platform, suppressions_disabled=False
    )
    assert exit_code == 0
    assert findings == []


def test_batch_inline_suppression_policy_is_per_call_and_defaults_to_honor(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """name: batch
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo dangerous-marker # taintly: ignore[TEST-CI-REMOTE-001]
""",
        encoding="utf-8",
    )
    rule = _rule(Platform.GITHUB)
    monkeypatch.setattr(
        batch.registry,
        "load_rules_for_platform",
        lambda platform: [rule] if platform is Platform.GITHUB else [],
    )

    disabled = batch.scan_repositories([repo], Platform.GITHUB, respect_inline_suppressions=False)
    defaulted = batch.scan_repositories([repo], Platform.GITHUB)
    disabled_again = batch.scan_repositories(
        [repo], Platform.GITHUB, respect_inline_suppressions=False
    )

    def matching(results):
        assert len(results) == 1
        assert results[0].error is None
        return [
            finding
            for report in results[0].reports
            for finding in report.findings
            if finding.rule_id == rule.id
        ]

    assert len(matching(disabled)) == 1
    assert matching(defaulted) == []
    assert len(matching(disabled_again)) == 1
