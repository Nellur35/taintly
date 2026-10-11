from __future__ import annotations

from taintly.rules.registry import get_rule_by_id

SECRET_PRESENCE_WORKFLOW = """name: deployment credential audit
on: pull_request
jobs:
  deploy_secret_check:
    runs-on: ubuntu-latest
    steps:
      - name: Check configured credential
        run: test -n "${{ secrets.DEPLOY_KEY }}"
"""

ACTUAL_DEPLOYMENT_WORKFLOW = """name: production release
on: workflow_dispatch
jobs:
  deploy-production:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy application
        run: ./deploy.sh production
"""


def _rule():
    rule = get_rule_by_id("SEC1-GH-001")
    assert rule is not None
    return rule


def _matches(rule, content: str) -> list[tuple[int, str]]:
    return rule.pattern.check(content, content.splitlines())


def test_named_secret_presence_job_is_only_a_review_candidate():
    rule = _rule()

    assert _matches(rule, SECRET_PRESENCE_WORKFLOW)
    assert rule.review_needed is True
    assert rule.confidence == "low"
    assert "job name" in rule.description.lower()
    assert "does not establish" in rule.description.lower()
    assert "immediate deployment" not in rule.description.lower()
    assert "production" not in rule.threat_narrative.lower()


def test_actual_deployment_job_without_environment_still_matches():
    rule = _rule()

    assert _matches(rule, ACTUAL_DEPLOYMENT_WORKFLOW)
    assert rule.severity.value == "MEDIUM"


def test_deployment_job_with_environment_is_not_a_candidate():
    rule = _rule()
    protected = ACTUAL_DEPLOYMENT_WORKFLOW.replace(
        "    runs-on: ubuntu-latest\n", "    environment: production\n    runs-on: ubuntu-latest\n"
    )

    assert not _matches(rule, protected)
