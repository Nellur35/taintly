"""Timeout hardening advice distinguishes absent configuration from defaults."""

from taintly.families import iter_families
from taintly.rules.registry import load_all_rules


def test_missing_timeout_keeps_posture_and_acknowledges_default():
    rule = next(rule for rule in load_all_rules() if rule.id == "SEC10-GH-001")
    source = "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
    assert rule.pattern.check(source, source.splitlines())
    assert "explicit" in rule.title
    assert "360-minute default" in rule.description
    assert "runner execution limits" in rule.description
    assert "workflow level" not in rule.remediation
    assert "unlimited" not in rule.title
    configured = source.replace("    steps:", "    timeout-minutes: 20\n    steps:")
    assert not rule.pattern.check(configured, configured.splitlines())


def test_timeout_is_owned_by_its_job_not_a_sibling_step_or_scalar():
    rule = next(rule for rule in load_all_rules() if rule.id == "SEC10-GH-001")
    source = """jobs:
  build:
    runs-on: [ubuntu-latest]
    steps:
      - timeout-minutes: 2
        run: |
          echo 'timeout-minutes: 50'
  lint:
    runs-on: ubuntu-latest
    "timeout-minutes": 10
    steps: [{run: echo hello}]
"""
    assert rule.pattern.check(source, source.splitlines()) == [(3, "runs-on: [ubuntu-latest]")]
    configured = source.replace("    steps:", "    timeout-minutes: 10\n    steps:", 1)
    assert not rule.pattern.check(configured, configured.splitlines())


def test_duplicate_job_keeps_timeout_absence_unresolved():
    from taintly.models import IncompletePatternMatches

    rule = next(rule for rule in load_all_rules() if rule.id == "SEC10-GH-001")
    source = """jobs:
  check:
    runs-on: ubuntu-latest
    steps: [{run: echo hello}]
  check:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps: [{run: echo hello}]
"""
    outcomes = rule.pattern.check(source, source.splitlines())
    assert isinstance(outcomes, IncompletePatternMatches)
    assert not outcomes


def test_job_merge_keeps_uncertainty_without_hiding_a_direct_sibling():
    from taintly.models import IncompletePatternMatches

    rule = next(rule for rule in load_all_rules() if rule.id == "SEC10-GH-001")
    source = """defaults: &runner
  runs-on: ubuntu-latest
jobs:
  inherited:
    <<: *runner
    steps: [{run: echo hello}]
  direct:
    runs-on: ubuntu-latest
    steps: [{run: echo hello}]
"""
    outcomes = rule.pattern.check(source, source.splitlines())
    assert isinstance(outcomes, IncompletePatternMatches)
    assert outcomes == [(8, "runs-on: ubuntu-latest")]


def test_shared_runner_line_keeps_exact_job_attribution_unresolved():
    from taintly.models import IncompletePatternMatches

    rule = next(rule for rule in load_all_rules() if rule.id == "SEC10-GH-001")
    source = (
        "jobs: {build: {runs-on: ubuntu-latest, steps: [{run: echo build}]}, "
        "lint: {runs-on: ubuntu-latest, timeout-minutes: 10, steps: [{run: echo lint}]}}"
    )
    outcomes = rule.pattern.check(source, source.splitlines())
    assert isinstance(outcomes, IncompletePatternMatches)
    assert not outcomes


def test_step_liveness_cannot_hide_timeout_on_the_same_line(tmp_path):
    from taintly.engine import scan_file

    rule = next(rule for rule in load_all_rules() if rule.id == "SEC10-GH-001")
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on: push\njobs:\n  build: {runs-on: ubuntu-latest, "
        "steps: [{if: false, run: echo skip}, {run: echo hello}]}\n",
        encoding="utf8",
    )
    outcomes = scan_file(str(workflow), [rule])
    assert [item.rule_id for item in outcomes] == ["ENGINE-ERR"]
    assert "job timeout ownership" in outcomes[0].description


def test_resource_family_does_not_claim_indefinite_github_execution():
    family = next(family for family in iter_families() if family.id == "resource_controls")
    assert "indefinitely" not in family.why
    assert "platform-imposed limit" in family.why
