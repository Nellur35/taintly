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


def test_resource_family_does_not_claim_indefinite_github_execution():
    family = next(family for family in iter_families() if family.id == "resource_controls")
    assert "indefinitely" not in family.why
    assert "platform-imposed limit" in family.why
