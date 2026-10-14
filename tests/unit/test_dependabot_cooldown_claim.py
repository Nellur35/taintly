"""Missing explicit policy must not imply a zero provider default.

Provider contract checked 2026-10-11 against GitHub's options reference:
https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference#cooldown
These are fresh controls, independent of the completed warning holdout.
"""

import pytest

from taintly.rules.registry import load_all_rules


def _rule():
    return next(rule for rule in load_all_rules() if rule.id == "SEC8-GH-005")


def test_missing_explicit_cooldown_preserves_posture_with_accurate_default():
    rule = _rule()
    content = (
        "version: 2\nupdates:\n  - package-ecosystem: cargo\n"
        "    directory: /\n    schedule:\n      interval: weekly\n"
    )
    assert rule.pattern.check(content, content.splitlines()) == [(3, "- package-ecosystem: cargo")]
    assert rule.review_needed
    assert "explicit" in rule.title.lower()
    assert "3 days" in rule.description
    assert "Security updates" in rule.description
    assert "does not establish immediate updates" in rule.description


@pytest.mark.parametrize("days", [0, 3, 7])
def test_explicit_policy_is_outside_missing_policy_contract(days):
    content = (
        "version: 2\nupdates:\n  - package-ecosystem: cargo\n"
        "    directory: /\n    schedule:\n      interval: weekly\n"
        f"    cooldown:\n      default-days: {days}\n"
    )
    # A zero-day policy may deserve a separate rule; this rule detects absence.
    assert _rule().pattern.check(content, content.splitlines()) == []


def test_cooldown_advice_does_not_promise_incident_prevention():
    rule = _rule()
    text = " ".join([rule.title, rule.description, rule.remediation, rule.threat_narrative])
    for old_claim in ["no post-release window", "within minutes", "any repo", "intra-minute"]:
        assert old_claim not in text
    assert "no fixed delay guarantees detection" in rule.threat_narrative
    assert "does not delay security updates" in rule.remediation
    assert rule.incidents == []
