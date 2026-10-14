"""Bound SEC4 privileged-trigger advice to configured source and authority evidence.

Acceptance context is fixed by the sealed C07-C09 cases: C07 selects a PR head,
sets ``contents: read`` and ``persist-credentials: false``, and invokes
``python verify.py`` without supplying its source; C08 declares VERIFY_TOKEN in
the consumer step without proving that the secret exists; C09 declares a secret
in a sibling job, which does not make it available to the consumer job.
"""

from taintly.families import default_review_needed, describe_family, iter_families
from taintly.models import Severity
from taintly.rules.registry import load_all_rules

_RULES = {rule.id: rule for rule in load_all_rules()}


def _rule(rule_id: str):
    return _RULES[rule_id]


def _rule_text(rule_id: str) -> str:
    rule = _rule(rule_id)
    return " ".join(
        str(getattr(rule, field, ""))
        for field in ("title", "description", "remediation", "threat_narrative")
    ).lower()


def _needs_review(rule_id: str) -> bool:
    return _rule(rule_id).review_needed or default_review_needed(rule_id)


def _assert_matcher_fixtures_unchanged(rule_id: str) -> None:
    rule = _rule(rule_id)
    assert rule.test_positive
    assert rule.test_negative
    assert all(rule.pattern.check(case, case.splitlines()) for case in rule.test_positive)
    assert all(not rule.pattern.check(case, case.splitlines()) for case in rule.test_negative)


def test_sec4_gh_001_describes_a_configured_checkout_candidate_not_proven_impact():
    rule_id = "SEC4-GH-001"
    text = _rule_text(rule_id)
    assert _rule(rule_id).severity is Severity.CRITICAL
    _assert_matcher_fixtures_unchanged(rule_id)
    assert _needs_review(rule_id)
    for required in (
        "pull_request_target",
        "head.sha",
        "allow-unsafe-pr-checkout",
        "persist-credentials",
        "owning",
        "command",
        "permissions",
        "secret",
    ):
        assert required in text
    assert "does not establish execution" in text or "does not prove execution" in text
    for unsupported_claim in (
        "full secret access",
        "all secrets",
        "attacker-controlled code executes",
        "arbitrary code execution",
        "at scale from thousands",
    ):
        assert unsupported_claim not in text


def test_sec4_gh_002_keeps_trigger_posture_separate_from_consumed_authority():
    rule_id = "SEC4-GH-002"
    text = _rule_text(rule_id)
    assert _rule(rule_id).severity is Severity.MEDIUM  # pinned PUBLIC baseline; LAB baseline was HIGH
    _assert_matcher_fixtures_unchanged(rule_id)
    assert _needs_review(rule_id)
    for required in (
        "base repository",
        "trigger",
        "permissions",
        "secret",
        "owning job",
    ):
        assert required in text
    assert "does not by itself prove" in text or "does not establish" in text
    for unsupported_claim in (
        "grants write repository access",
        "exposes secrets to all workflow steps",
        "inherently risky",
    ):
        assert unsupported_claim not in text


def test_sec4_gh_003_describes_missing_text_not_effective_guard_or_provenance():
    rule_id = "SEC4-GH-003"
    text = _rule_text(rule_id)
    assert _rule(rule_id).severity is Severity.MEDIUM
    _assert_matcher_fixtures_unchanged(rule_id)
    assert _needs_review(rule_id)
    for required in (
        "file-level",
        "workflow_run.conclusion",
        "owning job",
        "provenance",
        "run-id:",
        "github.event.workflow_run.id",
        "repository:",
        "github-token:",
        "actions: read",
        "name:",
    ):
        assert required in text
    assert "success is not artifact provenance" in text
    assert "head_repository.default_branch" not in text
    assert "base repo sha" not in text


def test_privileged_pr_trigger_family_is_conditional_and_preserves_membership():
    family = next(f for f in iter_families() if f.id == "privileged_pr_trigger")
    assert family.members == frozenset(
        {"SEC4-GH-001", "SEC4-GH-002", "SEC4-GH-003"}
    )
    title, why = describe_family("privileged_pr_trigger")
    text = f"{title} {why}".lower()
    for required in ("owning event", "job and step", "source", "permission settings", "secret"):
        assert required in text
    assert "does not by itself prove" in text or "does not by itself establish" in text
    assert "not a prevalence estimate" in text
    for unsupported_claim in (
        "single biggest source",
        "each finding expands the attacker's control surface",
        "all members",
    ):
        assert unsupported_claim not in text




