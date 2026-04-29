"""Precision fixtures — enforces the 'subtle safe-vs-unsafe' distinctions
called out in the improvement report (Phase 3, item 14).

Each test runs the real engine on a fixture file and asserts on the
shape of the findings, not just "did something fire".  The whole point
of these fixtures is to catch a future regression where a rule tweak
would flip a safe pattern into a false-positive alarm, or silently
downgrade a dangerous pattern into "medium".

Fixtures live in ``tests/fixtures/precision/``.  Each fixture file
starts with a comment block naming the report scenario it represents
and the expected behavior — keep the file and the test assertion in
sync when adjusting either.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform, Severity
from taintly.rules.registry import load_all_rules

_FIX = Path(__file__).parent.parent / "fixtures" / "precision"
_SAFE_GH = Path(__file__).parent.parent / "fixtures" / "github" / "safe"


@pytest.fixture(scope="module")
def gh_rules():
    return [r for r in load_all_rules() if r.platform == Platform.GITHUB]


# ---------------------------------------------------------------------------
# pull_request_target + permissions:{} + no checkout + no secrets
#
# Report: "Review-needed or lower priority, not top-severity alarm"
# ---------------------------------------------------------------------------


def test_benign_pr_target_is_review_needed_not_top_alarm(gh_rules):
    findings = scan_file(str(_FIX / "pr_target_benign.yml"), gh_rules)
    # SEC4-GH-002 should fire — the trigger IS present.
    sec4_002 = [f for f in findings if f.rule_id == "SEC4-GH-002"]
    assert sec4_002, "SEC4-GH-002 must detect the pull_request_target trigger"

    # But every SEC4-GH-002 finding here must carry review_needed = True
    # and NOT be surfaced as a confirmed top-severity risk.
    for f in sec4_002:
        assert f.review_needed is True, (
            f"SEC4-GH-002 on a benign pull_request_target must be review-needed, "
            f"got review_needed={f.review_needed}"
        )

    # Exploitability should be LOW — no checkout, no secrets, empty
    # permissions block means there's nothing to steal.
    privileged_findings = [f for f in findings if f.finding_family == "privileged_pr_trigger"]
    assert privileged_findings, "privileged_pr_trigger family must have at least one finding"
    for f in privileged_findings:
        assert f.exploitability == "low", (
            f"{f.rule_id} in a benign PR-target workflow should be exploitability=low, "
            f"got {f.exploitability!r}"
        )


# ---------------------------------------------------------------------------
# Unpinned action in a release workflow with contents: write
#
# Report: "Strong finding"
# ---------------------------------------------------------------------------


def test_unpinned_release_is_high_exploitability(gh_rules):
    findings = scan_file(str(_FIX / "unpinned_release.yml"), gh_rules)
    unpinned = [f for f in findings if f.rule_id in ("SEC3-GH-001", "SEC3-GH-002")]
    assert unpinned, "Unpinned action in a release workflow must fire SEC3-GH-001/002"

    for f in unpinned:
        assert f.exploitability == "high", (
            f"{f.rule_id} in release+write context should be exploitability=high, "
            f"got {f.exploitability!r}"
        )
        assert f.finding_family == "supply_chain_immutability"
        assert f.severity >= Severity.HIGH


# ---------------------------------------------------------------------------
# SHA-pinned reusable workflow with minimal permissions
#
# Report: "No mutable-reference finding"
# ---------------------------------------------------------------------------


def test_sha_pinned_reusable_produces_no_mutable_findings(gh_rules):
    findings = scan_file(str(_FIX / "pinned_reusable_minimal.yml"), gh_rules)
    mutable = [f for f in findings if f.finding_family == "supply_chain_immutability"]
    rule_ids = [f.rule_id for f in mutable]
    assert not mutable, (
        f"SHA-pinned reusable workflow with minimal permissions must produce NO "
        f"mutable-reference findings, but got: {rule_ids}"
    )


# ---------------------------------------------------------------------------
# workflow_dispatch input routed through a step env var
#
# Report: "Lower or no injection finding"
# ---------------------------------------------------------------------------


def test_safe_workflow_dispatch_env_routing_does_not_fire_injection(gh_rules):
    findings = scan_file(str(_FIX / "workflow_dispatch_safe_input.yml"), gh_rules)
    injection = [f for f in findings if f.finding_family == "script_injection"]

    # If any script-injection rule fires, it must not be high-exploitability
    # and it must not be severity CRITICAL — the value never reaches the
    # run: block as a raw expansion.
    for f in injection:
        assert f.severity < Severity.CRITICAL, (
            f"Safe env-routed workflow_dispatch input triggered CRITICAL "
            f"injection finding ({f.rule_id}) — false positive"
        )
        assert f.exploitability != "high", (
            f"Safe env-routed workflow_dispatch input produced a HIGH-"
            f"exploitability injection finding ({f.rule_id})"
        )


# ---------------------------------------------------------------------------
# Placeholder password for local keychain setup
#
# Report: "Do not classify as likely secret without stronger evidence"
# ---------------------------------------------------------------------------


def test_placeholder_password_not_treated_as_confirmed_secret(gh_rules):
    """The placeholder 'temp-keychain-pw' must not be flagged as a real
    leaked secret.  Rules that identify genuine checkout / credential-
    persistence behavior are allowed to fire (they target structure,
    not the placeholder string) — only rules that do pattern-based
    secret-string heuristics are in scope.
    """
    findings = scan_file(str(_FIX / "placeholder_password.yml"), gh_rules)

    # Secret-string heuristic rules are the ones whose confidence was
    # explicitly downgraded from the default in taintly.families.
    # If any of THOSE fire, they must be confidence<high AND must match
    # the placeholder text specifically.
    from taintly.families import default_confidence
    for f in findings:
        if default_confidence(f.rule_id) == "high":
            continue  # High-confidence structural rules are not in scope
        if "temp-keychain-pw" in (f.snippet or ""):
            assert f.confidence != "high", (
                f"{f.rule_id} classified the placeholder password with HIGH confidence"
            )


# ---------------------------------------------------------------------------
# SEC5-GH-001 — modern OIDC publishers (uv / twine / cargo / npm)
#
# Workflows that grant ``id-token: write`` and invoke a modern
# trusted-publishing command via ``run:`` legitimately need the
# permission.  SEC5-GH-001 must not fire on these.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture_name",
    [
        "oidc_uv_publish.yml",
        "oidc_twine_use_oidc.yml",
        "oidc_cargo_publish.yml",
        "oidc_npm_provenance.yml",
    ],
)
def test_oidc_shell_publishers_do_not_trip_sec5_gh_001(fixture_name, gh_rules):
    findings = scan_file(str(_SAFE_GH / fixture_name), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC5-GH-001"]
    assert not fired, (
        f"{fixture_name}: SEC5-GH-001 fired on a workflow with a "
        f"recognised shell-form OIDC publisher: {fired}"
    )
