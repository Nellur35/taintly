"""Rule-pack consistency — registry-wide invariants on every Rule.

The per-platform sanity checks in tests/integration/test_all_rules_clean.py
catch missing test samples and duplicate IDs. This file goes further —
it asserts metadata invariants that are easy to silently rot as the
rule pack grows past 200 entries:

  * Every CRITICAL / HIGH rule has at least one positive AND one
    negative sample (lower-severity rules can opt out via _is_stub_rule).
  * Every CRITICAL rule maps to a documented OWASP CICD-SEC-* category.
  * Every rule referencing an incident has a structured form (URL or
    CVE), not free text — keeps the link machine-checkable.
  * No two rules' positive samples are bit-identical with conflicting
    expected outcomes (a sign someone copy-pasted between rules).

The severity histogram is printed (not asserted) so silent severity
drift gets a visible signal in CI logs, but adding one MEDIUM rule
doesn't fail the build.
"""

from __future__ import annotations

import re

import pytest

from taintly.models import AbsencePattern, Platform, Rule, Severity
from taintly.rules.registry import load_all_rules


@pytest.fixture(scope="module")
def all_rules() -> list[Rule]:
    return load_all_rules()


def _is_stub_rule(rule: Rule) -> bool:
    """Mirror of the integration-test stub filter — rules that opt out
    of per-file sample contracts."""
    from taintly.gitlab_workflow_corpus import GitLabCorpusPattern
    from taintly.rules.github.sec3_sec4_supply_chain_ppe import ImposterCommitPattern
    from taintly.workflow_corpus import CorpusPattern

    if isinstance(rule.pattern, CorpusPattern):
        return True
    # GitLabCorpusPattern is the GL parallel — same stub treatment.
    # Composer/CHAIN-GL-* rules have no per-file sample shape because
    # their evidence is the resolved-corpus join across the entry file
    # plus its local includes.
    if isinstance(rule.pattern, GitLabCorpusPattern):
        return True
    if isinstance(rule.pattern, ImposterCommitPattern):
        return True
    if (
        getattr(rule, "review_needed", False)
        and rule.severity == Severity.INFO
        and getattr(rule, "finding_family", "") == "Mutable dependency references"
    ):
        return True
    return (
        isinstance(rule.pattern, AbsencePattern)
        and "INTENTIONALLY_DISABLED" in rule.pattern.absent
    )


# ---------------------------------------------------------------------------
# Severity-driven sample contract
# ---------------------------------------------------------------------------


def test_high_severity_rules_have_both_sample_polarities(all_rules):
    """Every CRITICAL / HIGH rule must ship at least one positive AND
    one negative sample. These are the rules where a precision
    regression matters most; the per-file sample contract enforced
    elsewhere only requires either polarity. Catching the gap here
    means a CRITICAL rule with positive samples but no negative
    samples (which would never be tested for false positives) trips
    a loud test failure."""
    missing = []
    for r in all_rules:
        if _is_stub_rule(r):
            continue
        if r.severity not in (Severity.CRITICAL, Severity.HIGH):
            continue
        if not r.test_positive:
            missing.append((r.id, "no positive samples"))
        if not r.test_negative:
            missing.append((r.id, "no negative samples"))
    assert not missing, (
        f"{len(missing)} CRITICAL/HIGH rules are missing one or both "
        f"sample polarities: {missing}"
    )


# ---------------------------------------------------------------------------
# OWASP / metadata contracts
# ---------------------------------------------------------------------------


_OWASP_RE = re.compile(r"^CICD-SEC-(?:[1-9]|10)$")


def test_critical_rules_map_to_valid_owasp(all_rules):
    """CRITICAL rules MUST cite a valid OWASP CI/CD Top 10 category.
    The OWASP framework caps at SEC-10; anything else is either a
    typo or a rule that needs a different-scoped category. Kept
    CRITICAL-only because lower-severity rules sometimes legitimately
    encode posture / hygiene checks that don't map cleanly."""
    bad = [
        (r.id, r.owasp_cicd) for r in all_rules
        if r.severity == Severity.CRITICAL and not _OWASP_RE.match(r.owasp_cicd or "")
    ]
    assert not bad, (
        f"CRITICAL rules with missing/invalid owasp_cicd: {bad}. "
        f"Expected format: 'CICD-SEC-1' through 'CICD-SEC-10'."
    )


_INCIDENT_REF_RE = re.compile(
    r"(?:https?://\S+|CVE-\d{4}-\d{4,7})", re.IGNORECASE
)


# Baseline of currently-unstructured incident references. Many AI-GH
# rules cite informal write-ups by name ("Stawinski — Trusting Claude
# With a Knife") rather than a URL. Cleaning these up touches a lot
# of rules and is independent work; for now this gate fails when the
# count GROWS — same growth-only discipline as
# taintly/testing/self_test.py::_KNOWN_MUTATION_GAPS. Lower this
# number as you replace free-text references with URL / CVE IDs.
_INCIDENT_REF_BASELINE = 109  # ported fine-tuned rules use more structured refs (shrink)


def test_incident_references_are_structured_no_growth(all_rules):
    """Every entry in ``rule.incidents`` should look like a URL or a
    CVE ID — free-text descriptions ("the trivy attack") rot as
    headlines age. We can't fix all the existing free-text references
    in this PR, but we CAN prevent NEW ones from being added: this
    gate fails if the count exceeds ``_INCIDENT_REF_BASELINE``.

    Allowed shapes:
      * https://… or http://… URLs
      * CVE-YYYY-NNNN (or longer NNNNN forms)

    To lower the baseline: replace free-text references with URL or
    CVE IDs in the rule definitions, then update the constant.
    """
    bad: list[tuple[str, str]] = []
    for r in all_rules:
        for incident in r.incidents:
            if not _INCIDENT_REF_RE.search(incident or ""):
                bad.append((r.id, incident))
    if len(bad) > _INCIDENT_REF_BASELINE:
        new_count = len(bad) - _INCIDENT_REF_BASELINE
        pytest.fail(
            f"{new_count} NEW unstructured incident reference(s) since "
            f"baseline of {_INCIDENT_REF_BASELINE}. New refs add free "
            f"text; please use a URL or CVE ID. Total now: {len(bad)}.\n"
            f"All current refs: {bad}"
        )
    if len(bad) < _INCIDENT_REF_BASELINE:
        # Shrinking is good; surface the new baseline so the constant
        # gets ratcheted down on the same PR.
        pytest.fail(
            f"unstructured incident reference count dropped to "
            f"{len(bad)} (baseline was {_INCIDENT_REF_BASELINE}). "
            f"Update _INCIDENT_REF_BASELINE in this file to {len(bad)} "
            f"so the gate stays meaningful."
        )


# ---------------------------------------------------------------------------
# No copy-paste collisions
# ---------------------------------------------------------------------------


# Same growth-only discipline as _INCIDENT_REF_BASELINE: 6 known
# overlaps exist today (e.g. ``- uses: tj-actions/changed-files@v40``
# is a positive sample for both SEC3-GH-004 and SEC3-GH-006 — both
# rules legitimately fire on the same incident-shaped line). New
# overlaps are flagged for review; reducing the count is a goal.
_DUPLICATE_POSITIVE_BASELINE = 9  # +3 from ported fine-tuned rules sharing sibling samples


def test_no_duplicate_positive_samples_across_rules_no_growth(all_rules):
    """If two rules share an exact positive sample, that's USUALLY a
    copy-paste mistake — rule samples should be the minimal YAML that
    triggers the rule, and the minimum YAML for two different rules
    should differ. Some legitimate overlap exists (incident-shaped
    samples that exercise multiple rules at once); we tolerate the
    current count and gate on growth, same discipline as
    ``_INCIDENT_REF_BASELINE``.

    Same-platform overlap is the main risk; cross-platform we tolerate
    (a YAML snippet that means the same thing on GitHub and GitLab
    is unusual but legal).

    To lower the baseline: refactor each shared sample into per-rule
    minimal samples, then update _DUPLICATE_POSITIVE_BASELINE.
    """
    seen: dict[tuple[str, str], list[str]] = {}
    for r in all_rules:
        for sample in r.test_positive:
            key = (r.platform.value, sample.strip())
            seen.setdefault(key, []).append(r.id)
    collisions = {
        sample[:80]: ids
        for (_, sample), ids in seen.items()
        if len(set(ids)) > 1
    }
    if len(collisions) > _DUPLICATE_POSITIVE_BASELINE:
        new_count = len(collisions) - _DUPLICATE_POSITIVE_BASELINE
        pytest.fail(
            f"{new_count} NEW shared positive sample(s) since baseline of "
            f"{_DUPLICATE_POSITIVE_BASELINE}. Two rules sharing a sample "
            f"is usually a copy-paste — make each rule's positive "
            f"sample minimal and distinguishing.\n"
            + "\n".join(f"  {sample!r} -> {ids}" for sample, ids in collisions.items())
        )
    if len(collisions) < _DUPLICATE_POSITIVE_BASELINE:
        pytest.fail(
            f"shared-sample count dropped to {len(collisions)} "
            f"(baseline was {_DUPLICATE_POSITIVE_BASELINE}). Update "
            f"_DUPLICATE_POSITIVE_BASELINE in this file to "
            f"{len(collisions)} so the gate stays meaningful."
        )


# ---------------------------------------------------------------------------
# Severity histogram — surfaces silent drift, doesn't gate
# ---------------------------------------------------------------------------


def test_print_severity_histogram(all_rules, capsys):
    """Print the severity histogram so CI logs surface silent drift
    over time. Doesn't assert any particular distribution because
    "the right shape" depends on what rules are landing.

    To inspect: ``pytest tests/unit/test_rule_pack_consistency.py -s``"""
    by_platform: dict[str, dict[str, int]] = {}
    for r in all_rules:
        by_platform.setdefault(r.platform.value, {}).setdefault(
            r.severity.value, 0
        )
        by_platform[r.platform.value][r.severity.value] += 1

    print()
    print("Severity histogram (by platform):")
    for platform in sorted(by_platform):
        counts = by_platform[platform]
        total = sum(counts.values())
        breakdown = ", ".join(
            f"{sev}={counts.get(sev, 0)}"
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        )
        print(f"  {platform:8s} ({total:3d}): {breakdown}")
