"""Drift sync between cross-step taint and single-step injection rules.

The cross-step taint analyzer (``taintly.taint._TAINTED_CONTEXTS``)
and the single-step injection regex
(``taintly.rules.github.sec3_sec4_supply_chain_ppe._DANGEROUS_GITHUB_CONTEXT_RE``)
must agree on which GitHub context expressions are attacker-controlled.
A drift between them lets the same attacker bytes escape one rule
even though the other catches them — a class of bug closed twice
in earlier work; this test prevents the next drift.

Same idea on the GitLab side: the variables enumerated in
``TAINT-GL-001``'s description and the regex in ``SEC4-GL-001``
must match.
"""

from __future__ import annotations

import re

from taintly.taint import _TAINTED_CONTEXTS


def _build_test_value(context_pattern: str) -> str:
    """Construct a literal interpolation that exercises the regex
    pattern.  The taint module stores patterns as escaped regex
    fragments; for sync-checking we need the real expression text.
    """
    # Each pattern is the escaped form of a dotted identifier path,
    # e.g. r"github\.event\.pull_request\.title".  Removing the
    # backslashes recovers the literal expression body.
    expr_body = context_pattern.replace(r"\.", ".")
    return f"${{{{ {expr_body} }}}}"


def test_every_tainted_context_is_caught_by_sec4_gh_004():
    """Every entry in ``_TAINTED_CONTEXTS`` must also be matched by
    ``_DANGEROUS_GITHUB_CONTEXT_RE``.  When they drift, the same
    attacker bytes appearing inline (without an intermediate
    ``env:`` hop) go unflagged even though the cross-step
    analyzer's list says they're tainted.
    """
    from taintly.rules.github.sec3_sec4_supply_chain_ppe import (
        _DANGEROUS_GITHUB_CONTEXT_RE,
    )

    misses: list[str] = []
    for ctx_pattern in _TAINTED_CONTEXTS:
        sample = _build_test_value(ctx_pattern)
        if not _DANGEROUS_GITHUB_CONTEXT_RE.search(sample):
            misses.append(ctx_pattern)

    assert not misses, (
        "Drift detected between _TAINTED_CONTEXTS (taint.py) and "
        "_DANGEROUS_GITHUB_CONTEXT_RE (sec3_sec4_supply_chain_ppe.py). "
        "These contexts are listed as tainted by the cross-step "
        "analyzer but not matched by the single-step injection regex; "
        "inline use of these expressions in a run: block goes "
        f"unflagged: {misses}"
    )


def test_gitlab_taint_variables_caught_by_single_step_rules():
    """Every attacker-controlled GitLab variable named in
    TAINT-GL-001's description must also be matched by some
    single-step rule.

    The single-step coverage is intentionally split across two
    rules: SEC4-GL-001 covers commit-message / MR-text shapes,
    SEC4-GL-004 covers branch-name shapes (different threat tier
    -- branch names are higher-frequency attacker-controlled
    inputs).  This test consults both regexes when verifying
    sync, so the cross-rule split doesn't register as drift.
    """
    from taintly.rules.gitlab.sec1_sec4_sec6_sec7_sec9 import RULES as GL_RULES
    from taintly.rules.gitlab.taint import RULES as GL_TAINT_RULES

    sec4_gl_001 = next(r for r in GL_RULES if r.id == "SEC4-GL-001")
    sec4_gl_003 = next(r for r in GL_RULES if r.id == "SEC4-GL-003")
    taint_gl_001 = next(r for r in GL_TAINT_RULES if r.id == "TAINT-GL-001")

    # SEC4-GL-001 covers commit-message / MR-text shapes;
    # SEC4-GL-003 covers branch-name / tag shapes (CI_COMMIT_REF_NAME,
    # CI_COMMIT_TAG, CI_BUILD_REF_NAME).
    single_step_patterns = (sec4_gl_001.pattern.match, sec4_gl_003.pattern.match)
    description = taint_gl_001.description
    described_vars = set(re.findall(r"\$(CI_[A-Z_]+)", description))

    misses: list[str] = []
    for var in sorted(described_vars):
        sample = f"echo ${var}"
        if not any(re.search(p, sample) for p in single_step_patterns):
            misses.append(var)

    assert not misses, (
        "Drift between TAINT-GL-001's description and the "
        "single-step rule coverage (SEC4-GL-001 + SEC4-GL-004). "
        "Either add to one of those rules' alternation or remove "
        f"from the description: {misses}"
    )
