"""FP simulator — surfaces false-positive-prone rules before they merge.

The mirror image of mutation testing: instead of mutating a *rule* and
checking the tests still kill it, this mutates a rule's own positive
sample into a *benign* variant and checks the rule does NOT fire on it.
A rule that still fires on the benignised input is false-positive-prone.

The initial advisory release ships one mutator — ``comment_embed`` —
the only one shown to be artifact-free in proof-of-concept testing. It
moves each line the rule matched into a comment; a rule that still fires
is flagging inert, commented-out code (a rule lacking a ``^\\s*#``
exclude).

The runner is delta-correct: a rule is flagged only when a finding lands
on a line the mutator actually neutralised — not merely "some finding
still exists" (which would false-flag multi-anchor and absence rules).

This mode is ADVISORY: it reports, it does not fail the build. See the
``--fp-simulate`` CLI flag.
"""

from __future__ import annotations

from taintly.models import Platform, Rule

from .self_test import TestResult

# Absence / posture patterns report their finding at a non-causal line —
# there is no single line whose *content* triggered the match — so a
# line-delta mutator cannot probe them. Skip.
_SKIP_PATTERN_TYPES: frozenset[str] = frozenset(
    {
        "AbsencePattern",
        "_NoExplicitPermissionsPattern",
        "_OverbroadWorkflowPermissionsPattern",
    }
)


def _comment_embed(rule: Rule, lines: list[str], matched: set[int]) -> str:
    """Return the sample with every matched line moved into a comment.

    Indentation is preserved; the platform comment marker (``//`` for
    Jenkinsfiles, ``#`` for YAML) is inserted after the indent. The
    matched token is now inert, so a correct rule must not fire on it.
    """
    marker = "//" if rule.platform is Platform.JENKINS else "#"
    out: list[str] = []
    for i, line in enumerate(lines, start=1):
        if i in matched and line.strip():
            stripped = line.lstrip()
            indent = line[: len(line) - len(stripped)]
            out.append(f"{indent}{marker} {stripped}")
        else:
            out.append(line)
    return "\n".join(out)


def run_fp_simulation(rules: list[Rule]) -> list[TestResult]:
    """Run the FP simulator over ``rules``.

    For each rule, each ``test_positive`` sample is benignised by the
    ``comment_embed`` mutator and re-scanned. A ``TestResult`` with
    ``passed=False`` is produced when the rule still reports a finding on
    a line the mutator commented out — an unambiguous false positive.
    """
    results: list[TestResult] = []
    for rule in rules:
        if type(rule.pattern).__name__ in _SKIP_PATTERN_TYPES:
            continue
        for sample in rule.test_positive:
            lines = sample.splitlines()
            try:
                base = rule.pattern.check(sample, lines)
            except Exception:
                # A rule that crashes on its own sample is a self-test
                # failure — reported there, not the simulator's concern.
                continue
            matched = {ln for ln, _ in base}
            if not matched:
                continue
            variant = _comment_embed(rule, lines, matched)
            try:
                after = rule.pattern.check(variant, variant.splitlines())
            except Exception:
                continue
            fp_hits = [ln for ln, _ in after if ln in matched]
            results.append(
                TestResult(
                    rule_id=rule.id,
                    test_type="fp_sim",
                    sample=variant[:80],
                    expected="no_trigger",
                    actual="trigger" if fp_hits else "no_trigger",
                    passed=not fp_hits,
                    mutation_op="comment_embed",
                )
            )
    return results


def format_fp_results(results: list[TestResult], rules: list[Rule]) -> str:
    """Human-readable advisory report for ``--fp-simulate``."""
    by_id = {r.id: r for r in rules}
    failures = [r for r in results if not r.passed]
    flagged_ids = {r.rule_id: r.mutation_op for r in failures}
    out = ["", "=== FP SIMULATOR (advisory) ===", ""]
    out.append(f"Benign variants probed: {len(results)}")
    out.append(f"FP-prone rules:         {len(flagged_ids)}")
    out.append("")
    if not flagged_ids:
        out.append("OK: no rule fired on a benignised variant.")
        return "\n".join(out)
    out.append("Rules that fire on benignised (commented-out) input:")
    for rid, op in sorted(flagged_ids.items()):
        rule = by_id.get(rid)
        sev = rule.severity.value if rule else "?"
        out.append(f"  [{sev:8}] {rid:16} ({op})")
    out.append("")
    out.append("Advisory only — this does not fail the build.")
    return "\n".join(out)
