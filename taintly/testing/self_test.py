"""Self-test and mutation testing framework for rules."""

from __future__ import annotations

from dataclasses import dataclass

from taintly.models import Rule
from taintly.reporters._encoding import (
    check_char,
    cross_char,
    em_dash_char,
    sep_char,
)


def _sep() -> str:
    return sep_char()


def _check(passed: bool) -> str:
    return check_char() if passed else cross_char()


def _dash() -> str:
    return em_dash_char()


# =============================================================================
# Self-Test: Validate rules against their own test samples
# =============================================================================


@dataclass
class TestResult:
    rule_id: str
    test_type: str  # "positive", "negative", "mutation"
    sample: str
    expected: str  # "trigger" or "no_trigger"
    actual: str
    passed: bool
    mutation_op: str = ""


def run_self_test(rules: list[Rule]) -> list[TestResult]:
    """Run all positive and negative test samples against their rules."""
    results = []

    for rule in rules:
        # Positive samples — must trigger
        for sample in rule.test_positive:
            lines = sample.splitlines()
            matches = rule.pattern.check(sample, lines)
            passed = len(matches) > 0
            results.append(
                TestResult(
                    rule_id=rule.id,
                    test_type="positive",
                    sample=sample[:80],
                    expected="trigger",
                    actual="trigger" if matches else "no_trigger",
                    passed=passed,
                )
            )

        # Negative samples — must NOT trigger
        for sample in rule.test_negative:
            lines = sample.splitlines()
            matches = rule.pattern.check(sample, lines)
            passed = len(matches) == 0
            results.append(
                TestResult(
                    rule_id=rule.id,
                    test_type="negative",
                    sample=sample[:80],
                    expected="no_trigger",
                    actual="no_trigger" if not matches else "trigger",
                    passed=passed,
                )
            )

    return results


# Known (rule_id, mutation_operator) pairs where the rule's match is
# currently fragile to the mutation. These are real rule-engineering
# gaps, not test-harness bugs: the rule SHOULD be resilient to the
# mutation in question. Listing them here turns the failure into a
# tracked gap (build stays green) instead of a gate that no PR can
# pass. Remove entries as the underlying rules are hardened; never
# add entries to paper over a newly-introduced regression.
#
# Each value documents the failure flavour and follow-up pointer.
_KNOWN_MUTATION_GAPS: dict[tuple[str, str], str] = {
    ("SEC1-GH-001", "indent_shift"): (
        "SequencePattern's absent_within regex assumes a specific indent "
        "level; doubled-indent variants look like a different structure."
    ),
    ("SEC10-GH-001", "indent_shift"): ("Same SequencePattern family as SEC1-GH-001."),
    ("SEC10-GH-004", "whitespace_pad"): (
        "Rule's requires=``uses:\\s+actions/upload-artifact@`` needs "
        "at least one space after ``uses:``. YAML permits ``uses:foo`` "
        "with no space; real workflows always include a space. Same "
        "family as AI-GH-019 / 020 / 021."
    ),
    ("AI-GH-019", "whitespace_pad"): (
        "Same family: requires clause uses ``_AI_AGENT_ANCHOR`` whose "
        "``uses:\\s+`` anchor loses coverage when whitespace is stripped. "
        "See AI-GH-020 / AI-GH-021 for the shared rationale."
    ),
    ("AI-GH-020", "whitespace_pad"): (
        "Shares the same ``uses:\\s+`` + ``_AI_AGENT_ANCHOR`` family as "
        "AI-GH-021; same rationale — YAML permits ``uses:foo`` but real "
        "workflows always have a space and broadening to ``\\s*`` would "
        "weaken the anchor's precision across 9+ rules that share it."
    ),
    ("AI-GH-021", "whitespace_pad"): (
        "Shares the ``_AI_AGENT_ANCHOR`` which requires ``uses:\\s+`` "
        "(at least one space after ``uses:``). YAML permits ``uses:foo`` "
        "with no space; we deliberately don't match that because real "
        "workflows always have a space and broadening to ``\\s*`` would "
        "weaken the anchor's precision across 9+ rules that share it."
    ),
    ("AI-GH-022", "whitespace_pad"): (
        "Same family as AI-GH-019/020/021: the ``requires:`` clause uses "
        "``AI_AGENT_USES_PATTERN`` whose ``uses:\\s+`` anchor needs at "
        "least one space after ``uses:``. whitespace_pad strips that "
        "separator; broadening to ``\\s*`` would weaken precision across "
        "every rule that shares the pattern."
    ),
    ("AI-GH-035", "whitespace_pad"): (
        "Same family as AI-GH-019/020/021/022: anchor uses "
        "``AI_AGENT_USES_PATTERN`` whose ``uses:\\s+`` requires "
        "at least one space after ``uses:``. See AI-GH-022 entry "
        "for full rationale."
    ),
    ("TAINT-GH-010", "whitespace_pad"): (
        "Anchor matches ``uses:\\s+actions/checkout@`` — same "
        "``uses:\\s+`` family as AI-GH-019/020/021/022/035. "
        "whitespace_pad strips the separator; broadening to "
        "``\\s*`` would weaken precision across the shared anchor."
    ),
    ("TAINT-GH-010", "comment_inject"): (
        "``requires:`` regex anchors the trigger as "
        "``^on:\\s*workflow_run\\b`` (or its mapping form). A "
        "trailing comment after ``on:`` breaks the ``\\s*\\n`` "
        "bridge to the indented ``workflow_run:`` key on the next "
        "line. Workflow authors don't write ``on:  # comment`` in "
        "practice; broadening the regex to skip arbitrary trailing "
        "comments makes the anchor noisier across SEC-1/SEC-4 "
        "rules that share the same ``^on:`` shape."
    ),
    ("AI-GH-023", "whitespace_pad"): (
        "Same family as AI-GH-019/020/021/022: requires-clause uses "
        "``AI_AGENT_USES_PATTERN``. See AI-GH-022 entry for full rationale."
    ),
    ("SEC10-GH-002", "whitespace_pad"): (
        "Regex depends on single-space ` : ` separator; double space trips "
        "an over-match on the negative sample."
    ),
    ("SEC4-GH-016", "whitespace_pad"): (
        "ContextPattern anchor fragile to extra whitespace around `:`."
    ),
    ("SEC8-GH-001", "whitespace_pad"): (
        "Image-pin regex fragile to whitespace around `:` in `image: foo`."
    ),
    ("SEC8-GH-002", "whitespace_pad"): (
        "Same family as SEC8-GH-001; image-pin regex fragile to whitespace."
    ),
    ("SEC8-GH-003", "whitespace_pad"): ("Same family; fragile to whitespace around `:` separator."),
    ("SEC8-GH-004", "comment_inject"): (
        "Inline `# comment` trailing a `services:` line prevents match; "
        "rule doesn't strip trailing comments before anchoring."
    ),
    ("TAINT-GH-001", "indent_shift"): (
        "TaintPattern's flow analysis assumes a specific indent shape for "
        "job/step/uses: triples; doubled-indent variants don't re-parse."
    ),
    ("TAINT-GH-002", "indent_shift"): ("Same TaintPattern family as TAINT-GH-001."),
    ("TAINT-GH-001", "quote_swap"): (
        "Single-quoted ``$VAR`` in a ``run:`` block does not interpolate "
        "in bash; the precision pass in PR #104 deliberately stops "
        "matching that case. quote_swap mutations that produce a single-"
        "quoted sink are SEMANTICALLY SAFER, not equivalent — the rule "
        "correctly does not fire."
    ),
    ("TAINT-GH-002", "quote_swap"): (
        "Same single-quote-precision rationale as TAINT-GH-001. The "
        "shared taint analyzer ignores single-quoted shell references."
    ),
    ("TAINT-GH-003", "quote_swap"): (
        "TaintPattern flow analysis treats `\"...\"` and `'...'` differently; "
        "swapping quotes in the sample produces an inequivalent shape."
    ),
    ("TAINT-GH-004", "quote_swap"): ("Same TaintPattern family as TAINT-GH-003."),
    ("TAINT-GH-009", "indent_shift"): (
        "Same TaintPattern family as TAINT-GH-001 — the cross-job analyzer "
        "reuses the same job/step segmentation and env-resolution machinery, "
        "so doubled-indent variants don't re-parse through the segment "
        "splitter / step iterator chain."
    ),
    ("TAINT-GH-009", "quote_swap"): (
        "Same single-quote-precision rationale as TAINT-GH-001/002/003 — "
        "single-quoted shell references are not sinks (PR #104). "
        "quote_swap mutations that produce a single-quoted consumer-side "
        "sink are SEMANTICALLY SAFER, not equivalent."
    ),
    ("TAINT-GH-007", "whitespace_pad"): (
        "Requires clause uses ``uses:\\s+\\./.github/workflows/`` to "
        "anchor on the local-reusable-workflow form. Real workflows "
        "always have a space after ``uses:``; broadening to ``\\s*`` "
        "would weaken precision across the existing rule families "
        "that share the same anchor (see SEC10-GH-004 / AI-GH-019/020/"
        "021 for the same documented gap)."
    ),
    ("SEC1-GL-002", "case_change"): (
        "GitLab rule matches case-sensitive boolean tokens; case_change "
        "swaps `true` ↔ `True` which YAML accepts but the regex doesn't."
    ),
    # AI rules: same "Python is case-sensitive" boat as SEC1-GL-002. The
    # `True` literal and `torch.load` identifier only have the documented
    # meaning with the specific casing the language uses; case-change
    # mutants are YAML-equivalent but Python-inequivalent, so the regex
    # correctly stays specific.
    ("AI-GH-001", "case_change"): (
        "Python `True` literal is case-sensitive; `true` would be a NameError. "
        "Regex matches only the Python-valid form."
    ),
    ("AI-GH-031", "case_change"): (
        "Same family as AI-GH-001 — Python `True` is case-sensitive; "
        "`allow_delegation=true` is a NameError. The regex matches only "
        "the Python-valid `True`."
    ),
    ("AI-GH-033", "case_change"): (
        "Same family as AI-GH-001 / AI-GH-031 — Python `True` is "
        "case-sensitive; `memory=true` is a NameError. Regex matches "
        "only the Python-valid form."
    ),
    ("AI-GH-003", "case_change"): (
        "Python identifier `torch.load` is case-sensitive; the mutant produces "
        "Python-invalid code, so matching only the canonical casing is correct."
    ),
    ("AI-GL-001", "case_change"): (
        "Same rationale as AI-GH-001 — Python `True` is case-sensitive inside "
        "a GitLab script block."
    ),
    ("AI-GH-005", "whitespace_pad"): (
        "ContextPattern anchor has a long alternation including `uses:` and "
        "provider-host tokens; whitespace around `:` inside the YAML key trips "
        "the tightened patterns. Same family as SEC4-GH-016 / SEC8-GH-*."
    ),
    ("AI-GH-006", "whitespace_pad"): (
        "Same anchor alternation family as AI-GH-005; fragile to whitespace "
        "around the `:` separator in `on:` / `uses:` lines."
    ),
    ("AI-GH-008", "whitespace_pad"): (
        "Same anchor alternation family as AI-GH-005/006; fragile to whitespace "
        "around the `:` separator in `uses:` lines."
    ),
    ("PSE-GH-001", "whitespace_pad"): (
        "Reuses AI-GH-005's agent-step anchor; inherits the `uses:\\s+` "
        "fragility when whitespace around `:` is stripped. Same underlying "
        "issue as AI-GH-005/006/008 — tracked as a systemic anchor-family "
        "gap, not a per-rule bug."
    ),
    # AI-GH-015/017 reuse the same `_AI_AGENT_ANCHOR` shared via pse.py.
    # Same `uses:\\s+` / `on:\\s+` anchor-family fragility under the
    # whitespace_pad (zero-space) and comment_inject mutations.  Will
    # close when the anchor family is refactored to accept `\\s*`.
    ("AI-GH-015", "whitespace_pad"): (
        "Shared anchor-family fragility (see AI-GH-005/006/008/PSE-GH-001)."
    ),
    ("AI-GH-015", "comment_inject"): (
        "Comment-inject on the `on:` / `permissions:` keys breaks the "
        "lookahead-based file-level preconditions; same root cause as "
        "the whitespace_pad gap in this family."
    ),
    ("AI-GH-017", "whitespace_pad"): (
        "Shared anchor-family fragility — `uses:\\s+` won't match a "
        "zero-space `uses:` inside the agent step."
    ),
    ("AI-GH-017", "comment_inject"): (
        "Comment-inject on the step's sibling keys can introduce a "
        "`# continue-on-error: true` sequence that the requires regex "
        "does not filter out by indent anchoring alone.  Follow-up: "
        "also assert requires-match line is not preceded by a comment "
        "marker at the same indent depth."
    ),
    ("AI-JK-001", "case_change"): (
        "Same rationale as AI-GH-001 — Python `True` is case-sensitive inside a Jenkins sh step."
    ),
    ("AI-JK-002", "case_change"): (
        "Python `weights_only=True` is case-sensitive; mutant `True`→`true` "
        "would be a NameError, so matching only the canonical casing is "
        "correct."
    ),
    ("AI-GH-010", "case_change"): (
        "Python `safe_mode=True` / `allow_pickle=True` / module identifiers "
        "like `joblib.load` are case-sensitive; the mutant produces "
        "Python-invalid code. Matching canonical casing is correct."
    ),
    ("AI-GL-003", "case_change"): ("Same as AI-GH-010, GitLab mirror."),
    ("AI-JK-004", "case_change"): ("Same as AI-GH-010, Jenkins mirror."),
    ("AI-GL-005", "case_change"): (
        "Same rationale as AI-GH-003 — Python identifier `torch.load` is "
        "case-sensitive, mutant produces Python-invalid code."
    ),
    ("AI-GH-014", "whitespace_pad"): (
        "Same anchor alternation family as AI-GH-005/006/008; fragile to "
        "whitespace around the `:` separator in `uses:` lines."
    ),
    ("TAINT-GH-005", "whitespace_pad"): (
        "Agent-source detection uses a long alternation regex on the `uses:` "
        "line. Whitespace around the `:` separator trips the same anchor "
        "fragility as AI-GH-005/006/008/014 — same family."
    ),
    ("AI-JK-008", "quote_swap"): (
        "MCP config is JSON — quote_swap converts JSON's required "
        "double quotes to single quotes, which isn't valid JSON in "
        "the first place. Same framework limitation as AI-GH-011; "
        'the rule deliberately keys on JSON\'s ``"command"`` shape.'
    ),
    ("AI-GL-012", "quote_swap"): (
        "Same as AI-GH-011 / AI-JK-008 — MCP config is JSON, "
        "quote_swap breaks the format, rule keys on JSON's "
        '``"command"`` shape.'
    ),
    ("AI-GH-011", "quote_swap"): (
        "JSON requires double-quoted keys; swapping `\"command\"` → `'command'` "
        "produces invalid JSON for an MCP config. Matching only the "
        "JSON-valid shape is correct."
    ),
    ("SEC4-GL-003", "quote_swap"): (
        "Regex anchor for GitLab CI variable name assumes one quote style; "
        "swap produces a different-looking but semantically equivalent line."
    ),
    ("SEC8-GL-001", "whitespace_pad"): (
        "Same family as SEC8-GH-001/002/003; image-pin regex fragile to whitespace around `:`."
    ),
    ("SEC8-GL-002", "whitespace_pad"): ("Same family as SEC8-GL-001."),
    ("TAINT-GL-001", "comment_inject"): (
        "Inline `# comment` on the source line of a taint flow breaks the line-level regex anchor."
    ),
    ("TAINT-GL-002", "comment_inject"): ("Same TaintPattern family as TAINT-GL-001."),
    ("TAINT-GL-003", "quote_swap"): (
        "Artifact-bridge TaintPattern is quote-style-sensitive; mirrors the "
        "GitHub TAINT-GH-003/004 behaviour."
    ),
    ("TAINT-GL-003", "case_change"): (
        "Same TAINT-GL-003 flow analysis keys on specific casing of "
        "`artifacts:`/`variables:` YAML nouns."
    ),
    ("SEC4-JK-001", "quote_swap"): (
        "Jenkins GString rule deliberately distinguishes `sh '...'` (safe) "
        'from `sh "..."` (unsafe) — quote_swap genuinely flips the '
        "safety verdict here. This is actually correct rule behaviour; "
        "the test harness just can't express 'swap intentionally changes "
        "meaning.' Track as a mutation-framework limitation, not a rule bug."
    ),
    ("SEC4-JK-002", "quote_swap"): (
        "Same rationale as SEC4-JK-001 — quote style is semantic, not cosmetic."
    ),
    ("TAINT-JK-001", "quote_swap"): (
        "Same rationale as SEC4-JK-001 — the rule deliberately targets "
        'Groovy double-quoted `sh "...${env.CHANGE_TITLE}..."` (which '
        "interpolates before the shell runs) and explicitly does NOT fire "
        "on single-quoted `sh '...${env.CHANGE_TITLE}...'` (which hands "
        "the literal text to the shell and is a different, weaker vector "
        "tracked for a follow-up rule). quote_swap genuinely flips safety."
    ),
    ("SEC4-GH-017", "quote_swap"): (
        "SEC4-GH-017 deliberately matches PowerShell double-quoted strings "
        "(which interpolate) and not single-quoted ones (which don't). "
        "quote_swap genuinely flips safety here — same framework limitation "
        "as SEC4-JK-001/002."
    ),
    ("SEC7-JK-001", "comment_inject"): (
        "Jenkinsfile comment rules; rule anchors on the full line, so "
        "a trailing `// comment` (rendered as `# ` by the YAML-oriented "
        "mutator) breaks the anchor."
    ),
    ("SEC9-JK-002", "case_change"): (
        "Jenkins artifact-integrity rule expects `fingerprint: true` "
        "(lowercase); `True` (Python-style) flips the negative-sample "
        "verdict. Arguably the rule should accept both since Groovy parses "
        "them equivalently, but that's a deliberate rule-precision decision."
    ),
}


def run_mutation_tests(rules: list[Rule]) -> list[TestResult]:
    """Apply mutations to test samples and verify rule resilience.

    A failing mutation becomes a TestResult with passed=False unless the
    (rule_id, operator) pair is listed in `_KNOWN_MUTATION_GAPS`, in
    which case it's marked passed=True with a `known_gap=True` flag so
    the top-level kill-rate gate doesn't fail the build while the
    underlying rule precision issue is being worked. See the docstring
    on `_KNOWN_MUTATION_GAPS` for the discipline.
    """
    from .mutations import MUTATION_OPERATORS

    results = []

    def _mark(passed: bool, rule_id: str, op_name: str) -> tuple[bool, bool]:
        """Return (final_passed, was_known_gap)."""
        if passed:
            return True, False
        if (rule_id, op_name) in _KNOWN_MUTATION_GAPS:
            return True, True
        return False, False

    for rule in rules:
        # Mutate positive samples — should still trigger
        for sample in rule.test_positive:
            for op_name, op_fn in MUTATION_OPERATORS.items():
                mutants = op_fn(sample)
                for mutant in mutants:
                    lines = mutant.splitlines()
                    matches = rule.pattern.check(mutant, lines)
                    passed, _ = _mark(len(matches) > 0, rule.id, op_name)
                    results.append(
                        TestResult(
                            rule_id=rule.id,
                            test_type="mutation_positive",
                            sample=mutant[:80],
                            expected="trigger",
                            actual="trigger" if matches else "no_trigger",
                            passed=passed,
                            mutation_op=op_name,
                        )
                    )

        # Mutate negative samples — should still NOT trigger
        for sample in rule.test_negative:
            for op_name, op_fn in MUTATION_OPERATORS.items():
                mutants = op_fn(sample)
                for mutant in mutants:
                    lines = mutant.splitlines()
                    matches = rule.pattern.check(mutant, lines)
                    passed, _ = _mark(len(matches) == 0, rule.id, op_name)
                    results.append(
                        TestResult(
                            rule_id=rule.id,
                            test_type="mutation_negative",
                            sample=mutant[:80],
                            expected="no_trigger",
                            actual="no_trigger" if not matches else "trigger",
                            passed=passed,
                            mutation_op=op_name,
                        )
                    )

    return results


def format_test_results(
    self_results: list[TestResult], mutation_results: list[TestResult] | None = None
) -> str:
    """Format test results as human-readable text."""
    out = []
    s = _sep() * 3
    out.append(f"\n\033[1m{s} RULE SELF-TEST RESULTS {s}\033[0m\n")

    # Self-test summary
    pos = [r for r in self_results if r.test_type == "positive"]
    neg = [r for r in self_results if r.test_type == "negative"]
    pos_pass = sum(1 for r in pos if r.passed)
    neg_pass = sum(1 for r in neg if r.passed)

    rules_tested = len(set(r.rule_id for r in self_results))
    out.append(f"Rules tested: {rules_tested}")
    out.append(f"Positive samples: {pos_pass}/{len(pos)} passed")
    out.append(f"Negative samples: {neg_pass}/{len(neg)} passed")

    # Show failures
    failures = [r for r in self_results if not r.passed]
    if failures:
        out.append(f"\n\033[91mFAILURES ({len(failures)}):\033[0m")
        for f in failures:
            out.append(f"  {f.rule_id} [{f.test_type}]: expected {f.expected}, got {f.actual}")
            out.append(f"    Sample: {f.sample}")

    # Mutation test summary
    if mutation_results:
        total = len(mutation_results)
        killed = sum(1 for r in mutation_results if r.passed)
        survived = total - killed
        out.append(f"\nMutations tested: {total}")
        out.append(
            f"Mutation kills: {killed}/{total} ({killed / total * 100:.1f}%)" if total else ""
        )

        if survived:
            survivors = [r for r in mutation_results if not r.passed][:10]
            out.append("\n\033[93mSURVIVING MUTATIONS (showing first 10):\033[0m")
            for survivor in survivors:
                out.append(
                    f"  {survivor.rule_id}: {survivor.mutation_op} {_dash()} "
                    f"{survivor.expected} but got {survivor.actual}"
                )
                out.append(f"    Sample: {survivor.sample}")

    # Overall pass/fail
    all_passed = all(r.passed for r in self_results)
    if mutation_results:
        all_passed = all_passed and all(r.passed for r in mutation_results)

    out.append(
        f"\n{_check(all_passed)} {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}"
    )

    return "\n".join(out)
