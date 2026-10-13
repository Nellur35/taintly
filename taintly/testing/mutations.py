"""Mutation operators for rule resilience testing.

Each operator takes a sample string and returns a list of mutated variants.
Mutations should preserve the semantic meaning of the sample but change
surface-level formatting to test that rules aren't fragile.
"""

from __future__ import annotations

import re
from collections.abc import Callable


def mutate_whitespace_pad(sample: str) -> list[str]:
    """Add/remove whitespace around colons and equals."""
    mutations = []
    mutations.append(sample.replace(": ", ":  "))
    mutations.append(sample.replace(": ", ":"))
    mutations.append(sample.replace("= ", "=  "))
    return [
        m
        for m in mutations
        if m != sample
        and not _invalidates_actions_guard(sample, m, allow_guard_loss=True)
        and not _invalidates_supported_uses_mapping(sample, m)
    ]


def mutate_indent_shift(sample: str) -> list[str]:
    """Scale indentation depth while preserving YAML structure.

    Naive approaches — `re.sub(r"^( {2})", r"    ", ...)` or uniformly
    prefixing every line with two spaces — are WRONG for YAML. In YAML
    the column of the first non-whitespace byte determines parenthood:
    promoting `strategy:` from column 0 to column 2 silently demotes
    it from a top-level key to a (usually invalid) nested value. A
    rule that correctly stops firing on such a mutant would be flagged
    as a regression, even though the mutant is semantically unlike the
    original. The broken version of this function produced exactly
    that failure mode on SEC4-GH-011 and SEC4-GH-015.

    This version scales EVERY line's leading-whitespace count by a
    shared factor, preserving all parent/child relationships:

    * 2x scale — a sample indented {0, 2, 4} becomes {0, 4, 8}.
    * 0.5x scale — a sample indented {0, 4, 8} becomes {0, 2, 4}.

    Mutations that would fractionalise an indent (e.g. halving a
    {0, 2} sample would produce {0, 1}, semantically valid but
    atypical for hand-written YAML) are skipped. Lines that are
    empty or consist only of whitespace are passed through
    unchanged so trailing newlines survive.
    """
    lines = sample.splitlines(keepends=True)

    def _indent(line: str) -> int:
        stripped = line.lstrip(" ")
        # Lines that are empty or only-whitespace don't contribute to the
        # scale check; treat them as indent 0.
        return 0 if stripped in ("", "\n") else len(line) - len(stripped)

    indents = [_indent(line) for line in lines]
    nonzero = [i for i in indents if i > 0]
    if not nonzero:
        return []

    def _scale(factor: float) -> str | None:
        scaled_lines: list[str] = []
        for line, indent in zip(lines, indents, strict=True):
            if indent == 0:
                scaled_lines.append(line)
                continue
            new_indent = indent * factor
            if new_indent != int(new_indent):
                # Fractional indent — skip this mutation as not
                # representative of hand-written YAML.
                return None
            scaled_lines.append(" " * int(new_indent) + line.lstrip(" "))
        result = "".join(scaled_lines)
        return result if result != sample else None

    mutations = []
    for factor in (2.0, 0.5):
        scaled = _scale(factor)
        if scaled is not None:
            mutations.append(scaled)
    return mutations


def mutate_quote_swap(sample: str) -> list[str]:
    """Swap single and double quotes.

    Only emits a mutant when the swap preserves balanced quoting —
    `run: echo "it's fine"` naively becomes `run: echo "it"s fine"`,
    which is YAML-invalid and makes the rule's correct skip look like
    a miss to the harness (inflating the survivor count).
    """
    mutations = []
    for mutated in (sample.replace("'", '"'), sample.replace('"', "'")):
        if mutated == sample:
            continue
        # Unbalanced quote counts imply we mangled the input; a rule
        # that correctly skips a syntactically invalid mutant should
        # not be scored as a false negative.
        if mutated.count('"') % 2 != 0 or mutated.count("'") % 2 != 0:
            continue
        if _invalidates_actions_guard(sample, mutated):
            continue
        mutations.append(mutated)
    return mutations


def _invalidates_actions_guard(
    original: str, mutated: str, *, allow_guard_loss: bool = False
) -> bool:
    """Reject only a proved valid-to-invalid Actions guard transformation."""
    from taintly.parsers.gha_expr import ExprSyntaxError, parse
    from taintly.parsers.structural import EventKind, walk_workflow

    def guards(source: str) -> dict[tuple[object, ...], str] | None:
        result: dict[tuple[object, ...], str] = {}
        keys: set[tuple[object, ...]] = set()
        for leaf in walk_workflow(
            "workflow.yml", content=source, include_keys=True, include_merge_origins=True
        ):
            if leaf.kind in {EventKind.ERROR, EventKind.CUTOFF} or leaf.merge_origins:
                return None
            if leaf.kind is EventKind.MAP_KEY:
                if leaf.path in keys:
                    return None
                keys.add(leaf.path)
            path = leaf.path
            if (
                leaf.kind is EventKind.LEAF_SCALAR
                and leaf.value is not None
                and path[:1] == ("jobs",)
                and path[-1:] == ("if",)
                and len(path) in {3, 5}
                and isinstance(path[1], str)
                and (len(path) == 3 or (path[2] == "steps" and isinstance(path[3], int)))
            ):
                value = leaf.value.strip()
                if value.startswith("${{") and value.endswith("}}"):
                    value = value[3:-2].strip()
                result[path] = value
        return result

    before, after = guards(original), guards(mutated)
    if before is None or after is None:
        return False
    if before.keys() != after.keys():
        if not allow_guard_loss or not after.keys() < before.keys():
            return False
        for path in before.keys() - after.keys():
            try:
                parse(before[path])
            except (ExprSyntaxError, RecursionError):
                continue
            return True
        return False
    for path, value in before.items():
        try:
            parse(value)
        except (ExprSyntaxError, RecursionError):
            continue
        try:
            parse(after[path])
        except (ExprSyntaxError, RecursionError):
            return True
    return False


def _supported_uses_mappings(
    source: str, *, composite: bool | None = None
) -> dict[tuple[object, ...], str] | None:
    """Return exact supported invocation mappings, or None if parsing is ambiguous.

    This is a mutation-equivalence premise check, not a detector: it only
    recognizes supported structural `uses` leaves from the shared YAML
    walker and never searches source text or applies namespace policy.
    """
    from taintly.parsers.structural import EventKind, walk_workflow

    events = list(
        walk_workflow("workflow.yml", content=source, include_keys=True, include_merge_origins=True)
    )
    keys: set[tuple[object, ...]] = set()
    for event in events:
        if event.kind in {EventKind.ERROR, EventKind.CUTOFF} or event.merge_origins:
            return None
        if event.kind is EventKind.MAP_KEY:
            if event.path in keys:
                return None
            keys.add(event.path)
    if composite is None:
        composite = any(
            event.kind is EventKind.LEAF_SCALAR
            and event.path == ("runs", "using")
            and event.value == "composite"
            for event in events
        )
    result: dict[tuple[object, ...], str] = {}
    for event in events:
        path = event.path
        if (
            event.kind is not EventKind.LEAF_SCALAR
            or path[-1:] != ("uses",)
            or not (event.value or "").strip()
        ):
            continue
        job_step = (
            len(path) == 5
            and path[0] == "jobs"
            and isinstance(path[1], str)
            and path[2] == "steps"
            and isinstance(path[3], int)
        )
        reusable_call = len(path) == 3 and path[0] == "jobs" and isinstance(path[1], str)
        composite_step = (
            composite
            and len(path) == 4
            and path[:2] == ("runs", "steps")
            and isinstance(path[2], int)
        )
        standalone_step = len(path) == 2 and isinstance(path[0], int)
        if job_step or reusable_call or composite_step or standalone_step:
            result[path] = event.value or ""
    return result


def _invalidates_supported_uses_mapping(original: str, mutated: str) -> bool:
    """Reject a mutation only when a complete parse proves an invocation vanished."""
    before = _supported_uses_mappings(original)
    if before is None or not before:
        return False
    original_composite = any(path[:2] == ("runs", "steps") for path in before)
    after = _supported_uses_mappings(mutated, composite=original_composite)
    if after is None:
        return False
    return bool(before.keys() - after.keys())


def mutate_comment_inject(sample: str) -> list[str]:
    """Add inline comments."""
    mutations = []
    lines = sample.splitlines()
    for i, line in enumerate(lines):
        if line.strip() and not line.strip().startswith("#"):
            mutated = list(lines)
            mutated[i] = line + "  # comment"
            mutations.append("\n".join(mutated))
            break
    return mutations


def mutate_trailing_whitespace(sample: str) -> list[str]:
    """Add trailing whitespace."""
    lines = sample.splitlines()
    mutations = []
    for i, line in enumerate(lines):
        if line.strip():
            mutated = list(lines)
            mutated[i] = line + "   "
            mutations.append("\n".join(mutated))
            break
    return mutations


def mutate_case_change(sample: str) -> list[str]:
    """Change casing of boolean-like values."""
    mutations = []
    mutations.append(sample.replace("true", "True").replace("false", "False"))
    mutations.append(sample.replace("True", "true").replace("False", "false"))
    return [m for m in mutations if m != sample]


def mutate_line_break(sample: str) -> list[str]:
    """Split long lines using YAML folded/literal block style (surface-level only)."""
    # For simple string values, add a trailing space to simulate reformatting
    mutations = []
    lines = sample.splitlines()
    for i, line in enumerate(lines):
        if len(line) > 40 and ":" in line:
            mutated = list(lines)
            mutated[i] = line.rstrip() + " "
            candidate = "\n".join(mutated)
            if candidate != sample:
                mutations.append(candidate)
                break
    return mutations


def mutate_expression_brace_space(sample: str) -> list[str]:
    """Remove spaces inside ${{ }} GitHub expression syntax.

    Verifies rules are resilient to ${{expr}} vs ${{ expr }} vs ${{  expr  }}.
    """
    compacted = re.sub(r"\$\{\{\s+", "${{", sample)
    compacted = re.sub(r"\s+\}\}", "}}", compacted)
    return [compacted] if compacted != sample else []


# ---------------------------------------------------------------------------
# Semantic-equivalence operators — surface differs, meaning identical.
#
# The eight surface mutators above probe whitespace / casing / quotes
# fragility. Real evasion vectors usually go through YAML's many
# semantically-equivalent shapes: ``true`` / ``yes`` / ``"true"``;
# ``on: push`` / ``on: [push]`` / ``on:\n  push:``; merge keys vs
# inline. A rule that only fires on one surface form quietly fails to
# detect an attacker who uses the other.
#
# These operators systematically search the equivalence-class space
# the audit's evasion folder documents only ad-hoc. Same kill-rate
# discipline applies: a survivor is a rule-engineering gap, an entry
# in _KNOWN_MUTATION_GAPS, not a thing to silently tolerate.
# ---------------------------------------------------------------------------


def mutate_yaml_boolean_synonyms(sample: str) -> list[str]:
    """Swap YAML 1.1 boolean synonyms.

    YAML 1.1 accepts ``true / yes / on / y`` (and case variants) as
    equivalent boolean tokens; some rules' regexes only match a
    canonical spelling. Real workflows use ``true`` overwhelmingly, but
    the parser doesn't care.

    Only emit when the swap is locally a value (preceded by ``: `` or
    ``=``) so we don't rewrite unrelated occurrences of the literal
    text inside ``run:`` script bodies.
    """
    mutations: list[str] = []
    swaps = [
        (r"(:\s+)true\b", r"\1yes"),
        (r"(:\s+)false\b", r"\1no"),
        (r"(:\s+)yes\b", r"\1true"),
        (r"(:\s+)no\b", r"\1false"),
    ]
    for pattern, replacement in swaps:
        new = re.sub(pattern, replacement, sample, count=1)
        if new != sample:
            mutations.append(new)
    return mutations


def mutate_trigger_shape(sample: str) -> list[str]:
    """Equivalent ``on:`` trigger shapes.

    GitHub Actions accepts:
      * ``on: push``                        (scalar)
      * ``on: [push]``                      (flow sequence)
      * ``on:\\n  push:``                   (mapping key with empty body)
    All three mean the same thing. A trigger-shape-sensitive rule
    silently fails when a workflow uses an alternate form.
    """
    mutations: list[str] = []
    # Scalar -> flow sequence
    m1 = re.sub(r"^(on):\s*([a-z_]+)\s*$", r"\1: [\2]", sample, count=1, flags=re.MULTILINE)
    if m1 != sample:
        mutations.append(m1)
    # Scalar -> mapping form
    m2 = re.sub(
        r"^(on):\s*([a-z_]+)\s*$",
        r"\1:\n  \2:",
        sample,
        count=1,
        flags=re.MULTILINE,
    )
    if m2 != sample:
        mutations.append(m2)
    return mutations


def mutate_quoted_scalar_form(sample: str) -> list[str]:
    """Add explicit double-quotes around values that don't need them.

    YAML accepts ``permissions: write-all`` and ``permissions: "write-all"``
    interchangeably. Some regexes anchor on the unquoted form and miss
    the quoted one — a real evasion vector for any rule keyed on a
    string literal.

    Only quotes simple scalars (no embedded ``: `` or quote chars) to
    avoid producing invalid YAML.
    """
    mutations: list[str] = []
    pattern = re.compile(
        r"^(\s*[A-Za-z][A-Za-z0-9_-]*:\s+)([A-Za-z][A-Za-z0-9._/\-]*)\s*$", re.MULTILINE
    )
    quoted = pattern.sub(r'\1"\2"', sample, count=1)
    if quoted != sample:
        mutations.append(quoted)
    return mutations


MUTATION_OPERATORS: dict[str, Callable[[str], list[str]]] = {
    "whitespace_pad": mutate_whitespace_pad,
    "indent_shift": mutate_indent_shift,
    "quote_swap": mutate_quote_swap,
    "comment_inject": mutate_comment_inject,
    "trailing_whitespace": mutate_trailing_whitespace,
    "case_change": mutate_case_change,
    "line_break": mutate_line_break,
    "expression_brace_space": mutate_expression_brace_space,
}


# Advisory operators — exercised by ``--mutate --semantic`` but NOT
# gated by the 100%-kill-rate CI step. Results surface as a separate
# section in the report so maintainers can SEE the rule-engineering
# gaps without the build failing the moment they're introduced.
#
# Why advisory and not in MUTATION_OPERATORS: enabling these without
# warning would explode the _KNOWN_MUTATION_GAPS allowlist on day one
# (each YAML-equivalence operator finds gaps across many rules at once)
# and the gap-growth gate at scripts/check_mutation_gap_count.py would
# block every PR. Phasing them in keeps the gate meaningful: a rule
# that survives a semantic mutation gets a follow-up ticket, not a
# silent allowlist entry.
SEMANTIC_MUTATION_OPERATORS: dict[str, Callable[[str], list[str]]] = {
    "yaml_boolean_synonyms": mutate_yaml_boolean_synonyms,
    "trigger_shape": mutate_trigger_shape,
    "quoted_scalar_form": mutate_quoted_scalar_form,
}
