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
    return [m for m in mutations if m != sample]


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
        mutations.append(mutated)
    return mutations


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
