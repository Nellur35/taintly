"""Pattern.check() return-value contract.

Every Pattern.check returns ``list[tuple[line_num, snippet]]``.  The
contract:

  * ``line_num`` is 1-based and refers to a line in the input ``lines``
    array passed to ``check()``.
  * ``snippet`` is the substring of ``lines[line_num - 1]`` after
    ``.strip()`` — i.e. the actual line of source that triggered the
    finding, sans surrounding whitespace.
  * If a pattern fires "because of" multiple lines (e.g. a context
    pattern), ``line_num`` MUST point at the line whose textual content
    is the most informative — not the anchor line, not a comment, not
    a structural keyword.

Documented exceptions (the contract sweep test treats these as such,
not as violations):

  * AbsencePattern — by design has no per-line evidence; it returns a
    sentinel snippet of the form ``(pattern not found: <regex>)``.
  * TaintPattern (per-platform) — emits a rendered provenance chain
    instead of a literal source substring; the chain summarises a
    multi-line dataflow that no single source line conveys.

This module's ``assert_snippet_matches_line`` is the executable form
of that contract; it is enforced by ``tests/unit/test_pattern_contract.py``.
"""

from __future__ import annotations


def assert_snippet_matches_line(line_num: int, snippet: str, lines: list[str]) -> None:
    """Raise AssertionError if (line_num, snippet) violates the contract.

    Documented exceptions (sentinel/rendered-chain snippets) are
    intentionally NOT handled here — callers (the contract sweep
    test) skip those rule classes by name before invoking this.
    """
    if not (1 <= line_num <= len(lines)):
        raise AssertionError(
            f"line_num={line_num} out of range for {len(lines)} lines"
        )
    src = lines[line_num - 1].strip()
    snip = (snippet or "").strip()
    if not snip:
        raise AssertionError(f"empty snippet at line {line_num}: {src!r}")
    # Allow substring rather than equality because some patterns
    # extract a sub-token (e.g. just the ``uses:`` value) — but the
    # snippet must come from the cited line, not a different one.
    if snip not in src and src not in snip:
        raise AssertionError(
            f"snippet/line mismatch at line {line_num}:\n"
            f"  snippet: {snip!r}\n"
            f"  line:    {src!r}"
        )
