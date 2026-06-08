"""Guard against the O(n^2) unanchored-EOF-lookahead regex class.

A :class:`ContextPattern` ``requires`` / ``requires_absent`` and an
:class:`AbsencePattern` ``absent`` are searched against the WHOLE file
content (via ``_safe_search_chunked``).  An unanchored lookahead whose body
can scan to end-of-file — ``(?=[\\s\\S]*...)`` without a leading ``\\A`` —
makes ``re.search`` retry the lookahead at every offset, each scan O(n), so
the check is O(n^2) when the matched text is ABSENT in a large file.

This is not hypothetical: AI-JK-009's ``requires`` was
``(?=[\\s\\S]*?<PR_CONTEXT>)`` and took ~9s on a 1000-step Jenkinsfile (it
flaked the fuzz no-hang gate).  Prefixing ``\\A`` pins re.search to offset 0
— a presence-anywhere lookahead only needs one start position — so the check
is O(n) with identical semantics (it dropped to 0.19s).

This test fails if any rule ships an unanchored EOF-scanning lookahead in a
content-wide pattern field, so the bug class cannot silently recur.
"""

from __future__ import annotations

from taintly.models import AbsencePattern, ContextPattern
from taintly.rules.registry import load_all_rules


def _is_unanchored_eof_lookahead(pattern: str) -> bool:
    """True for the dangerous shape: a lookahead body that can scan to EOF
    (``[\\s\\S]*`` / ``[\\s\\S]+``) while the overall search is NOT pinned to
    offset 0 by a leading ``\\A``.  Anchoring with ``\\A`` makes re.search
    evaluate the lookahead once (at offset 0) instead of at every offset."""
    return r"(?=[\s\S]" in pattern and not pattern.lstrip().startswith("\\A")


# Patterns that MATCH the dangerous shape but are VERIFIED O(n) because the
# unbounded lookahead is GATED by a preceding restrictive lookahead that almost
# always fails fast — so the EOF scan runs O(1) times, not once per offset. The
# static heuristic above can't see that gating, so these are allow-listed with a
# MEASURED justification. This is NOT a place to silence a genuine O(n^2): for
# an un-gated unbounded lookahead the fix is a leading ``\A`` (see AI-JK-009),
# not an entry here.
_VERIFIED_LINEAR: dict[str, str] = {
    "SEC9-GH-003": (
        "requires is (?=<bounded on:/release: trigger>)(?=[\\s\\S]*?setup-lang). "
        "The second (unbounded) lookahead only runs where the first (bounded, "
        "{0,30}? window) lookahead passes — i.e. at the single on: line — so the "
        "EOF scan is O(1)x, not per-offset. Measured linear: 0.6ms@500 lines -> "
        "5.6ms@4000 (release present, setup-lang absent — the worst case)."
    ),
}


def test_no_unanchored_eof_lookahead_in_content_wide_patterns() -> None:
    offenders: list[str] = []
    for rule in load_all_rules():
        p = rule.pattern
        if isinstance(p, ContextPattern):
            candidates = [("requires", p.requires), ("requires_absent", p.requires_absent)]
        elif isinstance(p, AbsencePattern):
            candidates = [("absent", p.absent)]
        else:
            continue
        for field_name, pat in candidates:
            if pat and _is_unanchored_eof_lookahead(pat) and rule.id not in _VERIFIED_LINEAR:
                offenders.append(f"{rule.id}.{field_name}: {pat[:70]!r}")

    assert not offenders, (
        "Unanchored EOF-scanning lookahead in a content-wide pattern — O(n^2) on "
        "large inputs where the match is absent.  Prefix the pattern with \\A so "
        "re.search evaluates the lookahead once at offset 0 (presence-anywhere is "
        "unchanged); or, if a preceding restrictive lookahead gates it to O(n), "
        "add it to _VERIFIED_LINEAR with a measured timing justification:\n  "
        + "\n  ".join(offenders)
    )


def test_verified_linear_allowlist_is_not_stale() -> None:
    """Every _VERIFIED_LINEAR entry must still be a registered rule that still
    has the flagged shape — so a rule that gets anchored/removed drops its
    now-pointless exemption instead of masking a future regression."""
    by_id = {r.id: r.pattern for r in load_all_rules()}
    stale: list[str] = []
    for rid in _VERIFIED_LINEAR:
        p = by_id.get(rid)
        if p is None:
            stale.append(f"{rid}: no longer a registered rule")
            continue
        fields = []
        if isinstance(p, ContextPattern):
            fields = [p.requires, p.requires_absent]
        elif isinstance(p, AbsencePattern):
            fields = [p.absent]
        if not any(f and r"(?=[\s\S]" in f and not f.lstrip().startswith("\\A") for f in fields):
            stale.append(f"{rid}: no longer has an unanchored EOF lookahead — drop the exemption")
    assert not stale, "Stale _VERIFIED_LINEAR entries:\n  " + "\n  ".join(stale)
