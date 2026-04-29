"""Recognise zizmor inline-suppression comments and map them to
taintly rule IDs.

Zizmor's inline ignore format (per the zizmor docs):

    # zizmor: ignore
    # zizmor: ignore[<rule-id>]
    # zizmor: ignore[<rule-a>,<rule-b>]

The first form suppresses every zizmor finding on the line.  When we
honour zizmor ignores, that translates to "suppress every taintly
finding on this line" — the maintainer's intent is clear at the
broader level even if the specific tooling differs.

The bracketed forms suppress a specific zizmor rule.  We map a small
set of zizmor rule IDs onto the taintly rule IDs whose threat shape
genuinely overlaps; mappings outside this allowlist degrade to the
broad-suppression behaviour (treat as "ignore on this line") because
silently dropping the unfamiliar id would surprise the user.

The mapping is deliberately conservative.  The goal is to avoid the
"flood of new findings on a repo that already passed zizmor review"
shape, not to claim full taxonomy parity.  Add an entry only when the
two scanners are detecting the same threat shape, not just adjacent
ones.
"""

from __future__ import annotations

import re
from typing import Mapping

# Module-level enabled flag.  CLI flips this when
# --respect-zizmor-ignores is passed; engine consults it during
# suppression checks.
_RESPECT_ZIZMOR_IGNORES: bool = False


def set_respect_zizmor_ignores(enabled: bool) -> None:
    global _RESPECT_ZIZMOR_IGNORES
    _RESPECT_ZIZMOR_IGNORES = enabled


def is_respect_zizmor_ignores_enabled() -> bool:
    return _RESPECT_ZIZMOR_IGNORES


# zizmor rule -> set of taintly rule IDs covering the same threat shape.
# Only mappings where the two scanners detect the same thing belong
# here.  When zizmor's id has no clear mapping, the bracketed form
# falls through to broad-line suppression (handled in
# ``is_zizmor_suppressed``).
ZIZMOR_TO_TAINTLY: Mapping[str, frozenset[str]] = {
    # Unpinned uses: tag and branch references — both scanners detect
    # the mutable-ref threat shape.
    "unpinned-uses": frozenset({"SEC3-GH-001", "SEC3-GH-002"}),
    # Dangerous triggers: pull_request_target / workflow_run.
    "dangerous-triggers": frozenset({"SEC4-GH-001", "SEC4-GH-002", "SEC4-GH-003"}),
    # Excessive permissions: write-all / unscoped permissions.
    "excessive-permissions": frozenset({"SEC2-GH-001", "SEC2-GH-002"}),
    # Template injection: ${{ github.event.* }} reaching shell.
    "template-injection": frozenset({"SEC4-GH-004"}),
    # Cache poisoning across privilege tiers.
    "cache-poisoning": frozenset({"XF-GH-001", "XF-GH-001A"}),
    # secrets: inherit on a reusable workflow caller.
    "secrets-inherit": frozenset({"XF-GH-003", "XF-GH-004"}),
    # Persist-credentials default on actions/checkout.
    "artipacked": frozenset({"SEC2-GH-005"}),
}


_ZIZMOR_GENERIC_RE = re.compile(r"#\s*zizmor\s*:\s*ignore\s*(?:#.*)?$", re.IGNORECASE)
_ZIZMOR_SPECIFIC_RE = re.compile(r"#\s*zizmor\s*:\s*ignore\[([^\]]+)\]", re.IGNORECASE)


def is_zizmor_suppressed(line: str, taintly_rule_id: str) -> bool:
    """Return True when the source line carries a zizmor inline ignore
    that, under the taintly→zizmor mapping, suppresses
    ``taintly_rule_id``.

    Cases:

    * ``# zizmor: ignore`` (whole-line) → suppress any taintly rule.
    * ``# zizmor: ignore[<ids>]`` where any id maps to a taintly rule
      set containing ``taintly_rule_id`` → suppress.
    * ``# zizmor: ignore[<ids>]`` where no listed id has a known
      mapping → broad-suppress on the line (treat the maintainer's
      intent as "this line was reviewed").  Conservative-but-safe:
      we don't fire findings on lines the maintainer marked under a
      foreign tool, but we don't expand the mapping silently either.
    """
    if _ZIZMOR_GENERIC_RE.search(line):
        return True
    m = _ZIZMOR_SPECIFIC_RE.search(line)
    if not m:
        return False
    listed = [s.strip() for s in m.group(1).split(",") if s.strip()]
    if not listed:
        return False
    any_unmapped = False
    for zid in listed:
        mapped = ZIZMOR_TO_TAINTLY.get(zid)
        if mapped is None:
            any_unmapped = True
            continue
        if taintly_rule_id in mapped:
            return True
    # If no listed id is mapped to this rule but at least one is
    # unmapped, treat as broad ignore (per docstring rationale).
    return any_unmapped
