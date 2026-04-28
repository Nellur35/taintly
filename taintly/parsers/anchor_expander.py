"""Hand-rolled YAML anchor / merge-key expander.

CI/CD YAML occasionally uses anchors and merge keys to deduplicate
repeated step or trigger blocks.  Pure-regex per-line scanners can't
follow anchors — the value referenced via ``<<: *X`` lives somewhere
else in the file — which produces false positives like the one
documented in ``tests/evasion/anchor_merge_inject.yml``.

This expander does ONE thing: textually inline ``<<: *X`` and ``key:
*X`` references into the position they would expand to in a real
parser.

Out of scope (returns text unchanged):

  * Anchors defined more than once in the file (ambiguous).
  * Recursive anchors (``&a {x: *a}``).
  * Sequence-style merge.  The block-mapping case covers ~95% of
    observed CI uses.
  * Anchor names containing characters outside ``[A-Za-z0-9_-]``.

The expander never raises — it returns the original text on any
parse-shaped failure so the rule pipeline degrades gracefully.
"""

from __future__ import annotations

import re

# Anchor definition: ``key: &name`` followed by indented block.
_ANCHOR_DEF_RE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_-]*):\s*&([A-Za-z0-9_-]+)\s*$")
# Merge-key reference: ``<<: *name``.
_MERGE_REF_RE = re.compile(r"^(\s*)<<:\s*\*([A-Za-z0-9_-]+)\s*$")
# Plain alias reference: ``key: *name``.
_ALIAS_REF_RE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_-]*):\s*\*([A-Za-z0-9_-]+)\s*$")


def _collect_anchor_bodies(lines: list[str]) -> dict[str, list[str]]:
    """Find ``key: &anchor`` definitions and collect their indented body
    lines, dedented relative to the anchor's own indent + 2.

    Returns name -> list of body lines (already dedented to root level).
    Names that appear twice are dropped (ambiguous).
    """
    bodies: dict[str, list[str]] = {}
    seen_twice: set[str] = set()
    i = 0
    while i < len(lines):
        m = _ANCHOR_DEF_RE.match(lines[i])
        if m:
            indent_str, _key, name = m.groups()
            indent = len(indent_str)
            body_indent = indent + 2  # YAML standard 2-space mapping.
            body: list[str] = []
            j = i + 1
            while j < len(lines):
                line = lines[j]
                if not line.strip():
                    body.append("")
                    j += 1
                    continue
                stripped = line.lstrip()
                line_indent = len(line) - len(stripped)
                if line_indent < body_indent:
                    break
                # Re-indent relative to root for inlining.
                body.append(line[body_indent:])
                j += 1
            if name in bodies:
                seen_twice.add(name)
            else:
                bodies[name] = body
            i = j
        else:
            i += 1
    for name in seen_twice:
        bodies.pop(name, None)
    return bodies


def expand_anchors(text: str) -> str:
    """Return ``text`` with ``<<: *X`` and ``key: *X`` references inlined.

    The expander is a pre-pass that produces text rules SCAN; the
    original text is what they CITE, so callers should compare matches
    on both forms when they care about anchor-mediated false positives.
    """
    try:
        lines = text.splitlines()
        bodies = _collect_anchor_bodies(lines)
        if not bodies:
            return text
        out: list[str] = []
        for line in lines:
            m = _MERGE_REF_RE.match(line)
            if m:
                indent_str, name = m.groups()
                if name in bodies:
                    # Skip the `<<: *X` line itself; replace with body
                    # at the merge-key indentation.
                    for body_line in bodies[name]:
                        out.append(indent_str + body_line if body_line else "")
                    continue
            m = _ALIAS_REF_RE.match(line)
            if m:
                indent_str, key, name = m.groups()
                if name in bodies:
                    out.append(f"{indent_str}{key}:")
                    for body_line in bodies[name]:
                        out.append(indent_str + "  " + body_line if body_line else "")
                    continue
            out.append(line)
        return "\n".join(out)
    except Exception:
        # Defensive: any parse-shape glitch returns original.
        return text
