#!/usr/bin/env python3
"""Duplicate-rule gate — fail when two rules are behaviourally identical.

SEC4-GH-021/023 and SEC4-GL-008/009 were exact duplicates (an encoding-
forked copy-paste) that shipped because nothing compared whole rules.
This gate does. It builds a behavioural signature for every rule —
``(platform, pattern-class, pattern-config)`` — and fails if two rules in
the same platform share one, because identical pattern + identical config
means identical firing (verified: 021/023 fired on the same 136 lines).

This is the title/class audit codified so the duplicate cannot recur, and
running it IS the deep-dive: any same-signature group it reports is a
duplicate to merge.

The signature deliberately ignores title/description/severity (those can
legitimately differ between an A/B pair) and keys on what the rule *does*:
the pattern class plus its configuration (regex/path/predicate/flags).
Distinct predicates, regexes, or path globs => distinct signature => not
flagged. A genuinely-intended same-signature pair can be allowlisted in
``_ALLOWED_DUP_SIGNATURES`` with a rationale.

Usage:
  python scripts/check_rule_duplicates.py          # CI mode (exit 1 on dup)
"""

from __future__ import annotations

import dataclasses
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Intentional same-signature pairs, keyed by frozenset of rule IDs, value =
# rationale.  Empty today; add here (with a reason) only if two rules are
# meant to share a pattern+config yet remain distinct rules.
_ALLOWED_DUP_SIGNATURES: dict[frozenset, str] = {}


def _stable(v: object) -> object:
    """Deterministic, JSON-safe rendering of a pattern-config value."""
    if isinstance(v, re.Pattern):
        return f"re:{v.pattern}:{v.flags}"
    if isinstance(v, (list, tuple)):
        return [_stable(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _stable(x) for k, x in sorted(v.items(), key=lambda kv: str(kv[0]))}
    if isinstance(v, (str, int, float, bool, type(None))):
        return v
    if callable(v):
        # A function's identity is its qualified name PLUS its closure
        # captures: factory-made closures (e.g. CHAIN's per-leg callbacks)
        # share a qualname but capture different config, so two rules are
        # only duplicates if both name and captures match.
        name = f"fn:{getattr(v, '__module__', '')}.{getattr(v, '__qualname__', repr(v))}"
        cells = getattr(v, "__closure__", None)
        if cells:
            name += "|closure:" + json.dumps(
                [_stable(c.cell_contents) for c in cells], sort_keys=True, default=repr
            )
        return name
    if dataclasses.is_dataclass(v):
        return _stable({f.name: getattr(v, f.name) for f in dataclasses.fields(v)})
    return f"repr:{type(v).__name__}:{v!r}"


def _pattern_signature(pattern: object) -> str:
    cls = type(pattern).__name__
    try:
        # Include ``_``-prefixed attrs: several patterns store their
        # DISTINGUISHING logic there (``_predicate`` on the Jenkins shell-leaf
        # pattern, ``_line_re`` on the dependency-review pattern).  A compiled
        # regex renders to its source, so ``_compiled`` just restates ``match``.
        config = dict(vars(pattern))
    except TypeError:
        config = {}
    return cls + "|" + json.dumps(_stable(config), sort_keys=True, default=repr)


def _duplicate_groups() -> list[tuple[str, list[str]]]:
    from taintly.rules.registry import load_all_rules

    by_sig: dict[tuple[str, str], list[str]] = defaultdict(list)
    for rule in load_all_rules():
        platform = getattr(rule.platform, "value", str(rule.platform))
        sig = (platform, _pattern_signature(rule.pattern))
        by_sig[sig].append(rule.id)

    groups: list[tuple[str, list[str]]] = []
    for (platform, sig), ids in by_sig.items():
        if len(ids) < 2:
            continue
        if frozenset(ids) in _ALLOWED_DUP_SIGNATURES:
            continue
        groups.append((f"{platform} :: {sig[:90]}", sorted(ids)))
    return groups


def main() -> int:
    groups = _duplicate_groups()
    if groups:
        lines = [f"  {ids}  [{sig}]" for sig, ids in sorted(groups, key=lambda g: g[1])]
        print(
            "FAIL: behaviourally-duplicate rules (same platform + pattern + "
            "config => identical firing):\n"
            + "\n".join(lines)
            + "\n\nThese rules fire identically — keep one, delete the rest "
            "(or, if the duplication is intentional, allowlist the ID set in "
            "_ALLOWED_DUP_SIGNATURES with a rationale).",
            file=sys.stderr,
        )
        return 1
    print("OK: no behaviourally-duplicate rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
