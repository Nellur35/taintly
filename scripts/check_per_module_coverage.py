#!/usr/bin/env python3
"""Per-module coverage gate.

The global ``--cov-fail-under=78`` only checks total branch coverage.
It cannot catch a regression where a single high-risk module's
coverage drops while the overall total stays above 78 — the global
denominator hides per-module drift. This script reads ``coverage.xml``
(produced by ``--cov-report=xml``) and asserts each module in
``_FLOORS`` meets its own floor.

The floors below are the CURRENT measured coverage rounded down to
the nearest whole percent — same growth-only discipline as
``_KNOWN_MUTATION_GAPS`` and ``_INCIDENT_REF_BASELINE``: tolerate
today, fail on regressions. Raise them in lockstep with the ratchet
plan documented in ``pyproject.toml [tool.coverage.report]``.

Targets (from pyproject):
    fixes.py                           current ~46%, target 90%
    config.py                          current ~64%, target 90%
    engine.py                          current ~65%, target 85%
    reporters/score_text.py            current ~68%, target 85%

CI invocation:
    python scripts/check_per_module_coverage.py coverage.xml
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET


# Per-module floors. Keys are repo-relative POSIX paths for readability
# (``taintly/fixes.py``). NOTE: coverage.py writes its <class filename>
# RELATIVE TO ``[tool.coverage.run] source`` (= "taintly"), so the XML
# carries package-relative names (``fixes.py``) with no ``taintly/``
# prefix. Matching normalises both sides (see ``_norm``) so the keys
# stay readable while still matching what coverage emits. Values are
# minimum acceptable line-rate percents, rounded down from current
# measured coverage. Lower the value only when intentionally relaxing
# the gate; raise it when new tests land for the module.
#
# Why these four: pyproject.toml documents these as the modules that
# drag the overall total below 85. The global gate alone can't catch
# per-module regressions — one of these dropping 10pp would still
# pass if the others compensated.
_FLOORS: dict[str, int] = {
    "taintly/fixes.py": 46,
    "taintly/config.py": 64,
    "taintly/engine.py": 65,
    "taintly/reporters/score_text.py": 68,
}


def _norm(path: str) -> str:
    """Normalise a coverage path for comparison: forward slashes, with a
    single leading ``taintly/`` stripped.

    coverage.py writes ``filename`` relative to ``[tool.coverage.run]
    source`` (= "taintly"), so it emits bare ``fixes.py`` while the
    ``_FLOORS`` keys carry a ``taintly/`` prefix for readability.
    Stripping the prefix from both sides makes the two forms compare
    equal regardless of which convention coverage emits (bare when
    ``source=["taintly"]``, prefixed when run from the repo root or
    against an installed package). An earlier version compared the
    prefixed key against the bare filename verbatim, so nothing matched
    and every module fell through to the non-fatal WARN branch — the
    gate was a silent no-op.
    """
    return path.replace("\\", "/").removeprefix("taintly/")


def _percent_for(root: ET.Element, filename: str) -> int | None:
    """Find <class filename="..."> and return its line-rate as an
    integer percent, or None if the file isn't in the report."""
    target = _norm(filename)
    for cls in root.iter("class"):
        # Coverage uses POSIX paths even on Windows runners.
        if _norm(cls.get("filename", "")) == target:
            line_rate = float(cls.get("line-rate", "0") or "0")
            return int(line_rate * 100)
    return None


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: check_per_module_coverage.py <coverage.xml>", file=sys.stderr)
        return 2

    try:
        tree = ET.parse(argv[1])
    except (FileNotFoundError, ET.ParseError) as e:
        print(f"could not read coverage XML at {argv[1]!r}: {e}", file=sys.stderr)
        return 2

    root = tree.getroot()
    failed = []
    for module, floor in sorted(_FLOORS.items()):
        actual = _percent_for(root, module)
        if actual is None:
            # Missing module is suspicious — but might mean the path
            # changed; surface it loudly rather than passing silently.
            print(
                f"WARN  {module}: not present in coverage.xml — "
                f"path may have changed; update _FLOORS",
                file=sys.stderr,
            )
            continue
        marker = "OK  " if actual >= floor else "FAIL"
        print(f"{marker}  {module:40s}  {actual:3d}%  (floor {floor}%)")
        if actual < floor:
            failed.append((module, actual, floor))

    if failed:
        print(file=sys.stderr)
        print("Per-module coverage floor regressions:", file=sys.stderr)
        for module, actual, floor in failed:
            print(f"  {module}: {actual}% < {floor}%", file=sys.stderr)
        print(
            "\nFix the regression by adding tests for the module, OR "
            "(if intentionally relaxing) lower the floor in "
            "scripts/check_per_module_coverage.py with rationale.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
