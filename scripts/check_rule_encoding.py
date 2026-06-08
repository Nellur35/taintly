#!/usr/bin/env python3
"""Encoding gate — fail on mojibake in user-facing rule text.

An em-dash (``—``) written to a file as UTF-8 and then re-saved by an
editor that misread it as Windows-1252 becomes ``â€"`` — valid UTF-8, but
garbage on screen.  This happened to 9 rules' titles/descriptions and was
spotted by a human audit, not CI.  This gate makes it CI's job.

It scans every rule's user-facing text fields for the cp1252-roundtrip
corruption of the punctuation that legitimately appears in rule prose
(em/en dashes, smart quotes, ellipsis, arrow, ©/®/™, °, ×).  It does NOT
ban non-ASCII — a real ``—`` is fine — only the known-corrupt byte
sequences.  Pure-ASCII text trivially passes.

Usage:
  python scripts/check_rule_encoding.py          # CI mode (exit 1 on mojibake)
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Punctuation that legitimately appears in rule prose.  We flag only the
# *corrupted* form of each (UTF-8 bytes misdecoded as Windows-1252), so a
# correctly-encoded character never trips the gate.
_LEGIT_UNICODE = [
    "—",  # — em dash
    "–",  # – en dash
    "‘",  # ' left single quote
    "’",  # ' right single quote / apostrophe
    "“",  # " left double quote
    "”",  # " right double quote
    "…",  # … ellipsis
    "•",  # • bullet
    "→",  # → arrow
    "©",  # © copyright
    "®",  # ® registered
    "™",  # ™ trademark
    "°",  # ° degree
    "×",  # × multiplication
    " ",  # non-breaking space
]


def _mojibake_map() -> dict[str, str]:
    """corrupted-bytes -> intended character."""
    out: dict[str, str] = {}
    for ch in _LEGIT_UNICODE:
        try:
            corrupt = ch.encode("utf-8").decode("cp1252")
        except UnicodeDecodeError:
            # Some UTF-8 trailing bytes are undefined in cp1252 — that
            # corruption can't arise this way; skip.
            continue
        if corrupt != ch:
            out[corrupt] = ch
    return out


_MOJIBAKE = _mojibake_map()

# Fields a user reads in a finding / the rule catalogue.
_TEXT_FIELDS = ("title", "description", "remediation", "threat_narrative", "reference")


def _findings() -> list[str]:
    from taintly.rules.registry import load_all_rules

    bad: list[str] = []
    for rule in load_all_rules():
        texts: list[tuple[str, str]] = []
        for f in _TEXT_FIELDS:
            val = getattr(rule, f, None)
            if isinstance(val, str):
                texts.append((f, val))
        for incident in getattr(rule, "incidents", ()) or ():
            if isinstance(incident, str):
                texts.append(("incidents", incident))
        for field, text in texts:
            for corrupt, intended in _MOJIBAKE.items():
                if corrupt in text:
                    bad.append(
                        f"  {rule.id} [{field}]: found {corrupt!r} "
                        f"(corrupted {intended!r})"
                    )
    return bad


def main() -> int:
    bad = _findings()
    if bad:
        print(
            "FAIL: mojibake (encoding corruption) in rule text:\n"
            + "\n".join(sorted(set(bad)))
            + "\n\nThese are UTF-8 characters that were re-saved through a "
            "Windows-1252 misread.  Fix the source bytes (replace the "
            "corrupted sequence with the intended character) and re-save the "
            "file as UTF-8.",
            file=sys.stderr,
        )
        return 1
    print(f"OK: no mojibake in rule text ({len(_MOJIBAKE)} corruption forms checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
