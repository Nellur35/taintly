#!/usr/bin/env python3
"""No-rules-change gate — guard against silent fixture drift.

Any commit that touches the rule pack, the engine, or the
parser stack risks subtly changing what an existing fixture
fires (or stops firing).  This script scans every fixture under
``tests/fixtures/`` with the standard rule pack, hashes the
emitted JSON, and exits non-zero if the hash differs from the
baseline.  When the change is intended, the baseline is
regenerated and committed together with the rule change so the
diff is reviewed deliberately.

Usage:

  python scripts/no_rules_change_gate.py --check   # CI mode
  python scripts/no_rules_change_gate.py --update  # baseline refresh

The baseline lives at ``tests/_rule_pack_hashes.json`` and is
checked into git.  Any change to existing rule firing — whether
from a rule edit, an engine change, or accidental side effect from
new infrastructure — produces a hash mismatch and forces an
explicit review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

BASELINE = ROOT / "tests" / "_rule_pack_hashes.json"


def _findings_signature(findings) -> str:
    """Produce a stable hash of a findings list.

    Strips fields that would cause spurious diffs: file paths
    (relative to the fixture, but absolute in finding output) are
    rebased, and metadata fields irrelevant to "did the rule
    fire" are dropped.
    """
    canonical = []
    for f in sorted(findings, key=lambda x: (x.rule_id, x.line, x.snippet)):
        canonical.append(
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "line": f.line,
                "snippet": f.snippet,
            }
        )
    blob = json.dumps(canonical, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _scan_corpus() -> dict[str, str]:
    from taintly.engine import scan_file
    from taintly.rules.registry import load_all_rules

    rules = load_all_rules()
    fixtures_root = ROOT / "tests" / "fixtures"
    out: dict[str, str] = {}
    for plat in ("github", "gitlab", "jenkins"):
        plat_dir = fixtures_root / plat
        if not plat_dir.exists():
            continue
        for ext in (".yml", ".yaml", ".Jenkinsfile"):
            for path in sorted(plat_dir.rglob(f"*{ext}")):
                rel = path.relative_to(fixtures_root).as_posix()
                try:
                    findings = scan_file(str(path), rules)
                except Exception as e:
                    out[rel] = f"ERROR: {type(e).__name__}: {e}"
                    continue
                out[rel] = _findings_signature(findings)
    # Also scan Jenkinsfile-shaped fixtures without relying on the
    # filesystem's glob case-sensitivity.  Windows/macOS match
    # ``jenkinsfile.adoc`` with ``rglob("Jenkinsfile*")``; Linux does
    # not.  Reuse the scanner classifier so this gate tracks the same
    # Jenkinsfile shapes on every OS.
    if (fixtures_root / "jenkins").exists():
        from taintly.engine import _is_jenkinsfile_name
        from taintly.engine import scan_file as _scan

        for jf in sorted((fixtures_root / "jenkins").rglob("*")):
            if not jf.is_file() or not _is_jenkinsfile_name(jf.name):
                continue
            rel = jf.relative_to(fixtures_root).as_posix()
            if rel in out:
                continue
            findings = _scan(str(jf), rules)
            out[rel] = _findings_signature(findings)
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--check", action="store_true", help="CI mode (default)")
    p.add_argument("--update", action="store_true", help="refresh baseline")
    args = p.parse_args()

    current = _scan_corpus()

    if args.update:
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        print(f"Wrote {len(current)} fixture hashes to {BASELINE.relative_to(ROOT)}")
        return 0

    # Check mode (default).
    if not BASELINE.exists():
        print(
            f"FAIL: baseline {BASELINE} does not exist.  Run with --update to seed.",
            file=sys.stderr,
        )
        return 2

    expected = json.loads(BASELINE.read_text())
    diffs: list[str] = []
    for path, sig in current.items():
        if expected.get(path) != sig:
            diffs.append(f"  {path}: baseline={expected.get(path)!r} current={sig!r}")
    for path in expected:
        if path not in current:
            diffs.append(f"  {path}: baseline present but file missing")

    if diffs:
        print(
            "FAIL: rule-pack output drifted on these fixtures:\n"
            + "\n".join(diffs)
            + "\n\nThis PR claims pure addition but rule firing changed.  "
            "Either revert the unintended change or run with "
            "--update if the change is deliberate.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: {len(current)} fixtures match baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
