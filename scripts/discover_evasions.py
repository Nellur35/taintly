#!/usr/bin/env python3
"""Adversarial-evasion discovery generator (audit chunk 3.4).

The hand-curated evasion corpus documents bypasses someone *noticed*.
This tool finds bypasses *systematically*: take each rule's positive
samples, mutate them along documented evasion vectors (variable
indirection, base64 wrapping, anchor merging, semantic-equivalent
shapes), and report which mutations no longer fire.

Output is a markdown table grouping by rule, sorted by severity, so a
maintainer can prioritise. This is a one-shot tool, not a CI gate —
running it against the full rule pack takes a few seconds and the
results need human triage before becoming evasion fixtures.

Usage:

  python scripts/discover_evasions.py [--platform github|gitlab|jenkins|codebuild]
                                       [--severity CRITICAL|HIGH]
                                       [--output report.md]
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

from taintly.engine import scan_file  # noqa: E402
from taintly.models import Platform, Rule  # noqa: E402
from taintly.rules.registry import load_all_rules  # noqa: E402
from taintly.testing.mutations import (  # noqa: E402
    MUTATION_OPERATORS,
    SEMANTIC_MUTATION_OPERATORS,
)


def _wrap_in_indirection(sample: str) -> list[str]:
    """Wrap a ``run:`` line that references a tainted ``${{ ... }}``
    expression in a shell variable indirection — the canonical evasion
    that breaks single-line taint regexes."""
    out = []
    if "${{" in sample and "run:" in sample:
        # Replace the first ${{ expr }} with a $VAR reference and prepend
        # an assignment line. Keeps formatting simple — quality of the
        # mutation matters less than coverage of the survival space.
        wrapped = sample.replace(
            "run: ",
            'run: |\n          VAR="X"\n          ',
            1,
        )
        out.append(wrapped)
    return out


def _wrap_in_base64(sample: str) -> list[str]:
    """Encode shell command bodies in base64 + decode-and-eval — evades
    literal pattern matchers."""
    out = []
    if "run:" in sample and "curl" in sample:
        out.append(
            sample.replace(
                "curl",
                # Base64 of "curl -s ..." stripped down for brevity.
                "echo Y3VybCAtcyA= | base64 -d | sh",
                1,
            )
        )
    return out


_DISCOVERY_OPERATORS: dict[str, Callable[[str], list[str]]] = {
    **MUTATION_OPERATORS,
    **SEMANTIC_MUTATION_OPERATORS,
    "shell_indirection": _wrap_in_indirection,
    "base64_wrap": _wrap_in_base64,
}


def _suffix_for(rule: Rule) -> str:
    return ".Jenkinsfile" if rule.platform == Platform.JENKINS else ".yml"


def _scan_sample(rule: Rule, sample: str, tmp_path: Path) -> set[str]:
    fpath = tmp_path / f"sample{_suffix_for(rule)}"
    fpath.write_text(sample, encoding="utf-8")
    findings = scan_file(str(fpath), rules=[rule])
    return {f.rule_id for f in findings if f.rule_id != "ENGINE-ERR"}


def discover(rules: list[Rule], severity_filter: str | None) -> list[dict[str, str]]:
    """Run every discovery operator against every rule's positive samples
    and return survivors."""
    import tempfile

    survivors: list[dict[str, str]] = []
    sev_set = {severity_filter} if severity_filter else None

    with tempfile.TemporaryDirectory() as td:
        tmp_path = Path(td)
        for r in rules:
            if sev_set and r.severity.value not in sev_set:
                continue
            for sample in r.test_positive:
                base_fired = _scan_sample(r, sample, tmp_path)
                if r.id not in base_fired:
                    # Rule doesn't even fire on its own positive sample
                    # in isolation — out of scope for evasion discovery
                    # (would always be a "survivor"). The minimal-fire
                    # gate at tests/integration/test_minimal_and_round_trip.py
                    # tracks that separately.
                    continue
                for op_name, op_fn in _DISCOVERY_OPERATORS.items():
                    for mutated in op_fn(sample):
                        fired = _scan_sample(r, mutated, tmp_path)
                        if r.id not in fired:
                            survivors.append(
                                {
                                    "rule_id": r.id,
                                    "severity": r.severity.value,
                                    "platform": r.platform.value,
                                    "operator": op_name,
                                    "sample": sample[:80],
                                    "mutated": mutated[:120],
                                }
                            )
    return survivors


def render_markdown(survivors: list[dict[str, str]]) -> str:
    out = ["# Adversarial evasion discovery", ""]
    out.append(f"Total survivors: **{len(survivors)}**")
    out.append("")
    out.append("| Severity | Platform | Rule | Operator | Sample (truncated) |")
    out.append("|---|---|---|---|---|")
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    survivors.sort(key=lambda s: (sev_order.get(s["severity"], 99), s["rule_id"]))
    for s in survivors:
        sample = s["mutated"].replace("\n", "\\n").replace("|", "\\|")
        out.append(
            f"| {s['severity']} | {s['platform']} | {s['rule_id']} | "
            f"{s['operator']} | `{sample[:80]}` |"
        )
    return "\n".join(out)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=tuple(platform.value for platform in Platform))
    parser.add_argument("--severity", choices=("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
    parser.add_argument("--output", help="write markdown to this file (default: stdout)")
    args = parser.parse_args(argv)

    rules = load_all_rules()
    if args.platform:
        rules = [r for r in rules if r.platform.value == args.platform]

    survivors = discover(rules, severity_filter=args.severity)
    md = render_markdown(survivors)

    if args.output:
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"wrote {len(survivors)} survivors to {args.output}", file=sys.stderr)
    else:
        print(md)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
