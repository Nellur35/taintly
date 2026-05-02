#!/usr/bin/env python3
"""Run a small empirical field-validation corpus and write review artifacts.

This is intentionally not a benchmark runner and not a scoring gate. It creates
repeatable evidence for deciding what to tune next without adding new scanner
semantics or hiding findings.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@dataclass(frozen=True)
class Target:
    name: str
    platform: str
    path: Path


def _parse_target(raw: str) -> Target:
    parts = raw.split("=", 2)
    if len(parts) != 3:
        raise argparse.ArgumentTypeError(
            "--target must use name=platform=path, for example goat=github=../repo"
        )
    name, platform, path = parts
    if platform not in {"github", "gitlab", "jenkins"}:
        raise argparse.ArgumentTypeError(f"unsupported platform: {platform}")
    return Target(name=name, platform=platform, path=Path(path).resolve())


def _counter_dict(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0])))


def _sample_findings(findings: list[Any], limit: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for finding in findings[:limit]:
        out.append(
            {
                "assessment": "unreviewed",
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "family": finding.finding_family,
                "file": finding.file,
                "line": finding.line,
                "snippet": finding.snippet,
                "review_note": "",
            }
        )
    return out


def scan_target(target: Target, sample_limit: int) -> dict[str, Any]:
    from taintly.deployment_context import (
        apply_context_notes_to_findings,
        load_deployment_context,
    )
    from taintly.engine import scan_repo
    from taintly.models import Platform
    from taintly.rules.registry import load_rules_for_platform

    platform = Platform(target.platform)
    rules = load_rules_for_platform(platform)
    reports = scan_repo(str(target.path), rules, platform)

    all_findings = []
    files_scanned = 0
    errors = []
    for report in reports:
        ctx = load_deployment_context(report.repo_path)
        apply_context_notes_to_findings(report.findings, ctx)
        report.summarize()
        files_scanned += report.files_scanned
        all_findings.extend(report.findings)
        errors.extend(report.engine_errors())

    severity_counts = Counter(f.severity.value for f in all_findings)
    family_counts = Counter(f.finding_family or "unknown" for f in all_findings)
    rule_counts = Counter(f.rule_id for f in all_findings)

    return {
        "name": target.name,
        "platform": target.platform,
        "path": str(target.path),
        "files_scanned": files_scanned,
        "findings_total": len(all_findings),
        "severity_counts": {
            "CRITICAL": severity_counts.get("CRITICAL", 0),
            "HIGH": severity_counts.get("HIGH", 0),
            "MEDIUM": severity_counts.get("MEDIUM", 0),
            "LOW": severity_counts.get("LOW", 0),
            "INFO": severity_counts.get("INFO", 0),
        },
        "top_families": _counter_dict(family_counts),
        "top_rules": _counter_dict(rule_counts),
        "review_needed_count": sum(1 for f in all_findings if f.review_needed),
        "triage_needed_count": sum(1 for f in all_findings if f.triage_needed),
        "context_notes_count": sum(1 for f in all_findings if f.context_notes),
        "calibration_reason_count": sum(1 for f in all_findings if f.calibration_reason),
        "surviving_suppression_reason_count": sum(1 for f in all_findings if f.suppression_reason),
        "engine_error_count": len(errors),
        "sample_findings": _sample_findings(all_findings, sample_limit),
    }


def _render_markdown(results: list[dict[str, Any]]) -> str:
    total_findings = sum(int(r["findings_total"]) for r in results)
    total_files = sum(int(r["files_scanned"]) for r in results)
    lines = [
        "# Phase 8 field-validation evidence",
        "",
        "Status: initial local corpus run. Human assessment fields remain unreviewed.",
        "",
        "## Corpus summary",
        "",
        f"- Targets scanned: {len(results)}",
        f"- Files scanned: {total_files}",
        f"- Findings emitted: {total_findings}",
        "",
        "| Target | Platform | Files | Findings | Critical | High | Medium | Low | Review-needed | Context notes | Calibration | Engine errors |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for result in results:
        sev = result["severity_counts"]
        lines.append(
            "| {name} | {platform} | {files} | {total} | {critical} | {high} | "
            "{medium} | {low} | {review} | {context} | {calibration} | {errors} |".format(
                name=result["name"],
                platform=result["platform"],
                files=result["files_scanned"],
                total=result["findings_total"],
                critical=sev["CRITICAL"],
                high=sev["HIGH"],
                medium=sev["MEDIUM"],
                low=sev["LOW"],
                review=result["review_needed_count"],
                context=result["context_notes_count"],
                calibration=result["calibration_reason_count"],
                errors=result["engine_error_count"],
            )
        )

    lines.extend(
        [
            "",
            "## Review method",
            "",
            "For each sampled finding, fill `assessment` with one of:",
            "",
            "- `valid`",
            "- `false_positive`",
            "- `false_negative_near_miss`",
            "- `needs_context`",
            "- `unclear`",
            "",
            "Do not treat this document as a suppression source. It is evidence for future work.",
            "",
            "## Top rule clusters",
            "",
        ]
    )
    for result in results:
        lines.extend([f"### {result['name']}", ""])
        for rule_id, count in list(result["top_rules"].items())[:10]:
            lines.append(f"- `{rule_id}`: {count}")
        lines.append("")

    lines.extend(["## Sample review queue", ""])
    for result in results:
        lines.extend([f"### {result['name']}", ""])
        sample = result["sample_findings"]
        if not sample:
            lines.extend(["No findings sampled.", ""])
            continue
        lines.extend(
            [
                "| Assessment | Rule | Severity | Family | File | Line | Snippet | Note |",
                "| --- | --- | --- | --- | --- | ---: | --- | --- |",
            ]
        )
        for finding in sample:
            file_name = Path(finding["file"]).name
            snippet = str(finding["snippet"]).replace("|", "\\|")
            lines.append(
                "| {assessment} | `{rule}` | {severity} | {family} | {file} | {line} | `{snippet}` |  |".format(
                    assessment=finding["assessment"],
                    rule=finding["rule_id"],
                    severity=finding["severity"],
                    family=finding["family"],
                    file=file_name,
                    line=finding["line"],
                    snippet=snippet[:120],
                )
            )
        lines.append("")

    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        action="append",
        type=_parse_target,
        required=True,
        help="Corpus target as name=platform=path. Repeat for multiple repos.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=ROOT / "docs" / "field-validation",
        help="Directory for generated JSON and Markdown artifacts.",
    )
    parser.add_argument("--sample-limit", type=int, default=12)
    args = parser.parse_args()

    results = [scan_target(target, args.sample_limit) for target in args.target]
    args.out_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.out_dir / "phase-8-local-corpus-summary.json"
    md_path = args.out_dir / "phase-8-local-corpus-review.md"
    payload = {
        "phase": 8,
        "purpose": "field validation before permissions-neutralization implementation",
        "targets": results,
    }
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(results), encoding="utf-8")
    print(f"Wrote {json_path.relative_to(ROOT)}")
    print(f"Wrote {md_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
