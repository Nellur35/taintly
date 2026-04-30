"""JSON output reporter."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from taintly.families import cluster_findings
from taintly.models import AuditReport

if TYPE_CHECKING:
    from taintly.scorer import ScoreReport


def format_json(report: AuditReport, score_report: "ScoreReport | None" = None) -> str:
    """Render an AuditReport as pretty-printed JSON."""
    clusters = cluster_findings(report.findings)
    confirmed_clusters = [cl for cl in clusters if not cl.review_needed]
    review_clusters = [cl for cl in clusters if cl.review_needed]

    # ``errors`` mirrors ENGINE-ERR findings into a top-level array so
    # downstream tooling can detect silent coverage loss without grep-
    # ping the findings stream by ``rule_id``.  The same Findings
    # remain in ``findings`` for backwards compatibility — pre-v1.1
    # consumers parsing only ``findings`` keep working unchanged.
    data: dict = {
        "repo_path": report.repo_path,
        "platform": report.platform,
        "files_scanned": report.files_scanned,
        "summary": report.summary,
        "distinct_risk_count": len(confirmed_clusters),
        "review_needed_count": len(review_clusters),
        "families": [cl.to_dict() for cl in clusters],
        "findings": [f.to_dict() for f in report.findings],
        "errors": [f.to_dict() for f in report.engine_errors()],
    }

    if score_report is not None:
        # Threat-model disclosure mirrors the score-text reporter.
        # Stable contract for aggregators: ``threat_model`` is an enum
        # string (only ``"public-oss-default"`` today; future values
        # would be added as a documented migration).
        # ``user_assessment_required: true`` is a constant for the
        # public-OSS profile — the tool always requires user
        # assessment for fit, regardless of the score number.
        # ``triage_doc`` points at a paste-ready AI-recalibration
        # prompt; flat sibling of ``threat_model`` rather than nested
        # to avoid breaking aggregators that already parse the prior
        # field shapes.
        # New fields added at the end so existing JSON consumers that
        # parse only the prior keys keep working unchanged.
        data["score"] = {
            "total": score_report.total_score,
            "grade": score_report.grade,
            "distinct_risks": score_report.distinct_risks,
            "review_needed": score_report.review_needed,
            "threat_model": "public-oss-default",
            "user_assessment_required": True,
            "triage_doc": "docs/AI_TRIAGE.md",
        }

    return json.dumps(data, indent=2)
