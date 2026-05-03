"""CSV output reporter."""

from __future__ import annotations

import csv
import io

from taintly.models import AuditReport
from taintly.reporters.text import INVENTORY_RULE_IDS

_FIELDS = [
    "rule_id",
    "kind",
    "severity",
    "title",
    "file",
    "line",
    "snippet",
    "owasp_cicd",
    "stride",
    "threat_narrative",
    "incidents",
    "description",
    "remediation",
    "reference",
    "context_notes",
    "context_tags",
    "triage_needed",
    "suppression_reason",
    "calibration_reason",
]


def format_csv(report: AuditReport) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_FIELDS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for f in report.findings:
        row = f.to_dict()
        # ``kind`` distinguishes vulnerability findings from third-party
        # inventory items so spreadsheet consumers can filter without
        # carrying a hardcoded inventory rule list.
        row["kind"] = "inventory" if f.rule_id in INVENTORY_RULE_IDS else "finding"
        # Truncate long fields for readability
        row["description"] = row["description"][:200]
        row["remediation"] = row["remediation"].split("\n")[0][:200]
        # Flatten list fields to delimited strings
        row["stride"] = "+".join(row.get("stride") or [])
        row["incidents"] = "; ".join(row.get("incidents") or [])
        row["context_notes"] = "; ".join(row.get("context_notes") or [])
        row["context_tags"] = "; ".join(row.get("context_tags") or [])
        writer.writerow(row)
    return buf.getvalue()
