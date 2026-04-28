"""CSV output reporter."""

from __future__ import annotations

import csv
import io

from taintly.models import AuditReport

_FIELDS = [
    "rule_id",
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
]


def format_csv(report: AuditReport) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_FIELDS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for f in report.findings:
        row = f.to_dict()
        # Truncate long fields for readability
        row["description"] = row["description"][:200]
        row["remediation"] = row["remediation"].split("\n")[0][:200]
        # Flatten list fields to delimited strings
        row["stride"] = "+".join(row.get("stride") or [])
        row["incidents"] = "; ".join(row.get("incidents") or [])
        writer.writerow(row)
    return buf.getvalue()
