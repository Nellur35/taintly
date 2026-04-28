"""SARIF 2.1.0 output reporter for GitHub Advanced Security and GitLab security dashboard."""

from __future__ import annotations

import json
from typing import Any

from taintly import __version__
from taintly.models import AuditReport, Severity

_LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_TOOL_NAME = "taintly"
_TOOL_URI = "https://github.com/Nellur35/taintly"
_TOOL_VERSION = __version__


def _build_rules(report: AuditReport) -> list[dict[str, Any]]:
    """Build the SARIF rules array from unique findings."""
    seen: dict[str, dict[str, Any]] = {}
    for f in report.findings:
        if f.rule_id in seen:
            continue
        rule = {
            "id": f.rule_id,
            "name": f.rule_id.replace("-", "_"),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description},
            "defaultConfiguration": {
                "level": _LEVEL_MAP.get(f.severity, "warning"),
            },
            "properties": {
                "tags": (
                    ([f.owasp_cicd] if f.owasp_cicd else [])
                    + [f"STRIDE:{c}" for c in (f.stride or [])]
                ),
                "severity": f.severity.value,
                "threat_narrative": f.threat_narrative or "",
                "incidents": f.incidents or [],
            },
        }
        if f.reference:
            rule["helpUri"] = f.reference
        if f.remediation:
            rule["help"] = {"text": f.remediation.split("\n")[0]}
        seen[f.rule_id] = rule
    return list(seen.values())


def _build_notifications(report: AuditReport) -> list[dict[str, Any]]:
    """Mirror ENGINE-ERR findings into SARIF tool-execution notifications.

    Per SARIF 2.1.0 §3.58, runtime events the tool itself raises (file
    unreadable, regex skipped, rule crashed) belong in
    ``invocations[*].toolExecutionNotifications`` — not in ``results``,
    which are reserved for findings about the analysed code.  We mirror
    rather than move so existing GitHub Advanced Security / GitLab
    dashboards that already show ENGINE-ERR as a SARIF result keep
    working.
    """
    out: list[dict[str, Any]] = []
    for f in report.engine_errors():
        out.append(
            {
                "level": _LEVEL_MAP.get(f.severity, "warning"),
                "message": {"text": f.title},
                "descriptor": {"id": f.rule_id},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file,
                                "uriBaseId": "%SRCROOT%",
                            },
                        },
                    }
                ]
                if f.file
                else [],
            }
        )
    return out


def format_sarif(report: AuditReport) -> str:
    rules = _build_rules(report)
    # rule_ids = {r["id"] for r in rules}  # reserved for dedup

    results = []
    for f in report.findings:
        # v2 reporting metadata travels in SARIF "properties" — GitHub and
        # GitLab both preserve unknown properties and surface them in
        # their dashboards so integrations can filter/group on these
        # without needing tool-specific knowledge.
        properties: dict[str, Any] = {}
        if f.finding_family:
            properties["finding_family"] = f.finding_family
        if f.confidence:
            properties["confidence"] = f.confidence
        if f.exploitability:
            properties["exploitability"] = f.exploitability
        if f.review_needed:
            properties["review_needed"] = True

        # SARIF `result` objects are heterogeneously nested (message,
        # locations array of physical/logical location trees, optional
        # properties/fixes). Explicit `Any` values let mypy track the
        # subsequent subscript-assignment below.
        result: dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": _LEVEL_MAP.get(f.severity, "warning"),
            "message": {"text": f.description[:1000]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": max(f.line, 1),
                        },
                    },
                }
            ],
        }
        if f.snippet:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": f.snippet[:500]
            }
        if properties:
            result["properties"] = properties
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": _TOOL_VERSION,
                        "informationUri": _TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "artifacts": list(
                    {
                        f.file: {"location": {"uri": f.file, "uriBaseId": "%SRCROOT%"}}
                        for f in report.findings
                    }.values()
                ),
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": _build_notifications(report),
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif, indent=2)
