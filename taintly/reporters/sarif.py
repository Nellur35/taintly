"""SARIF 2.1.0 output reporter for GitHub Advanced Security and GitLab security dashboard."""

from __future__ import annotations

import json
from typing import Any

from taintly import __version__
from taintly.baseline import fingerprint
from taintly.models import AuditReport, Severity
from taintly.reporters.text import INVENTORY_RULE_IDS


def _finding_sort_key(f: Any) -> tuple[str, int, str, str]:
    """Deterministic, content-derived ordering for findings in machine-readable
    output (SARIF/JSON), so byte-identical input yields byte-identical output
    and GHAS/GitLab dashboards don't churn on incidental reordering."""
    return (f.file or "", f.line or 0, f.rule_id or "", (f.snippet or "")[:200])


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


def _build_rules(findings: list[Any]) -> list[dict[str, Any]]:
    """Build the SARIF rules array from unique findings (caller passes a
    deterministically-sorted list so the rules array order is stable)."""
    seen: dict[str, dict[str, Any]] = {}
    for f in findings:
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
    for f in sorted(report.engine_errors(), key=_finding_sort_key):
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
    # Sort once up front so the rules array, results, and artifacts are all
    # emitted in a stable, content-derived order — byte-identical across runs.
    findings = sorted(report.findings, key=_finding_sort_key)
    rules = _build_rules(findings)

    results = []
    for f in findings:
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
        if f.context_notes:
            properties["context_notes"] = f.context_notes
        if f.context_tags:
            properties["context_tags"] = f.context_tags
        if f.triage_needed:
            properties["triage_needed"] = True
        if f.suppression_reason:
            properties["suppression_reason"] = f.suppression_reason
        if f.calibration_reason:
            properties["calibration_reason"] = f.calibration_reason

        # Inventory items (third-party CI surface area to review
        # periodically) get SARIF ``kind: "review"`` so dashboards
        # that distinguish review-tracked items from active findings
        # can group them automatically.  The ``taintly_kind`` property
        # is an explicit redundant signal for tool-specific filtering.
        is_inventory = f.rule_id in INVENTORY_RULE_IDS
        if is_inventory:
            properties["taintly_kind"] = "inventory"

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
        # Stable cross-run identity for GHAS / GitLab dashboard dedup; the
        # line number is excluded by design (see baseline.fingerprint), so a
        # finding that drifts lines keeps the same fingerprint.
        result["partialFingerprints"] = {"taintlyFingerprintV1": fingerprint(f, report.repo_path)}
        if is_inventory:
            result["kind"] = "review"
        if f.snippet:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": f.snippet[:500]
            }
        if properties:
            result["properties"] = properties
        results.append(result)

    # Top-level summary mirrors the JSON reporter's findings/inventory
    # split so SARIF consumers (dashboards, aggregators) can show the
    # two counts without enumerating ``results`` themselves.  Tool-
    # specific properties on the run are preserved by both GitHub
    # Advanced Security and GitLab's security dashboard.
    findings_count = sum(1 for f in report.findings if f.rule_id not in INVENTORY_RULE_IDS)
    inventory_count = sum(1 for f in report.findings if f.rule_id in INVENTORY_RULE_IDS)

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
                        for f in findings
                    }.values()
                ),
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": _build_notifications(report),
                    }
                ],
                "properties": {
                    "findings_count": findings_count,
                    "inventory_count": inventory_count,
                },
            }
        ],
    }

    return json.dumps(sarif, indent=2)


def format_sarif_reports(reports: list[AuditReport]) -> str:
    """Render multiple reports as one SARIF document with one run each."""
    if not reports:
        raise ValueError("at least one report is required")

    documents = [json.loads(format_sarif(report)) for report in reports]
    document = documents[0]
    document["runs"] = [run for item in documents for run in item["runs"]]
    return json.dumps(document, indent=2)
