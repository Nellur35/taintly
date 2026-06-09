"""Severity-aware exploitability floor (engine.py).

`family_id` drives BOTH clustering and exploitability, so a coarse OWASP→family
fallback can route a CRITICAL/HIGH rule into a hygiene family and let
`compute_exploitability` score it "low", discarding the rule's policy severity.
The floor refuses "low" for that exact mismatch. PSE-GH-006 (a CRITICAL fork-RCE
chain tagged CICD-SEC-1 → resource_controls by fallback) is the real instance.
"""

from __future__ import annotations

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform

_VULN = (
    "name: pr\n"
    "on: pull_request_target\n"
    "permissions: write-all\n"
    "jobs:\n"
    "  build:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: actions/checkout@v4\n"
    "        with:\n"
    "          ref: ${{ github.event.pull_request.head.sha }}\n"
    "      - run: npm install && npm test\n"
)

_BENIGN = (
    "name: ci\n"
    "on: push\n"
    "permissions: {}\n"
    "jobs:\n"
    "  t:\n"
    "    runs-on: ubuntu-latest\n"
    "    timeout-minutes: 5\n"
    "    steps:\n"
    "      - run: echo hi\n"
)


def _scan(content: str):
    rules = load_rules_for_platform(Platform.GITHUB)
    return scan_file("pr.yml", rules, content)


def test_floor_lifts_critical_hygiene_fallback_finding():
    """PSE-GH-006 (CRITICAL, routed to resource_controls by OWASP fallback) must
    NOT score 'low' on an attacker-reachable workflow — the floor lifts it to
    'medium' and tags it."""
    pse = [f for f in _scan(_VULN) if f.rule_id == "PSE-GH-006"]
    assert pse, "PSE-GH-006 should fire on the vuln workflow"
    f = pse[0]
    assert f.exploitability == "medium", f"expected floored medium, got {f.exploitability}"
    assert "severity-floor" in (f.context_tags or [])


def test_floor_does_not_fire_on_benign_workflow():
    """The floor must fire ONLY on the mismatch — a benign push workflow with no
    attacker-reachable context floors nothing."""
    floored = [f.rule_id for f in _scan(_BENIGN) if "severity-floor" in (f.context_tags or [])]
    assert floored == []


def test_floor_does_not_touch_correctly_classified_findings():
    """Findings that are NOT a CRITICAL/HIGH hygiene-fallback mismatch keep their
    computed exploitability (no spurious floor tag across the vuln scan)."""
    for f in _scan(_VULN):
        if "severity-floor" in (f.context_tags or []):
            assert f.severity.name in ("CRITICAL", "HIGH")
            assert not f.finding_family or f.finding_family in (
                "resource_controls",
                "logging_visibility",
            )
