"""Evasion corpus tests.

These tests assert that the tool CANNOT detect the documented bypasses.
A test PASSING here means the bypass is confirmed real.
A test FAILING here means a bypass was accidentally fixed — which is GOOD,
but the file should then be moved to fixtures/vulnerable/ and tested for detection.

Each entry carries metadata (audit chunk 3.3):

  discovered:  ISO date when the bypass was first documented.
  severity:    severity of the rule(s) the bypass evades. Long-lived
               bypasses against CRITICAL rules deserve higher
               prioritisation than equivalent gaps against INFO rules.
  platform:    which platform's rule pack is bypassed.

These metadata fields ride into the parametrize ID so test output
surfaces "this CRITICAL rule has had a known bypass for N months."

Run with: pytest tests/evasion/ -v
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform

EVASION_DIR = Path(__file__).parent


@dataclass(frozen=True)
class EvasionEntry:
    filename: str
    bypassed_rules: tuple[str, ...]
    notes: str
    discovered: str  # ISO date
    severity: str    # CRITICAL / HIGH / MEDIUM / LOW / INFO
    platform: str    # github / gitlab / jenkins


_EVASION_ENTRIES: tuple[EvasionEntry, ...] = (
    # ── Original GitHub corpus ─────────────────────────────────────────
    EvasionEntry(
        filename="variable_indirection.yml",
        bypassed_rules=("SEC4-GH-006",),
        notes="OUT=$GITHUB_ENV splits the pattern across lines",
        discovered="2025-08-01",
        severity="HIGH",
        platform="github",
    ),
    EvasionEntry(
        filename="cross_job_output_routing.yml",
        bypassed_rules=("SEC6-GH-004", "SEC6-GH-005"),
        notes="Secret routed through job outputs — cross-job taint invisible to static analysis",
        discovered="2025-08-01",
        severity="HIGH",
        platform="github",
    ),
    EvasionEntry(
        filename="base64_shell.yml",
        bypassed_rules=("SEC6-GH-007",),
        notes="curl|bash encoded in base64 — literal pattern never appears",
        discovered="2025-09-01",
        severity="HIGH",
        platform="github",
    ),
    EvasionEntry(
        filename="orphaned_sha.yml",
        bypassed_rules=("SEC3-GH-001",),
        notes=(
            "40-char hex pointing to orphaned fork commit — indistinguishable "
            "from real SHA without a network call. Mirrors the Mar-2026 "
            "aquasecurity/trivy attack."
        ),
        discovered="2026-03-15",
        severity="HIGH",
        platform="github",
    ),
    EvasionEntry(
        filename="shell_export_unsecure.yml",
        bypassed_rules=("SEC4-GH-009",),
        notes="export ACTIONS_ALLOW_UNSECURE_COMMANDS=true in run: not detected",
        discovered="2025-09-01",
        severity="HIGH",
        platform="github",
    ),
    EvasionEntry(
        filename="github_env_heredoc.yml",
        bypassed_rules=("SEC4-GH-006",),
        notes=(
            "Heredoc write to $GITHUB_ENV splits the ${{ ... }} and `>> $GITHUB_ENV` "
            "across lines — SEC4-GH-006's per-line regex cannot bridge them. Note "
            "SEC4-GH-004 still fires on the general context-in-run: surface, so "
            "detection degrades gracefully rather than failing silently."
        ),
        discovered="2025-10-01",
        severity="HIGH",
        platform="github",
    ),
    # ── GitLab + Jenkins + AI-cluster expansion (audit chunk 3.1) ──────
    # Pre-audit corpus had zero entries for GitLab / Jenkins / AI rules;
    # these four close that gap with rule-engineering-honest fixtures
    # (each is a real evasion vector against a real rule, not synthetic
    # filler).
    EvasionEntry(
        filename="gitlab_var_indirection.yml",
        bypassed_rules=("TAINT-GL-001",),
        notes=(
            "GitLab analog of GH variable_indirection: storing the "
            "tainted CI variable in a shell variable splits source/sink "
            "across lines. TAINT-GL-001's flow analyzer is single-line "
            "anchored same as GH SEC4-GH-006."
        ),
        discovered="2026-05-09",
        severity="HIGH",
        platform="gitlab",
    ),
    EvasionEntry(
        filename="jenkins_groovy_concat.Jenkinsfile",
        bypassed_rules=("SEC4-JK-001",),
        notes=(
            "Groovy string concatenation (sh 'literal' + params.X) avoids "
            "the double-quoted GString shape SEC4-JK-001 anchors on, "
            "while still injecting the parameter into the shell."
        ),
        discovered="2026-05-09",
        severity="HIGH",
        platform="jenkins",
    ),
    EvasionEntry(
        filename="ai_agent_via_indirection.yml",
        bypassed_rules=("AI-GH-005",),
        notes=(
            "AI-GH-005's prompt-injection-surface anchor only sees "
            "step-level `with:` keys. Sourcing the prompt via env: var "
            "(then using it inside run:) bypasses the surface check."
        ),
        discovered="2026-05-09",
        severity="HIGH",
        platform="github",
    ),
    EvasionEntry(
        filename="multi_hop_split_jobs.yml",
        bypassed_rules=("TAINT-GH-002",),
        notes=(
            "Multi-hop taint chained across non-contiguous steps. The "
            "analyzer's step segmentation walks sibling steps and may "
            "lose the chain when an unrelated step interrupts the "
            "source/indirection sequence."
        ),
        discovered="2026-05-09",
        severity="HIGH",
        platform="github",
    ),
)


@pytest.mark.parametrize(
    "entry",
    _EVASION_ENTRIES,
    ids=lambda e: f"{e.platform}-{e.severity}-{e.discovered}-{e.filename}",
)
def test_evasion_bypass_confirmed(entry: EvasionEntry, github_rules, gitlab_rules, jenkins_rules):
    """Confirm that documented bypasses are not detected.

    If a rule here starts firing, it means the bypass was fixed.
    In that case: run ``python scripts/promote_evasion.py FILENAME RULE_ID``
    to move the fixture into vulnerable/ and add a detection test, then
    remove it from this parametrize list.
    """
    rules = {
        "github": github_rules,
        "gitlab": gitlab_rules,
        "jenkins": jenkins_rules,
    }[entry.platform]

    filepath = EVASION_DIR / entry.filename
    findings = scan_file(str(filepath), rules=rules)
    fired = {f.rule_id for f in findings if f.rule_id != "ENGINE-ERR"}

    for rule_id in entry.bypassed_rules:
        assert rule_id not in fired, (
            f"BYPASS FIXED: {entry.filename} now triggers {rule_id}!\n"
            f"This is good — promote it to fixtures/vulnerable/.\n"
            f"  python scripts/promote_evasion.py {entry.filename} {rule_id}\n"
            f"Notes: {entry.notes}"
        )
