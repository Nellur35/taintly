"""Finding families — root-cause clustering for reporting v2.

Why this exists
---------------
The scanner can fire several correlated rules for one underlying weakness.
For example, a reusable workflow referenced by ``@main`` triggers:

    - SEC3-GH-001 (unpinned action / mutable tag)
    - SEC3-GH-002 (branch-pinned reference)
    - SEC8-GH-003 (unpinned reusable workflow)

These three hits describe **one** root-cause cluster ("mutable external
reusable workflow reference"), not three unrelated problems. The raw rule
list should still be preserved for debugging and triage, but the summary
and scoring layers need the clustered view so the report reflects distinct
risks rather than detector volume.

Design
------
Each family has:

* ``id``        — stable identifier used in JSON output and suppressions
* ``title``     — human-readable cluster name
* ``why``       — short "why it matters" paragraph shown in reports
* ``members``   — set of rule IDs that belong to the family

The ``DEFAULT_FALLBACKS`` map provides a coarse OWASP-prefix -> family
mapping for any rule that isn't explicitly listed. This keeps us from
having to exhaustively enumerate all 105+ rule IDs; rules that don't need
special grouping fall into an OWASP-derived bucket automatically.

Rules can also set ``Rule.finding_family`` and ``Rule.confidence`` directly
when the generic mapping would be misleading. That per-rule override is
the escape hatch; this module provides the defaults.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from taintly.models import Confidence, Finding


@dataclass
class FindingFamily:
    id: str
    title: str
    why: str
    members: frozenset[str] = field(default_factory=frozenset)


# ---------------------------------------------------------------------------
# Explicit family definitions
# ---------------------------------------------------------------------------
#
# Only list rules here when they either (a) describe the same underlying
# weakness as another rule in the family, or (b) need a family that differs
# from the OWASP-derived default.  Everything else falls through to
# ``DEFAULT_FALLBACKS`` below.

_FAMILIES: tuple[FindingFamily, ...] = (
    FindingFamily(
        id="supply_chain_immutability",
        title="Mutable dependency references",
        why=(
            "Actions, reusable workflows, and includes referenced by tag or "
            "branch can be force-pushed to point at different code without "
            "any record in your repository's history. Pin every external "
            "dependency to a full 40-char commit SHA."
        ),
        members=frozenset(
            {
                "SEC3-GH-001",
                "SEC3-GH-002",
                "SEC3-GH-003",
                "SEC8-GH-003",  # unpinned reusable workflow
                "SEC3-GL-001",
                "SEC3-GL-002",
                "PLAT-GH-009",  # Dependabot security updates disabled
                "PLAT-GH-010",  # Vulnerability alerts disabled
            }
        ),
    ),
    FindingFamily(
        id="privileged_pr_trigger",
        title="Privileged PR-trigger exposure",
        why=(
            "Workflows that run with write permissions or secrets in "
            "response to fork-controlled events (pull_request_target, "
            "issue_comment) are the single biggest source of public CI "
            "compromises. Each finding in this family expands the attacker's "
            "control surface."
        ),
        # Only trigger-level rules belong here.  SEC4-GH-004 is script
        # injection and SEC4-GH-005 is credential persistence — those
        # belong to their own families even though they live in SEC4.
        members=frozenset(
            {
                "SEC4-GH-001",
                "SEC4-GH-002",
                "SEC4-GH-003",
            }
        ),
    ),
    FindingFamily(
        id="script_injection",
        title="User-controlled input reaching shell execution",
        why=(
            "PR titles, commit messages, issue bodies, and branch names are "
            "attacker-controlled. When these values are expanded into run: "
            "blocks or written to $GITHUB_ENV / $GITHUB_OUTPUT, the "
            "attacker gets arbitrary code execution with the workflow's "
            "full permissions."
        ),
        # NB: the LOTP-GH-* rules used to live here.  P1.2 (targeted) moved
        # them to ``pipeline_tool_execution`` after the corpus measurement
        # showed build-tool / lifecycle-script execution genuinely collapsing
        # into this family even though its remediation (--ignore-scripts / drop
        # the PR checkout) is unrelated to input sanitization.
        members=frozenset(
            {
                "SEC4-GH-004",
                "SEC4-GH-006",
                "SEC4-GH-007",
                "SEC4-GH-008",
                "SEC4-GH-011",
                "TAINT-GH-001",
            }
        ),
    ),
    FindingFamily(
        id="credential_persistence",
        title="Credential persistence and exfiltration surface",
        why=(
            "Persisting the auto-generated GITHUB_TOKEN in .git/config or "
            "leaving secrets available to untrusted steps lets a later "
            "compromise pivot into repository write or package publish "
            "without needing to escalate privileges."
        ),
        # NB: SEC6-GL-002 (curl piped to shell) used to live here.  P1.2
        # (targeted) moved it to ``untrusted_code_execution`` — a curl|bash
        # primitive is remote code execution, not credential persistence, and
        # the corpus showed it collapsing this family's deduction.
        members=frozenset(
            {
                "SEC4-GH-005",  # checkout persists credentials — classic pivot surface
                "SEC4-GH-005B",  # checkout persists credentials — posture sibling
                "SEC6-GH-001",
                "SEC6-GH-003",
                "SEC6-GL-001",
                "PLAT-GH-013",  # Webhooks without HTTPS or secret
                "PLAT-GH-016",  # Secret scanning disabled/incomplete
                "PLAT-GL-010",  # GitLab webhooks insecure
            }
        ),
    ),
    FindingFamily(
        id="repository_governance",
        title="Repository governance and branch protection",
        why=(
            "Without branch protection, code-owner review, or fork-PR "
            "approval gating, a compromised contributor account or a "
            "merge-time mistake can push workflow changes straight to "
            "the default branch — bypassing every CI-time check the "
            "rest of this tool exists to enforce."
        ),
        members=frozenset(
            {
                # Platform-posture findings about branch rulesets, CODEOWNERS,
                # fork-PR approval, and default-branch protection belong here
                # rather than in resource_controls (where the OWASP-CICD-1
                # fallback would otherwise send them).
                "PLAT-GH-001",
                "PLAT-GH-002",
                "PLAT-GH-008",
                "PLAT-GH-011",  # Wiki attack surface
                "PLAT-GL-001",
                "PLAT-GL-002",
            }
        ),
    ),
    FindingFamily(
        id="identity_access",
        title="Over-broad token permissions",
        why=(
            "Missing or permissive permissions blocks give the workflow's "
            "GITHUB_TOKEN far more capability than the job actually needs. "
            "An injection or compromised dependency in that workflow gets "
            "the same broad scope."
        ),
        members=frozenset(
            {
                "SEC2-GH-001",
                "SEC2-GH-002",
                "SEC2-GH-003",
                # Platform posture: default-token-permission-is-write
                "PLAT-GH-007",
                "PLAT-GH-012",  # Deploy keys with write access
                "PLAT-GH-014",  # Outside collaborators with admin
                "PLAT-GL-009",  # GitLab deploy keys with write
                "PLAT-GL-011",  # GitLab owner-level members
                "PLAT-JK-001",  # Jenkins anonymous access
                "ACCT-GH-001",  # 2FA not enabled
                "ACCT-GH-002",  # Org 2FA not required
                "ACCT-GH-003",  # Org default permissions too broad
            }
        ),
    ),
    FindingFamily(
        id="resource_controls",
        title="Missing job resource / timeout controls",
        why=(
            "Jobs without explicit timeout-minutes can hang indefinitely, "
            "tying up runner capacity. In combination with a prompt-"
            "injection or DoS-triggering input, this becomes a cost and "
            "availability issue."
        ),
        members=frozenset(
            {
                "SEC1-GH-001",
                "SEC1-GH-002",
                "SEC1-GL-001",
                "SEC1-GL-002",
                # SEC10-GH-001 lives in the "logging & visibility" OWASP bucket
                # but is fundamentally a missing-timeout rule. Classify by
                # what it detects, not where OWASP files it.
                "SEC10-GH-001",
            }
        ),
    ),
    FindingFamily(
        id="release_integrity",
        title="Release / artifact integrity",
        why=(
            "Publishing workflows without provenance attestation, signature "
            "verification, or cache immutability let an upstream compromise "
            "turn into a distributed package compromise."
        ),
        members=frozenset(
            {
                "SEC9-GH-001",
                "SEC9-GH-002",
                "SEC9-GH-003",
                "SEC9-GL-001",
            }
        ),
    ),
    FindingFamily(
        id="ungoverned_services",
        title="Ungoverned / self-hosted runner exposure",
        why=(
            "Self-hosted runners on public repositories, third-party "
            "services pulled via curl|bash, and broad network egress all "
            "expand the attack surface beyond what static workflow review "
            "can cover."
        ),
        members=frozenset(
            {
                "SEC8-GH-001",
                "SEC8-GH-002",
                "SEC8-GL-001",
                # SEC8-GL-002 retired (duplicate of SEC3-GL-002).
            }
        ),
    ),
    FindingFamily(
        id="logging_visibility",
        title="Logging and visibility gaps",
        why=(
            "Workflows that disable logging, mask outputs aggressively, or "
            "omit audit-trail-relevant steps reduce the chance of detecting "
            "a compromise after the fact."
        ),
        members=frozenset(
            {
                # SEC10-GH-001 is *not* listed here — it's in resource_controls
                # because it's a missing-timeout rule, not a logging one.
                "SEC10-GH-002",
                "SEC10-GL-001",
            }
        ),
    ),
    FindingFamily(
        id="agent_instruction_file_inventory",
        title="AI agent instruction-file inventory",
        why=(
            "Files like ``CLAUDE.md``, ``.cursorrules``, ``AGENTS.md``, "
            "and ``.github/copilot-instructions.md`` are auto-loaded by "
            "AI agent harnesses (Claude Code, Cursor, Aider, GitHub "
            "Copilot, Gemini Code, Windsurf) as user-trust-tier "
            "instructions whenever an agent runs against the repo.  A "
            "malicious public repository — a fork, a transitive "
            "dependency cloned into a workspace, an issue-driven "
            "checkout — can plant attacker-controlled directives in "
            "those files and have a downstream agent execute them with "
            "the operator's full trust level.  This is the indirect-"
            "prompt-injection / supply-chain variant of the AI-agent "
            "rules: the file is not malicious in isolation, but its "
            "presence is the attack surface a reviewer needs to inventory."
        ),
        members=frozenset(
            {
                "AI-GH-036",
            }
        ),
    ),
    FindingFamily(
        id="ai_ml_model_risk",
        title="AI / ML model and agent risk",
        why=(
            "AI-specific supply-chain and execution risks don't share a "
            "remediation path with classic dependency pinning or script "
            "injection. A model file is executable (pickle, torch, keras); "
            "an AI coding agent is a weird-shaped privilege; the prompt is "
            "a control channel. Fixing one finding in this cluster — "
            "pinning a HuggingFace revision, passing weights_only=True, "
            "scoping an agent's tool surface — rarely addresses the "
            "others, so the reporter shows them as their own cluster "
            "rather than folding them into supply-chain or PPE families."
        ),
        members=frozenset(
            {
                "AI-GH-001",
                "AI-GH-002",
                "AI-GH-003",
                "AI-GH-004",
                "AI-GH-005",
                "AI-GH-006",
                "AI-GH-007",
                "AI-GH-008",
                "AI-GH-009",
                "AI-GH-010",
                "AI-GH-011",
                "AI-GH-012",
                "AI-GH-013",
                "AI-GH-014",
                "TAINT-GH-005",
                "AI-GL-001",
                "AI-GL-002",
                "AI-GL-003",
                "AI-GL-004",
                "AI-GL-005",
                "AI-GL-006",
                "AI-GL-007",
                "AI-GL-008",
                "AI-JK-001",
                "AI-JK-002",
                "AI-JK-003",
                "AI-JK-004",
            }
        ),
    ),
    FindingFamily(
        id="pipeline_tool_execution",
        title="Build-tool / package-manager execution in untrusted context",
        why=(
            "A build tool, test runner, or package-manager install that runs "
            "in a fork-reachable job executes attacker-supplied lifecycle "
            "scripts (npm/yarn/pnpm postinstall, a malicious setup.py, a "
            "Gradle/Maven plugin) WITHOUT any attacker-controlled string ever "
            "reaching a shell. The remediation is unrelated to input "
            "sanitization — pass --ignore-scripts, pin the toolchain, or drop "
            "the PR-head checkout — so this is a distinct root cause from the "
            "PR-title-into-run: script injection it used to be folded under "
            "(CICD-SEC-4)."
        ),
        # Living-off-the-pipeline rules + the SEC4 npm-lifecycle sibling.  Split
        # out of ``script_injection`` by P1.2 after the corpus measurement
        # showed them collapsing that family's per-cluster deduction.
        members=frozenset(
            {
                "LOTP-GH-001",
                "LOTP-GH-003",
                "LOTP-GH-004",
                "LOTP-GH-005",
                "LOTP-GL-001",
                "LOTP-GL-003",
                "LOTP-GL-005",
                "LOTP-JK-001",
                "LOTP-JK-003",
                "LOTP-JK-005",
                "SEC4-GH-011A",  # npm install in pull_request_target without --ignore-scripts
            }
        ),
    ),
    FindingFamily(
        id="untrusted_code_execution",
        title="Remote / encoded code fetched and executed in the pipeline",
        why=(
            "curl|bash, wget|sh, base64-decode-then-exec, eval on a variable, "
            "and remote-Groovy load are all ways the pipeline runs code that "
            "was never reviewed in the repository. The fix is to fetch to a "
            "file, verify a checksum or signature, and run the pinned artifact "
            "— a supply-chain integrity control, not the credential-hygiene "
            "remediation of the CICD-SEC-6 family these rules used to fold "
            "into."
        ),
        # curl|bash / eval / base64-exec / remote-Groovy primitives split out
        # of ``credential_persistence`` (and one SEC8 Jenkins sibling) by P1.2.
        members=frozenset(
            {
                "SEC6-GH-006",  # base64-decoded payload executed
                "SEC6-GH-007",  # curl/wget piped to shell
                "SEC6-GL-002",  # curl piped to shell
                "SEC6-GL-004",  # eval in script block
                "SEC6-GL-006",  # wget|bash / curl-subshell
                "SEC8-JK-002",  # remote Groovy script fetched from URL and executed
            }
        ),
    ),
    FindingFamily(
        id="insecure_transport",
        title="Disabled TLS / cleartext transport",
        why=(
            "Disabling certificate verification (curl -k, "
            "GIT_SSL_NO_VERIFY, an HTTP Request step with TLS validation off) "
            "or pulling over cleartext HTTP lets a network attacker MITM the "
            "fetched bytes. The remediation — re-enable verification, use "
            "HTTPS, pin a CA — is independent of the secret-handling fixes in "
            "the CICD-SEC-6 family these rules used to fold into."
        ),
        # TLS-verification-disabled / cleartext rules split out of
        # ``credential_persistence`` (+ one SEC7 Jenkins sibling) by P1.2.
        members=frozenset(
            {
                "SEC6-GL-003",  # TLS verification disabled
                "SEC6-JK-004",  # TLS certificate verification disabled in shell step
                "SEC6-JK-009",  # HTTP Request step disables TLS verification
                "SEC7-JK-004",  # Docker registry over cleartext HTTP
            }
        ),
    ),
)


# ---------------------------------------------------------------------------
# Fallback mapping by OWASP-CICD category + rule-ID prefix
# ---------------------------------------------------------------------------

_OWASP_FAMILY: dict[str, str] = {
    "CICD-SEC-1": "resource_controls",
    "CICD-SEC-2": "identity_access",
    "CICD-SEC-3": "supply_chain_immutability",
    "CICD-SEC-4": "script_injection",
    "CICD-SEC-5": "identity_access",
    "CICD-SEC-6": "credential_persistence",
    "CICD-SEC-7": "ungoverned_services",
    "CICD-SEC-8": "ungoverned_services",
    "CICD-SEC-9": "release_integrity",
    "CICD-SEC-10": "logging_visibility",
}

# ---------------------------------------------------------------------------
# Confidence overrides — rules whose precision is known to be less than "high"
# ---------------------------------------------------------------------------
#
# These IDs default to a lower confidence so the reporter can surface them in
# the review-needed section instead of as confirmed risks.  Anything not
# listed here is treated as high-confidence (exact syntactic match).

_CONFIDENCE_OVERRIDES: dict[str, str] = {
    # Shallow intra-job taint — no multi-hop, no $GITHUB_ENV writes.
    "TAINT-GH-001": Confidence.MEDIUM.value,
    # Trigger-level rule: can be safe or dangerous depending on design intent.
    "SEC4-GH-002": Confidence.MEDIUM.value,
    # Secret-string heuristics — pattern-based, not context-aware.
    "SEC6-GL-002": Confidence.MEDIUM.value,
}

# ---------------------------------------------------------------------------
# Grandfather baseline — rules validated-at-HIGH (P3.6)
# ---------------------------------------------------------------------------
#
# Historically ``default_confidence`` returned HIGH for every un-overridden
# rule, so a brand-new rule scored at full weight (1.0) the moment it was
# added — before any precision validation. P3.6 splits that:
#
#   * the rules that already existed when this baseline was frozen are
#     GRANDFATHERED at HIGH (zero retroactive score shift), and
#   * a NEW / unmapped rule id defaults to MEDIUM until someone validates it
#     by adding its id to this baseline (or sets an explicit ``confidence=``
#     on the Rule definition).
#
# The committed list lives beside the tests so a rule author edits it in the
# same review that adds the rule — making "I validated this at HIGH" an
# explicit, diff-visible decision rather than a silent default. The file is
# the sorted set of every registered rule id NOT in ``_CONFIDENCE_OVERRIDES``
# at freeze time; regenerate it with ``scripts/check_confidence_grandfather.py
# --update`` when a rule is validated.
_GRANDFATHER_BASELINE_PATH = (
    Path(__file__).resolve().parent.parent / "tests" / "_confidence_grandfather_baseline.json"
)


def _load_grandfather_baseline() -> frozenset[str]:
    """Load the validated-at-HIGH rule-id set from the committed baseline.

    A missing or unreadable baseline is treated as empty: that makes every
    un-overridden rule default MEDIUM rather than silently HIGH, which is the
    safe direction (under-stating confidence never inflates a grade).
    """
    try:
        data = json.loads(_GRANDFATHER_BASELINE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return frozenset()
    if not isinstance(data, list):
        return frozenset()
    return frozenset(str(rid) for rid in data)


_GRANDFATHERED_HIGH: frozenset[str] = _load_grandfather_baseline()

# Rules that should be flagged as "review needed" rather than confirmed risk
# unless elevated by additional context (checkout, secrets, write perms, ...).
_REVIEW_NEEDED_RULES: frozenset[str] = frozenset(
    {
        "SEC4-GH-002",  # pull_request_target — safe-or-dangerous by design
        # workflow_dispatch with an unconstrained string input is sometimes
        # the right design (commit messages, PR URLs, version strings).
        # Route to review-needed so the team can confirm intent rather than
        # treating every free-text input as a confirmed MEDIUM finding.
        "SEC7-GH-004",
    }
)


# ---------------------------------------------------------------------------
# Indexes built once at import time
# ---------------------------------------------------------------------------

_BY_ID: dict[str, FindingFamily] = {f.id: f for f in _FAMILIES}
_RULE_TO_FAMILY: dict[str, str] = {}
for _fam in _FAMILIES:
    for _rid in _fam.members:
        _RULE_TO_FAMILY[_rid] = _fam.id


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify_rule(rule_id: str, owasp_cicd: str = "") -> str:
    """Return the family ID for a rule.

    Lookup order:
      1. Explicit member mapping (``_RULE_TO_FAMILY``)
      2. OWASP-CICD category fallback
      3. Empty string (unclassified; reporter falls back to rule_id)
    """
    fam = _RULE_TO_FAMILY.get(rule_id)
    if fam:
        return fam
    if owasp_cicd:
        return _OWASP_FAMILY.get(owasp_cicd, "")
    return ""


def default_confidence(rule_id: str) -> str:
    """Return the default confidence for a rule.

    Resolution order (P3.6 grandfather mechanism):

      1. An explicit ``_CONFIDENCE_OVERRIDES`` entry always wins.
      2. A rule id in the committed grandfather baseline — i.e. one that
         already existed and was validated-at-HIGH when the baseline was
         frozen — defaults to HIGH.
      3. Anything else (a new / unmapped rule id) defaults to MEDIUM, so an
         un-validated detector cannot score at full weight before it earns
         it. Validate it (add the id to the baseline) or set an explicit
         ``confidence=`` on the Rule to promote it.

    Note this governs only the DEFAULT; a Rule that carries its own
    ``confidence=`` bypasses this entirely (the engine resolves
    ``rule.confidence or default_confidence(rule.id)``).
    """
    if rule_id in _CONFIDENCE_OVERRIDES:
        return _CONFIDENCE_OVERRIDES[rule_id]
    if rule_id in _GRANDFATHERED_HIGH:
        return Confidence.HIGH.value
    return Confidence.MEDIUM.value


def default_review_needed(rule_id: str) -> bool:
    """Return whether a rule should default to the review-needed bucket."""
    return rule_id in _REVIEW_NEEDED_RULES


def iter_families() -> tuple[FindingFamily, ...]:
    """Return the canonical ordered tuple of families.

    Exposed so the scorer can build its debt profile without reaching
    into ``_FAMILIES`` directly.
    """
    return _FAMILIES


def describe_family(family_id: str) -> tuple[str, str]:
    """Return ``(title, why)`` for a family ID, or a synthesized default."""
    fam = _BY_ID.get(family_id)
    if fam is not None:
        return fam.title, fam.why
    # Unknown family — synthesize a neutral description so the reporter
    # doesn't break.
    return family_id.replace("_", " ").title(), ""


# ---------------------------------------------------------------------------
# Clustering helpers used by reporters and the scorer
# ---------------------------------------------------------------------------


@dataclass
class FindingCluster:
    """A group of findings that share the same root-cause family.

    ``affected_files`` / ``rule_ids`` are sets so the reporter can show
    aggregate counts without walking the full finding list.
    """

    family_id: str
    title: str
    why: str
    findings: list[Finding] = field(default_factory=list)
    affected_files: set[str] = field(default_factory=set)
    rule_ids: set[str] = field(default_factory=set)

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def top_severity_rank(self) -> int:
        return max((f.severity.rank for f in self.findings), default=0)

    @property
    def top_exploitability(self) -> str:
        """Highest exploitability tier across the cluster's findings.

        Used by the reporter to rank clusters: a CRITICAL finding in a
        no-secrets sandbox workflow should not outrank a HIGH finding in
        a release workflow with full write permissions.
        """
        order = {"high": 3, "medium": 2, "low": 1}
        if not self.findings:
            return "medium"
        best = max(self.findings, key=lambda f: order.get(f.exploitability, 2))
        return best.exploitability or "medium"

    @property
    def review_needed(self) -> bool:
        """A cluster is review-needed only if *all* its findings are."""
        return bool(self.findings) and all(f.review_needed for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "family_id": self.family_id,
            "title": self.title,
            "why": self.why,
            "finding_count": self.count,
            "rule_ids": sorted(self.rule_ids),
            "affected_files": sorted(self.affected_files),
            "review_needed": self.review_needed,
            "top_exploitability": self.top_exploitability,
        }


def cluster_findings(findings: list[Finding]) -> list[FindingCluster]:
    """Group findings into root-cause clusters.

    Findings with an empty ``finding_family`` fall through to a
    ``rule_id``-keyed bucket so they still appear in the output. The
    returned list is ordered by severity rank (desc), then by finding
    count (desc), then by family title (asc) for stable display.
    """
    buckets: dict[str, FindingCluster] = {}
    for f in findings:
        key = f.finding_family or f"rule:{f.rule_id}"
        if key not in buckets:
            title, why = describe_family(f.finding_family) if f.finding_family else (f.title, "")
            buckets[key] = FindingCluster(
                family_id=f.finding_family or f.rule_id,
                title=title,
                why=why,
            )
        cluster = buckets[key]
        cluster.findings.append(f)
        cluster.affected_files.add(f.file)
        cluster.rule_ids.add(f.rule_id)

    # Rank clusters by (severity × exploitability), then by spread.
    # Using the product means a CRITICAL cluster in a benign context
    # can still outrank a MEDIUM cluster in a privileged context, but
    # a HIGH+high-exploitability cluster will outrank a CRITICAL+low
    # cluster — matching the improvement report's "base severity +
    # contextual modifiers = final priority" model.
    _expl_mul = {"high": 1.0, "medium": 0.8, "low": 0.5}
    return sorted(
        buckets.values(),
        key=lambda c: (
            -(c.top_severity_rank * _expl_mul.get(c.top_exploitability, 0.8)),
            -c.top_severity_rank,
            -c.count,
            c.title,
        ),
    )
