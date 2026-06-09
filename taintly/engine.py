"""Core scanning engine — loads rules, applies patterns, produces findings."""

from __future__ import annotations

import glob
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass

from .families import classify_rule, default_confidence, default_review_needed
from .gitlab_workflow_corpus import GitLabCorpusPattern, build_gitlab_corpus
from .gitlabguard import (
    GitLabContext,
    detect_gitlab_context,
    find_dead_gitlab_job_ranges,
    is_pipeline_whole_dead,
)
from .jenkinsguard import (
    JenkinsContext,
    find_dead_jenkins_stage_ranges,
    is_jenkinsfile_whole_dead,
)
from .models import (
    _CHUNK_COVERAGE_CEILING,
    _MAX_SAFE_TEXT_LEN,
    AuditReport,
    Finding,
    Platform,
    Rule,
    Severity,
    scan_session,
)
from .parsers.anchor_expander import expand_anchors
from .parsers.segmentation import for_each_job, job_at_line
from .pse_enrichment import enrich_pse_findings
from .staticguard import WorkflowContext as StaticGuardContext
from .staticguard import (
    detect_github_workflow_context,
    find_dead_line_ranges,
    is_workflow_whole_dead,
)
from .workflow_context import HARDEN_RUNNER_TEMPERED_FAMILIES, compute_exploitability
from .workflow_context import analyze as analyze_workflow
from .workflow_corpus import CorpusPattern, build_corpus, is_fork_reachable

# Hygiene families that ``classify_rule`` falls back to from broad OWASP
# categories (CICD-SEC-1 → resource_controls, CICD-SEC-10 → logging_visibility).
# ``compute_exploitability`` scores these "low" unconditionally, so a
# CRITICAL/HIGH rule with no explicit ``finding_family`` that lands here by
# fallback gets its exploitability silently rewritten to a hygiene tier — the
# severity-floor below guards exactly that mismatch.
_HYGIENE_FALLBACK_FAMILIES = frozenset({"resource_controls", "logging_visibility"})

# ---------------------------------------------------------------------------
# Inline suppression
# ---------------------------------------------------------------------------

_SUPPRESS_GENERIC = re.compile(r"#\s*taintly:\s*ignore\s*$", re.IGNORECASE)
_SUPPRESS_SPECIFIC = re.compile(r"#\s*taintly:\s*ignore\[([^\]]+)\]", re.IGNORECASE)


# Rules whose finding describes a project-level setting rather than a
# per-file pattern.  Firing them once per workflow file in a multi-file
# repo is noise — the underlying configuration is the same regardless
# of how many YAML files exist.  ``_dedupe_project_scope`` keeps only
# the first occurrence (lowest file path) per scan so the report
# surfaces the issue exactly once.
_PROJECT_SCOPE_RULES: frozenset[str] = frozenset(
    {
        "SEC10-GL-002",  # Public-pipelines visibility — a GitLab project setting
        # AI-GH-036 fires per workflow file when the repo contains an
        # agent-instruction file (CLAUDE.md, .cursorrules, AGENTS.md, …).
        # The presence is a repo-root property, not a workflow property,
        # so the per-file fan-out is noise.  Project-scope dedup keeps
        # the first occurrence per scan.
        "AI-GH-036",
        # AI-GH-039 reads the agent-instruction file's *content* at
        # repo-root scope and fires on directive×mutable-remote-ref.
        # Same dedup rationale as AI-GH-036 — the underlying state is
        # repo-content, not workflow-content, so per-file fan-out is
        # noise.  AI-GH-037 / AI-GH-038 are step-scoped and stay
        # off this list.
        "AI-GH-039",
    }
)


def _dedupe_project_scope(findings: list[Finding]) -> list[Finding]:
    """Keep only the first finding per project-scope rule_id.

    Project-scope rules describe one underlying configuration that is
    shared across every workflow file in the project.  Reporting them
    per file inflates the noise without adding signal.
    """
    seen_project_scope: set[str] = set()
    deduped: list[Finding] = []
    for f in findings:
        if f.rule_id in _PROJECT_SCOPE_RULES:
            if f.rule_id in seen_project_scope:
                continue
            seen_project_scope.add(f.rule_id)
        deduped.append(f)
    return deduped


def _dedupe_supersedes(findings: list[Finding], rules: list[Rule]) -> list[Finding]:
    """Drop findings whose rule_id is superseded by another rule that
    also fires on the same ``(file, line)``.

    Each rule may declare ``supersedes: list[str]`` naming rule IDs
    whose findings should be suppressed when this rule also fires on
    the same source location.  This collapses the canonical "one
    underlying bug, multiple overlapping rules" noise — e.g. a
    Jenkins ``sh "echo ${env.CHANGE_TITLE}"`` line that triggers
    TAINT-JK-001 CRITICAL + SEC4-JK-002 HIGH + SEC4-JK-005 HIGH +
    SEC4-JK-008 MEDIUM is reduced to just the CRITICAL.

    No-op when no rule in the pack declares ``supersedes``.  The
    relationship is strict: only declare it when every shape the
    superseded rule detects is also detected by the superseding rule
    — otherwise we silently drop real coverage.
    """
    # Build a lookup: superseded_id -> set of rule IDs that supersede it.
    superseded_by: dict[str, set[str]] = {}
    for rule in rules:
        for child_id in rule.supersedes:
            superseded_by.setdefault(child_id, set()).add(rule.id)

    if not superseded_by:
        return findings

    # Index which rule IDs fire on each (file, line).
    rules_at_loc: dict[tuple[str, int], set[str]] = {}
    for f in findings:
        rules_at_loc.setdefault((f.file, f.line), set()).add(f.rule_id)

    kept: list[Finding] = []
    for f in findings:
        supersedors = superseded_by.get(f.rule_id)
        if supersedors and supersedors & rules_at_loc[(f.file, f.line)]:
            # A superseding rule fired on the same line — drop this finding.
            continue
        kept.append(f)
    return kept


def _is_suppressed(line: str, rule_id: str) -> bool:
    """Return True if the line carries a taintly suppression comment for rule_id.

    Supported forms:
      # taintly: ignore                     — suppress all rules on this line
      # taintly: ignore[SEC3-GH-001]        — suppress a specific rule
      # taintly: ignore[SEC3-GH-001,SEC3-GH-002]  — suppress multiple rules

    Optionally also honours foreign-scanner inline-ignore comments
    when the user has opted in via ``--respect-zizmor-ignores``; the
    foreign-format check only runs in that mode so the default
    behaviour stays "taintly's own format only".
    """
    if _SUPPRESS_GENERIC.search(line):
        return True
    m = _SUPPRESS_SPECIFIC.search(line)
    if m:
        suppressed = {s.strip() for s in m.group(1).split(",")}
        if rule_id in suppressed:
            return True
    # Foreign-scanner suppression interop (opt-in).  Late import keeps
    # the default suppression path dependency-free.
    from taintly.suppressions import zizmor_compat

    if zizmor_compat.is_respect_zizmor_ignores_enabled():
        if zizmor_compat.is_zizmor_suppressed(line, rule_id):
            return True
    return False


# Anchor-aware suppression: how many lines may a SEC-NN-NNN finding's
# pre-expansion line number drift from its post-expansion equivalent
# while still being recognised as the same match?  Drift comes from
# ``<<: *anchor`` merge-key expansion inlining a multi-line anchor
# body above the SEC line.
#
# Empirical max drift observed in the in-repo corpus is bounded by
# the typical anchor-body height (3-8 lines for permissions blocks,
# 5-15 lines for step-templates).  The tolerance is set generously
# above that to absorb stacked-merge cases (two ``<<: *X`` merges
# in the same file).  ``tests/unit/test_anchor_expansion_tolerance.py``
# pins the threshold against a constructed worst-case anchor with
# known drift; lowering this value without updating that test will
# break suppression on stacked-merge workflows.
_ANCHOR_EXPANSION_LINE_TOLERANCE = 30

# Total wall-clock budget (seconds) for the per-rule scan loop of a SINGLE file.
# Distinct from models._CHUNKED_WALLCLOCK_BUDGET_S, which bounds ONE
# _safe_search_chunked call: this bounds the WHOLE file's rule loop, so a file
# that is individually-cheap-per-rule but expensive in aggregate (O(rules x size)
# on a multi-MB generated pipeline, or a taint-sink-dense file) still terminates.
# Measured worst case at 200 KB is ~7 s for the full GitHub pack, so 30 s only
# trips on genuinely large / pathological input. Overridable via --max-scan-seconds.
_FILE_SCAN_WALLCLOCK_BUDGET_S = 30.0


def scan_file(
    filepath: str,
    rules: list[Rule],
    _content: str | None = None,
    repoctx: StaticGuardContext | None = None,
    gitlabctx: GitLabContext | None = None,
    jenkinsctx: JenkinsContext | None = None,
    max_scan_seconds: float | None = None,
) -> list[Finding]:
    """Scan a single file against a list of rules.

    If _content is provided, use it directly instead of reading from disk.
    filepath is still used for Finding.file attribution.
    """
    findings = []
    if _content is not None:
        content = _content
        lines = content.splitlines()
    else:
        try:
            with open(filepath, encoding="utf-8", errors="replace") as f:
                content = f.read()
            lines = content.splitlines()
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="ENGINE-ERR",
                    severity=Severity.LOW,  # LOW so it survives --min-severity LOW filters
                    title=f"Could not read file: {e}",
                    description=str(e),
                    file=filepath,
                )
            )
            return findings

    # Build a lightweight per-file context once, then use it to derive a
    # context-aware exploitability tier for each finding.  The analyzer is
    # pure-regex (see workflow_context.py) so the cost is a few hundred
    # microseconds per file — comfortably below the per-rule scan budget.
    # Surface coverage loss — but distinguish "scanned in chunks (coverage
    # preserved)" from genuine loss. The ReDoS length cap in _safe_search
    # skips regex on text > _MAX_SAFE_TEXT_LEN, so file-scope patterns
    # (AbsencePattern, ContextPattern requires) route through
    # _safe_search_chunked, which windows oversize content and keeps FULL
    # coverage up to _CHUNK_COVERAGE_CEILING (_MAX_CHUNKS x _MAX_SAFE_TEXT_LEN,
    # ~1.31 MB). Past that ceiling the chunked search gives up — so the
    # "coverage preserved" notice must NOT be stated there. Two tiers:
    # past the ceiling => degraded; in the chunked band => benign notice.
    # Per-line regex always works (individual YAML lines fit under the cap).
    if len(content) > _CHUNK_COVERAGE_CEILING:
        findings.append(
            Finding(
                rule_id="ENGINE-ERR",
                severity=Severity.LOW,
                title=(
                    f"File size {len(content)} bytes exceeds the chunked-"
                    f"coverage ceiling ({_CHUNK_COVERAGE_CEILING}); file-scope "
                    "rule coverage degraded"
                ),
                description=(
                    "taintly scans oversize files in "
                    f"{_MAX_SAFE_TEXT_LEN}-byte windows up to "
                    f"{_CHUNK_COVERAGE_CEILING} bytes. Beyond that ceiling the "
                    "chunked search stops, so file-scope patterns "
                    "(ContextPattern requires / AbsencePattern) will not "
                    "report matches on this file. Per-line rules still run. "
                    "If this is a legitimate large CI config, split it via "
                    "includes / reusable workflows."
                ),
                file=filepath,
            )
        )
    elif len(content) > _MAX_SAFE_TEXT_LEN:
        findings.append(
            Finding(
                rule_id="ENGINE-ERR",
                severity=Severity.LOW,
                title=(
                    f"File size {len(content)} bytes exceeds scanner per-chunk "
                    f"cap ({_MAX_SAFE_TEXT_LEN}); content scanned in chunks"
                ),
                description=(
                    "To prevent regex denial-of-service on adversarial input, "
                    "taintly's per-regex evaluation is bounded by a "
                    f"{_MAX_SAFE_TEXT_LEN}-byte length cap. A chunked-search "
                    "path lets file-scope rules (ContextPattern requires / "
                    "AbsencePattern) still scan large workflows in "
                    "line-windowed chunks with overlap, up to "
                    f"{_CHUNK_COVERAGE_CEILING} bytes. Coverage is "
                    "preserved; this notice surfaces "
                    "only because the file is unusually large for a CI "
                    "config. If you suspect a regex match that spans a "
                    "chunk boundary was missed, split the workflow via "
                    "includes / reusable workflows."
                ),
                file=filepath,
            )
        )

    # File-level CUTOFF disclosure.  StructuralPattern rules emit
    # their own per-rule cutoff markers, but other rule types
    # (RegexPattern, ContextPattern, AbsencePattern) silently no-op
    # on the post-cutoff portion of the file.  Surfacing a single
    # file-level warning ensures the disclosure is visible regardless
    # of which rule types ran, so reviewers know the scan's coverage
    # was bounded by the unparseable construct.  Only YAML files go
    # through the structural reader; Jenkinsfiles use a different
    # path and don't produce CUTOFF events.
    fname = os.path.basename(filepath).lower()
    if fname.endswith((".yml", ".yaml")):
        try:
            from .parsers.structural import EventKind as _EventKind
            from .parsers.structural import walk_workflow as _walk

            for _ev in _walk(filepath, content=content, recover=True):
                if _ev.kind is _EventKind.CUTOFF:
                    # ENGINE-ERR is the documented rule_id for "scanner
                    # processed the file but coverage degraded" -- the
                    # file-size cap above uses the same id for the same
                    # class of non-fatal coverage loss.  The severity-
                    # filter exemption and the ``engine_errors`` accessor
                    # already surface ENGINE-ERR consistently across
                    # JSON / SARIF / text reporters.
                    findings.append(
                        Finding(
                            rule_id="ENGINE-ERR",
                            severity=Severity.LOW,
                            title=(
                                "Structural coverage degraded: file partially "
                                f"unparseable from line {_ev.line}"
                            ),
                            description=(
                                "The structural reader stopped at "
                                f"line {_ev.line} due to an unsupported YAML "
                                "construct.  Per-line rules continue to run "
                                "across the whole file, but rules that depend "
                                "on the structural reader (path-based "
                                "queries, anchor / merge-key resolution, "
                                "step enumeration) cannot evaluate the "
                                "post-cutoff portion of the file.  If the "
                                "construct is intentional, no action needed; "
                                "if it's accidental, fixing the YAML restores "
                                "full coverage."
                            ),
                            file=filepath,
                            line=_ev.line,
                        )
                    )
                    break
        except Exception:  # nosec B110 — defensive; never block the scan path on disclosure failure.
            pass

    wf_ctx = analyze_workflow(content, file=filepath)

    # Anchor-merge expansion: pre-compute lazily so rules that don't
    # opt in pay nothing.  See parsers/anchor_expander for the
    # capability/scope.
    _expanded_cache: dict[str, tuple[str, list[str]]] = {}

    def _get_expanded() -> tuple[str, list[str]]:
        if "v" not in _expanded_cache:
            ec = expand_anchors(content)
            _expanded_cache["v"] = (ec, ec.splitlines())
        return _expanded_cache["v"]

    # Bind ``filepath`` for any WorkflowAwarePattern rule dispatched
    # below.  Other pattern types ignore the contextvar; only
    # WorkflowAwarePattern's PredicateContext consumes it (for
    # caller-graph / repo-root resolution — see TAINT-GH-007).
    from taintly.workflow_aware_pattern import set_pattern_filepath_context

    budget = max_scan_seconds if max_scan_seconds is not None else _FILE_SCAN_WALLCLOCK_BUDGET_S
    deadline = time.monotonic() + budget
    unevaluated = 0
    with scan_session(), set_pattern_filepath_context(filepath):
        for idx, rule in enumerate(rules):
            if time.monotonic() >= deadline:
                unevaluated = len(rules) - idx
                break
            try:
                matches = rule.pattern.check(content, lines)
                # Anchor-aware suppression: if the rule opts in and an
                # anchor expansion would NOT produce the match, treat
                # it as an anchor-mediated false positive.  We never
                # ADD findings via expansion — only suppress.  The
                # tolerance below handles cases where the anchor
                # expansion shifts subsequent line numbers downward.
                if matches and getattr(rule, "anchor_aware", False):
                    expanded_content, expanded_lines = _get_expanded()
                    if expanded_content != content:
                        expanded_matches = rule.pattern.check(expanded_content, expanded_lines)
                        expanded_lineset = {ln for ln, _ in expanded_matches}
                        matches = [
                            (ln, snip)
                            for ln, snip in matches
                            if any(
                                abs(ln - eln) <= _ANCHOR_EXPANSION_LINE_TOLERANCE
                                for eln in expanded_lineset
                            )
                        ]
                for line_num, snippet in matches:
                    # Honour inline suppression comments on the matched line.
                    source_line = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
                    if _is_suppressed(source_line, rule.id):
                        continue
                    # Propagate v2 reporting metadata. Rule-level overrides win;
                    # otherwise fall back to the family/confidence defaults in
                    # taintly.families so every finding is classified.
                    family = rule.finding_family or classify_rule(rule.id, rule.owasp_cicd)
                    confidence = rule.confidence or default_confidence(rule.id)
                    review_needed = rule.review_needed or default_review_needed(rule.id)
                    exploitability = compute_exploitability(family, wf_ctx)
                    ctx_notes: list[str] = []
                    ctx_tags: list[str] = []
                    if (
                        wf_ctx.has_harden_runner_egress_block
                        and family in HARDEN_RUNNER_TEMPERED_FAMILIES
                    ):
                        ctx_notes.append(
                            "Harden-Runner egress-policy: block is present in this "
                            "workflow — exploitability tempered one tier (the "
                            "outbound exfil / C2 path is blocked)."
                        )
                        ctx_tags.append("harden-runner-egress-block")
                    # Severity-aware floor.  ``family`` drives BOTH clustering
                    # and exploitability, so a coarse OWASP→family fallback can
                    # route a CRITICAL/HIGH rule into a hygiene family and let
                    # ``compute_exploitability`` silently score it "low",
                    # discarding the rule's policy severity.  Guard the exact
                    # mismatch — a CRITICAL/HIGH rule routed to a hygiene family
                    # BY FALLBACK (no explicit ``finding_family``) in an
                    # attacker-reachable workflow — and refuse "low".  (e.g.
                    # PSE-GH-006, a fork-RCE chain tagged CICD-SEC-1 →
                    # resource_controls.)  Correctly-classified findings are
                    # untouched: they carry an explicit family, land in a
                    # non-hygiene branch, or aren't attacker-reachable.
                    if (
                        exploitability == "low"
                        and not rule.finding_family
                        and family in _HYGIENE_FALLBACK_FAMILIES
                        and rule.severity in (Severity.CRITICAL, Severity.HIGH)
                        and (wf_ctx.has_fork_triggered or wf_ctx.is_privileged)
                    ):
                        exploitability = "medium"
                        ctx_notes.append(
                            f"Exploitability floored to medium: a "
                            f"{rule.severity.name} rule was routed to the "
                            f"'{family}' hygiene family by OWASP fallback, which "
                            f"would otherwise score it low despite an "
                            f"attacker-reachable workflow context."
                        )
                        ctx_tags.append("severity-floor")
                    # Severity-aware ceiling — the mirror of the floor above.
                    # ``family`` also drives exploitability, so a coarse
                    # OWASP→family fallback can route a LOW/INFO POSTURE rule
                    # into a high-scoring family (credential_persistence,
                    # identity_access, …) where ``compute_exploitability``
                    # scores it "high" — overstating a review-posture item as
                    # actively exploitable.  Cap the exact mismatch: a LOW/INFO
                    # rule routed to a high-scoring family BY FALLBACK (no
                    # explicit ``finding_family``) has "high" capped to "medium".
                    # Explicitly-classified rules are untouched (the author
                    # chose that family deliberately).
                    elif (
                        exploitability == "high"
                        and not rule.finding_family
                        and rule.severity in (Severity.LOW, Severity.INFO)
                    ):
                        exploitability = "medium"
                        ctx_notes.append(
                            f"Exploitability capped to medium: a "
                            f"{rule.severity.name} rule was routed to the "
                            f"'{family}' family by OWASP fallback, which would "
                            f"otherwise overstate a low-severity posture item "
                            f"as highly exploitable."
                        )
                        ctx_tags.append("severity-ceiling")
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            severity=rule.severity,
                            title=rule.title,
                            description=rule.description,
                            file=filepath,
                            line=line_num,
                            snippet=snippet,
                            remediation=rule.remediation,
                            reference=rule.reference,
                            owasp_cicd=rule.owasp_cicd,
                            stride=rule.stride,
                            threat_narrative=rule.threat_narrative,
                            incidents=rule.incidents,
                            finding_family=family,
                            confidence=confidence,
                            exploitability=exploitability,
                            review_needed=review_needed,
                            context_notes=ctx_notes,
                            context_tags=ctx_tags,
                        )
                    )
            except Exception as e:
                findings.append(
                    Finding(
                        rule_id="ENGINE-ERR",
                        severity=Severity.INFO,
                        title=f"Rule {rule.id} failed on {filepath}: {e}",
                        description=str(e),
                        file=filepath,
                    )
                )

    if unevaluated:
        findings.append(
            Finding(
                rule_id="ENGINE-ERR",
                severity=Severity.LOW,
                title=(
                    f"File scan time-boxed at {budget:g} s; "
                    f"{unevaluated} of {len(rules)} rules not evaluated"
                ),
                description=(
                    "To bound total CPU on large or pathological CI configs, "
                    f"taintly caps the per-file rule loop at {budget:g} s. The "
                    f"budget was reached after evaluating "
                    f"{len(rules) - unevaluated} of {len(rules)} rules; the "
                    "remaining rules did not run on this file. Rules already "
                    "evaluated reported normally. If this is a legitimate large "
                    "config, split it via includes / reusable workflows, or raise "
                    "the budget with --max-scan-seconds."
                ),
                file=filepath,
            )
        )

    _run_post_processors(
        findings,
        rules=rules,
        content=content,
        repoctx=repoctx,
        gitlabctx=gitlabctx,
        jenkinsctx=jenkinsctx,
    )
    return findings


# ---------------------------------------------------------------------------
# Post-detection severity calibration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _PostProcessContext:
    rules: list[Rule]
    content: str
    repoctx: StaticGuardContext | None = None
    gitlabctx: GitLabContext | None = None
    jenkinsctx: JenkinsContext | None = None


_PostProcessor = Callable[[list[Finding], _PostProcessContext], None]


def _github_dead_postprocessor(findings: list[Finding], ctx: _PostProcessContext) -> None:
    if not any(rule.platform == Platform.GITHUB for rule in ctx.rules):
        return
    # Whole-workflow short-circuit: if every job in the file is
    # statically dead, the entire file is moot.  Suppress all findings
    # (including trigger-level ones that the per-job pass deliberately
    # leaves alone).  Per-job suppression handles the remaining cases:
    # live-jobs-with-dead-steps, mixed-dead-and-live-jobs.
    if is_workflow_whole_dead(ctx.content, ctx.repoctx):
        findings.clear()
        return
    _suppress_dead_findings(findings, ctx.content, ctx.repoctx)


def _gitlab_dead_postprocessor(findings: list[Finding], ctx: _PostProcessContext) -> None:
    if not any(rule.platform == Platform.GITLAB for rule in ctx.rules):
        return
    # Whole-pipeline short-circuit: if every job is statically dead,
    # the entire file is moot.  Suppress all findings (including
    # pipeline-level ones the per-job pass deliberately leaves alone).
    if is_pipeline_whole_dead(ctx.content, ctx.gitlabctx):
        findings.clear()
        return
    _suppress_gitlab_dead_findings(findings, ctx.content, ctx.gitlabctx)


def _jenkins_dead_postprocessor(findings: list[Finding], ctx: _PostProcessContext) -> None:
    if not any(rule.platform == Platform.JENKINS for rule in ctx.rules):
        return
    if is_jenkinsfile_whole_dead(ctx.content, ctx.jenkinsctx):
        findings.clear()
        return
    _suppress_jenkins_dead_findings(findings, ctx.content, ctx.jenkinsctx)


def _maintainer_downgrade_postprocessor(findings: list[Finding], ctx: _PostProcessContext) -> None:
    _downgrade_maintainer_gated_findings(findings, ctx.content)


# ---------------------------------------------------------------------------
# Guard / trigger-reachability calibration (calibration only).
#
# A control-flow analyzer can downgrade a finding when an identity / repo /
# association guard dominates the sink.  taintly has no control-flow graph,
# so it cannot PROVE dominance.  This pass is therefore CALIBRATION ONLY: when
# a fork-reachable GitHub/GitLab pipeline ALSO declares a strong guard, mark
# the finding's exploitability "low" and record why — but do NOT change
# severity.  Rationale: a mis-attributed guard must never suppress a real
# finding, so a presence-only signal may inform triage but must not act as a
# gate.  Downgrading severity would require a validated job/step dominance
# approximation, which is out of scope here.
# ---------------------------------------------------------------------------

# Same-repository check — the canonical fork-PR guard: the step only runs
# when the PR head repo equals the base repo (i.e. not a fork).
_GUARD_SAME_REPO_RE = re.compile(
    r"github\.event\.pull_request\.head\.repo\.full_name\s*==\s*github\.repository"
)
# Actor / triggering-actor / PR-author identity comparison in a condition.
_GUARD_ACTOR_RE = re.compile(
    r"\bgithub\.(?:actor|triggering_actor)\b\s*(?:==|!=)"
    r"|\bgithub\.event\.pull_request\.user\.login\b\s*(?:==|!=)"
)
# author_association gate (MEMBER / OWNER / COLLABORATOR membership).
_GUARD_ASSOCIATION_RE = re.compile(r"\bauthor_association\b")


def _detect_github_guards(content: str) -> list[str]:
    """Return labels for strong identity/repo guards declared anywhere in a
    GitHub workflow.  Presence-only — no dominance proof."""
    guards: list[str] = []
    if _GUARD_SAME_REPO_RE.search(content):
        guards.append("same-repository check")
    if _GUARD_ACTOR_RE.search(content):
        guards.append("actor-identity check")
    if _GUARD_ASSOCIATION_RE.search(content):
        guards.append("author-association check")
    return guards


# GitLab fork-reachable triggers: MR pipelines (incl. the GitHub-mirror
# external-PR bridge) and the ``only: merge_requests`` shorthand.
_GL_FORK_REACHABLE_RE = re.compile(
    r"merge_request_event|external_pull_request_event|\bmerge_requests\b"
)
# GitLab TRUSTWORTHY guards only — these are GitLab-assigned and an MR author
# cannot forge them.  Deliberately EXCLUDES ``$GITLAB_USER_*`` and
# ``$CI_MERGE_REQUEST_LABELS`` gates: those are attacker-spoofable, which is
# exactly why SEC4-GL-007 / SEC4-GL-011 flag them as *bad* — treating them as
# protective here would be unsound.
_GL_GUARD_SAME_PROJECT_RE = re.compile(
    r"CI_MERGE_REQUEST_SOURCE_PROJECT_ID\s*==\s*[\$\{]*\s*CI_PROJECT_ID"
    r"|CI_PROJECT_ID\s*==\s*[\$\{]*\s*CI_MERGE_REQUEST_SOURCE_PROJECT_ID"
)
_GL_GUARD_PROTECTED_REF_RE = re.compile(r"CI_COMMIT_REF_PROTECTED\s*==\s*['\"]?true")


def _detect_gitlab_guards(content: str) -> list[str]:
    """Return labels for TRUSTWORTHY GitLab guards (non-spoofable, GitLab-
    assigned).  Presence-only — no dominance proof."""
    guards: list[str] = []
    if _GL_GUARD_SAME_PROJECT_RE.search(content):
        guards.append("same-project MR check")
    if _GL_GUARD_PROTECTED_REF_RE.search(content):
        guards.append("protected-ref check")
    return guards


# NOTE: Jenkins is deliberately NOT given a guard-calibration pass.  On a
# fork PR, Jenkins runs the FORK's own Jenkinsfile, so the attacker controls
# the ``when {}`` guards themselves (they can remove or rewrite them).  A
# Jenkinsfile guard is therefore not a trustworthy protective signal; the real
# gate lives in the multibranch PR-trust / plugin configuration, which is not
# visible in the file.  Calibrating on an attacker-controllable guard would be
# unsound, so we don't.


def _annotate_guarded_findings(findings: list[Finding], content: str) -> None:
    """Calibration: on a fork-reachable GitHub or GitLab pipeline where a
    strong guard is declared IN THE SAME JOB as a finding, set that
    finding's exploitability to "low" and record the guard in
    ``calibration_reason``.  Severity is unchanged — a guard's presence is
    not proof that it dominates the sink.

    Two correctness properties:
      * Fork-reachability is checked across all four ``on:`` YAML shapes
        (block / flow-mapping / flow-list / bare) via the shared
        :func:`is_fork_reachable` parser, so a flow-style trigger is not
        missed.
      * Guards are detected and applied PER JOB: a guard in job A never
        calibrates a finding in job B.  A finding with no resolvable job
        (``line <= 0`` or preamble) is left untouched — the conservative
        direction for a calibration that must never suppress a real
        finding.

    The platform-specific guard detectors self-gate (GitHub guards only
    match GitHub content, GitLab guards only GitLab content)."""
    if not findings:
        return
    if is_fork_reachable(content):
        detect = _detect_github_guards
    elif _GL_FORK_REACHABLE_RE.search(content):
        detect = _detect_gitlab_guards
    else:
        return
    # Guards live in job/step ``if:`` (GitHub) or ``rules:`` (GitLab)
    # bodies; detect them per job segment so each guard's reach is bounded
    # to its own job.  ``for_each_job`` segments both GitHub and GitLab.
    guards_by_job: dict[str, list[str]] = {}
    for job in for_each_job(content):
        if not job.name:
            continue
        job_guards = detect(job.text)
        if job_guards:
            guards_by_job[job.name] = job_guards
    if not guards_by_job:
        return
    for f in findings:
        if f.origin != "file" or f.exploitability == "low":
            continue
        job_name = job_at_line(content, f.line)
        if job_name is None:
            continue
        guards = guards_by_job.get(job_name)
        if not guards:
            continue
        note = (
            f"This job is fork-reachable but declares a guard ({', '.join(guards)}); "
            "verify it dominates this finding's step before treating it as exploitable."
        )
        f.exploitability = "low"
        f.calibration_reason = (
            f"{f.calibration_reason} {note}".strip() if f.calibration_reason else note
        )


def _guard_calibration_postprocessor(findings: list[Finding], ctx: _PostProcessContext) -> None:
    if not any(rule.platform in (Platform.GITHUB, Platform.GITLAB) for rule in ctx.rules):
        return
    _annotate_guarded_findings(findings, ctx.content)


POST_PROCESSORS: tuple[_PostProcessor, ...] = (
    _github_dead_postprocessor,
    _gitlab_dead_postprocessor,
    _jenkins_dead_postprocessor,
    _maintainer_downgrade_postprocessor,
    _guard_calibration_postprocessor,
)


def _run_post_processors(
    findings: list[Finding],
    *,
    rules: list[Rule],
    content: str,
    repoctx: StaticGuardContext | None,
    gitlabctx: GitLabContext | None,
    jenkinsctx: JenkinsContext | None,
) -> None:
    ctx = _PostProcessContext(
        rules=rules,
        content=content,
        repoctx=repoctx,
        gitlabctx=gitlabctx,
        jenkinsctx=jenkinsctx,
    )
    for processor in POST_PROCESSORS:
        processor(findings, ctx)


def _suppress_gitlab_dead_findings(
    findings: list[Finding], content: str, gitlabctx: GitLabContext | None
) -> None:
    """Drop findings inside GitLab jobs proven dead by static rules logic."""
    if not findings:
        return
    dead_ranges = find_dead_gitlab_job_ranges(content, gitlabctx)
    if not dead_ranges:
        return
    findings[:] = [
        f
        for f in findings
        if f.line <= 0 or not any(start <= f.line <= end for start, end in dead_ranges)
    ]


def _suppress_jenkins_dead_findings(
    findings: list[Finding], content: str, jenkinsctx: JenkinsContext | None
) -> None:
    """Drop findings inside Jenkins stages proven dead by literal when logic."""
    if not findings:
        return
    dead_ranges = find_dead_jenkins_stage_ranges(content, jenkinsctx)
    if not dead_ranges:
        return
    findings[:] = [
        f
        for f in findings
        if f.line <= 0 or not any(start <= f.line <= end for start, end in dead_ranges)
    ]


# ``on:`` events whose firing is restricted to maintainers — pushing
# tags, creating releases, scheduling cron, or invoking
# workflow_dispatch all require maintainer-equivalent privilege.  When
# the workflow's trigger set is exclusively in this group, an
# unquoted ``$GITHUB_REF_NAME`` is only attacker-controlled if a
# maintainer is already compromised; HIGH severity overstates the
# threat in that context.
_MAINTAINER_GATED_TRIGGER_RE = re.compile(
    # ``on:`` block followed (anywhere in the file) by one of the
    # maintainer-gated events.  The presence of these events alongside
    # a fork-reachable event would still trip the un-narrowed firing,
    # so the per-file check below additionally requires the file to
    # contain none of the fork-reachable events.
    r"(?ms)^on:\s*\n.*?\b("
    r"push:\s*\n[^\S\n]*tags:"
    r"|push:\s*\n[^\S\n]*branches-ignore:"  # tag push only via branches-ignore
    r"|release:"
    r"|schedule:"
    r"|workflow_dispatch:"
    r")"
)
_FORK_REACHABLE_TRIGGER_RE = re.compile(
    r"(?m)^\s*("
    r"pull_request(?:_target|_review|_review_comment)?"
    r"|issue_comment"
    r"|issues"
    r"|discussion"
    r"|fork"
    r"|workflow_run"
    r"|workflow_call"
    r")\s*:"
)
# Single-line shape: ``on: push`` / ``on: [push, pull_request]``.
_INLINE_TRIGGER_RE = re.compile(r"^on:\s*(\[[^\]]+\]|\w+)\s*$", re.MULTILINE)
_REF_NAME_REF_RE = re.compile(r"\$\{?\s*GITHUB_REF_NAME\b|github\.ref_name\b", re.IGNORECASE)
_INPUTS_REF_RE = re.compile(
    r"\$\{\{\s*(?:github\.event\.inputs|inputs)\.[a-zA-Z0-9_]+\s*\}\}",
    re.IGNORECASE,
)
# LOTP-GH-001 severity-inflation FP: workflows whose ``ref:`` is a
# ``||`` fallback chain that *includes* ``pull_request.head.sha`` as
# one alternative but whose triggers are all maintainer-gated.  No
# ``pull_request`` event can ever fire the job, so the head-ref branch
# of the fallback never evaluates — the headline CRITICAL severity is
# inflated.  Pinned to LOTP-GH-001 because the finding's snippet is
# the build-tool line, not the ``ref:`` line that carries the FP
# signal: we have to scan the file content, not the snippet.
#
# The fallback shape (at least one ``||`` flanking the head-ref
# reference) is what discriminates the FP from the genuine attack
# (single-use ``ref: ${{ github.event.pull_request.head.sha }}``,
# which on a maintainer-gated trigger is dead code, not severity-
# inflated, and would not be reached here anyway because the rule's
# checkout-reference detector would still classify it as the
# attacker-controlled path).  The two-anchor form ``|| <ref> ||`` or
# ``<ref> ||`` or ``|| <ref>`` is the operator-defensive idiom.
_LOTP_PR_HEAD_IN_FALLBACK_RE = re.compile(
    # ``ref:`` value with ``${{ ... }}`` expression containing
    # ``github.event.pull_request.head.(sha|ref)`` adjacent (on either
    # side, possibly both) to a ``||`` operator.
    r"ref\s*:\s*\$\{\{[^}]*"
    r"(?:"
    # head-ref followed by ``||`` (head-ref is not the last term).
    r"github\.event\.pull_request\.head\.(?:sha|ref)\s*\|\|"
    r"|"
    # head-ref preceded by ``||`` (head-ref is not the first term).
    r"\|\|\s*github\.event\.pull_request\.head\.(?:sha|ref)"
    r")"
    r"[^}]*\}\}",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _DowngradePattern:
    """One entry in the maintainer-gated downgrade table.

    Exactly one of ``snippet_regex`` / ``content_regex`` should be set:

    * ``snippet_regex`` — match against ``finding.snippet`` only.  Use
      this when the FP signal lives on the same line as the finding
      (e.g. ``$GITHUB_REF_NAME`` is on the offending ``run:`` line).
    * ``content_regex`` — match against the whole file's content.  Use
      this when the FP signal lives on a *different* line than the
      finding (e.g. LOTP-GH-001's snippet is the build-tool line, but
      the signal is the fallback-chain ``ref:`` line in the checkout
      step earlier in the job).

    Both forms still gate on the workflow being maintainer-gated only
    (``_is_maintainer_gated_only``) and on the finding's family /
    optional rule_id matching.
    """

    rule_id: str | None
    family: str
    snippet_regex: re.Pattern[str] | None = None
    content_regex: re.Pattern[str] | None = None


_MAINTAINER_DOWNGRADE_PATTERNS: tuple[_DowngradePattern, ...] = (
    _DowngradePattern(
        rule_id=None,
        family="script_injection",
        snippet_regex=_REF_NAME_REF_RE,
    ),
    _DowngradePattern(
        rule_id="SEC4-GH-008",
        family="script_injection",
        snippet_regex=_INPUTS_REF_RE,
    ),
    # LOTP-GH-001 FP class: PR-head-sha appears as a ``||`` fallback
    # alternative in ``ref:`` on a workflow whose only triggers are
    # maintainer-gated.  Downgrade CRITICAL → HIGH; the head-ref branch
    # of the fallback never evaluates because no pull_request event can
    # fire the job.
    _DowngradePattern(
        rule_id="LOTP-GH-001",
        family="script_injection",
        content_regex=_LOTP_PR_HEAD_IN_FALLBACK_RE,
    ),
)


def _is_maintainer_gated_only(content: str) -> bool:
    """Return True when the workflow's ``on:`` block contains only
    maintainer-gated events (tag push, release, schedule,
    workflow_dispatch).  Returns False when any fork-reachable event
    is also declared, when the trigger uses an inline shorthand we
    can't classify, or when no recognised maintainer-gated event is
    present.
    """
    # Inline-shorthand form: ``on: push`` / ``on: [push, pull_request]``.
    # We can't tell whether the bare push is tag-only without a body,
    # so we conservatively decline to apply the downgrade in that
    # case.
    if _INLINE_TRIGGER_RE.search(content):
        return False
    if _FORK_REACHABLE_TRIGGER_RE.search(content):
        return False
    return bool(_MAINTAINER_GATED_TRIGGER_RE.search(content))


def _suppress_dead_findings(
    findings: list[Finding], content: str, repoctx: StaticGuardContext | None
) -> None:
    """Remove findings whose line is inside a statically dead job/step."""
    if not findings:
        return
    dead_ranges = find_dead_line_ranges(content, repoctx)
    if not dead_ranges:
        return
    findings[:] = [
        f
        for f in findings
        if f.line <= 0 or not any(start <= f.line <= end for start, end in dead_ranges)
    ]


def _downgrade_maintainer_gated_findings(findings: list[Finding], content: str) -> None:
    """Mutate ``findings`` in place: for findings matching any entry
    in ``_MAINTAINER_DOWNGRADE_PATTERNS`` on a workflow whose
    triggers are all maintainer-gated, downgrade severity by one tier.

    Rationale: exploitability presumes attacker control of the cited
    reference, but tag-push / release / schedule / workflow_dispatch
    events are maintainer-only firing paths.  CRITICAL/HIGH severity
    with low exploitability is internally inconsistent — when the
    only attacker path requires maintainer compromise, one-tier-down
    is the correct calibration.

    Two pattern shapes are supported:

    * snippet-anchored — the FP signal lives on the finding's own
      line (``$GITHUB_REF_NAME``, ``${{ inputs.X }}``).
    * content-anchored — the FP signal lives elsewhere in the file
      (LOTP-GH-001's ``ref:`` fallback chain, where the snippet is
      the build-tool line in a later step).
    """
    if not findings:
        return
    if not _is_maintainer_gated_only(content):
        return

    # Severity tier table — one step less severe.
    _downgrade = {
        Severity.CRITICAL: Severity.HIGH,
        Severity.HIGH: Severity.MEDIUM,
        Severity.MEDIUM: Severity.LOW,
        Severity.LOW: Severity.INFO,
    }

    for f in findings:
        if not _matches_maintainer_downgrade_pattern(f, content):
            continue
        new_sev = _downgrade.get(f.severity)
        if new_sev is not None and new_sev != f.severity:
            old_sev = f.severity
            f.severity = new_sev
            f.calibration_reason = (
                "Maintainer-gated trigger path downgraded severity "
                f"from {old_sev.value} to {new_sev.value}."
            )


def _matches_maintainer_downgrade_pattern(finding: Finding, content: str) -> bool:
    """Return True when ``finding`` matches any downgrade-table entry.

    Each entry checks the finding's ``family`` (and optional pinned
    ``rule_id``) plus one of:

    * ``snippet_regex`` against ``finding.snippet`` — original shape,
      used when the FP signal is on the offending line itself.
    * ``content_regex`` against ``content`` (the whole file) — used
      when the FP signal lives on a *different* line than the finding
      (e.g. LOTP-GH-001 where the snippet is the build-tool line but
      the signal is the ``ref:`` fallback chain in the checkout step).
    """
    for entry in _MAINTAINER_DOWNGRADE_PATTERNS:
        if entry.rule_id is not None and finding.rule_id != entry.rule_id:
            continue
        if getattr(finding, "finding_family", "") != entry.family:
            continue
        if entry.snippet_regex is not None:
            if entry.snippet_regex.search(finding.snippet or ""):
                return True
            continue
        if entry.content_regex is not None:
            if entry.content_regex.search(content):
                return True
            continue
    return False


def _normalize_input_path(path: str) -> tuple[str, list[str]]:
    """Resolve a user-supplied path into (repo_root, explicit_files).

    The CLI's ``path`` argument is most often the repository root, but
    callers also pass tighter paths to scope a scan: a single workflow
    file, the ``.github/workflows`` directory, the ``.github`` directory,
    or one of the GitLab CI subdirs. Without normalization the discover
    step finds no files (because it joins ``repo_path`` with literal
    ``.github/workflows``) and the scan returns "clean" — a silent
    failure mode that's worse than crashing.

    Returns:
        (repo_root, explicit_files): ``repo_root`` is what platform
        detection and discovery use; ``explicit_files`` is a list of
        absolute paths that should be scanned in addition to whatever
        ``discover_files`` finds.  Both lists may be empty.
    """
    abs_path = os.path.abspath(path)

    # Single file — caller wants exactly this one scanned.
    if os.path.isfile(abs_path):
        # Walk up to a repo-shaped ancestor so platform detection has
        # context (e.g. permissions-check rules that need to see the
        # file is under .github/workflows).  Stop at the filesystem
        # root if no ancestor looks repo-shaped.
        cur = os.path.dirname(abs_path)
        while cur and cur != os.path.dirname(cur):
            if (
                os.path.isdir(os.path.join(cur, ".github", "workflows"))
                or os.path.isfile(os.path.join(cur, ".github", "dependabot.yml"))
                or os.path.isfile(os.path.join(cur, ".github", "dependabot.yaml"))
                or os.path.isfile(os.path.join(cur, ".gitlab-ci.yml"))
                or os.path.isfile(os.path.join(cur, ".gitlab-ci.yaml"))
                or os.path.isfile(os.path.join(cur, ".gitlab", ".gitlab-ci.yml"))
                or os.path.isfile(os.path.join(cur, ".gitlab", ".gitlab-ci.yaml"))
                or os.path.isfile(os.path.join(cur, "Jenkinsfile"))
            ):
                return (cur, [abs_path])
            cur = os.path.dirname(cur)
        # No repo ancestor — return file's dir as root.
        return (os.path.dirname(abs_path), [abs_path])

    if not os.path.isdir(abs_path):
        # Doesn't exist — let the caller's existing error path handle it.
        return (abs_path, [])

    # Recognise common scope-narrowing directory names and walk up.
    norm = os.path.normpath(abs_path)
    parent = os.path.dirname(norm)
    base = os.path.basename(norm)
    grandparent = os.path.dirname(parent)
    parent_base = os.path.basename(parent)

    # <repo>/.github/workflows -> walk up 2.
    if parent_base == ".github" and base == "workflows":
        return (grandparent, [])
    # <repo>/.github -> walk up 1.
    if base == ".github":
        return (parent, [])
    # <repo>/.gitlab -> walk up 1.
    if base == ".gitlab":
        return (parent, [])

    return (abs_path, [])


def _file_matches_platform(filepath: str, platform: Platform) -> bool:
    """Cheap platform classifier for a single file path."""
    name = os.path.basename(filepath)
    if platform == Platform.GITHUB:
        if not (name.endswith(".yml") or name.endswith(".yaml")):
            return False
        norm = os.path.normpath(filepath).replace(os.sep, "/")
        return "/.github/workflows/" in norm or norm.endswith(
            ("/.github/dependabot.yml", "/.github/dependabot.yaml")
        )
    if platform == Platform.GITLAB:
        if name in {".gitlab-ci.yml", ".gitlab-ci.yaml"}:
            return True
        norm = os.path.normpath(filepath).replace(os.sep, "/")
        return "/.gitlab/" in norm or "/ci/" in norm
    if platform == Platform.JENKINS:
        return _is_jenkinsfile_name(name) or name.endswith(".groovy")
    raise ValueError(f"unsupported platform: {platform}")


# Extensions that look like Jenkinsfile-prefixed files but are actually
# documentation, not pipeline scripts.  ``content/doc/.../jenkinsfile.adoc``
# on case-insensitive filesystems (Windows, macOS) matches a naive
# ``Jenkinsfile.*`` glob and gets parsed as Groovy — causing CUTOFF
# events and noise.  Surfaced by the 2026-05-18 audit on jenkinsci/
# jenkins.io which ships exactly this layout.
_JENKINSFILE_DENIED_EXTS: frozenset[str] = frozenset(
    {"adoc", "md", "txt", "html", "rst", "asciidoc", "rtf", "pdf"}
)
_GITLAB_ENTRY_FILENAMES: tuple[str, ...] = (".gitlab-ci.yml", ".gitlab-ci.yaml")

# Content-verification gate for weak-heuristic discovery pickups.
#
# Some files are admitted by path shape alone — a loose ``*.groovy`` under a
# ``jenkins`` path segment, or any YAML under ``.gitlab/``.  But ``jenkins``
# is also a Groovy/Java *package* namespace (jenkinsci/jenkins ships UI views
# and plain classes under ``.../jenkins/model/...``), and ``.gitlab/`` also
# carries non-CI tool configs (GitLab Duo, issue templates).  Whether a file
# is a pipeline is decidable from its bytes, so gate these weak pickups on a
# cheap content sniff.  Strong signals (``Jenkinsfile*``, ``.gitlab-ci.yml``,
# explicit ``ci/`` includes) are NEVER routed through the gate, so a real
# pipeline that merely lacks a marker can never be dropped.
_JENKINS_PIPELINE_MARKERS: tuple[str, ...] = (
    "pipeline {",
    "pipeline{",
    "node {",
    "node{",
    "node(",
    "stage(",
)
_GITLAB_CI_STRONG_KEYS: tuple[str, ...] = (
    "stages:",
    "include:",
    "before_script:",
    "after_script:",
)


def _read_text_head(path: str, limit: int = 65536) -> str:
    """Read up to ``limit`` bytes of ``path`` as text, or "" on any OSError.

    Conservative on read errors: a file we cannot read is treated as NOT a
    pipeline by the callers below (dropped from the weak pickup).  It can
    still be scanned if it has a strong-signal name, which never routes
    through this gate.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def _groovy_looks_like_pipeline(path: str) -> bool:
    """True when a loose ``.groovy`` file carries a Jenkins pipeline marker."""
    head = _read_text_head(path)
    return bool(head) and any(m in head for m in _JENKINS_PIPELINE_MARKERS)


def _gitlab_yaml_looks_like_ci(path: str) -> bool:
    """True when a ``.gitlab/`` YAML carries a CI-defining key or job shape.

    A bare ``image:`` is deliberately NOT sufficient — that is exactly what
    Duo/tool YAMLs carry.  A CI-defining top-level key (``stages:``,
    ``include:``, ``before_script:``, ``after_script:``) or a job-shaped
    indented ``script:`` line is required.
    """
    head = _read_text_head(path)
    if not head:
        return False
    for line in head.splitlines():
        s = line.strip()
        if any(s.startswith(k) for k in _GITLAB_CI_STRONG_KEYS):
            return True
    return bool(re.search(r"(?m)^\s+script\s*:", head))  # job-shaped block


# A GitLab ``include: local:`` path that interpolates a CI/CD variable or a
# spec ``inputs:`` value (``$VAR`` / ``${VAR}`` / ``$[[ inputs.x ]]``) only
# resolves at pipeline-run time — its target is unknowable from static bytes.
# We count these so discovery can report "there is CI here we could not reach"
# instead of silently pretending the pipeline is fully covered.
_GITLAB_DYNAMIC_INCLUDE_RE = re.compile(r"\$\{|\$\[|\$[A-Za-z_]")

# Bound the include-graph closure so a pathological / cyclic repo can't make
# discovery walk forever.  Real pipelines are far below this.
_INCLUDE_GRAPH_MAX_FILES = 200


def _resolve_local_include(repo_path: str, ref: str) -> list[str]:
    """Resolve one GitLab ``include: local:`` ref to existing repo files.

    GitLab resolves ``local:`` paths from the REPO ROOT — a leading ``/`` is
    repo-root-absolute, not filesystem-absolute.  Globs (``*``/``**``/``?``)
    are expanded the way GitLab expands them.  Returns matching existing files
    (absolute paths); empty when the ref is a URL or matches nothing.
    """
    ref = ref.strip().strip("'\"")
    if not ref or "://" in ref:
        return []
    rel = ref.lstrip("/")
    base = os.path.join(repo_path, *rel.split("/"))
    if any(ch in rel for ch in "*?["):
        return [p for p in glob.glob(base, recursive=True) if os.path.isfile(p)]
    return [base] if os.path.isfile(base) else []


def _discover_gitlab_include_graph(
    repo_path: str, seed_files: list[str], seen: set[str]
) -> tuple[list[str], int]:
    """Follow ``include: local:`` refs transitively from ``seed_files`` to CI
    fragments that live OUTSIDE the ``ci/`` and ``.gitlab/`` glob roots (e.g.
    ``templates/build.yml``).

    An explicit ``include:`` reference is an AUTHORITATIVE CI signal — the
    pipeline author declared the file is part of the pipeline — so these files
    are admitted WITHOUT the content-shape gate that weak path pickups must
    pass.  ``seen`` (normalised paths) is shared with the caller and mutated.

    Returns ``(new_files, n_dynamic)`` where ``n_dynamic`` counts include refs
    that interpolate a runtime variable and so could not be resolved statically.
    """
    from taintly.gitlab_workflow_corpus import _extract_local_include_paths

    new_files: list[str] = []
    n_dynamic = 0
    queue = list(seed_files)
    while queue and len(new_files) < _INCLUDE_GRAPH_MAX_FILES:
        content = _read_text_head(queue.pop())
        if not content:
            continue
        for ref in _extract_local_include_paths(content):
            if _GITLAB_DYNAMIC_INCLUDE_RE.search(ref):
                n_dynamic += 1
                continue
            for hit in _resolve_local_include(repo_path, ref):
                norm = os.path.normpath(hit)
                if norm in seen:
                    continue
                seen.add(norm)
                new_files.append(hit)
                queue.append(hit)  # transitive: follow ITS includes too
    return new_files, n_dynamic


def _discover_gitlab_entry_files(repo_path: str) -> list[str]:
    """Find GitLab CI entry files supported by GitLab and our corpus reader."""
    files: list[str] = []
    for name in _GITLAB_ENTRY_FILENAMES:
        root_entry = os.path.join(repo_path, name)
        if os.path.isfile(root_entry):
            files.append(root_entry)
        hidden_entry = os.path.join(repo_path, ".gitlab", name)
        if os.path.isfile(hidden_entry):
            files.append(hidden_entry)
    return files


def _discover_gitlab_files(repo_path: str) -> tuple[list[str], int]:
    """Find GitLab CI entry files plus local include candidates.

    Entry files and explicit ``ci/`` includes are strong signals, admitted
    unconditionally.  ``.gitlab/`` YAML is a weak signal — the directory also
    holds non-CI tool configs (GitLab Duo, issue templates), so those pickups
    are content-gated via :func:`_gitlab_yaml_looks_like_ci`.  Entry files are
    never gated, so an ``include:``-only fragment can never be dropped.

    Returns ``(files, n_dynamic)`` where ``n_dynamic`` counts ``include:
    local:`` refs that interpolate a runtime variable and so could not be
    resolved statically — surfaced by :func:`scan_repo` as a coverage
    disclosure so "scan clean" isn't overstated when there is pipeline behind
    an unresolvable include.
    """
    entry_files = _discover_gitlab_entry_files(repo_path)
    files = list(entry_files)
    entry_set = {os.path.normpath(p) for p in entry_files}

    # Strong signal: an explicit ``ci/`` include directory — admit all.
    for pattern in ("ci/*.yml", "ci/**/*.yml", "ci/*.yaml", "ci/**/*.yaml"):
        files.extend(glob.glob(os.path.join(repo_path, pattern), recursive=True))

    # Weak signal: ``.gitlab/`` also carries non-CI tool configs, so gate on
    # content (e.g. ``.gitlab/duo/agent-config.yml`` must not parse as CI).
    for pattern in (
        ".gitlab/*.yml",
        ".gitlab/**/*.yml",
        ".gitlab/*.yaml",
        ".gitlab/**/*.yaml",
    ):
        for cand in glob.glob(os.path.join(repo_path, pattern), recursive=True):
            if os.path.normpath(cand) in entry_set:
                continue
            if _gitlab_yaml_looks_like_ci(cand):
                files.append(cand)
    # Include-graph closure: follow ``include: local:`` refs transitively so
    # fragments OUTSIDE ci/ and .gitlab/ (e.g. ``templates/build.yml``) are
    # scanned too. An explicit include is authoritative CI, so these skip the
    # content-shape gate.
    seen = {os.path.normpath(p) for p in files}
    include_files, n_dynamic = _discover_gitlab_include_graph(repo_path, list(files), seen)
    files.extend(include_files)
    return files, n_dynamic


def _discovery_confidence(repo_path: str, platform: Platform, files: list[str]) -> dict[str, str]:
    """Classify each discovered file's discovery confidence (normpath -> tier).

    "high" — admitted by an AUTHORITATIVE signal: a canonical GitHub location
             (``.github/workflows/`` + dependabot), a Jenkinsfile-named file, a
             GitLab entry file, a ``*.gitlab-ci.yml``-named file, or a file
             reached by an explicit ``include: local:`` reference.
    "low"  — admitted only by a WEAK path heuristic the content gate let
             through: a ``.gitlab/**`` glob pickup, or a loose ``.groovy``
             inside a jenkins-named dir.

    See :func:`_apply_discovery_confidence` for how the tier is consumed.
    """
    if platform == Platform.GITHUB:
        # .github/workflows/ and dependabot.yml are location-authoritative.
        return {os.path.normpath(f): "high" for f in files}
    if platform == Platform.JENKINS:
        return {
            os.path.normpath(f): ("high" if _is_jenkinsfile_name(os.path.basename(f)) else "low")
            for f in files
        }
    # GitLab: authoritative = entry files, anything reached by include, OR any
    # file whose NAME is the canonical CI filename (``*.gitlab-ci.yml``). The
    # last clause matters for monorepos (gitlab-org/gitlab) whose child-pipeline
    # configs are named ``main.gitlab-ci.yml`` and are TRIGGERED (not root-
    # included), so the include-graph never reaches them — but the filename is
    # itself authoritative. The remaining ci/ & .gitlab/ glob pickups are weak.
    authoritative = {os.path.normpath(f) for f in _discover_gitlab_entry_files(repo_path)}
    reached, _n = _discover_gitlab_include_graph(repo_path, list(authoritative), set(authoritative))
    authoritative.update(os.path.normpath(f) for f in reached)

    def _is_ci_named(p: str) -> bool:
        return os.path.basename(p).endswith((".gitlab-ci.yml", ".gitlab-ci.yaml"))

    return {
        os.path.normpath(f): (
            "high" if (os.path.normpath(f) in authoritative or _is_ci_named(f)) else "low"
        )
        for f in files
    }


def _apply_discovery_confidence(findings: list[Finding], conf_map: dict[str, str]) -> None:
    """Tag each finding with the discovery confidence of its file and cap
    low-confidence findings at review-needed.

    A file admitted only by a weak path heuristic (a ``.gitlab/**`` glob
    pickup, a loose ``.groovy``) shouldn't drive a confident, score-affecting
    finding — even after the content gate, the path signal was weak and the
    file may be a fragment scanned out of context. Mutates in place. Findings
    whose file isn't in the map (e.g. cross-file corpus findings) default to
    "high" so nothing is silently downgraded.
    """
    for f in findings:
        c = conf_map.get(os.path.normpath(f.file), "high")
        f.discovery_confidence = c
        if c == "low":
            f.review_needed = True


def _is_jenkinsfile_name(name: str) -> bool:
    """Return True when ``name`` is a Jenkinsfile-shaped filename.

    Matches:
      * ``Jenkinsfile`` (exact, case-sensitive)
      * ``Jenkinsfile.<ext>`` for non-doc extensions (e.g.
        ``Jenkinsfile.groovy``, ``Jenkinsfile.ci``).  Doc-format
        extensions in :data:`_JENKINSFILE_DENIED_EXTS` are rejected.
      * ``Jenkinsfile_<suffix>`` / ``Jenkinsfile-<suffix>`` for
        operator-specific variants (``Jenkinsfile_k8s``,
        ``Jenkinsfile-prod``) — common in production setups.  Audit
        2026-05-18 found jenkinsci/jenkins.io ships ``Jenkinsfile_k8s``.
      * ``<name>.jenkinsfile`` — uncommon but documented in Jenkins
        editor-mode hints.

    Case-sensitive on the ``Jenkinsfile`` prefix because case-insensitive
    filesystems (Windows, macOS) would otherwise slurp
    ``jenkinsfile.adoc`` doc files.
    """
    if name == "Jenkinsfile":
        return True
    if name.startswith("Jenkinsfile") and len(name) > len("Jenkinsfile"):
        sep = name[len("Jenkinsfile")]
        if sep in "_-":
            return True
        if sep == ".":
            ext = name[len("Jenkinsfile.") :].lower()
            return bool(ext) and ext not in _JENKINSFILE_DENIED_EXTS
    return name.endswith(".jenkinsfile")


def _discover_jenkins_files(repo_path: str) -> list[str]:
    """Find Jenkins pipeline files using the platform-specific naming rules."""
    files: list[str] = []
    excluded_segments = {"node_modules", ".git", "vendor", "__pycache__"}
    for root, dirs, names in os.walk(repo_path):
        # Prune vendor/dep dirs in-place so os.walk doesn't descend.
        # Hidden dirs (``.jenkins``, ``.ci``, etc.) stay in the list.
        dirs[:] = [d for d in dirs if d not in excluded_segments]
        rel_root = os.path.relpath(root, repo_path)
        in_jenkins_dir = rel_root != "." and (
            rel_root.split(os.sep)[0] == "jenkins"
            or "jenkins" in rel_root.replace(os.sep, "/").split("/")
        )
        for name in names:
            if _is_jenkinsfile_name(name):
                files.append(os.path.join(root, name))
            elif name.endswith(".groovy") and in_jenkins_dir:
                # ``jenkins/**/*.groovy`` form - only inside a
                # ``jenkins`` directory. Skip random ``*.groovy`` files
                # elsewhere in the repo (usually build-tool scripts).
                # ``jenkins`` is also a Groovy package namespace, so
                # content-gate: keep only files with a pipeline marker.
                cand = os.path.join(root, name)
                if _groovy_looks_like_pipeline(cand):
                    files.append(cand)
    return files


def detect_platform(repo_path: str) -> Platform | None:
    """Auto-detect CI/CD platform from directory structure.

    Returns a single Platform when exactly one platform's signal is
    present.  Returns None when zero or two-or-more signals are
    present — the caller (``scan_repo``) handles None by probing all
    three platforms via ``discover_files``.

    Prior to this change, the function short-circuited on the first
    detected platform in ``has_github → has_gitlab → has_jenkins``
    order, so any repo with both ``.github/workflows/`` and a
    ``Jenkinsfile`` (a common shape during migrations and in repos
    that publish via multiple CI systems) silently dropped the
    Jenkinsfile from scan coverage.  The existing
    ``has_github and has_gitlab`` special case is generalised here.
    """
    gh_dir = os.path.join(repo_path, ".github", "workflows")
    has_github = os.path.isdir(gh_dir) or any(
        os.path.isfile(os.path.join(repo_path, ".github", f"dependabot.{ext}"))
        for ext in ("yml", "yaml")
    )
    has_gitlab = bool(_discover_gitlab_entry_files(repo_path))
    has_jenkins = bool(_discover_jenkins_files(repo_path))

    detected: list[Platform] = []
    if has_github:
        detected.append(Platform.GITHUB)
    if has_gitlab:
        detected.append(Platform.GITLAB)
    if has_jenkins:
        detected.append(Platform.JENKINS)

    if len(detected) == 1:
        return detected[0]
    # Zero or multiple — caller probes all three via discover_files
    return None


def discover_files(repo_path: str, platform: Platform) -> list[str]:
    """Find all CI/CD config files for a given platform."""
    files = []

    if platform == Platform.GITHUB:
        workflow_dir = os.path.join(repo_path, ".github", "workflows")
        if os.path.isdir(workflow_dir):
            files.extend(glob.glob(os.path.join(workflow_dir, "*.yml")))
            files.extend(glob.glob(os.path.join(workflow_dir, "*.yaml")))
        # Dependabot config — sibling file under .github/ — picked up
        # so the SEC8 dependabot rule family can audit it.  Other
        # GitHub rules' patterns won't match (no jobs:/steps:/uses:),
        # so the extra file in scope is a no-op for them.
        for ext in ("yml", "yaml"):
            dep = os.path.join(repo_path, ".github", f"dependabot.{ext}")
            if os.path.isfile(dep):
                files.append(dep)

    elif platform == Platform.GITLAB:
        gl_files, _n_dynamic = _discover_gitlab_files(repo_path)
        files.extend(gl_files)

    elif platform == Platform.JENKINS:
        # ``glob.glob(recursive=True)`` SKIPS hidden directories by
        # default on every Python version (``include_hidden=True`` is
        # 3.11+; lab supports 3.10+).  Apache and infra projects
        # commonly use ``.jenkins/Jenkinsfile`` / ``.ci/Jenkinsfile``
        # layouts that the old glob never visited — apache/cassandra
        # has a 667-line ``.jenkins/Jenkinsfile`` that 2026-05-18
        # audit found was completely missed.  Walk manually so we
        # descend into dot-prefixed dirs while still pruning the
        # documented vendor/dep dirs.
        excluded_segments = {"node_modules", ".git", "vendor", "__pycache__"}
        for root, dirs, names in os.walk(repo_path):
            # Prune vendor/dep dirs in-place so os.walk doesn't
            # descend.  Hidden dirs (``.jenkins``, ``.ci``, etc.)
            # stay in the list — that's the point of the rewrite.
            dirs[:] = [d for d in dirs if d not in excluded_segments]
            rel_root = os.path.relpath(root, repo_path)
            in_jenkins_dir = rel_root != "." and (
                rel_root.split(os.sep)[0] == "jenkins"
                or "jenkins" in rel_root.replace(os.sep, "/").split("/")
            )
            for name in names:
                if _is_jenkinsfile_name(name):
                    files.append(os.path.join(root, name))
                elif name.endswith(".groovy") and in_jenkins_dir:
                    # ``jenkins/**/*.groovy`` form — only inside a
                    # ``jenkins`` directory.  Skip random ``*.groovy``
                    # files elsewhere in the repo (these are usually
                    # build-tool scripts, not pipeline definitions).
                    # ``jenkins`` is also a Groovy package namespace
                    # (jenkinsci/jenkins ships UI views / plain classes
                    # under it), so content-gate on a pipeline marker.
                    cand = os.path.join(root, name)
                    if _groovy_looks_like_pipeline(cand):
                        files.append(cand)

    # Normalise separators before deduping.  Windows paths returned by
    # ``os.path.join`` use ``\`` while ``glob`` recursion can produce
    # the same file with mixed separators ("C:\repo/Jenkinsfile" vs
    # "C:\repo\Jenkinsfile"); ``set()`` would treat those as distinct
    # and a Jenkinsfile would be scanned twice, doubling findings.
    # ``os.path.normpath`` collapses to the platform's native form.
    return sorted({os.path.normpath(p) for p in files})


def _is_dependabot_config(filepath: str) -> bool:
    norm = os.path.normpath(filepath).replace(os.sep, "/")
    return norm.endswith(("/.github/dependabot.yml", "/.github/dependabot.yaml"))


def _rules_for_file(filepath: str, rules: list[Rule]) -> list[Rule]:
    if _is_dependabot_config(filepath):
        return [r for r in rules if r.id == "SEC8-GH-005"]
    return rules


def scan_repo(
    repo_path: str,
    rules: list[Rule],
    platform: Platform | None = None,
    *,
    explicit_github_repoctx: StaticGuardContext | None = None,
    max_scan_seconds: float | None = None,
) -> list[AuditReport]:
    """Scan an entire repository. Returns one report per platform detected.

    ``explicit_github_repoctx`` lets callers (the CLI's ``--github-repo``
    flag, in particular) override ``git remote`` auto-detection for the
    static-guard ``WorkflowContext`` on the GitHub scan path.  Useful
    when the directory is not a git checkout or its remote is not named
    ``origin``.  When omitted, auto-detection is used as before.
    """
    import sys as _sys

    repo_path, explicit_files = _normalize_input_path(repo_path)
    if explicit_files:
        # Surface that we're operating in scoped mode so a misconfigured
        # caller doesn't conclude "clean" from "we only scanned 1 file".
        print(
            f"taintly: scoped to {len(explicit_files)} explicit file(s); "
            f"use the repo root for full coverage.",
            file=_sys.stderr,
        )

    reports = []

    platforms_to_scan = []
    if platform:
        platforms_to_scan = [platform]
    else:
        detected = detect_platform(repo_path)
        if detected:
            platforms_to_scan = [detected]
        else:
            # Check all supported platforms
            for p in [Platform.GITHUB, Platform.GITLAB, Platform.JENKINS]:
                if discover_files(repo_path, p) or any(
                    _file_matches_platform(ef, p) for ef in explicit_files
                ):
                    platforms_to_scan.append(p)

    if not platforms_to_scan:
        report = AuditReport(repo_path=repo_path)
        return [report]

    for plat in platforms_to_scan:
        report = AuditReport(repo_path=repo_path, platform=plat.value)
        platform_rules = [r for r in rules if r.platform == plat]
        n_dynamic_includes = 0
        if explicit_files:
            # Scoped mode: caller named specific files; scan ONLY those
            # (and only the ones that match this platform).  The repo
            # root is still used so platform-aware context (path-based
            # rules, etc.) sees the file in its real location.
            files = [ef for ef in explicit_files if _file_matches_platform(ef, plat)]
        elif plat == Platform.GITLAB:
            # Call the GitLab discoverer directly (not the generic
            # ``discover_files``) so the dynamic-include count is captured
            # for the coverage disclosure below.
            files, n_dynamic_includes = _discover_gitlab_files(repo_path)
        else:
            files = discover_files(repo_path, plat)
        report.files_scanned = len(files)
        report.rules_loaded = len(platform_rules)
        # Discovery-confidence map: findings on weakly-discovered files get
        # capped at review-needed by _apply_discovery_confidence below.
        discovery_conf = _discovery_confidence(repo_path, plat, files)

        all_findings: list[Finding] = []
        if n_dynamic_includes and files:
            # Coverage disclosure: GitLab ``include: local:`` refs that
            # interpolate a runtime variable resolve only at pipeline-run
            # time, so their target is unknowable from static bytes. We
            # scanned every statically-reachable file but could not reach
            # the config behind these includes — surface it so "scan clean"
            # isn't overstated. Attached to the primary entry file.
            all_findings.append(
                Finding(
                    rule_id="ENGINE-ERR",
                    severity=Severity.LOW,
                    title=(
                        f"{n_dynamic_includes} GitLab include(s) interpolate a "
                        "runtime variable and could not be resolved statically; "
                        "pipeline behind them was not scanned"
                    ),
                    description=(
                        "An ``include: local:`` path containing a CI/CD variable "
                        "or spec input ($VAR / ${VAR} / $[[ inputs.x ]]) only "
                        "resolves at pipeline-run time, so its target file is "
                        "unknowable from static bytes. taintly scanned every "
                        "statically-reachable file but could not reach the "
                        "configuration behind these dynamic includes. If they "
                        "pull in security-relevant jobs, review those targets "
                        "manually or pin the include to a static path."
                    ),
                    file=files[0],
                )
            )
        if plat == Platform.GITHUB:
            if explicit_github_repoctx is not None:
                repoctx = explicit_github_repoctx
                report.repo_identity_source = "explicit"
            else:
                repoctx = detect_github_workflow_context(repo_path)
                if repoctx.repository:
                    report.repo_identity_source = "auto"
                else:
                    report.repo_identity_source = "unset"
            if repoctx.repository:
                report.repo_identity_value = repoctx.repository
        else:
            repoctx = None
        # ContextPattern rules whose finding_family is set are the
        # subset we can answer "did this family have a candidate
        # location?" for.  We compute anchor-match counts per file
        # and populate report.families_with_surface, which the scorer
        # uses to label "Strong" vs "Not applicable" on families
        # with zero findings.
        from taintly.models import ContextPattern as _ContextPattern

        ctx_rules_by_family: dict[str, list[Rule]] = {}
        for r in platform_rules:
            if isinstance(r.pattern, _ContextPattern) and r.finding_family:
                ctx_rules_by_family.setdefault(r.finding_family, []).append(r)
        report.families_with_ctx_coverage = set(ctx_rules_by_family)

        # Auto-detect GitLab context from CI predefined variables when
        # taintly itself runs inside a GitLab CI job.  Outside that
        # environment every field is None and the result is
        # indistinguishable from ``GitLabContext()``, preserving the
        # conservative-by-default suppression path.
        if plat == Platform.GITLAB:
            gitlabctx = detect_gitlab_context()
            for field_name in ("pipeline_source", "commit_branch", "default_branch"):
                value = getattr(gitlabctx, field_name)
                if value:
                    report.gitlab_ctx_detected[field_name] = value
        else:
            gitlabctx = None
        # JenkinsContext is currently empty (reserved as a typed
        # extension point); ``evaluate_jenkins_when`` discards ctx.
        # We still instantiate one per-Jenkins-scan so downstream
        # callers that take ``JenkinsContext | None`` see the same
        # truthy-but-empty marker they did before.
        jenkinsctx = JenkinsContext() if plat == Platform.JENKINS else None
        for fpath in files:
            file_rules = _rules_for_file(fpath, platform_rules)
            # Read the file ONCE; both the scan and the surface-evaluation pass
            # below share the content (each previously opened the file
            # separately — a redundant read per scanned file). On a read
            # failure ``_content`` stays None: scan_file re-reads and emits the
            # ENGINE-ERR finding (preserving the prior error behaviour) and the
            # surface pass is skipped.
            try:
                with open(fpath, encoding="utf-8", errors="replace") as _f:
                    _content = _f.read()
            except OSError:
                _content = None
            all_findings.extend(
                scan_file(
                    fpath,
                    file_rules,
                    _content=_content,
                    repoctx=repoctx,
                    gitlabctx=gitlabctx,
                    jenkinsctx=jenkinsctx,
                    max_scan_seconds=max_scan_seconds,
                )
            )
            # Surface-evaluation pass (reusing the content read above): a
            # family whose ContextPattern anchors find a candidate is marked
            # "has surface"; a family with no candidates anywhere stays
            # "Not applicable".
            if ctx_rules_by_family and _content is not None:
                _lines = _content.splitlines()
                for family, fam_rules in ctx_rules_by_family.items():
                    if family in report.families_with_surface:
                        continue
                    for r in fam_rules:
                        pattern = r.pattern
                        if (
                            isinstance(pattern, _ContextPattern)
                            and pattern.count_anchor_matches(_content, _lines) > 0
                        ):
                            report.families_with_surface.add(family)
                            break
        # IAM blast-radius escalation: enrich PSE-GH-001 findings by classifying
        # any local IAM policy that matches the workflow's role-to-assume
        # ARN.  Mutates findings in-place — escalation only happens on
        # a CRITICAL classifier verdict; absence of evidence keeps the
        # finding at HIGH.  GitHub-only (the rule is GH-platform).
        if plat == Platform.GITHUB:
            all_findings = enrich_pse_findings(all_findings, repo_path)
            # B2 cross-file pass: build the WorkflowCorpus once per
            # platform-scan and run any rule whose pattern is a
            # CorpusPattern.  Per-file rules (RegexPattern /
            # ContextPattern / …) are unaffected because their
            # CorpusPattern siblings stub `check()` to return [].
            all_findings.extend(_run_corpus_rules(repo_path, platform_rules))
            # B3 composer pass: re-invoke corpus rules whose
            # finding_family is "chain-composition", this time with
            # the full per-file + corpus findings list seeded as EDB.
            # These rules read prior findings via composer.run_composer
            # and emit composite (CHAIN-GH-1xx) findings.
            all_findings.extend(
                _run_corpus_rules(
                    repo_path,
                    platform_rules,
                    prior_findings=list(all_findings),
                    composer_only=True,
                )
            )
        if plat == Platform.GITLAB:
            # GitLab CHAIN composer pass: build the GitLabWorkflowCorpus
            # (entry file + resolved local includes) once per scan and
            # run any rule whose pattern is a GitLabCorpusPattern.
            # Mirrors the GH _run_corpus_rules shape; per-file rules
            # are unaffected because GitLabCorpusPattern.check stubs to [].
            all_findings.extend(_run_gitlab_corpus_rules(repo_path, platform_rules))
        # Order matters: drop superseded same-line duplicates first so
        # the project-scope dedup sees the post-supersedes finding set
        # (otherwise a superseded finding could "win" the project-scope
        # first-seen slot and silently mask the canonical finding).
        _apply_discovery_confidence(all_findings, discovery_conf)
        all_findings = _dedupe_supersedes(all_findings, platform_rules)
        for f in _dedupe_project_scope(all_findings):
            report.add(f)

        report.summarize()
        reports.append(report)

    return reports


def _run_corpus_rules(
    repo_path: str,
    rules: list[Rule],
    *,
    prior_findings: list[Finding] | None = None,
    composer_only: bool = False,
) -> list[Finding]:
    """Build a WorkflowCorpus and run every CorpusPattern rule against it.

    Returns the findings list (already wrapped in :class:`Finding` with
    the rule's metadata).  No-op when no CorpusPattern rules are loaded;
    the corpus build is then skipped entirely so non-cross-file users
    don't pay the walk cost.

    Composer pass: when ``composer_only=True`` we ONLY run rules whose
    ``finding_family == "chain-composition"`` (the CHAIN-GH-1xx
    composer family).  Their callbacks read ``corpus._prior_findings``
    to compose new findings from existing ones; we smuggle the prior
    list onto the corpus object so the regular CorpusPattern contract
    stays unchanged.
    """
    corpus_rules = [r for r in rules if isinstance(r.pattern, CorpusPattern)]
    if composer_only:
        corpus_rules = [r for r in corpus_rules if r.finding_family == "chain-composition"]
    else:
        # Non-composer pass: exclude composer rules so they only fire
        # in the dedicated post-pass with the seeded findings list.
        corpus_rules = [r for r in corpus_rules if r.finding_family != "chain-composition"]
    if not corpus_rules:
        return []

    corpus = build_corpus(repo_path)
    if prior_findings is not None:
        # Smuggled onto the corpus object for composer rules to read.
        corpus._prior_findings = prior_findings  # type: ignore[attr-defined]
    findings: list[Finding] = []
    with scan_session():
        for rule in corpus_rules:
            # The isinstance(r.pattern, CorpusPattern) filter above
            # guarantees this method exists; assert the narrow type
            # for mypy without paying a runtime check at the call.
            corpus_pattern = rule.pattern
            assert isinstance(corpus_pattern, CorpusPattern)  # nosec B101
            try:
                hits = corpus_pattern.check_corpus(corpus)
            except Exception as e:
                findings.append(
                    Finding(
                        rule_id="ENGINE-ERR",
                        severity=Severity.INFO,
                        title=f"Corpus rule {rule.id} failed: {e}",
                        description=str(e),
                        file=repo_path,
                    )
                )
                continue
            for hit in hits:
                # A corpus callback may emit a 4-tuple to override the
                # static rule title per-finding (e.g. XF-GH-004 names the
                # specific pwn-request event that fired). mypy narrows the
                # tuple union by length.
                if len(hit) == 4:
                    filepath, line_num, snippet, title = hit
                else:
                    filepath, line_num, snippet = hit
                    title = rule.title
                family = rule.finding_family or classify_rule(rule.id, rule.owasp_cicd)
                confidence = rule.confidence or default_confidence(rule.id)
                review_needed = rule.review_needed or default_review_needed(rule.id)
                # Cross-file findings don't have a single workflow_context
                # to derive exploitability from — the rule's own logic is
                # the exploitability gate.  Default to "medium" so the
                # reporter doesn't downrank the finding without basis.
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        title=title,
                        description=rule.description,
                        file=filepath,
                        line=line_num,
                        snippet=snippet,
                        remediation=rule.remediation,
                        reference=rule.reference,
                        owasp_cicd=rule.owasp_cicd,
                        stride=rule.stride,
                        threat_narrative=rule.threat_narrative,
                        incidents=rule.incidents,
                        origin="cross-workflow",
                        finding_family=family,
                        confidence=confidence,
                        exploitability="medium",
                        review_needed=review_needed,
                    )
                )
    return findings


def _run_gitlab_corpus_rules(repo_path: str, rules: list[Rule]) -> list[Finding]:
    """Build a GitLabWorkflowCorpus and run every GitLabCorpusPattern
    rule against it.

    Mirrors :func:`_run_corpus_rules` but for the GitLab side.  Returns
    findings already wrapped in :class:`Finding` with the rule's
    metadata.  No-op when no GitLabCorpusPattern rules are loaded; the
    corpus build is then skipped entirely so non-cross-file GL scans
    don't pay the walk cost.
    """
    corpus_rules = [r for r in rules if isinstance(r.pattern, GitLabCorpusPattern)]
    if not corpus_rules:
        return []

    corpus = build_gitlab_corpus(repo_path)
    findings: list[Finding] = []
    with scan_session():
        for rule in corpus_rules:
            corpus_pattern = rule.pattern
            assert isinstance(corpus_pattern, GitLabCorpusPattern)  # nosec B101
            try:
                hits = corpus_pattern.check_corpus(corpus)
            except Exception as e:
                findings.append(
                    Finding(
                        rule_id="ENGINE-ERR",
                        severity=Severity.INFO,
                        title=f"GitLab corpus rule {rule.id} failed: {e}",
                        description=str(e),
                        file=repo_path,
                    )
                )
                continue
            for filepath, line_num, snippet in hits:
                family = rule.finding_family or classify_rule(rule.id, rule.owasp_cicd)
                confidence = rule.confidence or default_confidence(rule.id)
                review_needed = rule.review_needed or default_review_needed(rule.id)
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        file=filepath,
                        line=line_num,
                        snippet=snippet,
                        remediation=rule.remediation,
                        reference=rule.reference,
                        owasp_cicd=rule.owasp_cicd,
                        stride=rule.stride,
                        threat_narrative=rule.threat_narrative,
                        incidents=rule.incidents,
                        origin="cross-workflow",
                        finding_family=family,
                        confidence=confidence,
                        exploitability="medium",
                        review_needed=review_needed,
                    )
                )
    return findings
