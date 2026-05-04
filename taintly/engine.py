"""Core scanning engine — loads rules, applies patterns, produces findings."""

from __future__ import annotations

import glob
import os
import re
from collections.abc import Callable
from dataclasses import dataclass

from .families import classify_rule, default_confidence, default_review_needed
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
    _MAX_SAFE_TEXT_LEN,
    AuditReport,
    Finding,
    Platform,
    Rule,
    Severity,
    scan_session,
)
from .parsers.anchor_expander import expand_anchors
from .pse_enrichment import enrich_pse_findings
from .staticguard import WorkflowContext as StaticGuardContext
from .staticguard import (
    detect_github_workflow_context,
    find_dead_line_ranges,
    is_workflow_whole_dead,
)
from .workflow_context import analyze as analyze_workflow
from .workflow_context import compute_exploitability
from .workflow_corpus import CorpusPattern, build_corpus

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


def scan_file(
    filepath: str,
    rules: list[Rule],
    _content: str | None = None,
    repoctx: StaticGuardContext | None = None,
    gitlabctx: GitLabContext | None = None,
    jenkinsctx: JenkinsContext | None = None,
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
    # Surface silent coverage loss: the ReDoS length cap in _safe_search
    # skips regex evaluation on text > _MAX_SAFE_TEXT_LEN. Full-content
    # patterns (AbsencePattern, ContextPattern requires) on oversize files
    # return no matches regardless of what's inside. Emit a single
    # informational finding so "scan clean" can be distinguished from
    # "scan skipped". Per-line regex continues to work because individual
    # YAML lines fit comfortably under the cap.
    if len(content) > _MAX_SAFE_TEXT_LEN:
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
                    f"{_MAX_SAFE_TEXT_LEN}-byte length cap. The chunked-search "
                    "path scans large workflows in line-windowed chunks with "
                    "overlap so file-scope rules (ContextPattern requires / "
                    "AbsencePattern) still resolve. Coverage is preserved; "
                    "this notice surfaces because the file is unusually large "
                    "for a CI config. If you suspect a regex match that spans "
                    "a chunk boundary was missed, split the workflow via "
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

    with scan_session():
        for rule in rules:
            try:
                matches = rule.pattern.check(content, lines)
                # Anchor-aware suppression: if the rule opts in and an
                # anchor expansion would NOT produce the match, treat
                # it as an anchor-mediated false positive.  We never
                # ADD findings via expansion — only suppress.  The
                # 30-line tolerance handles cases where the anchor
                # expansion shifts subsequent line numbers downward.
                if matches and getattr(rule, "anchor_aware", False):
                    expanded_content, expanded_lines = _get_expanded()
                    if expanded_content != content:
                        expanded_matches = rule.pattern.check(expanded_content, expanded_lines)
                        expanded_lineset = {ln for ln, _ in expanded_matches}
                        matches = [
                            (ln, snip)
                            for ln, snip in matches
                            if any(abs(ln - eln) <= 30 for eln in expanded_lineset)
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


POST_PROCESSORS: tuple[_PostProcessor, ...] = (
    _github_dead_postprocessor,
    _gitlab_dead_postprocessor,
    _jenkins_dead_postprocessor,
    _maintainer_downgrade_postprocessor,
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
_MAINTAINER_DOWNGRADE_PATTERNS: tuple[tuple[str | None, str, re.Pattern[str]], ...] = (
    (None, "script_injection", _REF_NAME_REF_RE),
    ("SEC4-GH-008", "script_injection", _INPUTS_REF_RE),
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
    """Mutate ``findings`` in place: for findings in the
    script-injection family that cite ``$GITHUB_REF_NAME`` (or
    ``github.ref_name``) on a workflow whose triggers are all
    maintainer-gated, downgrade severity by one tier.

    Rationale: exploitability presumes attacker control of
    ``$GITHUB_REF_NAME``, but tag-push / release / schedule events
    are maintainer-only firing paths.  HIGH severity with low
    exploitability is internally inconsistent — when the only
    attacker path requires maintainer compromise, MEDIUM is the
    correct calibration.
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
        if not _matches_maintainer_downgrade_pattern(f):
            continue
        new_sev = _downgrade.get(f.severity)
        if new_sev is not None and new_sev != f.severity:
            old_sev = f.severity
            f.severity = new_sev
            f.calibration_reason = (
                "Maintainer-gated trigger path downgraded severity "
                f"from {old_sev.value} to {new_sev.value}."
            )


def _matches_maintainer_downgrade_pattern(finding: Finding) -> bool:
    for rule_id, family, pattern in _MAINTAINER_DOWNGRADE_PATTERNS:
        if rule_id is not None and finding.rule_id != rule_id:
            continue
        if getattr(finding, "finding_family", "") != family:
            continue
        if pattern.search(finding.snippet or ""):
            return True
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
                or os.path.isfile(os.path.join(cur, ".gitlab-ci.yml"))
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
        return "/.github/workflows/" in norm
    if platform == Platform.GITLAB:
        if name == ".gitlab-ci.yml":
            return True
        norm = os.path.normpath(filepath).replace(os.sep, "/")
        return "/.gitlab/" in norm or "/ci/" in norm
    if platform == Platform.JENKINS:
        return (
            name == "Jenkinsfile"
            or name.startswith("Jenkinsfile.")
            or name.endswith(".jenkinsfile")
            or name.endswith(".groovy")
        )
    raise ValueError(f"unsupported platform: {platform}")


def detect_platform(repo_path: str) -> Platform | None:
    """Auto-detect CI/CD platform from directory structure."""
    gh_dir = os.path.join(repo_path, ".github", "workflows")
    gl_file = os.path.join(repo_path, ".gitlab-ci.yml")
    jk_file = os.path.join(repo_path, "Jenkinsfile")

    has_github = os.path.isdir(gh_dir)
    has_gitlab = os.path.isfile(gl_file)
    has_jenkins = os.path.isfile(jk_file) or bool(
        glob.glob(os.path.join(repo_path, "Jenkinsfile.*"))
    )

    if has_github and has_gitlab:
        return None  # Both — caller should scan both
    if has_github:
        return Platform.GITHUB
    if has_gitlab:
        return Platform.GITLAB
    if has_jenkins:
        return Platform.JENKINS
    return None


def discover_files(repo_path: str, platform: Platform) -> list[str]:
    """Find all CI/CD config files for a given platform."""
    files = []

    if platform == Platform.GITHUB:
        workflow_dir = os.path.join(repo_path, ".github", "workflows")
        if os.path.isdir(workflow_dir):
            files.extend(glob.glob(os.path.join(workflow_dir, "*.yml")))
            files.extend(glob.glob(os.path.join(workflow_dir, "*.yaml")))

    elif platform == Platform.GITLAB:
        gl_file = os.path.join(repo_path, ".gitlab-ci.yml")
        if os.path.isfile(gl_file):
            files.append(gl_file)
        # Also check for local includes
        for pattern in ["ci/*.yml", "ci/**/*.yml", ".gitlab/*.yml", ".gitlab/**/*.yml"]:
            files.extend(glob.glob(os.path.join(repo_path, pattern), recursive=True))

    elif platform == Platform.JENKINS:
        # Root-level canonical names first — cheap, deterministic.
        for name in ("Jenkinsfile", "Jenkinsfile.groovy"):
            p = os.path.join(repo_path, name)
            if os.path.isfile(p):
                files.append(p)
        files.extend(glob.glob(os.path.join(repo_path, "Jenkinsfile.*")))
        # Nested pipelines: monorepos, ci/, scripts/, jenkins/, per-vendor
        # subtrees. Four patterns cover the common nesting shapes.
        # Filter out vendor/dep dirs to avoid scanning third-party code.
        excluded_segments = {"node_modules", ".git", "vendor", "__pycache__"}
        for pattern in (
            "**/Jenkinsfile",
            "**/Jenkinsfile.*",
            "**/*.jenkinsfile",
            "jenkins/**/*.groovy",
        ):
            for match in glob.glob(os.path.join(repo_path, pattern), recursive=True):
                # Path-segment check avoids matching node_modules_old etc.
                rel = os.path.relpath(match, repo_path)
                if any(seg in excluded_segments for seg in rel.split(os.sep)):
                    continue
                files.append(match)

    # Normalise separators before deduping.  Windows paths returned by
    # ``os.path.join`` use ``\`` while ``glob`` recursion can produce
    # the same file with mixed separators ("C:\repo/Jenkinsfile" vs
    # "C:\repo\Jenkinsfile"); ``set()`` would treat those as distinct
    # and a Jenkinsfile would be scanned twice, doubling findings.
    # ``os.path.normpath`` collapses to the platform's native form.
    return sorted({os.path.normpath(p) for p in files})


def scan_repo(
    repo_path: str,
    rules: list[Rule],
    platform: Platform | None = None,
    *,
    explicit_github_repoctx: StaticGuardContext | None = None,
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
        if explicit_files:
            # Scoped mode: caller named specific files; scan ONLY those
            # (and only the ones that match this platform).  The repo
            # root is still used so platform-aware context (path-based
            # rules, etc.) sees the file in its real location.
            files = [ef for ef in explicit_files if _file_matches_platform(ef, plat)]
        else:
            files = discover_files(repo_path, plat)
        report.files_scanned = len(files)
        report.rules_loaded = len(platform_rules)

        all_findings: list[Finding] = []
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
        # Jenkins parameter_values has no consumer in the evaluator
        # today (``evaluate_jenkins_when`` discards ctx).  Populating
        # from the environment would be speculative without effect;
        # leave the field empty until a context-aware evaluator
        # lands.
        jenkinsctx = JenkinsContext() if plat == Platform.JENKINS else None
        for fpath in files:
            all_findings.extend(
                scan_file(
                    fpath,
                    platform_rules,
                    repoctx=repoctx,
                    gitlabctx=gitlabctx,
                    jenkinsctx=jenkinsctx,
                )
            )
            # Surface-evaluation pass: re-read the file once and
            # check each ContextPattern's anchor regex.  Only families
            # whose anchors found a candidate get added — so a family
            # with no candidates anywhere stays "Not applicable".
            if ctx_rules_by_family:
                try:
                    with open(fpath, encoding="utf-8", errors="replace") as _f:
                        _content = _f.read()
                    _lines = _content.splitlines()
                except OSError:
                    continue
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
        # PSE-GH-002: enrich PSE-GH-001 findings by classifying any
        # local IAM policy that matches the workflow's role-to-assume
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
        for f in _dedupe_project_scope(all_findings):
            report.add(f)

        report.summarize()
        reports.append(report)

    return reports


def _run_corpus_rules(repo_path: str, rules: list[Rule]) -> list[Finding]:
    """Build a WorkflowCorpus and run every CorpusPattern rule against it.

    Returns the findings list (already wrapped in :class:`Finding` with
    the rule's metadata).  No-op when no CorpusPattern rules are loaded;
    the corpus build is then skipped entirely so non-cross-file users
    don't pay the walk cost.
    """
    corpus_rules = [r for r in rules if isinstance(r.pattern, CorpusPattern)]
    if not corpus_rules:
        return []

    corpus = build_corpus(repo_path)
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
            for filepath, line_num, snippet in hits:
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
