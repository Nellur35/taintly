"""GitLab — CHAIN composer rules (CHAIN-GL-1xx).

The CHAIN-GL family fires when MULTIPLE single-rule conditions co-
occur in the resolved GitLab CI graph, escalating the combined
finding above what any single conjunct would warrant.  Each rule's
pattern is a :class:`taintly.gitlab_workflow_corpus.GitLabCorpusPattern`
whose callback inspects the pre-built :class:`GitLabWorkflowCorpus`
and asserts all conjuncts before emitting.

Rules in this module:

  * CHAIN-GL-101 — source-owned review of MR publication and job credentials.
  * CHAIN-GL-102 — mutable project include with enabled or unknown
                   root MR configuration. Severity HIGH, review needed:
                   external include execution and privileges are unresolved.
  * CHAIN-GL-103 — TAINT-GL-001 shape (shallow-taint via variables:)
                   + fork-reachable trigger + id_tokens declared.
                   Severity HIGH.  Taint composition: a fork MR can
                   inject shell metacharacters that execute in a job
                   holding the OIDC write-token.

Each rule uses its own evidence profile and describes its analysis limits.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from taintly.gitlab_workflow_corpus import (
    GitLabCorpusFindings,
    GitLabCorpusPattern,
    GitLabWorkflowCorpus,
    GitLabWorkflowSummary,
)
from taintly.models import Platform, Rule, Severity
from taintly.parsers.structural import Event, EventKind, walk_workflow
from taintly.parsers.structural.tokenizer import TokenizerError, TokenKind, tokenize
from taintly.workflow_corpus import TriggerFamily

from .mr_publish import compose_mr_publication

# ---------------------------------------------------------------------------
# Conjunct redetection helpers
# ---------------------------------------------------------------------------

# TAINT-GL-001's conjunct shape: a "tainted CI variable into project
# variable into script" laundering pattern.  We re-detect a lightweight
# version: any project-defined variable receives a tainted source and
# is referenced UNQUOTED in a script line.  The single-rule's full
# taint engine carries the precision; the composite only gates on
# co-occurrence with id_tokens, which is the escalation trigger.
_TAINTED_SOURCES_RE = re.compile(
    r"\$CI_(?:COMMIT_(?:TITLE|MESSAGE|BRANCH|REF_NAME|AUTHOR)|"
    r"MERGE_REQUEST_(?:TITLE|DESCRIPTION|SOURCE_BRANCH_NAME))",
)


def _has_taint_variable_laundering(summary: GitLabWorkflowSummary) -> tuple[bool, int]:
    """Return ``(present, line_1based)`` indicating whether a tainted
    CI variable is assigned into a project ``variables:`` block AND a
    later script line references a project variable unquoted.

    Conservative shape match: we look for the tainted assignment plus
    any unquoted ``$VAR`` script reference.  The cross-variable
    reachability is not proven here — TAINT-GL-001 carries the actual
    flow analysis, and CHAIN-GL-103 only asserts the threat shape's
    raw materials are present alongside the id_tokens escalation.
    """
    # Find the first laundering assignment line (``VAR: $CI_*``).
    laundering_line = 0
    for idx, line in enumerate(summary.lines):
        if line.lstrip().startswith("#"):
            continue
        # Match `KEY: $CI_COMMIT_TITLE` shape inside a variables: block
        # heuristic: line shape is `  NAME: $CI_*`.
        if _TAINTED_SOURCES_RE.search(line) and re.match(
            r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s*\$CI_", line
        ):
            laundering_line = idx + 1
            break
    if laundering_line == 0:
        return False, 0
    # Confirm at least one unquoted `$VAR` reference in a script line.
    in_script = False
    for line in summary.lines:
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^\s*(script|before_script|after_script)\s*:", line):
            in_script = True
            continue
        if in_script:
            # The script block ends when a non-list-item top-level-ish key
            # appears.  Coarse: stop scanning once we hit a non-dash
            # script item at less-or-equal indent.  We just scan all
            # subsequent lines for the unquoted shape — any unquoted
            # $VAR in any script body is enough to confirm the threat
            # shape's tail.
            if re.search(r"(?<!['\"])\$[A-Z_][A-Z0-9_]*(?!['\"])", line):
                return True, laundering_line
    return False, 0


# ---------------------------------------------------------------------------
# CHAIN-GL-102 — Unpinned project include + fork-reachable trigger
# ---------------------------------------------------------------------------


_MR_SOURCE_COMPARE = re.compile(r"""\$CI_PIPELINE_SOURCE\s*(==|!=)\s*(["'])([a-z_]+)\2""")
_DEFAULT_BRANCH_COMPARE = re.compile(
    r"(?:\$CI_COMMIT_BRANCH\s*==\s*\$CI_DEFAULT_BRANCH|"
    r"\$CI_DEFAULT_BRANCH\s*==\s*\$CI_COMMIT_BRANCH)"
)


def _mr_rule_decision(events: list[Event], prefix: tuple[object, ...]) -> tuple[bool | None, bool]:
    """Bounded first-match rules evaluation for an MR pipeline.

    None is unknown, never proof of denial. The second value records a
    matching literal MR-source predicate, rather than generic admission.
    Unsupported predicates/fields and duplicate keys retain uncertainty.
    """
    rows: dict[int, dict[str, str]] = {}
    keys: set[tuple[object, ...]] = set()
    present = False
    for event in events:
        if event.path == prefix and event.kind is EventKind.MAP_KEY:
            if present:
                return None, False
            present = True
        if event.path[: len(prefix)] != prefix or len(event.path) <= len(prefix):
            continue
        tail = event.path[len(prefix) :]
        if len(tail) != 2 or not isinstance(tail[0], int) or tail[1] not in {"if", "when"}:
            return None, False
        if event.kind is EventKind.MAP_KEY:
            if event.path in keys:
                return None, False
            keys.add(event.path)
            rows.setdefault(tail[0], {})
        elif event.kind is EventKind.LEAF_SCALAR and event.value is not None:
            rows.setdefault(tail[0], {})[str(tail[1])] = event.value
    if not present or not rows:
        return None, False
    for index, row in sorted(rows.items()):
        if any(prefix + (index, key) in keys and key not in row for key in ("if", "when")):
            return None, False
        condition = row.get("if")
        explicit_mr = False
        if condition is None:
            matches: bool | None = True
        elif match := _MR_SOURCE_COMPARE.fullmatch(condition.strip()):
            is_mr = match[3] == "merge_request_event"
            matches = is_mr if match[1] == "==" else not is_mr
            explicit_mr = is_mr and match[1] == "=="
        elif _DEFAULT_BRANCH_COMPARE.fullmatch(condition.strip()):
            # CI_COMMIT_BRANCH is unavailable in merge-request pipelines.
            matches = False
        else:
            matches = None
        if matches is None:
            return None, False
        if not matches:
            continue
        when = row.get("when", "on_success")
        if when not in {"never", "always", "on_success", "manual", "delayed"}:
            return None, False
        return when != "never", explicit_mr
    return False, False


def _root_mr_state(corpus: GitLabWorkflowCorpus) -> str:
    """Use root configuration only; included job rules do not enable MR CI."""
    root = corpus.by_filepath(corpus.entry_filepath) if corpus.entry_filepath else None
    if root is None or root.content_truncated:
        return "unknown"
    try:
        if any(token.kind is TokenKind.ALIAS for token in tokenize(root.content)):
            return "unknown"
    except TokenizerError:
        return "unknown"
    events = list(walk_workflow(root.filepath, content=root.content, include_keys=True))
    if any(event.kind in {EventKind.ERROR, EventKind.CUTOFF} for event in events):
        return "unknown"
    # Duplicate root mappings can replace policy or jobs; do not guess precedence.
    root_keys: set[tuple[object, ...]] = set()
    for event in events:
        if event.kind is EventKind.MAP_KEY and len(event.path) == 1:
            if event.path in root_keys:
                return "unknown"
            root_keys.add(event.path)
    allowed, explicit = _mr_rule_decision(events, ("workflow", "rules"))
    if allowed is False:
        # GitLab's external GitHub PR integration ignores fork PRs; that
        # distinct source alone does not establish this native-MR chain.
        return "denied"
    if allowed is True and explicit:
        return "enabled"
    if allowed is None and any(event.path == ("workflow", "rules") for event in events):
        return "unknown"
    for job in root.job_definitions:
        if job.name.startswith("."):
            continue
        admitted, explicit = _mr_rule_decision(events, (job.name, "rules"))
        if admitted is True and explicit:
            return "enabled"
    return "unknown"


def _compose_chain_gl_102(corpus: GitLabWorkflowCorpus) -> GitLabCorpusFindings:
    """Review candidate at the mutable include's actionable call site.

    Only a supported root workflow denial excludes the MR candidate.
    Unresolved include bodies and inherited policy remain unknown.
    """
    findings: GitLabCorpusFindings = []
    state = _root_mr_state(corpus)
    if state == "denied":
        return findings
    seen: set[tuple[str, int]] = set()
    for w in corpus.all():
        for ref in w.unpinned_project_includes:
            key = (ref.filepath, ref.line)
            if key in seen:
                continue
            seen.add(key)
            snippet = (
                f"CHAIN-GL-102: mutable project include '{ref.target}'; "
                f"root MR configuration is {state}. The include body and activation rules "
                "are unresolved; upstream modification authority and execution require review. "
                "Fork MR pipelines normally use fork resources; parent-project execution "
                "and secret access are not established by this finding."
            )
            findings.append((ref.filepath, ref.line, snippet))
    return findings


# ---------------------------------------------------------------------------
# CHAIN-GL-103 — Tainted-variable laundering + fork-reachable + id_tokens
# ---------------------------------------------------------------------------


def _compose_chain_gl_103(corpus: GitLabWorkflowCorpus) -> GitLabCorpusFindings:
    """Compose validated CODE with same-job token and bounded MR-rule context."""
    from .shell_role import (
        GitLabShellRole,
        _profile_paths,
        _source_profile,
        classify_gitlab_shallow_use,
        validate_gitlab_shallow_use,
    )

    findings: GitLabCorpusFindings = []
    for w in corpus.all():
        profile = _source_profile(w.content, w.filepath)
        for path in _profile_paths(profile):
            if path.kind != "shallow" or path.sink_kind != "script":
                continue
            evidence = classify_gitlab_shallow_use(w.content, w.filepath, path)
            if evidence.role is not GitLabShellRole.CODE or not validate_gitlab_shallow_use(
                evidence, w.content, w.filepath, path.sink_line
            ):
                continue
            owner_job = evidence.owner_path[0] if evidence.owner_path else None
            matching_jobs = [
                candidate
                for candidate in w.job_definitions
                if candidate.name == owner_job
                and candidate.line <= path.sink_line < candidate.end_line
            ]
            if len(matching_jobs) != 1:
                continue
            job = matching_jobs[0]
            activation = _gl103_mr_activation(w.content, w.filepath, job.name, profile.events)
            if activation is False:
                continue
            # The corpus trigger summary is only a possibility filter when
            # YAML rules do not resolve activation. It is never proof that a
            # specific owner job admits merge-request pipelines.
            if activation is None and TriggerFamily.FORK_REACHABLE not in job.triggers:
                continue
            if job.protected_branch_only or job.bot_gate_pattern:
                continue
            if not _gl103_has_owned_token_audience(w.content, w.filepath, job.name, profile.events):
                continue
            activation_note = (
                "Supported workflow/owning-job rules do not deny an MR pipeline; actual "
                "triggering remains unverified."
                if activation is True
                else "MR activation for the owning job is unresolved from this YAML; "
                "the project setting and effective execution remain unverified."
            )
            snippet = (
                "CHAIN-GL-103: tainted value $"
                f"{path.laundered_var} from ${path.source_var} reaches a supported "
                "conditional POSIX shell code profile in this job. The same job has "
                "a structural id_tokens token declaration with a nonempty aud value. "
                f"{activation_note} Runner behavior, token issuance, federation "
                "acceptance, and permissions are unverified."
            )
            findings.append((w.filepath, path.sink_line, snippet))
            break
    return findings


def _gl103_has_owned_token_audience(
    content: str,
    filepath: str,
    job_name: str,
    events: Sequence[Event] | None = None,
) -> bool:
    """Require a direct owner-job id_tokens token map with nonempty aud."""
    if events is None:
        try:
            events = tuple(
                walk_workflow(
                    filepath,
                    schema="gitlab_ci",
                    content=content,
                    include_keys=True,
                )
            )
        except Exception:
            return False
    if any(event.kind in {EventKind.CUTOFF, EventKind.ERROR} for event in events):
        return False

    token_prefix = (job_name, "id_tokens")
    token_names = {
        event.path[2]
        for event in events
        if event.kind is EventKind.MAP_KEY
        and len(event.path) == 3
        and event.path[:2] == token_prefix
        and isinstance(event.path[2], str)
        and event.path[2].strip()
    }
    if not token_names:
        return False

    for token_name in token_names:
        audience_path = token_prefix + (token_name, "aud")
        audience_key = any(
            event.kind is EventKind.MAP_KEY and event.path == audience_path for event in events
        )
        if not audience_key:
            continue
        audience_values = [
            event.value
            for event in events
            if event.kind is EventKind.LEAF_SCALAR
            and event.path[: len(audience_path)] == audience_path
            and (
                event.path == audience_path
                or (
                    len(event.path) == len(audience_path) + 1
                    and isinstance(event.path[-1], int)
                    and not isinstance(event.path[-1], bool)
                )
            )
        ]
        if audience_values and all(
            isinstance(value, str) and value.strip() for value in audience_values
        ):
            return True
    return False


def _gl103_mr_activation(
    content: str,
    filepath: str,
    job_name: str,
    events: Sequence[Event] | None = None,
) -> bool | None:
    """Return bounded YAML MR admission for the workflow and exact owner job.

    False means supported rules deny MR activation. True means supported
    workflow and job rules admit it. None is unresolved, including the
    default job-rule behavior and external project settings.
    """
    if events is None:
        try:
            events = tuple(
                walk_workflow(
                    filepath,
                    schema="gitlab_ci",
                    content=content,
                    include_keys=True,
                )
            )
        except Exception:
            return None
    if any(event.kind in {EventKind.CUTOFF, EventKind.ERROR} for event in events):
        return None

    workflow_rules_path = ("workflow", "rules")
    job_rules_path = (job_name, "rules")
    workflow_rules_present = any(
        event.kind is EventKind.MAP_KEY and event.path == workflow_rules_path for event in events
    )
    job_rules_present = any(
        event.kind is EventKind.MAP_KEY and event.path == job_rules_path for event in events
    )
    unresolved = False
    # Legacy only/except semantics and project-level defaults are deliberately
    # not inferred by this bounded rules reader.
    if any(
        event.kind is EventKind.MAP_KEY and event.path in {(job_name, "only"), (job_name, "except")}
        for event in events
    ):
        unresolved = True

    if workflow_rules_present:
        workflow_allowed, _workflow_explicit_mr = _mr_rule_decision(
            list(events), workflow_rules_path
        )
        if workflow_allowed is False:
            return False
        if workflow_allowed is None:
            unresolved = True

    if job_rules_present:
        job_allowed, _job_explicit_mr = _mr_rule_decision(list(events), job_rules_path)
        if job_allowed is False:
            return False
        if job_allowed is None:
            unresolved = True
    else:
        unresolved = True

    return None if unresolved else True


# ---------------------------------------------------------------------------
# Rule registrations
# ---------------------------------------------------------------------------


RULES: list[Rule] = [
    Rule(
        id="CHAIN-GL-101",
        title="Review: GitLab merge-request publication with job credential context",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "One source-owned GitLab job has a possible local merge-request selection and "
            "configures a publication operation alongside an ID-token declaration or a "
            "supported GitLab registry authentication and build sequence. The evidence "
            "distinguishes a declared token from its use and privileges."
        ),
        pattern=GitLabCorpusPattern(callback=compose_mr_publication),
        remediation=(
            "Verify the effective job and whether an authorized user can run this fork MR "
            "in the parent project. Check the registry's repository and tag rules, or the "
            "OIDC relying party's audience, subject and permissions, as applicable. Move "
            "privileged publication to reviewed, protected refs where MR publication is "
            "unnecessary. Where preview publication is required, isolate its credentials "
            "and destinations from release publication."
        ),
        reference="https://docs.gitlab.com/ci/pipelines/merge_request_pipelines/",
        test_positive=[],
        test_negative=[],
        stride=["E", "T", "I"],
        threat_narrative=(
            "An MR can change code consumed by a publication job. A fork pipeline normally "
            "uses the fork's resources. A separately authorized parent-project pipeline can "
            "run fork configuration in the parent's context. What a credential can publish "
            "depends on the effective run and receiving service policy."
        ),
        confidence="medium",
        review_needed=True,
        finding_family="privileged_pr_trigger",
    ),
    Rule(
        id="CHAIN-GL-102",
        title="CHAIN: mutable project include; MR execution context requires review",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A mutable project include is present and the root configuration either "
            "admits merge-request pipelines or leaves their reachability unknown. "
            "Root workflow rules that prove MR denial exclude this candidate. Included "
            "rules, comments and script strings do not establish root MR enablement. "
            "External GitHub PR integration alone is outside this native-MR chain. "
            "The external include body, conditional activation, upstream modification "
            "authority and effective privileges require review. The independent "
            "SEC3-GL-002 immutability warning remains applicable without MR reachability."
        ),
        pattern=GitLabCorpusPattern(callback=_compose_chain_gl_102),
        remediation=(
            "Pin the project include to a full 40-character commit SHA:\n"
            "  include:\n"
            "    - project: 'my-group/my-project'\n"
            '      ref: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"\n'
            "      file: '/templates/ci.yml'\n"
            "Find the current SHA with:\n"
            "  git ls-remote https://gitlab.com/my-group/my-project refs/heads/main\n"
            "Run `taintly --guide CHAIN-GL-102` for the full checklist."
        ),
        reference=(
            "https://docs.gitlab.com/ci/yaml/includes/; "
            "https://docs.gitlab.com/ci/pipelines/merge_request_pipelines/; "
            "https://docs.gitlab.com/ci/ci_cd_for_external_repos/#known-issues"
        ),
        test_positive=[],
        test_negative=[],
        stride=["T", "E"],
        threat_narrative=(
            "An actor with upstream modification authority could change the mutable "
            "include. If that include is activated and its jobs execute, the change "
            "could affect a consuming pipeline. Fork MR pipelines normally run with "
            "fork resources; a separately authorized parent-project run has different "
            "privileges. Neither execution nor parent secret access is proven here."
        ),
        confidence="medium",
        review_needed=True,
        finding_family="supply_chain_immutability",
    ),
    Rule(
        id="CHAIN-GL-103",
        title=("CHAIN: supported shell-code use + possible MR activation + id_tokens (review)"),
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A source-bound CI value reaches one supported command-code form in a "
            "uniquely owned script item under the conditional POSIX shell profile. "
            "The same job declares ``id_tokens`` with an audience. Supported YAML "
            "rules may admit an MR pipeline; otherwise activation can remain unresolved "
            "because default behavior and project settings are outside this analysis. "
            "This is a conditional review candidate, not proof of fork reachability or "
            "execution. Runner shell, token issuance or availability, external federation "
            "acceptance, and cloud permissions are not established."
        ),
        pattern=GitLabCorpusPattern(callback=_compose_chain_gl_103),
        remediation=(
            "Keep attacker-controlled values as data. Remove eval or interpreter-code "
            "consumption; quoting alone does not make those uses safe. Review the job's "
            "trigger conditions and ``id_tokens`` audience separately, then verify "
            "token issuance, external federation trust, and permissions with the "
            "relevant provider configuration."
        ),
        reference=(
            "https://docs.gitlab.com/ci/variables/predefined_variables/; "
            "https://docs.gitlab.com/ci/cloud_services/"
        ),
        test_positive=[],
        test_negative=[],
        stride=["T", "E"],
        threat_narrative=(
            "A job has a source-bound value in a supported conditional POSIX code position "
            "and declares ``id_tokens``. YAML may admit an MR pipeline or leave its "
            "activation unresolved. If the job is triggered and the runner interprets "
            "the value as modeled, code use is a review concern. Token issuance, federation "
            "acceptance, and permissions remain unverified; the finding does not establish "
            "fork reachability or cloud access."
        ),
        confidence="medium",
        review_needed=True,
        finding_family="script_injection",
    ),
]
