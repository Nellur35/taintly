"""Cross-file GitLab CI corpus — GL parallel of :mod:`taintly.workflow_corpus`.

The per-file rule pipeline (``ContextPattern`` / ``RegexPattern`` /
``BlockPattern`` / ``PathPattern``) cannot answer questions whose
evidence requires reading the resolved ``include:`` graph as a whole —
"this MR-pipeline job runs a deploy command AND the project also
declares ``id_tokens:`` AND the include set is unpinned" needs the
entry file plus everything it pulls in via ``include: local:`` in
scope at once.

:class:`GitLabWorkflowCorpus` builds a one-time, per-scan index of
``.gitlab-ci.yml`` (the entry file) plus every ``include: local:``
target reachable from it, capped by depth/file-count/byte-budget.  It
exposes per-file:

  * ``triggers`` — fork-reachable / privileged / scheduled (mapped
    from ``$CI_PIPELINE_SOURCE`` / ``rules: if:`` clauses).
  * ``id_tokens_declared`` — whether the file declares ``id_tokens:``
    at workflow or job level (the GL analogue of "has write token";
    id_tokens grant OIDC to cloud providers).
  * ``protected_branch_only`` — whether the workflow gates execution
    to default/protected branches via ``rules: if:`` literal compares
    against ``$CI_COMMIT_BRANCH`` / ``$CI_COMMIT_REF_PROTECTED`` /
    ``$CI_COMMIT_TAG``.
  * ``bot_gate_pattern`` — whether ``rules: if:`` literal-equals-
    compares ``$GITLAB_USER_LOGIN`` to a known trusted bot.
  * ``cross_project_includes`` — unresolved (out-of-scope) include
    references: ``include: project:`` / ``template:`` / ``remote:`` /
    ``component:`` entries.  Recorded for trigger/permission
    analysis; bodies are NOT fetched (the composer's threat model is
    the local repo's surface).
  * ``unpinned_project_includes`` — subset of cross-project includes
    that lack a 40-char SHA ref.  Used by CHAIN-GL-102.

Design constraints:
  * Pure-Python extraction uses the structural reader for local include
    paths and bounded regex summaries for the remaining fields; no PyYAML.
  * Idempotent: extractors return value objects, no side-effects.
  * Bounded recursion (max depth, max files) to handle pathological
    ``include`` cycles safely.
  * Cap content size per file via ``_MAX_SAFE_TEXT_LEN`` from
    :mod:`taintly.models`.

This file is the data-extraction layer only.  Cross-file *rules* live
in :mod:`taintly.rules.gitlab.chain_compose` and consume the corpus
via the new :class:`GitLabCorpusPattern` shape declared below.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from .models import _MAX_SAFE_TEXT_LEN
from .parsers.structural import EventKind, walk_workflow
from .parsers.structural.tokenizer import TokenizerError, TokenKind, tokenize
from .path_safety import is_within_repo, resolve_local_include
from .workflow_corpus import TriggerFamily

# ---------------------------------------------------------------------------
# $CI_PIPELINE_SOURCE → TriggerFamily mapping
# ---------------------------------------------------------------------------
#
# GitLab's $CI_PIPELINE_SOURCE values are an enum-ish string.  The
# attacker-utility classification:
#
#   * merge_request_event / external_pull_request_event — fork-reachable.
#     An MR pipeline fires under the SOURCE project (the parent the fork
#     was opened against); the runner sees the source project's
#     unprotected CI/CD variables but executes the FORK's code.
#   * push — privileged when on default/protected branch; otherwise
#     still privileged but lower-trust (a contributor with a feature
#     branch in the same project).  Composer treats `push` as
#     PRIVILEGED conservatively.
#   * schedule — SCHEDULED (cron pipelines, maintainer-configured).
#   * web / api / trigger / pipeline / chat / external — PRIVILEGED
#     (initiated by a logged-in user, an API token, or an internal
#     pipeline-trigger token; not a fork-author primitive).
#   * parent_pipeline / pipeline — privileged (multi-project pipeline
#     trigger from a parent).
_GL_FORK_REACHABLE_SOURCES: frozenset[str] = frozenset(
    {
        "merge_request_event",
        "external_pull_request_event",
    }
)

_GL_PRIVILEGED_SOURCES: frozenset[str] = frozenset(
    {
        "push",
        "web",
        "api",
        "trigger",
        "pipeline",
        "chat",
        "external",
        "parent_pipeline",
    }
)

_GL_SCHEDULED_SOURCES: frozenset[str] = frozenset({"schedule"})

# ---------------------------------------------------------------------------
# Bot-gate detection — analogue of GH's _content_has_trusted_bot_gate
# ---------------------------------------------------------------------------
#
# A ``rules: if:`` clause that literal-equals-compares
# ``$GITLAB_USER_LOGIN`` (or ``$GITLAB_USER_NAME``) to one of these
# names is the canonical "bot gate" — author intended to allow only
# the named bot to bypass an access check.  We surface this so the
# composer can decide that a trusted-bot-only path doesn't carry the
# fork-attacker risk.
_TRUSTED_BOT_NAMES: frozenset[str] = frozenset(
    {
        "gitlab-bot",
        "renovate-bot",
        "dependabot-gitlab",
        "project_bot",
        "project-bot",
        "release-bot",
    }
)

# Bounded recursion — `include:` can cycle in pathological configs.
# These bounds match the shape `taintly.workflow_corpus` already uses
# for reusable-workflow walks (depth 5, total file count 64).  Cycles
# are also detected by tracking visited absolute paths.
_MAX_INCLUDE_DEPTH = 5
_MAX_INCLUDE_FILES = 64


# ---------------------------------------------------------------------------
# Per-feature value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GitLabJobSummary:
    """Per-job summary inside a GitLab CI file.

    :attr name: Job name (the YAML mapping key under top-level).
    :attr id_tokens_declared: ``True`` when this job declares
        ``id_tokens:`` (workflow-level id_tokens are tracked
        separately on :class:`GitLabWorkflowSummary`).
    :attr triggers: Trigger families that can reach this job after
        intersecting workflow and job ``rules:`` constraints.
    :attr protected_branch_only: Whether workflow or job rules restrict
        this job to protected/default branches.
    :attr bot_gate_pattern: Whether workflow or job rules restrict this
        job to a trusted bot identity.
    :attr line: 1-based line of the job's name key.
    :attr end_line: 1-based exclusive end of this job's top-level block.
    """

    name: str
    id_tokens_declared: bool
    line: int
    end_line: int
    triggers: frozenset[TriggerFamily] = field(default_factory=frozenset)
    protected_branch_only: bool = False
    bot_gate_pattern: bool = False


@dataclass(frozen=True)
class GitLabIncludeRef:
    """An unresolved ``include:`` reference.

    Local includes ARE resolved during the walk and become their own
    :class:`GitLabWorkflowSummary` in the corpus; only cross-project /
    remote / template / component refs land here.

    :attr kind: ``"project"`` | ``"remote"`` | ``"template"`` |
        ``"component"``.
    :attr target: A human-readable identifier — for ``project`` the
        ``project/path:ref:file`` triple; for ``remote`` the URL; for
        ``template`` / ``component`` the literal name.
    :attr ref: For ``project`` includes, the ``ref:`` value (or empty
        when omitted).  Used by CHAIN-GL-102 to detect unpinned refs.
    :attr filepath: The file in which the include was declared (so
        composer findings can cite the call site, not the included
        body).
    :attr line: 1-based line.
    """

    kind: str
    target: str
    ref: str
    filepath: str
    line: int


@dataclass
class GitLabWorkflowSummary:
    """Per-file summary of one resolved GitLab CI file.

    Carries the file body so composer rules can quote a snippet at
    finding-emit time without re-reading the file.

    :attr filepath: Absolute path on disk.
    :attr content: File body (capped at :data:`_MAX_SAFE_TEXT_LEN`).
    :attr lines: ``content.splitlines()`` — kept for parity with the
        GH ``WorkflowSummary`` shape.
    :attr triggers: Classified :class:`TriggerFamily` set derived from
        ``workflow: rules:`` + per-job ``rules:`` ``$CI_PIPELINE_SOURCE``
        compares.  When the file does NOT restrict triggers, every
        :class:`TriggerFamily` is included (worst-case assumption: the
        pipeline runs on whatever fires it).
    :attr raw_source_names: The raw ``$CI_PIPELINE_SOURCE`` literal
        values seen in compares — diagnostic.
    :attr id_tokens_declared: Whether ``id_tokens:`` appears anywhere
        (workflow- or job-level) in this file.
    :attr protected_branch_only: Whether ``rules: if:`` clauses gate
        execution to default/protected branches.
    :attr bot_gate_pattern: Whether ``rules: if:`` literal-equals a
        trusted-bot name against ``$GITLAB_USER_LOGIN`` /
        ``$GITLAB_USER_NAME``.
    :attr job_definitions: Per-job summaries (one per top-level
        non-keyword key with a mapping value).
    :attr cross_project_includes: ``include:`` refs whose body was NOT
        fetched (project / remote / template / component).
    :attr unpinned_project_includes: Subset of cross_project_includes
        where ``kind == "project"`` and ``ref`` is not a 40-char SHA.
    """

    filepath: str
    content: str
    lines: list[str]
    triggers: frozenset[TriggerFamily] = field(default_factory=frozenset)
    raw_source_names: frozenset[str] = field(default_factory=frozenset)
    id_tokens_declared: bool = False
    protected_branch_only: bool = False
    bot_gate_pattern: bool = False
    job_definitions: tuple[GitLabJobSummary, ...] = ()
    cross_project_includes: tuple[GitLabIncludeRef, ...] = ()
    unpinned_project_includes: tuple[GitLabIncludeRef, ...] = ()
    content_truncated: bool = False


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------


@dataclass
class GitLabWorkflowCorpus:
    """Collection of :class:`GitLabWorkflowSummary` keyed by filepath.

    Built once per scan from a repo root.  The corpus contains the
    entry file (``.gitlab-ci.yml`` or ``.gitlab/.gitlab-ci.yml``) PLUS
    every ``include: local:`` target reachable from it, bounded by
    :data:`_MAX_INCLUDE_DEPTH` / :data:`_MAX_INCLUDE_FILES`.

    Composer rules iterate via :meth:`all` or :meth:`by_trigger`.
    """

    repo_path: str
    workflows: dict[str, GitLabWorkflowSummary] = field(default_factory=dict)
    entry_filepath: str | None = None

    def all(self) -> list[GitLabWorkflowSummary]:
        return list(self.workflows.values())

    def by_trigger(self, family: TriggerFamily) -> list[GitLabWorkflowSummary]:
        """All summaries whose trigger set contains ``family``."""
        return [w for w in self.workflows.values() if family in w.triggers]

    def by_filepath(self, filepath: str) -> GitLabWorkflowSummary | None:
        return self.workflows.get(filepath)


# ---------------------------------------------------------------------------
# Loader — entry-point + include resolution
# ---------------------------------------------------------------------------


def build_gitlab_corpus(repo_path: str) -> GitLabWorkflowCorpus:
    """Walk a repo, locate ``.gitlab-ci.yml``, resolve local includes,
    and return a :class:`GitLabWorkflowCorpus`.

    Entry-file discovery: prefers ``./.gitlab-ci.yml``; falls back to
    ``./.gitlab/.gitlab-ci.yml`` (documented as a valid alternative
    location).  When neither exists, returns an empty corpus.

    Include resolution is bounded:

      * Depth ≤ :data:`_MAX_INCLUDE_DEPTH` (5).
      * Total visited files ≤ :data:`_MAX_INCLUDE_FILES` (64).
      * Per-file cycle detection by absolute path — once a file is in
        the corpus we don't re-walk its includes.

    Files that fail to read (encoding, ENOENT for a relative include
    target that doesn't exist) are skipped silently — the per-file
    scan will still emit single-file rules against the entry.
    """
    corpus = GitLabWorkflowCorpus(repo_path=repo_path)
    entry = _locate_entry_file(repo_path)
    if entry is None:
        return corpus

    corpus.entry_filepath = entry
    _walk_includes(corpus, entry, depth=0)
    return corpus


def _locate_entry_file(repo_path: str) -> str | None:
    """Return the absolute path of the entry ``.gitlab-ci.yml``, or
    ``None`` when the repo has neither standard location.

    Order: ``./.gitlab-ci.yml`` first, then
    ``./.gitlab/.gitlab-ci.yml``.  Symlinks are followed (``os.path.isfile``).
    """
    for candidate in (
        os.path.join(repo_path, ".gitlab-ci.yml"),
        os.path.join(repo_path, ".gitlab", ".gitlab-ci.yml"),
    ):
        if os.path.isfile(candidate) and is_within_repo(repo_path, candidate):
            return candidate
    return None


def _walk_includes(
    corpus: GitLabWorkflowCorpus,
    filepath: str,
    depth: int,
) -> None:
    """Recursive include walker.  Adds each file to the corpus once,
    then recurses into the file's ``include: local:`` targets at depth
    + 1, stopping at :data:`_MAX_INCLUDE_DEPTH` or once the corpus
    holds :data:`_MAX_INCLUDE_FILES` entries.

    Cycle handling: a file already in ``corpus.workflows`` is skipped
    (no second visit, no re-walk of its includes).  This terminates
    the walk for any cycle of any length without explicit cycle
    detection state.
    """
    if depth > _MAX_INCLUDE_DEPTH:
        return
    if len(corpus.workflows) >= _MAX_INCLUDE_FILES:
        return
    norm = os.path.normpath(filepath)
    if norm in corpus.workflows:
        return

    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return
    truncated = len(content) > _MAX_SAFE_TEXT_LEN
    if truncated:
        # Truncate beyond the cap.  The extractors are line-driven and
        # bounded, but the byte-length cap is the shared invariant so
        # one pathological file can't blow up corpus build time.
        content = content[:_MAX_SAFE_TEXT_LEN]

    summary = _summarize_gitlab_file(norm, content)
    summary.content_truncated = truncated
    corpus.workflows[norm] = summary

    # Recurse into local include targets.  Targets are resolved
    # relative to the repo root per the GitLab docs ("file is searched
    # relative to the project root"), NOT relative to the including
    # file's directory.
    for target in _extract_local_include_paths(content):
        # The shared resolver handles root-relative syntax, globs, and
        # real-path containment before this reader opens a target.
        for sub in resolve_local_include(corpus.repo_path, target, expand_globs=True):
            _walk_includes(corpus, sub, depth=depth + 1)


# ---------------------------------------------------------------------------
# Include extraction — local vs cross-project
# ---------------------------------------------------------------------------

# Root-level include blocks are isolated before parsing so an unrelated
# unsupported YAML feature elsewhere in the file cannot hide local includes.
_ROOT_INCLUDE_LINE_RE = re.compile(r"^(?:include|'include'|\"include\")\s*:")
_ROOT_KEY_LINE_RE = re.compile(r"^(?:[A-Za-z_$][A-Za-z0-9_.-]*|\"[^\"]+\"|'[^']+')\s*:")
_DOCUMENT_BOUNDARY_LINE_RE = re.compile(r"^(?:---|\.\.\.)(?:\s+#.*)?\s*$")

_LOCAL_INCLUDE_PROVIDER_KEYS = frozenset({"project", "remote", "template", "component"})

# Cross-project / remote / template / component keys inside a block
# include item.  Each one shifts the include's kind classification.
_PROJECT_KEY_RE = re.compile(r"^\s*project\s*:\s*['\"]?(?P<value>[^\s'\"#]+)['\"]?\s*(?:#.*)?$")
_REMOTE_KEY_RE = re.compile(r"^\s*remote\s*:\s*['\"]?(?P<value>\S+)['\"]?\s*(?:#.*)?$")
_TEMPLATE_KEY_RE = re.compile(r"^\s*template\s*:\s*['\"]?(?P<value>\S+)['\"]?\s*(?:#.*)?$")
_COMPONENT_KEY_RE = re.compile(r"^\s*component\s*:\s*['\"]?(?P<value>\S+)['\"]?\s*(?:#.*)?$")
_REF_KEY_RE = re.compile(r"^\s*ref\s*:\s*['\"]?(?P<value>[^\s'\"#]+)['\"]?\s*(?:#.*)?$")
_FILE_KEY_RE = re.compile(r"^\s*file\s*:\s*['\"]?(?P<value>[^\s'\"#]+)['\"]?\s*(?:#.*)?$")

# Detect 40-char hex SHA refs (matches GitLab's strictest pinning
# guidance, mirroring SEC3-GL-002's check).  Shorter abbreviated SHAs
# are allowed by Git but not considered pinned for supply-chain
# purposes because they collide more readily.
_SHA40_RE = re.compile(r"^[a-f0-9]{40}$")


def _extract_local_include_paths(content: str) -> list[str]:
    """Extract direct local include values from the first root include block.

    Accepted values are a bare include scalar, a bare scalar item in the
    include list, or a direct ``local:`` field on an include mapping. Nested
    values such as a project include's ``file: [..]`` are not local paths.
    Duplicate root include keys are invalid/unsupported. Cross-project refs
    are captured separately by :func:`_extract_cross_project_includes`.
    """
    lines = content.splitlines()
    for start, line in enumerate(lines):
        if _ROOT_INCLUDE_LINE_RE.match(line):
            end = _include_block_end(lines, start)
            block = "\n".join(lines[start:end])
            return _local_paths_from_include_block(block) if block else []
    return []


def _include_block_end(lines: list[str], start: int) -> int:
    """Find the exclusive line bound of one root ``include`` block.

    Flow tokens keep keys inside multiline collections from looking like
    sibling root keys. The tokenizer skips document markers, so raw lines are
    checked only across gaps in its token stream.
    """
    flow_closers: list[TokenKind] = []
    suffix = "\n".join(lines[start:])
    last_line = 1
    current_token_line = 0
    line_has_root_dash = False

    def document_boundary(first: int, last: int) -> int | None:
        for suffix_line in range(first, last + 1):
            source_index = start + suffix_line - 1
            if source_index < len(lines) and _DOCUMENT_BOUNDARY_LINE_RE.match(lines[source_index]):
                return source_index
        return None

    try:
        for token in tokenize(suffix):
            boundary = document_boundary(last_line + 1, token.line - 1)
            if boundary is not None:
                # A separator inside an open flow is invalid YAML. End the
                # isolated slice there so a later document cannot be treated
                # as a continuation of this include.
                return boundary
            if token.line != current_token_line:
                current_token_line = token.line
                line_has_root_dash = False
            if token.kind is TokenKind.SEQUENCE_DASH and token.indent == 0:
                line_has_root_dash = True
            if (
                token.line > 1
                and token.kind is TokenKind.KEY
                and token.indent == 0
                and not flow_closers
                and not line_has_root_dash
            ):
                return start + token.line - 1
            if token.kind is TokenKind.FLOW_OPEN_SEQ:
                flow_closers.append(TokenKind.FLOW_CLOSE_SEQ)
            elif token.kind is TokenKind.FLOW_OPEN_MAP:
                flow_closers.append(TokenKind.FLOW_CLOSE_MAP)
            elif token.kind in (TokenKind.FLOW_CLOSE_SEQ, TokenKind.FLOW_CLOSE_MAP):
                if flow_closers and flow_closers[-1] is token.kind:
                    flow_closers.pop()
            last_line = max(last_line, token.line)
    except TokenizerError as exc:
        boundary = document_boundary(last_line + 1, exc.line - 1)
        if boundary is not None:
            return boundary
        source_index = start + exc.line - 1
        if (
            not flow_closers
            and source_index > start
            and source_index < len(lines)
            and _ROOT_KEY_LINE_RE.match(lines[source_index])
        ):
            return source_index

    boundary = document_boundary(last_line + 1, len(lines) - start)
    return len(lines) if boundary is None else boundary


def _local_paths_from_include_block(block: str) -> list[str]:
    """Extract direct local/bare include scalars from an isolated block."""
    events = list(
        walk_workflow(
            ".gitlab-ci.yml",
            schema="gitlab_ci",
            content=block,
            include_keys=True,
        )
    )
    providers: dict[int | None, set[str]] = {}
    local_key_counts: dict[int | None, int] = {}

    def direct_item(path: tuple[object, ...]) -> tuple[bool, int | None]:
        if path and path[0] == "include":
            if len(path) == 2 and isinstance(path[1], str):
                return True, None
            if len(path) == 3 and isinstance(path[1], int) and isinstance(path[2], str):
                return True, path[1]
        return False, None

    for event in events:
        if event.kind is not EventKind.MAP_KEY or event.value_kind == "merge_key":
            continue
        if not event.path or event.path[0] != "include" or not isinstance(event.value, str):
            continue
        is_direct, item = direct_item(event.path)
        if not is_direct:
            continue
        if event.value == "local":
            local_key_counts[item] = local_key_counts.get(item, 0) + 1
        elif event.value in _LOCAL_INCLUDE_PROVIDER_KEYS:
            providers.setdefault(item, set()).add(event.value)

    paths: list[str] = []
    for event in events:
        if event.kind is not EventKind.LEAF_SCALAR or event.value is None:
            continue
        path = event.path
        if path == ("include",):
            item = None
        elif len(path) == 2 and path[0] == "include" and isinstance(path[1], int):
            item = path[1]
        elif (
            len(path) == 3
            and path[0] == "include"
            and isinstance(path[1], int)
            and path[2] == "local"
        ):
            item = path[1]
            if local_key_counts.get(item, 0) != 1:
                continue
        elif path == ("include", "local"):
            item = None
            if local_key_counts.get(item, 0) != 1:
                continue
        else:
            continue
        if providers.get(item):
            continue
        value = event.value.strip()
        if value and "://" not in value:
            paths.append(value)
    return paths


def _extract_cross_project_includes(filepath: str, content: str) -> list[GitLabIncludeRef]:
    """Return every cross-project / remote / template / component
    include reference declared in ``content``.

    Each include in the GitLab YAML can carry multiple keys
    (``project: file: ref:``); we group adjacent keys into a single
    block by tracking indentation and emit one :class:`GitLabIncludeRef`
    per logical block.
    """
    out: list[GitLabIncludeRef] = []
    lines = content.splitlines()
    in_include_block = False
    n = len(lines)
    i = 0
    while i < n:
        line = lines[i]
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        indent = len(line) - len(stripped)
        if indent == 0 and re.match(r"^include\s*:\s*", line):
            in_include_block = True
            i += 1
            continue
        if in_include_block:
            if indent == 0:
                in_include_block = False
                continue
            # A block include item starts with `-`.  Collect every
            # mapping key (project / remote / template / component /
            # ref / file) inside the item until the next `-` at the
            # same indent or a parent-level key.
            if stripped.startswith("-"):
                # Determine the item's indent — the body of the item
                # is at a deeper indent than the dash line.
                item_indent = indent
                # Process the dash line as a key-value too: it can be
                # `- project: '...'` directly.
                block_lines: list[str] = [line[item_indent + 1 :]]
                j = i + 1
                while j < n:
                    nxt = lines[j]
                    nxt_stripped = nxt.lstrip()
                    if not nxt_stripped or nxt_stripped.startswith("#"):
                        j += 1
                        continue
                    nxt_indent = len(nxt) - len(nxt_stripped)
                    if nxt_indent <= item_indent:
                        break
                    block_lines.append(nxt)
                    j += 1
                ref = _build_include_ref_from_block(filepath, i + 1, block_lines)
                if ref is not None:
                    out.append(ref)
                i = j
                continue
        i += 1
    return out


def _build_include_ref_from_block(
    filepath: str,
    start_line: int,
    block_lines: list[str],
) -> GitLabIncludeRef | None:
    """Pick the include kind from a block item's keys.  Returns None
    for local-only items (those are handled by the include walker).
    """
    kind: str | None = None
    target_value = ""
    ref_value = ""
    file_value = ""
    for body in block_lines:
        m_project = _PROJECT_KEY_RE.match(body)
        if m_project:
            kind = "project"
            target_value = m_project.group("value")
            continue
        m_remote = _REMOTE_KEY_RE.match(body)
        if m_remote:
            kind = "remote"
            target_value = m_remote.group("value")
            continue
        m_template = _TEMPLATE_KEY_RE.match(body)
        if m_template:
            kind = "template"
            target_value = m_template.group("value")
            continue
        m_component = _COMPONENT_KEY_RE.match(body)
        if m_component:
            kind = "component"
            target_value = m_component.group("value")
            continue
        m_ref = _REF_KEY_RE.match(body)
        if m_ref:
            ref_value = m_ref.group("value")
            continue
        m_file = _FILE_KEY_RE.match(body)
        if m_file:
            file_value = m_file.group("value")
            continue
    if kind is None:
        return None
    # Compose a stable target identifier for project includes:
    # `project:file[@ref]`.
    if kind == "project":
        composed = target_value
        if file_value:
            composed = f"{composed}:{file_value}"
        if ref_value:
            composed = f"{composed}@{ref_value}"
        target_value = composed
    return GitLabIncludeRef(
        kind=kind,
        target=target_value,
        ref=ref_value,
        filepath=filepath,
        line=start_line,
    )


# ---------------------------------------------------------------------------
# Per-file summarisation
# ---------------------------------------------------------------------------


def _summarize_gitlab_file(filepath: str, content: str) -> GitLabWorkflowSummary:
    """Run every extractor against a single GitLab CI file and return
    the assembled :class:`GitLabWorkflowSummary`."""
    lines = content.splitlines()
    raw_sources = _extract_pipeline_sources(content)
    triggers = _classify_gitlab_triggers(raw_sources, content)
    id_tokens = _detect_id_tokens(content)
    protected = _detect_protected_branch_only(content)
    bot_gate = _detect_bot_gate(content)
    workflow_content = _top_level_block(lines, "workflow")
    default_content = _top_level_block(lines, "default")
    workflow_triggers = _classify_gitlab_triggers(
        _extract_pipeline_sources(workflow_content), workflow_content
    )
    workflow_protected = _detect_protected_branch_only(workflow_content)
    workflow_bot_gate = _detect_bot_gate(workflow_content)
    default_id_tokens = _detect_id_tokens(default_content)
    job_defs = _extract_job_definitions(
        lines,
        workflow_triggers=workflow_triggers,
        workflow_protected=workflow_protected,
        workflow_bot_gate=workflow_bot_gate,
        default_id_tokens=default_id_tokens,
    )
    cross_project = _extract_cross_project_includes(filepath, content)
    unpinned = tuple(
        r for r in cross_project if r.kind == "project" and not _SHA40_RE.match(r.ref or "")
    )
    return GitLabWorkflowSummary(
        filepath=filepath,
        content=content,
        lines=lines,
        triggers=triggers,
        raw_source_names=frozenset(raw_sources),
        id_tokens_declared=id_tokens,
        protected_branch_only=protected,
        bot_gate_pattern=bot_gate,
        job_definitions=tuple(job_defs),
        cross_project_includes=tuple(cross_project),
        unpinned_project_includes=unpinned,
    )


# ---------------------------------------------------------------------------
# Extractors — pipeline sources, triggers, id_tokens, protected, bot-gate
# ---------------------------------------------------------------------------

# Match a literal-equality `$CI_PIPELINE_SOURCE == 'value'` clause.
# Regex and inequality operators cannot prove that a source is reachable,
# so they must not become trigger evidence for an escalated chain.
_PIPELINE_SOURCE_COMPARE_RE = re.compile(
    r"\$CI_PIPELINE_SOURCE\s*==\s*['\"]([a-z_]+)['\"]",
)


def _extract_pipeline_sources(content: str) -> set[str]:
    """Return the set of literal $CI_PIPELINE_SOURCE values compared
    in ``rules: if:`` expressions throughout the file.

    Empty result means the file doesn't gate on pipeline source — the
    pipeline can fire from any source the project permits.
    """
    return {m.group(1) for m in _PIPELINE_SOURCE_COMPARE_RE.finditer(content)}


def _classify_gitlab_triggers(
    raw_sources: set[str],
    content: str,
) -> frozenset[TriggerFamily]:
    """Map a $CI_PIPELINE_SOURCE literal set to :class:`TriggerFamily`.

    When the file declares NO ``$CI_PIPELINE_SOURCE`` compares anywhere,
    we treat every family as potentially reachable — the absence of a
    gate means the pipeline runs on whatever fires it, which in a
    multi-developer project includes MR pipelines from forks.  This is
    the conservative worst-case the composer needs to avoid missing
    real exposures behind an "I'll add rules later" empty-gates
    configuration.

    Heuristic refinement: if the content does NOT contain the literal
    string ``$CI_PIPELINE_SOURCE`` at all, the file is genuinely
    ungated and gets ALL families.  If the literal string IS present
    but no compare extracted (e.g. the author put it in a comment or a
    different operator we don't parse), we still credit the families
    that the recognised compares cover.
    """
    out: set[TriggerFamily] = set()
    for src in raw_sources:
        if src in _GL_FORK_REACHABLE_SOURCES:
            out.add(TriggerFamily.FORK_REACHABLE)
        if src in _GL_PRIVILEGED_SOURCES:
            out.add(TriggerFamily.PRIVILEGED)
        if src in _GL_SCHEDULED_SOURCES:
            out.add(TriggerFamily.SCHEDULED)
    if not raw_sources and "$CI_PIPELINE_SOURCE" not in content:
        # Truly ungated — assume every family is reachable.
        return frozenset(
            {
                TriggerFamily.FORK_REACHABLE,
                TriggerFamily.PRIVILEGED,
                TriggerFamily.SCHEDULED,
            }
        )
    return frozenset(out)


_ID_TOKENS_RE = re.compile(r"(?m)^\s*id_tokens\s*:\s*$")


def _detect_id_tokens(content: str) -> bool:
    """Return True when ``id_tokens:`` appears as a YAML key anywhere
    in the file.  Block-form only (the standard shape per the GitLab
    docs); a hypothetical inline mapping is conservatively ignored
    here because the standard pattern is multi-line.
    """
    return bool(_ID_TOKENS_RE.search(content))


# Default-branch / protected-branch gate patterns.  These are the
# canonical compare shapes from the GitLab CI docs ("Run jobs only for
# the default branch") and the protected-ref family.
_PROTECTED_BRANCH_RE = re.compile(
    r"\$CI_COMMIT_BRANCH\s*==\s*\$CI_DEFAULT_BRANCH"
    r"|\$CI_DEFAULT_BRANCH\s*==\s*\$CI_COMMIT_BRANCH"
    r"|\$CI_COMMIT_REF_PROTECTED\s*==\s*['\"]true['\"]"
    r"|\$CI_COMMIT_TAG\b"
    r"|\$CI_COMMIT_REF_NAME\s*==\s*\$CI_DEFAULT_BRANCH",
)


def _detect_protected_branch_only(content: str) -> bool:
    """Return True when the file gates execution to default/protected
    branches via a ``rules: if:`` clause that compares against the
    canonical protected-ref CI variables.
    """
    return bool(_PROTECTED_BRANCH_RE.search(content))


def _detect_bot_gate(content: str) -> bool:
    """Return True when any ``rules: if:`` clause literal-equals
    ``$GITLAB_USER_LOGIN`` (or ``$GITLAB_USER_NAME``) against one of
    the known trusted-bot names in :data:`_TRUSTED_BOT_NAMES`.

    Reads compares in either direction
    (``$GITLAB_USER_LOGIN == 'renovate-bot'`` or
    ``'renovate-bot' == $GITLAB_USER_LOGIN``) since both are valid YAML.
    """
    pattern = re.compile(
        r"\$GITLAB_USER_(?:LOGIN|NAME)\s*==\s*['\"]([\w_-]+)['\"]"
        r"|['\"]([\w_-]+)['\"]\s*==\s*\$GITLAB_USER_(?:LOGIN|NAME)",
    )
    for m in pattern.finditer(content):
        name = m.group(1) or m.group(2)
        if name and name in _TRUSTED_BOT_NAMES:
            return True
    return False


# A top-level job key is any indent-0 mapping key that is NOT a
# GitLab reserved keyword.  See https://docs.gitlab.com/ci/yaml/
# for the keyword list; we keep the common subset.
_GITLAB_RESERVED_KEYS: frozenset[str] = frozenset(
    {
        "default",
        "include",
        "stages",
        "variables",
        "workflow",
        "image",
        "services",
        "before_script",
        "after_script",
        "cache",
        "interruptible",
        "retry",
        "timeout",
        "pages",  # actually a job, but its presence is benign here
    }
)


def _top_level_block(lines: list[str], name: str) -> str:
    """Return the source for a named top-level mapping block."""
    for i, line in enumerate(lines):
        if re.match(rf"^{re.escape(name)}\s*:\s*(?:#.*)?$", line):
            end = i + 1
            while end < len(lines):
                candidate = lines[end]
                stripped = candidate.lstrip()
                if (
                    stripped
                    and not stripped.startswith("#")
                    and not candidate.startswith((" ", "\t"))
                ):
                    break
                end += 1
            return "\n".join(lines[i:end])
    return ""


def _extract_job_definitions(
    lines: list[str],
    *,
    workflow_triggers: frozenset[TriggerFamily],
    workflow_protected: bool,
    workflow_bot_gate: bool,
    default_id_tokens: bool,
) -> list[GitLabJobSummary]:
    """Return one :class:`GitLabJobSummary` per top-level job key.

    Walks indent-0 mapping keys, skips reserved keywords + hidden jobs
    (names starting with ``.``), and probes the job's body for an
    ``id_tokens:`` declaration.
    """
    out: list[GitLabJobSummary] = []
    n = len(lines)
    i = 0
    while i < n:
        line = lines[i]
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        indent = len(line) - len(stripped)
        if indent != 0:
            i += 1
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*:\s*(?:#.*)?$", stripped)
        if not m:
            i += 1
            continue
        name = m.group(1)
        if name in _GITLAB_RESERVED_KEYS or name.startswith("."):
            i += 1
            continue
        j = i + 1
        while j < n:
            nxt = lines[j]
            nxt_stripped = nxt.lstrip()
            if not nxt_stripped or nxt_stripped.startswith("#"):
                j += 1
                continue
            nxt_indent = len(nxt) - len(nxt_stripped)
            if nxt_indent == 0:
                break
            j += 1
        job_content = "\n".join(lines[i:j])
        job_triggers = _classify_gitlab_triggers(
            _extract_pipeline_sources(job_content), job_content
        )
        out.append(
            GitLabJobSummary(
                name=name,
                id_tokens_declared=default_id_tokens or _detect_id_tokens(job_content),
                line=i + 1,
                end_line=j + 1,
                triggers=workflow_triggers & job_triggers,
                protected_branch_only=workflow_protected
                or _detect_protected_branch_only(job_content),
                bot_gate_pattern=workflow_bot_gate or _detect_bot_gate(job_content),
            )
        )
        i = j
    return out


# ---------------------------------------------------------------------------
# GitLabCorpusPattern — the cross-file pattern shape consumed by the engine
# ---------------------------------------------------------------------------


GitLabCorpusFindings = list[tuple[str, int, str]]


@dataclass
class GitLabCorpusPattern:
    """A cross-file GitLab CI pattern that consumes a
    :class:`GitLabWorkflowCorpus`.

    Use this shape when the rule's evidence requires reading the
    resolved include graph as a whole.  Per-file scanning silently
    yields nothing for these rules (``check`` returns ``[]``); the
    engine's GitLab corpus pass invokes :meth:`check_corpus`.

    The callback returns ``(filepath, line, snippet)`` triples — one
    per finding to emit.  The engine wraps each triple in a
    :class:`taintly.models.Finding` using the rule's metadata.
    """

    callback: Callable[[GitLabWorkflowCorpus], GitLabCorpusFindings]

    def check(
        self,
        content: str,  # noqa: ARG002 — required for PatternProtocol shape
        lines: list[str],  # noqa: ARG002
    ) -> list[tuple[int, str]]:
        # Per-file scan path is a no-op for corpus rules.
        return []

    def check_corpus(self, corpus: GitLabWorkflowCorpus) -> GitLabCorpusFindings:
        return self.callback(corpus)
