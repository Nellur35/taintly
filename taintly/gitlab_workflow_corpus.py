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
  * Pure-Python regex extraction — no PyYAML dep (zero-dep design).
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
    :attr line: 1-based line of the job's name key.
    """

    name: str
    id_tokens_declared: bool
    line: int


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
        if os.path.isfile(candidate):
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
    if len(content) > _MAX_SAFE_TEXT_LEN:
        # Truncate beyond the cap.  The extractors are line-driven and
        # bounded, but the byte-length cap is the shared invariant so
        # one pathological file can't blow up corpus build time.
        content = content[:_MAX_SAFE_TEXT_LEN]

    summary = _summarize_gitlab_file(norm, content)
    corpus.workflows[norm] = summary

    # Recurse into local include targets.  Targets are resolved
    # relative to the repo root per the GitLab docs ("file is searched
    # relative to the project root"), NOT relative to the including
    # file's directory.
    for target in _extract_local_include_paths(content):
        # The leading "/" in `include: local: /ci/foo.yml` is rooted
        # at the project root; lstrip it so os.path.join doesn't treat
        # it as an absolute path on POSIX.
        rel = target.lstrip("/")
        sub = os.path.join(corpus.repo_path, rel)
        if os.path.isfile(sub):
            _walk_includes(corpus, sub, depth=depth + 1)


# ---------------------------------------------------------------------------
# Include extraction — local vs cross-project
# ---------------------------------------------------------------------------

# A bare-string local include: `include: 'local-file.yml'` OR
# `include: ['a.yml', 'b.yml']` OR a list of strings at top level.
# Cross-project / remote / template / component all use the BLOCK form
# (a mapping under the include item) so they're not matched by these
# string regexes.
_INCLUDE_STRING_LINE_RE = re.compile(
    r"^\s*-?\s*include\s*:\s*(?P<rest>.+)$",
)

# A `local:` key inside a block include item.
_LOCAL_KEY_RE = re.compile(r"^\s*local\s*:\s*['\"]?(?P<value>[^\s'\"#]+)['\"]?\s*(?:#.*)?$")

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
    """Return a list of repo-relative file paths from ``include: local:``
    entries — both the inline-string shape and the block-mapping shape.

    Used by the include walker; the cross-project /
    remote / template / component refs are captured separately by
    :func:`_extract_cross_project_includes`.
    """
    out: list[str] = []
    lines = content.splitlines()
    # Find the top-level `include:` key (indent 0) and walk its
    # children.  Bare `include: ./file.yml` on one line is the inline-
    # string shape; block items follow under a list.
    in_include_block = False
    for line in lines:
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if indent == 0 and re.match(r"^include\s*:\s*(.*)$", line):
            m = re.match(r"^include\s*:\s*(?P<rest>.*)$", line)
            assert m is not None  # nosec B101
            rest = m.group("rest").strip()
            if rest and not rest.startswith("#"):
                # Inline string: `include: 'file.yml'` (uncommon).
                # Filter to local-looking strings — relative paths
                # without a URL scheme and not bare keywords.
                inline = rest.strip("'\"").strip()
                if inline and "://" not in inline and not inline.startswith("["):
                    out.append(inline)
                # `include: ['a.yml', 'b.yml']` — flow-list of strings.
                if inline.startswith("["):
                    inside = inline.strip("[]")
                    for tok in inside.split(","):
                        s = tok.strip().strip("'\"")
                        if s and "://" not in s:
                            out.append(s)
            in_include_block = True
            continue
        if in_include_block:
            if indent == 0:
                in_include_block = False
                continue
            # Look for `- local: ...` shorthand and `local: ...` inside
            # a block item.  Either way we extract the value.
            m_local = _LOCAL_KEY_RE.match(line) or re.match(
                r"^\s*-\s*local\s*:\s*['\"]?(?P<value>[^\s'\"#]+)['\"]?\s*(?:#.*)?$",
                line,
            )
            if m_local:
                out.append(m_local.group("value"))
                continue
            # Shorthand: a bare `- "path/to/file.yml"` list item directly
            # under `include:` is treated as a local include per the
            # GitLab docs.
            m_bare = re.match(
                r"^\s*-\s*['\"]?(?P<value>[^\s'\"#:]+\.ya?ml)['\"]?\s*(?:#.*)?$", line
            )
            if m_bare:
                val = m_bare.group("value")
                if "://" not in val:
                    out.append(val)
                continue
    return out


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
    job_defs = _extract_job_definitions(lines)
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

# Match a `$CI_PIPELINE_SOURCE == 'value'` (or `=~`) clause inside an
# `if:` expression.  GitLab YAML accepts single or double quotes; we
# capture the bare value.
_PIPELINE_SOURCE_COMPARE_RE = re.compile(
    r"\$CI_PIPELINE_SOURCE\s*(?:==|!=|=~)\s*['\"]([a-z_]+)['\"]",
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


def _extract_job_definitions(lines: list[str]) -> list[GitLabJobSummary]:
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
        # Scan job body for id_tokens at any deeper indent.
        body_has_id_tokens = False
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
            if re.match(r"^\s*id_tokens\s*:\s*$", nxt):
                body_has_id_tokens = True
            j += 1
        out.append(
            GitLabJobSummary(
                name=name,
                id_tokens_declared=body_has_id_tokens,
                line=i + 1,
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
