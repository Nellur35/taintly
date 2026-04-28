"""Cross-file workflow corpus — Phase B2.

The per-file rule pipeline (``ContextPattern`` / ``RegexPattern`` /
``BlockPattern`` / ``PathPattern``) cannot answer questions whose
evidence lives in two different workflow files: "this fork-reachable
workflow writes a cache; this privileged workflow reads from the
same prefix" needs both files in scope at once.

:class:`WorkflowCorpus` builds a one-time, per-scan index of every
``.github/workflows/*.yml`` file in a repo and exposes:

  * ``cache_keys`` — keys + restore-keys + their textual prefixes.
  * ``concurrency_groups`` — group strings with cancel-in-progress.
  * ``environments`` — environment names (case-normalized).
  * ``reusable_uses`` — local ``./.github/workflows/X.yml`` and
    cross-repo ``org/repo/.github/workflows/X.yml@ref`` references.
  * ``triggers`` — fork-reachable / privileged / scheduled / dispatch.
  * ``permissions`` — workflow-level and per-job blocks.

This file is the data-extraction layer only.  Cross-file *rules* live
in :mod:`taintly.rules.github` and consume the corpus via the new
:class:`CorpusPattern` shape (see :mod:`taintly.models`).

Design constraints:
  * Pure-Python regex extraction — no PyYAML dep (zero-dep design).
  * Idempotent: extractors return value objects, no side-effects.
  * Per-job indexing via ``_split_into_job_segments`` (the same
    helper :class:`ContextPattern` uses for ``scope="job"``) so the
    corpus and per-file rules agree on what a "job" is.
  * Cheap: each extractor is O(N) on file content and runs once per
    scan; the corpus-pattern callbacks then iterate over the indexes
    rather than re-parsing.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from .models import _split_into_job_segments

# ---------------------------------------------------------------------------
# Trigger family
# ---------------------------------------------------------------------------


class TriggerFamily(str, Enum):
    """Coarse classification of a workflow's ``on:`` block.

    A single workflow can carry multiple triggers; ``WorkflowSummary``
    stores a ``set[TriggerFamily]`` rather than a single enum so the
    classifier can answer "is this workflow reachable from a fork?"
    independent of "is it also reachable from a schedule?".

    The taxonomy is deliberately attacker-utility-flavoured:
      * FORK_REACHABLE — events external contributors can fire
        (``pull_request``, ``pull_request_target``, ``issue_comment``,
        ``issues``, ``discussion``, ``discussion_comment``,
        ``workflow_run`` from a fork-reachable parent).
      * PRIVILEGED — events that imply a maintainer push (``push``,
        ``release``, ``deployment``, ``deployment_status``,
        ``registry_package``, ``branch_protection_rule``).  These
        runs typically receive elevated GITHUB_TOKEN scopes by repo
        policy.
      * SCHEDULED — ``schedule`` (cron).
      * DISPATCH — ``workflow_dispatch`` / ``repository_dispatch``.
        Treat as maintainer-triggered for risk purposes; an attacker
        cannot fire these without prior compromise.
    """

    FORK_REACHABLE = "fork_reachable"
    PRIVILEGED = "privileged"
    SCHEDULED = "scheduled"
    DISPATCH = "dispatch"


# Event names per family — verified against the GitHub Actions docs
# (https://docs.github.com/en/actions/writing-workflows/choosing-when-
# workflows-run/events-that-trigger-workflows).  Maintained as
# frozensets so trigger classification is O(1) per event name.
_FORK_REACHABLE_EVENTS: frozenset[str] = frozenset(
    {
        "pull_request",
        "pull_request_target",
        "issue_comment",
        "issues",
        "discussion",
        "discussion_comment",
        "fork",
        "watch",
        # workflow_run is dual-natured — only fork-reachable when its
        # parent workflow is.  We classify it as fork-reachable here
        # and let consumers narrow with workflow_run-specific logic.
        "workflow_run",
    }
)

_PRIVILEGED_EVENTS: frozenset[str] = frozenset(
    {
        "push",
        "release",
        "deployment",
        "deployment_status",
        "registry_package",
        "branch_protection_rule",
        "create",
        "delete",
        "page_build",
        "status",
        "milestone",
        "label",
        "project",
        "project_card",
        "project_column",
    }
)

_SCHEDULED_EVENTS: frozenset[str] = frozenset({"schedule"})

_DISPATCH_EVENTS: frozenset[str] = frozenset({"workflow_dispatch", "repository_dispatch"})


# ---------------------------------------------------------------------------
# Per-feature value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CacheRef:
    """A single cache key reference extracted from ``actions/cache@*`` or
    ``actions/cache/restore@*`` / ``actions/cache/save@*`` step inputs.

    :attr key: The literal value of ``with: key:`` (template
        expressions like ``${{ ... }}`` retained — callers compute
        prefixes via :attr:`prefix`).
    :attr restore_keys: Values from the multi-line ``with: restore-keys:``
        block (each fallback key, in declaration order).
    :attr prefix: A textual prefix derived from ``key`` — everything up
        to but not including the first template ``${{`` or hash-marker
        token.  Useful for "did file A write a cache the privileged
        file might restore via prefix?" matching.
    :attr role: One of three values, distinguishing the action variant
        so cross-file rules can pick the correct sub-set:
          * ``"write"``  — ``actions/cache/save@*`` (write only)
          * ``"read"``   — ``actions/cache/restore@*`` (read only)
          * ``"both"``   — bare ``actions/cache@*`` (writes on success,
            reads via key/restore-keys on miss).
        The cache-poisoning cross-file rule uses
        ``role in ("write", "both")`` for write-side candidates and
        ``role in ("read", "both")`` for read-side candidates.
    :attr line: 1-based line number of the ``with: key:`` line for
        finding attribution.
    """

    key: str
    restore_keys: tuple[str, ...]
    prefix: str
    role: str
    line: int


@dataclass(frozen=True)
class ConcurrencyRef:
    """A ``concurrency:`` block reference.

    :attr group: The literal ``concurrency.group`` string.
    :attr cancel_in_progress: ``True`` when ``cancel-in-progress: true``
        (or any YAML-bool-true synonym) is set.  Used by the cross-
        workflow concurrency-cancel rule: a privileged workflow with
        ``cancel-in-progress: true`` whose group string also appears
        in a fork-reachable workflow is exposed to attacker-driven
        cancellation.
    :attr scope: ``"workflow"`` if the concurrency block sits at the
        top level, ``"job"`` if under a specific job.  Multiple
        concurrency refs can co-exist in one workflow.
    :attr line: 1-based line of the ``group:`` line.
    """

    group: str
    cancel_in_progress: bool
    scope: str
    line: int


@dataclass(frozen=True)
class EnvRef:
    """A deployment environment reference.

    :attr name: The literal value of ``environment:`` or
        ``environment.name:``.
    :attr name_normalized: ``name.casefold()`` for case-insensitive
        cross-file matching (``Production`` vs ``production`` is the
        canonical aliasing rule).
    :attr line: 1-based line number.
    """

    name: str
    name_normalized: str
    line: int


@dataclass(frozen=True)
class ReusableRef:
    """A reusable-workflow ``uses:`` reference.

    Two shapes:
      * Local: ``uses: ./.github/workflows/X.yml`` (no @ref required).
        :attr ref is empty string.
      * Cross-repo: ``uses: org/repo/.github/workflows/X.yml@ref``.
        :attr ref carries the @-suffix (tag, branch, or SHA).

    :attr secrets_inherit: ``True`` when the caller passes
        ``secrets: inherit`` at the calling-job level.  The
        reusable-fanout hub rule unions exposure across N callers
        carrying ``inherit``.
    :attr line: 1-based line of the ``uses:`` line.
    """

    target: str  # The full uses: value
    is_local: bool
    repo_path: str  # "" for local, "org/repo" for cross-repo
    workflow_path: str  # ".github/workflows/X.yml"
    ref: str  # "" for local, otherwise the @ref suffix
    secrets_inherit: bool
    line: int


@dataclass(frozen=True)
class PermissionBlock:
    """A ``permissions:`` block (workflow-level or job-level).

    :attr scope_what: ``str`` indicating ``"workflow"`` or job name.
    :attr is_write_all: ``True`` when ``permissions: write-all`` (the
        sledgehammer form).  Otherwise individual permission keys
        live in :attr:`grants`.
    :attr is_read_all: ``True`` when ``permissions: read-all``.
    :attr grants: Mapping from permission key → value
        (e.g. ``{"contents": "write", "id-token": "write"}``).  The
        empty form (``permissions: {}``) leaves this empty.
    :attr line: 1-based line of the ``permissions:`` key.

    When neither ``is_write_all``, ``is_read_all``, nor ``grants`` is
    set, the workflow has no explicit permissions block — the
    GITHUB_TOKEN inherits the repo-default (read-write or read,
    depending on the org policy).  The corpus does NOT synthesise the
    repo default; that's the consumer's responsibility.
    """

    scope_what: str
    is_write_all: bool
    is_read_all: bool
    grants: dict[str, str]
    line: int


@dataclass
class WorkflowSummary:
    """Per-file summary of one workflow in the corpus.

    Carries the indexed views plus the source content so cross-file
    rules can quote a snippet at finding-emit time without re-reading
    the file.
    """

    filepath: str
    content: str
    lines: list[str]
    triggers: frozenset[TriggerFamily] = field(default_factory=frozenset)
    raw_event_names: frozenset[str] = field(default_factory=frozenset)
    cache_keys: tuple[CacheRef, ...] = ()
    concurrency_groups: tuple[ConcurrencyRef, ...] = ()
    environments: tuple[EnvRef, ...] = ()
    reusable_uses: tuple[ReusableRef, ...] = ()
    workflow_permissions: PermissionBlock | None = None
    job_permissions: tuple[PermissionBlock, ...] = ()


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------


@dataclass
class WorkflowCorpus:
    """Collection of :class:`WorkflowSummary` objects keyed by filepath.

    Built once per scan from a repo path.  Cross-file rules iterate
    via :meth:`all` or :meth:`by_trigger` (e.g. "give me every
    fork-reachable workflow") and emit findings citing one or more
    files from the corpus.
    """

    repo_path: str
    workflows: dict[str, WorkflowSummary] = field(default_factory=dict)

    def all(self) -> list[WorkflowSummary]:
        return list(self.workflows.values())

    def by_trigger(self, family: TriggerFamily) -> list[WorkflowSummary]:
        """All workflows whose trigger set contains ``family``."""
        return [w for w in self.workflows.values() if family in w.triggers]

    def by_filepath(self, filepath: str) -> WorkflowSummary | None:
        return self.workflows.get(filepath)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


_WORKFLOW_GLOB_DIRS = (os.path.join(".github", "workflows"),)


def build_corpus(repo_path: str) -> WorkflowCorpus:
    """Walk ``repo_path/.github/workflows/`` and build a
    :class:`WorkflowCorpus`.

    Files that fail to read are skipped silently — the per-file scan
    will already have emitted an ENGINE-ERR finding for them.  Files
    above the standard 50_000-byte safety cap are still loaded into
    the corpus (the cap protects regex evaluation; the corpus
    extractors are line- and event-driven and bounded by file size).
    """
    corpus = WorkflowCorpus(repo_path=repo_path)
    wf_dir = os.path.join(repo_path, ".github", "workflows")
    if not os.path.isdir(wf_dir):
        return corpus

    for fname in sorted(os.listdir(wf_dir)):
        if not (fname.endswith(".yml") or fname.endswith(".yaml")):
            continue
        fpath = os.path.join(wf_dir, fname)
        try:
            with open(fpath, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            continue
        corpus.workflows[fpath] = _summarize_workflow(fpath, content)

    return corpus


def _summarize_workflow(filepath: str, content: str) -> WorkflowSummary:
    """Run every extractor against a single workflow file and return
    the assembled :class:`WorkflowSummary`."""
    lines = content.splitlines()
    raw_events = _extract_raw_events(content)
    triggers = _classify_triggers(raw_events)
    return WorkflowSummary(
        filepath=filepath,
        content=content,
        lines=lines,
        triggers=triggers,
        raw_event_names=frozenset(raw_events),
        cache_keys=tuple(_extract_cache_refs(lines)),
        concurrency_groups=tuple(_extract_concurrency_refs(lines)),
        environments=tuple(_extract_environment_refs(lines)),
        reusable_uses=tuple(_extract_reusable_refs(lines)),
        workflow_permissions=_extract_workflow_permissions(lines),
        job_permissions=tuple(_extract_job_permissions(lines)),
    )


# ---------------------------------------------------------------------------
# Extractors — one per indexed feature
# ---------------------------------------------------------------------------

# Implementations land in subsequent commits — splitting the WorkflowCorpus
# task into smaller pieces keeps each diff reviewable.  Stub returns
# preserve the WorkflowSummary contract so callers can already construct
# a corpus in tests.


def _extract_raw_events(content: str) -> set[str]:
    """Return the set of event names from the ``on:`` block.

    Three valid YAML shapes are supported:

      1. Single string:    ``on: push``
      2. List:             ``on: [push, pull_request]``
      3. Mapping block:    ``on:\\n  push:\\n    branches: [main]``

    Anchors via the ``^on:`` start-of-line token (case-sensitive per
    the GitHub Actions spec) so a ``run:`` step containing the literal
    text ``on:`` doesn't false-match.
    """
    events: set[str] = set()
    # `\s` matches newline; using `[ \t]*` keeps the colon/value match
    # on the same line as `on:` so the (.*) capture doesn't slurp the
    # first event from the next line.
    m = re.search(r"(?m)^on[ \t]*:[ \t]*(.*)$", content)
    if not m:
        return events
    rest = m.group(1).strip()

    # Shape 1 — single bare event name on the same line.
    if rest and not rest.startswith("[") and not rest.startswith("#"):
        events.add(rest.split()[0].rstrip(":").strip())
        return events

    # Shape 2 — flow-list on the same line.
    if rest.startswith("["):
        inside = rest.strip("[]")
        for token in inside.split(","):
            tok = token.strip().strip("'\"")
            if tok:
                events.add(tok)
        return events

    # Shape 3 — block mapping. Iterate following lines and accept only
    # keys at the FIRST observed indent level (the "event-name" tier).
    # Deeper indents are event options (``branches:``, ``types:``,
    # ``paths:``, list items under ``schedule:``); list-item dashes
    # are skipped outright.
    on_line_idx = content.count("\n", 0, m.start())
    lines = content.splitlines()
    event_indent: int | None = None
    for i in range(on_line_idx + 1, len(lines)):
        line = lines[i]
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        indent = len(line) - len(stripped)
        if indent == 0:
            break
        if event_indent is None:
            event_indent = indent
        if indent != event_indent:
            continue
        if ":" in stripped:
            key = stripped.split(":", 1)[0].strip()
            if key:
                events.add(key)
    return events


def _classify_triggers(events: set[str]) -> frozenset[TriggerFamily]:
    """Map raw event names to :class:`TriggerFamily` flags."""
    out: set[TriggerFamily] = set()
    for ev in events:
        if ev in _FORK_REACHABLE_EVENTS:
            out.add(TriggerFamily.FORK_REACHABLE)
        if ev in _PRIVILEGED_EVENTS:
            out.add(TriggerFamily.PRIVILEGED)
        if ev in _SCHEDULED_EVENTS:
            out.add(TriggerFamily.SCHEDULED)
        if ev in _DISPATCH_EVENTS:
            out.add(TriggerFamily.DISPATCH)
    return frozenset(out)


# Stub implementations — filled in by the next commits.  Returning empty
# tuples keeps the WorkflowSummary contract honest while the per-feature
# extractors are still pending.


_CACHE_USES_RE = re.compile(
    r"^(\s*)-\s*(?:[a-zA-Z0-9_-]+:\s*[^\n]+\s*\n\s*)?"  # optional leading `name:` line preceding the uses
    r"uses\s*:\s*['\"]?actions/cache(?P<sub>(?:/(?:save|restore))?)@[^\s'\"#]+",
    re.MULTILINE,
)

# Single-line uses: form (the dominant shape) — keep separate from the
# combined regex above for simpler line-driven walking.
_CACHE_USES_LINE_RE = re.compile(
    r"^(?P<indent>\s*)-?\s*uses\s*:\s*['\"]?actions/cache(?P<sub>(?:/(?:save|restore))?)@[^\s'\"#]+",
)


def _extract_cache_refs(lines: list[str]) -> list[CacheRef]:
    """Extract every ``actions/cache@*`` / ``actions/cache/save@*`` /
    ``actions/cache/restore@*`` step's cache key + restore-keys.

    Walks the file once.  When a step's ``uses:`` line matches the
    cache action, the function looks ahead for the step's ``with:``
    block (at strictly deeper indent than the step's first line) and
    reads ``key:`` plus the multi-line ``restore-keys:`` block inside.

    The ``role`` field is derived from the action subpath:
      * ``actions/cache`` (bare) → ``"write"`` (also reads on miss but
        the attacker-utility path is the write side)
      * ``actions/cache/save`` → ``"write"``
      * ``actions/cache/restore`` → ``"read"``

    The ``prefix`` field is the substring of ``key`` before the first
    ``${{`` template token — useful for cross-file prefix matching
    (the ``restore-keys: foo-`` shape that lets a privileged workflow
    pull the cache a fork-reachable workflow wrote).  When the key
    starts with a template, prefix is the empty string.
    """
    out: list[CacheRef] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = _CACHE_USES_LINE_RE.match(line)
        if not m:
            i += 1
            continue
        # Determine the role from the action subpath.
        sub = m.group("sub")
        if sub == "/restore":
            role = "read"
        elif sub == "/save":
            role = "write"
        else:
            # Bare ``actions/cache@*`` reads on miss AND writes on success.
            role = "both"
        step_indent = len(m.group("indent"))

        # Look ahead for the step's `with:` block.  The step ends when a
        # line at indent < step_indent appears (the dash of the next
        # step or a sibling key of the parent `steps:` block) — the
        # `<` (not `<=`) comparison is critical: `with:` is a sibling
        # of `uses:` at the SAME indent, so `<= step_indent` would
        # close the step before we reach `with:`.  A new step is
        # detected by the leading `- ` token at the parent indent.
        with_block_lines: list[tuple[int, str]] = []
        j = i + 1
        in_with = False
        with_indent: int | None = None
        while j < n:
            nxt = lines[j]
            stripped = nxt.lstrip()
            if not stripped or stripped.startswith("#"):
                j += 1
                continue
            indent = len(nxt) - len(stripped)
            if indent < step_indent:
                break
            # Same-indent next-step dash terminator — covers the
            # ``- uses:`` and ``- name:`` shapes equally.
            if indent == step_indent and stripped.startswith("- "):
                break
            # Detect the `with:` key inside this step.
            if not in_with and re.match(r"^\s*with\s*:\s*$", nxt):
                in_with = True
                with_indent = indent
                j += 1
                continue
            if in_with:
                if with_indent is not None and indent <= with_indent:
                    in_with = False
                else:
                    with_block_lines.append((j, nxt))
            j += 1

        # Parse `key:` and `restore-keys:` from the with: block.
        key = ""
        key_line = i + 1  # 1-based; default to the uses: line if we never see key:
        restore_keys: list[str] = []
        k = 0
        while k < len(with_block_lines):
            lineno_idx, body = with_block_lines[k]
            mkv = re.match(r"^\s*key\s*:\s*(.*)$", body)
            if mkv:
                key = mkv.group(1).strip().strip("'\"")
                key_line = lineno_idx + 1
                k += 1
                continue
            mrk = re.match(r"^\s*restore-keys\s*:\s*(.*)$", body)
            if mrk:
                inline = mrk.group(1).strip()
                if inline and inline not in {"|", ">", "|-", ">-"}:
                    restore_keys.append(inline.strip("'\""))
                    k += 1
                    continue
                # Block scalar — read indented continuation lines.
                base_indent = len(body) - len(body.lstrip())
                k += 1
                while k < len(with_block_lines):
                    _rk_idx, rk_body = with_block_lines[k]
                    rk_stripped = rk_body.lstrip()
                    if not rk_stripped:
                        k += 1
                        continue
                    rk_indent = len(rk_body) - len(rk_stripped)
                    if rk_indent <= base_indent:
                        break
                    restore_keys.append(rk_stripped.rstrip().strip("'\""))
                    k += 1
                continue
            k += 1

        prefix = _cache_key_prefix(key)
        out.append(
            CacheRef(
                key=key,
                restore_keys=tuple(restore_keys),
                prefix=prefix,
                role=role,
                line=key_line,
            )
        )
        i = max(j, i + 1)
    return out


def _cache_key_prefix(key: str) -> str:
    """Return the literal-prefix portion of a cache key string.

    The literal prefix is everything before the first ``${{`` template
    token.  Examples::

        Linux-build-${{ hashFiles('**/lockfile') }}  ->  "Linux-build-"
        ${{ runner.os }}-cache                        ->  ""
        v2-deps-${{ hashFiles('go.sum') }}-${{ runner.os }}  ->  "v2-deps-"
        plain-static-key                              ->  "plain-static-key"
    """
    idx = key.find("${{")
    return key if idx < 0 else key[:idx]


_CONCURRENCY_KEY_RE = re.compile(r"^(?P<indent>\s*)concurrency\s*:\s*(?P<rest>.*)$")


def _extract_concurrency_refs(lines: list[str]) -> list[ConcurrencyRef]:
    """Extract every ``concurrency:`` block (workflow-level and per-job).

    Two YAML shapes:

      1. Inline string:        ``concurrency: my-group``
      2. Block mapping:        ``concurrency:\\n  group: my-group\\n
                                  cancel-in-progress: true``

    The shorthand string form has no ``cancel-in-progress`` field —
    GitHub Actions defaults to ``false`` in that case.  The block
    mapping form must read both ``group:`` and ``cancel-in-progress:``;
    boolean parsing accepts the YAML 1.1 family (``true / yes / on /
    1 / 'true'`` and the negated counterparts).

    Scope (``"workflow"`` vs ``"job"``) is derived from the indent of
    the ``concurrency:`` key:

      * Indent 0           → workflow-level
      * Indent > 0         → job-level (the canonical 4-space form
        sits under a job at indent 4; we use a lenient ``> 0`` test
        so non-canonical indents still classify correctly)
    """
    out: list[ConcurrencyRef] = []
    n = len(lines)
    i = 0
    while i < n:
        line = lines[i]
        m = _CONCURRENCY_KEY_RE.match(line)
        if not m:
            i += 1
            continue
        block_indent = len(m.group("indent"))
        scope = "workflow" if block_indent == 0 else "job"
        rest = m.group("rest").strip()

        # Shorthand: `concurrency: my-group` on the same line.
        if rest and not rest.startswith("#"):
            group_str = rest.strip("'\"")
            out.append(
                ConcurrencyRef(
                    group=group_str,
                    cancel_in_progress=False,
                    scope=scope,
                    line=i + 1,
                )
            )
            i += 1
            continue

        # Block mapping: scan the immediately following lines at deeper
        # indent, stop at the first sibling/parent line.  Capture
        # group: and cancel-in-progress: scalars.
        group_str = ""
        cancel_in_progress = False
        group_line = i + 1
        j = i + 1
        while j < n:
            nxt = lines[j]
            stripped = nxt.lstrip()
            if not stripped or stripped.startswith("#"):
                j += 1
                continue
            indent = len(nxt) - len(stripped)
            if indent <= block_indent:
                break
            mg = re.match(r"^\s*group\s*:\s*(.*)$", nxt)
            if mg:
                group_str = mg.group(1).strip().strip("'\"")
                group_line = j + 1
                j += 1
                continue
            mc = re.match(r"^\s*cancel-in-progress\s*:\s*(.*)$", nxt)
            if mc:
                cancel_in_progress = _parse_yaml_bool(mc.group(1).strip())
                j += 1
                continue
            j += 1

        out.append(
            ConcurrencyRef(
                group=group_str,
                cancel_in_progress=cancel_in_progress,
                scope=scope,
                line=group_line,
            )
        )
        i = j
    return out


def _parse_yaml_bool(value: str) -> bool:
    """Return True when ``value`` is one of the YAML 1.1 truthy forms.

    GitHub Actions accepts the YAML 1.1 boolean spelling family —
    ``true / yes / on / 1`` (case-insensitive) and their quoted
    variants.  Anything else returns False, which also covers the
    common typo of writing ``"True"`` (capital T) thinking it's
    Python — that IS a valid YAML truthy via case-insensitive match,
    so it's covered too.
    """
    v = value.strip().strip("'\"").lower()
    return v in {"true", "yes", "on", "1"}


_ENV_INLINE_RE = re.compile(r"^\s*environment\s*:\s*(?P<rest>.*)$")
_ENV_NAME_RE = re.compile(r"^\s*name\s*:\s*(?P<rest>.*)$")


def _extract_environment_refs(lines: list[str]) -> list[EnvRef]:
    """Extract every job's deployment environment reference.

    Two YAML shapes:

      1. Inline string:    ``environment: production``
      2. Block mapping:    ``environment:\\n  name: production\\n
                              url: https://prod.example.com``

    The case-normalized ``name_normalized`` field is the join key for
    the environment-aliasing rule: ``Production`` and ``production``
    are the SAME deployment environment to GitHub Actions but a fresh
    review eye misreads them as distinct.

    Returns one :class:`EnvRef` per environment usage; a single
    workflow with three jobs each pointing at ``production`` produces
    three refs (callers wanting unique-name views can dedupe
    on ``name_normalized``).
    """
    out: list[EnvRef] = []
    n = len(lines)
    for i, line in enumerate(lines):
        m = _ENV_INLINE_RE.match(line)
        if not m:
            continue
        # Filter false-matches: a top-level `environment:` key under
        # the workflow root would normally be illegal in GitHub Actions
        # but a similarly-named user key in `inputs:` could shape-match.
        # We require the line sit at indent >= 2 (a job-or-deeper
        # context) to skip these.
        indent = len(line) - len(line.lstrip())
        if indent < 2:
            continue
        rest = m.group("rest").strip()

        # Shorthand: `environment: production` on the same line.
        if rest and not rest.startswith("#") and not rest.startswith("{"):
            name = rest.strip("'\"").rstrip(":")
            if name:
                out.append(
                    EnvRef(
                        name=name,
                        name_normalized=name.casefold(),
                        line=i + 1,
                    )
                )
            continue

        # Block mapping: scan deeper-indented lines for `name:`.
        block_indent = indent
        for j in range(i + 1, n):
            nxt = lines[j]
            stripped = nxt.lstrip()
            if not stripped or stripped.startswith("#"):
                continue
            sub_indent = len(nxt) - len(stripped)
            if sub_indent <= block_indent:
                break
            mn = _ENV_NAME_RE.match(nxt)
            if mn:
                name = mn.group("rest").strip().strip("'\"")
                if name:
                    out.append(
                        EnvRef(
                            name=name,
                            name_normalized=name.casefold(),
                            line=j + 1,
                        )
                    )
                break  # one name per environment block
    return out


# A reusable-workflow ``uses:`` line at job level (NOT step level).
# Two shapes per the GitHub Actions spec:
#   * Local:      uses: ./.github/workflows/foo.yml          (no @ref)
#   * Cross-repo: uses: org/repo/.github/workflows/foo.yml@<ref>
# Step-level ``uses:`` (action references like ``uses: actions/checkout@v4``)
# is the dominant shape and MUST NOT match here — only ``.yml`` /
# ``.yaml`` paths are reusable workflows.
_REUSABLE_USES_RE = re.compile(
    r"^(?P<indent>\s*)(?:-\s*)?uses\s*:\s*"
    r"(?P<value>['\"]?"
    r"(?:\./[^\s'\"#]+\.ya?ml"  # local
    r"|[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+/[^\s'\"#]+\.ya?ml@[^\s'\"#]+)"  # cross-repo
    r"['\"]?)\s*(?:#.*)?$"
)


def _extract_reusable_refs(lines: list[str]) -> list[ReusableRef]:
    """Extract reusable-workflow ``uses:`` references at job level.

    Distinguishes two shapes by inspecting the captured value:

      * Starts with ``./`` → local reference.  ``repo_path`` is empty,
        ``ref`` is empty (local refs always resolve to the calling
        commit).
      * Otherwise → cross-repo: ``org/repo/.github/workflows/X.yml@ref``.
        Splits on the LAST ``@`` to separate ``ref``; everything
        before the first ``/.github/workflows/`` is the ``repo_path``;
        what's between is the workflow path within the called repo.

    Step-level ``uses:`` to actions (``actions/checkout@v4``,
    ``my-org/my-action@sha``) is filtered out by the regex requiring
    a ``.yml`` / ``.yaml`` suffix.

    The ``secrets_inherit`` field is computed by looking at the
    immediately following lines for a ``secrets: inherit`` key
    inside the same job's ``uses:`` block.
    """
    out: list[ReusableRef] = []
    n = len(lines)
    for i, line in enumerate(lines):
        m = _REUSABLE_USES_RE.match(line)
        if not m:
            continue
        # Skip lines that are inside a `steps:` block — only job-level
        # `uses:` calls a reusable workflow.  Heuristic: walk backwards
        # until we hit either ``steps:`` (skip this line) or the parent
        # job key (accept).
        if _is_under_steps_block(lines, i):
            continue
        target = m.group("value").strip("'\"")
        is_local = target.startswith("./")
        repo_path = ""
        workflow_path = ""
        ref = ""

        if is_local:
            # ``./.github/workflows/foo.yml`` — strip the literal
            # ``./`` prefix.  ``str.lstrip("./")`` would chew through
            # the leading ``.`` of ``.github`` because lstrip
            # interprets its argument as a character set, not a
            # prefix.  removeprefix is the right primitive.
            workflow_path = target.removeprefix("./")
        else:
            # Cross-repo: split on the LAST ``@`` so SHAs containing
            # ``@`` (they don't, but tags can carry ``@`` if author
            # gets weird) won't break parsing.
            ref_split = target.rsplit("@", 1)
            if len(ref_split) == 2:
                ref = ref_split[1]
                full_path = ref_split[0]
            else:
                full_path = target
            # ``org/repo/.github/workflows/foo.yml`` — split on the
            # known canonical path segment.
            marker = "/.github/workflows/"
            idx = full_path.find(marker)
            if idx > 0:
                repo_path = full_path[:idx]
                workflow_path = full_path[idx + 1 :]  # drop the leading "/"

        # Look ahead for ``secrets: inherit``.  In a reusable-workflow
        # call shape, ``uses:`` and ``secrets:`` are sibling keys
        # under the same job — both at the same indent.  We look for
        # any line at exactly ``uses_indent`` indent that is not the
        # start of a new job (a key at the parent indent ends the
        # current job's scope).  The break condition is
        # ``indent < uses_indent``, so siblings are scanned but
        # parent-level keys terminate the search.
        secrets_inherit = False
        uses_indent = len(m.group("indent"))
        for j in range(i + 1, n):
            nxt = lines[j]
            stripped = nxt.lstrip()
            if not stripped or stripped.startswith("#"):
                continue
            sub_indent = len(nxt) - len(stripped)
            if sub_indent < uses_indent:
                break
            if sub_indent == uses_indent and re.match(r"^\s*secrets\s*:\s*inherit\s*$", nxt):
                secrets_inherit = True
                break

        out.append(
            ReusableRef(
                target=target,
                is_local=is_local,
                repo_path=repo_path,
                workflow_path=workflow_path,
                ref=ref,
                secrets_inherit=secrets_inherit,
                line=i + 1,
            )
        )
    return out


def _is_under_steps_block(lines: list[str], i: int) -> bool:
    """Return True when line ``i`` lives inside a ``steps:`` array.

    Walks backwards from ``i`` looking at lines whose indent is
    strictly less than line ``i``'s indent.  The first such line
    determines the parent context: a ``steps:`` parent means we're
    in a step-level ``uses:`` (action call); any other parent means
    we're at job level (reusable-workflow call).
    """
    line_indent = len(lines[i]) - len(lines[i].lstrip())
    for j in range(i - 1, -1, -1):
        l = lines[j]  # noqa: E741 — `l` is the local for "line j", not the math constant
        stripped = l.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(l) - len(stripped)
        if indent < line_indent:
            return stripped.startswith("steps:")
    return False


_PERMISSIONS_KEY_RE = re.compile(r"^(?P<indent>\s*)permissions\s*:\s*(?P<rest>.*)$")
_GRANT_LINE_RE = re.compile(
    r"^\s*(?P<key>[a-zA-Z0-9_-]+)\s*:\s*(?P<value>none|read|write)\s*(?:#.*)?$"
)


def _extract_workflow_permissions(lines: list[str]) -> PermissionBlock | None:
    """Return the workflow-level ``permissions:`` block, or ``None`` if
    the workflow has no top-level permissions key.

    Top-level means indent 0; any deeper occurrence is a job-level
    permission and is handled by :func:`_extract_job_permissions`.

    Three valid YAML shapes:
      1. ``permissions: write-all`` (the ``permissions: read-all`` /
         ``permissions: {}`` shorthands also)
      2. ``permissions:\\n  contents: write\\n  id-token: write``
      3. ``permissions: {}`` — empty mapping

    On shape (1) ``write-all`` / ``read-all`` set the corresponding
    flag and leave grants empty; on shape (3) all flags are False
    and grants are empty (intentional: an empty mapping means "deny
    everything by default" per GitHub Actions semantics).
    """
    for i, line in enumerate(lines):
        m = _PERMISSIONS_KEY_RE.match(line)
        if not m or len(m.group("indent")) != 0:
            continue
        return _parse_permission_block(lines, i, scope_what="workflow")
    return None


def _extract_job_permissions(lines: list[str]) -> list[PermissionBlock]:
    """Return one :class:`PermissionBlock` per job-level
    ``permissions:`` block.

    Job-level means indent > 0 AND the immediately enclosing key chain
    is ``jobs.<name>.permissions``.  We approximate that by tracking
    the most recent job key (an entry under ``jobs:`` whose own indent
    is the deepest first-level under ``jobs:``) and crediting any
    ``permissions:`` we see at one indent level deeper.
    """
    out: list[PermissionBlock] = []
    in_jobs_block = False
    job_indent: int | None = None
    current_job: str | None = None
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if re.match(r"^jobs\s*:\s*(?:#.*)?$", line):
            in_jobs_block = True
            continue
        if in_jobs_block:
            if indent == 0:
                in_jobs_block = False
                continue
            # Auto-detect job indent from the first non-comment line
            # under ``jobs:``.
            if job_indent is None:
                job_indent = indent
            if indent == job_indent and ":" in stripped:
                current_job = stripped.split(":", 1)[0].strip()
                continue
            if (
                current_job
                and re.match(r"^\s*permissions\s*:", line)
                and indent == (job_indent + 2)
            ):
                out.append(_parse_permission_block(lines, i, scope_what=current_job))
    return out


def _parse_permission_block(lines: list[str], i: int, scope_what: str) -> PermissionBlock:
    """Parse a single ``permissions:`` block starting at line ``i``.

    Handles the three shapes documented in
    :func:`_extract_workflow_permissions`.  Caller responsibility:
    ensure the block belongs to the requested scope.
    """
    line = lines[i]
    m = _PERMISSIONS_KEY_RE.match(line)
    assert m, "caller must pass a line that starts with permissions:"  # nosec B101
    block_indent = len(m.group("indent"))
    rest = m.group("rest").strip()

    is_write_all = False
    is_read_all = False
    grants: dict[str, str] = {}

    # Inline shorthand on the same line.
    if rest:
        if rest in {"{}"}:
            return PermissionBlock(
                scope_what=scope_what,
                is_write_all=False,
                is_read_all=False,
                grants={},
                line=i + 1,
            )
        rest_clean = rest.split("#", 1)[0].strip().strip("'\"").lower()
        if rest_clean == "write-all":
            is_write_all = True
        elif rest_clean == "read-all":
            is_read_all = True
        return PermissionBlock(
            scope_what=scope_what,
            is_write_all=is_write_all,
            is_read_all=is_read_all,
            grants=grants,
            line=i + 1,
        )

    # Block mapping: read indented child lines until the indent comes
    # back to ``block_indent`` or shallower.
    n = len(lines)
    for j in range(i + 1, n):
        nxt = lines[j]
        stripped = nxt.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(nxt) - len(stripped)
        if indent <= block_indent:
            break
        gm = _GRANT_LINE_RE.match(nxt)
        if gm:
            grants[gm.group("key")] = gm.group("value")
    return PermissionBlock(
        scope_what=scope_what,
        is_write_all=False,
        is_read_all=False,
        grants=grants,
        line=i + 1,
    )


# ---------------------------------------------------------------------------
# Helpers shared by extractors
# ---------------------------------------------------------------------------


def _job_segments(lines: list[str]) -> list[tuple[int, list[str]]]:
    """Adapter over :func:`taintly.models._split_into_job_segments`.

    Re-exposed at module level so the extractors don't carry their own
    job-boundary heuristic — the corpus and per-file rules MUST agree
    on what a job is, otherwise cross-file findings will cite line
    ranges that disagree with single-file findings on the same file.
    """
    return _split_into_job_segments(lines)


# ---------------------------------------------------------------------------
# CorpusPattern — the cross-file pattern shape consumed by the engine
# ---------------------------------------------------------------------------


# Cross-file rule callbacks return a list of (filepath, line, snippet)
# triples — same as the per-file PatternProtocol but with the file
# attribution carried explicitly because cross-file findings can cite
# any workflow in the corpus.
CorpusFindings = list[tuple[str, int, str]]


@dataclass
class CorpusPattern:
    """A cross-file pattern that consumes a :class:`WorkflowCorpus`.

    Use this shape when the rule's evidence lives in MORE THAN ONE
    workflow file: "fork-reachable workflow A writes a cache prefix
    that privileged workflow B restores".

    The callback receives the whole corpus and returns a list of
    ``(filepath, line, snippet)`` triples — one per finding to emit.
    The engine wraps each triple in a :class:`taintly.models.Finding`
    using the rule's metadata (id, title, severity, …).

    To keep the existing :class:`PatternProtocol` contract intact,
    :meth:`check` is stubbed to return ``[]``: per-file scanning
    silently yields nothing for corpus rules, and a separate corpus
    pass in :func:`taintly.engine.scan_repo` invokes
    :meth:`check_corpus`.  The two passes never interfere.
    """

    callback: Callable[[WorkflowCorpus], CorpusFindings]

    # CONTRACT: per-file ``check`` returns ``[]`` — corpus rules emit
    # via ``check_corpus`` instead.  ``check_corpus`` returns
    # (filepath, line_num, snippet) where line_num cites the line in
    # ``filepath`` that anchors the cross-file finding; rules MUST
    # set this explicitly because the engine cannot derive it.
    def check(
        self,
        content: str,  # noqa: ARG002 — required for PatternProtocol shape
        lines: list[str],  # noqa: ARG002
    ) -> list[tuple[int, str]]:
        # Per-file scan path is a no-op for corpus rules.
        return []

    def check_corpus(self, corpus: WorkflowCorpus) -> CorpusFindings:
        return self.callback(corpus)
