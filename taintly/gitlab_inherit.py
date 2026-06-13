"""GitLab CI inheritance + reference resolution for cross-file taint.

``taintly.gitlab_taint`` analyses ONE ``.gitlab-ci.yml`` at a time and
its docstring punts the three constructs that move a value across a
job / file boundary:

* ``extends:`` — a job deep-merges one or more parent jobs' keys
  (``variables:``, ``script:``, ...).  A tainted ``variables:`` entry
  declared on the parent is invisible to a single-file pass that reads
  only the child, and a parent ``script:`` that references the child's
  variable is invisible to a pass that reads only the parent.
* ``!reference [job, key]`` — a YAML tag that splices another job's
  ``key`` block in verbatim.  The spliced body can be a tainted
  ``variables:`` value or a ``script:`` line referencing a laundered
  variable.
* ``include: local:`` — pulls another repo file's jobs into the same
  pipeline namespace, so an ``extends:`` / ``!reference`` target can
  live in a *different file* entirely (the common GitLab Component /
  shared-template shape).

This module RESOLVES those three so the taint engine sees the
EFFECTIVE job: the deep-merged set of ``variables:`` / ``script:`` /
``image:`` / ``services:`` / ``tags:`` leaves a job actually runs
with, each leaf tagged with the *source file + line* it came from so a
flow can be reported as cross-file when its source and sink live in
different files (or the value was laundered across an inheritance
boundary).

It is the GitLab parallel of :mod:`taintly.cross_workflow_facts` (the
GitHub caller→reusable-workflow cross-file taint).  Cross-*project* /
remote / template / component includes are out of scope — their bodies
are not on disk (mirrors the GH "cross-repo reusable workflow content
is not in the corpus" boundary).  The cross-component-INPUT shape is
already handled by TAINT-GL-004.

Design constraints (shared with the rest of the engine):
  * Zero-dep: the structural parser (``taintly.parsers.structural``)
    is the only YAML reader; no PyYAML.
  * Bounded: include resolution reuses ``GitLabWorkflowCorpus``'s
    depth/file caps; ``extends:`` / ``!reference`` resolution carries
    a visited-set so inheritance cycles terminate.
  * Conservative: only a *standalone* ``$OTHER`` reference launders a
    variable (same rule as the single-file analyzer), and a leaf is
    only credited to a job once (first writer in merge order wins,
    matching GitLab's "more specific overrides less specific").
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from .gitlab_taint import (
    _TAINTED_REF_RE,
    TaintHop,
    _extract_var_ref,
    _references_var,
)
from .parsers.structural import EventKind, walk_workflow

# Reserved top-level keys that are NOT jobs (mirror of the set in
# ``gitlab_taint`` / ``gitlab_workflow_corpus``; kept local to avoid a
# cross-module import that would couple the resolver to the taint
# engine's private constants).
_RESERVED_TOP_KEYS = frozenset(
    [
        "stages",
        "variables",
        "include",
        "cache",
        "default",
        "workflow",
        "image",
        "services",
        "before_script",
        "after_script",
        "types",
        "pages",
        "spec",
    ]
)

# Keys whose value the runner expands as a shell / image / tag string —
# the keys the taint engine treats as a sink or a source.  We resolve
# inheritance for exactly these so the merged job carries them.
_SCRIPT_KEYS = ("script", "before_script", "after_script")

# A ``!reference [job, key]`` (or deeper ``[job, key, subkey]``) tag.
# GitLab allows the job to be a hidden job (leading dot) and the keys
# to be quoted or bare.  We capture the job and the FIRST key (the
# block we splice); deeper indexing is rare and conservatively treated
# as "reference the whole key block".
_REFERENCE_TAG_RE = re.compile(
    r"^!reference\s*\[\s*(?P<job>[^,\]]+?)\s*,\s*(?P<key>[^,\]]+?)\s*(?:,[^\]]*)?\]\s*$"
)

# Bounded inheritance depth — ``extends:`` chains are short in practice;
# a generous cap stops a pathological cycle without truncating real
# configs.  (Cycle detection via the visited set is the real guard; the
# depth cap is belt-and-suspenders.)
_MAX_EXTENDS_DEPTH = 16

# A structural path tuple relative to a job — a heterogeneous mix of
# str keys and int list indices (e.g. ``("script", 3)``), so the
# element type is ``object``.
RelPath = tuple[object, ...]


@dataclass(frozen=True)
class ResolvedLeaf:
    """One leaf of a job's *effective* definition after inheritance.

    ``path`` is the structural path RELATIVE to the job (e.g.
    ``("variables", "FOO")`` or ``("script", 3)``).  ``file`` / ``line``
    record where the leaf literally came from — which may be a parent
    job in a *different file* than the job that inherits it.  ``via`` is
    the resolution edge that pulled the leaf in:

      * ``"own"`` — declared directly on the job.
      * ``"extends"`` — inherited from an ``extends:`` parent.
      * ``"reference"`` — spliced via ``!reference [job, key]``.
    """

    path: RelPath
    value: str
    file: str
    line: int
    via: str


@dataclass
class _RawJob:
    """A job's leaves, possibly accumulated across files.

    A job name can be defined in more than one file (GitLab merges
    same-named jobs pulled in via ``include:``), so provenance is
    tracked PER LEAF — ``leaves`` maps a relative path to
    ``(value, line, file)`` — not on the job as a whole.  ``def_file``
    is just the first file that introduced the job (a stable home for
    the runnable-job's ``home_file``); the per-leaf ``file`` is what a
    cross-file flow reports.
    """

    name: str
    def_file: str
    # Relative path tuple -> (value, line, file).  First writer in a
    # single file wins (duplicate keys are a YAML error anyway); a later
    # FILE overrides (GitLab include-merge "later wins").
    leaves: dict[RelPath, tuple[str, int, str]] = field(default_factory=dict)
    extends: list[str] = field(default_factory=list)


@dataclass
class ResolvedJob:
    """A job's effective definition, with provenance per leaf."""

    name: str
    # The file the job's own (non-inherited) body lives in.  Used to
    # decide a leaf is "cross-file" (leaf.file != home_file) for the
    # rule's boundary filter.
    home_file: str
    leaves: list[ResolvedLeaf]


@dataclass
class _ResolvedGraph:
    """The resolved cross-file job graph for one pipeline."""

    jobs: dict[str, ResolvedJob]
    # filepath -> raw text, so a consumer can fall back to the original
    # source line for snippet display.
    file_text: dict[str, list[str]]


# ---------------------------------------------------------------------------
# Per-file raw extraction
# ---------------------------------------------------------------------------


def _extract_raw_jobs(filepath: str, content: str) -> dict[str, _RawJob]:
    """Walk ONE file and return every top-level key (job OR hidden
    template job) with its leaves + ``extends:`` parents.

    Hidden jobs (leading ``.``) ARE kept — they are the canonical
    ``extends:`` / ``!reference`` targets.  Reserved top-level keys are
    skipped (they are not jobs and never an inheritance target), EXCEPT
    that the top-level ``variables:`` block is captured under the
    synthetic name ``""`` so the cascade is modelled by the caller.
    """
    raw: dict[str, _RawJob] = {}
    for ev in walk_workflow(filepath, content=content):
        if ev.kind is EventKind.CUTOFF:
            break
        if ev.kind is not EventKind.LEAF_SCALAR:
            continue
        path = ev.path
        if not path or not isinstance(path[0], str):
            continue
        head = path[0]
        rest = path[1:]
        # Top-level variables: cascade — synthetic job name "".
        if head == "variables" and len(rest) == 1 and isinstance(rest[0], str):
            job = raw.setdefault("", _RawJob("", filepath))
            job.leaves.setdefault(("variables", rest[0]), (ev.value or "", ev.line, filepath))
            continue
        if head in _RESERVED_TOP_KEYS:
            continue
        job = raw.setdefault(head, _RawJob(head, filepath))
        if not rest:
            continue
        # extends: parent (scalar or list item).
        if rest[0] == "extends" and (
            len(rest) == 1 or (len(rest) == 2 and isinstance(rest[1], int))
        ):
            parent = (ev.value or "").strip()
            if parent:
                job.extends.append(parent)
            continue
        # Record the leaf, plus its block-scalar body lines if any (so a
        # multi-line script: | body contributes each physical line).
        if ev.block_lines and rest and rest[0] in _SCRIPT_KEYS:
            for src_line, body in ev.block_lines:
                # Synthesize a stable per-physical-line index so two
                # block lines don't collide on the same path key.
                job.leaves.setdefault(
                    (*rest, "__line__", src_line), (body.strip(), src_line, filepath)
                )
        else:
            job.leaves.setdefault(rest, (ev.value or "", ev.line, filepath))
    return raw


# ---------------------------------------------------------------------------
# Inheritance + reference resolution
# ---------------------------------------------------------------------------


def _resolve_references_in_value(
    value: str,
    raw_by_name: dict[str, _RawJob],
) -> list[tuple[RelPath, str, str, int]]:
    """If ``value`` is a ``!reference [job, key]`` tag, return the
    referenced job's leaves under ``key`` as ``(rel_path, value, file,
    line)`` tuples (the spliced block).  Otherwise return ``[]``.

    Only one level of indirection is resolved here; nested references
    inside the spliced block are resolved by the caller's outer merge
    loop because the spliced leaves re-enter ``_merge_job``.
    """
    m = _REFERENCE_TAG_RE.match(value.strip())
    if m is None:
        return []
    target_job = m.group("job").strip()
    target_key = m.group("key").strip()
    src = raw_by_name.get(target_job)
    if src is None:
        return []
    out: list[tuple[RelPath, str, str, int]] = []
    for rel, (val, line, leaf_file) in src.leaves.items():
        if rel and rel[0] == target_key:
            out.append((rel, val, leaf_file, line))
    return out


def _merge_job(
    name: str,
    raw_by_name: dict[str, _RawJob],
    *,
    visited: frozenset[str] = frozenset(),
    depth: int = 0,
) -> dict[RelPath, ResolvedLeaf]:
    """Deep-merge a job's effective leaves: ``extends:`` parents first
    (least specific), then the job's own body (most specific overrides),
    expanding ``!reference`` tags inline.

    Returns ``{rel_path: ResolvedLeaf}``.  Cycle-safe via ``visited``;
    the GitLab "more specific wins" rule is modelled by letting a later
    write (the job's own leaf) overwrite an earlier (parent) leaf for
    the same ``rel_path``.
    """
    if name in visited or depth > _MAX_EXTENDS_DEPTH:
        return {}
    src = raw_by_name.get(name)
    if src is None:
        return {}
    merged: dict[RelPath, ResolvedLeaf] = {}
    # 1. Parents, in declaration order (left-most lowest precedence per
    #    GitLab's documented extends merge order).
    for parent in src.extends:
        for rel, leaf in _merge_job(
            parent, raw_by_name, visited=visited | {name}, depth=depth + 1
        ).items():
            # Re-tag the inherited leaf's resolution edge as "extends"
            # so the consumer can see it crossed an inheritance boundary;
            # keep the parent's source file/line (where the bytes live).
            merged[rel] = ResolvedLeaf(rel, leaf.value, leaf.file, leaf.line, "extends")
    # 2. The job's own leaves, overriding parents; expand !reference.
    for rel, (val, line, leaf_file) in src.leaves.items():
        ref_leaves = _resolve_references_in_value(val, raw_by_name)
        if ref_leaves:
            # The leaf is a `!reference` to another job's key block.  Map
            # the spliced leaves under THIS leaf's parent key, keeping
            # their original line + file but tagging via="reference".
            for spliced_rel, spliced_val, spliced_file, spliced_line in ref_leaves:
                # Re-root: `variables: X: !reference [.a, variables]`
                # already shares the (variables, X) path; for a script
                # `!reference [.a, script]` we keep the referenced job's
                # script indices but namespaced under this job's key.
                tgt = rel if rel[0] == spliced_rel[0] else (rel[0], *spliced_rel[1:])
                merged[tgt] = ResolvedLeaf(
                    tgt, spliced_val, spliced_file, spliced_line, "reference"
                )
        else:
            merged[rel] = ResolvedLeaf(rel, val, leaf_file, line, "own")
    return merged


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def resolve_pipeline(files: list[tuple[str, str]]) -> _ResolvedGraph:
    """Resolve a pipeline's cross-file inheritance graph.

    ``files`` is ``[(filepath, content), ...]`` — the entry file plus
    every resolved ``include: local:`` target (the caller supplies the
    include resolution; this module only does the inheritance / reference
    merge across the combined job namespace).

    Returns a :class:`_ResolvedGraph` whose ``jobs`` maps every real
    (non-hidden, non-reserved) job name to its effective leaves with
    per-leaf provenance.  Hidden template jobs (leading ``.``) are
    resolved as inheritance targets but NOT surfaced as runnable jobs.
    """
    raw_by_name: dict[str, _RawJob] = {}
    file_text: dict[str, list[str]] = {}
    for filepath, content in files:
        file_text[filepath] = content.splitlines()
        for name, rawjob in _extract_raw_jobs(filepath, content).items():
            existing = raw_by_name.get(name)
            if existing is None:
                raw_by_name[name] = rawjob
            else:
                # The same job name defined across files: GitLab merges
                # them (later include wins on conflict).  Merge leaves
                # (later file overrides) and concatenate extends.
                for rel, lv in rawjob.leaves.items():
                    existing.leaves[rel] = lv
                existing.extends.extend(rawjob.extends)

    # Top-level cascade: every file may contribute to the synthetic ""
    # variables job; fold those into a single cascade set.
    cascade: dict[RelPath, ResolvedLeaf] = {}
    top = raw_by_name.get("")
    if top is not None:
        for rel, (val, line, leaf_file) in top.leaves.items():
            cascade[rel] = ResolvedLeaf(rel, val, leaf_file, line, "own")

    jobs: dict[str, ResolvedJob] = {}
    for name, rawjob in raw_by_name.items():
        if name == "" or name in _RESERVED_TOP_KEYS or name.startswith("."):
            continue
        merged = _merge_job(name, raw_by_name)
        # Overlay the top-level variables cascade UNDER the job's own /
        # inherited variables (job-level wins), so a sink in an inherited
        # script can still see a top-level tainted cascade var.
        leaves: list[ResolvedLeaf] = []
        seen_var_names = {rel[1] for rel in merged if len(rel) == 2 and rel[0] == "variables"}
        for rel, leaf in cascade.items():
            if len(rel) == 2 and rel[0] == "variables" and rel[1] not in seen_var_names:
                leaves.append(ResolvedLeaf(rel, leaf.value, leaf.file, leaf.line, "cascade"))
        leaves.extend(merged.values())
        jobs[name] = ResolvedJob(name=name, home_file=rawjob.def_file, leaves=leaves)

    return _ResolvedGraph(jobs=jobs, file_text=file_text)


# ---------------------------------------------------------------------------
# Cross-file / inheritance taint edges
# ---------------------------------------------------------------------------
#
# Mirror of the single-file taint detection in ``gitlab_taint.analyze``,
# but run over the RESOLVED per-job leaves so a source and sink that the
# single-file pass never sees together (because they live in different
# files or are spliced via extends/!reference) are joined.  We emit a
# flow ONLY when it crosses a boundary — otherwise the single-file
# engine already reports it, and we would double-fire.

# Sink leaf classes and the sink_kind label each maps to (parallel to
# gitlab_taint._SinkSite.kind).  ``image.name`` / ``services[i].name``
# collapse onto image / service_image.
_SINK_LEAF_KINDS = {
    "script": "script",
    "before_script": "script",
    "after_script": "script",
    "image": "image",
    "services": "service_image",
    "tags": "tags",
}


@dataclass(frozen=True)
class CrossFileTaintPath:
    """A confirmed cross-file / inheritance-laundered GitLab taint flow.

    ``source_file`` / ``source_line`` point at the ``variables:`` (or
    inherited) assignment that introduces the attacker bytes;
    ``sink_file`` / ``sink_line`` point at the resolved sink leaf.  At
    least one of these holds:

      * ``source_file != sink_file`` (the value and its sink live in
        different files), OR
      * the flow was laundered across an inheritance edge
        (``boundary`` contains ``"extends"`` or ``"reference"``).

    so the flow is genuinely invisible to the single-file analyzer.
    """

    job: str
    source_var: str  # e.g. "CI_COMMIT_REF_SLUG"
    laundered_var: str  # the user-named variable carrying the taint
    source_file: str
    source_line: int
    sink_file: str
    sink_line: int
    sink_snippet: str
    sink_kind: str  # "script" | "image" | "service_image" | "tags"
    boundary: str  # human-readable: "extends" | "reference" | "include" | combos
    hops: tuple[TaintHop, ...]


def _resolve_job_taint(
    job: ResolvedJob,
) -> dict[str, tuple[str, str, int, str, tuple[TaintHop, ...]]]:
    """Fixed-point resolve which of ``job``'s effective ``variables:``
    carry attacker bytes.

    Returns ``{var_name: (source_var, source_file, source_line, via,
    hops)}``.  Handles both a direct ``$CI_TAINTED`` reference and a
    multi-hop ``B: $A`` laundering chain over the job's resolved
    variable set (same conservative single-standalone-ref rule as the
    single-file analyzer).
    """
    # Effective variables: rel ("variables", NAME) -> ResolvedLeaf.
    var_leaves: dict[str, ResolvedLeaf] = {}
    for leaf in job.leaves:
        if len(leaf.path) == 2 and leaf.path[0] == "variables" and isinstance(leaf.path[1], str):
            # Later leaf (job-own) overrides earlier (cascade) — the
            # resolve_pipeline ordering already puts cascade first, so
            # last-write-wins is correct.
            var_leaves[leaf.path[1]] = leaf

    tainted: dict[str, tuple[str, str, int, str, tuple[TaintHop, ...]]] = {}
    # Seed: direct $CI_TAINTED references.
    for name, leaf in var_leaves.items():
        m = _TAINTED_REF_RE.search(leaf.value)
        if m is not None:
            src = m.group(1)
            tainted[name] = (
                src,
                leaf.file,
                leaf.line,
                leaf.via,
                (
                    TaintHop(
                        kind="var_static",
                        line=leaf.line,
                        name=name,
                        detail=f"variables.{name} := ${src}",
                    ),
                ),
            )
    # Fixed point: B: $A where A is already tainted.
    changed = True
    while changed:
        changed = False
        for name, leaf in var_leaves.items():
            if name in tainted:
                continue
            other = _extract_var_ref(leaf.value)
            if other and other in tainted:
                src, sfile, sline, svia, hops = tainted[other]
                # The launder edge crosses a boundary if THIS leaf or the
                # upstream came via extends/reference, or differs in file.
                via = leaf.via if leaf.via != "own" else svia
                tainted[name] = (
                    src,
                    sfile,
                    sline,
                    via,
                    (
                        *hops,
                        TaintHop(
                            kind="var_indirect",
                            line=leaf.line,
                            name=name,
                            detail=f"variables.{name} := ${other}",
                        ),
                    ),
                )
                changed = True
    return tainted


def _sink_leaves(job: ResolvedJob) -> list[tuple[str, ResolvedLeaf]]:
    """Return ``(sink_kind, leaf)`` for every resolved leaf that is a
    taint sink — a ``script:`` line, an ``image:`` / ``services.*``
    image value, or a ``tags:`` selector."""
    out: list[tuple[str, ResolvedLeaf]] = []
    for leaf in job.leaves:
        if not leaf.path:
            continue
        head = leaf.path[0]
        kind = _SINK_LEAF_KINDS.get(head if isinstance(head, str) else "")
        if kind is None:
            continue
        if kind in ("image", "service_image"):
            # image: scalar, image.name, services[i], services[i].name.
            tail = leaf.path[1:]
            if (
                tail
                and tail != ("name",)
                and not (len(tail) == 2 and isinstance(tail[0], int) and tail[1] == "name")
                and not (len(tail) == 1 and isinstance(tail[0], int))
            ):
                continue
        out.append((kind, leaf))
    return out


def find_cross_file_taint(files: list[tuple[str, str]]) -> list[CrossFileTaintPath]:
    """Resolve the pipeline's inheritance graph and return every
    confirmed cross-file / inheritance-laundered taint flow.

    A flow is emitted only when the source and sink are NOT both in the
    same file via the job's own (non-inherited) body — i.e. it is one
    the single-file analyzer cannot see — so this never double-fires
    with TAINT-GL-001/002/003/005/006.
    """
    graph = resolve_pipeline(files)
    out: list[CrossFileTaintPath] = []
    for job in graph.jobs.values():
        tainted = _resolve_job_taint(job)
        if not tainted:
            continue
        for sink_kind, leaf in _sink_leaves(job):
            text = leaf.value or ""
            for var, (src, sfile, sline, svia, hops) in tainted.items():
                if not _references_var(text, var):
                    continue
                # Boundary test: emit only when the flow is invisible to
                # the single-file pass — the source leaf and the sink
                # leaf live in different files, OR either crossed an
                # inheritance edge (extends/reference).
                crosses_file = sfile != leaf.file
                via_inherit = svia in ("extends", "reference") or leaf.via in (
                    "extends",
                    "reference",
                )
                if not (crosses_file or via_inherit):
                    continue
                boundary = _describe_boundary(crosses_file, svia, leaf.via)
                sink_hop = TaintHop(
                    kind="sink",
                    line=leaf.line,
                    name=var,
                    detail=f"{sink_kind}: references ${var}",
                )
                out.append(
                    CrossFileTaintPath(
                        job=job.name,
                        source_var=src,
                        laundered_var=var,
                        source_file=sfile,
                        source_line=sline,
                        sink_file=leaf.file,
                        sink_line=leaf.line,
                        sink_snippet=text[:200],
                        sink_kind=sink_kind,
                        boundary=boundary,
                        hops=(*hops, sink_hop),
                    )
                )
    out.sort(key=lambda p: (p.sink_file, p.sink_line, p.job, p.laundered_var))
    # Deduplicate identical (sink_file, sink_line, laundered_var, source_var)
    # tuples that can arise when a block-scalar line is reached by more
    # than one resolved index.
    seen: set[tuple[str, int, str, str, str]] = set()
    deduped: list[CrossFileTaintPath] = []
    for p in out:
        key = (p.sink_file, p.sink_line, p.laundered_var, p.source_var, p.sink_kind)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(p)
    return deduped


def _describe_boundary(crosses_file: bool, source_via: str, sink_via: str) -> str:
    """Human-readable boundary label for the rendered finding."""
    parts: list[str] = []
    if "extends" in (source_via, sink_via):
        parts.append("extends")
    if "reference" in (source_via, sink_via):
        parts.append("!reference")
    if crosses_file:
        parts.append("include")
    return "+".join(dict.fromkeys(parts)) or "inheritance"


def _basename(path: str) -> str:
    return os.path.basename(path.replace("\\", "/"))
