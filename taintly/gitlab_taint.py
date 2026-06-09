"""Taint analysis for GitLab CI pipelines.

Mirror of :mod:`taintly.taint` for GitLab CI YAML.  Same shape,
different vocabulary:

* Attacker-controlled sources are GitLab pre-defined CI variables
  whose value the runner copies from the commit / merge-request that
  triggered the pipeline (``$CI_COMMIT_TITLE``, ``$CI_MERGE_REQUEST_TITLE``,
  ``$CI_COMMIT_REF_NAME``, ...).  They are plain bash variables — no
  ``${{ }}`` expression engine to model.
* The env: block is GitLab's ``variables:`` block (top-level *and* job-level
  — top-level cascades to every job).
* Sinks are lines under ``script:``, ``before_script:``, or
  ``after_script:`` that reference the tainted variable via ``$VAR``,
  ``${VAR}``, or ``%VAR%`` (Windows runners).

Scope — three rules shipped:

1. **Shallow** (TAINT-GL-001, ``kind="shallow"``):

       variables:
         FOO: $CI_COMMIT_TITLE
       job:
         script:
           - echo "$FOO"

2. **Multi-hop variable propagation** (TAINT-GL-002, ``kind="multi_hop"``):

       variables:
         A: $CI_COMMIT_TITLE
         B: $A
         C: $B
       job:
         script:
           - echo "$C"

   A chain of any depth through ``$VAR`` references inside
   ``variables:`` values is resolved by fixed-point iteration, so
   declaration order inside the block does not matter and chains that
   thread job-level assignments on top of top-level cascades are
   picked up too.

3. **Dotenv artefact bridge** (TAINT-GL-003, ``kind="dotenv"``):

       producer:
         variables:
           RAW: $CI_COMMIT_TITLE
         script:
           - echo "TITLE=$RAW" > build.env
         artifacts:
           reports:
             dotenv: build.env

       consumer:
         needs: [producer]
         script:
           - echo "$TITLE"

   The runner parses the producer's ``reports.dotenv`` artefact and
   sets the resulting ``NAME=VALUE`` lines as real environment
   variables in every job that ``needs:`` the producer (unless that
   ``needs:`` entry opts out with ``artifacts: false``).  The
   consumer then shell-expands ``$TITLE`` with the attacker's string.
   This is the closest GitLab analog of the GitHub
   ``$GITHUB_ENV`` bridge caught by TAINT-GH-003.

Still out of scope (future deep-taint work, listed here so the gap stays
visible):

* ``extends:`` / ``!reference`` job inheritance — values inherited from a
  parent job's ``variables:`` block.
* ``include:``-d files contributing variables.
* Shell-quoting analysis — any textual reference to ``$VAR`` in a
  script line counts as a sink, even when wrapped in single or double
  quotes.  False positives here are preferable to misses, same trade-off
  as the GitHub analyzer.

Line-based (no real YAML parser) for zero-dep symmetry with the rest of
the engine; job boundaries come from ``_split_into_job_segments`` in
``taintly.models``.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from .models import _split_into_job_segments
from .parsers.structural import EventKind, walk_workflow
from .taint_facts import Database, solve

# ---------------------------------------------------------------------------
# Source definitions
# ---------------------------------------------------------------------------

# Predefined GitLab CI variables whose value comes from the
# attacker-controlled commit / merge-request data.  Conservative list —
# we deliberately exclude SHAs (``$CI_COMMIT_SHA`` etc.) and IDs
# (``$CI_MERGE_REQUEST_IID``) because their character set is too
# constrained to carry shell metacharacters.  See
# https://docs.gitlab.com/ci/variables/predefined_variables/ for the
# full canonical list.
_TAINTED_VARS = [
    "CI_COMMIT_TITLE",
    "CI_COMMIT_DESCRIPTION",
    "CI_COMMIT_MESSAGE",
    "CI_COMMIT_AUTHOR",
    "CI_COMMIT_BRANCH",
    "CI_COMMIT_TAG",
    "CI_COMMIT_REF_NAME",
    "CI_COMMIT_REF_SLUG",
    "CI_MERGE_REQUEST_TITLE",
    "CI_MERGE_REQUEST_DESCRIPTION",
    "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
    "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
    "CI_MERGE_REQUEST_LABELS",
    # External pull-request mirror variables (a GitHub repo mirrored into
    # GitLab with CI/CD on external PRs enabled). The external PR author
    # controls the source branch (already listed), and equally the title,
    # description, and target-branch name — all attacker-supplied free
    # text, the same exposure class as the CI_MERGE_REQUEST_* set above.
    "CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME",
    "CI_EXTERNAL_PULL_REQUEST_TARGET_BRANCH_NAME",
    "CI_EXTERNAL_PULL_REQUEST_TITLE",
    "CI_EXTERNAL_PULL_REQUEST_DESCRIPTION",
    # Triggerer-identity variables: populated from the user's GitLab
    # profile. Display name and email accept arbitrary UTF-8 including
    # shell metacharacters; they reach scripts the moment a job echoes
    # or stores them unsafely. Login is more constrained but still
    # attacker-chosen on self-serve instances.
    "GITLAB_USER_NAME",
    "GITLAB_USER_LOGIN",
    "GITLAB_USER_EMAIL",
]

# A bash-style reference to one of the tainted CI variables: ``$VAR`` or
# ``${VAR}``.  Word-boundary anchors so ``$CI_COMMIT_BRANCH_X`` does not
# match ``CI_COMMIT_BRANCH``.
_TAINTED_REF_RE = re.compile(r"\$\{?(" + "|".join(_TAINTED_VARS) + r")\}?\b")

# A YAML key/value pair inside a ``variables:`` block: ``  NAME: value``.
# Indent isn't anchored; the ``variables:`` walker handles scoping.
_VAR_ASSIGN_RE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?)\s*$")

# ``variables:`` block header — value empty, children follow at deeper
# indent.  Matches both top-level and job-level variables blocks.
_VARIABLES_HEADER_RE = re.compile(r"^(\s*)variables\s*:\s*$")

# Script-block headers.  GitLab has three flavours; all are list-typed
# and may appear with either inline (``script: echo hi``) or block-list
# (``script:`` then ``- echo hi``) shape.  We detect the header line and
# walk children at deeper indent.
_SCRIPT_HEADER_RE = re.compile(r"^(\s*)(?:script|before_script|after_script)\s*:\s*$")
_SCRIPT_INLINE_RE = re.compile(r"^(\s*)(?:script|before_script|after_script)\s*:\s*(.+?)\s*$")

# ``needs:`` header.  Three flavours to parse downstream:
#   - Inline list: ``needs: [build, test]``
#   - Inline list (strings-or-mappings is not accepted inline in YAML, so
#     inline is always a list of bare strings for us).
#   - Block list: ``needs:\n  - build\n  - job: test\n    artifacts: true``
_NEEDS_HEADER_RE = re.compile(r"^(\s*)needs\s*:\s*$")
_NEEDS_INLINE_RE = re.compile(r"^(\s*)needs\s*:\s*\[(?P<inline>[^\]]*)\]\s*$")

# Entry forms inside a block-list ``needs:``:
#   ``- <name>``             (bare string)
#   ``- job: <name>``        (mapping that also allows ``artifacts:``)
_NEEDS_BARE_ITEM_RE = re.compile(r"^\s*-\s+[\"']?(?P<name>[A-Za-z_][A-Za-z0-9_-]*)[\"']?\s*$")
_NEEDS_JOB_ITEM_RE = re.compile(
    r"^\s*-\s+job\s*:\s*[\"']?(?P<name>[A-Za-z_][A-Za-z0-9_-]*)[\"']?\s*$"
)
_NEEDS_ARTIFACTS_RE = re.compile(r"^\s+artifacts\s*:\s*(?P<val>true|false)\s*$")

# ``artifacts:`` header then ``reports:`` then ``dotenv:``.  The dotenv
# value can be a single filename (``dotenv: build.env``) or a list of
# filenames.  We support both shapes; the list form is rare but valid.
_ARTIFACTS_HEADER_RE = re.compile(r"^(\s*)artifacts\s*:\s*$")
_REPORTS_HEADER_RE = re.compile(r"^(\s*)reports\s*:\s*$")
_DOTENV_INLINE_RE = re.compile(r"^(\s*)dotenv\s*:\s*[\"']?(?P<file>[^\s\"'\[\]]+)[\"']?\s*$")
_DOTENV_HEADER_RE = re.compile(r"^(\s*)dotenv\s*:\s*$")
_DOTENV_LIST_ITEM_RE = re.compile(r"^\s*-\s+[\"']?(?P<file>[^\s\"'\[\]]+)[\"']?\s*$")

# ``echo NAME=VALUE > file`` or ``echo NAME=VALUE >> file``.  We reuse the
# body-extraction trick from the GitHub $GITHUB_ENV detector: match every
# common quoted form so embedded ``\"`` escapes don't terminate the body
# prematurely.  ``file`` captures the redirect target so the caller can
# confirm it matches the job's declared dotenv filename.
_ECHO_ASSIGN_TO_FILE_RE = re.compile(
    r"""
    \becho
    (?:\s+-[a-zA-Z]+)*                       # optional flags (-n, -e, ...)
    \s+
    (?:
        "(?P<dq>(?:\\.|[^"\\])*)"            # "..."  with \-escapes
      | '(?P<sq>(?:\\.|[^'\\])*)'            # '...'  with \-escapes
      | (?P<bare>[^\s"'>|&;]+)               # unquoted bare word
    )
    \s*>>?\s*                                # > or >> redirect
    [\"']?(?P<file>[^\s"'>|&;]+)[\"']?       # redirect target filename
    """,
    re.VERBOSE,
)

# Extract NAME=VALUE from an already-dequoted echo body.
_NAME_VALUE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)

# Top-level job name — a key at column 0 that is NOT a reserved GitLab
# keyword.  The reserved set mirrors ``_GITLAB_KEYWORDS`` in
# ``taintly.models`` (kept here to avoid circular import).
_RESERVED_GITLAB_TOP_KEYS = frozenset(
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
    ]
)
_JOB_NAME_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*:")


# ---------------------------------------------------------------------------
# Public data model
# ---------------------------------------------------------------------------


@dataclass
class TaintHop:
    """One step in a GitLab taint provenance chain.

    Hop kinds:

    * ``"var_static"`` — a ``variables:`` assignment whose value
      directly references a tainted CI variable.
    * ``"var_indirect"`` — a ``variables:`` assignment whose value is
      ``$OTHER`` (or ``${OTHER}``) where ``OTHER`` is already tainted,
      i.e. one hop in a multi-hop chain.
    * ``"dotenv"`` — a shell write of ``NAME=VALUE`` into a file that
      the writing job declares as an ``artifacts.reports.dotenv``
      artefact.  Consumer jobs that ``needs:`` the writer inherit
      ``NAME`` as a real environment variable.
    * ``"sink"`` — the script-line where the tainted variable is
      shell-expanded.
    """

    kind: str  # "var_static" | "var_indirect" | "dotenv" | "sink"
    line: int  # 1-indexed line in the source file
    name: str  # variable name at this hop
    detail: str  # human-readable description


@dataclass
class TaintPath:
    """A detected end-to-end taint flow from a tainted GitLab CI
    variable into a pipeline sink.

    ``sink_kind`` says *where the value landed* — ``"script"`` (a
    ``script:`` / ``before_script:`` / ``after_script:`` shell line —
    the default and by far the most common), ``"image"`` (a job
    ``image:`` value), ``"service_image"`` (a ``services.*`` image),
    or ``"tags"`` (a runner ``tags:`` selector).  It defaults to
    ``"script"`` so every existing call site and rule keeps its
    behaviour.
    """

    source_var: str  # e.g. "CI_COMMIT_TITLE"
    source_line: int  # 1-indexed line of the variables: assignment
    laundered_var: str  # the user-named variable that carries the taint
    sink_line: int  # 1-indexed line of the sink
    sink_snippet: str  # literal text of that sink line, stripped
    kind: str = "shallow"
    hops: list[TaintHop] = field(default_factory=list)
    sink_kind: str = "script"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Facts model
#
# Mirror of the GitHub facts engine in :mod:`taintly.taint`.  GitLab is
# simpler: the only hand-rolled convergence loop was
# ``_resolve_var_taints`` (multi-hop ``variables:`` chains); the dotenv
# bridge was a forward two-pass.  Both collapse into ONE relational
# fixed point.  Phase A extracts the EDB by reusing the existing
# line-walkers; Phase B swaps in the structural parser.
# ---------------------------------------------------------------------------

_R_VAR_ASSIGN = "var_assign"  # EDB
_R_SCRIPT_LINE = "script_line"  # EDB
_R_DOTENV_WRITE = "dotenv_write"  # EDB
_R_NEEDS_EDGE = "needs_edge"  # EDB
_R_SINK_SITE = "sink_site"  # EDB  (non-script: sinks — image:, services:, tags:)
_R_TAINTED_VAR = "tainted_var"  # IDB
_R_VISIBLE_VAR = "visible_var"  # IDB
_R_TAINTED_DOTENV = "tainted_dotenv"  # IDB
_R_INHERITED_VAR = "inherited_var"  # IDB


@dataclass
class _VarAssign:
    """EDB: a ``variables:`` assignment at ``scope`` — ``"top"`` or
    ``("job", job_name)``."""

    scope: object
    name: str
    raw: str
    line: int

    def fact_key(self):
        return (self.scope, self.name, self.line)

    def fact_rank(self):
        return ()


@dataclass
class _ScriptLine:
    """EDB: one line of a ``script:`` / ``before_script:`` /
    ``after_script:`` body."""

    job: str
    line: int
    text: str

    def fact_key(self):
        return (self.job, self.line)

    def fact_rank(self):
        return ()


@dataclass
class _SinkSite:
    """EDB: a non-``script:`` job key whose value the runner expands
    and which is therefore a taint sink in its own right.

    ``kind`` — ``"image"`` (the job's container image), ``"service_image"``
    (a ``services.*`` image), or ``"tags"`` (a runner tag selector).
    ``value`` is the parsed scalar (drives ``$VAR`` detection);
    ``snippet`` is the raw source line (the displayed
    ``sink_snippet``).
    """

    job: str
    kind: str
    line: int
    value: str
    snippet: str

    def fact_key(self):
        return (self.job, self.kind, self.line, self.value)

    def fact_rank(self):
        return ()


@dataclass
class _DotenvWrite:
    """EDB: an ``echo "NAME=VALUE" > <dotenv_file>`` write whose
    redirect target is the job's declared dotenv artefact."""

    job: str
    name: str
    value: str
    line: int
    quoted_single: bool
    seq: int

    def fact_key(self):
        return (self.job, self.name, self.seq)

    def fact_rank(self):
        return ()


@dataclass
class _NeedsEdge:
    """EDB: ``job`` declares ``needs: producer``; ``artifacts`` is the
    effective ``artifacts:`` inheritance flag for that entry."""

    job: str
    producer: str
    artifacts: bool

    def fact_key(self):
        return (self.job, self.producer)

    def fact_rank(self):
        return ()


@dataclass
class _TaintedVar:
    """IDB: a ``variables:`` entry at ``scope`` carries attacker bytes."""

    scope: object
    name: str
    source_var: str
    source_line: int
    hops: list[TaintHop]

    def fact_key(self):
        return (self.scope, self.name)

    def fact_rank(self):
        return (len(self.hops), self.source_line)


@dataclass
class _VisibleVar:
    """IDB: variable ``name`` carries attacker bytes in ``job``'s
    environment.  ``cls`` carries scope precedence — ``0`` job-level
    ``variables:`` overrides ``1`` the top-level cascade."""

    job: str
    name: str
    cls: int
    source_var: str
    source_line: int
    hops: list[TaintHop]

    def fact_key(self):
        return (self.job, self.name)

    def fact_rank(self):
        return (self.cls, len(self.hops), self.source_line)


@dataclass
class _TaintedDotenv:
    """IDB: ``producer`` writes attacker bytes into ``name`` in its
    declared dotenv artefact."""

    producer: str
    name: str
    seq: int
    source_var: str
    source_line: int
    hops: list[TaintHop]

    def fact_key(self):
        return (self.producer, self.name)

    def fact_rank(self):
        return (-self.seq, len(self.hops))


@dataclass
class _InheritedVar:
    """IDB: ``job`` inherits a tainted ``name`` as a real environment
    variable via a ``needs:`` edge to a dotenv-producing job."""

    job: str
    name: str
    source_var: str
    source_line: int
    hops: list[TaintHop]

    def fact_key(self):
        return (self.job, self.name)

    def fact_rank(self):
        return (len(self.hops), self.source_line)


@dataclass
class _Job:
    """The per-job spine the projection walks."""

    name: str
    seg_start: int
    seg_lines: list[str]
    dotenv_file: str | None


def _build_facts(lines: list[str]) -> tuple[Database, list[_Job]]:
    """Extract the EDB for ``lines``, run the closure, and return the
    saturated :class:`Database` plus the job spine."""
    db = Database()
    jobs: list[_Job] = []
    _seq = 0

    # Top-level variables: cascade to every job.
    for name, raw, line in _collect_top_level_var_assignments(lines):
        db.add(_R_VAR_ASSIGN, _VarAssign("top", name, raw, line))

    for seg_start, seg_lines in _split_into_job_segments(lines):
        name = _extract_job_name(seg_lines)
        if name is None:
            continue
        for vname, raw, line in _collect_var_assignments_in_segment(seg_lines, seg_start):
            db.add(_R_VAR_ASSIGN, _VarAssign(("job", name), vname, raw, line))

        dotenv_file = _extract_dotenv_filename(seg_lines)
        for sink_line, sink_snippet in _iter_script_lines(seg_lines, seg_start):
            db.add(_R_SCRIPT_LINE, _ScriptLine(name, sink_line, sink_snippet))
            if dotenv_file is not None:
                for m in _ECHO_ASSIGN_TO_FILE_RE.finditer(sink_snippet):
                    if m.group("file") != dotenv_file:
                        continue
                    for wname, value, qs in _echo_body_name_value(m):
                        db.add(
                            _R_DOTENV_WRITE,
                            _DotenvWrite(name, wname, value, sink_line, qs, _seq),
                        )
                        _seq += 1

        for producer, artifacts in _extract_needs(seg_lines):
            db.add(_R_NEEDS_EDGE, _NeedsEdge(name, producer, artifacts))

        jobs.append(_Job(name, seg_start, seg_lines, dotenv_file))

    solve(db, _gitlab_rules(jobs))
    return db, jobs


# --- EDB extraction: Phase B (structural parser) ---------------------------

_SCRIPT_KEYS = ("script", "before_script", "after_script")


def _build_facts_structural(content: str, lines: list[str]) -> tuple[Database, list[_Job]]:
    """Phase B EDB extractor for GitLab: source the extensional facts
    from the structural parser instead of the line-walkers.

    Produces the same relation shapes as :func:`_build_facts`, so the
    closure rule set and the projection are shared unchanged.  Script
    lines are normalised to the stripped source line (matching the
    line backend's ``_iter_script_lines``) so the displayed
    ``sink_snippet`` stays byte-identical.
    """
    n_lines = len(lines)

    def _src_strip(line_no: int, fallback: str) -> str:
        return lines[line_no - 1].strip() if 1 <= line_no <= n_lines else fallback

    job_order: list[str] = []
    var_assigns: list[_VarAssign] = []
    # job -> list of (line, text)
    script_lines: dict[str, list[tuple[int, str]]] = {}
    # job -> dotenv filename
    dotenv_files: dict[str, str] = {}
    # (job, i) -> [producer, artifacts]
    needs_raw: dict[tuple[str, int], list] = {}
    sink_sites: list[_SinkSite] = []

    def _note_job(job: str) -> None:
        if job not in script_lines:
            script_lines[job] = []
            job_order.append(job)

    def _is_job(name: object) -> bool:
        return (
            isinstance(name, str)
            and name not in _RESERVED_GITLAB_TOP_KEYS
            and not name.startswith(".")
        )

    for ev in walk_workflow(".gitlab-ci.yml", content=content):
        if ev.kind is EventKind.CUTOFF:
            break
        if ev.kind is not EventKind.LEAF_SCALAR:
            continue
        path = ev.path
        if not path:
            continue
        # ('variables', <name>) — top-level cascade.
        if len(path) == 2 and path[0] == "variables" and isinstance(path[1], str):
            var_assigns.append(_VarAssign("top", path[1], ev.value or "", ev.line))
            continue
        head = path[0]
        if not _is_job(head):
            continue
        job = head
        rest = path[1:]
        # <job>.variables.<name>
        if len(rest) == 2 and rest[0] == "variables" and isinstance(rest[1], str):
            _note_job(job)
            var_assigns.append(_VarAssign(("job", job), rest[1], ev.value or "", ev.line))
            continue
        # <job>.{script,before_script,after_script}[i]  /  inline <job>.script
        if rest and rest[0] in _SCRIPT_KEYS:
            _note_job(job)
            tail = rest[1:]
            # Inline ``script: echo hi`` (no index) or list item
            # ``script:`` -> ``- echo hi`` (integer index).  Anything
            # deeper is the structural tokenizer mis-splitting a
            # ``: ``-containing command into a spurious key — those
            # lines are simply not recovered (a documented Phase B
            # divergence, see the decision record).
            if not tail or (len(tail) == 1 and isinstance(tail[0], int)):
                if ev.block_lines:
                    # Block-scalar body lines keep their internal
                    # indentation; the line backend's
                    # ``_iter_script_lines`` strips it, so match that.
                    for src_line, body in ev.block_lines:
                        script_lines[job].append((src_line, _src_strip(src_line, body.strip())))
                else:
                    script_lines[job].append((ev.line, ev.value or ""))
            continue
        # <job>.artifacts.reports.dotenv  (plain or list form)
        if (
            len(rest) >= 3
            and rest[0] == "artifacts"
            and rest[1] == "reports"
            and rest[2] == "dotenv"
        ):
            _note_job(job)
            if job not in dotenv_files and ev.value:
                dotenv_files[job] = ev.value
            continue
        # <job>.needs[i]            -> bare producer string
        # <job>.needs[i].job        -> mapping-form producer
        # <job>.needs[i].artifacts  -> inheritance flag
        if len(rest) >= 2 and rest[0] == "needs" and isinstance(rest[1], int):
            _note_job(job)
            slot = needs_raw.setdefault((job, rest[1]), [None, True])
            sub = rest[2:]
            if not sub or sub == ("job",):
                slot[0] = ev.value
            elif sub == ("artifacts",):
                slot[1] = (ev.value or "").strip() == "true"
            continue
        # Non-script: sink sites — the runner expands ``$VAR`` in each.
        #   <job>.image / <job>.image.name      -> the job's container
        #   <job>.services[i] / [i].name        -> a service container
        #   <job>.tags / <job>.tags[i]          -> runner tag selector
        if rest == ("image",) or rest == ("image", "name"):
            _note_job(job)
            val = ev.value or ""
            sink_sites.append(_SinkSite(job, "image", ev.line, val, _src_strip(ev.line, val)))
            continue
        if (
            len(rest) >= 2
            and rest[0] == "services"
            and isinstance(rest[1], int)
            and (len(rest) == 2 or rest[2:] == ("name",))
        ):
            _note_job(job)
            val = ev.value or ""
            sink_sites.append(
                _SinkSite(job, "service_image", ev.line, val, _src_strip(ev.line, val))
            )
            continue
        if (
            rest
            and rest[0] == "tags"
            and (len(rest) == 1 or (len(rest) == 2 and isinstance(rest[1], int)))
        ):
            _note_job(job)
            val = ev.value or ""
            sink_sites.append(_SinkSite(job, "tags", ev.line, val, _src_strip(ev.line, val)))
            continue

    # Build the EDB.
    db = Database()
    for va in var_assigns:
        db.add(_R_VAR_ASSIGN, va)
    for ss in sink_sites:
        db.add(_R_SINK_SITE, ss)
    jobs: list[_Job] = []
    _seq = 0
    for job in job_order:
        dotenv_file = dotenv_files.get(job)
        for line, text in script_lines[job]:
            db.add(_R_SCRIPT_LINE, _ScriptLine(job, line, text))
            if dotenv_file is not None:
                for m in _ECHO_ASSIGN_TO_FILE_RE.finditer(text):
                    if m.group("file") != dotenv_file:
                        continue
                    for wname, value, qs in _echo_body_name_value(m):
                        db.add(
                            _R_DOTENV_WRITE,
                            _DotenvWrite(job, wname, value, line, qs, _seq),
                        )
                        _seq += 1
        jobs.append(_Job(job, -1, [], dotenv_file))
    for (job, _i), (producer, artifacts) in needs_raw.items():
        if producer:
            db.add(_R_NEEDS_EDGE, _NeedsEdge(job, producer, artifacts))

    solve(db, _gitlab_rules(jobs))
    return db, jobs


def _taint_backend() -> str:
    """Which EDB extractor :func:`analyze` uses — ``"structural"``
    (Phase B, default) or ``"line"`` (Phase A, the comparison
    baseline / escape hatch).  Selected via the
    ``TAINTLY_TAINT_BACKEND`` environment variable."""
    return os.environ.get("TAINTLY_TAINT_BACKEND", "structural")


def _echo_body_name_value(m):
    """Pull ``(name, value, quoted_single)`` out of a matched
    ``_ECHO_ASSIGN_TO_FILE_RE`` echo body."""
    dq, sq, bare = m.group("dq"), m.group("sq"), m.group("bare")
    if dq is not None:
        body = re.sub(r"\\(.)", r"\1", dq)
        quoted_single = False
    elif sq is not None:
        body = sq
        quoted_single = True
    else:
        body = bare or ""
        quoted_single = False
    am = _NAME_VALUE_RE.match(body)
    if am:
        yield (am.group(1), am.group(2), quoted_single)


def _gitlab_rules(jobs: list[_Job]):
    """Build the GitLab rule set.  ``jobs`` is captured so the
    visibility rule can fan the top-level cascade across every job."""
    job_names = [j.name for j in jobs]

    def rule_tainted_var(db: Database):
        for va in db.all(_R_VAR_ASSIGN):
            # (a) direct $CI_<tainted> reference.
            m = _TAINTED_REF_RE.search(va.raw)
            if m is not None:
                source = m.group(1)
                yield (
                    _R_TAINTED_VAR,
                    _TaintedVar(
                        va.scope,
                        va.name,
                        source,
                        va.line,
                        [
                            TaintHop(
                                kind="var_static",
                                line=va.line,
                                name=va.name,
                                detail=f"variables.{va.name} := ${source}",
                            )
                        ],
                    ),
                )
                continue
            # (b) multi-hop: pure ``$OTHER`` reference.
            other = _extract_var_ref(va.raw)
            if not other:
                continue
            if va.scope == "top":
                parent = db.get(_R_TAINTED_VAR, ("top", other))
            else:  # ("job", name)
                parent = db.get(_R_VISIBLE_VAR, (va.scope[1], other))
            if parent is not None:
                yield (
                    _R_TAINTED_VAR,
                    _TaintedVar(
                        va.scope,
                        va.name,
                        parent.source_var,
                        parent.source_line,
                        parent.hops
                        + [
                            TaintHop(
                                kind="var_indirect",
                                line=va.line,
                                name=va.name,
                                detail=f"variables.{va.name} := ${other}",
                            )
                        ],
                    ),
                )

    def rule_visible_var(db: Database):
        # A job that re-declares a variable in its own ``variables:``
        # block SHADOWS the top-level cascade for that name — so a
        # job-level ``variables: VAR: <clean literal>`` over a
        # top-tainted ``VAR`` un-taints ``VAR`` in that job (a
        # job-level tainted re-declaration is carried by the
        # job-scope ``tainted_var`` branch instead).  Not suppressing
        # this is the clean-override false positive.
        job_redecl = {(va.scope[1], va.name) for va in db.all(_R_VAR_ASSIGN) if va.scope != "top"}
        for tv in db.all(_R_TAINTED_VAR):
            if tv.scope == "top":
                for jn in job_names:
                    if (jn, tv.name) in job_redecl:
                        continue  # the job's own variables: governs this name
                    yield (
                        _R_VISIBLE_VAR,
                        _VisibleVar(jn, tv.name, 1, tv.source_var, tv.source_line, tv.hops),
                    )
            else:  # ("job", name)
                yield (
                    _R_VISIBLE_VAR,
                    _VisibleVar(tv.scope[1], tv.name, 0, tv.source_var, tv.source_line, tv.hops),
                )

    def rule_tainted_dotenv(db: Database):
        for dw in db.all(_R_DOTENV_WRITE):
            # (a) direct $CI_<tainted> reference in the echo body.
            m = _TAINTED_REF_RE.search(dw.value)
            if m is not None:
                source = m.group(1)
                yield (
                    _R_TAINTED_DOTENV,
                    _TaintedDotenv(
                        dw.job,
                        dw.name,
                        dw.seq,
                        source,
                        dw.line,
                        [
                            TaintHop(
                                kind="dotenv",
                                line=dw.line,
                                name=f"{dw.job}.{dw.name}",
                                detail=(f"dotenv artefact of {dw.job} sets {dw.name} := ${source}"),
                            )
                        ],
                    ),
                )
                continue
            # (b) indirect: shell ref to an already-tainted visible var.
            if dw.quoted_single:
                continue
            for vv in db.all(_R_VISIBLE_VAR):
                if vv.job == dw.job and _references_var(dw.value, vv.name):
                    yield (
                        _R_TAINTED_DOTENV,
                        _TaintedDotenv(
                            dw.job,
                            dw.name,
                            dw.seq,
                            vv.source_var,
                            vv.source_line,
                            vv.hops
                            + [
                                TaintHop(
                                    kind="dotenv",
                                    line=dw.line,
                                    name=f"{dw.job}.{dw.name}",
                                    detail=(
                                        f"dotenv artefact of {dw.job} sets {dw.name} := ${vv.name}"
                                    ),
                                )
                            ],
                        ),
                    )
                    break

    def rule_inherited_var(db: Database):
        for ne in db.all(_R_NEEDS_EDGE):
            if not ne.artifacts:
                continue
            for td in db.all(_R_TAINTED_DOTENV):
                if td.producer == ne.producer:
                    yield (
                        _R_INHERITED_VAR,
                        _InheritedVar(ne.job, td.name, td.source_var, td.source_line, td.hops),
                    )

    return [
        rule_tainted_var,
        rule_visible_var,
        rule_tainted_dotenv,
        rule_inherited_var,
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze(content: str, lines: list[str]) -> list[TaintPath]:
    """Return every variables-mediated taint flow in a GitLab CI file.

    Each returned path carries ``kind``:

    * ``"shallow"`` — direct ``variables: { X: $CI_TAINTED }`` +
      ``script: $X`` (TAINT-GL-001).
    * ``"multi_hop"`` — at least one ``$OTHER`` indirection through a
      project-defined variable before the sink (TAINT-GL-002).
    * ``"dotenv"`` — a writer job's ``artifacts.reports.dotenv``
      propagates attacker-controlled bytes to a consumer job that
      ``needs:`` it (TAINT-GL-003).

    Rules filter on ``kind`` to attribute each finding to the right
    TAINT-GL-XXX rule.

    Implementation: the dataflow is a single relational fixed point
    (see :func:`_build_facts`); this function projects the saturated
    relations onto each job's script lines in file order.
    """
    if _taint_backend() == "structural":
        db, jobs = _build_facts_structural(content, lines)
    else:
        db, jobs = _build_facts(lines)
    out: list[TaintPath] = []
    for job in jobs:
        # Effective taint set for this job: the top-level cascade and
        # job-level ``variables:`` (already merged with precedence in
        # ``visible_var``), then dotenv taints inherited via ``needs:``
        # overlaid on top.
        visible: dict[str, _TaintInfo] = {}
        for vv in db.all(_R_VISIBLE_VAR):
            if vv.job == job.name:
                visible[vv.name] = _TaintInfo(vv.source_var, vv.source_line, vv.hops)
        for iv in db.all(_R_INHERITED_VAR):
            if iv.job == job.name:
                visible[iv.name] = _TaintInfo(iv.source_var, iv.source_line, iv.hops)
        if not visible:
            continue

        script_lines = [sl for sl in db.all(_R_SCRIPT_LINE) if sl.job == job.name]
        script_lines.sort(key=lambda sl: sl.line)
        for sl in script_lines:
            # The writer's own ``echo NAME=... > dotenv_file`` lines are
            # not traditional sinks — the bytes are written verbatim and
            # the downstream consumer is the real sink (caught via the
            # dotenv bridge).  Skipping prevents double-firing.
            if job.dotenv_file and _is_dotenv_write_line(sl.text, job.dotenv_file):
                continue
            for var, tinfo in visible.items():
                if _references_var(sl.text, var):
                    out.append(_make_path(tinfo, var, sl.line, sl.text))

        # Non-script: sink sites — a tainted variable expanded into a
        # job's ``image:`` / ``services.*`` image / runner ``tags:`` is
        # a taint flow in its own right (attacker-controlled image
        # pull, runner selection).  These carry ``sink_kind != "script"``
        # so the existing TAINT-GL-* rules are unaffected; new rules
        # opt in.  Emitted in source-line order.
        sites = sorted(
            (s for s in db.all(_R_SINK_SITE) if s.job == job.name),
            key=lambda s: (s.line, s.kind),
        )
        for site in sites:
            for var, tinfo in visible.items():
                if _references_var(site.value, var):
                    out.append(_make_path(tinfo, var, site.line, site.snippet, sink_kind=site.kind))
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


@dataclass
class _TaintInfo:
    """Internal: a resolved variable's taint provenance.

    Public surface is :class:`TaintPath`; we keep this internal struct
    so we don't construct the sink hop until we actually see a sink.
    """

    source_var: str
    source_line: int
    hops: list[TaintHop]


def _collect_top_level_var_assignments(
    lines: list[str],
) -> list[tuple[str, str, int]]:
    """Collect ``variables:`` assignments at the *top* of the YAML file
    (indent 0).  These cascade to every job.  Returns
    ``[(name, raw_value, 1-indexed_line), ...]`` in file order.

    Top-level ``variables:`` is identified by the header appearing at
    column 0.  Job-level variables (which can also exist at column 0
    inside a job block, but with their *parent* — the job key — also
    at column 0) are picked up by :func:`_collect_var_assignments_in_segment`
    when iterating each job's segment.

    For the top-level scan we look for ``^variables:\\s*$`` (zero
    indent) and walk children at indent > 0 until we leave the block.
    """
    out: list[tuple[str, str, int]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _VARIABLES_HEADER_RE.match(line)
        if not m or len(m.group(1)) != 0:
            i += 1
            continue
        # Found a top-level variables: header.  Walk children.
        j = i + 1
        while j < len(lines):
            child = lines[j]
            stripped = child.lstrip()
            if not stripped or stripped.startswith("#"):
                j += 1
                continue
            child_indent = len(child) - len(stripped)
            if child_indent == 0:
                break  # left the variables block (next top-level key)
            am = _VAR_ASSIGN_RE.match(child)
            if am:
                var = am.group(2)
                value = am.group(3).strip().strip('"').strip("'")
                out.append((var, value, j + 1))
            j += 1
        i = j
    return out


def _collect_var_assignments_in_segment(
    seg_lines: list[str], seg_start: int
) -> list[tuple[str, str, int]]:
    """Collect ``variables:`` assignments inside a single job segment.

    Job-level variables override the top-level cascade, and within the
    job they are visible to every script line.  We walk every
    ``variables:`` header in the segment (a job rarely has more than
    one, but ``include:``-d snippets etc. can cause weird shapes).
    """
    out: list[tuple[str, str, int]] = []
    i = 0
    while i < len(seg_lines):
        line = seg_lines[i]
        m = _VARIABLES_HEADER_RE.match(line)
        if not m:
            i += 1
            continue
        header_indent = len(m.group(1))
        j = i + 1
        while j < len(seg_lines):
            child = seg_lines[j]
            stripped = child.lstrip()
            if not stripped or stripped.startswith("#"):
                j += 1
                continue
            child_indent = len(child) - len(stripped)
            if child_indent <= header_indent:
                break
            am = _VAR_ASSIGN_RE.match(child)
            if am:
                var = am.group(2)
                value = am.group(3).strip().strip('"').strip("'")
                out.append((var, value, seg_start + j + 1))
            j += 1
        i = j
    return out


def _extract_var_ref(value: str) -> str | None:
    """Return the inner variable name if ``value`` is a pure bash
    variable reference (``$OTHER`` or ``${OTHER}``); otherwise ``None``.

    Deliberately strict: only a standalone reference to a single
    variable propagates taint.  Values that mix a reference with other
    text (``$A-suffix``, ``prefix-${A}``) are treated as non-propagating
    because the user-inserted fragment changes the semantics — we keep
    the resolver conservative, same trade-off as the GitHub analyzer's
    ``_extract_env_ref``.
    """
    s = value.strip()
    # Remove matched surrounding quotes if present.
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        s = s[1:-1]
    m = re.fullmatch(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", s)
    return m.group(1) if m else None


def _iter_script_lines(seg_lines: list[str], seg_start: int) -> list[tuple[int, str]]:
    """Yield ``(1-indexed_line, stripped_text)`` for every line whose
    text participates in a ``script:`` / ``before_script:`` /
    ``after_script:`` shell body inside the segment.

    Handles both shapes: list-block (``script:`` header followed by
    ``- cmd`` children) and inline (``script: echo hi``).
    """
    out: list[tuple[int, str]] = []
    i = 0
    while i < len(seg_lines):
        line = seg_lines[i]

        # Inline: ``script: echo hi`` (one-liner).
        im = _SCRIPT_INLINE_RE.match(line)
        if im:
            # Make sure we don't double-process a header where the
            # value starts on the next line — inline match requires a
            # non-empty captured value group.
            value = im.group(2)
            if value and not value.startswith(("|", ">")):
                out.append((seg_start + i + 1, value.strip()))
                i += 1
                continue

        m = _SCRIPT_HEADER_RE.match(line)
        if not m:
            i += 1
            continue
        header_indent = len(m.group(1))
        j = i + 1
        while j < len(seg_lines):
            child = seg_lines[j]
            stripped = child.lstrip()
            if not stripped or stripped.startswith("#"):
                j += 1
                continue
            child_indent = len(child) - len(stripped)
            # A ``- cmd`` list item AT header_indent is a valid same-indent
            # YAML block sequence (``script:`` then ``- cmd`` at the same
            # column) and must NOT end the block.  Only a dedent, or a
            # sibling key sitting at the header indent, terminates it.
            is_list_item = stripped.startswith("- ") or stripped.startswith("-\t")
            if child_indent < header_indent or (child_indent == header_indent and not is_list_item):
                break
            # The script value is typically a YAML list item: ``- cmd``.
            # Strip the leading ``- `` so the snippet shows the command,
            # not the YAML decoration.
            text = stripped
            if is_list_item:
                text = text[2:].strip()
            out.append((seg_start + j + 1, text))
            j += 1
        i = j
    return out


def _references_var(line: str, var: str) -> bool:
    """Return True if ``line`` references shell variable ``var``.

    Accepts ``$VAR``, ``${VAR}``, and the Windows-runner ``%VAR%``
    form.  Word-boundary anchored so ``$VARIANT`` does not match
    ``VAR``.
    """
    patterns = [
        rf"\$\{{{var}\b",  # ${VAR...
        rf"\${var}\b",  # $VAR
        rf"%{var}%",  # %VAR% (Windows runners)
    ]
    return any(re.search(p, line) for p in patterns)


def _classify_kind(hops: list[TaintHop]) -> str:
    """Pick the ``TaintPath.kind`` label from the chain's hop kinds.

    Priority (highest -> lowest): ``dotenv`` > ``multi_hop`` >
    ``shallow``.  A chain containing *any* ``dotenv`` hop is reported
    as ``"dotenv"`` — the cross-job bridge is the most damning
    transition and is what TAINT-GL-003 needs to surface.  Any
    ``var_indirect`` hop (a ``B: $A`` laundering step) upgrades
    ``"shallow"`` to ``"multi_hop"``.  A chain of only ``var_static``
    hops is the original ``"shallow"`` flow handled by TAINT-GL-001.
    """
    if any(h.kind == "dotenv" for h in hops):
        return "dotenv"
    if any(h.kind == "var_indirect" for h in hops):
        return "multi_hop"
    return "shallow"


# Human-readable label per sink kind, used in the terminal hop detail.
_SINK_LABEL = {
    "script": "script:",
    "image": "image:",
    "service_image": "services.*.image:",
    "tags": "tags:",
}


def _make_path(
    info: _TaintInfo,
    laundered: str,
    sink_line: int,
    sink_snippet: str,
    sink_kind: str = "script",
) -> TaintPath:
    label = _SINK_LABEL.get(sink_kind, "script:")
    sink_hop = TaintHop(
        kind="sink",
        line=sink_line,
        name=laundered,
        detail=f"{label} references ${laundered}",
    )
    return TaintPath(
        source_var=info.source_var,
        source_line=info.source_line,
        laundered_var=laundered,
        sink_line=sink_line,
        sink_snippet=sink_snippet,
        kind=_classify_kind(info.hops),
        hops=info.hops + [sink_hop],
        sink_kind=sink_kind,
    )


# ---------------------------------------------------------------------------
# Per-job structural helpers (job name, dotenv file, needs:)
# ---------------------------------------------------------------------------


def _extract_job_name(seg_lines: list[str]) -> str | None:
    """Return the job's name (the 0-indent key that starts the segment)
    or ``None`` when the segment is pre-job content (top-level
    ``stages:``, ``variables:``, ``include:``, etc.).

    GitLab's YAML allows any top-level key that is not a reserved
    keyword to be treated as a job.  ``_split_into_job_segments``
    already lumps every reserved top-level block into the first
    segment, so we just read the first 0-indent key and filter out
    the keyword case to stay safe against odd files.
    """
    for line in seg_lines:
        if not line or line[0] in (" ", "\t"):
            continue
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _JOB_NAME_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        if name in _RESERVED_GITLAB_TOP_KEYS:
            return None
        return name
    return None


def _extract_dotenv_filename(seg_lines: list[str]) -> str | None:
    """Return the filename declared under ``artifacts.reports.dotenv:``,
    or ``None`` if the job doesn't produce a dotenv artefact.

    Supports both the inline single-filename form
    (``dotenv: build.env``) and the list form
    (``dotenv:\\n  - build.env``).  When the list has more than one
    entry we return the first — good enough for the writer / consumer
    linking because the same job produces all listed files and the
    caller uses the filename to filter its own script lines, not to
    claim every possible dotenv write.
    """
    # Walk until we see ``artifacts:`` at any indent.
    i = 0
    while i < len(seg_lines):
        m = _ARTIFACTS_HEADER_RE.match(seg_lines[i])
        if not m:
            i += 1
            continue
        art_indent = len(m.group(1))
        # Look for ``reports:`` child with indent > art_indent.
        j = i + 1
        while j < len(seg_lines):
            child = seg_lines[j]
            stripped = child.lstrip()
            if not stripped or stripped.startswith("#"):
                j += 1
                continue
            child_indent = len(child) - len(stripped)
            if child_indent <= art_indent:
                break
            rm = _REPORTS_HEADER_RE.match(child)
            if not rm:
                j += 1
                continue
            rep_indent = len(rm.group(1))
            # Now look for ``dotenv:`` under reports.
            k = j + 1
            while k < len(seg_lines):
                inner = seg_lines[k]
                inner_stripped = inner.lstrip()
                if not inner_stripped or inner_stripped.startswith("#"):
                    k += 1
                    continue
                inner_indent = len(inner) - len(inner_stripped)
                if inner_indent <= rep_indent:
                    break
                dim = _DOTENV_INLINE_RE.match(inner)
                if dim:
                    return dim.group("file")
                dh = _DOTENV_HEADER_RE.match(inner)
                if dh:
                    # Walk list items.
                    dotenv_indent = len(dh.group(1))
                    m2 = k + 1
                    while m2 < len(seg_lines):
                        item = seg_lines[m2]
                        istripped = item.lstrip()
                        if not istripped or istripped.startswith("#"):
                            m2 += 1
                            continue
                        iindent = len(item) - len(istripped)
                        if iindent <= dotenv_indent:
                            break
                        li = _DOTENV_LIST_ITEM_RE.match(item)
                        if li:
                            return li.group("file")
                        m2 += 1
                k += 1
            j = k
        i = j
    return None


def _extract_needs(
    seg_lines: list[str],
) -> list[tuple[str, bool]]:
    """Parse the job's ``needs:`` list.

    Returns ``[(producer_name, artifacts_inherited), ...]``.  When a
    job is declared with either the bare-string form
    (``needs: [build]``) or the mapping form without an explicit
    ``artifacts:`` key, we default to ``artifacts_inherited=True``
    because that matches GitLab's own default for ``needs:``.  An
    explicit ``artifacts: false`` opts out of inheritance.

    Inline list form (``needs: [a, b]``) is also supported — entries
    are bare strings only in that shape.
    """
    out: list[tuple[str, bool]] = []

    i = 0
    while i < len(seg_lines):
        line = seg_lines[i]

        # Inline form: ``needs: [build, test]``.
        inline_m = _NEEDS_INLINE_RE.match(line)
        if inline_m:
            raw = inline_m.group("inline")
            for piece in raw.split(","):
                piece = piece.strip().strip('"').strip("'")
                if piece:
                    out.append((piece, True))
            i += 1
            continue

        header_m = _NEEDS_HEADER_RE.match(line)
        if not header_m:
            i += 1
            continue
        header_indent = len(header_m.group(1))
        j = i + 1
        current_name: str | None = None
        current_artifacts: bool = True
        while j < len(seg_lines):
            child = seg_lines[j]
            stripped = child.lstrip()
            if not stripped or stripped.startswith("#"):
                j += 1
                continue
            child_indent = len(child) - len(stripped)
            if child_indent <= header_indent:
                break

            bare = _NEEDS_BARE_ITEM_RE.match(child)
            jobm = _NEEDS_JOB_ITEM_RE.match(child)
            if bare:
                if current_name is not None:
                    out.append((current_name, current_artifacts))
                current_name = bare.group("name")
                current_artifacts = True
                j += 1
                continue
            if jobm:
                if current_name is not None:
                    out.append((current_name, current_artifacts))
                current_name = jobm.group("name")
                current_artifacts = True
                j += 1
                continue
            art = _NEEDS_ARTIFACTS_RE.match(child)
            if art and current_name is not None:
                current_artifacts = art.group("val") == "true"
                j += 1
                continue
            j += 1
        if current_name is not None:
            out.append((current_name, current_artifacts))
        i = j
    return out


def _is_dotenv_write_line(sink_snippet: str, dotenv_file: str) -> bool:
    """Return True if ``sink_snippet`` redirects into the job's
    declared dotenv artefact file.

    Used by :func:`analyze` to exclude the writer's own
    ``echo "NAME=$RAW" > dotenv_file`` lines from the generic sink
    scan — shell expansion inside an echo-to-file does not execute
    attacker-controlled bytes, the runner's dotenv parser is the real
    consumer, and a downstream script line is where the attacker's
    value lands in a shell.
    """
    for m in _ECHO_ASSIGN_TO_FILE_RE.finditer(sink_snippet):
        if m.group("file") == dotenv_file:
            return True
    return False
