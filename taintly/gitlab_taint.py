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

import re
from dataclasses import dataclass, field

from .models import _split_into_job_segments

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
    "CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME",
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
    variable into a script line."""

    source_var: str  # e.g. "CI_COMMIT_TITLE"
    source_line: int  # 1-indexed line of the variables: assignment
    laundered_var: str  # the user-named variable that carries the taint
    sink_line: int  # 1-indexed line of the script: content
    sink_snippet: str  # literal text of that script line, stripped
    kind: str = "shallow"
    hops: list[TaintHop] = field(default_factory=list)


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

    Two-pass because the dotenv bridge is cross-job: we first walk
    every job to collect what it would contribute to its consumers
    (both the ``visible`` env that reaches its own scripts AND any
    ``NAME`` it writes into its declared dotenv artefact).  Then we
    walk the jobs again, this time as consumers, merging inherited
    dotenv taints from every writer referenced by ``needs:`` and
    scanning each job's scripts for sinks.
    """
    out: list[TaintPath] = []

    # Top-level variables: cascade to every job.  Resolve them once.
    top_level = _collect_top_level_var_assignments(lines)
    top_taints = _resolve_var_taints(top_level)

    # Pass 1 — per-job metadata + dotenv writes produced by each job.
    #
    # ``job_infos`` is a list (not a dict) so we preserve file order,
    # and we key dotenv-write lookups by job name in a separate dict
    # (``dotenv_produced``).  Pre-job segments (stages:, variables:,
    # etc.) have no name and are skipped.
    job_infos: list[_JobInfo] = []
    dotenv_produced: dict[str, dict[str, _TaintInfo]] = {}

    for seg_start, seg_lines in _split_into_job_segments(lines):
        name = _extract_job_name(seg_lines)
        if name is None:
            continue
        job_assignments = _collect_var_assignments_in_segment(seg_lines, seg_start)
        job_taints = _resolve_var_taints(job_assignments, base=top_taints)
        visible = {**top_taints, **job_taints}

        dotenv_file = _extract_dotenv_filename(seg_lines)
        dotenv_writes: dict[str, _TaintInfo] = {}
        if dotenv_file is not None:
            dotenv_writes = _detect_dotenv_writes(seg_lines, seg_start, visible, dotenv_file, name)
            dotenv_produced[name] = dotenv_writes

        job_infos.append(
            _JobInfo(
                name=name,
                seg_start=seg_start,
                seg_lines=seg_lines,
                visible=visible,
                dotenv_file=dotenv_file,
                dotenv_writes=dotenv_writes,
                needs=_extract_needs(seg_lines),
            )
        )

    # Pass 2 — scan each job's scripts for sinks.
    for info in job_infos:
        # Merge in dotenv taints inherited via ``needs:`` (skip entries
        # that opt out with ``artifacts: false``).
        inherited: dict[str, _TaintInfo] = {}
        for producer_name, artifacts_inherited in info.needs:
            if not artifacts_inherited:
                continue
            inherited.update(dotenv_produced.get(producer_name, {}))
        visible = {**info.visible, **inherited}
        if not visible:
            continue

        for sink_line, sink_snippet in _iter_script_lines(info.seg_lines, info.seg_start):
            # The writer's own ``echo NAME=... > dotenv_file`` lines are
            # NOT traditional sinks — the double-quoted shell expansion
            # inside an echo-to-file is safe; the bytes are written
            # verbatim.  The real sink is the downstream consumer, which
            # this two-pass model catches.  Skipping here prevents
            # double-firing TAINT-GL-001/002 on the write line on top
            # of TAINT-GL-003 on the read line.
            if info.dotenv_file and _is_dotenv_write_line(sink_snippet, info.dotenv_file):
                continue
            for var, tinfo in visible.items():
                if _references_var(sink_snippet, var):
                    out.append(_make_path(tinfo, var, sink_line, sink_snippet))
    return out


@dataclass
class _JobInfo:
    """Internal: per-job state collected in pass 1 and consumed in
    pass 2 of :func:`analyze`.
    """

    name: str
    seg_start: int
    seg_lines: list[str]
    visible: dict[str, _TaintInfo]
    dotenv_file: str | None
    dotenv_writes: dict[str, _TaintInfo]
    needs: list[tuple[str, bool]]


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


def _resolve_var_taints(
    assignments: list[tuple[str, str, int]],
    base: dict[str, _TaintInfo] | None = None,
) -> dict[str, _TaintInfo]:
    """Resolve which user-named variables carry attacker-controlled data.

    Handles two cases, via fixed-point iteration so declaration order
    inside the ``variables:`` block does not matter:

    * **Direct** — value contains a ``$CI_<tainted>`` reference.  The
      user-named var inherits that taint with a ``"var_static"`` hop.
    * **Indirect (multi-hop)** — value is ``$OTHER`` (or
      ``${OTHER}``) where ``OTHER`` has already been resolved as
      tainted.  The user-named var inherits the *existing* provenance
      chain, extended by a ``"var_indirect"`` hop so the reviewer can
      see every launderer in the chain.

    ``base`` seeds the resolver with already-known taints from an
    *outer* scope (e.g. top-level cascade for a job-level resolve) so
    job-level ``variables:`` can multi-hop against top-level ones.
    The returned dict merges ``base`` with the newly-resolved entries;
    when a var is assigned in both scopes, the inner-scope chain wins
    (standard YAML override semantics for ``variables:``).
    """
    base = dict(base or {})
    resolved: dict[str, _TaintInfo] = {}
    changed = True
    while changed:
        changed = False
        for var, value, line in assignments:
            if var in resolved:
                continue
            # (a) Direct tainted CI variable.
            m = _TAINTED_REF_RE.search(value)
            if m is not None:
                source = m.group(1)
                resolved[var] = _TaintInfo(
                    source_var=source,
                    source_line=line,
                    hops=[
                        TaintHop(
                            kind="var_static",
                            line=line,
                            name=var,
                            detail=f"variables.{var} := ${source}",
                        )
                    ],
                )
                changed = True
                continue
            # (b) Multi-hop: pure ``$OTHER`` reference where OTHER is
            #     already tainted (either seeded from base or resolved
            #     on an earlier iteration of this loop).
            other = _extract_var_ref(value)
            if not other:
                continue
            parent = resolved.get(other) or base.get(other)
            if parent is None:
                continue
            resolved[var] = _TaintInfo(
                source_var=parent.source_var,
                source_line=parent.source_line,
                hops=parent.hops
                + [
                    TaintHop(
                        kind="var_indirect",
                        line=line,
                        name=var,
                        detail=f"variables.{var} := ${other}",
                    )
                ],
            )
            changed = True
    # Inner-scope wins: start from base, then overlay our resolutions.
    return {**base, **resolved}


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
            if child_indent <= header_indent:
                break
            # The script value is typically a YAML list item: ``- cmd``.
            # Strip the leading ``- `` so the snippet shows the command,
            # not the YAML decoration.
            text = stripped
            if text.startswith("- ") or text.startswith("-\t"):
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


def _make_path(
    info: _TaintInfo,
    laundered: str,
    sink_line: int,
    sink_snippet: str,
) -> TaintPath:
    sink_hop = TaintHop(
        kind="sink",
        line=sink_line,
        name=laundered,
        detail=f"script: references ${laundered}",
    )
    return TaintPath(
        source_var=info.source_var,
        source_line=info.source_line,
        laundered_var=laundered,
        sink_line=sink_line,
        sink_snippet=sink_snippet,
        kind=_classify_kind(info.hops),
        hops=info.hops + [sink_hop],
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


def _detect_dotenv_writes(
    seg_lines: list[str],
    seg_start: int,
    visible_env: dict[str, _TaintInfo],
    dotenv_file: str,
    producer_job: str,
) -> dict[str, _TaintInfo]:
    """Find ``echo "NAME=VALUE" > <dotenv_file>`` writes in the
    writer's script.

    Returns ``{NAME: _TaintInfo}`` for every write whose ``VALUE``
    carries attacker-controlled data — either a direct
    ``$CI_<tainted>`` reference embedded in the echo string, or a
    shell reference to an already-tainted variable in
    ``visible_env``.

    Only echo lines whose redirect target equals ``dotenv_file`` are
    treated as dotenv writes.  Writes into arbitrary unrelated files
    (``echo log=hi > /tmp/log``) are ignored here.

    Symmetrical to the GitHub ``_detect_github_env_writes`` helper —
    same quoting rules (single-quoted shell refs don't propagate
    through ``'$RAW'``; direct ``$CI_<tainted>`` references inside
    single quotes still do because GitLab's runner doesn't re-expand
    once the shell has written the line).  Both quote styles are
    treated the same at the NAME=VALUE level.
    """
    out: dict[str, _TaintInfo] = {}
    for sink_line, sink_snippet in _iter_script_lines(seg_lines, seg_start):
        for m in _ECHO_ASSIGN_TO_FILE_RE.finditer(sink_snippet):
            if m.group("file") != dotenv_file:
                continue
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
            if not am:
                continue
            name, value = am.group(1), am.group(2)

            info = _build_dotenv_taint(
                name,
                value,
                visible_env,
                sink_line,
                producer_job,
                quoted_single,
            )
            if info is not None:
                out[name] = info
    return out


def _build_dotenv_taint(
    name: str,
    value: str,
    visible_env: dict[str, _TaintInfo],
    lineno: int,
    producer_job: str,
    quoted_single: bool,
) -> _TaintInfo | None:
    """Classify the taint that flows into a dotenv-written variable,
    if any.  Returns ``None`` when the value carries no
    attacker-controlled data.

    A successful match extends the existing provenance chain (either
    a direct ``$CI_<tainted>`` source or the chain of the referenced
    ``visible_env`` entry) with a ``"dotenv"`` hop tagged with the
    producer job name so the downstream sink renderer can show the
    full bridge.
    """
    # (a) Direct tainted CI variable embedded in the echo body.
    m = _TAINTED_REF_RE.search(value)
    if m is not None:
        source = m.group(1)
        return _TaintInfo(
            source_var=source,
            source_line=lineno,
            hops=[
                TaintHop(
                    kind="dotenv",
                    line=lineno,
                    name=f"{producer_job}.{name}",
                    detail=(f"dotenv artefact of {producer_job} sets {name} := ${source}"),
                )
            ],
        )

    # (b) Indirect: shell reference to an already-tainted visible
    # variable.  Skip if single-quoted — bash doesn't expand ``$RAW``
    # inside single quotes, so the attacker's bytes don't propagate.
    if quoted_single:
        return None
    for var, info in visible_env.items():
        if _references_var(value, var):
            return _TaintInfo(
                source_var=info.source_var,
                source_line=info.source_line,
                hops=info.hops
                + [
                    TaintHop(
                        kind="dotenv",
                        line=lineno,
                        name=f"{producer_job}.{name}",
                        detail=(f"dotenv artefact of {producer_job} sets {name} := ${var}"),
                    )
                ],
            )
    return None
