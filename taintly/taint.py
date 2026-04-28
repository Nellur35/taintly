"""Taint analysis for GitHub Actions workflows.

Scope — catches five kinds of env-mediated flows from attacker-
controlled GitHub contexts into shell sinks:

1. **Shallow** (TAINT-GH-001, ``kind="shallow"``):

       env: VAR: ${{ <attacker-controlled context> }}
       run: ... $VAR / ${VAR} / ${{ env.VAR }} ...

2. **Multi-hop env propagation** (TAINT-GH-002, ``kind="multi_hop"``):

       env:
         A: ${{ <attacker-controlled context> }}
         B: ${{ env.A }}          # indirect — depends on A
         C: ${{ env.B }}          # transitive — depends on B
       run: echo "$C"

   A chain of any depth through ``${{ env.X }}`` references is resolved
   by fixed-point iteration, so ``A -> B -> C -> D -> ... -> run: $X``
   is caught in a single pass.

3. **Dynamic ``$GITHUB_ENV`` writes** (TAINT-GH-003, ``kind="github_env"``):

       # step 1 launders a tainted value into $GITHUB_ENV ...
       - env: {RAW: ${{ github.event.pull_request.title }}}
         run: echo "TITLE=$RAW" >> $GITHUB_ENV
       # ... step 2 then runs with $TITLE in its environment.
       - run: echo "$TITLE"

   Propagation is order-sensitive: a write in step N taints the env
   var for steps N+1 .. end of job, never the step that performed the
   write itself (that's how the Actions runner materialises
   ``$GITHUB_ENV`` between steps).  The analyzer iterates steps in
   file order and maintains a running ``dynamic_env`` dict to carry
   these taints forward.

4. **Step output chains** (TAINT-GH-004, ``kind="step_output"``):

       - id: write
         env: {RAW: ${{ github.event.issue.title }}}
         run: echo "name=$RAW" >> $GITHUB_OUTPUT
       - run: echo "${{ steps.write.outputs.name }}"

   Same order-sensitivity as ``$GITHUB_ENV``: a write in step N is
   visible to ``${{ steps.<id>.outputs.<name> }}`` in steps N+1
   onward, never inside the writing step itself.  Both the
   ``echo "k=v" >> $GITHUB_OUTPUT`` and the legacy
   ``echo "::set-output name=k::v"`` shapes are recognised, in every
   common quoting / brace variant.  The analyzer maintains an
   ``output_taints`` dict keyed by ``"<step_id>.<output_name>"``.

5. **AI coding-agent step outputs** (TAINT-GH-005, ``kind="agent_output"``):

       - uses: anthropics/claude-code-action@v1
         id: review
       - run: echo "${{ steps.review.outputs.summary }}"

   Source-side synthesis: a step whose ``uses:`` matches a known
   agent action (see :data:`_AGENT_USES_RE`) is registered as a
   taint source even though no ``$GITHUB_OUTPUT`` write is visible
   in the YAML — the agent emits its declared outputs at runtime,
   and any prompt-injection payload reaching the model lands in
   those bytes.  Provenance starts at the agent package name
   (``agent:<owner>/<repo>``) instead of at a github.event.* field.

6. **Cross-job ``needs.<j>.outputs.<n>``** (TAINT-GH-009, ``kind="cross_job"``):

       jobs:
         produce:
           outputs:
             title: ${{ github.event.pull_request.title }}
           steps: ...
         consume:
           needs: produce
           steps:
             - run: echo "${{ needs.produce.outputs.title }}"

   The cross-job analog of TAINT-GH-004.  :func:`analyze` runs a
   first pass that iterates each job's dataflow against an evolving
   ``{(producer_job, output_name): _TaintInfo}`` map until the map
   stabilises (transitive A→B→C chains converge in O(declared
   outputs) iterations).  The second pass emits sink findings
   using the converged map, including:

      * direct ``${{ needs.<j>.outputs.<n> }}`` substitutions inside
        ``run:`` lines (server-side substitution, not shell-quote
        sensitive — same shape as TAINT-GH-004);
      * env-mediated consumer-side flows where the cross-job
        reference appears in an ``env:`` value and the variable is
        later interpolated in a ``run:`` line.

Precision notes:

* **Shell-quoting awareness.** Sinks inside single quotes are
  dropped — bash never interpolates there.  Double-quoted and
  unquoted references are still treated as sinks (attackers can
  break out of double quotes via embedded ``"`` plus
  metacharacters).  Implementation: :func:`_shell_quote_context_at`.
  Known gaps live in the "out of scope" list below.
* **Compound expressions.** ``${{ github.head_ref || github.ref }}``
  and similar fallback forms are recognised by scanning inside any
  ``${{ ... }}`` body for a tainted context, not just exact matches.
* **Same-step self-reference suppression.** Both ``$GITHUB_ENV`` and
  ``$GITHUB_OUTPUT`` taint dicts are updated *after* the current
  step's sinks are evaluated, matching runner semantics.

Attacker-controlled sources (``github.event.pull_request.title``,
``github.head_ref``, ``github.event.comment.body``, ...) are enumerated
in :data:`_TAINTED_CONTEXTS` and kept in sync with ``SEC4-GH-004``.

Cross-workflow taint (TAINT-GH-006 callee-side, TAINT-GH-007 caller-
side) is handled by the rule layer (``taintly.rules.github.taint``)
using structural patterns rather than this dataflow analyzer; the two
share the same source-context list.

Still out of scope (future deep-taint work):

* ``workflow_call`` callee-side dataflow: TAINT-GH-006 surfaces the
  ``${{ inputs.X }}`` reference for review, but the analyzer does
  not propagate caller-passed taint into the callee's run: blocks.
* ``workflow_run`` artefact / state propagation between the
  triggering and triggered workflow (the run-time inheritance, not
  the YAML-level one TAINT-GH-008 already catches).
* Artefact / cache / file-system propagation across jobs (a step
  writing an attacker-controlled value to a file that a later
  step reads).  Cross-job *expression-level* propagation
  (``needs.<j>.outputs.<n>``) IS handled by TAINT-GH-009.
* Cross-job sinks other than ``run:`` — ``runs-on:``,
  ``container.image:``, ``strategy.matrix:`` and ``if:`` can also
  consume ``${{ needs.X.outputs.Y }}`` and each carries its own
  attack class (self-hosted runner hijack, attacker-image pull,
  matrix DoS, gate suppression).  These are tracked as separate
  rule shapes, not subsumed under TAINT-GH-009.
* Heredocs and multi-line string continuations —
  :func:`_shell_quote_context_at` operates on a single line and
  cannot carry quoting state across the lines of a ``run: |``
  block.  ANSI-C ``$'...'`` quoting is handled now (it collapses
  into the ``"single"`` non-interpolating state).
* Heredoc / piped / ``printf`` shapes of ``$GITHUB_ENV`` and
  ``$GITHUB_OUTPUT`` writes.  The detectors match the canonical
  ``echo "NAME=VALUE" >> $GITHUB_{ENV,OUTPUT}`` pattern (in every
  quoting / brace variant), which covers the vast majority of
  real workflows; exotic shapes fall through.

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

# Attacker-controlled GitHub contexts.  Intentionally enumerated; keep in sync
# with the SEC4-GH-004 regex.
_TAINTED_CONTEXTS = [
    r"github\.event\.pull_request\.title",
    r"github\.event\.pull_request\.body",
    r"github\.event\.pull_request\.head\.ref",
    r"github\.event\.pull_request\.head_ref",
    r"github\.event\.pull_request\.user\.login",
    r"github\.event\.issue\.title",
    r"github\.event\.issue\.body",
    r"github\.event\.comment\.body",
    r"github\.event\.review\.body",
    r"github\.event\.head_commit\.message",
    r"github\.event\.head_commit\.author\.name",
    r"github\.event\.head_commit\.author\.email",
    r"github\.head_ref",
    r"github\.event\.workflow_run\.head_branch",
]

_TAINTED_RE = re.compile(r"\$\{\{\s*(?:" + "|".join(_TAINTED_CONTEXTS) + r")\s*\}\}")

# Match ANY ``${{ ... }}`` substitution so the detector can look inside
# for a tainted context reference.  Real workflows routinely wrap
# taint in compound expressions — ``${{ github.head_ref || github.ref
# }}``, ``${{ github.event.pull_request.title || '' }}``, etc. — which
# ``_TAINTED_RE`` above rejects because it requires the tainted context
# to be the *entire* substitution body.  Missing those flows is a huge
# false-negative: ``||`` fallback is the idiomatic way to default a PR
# context, and when the attacker sets the lhs the rhs is never taken.
_GHA_EXPR_RE = re.compile(r"\$\{\{\s*(.+?)\s*\}\}", re.DOTALL)

# Inner matcher applied to the body of each ``${{ ... }}`` expression
# found by ``_GHA_EXPR_RE``.  Word boundaries keep ``github.head_ref``
# from matching inside a longer dotted path like ``github.head_ref_foo``
# (hypothetical — keeps us forward-compatible with unknown contexts).
_TAINTED_IN_EXPR_RE = re.compile(r"\b(?:" + "|".join(_TAINTED_CONTEXTS) + r")\b")

# ``${{ env.VAR }}`` — indirect reference used by multi-hop chains.
_ENV_REF_RE = re.compile(r"\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")

# ``${{ steps.<id>.outputs.<name> }}`` — reference to a step output.
# Step IDs and output names allow underscores and hyphens per the GitHub
# Actions name validation rules.
_STEP_OUTPUT_REF_RE = re.compile(
    r"\$\{\{\s*steps\.([A-Za-z_][A-Za-z0-9_-]*)"
    r"\.outputs\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}"
)

# ``${{ needs.<job>.outputs.<name> }}`` — cross-job reference to another
# job's declared output. Job IDs follow the same name rules as step IDs.
# This is the cross-job analog of ``_STEP_OUTPUT_REF_RE``: the consumer
# job sees the producer's declared output as a server-side substitution
# at workflow-parse time, so attacker bytes land in the run: text the
# same way they would for a same-job step output reference.
_NEEDS_OUTPUT_REF_RE = re.compile(
    r"\$\{\{\s*needs\.([A-Za-z_][A-Za-z0-9_-]*)"
    r"\.outputs\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}"
)

# Line with an env assignment: ``  NAME: value``.  We don't anchor the indent
# because env lives both at step level (6 spaces) and job level (4 spaces)
# depending on style; job-segment scoping keeps this tractable.
_ENV_ASSIGN_RE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?)\s*$")

# ``run:`` step block — either inline ``run: foo`` or block-scalar
# ``run: |`` / ``run: >``.  We allow an optional YAML list-item marker
# (``- ``) before the key for steps that place the key on the same line as
# the bullet.  The captured indent is the column of the key itself so that
# child indent comparisons behave consistently.
_RUN_INLINE_RE = re.compile(r"^(\s*(?:-\s+)?)run\s*:\s*(.+?)\s*$")
_RUN_BLOCK_RE = re.compile(r"^(\s*(?:-\s+)?)run\s*:\s*[|>][+-]?\s*$")

# ``env:`` header — value empty, children follow at deeper indent.
_ENV_HEADER_RE = re.compile(r"^(\s*(?:-\s+)?)env\s*:\s*$")

# Redirect onto ``$GITHUB_ENV`` in any common quoting / brace form:
#   >> $GITHUB_ENV
#   >> "$GITHUB_ENV"
#   >> ${GITHUB_ENV}
#   >> "${GITHUB_ENV}"
#   > $GITHUB_ENV (rare overwrite form)
#
# Used by both :func:`_analyze_job` (to skip these lines as traditional
# sinks — shell expansion inside an echo-to-file is safe) and
# :func:`_detect_github_env_writes` (the dedicated detector).
_GITHUB_ENV_REDIRECT_RE = re.compile(r">>?\s*[\"']?\$\{?GITHUB_ENV\}?[\"']?")

# Same shape as ``_GITHUB_ENV_REDIRECT_RE`` but for ``$GITHUB_OUTPUT``.
# Step output writes follow the identical syntax — only the variable
# name differs — so we keep the two redirects symmetrical.
_GITHUB_OUTPUT_REDIRECT_RE = re.compile(r">>?\s*[\"']?\$\{?GITHUB_OUTPUT\}?[\"']?")

# Single source of truth for the AI coding-agent keyword alternation.
# Every detector that needs to recognise an agent-action ``uses:`` line
# imports from here so the keyword list lives in exactly one place.
# Consumers: TAINT-GH-005 (this module's ``_AGENT_USES_RE``), AI-GH-005,
# AI-GH-006, AI-GH-008, AI-GH-014 (anchors in ``rules/github/ai.py``),
# and PSE-GH-001 (anchor in ``rules/github/pse.py``).
#
# Add a new agent action HERE only — the import surface fans the change
# out to every callsite at once, so the drift risk that motivated this
# extraction stays closed.
AI_AGENT_KEYWORDS = (
    r"claude-code|aider|openhands|coderabbit|cursor-?(?:bot|action)"
    r"|ai-review|gpt-pr|ai-code-review|openai-action|anthropic-action"
    r"|llm-agent"
)

# The canonical ``uses: <owner>/<repo-with-keyword>@<rev>`` pattern.
# Drop into a larger regex via f-string substitution:
#
#   anchor = rf"... |{AI_AGENT_USES_PATTERN}| ..."
#
# No capturing parens — call sites that need the action name wrap the
# capturing region themselves (see ``_AGENT_USES_RE`` below).
AI_AGENT_USES_PATTERN = (
    r"uses:\s+[^@\s/]+/[^@\s]*"
    rf"(?:{AI_AGENT_KEYWORDS})"
    r"[^@\s]*@"
)

# AI coding-agent ``uses:`` shape with the action name captured.
# A step referencing one of these actions produces outputs whose bytes
# are attacker-shaped whenever a prompt-injection payload reaches the
# agent (via PR body, comment, review, or the agent's own read tools).
# Treating such a step as a taint source lets TAINT-GH-005 emit a
# provenance chain starting at the agent's package name instead of at
# an unknown "$GITHUB_OUTPUT write" — the agent never actually calls
# ``echo ... >> $GITHUB_OUTPUT``, so the existing step-output detector
# misses these flows.
_AGENT_USES_RE = re.compile(rf"uses:\s+([^@\s/]+/[^@\s]*(?:{AI_AGENT_KEYWORDS})[^@\s]*)@")


# ---------------------------------------------------------------------------
# Public data model
# ---------------------------------------------------------------------------


@dataclass
class TaintHop:
    """One step in a taint provenance chain.

    ``kind`` identifies the kind of propagation that happened at this
    hop, so a reader of the chain can reconstruct why the final sink
    was considered tainted.
    """

    kind: str
    # Valid values:
    #   "env_static"   — env: VAR: ${{ tainted }} assignment.
    #   "env_indirect" — env: VAR: ${{ env.OTHER }} indirection.
    #   "github_env"   — echo "NAME=..." >> $GITHUB_ENV bridge.
    #   "step_output"  — echo "name=..." >> $GITHUB_OUTPUT / ::set-output bridge.
    #   "agent_output" — synthesized AI-agent step output (TAINT-GH-005).
    #   "job_output"   — producer job's declared outputs: <name>: <expr>
    #                    that resolved to attacker-controlled (TAINT-GH-009).
    #   "needs_ref"    — consumer job references the producer via
    #                    ${{ needs.<j>.outputs.<n> }} (TAINT-GH-009).
    #   "sink"         — terminal hop: the run: line that consumes the taint.
    line: int  # 1-indexed line in the source file
    name: str  # variable / output name at this hop
    detail: str  # human-readable description


@dataclass
class TaintPath:
    """A detected end-to-end taint flow from an attacker-controlled
    source into a ``run:`` block.

    ``kind`` summarises the chain so rules can filter on a specific
    propagation style (``"shallow"`` for TAINT-GH-001, ``"multi_hop"``
    for TAINT-GH-002, ...).  ``hops`` carries the per-step provenance
    so reviewers see exactly how the taint propagated.
    """

    source_expr: str  # e.g. "github.event.pull_request.title"
    source_line: int  # 1-indexed line of the first env assignment
    env_var: str  # name of the variable/output at the sink hop
    sink_line: int  # 1-indexed line of the run: content
    sink_snippet: str  # literal text of that run: line, stripped
    kind: str = "shallow"
    hops: list[TaintHop] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze(content: str, lines: list[str]) -> list[TaintPath]:
    """Return every env-mediated taint flow found in ``content``.

    Each returned path carries ``kind``:

    * ``"shallow"`` — direct ``env: VAR := ${{ tainted }}`` then
      ``run: $VAR``.
    * ``"multi_hop"`` — propagation through one or more
      ``${{ env.X }}`` indirections before the run-block sink.
    * ``"github_env"`` — at least one ``echo "NAME=..." >> $GITHUB_ENV``
      bridge between an earlier and a later step.
    * ``"step_output"`` — at least one ``echo "name=..." >> $GITHUB_OUTPUT``
      (or legacy ``::set-output``) write in a step with an ``id:``,
      followed by a downstream ``${{ steps.<id>.outputs.<name> }}``
      reference.
    * ``"agent_output"`` — synthesized AI coding-agent step output
      that reaches a shell sink via ``${{ steps.<id>.outputs.* }}``.
    * ``"cross_job"`` — a producer job's declared output carries
      attacker bytes; a consumer job references that output via
      ``${{ needs.<job>.outputs.<n> }}`` and the value lands in a
      shell sink.  See :func:`_resolve_declared_output_taints` for
      how the producer side is resolved.

    Rules filter on ``kind`` to decide which findings to surface.

    The cross-job path requires two passes: first we iterate to a
    fixed point on a ``{(producer_job, output_name): _TaintInfo}``
    map by walking each job's dataflow against the current map, then
    we run a final pass that emits sink findings (including direct
    ``${{ needs.X.outputs.Y }}`` references and env-mediated
    consumer-side flows) using the converged map.
    """
    segments = list(_split_into_job_segments(lines))
    job_metadata: list[tuple[str | None, int, list[str], dict[str, tuple[str, int]]]] = []
    for seg_start, seg_lines in segments:
        job_id = _extract_job_id(seg_lines)
        declared = _collect_declared_outputs(seg_lines, seg_start) if job_id else {}
        job_metadata.append((job_id, seg_start, seg_lines, declared))

    # Iterate cross-job map to a fixed point.  In practice the loop
    # body runs O(jobs * iters); convergence is bounded by the number
    # of declared outputs (each can flip from "unknown" to "tainted"
    # at most once) so the worst case is O(declared_outputs).  An
    # explicit safety cap prevents pathological inputs from spinning.
    cross_job_map: dict[tuple[str, str], _TaintInfo] = {}
    max_iters = max(8, sum(len(d) for _, _, _, d in job_metadata) + 2)
    for _ in range(max_iters):
        changed = False
        for job_id, seg_start, seg_lines, declared in job_metadata:
            if job_id is None or not declared:
                continue
            _, end_env, end_outputs = _analyze_job(seg_start, seg_lines, lines, cross_job_map)
            new = _resolve_declared_output_taints(
                job_id,
                declared,
                end_env,
                end_outputs,
                cross_job_map,
            )
            for key, info in new.items():
                if key not in cross_job_map:
                    cross_job_map[key] = info
                    changed = True
        if not changed:
            break

    # Final emit pass with the converged cross-job map.
    out: list[TaintPath] = []
    for _job_id, seg_start, seg_lines, _declared in job_metadata:
        paths, _, _ = _analyze_job(seg_start, seg_lines, lines, cross_job_map)
        out.extend(paths)
    return out


def _resolve_declared_output_taints(
    job_id: str,
    declared: dict[str, tuple[str, int]],
    end_env: dict[str, _TaintInfo],
    end_outputs: dict[str, _TaintInfo],
    cross_job_map: dict[tuple[str, str], _TaintInfo],
) -> dict[tuple[str, str], _TaintInfo]:
    """For one job, decide which of its declared ``outputs:`` carry
    attacker-controlled bytes given the dataflow state at the end of
    the job (``end_env`` and ``end_outputs``) plus the cross-job map
    accumulated from previous iterations.

    Recognises four ways a declared output can become tainted:

      1. Direct attacker context: ``${{ github.event.X }}`` in the
         output value.
      2. ``${{ steps.<id>.outputs.<n> }}`` where the step output was
         tainted by an earlier step (``end_outputs``).
      3. ``${{ env.<X> }}`` where the env var resolved to tainted
         (job-level or ``$GITHUB_ENV`` write).
      4. ``${{ needs.<j>.outputs.<n> }}`` where the upstream job's
         output is already in ``cross_job_map`` (transitive
         cross-job).
    """
    out: dict[tuple[str, str], _TaintInfo] = {}
    for output_name, (raw_value, line) in declared.items():
        # (1) Direct attacker context.
        src = _extract_tainted_source(raw_value)
        if src is not None:
            out[(job_id, output_name)] = _TaintInfo(
                source_expr=src,
                source_line=line,
                hops=[
                    TaintHop(
                        kind="job_output",
                        line=line,
                        name=f"{job_id}.{output_name}",
                        detail=(f"job {job_id} declared output {output_name} := ${{{{ {src} }}}}"),
                    )
                ],
            )
            continue
        # (2) Step output reference.
        sm = _STEP_OUTPUT_REF_RE.search(raw_value)
        if sm is not None:
            key = f"{sm.group(1)}.{sm.group(2)}"
            up = end_outputs.get(key)
            if up is not None:
                out[(job_id, output_name)] = _TaintInfo(
                    source_expr=up.source_expr,
                    source_line=up.source_line,
                    hops=up.hops
                    + [
                        TaintHop(
                            kind="job_output",
                            line=line,
                            name=f"{job_id}.{output_name}",
                            detail=(
                                f"job {job_id} declared output {output_name} "
                                f":= ${{{{ steps.{key} }}}}"
                            ),
                        )
                    ],
                )
                continue
        # (3) Env reference.
        em = _ENV_REF_RE.search(raw_value)
        if em is not None:
            up = end_env.get(em.group(1))
            if up is not None:
                out[(job_id, output_name)] = _TaintInfo(
                    source_expr=up.source_expr,
                    source_line=up.source_line,
                    hops=up.hops
                    + [
                        TaintHop(
                            kind="job_output",
                            line=line,
                            name=f"{job_id}.{output_name}",
                            detail=(
                                f"job {job_id} declared output {output_name} "
                                f":= ${{{{ env.{em.group(1)} }}}}"
                            ),
                        )
                    ],
                )
                continue
        # (4) Transitive cross-job reference.
        nm = _NEEDS_OUTPUT_REF_RE.search(raw_value)
        if nm is not None:
            up = cross_job_map.get((nm.group(1), nm.group(2)))
            if up is not None:
                out[(job_id, output_name)] = _TaintInfo(
                    source_expr=up.source_expr,
                    source_line=up.source_line,
                    hops=up.hops
                    + [
                        TaintHop(
                            kind="job_output",
                            line=line,
                            name=f"{job_id}.{output_name}",
                            detail=(
                                f"job {job_id} declared output {output_name} "
                                f":= ${{{{ needs.{nm.group(1)}.outputs.{nm.group(2)} }}}}"
                            ),
                        )
                    ],
                )
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


@dataclass
class _TaintInfo:
    """Internal: a resolved env variable's taint provenance.

    Not part of the public API — the public surface is :class:`TaintPath`
    with its ``hops`` list.  We keep this as a separate struct so we
    don't build the sink hop until we actually see a sink.
    """

    source_expr: str
    source_line: int
    hops: list[TaintHop]


def _analyze_job(
    job_start: int,
    job_lines: list[str],
    all_lines: list[str],
    cross_job_map: dict[tuple[str, str], _TaintInfo] | None = None,
) -> tuple[list[TaintPath], dict[str, _TaintInfo], dict[str, _TaintInfo]]:
    """Analyse one job segment.

    Returns ``(paths, end_visible_env, end_output_taints)`` so the
    cross-job driver in :func:`analyze` can resolve the job's declared
    ``outputs:`` block against the end-of-job dataflow state.

    Step-aware: iterates steps in file order and maintains two running
    state dicts:

    * ``dynamic_env`` — taints introduced via
      ``echo "NAME=..." >> $GITHUB_ENV`` in earlier steps.  These
      become real env vars in subsequent steps' processes.
    * ``output_taints`` — taints introduced via
      ``echo "name=..." >> $GITHUB_OUTPUT`` (or legacy ``::set-output``)
      in earlier steps that have an ``id:``.  These are referenceable
      via ``${{ steps.<id>.outputs.<name> }}`` in subsequent steps.

    Both are updated *after* processing the current step's sinks so
    same-step self-references don't propagate (matches GitHub Actions
    runner semantics — both files are only consumed between steps).

    ``cross_job_map`` (optional) carries
    ``{(producer_job, output_name): _TaintInfo}`` from earlier passes
    of :func:`analyze`.  When set, it lets:

      - ``env: VAR: ${{ needs.<j>.outputs.<n> }}`` register VAR as a
        taint source whose provenance chain is rooted in the producer
        job's hops, not in this consumer job;
      - direct ``${{ needs.<j>.outputs.<n> }}`` references inside
        ``run:`` lines emit a ``cross_job`` :class:`TaintPath`
        without any consumer-side env hop in between.
    """
    cross_job_map = cross_job_map or {}
    steps = list(_iter_steps(job_lines, job_start))

    job_env_assignments = _collect_job_level_env_assignments(job_lines, job_start)
    job_env = _resolve_env_taints(job_env_assignments, base_taints={}, cross_job_map=cross_job_map)

    paths: list[TaintPath] = []
    dynamic_env: dict[str, _TaintInfo] = {}
    # ``"<step_id>.<output_name>"`` -> _TaintInfo
    output_taints: dict[str, _TaintInfo] = {}
    # Step IDs whose parent step uses an AI coding-agent action.
    # A ``steps.<id>.outputs.*`` reference in a later step is an
    # attacker-shaped taint source even though the agent never
    # writes to ``$GITHUB_OUTPUT`` explicitly.
    agent_step_ids: dict[str, str] = {}  # step_id -> agent package name
    _agent_source_lines: dict[str, int] = {}  # step_id -> 1-indexed source line

    if not steps:
        # No steps block (reusable workflow etc.).  Fall back to the
        # original "all env blocks, any run: line" model so we still
        # catch shallow + multi-hop flows in these rarer files.
        all_assignments = _collect_all_env_assignments(job_lines, job_start)
        taints = _resolve_env_taints(all_assignments, base_taints={}, cross_job_map=cross_job_map)
        run_line_nos = _collect_run_line_numbers(job_lines, job_start)
        for lineno in run_line_nos:
            line = all_lines[lineno - 1]
            for name, info in taints.items():
                if _references_var(line, name):
                    paths.append(_make_path(info, name, lineno, line.strip()))
            # Direct cross-job sink: ${{ needs.<j>.outputs.<n> }}.
            for ref in _NEEDS_OUTPUT_REF_RE.finditer(line):
                xinfo = cross_job_map.get((ref.group(1), ref.group(2)))
                if xinfo is not None:
                    paths.append(
                        _make_cross_job_path(
                            xinfo, ref.group(1), ref.group(2), lineno, line.strip()
                        )
                    )
        return paths, taints, {}

    for step_start, step_lines in steps:
        step_id = _get_step_id(step_lines)

        # Register agent-action steps as taint sources. The detector
        # walks downstream step-output references later in the scan
        # and synthesizes taints with ``kind="agent_output"`` when
        # they point at a known agent step. We record the action
        # package name so the provenance chain can say
        # ``agent:anthropics/claude-code-action -> steps.X.outputs.Y``.
        if step_id is not None:
            for line in step_lines:
                m = _AGENT_USES_RE.search(line)
                if m:
                    agent_step_ids[step_id] = m.group(1)
                    # 1-indexed source line for the agent uses:.
                    _agent_source_lines[step_id] = step_start + step_lines.index(line) + 1
                    break

        step_env_assignments = _collect_all_env_assignments(step_lines, step_start)
        step_env = _resolve_env_taints(
            step_env_assignments,
            base_taints={**job_env, **dynamic_env},
            cross_job_map=cross_job_map,
        )
        visible_env = {**job_env, **dynamic_env, **step_env}

        # Sinks in this step's run: body.
        #
        # We skip the *write* lines themselves from the generic sink
        # scan because shell expansion inside an echo-to-file is not a
        # code-execution sink — the bytes are written verbatim and the
        # downstream-step read is the real sink, caught by the
        # dedicated detectors below.
        run_line_nos = _collect_run_line_numbers(step_lines, step_start)
        for lineno in run_line_nos:
            line = all_lines[lineno - 1]
            if _GITHUB_ENV_REDIRECT_RE.search(line):
                continue
            if _GITHUB_OUTPUT_REDIRECT_RE.search(line):
                continue
            # Env-var references (shell expansion).
            for name, info in visible_env.items():
                if _references_var(line, name):
                    paths.append(_make_path(info, name, lineno, line.strip()))
            # Step-output references via ``${{ steps.<id>.outputs.<name> }}``.
            #
            # GitHub Actions substitutes the value into the run: text
            # at workflow-parse time, before bash sees it; the
            # attacker-controlled bytes therefore land directly in the
            # shell command line.  This is the canonical TAINT-GH-004
            # sink shape — and, when ``<id>`` points at an AI coding-
            # agent step, the TAINT-GH-005 sink shape (same bridge,
            # different source).
            for ref in _STEP_OUTPUT_REF_RE.finditer(line):
                ref_id = ref.group(1)
                ref_name = ref.group(2)
                key = f"{ref_id}.{ref_name}"
                info_opt: _TaintInfo | None = output_taints.get(key)
                if info_opt is None and ref_id in agent_step_ids:
                    # Synthesize agent-output taint: the agent's
                    # output is attacker-shaped by prompt injection.
                    # Source line is the agent step's ``uses:`` line
                    # that added it to ``agent_step_ids``, captured
                    # when we scanned that step below.
                    info_opt = _TaintInfo(
                        source_expr=f"agent:{agent_step_ids[ref_id]}",
                        source_line=_agent_source_lines.get(ref_id, 0),
                        hops=[
                            TaintHop(
                                kind="agent_output",
                                line=lineno,
                                name=key,
                                detail=(f"agent {agent_step_ids[ref_id]} step output {ref_name}"),
                            )
                        ],
                    )
                if info_opt is not None:
                    info = info_opt
                    paths.append(_make_path(info, key, lineno, line.strip()))
            # Cross-job sink: ``${{ needs.<j>.outputs.<n> }}`` referenced
            # inside a run: line.  Same server-side substitution shape
            # as TAINT-GH-004; the only difference is the producer is
            # a different job rather than an earlier step in this one.
            for ref in _NEEDS_OUTPUT_REF_RE.finditer(line):
                xinfo = cross_job_map.get((ref.group(1), ref.group(2)))
                if xinfo is not None:
                    paths.append(
                        _make_cross_job_path(
                            xinfo, ref.group(1), ref.group(2), lineno, line.strip()
                        )
                    )

        # After sinks: scan this step for $GITHUB_ENV / $GITHUB_OUTPUT
        # writes.  These propagate to *subsequent* steps only.
        dynamic_env.update(_detect_github_env_writes(step_lines, step_start, visible_env))
        if step_id is not None:
            output_taints.update(
                _detect_step_output_writes(step_lines, step_start, visible_env, step_id)
            )

    # ``end_visible_env`` is the dataflow state the job's declared
    # ``outputs:`` block sees: job-level + dynamically-written env vars,
    # but NOT a particular step's step-local env (those don't escape
    # the step).  Returned to ``analyze`` so the cross-job driver can
    # resolve declared outputs.
    end_visible_env = {**job_env, **dynamic_env}
    return paths, end_visible_env, output_taints


def _collect_all_env_assignments(
    seg_lines: list[str], seg_start: int
) -> list[tuple[str, str, int]]:
    """Walk every ``env:`` block in the segment and return
    ``[(var_name, raw_value, 1-indexed_line), ...]`` in file order.

    Both job-level and step-level ``env:`` blocks contribute.  We do
    NOT resolve taint here; that happens in
    :func:`_resolve_env_taints` so multi-hop can iterate to a fixed
    point.
    """
    out: list[tuple[str, str, int]] = []
    i = 0
    while i < len(seg_lines):
        line = seg_lines[i]
        m = _ENV_HEADER_RE.match(line)
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
            am = _ENV_ASSIGN_RE.match(child)
            if am:
                var = am.group(2)
                value = am.group(3).strip().strip('"').strip("'")
                out.append((var, value, seg_start + j + 1))
            j += 1
        i = j
    return out


def _resolve_env_taints(
    assignments: list[tuple[str, str, int]],
    base_taints: dict[str, _TaintInfo] | None = None,
    cross_job_map: dict[tuple[str, str], _TaintInfo] | None = None,
) -> dict[str, _TaintInfo]:
    """Resolve taint propagation through env chains.

    Returns a ``{var: _TaintInfo}`` mapping covering every var that
    transitively carries attacker-controlled data.  Uses fixed-point
    iteration so declaration order inside the env block does not
    matter — ``B: ${{ env.A }}`` resolves on a later iteration once
    ``A`` itself has been resolved.

    ``base_taints`` seeds the resolver with outer-scope taints so that
    a step-level ``env: B: ${{ env.A }}`` can multi-hop against a
    job-level (or dynamically-written) ``A``.  The returned dict
    includes the base taints plus any newly-resolved ones; the caller
    layers them with dict unpacking.

    ``cross_job_map`` lets a value like
    ``env: VAR: ${{ needs.<j>.outputs.<n> }}`` register as a taint
    source when the producer's declared output was determined tainted
    in an earlier pass of :func:`analyze`.  The producer's provenance
    chain is prepended so the consumer-side hop appears as a
    ``needs_ref`` link continuing the producer's history, not a fresh
    chain that forgets where the bytes came from.
    """
    resolved: dict[str, _TaintInfo] = dict(base_taints or {})
    cmap = cross_job_map or {}
    changed = True
    while changed:
        changed = False
        for var, value, line in assignments:
            if var in resolved:
                continue
            # (a) Direct tainted source.
            src = _extract_tainted_source(value)
            if src is not None:
                resolved[var] = _TaintInfo(
                    source_expr=src,
                    source_line=line,
                    hops=[
                        TaintHop(
                            kind="env_static",
                            line=line,
                            name=var,
                            detail=f"env {var} := ${{{{ {src} }}}}",
                        )
                    ],
                )
                changed = True
                continue
            # (b) Multi-hop: ${{ env.OTHER }} where OTHER is already tainted.
            other = _extract_env_ref(value)
            if other and other in resolved:
                parent = resolved[other]
                resolved[var] = _TaintInfo(
                    source_expr=parent.source_expr,
                    source_line=parent.source_line,
                    hops=parent.hops
                    + [
                        TaintHop(
                            kind="env_indirect",
                            line=line,
                            name=var,
                            detail=f"env {var} := ${{{{ env.{other} }}}}",
                        )
                    ],
                )
                changed = True
                continue
            # (c) Cross-job: ${{ needs.<j>.outputs.<n> }} where (j, n)
            #     was determined tainted in an earlier analyze() pass.
            xref = _references_needs_output_taint(value, cmap)
            if xref is not None:
                # Find the actual (j, n) so the consumer-side hop is
                # accurate even if the value also contains other
                # ${{ ... }} substitutions.
                m = next(_NEEDS_OUTPUT_REF_RE.finditer(value))
                resolved[var] = _TaintInfo(
                    source_expr=xref.source_expr,
                    source_line=xref.source_line,
                    hops=xref.hops
                    + [
                        TaintHop(
                            kind="needs_ref",
                            line=line,
                            name=var,
                            detail=(
                                f"env {var} := ${{{{ needs.{m.group(1)}.outputs.{m.group(2)} }}}}"
                            ),
                        )
                    ],
                )
                changed = True
    return resolved


def _extract_tainted_source(value: str) -> str | None:
    """Return the dotted context name if any ``${{ ... }}`` substitution
    in ``value`` references an attacker-controlled context; otherwise
    ``None``.

    Handles the common compound-expression patterns real workflows use:

      * Bare: ``${{ github.head_ref }}`` — head_ref.
      * Fallback: ``${{ github.head_ref || github.ref }}`` — head_ref
        (wins when set, i.e. exactly the attacker scenario).
      * Default: ``${{ github.event.pull_request.title || '' }}`` — title.
      * Multiple substitutions: ``${{ github.sha }}-${{ github.head_ref }}``
        — head_ref (the first tainted one found).

    Conservative: any expression that mentions a tainted context is
    treated as carrying that taint, even when the full expression is a
    boolean check like ``${{ startsWith(github.head_ref, 'x') }}``.  The
    false-positive rate on boolean expressions in env: values is low
    enough that the simpler rule beats the cost of missing ``||``
    fallbacks (which dominate real-world taint sinks).
    """
    for expr in _GHA_EXPR_RE.finditer(value):
        m = _TAINTED_IN_EXPR_RE.search(expr.group(1))
        if m:
            return m.group(0)
    return None


def _extract_env_ref(value: str) -> str | None:
    """Return the inner variable name if ``value`` is a pure
    ``${{ env.X }}`` reference; otherwise ``None``.

    Deliberately conservative: we only propagate taint through single
    ``${{ env.X }}`` substitutions so we don't over-taint expressions
    like ``${{ env.A }}-${{ github.sha }}`` where the attacker only
    controls part of the value.  Such partial mixes are still covered
    by the direct ``SEC4-GH-004`` rule if the tainted half is inlined
    somewhere downstream.
    """
    m = _ENV_REF_RE.fullmatch(value)
    return m.group(1) if m else None


def _collect_run_line_numbers(seg_lines: list[str], seg_start: int) -> list[int]:
    """Return 1-indexed line numbers (in the full file) of every line
    whose text participates in a ``run:`` shell body.

    For inline ``run: echo $X`` this is just that one line.  For
    block-scalar ``run: |`` we include every continuation line at
    deeper indent.
    """
    out: list[int] = []
    i = 0
    while i < len(seg_lines):
        line = seg_lines[i]
        bm = _RUN_BLOCK_RE.match(line)
        if bm:
            indent = len(bm.group(1))
            j = i + 1
            while j < len(seg_lines):
                child = seg_lines[j]
                stripped = child.lstrip()
                if stripped and not stripped.startswith("#"):
                    child_indent = len(child) - len(stripped)
                    if child_indent <= indent:
                        break
                out.append(seg_start + j + 1)
                j += 1
            i = j
            continue
        im = _RUN_INLINE_RE.match(line)
        if im and not _RUN_BLOCK_RE.match(line):
            out.append(seg_start + i + 1)
        i += 1
    return out


def _references_var(line: str, var: str) -> bool:
    """Return True if ``line`` references shell variable ``var`` in a
    context where it actually expands.

    Accepts ``$VAR``, ``${VAR}``, and the GitHub-Actions-specific
    ``${{ env.VAR }}`` form (which is expanded server-side before the
    shell sees it, so its quote context doesn't matter).  Word-boundary
    aware so ``$VARIANT`` doesn't match ``VAR``.

    References inside single quotes are ignored — bash never interpolates
    there, so they are not a sink.  References in double quotes or
    unquoted text both expand and are treated as references.
    """
    # Server-side ${{ env.VAR }} is substituted before bash sees the
    # line, so shell quoting is irrelevant — check it first.
    if re.search(rf"\$\{{\{{\s*env\.{var}\s*\}}\}}", line):
        return True
    # Shell $VAR / ${VAR}. Only count matches in expanding contexts.
    for m in re.finditer(rf"\$\{{?{var}\}}?\b", line):
        if _shell_quote_context_at(line, m.start()) != "single":
            return True
    return False


def _shell_quote_context_at(line: str, pos: int) -> str:
    """Return the bash-style quote context at ``line[pos]``.

    Walks ``line[:pos]`` tracking single-quote, double-quote, and
    ANSI-C (``$'...'``) state with backslash escape handling.
    Returns ``"single"``, ``"double"``, or ``"unquoted"``.  ANSI-C
    quoting collapses into ``"single"`` because the two share the
    one property the analyzer cares about: ``$VAR`` is *not*
    interpolated inside.

    Note: ``$"..."`` (locale-translated strings) are NOT collapsed —
    bash still interpolates parameters there, so they map to the
    regular ``"double"`` state.

    Still does not handle heredocs or multi-line string
    continuations — those need cross-line state and are tracked as
    separate work in the README's Limitations section.
    """
    state: str | None = None  # None | "'" | '"' | "ansi_c"
    i = 0
    while i < pos:
        c = line[i]
        if state is None:
            # ANSI-C quoting: ``$'...'``.  The `$'` opener must come
            # before regular `'` detection because we need to consume
            # both characters and switch into a state that's literal-
            # like but with C-style backslash escapes.
            if c == "$" and i + 1 < pos and line[i + 1] == "'":
                state = "ansi_c"
                i += 2
                continue
            if c == "'":
                state = "'"
            elif c == '"':
                state = '"'
            elif c == "\\" and i + 1 < pos:
                # Unquoted backslash escapes the next char.
                i += 2
                continue
        elif state == "'":
            # Single quotes are literal — only another ' closes them.
            if c == "'":
                state = None
        elif state == "ansi_c":
            # Inside $'...': backslash escapes any next char (incl. \').
            # No parameter expansion happens, so callers see this as
            # "single" via the return mapping below.
            if c == "\\" and i + 1 < pos:
                i += 2
                continue
            if c == "'":
                state = None
        else:  # state == '"'
            if c == '"':
                state = None
            elif c == "\\" and i + 1 < pos and line[i + 1] in ('"', "\\", "$", "`"):
                # Double quotes honour a limited set of escapes.
                i += 2
                continue
        i += 1
    if state == "'" or state == "ansi_c":
        return "single"
    if state == '"':
        return "double"
    return "unquoted"


def _classify_kind(hops: list[TaintHop]) -> str:
    """Pick the ``TaintPath.kind`` label from the chain's hop kinds.

    Priority (highest → lowest):
        ``cross_job`` > ``agent_output`` > ``step_output`` >
        ``github_env`` > ``multi_hop`` > ``shallow``.

    ``cross_job`` ranks highest because crossing a job boundary
    breaks the assumption most reviewers carry ("this run: only sees
    its own job's data") — flagging it as the dominant kind makes the
    boundary crossing visible in the report.  ``agent_output`` ranks
    next because the source is a model steered by prompt injection.
    A chain containing *any* ``step_output`` hop is reported as
    ``"step_output"`` because the cross-step output bridge is the
    most damning transition (it makes the value available via the
    workflow expression engine, not just shell, so the consumer
    pattern is wider).  Then ``github_env`` wins over ``multi_hop``,
    and ``multi_hop`` wins over plain ``shallow``.  A chain of only
    ``env_static`` hops is the original ``"shallow"`` flow handled by
    TAINT-GH-001.
    """
    if any(h.kind == "needs_ref" for h in hops):
        return "cross_job"
    if any(h.kind == "agent_output" for h in hops):
        return "agent_output"
    if any(h.kind == "step_output" for h in hops):
        return "step_output"
    if any(h.kind == "github_env" for h in hops):
        return "github_env"
    if any(h.kind == "env_indirect" for h in hops):
        return "multi_hop"
    return "shallow"


def _make_path(info: _TaintInfo, sink_name: str, sink_line: int, sink_snippet: str) -> TaintPath:
    sink_hop = TaintHop(
        kind="sink",
        line=sink_line,
        name=sink_name,
        detail=f"run: references ${sink_name}",
    )
    return TaintPath(
        kind=_classify_kind(info.hops),
        source_expr=info.source_expr,
        source_line=info.source_line,
        env_var=sink_name,
        sink_line=sink_line,
        sink_snippet=sink_snippet,
        hops=info.hops + [sink_hop],
    )


def _make_cross_job_path(
    producer_info: _TaintInfo,
    producer_job: str,
    output_name: str,
    sink_line: int,
    sink_snippet: str,
) -> TaintPath:
    """Build a cross-job :class:`TaintPath` for a direct
    ``${{ needs.<j>.outputs.<n> }}`` reference inside a ``run:`` line.

    The producer's hops are preserved verbatim; a ``needs_ref`` hop
    marks the boundary crossing into the consumer job; a ``sink`` hop
    closes the chain at the run: line.  Severity (and rule routing)
    happens downstream — this just shapes the provenance record.
    """
    needs_label = f"needs.{producer_job}.outputs.{output_name}"
    needs_hop = TaintHop(
        kind="needs_ref",
        line=sink_line,
        name=needs_label,
        detail=f"run: references ${{{{ {needs_label} }}}}",
    )
    sink_hop = TaintHop(
        kind="sink",
        line=sink_line,
        name=needs_label,
        detail=f"run: ${{{{ {needs_label} }}}}",
    )
    return TaintPath(
        kind="cross_job",
        source_expr=producer_info.source_expr,
        source_line=producer_info.source_line,
        env_var=needs_label,
        sink_line=sink_line,
        sink_snippet=sink_snippet,
        hops=producer_info.hops + [needs_hop, sink_hop],
    )


# ---------------------------------------------------------------------------
# Step-level segmentation (needed for order-sensitive $GITHUB_ENV flows)
# ---------------------------------------------------------------------------


# List-item marker followed by any non-space (the step's first key, e.g.
# "- name:", "- env:", "- run:").  The indent captured is the column of
# the hyphen, so ``len(group(1))`` gives a reproducible "step indent".
_LIST_ITEM_RE = re.compile(r"^(\s*)-\s+\S")

# Recognise job-child keys so we can pin the "job-child indent" that
# distinguishes job-level env: from step-level env:.  We intentionally
# only match hyphenated / uniquely-job keys to avoid false matches on
# env var names that happen to share a word.
_JOB_CHILD_RE = re.compile(
    r"^(\s*)(runs-on|steps|timeout-minutes|continue-on-error|"
    r"strategy|needs|permissions|concurrency|outputs|services|defaults)"
    r"\s*:",
)


def _iter_steps(job_lines: list[str], job_start: int) -> list[tuple[int, list[str]]]:
    """Yield ``(step_start_0indexed, step_lines)`` for each step in the job.

    Step boundaries come from the ``- `` list-item markers nested under
    the ``steps:`` key.  Each returned ``step_start`` is the 0-indexed
    file line of the step's first line, matching the convention used by
    :func:`_split_into_job_segments`.  Returns an empty list if the job
    has no ``steps:`` block (e.g. reusable workflows).
    """
    # Find the `steps:` header.
    steps_idx: int | None = None
    steps_header_indent: int = 0
    for i, line in enumerate(job_lines):
        m = re.match(r"^(\s*)steps\s*:\s*$", line)
        if m:
            steps_idx = i
            steps_header_indent = len(m.group(1))
            break
    if steps_idx is None:
        return []

    # Find the indent of the list-item markers for the first step.
    list_indent: int | None = None
    for idx in range(steps_idx + 1, len(job_lines)):
        line = job_lines[idx]
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if indent <= steps_header_indent:
            break  # left the steps section without finding a list item
        m = _LIST_ITEM_RE.match(line)
        if m:
            list_indent = len(m.group(1))
            break
    if list_indent is None:
        return []

    # Split into step segments.
    steps: list[tuple[int, list[str]]] = []
    current_start: int | None = None
    current_lines: list[str] = []
    idx = steps_idx + 1
    while idx < len(job_lines):
        line = job_lines[idx]
        stripped = line.lstrip()
        if stripped and not stripped.startswith("#"):
            indent = len(line) - len(stripped)
            # Exit if we've left the steps block entirely.
            if indent <= steps_header_indent:
                break
            m = _LIST_ITEM_RE.match(line)
            if m and len(m.group(1)) == list_indent:
                if current_start is not None:
                    steps.append((current_start, current_lines))
                current_start = job_start + idx
                current_lines = [line]
                idx += 1
                continue
        # Accumulate onto the current step (only after we've seen one).
        if current_start is not None:
            current_lines.append(line)
        idx += 1

    if current_start is not None:
        steps.append((current_start, current_lines))
    return steps


# ---------------------------------------------------------------------------
# Cross-job (needs.<job>.outputs.<name>) helpers
# ---------------------------------------------------------------------------


_JOB_ID_HEADER_RE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(?:#.*)?$")


def _extract_job_id(seg_lines: list[str]) -> str | None:
    """Return the GitHub Actions job ID for a segment, or ``None`` if
    the segment is the pre-jobs preamble (the first segment from
    :func:`_split_into_job_segments` carries top-level keys before the
    first job appears).

    The job ID is the first non-blank, non-comment key whose value is
    empty (``build:``) — i.e. the segment-opening line.  We don't try
    to be clever with quoted IDs because GitHub Actions itself rejects
    those at parse time.
    """
    for line in seg_lines:
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _JOB_ID_HEADER_RE.match(line)
        if m:
            return m.group(2)
        # First non-blank line wasn't a bare key (e.g. preamble's
        # ``name: ...`` or ``on:`` block): not a job segment.
        return None
    return None


def _collect_declared_outputs(seg_lines: list[str], seg_start: int) -> dict[str, tuple[str, int]]:
    """Parse a job's ``outputs:`` block at job-child indent.

    Returns ``{output_name: (raw_value, 1-indexed_line)}``.  Values are
    captured raw — the same shape as :func:`_collect_all_env_assignments`
    — so the same taint resolvers can run against them.

    Job-child indent is auto-detected via ``_JOB_CHILD_RE``; an
    ``outputs:`` block at any deeper indent (e.g. inside a nested
    ``with:`` of a reusable-workflow call) is intentionally ignored.
    """
    job_child_indent: int | None = None
    for line in seg_lines:
        m = _JOB_CHILD_RE.match(line)
        if m:
            job_child_indent = len(m.group(1))
            break
    if job_child_indent is None:
        return {}

    out: dict[str, tuple[str, int]] = {}
    i = 0
    while i < len(seg_lines):
        line = seg_lines[i]
        m = re.match(r"^(\s*)outputs\s*:\s*$", line)
        if not m or len(m.group(1)) != job_child_indent:
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
            am = _ENV_ASSIGN_RE.match(child)
            if am:
                name = am.group(2)
                value = am.group(3).strip().strip('"').strip("'")
                out[name] = (value, seg_start + j + 1)
            j += 1
        i = j
    return out


def _references_needs_output_taint(
    value: str,
    cross_job_map: dict[tuple[str, str], _TaintInfo],
) -> _TaintInfo | None:
    """If ``value`` contains a ``${{ needs.X.outputs.Y }}`` substitution
    whose ``(X, Y)`` is registered as tainted in ``cross_job_map``,
    return that producer's :class:`_TaintInfo`.  Otherwise ``None``.

    Used by both env-assignment resolution (multi-hop sources) and
    declared-output propagation (transitive cross-job).
    """
    for m in _NEEDS_OUTPUT_REF_RE.finditer(value):
        info = cross_job_map.get((m.group(1), m.group(2)))
        if info is not None:
            return info
    return None


def _collect_job_level_env_assignments(
    job_lines: list[str], job_start: int
) -> list[tuple[str, str, int]]:
    """Collect ``env:`` assignments that live at job scope, skipping
    step-level ``env:`` blocks.

    A job-level ``env:`` header has the same indent as other
    job-children keys (``steps:``, ``runs-on:``, ...).  Step-level
    ``env:`` headers live deeper (inside a list-item body).  If the
    job structure doesn't give us a clear job-child indent reference
    (weird/non-idiomatic YAML, reusable workflow without ``steps:``),
    we fall back to collecting every ``env:`` block so we don't
    silently lose flows; step iteration will then process those blocks
    in order anyway.
    """
    # Determine job-child indent from a hyphenated/unique key.
    job_child_indent: int | None = None
    for line in job_lines:
        m = _JOB_CHILD_RE.match(line)
        if m:
            job_child_indent = len(m.group(1))
            break
    if job_child_indent is None:
        return []

    out: list[tuple[str, str, int]] = []
    i = 0
    while i < len(job_lines):
        line = job_lines[i]
        m = _ENV_HEADER_RE.match(line)
        if not m:
            i += 1
            continue
        header_indent = len(m.group(1))
        if header_indent != job_child_indent:
            # step-level or deeper — not our concern here.
            i += 1
            continue
        # Walk children of this job-level env: block.
        j = i + 1
        while j < len(job_lines):
            child = job_lines[j]
            stripped = child.lstrip()
            if not stripped or stripped.startswith("#"):
                j += 1
                continue
            child_indent = len(child) - len(stripped)
            if child_indent <= header_indent:
                break
            am = _ENV_ASSIGN_RE.match(child)
            if am:
                var = am.group(2)
                value = am.group(3).strip().strip('"').strip("'")
                out.append((var, value, job_start + j + 1))
            j += 1
        i = j
    return out


# ---------------------------------------------------------------------------
# $GITHUB_ENV dynamic write detection
# ---------------------------------------------------------------------------

# (``_GITHUB_ENV_REDIRECT_RE`` is defined up-top with the other module-
# level regexes because ``_analyze_job`` needs it to skip these lines
# from the generic sink scan.)

# Match a full ``echo ... >> $GITHUB_ENV`` write in one pass.  Combining
# the echo body and the redirect into a single regex makes ``finditer``
# useable (handy for lines like
#   echo "A=1" >> $GITHUB_ENV && echo "B=2" >> $GITHUB_ENV
# that pack two writes onto one line) and eliminates the earlier bug
# where a naïve value matcher terminated on the first embedded ``\"``
# inside a double-quoted echo argument.  The three alternations cover
#   - "..." with backslash escapes (the common quoted form),
#   - '...' with backslash escapes (rare — single quotes disable shell
#     expansion for ``$VAR`` refs but a ``${{ tainted }}`` context is
#     still expanded *before* the shell sees it, so we still flag it),
#   - bare words (unquoted ``echo NAME=$V``) up to a shell metachar.
_ECHO_TO_GITHUB_ENV_RE = re.compile(
    r"""
    \becho                                   # echo builtin
    (?:\s+-[a-zA-Z]+)*                       # optional flags (-n, -e, ...)
    \s+
    (?:
        "(?P<dq>(?:\\.|[^"\\])*)"            # double-quoted, w/ escapes
      | '(?P<sq>(?:\\.|[^'\\])*)'            # single-quoted, w/ escapes
      | (?P<bare>[^\s"'>|&;]+)               # unquoted bare word
    )
    \s*
    >>?\s*                                   # redirect operator
    [\"']?\$\{?GITHUB_ENV\}?[\"']?           # $GITHUB_ENV in any form
    """,
    re.VERBOSE,
)

# Extract ``NAME=VALUE`` once we have an unquoted echo body.
_NAME_VALUE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)

# Same shape as ``_ECHO_TO_GITHUB_ENV_RE`` but redirected to
# ``$GITHUB_OUTPUT`` — exposed separately so the two detectors can
# scan independently and so we can skip output-write lines from the
# generic sink scan (same rationale as for $GITHUB_ENV writes:
# double-quoted shell expansion inside an echo-to-file is not a code
# execution sink).
_ECHO_TO_GITHUB_OUTPUT_RE = re.compile(
    r"""
    \becho
    (?:\s+-[a-zA-Z]+)*
    \s+
    (?:
        "(?P<dq>(?:\\.|[^"\\])*)"
      | '(?P<sq>(?:\\.|[^'\\])*)'
      | (?P<bare>[^\s"'>|&;]+)
    )
    \s*
    >>?\s*
    [\"']?\$\{?GITHUB_OUTPUT\}?[\"']?
    """,
    re.VERBOSE,
)

# Legacy ``echo "::set-output name=NAME::VALUE"`` form.  Officially
# deprecated in favour of ``$GITHUB_OUTPUT`` but still accepted by the
# runner and present in many older / un-migrated workflows, so we have
# to match it to avoid false negatives in the wild.  Captures the name
# and the raw value text up to (but not including) any trailing closing
# echo quote.
_SET_OUTPUT_RE = re.compile(
    r"::set-output\s+name=(?P<name>[A-Za-z_][A-Za-z0-9_-]*)"
    r"::(?P<value>.*?)(?=[\"'\n]|$)"
)


def _detect_github_env_writes(
    step_lines: list[str],
    step_start: int,
    visible_env: dict[str, _TaintInfo],
) -> dict[str, _TaintInfo]:
    """Find ``echo "NAME=VALUE" >> $GITHUB_ENV`` writes in this step.

    Returns ``{NAME: _TaintInfo}`` for every write whose ``VALUE``
    carries attacker-controlled data — either directly via a
    ``${{ <tainted_context> }}`` substitution inside the echo string,
    or indirectly via a shell reference to an already-tainted env var
    (``$V`` / ``${V}`` / ``${{ env.V }}``).

    Uses :data:`_ECHO_TO_GITHUB_ENV_RE` with ``finditer`` so lines that
    chain multiple writes (``echo "A=$X" >> $GITHUB_ENV && echo "B=$Y"
    >> $GITHUB_ENV``) contribute both writes.  The body regex handles
    backslash-escaped quotes inside double-quoted strings so realistic
    echoes like
        echo "MSG=Welcome @$AUTHOR! Your PR \\"$PR_TITLE\\" ..." >> $GITHUB_ENV
    don't slip through as false negatives.

    The returned taints represent variables that subsequent steps will
    see in their environment.  The caller applies them *after*
    processing the current step's sinks so a step's own write does not
    self-taint within the same step.
    """
    out: dict[str, _TaintInfo] = {}
    run_line_nos = _collect_run_line_numbers(step_lines, step_start)
    for lineno in run_line_nos:
        idx = lineno - step_start - 1
        if idx < 0 or idx >= len(step_lines):
            continue
        line = step_lines[idx]
        for m in _ECHO_TO_GITHUB_ENV_RE.finditer(line):
            # Pull the echo body out of whichever alternation matched.
            dq = m.group("dq")
            sq = m.group("sq")
            bare = m.group("bare")
            if dq is not None:
                # Un-escape shell backslash-escapes we care about.
                body = re.sub(r"\\(.)", r"\1", dq)
                # Inside double quotes bash DOES expand $VAR — so shell
                # references to tainted vars are real taint carriers.
                quoted_single = False
            elif sq is not None:
                body = sq
                # Inside single quotes bash does NOT expand $VAR, so
                # ``$RAW`` in a single-quoted echo is just literal bytes
                # and carries no taint.  However ``${{ tainted_context }}``
                # is still expanded by the workflow engine BEFORE the
                # shell sees it, so those references remain relevant.
                quoted_single = True
            else:
                body = bare or ""
                quoted_single = False

            am = _NAME_VALUE_RE.match(body)
            if not am:
                continue
            name, value = am.group(1), am.group(2)

            # (a) Direct tainted context embedded in the echo body.
            src = _extract_tainted_source(value)
            if src is not None:
                out[name] = _TaintInfo(
                    source_expr=src,
                    source_line=lineno,
                    hops=[
                        TaintHop(
                            kind="github_env",
                            line=lineno,
                            name=name,
                            detail=f"$GITHUB_ENV {name} := ${{{{ {src} }}}}",
                        )
                    ],
                )
                continue

            # (b) Indirect: the echo references an already-tainted env
            #     var via shell expansion.  Skip this branch when the
            #     body was single-quoted: bash won't actually expand
            #     ``$RAW`` in that case, so there is no propagation.
            if quoted_single:
                continue
            for var, info in visible_env.items():
                if _references_var(value, var):
                    out[name] = _TaintInfo(
                        source_expr=info.source_expr,
                        source_line=info.source_line,
                        hops=info.hops
                        + [
                            TaintHop(
                                kind="github_env",
                                line=lineno,
                                name=name,
                                detail=f"$GITHUB_ENV {name} := ${var}",
                            )
                        ],
                    )
                    break
    return out


# ---------------------------------------------------------------------------
# Step output detection ($GITHUB_OUTPUT + legacy ::set-output)
# ---------------------------------------------------------------------------


# Match the step's ``id:`` key.  Step IDs and output names allow
# underscores and hyphens per the GitHub Actions name validation rules.
# The optional ``-\s+`` lets us match either form: ``- id: foo`` (id is
# the first key on the bullet line) or ``id: foo`` (id appears as a
# child key after ``- name: ...``).
_STEP_ID_RE = re.compile(r"^\s*(?:-\s+)?id\s*:\s*[\"']?([A-Za-z_][A-Za-z0-9_-]*)[\"']?\s*$")


def _get_step_id(step_lines: list[str]) -> str | None:
    """Return the step's ``id:`` value if it has one, else ``None``.

    A step without an ``id:`` cannot have its outputs referenced via
    ``${{ steps.<id>.outputs.<name> }}``, so any ``$GITHUB_OUTPUT``
    write in such a step is unreachable from a subsequent sink and we
    can short-circuit by returning ``None`` here.
    """
    for line in step_lines:
        m = _STEP_ID_RE.match(line)
        if m:
            return m.group(1)
    return None


def _detect_step_output_writes(
    step_lines: list[str],
    step_start: int,
    visible_env: dict[str, _TaintInfo],
    step_id: str,
) -> dict[str, _TaintInfo]:
    """Find ``echo "name=VALUE" >> $GITHUB_OUTPUT`` and legacy
    ``echo "::set-output name=NAME::VALUE"`` writes in this step.

    Returns ``{"<step_id>.<output_name>": _TaintInfo}`` for every write
    whose ``VALUE`` carries attacker-controlled data — either a direct
    ``${{ <tainted_context> }}`` substitution embedded in the echo
    string, or a shell reference to an already-tainted env var
    (``$V`` / ``${V}``).

    Symmetrical to :func:`_detect_github_env_writes` — same quoting
    rules (single-quoted shell refs do not propagate; single-quoted
    workflow contexts still do because the workflow engine expands
    them before bash sees the line) and same multi-write-per-line
    handling via ``finditer``.

    Caller pre-condition: ``step_id is not None``.  The check lives in
    :func:`_analyze_job` so we don't even call this function for steps
    that can't have referenceable outputs.
    """
    out: dict[str, _TaintInfo] = {}
    run_line_nos = _collect_run_line_numbers(step_lines, step_start)
    for lineno in run_line_nos:
        idx = lineno - step_start - 1
        if idx < 0 or idx >= len(step_lines):
            continue
        line = step_lines[idx]

        # (1) Modern ``echo "name=value" >> $GITHUB_OUTPUT`` form.
        for m in _ECHO_TO_GITHUB_OUTPUT_RE.finditer(line):
            dq = m.group("dq")
            sq = m.group("sq")
            bare = m.group("bare")
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
            info = _build_step_output_taint(
                name, value, visible_env, lineno, step_id, quoted_single
            )
            if info is not None:
                out[f"{step_id}.{name}"] = info

        # (2) Legacy ``echo "::set-output name=NAME::VALUE"`` form.
        #     Find any echo body that contains a ``::set-output`` token.
        for m in _SET_OUTPUT_RE.finditer(line):
            name = m.group("name")
            value = m.group("value")
            # Heuristic: ``::set-output`` lives inside a quoted echo
            # body in practice, so the value half can include shell
            # ``$VAR`` references that bash WILL expand at echo time.
            # Treat as not-single-quoted for taint propagation.
            info = _build_step_output_taint(
                name,
                value,
                visible_env,
                lineno,
                step_id,
                quoted_single=False,
            )
            if info is not None:
                out[f"{step_id}.{name}"] = info

    return out


def _build_step_output_taint(
    name: str,
    value: str,
    visible_env: dict[str, _TaintInfo],
    lineno: int,
    step_id: str,
    quoted_single: bool,
) -> _TaintInfo | None:
    """Helper: classify the taint, if any, that flows into a step
    output named ``name`` on line ``lineno``.

    Returns ``None`` when the value carries no attacker-controlled
    data.  Otherwise returns a :class:`_TaintInfo` whose ``hops``
    chain is extended by a ``"step_output"`` hop describing the
    ``steps.<step_id>.outputs.<name>`` bridge.
    """
    src = _extract_tainted_source(value)
    if src is not None:
        return _TaintInfo(
            source_expr=src,
            source_line=lineno,
            hops=[
                TaintHop(
                    kind="step_output",
                    line=lineno,
                    name=f"{step_id}.{name}",
                    detail=(f"steps.{step_id}.outputs.{name} := ${{{{ {src} }}}}"),
                )
            ],
        )
    if quoted_single:
        return None
    for var, info in visible_env.items():
        if _references_var(value, var):
            return _TaintInfo(
                source_expr=info.source_expr,
                source_line=info.source_line,
                hops=info.hops
                + [
                    TaintHop(
                        kind="step_output",
                        line=lineno,
                        name=f"{step_id}.{name}",
                        detail=(f"steps.{step_id}.outputs.{name} := ${var}"),
                    )
                ],
            )
    return None
