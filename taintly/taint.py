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

import os
import re
from dataclasses import dataclass, field

from .models import _split_into_job_segments
from .parsers.structural import EventKind, walk_workflow
from .taint_facts import Database, solve

# ---------------------------------------------------------------------------
# Source definitions
# ---------------------------------------------------------------------------

# Attacker-controlled GitHub contexts.  Intentionally enumerated; keep in sync
# with the SEC4-GH-004 regex.
_TAINTED_CONTEXTS = [
    r"github\.event\.pull_request\.title",
    r"github\.event\.pull_request\.body",
    r"github\.event\.pull_request\.head\.ref",
    r"github\.event\.pull_request\.head\.label",
    r"github\.event\.pull_request\.user\.login",
    r"github\.event\.issue\.title",
    r"github\.event\.issue\.body",
    r"github\.event\.comment\.body",
    r"github\.event\.review\.body",
    # ``review_comment.body`` is the inline PR-review comment body — listed
    # alongside the other comment/body fields in GitHub's "Understanding the
    # risk of script injections" untrusted-input table.
    r"github\.event\.review_comment\.body",
    # GitHub Discussions are opened by any user; the discussion event payload
    # ``title`` / ``body`` are attacker-controlled in the same way as the
    # issue equivalents.
    r"github\.event\.discussion\.title",
    r"github\.event\.discussion\.body",
    r"github\.event\.head_commit\.message",
    r"github\.event\.head_commit\.author\.name",
    r"github\.event\.head_commit\.author\.email",
    # The ``committer`` identity of a push/commit is set from git metadata
    # just like ``author`` and is equally attacker-controlled.
    r"github\.event\.head_commit\.committer\.name",
    r"github\.event\.head_commit\.committer\.email",
    # The fork's default branch name (PR head repo) is chosen by the PR
    # author — GitHub documents it as untrusted input.
    r"github\.event\.pull_request\.head\.repo\.default_branch",
    # ``commits`` is the push-event array of commits; element fields
    # (``[0].message``, ``[0].author.name``) carry the same attacker
    # bytes as ``head_commit``.  Word-boundary matching downstream
    # catches array-index accesses.  ``pages`` is the gollum-event
    # array of wiki updates; ``[0].title`` / ``[0].summary`` are
    # attacker-controlled (anyone with wiki access).
    r"github\.event\.commits",
    r"github\.event\.pages",
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

# ``inputs.<name>`` inside an expression body.  A *conditional* taint
# source: in a reusable workflow (``on: workflow_call``) the caller
# decides whether ``inputs.X`` carries attacker-controlled bytes, so
# this is only treated as a source when the file is a reusable
# workflow, and the resulting findings are review-needed (see
# TAINT-GH-017).  Name rules follow the GitHub Actions input grammar.
_INPUT_REF_IN_EXPR_RE = re.compile(r"\binputs\.([A-Za-z_][A-Za-z0-9_-]*)\b")

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

# Relaxed form: ``needs.<job>.outputs.<name>`` appearing ANYWHERE
# inside an expression, not just as the whole ``${{ ... }}`` body.
# ``run:`` / ``runs-on:`` etc. interpolate the bare value so the
# strict form above is right for them; a job ``if:`` is a boolean
# *expression* (``needs.x.outputs.y == 'ok'``), so its taint check
# needs to spot the reference inside the larger condition.
_NEEDS_OUTPUT_IN_EXPR_RE = re.compile(
    r"\bneeds\.([A-Za-z_][A-Za-z0-9_-]*)"
    r"\.outputs\.([A-Za-z_][A-Za-z0-9_-]*)\b"
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
# Used by the facts-model projection (to skip these write lines from
# the generic sink scan — shell expansion inside an echo-to-file is
# safe) and by the ``env_write`` EDB extractor.
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
    source into a workflow sink.

    ``kind`` summarises the *propagation style* so rules can filter on
    it (``"shallow"`` for TAINT-GH-001, ``"multi_hop"`` for
    TAINT-GH-002, ...).  ``sink_kind`` says *where the value landed* —
    ``"run"`` (a ``run:`` shell block — the original and by far the
    most common), ``"runs_on"`` (a ``runs-on:`` value — self-hosted
    runner / label hijack), ``"container_image"`` /
    ``"service_image"`` (a job ``container:`` / ``services.*.image:``
    — attacker-image pull).  ``hops`` carries the per-step provenance.

    The two axes are independent: a cross-job output (``kind`` is
    ``"cross_job"``) can land in a ``run:`` block *or* a ``runs-on:``
    value, and each is a distinct attack class.  Rules filter on the
    pair.  ``sink_kind`` defaults to ``"run"`` so every existing call
    site and rule keeps its current behaviour.
    """

    source_expr: str  # e.g. "github.event.pull_request.title"
    source_line: int  # 1-indexed line of the first env assignment
    env_var: str  # name of the variable/output at the sink hop
    sink_line: int  # 1-indexed line of the sink
    sink_snippet: str  # literal text of that sink line, stripped
    kind: str = "shallow"
    hops: list[TaintHop] = field(default_factory=list)
    sink_kind: str = "run"


# ---------------------------------------------------------------------------
# Internal projection struct
# ---------------------------------------------------------------------------


@dataclass
class _TaintInfo:
    """Internal: a resolved env variable's taint provenance.

    Not part of the public API — the public surface is :class:`TaintPath`
    with its ``hops`` list.  We keep this as a separate struct so we
    don't build the sink hop until we actually see a sink, and so the
    facts-model projection can hand a uniform shape to :func:`_make_path`.
    """

    source_expr: str
    source_line: int
    hops: list[TaintHop]


# ---------------------------------------------------------------------------
# Facts model
#
# The taint subsystem used to run three hand-rolled convergence loops
# (multi-hop env resolution, the order-sensitive step-state pass, the
# cross-job fixed point).  They are collapsed here into ONE relational
# fixed point: extract extensional facts (EDB), saturate the rule set
# with :func:`taintly.taint_facts.solve`, then project the derived
# ``visible_env`` / ``tainted_output`` / ``tainted_job_output``
# relations back onto the legacy job→step→run-line traversal so the
# emitted :class:`TaintPath` list is byte-identical to the old code.
#
# Phase A (this code): the EDB is extracted by reusing the existing,
# proven line-walkers below.  Phase B swaps that extractor for the
# structural parser.
# ---------------------------------------------------------------------------

# Relation names.
_R_ENV_ASSIGN = "env_assign"  # EDB
_R_RUN_LINE = "run_line"  # EDB
_R_ENV_WRITE = "env_write"  # EDB  ($GITHUB_ENV)
_R_OUTPUT_WRITE = "output_write"  # EDB  ($GITHUB_OUTPUT / ::set-output)
_R_AGENT_STEP = "agent_step"  # EDB
_R_OUTPUT_DECL = "output_decl"  # EDB
_R_SINK_SITE = "sink_site"  # EDB  (non-run: sinks — runs-on:, container.image:, ...)
_R_FILE_WRITE = "file_write"  # EDB  (echo <body> >> <ordinary file>)
_R_TAINTED_ENV = "tainted_env"  # IDB
_R_VISIBLE_ENV = "visible_env"  # IDB
_R_TAINTED_DYN_ENV = "tainted_dyn_env"  # IDB
_R_TAINTED_OUTPUT = "tainted_output"  # IDB
_R_TAINTED_JOB_OUTPUT = "tainted_job_output"  # IDB
_R_TAINTED_FILE = "tainted_file"  # IDB  (a file path holds attacker bytes)


@dataclass
class _EnvAssign:
    """EDB: an ``env:`` assignment at ``scope`` — ``("job", job_id)``
    or ``("step", job_id, idx)``."""

    scope: tuple
    name: str
    raw: str
    line: int

    def fact_key(self):
        return (self.scope, self.name, self.line)

    def fact_rank(self):
        return ()


@dataclass
class _RunLine:
    """EDB: one shell line participating in a ``run:`` body.

    ``text`` is what sink detection runs against — the *shell* command
    (the structural backend hands the parsed value, with any YAML
    quote-wrapper already stripped, so a fully YAML-single-quoted
    ``run: 'echo "$X"'`` is correctly seen as a double-quoted shell
    sink).  ``snippet`` is the raw source line, used only for the
    displayed ``TaintPath.sink_snippet`` so the rendered finding stays
    byte-identical to the line backend.  For the line backend the two
    are the same string.
    """

    job: str
    idx: int
    line: int
    text: str
    snippet: str

    def fact_key(self):
        return (self.job, self.idx, self.line)

    def fact_rank(self):
        return ()


@dataclass
class _SinkSite:
    """EDB: a non-``run:`` job-level key whose value is server-side
    substituted and therefore a taint sink in its own right.

    ``kind`` is the sink class — ``"runs_on"`` (a ``runs-on:`` value:
    self-hosted runner / label hijack), ``"container_image"`` (a job
    ``container:`` / ``container.image:``: attacker-image pull), or
    ``"service_image"`` (a ``services.*.image:``).  ``value`` is the
    raw scalar; the projection scans it for ``${{ needs.* }}`` /
    ``${{ env.* }}`` references against the closure's
    ``tainted_job_output`` / ``tainted_env`` relations.

    Job-level (no step index): ``runs-on`` / ``container`` /
    ``services`` are all resolved before any step runs.  ``value`` is
    the parsed scalar (drives detection); ``snippet`` is the raw
    source line (the displayed ``sink_snippet``).
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
class _EnvWrite:
    """EDB: an ``echo "NAME=VALUE" >> $GITHUB_ENV`` write."""

    job: str
    idx: int
    name: str
    value: str
    line: int
    quoted_single: bool
    seq: int

    def fact_key(self):
        return (self.job, self.idx, self.name, self.seq)

    def fact_rank(self):
        return ()


@dataclass
class _OutputWrite:
    """EDB: an ``echo "name=VALUE" >> $GITHUB_OUTPUT`` (or legacy
    ``::set-output``) write in a step that carries an ``id:``."""

    job: str
    idx: int
    step_id: str
    name: str
    value: str
    line: int
    quoted_single: bool
    seq: int

    def fact_key(self):
        return (self.job, self.idx, self.step_id, self.name, self.seq)

    def fact_rank(self):
        return ()


@dataclass
class _FileWrite:
    """EDB: an ``echo <body> >>? <path>`` write to an ordinary file.

    ``value`` is the echo body (drives taint detection — resolved
    against the writing step's ``visible_env``, like a ``$GITHUB_ENV``
    write); ``path`` is the redirect target.  Files persist for the
    whole job, so a later step that *executes* the path (``source`` /
    ``bash`` / ...) consumes whatever was written before it.
    """

    job: str
    idx: int
    line: int
    seq: int
    path: str
    value: str
    quoted_single: bool

    def fact_key(self):
        return (self.job, self.idx, self.line, self.seq, self.path)

    def fact_rank(self):
        return ()


@dataclass
class _AgentStep:
    """EDB: a step whose ``uses:`` matches a known AI coding-agent
    action — its outputs are attacker-shaped by prompt injection."""

    job: str
    idx: int
    step_id: str
    action: str
    line: int

    def fact_key(self):
        return (self.job, self.idx, self.step_id)

    def fact_rank(self):
        return ()


@dataclass
class _OutputDecl:
    """EDB: an entry in a job's ``outputs:`` block."""

    job: str
    name: str
    raw: str
    line: int

    def fact_key(self):
        return (self.job, self.name)

    def fact_rank(self):
        return ()


@dataclass
class _TaintedEnv:
    """IDB: an ``env:`` variable at ``scope`` carries attacker bytes."""

    scope: tuple
    name: str
    source_expr: str
    source_line: int
    hops: list[TaintHop]

    def fact_key(self):
        return (self.scope, self.name)

    def fact_rank(self):
        # Keep the shortest proof; tie-break deterministically.
        return (len(self.hops), self.source_line)


@dataclass
class _VisibleEnv:
    """IDB: variable ``name`` carries attacker bytes in the environment
    *as seen by* step ``idx`` of ``job``.

    ``cls`` encodes scope precedence so the store keeps the value the
    runner would actually expand: ``0`` dynamic ``$GITHUB_ENV`` write
    (most specific — newest write wins via ``-writer_idx``), ``1``
    job-level ``env:``, ``2`` step-level ``env:``.  This mirrors the
    old ``{**job_env, **dynamic_env, **step_env}`` layering, where a
    step-level re-declaration is ignored if the name already resolved
    at job or dynamic scope.
    """

    job: str
    idx: int
    name: str
    cls: int
    writer_idx: int
    source_expr: str
    source_line: int
    hops: list[TaintHop]

    def fact_key(self):
        return (self.job, self.idx, self.name)

    def fact_rank(self):
        return (self.cls, -self.writer_idx, len(self.hops), self.source_line)


@dataclass
class _TaintedDynEnv:
    """IDB: a ``$GITHUB_ENV`` write at step ``writer_idx`` taints
    ``name`` for every later step in the job."""

    job: str
    writer_idx: int
    name: str
    seq: int
    source_expr: str
    source_line: int
    hops: list[TaintHop]

    def fact_key(self):
        return (self.job, self.writer_idx, self.name)

    def fact_rank(self):
        # Last write in source order wins (matches dict-update order
        # of the old ``dynamic_env`` running state).
        return (-self.seq, len(self.hops))


@dataclass
class _TaintedOutput:
    """IDB: ``steps.<step_id>.outputs.<name>`` carries attacker bytes.

    ``writer_idx`` is the step index of the writing step; a
    ``${{ steps.<id>.outputs.<name> }}`` reference only sees the value
    from a *strictly later* step (the runner materialises
    ``$GITHUB_OUTPUT`` between steps), so the projection gates the
    sink on ``sink_idx > writer_idx``.
    """

    step_id: str
    name: str
    writer_idx: int
    seq: int
    source_expr: str
    source_line: int
    hops: list[TaintHop]

    def fact_key(self):
        return (self.step_id, self.name)

    def fact_rank(self):
        return (-self.seq, len(self.hops))


@dataclass
class _TaintedJobOutput:
    """IDB: a job's declared ``outputs.<name>`` carries attacker bytes."""

    job: str
    name: str
    source_expr: str
    source_line: int
    hops: list[TaintHop]

    def fact_key(self):
        return (self.job, self.name)

    def fact_rank(self):
        return (len(self.hops), self.source_line)


@dataclass
class _TaintedFile:
    """IDB: a file ``path`` in ``job`` holds attacker-controlled bytes,
    written at step ``writer_idx`` / line ``writer_line``.  A later
    run line that *executes* ``path`` (``source`` / ``.`` / ``bash`` /
    ``sh`` / ``zsh``) is a sink — gated on the exec position being
    strictly after ``(writer_idx, writer_line)`` in program order
    (files persist for the whole job)."""

    job: str
    path: str
    writer_idx: int
    writer_line: int
    seq: int
    source_expr: str
    source_line: int
    hops: list[TaintHop]

    def fact_key(self):
        return (self.job, self.path)

    def fact_rank(self):
        return (-self.seq, len(self.hops))


# --- Job / step structure (the spine the EDB extractor walks) --------------


@dataclass
class _Step:
    idx: int
    start: int
    lines: list[str]
    step_id: str | None


@dataclass
class _Job:
    job_id: str | None
    seg_start: int
    seg_lines: list[str]
    steps: list[_Step]  # synthetic single step for step-less jobs


# --- EDB extraction --------------------------------------------------------


def _iter_env_writes(text: str):
    """Yield ``(name, value, quoted_single)`` for each
    ``echo "NAME=VALUE" >> $GITHUB_ENV`` write in ``text``."""
    for m in _ECHO_TO_GITHUB_ENV_RE.finditer(text):
        yield from _echo_body_name_value(m)


def _iter_output_writes(text: str):
    """Yield ``(name, value, quoted_single)`` for each
    ``$GITHUB_OUTPUT`` / legacy ``::set-output`` write in ``text``."""
    for m in _ECHO_TO_GITHUB_OUTPUT_RE.finditer(text):
        yield from _echo_body_name_value(m)
    for m in _SET_OUTPUT_RE.finditer(text):
        # ``::set-output`` lives inside a quoted echo body; the value
        # half can carry shell ``$VAR`` refs bash expands at echo time.
        yield (m.group("name"), m.group("value"), False)


def _echo_body_name_value(m):
    """Pull ``(name, value, quoted_single)`` out of a matched
    ``_ECHO_TO_GITHUB_{ENV,OUTPUT}_RE`` echo body."""
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


def _iter_file_writes(text: str):
    """Yield ``(path, value, quoted_single)`` for each
    ``echo <body> >>? <path>`` write in ``text`` to an *ordinary* file
    — the ``$GITHUB_ENV`` / ``$GITHUB_OUTPUT`` redirect targets are
    skipped here because they have their own dedicated detectors."""
    for m in _ECHO_TO_FILE_RE.finditer(text):
        path = m.group("file")
        if "GITHUB_ENV" in path or "GITHUB_OUTPUT" in path:
            continue
        dq, sq, bare = m.group("dq"), m.group("sq"), m.group("bare")
        if dq is not None:
            value = re.sub(r"\\(.)", r"\1", dq)
            quoted_single = False
        elif sq is not None:
            value = sq
            quoted_single = True
        else:
            value = bare or ""
            quoted_single = False
        yield (path, value, quoted_single)


# A reusable workflow declares ``on: workflow_call`` (scalar, list, or
# block-mapping form).  In such a file ``${{ inputs.<name> }}`` is a
# conditional taint source (the caller decides what it carries) — see
# :func:`_extract_tainted_source` and TAINT-GH-017.
_WORKFLOW_CALL_RE = re.compile(
    r"(?m)^on:\s*workflow_call\s*$"
    r"|^on:\s*\[[^\]]*\bworkflow_call\b"
    r"|^[ \t]+workflow_call\s*:"
)


def _build_facts(lines: list[str]) -> tuple[Database, list[_Job]]:
    """Extract the extensional facts (EDB) for ``lines`` and run the
    closure.  Returns the saturated :class:`Database` and the job/step
    spine the projection walks."""
    db = Database()
    jobs: list[_Job] = []
    is_reusable = bool(_WORKFLOW_CALL_RE.search("\n".join(lines)))
    _seq = 0  # global source order for write facts

    for seg_start, seg_lines in _split_into_job_segments(lines):
        job_id = _extract_job_id(seg_lines)
        raw_steps = list(_iter_steps(seg_lines, seg_start))

        if not raw_steps:
            # Step-less job (reusable workflow etc.): one synthetic
            # step, every env block at job scope, every run line a
            # candidate sink.  Matches the old ``_analyze_job``
            # no-steps fallback.
            job_key = job_id if job_id is not None else f"<seg@{seg_start}>"
            for name, raw, line in _collect_all_env_assignments(seg_lines, seg_start):
                db.add(_R_ENV_ASSIGN, _EnvAssign(("job", job_key), name, raw, line))
            for lineno in _collect_run_line_numbers(seg_lines, seg_start):
                raw_line = lines[lineno - 1]
                db.add(_R_RUN_LINE, _RunLine(job_key, 0, lineno, raw_line, raw_line))
            steps = [_Step(0, seg_start, seg_lines, None)]
            if job_id is not None:
                for name, (raw, line) in _collect_declared_outputs(seg_lines, seg_start).items():
                    db.add(_R_OUTPUT_DECL, _OutputDecl(job_id, name, raw, line))
            jobs.append(_Job(job_id, seg_start, seg_lines, steps))
            continue

        job_key = job_id if job_id is not None else f"<seg@{seg_start}>"
        # Job-level env: block.
        for name, raw, line in _collect_job_level_env_assignments(seg_lines, seg_start):
            db.add(_R_ENV_ASSIGN, _EnvAssign(("job", job_key), name, raw, line))

        steps = []
        for idx, (step_start, step_lines) in enumerate(raw_steps):
            step_id = _get_step_id(step_lines)
            steps.append(_Step(idx, step_start, step_lines, step_id))

            # Step-level env: blocks.
            for name, raw, line in _collect_all_env_assignments(step_lines, step_start):
                db.add(_R_ENV_ASSIGN, _EnvAssign(("step", job_key, idx), name, raw, line))

            # run: sink lines + $GITHUB_ENV / $GITHUB_OUTPUT / file writes.
            for lineno in _collect_run_line_numbers(step_lines, step_start):
                text = lines[lineno - 1]
                db.add(_R_RUN_LINE, _RunLine(job_key, idx, lineno, text, text))
                for name, value, qs in _iter_env_writes(text):
                    db.add(
                        _R_ENV_WRITE,
                        _EnvWrite(job_key, idx, name, value, lineno, qs, _seq),
                    )
                    _seq += 1
                if step_id is not None:
                    for name, value, qs in _iter_output_writes(text):
                        db.add(
                            _R_OUTPUT_WRITE,
                            _OutputWrite(job_key, idx, step_id, name, value, lineno, qs, _seq),
                        )
                        _seq += 1
                for fpath, value, qs in _iter_file_writes(text):
                    db.add(
                        _R_FILE_WRITE,
                        _FileWrite(job_key, idx, lineno, _seq, fpath, value, qs),
                    )
                    _seq += 1

            # Agent-action step: outputs are attacker-shaped.
            if step_id is not None:
                for ln in step_lines:
                    am = _AGENT_USES_RE.search(ln)
                    if am:
                        src_line = step_start + step_lines.index(ln) + 1
                        db.add(
                            _R_AGENT_STEP,
                            _AgentStep(job_key, idx, step_id, am.group(1), src_line),
                        )
                        break

        if job_id is not None:
            for name, (raw, line) in _collect_declared_outputs(seg_lines, seg_start).items():
                db.add(_R_OUTPUT_DECL, _OutputDecl(job_id, name, raw, line))

        jobs.append(_Job(job_id, seg_start, seg_lines, steps))

    solve(db, _github_rules(jobs, is_reusable))
    return db, jobs


# --- EDB extraction: Phase B (structural parser) ---------------------------

# AI coding-agent ``uses:`` value matcher.  ``_AGENT_USES_RE`` expects
# the literal ``uses: <value>`` line; the structural parser hands us
# just the value, so we match the ``<owner>/<repo>@<rev>`` shape
# directly.
_AGENT_USES_VALUE_RE = re.compile(rf"^([^@\s/]+/[^@\s]*(?:{AI_AGENT_KEYWORDS})[^@\s]*)@")


def _build_facts_structural(content: str, lines: list[str]) -> tuple[Database, list[_Job]]:
    """Phase B EDB extractor: source the extensional facts from the
    structural parser (``taintly.parsers.structural``) instead of the
    line-walkers.

    Produces the *same* relation shapes as :func:`_build_facts`, so the
    closure rule set and the projection in :func:`analyze` are shared
    unchanged.  Scope is held identical to Phase A on purpose — job-
    and step-level ``env:`` only, no workflow-level ``env:`` — so a
    backend comparison isolates *parsing* differences (flow-style
    blocks, anchors, CUTOFF coverage) from *coverage-scope* changes.

    ``RunLine.text`` is taken from the raw source line (``lines``),
    not the structural parser's parsed value — the structural parser
    decides *which* lines are run-body lines, but the sink snippet
    stays byte-identical to Phase A so the cutover is a true zero-diff.
    """
    n_lines = len(lines)

    def _src(line_no: int, fallback: str) -> str:
        return lines[line_no - 1] if 1 <= line_no <= n_lines else fallback

    # The ``id:`` leaf of a step can appear after its ``uses:`` /
    # ``run:`` in source order, so the walk buffers raw extractions and
    # the facts are built once every step id is known.
    job_order: list[str] = []
    job_step_idx: dict[str, set[int]] = {}
    job_step_id: dict[tuple[str, int], str | None] = {}
    env_assigns: list[_EnvAssign] = []
    output_decls: list[_OutputDecl] = []
    sink_sites: list[_SinkSite] = []
    # (job, idx, src_line, text, snippet) — ``text`` is the parsed
    # shell command (sink detection runs on it), ``snippet`` is the
    # raw source line (the displayed sink_snippet).
    run_units: list[tuple[str, int, int, str, str]] = []
    uses_hits: list[tuple[str, int, str, int]] = []  # (job, idx, action, line)
    is_reusable = False

    def _note_job(job: str) -> None:
        if job not in job_step_idx:
            job_step_idx[job] = set()
            job_order.append(job)

    def _note_step(job: str, idx: int) -> None:
        _note_job(job)
        job_step_idx[job].add(idx)
        job_step_id.setdefault((job, idx), None)

    for ev in walk_workflow("workflow.yml", content=content):
        if ev.kind is EventKind.CUTOFF:
            # Coverage degraded from here on — the contract guarantees
            # no further events.  Facts gathered before the cutoff
            # stay valid; downstream jobs simply go unanalysed.
            break
        if ev.kind is not EventKind.LEAF_SCALAR:
            continue
        path = ev.path
        # ``on: workflow_call`` in any of its three shapes — scalar
        # ``("on",)``, list ``("on", <i>)``, or block-mapping
        # ``("on", "workflow_call", ...)``.
        if path and path[0] == "on" and ("workflow_call" in path or ev.value == "workflow_call"):
            is_reusable = True
        if len(path) < 2 or path[0] != "jobs":
            continue
        job = path[1]
        if not isinstance(job, str):
            continue
        rest = path[2:]

        # jobs.<job>.env.<name>
        if len(rest) == 2 and rest[0] == "env" and isinstance(rest[1], str):
            _note_job(job)
            env_assigns.append(_EnvAssign(("job", job), rest[1], ev.value or "", ev.line))
            continue
        # jobs.<job>.outputs.<name>
        if len(rest) == 2 and rest[0] == "outputs" and isinstance(rest[1], str):
            _note_job(job)
            output_decls.append(_OutputDecl(job, rest[1], ev.value or "", ev.line))
            continue
        # Non-run: sink sites — all job-level, all server-side
        # substituted before any step runs.
        #   jobs.<job>.runs-on            (scalar or list)
        #   jobs.<job>.container          (scalar `node:14` form)
        #   jobs.<job>.container.image
        #   jobs.<job>.services.<name>.image
        if (
            rest
            and rest[0] == "runs-on"
            and (len(rest) == 1 or (len(rest) == 2 and isinstance(rest[1], int)))
        ):
            _note_job(job)
            val = ev.value or ""
            sink_sites.append(_SinkSite(job, "runs_on", ev.line, val, _src(ev.line, val)))
            continue
        if rest == ("container",) or rest == ("container", "image"):
            _note_job(job)
            val = ev.value or ""
            sink_sites.append(_SinkSite(job, "container_image", ev.line, val, _src(ev.line, val)))
            continue
        if (
            len(rest) == 3
            and rest[0] == "services"
            and isinstance(rest[1], str)
            and rest[2] == "image"
        ):
            _note_job(job)
            val = ev.value or ""
            sink_sites.append(_SinkSite(job, "service_image", ev.line, val, _src(ev.line, val)))
            continue
        # jobs.<job>.if — a job-level gate condition.  Server-side
        # evaluated before the job runs; a cross-job tainted output in
        # it lets the attacker control whether the (often privileged)
        # job runs at all.  Job ``if:`` cannot see ``env:``, so only
        # the cross-job shape is a flow here.
        if rest == ("if",):
            _note_job(job)
            val = ev.value or ""
            sink_sites.append(_SinkSite(job, "if", ev.line, val, _src(ev.line, val)))
            continue
        # jobs.<job>.steps[idx]....
        if len(rest) >= 2 and rest[0] == "steps" and isinstance(rest[1], int):
            idx = rest[1]
            _note_step(job, idx)
            tail = rest[2:]
            if len(tail) == 2 and tail[0] == "env" and isinstance(tail[1], str):
                env_assigns.append(_EnvAssign(("step", job, idx), tail[1], ev.value or "", ev.line))
            elif tail == ("id",):
                job_step_id[(job, idx)] = ev.value
            elif tail == ("uses",):
                m = _AGENT_USES_VALUE_RE.search(ev.value or "")
                if m:
                    uses_hits.append((job, idx, m.group(1), ev.line))
            elif tail == ("run",):
                if ev.block_lines:
                    # Block-scalar body lines are never YAML-quoted, so
                    # the raw source line is also the shell command.
                    for src_line, body in ev.block_lines:
                        if body.lstrip().startswith("#"):
                            continue
                        raw = _src(src_line, body)
                        run_units.append((job, idx, src_line, raw, raw))
                else:
                    # Inline ``run:`` — detect against the parsed value
                    # (YAML quote-wrapper stripped), display the raw line.
                    if (ev.value or "").lstrip().startswith("#"):
                        continue
                    run_units.append(
                        (job, idx, ev.line, ev.value or "", _src(ev.line, ev.value or ""))
                    )

    # Build the job spine.
    jobs: list[_Job] = []
    for job in job_order:
        steps = [
            _Step(idx, -1, [], job_step_id.get((job, idx))) for idx in sorted(job_step_idx[job])
        ]
        jobs.append(_Job(job, -1, [], steps))

    # Build the EDB now that step ids are resolved.
    db = Database()
    for ea in env_assigns:
        db.add(_R_ENV_ASSIGN, ea)
    for od in output_decls:
        db.add(_R_OUTPUT_DECL, od)
    for ss in sink_sites:
        db.add(_R_SINK_SITE, ss)
    for job, idx, action, line in uses_hits:
        sid = job_step_id.get((job, idx))
        if sid:
            db.add(_R_AGENT_STEP, _AgentStep(job, idx, sid, action, line))
    _seq = 0
    for job, idx, src_line, text, snippet in run_units:
        db.add(_R_RUN_LINE, _RunLine(job, idx, src_line, text, snippet))
        for name, value, qs in _iter_env_writes(text):
            db.add(_R_ENV_WRITE, _EnvWrite(job, idx, name, value, src_line, qs, _seq))
            _seq += 1
        sid = job_step_id.get((job, idx))
        if sid:
            for name, value, qs in _iter_output_writes(text):
                db.add(
                    _R_OUTPUT_WRITE,
                    _OutputWrite(job, idx, sid, name, value, src_line, qs, _seq),
                )
                _seq += 1
        for fpath, value, qs in _iter_file_writes(text):
            db.add(
                _R_FILE_WRITE,
                _FileWrite(job, idx, src_line, _seq, fpath, value, qs),
            )
            _seq += 1

    solve(db, _github_rules(jobs, is_reusable))
    return db, jobs


def _taint_backend() -> str:
    """Which EDB extractor :func:`analyze` uses.

    ``"structural"`` (default) — Phase B, the structural-parser
    extractor.  Promoted to default after the A/B comparison measured
    it byte-identical to the line backend on the in-repo corpus
    (including all 127 no-rules-change-gate fixtures) and a strict
    precision improvement on a 551-file wild corpus.

    ``"line"`` — Phase A, the line-walker extractor.  Retained as the
    comparison baseline and an escape hatch.

    Selected via the ``TAINTLY_TAINT_BACKEND`` environment variable.
    """
    return os.environ.get("TAINTLY_TAINT_BACKEND", "structural")


# --- Closure rules ---------------------------------------------------------


def _github_rules(jobs: list[_Job], is_reusable: bool = False):
    """Build the rule set for ``jobs``.  Each rule is
    ``fn(db) -> Iterable[(relation, fact)]``; :func:`solve` saturates
    them.  The job/step spine is captured so visibility rules can fan
    a job-scope taint across every step index.

    ``is_reusable`` — the file is a reusable workflow
    (``on: workflow_call``), so ``${{ inputs.<name> }}`` is treated as
    a (conditional) taint source by every source-extracting rule.
    """

    job_step_idxs: dict[str, list[int]] = {}
    for job in jobs:
        key = job.job_id if job.job_id is not None else f"<seg@{job.seg_start}>"
        job_step_idxs[key] = [s.idx for s in job.steps]

    def rule_tainted_env(db: Database):
        # Direct attacker context, multi-hop ${{ env.X }}, and
        # env-mediated cross-job ${{ needs.X.outputs.Y }} — the three
        # ways an ``env:`` assignment becomes tainted.
        for ea in db.all(_R_ENV_ASSIGN):
            if db.has(_R_TAINTED_ENV, (ea.scope, ea.name)):
                # Shortest-proof dedup still applies, but a resolved
                # var never needs re-deriving from a longer chain.
                pass
            # (a) direct.
            src = _extract_tainted_source(ea.raw, is_reusable)
            if src is not None:
                yield (
                    _R_TAINTED_ENV,
                    _TaintedEnv(
                        ea.scope,
                        ea.name,
                        src,
                        ea.line,
                        [
                            TaintHop(
                                kind="env_static",
                                line=ea.line,
                                name=ea.name,
                                detail=f"env {ea.name} := ${{{{ {src} }}}}",
                            )
                        ],
                    ),
                )
                continue
            # (b) multi-hop ${{ env.OTHER }}.
            other = _extract_env_ref(ea.raw)
            if other is not None:
                parent = None
                if ea.scope[0] == "job":
                    parent = db.get(_R_TAINTED_ENV, (ea.scope, other))
                else:  # ("step", job, idx)
                    parent = db.get(_R_VISIBLE_ENV, (ea.scope[1], ea.scope[2], other))
                if parent is not None:
                    yield (
                        _R_TAINTED_ENV,
                        _TaintedEnv(
                            ea.scope,
                            ea.name,
                            parent.source_expr,
                            parent.source_line,
                            parent.hops
                            + [
                                TaintHop(
                                    kind="env_indirect",
                                    line=ea.line,
                                    name=ea.name,
                                    detail=f"env {ea.name} := ${{{{ env.{other} }}}}",
                                )
                            ],
                        ),
                    )
                    continue
            # (c) cross-job ${{ needs.X.outputs.Y }}.
            for nm in _NEEDS_OUTPUT_REF_RE.finditer(ea.raw):
                up = db.get(_R_TAINTED_JOB_OUTPUT, (nm.group(1), nm.group(2)))
                if up is not None:
                    yield (
                        _R_TAINTED_ENV,
                        _TaintedEnv(
                            ea.scope,
                            ea.name,
                            up.source_expr,
                            up.source_line,
                            up.hops
                            + [
                                TaintHop(
                                    kind="needs_ref",
                                    line=ea.line,
                                    name=ea.name,
                                    detail=(
                                        f"env {ea.name} := "
                                        f"${{{{ needs.{nm.group(1)}.outputs.{nm.group(2)} }}}}"
                                    ),
                                )
                            ],
                        ),
                    )
                    break

    def rule_visible_env(db: Database):
        # Fan tainted_env / tainted_dyn_env onto the per-step
        # ``visible_env`` relation, carrying scope precedence in ``cls``.
        #
        # A step that re-declares a variable in its own ``env:`` block
        # SHADOWS the job-level and dynamic-write values for that name
        # at that step — ``env:`` set directly on the step is what the
        # runner exports.  So a step-local ``env: VAR: <clean literal>``
        # over a job-tainted ``VAR`` un-taints ``VAR`` at that step's
        # sinks (and a step-local tainted re-declaration is carried by
        # the step-scope ``tainted_env`` branch below instead).  Not
        # suppressing this is the clean-override false positive.
        step_redecl = {
            (ea.scope[1], ea.scope[2], ea.name)
            for ea in db.all(_R_ENV_ASSIGN)
            if ea.scope[0] == "step"
        }
        for te in db.all(_R_TAINTED_ENV):
            if te.scope[0] == "job":
                job = te.scope[1]
                for idx in job_step_idxs.get(job, []):
                    if (job, idx, te.name) in step_redecl:
                        continue  # step's own env: governs this name
                    yield (
                        _R_VISIBLE_ENV,
                        _VisibleEnv(
                            job, idx, te.name, 1, -1, te.source_expr, te.source_line, te.hops
                        ),
                    )
            else:  # step scope
                _, job, idx = te.scope
                yield (
                    _R_VISIBLE_ENV,
                    _VisibleEnv(job, idx, te.name, 2, -1, te.source_expr, te.source_line, te.hops),
                )
        for tde in db.all(_R_TAINTED_DYN_ENV):
            for idx in job_step_idxs.get(tde.job, []):
                if idx > tde.writer_idx and (tde.job, idx, tde.name) not in step_redecl:
                    yield (
                        _R_VISIBLE_ENV,
                        _VisibleEnv(
                            tde.job,
                            idx,
                            tde.name,
                            0,
                            tde.writer_idx,
                            tde.source_expr,
                            tde.source_line,
                            tde.hops,
                        ),
                    )

    def rule_tainted_dyn_env(db: Database):
        for ew in db.all(_R_ENV_WRITE):
            # (a) direct attacker context embedded in the echo body.
            src = _extract_tainted_source(ew.value, is_reusable)
            if src is not None:
                yield (
                    _R_TAINTED_DYN_ENV,
                    _TaintedDynEnv(
                        ew.job,
                        ew.idx,
                        ew.name,
                        ew.seq,
                        src,
                        ew.line,
                        [
                            TaintHop(
                                kind="github_env",
                                line=ew.line,
                                name=ew.name,
                                detail=f"$GITHUB_ENV {ew.name} := ${{{{ {src} }}}}",
                            )
                        ],
                    ),
                )
                continue
            # (b) indirect: shell ref to an already-tainted visible var.
            if ew.quoted_single:
                continue
            for ve in db.all(_R_VISIBLE_ENV):
                if ve.job == ew.job and ve.idx == ew.idx and _references_var(ew.value, ve.name):
                    yield (
                        _R_TAINTED_DYN_ENV,
                        _TaintedDynEnv(
                            ew.job,
                            ew.idx,
                            ew.name,
                            ew.seq,
                            ve.source_expr,
                            ve.source_line,
                            ve.hops
                            + [
                                TaintHop(
                                    kind="github_env",
                                    line=ew.line,
                                    name=ew.name,
                                    detail=f"$GITHUB_ENV {ew.name} := ${ve.name}",
                                )
                            ],
                        ),
                    )
                    break

    def rule_tainted_file(db: Database):
        # A file written with attacker-controlled bytes.  Same value
        # resolution as a $GITHUB_ENV write — direct attacker context
        # in the echo body, or a shell ref to an already-tainted
        # visible env var of the writing step.
        for fw in db.all(_R_FILE_WRITE):
            src = _extract_tainted_source(fw.value, is_reusable)
            if src is not None:
                yield (
                    _R_TAINTED_FILE,
                    _TaintedFile(
                        fw.job,
                        fw.path,
                        fw.idx,
                        fw.line,
                        fw.seq,
                        src,
                        fw.line,
                        [
                            TaintHop(
                                kind="file_write",
                                line=fw.line,
                                name=fw.path,
                                detail=f"file {fw.path} := ${{{{ {src} }}}}",
                            )
                        ],
                    ),
                )
                continue
            if fw.quoted_single:
                continue
            for ve in db.all(_R_VISIBLE_ENV):
                if ve.job == fw.job and ve.idx == fw.idx and _references_var(fw.value, ve.name):
                    yield (
                        _R_TAINTED_FILE,
                        _TaintedFile(
                            fw.job,
                            fw.path,
                            fw.idx,
                            fw.line,
                            fw.seq,
                            ve.source_expr,
                            ve.source_line,
                            ve.hops
                            + [
                                TaintHop(
                                    kind="file_write",
                                    line=fw.line,
                                    name=fw.path,
                                    detail=f"file {fw.path} := ${ve.name}",
                                )
                            ],
                        ),
                    )
                    break

    def rule_tainted_output(db: Database):
        for ow in db.all(_R_OUTPUT_WRITE):
            src = _extract_tainted_source(ow.value, is_reusable)
            if src is not None:
                yield (
                    _R_TAINTED_OUTPUT,
                    _TaintedOutput(
                        ow.step_id,
                        ow.name,
                        ow.idx,
                        ow.seq,
                        src,
                        ow.line,
                        [
                            TaintHop(
                                kind="step_output",
                                line=ow.line,
                                name=f"{ow.step_id}.{ow.name}",
                                detail=(
                                    f"steps.{ow.step_id}.outputs.{ow.name} := ${{{{ {src} }}}}"
                                ),
                            )
                        ],
                    ),
                )
                continue
            if ow.quoted_single:
                continue
            for ve in db.all(_R_VISIBLE_ENV):
                if ve.job == ow.job and ve.idx == ow.idx and _references_var(ow.value, ve.name):
                    yield (
                        _R_TAINTED_OUTPUT,
                        _TaintedOutput(
                            ow.step_id,
                            ow.name,
                            ow.idx,
                            ow.seq,
                            ve.source_expr,
                            ve.source_line,
                            ve.hops
                            + [
                                TaintHop(
                                    kind="step_output",
                                    line=ow.line,
                                    name=f"{ow.step_id}.{ow.name}",
                                    detail=(f"steps.{ow.step_id}.outputs.{ow.name} := ${ve.name}"),
                                )
                            ],
                        ),
                    )
                    break

    def rule_tainted_job_output(db: Database):
        # Four ways a declared output becomes tainted, in priority
        # order (direct > step-output ref > env ref > transitive
        # cross-job ref).  ``end_env`` for the env-ref case is the
        # job-level env plus every $GITHUB_ENV write in the job.
        for od in db.all(_R_OUTPUT_DECL):
            src = _extract_tainted_source(od.raw, is_reusable)
            if src is not None:
                yield (
                    _R_TAINTED_JOB_OUTPUT,
                    _TaintedJobOutput(
                        od.job,
                        od.name,
                        src,
                        od.line,
                        [
                            TaintHop(
                                kind="job_output",
                                line=od.line,
                                name=f"{od.job}.{od.name}",
                                detail=(
                                    f"job {od.job} declared output {od.name} := ${{{{ {src} }}}}"
                                ),
                            )
                        ],
                    ),
                )
                continue
            sm = _STEP_OUTPUT_REF_RE.search(od.raw)
            if sm is not None:
                up = db.get(_R_TAINTED_OUTPUT, (sm.group(1), sm.group(2)))
                if up is not None:
                    yield (
                        _R_TAINTED_JOB_OUTPUT,
                        _TaintedJobOutput(
                            od.job,
                            od.name,
                            up.source_expr,
                            up.source_line,
                            up.hops
                            + [
                                TaintHop(
                                    kind="job_output",
                                    line=od.line,
                                    name=f"{od.job}.{od.name}",
                                    detail=(
                                        f"job {od.job} declared output {od.name} "
                                        f":= ${{{{ steps.{sm.group(1)}.{sm.group(2)} }}}}"
                                    ),
                                )
                            ],
                        ),
                    )
                    continue
            em = _ENV_REF_RE.search(od.raw)
            if em is not None:
                up = db.get(_R_TAINTED_ENV, (("job", od.job), em.group(1)))
                if up is None:
                    # Also consult $GITHUB_ENV writes in this job.
                    best = None
                    for tde in db.all(_R_TAINTED_DYN_ENV):
                        if tde.job == od.job and tde.name == em.group(1):
                            if best is None or tde.seq > best.seq:
                                best = tde
                    up = best
                if up is not None:
                    yield (
                        _R_TAINTED_JOB_OUTPUT,
                        _TaintedJobOutput(
                            od.job,
                            od.name,
                            up.source_expr,
                            up.source_line,
                            up.hops
                            + [
                                TaintHop(
                                    kind="job_output",
                                    line=od.line,
                                    name=f"{od.job}.{od.name}",
                                    detail=(
                                        f"job {od.job} declared output {od.name} "
                                        f":= ${{{{ env.{em.group(1)} }}}}"
                                    ),
                                )
                            ],
                        ),
                    )
                    continue
            nm = _NEEDS_OUTPUT_REF_RE.search(od.raw)
            if nm is not None:
                up = db.get(_R_TAINTED_JOB_OUTPUT, (nm.group(1), nm.group(2)))
                if up is not None:
                    yield (
                        _R_TAINTED_JOB_OUTPUT,
                        _TaintedJobOutput(
                            od.job,
                            od.name,
                            up.source_expr,
                            up.source_line,
                            up.hops
                            + [
                                TaintHop(
                                    kind="job_output",
                                    line=od.line,
                                    name=f"{od.job}.{od.name}",
                                    detail=(
                                        f"job {od.job} declared output {od.name} "
                                        f":= ${{{{ needs.{nm.group(1)}.outputs.{nm.group(2)} }}}}"
                                    ),
                                )
                            ],
                        ),
                    )

    return [
        rule_tainted_env,
        rule_visible_env,
        rule_tainted_dyn_env,
        rule_tainted_file,
        rule_tainted_output,
        rule_tainted_job_output,
    ]


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
      shell sink.

    Rules filter on ``kind`` to decide which findings to surface.

    Implementation: the dataflow is computed by a single relational
    fixed point (see :func:`_build_facts`); this function projects the
    saturated relations back onto the legacy job→step→run-line
    traversal so the emitted path order is unchanged.
    """
    if _taint_backend() == "structural":
        db, jobs = _build_facts_structural(content, lines)
    else:
        db, jobs = _build_facts(lines)
    out: list[TaintPath] = []
    for job in jobs:
        job_key = job.job_id if job.job_id is not None else f"<seg@{job.seg_start}>"
        for step in job.steps:
            run_lines = [
                rl for rl in db.all(_R_RUN_LINE) if rl.job == job_key and rl.idx == step.idx
            ]
            run_lines.sort(key=lambda rl: rl.line)
            for rl in run_lines:
                # ``line`` drives sink detection (the parsed shell
                # command); ``snippet`` is the displayed source text.
                line = rl.text
                snippet = rl.snippet.strip()
                if _GITHUB_ENV_REDIRECT_RE.search(line):
                    continue
                if _GITHUB_OUTPUT_REDIRECT_RE.search(line):
                    continue
                # Env-var references (shell expansion).
                for ve in db.all(_R_VISIBLE_ENV):
                    if ve.job != job_key or ve.idx != step.idx:
                        continue
                    if _references_var(line, ve.name):
                        info = _TaintInfo(ve.source_expr, ve.source_line, ve.hops)
                        out.append(_make_path(info, ve.name, rl.line, snippet))
                # Step-output references (step-ful jobs only — a
                # step-less job has no referenceable step ids).
                if step.step_id is not None or any(s.step_id for s in job.steps):
                    for ref in _STEP_OUTPUT_REF_RE.finditer(line):
                        ref_id, ref_name = ref.group(1), ref.group(2)
                        up = db.get(_R_TAINTED_OUTPUT, (ref_id, ref_name))
                        info_opt: _TaintInfo | None = None
                        # A $GITHUB_OUTPUT write is only visible to a
                        # strictly later step (the runner materialises
                        # it between steps).
                        if up is not None and step.idx > up.writer_idx:
                            info_opt = _TaintInfo(up.source_expr, up.source_line, up.hops)
                        else:
                            # Agent fallback: an agent step at this
                            # step or any earlier one taints its whole
                            # output namespace.
                            agent = None
                            for s in job.steps:
                                if s.idx > step.idx:
                                    break
                                cand = db.get(_R_AGENT_STEP, (job_key, s.idx, ref_id))
                                if cand is not None:
                                    agent = cand
                            if agent is not None:
                                info_opt = _TaintInfo(
                                    f"agent:{agent.action}",
                                    agent.line,
                                    [
                                        TaintHop(
                                            kind="agent_output",
                                            line=rl.line,
                                            name=f"{ref_id}.{ref_name}",
                                            detail=(f"agent {agent.action} step output {ref_name}"),
                                        )
                                    ],
                                )
                        if info_opt is not None:
                            out.append(
                                _make_path(
                                    info_opt,
                                    f"{ref_id}.{ref_name}",
                                    rl.line,
                                    snippet,
                                )
                            )
                # Cross-job ${{ needs.X.outputs.Y }} sinks.
                for ref in _NEEDS_OUTPUT_REF_RE.finditer(line):
                    up = db.get(_R_TAINTED_JOB_OUTPUT, (ref.group(1), ref.group(2)))
                    if up is not None:
                        xinfo = _TaintInfo(up.source_expr, up.source_line, up.hops)
                        out.append(
                            _make_cross_job_path(
                                xinfo, ref.group(1), ref.group(2), rl.line, snippet
                            )
                        )
                # File-execution sinks: ``source`` / ``.`` / ``bash`` /
                # ``sh`` of a path that an earlier line wrote attacker
                # bytes into.  Files persist for the whole job, so the
                # write only has to come before the exec in program
                # order.
                for em in _FILE_EXEC_RE.finditer(line):
                    tf = db.get(_R_TAINTED_FILE, (job_key, em.group("file")))
                    if tf is not None and (step.idx, rl.line) > (
                        tf.writer_idx,
                        tf.writer_line,
                    ):
                        finfo = _TaintInfo(tf.source_expr, tf.source_line, tf.hops)
                        out.append(
                            _make_path(finfo, tf.path, rl.line, snippet, sink_kind="file_exec")
                        )

        # Non-run: sink sites (runs-on:, container.image:,
        # services.*.image:, if:).  A cross-job ``${{ needs.X.outputs.Y }}``
        # or env-mediated ``${{ env.X }}`` reference reaching one of
        # these job-level keys is a taint flow in its own right — each
        # a distinct attack class (self-hosted runner / label hijack,
        # attacker-image pull, gate suppression).  These carry
        # ``sink_kind != "run"`` so the existing TAINT-* rules (which
        # filter ``sink_kind=="run"``) are unaffected; new rules opt
        # in.  Job-level, emitted in source-line order.
        sites = sorted(
            (s for s in db.all(_R_SINK_SITE) if s.job == job_key),
            key=lambda s: (s.line, s.kind),
        )
        for site in sites:
            site_snippet = site.snippet.strip()
            # ``if:`` is a boolean expression — the cross-job ref is
            # almost always inside a comparison — so it needs the
            # relaxed matcher.  The other sinks interpolate the bare
            # value, so the strict whole-body form is correct there.
            needs_re = _NEEDS_OUTPUT_IN_EXPR_RE if site.kind == "if" else _NEEDS_OUTPUT_REF_RE
            for ref in needs_re.finditer(site.value):
                up = db.get(_R_TAINTED_JOB_OUTPUT, (ref.group(1), ref.group(2)))
                if up is not None:
                    xinfo = _TaintInfo(up.source_expr, up.source_line, up.hops)
                    out.append(
                        _make_cross_job_path(
                            xinfo,
                            ref.group(1),
                            ref.group(2),
                            site.line,
                            site_snippet,
                            sink_kind=site.kind,
                        )
                    )
            # A job-level ``if:`` cannot reference ``env:`` (the env
            # context is not in scope at job-gate evaluation time), so
            # the env-mediated branch only applies to the other sinks.
            if site.kind == "if":
                continue
            for ref in _ENV_REF_RE.finditer(site.value):
                te = db.get(_R_TAINTED_ENV, (("job", job_key), ref.group(1)))
                if te is not None:
                    info = _TaintInfo(te.source_expr, te.source_line, te.hops)
                    out.append(
                        _make_path(
                            info,
                            ref.group(1),
                            site.line,
                            site_snippet,
                            sink_kind=site.kind,
                        )
                    )
    return out


def _collect_all_env_assignments(
    seg_lines: list[str], seg_start: int
) -> list[tuple[str, str, int]]:
    """Walk every ``env:`` block in the segment and return
    ``[(var_name, raw_value, 1-indexed_line), ...]`` in file order.

    Both job-level and step-level ``env:`` blocks contribute.  We do
    NOT resolve taint here; the raw assignments become ``env_assign``
    EDB facts and the closure resolves multi-hop chains.
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


def _extract_tainted_source(value: str, include_inputs: bool = False) -> str | None:
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

    ``include_inputs`` — when True (the file is a reusable workflow,
    ``on: workflow_call``), ``inputs.<name>`` also counts as a source.
    Attacker-context matches still win over ``inputs`` matches within
    the same expression: a literal attacker context is unconditionally
    tainted, whereas ``inputs.X`` is only *conditionally* so (the
    caller decides) — see TAINT-GH-017.
    """
    for expr in _GHA_EXPR_RE.finditer(value):
        m = _TAINTED_IN_EXPR_RE.search(expr.group(1))
        if m:
            return m.group(0)
        if include_inputs:
            im = _INPUT_REF_IN_EXPR_RE.search(expr.group(1))
            if im:
                return im.group(0)
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
                if not stripped.startswith("#"):
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


# Lines where double-quoting is NOT enough — the quoted value is
# re-parsed as code by an explicit eval-class command.  Used by the
# ``sink_quote_filter`` partition (rules/github/taint.py) and by the
# dangerous-combination join (combination_facts.py) to keep these
# classed as unsafe sinks even when the variable reference itself is
# double-quoted.
_REPARSING_CMD_RE = re.compile(
    r"\b(?:eval|sh\s+-c|bash\s+-c|zsh\s+-c|"
    r"python(?:3)?\s+-c|perl\s+-e|ruby\s+-e|node\s+-e)\b"
)


def _sink_is_safely_quoted(snippet: str, var_name: str) -> bool:
    """True if every shell reference to ``var_name`` in ``snippet`` is
    double-quoted AND the line contains no eval-class re-parsing
    command. Server-side ``${{ env.X }}`` references (resolved before
    the shell runs) are out of scope here — quoting doesn't apply.
    """
    if _REPARSING_CMD_RE.search(snippet):
        return False
    found_any = False
    for m in re.finditer(rf"\$\{{?{re.escape(var_name)}\}}?\b", snippet):
        found_any = True
        if _shell_quote_context_at(snippet, m.start()) != "double":
            return False
    # If we found no shell-form reference at all, the sink reaches the
    # variable via ``${{ env.X }}`` server-side substitution — treat as
    # NOT-safely-quoted because the value is interpolated by GitHub
    # before any shell quoting can apply.
    return found_any


# A line whose meaningful content is a single shell assignment:
# ``NAME=...`` or ``export NAME=...``.
_BARE_ASSIGN_LINE_RE = re.compile(r"^(?:export\s+)?[A-Za-z_]\w*=")

# Shell metacharacters that would let an assignment line do more than
# *copy* a value — command substitution, statement separators, pipes,
# redirections, backgrounding.
_ASSIGN_UNSAFE_TOKENS = ("$(", "`", ";", "|", "&", "\n", "<", ">")


def _sink_is_bare_assignment(snippet: str, var_name: str) -> bool:
    """True if the sink line only *copies* the tainted value into a
    shell variable (``ref_name=$VAR``) and does nothing else.

    Bash does not word-split or glob-expand an assignment's RHS, so the
    tainted bytes land inertly in another shell variable — the flagged
    line is not an injection point.  What that downstream shell
    variable is later used for is beyond :func:`analyze`'s model (it
    tracks workflow-level env / output propagation, not shell-local
    variables), but reporting the *assignment* as a command-injection
    sink is a false positive.  ``analyze`` over-reports these; consumers
    that need precision (the dangerous-combination join) filter them
    out with this predicate.

    Conservative by construction: the whole stripped line must be one
    assignment statement — no command substitution, no eval-class
    re-parse, no separators that could append a command.
    """
    line = snippet.strip()
    if not _BARE_ASSIGN_LINE_RE.match(line):
        return False
    if _REPARSING_CMD_RE.search(line):
        return False
    if any(tok in line for tok in _ASSIGN_UNSAFE_TOKENS):
        return False
    # The line is a single assignment; confirm the tainted var is what
    # it assigns (not some unrelated reference the matcher missed).
    return bool(re.search(rf"\$\{{?{re.escape(var_name)}\}}?\b", line))


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


# Human-readable label for each sink kind, used in the terminal hop's
# ``detail`` string.
_SINK_LABEL = {
    "run": "run:",
    "runs_on": "runs-on:",
    "container_image": "container.image:",
    "service_image": "services.*.image:",
    "if": "if:",
    "file_exec": "executed file:",
}


def _make_path(
    info: _TaintInfo,
    sink_name: str,
    sink_line: int,
    sink_snippet: str,
    sink_kind: str = "run",
) -> TaintPath:
    label = _SINK_LABEL.get(sink_kind, "run:")
    sink_hop = TaintHop(
        kind="sink",
        line=sink_line,
        name=sink_name,
        detail=f"{label} references ${sink_name}",
    )
    return TaintPath(
        kind=_classify_kind(info.hops),
        source_expr=info.source_expr,
        source_line=info.source_line,
        env_var=sink_name,
        sink_line=sink_line,
        sink_snippet=sink_snippet,
        hops=info.hops + [sink_hop],
        sink_kind=sink_kind,
    )


def _make_cross_job_path(
    producer_info: _TaintInfo,
    producer_job: str,
    output_name: str,
    sink_line: int,
    sink_snippet: str,
    sink_kind: str = "run",
) -> TaintPath:
    """Build a cross-job :class:`TaintPath` for a direct
    ``${{ needs.<j>.outputs.<n> }}`` reference at a sink.

    ``sink_kind`` says where the reference landed — ``"run"`` (a
    shell ``run:`` line, the original TAINT-GH-009 shape) or a
    non-run job key (``"runs_on"`` / ``"container_image"`` /
    ``"service_image"``), each its own attack class.

    The producer's hops are preserved verbatim; a ``needs_ref`` hop
    marks the boundary crossing into the consumer job; a ``sink`` hop
    closes the chain.  Severity (and rule routing) happens downstream
    — this just shapes the provenance record.
    """
    label = _SINK_LABEL.get(sink_kind, "run:")
    needs_label = f"needs.{producer_job}.outputs.{output_name}"
    needs_hop = TaintHop(
        kind="needs_ref",
        line=sink_line,
        name=needs_label,
        detail=f"{label} references ${{{{ {needs_label} }}}}",
    )
    sink_hop = TaintHop(
        kind="sink",
        line=sink_line,
        name=needs_label,
        detail=f"{label} ${{{{ {needs_label} }}}}",
    )
    return TaintPath(
        kind="cross_job",
        source_expr=producer_info.source_expr,
        source_line=producer_info.source_line,
        env_var=needs_label,
        sink_line=sink_line,
        sink_snippet=sink_snippet,
        hops=producer_info.hops + [needs_hop, sink_hop],
        sink_kind=sink_kind,
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
# level regexes because the facts-model projection needs it to skip
# these write lines from the generic sink scan.)

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

# ``echo <body> >>? <file>`` to an arbitrary path.  Same body-
# extraction as the ``$GITHUB_ENV`` matcher; ``file`` captures the
# redirect target.  Used by :func:`_iter_file_writes` — callers skip
# the ``$GITHUB_ENV`` / ``$GITHUB_OUTPUT`` targets (handled by their
# dedicated detectors) and keep only ordinary filesystem paths.
_ECHO_TO_FILE_RE = re.compile(
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
    [\"']?(?P<file>[^\s"'>|&;]+)[\"']?
    """,
    re.VERBOSE,
)

# A shell command that *executes* a file: ``source f`` / ``. f`` /
# ``bash f`` / ``sh f`` / ``zsh f``.  The command must sit at the
# start of a command (line start or after ``;`` / ``&&`` / ``||`` /
# ``|`` / ``(``) so ``echo source x`` is not a false match; the path
# must not start with ``-`` so ``sh -c`` (run a string, not a file)
# is excluded.  Captures the file path.
_FILE_EXEC_RE = re.compile(
    r"(?:^|[;&|(]|&&|\|\|)\s*"
    r"(?:source|bash|sh|zsh|\.)\s+"
    r"(?!-)(?P<file>[^\s;&|]+)"
)


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
