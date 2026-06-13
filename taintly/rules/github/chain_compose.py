"""GitHub Actions — finding-composition CHAIN rules (CHAIN-GH-1xx).

The CHAIN-GH-1xx family realises the user's "stack low → critical"
concept by composing *existing* findings into higher-severity
composite findings. Distinct from CHAIN-GH-001, which was a single
hard-coded threat shape (self-hosted-runner persistence) — these are
the generic composer's output, parameterised by which combinations
matter.

Architecture: see :mod:`taintly.composer`. Each rule is a closure-
rule callable that reads the composer Database and asserts
``CompositeFact`` entries when its join condition holds. The engine
emits one :class:`taintly.models.Finding` per asserted composite.

The 1xx range avoids collision with CHAIN-GH-001 (a single
hard-coded threat shape, kept separate from the generic
composer's output).

Initial three rules (all conjunctive; the join is what the engine
layer can't do):

* CHAIN-GH-101 — SEC4-GH-005 + fork-reachable + write-token =
  CRITICAL. The actions/checkout step persists a write-capable
  GITHUB_TOKEN onto a runner that any fork PR can execute code on.
* CHAIN-GH-102 — SEC3-GH-001 + fork-reachable = HIGH. An unpinned
  third-party action in a workflow attackers can fire; a single
  upstream compromise → arbitrary code in the fork-reachable job.
* CHAIN-GH-103 — TAINT-GH-001 + fork-reachable = HIGH. Attacker-
  controlled value reaches a shell in a job attackers can trigger;
  the fork-reachable trigger upgrades the taint finding from
  "review-needed" to "concrete pwn-request shape."

The conjuncts intentionally cite *existing* lab-shipped rules rather
than re-implementing their patterns. Composer rules earn their keep
exactly by NOT duplicating detection logic — they layer threat-level
implications on top of what's already detected.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import TYPE_CHECKING

from taintly.composer import CompositeFact, context_for, findings_by_rule
from taintly.models import Platform, Rule, Severity
from taintly.workflow_corpus import (
    CorpusFindings,
    CorpusPattern,
    WorkflowCorpus,
)

if TYPE_CHECKING:
    from taintly.taint_facts.relations import Database, Fact

# ---------------------------------------------------------------------------
# Composer rules (closure-rule callables)
# ---------------------------------------------------------------------------


def _compose_chain_gh_101(db: Database) -> Iterable[tuple[str, Fact]]:
    """SEC4-GH-005 + fork-reachable + write-token → CRITICAL.

    The pwn-request shape, derived from existing finding output rather
    than re-detected from YAML. Anchors at the SEC4-GH-005 finding's
    line — that's the actions/checkout that should have set
    ``persist-credentials: false``.

    Note: SEC4-GH-005B (INFO posture sibling, added 2026-05-19 by
    github-tanstack-posture-design-v1) does NOT feed this composer.
    SEC4-GH-005B fires only when no downstream credential consumer
    is detected — the "consumer present" gate is exactly what makes
    SEC4-GH-005 a confident pwn-request building block.  Composing
    SEC4-GH-005B into CHAIN-GH-101 would re-introduce the FP-density
    noise the May-17 SEC4-GH-005 precision tune eliminated.  The
    composer's input set is intentionally limited to confirmed-
    consumer findings (SEC4-GH-005 only).
    """
    for f in findings_by_rule(db, "SEC4-GH-005"):
        ctx = context_for(db, f.file, f.job)
        if ctx is None:
            continue
        if not ctx.fork_reachable:
            continue
        if not ctx.has_write_token:
            continue
        if ctx.trusted_bot_gate:
            continue
        snippet = (
            "CHAIN: actions/checkout without `persist-credentials: false` "
            "in a fork-reachable, write-token-holding job. A PR from a "
            "fork executes code with the persisted GITHUB_TOKEN — the "
            "classic pwn-request shape, composed from "
            "SEC4-GH-005 + fork trigger + write-scope permissions."
        )
        yield (
            "composite",
            CompositeFact(
                chain_id="CHAIN-GH-101",
                file=f.file,
                job=f.job,
                anchor_line=f.line,
                snippet=snippet,
            ),
        )


def _compose_chain_gh_102(db: Database) -> Iterable[tuple[str, Fact]]:
    """SEC3-GH-001 (unpinned third-party action) + fork-reachable +
    high-blast-radius action → HIGH.

    Unpinned-action risk in isolation is MEDIUM (SEC3-GH-001's own
    severity). A fork-reachable workflow upgrades it ONLY when the
    action's blast radius is high: it consumes secrets, it's a
    container action, or it's a documented release / push / deploy
    action. Otherwise the upstream-compromise leg lands a malicious
    action in a setup/lint/cache step whose runtime authority is
    limited to the runner's own tree — already covered by SEC3-GH-001
    itself at lower severity.

    The blast-radius narrowing is what makes this rule pay rent: the
    unbounded form fires on every fork-reachable workflow that uses
    `pnpm/action-setup` or `Swatinem/rust-cache`, which is most of
    them. The narrowed form fires only when the supply-chain risk
    actually changes the threat tier.
    """
    for f in findings_by_rule(db, "SEC3-GH-001"):
        ctx = context_for(db, f.file, f.job)
        if ctx is None:
            continue
        if not ctx.fork_reachable:
            continue
        if ctx.trusted_bot_gate:
            continue
        if not _is_high_blast_radius_action(db, f.file, f.line):
            continue
        snippet = (
            "CHAIN: high-blast-radius third-party action used at a "
            "mutable ref (SEC3-GH-001) inside a fork-reachable "
            "workflow. The action handles secrets, runs in a "
            "container, or pushes/publishes/deploys — an upstream tag "
            "overwrite (by the action's maintainer or by an attacker "
            "who compromises them) silently lands "
            "attacker-controlled code in a workflow any external "
            "contributor can trigger, with the action's full runtime "
            "authority."
        )
        yield (
            "composite",
            CompositeFact(
                chain_id="CHAIN-GH-102",
                file=f.file,
                job=f.job,
                anchor_line=f.line,
                snippet=snippet,
            ),
        )


# Actions whose name (case-insensitive) contains any of these tokens
# are documented push / deploy / publish actions whose runtime
# authority makes them high-blast-radius. Selected from real-world
# corpora; conservative — false-positives in this list yield only
# CHAIN-GH-102 fires that would otherwise have been classified
# correctly by SEC3-GH-001 at lower severity.
_HIGH_BLAST_RADIUS_NAME_TOKENS: tuple[str, ...] = (
    "publish",
    "deploy",
    "push",
    "release",
    "gh-pages",
    "auto-commit",
    "twine",
    "actions-gh-pages",
    "github-push",
)


def _is_high_blast_radius_action(db: Database, file: str, line: int) -> bool:  # noqa: ARG001
    """Inspect the step at ``file:line`` and decide whether the action
    is high-blast-radius. Three criteria, any of which qualifies:

    * The action's name (the ``uses:`` value) contains a token from
      :data:`_HIGH_BLAST_RADIUS_NAME_TOKENS`.
    * The action is a container action (``uses: docker://...`` or
      ``uses: ./.github/actions/<dir>`` with a Dockerfile — the
      docker form is what we can detect statically).
    * The step's ``with:`` block (next ~12 lines after the ``uses:``)
      contains ``${{ secrets.``, indicating the action consumes
      repo / org secrets.

    Returns False when the file isn't readable. Conservative: we'd
    rather miss a chain than emit FPs on cache / setup / lint
    actions which dominate the ordinary corpus.
    """
    import re

    # Resolve file content via the corpus we smuggled onto the db.
    # Composer rules don't get a direct corpus handle — we get the
    # workflow content from disk on-demand. CI files are bounded by
    # size so the cost is negligible.
    try:
        with open(file, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return False
    if not (1 <= line <= len(lines)):
        return False
    uses_line = lines[line - 1]
    m = re.search(r"uses:\s*['\"]?([^@\s'\"]+)", uses_line)
    if not m:
        return False
    name = m.group(1).lower()
    if name.startswith("docker://"):
        return True
    for token in _HIGH_BLAST_RADIUS_NAME_TOKENS:
        if token in name:
            return True
    # Scan the with: block window for secret references. Bound at 12
    # lines past the uses: line — bigger than typical with: blocks but
    # small enough to stay step-local.
    window = "".join(lines[line - 1 : line + 12])
    if "${{ secrets." in window or "${{secrets." in window:  # noqa: SIM103
        return True
    return False


def _compose_chain_gh_103(db: Database) -> Iterable[tuple[str, Fact]]:
    """TAINT-GH-001 (tainted run) + fork-reachable → HIGH.

    TAINT-GH-001 normally flags "this `${{ github.event.X }}` reaches a
    shell"; on a non-fork-reachable trigger, the attack story is weak
    (only a maintainer can fire the trigger). Composed with a fork-
    reachable trigger, it becomes a concrete pwn-request shape:
    external attacker fires the workflow → injects shell → executes
    in the workflow's context.
    """
    for f in findings_by_rule(db, "TAINT-GH-001"):
        ctx = context_for(db, f.file, f.job)
        if ctx is None:
            continue
        if not ctx.fork_reachable:
            continue
        if ctx.trusted_bot_gate:
            continue
        # Surface the constituent TAINT-GH-001 finding's rendered
        # source→hop→sink path (its snippet) so the upgraded finding shows
        # WHY it chained, not just the conclusion.
        path_note = f" Taint path: {f.snippet}" if f.snippet else ""
        snippet = (
            "CHAIN: tainted value reaches a shell run: in a fork-"
            "reachable workflow. TAINT-GH-001 by itself flagged the "
            "flow; the fork-reachable trigger upgrades that to a "
            "concrete external-attacker-injectable shell." + path_note
        )
        yield (
            "composite",
            CompositeFact(
                chain_id="CHAIN-GH-103",
                file=f.file,
                job=f.job,
                anchor_line=f.line,
                snippet=snippet,
            ),
        )


def _compose_chain_gh_104(db: Database) -> Iterable[tuple[str, Fact]]:
    """SEC6-GH-010 (secret to action input without masking) +
    fork-reachable + unpinned action → HIGH.

    Three legs:
      (1) SEC6-GH-010: a credential-named action input takes
          ``${{ secrets.X }}`` directly (no env-block masking).
      (2) fork_reachable: the workflow fires on a trigger
          external contributors can reach.
      (3) SEC3-GH-001: the action at this step is unpinned
          (mutable ref, not SHA).

    Each leg in isolation is MEDIUM or review-needed.  Combined,
    the supply-chain + secret-disclosure shape is concrete: a fork
    PR fires the workflow, the action — published at a mutable
    ref — receives the secret in plaintext, and an upstream
    compromise (tag overwrite, maintainer takeover) immediately
    exfiltrates the secret.

    The unpinned-action leg is what makes this rule pay rent.
    Without it, ``secrets.GITHUB_TOKEN`` passed to official
    SHA-pinned actions (the dominant ordinary-corpus shape) fires
    as a false positive: SHA-pinned actions can't be silently
    swapped, so the supply-chain leg of the chain doesn't exist.
    Requiring SEC3-GH-001 narrows fires to the case where the
    chain is real end-to-end.
    """
    # Build (file, line) anchors of every UNPINNED THIRD-PARTY
    # action finding.  SEC3-GH-001 fires on the ``uses:`` line for
    # third-party actions only; SEC3-GH-001A fires on first-party
    # actions (``actions/*``, ``aws-actions/*``, ``github/*``,
    # ``microsoft/*``, ``Azure/*``) and is INTENTIONALLY EXCLUDED:
    # first-party publishers carry materially lower supply-chain
    # risk (operationally trusted, audit-attested by the vendor),
    # so the "upstream compromise" leg of the chain doesn't fire
    # in the same way.  SEC6-GH-010 itself flags the hardening
    # miss on first-party actions at its own severity.
    #
    # SEC6-GH-010 fires on the ``token: ${{ secrets.X }}`` line a
    # few lines below the ``uses:`` line inside the same step's
    # ``with:`` block.  A step is typically 2-12 lines tall, so a
    # SEC3-GH-001 finding within 15 lines BEFORE the SEC6-GH-010
    # line in the same file is the same step.
    unpinned_by_file: dict[str, set[int]] = {}
    for f in findings_by_rule(db, "SEC3-GH-001"):
        unpinned_by_file.setdefault(f.file, set()).add(f.line)

    for f in findings_by_rule(db, "SEC6-GH-010"):
        ctx = context_for(db, f.file, f.job)
        if ctx is None:
            continue
        if not ctx.fork_reachable:
            continue
        if ctx.trusted_bot_gate:
            continue
        # Leg (3): does the SEC6-GH-010-bearing step's ``uses:``
        # line itself have a SEC3-GH-001 finding?  This locks the
        # third leg to the actual step, not a nearby earlier step.
        unpinned_lines = unpinned_by_file.get(f.file, set())
        if not unpinned_lines:
            continue
        if not _has_unpinned_in_step_window(unpinned_lines, f.line, f.file):
            continue
        snippet = (
            "CHAIN: secret passed to an action input without env-block "
            "masking (SEC6-GH-010) in a fork-reachable workflow, and "
            "the action is pinned to a mutable ref (SEC3-GH-001). "
            "Any external PR fires the workflow; the action receives "
            "the secret in plaintext via `with:`; an upstream "
            "compromise of the action's tag or branch immediately "
            "exposes the secret to the attacker pool external "
            "contributors are in."
        )
        yield (
            "composite",
            CompositeFact(
                chain_id="CHAIN-GH-104",
                file=f.file,
                job=f.job,
                anchor_line=f.line,
                snippet=snippet,
            ),
        )


# Step window: how many lines BEFORE a SEC6-GH-010 hit may the
# step's ``uses:`` line be?  A step typically opens with ``- uses:``
# on one line, then ``with:`` and 1-N input lines.  15 lines is the
# 99th-percentile step height in the corpus.
_STEP_LINE_WINDOW = 15


_USES_LINE_RE = re.compile(r"^\s*(?:-\s*)?uses\s*:")


def _step_uses_line(file: str, target_line: int) -> int:
    """Return the line number of the SEC6-GH-010-bearing step's
    ``uses:`` declaration, or -1 if not found within
    ``_STEP_LINE_WINDOW`` lines.

    The step's anchor is the FIRST ``uses:`` line found by scanning
    backward from ``target_line``.  This locks the chain to the
    actual step that holds the secret-passing input, not a nearby
    earlier step.
    """
    try:
        with open(file, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return -1
    # Scan from (target_line - 1) backward up to _STEP_LINE_WINDOW
    # lines.  Python's list is 0-indexed; line numbers in findings
    # are 1-indexed.
    start_idx = min(target_line - 1, len(lines) - 1)
    lower = max(0, start_idx - _STEP_LINE_WINDOW)
    for idx in range(start_idx, lower - 1, -1):
        if _USES_LINE_RE.match(lines[idx]):
            return idx + 1  # back to 1-indexed
    return -1


def _has_unpinned_in_step_window(
    unpinned_lines: list[int],
    target_line: int,
    file: str,
) -> bool:
    """Return True iff the SEC6-GH-010-bearing step's ``uses:`` line
    is itself a SEC3-GH-001 finding line.

    The previous form (any unpinned anchor within a 15-line window)
    over-attributed: a workflow with two steps where step A has an
    unpinned third-party action and step B has a SHA-pinned (or
    first-party) action would falsely chain step A's unpinned signal
    to step B's secret-passing.

    Concrete FP this fixes: ``cloudflare/wrangler-action@v3`` at
    line 82-87 (unpinned third-party), then ``actions/github-script
    @v8`` at line 90-95 (first-party).  SEC6-GH-010 fires on the
    github-script step's ``token:`` line.  The cloudflare ``uses:``
    line is within 15 lines but it's not the github-script step's
    anchor; the chain doesn't hold for the github-script step.

    This form locks the anchor by finding the step's actual
    ``uses:`` line (the closest one above the SEC6-GH-010 finding)
    and asking whether THAT specific line is in the SEC3-GH-001 set.
    """
    step_line = _step_uses_line(file, target_line)
    if step_line == -1:
        return False
    return step_line in unpinned_lines


# ---------------------------------------------------------------------------
# CHAIN-GH-105 — cross-job privilege escalation (P1.3)
# ---------------------------------------------------------------------------

# ``${{ needs.<job>.outputs.<name> }}`` — the cross-job output reference.
# Mirrors taint._NEEDS_OUTPUT_REF_RE but kept local so this rule does not
# take a dependency on the taint engine's internals.
_NEEDS_OUTPUT_REF_RE = re.compile(
    r"\$\{\{\s*needs\.([A-Za-z_][A-Za-z0-9_-]*)"
    r"\.outputs\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}"
)


class _CrossJobEdge:
    """One producer→consumer cross-job output edge in a single file.

    * ``producer`` — the job named in ``needs.<producer>.outputs.*``.
    * ``consumer`` — the job whose body contains the reference.
    * ``line`` — 1-based line of the consumer's reference (anchor).
    * ``output`` — the referenced output name (for the snippet).
    """

    __slots__ = ("consumer", "line", "output", "producer")

    def __init__(self, producer: str, consumer: str, line: int, output: str) -> None:
        self.producer = producer
        self.consumer = consumer
        self.line = line
        self.output = output


def _producer_jobs_in_file(file: str) -> set[str]:
    """Return the set of job names in ``file`` that declare an
    ``outputs:`` block (the producers of cross-job output edges).

    A job declares outputs when an ``outputs:`` key appears at the
    job-body indent (one level deeper than the job key). We use the
    shared :func:`_split_into_job_segments` so the job-boundary
    heuristic matches the corpus and per-file rules exactly.
    """
    from taintly.models import _split_into_job_segments

    try:
        with open(file, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return set()
    producers: set[str] = set()
    for _start_idx, seg in _split_into_job_segments(lines):
        # The first line of a job segment is the ``<jobname>:`` key
        # (pre-job preamble lands in the first segment, whose first
        # line is not a job key — that segment has no outputs-bearing
        # job name to credit, so a missing match simply skips it).
        if not seg:
            continue
        head = seg[0].lstrip()
        if ":" not in head:
            continue
        job_name = head.split(":", 1)[0].strip()
        if not job_name or job_name in {"jobs", "on", "name", "permissions", "env"}:
            continue
        # Does any line in this segment declare an ``outputs:`` block?
        for ln in seg[1:]:
            if re.match(r"^\s+outputs\s*:\s*(?:#.*)?$", ln):
                producers.add(job_name)
                break
    return producers


def _crossjob_edges_in_file(file: str) -> list[_CrossJobEdge]:
    """Extract every ``needs.<producer>.outputs.<name>`` edge in
    ``file``, attributing each reference to the consumer job whose
    segment contains it.

    Only edges whose producer actually declares an ``outputs:`` block
    are kept: a ``needs.X.outputs.Y`` reference to a job that doesn't
    declare outputs is a typo / dead reference, not a real data edge.
    """
    from taintly.models import _split_into_job_segments

    try:
        with open(file, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return []
    producers = _producer_jobs_in_file(file)
    if not producers:
        return []
    edges: list[_CrossJobEdge] = []
    for start_idx, seg in _split_into_job_segments(lines):
        if not seg:
            continue
        head = seg[0].lstrip()
        if ":" not in head:
            continue
        consumer = head.split(":", 1)[0].strip()
        if not consumer or consumer in {"jobs", "on", "name", "permissions", "env"}:
            continue
        for offset, ln in enumerate(seg):
            for m in _NEEDS_OUTPUT_REF_RE.finditer(ln):
                producer, output = m.group(1), m.group(2)
                if producer not in producers:
                    continue
                if producer == consumer:
                    continue  # a job can't ``needs`` itself; defensive
                edges.append(
                    _CrossJobEdge(
                        producer=producer,
                        consumer=consumer,
                        line=start_idx + offset + 1,  # 1-based file line
                        output=output,
                    )
                )
    return edges


def _files_with_contexts(db: Database) -> set[str]:
    """The set of workflow files the composer seeded job contexts for.

    CHAIN-GH-105 has no foothold finding to iterate (unlike the
    finding-composing siblings); it joins purely on workflow
    structure + per-job permission context. The seeded
    :class:`JobContextFact` rows enumerate exactly the files in scope.
    """
    from taintly.composer import JobContextFact

    files: set[str] = set()
    for ctx in db.all("job_context"):
        if isinstance(ctx, JobContextFact) and ctx.file:
            files.add(ctx.file)
    return files


def _compose_chain_gh_105(db: Database) -> Iterable[tuple[str, Fact]]:
    """Cross-job privilege escalation (P1.3) → HIGH.

    A LOW-privilege producer job (``has_write_token=False``) declares
    an output that a HIGH-privilege consumer job
    (``has_write_token=True``) reads via
    ``${{ needs.<producer>.outputs.<name> }}``. The producer is the
    exposed / attacker-influenceable surface; its output crossing into
    a write-capable job is a privilege-escalation vector — the
    write-capable job acts on data shaped in a context that was never
    granted that authority.

    Distinct from TAINT-GH-009 (cross-job output → *shell* sink) and
    from the severity-escalation / id-token co-occurrence rules: the
    sink here is the *privilege boundary itself*, not a shell or a
    specific dangerous statement. The composite fires only when the
    privilege GRADIENT exists (read producer → write consumer); a
    same-tier or high→low edge is benign data flow and is suppressed.

    Per-job write-token resolution relies on each job declaring its
    own ``permissions:`` block (the only way the corpus can attribute
    a job-specific :class:`JobContextFact`). When both jobs fall back
    to the workflow-default wildcard, no gradient is observable and
    the rule conservatively does NOT fire — favouring precision, the
    whole point of the composer family.
    """
    files = _files_with_contexts(db)
    for file in sorted(files):
        edges = _crossjob_edges_in_file(file)
        if not edges:
            continue
        for edge in edges:
            producer_ctx = context_for(db, file, edge.producer)
            consumer_ctx = context_for(db, file, edge.consumer)
            if producer_ctx is None or consumer_ctx is None:
                continue
            # Suppress when a trusted-bot gate restricts the workflow:
            # the producer surface isn't externally attacker-controlled.
            if consumer_ctx.trusted_bot_gate or producer_ctx.trusted_bot_gate:
                continue
            # The privilege GRADIENT: read-only producer → write consumer.
            if producer_ctx.has_write_token:
                continue
            if not consumer_ctx.has_write_token:
                continue
            snippet = (
                "CHAIN: cross-job privilege escalation. Low-privilege "
                f"producer job `{edge.producer}` (read-only token) "
                f"declares output `{edge.output}`, which the "
                f"write-capable consumer job `{edge.consumer}` reads "
                f"via `${{{{ needs.{edge.producer}.outputs.{edge.output} }}}}`. "
                "The producer is the exposed, attacker-influenceable "
                "surface; its output crossing into a job that holds a "
                "write-capable token (contents/id-token/packages write) "
                "lets a value shaped under low authority drive an action "
                "under high authority — a privilege-escalation gradient "
                f"({edge.producer} → {edge.consumer})."
            )
            yield (
                "composite",
                CompositeFact(
                    chain_id="CHAIN-GH-105",
                    file=file,
                    job=edge.consumer,
                    anchor_line=edge.line,
                    snippet=snippet,
                ),
            )


COMPOSER_RULES = [
    _compose_chain_gh_101,
    _compose_chain_gh_102,
    _compose_chain_gh_103,
    _compose_chain_gh_104,
    _compose_chain_gh_105,
]


# ---------------------------------------------------------------------------
# Rule registrations
# ---------------------------------------------------------------------------


def _make_chain_callback(chain_id: str):
    """Return a CorpusPattern callback that emits findings for one
    composite chain_id from the corpus + prior_findings.

    The callback reads ``corpus._prior_findings`` (a list smuggled in
    by :func:`taintly.engine._run_composer_rules`); when absent (e.g.
    a unit test invoking the corpus pass without seeding findings), the
    callback returns an empty list and never asserts anything.
    """

    def callback(corpus: WorkflowCorpus) -> CorpusFindings:
        prior = getattr(corpus, "_prior_findings", None)
        if prior is None:
            return []
        from taintly.composer import run_composer

        composites = run_composer(corpus, prior, COMPOSER_RULES)
        return [(c.file, c.anchor_line, c.snippet) for c in composites if c.chain_id == chain_id]

    return callback


RULES: list[Rule] = [
    Rule(
        id="CHAIN-GH-101",
        title=(
            "Composite: persisted checkout credential in a fork-reachable, "
            "write-token job (SEC4-GH-005 + fork trigger + write-scope)"
        ),
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-1",
        description=(
            "CHAIN-GH-101 composes three findings/contexts: "
            "(1) SEC4-GH-005 fires on an actions/checkout step that "
            "doesn't set `persist-credentials: false`; "
            "(2) the workflow's trigger is fork-reachable "
            "(`pull_request`, `pull_request_target`, `issue_comment`, "
            "`workflow_run`, ...); "
            "(3) the job holds a write-capable GITHUB_TOKEN.\n\n"
            "Individually each is MEDIUM/HIGH at most; combined, an "
            "external PR can execute code with the persisted "
            "write-token — the canonical pwn-request RCE shape."
        ),
        pattern=CorpusPattern(callback=_make_chain_callback("CHAIN-GH-101")),
        remediation=(
            "Break any one of the three legs:\n"
            "  1. Set `persist-credentials: false` on the checkout step "
            "(addresses SEC4-GH-005);\n"
            "  2. Move the workflow off fork-reachable triggers (or "
            "use `pull_request` instead of `pull_request_target` if you "
            "don't need write-scope secrets);\n"
            "  3. Drop the job's permissions to the minimum needed "
            "(`permissions: contents: read`).\n"
            "Run `taintly --guide CHAIN-GH-101` for the full checklist."
        ),
        reference=(
            "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"
        ),
        test_positive=[],
        test_negative=[],
        stride=["E", "T", "S"],
        threat_narrative=(
            "An external contributor opens a PR. The workflow fires "
            "on `pull_request_target` with the default write-capable "
            "GITHUB_TOKEN. The fork's code is checked out without "
            "`persist-credentials: false`, so the checkout step writes "
            "the workflow's GITHUB_TOKEN into the local git config. "
            "A later step in the same job runs `git push` (or any "
            "shell op an attacker landed in the fork) and uses that "
            "persisted token — now arbitrary writes against the host "
            "repo from a fork PR."
        ),
        confidence="high",
        review_needed=False,
        finding_family="chain-composition",
        composition_tags=frozenset({"chain-composition"}),
    ),
    Rule(
        id="CHAIN-GH-102",
        title=(
            "Composite: unpinned third-party action in a fork-reachable "
            "workflow (SEC3-GH-001 + fork trigger)"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "CHAIN-GH-102 composes: (1) SEC3-GH-001 fires on a "
            "third-party action used at a mutable ref (tag or branch); "
            "(2) the workflow is fork-reachable. Unpinned-action risk "
            "in isolation is MEDIUM; combined with a fork-reachable "
            "trigger, an upstream supply-chain compromise reaches "
            "the lowest-privilege attacker pool immediately."
        ),
        pattern=CorpusPattern(callback=_make_chain_callback("CHAIN-GH-102")),
        remediation=(
            "Pin the third-party action to a full commit SHA "
            "(addresses SEC3-GH-001). The fork-reachable trigger is "
            "a property of the workflow's intent and may be unchangeable; "
            "pinning removes the upstream-compromise leg of the chain."
        ),
        reference=(
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"
        ),
        test_positive=[],
        test_negative=[],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker who compromises a popular GitHub Action "
            "(via maintainer takeover or upstream account theft) "
            "publishes a malicious release under the existing tag. "
            "Every fork-reachable workflow that uses the action at "
            "that tag picks up the malicious code on the next PR — "
            "no maintainer action required by the victim repo."
        ),
        confidence="high",
        review_needed=False,
        finding_family="chain-composition",
        composition_tags=frozenset({"chain-composition"}),
    ),
    Rule(
        id="CHAIN-GH-104",
        title=(
            "Composite: secret passed to unpinned action input "
            "without env-block masking in a fork-reachable workflow "
            "(SEC6-GH-010 + SEC3-GH-001 + fork trigger)"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "CHAIN-GH-104 composes three legs: (1) SEC6-GH-010 fires "
            "on a credential-named action input that receives a "
            "`${{ secrets.X }}` value directly (no env-block masking); "
            "(2) the workflow is fork-reachable; (3) the action is "
            "pinned to a mutable ref (SEC3-GH-001), not a full SHA.\n\n"
            "Individually each is MEDIUM or review-needed. Combined: "
            "any external contributor's PR fires the workflow, the "
            "action — published at a mutable ref — receives the "
            "secret in plaintext via `with:`, and an upstream "
            "compromise (tag overwrite, maintainer takeover) "
            "exfiltrates the secret without needing any change to the "
            "host repo.\n\n"
            "The unpinned-action leg is what distinguishes a real "
            "supply-chain shape from the common hardening miss of "
            "passing `secrets.GITHUB_TOKEN` to an official "
            "SHA-pinned action: SHA-pinned actions can't be silently "
            "swapped, so the supply-chain leg of the chain doesn't "
            "exist."
        ),
        pattern=CorpusPattern(callback=_make_chain_callback("CHAIN-GH-104")),
        remediation=(
            "Sanitise either leg:\n"
            "  1. Bind the secret to a step `env:` variable and pass "
            "`${{ env.NAME }}` (with the leading double-quoted shell "
            "form for run-blocks); GitHub's runner masks env-bound "
            "secrets in logs and on injection;\n"
            "  2. Pin the action to a full commit SHA and audit it "
            "(removes the upstream-compromise leg)."
        ),
        reference=(
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets"
        ),
        test_positive=[],
        test_negative=[],
        stride=["I", "T", "E"],
        threat_narrative=(
            "An external contributor opens a PR. The workflow fires "
            "and invokes a third-party action that takes a "
            "`token:` input; the workflow passes `${{ secrets.PAT }}` "
            "to it without an env-block. The action's source — "
            "controlled by its upstream maintainer or anyone who "
            "compromises them — receives the secret in plaintext. "
            "The PR doesn't need to do anything except trigger; the "
            "secret leak is automatic."
        ),
        confidence="high",
        review_needed=False,
        finding_family="chain-composition",
        composition_tags=frozenset({"chain-composition"}),
    ),
    Rule(
        id="CHAIN-GH-103",
        title=(
            "Composite: tainted value reaches shell in a fork-reachable "
            "workflow (TAINT-GH-001 + fork trigger)"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "CHAIN-GH-103 composes: (1) TAINT-GH-001 fires on a "
            "`${{ github.event.X }}` value reaching a shell `run:` "
            "block; (2) the workflow is fork-reachable. Taint in "
            "isolation is review-needed; combined with a fork trigger "
            "it becomes a concrete external-attacker-injectable shell."
        ),
        pattern=CorpusPattern(callback=_make_chain_callback("CHAIN-GH-103")),
        remediation=(
            "Sanitise the tainted input — bind to an env var, then use "
            '`"$VAR"` inside the run block; never expand '
            "`${{ ... }}` directly into shell. The fork-reachable "
            "trigger is workflow intent; sanitising the taint flow "
            "removes the injection leg."
        ),
        reference=(
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable"
        ),
        test_positive=[],
        test_negative=[],
        stride=["T", "E"],
        threat_narrative=(
            "An external contributor opens a PR whose title contains "
            "shell metacharacters. The workflow's CI job inlines that "
            "title into a shell run via `${{ github.event.pull_request.title }}`. "
            "The shell interprets the metacharacters; arbitrary commands "
            "execute in the job's context with the workflow's secrets "
            "and token."
        ),
        confidence="high",
        review_needed=False,
        finding_family="chain-composition",
        composition_tags=frozenset({"chain-composition"}),
    ),
    Rule(
        id="CHAIN-GH-105",
        title=(
            "Composite: cross-job privilege escalation — low-privilege "
            "producer output flows into a write-capable consumer job "
            "(needs.*.outputs + privilege gradient)"
        ),
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-2",
        description=(
            "CHAIN-GH-105 composes workflow structure with per-job "
            "permission context: (1) a producer job declares an "
            "`outputs:` value and holds only a read-scope GITHUB_TOKEN; "
            "(2) a consumer job reads that value via "
            "`${{ needs.<producer>.outputs.<name> }}`; (3) the consumer "
            "job holds a write-capable token (e.g. `contents: write`, "
            "`id-token: write`).\n\n"
            "The producer is the lower-privilege, attacker-influenceable "
            "surface; its output crossing the job boundary into a "
            "write-capable consumer is a privilege-escalation vector — a "
            "value shaped under low authority drives an action under "
            "high authority.\n\n"
            "This is DISTINCT from TAINT-GH-009 (cross-job output "
            "reaching a *shell* sink): the boundary crossed here is the "
            "privilege gradient itself, not a specific dangerous "
            "statement. The composite fires only when the gradient is "
            "observable (read producer → write consumer); same-tier or "
            "high→low edges are benign data flow and are suppressed. "
            "Per-job permission attribution requires each job to declare "
            "its own `permissions:` block; when both jobs inherit the "
            "workflow default, no gradient is observable and the rule "
            "conservatively does not fire."
        ),
        pattern=CorpusPattern(callback=_make_chain_callback("CHAIN-GH-105")),
        remediation=(
            "Break the gradient or harden the boundary:\n"
            "  1. Treat `${{ needs.*.outputs.* }}` from a lower-privilege "
            "job as untrusted in the write-capable consumer — validate / "
            "allowlist it before it drives any write, publish, or "
            "deploy action;\n"
            "  2. Drop the consumer job's permissions to the minimum it "
            "actually needs (`permissions: contents: read`) so the "
            "escalation surface disappears;\n"
            "  3. If the producer genuinely needs to feed a privileged "
            "step, move the value through an explicitly validated "
            "intermediate (e.g. a checksum / enum check) rather than "
            "consuming it raw."
        ),
        reference=(
            "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-02-Inadequate-Identity-And-Access-Management"
        ),
        test_positive=[],
        test_negative=[],
        stride=["E", "T"],
        threat_narrative=(
            "A repository runs a two-job workflow: a read-only "
            "`validate` job (its `permissions:` block grants only "
            "`contents: read`) computes an output from data an external "
            "contributor can influence, and a `publish` job declares "
            "`contents: write` / `id-token: write` and consumes "
            "`${{ needs.validate.outputs.tag }}`. An attacker who can "
            "shape the producer's output — without ever obtaining "
            "write authority directly — steers what the write-capable "
            "job does, escalating from the low-privilege surface into "
            "the privileged one across the job boundary."
        ),
        confidence="medium",
        review_needed=True,
        finding_family="chain-composition",
        composition_tags=frozenset({"chain-composition"}),
    ),
]
