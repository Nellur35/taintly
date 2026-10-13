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

* CHAIN-GH-101 — SEC4-GH-005 + fork-reachable + an externally-triggered
  event that can retain write-token scope + write-token candidate.
  Also accepts a source-bound configured PR-head checkout/build/persisted-token
  path without a later Git command. Potential CRITICAL impact, review needed:
  neither branch proves runtime execution or effective provider authority.
* CHAIN-GH-102 — SEC3-GH-001 + fork-reachable = HIGH. An unpinned
  third-party action in a workflow attackers can fire; a single
  upstream compromise → arbitrary code in the fork-reachable job.
* CHAIN-GH-103 — TAINT-GH-001 + possible external context = HIGH,
  review needed. Owning guards exclude proven impossible events;
  runtime control, execution and authority still need verification.

The conjuncts intentionally cite *existing* lab-shipped rules rather
than re-implementing their patterns. Composer rules earn their keep
exactly by NOT duplicating detection logic — they layer threat-level
implications on top of what's already detected.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import TYPE_CHECKING

from taintly.composer import (
    CheckoutBuildFact,
    CompositeFact,
    context_for,
    execution_events_for,
    findings_by_rule,
)
from taintly.models import Platform, Rule, Severity
from taintly.workflow_corpus import (
    CorpusEvidence,
    CorpusFindings,
    CorpusPattern,
    WorkflowCorpus,
)

if TYPE_CHECKING:
    from taintly.parsers.segmentation import JobSegment, StepSegment
    from taintly.taint_facts.relations import Database, Fact

# ---------------------------------------------------------------------------
# Composer rules (closure-rule callables)
# ---------------------------------------------------------------------------

_CHAIN_101_TITLE = "Review: persisted checkout credential with external-trigger/write-scope context"
_CHAIN_101_REASON = (
    "The composition matches credential-consumer, trigger and permission candidates; "
    "it does not prove attacker-controlled checkout/execution or effective credential authority."
)
_CHAIN_101_REMEDIATION = (
    "First verify the checkout repository/ref, the later command or action that executes "
    "attacker-controlled bytes, and the persisted credential's identity and effective scopes. "
    "A default checkout followed by a fixed git command is not proof of fork-code execution.\n"
    "  1. Keep untrusted code execution in a separate unprivileged job;\n"
    "  2. Set `persist-credentials: false` when later steps do not need checkout authentication;\n"
    "  3. Declare minimum GITHUB_TOKEN permissions and separately restrict any custom token.\n"
    "Review repository defaults, workflow_run parent provenance and event/job/step guards. "
    "Requested write scopes and a trigger name alone do not establish an exploitable chain."
)


def _compose_chain_gh_101(db: Database) -> Iterable[tuple[str, Fact]]:
    """Compose a configured checkout/build path or a consumer review candidate.

    Both are possible pwn-request paths, not runtime/authority proof.
    Derived from existing finding output rather than re-detected from YAML.
    Anchors at the SEC4-GH-005 finding's
    line — that's the actions/checkout that should have set
    ``persist-credentials: false``.

    Note: SEC4-GH-005B (INFO posture sibling, added 2026-05-19 by
    github-tanstack-posture-design-v1) does NOT feed this composer.
    SEC4-GH-005B fires only when no downstream credential consumer
    is detected. A credential consumer alone does not prove that the
    attacker controls the command or checked-out code. Composing
    SEC4-GH-005B into CHAIN-GH-101 would re-introduce the FP-density
    noise the May-17 SEC4-GH-005 precision tune eliminated.  The
    composer's input set is intentionally limited to consumer candidates
    (SEC4-GH-005 only).

    Trigger eligibility follows the default public-repository GITHUB_TOKEN
    model: a fork-originated ``pull_request`` run is downgraded to read-only,
    even when the workflow also has a trusted ``push`` trigger or declares
    write permissions. ``pull_request_target``, ``issue_comment``, and a
    ``workflow_run`` with an external parent retain write scope. Unresolved
    workflow_run parents remain conservatively eligible. Static YAML cannot
    determine a private-repository setting that grants fork PR write tokens,
    nor whether checkout uses a custom PAT; this chain is specifically about
    the GITHUB_TOKEN and does not infer those repository-level overrides.
    """
    witnessed: set[tuple[str, str, int]] = set()
    for fact in db.all("checkout_build"):
        if not isinstance(fact, CheckoutBuildFact):
            continue
        w = fact.witness
        # This witness already validates the owning event/guards/grants. The
        # broader job heuristics below can be affected by unrelated later steps
        # and must not discard this stronger, source-bound configuration path.
        witnessed.add((w.file, w.job, w.checkout_line))
        scopes = ", ".join(f"{scope}:write (line {line})" for scope, line in w.write_scopes)
        yield (
            "composite",
            CompositeFact(
                chain_id="CHAIN-GH-101",
                file=w.file,
                job=w.job,
                anchor_line=w.checkout_line,
                snippet=(
                    f"Configured pull_request_target path in job '{w.job}': "
                    f"PR-head repository/ref at lines {w.repository_line}/{w.ref_line} "
                    f"-> checkout at line {w.checkout_line} -> local build `{w.command}` "
                    f"at line {w.build_line}. The build can execute checkout-provided hooks "
                    f"with a persisted GITHUB_TOKEN candidate (line {w.persistence_line}); "
                    f"requested scopes: {scopes}. Runtime execution and effective provider "
                    "authority remain unverified."
                ),
                checkout_build=w,
            ),
        )
    for f in findings_by_rule(db, "SEC4-GH-005"):
        if not f.job:
            continue
        ctx = context_for(db, f.file, f.job)
        if ctx is None:
            continue
        if not ctx.fork_reachable:
            continue
        possible = execution_events_for(db, f.file, f.job, f.line, privileged=True)
        if possible == frozenset():
            continue
        if not ctx.external_privileged:
            continue
        if not ctx.has_write_token:
            continue
        if (f.file, f.job, f.line) in witnessed:
            continue
        snippet = (
            f"CHAIN candidate in job '{f.job}', checkout anchor line {f.line}: "
            "SEC4-GH-005 credential-consumer candidate + external-privileged "
            "trigger + declared or default-unknown write-token context. "
            "Attacker-controlled code execution and effective persisted-token "
            "authority are not proven by this join."
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
        if not f.job:
            continue
        ctx = context_for(db, f.file, f.job)
        if ctx is None:
            continue
        if not ctx.fork_reachable:
            continue
        possible = execution_events_for(db, f.file, f.job, f.line, privileged=False)
        if possible == frozenset():
            continue
        if not _is_high_blast_radius_action(db, f.file, f.line):
            continue
        snippet = (
            "Review: mutable third-party action (SEC3-GH-001) with a secret, "
            "container or publish/deploy indicator in externally triggered context. "
            "An upstream compromise could affect this invocation. Verify action "
            "behavior, actual event/guards, approvals and available credentials; "
            "the join does not prove compromise or effective runtime authority."
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
    """Taint candidate plus compatible external event context, review needed."""
    for f in findings_by_rule(db, "TAINT-GH-001"):
        if not f.job:
            continue
        ctx = context_for(db, f.file, f.job)
        if ctx is None:
            continue
        if not ctx.fork_reachable:
            continue
        possible = execution_events_for(db, f.file, f.job, f.line, privileged=False)
        if possible == frozenset():
            continue
        # Surface the constituent TAINT-GH-001 finding's rendered
        # source→hop→sink path (its snippet) so the upgraded finding shows
        # WHY it chained, not just the conclusion.
        path_note = f" Taint path: {f.snippet}" if f.snippet else ""
        snippet = (
            "Review: TAINT-GH-001 source-to-shell candidate in externally triggered "
            "context. Verify attacker control, owning guards and shell interpretation. "
            "A trusted triggering actor does not establish input integrity; runtime "
            "execution, secret availability and token authority remain unverified." + path_note
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
    """Secret-input and mutable-action candidates at one compatible step.

    Upstream compromise, secret availability and authority are unverified.
    Environment transport and log masking do not isolate a secret from its
    recipient. The source rule's legacy category is not an access proof.
    """
    # Build (file, line) anchors of every UNPINNED THIRD-PARTY
    # action finding.  SEC3-GH-001 fires on the ``uses:`` line for
    # third-party actions only; SEC3-GH-001A fires on first-party
    # actions (``actions/*``, ``aws-actions/*``, ``github/*``,
    # ``microsoft/*``, ``Azure/*``) and is INTENTIONALLY EXCLUDED:
    # This is the existing third-party rule boundary, not proof of a
    # publisher's integrity or a pinned action's safety.
    #
    # SEC6-GH-010 fires on the ``token: ${{ secrets.X }}`` line a
    # few lines below the ``uses:`` line inside the same step's
    # ``with:`` block. The helper below requires the actual step's uses
    # anchor, rather than accepting an arbitrary nearby action finding.
    unpinned_by_job: dict[tuple[str, str], set[int]] = {}
    for f in findings_by_rule(db, "SEC3-GH-001"):
        if f.job:
            unpinned_by_job.setdefault((f.file, f.job), set()).add(f.line)

    for f in findings_by_rule(db, "SEC6-GH-010"):
        if not f.job:
            continue
        ctx = context_for(db, f.file, f.job)
        if ctx is None:
            continue
        if not ctx.fork_reachable:
            continue
        possible = execution_events_for(db, f.file, f.job, f.line, privileged=False)
        if possible == frozenset():
            continue
        # Leg (3): does the SEC6-GH-010-bearing step's ``uses:``
        # line itself have a SEC3-GH-001 finding?  This locks the
        # third leg to the actual step, not a nearby earlier step.
        unpinned_lines = unpinned_by_job.get((f.file, f.job), set())
        if not unpinned_lines:
            continue
        if not _has_unpinned_in_step_window(unpinned_lines, f.line, f.file):
            continue
        snippet = (
            "Review: a secret reference is supplied to a mutable third-party action "
            "at the same step (SEC6-GH-010 + SEC3-GH-001), in externally triggered "
            "context. A compromised action could misuse a credential if available. "
            "Verify secret availability, action behavior and effective authority. "
            "Changing with: to env: does not isolate a secret from its recipient."
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

# Observable uses of GitHub/package authority inside a write-capable job. The
# list is deliberately structural and conservative: it proves that the job
# actually exercises authority somewhere in the relevant step/scope, while the
# rule remains review-needed until value-to-call argument provenance is known.
_GITHUB_REST_WRITE_RE = re.compile(
    r"\bgithub\.rest\.[A-Za-z0-9_]+\."
    r"(?:add|cancel|close|create|delete|disable|dismiss|enable|lock|merge|"
    r"remove|reopen|replace|request|rerun|set|submit|transfer|unlock|update)"
    r"[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE,
)
_GITHUB_REQUEST_WRITE_RE = re.compile(
    r"\bgithub\.request\s*\(\s*(?:"
    r"[\"'`]\s*(?:POST|PUT|PATCH|DELETE)\b|"
    r"\{(?:(?!\}\s*\)).){0,1000}?\bmethod\s*:\s*[\"'`]"
    r"(?:POST|PUT|PATCH|DELETE)\b"
    r")",
    re.IGNORECASE | re.DOTALL,
)
_GITHUB_GRAPHQL_MUTATION_RE = re.compile(
    r"\bgithub\.graphql\s*\(\s*[\"'`]?\s*mutation\b",
    re.IGNORECASE,
)
_GH_CLI_WRITE_RE = re.compile(
    r"\bgh\s+(?:"
    r"issue\s+(?:close|comment|create|delete|edit|lock|pin|reopen|transfer|unlock)|"
    r"pr\s+(?:close|comment|create|edit|lock|merge|ready|reopen|review|unlock)|"
    r"release\s+(?:create|delete|edit|upload)|"
    r"repo\s+(?:archive|create|delete|edit|fork|rename|sync)|"
    r"run\s+(?:cancel|delete|rerun)|"
    r"workflow\s+(?:disable|enable|run)"
    r")\b",
    re.IGNORECASE,
)
_GH_API_RE = re.compile(r"\bgh\s+api\b", re.IGNORECASE)
_GH_API_WRITE_METHOD_RE = re.compile(
    r"(?:--method(?:=|\s+)|-X\s*)(?:POST|PUT|PATCH|DELETE)\b", re.IGNORECASE
)
_GH_API_READ_METHOD_RE = re.compile(r"(?:--method(?:=|\s+)|-X\s*)(?:GET|HEAD)\b", re.IGNORECASE)
_GH_API_IMPLICIT_POST_RE = re.compile(
    r"(?:^|\s)(?:-f|-F|--field|--raw-field)(?:=|\s+)", re.IGNORECASE
)
_OTHER_AUTHORITY_OPERATION_RE = re.compile(
    r"\bgit\s+push\b|"
    r"\b(?:npm|pnpm|yarn)\s+publish\b|"
    r"\b(?:twine\s+upload|docker\s+push)\b|"
    r"\b(?:curl|wget)\b[^\n]*(?:"
    r"\bapi\.github\.com\b[^\n]*(?:-X|--request)\s*"
    r"(?:POST|PUT|PATCH|DELETE)\b|"
    r"(?:-X|--request)\s*(?:POST|PUT|PATCH|DELETE)\b[^\n]*"
    r"\bapi\.github\.com\b)",
    re.IGNORECASE,
)
_ACTION_USES_RE = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*([^\s#]+)", re.MULTILINE)
_AUTHORITY_TOKEN_INPUT_RE = re.compile(
    r"^\s*(?:github[_-]?token|token)\s*:\s*['\"]?"
    r"\$\{\{\s*(?:secrets\.[A-Za-z_][A-Za-z0-9_]*|github\.token)\s*\}\}['\"]?",
    re.IGNORECASE | re.MULTILINE,
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


def _producer_jobs_in_lines(lines: list[str]) -> set[str]:
    """Return job names in ``lines`` that declare an
    ``outputs:`` block (the producers of cross-job output edges).

    A job declares outputs when an ``outputs:`` key appears at the
    job-body indent (one level deeper than the job key). We use the
    shared :func:`_split_into_job_segments` so the job-boundary
    heuristic matches the corpus and per-file rules exactly.
    """
    from taintly.models import _split_into_job_segments

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


def _crossjob_edges_in_content(content: str) -> list[_CrossJobEdge]:
    """Extract every ``needs.<producer>.outputs.<name>`` edge in
    ``content``, attributing each reference to the consumer job whose
    segment contains it.

    Only edges whose producer actually declares an ``outputs:`` block
    are kept: a ``needs.X.outputs.Y`` reference to a job that doesn't
    declare outputs is a typo / dead reference, not a real data edge.
    """
    from taintly.models import _split_into_job_segments

    lines = content.splitlines()
    producers = _producer_jobs_in_lines(lines)
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


def _scope_exercises_write_authority(text: str) -> bool:
    """Whether a step/job contains a recognized authority-operation indicator.

    A declared write permission by itself is latent capability. CHAIN-GH-105
    needs an operation indicator in the consumer scope. Direct API, CLI, push,
    or publish call text qualifies. An action step qualifies when it is
    explicitly handed a GitHub/PAT token. This textual indicator does not prove
    runtime execution, effective authority, or argument-level propagation.
    """
    if _GITHUB_REST_WRITE_RE.search(text) or _GH_CLI_WRITE_RE.search(text):
        return True
    if _GITHUB_REQUEST_WRITE_RE.search(text):
        return True
    if _GITHUB_GRAPHQL_MUTATION_RE.search(text):
        return True
    if _GH_API_RE.search(text):
        if _GH_API_WRITE_METHOD_RE.search(text):
            return True
        if not _GH_API_READ_METHOD_RE.search(text) and _GH_API_IMPLICIT_POST_RE.search(text):
            return True
    if _OTHER_AUTHORITY_OPERATION_RE.search(text):
        return True
    return bool(_ACTION_USES_RE.search(text) and _AUTHORITY_TOKEN_INPUT_RE.search(text))


def _edge_has_authority_sink(
    edge: _CrossJobEdge,
    steps: list[StepSegment],
    jobs: list[JobSegment],
    authority_cache: dict[tuple[str, int, int], bool],
) -> bool:
    """Require a recognized authority-operation indicator in the edge scope.

    Step-local references (the common ``env:`` / ``with:`` shape) cannot borrow
    an unrelated privileged action from another step. A reference in job-level
    ``env:`` or ``if:`` can feed later steps, so the whole consumer job is the
    conservative scope.
    """
    for step in steps:
        if step.job_name == edge.consumer and step.start_line <= edge.line <= step.end_line:
            key = ("step", step.start_line, step.end_line)
            if key not in authority_cache:
                authority_cache[key] = _scope_exercises_write_authority(step.text)
            return authority_cache[key]

    for job in jobs:
        if job.name == edge.consumer and job.start_line <= edge.line <= job.end_line:
            key = ("job", job.start_line, job.end_line)
            if key not in authority_cache:
                authority_cache[key] = _scope_exercises_write_authority(job.text)
            return authority_cache[key]
    return False


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


def _edge_events_compatible(db: Database, file: str, edge: _CrossJobEdge, steps) -> bool:
    """Reject only proven disjoint producer/reader/authority event sets."""
    possibilities = [
        execution_events_for(db, file, edge.producer, privileged=True),
        execution_events_for(db, file, edge.consumer, privileged=True),
        execution_events_for(db, file, edge.consumer, edge.line, privileged=True),
    ]
    same_step = any(
        step.job_name == edge.consumer and step.start_line <= edge.line <= step.end_line
        for step in steps
    )
    if not same_step:
        # Job-level env references can be read in a different step. Include
        # every statically recognized authority scope; opaque ownership stays
        # unknown. Job conditions above still apply independently.
        authorities = [
            execution_events_for(db, file, edge.consumer, step.start_line, privileged=True)
            for step in steps
            if step.job_name == edge.consumer and _scope_exercises_write_authority(step.text)
        ]
        if authorities and all(events is not None for events in authorities):
            possibilities.append(frozenset().union(*authorities))
    known = [events for events in possibilities if events is not None]
    return not known or bool(frozenset.intersection(*known))


def _compose_chain_gh_105(db: Database) -> Iterable[tuple[str, Fact]]:
    """Cross-job privilege escalation (P1.3) → MEDIUM review candidate.

    A LOW-privilege producer job (``has_write_token=False``) declares
    an output that a HIGH-privilege consumer job
    (``has_write_token=True``) reads via
    ``${{ needs.<producer>.outputs.<name> }}``. The producer is the
    exposed / attacker-influenceable surface. The relevant consumer
    step or job scope must also contain a recognized textual authority
    indicator, such as a mutating GitHub API/CLI call, a push/publish
    command, or an action explicitly handed a token.

    Distinct from TAINT-GH-009 (cross-job output → *shell* sink) and
    from the severity-escalation / id-token co-occurrence rules: this
    rule accepts API and action sinks as well as shell operations. It
    requires a privilege GRADIENT (read producer → write consumer) and
    a co-scoped operation indicator. It remains review-needed because this
    layer does not establish runtime execution, effective authority, or
    argument-level proof that the transferred value controls the operation.

    Per-job write-token resolution relies on each job declaring its
    own ``permissions:`` block (the only way the corpus can attribute
    a job-specific :class:`JobContextFact`). When both jobs fall back
    to the workflow-default wildcard, no gradient is observable and
    the rule conservatively does NOT fire — favouring precision, the
    whole point of the composer family.

    A plain ``pull_request`` from a fork is not sufficient: GitHub normally
    downgrades every declared write scope to read-only for that event. The
    rule therefore also requires an externally-triggerable event that can
    retain write authority (for example ``pull_request_target``, ``issues``,
    or ``workflow_run`` whose named parent is externally reachable). A
    push-only ``workflow_run`` parent is excluded; an unresolved parent fails
    open as review-needed. Repository settings can opt private forks out of the
    downgrade; without that deployment context, those remain outside the
    statically confirmed rule contract.
    """
    files = _files_with_contexts(db)
    for file in sorted(files):
        try:
            with open(file, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        edges = _crossjob_edges_in_content(content)
        if not edges:
            continue
        from taintly.parsers.segmentation import for_each_job, for_each_step

        steps = for_each_step(content)
        jobs = for_each_job(content)
        authority_cache: dict[tuple[str, int, int], bool] = {}
        for edge in edges:
            producer_ctx = context_for(db, file, edge.producer)
            consumer_ctx = context_for(db, file, edge.consumer)
            if producer_ctx is None or consumer_ctx is None:
                continue
            # A normal fork-originated pull_request token is forced read-only
            # by GitHub, even when the YAML requests write. Without an event
            # that can retain write authority, the claimed privilege gradient
            # does not exist in the default execution model.
            if not producer_ctx.external_privileged:
                continue
            # The privilege GRADIENT: read-only producer → write consumer.
            if producer_ctx.has_write_token:
                continue
            if not consumer_ctx.has_write_token:
                continue
            # A write scope is latent capability, not proof of a privileged
            # operation. Require a recognized textual operation indicator in
            # the relevant step (or job for job-level references); runtime
            # execution and value-to-operation propagation remain unproven.
            if not _edge_has_authority_sink(edge, steps, jobs, authority_cache):
                continue
            if not _edge_events_compatible(db, file, edge, steps):
                continue
            snippet = (
                f"Review: producer job `{edge.producer}` declares output `{edge.output}` "
                f"read by consumer `{edge.consumer}` via "
                f"`${{{{ needs.{edge.producer}.outputs.{edge.output} }}}}`. "
                "Configured token permissions show a read-to-write candidate gradient, "
                "and the relevant consumer scope contains an authority-operation "
                "indicator. Verify producer input control, argument-level propagation, "
                "compatible guards, token identity and effective provider authority; "
                "this composition does not establish a successful privilege escalation."
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
        results: CorpusFindings = []
        for c in composites:
            if c.chain_id != chain_id:
                continue
            if chain_id == "CHAIN-GH-101":
                if c.checkout_build is not None:
                    w = c.checkout_build
                    reason = (
                        "The same-source structural witness links PR-head checkout, a "
                        "supported local build command and configured persisted GITHUB_TOKEN "
                        "write scopes. Hook existence, tool/configuration behavior, successful "
                        "execution, approvals and effective provider authority need review."
                    )
                    results.append(
                        CorpusEvidence(
                            file=c.file,
                            line=c.anchor_line,
                            snippet=c.snippet,
                            title="Review: PR-head build can access a persisted write-token candidate",
                            remediation=(
                                f"In job '{w.job}', set `persist-credentials: false` on the "
                                f"checkout at line {w.checkout_line} (persistence input/default "
                                f"at line {w.persistence_line}), and run the untrusted build at "
                                f"line {w.build_line} in a separate unprivileged job. Minimize "
                                f"the requested permissions at line {w.permission_line}. Verify "
                                "the checked-out build definitions, tool configuration, guards, "
                                "approvals and provider-granted token scopes before concluding "
                                "that this path is exploitable."
                            ),
                            context_notes=(reason,),
                            context_tags=(
                                "checkout-build-path-evidenced",
                                "persisted-github-token-configured",
                                "runtime-execution-unverified",
                                "effective-token-policy-unresolved",
                            ),
                            calibration_reason=reason,
                        )
                    )
                    continue
                results.append(
                    CorpusEvidence(
                        file=c.file,
                        line=c.anchor_line,
                        snippet=c.snippet,
                        title=_CHAIN_101_TITLE,
                        remediation=_CHAIN_101_REMEDIATION,
                        context_notes=(_CHAIN_101_REASON,),
                        context_tags=("execution-unproven", "credential-authority-unproven"),
                        calibration_reason=_CHAIN_101_REASON,
                    )
                )
            else:
                results.append((c.file, c.anchor_line, c.snippet))
        return results

    return callback


RULES: list[Rule] = [
    Rule(
        id="CHAIN-GH-101",
        title=_CHAIN_101_TITLE,
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-1",
        description=(
            "CHAIN-GH-101 accepts either a source-bound configured path from "
            "PR-head repository/ref through a supported local build command to "
            "a persisted GITHUB_TOKEN with explicit requested write scopes, or "
            "a broader join of three findings/contexts: "
            "(1) SEC4-GH-005 fires on an actions/checkout step that "
            "doesn't set `persist-credentials: false`; "
            "(2) an external trigger can start the job with retained "
            "write scope (`pull_request_target`, `issue_comment`, or "
            "`workflow_run` whose named parent is externally reachable); "
            "and (3) the job requests write permissions, or permissions "
            "are omitted and the repository default is unknown. A plain "
            "`pull_request` run is downgraded to read-only by default, and "
            "adding a trusted `push` trigger does not upgrade that PR run.\n\n"
            "This uses GitHub's default public-repository fork-token policy. "
            "Static workflow YAML cannot identify private-repository settings "
            "that grant fork PRs write tokens or prove that checkout receives "
            "a custom PAT; custom credentials are outside this GITHUB_TOKEN "
            "authority proof. An unresolved workflow_run parent remains conservatively "
            "eligible.\n\n"
            "This is a review candidate with potentially CRITICAL consequences, "
            "not a confirmed pwn request. The broader join does not establish an "
            "attacker-controlled repository/ref, execution of those bytes, "
            "compatible runtime guards, or the persisted token's identity and "
            "effective authority. A default pull_request_target checkout uses "
            "trusted base code; even an untrusted checkout alone is not execution. "
            "The configured-path branch cites exact source, build, persistence "
            "and permission lines without requiring a later fixed Git command. "
            "Build-hook existence, configuration, runtime success, approvals "
            "and effective provider permissions remain unverified."
        ),
        pattern=CorpusPattern(callback=_make_chain_callback("CHAIN-GH-101")),
        remediation=_CHAIN_101_REMEDIATION,
        reference=(
            "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"
        ),
        test_positive=[],
        test_negative=[],
        stride=["E", "T", "S"],
        threat_narrative=(
            "If an external contributor can cause attacker-controlled code to "
            "execute in this job while a persisted credential has useful write "
            "authority, that code could reuse the credential to modify authorized "
            "repository resources. This composition does not prove those conditions: "
            "a later git command may be entirely trusted, an omitted permissions "
            "block leaves repository defaults unknown, and a custom checkout token "
            "may have different authority from GITHUB_TOKEN. Verify each missing "
            "source-to-execution and credential-authority edge before treating "
            "the candidate as exploitable."
        ),
        confidence="medium",
        review_needed=True,
        finding_family="chain-composition",
        composition_tags=frozenset({"chain-composition"}),
    ),
    Rule(
        id="CHAIN-GH-102",
        title=(
            "Review: mutable third-party action with sensitive-operation indicators in external context"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "Joins a mutable third-party action finding, a sensitive-operation indicator and external-trigger context. Possible upstream compromise and runtime authority require review; this does not prove attacker control of the action or execution."
        ),
        pattern=CorpusPattern(callback=_make_chain_callback("CHAIN-GH-102")),
        remediation=(
            "Pin the action to a reviewed full commit SHA and minimize credentials and permissions supplied to it. Verify the actual event, owning guards and action behavior. Pinning prevents silent tag/branch replacement; it does not establish that the pinned implementation is safe."
        ),
        reference=(
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"
        ),
        test_positive=[],
        test_negative=[],
        stride=["T", "E"],
        threat_narrative=(
            "If an upstream publisher or mutable ref is compromised and the action executes with useful credentials, malicious action code could misuse those credentials. External triggering, action compromise, secret availability and effective authority are separate prerequisites."
        ),
        confidence="medium",
        review_needed=True,
        finding_family="chain-composition",
        composition_tags=frozenset({"chain-composition"}),
    ),
    Rule(
        id="CHAIN-GH-104",
        title=(
            "Review: secret reference supplied to a mutable third-party action in external context"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "Joins a secret-input finding with a mutable third-party action at the same step and external-trigger context. This identifies a potential sensitive recipient; it does not prove secret availability, malicious behavior or exfiltration. Both with and env can supply secrets to actions."
        ),
        pattern=CorpusPattern(callback=_make_chain_callback("CHAIN-GH-104")),
        remediation=(
            "Audit and pin the recipient action to a full commit SHA; remove unnecessary secrets and minimize credential permissions. Verify event-specific secret availability and recipient behavior. Moving a secret from with: to env: does not protect it from an action that receives it; log masking is not isolation."
        ),
        reference=(
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets"
        ),
        test_positive=[],
        test_negative=[],
        stride=["I", "T", "E"],
        threat_narrative=(
            "A compromised action could misuse a secret supplied to it, whether delivered as an input or environment variable, if the credential is available for that invocation. A mutable ref and a secret reference alone do not prove compromise, access, exfiltration or usable authority."
        ),
        confidence="medium",
        review_needed=True,
        finding_family="chain-composition",
        composition_tags=frozenset({"chain-composition"}),
    ),
    Rule(
        id="CHAIN-GH-103",
        title=("Review: source-to-shell candidate with external-trigger context"),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "Joins TAINT-GH-001 with possible external execution context. Proven impossible owning event guards are excluded. Input control, shell interpretation, runtime execution and credential authority remain review questions."
        ),
        pattern=CorpusPattern(callback=_make_chain_callback("CHAIN-GH-103")),
        remediation=(
            "Pass untrusted data as structured arguments or through an intermediate environment variable and quote shell expansions. Remove eval, shell -c and other reevaluation of untrusted values: quoting a variable passed to eval does not prevent command injection. Verify the actual source, owning guards and sink."
        ),
        reference=(
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable"
        ),
        test_positive=[],
        test_negative=[],
        stride=["T", "E"],
        threat_narrative=(
            "If attacker-controlled content reaches a shell interpretation or reevaluation sink in a reachable invocation, it could execute commands with that invocation's available authority. A trusted triggering actor alone does not sanitize that content. Secret availability and effective token scopes need separate verification."
        ),
        confidence="medium",
        review_needed=True,
        finding_family="chain-composition",
        composition_tags=frozenset({"chain-composition"}),
    ),
    Rule(
        id="CHAIN-GH-105",
        title=(
            "Review: cross-job output with configured privilege gradient and authority-operation indicator"
        ),
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-2",
        description=(
            "Joins a declared producer output, consumer needs reference, configured read-to-write permission gradient and consumer authority-operation indicator. Proven disjoint event guards are excluded. Producer attacker control, argument-level propagation, runtime success, token identity and effective provider authority remain unverified."
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
