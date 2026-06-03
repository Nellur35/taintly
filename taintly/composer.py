"""Finding-as-EDB composer — the CHAIN concept.

This module wires the fixed-point engine to consume scan-time
findings as facts, then derive composite findings when
combinations indicate a higher-severity threat.

Architecture:

1. Per-file scan + corpus pass run first (engine.py owns those).
2. Their findings are pushed into a fresh :class:`Database` as
   :class:`FindingFact` rows.
3. Context facts (:class:`JobContextFact`) are seeded from the
   workflow corpus — job triggers, write-token state, trusted-bot
   if-gates.
4. Composer rules close over the database; when their preconditions
   hold for some (file, job), they assert :class:`CompositeFact`
   rows.
5. The engine reads the asserted composites back out and wraps each
   as a :class:`taintly.models.Finding` with the chain rule's
   metadata.

The composer rules are deliberately small (each is a co-occurrence
check with a workflow-context predicate). The substrate isn't doing
recursion here — it's doing the *join* — which is what makes the
machinery actually earn its keep on this layer of the system.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from taintly.taint_facts.closure import solve
from taintly.taint_facts.relations import Database

if TYPE_CHECKING:
    from taintly.models import Finding
    from taintly.workflow_corpus import WorkflowCorpus

# ---------------------------------------------------------------------------
# EDB fact types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FindingFact:
    """One scan-time finding, lifted into the composer's database.

    Key columns identify the finding's location + rule; severity and
    anchor line are carried as payload so composer rules don't have
    to re-look-up. ``job`` may be ``None`` when the source finding
    didn't carry job attribution (e.g. workflow-level findings); such
    findings still match composer rules that only join on file.
    """

    rule_id: str
    file: str
    job: str | None
    line: int
    severity_value: str  # Severity.value (string) — keeps Fact hashable

    def fact_key(self):
        return (self.rule_id, self.file, self.job, self.line)

    def fact_rank(self):
        return (0,)  # findings are first-class; never displaced


@dataclass(frozen=True)
class JobContextFact:
    """Workflow context predicates a composer rule can join against.

    Derived from the corpus, NOT from findings. Keyed by (file, job)
    so composer rules can index it by the join column of choice.

    Predicates:

    * ``fork_reachable``: any trigger in the workflow is in
      ``TriggerFamily.FORK_REACHABLE``.
    * ``has_write_token``: the job's effective permissions include
      any write-scope (or the workflow defaults to write because no
      explicit ``permissions:`` block exists at workflow or job
      level).
    * ``trusted_bot_gate``: the job's ``if:`` restricts execution to
      a known-trusted bot (dependabot, renovate, github-actions[bot],
      pre-commit-ci); if present, composer rules that depend on
      *external* attacker control should suppress.
    """

    file: str
    job: str
    fork_reachable: bool
    has_write_token: bool
    trusted_bot_gate: bool

    def fact_key(self):
        return (self.file, self.job)

    def fact_rank(self):
        return (0,)


@dataclass(frozen=True)
class CompositeFact:
    """A chain rule's output — one per (chain_id, file, job) match.

    Anchor line is the cited line in ``file`` for the composite
    finding (typically the line of the *foothold* finding that
    started the chain). Snippet is the rendered explanation.
    """

    chain_id: str
    file: str
    job: str | None
    anchor_line: int
    snippet: str

    def fact_key(self):
        return (self.chain_id, self.file, self.job, self.anchor_line)

    def fact_rank(self):
        return (0,)


# ---------------------------------------------------------------------------
# Composer rule type
# ---------------------------------------------------------------------------

# A composer rule is just a closure-rule callable: it reads the
# database and yields ``("composite", CompositeFact(...))`` tuples for
# every chain match it finds. Keeping the type alias here lets the
# CHAIN-GH-* modules import a self-documenting name.
ComposerRule = "Callable[[Database], Iterable[tuple[str, Fact]]]"


# ---------------------------------------------------------------------------
# Trusted-bot user.login allowlist (matches PSE-GH-006's gate)
# ---------------------------------------------------------------------------

_TRUSTED_BOT_PATTERNS: tuple[str, ...] = (
    "dependabot[bot]",
    "renovate[bot]",
    "github-actions[bot]",
    "pre-commit-ci[bot]",
)


def _job_has_trusted_bot_gate(job_if: str | None) -> bool:
    """Return True when ``job.if`` restricts execution to a trusted bot.

    Matches forms:
      * ``github.event.pull_request.user.login == 'dependabot[bot]'``
      * ``github.actor == 'renovate[bot]'``
      * ``github.triggering_actor == 'github-actions[bot]'``

    Conservatively: any bot pattern's presence in the if-expr suppresses
    the chain. False positives here (a job that mentions dependabot but
    doesn't really gate on it) yield only missed CHAIN findings, never
    extra ones — the trade-off is precision over recall.
    """
    if not job_if:
        return False
    low = job_if.lower()
    return any(pat.lower() in low for pat in _TRUSTED_BOT_PATTERNS)


# ---------------------------------------------------------------------------
# EDB seeding
# ---------------------------------------------------------------------------


def _seed_findings(
    db: Database,
    prior_findings: Iterable[Finding],
) -> None:
    """Push each prior finding into the database as a FindingFact.

    The composer can't derive what existing rules emit; it sees only
    what the engine hands it. Findings without a job attribution are
    still seeded (key carries ``job=None``); composer rules that
    require job-level co-occurrence simply won't match them.
    """
    for f in prior_findings:
        if f.rule_id == "ENGINE-ERR":
            continue  # don't compose error-class findings into chains
        # ``Finding.job`` was added late and may not exist on older
        # Finding subclasses; tolerate the absence gracefully.
        job = getattr(f, "job", None)
        line = f.line or 0
        db.add(
            "finding",
            FindingFact(
                rule_id=f.rule_id,
                file=f.file or "",
                job=job,
                line=line,
                severity_value=f.severity.value if f.severity else "info",
            ),
        )


def _seed_job_contexts(db: Database, corpus: WorkflowCorpus) -> None:
    """Walk the corpus and assert one JobContextFact per (file, job).

    Workflow-level permissions and triggers cascade to every job in
    the file. Job-level permissions override the workflow default
    when present.

    Trusted-bot gate detection is content-level: if any `if:` line in
    the workflow file mentions a trusted-bot user.login pattern, the
    workflow-level context's ``trusted_bot_gate`` is set to True. This
    over-approximates (a single bot-gated job suppresses all chain
    findings on the file) but errs on the side of fewer FPs, which is
    the right trade-off for composer rules whose precision is the
    whole point.
    """
    from taintly.workflow_corpus import TriggerFamily

    for wf in corpus.all():
        fork = TriggerFamily.FORK_REACHABLE in wf.triggers
        wf_write = _permission_block_has_write(wf.workflow_permissions)
        # Workflow's default GITHUB_TOKEN is write-capable when there is
        # no explicit `permissions:` block at all. (GitHub's default
        # changed in 2023 to read-only for new orgs but old orgs and
        # repos still default to write; the rule's threat model treats
        # absence as write-capable.)
        wf_default_write = wf.workflow_permissions is None

        # Content-level bot-gate scan. Look for `if:` lines whose
        # right-hand side mentions any trusted-bot pattern.
        bot_gated = _content_has_trusted_bot_gate(wf.content)

        # No structured job list in WorkflowSummary today — derive job
        # names from the job_permissions blocks (which carry one entry
        # per job that declared an override) plus the implicit "no
        # override" jobs we can't see at this layer. The composer
        # therefore creates JobContextFact only for jobs we have
        # *enough* signal to reason about. Jobs whose permissions
        # block is implicit fall back to workflow-level state under
        # the same (file, "*") key.
        for jb in wf.job_permissions:
            job_name = getattr(jb, "job", None) or getattr(jb, "name", None)
            if not job_name:
                continue
            db.add(
                "job_context",
                JobContextFact(
                    file=wf.filepath,
                    job=job_name,
                    fork_reachable=fork,
                    has_write_token=_permission_block_has_write(jb),
                    trusted_bot_gate=bot_gated,
                ),
            )

        # Workflow-default context — anchored at job="*". Composer rules
        # that need per-job attribution can join against this when the
        # job is implicit.
        db.add(
            "job_context",
            JobContextFact(
                file=wf.filepath,
                job="*",
                fork_reachable=fork,
                has_write_token=wf_write or wf_default_write,
                trusted_bot_gate=bot_gated,
            ),
        )


def _content_has_trusted_bot_gate(content: str) -> bool:
    """Quick content-level scan for `if:` lines that gate on a trusted bot.

    Matches an `if:` line followed (within ~200 chars) by any of:
      * ``user.login == 'dependabot[bot]'``
      * ``github.actor == 'renovate[bot]'``
      * ``triggering_actor == 'github-actions[bot]'``
      * exact-match on any pattern in :data:`_TRUSTED_BOT_PATTERNS`

    Over-approximates: a workflow with one bot-gated job marks the
    whole file as gated. That favours fewer composer FPs at the cost
    of missed multi-job composites; tractable for the precision-
    focused composer family.
    """
    import re

    # Find every `if:` line and check the next ~200 chars for a bot
    # pattern. ``re.IGNORECASE`` because user.login matches are
    # case-insensitive in GHA expression evaluation.
    for m in re.finditer(r"\bif\s*:", content):
        window = content[m.start() : m.start() + 200]
        for pat in _TRUSTED_BOT_PATTERNS:
            if pat.lower() in window.lower():
                return True
    return False


def _permission_block_has_write(perm) -> bool:
    """Return True when any grant in a PermissionBlock is a write-scope.

    ``permissions: write-all`` and any per-scope grant whose value is
    ``write`` (e.g. ``contents: write``) both qualify. ``read-all`` and
    the empty block do not.
    """
    if perm is None:
        return False
    if getattr(perm, "is_write_all", False):
        return True
    grants = getattr(perm, "grants", None) or {}
    for scope, level in grants.items():
        lvl = (level or "").strip().lower()
        if lvl == "write" or scope.strip().lower() == "write-all":
            return True
    return False


# ---------------------------------------------------------------------------
# Composer driver
# ---------------------------------------------------------------------------


def run_composer(
    corpus: WorkflowCorpus,
    prior_findings: Iterable[Finding],
    composer_rules: list,
) -> list[CompositeFact]:
    """Build the composer database, run rules to fixed point, return
    the asserted composite facts.

    ``composer_rules`` is a list of closure-rule callables (each takes
    the :class:`Database` and yields ``(relation, fact)`` tuples).
    """
    db = Database()
    _seed_findings(db, prior_findings)
    _seed_job_contexts(db, corpus)
    solve(db, composer_rules)
    return list(db.all("composite"))  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Helpers exposed to composer rule modules
# ---------------------------------------------------------------------------


def findings_by_rule(db: Database, rule_id: str) -> list[FindingFact]:
    """Convenience: every FindingFact with a given rule_id.

    O(n) over the finding relation; composer rules call this rather
    than building per-rule indexes by hand. Database stays
    index-free per its `taint_facts/relations.py` design note.
    """
    return [f for f in db.all("finding") if isinstance(f, FindingFact) and f.rule_id == rule_id]


def context_for(db: Database, file: str, job: str | None) -> JobContextFact | None:
    """Return the JobContextFact for (file, job), falling back to the
    workflow-level wildcard `(file, "*")` when the job-specific one
    isn't asserted.
    """
    if job:
        ctx = db.get("job_context", (file, job))
        if isinstance(ctx, JobContextFact):
            return ctx
    ctx = db.get("job_context", (file, "*"))
    return ctx if isinstance(ctx, JobContextFact) else None
