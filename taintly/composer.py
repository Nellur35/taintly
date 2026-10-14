"""Finding-as-EDB composer — the CHAIN concept.

This module wires the fixed-point engine to consume scan-time
findings as facts, then derive composite findings when
combinations indicate a higher-severity threat.

Architecture:

1. Per-file scan + corpus pass run first (engine.py owns those).
2. Their findings are pushed into a fresh :class:`Database` as
   :class:`FindingFact` rows.
3. Context facts (:class:`JobContextFact`) are seeded from the
   workflow corpus — owning event guards and configured write-token state.
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

from bisect import bisect_right
from collections import OrderedDict
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass, field, replace
from hashlib import sha256
from itertools import pairwise
from typing import TYPE_CHECKING

from taintly.taint_facts.closure import solve
from taintly.taint_facts.relations import Database

if TYPE_CHECKING:
    from taintly.eventguard import GuardConstraints
    from taintly.models import CheckoutBuildWitness, Finding
    from taintly.parsers.segmentation import JobSegment
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
    # The source finding's snippet (e.g. TAINT-GH-001's rendered
    # source→hop→sink path). Payload only — ``compare=False`` keeps it
    # out of the Fact's identity so the datalog joins/dedup (which key on
    # ``fact_key``) are unaffected; composer rules can surface the path
    # on the upgraded finding so triage sees WHY it chained.
    snippet: str = field(default="", compare=False)
    shell_use: str = field(default="unknown", compare=False)
    """Conservative role aggregation of source-bound contributors at this key."""

    def fact_key(self):
        return (self.rule_id, self.file, self.job, self.line)

    def fact_rank(self):
        return (0,)  # findings are first-class; never displaced


@dataclass(frozen=True)
class CheckoutBuildFact:
    """A source-bound configured build path, separate from warning categories."""

    witness: CheckoutBuildWitness

    def fact_key(self):
        w = self.witness
        return (w.file, w.job, w.checkout_step, w.build_step, w.build_line)

    def fact_rank(self):
        return (0,)


@dataclass(frozen=True)
class JobContextFact:
    """Workflow context predicates a composer rule can join against.

    Derived from the corpus, NOT from findings. Keyed by (file, job)
    so composer rules can index it by the join column of choice.

    Predicates:

    * ``fork_reachable``: any trigger in the workflow is in
      ``TriggerFamily.FORK_REACHABLE``.
    * ``external_privileged``: the workflow has an externally-triggerable
      event whose token is not automatically downgraded to read-only like a
      fork-originated ``pull_request`` token.
    * ``has_write_token``: the job's effective permissions include
      any write-scope (or the workflow defaults to write because no
      explicit ``permissions:`` block exists at workflow or job
      level).
    * ``trusted_bot_gate``: compatibility field, always False. Actor identity
      is not proof that third-party code or event content is trustworthy.
    """

    file: str
    job: str
    fork_reachable: bool
    external_privileged: bool
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
    checkout_build: CheckoutBuildWitness | None = field(default=None, compare=False)

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
# EDB seeding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _JobIndex:
    """Immutable job ranges, retained only for one composer invocation."""

    segments: tuple[JobSegment, ...]
    starts: tuple[int, ...]
    source_sha256: str = ""
    content: str = ""

    def at_line(self, line: int) -> str | None:
        if line <= 0:
            return None
        position = bisect_right(self.starts, line) - 1
        if position < 0:
            return None
        job = self.segments[position]
        return job.name if job.name and line <= job.end_line else None


def _script_witness_matches(content: str, witness: CheckoutBuildWitness) -> bool:
    """Reconstruct a typed script witness with the authority source parser."""

    if (
        witness.execution_kind != "script"
        or witness.script_path is None
        or witness.source_sha256 != sha256(content.encode("utf-8")).hexdigest()
    ):
        return False
    # Share the source parser and authority predicates with the producer. This
    # avoids a second expression/format parser drifting from the admitted path.
    from taintly.authority_context import _classify, _configured_build_path, _Index
    from taintly.models import Finding, Severity

    candidate = Finding(
        rule_id="LOTP-GH-006",
        severity=Severity.HIGH,
        title="",
        description="",
        file=witness.file,
        line=witness.build_line,
    )
    index = _Index(content)
    state, _ = _classify(index, candidate)
    if state != "evidenced":
        return False
    expected = _configured_build_path(index, candidate)
    return expected is not None and expected == witness


def _seed_findings(
    db: Database,
    prior_findings: Iterable[Finding],
    job_indexes: dict[str, _JobIndex],
) -> None:
    """Push prior findings into the database with conservative role aggregation.

    The composer derives job identity from the finding's source line when a
    rule has not set it explicitly. Findings outside a known job remain
    unscoped and cannot satisfy job-sensitive chains. Shell roles are accepted
    only from a same-source, same-line, same-owner validated witness.
    """
    from taintly.shell_use import ShellUse, ShellUseEvidence, validate_shell_use

    facts: dict[tuple, FindingFact] = {}
    roles: dict[tuple, list[ShellUse]] = {}
    representatives: dict[tuple, ShellUse] = {}
    role_priority = {ShellUse.DATA: 0, ShellUse.UNKNOWN: 1, ShellUse.CODE: 2}
    for f in prior_findings:
        if f.rule_id == "ENGINE-ERR":
            continue  # don't compose error-class findings into chains
        line = f.line or 0
        job = getattr(f, "job", None)
        if not job:
            index = job_indexes.get(f.file or "")
            job = index.at_line(line) if index is not None else None
        fact = FindingFact(
            rule_id=f.rule_id,
            file=f.file or "",
            job=job,
            line=line,
            severity_value=f.severity.value if f.severity else "info",
            snippet=getattr(f, "snippet", "") or "",
        )
        key = fact.fact_key()
        index = job_indexes.get(f.file or "")
        shell = getattr(f, "_shell_use", None)
        role = ShellUse.UNKNOWN
        if (
            f.rule_id
            in {
                "TAINT-GH-001",
                "TAINT-GH-002",
                "TAINT-GH-003",
                "TAINT-GH-004",
                "TAINT-GH-005",
                "TAINT-GH-009",
                "TAINT-GH-012",
                "TAINT-GH-017",
            }
            and f.origin == "file"
            and isinstance(shell, ShellUseEvidence)
            and index is not None
            and shell.source_sha256 == index.source_sha256
            and len(shell.owner_path) >= 2
            and shell.owner_path[:2] == ("jobs", job)
            and validate_shell_use(shell, index.content, f.file, line)
        ):
            role = shell.disposition
        if key not in facts or role_priority[role] > role_priority[representatives[key]]:
            facts[key] = fact
            representatives[key] = role
        roles.setdefault(key, []).append(role)

        # Preserve PUBLIC's existing checkout/build witness validation exactly.
        witness = getattr(f, "_checkout_build", None)
        if (
            witness is not None
            and f.rule_id in {"LOTP-GH-001", "LOTP-GH-003", "LOTP-GH-006"}
            and f.origin == "file"
            and index is not None
            and witness.file == f.file
            and witness.job == job
            and witness.source_sha256 == index.source_sha256
            and witness.build_line == line
            and index.at_line(line) == job
            and index.at_line(witness.checkout_line) == job
            and witness.checkout_line < line
            and witness.build_step == witness.checkout_step + 1
            and (
                _script_witness_matches(index.content, witness)
                if f.rule_id == "LOTP-GH-006"
                else witness.execution_kind == "build"
                and witness.script_path is None
                and witness.interpreter is None
            )
        ):
            db.add("checkout_build", CheckoutBuildFact(witness))

    for key, fact in facts.items():
        contributors = roles[key]
        aggregate = (
            ShellUse.CODE
            if ShellUse.CODE in contributors
            else ShellUse.UNKNOWN
            if ShellUse.UNKNOWN in contributors
            else ShellUse.DATA
        )
        db.add("finding", replace(fact, shell_use=aggregate.value))


def _flow_value_end(tokens, start: int, depth: int = 0) -> int | None:
    """Consume a complete flow value, rejecting trailing or dropped tokens."""
    from taintly.parsers.structural.tokenizer import TokenKind

    if start >= len(tokens) or depth > 64:
        return None
    kind = tokens[start].kind
    if kind in {TokenKind.SCALAR_PLAIN, TokenKind.SCALAR_QUOTED}:
        return start + 1
    mapping = kind is TokenKind.FLOW_OPEN_MAP
    if not mapping and kind is not TokenKind.FLOW_OPEN_SEQ:
        return None
    close = TokenKind.FLOW_CLOSE_MAP if mapping else TokenKind.FLOW_CLOSE_SEQ
    position = start + 1
    while position < len(tokens):
        if tokens[position].kind is close:
            return position + 1
        if mapping:
            if tokens[position].kind is not TokenKind.KEY:
                return None
            position += 1
            # A mapping key may have an implicit null value.
            if position < len(tokens) and tokens[position].kind in {close, TokenKind.FLOW_COMMA}:
                pass
            else:
                next_position = _flow_value_end(tokens, position, depth + 1)
                if next_position is None:
                    return None
                position = next_position
        else:
            next_position = _flow_value_end(tokens, position, depth + 1)
            if next_position is None:
                return None
            position = next_position
        if position >= len(tokens):
            return None
        if tokens[position].kind is close:
            return position + 1
        if tokens[position].kind is not TokenKind.FLOW_COMMA:
            return None
        position += 1
    return None


def _certified_composer_events(content: str) -> frozenset[str] | None:
    """Return complete supported declarations; malformed/opaque YAML is unknown.

    Token-shape checks follow LOTP's conservative trigger certificate, extended
    to retain event names rather than certify only head_ref unavailability.
    This does not validate GitHub's complete event-filter configuration.
    """
    import re

    from taintly.parsers.structural import EventKind, walk_workflow
    from taintly.parsers.structural.tokenizer import TokenizerError, TokenKind, tokenize

    if re.search(r"(?m)^(?:---|\.\.\.)(?:\s|$)", content):
        return None  # The structural reader skips document boundaries.
    events = list(
        walk_workflow("composer-events.yml", content=content, include_keys=True, recover=True)
    )
    if any(event.kind in {EventKind.ERROR, EventKind.CUTOFF} for event in events):
        return None
    declarations = [
        event for event in events if event.kind is EventKind.MAP_KEY and event.path == ("on",)
    ]
    if len(declarations) != 1:
        return None
    try:
        tokens = list(tokenize(content))
    except TokenizerError:
        return None
    brackets: list[TokenKind] = []
    for token in tokens:
        if token.kind in {TokenKind.ANCHOR, TokenKind.ALIAS, TokenKind.MERGE_KEY}:
            return None
        if token.kind in {TokenKind.FLOW_OPEN_SEQ, TokenKind.FLOW_OPEN_MAP}:
            brackets.append(token.kind)
        elif token.kind in {TokenKind.FLOW_CLOSE_SEQ, TokenKind.FLOW_CLOSE_MAP}:
            expected = (
                TokenKind.FLOW_OPEN_SEQ
                if token.kind is TokenKind.FLOW_CLOSE_SEQ
                else TokenKind.FLOW_OPEN_MAP
            )
            if not brackets or brackets.pop() is not expected:
                return None
    if brackets:
        return None

    # Empty collection members disappear from the leaf stream. Certifying a
    # trigger list therefore needs its complete token shape, not just leaves.
    declaration = declarations[0]
    starts = [
        index
        for index, token in enumerate(tokens)
        if token.kind is TokenKind.KEY
        and token.value == "on"
        and token.line == declaration.line
        and token.column == declaration.column
    ]
    if len(starts) != 1 or declaration.column != 1:
        return None
    start = starts[0] + 1
    end = next(
        (
            index
            for index in range(start, len(tokens))
            if tokens[index].kind is TokenKind.KEY
            and tokens[index].column == 1
            and tokens[index].line > declaration.line
        ),
        len(tokens),
    )
    value_tokens = [
        token
        for token in tokens[start:end]
        if token.kind not in {TokenKind.INDENT, TokenKind.COMMENT, TokenKind.EOF}
    ]
    scalar_kinds = {TokenKind.SCALAR_PLAIN, TokenKind.SCALAR_QUOTED}
    if not value_tokens:
        return None
    if value_tokens[0].kind is TokenKind.FLOW_OPEN_MAP:
        if _flow_value_end(value_tokens, 0) != len(value_tokens):
            return None
    if value_tokens[0].kind is TokenKind.FLOW_OPEN_SEQ:
        if value_tokens[-1].kind is not TokenKind.FLOW_CLOSE_SEQ:
            return None
        expect_scalar = True
        for token in value_tokens[1:-1]:
            if expect_scalar:
                if token.kind not in scalar_kinds:
                    return None
            elif token.kind is not TokenKind.FLOW_COMMA:
                return None
            expect_scalar = not expect_scalar
    elif value_tokens[0].kind is TokenKind.SEQUENCE_DASH:
        if len(value_tokens) % 2:
            return None
        for dash, scalar in zip(value_tokens[::2], value_tokens[1::2], strict=True):
            if (
                dash.kind is not TokenKind.SEQUENCE_DASH
                or scalar.kind not in scalar_kinds
                or dash.line != scalar.line
            ):
                return None

    on_events = [event for event in events if event.path and event.path[0] == "on"]
    keys = [event.path for event in on_events if event.kind is EventKind.MAP_KEY]
    if len(keys) != len(set(keys)):
        return None
    bare = [
        event
        for event in on_events
        if event.kind is EventKind.LEAF_SCALAR and event.path == ("on",)
    ]
    items = [event for event in on_events if len(event.path) > 1 and isinstance(event.path[1], int)]
    mapping = [
        event for event in on_events if len(event.path) > 1 and isinstance(event.path[1], str)
    ]
    if sum(bool(shape) for shape in (bare, items, mapping)) != 1:
        return None
    if bare:
        if len(bare) != 1 or bare[0].value_kind not in {"plain", "quoted"}:
            return None
        if len(value_tokens) != 1 or value_tokens[0].kind not in scalar_kinds:
            return None  # Do not certify a scalar followed by dropped child content.
        names = {bare[0].value}
    elif items:
        if any(
            len(event.path) != 2
            or event.kind is not EventKind.LEAF_SCALAR
            or event.value_kind not in {"plain", "quoted"}
            for event in items
        ):
            return None
        names = {event.value for event in items}
    else:
        if value_tokens[0].kind not in {TokenKind.KEY, TokenKind.FLOW_OPEN_MAP}:
            return None
        # Block-map peers begin with keys. Consume flow subvalues completely
        # so a dropped sibling container cannot certify event completeness.
        if value_tokens[0].kind is TokenKind.KEY:
            peer_indent = value_tokens[0].indent
            # Root peers are block keys at this indent, never keys inside a
            # flow value. Check each complete value before advancing a peer.
            peers = [0]
            depth = 0
            for position, token in enumerate(value_tokens):
                if token.kind in {TokenKind.FLOW_OPEN_MAP, TokenKind.FLOW_OPEN_SEQ}:
                    depth += 1
                elif token.kind in {TokenKind.FLOW_CLOSE_MAP, TokenKind.FLOW_CLOSE_SEQ}:
                    depth -= 1
                elif position and depth == 0 and token.kind is TokenKind.KEY:
                    if token.indent == peer_indent:
                        peers.append(position)
            peers.append(len(value_tokens))
            for start, end in pairwise(peers):
                span = value_tokens[start + 1 : end]
                if not span:
                    continue  # Empty event configuration is supported.
                if span[0].line > value_tokens[start].line and span[0].indent <= peer_indent:
                    return None  # A peer-indented anonymous value is not a child.
                if span[0].kind in {
                    TokenKind.FLOW_OPEN_MAP,
                    TokenKind.FLOW_OPEN_SEQ,
                    TokenKind.SCALAR_PLAIN,
                    TokenKind.SCALAR_QUOTED,
                }:
                    if _flow_value_end(span, 0) != len(span):
                        return None
                elif span[0].kind is not TokenKind.KEY or any(
                    token.indent <= peer_indent for token in span
                ):
                    return None
        if any(
            len(event.path) == 2
            and event.kind is EventKind.LEAF_SCALAR
            and (event.value_kind != "plain" or event.value not in {"null", "~", ""})
            for event in mapping
        ):
            return None
        for event in mapping:
            if len(event.path) != 2 or event.kind is not EventKind.MAP_KEY:
                continue
            position = next(
                (
                    index
                    for index, token in enumerate(tokens)
                    if token.kind is TokenKind.KEY
                    and token.line == event.line
                    and token.column == event.column
                ),
                None,
            )
            if position is None:
                return None
            following = next(
                (
                    token
                    for token in tokens[position + 1 :]
                    if token.kind not in {TokenKind.INDENT, TokenKind.COMMENT}
                ),
                None,
            )
            if following is not None and following.kind in {
                TokenKind.FLOW_OPEN_SEQ,
                TokenKind.SEQUENCE_DASH,
                TokenKind.SCALAR_BLOCK_HEADER,
            }:
                return None
        names = {
            str(event.path[1])
            for event in mapping
            if len(event.path) == 2 and event.kind is EventKind.MAP_KEY
        }
    known = {
        "branch_protection_rule",
        "check_run",
        "check_suite",
        "create",
        "delete",
        "deployment",
        "deployment_status",
        "discussion",
        "discussion_comment",
        "fork",
        "gollum",
        "issue_comment",
        "issues",
        "label",
        "merge_group",
        "milestone",
        "page_build",
        "public",
        "pull_request",
        "pull_request_comment",
        "pull_request_review",
        "pull_request_review_comment",
        "pull_request_target",
        "push",
        "registry_package",
        "release",
        "repository_dispatch",
        "schedule",
        "status",
        "watch",
        "workflow_dispatch",
        "workflow_run",
    }
    # workflow_call inherits a caller's event; an unknown/new event cannot
    # establish a complete external-trigger exclusion.
    return frozenset(names) if names and names <= known else None


@dataclass(frozen=True)
class ExecutionContextFact:
    """Immutable per-invocation guards and ownership, never actor trust."""

    file: str
    events: frozenset[str] | None
    privileged_events: frozenset[str] | None
    keys: frozenset[tuple[object, ...]]
    guards: tuple[tuple[tuple[object, ...], str | None], ...]
    owners: tuple[tuple[int, tuple[object, ...]], ...]

    def fact_key(self):
        return (self.file,)

    def fact_rank(self):
        return (0,)


@dataclass(frozen=True)
class _ExecutionStructure:
    """Immutable facts extracted from workflow bytes, with no file identity."""

    events: frozenset[str] | None
    keys: frozenset[tuple[object, ...]]
    guards: tuple[tuple[tuple[object, ...], str | None], ...]
    owners: tuple[tuple[int, tuple[object, ...]], ...]


@dataclass
class _ExecutionStructureCache:
    """Small, composer-pass-local cache for content-only extraction."""

    helper_identity: tuple[object, ...]
    entries: OrderedDict[str, _ExecutionStructure] = field(default_factory=OrderedDict)


_EXECUTION_STRUCTURE_CACHE: ContextVar[_ExecutionStructureCache | None] = ContextVar(
    "taintly_composer_execution_structure_cache", default=None
)
_EXECUTION_STRUCTURE_CACHE_LIMIT = 8
_EXECUTION_STRUCTURE_MAX_CONTENT_CHARS = 65_536


def _execution_structure_helpers() -> tuple[object, ...]:
    from taintly.agentguards import AgentGuardIndex

    return (AgentGuardIndex, _certified_composer_events, _certified_guards)


@contextmanager
def composer_execution_structure_cache() -> Iterator[None]:
    """Reuse immutable execution structure only within one composer engine pass.

    Nested passes receive an independent cache; ContextVar tokens restore the
    outer pass even when a callback raises. Standalone composer calls remain
    uncached unless the engine explicitly establishes this scope.
    """
    cache = _ExecutionStructureCache(_execution_structure_helpers())
    token: Token[_ExecutionStructureCache | None] = _EXECUTION_STRUCTURE_CACHE.set(cache)
    try:
        yield
    finally:
        _EXECUTION_STRUCTURE_CACHE.reset(token)


def _build_execution_structure(content: str) -> _ExecutionStructure:
    from taintly.agentguards import AgentGuardIndex

    index = AgentGuardIndex(content)
    events = _certified_composer_events(content) if index.valid else None
    return _ExecutionStructure(
        events=events,
        keys=frozenset(index.keys),
        guards=_certified_guards(content, index),
        owners=tuple(
            (line, owner) for line in index.owners if (owner := index.owner(line)) is not None
        ),
    )


def _execution_structure(content: str) -> _ExecutionStructure:
    if len(content) > _EXECUTION_STRUCTURE_MAX_CONTENT_CHARS:
        return _build_execution_structure(content)
    cache = _EXECUTION_STRUCTURE_CACHE.get()
    if cache is None:
        return _build_execution_structure(content)
    helpers = _execution_structure_helpers()
    if helpers != cache.helper_identity:
        # A callback may replace extraction helpers while a pass is active.
        # Use the current implementation without consulting or populating the
        # cache, so an earlier result cannot cross that boundary.
        return _build_execution_structure(content)
    structure = cache.entries.get(content)
    if structure is not None:
        cache.entries.move_to_end(content)
        return structure
    structure = _build_execution_structure(content)
    if _execution_structure_helpers() == helpers:
        cache.entries[content] = structure
        cache.entries.move_to_end(content)
        while len(cache.entries) > _EXECUTION_STRUCTURE_CACHE_LIMIT:
            cache.entries.popitem(last=False)
    return structure


def execution_events_for(
    db: Database,
    file: str,
    job: str | None,
    line: int | None = None,
    *,
    privileged: bool = False,
) -> frozenset[str] | None:
    """Possible events for an actual owner; None cannot justify pruning.

    A named actor does not establish integrity of the bytes used by that actor.
    Only an owning guard proven false for an event can remove that event.
    """
    constraints = execution_constraints_for(db, file, job, line, privileged=privileged)
    return None if constraints is None else frozenset(constraints)


def execution_constraints_for(
    db: Database,
    file: str,
    job: str | None,
    line: int | None = None,
    *,
    privileged: bool = False,
) -> dict[str, GuardConstraints] | None:
    """Retain same-invocation ref correlations until a path has been joined.

    Missing/opaque ownership remains unknown. These constraints are local to
    this file invocation and must never be joined across callers or runs.
    """
    from taintly.eventguard import event_guard_verdict, guard_constraints

    fact = db.get("execution_context", (file,))
    if not isinstance(fact, ExecutionContextFact) or not job:
        return None
    events = fact.privileged_events if privileged else fact.events
    if events is None or ("jobs", job) not in fact.keys:
        return None
    scopes = [("jobs", job)]
    if line is not None:
        owner = dict(fact.owners).get(line)
        if owner is None or owner[:2] != ("jobs", job):
            return None
        scopes.append(owner)
    guards = dict(fact.guards)
    conditions = []
    for scope in scopes:
        path = scope + ("if",)
        if path in fact.keys and path not in guards:
            return None  # A collection-valued if is not a missing guard.
        conditions.append(guards.get(path))
    return {
        event: domain
        for event in events
        if not any(event_guard_verdict(guard, event) is False for guard in conditions)
        if (domain := guard_constraints(conditions, event))
    }


def _certified_guards(content: str, index) -> tuple:
    """Keep scalar guards only when the entire value span is represented."""
    from taintly.parsers.structural.tokenizer import TokenizerError, TokenKind, tokenize

    try:
        tokens = [
            token
            for token in tokenize(content)
            if token.kind not in {TokenKind.INDENT, TokenKind.COMMENT, TokenKind.EOF}
        ]
    except TokenizerError:
        return ()
    guards = []
    for path, value in index.values.items():
        if path[-1:] != ("if",) or value is None:
            continue
        starts = [
            position
            for position, token in enumerate(tokens)
            if token.kind is TokenKind.KEY
            and token.value == "if"
            and token.line == index.keys.get(path)
        ]
        if len(starts) != 1:
            continue
        start = starts[0]
        key = tokens[start]
        end = next(
            (
                position
                for position in range(start + 1, len(tokens))
                if tokens[position].line > key.line
                and (
                    (
                        tokens[position].kind is TokenKind.KEY
                        and tokens[position].indent <= key.column - 1
                    )
                    or (
                        tokens[position].kind is TokenKind.SEQUENCE_DASH
                        and tokens[position].indent <= key.indent
                    )
                )
            ),
            len(tokens),
        )
        span = tokens[start + 1 : end]
        scalar = len(span) == 1 and span[0].kind in {
            TokenKind.SCALAR_PLAIN,
            TokenKind.SCALAR_QUOTED,
        }
        block = (
            bool(span)
            and span[0].kind is TokenKind.SCALAR_BLOCK_HEADER
            and all(token.kind is TokenKind.SCALAR_BLOCK_LINE for token in span[1:])
        )
        if scalar or block:
            guards.append((path, value))
    return tuple(guards)


def _seed_execution_contexts(db: Database, corpus: WorkflowCorpus) -> None:
    from taintly.workflow_corpus import _EXTERNAL_PRIVILEGED_EVENTS, _FORK_REACHABLE_EVENTS

    for workflow in corpus.all():
        structure = _execution_structure(workflow.content)
        names = structure.events
        events = None if names is None else names & _FORK_REACHABLE_EVENTS
        privileged = None if names is None else names & _EXTERNAL_PRIVILEGED_EVENTS
        if events is not None and "workflow_run" in events:
            if corpus.workflow_run_parent_fork_reachable(workflow) is False:
                events = events - {"workflow_run"}
                privileged = privileged - {"workflow_run"}
        db.add(
            "execution_context",
            ExecutionContextFact(
                workflow.filepath,
                events,
                privileged,
                structure.keys,
                structure.guards,
                structure.owners,
            ),
        )


def _seed_job_contexts(
    db: Database, corpus: WorkflowCorpus, job_indexes: dict[str, _JobIndex]
) -> None:
    """Walk the corpus and assert one JobContextFact per (file, job).

    Workflow-level permissions and triggers cascade to every job in
    the file. Job-level permissions override the workflow default
    when present.

    Complete owning-job event proofs narrow trigger candidates. Unknown
    structure retains the legacy candidate; actor names confer no integrity.
    """
    from taintly.workflow_corpus import TriggerFamily

    for wf in corpus.all():
        fork = TriggerFamily.FORK_REACHABLE in wf.triggers
        external_privileged = corpus.has_external_privileged_trigger(wf)
        wf_write = _permission_block_has_write(wf.workflow_permissions)
        # Workflow's default GITHUB_TOKEN is write-capable when there is
        # no explicit `permissions:` block at all. (GitHub's default
        # changed in 2023 to read-only for new orgs but old orgs and
        # repos still default to write; the rule's threat model treats
        # absence as write-capable.)
        wf_default_write = wf.workflow_permissions is None

        job_permissions = {
            block.scope_what: block
            for block in wf.job_permissions
            if block.scope_what and block.scope_what != "workflow"
        }

        # Every segmented job receives its effective permission context.
        for job in job_indexes[wf.filepath].segments:
            if not job.name:
                continue
            jb = job_permissions.get(job.name)
            job_name = job.name
            db.add(
                "job_context",
                JobContextFact(
                    file=wf.filepath,
                    job=job_name,
                    fork_reachable=fork,
                    external_privileged=external_privileged,
                    has_write_token=(
                        _permission_block_has_write(jb)
                        if jb is not None
                        else wf_write or wf_default_write
                    ),
                    trusted_bot_gate=False,
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
                external_privileged=external_privileged,
                has_write_token=wf_write or wf_default_write,
                trusted_bot_gate=False,
            ),
        )


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
    from taintly.parsers.segmentation import for_each_job

    # Job ranges are identical for finding attribution and context seeding.
    # Keep this index local: a later invocation may see changed source content.
    prior_findings = tuple(prior_findings)
    witnessed_files = {
        f.file
        for f in prior_findings
        if getattr(f, "_checkout_build", None) is not None
        or getattr(f, "_shell_use", None) is not None
    }
    job_indexes = {}
    for workflow in corpus.all():
        segments = tuple(for_each_job(workflow.content))
        job_indexes[workflow.filepath] = _JobIndex(
            segments,
            tuple(job.start_line for job in segments),
            sha256(workflow.content.encode("utf-8")).hexdigest()
            if workflow.filepath in witnessed_files
            else "",
            workflow.content if workflow.filepath in witnessed_files else "",
        )
    db = Database()
    _seed_execution_contexts(db, corpus)
    _seed_findings(db, prior_findings, job_indexes)
    _seed_job_contexts(db, corpus, job_indexes)
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
