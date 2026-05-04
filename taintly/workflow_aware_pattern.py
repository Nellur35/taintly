"""WorkflowAwarePattern — StructuralPattern with workflow-scope context.

A ``WorkflowAwarePattern`` extends ``StructuralPattern``'s per-leaf
predicate signature with a ``PredicateContext`` argument that carries
the workflow's full structural state.  Use when a rule needs to reason
about cross-node state — sibling values, sink-key classification, or
descendant search — that ``StructuralPattern``'s ``(value, value_kind,
path)`` signature can't observe.

Three concrete tunes drove the introduction (Phase 8 iteration 2,
2026-05-04):

  * SEC6-GH-010 — needs the parent step's ``uses:`` value to look up
    the action name and apply a ``(action_name, input_slot)`` safe-
    consumer allowlist.
  * TAINT-GH-006 — needs to classify the sink-kind from the leaf's
    own path (shell sink vs identifier sink).
  * SEC4-GH-005 (deferred to a later iteration) — needs to scan
    subsequent steps in the same job for ``git push`` / ``git config``.

Phase contract is the same as ``StructuralPattern``:

  * Conforms to ``PatternProtocol.check(content, lines) ->
    list[(line, snippet)]`` so existing engine code dispatches it
    without changes.
  * One walk per file, regardless of how many path globs the rule
    declares.  All leaves are collected into the predicate context
    on the first pass; the second pass iterates query-matched leaves
    and runs the predicate.
  * CUTOFF events emit the same ``STRUCTURAL-CUTOFF:`` sentinel as
    ``StructuralPattern`` so the engine's coverage-warning path
    reports degraded structural reads consistently.
"""

from __future__ import annotations

import contextvars
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .parsers.structural import Event, EventKind, walk_workflow

# ---------------------------------------------------------------------------
# Per-scan filepath context — populated by the engine before invoking
# ``rule.pattern.check()`` so WorkflowAwarePattern predicates can
# resolve sibling workflow files (caller-graph for TAINT-GH-007),
# repo-root walks (file-presence rules), and similar cross-file
# context.
#
# Other pattern types ignore this; using a contextvar avoids
# changing the cross-pattern ``PatternProtocol.check`` signature
# (every pattern type and dozens of test call sites would otherwise
# need updating).
# ---------------------------------------------------------------------------

_current_filepath: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "taintly_pattern_filepath", default=None
)


@contextmanager
def set_pattern_filepath_context(filepath: Optional[str]):
    """Bind ``filepath`` for the duration of this with-block so any
    ``WorkflowAwarePattern`` predicate dispatched inside the block
    can read it via :attr:`PredicateContext.filepath`.

    Used by the engine to thread the current file's path down through
    ``rule.pattern.check()`` without changing the cross-pattern
    protocol.  Outside an active block, ``PredicateContext.filepath``
    is ``None`` — predicates that need filepath must defend that.
    """
    token = _current_filepath.set(filepath)
    try:
        yield
    finally:
        _current_filepath.reset(token)


@dataclass
class PredicateContext:
    """Read-only workflow structural state, lazily indexed.

    Built once per ``WorkflowAwarePattern.check()`` call from the
    workflow's full ``LEAF_SCALAR`` event stream.  The context is
    immutable once constructed; helper methods build derived
    indices on demand and cache them on the instance.
    """

    leaves: tuple[Event, ...]
    filepath: Optional[str] = None
    """Absolute or relative path of the file being scanned, populated
    by :func:`set_pattern_filepath_context` during the engine's per-
    file pass.  ``None`` when the pattern is invoked outside an
    engine scan (self-test samples, unit tests).  Predicates that
    rely on this MUST defend the ``None`` case."""

    _by_path_cache: dict[tuple[object, ...], Event] = field(
        default_factory=dict, init=False, repr=False
    )
    _is_reusable: Optional[bool] = field(default=None, init=False, repr=False)
    _caller_graph_cache: Optional[tuple[CallerInfo, ...]] = field(
        default=None, init=False, repr=False
    )

    # ------------------------------------------------------------------
    # Direct lookups
    # ------------------------------------------------------------------

    def get_leaf(self, target_path: tuple[object, ...]) -> Optional[Event]:
        """Return the leaf event at ``target_path``, or None if absent."""
        if not self._by_path_cache and self.leaves:
            for ev in self.leaves:
                self._by_path_cache.setdefault(ev.path, ev)
        return self._by_path_cache.get(target_path)

    def get_value(self, target_path: tuple[object, ...]) -> Optional[str]:
        """Return the scalar value at ``target_path``, or None if absent."""
        ev = self.get_leaf(target_path)
        return ev.value if ev else None

    # ------------------------------------------------------------------
    # Structural relations
    # ------------------------------------------------------------------

    def siblings(self, path: tuple[object, ...]) -> Iterator[Event]:
        """Yield leaves whose immediate parent matches ``path``'s parent.

        The leaf at ``path`` itself is excluded.  Useful for
        "look at peer keys under the same mapping" predicates.
        """
        if not path:
            return
        parent = path[:-1]
        for ev in self.leaves:
            if ev.path != path and ev.path[:-1] == parent:
                yield ev

    def descendants(self, prefix: tuple[object, ...]) -> Iterator[Event]:
        """Yield leaves whose path strictly extends ``prefix``."""
        n = len(prefix)
        if n == 0:
            yield from self.leaves
            return
        for ev in self.leaves:
            if len(ev.path) > n and ev.path[:n] == prefix:
                yield ev

    # ------------------------------------------------------------------
    # GitHub-Actions step helpers
    # ------------------------------------------------------------------

    def step_index(self, path: tuple[object, ...]) -> Optional[tuple[str, int]]:
        """Return ``(job_id, step_idx)`` if ``path`` is inside a step.

        ``path`` is considered "inside a step" when its prefix is
        ``("jobs", <job-id-string>, "steps", <step-idx-int>)``.
        Returns ``None`` for non-step paths (top-level keys, on-block
        leaves, GitLab CI paths, Jenkins paths, etc.).
        """
        if (
            len(path) >= 4
            and path[0] == "jobs"
            and isinstance(path[1], str)
            and path[2] == "steps"
            and isinstance(path[3], int)
        ):
            return (path[1], path[3])
        return None

    def step_uses(self, path: tuple[object, ...]) -> Optional[str]:
        """Return the ``uses:`` value of the step containing ``path``.

        ``None`` if ``path`` is not inside a step or the step has no
        ``uses:`` key (script step).
        """
        loc = self.step_index(path)
        if loc is None:
            return None
        job_id, step_i = loc
        return self.get_value(("jobs", job_id, "steps", step_i, "uses"))

    def steps_after(self, path: tuple[object, ...]) -> Iterator[Event]:
        """Yield leaves in the same job's steps with a higher step index."""
        loc = self.step_index(path)
        if loc is None:
            return
        job_id, step_i = loc
        for ev in self.leaves:
            ep = ev.path
            if (
                len(ep) >= 5
                and ep[0] == "jobs"
                and ep[1] == job_id
                and ep[2] == "steps"
                and isinstance(ep[3], int)
                and ep[3] > step_i
            ):
                yield ev

    # ------------------------------------------------------------------
    # File-shape helpers
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Caller-graph helpers — Phase 8 iter-4 (2026-05-04).
    #
    # Used by TAINT-GH-007 to suppress TAINT-GH-006 fires when every
    # in-repo caller of THIS reusable workflow passes literal /
    # matrix-literal values to the input (no attacker reachability).
    # Sample-and-label of TAINT-GH-006's 21 corpus fires found 19/21
    # FP because of this exact shape (matrix-driven build/test fan-
    # out into a callee that takes inputs).
    # ------------------------------------------------------------------

    def find_callers_of_self(self) -> tuple[CallerInfo, ...]:
        """Return CallerInfo for every workflow file in the same
        ``.github/workflows/`` directory that invokes the current
        file via ``uses: ./.github/workflows/<self>.yml`` (or any
        other ``uses:`` reference whose suffix matches the current
        filename).

        Empty tuple when:

        * ``self.filepath`` is ``None`` (no engine context — unit
          tests / self-test samples).
        * ``self.filepath``'s parent directory has no other YAML
          workflow files.
        * No file in the parent directory references the current
          file via ``uses:``.

        Result is cached on the predicate context for the lifetime
        of one ``check()`` call so a rule that calls this in its
        per-leaf predicate doesn't re-walk the directory on every
        leaf.
        """
        if self._caller_graph_cache is not None:
            return self._caller_graph_cache
        if not self.filepath:
            self._caller_graph_cache = ()
            return ()
        callers: list[CallerInfo] = []
        try:
            self_path = Path(self.filepath).resolve()
            self_name = self_path.name
            wf_dir = self_path.parent
        except (OSError, ValueError):
            self._caller_graph_cache = ()
            return ()
        if not wf_dir.exists():
            self._caller_graph_cache = ()
            return ()
        for sibling in sorted(wf_dir.iterdir()):
            if not sibling.is_file():
                continue
            if sibling.suffix not in (".yml", ".yaml"):
                continue
            if sibling.resolve() == self_path:
                continue
            try:
                content = sibling.read_text(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                continue
            callers.extend(_parse_callers(content, self_name, str(sibling)))
        self._caller_graph_cache = tuple(callers)
        return self._caller_graph_cache

    def is_reusable_workflow(self) -> bool:
        """True if the file is a GitHub Actions reusable workflow.

        Detects the three legal shapes of ``on: workflow_call``:

        * bare string  — ``on: workflow_call`` →
          leaf path == ``("on",)``, value == ``"workflow_call"``
        * block form   — ``on:\\n  workflow_call:`` →
          a leaf at ``("on", "workflow_call", ...)``
        * list form    — ``on: [workflow_call, push]`` →
          a leaf at ``("on", <int>)``, value == ``"workflow_call"``

        The result is cached on the context for the lifetime of the
        scan.
        """
        if self._is_reusable is not None:
            return self._is_reusable
        result = False
        for ev in self.leaves:
            path = ev.path
            if path == ("on",) and ev.value == "workflow_call":
                result = True
                break
            if len(path) >= 2 and path[0] == "on" and path[1] == "workflow_call":
                result = True
                break
            if (
                len(path) == 2
                and path[0] == "on"
                and isinstance(path[1], int)
                and ev.value == "workflow_call"
            ):
                result = True
                break
        self._is_reusable = result
        return result


PredicateFn = Callable[[str, str, tuple[object, ...], PredicateContext], bool]


@dataclass(frozen=True)
class CallerInfo:
    """Parsed information about a workflow file that invokes another
    reusable workflow.

    Returned by :meth:`PredicateContext.find_callers_of_self`.  The
    fields are minimal — only what TAINT-GH-007 needs to decide
    whether a callee's ``inputs.X`` reference can be reached by
    attacker bytes.
    """

    caller_path: str
    """Absolute path to the calling workflow file."""

    triggers: tuple[str, ...]
    """Trigger event names declared on the caller (``on:``)."""

    with_map: dict[str, str]
    """Map of input-name → caller's ``with:`` value, as a literal
    string.  Multi-line / structured values are flattened to their
    raw text representation for predicate inspection."""

    def passes_only_literals(self) -> bool:
        """True when every value in ``with_map`` looks like a
        trusted-literal — no attacker-reachable context references.

        Heuristic: a value is *trusted* if it does NOT contain any of
        ``github.event.*``, ``github.head_ref``, ``github.actor``,
        or ``${{ inputs.* }}`` (forwarding-from-own-inputs case).
        Matrix literals (``${{ matrix.X }}``) are trusted because
        the matrix is workflow-author-controlled.
        """
        if not self.with_map:
            return True
        for value in self.with_map.values():
            if _ATTACKER_REACHABLE_CONTEXT_RE.search(value):
                return False
        return True


# Attacker-reachable expression shapes inside a caller's ``with:``
# value.  If ANY of these appear in any forwarded value, the caller
# can plausibly transport attacker bytes into the callee's
# ``inputs.X`` namespace, so TAINT-GH-006 should NOT be suppressed.
_ATTACKER_REACHABLE_CONTEXT_RE = re.compile(
    r"\$\{\{\s*github\.(?:"
    r"event\.(?:issue|pull_request|comment|review|head_commit|"
    r"discussion|workflow_run|push|release)\.|"
    r"head_ref|"
    r"event\.inputs\."
    r")"
    r"|\$\{\{\s*inputs\."
)


def _parse_callers(content: str, callee_name: str, caller_path: str) -> list[CallerInfo]:
    """Extract CallerInfo objects from a workflow file's text.

    Walks the workflow with the structural reader, looking for
    ``jobs.<job>.uses`` leaves whose value ends in ``/<callee_name>``
    (or is ``./.github/workflows/<callee_name>``).  For each caller
    job, collects the corresponding ``jobs.<job>.with.*`` map and
    the file's ``on:`` triggers.

    Errors during parsing yield no callers — the rule should fall
    back to firing (conservative) rather than silently suppressing.
    """
    try:
        leaves = [
            ev
            for ev in walk_workflow(caller_path, content=content, recover=True)
            if ev.kind == EventKind.LEAF_SCALAR
        ]
    except Exception:
        return []

    # Triggers: any leaf whose path starts with ('on',).  Collect both
    # the bare-string form (path == ('on',), value is the event name)
    # and the block-form (path[1] is the event name, ignore values).
    triggers: list[str] = []
    for ev in leaves:
        if not ev.path or ev.path[0] != "on":
            continue
        if ev.path == ("on",) and ev.value:
            triggers.append(ev.value)
        elif len(ev.path) >= 2 and isinstance(ev.path[1], str):
            triggers.append(ev.path[1])
        elif len(ev.path) == 2 and isinstance(ev.path[1], int) and ev.value:
            triggers.append(ev.value)

    # Group leaves by job for ``jobs.<job>.uses`` + ``jobs.<job>.with.*``
    # pairing.  Reusable-workflow callers use the JOB-level form
    # (``jobs: build: uses: ./.../x.yml`` + ``jobs: build: with: ...``);
    # a step-level uses (``jobs.<j>.steps[*].uses``) is an action call,
    # not a reusable-workflow call.
    job_uses: dict[str, str] = {}
    job_with: dict[str, dict[str, str]] = {}
    for ev in leaves:
        path = ev.path
        if (
            len(path) == 3
            and path[0] == "jobs"
            and isinstance(path[1], str)
            and path[2] == "uses"
            and ev.value
        ):
            job_uses[path[1]] = ev.value
        elif (
            len(path) >= 4
            and path[0] == "jobs"
            and isinstance(path[1], str)
            and path[2] == "with"
            and isinstance(path[3], str)
            and ev.value is not None
        ):
            job_with.setdefault(path[1], {})[path[3]] = ev.value

    callers: list[CallerInfo] = []
    unique_triggers = tuple(sorted(set(triggers)))
    for job_id, uses_value in job_uses.items():
        # Match callee_name as the trailing path segment of the uses
        # reference.  Both ``./.github/workflows/<name>``,
        # ``./<name>``, and cross-repo
        # ``<org>/<repo>/.github/workflows/<name>@<ref>`` resolve.
        head = uses_value.split("@", 1)[0].strip()
        if not (head.endswith("/" + callee_name) or head == callee_name):
            continue
        callers.append(
            CallerInfo(
                caller_path=caller_path,
                triggers=unique_triggers,
                with_map=dict(job_with.get(job_id, {})),
            )
        )
    return callers


@dataclass
class WorkflowAwarePattern:
    """Pattern that queries a path glob and applies a context-aware
    predicate to each matching leaf.

    Args:
        path: a single path glob, or a list of globs.  When a list
            is given, leaves matching ANY of the globs are
            considered.  Same shape semantics as
            :class:`taintly.structural_pattern.StructuralPattern`.
        predicate: ``predicate(value, value_kind, full_path, ctx) ->
            bool``.  Truthy result fires a finding at the leaf's
            line.  ``ctx`` is a :class:`PredicateContext` carrying
            the workflow's full LEAF_SCALAR set.
        snippet_format: optional ``str.format``-style template that
            produces the finding's snippet.  Defaults to the stripped
            source line.  Available placeholders: ``{value}``,
            ``{value_kind}``, ``{path}``, ``{line}``.
    """

    path: str | list[str]
    predicate: PredicateFn
    snippet_format: Optional[str] = None
    _schema_name: Optional[str] = field(default=None, init=False, repr=False)

    def _paths(self) -> list[str]:
        if isinstance(self.path, str):
            return [self.path]
        return list(self.path)

    # CONTRACT: returns (line_num, snippet) where line_num points at
    # the line whose textual content drove the predicate's truthy
    # result, and snippet is ``lines[line_num - 1].strip()`` (or the
    # ``snippet_format``-rendered string when provided).
    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        # Pass 1: collect every LEAF_SCALAR for the predicate context.
        all_leaves: list[Event] = []
        cutoff_seen = False
        cutoff_line = 0
        for ev in walk_workflow("anonymous.yml", content=content, recover=True):
            if ev.kind == EventKind.CUTOFF:
                cutoff_seen = True
                cutoff_line = ev.line
                break
            if ev.kind == EventKind.LEAF_SCALAR:
                all_leaves.append(ev)

        ctx = PredicateContext(
            leaves=tuple(all_leaves),
            filepath=_current_filepath.get(),
        )

        # Pass 2: per-glob query against the same content.  Walking
        # again with a query is cheap (single-pass tokenizer) and
        # keeps glob-matching logic inside the walker rather than
        # duplicating ``_path_match_recursive`` here.
        results: list[tuple[int, str]] = []
        seen: set[tuple[int, str]] = set()
        any_leaf_seen = bool(all_leaves)

        for path_glob in self._paths():
            for ev in walk_workflow(
                "anonymous.yml",
                query=path_glob,
                content=content,
                recover=True,
            ):
                if ev.kind == EventKind.CUTOFF:
                    # Already accounted for by pass 1's marker; skip
                    # to avoid emitting twice.
                    break
                if ev.kind != EventKind.LEAF_SCALAR:
                    continue
                value = ev.value or ""
                value_kind = ev.value_kind or "plain"

                if ev.block_lines:
                    for sub_line, sub_text in ev.block_lines:
                        try:
                            sub_hit = self.predicate(sub_text, value_kind, ev.path, ctx)
                        except Exception:
                            sub_hit = False
                        if not sub_hit:
                            continue
                        sub_snippet = self._render_snippet(
                            sub_text, value_kind, ev.path, sub_line, lines
                        )
                        key = (sub_line, sub_snippet)
                        if key in seen:
                            continue
                        seen.add(key)
                        results.append((sub_line, sub_snippet))
                    continue

                try:
                    hit = self.predicate(value, value_kind, ev.path, ctx)
                except Exception:
                    hit = False
                if hit:
                    snippet = self._render_snippet(value, value_kind, ev.path, ev.line, lines)
                    key = (ev.line, snippet)
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append((ev.line, snippet))

        if cutoff_seen and any_leaf_seen:
            cutoff_marker = (
                cutoff_line or 1,
                f"STRUCTURAL-CUTOFF: structural reader stopped at "
                f"line {cutoff_line} (unsupported YAML construct); "
                "rule cannot evaluate this file fully",
            )
            if cutoff_marker not in seen:
                results.append(cutoff_marker)
        return results

    def _render_snippet(
        self,
        value: str,
        value_kind: str,
        path: tuple[object, ...],
        line: int,
        lines: list[str],
    ) -> str:
        if self.snippet_format is not None:
            return self.snippet_format.format(
                value=value, value_kind=value_kind, path=path, line=line
            )
        if 0 < line <= len(lines):
            return lines[line - 1].strip()
        return value


__all__ = [
    "CallerInfo",
    "PredicateContext",
    "PredicateFn",
    "WorkflowAwarePattern",
    "set_pattern_filepath_context",
]
