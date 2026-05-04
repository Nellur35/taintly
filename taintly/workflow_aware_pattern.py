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

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Optional

from .parsers.structural import Event, EventKind, walk_workflow


@dataclass
class PredicateContext:
    """Read-only workflow structural state, lazily indexed.

    Built once per ``WorkflowAwarePattern.check()`` call from the
    workflow's full ``LEAF_SCALAR`` event stream.  The context is
    immutable once constructed; helper methods build derived
    indices on demand and cache them on the instance.
    """

    leaves: tuple[Event, ...]
    _by_path_cache: dict[tuple[object, ...], Event] = field(
        default_factory=dict, init=False, repr=False
    )
    _is_reusable: Optional[bool] = field(default=None, init=False, repr=False)

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

        ctx = PredicateContext(leaves=tuple(all_leaves))

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


__all__ = ["PredicateContext", "PredicateFn", "WorkflowAwarePattern"]
