"""StructuralPattern — Phase 2 of the structural CI YAML reader.

A ``StructuralPattern`` is a rule-time pattern that uses the
schema-bounded path-extraction reader at
:mod:`taintly.parsers.structural` instead of regex matching.

Phase 2 contract:

  * Conforms to ``PatternProtocol.check(content, lines) ->
    list[(line, snippet)]`` so existing engine code dispatches it
    without changes.
  * Each call walks the file with a fixed path glob and applies a
    Python predicate to every leaf scalar at that path.  Truthy
    predicate result emits a finding at the leaf's line.
  * If the walker emits a ``CUTOFF`` event before the query
    completes, ``check`` emits a sentinel ``ENGINE-ERR``-shaped
    finding marking degraded structural coverage.  The engine's
    standard exit-11 path picks this up — same mechanism the
    existing ``ENGINE-ERR`` LOW finding uses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from .parsers.structural import EventKind, walk_workflow


@dataclass
class StructuralPattern:
    """Pattern that queries one or more path globs and applies a
    predicate.

    Args:
        path: a single path glob, or a list of globs.  When a list
            is given, leaves matching ANY of the globs are
            considered.  The list form is the right shape for
            keys that accept ``string-or-sequence-of-string``
            shapes (e.g., ``runs-on: x`` vs.
            ``runs-on: [x, y]``): pass both ``"**.runs-on"`` and
            ``"**.runs-on[*]"``.
        predicate: ``predicate(value, value_kind, full_path) -> bool``.
            Truthy result fires a finding at the leaf's line.
        snippet_format: optional ``str.format``-style template
            that produces the finding's snippet.  Defaults to the
            stripped source line.  Available placeholders:
            ``{value}``, ``{value_kind}``, ``{path}``, ``{line}``.
    """

    path: str | list[str]
    predicate: Callable[[str, str, tuple[object, ...]], bool]
    snippet_format: Optional[str] = None
    _schema_name: Optional[str] = field(default=None, init=False, repr=False)

    def _paths(self) -> list[str]:
        if isinstance(self.path, str):
            return [self.path]
        return list(self.path)

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        cutoff_seen = False
        cutoff_line = 0
        any_leaf_seen = False
        # Dedupe (line, snippet) — a leaf that matches more than
        # one of the supplied path globs should still emit a
        # single finding.
        seen: set[tuple[int, str]] = set()

        for path_glob in self._paths():
            for ev in walk_workflow(
                "anonymous.yml",
                query=path_glob,
                content=content,
                recover=True,
            ):
                if ev.kind == EventKind.CUTOFF:
                    cutoff_seen = True
                    cutoff_line = ev.line
                    break
                if ev.kind != EventKind.LEAF_SCALAR:
                    continue
                any_leaf_seen = True
                value = ev.value or ""
                value_kind = ev.value_kind or "plain"
                try:
                    hit = self.predicate(value, value_kind, ev.path)
                except Exception:
                    hit = False
                if hit:
                    snippet = self._render_snippet(
                        value, value_kind, ev.path, ev.line, lines
                    )
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
        # Default: stripped source line — matches RegexPattern's
        # snippet contract so a regex→structural migration is
        # output-equivalent on existing fixtures.
        if 0 < line <= len(lines):
            return lines[line - 1].strip()
        return value


__all__ = ["StructuralPattern"]
