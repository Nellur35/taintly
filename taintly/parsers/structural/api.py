"""Public API for the structural CI YAML reader.

Rules import from :mod:`taintly.parsers.structural` (re-exports
this module's symbols); the ``tokenizer``, ``walker``, and
``schemas`` modules are private implementation details.

Usage::

    from taintly.parsers.structural import walk_workflow

    for event in walk_workflow(filepath, query="jobs.*.steps[*].uses"):
        if event.kind == EventKind.LEAF_SCALAR:
            ...
        elif event.kind == EventKind.CUTOFF:
            # Structural coverage degraded for this file from
            # event.line onward.  Treat downstream queries as
            # could-not-evaluate, not no-finding.
            ...
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, Optional

from .schemas import detect_schema_for_path
from .walker import Event, EventKind, walk as _walk


def walk_workflow(
    filepath: str,
    *,
    query: Optional[str] = None,
    schema: Optional[str] = None,  # noqa: ARG001 — reserved for Phase 2
    content: Optional[str] = None,
    recover: bool = True,
) -> Iterator[Event]:
    """Walk a CI YAML file, yielding events.

    Args:
        filepath: path to the file (used for schema detection if
            ``schema`` is not supplied).
        query: optional path glob; when supplied, only LEAF_SCALAR
            events whose path matches are yielded.  CUTOFF and
            ERROR events always pass through.
        schema: explicit schema name (``"github_actions"``,
            ``"gitlab_ci"``).  Auto-detected from filepath when
            omitted; ``"unknown"`` when neither pattern matches.
        content: pre-read file contents.  When provided, ``filepath``
            is used only for schema detection.
        recover: if True (default), the walker yields a ``CUTOFF``
            event when the tokenizer hits an unsupported construct
            and stops.  If False, the underlying ``TokenizerError``
            propagates.

    Schema disambiguation lands in Phase 1.5 — the schema name is
    accepted today so consumers can write forward-compatible call
    sites; the walker currently treats every path as
    ``ValueShape.UNKNOWN`` and infers shape from the token stream.
    """
    if content is None:
        content = Path(filepath).read_text(encoding="utf-8", errors="replace")
    # Schema currently looked up but not consumed.  When the schema-
    # consultation hook lands in Phase 1.5, this is where it wires
    # into the walker.
    _ = schema or detect_schema_for_path(filepath)
    yield from _walk(content, query=query, recover=recover)


__all__ = ["walk_workflow", "Event", "EventKind"]
