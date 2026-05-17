"""Event types emitted by the structural Jenkinsfile reader.

Mirrors :mod:`taintly.parsers.structural.walker`'s Event shape so
rule code that handles structural events from either reader is
uniform.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class EventKind(str, Enum):
    """Public event types yielded by :func:`walk_jenkinsfile`.

    * ``LEAF`` — a scalar value at a fully-resolved structural path
      (the body of a ``sh '...'`` call, an ``env`` block assignment,
      a ``tool`` argument, the credentialsId of a
      ``withCredentials`` entry, etc.).
    * ``CUTOFF`` — the underlying parser hit an unrecoverable error
      or an unsupported construct.  Events emitted before this point
      are valid; no further events follow.  Consumers should treat
      any unresolved query as could-not-evaluate (matches the YAML
      reader's exit-11 contract).
    * ``ERROR`` — a recoverable parse-time problem the walker chose
      to surface but continue past (e.g., a Groovy construct the
      walker doesn't model but the parser handled).
    """

    LEAF = "leaf"
    CUTOFF = "cutoff"
    ERROR = "error"


@dataclass(frozen=True)
class Event:
    """One event from the walker.

    Fields:
      kind: see :class:`EventKind`.
      path: tuple of structural path components from the document
        root to this leaf.  Components are strings (block names or
        directive names) or integers (sequence indices).  Empty for
        CUTOFF / ERROR events.
      value: scalar value as a Python string.  None for non-LEAF
        events.
      value_kind: ``"shell"`` for shell-body strings (sh / bat /
        powershell), ``"string"`` for plain string literals,
        ``"identifier"`` for bareword identifiers (e.g. ``any`` in
        ``agent any``).  None for non-LEAF events.
      line: 1-based line number in the source where this leaf
        originates.  For CUTOFF events, the line where the parser
        first encountered the unrecoverable construct.
      detail: free-form context string (e.g. an error message for
        CUTOFF / ERROR events).
    """

    kind: EventKind
    path: tuple[object, ...] = field(default_factory=tuple)
    value: str | None = None
    value_kind: str | None = None
    line: int = 0
    detail: str | None = None
