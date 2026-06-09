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

from collections import OrderedDict
from collections.abc import Iterator
from pathlib import Path

from .schemas import detect_schema_for_path
from .walker import Event, EventKind, _glob_to_segments, _path_matches
from .walker import walk as _walk

# ---------------------------------------------------------------------------
# Parse memoization.
#
# The FULL walk is a PURE function of (content, recover, include_keys) — the
# schema lookup is not consumed and the filepath only feeds it, and ``query`` is
# just a post-filter over the yielded events (see ``walk()``).  A single
# ``scan_file`` calls ``walk_workflow`` hundreds-to-tens-of-thousands of times on
# the SAME content (one call per structural rule / query / taint fact-build).
# Keying the cache by (content, recover, include_keys) and applying ``query`` as
# an in-memory filter means all those distinct-query calls share ONE walk
# (≤4 per file, the recover/include_keys combos) instead of re-walking per query.
#
# Bounded LRU: the dominant redundancy is *within* one file's scan (same
# content, a handful of query/flag variants), so a small cap captures nearly all
# of the win while keeping memory flat across a whole-repo scan (old files
# evict).  Events are treated as read-only by every consumer (parse output), so
# replaying the same Event objects is safe — the no-rules-change / determinism /
# mutation gates prove behaviour is preserved.
_WALK_CACHE_MAXSIZE = 64
_walk_cache: OrderedDict[tuple[object, ...], tuple[Event, ...]] = OrderedDict()


def clear_walk_cache() -> None:
    """Drop all memoised walks (test hook; not needed in normal operation —
    the LRU bounds memory and the walk is content-keyed so stale hits are
    impossible)."""
    _walk_cache.clear()


def _full_walk(content: str, recover: bool, include_keys: bool) -> tuple[Event, ...]:
    """One materialised FULL (``query=None``) walk per (content, recover,
    include_keys), so the many distinct-query calls on one file share a single
    walk.  ``query`` is applied as a cheap in-memory post-filter in
    :func:`walk_workflow`; ``walk()`` already treats the query as a pure
    post-filter, so filtering the full stream is byte-identical to a per-query
    walk."""
    key = (content, recover, include_keys)
    cached = _walk_cache.get(key)
    if cached is not None:
        _walk_cache.move_to_end(key)
        return cached
    events = tuple(_walk(content, query=None, recover=recover, include_keys=include_keys))
    _walk_cache[key] = events
    _walk_cache.move_to_end(key)
    if len(_walk_cache) > _WALK_CACHE_MAXSIZE:
        _walk_cache.popitem(last=False)
    return events


def walk_workflow(
    filepath: str,
    *,
    query: str | None = None,
    schema: str | None = None,
    content: str | None = None,
    recover: bool = True,
    include_keys: bool = False,
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
        include_keys: if True, additionally yield ``MAP_KEY`` events for
            mapping keys (incl. keys with empty/null/nested-map values
            that produce no ``LEAF_SCALAR``).  Default False keeps the
            event stream byte-identical for leaf-only consumers.

    The schema name is accepted for forward compatibility; the
    walker currently treats every path as ``ValueShape.UNKNOWN``
    and infers shape from the token stream.
    """
    if content is None:
        content = Path(filepath).read_text(encoding="utf-8", errors="replace")
    # Schema currently looked up but not consumed; the lookup site
    # is preserved so a future schema-consultation hook wires in
    # here without touching the call sites.
    _ = schema or detect_schema_for_path(filepath)
    # Walk ONCE per (content, recover, include_keys) — cached full event stream —
    # then apply ``query`` as a cheap in-memory post-filter.  ``walk()`` already
    # treats query as a pure post-filter over LEAF_SCALAR/MAP_KEY events
    # (CUTOFF/ERROR always pass through), so this is byte-identical to a per-query
    # walk while collapsing the many distinct-query walks/file to ≤4.  filepath /
    # schema do not affect the event stream.
    events = _full_walk(content, recover, include_keys)
    if query is None:
        return iter(events)
    segments = _glob_to_segments(query)

    def _filtered() -> Iterator[Event]:
        for ev in events:
            # CUTOFF/ERROR (non-addressable) always pass; LEAF_SCALAR/MAP_KEY
            # pass only on a path match — identical to ``walk()``'s filter.
            if ev.kind not in (EventKind.LEAF_SCALAR, EventKind.MAP_KEY) or _path_matches(
                ev.path, segments
            ):
                yield ev

    return _filtered()


__all__ = ["Event", "EventKind", "clear_walk_cache", "walk_workflow"]
