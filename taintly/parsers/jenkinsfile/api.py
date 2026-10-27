"""Public walk_jenkinsfile entry point.

The zero-dependency island-grammar Groovy reader: a tolerant, pure-Python
reader that never raises on unmodelled Groovy (it skips to the next
recognisable island rather than cutting off) and works on every install with
no optional extra and no native parser.
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache

from .events import Event
from .island_walker import iter_island_leaves


@lru_cache(maxsize=8)
def _cached_island_events(content: str, recover: bool) -> tuple[Event, ...]:
    """Bounded reuse of immutable events for one exact source/options pair.

    Events contain source-relative locations, not file or invocation identity;
    consumers attach ownership at their call sites. Diagnostic events retain
    their original order and positions.
    """
    del recover  # Tolerant reader: recovery is unconditional.
    return tuple(iter_island_leaves(content))


def walk_jenkinsfile(content: str, *, recover: bool = True) -> Iterator[Event]:
    """Walk a Jenkinsfile, yielding :class:`Event` instances.

    Args:
        content: Jenkinsfile source as a string.
        recover: accepted for API compatibility.  The island reader is
            tolerant and never raises, so recovery is always on regardless
            of this flag.

    Yields:
        :class:`Event` instances.  See :class:`EventKind` for the
        documented stream contract.
    """
    yield from _cached_island_events(content, recover)
