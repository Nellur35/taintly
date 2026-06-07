"""Structural query helpers over :func:`walk_workflow`.

Small, structurally-grounded readers that collapse the several YAML encodings of
a construct (e.g. the ``on:`` trigger node) to a single answer, so consumers
don't re-derive shape-fragile regexes.
"""

from __future__ import annotations

from .walker import EventKind
from .walker import walk as _walk

__all__ = ["triggers"]


def triggers(content: str) -> frozenset[str]:
    """Return the GitHub Actions trigger event names declared under ``on:``,
    read structurally so all four YAML encodings collapse to one answer:

      * bare scalar    ``on: pull_request_target``
      * flow list      ``on: [push, pull_request_target]``
      * block list     ``on:\\n  - push``
      * block mapping  ``on:\\n  pull_request_target:`` (incl. empty value)
      * flow mapping   ``on: { pull_request_target: {} }``

    This is the structural home for the trigger check currently done by the
    regex ``workflow_corpus._extract_raw_events``. It uses the opt-in
    ``MAP_KEY`` events so mapping keys whose value is empty/nested (which emit
    no ``LEAF_SCALAR``) are still seen — the flow-mapping and empty-block-value
    forms the regex path handled inconsistently.

    Returns raw event-name strings (case preserved, matching
    ``_extract_raw_events``); classification into trigger families stays with
    ``workflow_corpus._classify_triggers``.
    """
    events: set[str] = set()
    for ev in _walk(content, include_keys=True):
        path = ev.path
        if ev.kind is EventKind.MAP_KEY:
            # Immediate child key of ``on:`` → a mapping-form event name.
            if len(path) == 2 and path[0] == "on":
                events.add(str(path[1]))
        elif ev.kind is EventKind.LEAF_SCALAR and ev.value:
            # Bare scalar (``on:`` value) or a list item (``on[*]``).
            is_bare = path == ("on",)
            is_list_item = len(path) == 2 and path[0] == "on" and isinstance(path[1], int)
            if is_bare or is_list_item:
                events.add(ev.value)
    return frozenset(events)
