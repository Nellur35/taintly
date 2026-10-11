"""Conservative effective-leaf view for GitLab YAML merge-key precedence.

The structural reader remains the only parser. This view removes inherited
leaves only when a concrete explicit key at the merge destination overrides
their immediate subtree. Unsupported or ambiguous structure returns the
legacy raw event stream with ``complete=False``. That fallback preserves
existing behavior and limitations; it is not a claim that every unresolved or
inherited threat becomes visible.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .parsers.structural import Event, EventKind, walk_workflow


@dataclass(frozen=True)
class GitLabEffectiveView:
    events: tuple[Event, ...]
    complete: bool


def walk_gitlab_effective(
    filepath: str,
    *,
    content: str | None = None,
) -> GitLabEffectiveView:
    """Return raw events with only definitely overridden merged leaves removed.

    Explicit key presence wins over YAML-merged defaults at the same mapping,
    whether it appears before or after ``<<`` and whether its value is a
    scalar, null, map, or sequence. Repeated explicit keys, repeated merge
    sites, parser errors, and parser cutoffs make the view incomplete; in that
    case all events are returned unchanged.
    """

    if content is None:
        content = Path(filepath).read_text(encoding="utf-8", errors="replace")
    events = tuple(
        walk_workflow(
            filepath,
            schema="gitlab_ci",
            content=content,
            recover=True,
            include_keys=True,
            include_merge_origins=True,
        )
    )
    explicit_counts: Counter[tuple[object, ...]] = Counter()
    merge_counts: Counter[tuple[object, ...]] = Counter()
    incomplete = False

    for event in events:
        if event.kind in {EventKind.ERROR, EventKind.CUTOFF}:
            incomplete = True
        elif event.kind is EventKind.MAP_KEY:
            if event.value_kind == "merge_key":
                merge_counts[event.path] += 1
            else:
                explicit_counts[event.path] += 1

    if any(count > 1 for count in explicit_counts.values()) or any(
        count > 1 for count in merge_counts.values()
    ):
        incomplete = True
    if incomplete:
        # The annotated walk has additional metadata fuel and can stop sooner
        # than the legacy reader. Preserve its public behavior and findings by
        # returning the unannotated stream; ``complete`` keeps callers aware
        # that no precedence suppression was performed.
        raw_events = tuple(
            walk_workflow(
                filepath,
                schema="gitlab_ci",
                content=content,
                recover=True,
                include_keys=True,
            )
        )
        return GitLabEffectiveView(raw_events, complete=False)

    explicit_keys = {(path[:-1], path[-1]) for path in explicit_counts}
    effective = tuple(
        event
        for event in events
        if not (
            event.kind is EventKind.LEAF_SCALAR
            and any(origin in explicit_keys for origin in event.merge_origins)
        )
    )
    return GitLabEffectiveView(effective, complete=True)
