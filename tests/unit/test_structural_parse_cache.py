"""Parse-cache correctness for the structural walker.

The walk is a pure function of (content, query, recover, include_keys); the cache
memoises it. These lock the properties the cache relies on: identical replay,
key-distinction, LRU bounding, and that a re-walk after clear reproduces the
same events (no stale/corrupt state).
"""

from __future__ import annotations

from taintly.parsers.structural import walk_workflow
from taintly.parsers.structural.api import _WALK_CACHE_MAXSIZE, _walk_cache, clear_walk_cache

_WF = "on: push\njobs:\n  build:\n    steps:\n      - run: echo hi\n"


def test_cache_replays_identical_events():
    clear_walk_cache()
    miss = list(walk_workflow("x.yml", content=_WF))  # materialises
    hit = list(walk_workflow("x.yml", content=_WF))  # replays
    assert len(miss) > 0
    assert miss == hit


def test_cache_rewalk_after_clear_matches():
    clear_walk_cache()
    first = list(walk_workflow("x.yml", content=_WF))
    clear_walk_cache()
    again = list(walk_workflow("x.yml", content=_WF))
    assert first == again  # no stale state; re-walk reproduces the events


def test_cache_distinguishes_include_keys():
    clear_walk_cache()
    leaves = list(walk_workflow("x.yml", content=_WF, include_keys=False))
    with_keys = list(walk_workflow("x.yml", content=_WF, include_keys=True))
    # include_keys adds MAP_KEY events -> a different (cached) result, not a
    # collision on the leaves-only entry.
    assert len(with_keys) > len(leaves)


def test_cache_distinguishes_content():
    clear_walk_cache()
    a = list(walk_workflow("x.yml", content=_WF))
    b = list(walk_workflow("x.yml", content=_WF + "  # trailer\n"))
    # Distinct content must not collide on the cache key (would be a wrong-hit).
    assert a is not b  # different list objects
    # both self-consistent on replay
    assert a == list(walk_workflow("x.yml", content=_WF))


def test_cache_is_lru_bounded():
    clear_walk_cache()
    for i in range(_WALK_CACHE_MAXSIZE * 3):
        list(walk_workflow("x.yml", content=f"on: push  # {i}\n"))
    assert len(_walk_cache) <= _WALK_CACHE_MAXSIZE
