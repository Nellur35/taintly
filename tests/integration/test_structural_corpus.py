"""Integration test: walk every YAML fixture in the corpus.

The structural reader is pure addition in Phase 1 — no rules
consume it yet.  This test catches a much narrower regression:
the walker should not crash on any file in the existing rule-pack
corpus, and recovery mode should produce a CUTOFF event (rather
than an exception) for any file that uses an unsupported
construct.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.parsers.structural import EventKind, walk_workflow


_FIXTURE_ROOT = Path(__file__).resolve().parent.parent / "fixtures"


def _yaml_fixtures() -> list[Path]:
    paths: list[Path] = []
    for plat in ("github", "gitlab"):
        plat_dir = _FIXTURE_ROOT / plat
        if not plat_dir.exists():
            continue
        for ext in (".yml", ".yaml"):
            paths.extend(plat_dir.rglob(f"*{ext}"))
    return sorted(paths)


@pytest.mark.parametrize("fixture_path", _yaml_fixtures(), ids=lambda p: p.name)
def test_walker_does_not_crash_on_fixture(fixture_path: Path) -> None:
    """The walker must consume every existing fixture file without
    raising in recover mode.  CUTOFF events are an acceptable
    outcome for files that use unsupported constructs; the contract
    is "no exceptions escape ``walk_workflow``".
    """
    events = list(walk_workflow(str(fixture_path), recover=True))
    # If a CUTOFF event was emitted, no later events should follow.
    cutoffs = [e for e in events if e.kind == EventKind.CUTOFF]
    if cutoffs:
        cutoff_idx = events.index(cutoffs[0])
        assert cutoff_idx == len(events) - 1, (
            f"CUTOFF must be the last event when emitted; got "
            f"{len(events) - cutoff_idx - 1} events after the cutoff"
        )
