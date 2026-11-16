"""Authored boundary regressions for saved workflow-run Release evidence."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from taintly.ingestion.github_preview import PreviewEvidenceError
from taintly.ingestion.github_release_observation import _job_window, _publisher_index


BASE = """on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: echo sample
"""
WORKFLOW = ".github/workflows/publish.yml"
REVISION = "a" * 40


def projection(root: Path, content: str):
    data = content.encode()
    path = root / WORKFLOW
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"path": WORKFLOW, "revision": REVISION, "sha256": hashlib.sha256(data).hexdigest()}


def test_publisher_projection_keeps_owned_event(tmp_path):
    saved = projection(tmp_path, BASE)
    index, source = _publisher_index(tmp_path, {"path": WORKFLOW, "head_sha": REVISION}, saved)
    assert source == saved
    assert len(index.keys[("on", "workflow_run")]) == 1


@pytest.mark.parametrize("added", [
    'on: {}\n',
    '"o\\u006e": {}\n',
    '"j\\u006fbs": {}\n',
    '---\non: {}\n',
    'extra: &x { jobs: {} }\n<<: *x\n',
])
def test_ambiguous_source_does_not_reach_release_semantics(tmp_path, added):
    saved = projection(tmp_path, BASE + added)
    with pytest.raises(PreviewEvidenceError):
        _publisher_index(tmp_path, {"path": WORKFLOW, "head_sha": REVISION}, saved)


def test_lexically_plausible_job_cannot_move_outside_run():
    run = {"created_at": "2026-11-16T15:30:00Z", "updated_at": "2026-11-16T15:35:00Z"}
    job = {"started_at": "2026-11-16T15:30:01Z", "completed_at": "2026-11-16T15:35:00Z"}
    _job_window(run, job)
    with pytest.raises(PreviewEvidenceError, match="owning run"):
        _job_window(run, {**job, "completed_at": "2026-11-16T15:35:01Z"})
