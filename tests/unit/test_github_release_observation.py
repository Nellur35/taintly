"""Authored boundary regressions for saved workflow-run Release evidence."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

from taintly import __main__ as cli
from taintly.ingestion import github_release_observation
from taintly.ingestion.github_preview import PreviewEvidenceError
from taintly.ingestion.github_release_observation import _job_window, _publisher_index, _tag_receipt


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


def test_report_distinguishes_pr_head_and_publishing_revision(tmp_path, monkeypatch, capsys):
    head = "b" * 40
    result = {
        "state": "release-asset-observed",
        "pr": {"number": 6, "source_repository": "example-fork/project", "source_head": head},
        "producer_run": 51,
        "consumer_run": 52,
        "source": {"path": WORKFLOW, "revision": REVISION},
        "configured_publish": {"credential_binding": "secrets.PUBLISH", "line": 9},
        "publication": {
            "asset": "build.zip",
            "target_repository": "example/previews",
            "tag": "pr-6",
            "recorded_uploader": {"login": "example-publisher"},
        },
        "scope": "One uploaded asset.",
    }
    monkeypatch.setattr(github_release_observation, "release_observation", lambda *_: result)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "taintly",
            str(tmp_path),
            "--no-config",
            "--github-release-observation",
            str(tmp_path / "receipt.json"),
            "example/project",
            "51",
            "52",
        ],
    )
    with pytest.raises(SystemExit) as exited:
        cli.main()
    assert exited.value.code == 0
    text = capsys.readouterr().out
    assert f"PR head: example-fork/project at {head}." in text
    assert f"Publishing workflow: {WORKFLOW}:9 at {REVISION}." in text


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


def test_tag_receipt_requires_exact_attempt_and_ref_target():
    revision = "a" * 40
    tag = "pr-release-6-aaaaaaa"
    target = "team/preview"
    api = f"https://api.github.com/repos/{target}/git"
    evidence = {
        "run": 51,
        "job": 64,
        "attempt": 2,
        "push_start": {
            "row": 7,
            "time": "2026-11-16T15:33:05.124Z",
            "value": "##[group]Run git init --bare lean4.git",
        },
        "next_start": {
            "row": 12,
            "time": "2026-11-16T15:33:07.510Z",
            "value": "##[group]Run # Delete any existing releases for this PR.",
        },
        "remote": {
            "row": 10,
            "time": "2026-11-16T15:33:07.134Z",
            "value": f"https://github.com/{target}.git",
        },
        "new_tag": {"row": 11, "time": "2026-11-16T15:33:07.433Z", "value": tag},
        "ref": {
            "ref": f"refs/tags/{tag}",
            "url": f"{api}/refs/tags/{tag}",
            "object": {"sha": revision, "url": f"{api}/commits/{revision}", "type": "commit"},
        },
        "retrieved_at": "2026-11-16T15:36:00Z",
    }
    job = {"id": 64, "run_id": 51, "run_attempt": 2, "completed_at": "2026-11-16T15:35:00Z"}
    step = {"started_at": "2026-11-16T15:33:05Z", "completed_at": "2026-11-16T15:33:07Z"}
    following = {"started_at": "2026-11-16T15:33:07Z", "completed_at": "2026-11-16T15:33:09Z"}
    pr = {"number": 6, "source_head": revision}

    result = _tag_receipt(evidence, job, step, following, pr, "team/source")
    assert result["ref"] == f"refs/tags/{tag}"
    assert result["operation"] == "github-git-tag-push"
    with pytest.raises(PreviewEvidenceError, match="exact job, target, time and PR commit"):
        _tag_receipt({**evidence, "attempt": 1}, job, step, following, pr, "team/source")
    with pytest.raises(PreviewEvidenceError, match="exact job, target, time and PR commit"):
        _tag_receipt(
            {**evidence, "remote": {**evidence["remote"], "value": "https://github.com/team/sibling.git"}},
            job,
            step,
            following,
            pr,
            "team/source",
        )
    outside_group = {**evidence["new_tag"], "time": "2026-11-16T15:33:07.511Z"}
    with pytest.raises(PreviewEvidenceError, match="exact job, target, time and PR commit"):
        _tag_receipt(
            {**evidence, "new_tag": outside_group}, job, step, following, pr, "team/source"
        )
