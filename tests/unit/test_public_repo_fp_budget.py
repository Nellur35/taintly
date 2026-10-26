"""The field gate must compare scanner output against immutable source bytes."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import check_public_repo_fp_budget as gate


def _git(path: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(path), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


@pytest.mark.skipif(shutil.which("git") is None, reason="git is needed for source pin test")
def test_gate_fetches_exact_revision_and_rejects_changed_cache(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "-q")
    _git(source, "config", "user.email", "test@example.invalid")
    _git(source, "config", "user.name", "Test")
    workflow = source / "workflow.yml"
    workflow.write_text("first\n", encoding="utf-8")
    _git(source, "add", "workflow.yml")
    _git(source, "commit", "-q", "-m", "first")
    pinned = _git(source, "rev-parse", "HEAD")

    workflow.write_text("second\n", encoding="utf-8")
    _git(source, "commit", "-q", "-am", "second")
    newer = _git(source, "rev-parse", "HEAD")
    assert newer != pinned

    cache = tmp_path / "cache" / "checkout"
    assert gate._ensure_clone(str(source), pinned, cache, "workflow.yml") is None
    assert _git(cache, "rev-parse", "HEAD") == pinned
    assert (cache / "workflow.yml").read_text(encoding="utf-8") == "first\n"

    _git(cache, "fetch", "-q", "origin", newer)
    _git(cache, "checkout", "--detach", "-q", newer)
    assert "cache identity mismatch" in gate._ensure_clone(
        str(source), pinned, cache, "workflow.yml"
    )


@pytest.mark.skipif(shutil.which("git") is None, reason="git is needed for source pin test")
def test_gate_rejects_dirty_cached_source(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "-q")
    _git(source, "config", "user.email", "test@example.invalid")
    _git(source, "config", "user.name", "Test")
    (source / "workflow.yml").write_text("clean\n", encoding="utf-8")
    _git(source, "add", "workflow.yml")
    _git(source, "commit", "-q", "-m", "first")
    pinned = _git(source, "rev-parse", "HEAD")
    cache = tmp_path / "checkout"
    assert gate._ensure_clone(str(source), pinned, cache, "workflow.yml") is None
    (cache / "workflow.yml").write_text("changed\n", encoding="utf-8")
    assert "cache identity mismatch" in gate._ensure_clone(
        str(source), pinned, cache, "workflow.yml"
    )


@pytest.mark.parametrize(
    ("counts", "expected"),
    [
        ({"RULE-A": 2, "RULE-B": 1}, 0),
        ({"RULE-A": 1, "RULE-B": 2}, 1),  # unchanged total; new RULE-B path
        ({"RULE-A": 2, "RULE-C": 1}, 1),  # unreviewed rule
    ],
)
def test_reviewed_rule_ceiling_detects_offsetting_growth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    counts: dict[str, int],
    expected: int,
) -> None:
    monkeypatch.setattr(
        gate,
        "_TARGETS",
        [("sample", "local", "a" * 40, "sample", ".", "github", {"RULE-A": 2, "RULE-B": 1})],
    )
    monkeypatch.setattr(gate, "_CACHE", tmp_path)
    monkeypatch.setattr(gate, "_ensure_clone", lambda *_: None)
    monkeypatch.setattr(gate, "_scan_counts", lambda *_: counts)
    monkeypatch.setattr(sys, "argv", ["check_public_repo_fp_budget.py", "--strict-skips"])
    assert gate.main() == expected
