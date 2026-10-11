"""Batch reuse must preserve core output, input order, isolation and failures."""

from collections import Counter
from pathlib import Path

import pytest

import taintly.batch as batch
from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_all_rules


def gh(root: Path, script: str) -> Path:
    path = root / ".github/workflows/ci.yml"
    path.parent.mkdir(parents=True)
    path.write_text(
        "on: pull_request\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n      - run: "
        + script
        + "\n",
        encoding="utf-8",
    )
    return root


def signature(reports):
    return [(r.platform, r.files_scanned, [f.to_dict() for f in r.findings]) for r in reports]


def test_batch_matches_repeated_scans_and_isolates_same_filenames(tmp_path, monkeypatch):
    risky = gh(tmp_path / "risk", 'echo "${{ github.event.pull_request.title }}"')
    safe = gh(tmp_path / "safe", "echo fixed-text")
    gl = tmp_path / "gl"
    gl.mkdir()
    (gl / ".gitlab-ci.yml").write_text("inspect:\n  script:\n    - echo fixed\n", encoding="utf-8")
    paths = [risky, safe, gl, risky]
    rules = load_all_rules()
    expected = [signature(scan_repo(str(p), rules)) for p in paths]
    original = batch.registry.load_rules_for_platform
    calls = []

    def counted(platform):
        calls.append(platform)
        return original(platform)

    monkeypatch.setattr(batch.registry, "load_rules_for_platform", counted)
    results = batch.scan_repositories(paths)
    assert [r.repo_path for r in results] == [str(p) for p in paths]
    assert all(r.error is None for r in results)
    assert [signature(r.reports) for r in results] == expected
    assert Counter(calls) == Counter(Platform)
    assert results[0].reports is not results[3].reports


def test_invalid_root_and_exception_do_not_hide_following_result(tmp_path, monkeypatch):
    valid = gh(tmp_path / "valid", "echo okay")
    original = batch.scan_repo

    def injected(path, rules, platform, **kwargs):
        if path.endswith("broken"):
            raise ValueError("injected scanner failure")
        return original(path, rules, platform, **kwargs)

    broken = tmp_path / "broken"
    broken.mkdir()
    monkeypatch.setattr(batch, "scan_repo", injected)
    results = batch.scan_repositories([tmp_path / "missing", broken, valid], Platform.GITHUB)
    assert "NotADirectoryError" in results[0].error
    assert "injected scanner failure" in results[1].error
    assert not results[0].reports and not results[1].reports
    assert results[2].error is None and results[2].reports[0].files_scanned == 1


def test_rule_import_failure_is_explicit_for_every_input(monkeypatch):
    def failed(platform):
        batch.registry._IMPORT_FAILURES[:] = ["injected.failed.module"]
        return []

    monkeypatch.setattr(batch.registry, "load_rules_for_platform", failed)
    results = batch.scan_repositories(["first", "second"], Platform.GITHUB)
    assert len(results) == 2
    assert all(r.error and "injected.failed.module" in r.error and not r.reports for r in results)
    batch.registry._IMPORT_FAILURES.clear()


def test_explicit_platform_loads_only_one_pack(tmp_path, monkeypatch):
    root = gh(tmp_path / "repo", "echo okay")
    original = batch.registry.load_rules_for_platform
    calls = []

    def counted(platform):
        calls.append(platform)
        return original(platform)

    monkeypatch.setattr(batch.registry, "load_rules_for_platform", counted)
    assert batch.scan_repositories([root, root], Platform.GITHUB)[0].error is None
    assert calls == [Platform.GITHUB]


def test_empty_batch_does_not_load_rules(monkeypatch):
    monkeypatch.setattr(
        batch.registry, "load_rules_for_platform", lambda _: pytest.fail("loaded empty batch")
    )
    assert batch.scan_repositories([]) == []
