from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "public_repo_fp_budget", ROOT / "scripts" / "check_public_repo_fp_budget.py"
)
assert SPEC is not None
assert SPEC.loader is not None
budget = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = budget
SPEC.loader.exec_module(budget)


def _target(**changes):
    values = {
        "label": "fixture",
        "repo_url": "unused",
        "revision": "a" * 40,
        "cache_name": "fixture",
        "scan_target": ".github/workflows",
        "platform": "github",
        "max_confirmed": 1,
        "max_review_needed": 1,
    }
    values.update(changes)
    return budget.Target(**values)


def test_frozen_target_budgets_keep_evidence_classes_separate():
    assert {
        target.label: (target.max_confirmed, target.max_review_needed)
        for target in budget._TARGETS
    } == {
        "ripgrep": (17, 5),
        "flask": (10, 2),
        "maven_jenkinsfile": (2, 0),
    }


def test_scanner_identity_falls_back_to_local_commit(monkeypatch):
    monkeypatch.delenv("GITHUB_SHA", raising=False)

    identity = budget._scanner_identity()

    assert len(identity["revision"]) == 40
    assert isinstance(identity["tracked_files_dirty"], bool)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"revision": "main"}, "full lowercase SHA"),
        ({"scan_target": "../secret.yml"}, "inside the checkout"),
        ({"cache_name": "../escape"}, "unsafe cache_name"),
        ({"max_confirmed": -1}, "non-negative"),
    ],
)
def test_target_validation_rejects_unstable_or_escaping_inputs(changes, message):
    with pytest.raises(ValueError, match=message):
        budget._validate_target(_target(**changes))


def test_normalise_finding_removes_machine_path_and_hashes_evidence(tmp_path: Path):
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: test\n", encoding="utf-8")
    raw = {
        "rule_id": "SEC-X",
        "severity": "HIGH",
        "file": str(workflow),
        "line": 7,
        "title": "example",
        "snippet": "secret evidence",
        "review_needed": True,
    }

    result = budget._normalise_finding(raw, tmp_path)

    assert result["file"] == ".github/workflows/ci.yml"
    assert result["review_needed"] is True
    assert len(result["fingerprint"]) == 64
    assert "secret evidence" not in json.dumps(result)
    assert str(tmp_path) not in json.dumps(result)


def test_budget_separates_confirmed_review_and_coverage_failures():
    result = budget.ScanResult(
        confirmed=2,
        review_needed=3,
        engine_errors=1,
        findings=(),
        rule_counts={},
        severity_counts={},
    )

    failures = budget._budget_failures(_target(), result)

    assert failures == [
        "confirmed 2 exceeds 1",
        "review-needed 3 exceeds 1",
        "1 ENGINE-ERR coverage finding(s)",
    ]


@pytest.mark.parametrize(
    ("returncode", "payload", "message"),
    [
        (3, {"findings": [], "errors": []}, "exited with code 3"),
        (0, [], "root is not an object"),
        (0, {"findings": ["bad"], "errors": []}, "malformed finding"),
        (0, {"findings": [], "errors": {}}, "errors field is not a list"),
    ],
)
def test_scan_rejects_incomplete_or_failed_measurements(
    monkeypatch, tmp_path: Path, returncode, payload, message
):
    completed = subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=json.dumps(payload), stderr=""
    )
    monkeypatch.setattr(
        budget.subprocess, "run", lambda *_args, **_kwargs: completed
    )

    result, error = budget._scan(tmp_path, _target())

    assert result is None
    assert message in str(error)


def test_scan_counts_top_level_coverage_errors(monkeypatch, tmp_path: Path):
    payload = {
        "findings": [],
        "errors": [{"rule_id": "ENGINE-ERR", "title": "coverage degraded"}],
    }
    completed = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=json.dumps(payload), stderr=""
    )
    monkeypatch.setattr(
        budget.subprocess, "run", lambda *_args, **_kwargs: completed
    )

    result, error = budget._scan(tmp_path, _target())

    assert error is None
    assert result is not None
    assert result.engine_errors == 1


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def test_materialize_fetches_exact_commit_with_sparse_checkout(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "-q")
    _git(source, "config", "user.name", "Taintly Test")
    _git(source, "config", "user.email", "taintly@example.invalid")
    workflow = source / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: pinned\n", encoding="utf-8")
    (source / "unrelated.txt").write_text("do not checkout\n", encoding="utf-8")
    _git(source, "add", ".github/workflows/ci.yml", "unrelated.txt")
    _git(source, "commit", "-qm", "fixture")
    revision = _git(source, "rev-parse", "HEAD")
    target = _target(repo_url=str(source), revision=revision)

    checkout, error = budget._materialize(target, tmp_path / "cache")

    assert error is None
    assert checkout is not None
    assert budget._head_sha(checkout) == revision
    assert (checkout / ".github" / "workflows" / "ci.yml").is_file()
    assert not (checkout / "unrelated.txt").exists()


def test_materialize_refuses_corrupted_cached_identity(tmp_path: Path):
    cache = tmp_path / "cache"
    target = _target()
    checkout = cache / target.cache_key
    checkout.mkdir(parents=True)

    actual, error = budget._materialize(target, cache)

    assert actual is None
    assert "no valid HEAD" in str(error)
