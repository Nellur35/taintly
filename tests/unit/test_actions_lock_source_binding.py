"""Authored lockfile contracts; real-source evidence is evaluated separately."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from taintly.actions_lock import ActionsLockAwarePattern
from taintly.engine import scan_file
from taintly.models import IncompletePatternMatches, Platform
from taintly.rules.registry import load_rules_for_platform

_IDS = {"SEC3-GH-001", "SEC3-GH-002", "SEC8-GH-003"}
_REFS = (
    "other/tagged@v1",
    "actions/checkout@v4",
    "other/branched@main",
    "other/ci/.github/workflows/build.yml@v1",
)
_COMMIT = "sha1-" + "a" * 40


def _workflow() -> str:
    return (
        "name: lock test\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: other/tagged@v1\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: other/branched@main\n"
        "  shared:\n    uses: other/ci/.github/workflows/build.yml@v1\n"
    )


def _lock(*, listed: tuple[str, ...] = _REFS, version: str = "v0.0.2") -> str:
    entries = "\n".join(f"    - '{ref}'" for ref in listed)
    dependencies = "\n".join(
        f"  '{ref}':\n"
        f"    ref: '{ref.rpartition('@')[2]}'\n"
        f"    commit: '{_COMMIT}'\n"
        "    owner_id: 11\n"
        "    repo_id: 22"
        for ref in _REFS
    )
    return (
        f"version: '{version}'\nworkflows:\n  '.github/workflows/ci.yml':\n"
        f"{entries}\ndependencies:\n{dependencies}\n"
    )


def _case(tmp_path: Path, lock: str | None) -> Path:
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True)
    workflow = directory / "ci.yml"
    workflow.write_text(_workflow(), encoding="utf8")
    if lock is not None:
        (directory / "actions.lock").write_text(lock, encoding="utf8")
    return workflow


def _scan(path: Path):
    rules = [rule for rule in load_rules_for_platform(Platform.GITHUB) if rule.id in _IDS]
    return scan_file(str(path), rules)


@pytest.mark.parametrize("version", ["v0.0.2", "v0.0.3"])
def test_exact_source_bound_lock_removes_only_mutable_ref_claims(tmp_path: Path, version: str):
    path = _case(tmp_path, _lock(version=version))
    findings = _scan(path)
    assert findings == []


def test_without_lock_the_findings_remain(tmp_path: Path):
    path = _case(tmp_path, None)
    findings = _scan(path)
    assert {finding.rule_id for finding in findings} == _IDS


@pytest.mark.parametrize(
    "changed",
    [
        lambda text: text.replace("v0.0.2", "v0.0.4"),
        lambda text: text.replace(".github/workflows/ci.yml", ".github/workflows/other.yml"),
        lambda text: text.replace("sha1-" + "a" * 40, "sha1-bad"),
        lambda text: text.replace("owner_id: 11", "owner_id: 0"),
        lambda text: text.replace("'other/tagged@v1'\n", "'other/tagged@v2'\n", 1),
    ],
)
def test_unknown_or_mismatched_lock_cannot_erase_tag_finding(tmp_path: Path, changed):
    path = _case(tmp_path, changed(_lock()))
    findings = _scan(path)
    assert any(finding.rule_id == "SEC3-GH-001" for finding in findings)


def test_duplicate_dependency_record_remains_unresolved(tmp_path: Path):
    lock = _lock() + (
        "  'other/tagged@v1':\n    ref: 'v1'\n"
        f"    commit: '{_COMMIT}'\n    owner_id: 11\n    repo_id: 22\n"
    )
    path = _case(tmp_path, lock)
    findings = _scan(path)
    assert any(finding.rule_id == "SEC3-GH-001" for finding in findings)


def test_changed_scan_content_cannot_borrow_physical_lockfile(tmp_path: Path):
    path = _case(tmp_path, _lock())
    changed = _workflow().replace("name: lock test", "name: changed source")
    rules = [rule for rule in load_rules_for_platform(Platform.GITHUB) if rule.id == "SEC3-GH-001"]
    findings = scan_file(str(path), rules, _content=changed)
    assert any(finding.rule_id == "SEC3-GH-001" for finding in findings)


def test_incomplete_underlying_pattern_keeps_coverage_signal(tmp_path: Path):
    partial = IncompletePatternMatches([(1, "uses: other/tagged@v1")], reason="budget exhausted")
    wrapped = ActionsLockAwarePattern(SimpleNamespace(check=lambda _content, _lines: partial))
    result = wrapped.check_with_filepath(
        "uses: other/tagged@v1\n", ["uses: other/tagged@v1"], str(tmp_path / "ci.yml")
    )
    assert result is partial
    assert result.reason == "budget exhausted"
