"""Synthetic cache-mode contracts for SEC4-GH-026A."""

from pathlib import Path

from taintly.engine import scan_file
from taintly.rules.registry import load_all_rules

def _rule_ids(path: Path) -> set[str]:
    return {finding.rule_id for finding in scan_file(str(path), load_all_rules())}


def test_plain_pull_request_cache_posture_rule_is_retired() -> None:
    assert "SEC4-GH-026" not in {rule.id for rule in load_all_rules()}


def test_prt_default_cache_access_is_read_only(tmp_path: Path) -> None:
    workflow = tmp_path / "default-read.yml"
    workflow.write_text(
        "on:\n  pull_request_target:\njobs:\n  test:\n"
        "    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/cache@v4\n"
        "        with:\n          path: out\n          key: build\n",
        encoding="utf-8",
    )
    assert "SEC4-GH-026A" not in _rule_ids(workflow)


def test_workflow_write_override_and_direct_cache_fire(tmp_path: Path) -> None:
    workflow = tmp_path / "workflow-write.yml"
    workflow.write_text(
        "on:\n  pull_request_target:\ncache-mode: write\njobs:\n  test:\n"
        "    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/cache@v4\n"
        "        with:\n          path: out\n          key: build\n",
        encoding="utf-8",
    )
    assert "SEC4-GH-026A" in _rule_ids(workflow)


def test_job_read_override_closes_workflow_write_access(tmp_path: Path) -> None:
    workflow = tmp_path / "job-read.yml"
    workflow.write_text(
        "on:\n  pull_request_target:\ncache-mode: write\njobs:\n  test:\n"
        "    runs-on: ubuntu-latest\n    cache-mode: read\n    steps:\n"
        "      - uses: actions/cache@v4\n"
        "        with:\n          path: out\n          key: build\n",
        encoding="utf-8",
    )
    assert "SEC4-GH-026A" not in _rule_ids(workflow)


def test_setup_go_default_cache_fires_with_job_write_override(tmp_path: Path) -> None:
    workflow = tmp_path / "setup-go-default.yml"
    workflow.write_text(
        "on:\n  pull_request_target:\njobs:\n  test:\n"
        "    runs-on: ubuntu-latest\n    cache-mode: write-only\n    steps:\n"
        "      - uses: actions/setup-go@v6\n"
        "        with:\n          go-version: '1.25'\n",
        encoding="utf-8",
    )
    assert "SEC4-GH-026A" in _rule_ids(workflow)


def test_restore_only_stays_silent_even_with_write_override(tmp_path: Path) -> None:
    workflow = tmp_path / "restore-only.yml"
    workflow.write_text(
        "on:\n  pull_request_target:\ncache-mode: write\njobs:\n  test:\n"
        "    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/cache/restore@v4\n"
        "        with:\n          path: out\n          key: build\n",
        encoding="utf-8",
    )
    assert "SEC4-GH-026A" not in _rule_ids(workflow)
