"""Synthetic regressions for Git mutation and remote URL provenance."""

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.github.lotp import _git_remote_events, _shell_quote_mask
from taintly.rules.registry import load_all_rules


_LOTP_RULE_IDS = {"LOTP-GH-001", "LOTP-GH-003"}


def _findings_for_workflow(tmp_path: Path, workflow: str) -> set[str]:
    workflow_path = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(workflow, encoding="utf-8")
    rules = [rule for rule in load_all_rules() if rule.id in _LOTP_RULE_IDS]
    reports = scan_repo(str(tmp_path), rules, Platform.GITHUB)
    return {finding.rule_id for report in reports for finding in report.findings}


def test_git_config_remote_url_handoff_to_fetch_and_build(tmp_path: Path) -> None:
    cases = (
        (
            "git config remote.origin.url https://github.com/${{ github.event.pull_request.head.repo.full_name }}.git",
            "untrusted",
            True,
        ),
        (
            "git config remote.origin.url https://github.com/${{ github.repository }}.git",
            "trusted",
            False,
        ),
    )
    for command, expected_state, expected_finding in cases:
        mask, _, _ = _shell_quote_mask(command, None)
        assert _git_remote_events(command, mask) == [
            (0, "origin", expected_state, (), "replace")
        ], command
        workflow = f"""on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: {command}; git fetch origin main; git checkout FETCH_HEAD; npm ci
"""
        findings = _findings_for_workflow(tmp_path, workflow)
        assert (_LOTP_RULE_IDS <= findings) is expected_finding, (command, findings)


def test_git_config_remote_url_read_does_not_change_provenance(tmp_path: Path) -> None:
    command = "git config --get remote.origin.url"
    mask, _, _ = _shell_quote_mask(command, None)
    assert _git_remote_events(command, mask) == []
    workflow = f"""on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: {command}; git fetch origin main; git checkout FETCH_HEAD; npm ci
"""
    assert not (_findings_for_workflow(tmp_path, workflow) & _LOTP_RULE_IDS)


def test_git_config_remote_url_unknown_value_does_not_inherit_origin_trust() -> None:
    for value in ("$FETCH_URL", "origin"):
        command = f"git config remote.origin.url {value}"
        mask, _, _ = _shell_quote_mask(command, None)
        assert _git_remote_events(command, mask) == [
            (0, "origin", "unknown", (), "replace")
        ], command


@pytest.mark.parametrize("track_option", ("--track", "-t", "--track=direct"))
def test_tracked_branch_from_fetched_fork_remote_taints_build(
    tmp_path: Path, track_option: str
) -> None:
    workflow = f"""on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git remote add fork https://github.com/${{{{ github.event.pull_request.head.repo.full_name }}}}.git; git fetch fork main; git branch {track_option} review fork/main; git checkout review; npm ci
"""
    assert _LOTP_RULE_IDS <= _findings_for_workflow(tmp_path, workflow)


def test_tracked_branch_from_fetched_base_remote_stays_clean(tmp_path: Path) -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git fetch origin main; git branch --track review origin/main; git checkout review; npm ci
"""
    assert not (_findings_for_workflow(tmp_path, workflow) & _LOTP_RULE_IDS)


def test_direct_tracking_branch_from_fetched_base_remote_stays_clean(tmp_path: Path) -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git fetch origin main; git branch --track=direct review origin/main; git checkout review; npm ci
"""
    assert not (_findings_for_workflow(tmp_path, workflow) & _LOTP_RULE_IDS)


def test_unresolved_valid_update_ref_does_not_trust_static_branch_name(tmp_path: Path) -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git remote add fork https://github.com/${{ github.event.pull_request.head.repo.full_name }}.git; git fetch fork main; git update-ref refs/heads/review refs/remotes/fork/main; git checkout review; npm ci
"""
    assert _LOTP_RULE_IDS <= _findings_for_workflow(tmp_path, workflow)


def test_update_ref_overwrites_provenance_of_existing_trusted_branch(tmp_path: Path) -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git remote add fork https://github.com/${{ github.event.pull_request.head.repo.full_name }}.git; git fetch fork main; git update-ref refs/heads/main refs/remotes/fork/main; git checkout main; npm ci
"""
    assert _LOTP_RULE_IDS <= _findings_for_workflow(tmp_path, workflow)


def test_update_ref_of_fetched_trusted_target_uses_new_source(tmp_path: Path) -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git fetch origin refs/pull/${{ github.event.pull_request.number }}/head:pr; git fetch origin main:refs/heads/candidate; git update-ref refs/heads/candidate "$COMMIT"; git checkout candidate; npm ci
"""
    assert _LOTP_RULE_IDS <= _findings_for_workflow(tmp_path, workflow)


def test_renamed_local_branch_keeps_fetched_pr_provenance(tmp_path: Path) -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git fetch origin refs/pull/${{ github.event.pull_request.number }}/head:pr; git branch review pr; git branch -m review candidate; git checkout candidate; npm ci
"""
    assert _LOTP_RULE_IDS <= _findings_for_workflow(tmp_path, workflow)


def test_replace_all_remote_url_tracks_pr_source_through_fetch(tmp_path: Path) -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git config --replace-all remote.origin.url https://github.com/${{ github.event.pull_request.head.repo.full_name }}.git .*; git fetch origin main; git checkout FETCH_HEAD; npm ci
"""
    assert _LOTP_RULE_IDS <= _findings_for_workflow(tmp_path, workflow)


def test_unused_fork_branch_mutation_does_not_taint_trusted_checkout(tmp_path: Path) -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git remote add fork https://github.com/${{ github.event.pull_request.head.repo.full_name }}.git; git fetch fork main; git update-ref refs/heads/review refs/remotes/fork/main; git checkout main; npm ci
"""
    assert not (_findings_for_workflow(tmp_path, workflow) & _LOTP_RULE_IDS)


def test_sibling_repository_ref_mutation_does_not_taint_root_build(tmp_path: Path) -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git -C sibling remote add fork https://github.com/${{ github.event.pull_request.head.repo.full_name }}.git; git -C sibling fetch fork main; git -C sibling update-ref refs/heads/review refs/remotes/fork/main; npm ci
"""
    assert not (_findings_for_workflow(tmp_path, workflow) & _LOTP_RULE_IDS)


def test_branch_inspection_and_push_url_mutation_do_not_taint_build(tmp_path: Path) -> None:
    workflow = """on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - run: git branch --list review; git branch --show-current; git config remote.origin.pushurl https://example.invalid/push.git; git config --get remote.origin.url; npm ci
"""
    assert not (_findings_for_workflow(tmp_path, workflow) & _LOTP_RULE_IDS)
