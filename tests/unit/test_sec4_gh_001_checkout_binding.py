"""SEC4-GH-001 must bind PR provenance to the checkout ref."""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_all_rules


def _write_workflow(root: Path, content: str) -> None:
    path = root / ".github" / "workflows" / "ci.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _sec4_gh_001(root: Path) -> list:
    reports = scan_repo(str(root), load_all_rules(), Platform.GITHUB)
    return [
        finding
        for report in reports
        for finding in report.findings
        if finding.rule_id == "SEC4-GH-001"
    ]


def test_pull_request_head_sha_used_for_metadata_with_default_checkout_is_clean(
    tmp_path: Path,
) -> None:
    _write_workflow(
        tmp_path,
        """name: Label approval
on:
  pull_request_target:
    types: [labeled]
jobs:
  approve:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
      - name: Find pending run
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SHA: ${{ github.event.pull_request.head.sha }}
        run: gh run list -c "$SHA" -s action_required
""",
    )

    assert _sec4_gh_001(tmp_path) == []


@pytest.mark.parametrize(
    "head_reference",
    [
        "${{ github.event.pull_request.head.sha }}",
        "${{ github.event.pull_request.head.ref }}",
        "${{ github['event']['pull_request']['head']['sha'] }}",
        "${{ GITHUB.event.pull_request.head.ref }}",
    ],
)
def test_pull_request_head_reference_in_checkout_with_mapping_is_positive(
    tmp_path: Path, head_reference: str
) -> None:
    _write_workflow(
        tmp_path,
        f"""on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with: {{ ref: \"{head_reference}\" }}
      - run: make test
""",
    )

    assert len(_sec4_gh_001(tmp_path)) == 1


@pytest.mark.parametrize(
    "metadata_step",
    [
        """      - name: Query run by SHA
        env:
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: gh run list -c "$HEAD_SHA"
""",
        """      - name: Query run by SHA
        run: gh run list -c "$HEAD_SHA"
        env:
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
""",
        """      - uses: actions/github-script@v7
        with:
          commit_sha: ${{ github.event.pull_request.head.sha }}
          script: console.log('approve')
""",
    ],
)
def test_head_metadata_unrelated_to_default_checkout_is_clean(
    tmp_path: Path, metadata_step: str
) -> None:
    _write_workflow(
        tmp_path,
        """on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
"""
        + metadata_step,
    )

    assert _sec4_gh_001(tmp_path) == []


def test_nested_with_ref_and_fake_run_checkout_are_not_real_checkouts(
    tmp_path: Path,
) -> None:
    _write_workflow(
        tmp_path,
        """on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: example/metadata-action@v1
        with:
          settings:
            ref: ${{ github.event.pull_request.head.sha }}
      - run: |
          echo "uses: actions/checkout@v4"
          echo "git checkout ${{ github.event.pull_request.head.sha }}"
""",
    )

    assert _sec4_gh_001(tmp_path) == []


def test_step_env_alias_precedence_preserves_pr_head_source(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        """on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      CHECKOUT_REF: refs/heads/main
    steps:
      - uses: actions/checkout@v5
        env:
          CHECKOUT_REF: ${{ github.event.pull_request.head.sha }}
        with:
          ref: ${{ env.CHECKOUT_REF }}
""",
    )

    assert len(_sec4_gh_001(tmp_path)) == 1


@pytest.mark.parametrize(
    "step_env",
    [
        """          PR_HEAD: ${{ github.event.pull_request.head.sha }}
          CHECKOUT_REF: ${{ env.PR_HEAD }}
""",
        """          REF_A: ${{ env.REF_B }}
          REF_B: ${{ env.REF_A }}
          PR_HEAD: ${{ github.event.pull_request.head.sha }}
          CHECKOUT_REF: ${{ env.REF_A }}
""",
        """          PR_HEAD: ${{ github.event.pull_request.head.sha }}
          CHECKOUT_REF: ${{ env.UNRESOLVED_REF }}
""",
    ],
)
def test_env_alias_cycle_or_unresolved_ref_with_pr_source_stays_conservative(
    tmp_path: Path, step_env: str
) -> None:
    _write_workflow(
        tmp_path,
        """on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        env:
"""
        + step_env
        + """        with:
          ref: ${{ env.CHECKOUT_REF }}
""",
    )

    assert len(_sec4_gh_001(tmp_path)) == 1


def test_yaml_alias_preserves_pr_head_checkout_provenance(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        """on: pull_request_target
env:
  PR_HEAD: &pr_head "${{ github.event.pull_request.head.sha }}"
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          ref: *pr_head
""",
    )

    assert len(_sec4_gh_001(tmp_path)) == 1


@pytest.mark.parametrize(
    "trigger",
    [
        "on: [pull_request_target, push]",
        "on: { pull_request_target: { types: [opened] } }",
    ],
)
def test_root_list_and_flow_mapping_pull_request_target_triggers_are_positive(
    tmp_path: Path, trigger: str
) -> None:
    _write_workflow(
        tmp_path,
        f"""{trigger}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          ref: "${{{{ github.event.pull_request.head.sha }}}}"
""",
    )

    assert len(_sec4_gh_001(tmp_path)) == 1


def test_pull_request_head_checkout_remains_positive_when_persist_credentials_false(
    tmp_path: Path,
) -> None:
    _write_workflow(
        tmp_path,
        """on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make test
""",
    )

    assert len(_sec4_gh_001(tmp_path)) == 1


def test_mixed_default_and_pull_request_head_checkouts_remain_positive(
    tmp_path: Path,
) -> None:
    _write_workflow(
        tmp_path,
        """on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/checkout@v5
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make test
""",
    )

    assert len(_sec4_gh_001(tmp_path)) == 1


def test_comment_mentioning_pull_request_target_does_not_create_trigger(
    tmp_path: Path,
) -> None:
    _write_workflow(
        tmp_path,
        """on: push
# pull_request_target is only mentioned in this comment
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make test
""",
    )

    assert _sec4_gh_001(tmp_path) == []


def test_structural_cutoff_is_reported_instead_of_silently_cleared(
    tmp_path: Path,
) -> None:
    _write_workflow(
        tmp_path,
        """on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          ref: main
%YAML 1.2
""",
    )

    findings = _sec4_gh_001(tmp_path)
    assert len(findings) == 1
    assert findings[0].snippet.startswith("STRUCTURAL-CUTOFF:")
