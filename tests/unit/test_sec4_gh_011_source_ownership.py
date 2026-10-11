from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform

_TRIGGER = "on:\n  pull_request_target:\njobs:\n"


def _scan(tmp_path: Path, workflow: str) -> set[str]:
    path = tmp_path / "workflow.yml"
    path.write_text(workflow, encoding="utf-8")
    return {
        finding.rule_id
        for finding in scan_file(str(path), load_rules_for_platform(Platform.GITHUB))
    }


def test_sec4_gh_011_suppresses_build_from_default_pull_request_target_checkout(
    tmp_path: Path,
) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        + "      - uses: actions/checkout@v7\n"
        + "      - run: make test\n"
    )

    assert "SEC4-GH-011" not in _scan(tmp_path, workflow)


def test_sec4_gh_011_retains_explicit_fork_checkout_build(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        + "      - uses: actions/checkout@v6\n        with:\n"
        + "          ref: ${{ github.event.pull_request.head.sha }}\n"
        + "      - run: npm ci && npm test\n"
    )

    assert "SEC4-GH-011" in _scan(tmp_path, workflow)


def test_sec4_gh_011_keeps_no_checkout_as_unknown_review_candidate(tmp_path: Path) -> None:
    workflow = _TRIGGER + "  build:\n    steps:\n      - run: python -m build\n"

    assert "SEC4-GH-011" in _scan(tmp_path, workflow)
    findings = scan_file(str(tmp_path / "workflow.yml"), load_rules_for_platform(Platform.GITHUB))
    candidate = next(f for f in findings if f.rule_id == "SEC4-GH-011")
    assert candidate.review_needed is True
    assert candidate.confidence == "medium"


def test_sec4_gh_011_keeps_dynamic_checkout_as_unknown_review_candidate(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - uses: actions/checkout@v6\n        with:\n"
        + "          ref: ${{ inputs.ref }}\n"
        + "      - run: make test\n"
    )

    assert "SEC4-GH-011" in _scan(tmp_path, workflow)


def test_sec4_gh_011_checkout_after_build_does_not_retroactively_bind_source(
    tmp_path: Path,
) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - run: make test\n"
        + "      - uses: actions/checkout@v7\n"
    )

    assert "SEC4-GH-011" in _scan(tmp_path, workflow)


def test_sec4_gh_011_keeps_v7_fork_checkout_when_unsafe_opt_in_is_true(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - uses: actions/checkout@v7\n        with:\n"
        + "          ref: ${{ github.event.pull_request.head.sha }}\n"
        + "          allow-unsafe-pr-checkout: true\n"
        + "      - run: make test\n"
    )

    assert "SEC4-GH-011" in _scan(tmp_path, workflow)


def test_sec4_gh_011_keeps_v7_fork_ref_as_review_candidate_without_opt_in(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - uses: actions/checkout@v7\n        with:\n"
        + "          ref: ${{ github.event.pull_request.head.sha }}\n"
        + "      - run: make test\n"
    )

    assert "SEC4-GH-011" in _scan(tmp_path, workflow)


def test_sec4_gh_011_does_not_infer_checkout_opt_in_for_older_pins(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - uses: actions/checkout@v6\n        with:\n"
        + "          ref: ${{ github.event.pull_request.head.sha }}\n"
        + "          allow-unsafe-pr-checkout: false\n"
        + "      - run: make test\n"
    )

    assert "SEC4-GH-011" in _scan(tmp_path, workflow)


def test_sec4_gh_011_checkout_and_build_source_are_job_scoped(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  untrusted:\n    steps:\n"
        + "      - uses: actions/checkout@v6\n        with:\n"
        + "          ref: ${{ github.event.pull_request.head.sha }}\n"
        + "  trusted:\n    steps:\n"
        + "      - uses: actions/checkout@v7\n"
        + "      - run: make test\n"
    )

    assert "SEC4-GH-011" not in _scan(tmp_path, workflow)


def test_sec4_gh_011_trusted_git_reset_before_build_is_not_pr_source(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - uses: actions/checkout@v6\n        with:\n"
        + "          ref: ${{ github.event.pull_request.head.sha }}\n"
        + "      - run: git checkout main && make test\n"
    )

    assert "SEC4-GH-011" not in _scan(tmp_path, workflow)


def test_sec4_gh_011_flow_checkout_path_binds_subdirectory_build(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - uses: actions/checkout@v6\n"
        + '        with: { ref: "${{ github.event.pull_request.head.sha }}", path: fork-tree }\n'
        + "      - run: cd fork-tree && make test\n"
    )

    assert "SEC4-GH-011" in _scan(tmp_path, workflow)


def test_sec4_gh_011_flow_checkout_path_does_not_taint_root_build(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - uses: actions/checkout@v6\n"
        + '        with: { ref: "${{ github.event.pull_request.head.sha }}", path: fork-tree }\n'
        + "      - run: make test\n"
    )

    assert "SEC4-GH-011" not in _scan(tmp_path, workflow)


def test_sec4_gh_011_flow_checkout_default_ref_is_trusted(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - uses: actions/checkout@v6\n"
        + "        with: { path: fork-tree }\n"
        + "      - run: cd fork-tree && make test\n"
    )

    assert "SEC4-GH-011" not in _scan(tmp_path, workflow)


def test_sec4_gh_011_same_repository_default_checkout_is_trusted(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - uses: actions/checkout@v6\n"
        + '        with: { repository: "${{ github.repository }}", path: fork-tree }\n'
        + "      - run: cd fork-tree && make test\n"
    )

    assert "SEC4-GH-011" not in _scan(tmp_path, workflow)


def test_sec4_gh_011_unknown_git_source_selection_remains_candidate(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - uses: actions/checkout@v6\n"
        + "      - run: git fetch origin '${{ inputs.pr_ref }}' && git checkout FETCH_HEAD && make test\n"
    )

    assert "SEC4-GH-011" in _scan(tmp_path, workflow)


def test_sec4_gh_011_duplicate_checkout_inputs_remain_unknown(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - uses: actions/checkout@v6\n        with:\n"
        + "          ref: main\n"
        + "          ref: ${{ github.event.pull_request.head.sha }}\n"
        + "      - run: make test\n"
    )

    assert "SEC4-GH-011" in _scan(tmp_path, workflow)


def test_sec4_gh_011_duplicate_with_containers_remain_unknown(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - uses: actions/checkout@v6\n"
        + "        with: { ref: main }\n"
        + '        with: { ref: "${{ github.event.pull_request.head.sha }}" }\n'
        + "      - run: make test\n"
    )

    assert "SEC4-GH-011" in _scan(tmp_path, workflow)


def test_sec4_gh_011_duplicate_uses_keys_remain_unknown(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - uses: actions/checkout@v6\n"
        + "        uses: actions/checkout@v7\n"
        + "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        + "      - run: make test\n"
    )

    assert "SEC4-GH-011" in _scan(tmp_path, workflow)


def test_sec4_gh_011_unresolved_checkout_alias_remains_unknown(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - uses: actions/checkout@v6\n"
        + "        with: *checkout-inputs\n"
        + "      - run: make test\n"
    )

    assert "SEC4-GH-011" in _scan(tmp_path, workflow)


def test_sec4_gh_011_unresolved_checkout_field_alias_remains_unknown(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - uses: actions/checkout@v6\n        with:\n"
        + "          ref: *checkout-ref\n"
        + "      - run: make test\n"
    )

    assert "SEC4-GH-011" in _scan(tmp_path, workflow)


def test_sec4_gh_011_incomplete_checkout_flow_mapping_remains_unknown(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - uses: actions/checkout@v6\n"
        + '        with: { ref: "${{ inputs.ref }}", path: fork-tree\n'
        + "      - run: cd fork-tree && make test\n"
    )

    assert "SEC4-GH-011" in _scan(tmp_path, workflow)


def test_sec4_gh_011_metadata_and_comments_are_not_build_sinks(tmp_path: Path) -> None:
    workflow = (
        _TRIGGER
        + "  build:\n    steps:\n"
        + "      - name: npm install is documented here\n"
        + "        env:\n          COMMAND: make test\n"
        + "        with:\n          note: python -m build\n"
        + "      # run: npm install\n"
        + "      - run: echo 'make sure the docs are read'\n"
    )

    assert "SEC4-GH-011" not in _scan(tmp_path, workflow)


def test_sec4_gh_011_retains_candidate_when_step_segmentation_is_unavailable(
    tmp_path: Path,
) -> None:
    workflow = "on: pull_request_target\nrun: npm install\n"

    assert "SEC4-GH-011" in _scan(tmp_path, workflow)


@pytest.mark.parametrize("header", ["| # executable build", "|- # build", "> # build", "|2", ">2- # build", "|+2 # build"])
@pytest.mark.parametrize("fork", [True, False])
def test_sec4_gh_011_valid_block_headers_preserve_build_source(
    tmp_path: Path, header: str, fork: bool,
) -> None:
    checkout = "      - uses: actions/checkout@v6\n"
    if fork:
        checkout += "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    workflow = (
        _TRIGGER + "  build:\n    steps:\n" + checkout
        + f"      - run: {header}\n          make test\n"
    )
    assert ("SEC4-GH-011" in _scan(tmp_path, workflow)) is fork


def test_sec4_gh_011_commented_block_tracks_unknown_fetch_after_trusted_checkout(
    tmp_path: Path,
) -> None:
    workflow = (
        _TRIGGER + "  build:\n    steps:\n"
        + "      - uses: actions/checkout@v6\n"
        + "      - run: | # source changes still execute\n"
        + "          git fetch origin $REF\n          git checkout FETCH_HEAD\n"
        + "          make test\n"
    )
    assert "SEC4-GH-011" in _scan(tmp_path, workflow)
