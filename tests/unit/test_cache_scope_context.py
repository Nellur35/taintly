"""Source-labeled contracts for cross-workflow GitHub cache scope.

These fixtures distinguish cache *key* overlap from the branch/ref namespace
and access mode that lets one workflow save an entry another can restore.
The scanner must retain uncertain branch/mode cases as review candidates.

Provider sources: the current GitHub.com dependency-caching reference documents
pull-request merge-ref isolation and low-trust cache modes at
https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching.
GitHub Enterprise Server 3.21/3.22 documents the same merge-ref and low-trust
defaults, but its workflow-syntax docs do not list ``cache-mode``. The dynamic
mode control below is therefore YAML-valid but explicitly schema-unresolved.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_all_rules

_CACHE_RULE_IDS = {"XF-GH-001", "XF-GH-001A"}
_KEY = "linux-build-${{ github.sha }}"


def _write_pair(tmp_path: Path, writer: str, reader: str) -> list:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    (workflows / "writer.yml").write_text(writer, encoding="utf-8")
    (workflows / "reader.yml").write_text(reader, encoding="utf-8")
    reports = scan_repo(str(tmp_path), load_all_rules(), Platform.GITHUB)
    return [
        finding
        for report in reports
        for finding in report.findings
        if finding.rule_id in _CACHE_RULE_IDS
    ]


def _writer(
    trigger: str,
    *,
    key: str = _KEY,
    workflow_mode: str = "",
    job_mode: str = "",
    job_if: str = "",
    step_if: str = "",
    extra_job: str = "",
) -> str:
    mode = f"cache-mode: {workflow_mode}\n" if workflow_mode else ""
    job_mode_line = f"    cache-mode: {job_mode}\n" if job_mode else ""
    job_if_line = f"    if: ${{{{ {job_if} }}}}\n" if job_if else ""
    step_if_line = f"        if: ${{{{ {step_if} }}}}\n" if step_if else ""
    return (
        "name: Cache producer\n"
        f"on:\n{trigger}\n"
        f"{mode}"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        f"{job_if_line}"
        f"{job_mode_line}"
        "    steps:\n"
        f"      - uses: actions/cache@v4\n"
        f"{step_if_line}"
        "        with:\n"
        f"          key: {key}\n"
        "          path: .cache/build\n"
        f"{extra_job}"
    )


def _reader(
    *,
    key: str = _KEY,
    restore_keys: str | None = "linux-build-",
    job_mode: str = "",
    step_if: str = "",
) -> str:
    job_mode_line = f"    cache-mode: {job_mode}\n" if job_mode else ""
    step_if_line = f"        if: ${{{{ {step_if} }}}}\n" if step_if else ""
    restore_keys_line = (
        f"          restore-keys: {restore_keys}\n" if restore_keys is not None else ""
    )
    return (
        "name: Cache consumer\n"
        "on:\n  push:\n"
        "jobs:\n"
        "  consume:\n"
        "    runs-on: ubuntu-latest\n"
        f"{job_mode_line}"
        "    steps:\n"
        "      - uses: actions/cache/restore@v4\n"
        f"{step_if_line}"
        "        with:\n"
        f"          key: {key}\n"
        f"{restore_keys_line}"
        "          path: .cache/build\n"
    )


def _known_default_target_guard() -> str:
    # Source witness: the job runs only when the PR base equals the repository
    # default branch; a pull_request_target event alone does not prove that.
    return (
        "github.event.pull_request.base.ref == "
        "github.event.repository.default_branch"
    )


def _assert_no_candidate(findings: list) -> None:
    assert findings == []


def _assert_review_candidate(findings: list) -> None:
    assert len(findings) == 1
    assert findings[0].rule_id in _CACHE_RULE_IDS
    assert findings[0].review_needed is True


def test_pr_cache_is_merge_ref_isolated_even_with_write_mode(tmp_path: Path) -> None:
    """SRC-CACHE-01: `pull_request` writes to its merge-ref scope."""
    findings = _write_pair(
        tmp_path,
        _writer("  pull_request:\n", workflow_mode="write"),
        _reader(),
    )
    _assert_no_candidate(findings)


def test_dual_push_and_pr_writer_does_not_join_pr_cache_to_push_reader(
    tmp_path: Path,
) -> None:
    """SRC-CACHE-02: the untrusted PR run remains merge-ref scoped."""
    findings = _write_pair(
        tmp_path,
        _writer("  push:\n  pull_request:\n"),
        _reader(),
    )
    _assert_no_candidate(findings)


def test_default_branch_target_without_override_is_read_only(
    tmp_path: Path,
) -> None:
    """SRC-CACHE-03: explicit base/default equality proves the target branch."""
    findings = _write_pair(
        tmp_path,
        _writer(
            "  pull_request_target:\n",
            job_if=_known_default_target_guard(),
        ),
        _reader(),
    )
    _assert_no_candidate(findings)


def test_default_branch_target_workflow_write_override_is_candidate(
    tmp_path: Path,
) -> None:
    """SRC-CACHE-04: workflow-level write override permits a cache save."""
    findings = _write_pair(
        tmp_path,
        _writer(
            "  pull_request_target:\n",
            key="node_modules-${{ github.sha }}",
            workflow_mode="write",
            job_if=_known_default_target_guard(),
        ),
        _reader(key="node_modules-${{ github.sha }}", restore_keys="node_modules-"),
    )
    _assert_review_candidate(findings)


def test_default_branch_target_job_write_override_is_candidate(
    tmp_path: Path,
) -> None:
    """SRC-CACHE-05: job-level write overrides the workflow-level mode."""
    findings = _write_pair(
        tmp_path,
        _writer(
            "  pull_request_target:\n",
            key="linux-build-${{ github.ref }}",
            workflow_mode="read",
            job_mode="write",
            job_if="github.ref == 'refs/heads/main'",
        ),
        _reader(key="linux-build-${{ github.ref }}"),
    )
    _assert_review_candidate(findings)


@pytest.mark.parametrize("mode", ["read", "none"])
def test_job_read_or_none_overrides_workflow_write(
    tmp_path: Path,
    mode: str,
) -> None:
    """SRC-CACHE-06/07: job access mode owns its cache writer."""
    findings = _write_pair(
        tmp_path,
        _writer(
            "  pull_request_target:\n",
            workflow_mode="write",
            job_mode=mode,
            job_if=_known_default_target_guard(),
        ),
        _reader(),
    )
    _assert_no_candidate(findings)


def test_reader_none_mode_cannot_consume_a_matching_cache(
    tmp_path: Path,
) -> None:
    """SRC-CACHE-08: reader mode is part of the cross-workflow join."""
    findings = _write_pair(
        tmp_path,
        _writer(
            "  pull_request_target:\n",
            workflow_mode="write",
            job_if=_known_default_target_guard(),
        ),
        _reader(job_mode="none"),
    )
    _assert_no_candidate(findings)


def test_push_guarded_writer_is_not_a_fork_cache_writer(
    tmp_path: Path,
) -> None:
    """SRC-CACHE-09: event-specific step guard removes the PR write path."""
    findings = _write_pair(
        tmp_path,
        _writer(
            "  push:\n  pull_request_target:\n",
            workflow_mode="write",
            step_if="github.event_name == 'push'",
        ),
        _reader(),
    )
    _assert_no_candidate(findings)


def test_pull_request_target_guarded_reader_is_not_a_push_reader(
    tmp_path: Path,
) -> None:
    """SRC-CACHE-10: reader step condition excludes the push event."""
    findings = _write_pair(
        tmp_path,
        _writer(
            "  pull_request_target:\n",
            workflow_mode="write",
            job_if=_known_default_target_guard(),
        ),
        _reader(step_if="github.event_name == 'pull_request_target'"),
    )
    _assert_no_candidate(findings)


def test_dynamic_cache_mode_keeps_review_candidate(tmp_path: Path) -> None:
    """SRC-CACHE-11: an expression-valued mode is not assumed read-only."""
    # YAML-valid control. Whether GitHub accepts expressions for this enum
    # field is platform-schema dependent and intentionally unresolved here.
    writer = _writer(
        "  pull_request_target:\n",
        job_if=_known_default_target_guard(),
    ).replace(
        "    runs-on: ubuntu-latest\n",
        "    runs-on: ubuntu-latest\n"
        "    cache-mode: ${{ vars.CACHE_MODE }}\n",
        1,
    )
    findings = _write_pair(tmp_path, writer, _reader())
    _assert_review_candidate(findings)


def test_branch_filter_without_default_branch_identity_keeps_candidate(
    tmp_path: Path,
) -> None:
    """SRC-CACHE-12: a PR branch filter does not identify the default branch."""
    findings = _write_pair(
        tmp_path,
        _writer(
            "  pull_request_target:\n    branches: ['release/**']\n",
            workflow_mode="write",
        ),
        _reader(),
    )
    _assert_review_candidate(findings)


def test_sibling_job_write_mode_does_not_authorize_cache_job(
    tmp_path: Path,
) -> None:
    """SRC-CACHE-13: a sibling job's mode cannot grant this job cache writes."""
    sibling = (
        "  unrelated:\n"
        "    runs-on: ubuntu-latest\n"
        "    cache-mode: write\n"
        "    steps:\n"
        "      - run: echo unrelated\n"
    )
    findings = _write_pair(
        tmp_path,
        _writer(
            "  pull_request_target:\n",
            job_if=_known_default_target_guard(),
            extra_job=sibling,
        ),
        _reader(),
    )
    _assert_no_candidate(findings)


def test_primary_key_prefix_can_match_without_restore_keys(tmp_path: Path) -> None:
    """SRC-CACHE-14: the primary key itself has partial-match semantics."""
    findings = _write_pair(
        tmp_path,
        _writer(
            "  pull_request_target:\n",
            key="linux-build-fixed-v2",
            workflow_mode="write",
            job_if=_known_default_target_guard(),
        ),
        _reader(key="linux-build-fixed", restore_keys=None),
    )
    _assert_review_candidate(findings)
