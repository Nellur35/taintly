"""Finite direct-operation and evidence boundaries, separate from frozen controls."""

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.github.cross_workflow import RULES


def _workflow(event, action, *, mode="", guard="", lookup="", key="shared-fixed-v2"):
    trigger = f"on:\n  {event}:\n"
    if event == "workflow_run":
        trigger += "    workflows: [Build]\n    types: [completed]\n"
    return (
        trigger
        + (f"cache-mode: {mode}\n" if mode else "")
        + "jobs:\n  cache_job:\n    runs-on: ubuntu-latest\n"
        + (f"    if: {guard}\n" if guard else "")
        + f"    steps:\n      - uses: actions/cache/{action}@v4\n"
        + "        with:\n"
        + f"          key: {key}\n          path: .cache/build\n"
        + (f"          lookup-only: {lookup}\n" if lookup else "")
    )


def _findings(root: Path, writer, reader, *, extra_writer=None):
    directory = root / ".github/workflows"
    directory.mkdir(parents=True)
    for name, content in [("writer.yml", writer), ("reader.yml", reader)]:
        (directory / name).write_text(content, encoding="utf-8")
    if extra_writer:
        (directory / "a-other-writer.yml").write_text(extra_writer, encoding="utf-8")
    return [finding for report in scan_repo(str(root), RULES, Platform.GITHUB) for finding in report.findings]


@pytest.mark.parametrize("lookup, count", [("true", 0), ("false", 1), ("${{ vars.LOOKUP_ONLY }}", 1)])
def test_lookup_operation_is_distinct_from_content_restore(tmp_path, lookup, count):
    findings = _findings(
        tmp_path,
        _workflow("pull_request_target", "save", mode="write"),
        _workflow("push", "restore", lookup=lookup, key="shared-fixed"),
    )
    assert len(findings) == count
    if findings:
        assert findings[0].review_needed
        if "${{" in lookup:
            assert any("Lookup-only value is unresolved" in note for note in findings[0].context_notes)


def test_bare_cache_lookup_does_not_disable_post_save(tmp_path):
    writer = _workflow("pull_request_target", "save", mode="write", lookup="true").replace("actions/cache/save@", "actions/cache@")
    assert len(_findings(tmp_path, writer, _workflow("push", "restore", key="shared-fixed"))) == 1


def test_unknown_target_default_without_override_is_review(tmp_path):
    findings = _findings(tmp_path, _workflow("pull_request_target", "save"), _workflow("push", "restore", key="shared-fixed"))
    assert len(findings) == 1
    assert findings[0].review_needed
    assert any("Default-branch identity/access restriction is unresolved" in n for n in findings[0].context_notes)


@pytest.mark.parametrize("guard, count", [
    ("${{ github.base_ref == github.event.repository.default_branch || vars.RUN_EXTRA }}", 1),
    ("${{ !(github.base_ref != github.event.repository.default_branch) }}", 0),
    ("${{ false }}", 0),
])
def test_default_branch_proof_requires_the_owning_predicate(tmp_path, guard, count):
    findings = _findings(tmp_path, _workflow("pull_request_target", "save", guard=guard), _workflow("push", "restore", key="shared-fixed"))
    assert len(findings) == count


def test_write_only_reader_has_no_content_restore(tmp_path):
    assert not _findings(tmp_path, _workflow("pull_request_target", "save", mode="write"), _workflow("push", "restore", mode="write-only", key="shared-fixed"))


def test_flow_mapping_site_has_structural_owner(tmp_path):
    writer = "on: {pull_request_target: {}}\ncache-mode: write\njobs:\n  producer:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/cache/save@v4\n        with: {key: shared-fixed-v2, path: .cache/build}\n"
    findings = _findings(tmp_path, writer, _workflow("push", "restore", key="shared-fixed"))
    assert len(findings) == 1
    assert any("Job 'producer'" in n for n in findings[0].context_notes)


def test_script_data_is_not_fallback_cache_even_with_unrelated_duplicate(tmp_path):
    writer = "name: first\nname: duplicate\non:\n  pull_request_target:\ncache-mode: write\njobs:\n  script:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo data\n          - uses: actions/cache/save@v4\n            with:\n              key: shared-fixed-v2\n              path: .cache/build\n"
    assert not _findings(tmp_path, writer, _workflow("push", "restore", key="shared-fixed"))


def test_ambiguous_mode_cannot_prove_read_only(tmp_path):
    writer = _workflow("pull_request_target", "save", mode="read").replace("cache-mode: read\n", "cache-mode: write\ncache-mode: read\n")
    findings = _findings(tmp_path, writer, _workflow("push", "restore", key="shared-fixed"))
    assert len(findings) == 1
    assert any("structurally unresolved" in n for n in findings[0].context_notes)


def test_literal_shorter_writer_does_not_satisfy_longer_query(tmp_path):
    assert not _findings(tmp_path, _workflow("pull_request_target", "save", mode="write", key="shared-"), _workflow("push", "restore", key="shared-longer"))


def test_dynamic_writer_suffix_can_complete_longer_query(tmp_path):
    findings = _findings(tmp_path, _workflow("pull_request_target", "save", mode="write", key="shared-${{ github.sha }}"), _workflow("push", "restore", key="shared-longer"))
    assert len(findings) == 1
    assert findings[0].review_needed


def test_representative_prefers_package_candidate_and_is_source_bound(tmp_path):
    findings = _findings(
        tmp_path,
        _workflow("pull_request_target", "save", mode="write", key="shared-node_modules-v2"),
        _workflow("push", "restore", key="shared-"),
        extra_writer=_workflow("pull_request_target", "save", mode="write", key="shared-data"),
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "XF-GH-001A"
    assert finding.review_needed
    assert "writer.yml:" in finding.snippet
    assert any("Representative matching writer" in n for n in finding.context_notes)
    assert "removing restore-keys alone does not prevent" in finding.remediation
    assert any("attacker control" in n for n in finding.context_notes)


@pytest.mark.parametrize("event", ["issue_comment", "issues", "discussion", "discussion_comment", "fork", "watch", "workflow_run"])
def test_documented_default_ref_events_are_implicitly_read_only(tmp_path, event):
    assert not _findings(tmp_path, _workflow(event, "save"), _workflow("push", "restore", key="shared-fixed"))


def test_default_ref_event_write_override_retains_review(tmp_path):
    findings = _findings(tmp_path, _workflow("issue_comment", "save", mode="write"), _workflow("push", "restore", key="shared-fixed"))
    assert len(findings) == 1
    assert findings[0].review_needed


def test_workflow_run_can_be_a_privileged_cache_consumer(tmp_path):
    findings = _findings(tmp_path, _workflow("pull_request_target", "save", mode="write"), _workflow("workflow_run", "restore", key="shared-fixed"))
    assert len(findings) == 1
    assert findings[0].review_needed
    assert any("event 'workflow_run'" in n for n in findings[0].context_notes)
