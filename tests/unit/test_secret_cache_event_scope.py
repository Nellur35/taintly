"""Default GitHub cache access depends on the workflow trigger."""

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.github.secret_cache import SecretCachePattern
from taintly.rules.registry import load_rules_for_platform
from taintly.parsers.structural import api as structural_api
from taintly.parsers.structural import query as structural_query
from taintly.parsers.structural.query import triggers

clear_walk_cache = structural_api.clear_walk_cache

RULE_ID = "SEC6-GH-015"


def workflow(
    trigger: str,
    *,
    workflow_mode: str = "",
    job_mode: str = "",
    cache_if: str = "",
    build_if: str = "",
) -> str:
    workflow_mode_line = f"cache-mode: {workflow_mode}\n" if workflow_mode else ""
    job_mode_line = f"    cache-mode: {job_mode}\n" if job_mode else ""
    cache_guard = f"      - if: {cache_if}\n" if cache_if else "      - "
    if cache_if:
        cache_uses = "        uses: actions/cache@v4\n"
    else:
        cache_uses = "uses: actions/cache@v4\n"
    build_guard = f"      - if: {build_if}\n" if build_if else "      - "
    if build_if:
        build_run = "        run: cargo build\n"
    else:
        build_run = "run: cargo build\n"
    return (
        f"on: {trigger}\n"
        + workflow_mode_line
        + "permissions: {contents: read}\n"
        + "jobs:\n  build:\n"
        + "    runs-on: ubuntu-latest\n"
        + job_mode_line
        + "    steps:\n"
        + cache_guard
        + cache_uses
        + "        with:\n          path: target/\n          key: cargo-v1\n"
        + build_guard
        + build_run
        + "        env:\n          SERVICE_TOKEN: ${{ secrets.SERVICE_TOKEN }}\n"
    )


def rule_hits(content: str) -> list[tuple[int, str]]:
    return SecretCachePattern().check(content, content.splitlines())


@pytest.mark.parametrize(
    "trigger",
    [
        "push",
        "workflow_dispatch",
        "repository_dispatch",
        "delete",
        "registry_package",
        "page_build",
        "schedule",
    ],
)
def test_default_trusted_events_can_save_secret_bearing_cache(trigger):
    assert rule_hits(workflow(trigger))


def test_release_default_cache_mode_is_read_only():
    assert rule_hits(workflow("release")) == []


def test_release_write_only_mode_enables_cache_writer():
    assert rule_hits(workflow("release", workflow_mode="write-only"))


def test_job_none_mode_overrides_workflow_write_mode():
    assert rule_hits(workflow("push", workflow_mode="write", job_mode="none")) == []


def test_low_trust_event_with_explicit_write_mode_is_reported():
    assert rule_hits(workflow("workflow_run", job_mode="write"))


@pytest.mark.parametrize(
    "workflow_mode,job_mode,expected",
    [
        ("write", "", True),
        ("", "write", True),
        ("read", "write", True),
        ("write", "read", False),
    ],
)
def test_explicit_cache_mode_overrides_event_default(workflow_mode, job_mode, expected):
    assert bool(rule_hits(workflow("release", workflow_mode=workflow_mode, job_mode=job_mode))) == expected


@pytest.mark.parametrize("trigger", ["pull_request_target", "issue_comment", "workflow_run"])
def test_low_trust_events_default_to_read_only(trigger):
    assert rule_hits(workflow(trigger)) == []


def test_pull_request_merge_ref_is_not_a_shared_cache_writer_even_with_write_mode():
    assert rule_hits(workflow("pull_request", workflow_mode="write")) == []
    assert rule_hits(workflow("pull_request", job_mode="write")) == []


def test_disjoint_event_guards_do_not_join_cache_and_secret_output():
    content = workflow(
        "[delete, release]",
        cache_if="github.event_name == 'delete'",
        build_if="github.event_name == 'release'",
    )
    assert rule_hits(content) == []


def test_mixed_event_workflow_reports_matching_guarded_writer():
    content = workflow(
        "[delete, release]",
        cache_if="github.event_name == 'delete'",
        build_if="github.event_name == 'delete'",
    )
    assert rule_hits(content)


def test_unknown_guard_remains_conservative_for_mixed_events():
    content = workflow(
        "[delete, release]",
        cache_if="github.event_name == 'not-real'",
        build_if="github.event_name == 'not-real'",
    )
    assert rule_hits(content)


def test_release_guarded_steps_do_not_write_under_default_read_only_mode():
    content = workflow(
        "[delete, release]",
        cache_if="github.event_name == 'release'",
        build_if="github.event_name == 'release'",
    )
    assert rule_hits(content) == []


def engine_hits(tmp_path: Path, content: str):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    (workflows / "cache.yml").write_text(content, encoding="utf-8")
    return [
        finding
        for report in scan_repo(str(tmp_path), load_rules_for_platform(Platform.GITHUB))
        for finding in report.findings
        if finding.rule_id == RULE_ID
    ]


def test_full_engine_reports_trusted_delete_cache_writer(tmp_path):
    assert engine_hits(tmp_path, workflow("delete"))


def test_full_engine_does_not_report_default_release_cache_write(tmp_path):
    assert engine_hits(tmp_path, workflow("release")) == []


def test_trigger_query_and_secret_cache_rule_share_one_structural_parse(monkeypatch):
    content = workflow("push")
    clear_walk_cache()
    calls = []
    api_walk = structural_api._walk
    query_walk = getattr(structural_query, "_walk", api_walk)

    def counted_api_walk(*args, **kwargs):
        calls.append("raw-walk")
        return api_walk(*args, **kwargs)

    def counted_query_walk(*args, **kwargs):
        calls.append("raw-walk")
        return query_walk(*args, **kwargs)

    monkeypatch.setattr(structural_api, "_walk", counted_api_walk)
    monkeypatch.setattr(structural_query, "_walk", counted_query_walk, raising=False)
    assert triggers(content) == frozenset({"push"})
    assert rule_hits(content)
    assert calls == ["raw-walk"]
    clear_walk_cache()
