"""Secret/cache detection and parser integration contracts.

Registry loading exercises automatic rule discovery without importing the
concrete detector class.
"""

from pathlib import Path

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.parsers.gha_expr import iter_expression_bodies, result_provenance_paths
from taintly.parsers.structural import query as structural_query
from taintly.parsers.structural import triggers
from taintly.parsers.structural import api as structural_api
from taintly.parsers.structural.api import clear_walk_cache, walk_workflow
from taintly.rules.registry import load_rules_for_platform

RULE_ID = "SEC6-GH-015"


def _cache_workflow(secret_expression: str) -> str:
    return (
        "on: push\n"
        "permissions: {contents: read}\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/cache@v4\n"
        "        with: {path: target/, key: cargo-v1}\n"
        "      - run: cargo build\n"
        "        env:\n"
        f"          SERVICE_TOKEN: ${{{{ {secret_expression} }}}}\n"
    )


def _scan_rule_ids(tmp_path: Path, content: str) -> set[str]:
    workflow = tmp_path / ".github" / "workflows" / "cache.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(content, encoding="utf-8")
    rules = load_rules_for_platform(Platform.GITHUB)
    return {
        finding.rule_id
        for report in scan_repo(str(tmp_path), rules)
        for finding in report.findings
    }


def test_full_engine_reports_secret_bearing_cache_write(tmp_path: Path) -> None:
    assert RULE_ID in _scan_rule_ids(tmp_path, _cache_workflow("secrets.SERVICE_TOKEN"))


def test_full_engine_keeps_public_value_cache_control_clean(tmp_path: Path) -> None:
    assert RULE_ID not in _scan_rule_ids(tmp_path, _cache_workflow("vars.PUBLIC_VALUE"))


def test_quoted_format_braces_do_not_hide_secret_expression_provenance() -> None:
    expression = "${{ format('/{0}/compare/{{base}}...{{head}}', secrets.TOKEN) }}"
    bodies = list(iter_expression_bodies(expression))
    assert len(bodies) == 1
    assert "secrets.TOKEN" in bodies[0]
    assert "secrets.token" in result_provenance_paths(bodies[0])


def test_compact_json_quoted_flow_keys_are_structural_triggers() -> None:
    compact = (
        '{"on":"push","jobs":{"build":{"runs-on":"ubuntu-latest",'
        '"steps":[{"run":"echo hi"}]}}}'
    )
    assert triggers(compact) == frozenset({"push"})


def test_trigger_query_and_matching_cached_walk_share_one_raw_parse(monkeypatch) -> None:
    content = "on: push\njobs:\n  build:\n    steps:\n      - run: echo hi\n"
    clear_walk_cache()
    calls: list[None] = []
    api_walk = structural_api._walk
    query_walk = getattr(structural_query, "_walk", api_walk)

    def count_api_walk(*args, **kwargs):
        calls.append(None)
        return api_walk(*args, **kwargs)

    def count_query_walk(*args, **kwargs):
        calls.append(None)
        return query_walk(*args, **kwargs)

    monkeypatch.setattr(structural_api, "_walk", count_api_walk)
    monkeypatch.setattr(structural_query, "_walk", count_query_walk, raising=False)
    assert triggers(content) == frozenset({"push"})
    assert list(walk_workflow("workflow.yml", content=content, include_keys=True, recover=True))
    assert len(calls) == 1
    clear_walk_cache()
