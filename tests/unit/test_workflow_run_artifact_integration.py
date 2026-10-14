from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from taintly.models import IncompletePatternMatches, Platform, Severity
from tests.unit._workflow_run_artifact_sources import (
    CASE_EXEC,
    CASE_DATA,
    CASE_UNKNOWN,
    CONSUMERS,
)
from taintly.rules.registry import load_rules_for_platform

DRAFT_ROOT = Path(__file__).resolve().parents[2]
RULE_ID = "SEC4-GH-023"
_FALSE_GUARD = (
    "if: github.event.workflow_run.event == 'pull_request' && "
    "github.event.workflow_run.conclusion == 'success'"
)


def _rule():
    return next(
        rule for rule in load_rules_for_platform(Platform.GITHUB) if rule.id == RULE_ID
    )


def _source(case: str) -> str:
    return CONSUMERS[case]


def _false_consumer(source: str) -> str:
    assert source.count(_FALSE_GUARD) == 1
    return source.replace(_FALSE_GUARD, "if: false")


def _write_workflow(root: Path, name: str, source: str) -> Path:
    path = root / ".github" / "workflows" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8", newline="\n")
    return path


def _cli(path: Path) -> dict:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(DRAFT_ROOT)
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "taintly",
            str(path),
            "--platform",
            "github",
            "--format",
            "json",
            "--no-color",
        ],
        cwd=DRAFT_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)
    assert completed.returncode in (0, 11)
    if completed.returncode == 11:
        assert result["engine_error_count"] > 0
    return result


def test_rule_metadata_and_exact_physical_consumer_occurrence() -> None:
    rule = _rule()
    assert rule.severity is Severity.MEDIUM
    assert rule.review_needed is True
    assert rule.confidence == "medium"
    assert rule.pattern.check(rule.test_positive[0], rule.test_positive[0].splitlines())
    assert not rule.pattern.check(
        rule.test_negative[0], rule.test_negative[0].splitlines()
    )
    source = _source(CASE_EXEC)
    matches = rule.pattern.check_with_filepath(
        source, source.splitlines(), "explicit.yml"
    )
    assert matches == [(24, "run: bash incoming/preview.sh")]
    notes = rule.pattern.context_notes_for_matches(source, "explicit.yml", matches)
    assert notes[0] is not None
    joined = "\n".join(notes[0].notes)
    assert "producer identity" in joined
    assert "PR origin remain unresolved" in joined
    assert "PREVIEW_SECRET" in joined


def test_candidate_exploitability_cap_is_rule_specific() -> None:
    from taintly.families import classify_rule
    from taintly.workflow_context import WorkflowContext, compute_exploitability

    assert classify_rule(RULE_ID) == "untrusted_code_execution"

    privileged_secret_context = WorkflowContext(
        has_privileged_fork_trigger=True,
        has_secrets_reference=True,
    )
    assert (
        compute_exploitability(
            "untrusted_code_execution",
            privileged_secret_context,
            rule_id=RULE_ID,
        )
        == "medium"
    )
    assert (
        compute_exploitability(
            "untrusted_code_execution",
            privileged_secret_context,
            rule_id="SEC6-GH-007",
        )
        == "high"
    )
    assert (
        compute_exploitability(
            "script_injection",
            privileged_secret_context,
            rule_id="SEC4-GH-021",
        )
        == "high"
    )


def test_data_false_consumer_unknown_and_incomplete_api_outcomes() -> None:
    pattern = _rule().pattern
    data = _source(CASE_DATA)
    assert pattern.check_with_filepath(data, data.splitlines(), "data.yml") == []

    false_source = _false_consumer(_source(CASE_EXEC))
    assert (
        pattern.check_with_filepath(
            false_source, false_source.splitlines(), "false.yml"
        )
        == []
    )

    unknown = _source(CASE_UNKNOWN)
    unknown_matches = pattern.check_with_filepath(
        unknown, unknown.splitlines(), "unknown.yml"
    )
    assert len(unknown_matches) == 1
    context = pattern.context_notes_for_matches(unknown, "unknown.yml", unknown_matches)
    assert context[0] is not None
    assert any(
        "origin" in note.lower() and "unresolved" in note.lower()
        for note in context[0].notes
    )

    malformed = _source(CASE_EXEC).replace("path: incoming\n", "path: ../incoming\n")
    incomplete = pattern.check_with_filepath(
        malformed, malformed.splitlines(), "incomplete.yml"
    )
    assert isinstance(incomplete, IncompletePatternMatches)
    assert incomplete == []
    assert "destination" in incomplete.reason or "path" in incomplete.reason


def test_actual_cli_mixed_file_scan_and_explicit_file_path(tmp_path: Path) -> None:
    positive = _source(CASE_EXEC)
    data = _source(CASE_DATA)
    false = _false_consumer(positive)
    unknown = _source(CASE_UNKNOWN)
    malformed = positive.replace("path: incoming\n", "path: ../incoming\n")
    _write_workflow(tmp_path, "positive.yml", positive)
    _write_workflow(tmp_path, "data.yml", data)
    _write_workflow(tmp_path, "false.yml", false)
    _write_workflow(tmp_path, "unknown.yml", unknown)
    _write_workflow(tmp_path, "incomplete.yml", malformed)

    repo_result = _cli(tmp_path)
    assert repo_result["files_scanned"] == 5
    hits = [
        finding for finding in repo_result["findings"] if finding["rule_id"] == RULE_ID
    ]
    assert len(hits) == 2
    by_file = {Path(finding["file"]).name: finding for finding in hits}
    assert set(by_file) == {"positive.yml", "unknown.yml"}
    assert by_file["positive.yml"]["line"] == 24
    assert by_file["positive.yml"]["snippet"] == "run: bash incoming/preview.sh"
    assert by_file["positive.yml"]["review_needed"] is True
    assert by_file["positive.yml"]["exploitability"] == "medium"
    assert any(
        "producer identity" in note for note in by_file["positive.yml"]["context_notes"]
    )
    assert any(
        "origin" in note.lower() and "unresolved" in note.lower()
        for note in by_file["unknown.yml"]["context_notes"]
    )
    assert not any(
        finding["rule_id"] == RULE_ID and Path(finding["file"]).name == "incomplete.yml"
        for finding in repo_result["findings"]
    )
    assert repo_result["engine_error_count"] == 1

    explicit = _cli(tmp_path / ".github" / "workflows" / "positive.yml")
    explicit_hits = [
        finding for finding in explicit["findings"] if finding["rule_id"] == RULE_ID
    ]
    assert explicit["files_scanned"] == 1
    assert len(explicit_hits) == 1
    assert explicit_hits[0]["line"] == 24


def test_same_file_keeps_valid_hit_and_unrelated_incomplete_api_and_cli(
    tmp_path: Path,
) -> None:
    valid = _source(CASE_EXEC)
    extra_bad_job = (
        "  unrelated_bad_download:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/download-artifact@v5\n"
        "        with:\n"
        "          name: other\n"
        "          run-id: ${{ github.event.workflow_run.id }}\n"
        "          repository: ${{ github.repository }}\n"
        "          github-token: ${{ github.token }}\n"
        "          path: ../escape\n"
    )
    source = valid.rstrip() + "\n" + extra_bad_job

    pattern = _rule().pattern
    matches = pattern.check_with_filepath(source, source.splitlines(), "mixed.yml")
    assert len(matches) == 1
    assert matches[0] == (24, "run: bash incoming/preview.sh")
    result = pattern.check_with_filepath(source, source.splitlines(), "mixed.yml")
    assert isinstance(result, IncompletePatternMatches)
    assert len(result) == 1
    assert "destination" in result.reason or "path" in result.reason

    _write_workflow(tmp_path, "mixed.yml", source)
    cli_result = _cli(tmp_path / ".github" / "workflows" / "mixed.yml")
    hits = [
        finding for finding in cli_result["findings"] if finding["rule_id"] == RULE_ID
    ]
    assert len(hits) == 1
    assert hits[0]["line"] == 24
    assert cli_result["engine_error_count"] >= 1


def test_exact_run_repository_and_token_bindings_allow_ascii_spacing() -> None:
    source = _source(CASE_EXEC)
    for spaced, compact in (
        (
            "run-id: ${{ github.event.workflow_run.id }}",
            "run-id: ${{github.event.workflow_run.id}}",
        ),
        ("repository: ${{ github.repository }}", "repository: ${{github.repository}}"),
        ("github-token: ${{ github.token }}", "github-token: ${{github.token}}"),
    ):
        assert source.count(spaced) == 1
        source = source.replace(spaced, compact)

    matches = _rule().pattern.check_with_filepath(
        source, source.splitlines(), "compact-expressions.yml"
    )
    assert matches == [(24, "run: bash incoming/preview.sh")]


def test_ascii_spacing_inside_direct_expression_keeps_the_same_binding() -> None:
    source = _source(CASE_EXEC).replace(
        "run-id: ${{ github.event.workflow_run.id }}",
        "run-id: ${{  github . event . workflow_run . id  }}",
    )
    matches = _rule().pattern.check_with_filepath(
        source, source.splitlines(), "spaced-expression.yml"
    )
    assert matches == [(24, "run: bash incoming/preview.sh")]


@pytest.mark.parametrize(
    "expression",
    [
        "${{ github.event.workflow_run.id || '1' }}",
        "${{ fromJSON(github.event.workflow_run.id) }}",
        "${{ github.event.workflow_run['id'] }}",
        "prefix ${{ github.event.workflow_run.id }}",
        "${{ github.\u00a0event.workflow_run.id }}",
    ],
)
def test_non_direct_run_id_expressions_remain_incomplete(expression: str) -> None:
    source = _source(CASE_EXEC).replace(
        "run-id: ${{ github.event.workflow_run.id }}", f"run-id: {expression}"
    )
    result = _rule().pattern.check_with_filepath(
        source, source.splitlines(), "unsupported-expression.yml"
    )
    assert isinstance(result, IncompletePatternMatches)
    assert result == []
    assert "binding" in result.reason


def test_second_supported_direct_github_token_identifier_stays_supported() -> None:
    source = _source(CASE_EXEC).replace(
        "github-token: ${{ github.token }}",
        "github-token: ${{ secrets . GITHUB_TOKEN }}",
    )
    matches = _rule().pattern.check_with_filepath(
        source, source.splitlines(), "secrets-token.yml"
    )
    assert matches == [(24, "run: bash incoming/preview.sh")]


@pytest.mark.parametrize(
    "old,new",
    [
        ("repository: ${{ github.repository }}", "repository: ${{ github.actor }}"),
        ("github-token: ${{ github.token }}", "github-token: ${{ github.actor }}"),
    ],
)
def test_unknown_repository_and_token_identifiers_stay_incomplete(
    old: str, new: str
) -> None:
    source = _source(CASE_EXEC).replace(old, new)
    result = _rule().pattern.check_with_filepath(
        source, source.splitlines(), "unknown-transfer-identifier.yml"
    )
    assert isinstance(result, IncompletePatternMatches)
    assert result == []
    assert "binding" in result.reason
