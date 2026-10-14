from __future__ import annotations

import json
from pathlib import Path

import pytest

from taintly.rules.github._workflow_run_artifact import analyze_corpus
from tests.unit._workflow_run_artifact_sources import (
    CASE_IDS,
    CONSUMERS,
    PRODUCER,
    SOURCE_SHA256,
    source_sha256,
)
from taintly.workflow_corpus import build_corpus


ROOT = Path(__file__).resolve().parents[2]


def test_embedded_sources_match_preserved_canonical_sha256() -> None:
    assert set(SOURCE_SHA256) == {
        f"{CASE_IDS[0]}/consumer.yml",
        f"{CASE_IDS[0]}/producer.yml",
        f"{CASE_IDS[1]}/consumer.yml",
        f"{CASE_IDS[2]}/consumer.yml",
    }
    for case_id in CASE_IDS:
        assert (
            source_sha256(CONSUMERS[case_id])
            == SOURCE_SHA256[f"{case_id}/consumer.yml"]
        )
    assert source_sha256(PRODUCER) == SOURCE_SHA256[f"{CASE_IDS[0]}/producer.yml"]


def _analyze(tmp_path: Path, source: str, name: str = "candidate.yml"):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    (workflow_dir / name).write_text(source, encoding="utf-8", newline="\n")
    return analyze_corpus(build_corpus(str(tmp_path)))


def _case_consumer(case_id: str) -> str:
    return CONSUMERS[case_id]


def _single_line_flow(consumer_guard: str) -> str:
    """Build valid block/flow YAML with several owners sharing one step line."""
    steps = [
        {
            "uses": "actions/download-artifact@v5",
            "with": {
                "name": "pr-preview",
                "run-id": "${{ github.event.workflow_run.id }}",
                "github-token": "${{ github.token }}",
                "repository": "${{ github.repository }}",
                "path": "incoming",
            },
        },
        {"if": consumer_guard, "run": "bash incoming/preview.sh"},
        {"if": "true", "run": "echo true sibling"},
        {"if": "needs.approval.result == 'success'", "run": "echo unknown sibling"},
    ]
    return (
        "name: Flow ownership control\n"
        "on:\n  workflow_run:\n    workflows: [PR Preview]\n    types: [completed]\n"
        "jobs:\n  consume:\n    if: github.event.workflow_run.event == 'pull_request'\n"
        "    runs-on: ubuntu-latest\n    permissions:\n      actions: read\n"
        "    steps: " + json.dumps(steps, separators=(",", ":")) + "\n"
    )


def test_sealed_cases_emit_only_the_two_direct_script_consumers(tmp_path: Path) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    for case_id in CASE_IDS:
        (workflow_dir / f"{case_id}.yml").write_text(
            CONSUMERS[case_id], encoding="utf-8", newline="\n"
        )

    result = analyze_corpus(build_corpus(str(tmp_path)))
    assert len(result.findings) == 2
    by_name = {Path(item.file).stem: item for item in result.findings}
    assert set(by_name) == {
        "workflow_run_pr_artifact_exec_secret",
        "workflow_run_unknown_external_producer",
    }
    assert result.incomplete == ()

    for case_id, finding in by_name.items():
        source = _case_consumer(case_id)
        assert finding.review_needed is True
        assert finding.line == next(
            number
            for number, line in enumerate(source.splitlines(), 1)
            if line.strip() == finding.snippet and line.lstrip().startswith("run:")
        )
        assert finding.snippet.startswith("run: bash incoming/")
        joined = "\n".join(finding.context_notes)
        assert (
            "producer identity, artifact member mapping, file bytes, successful execution, and PR origin remain unresolved"
            in joined
        )
        assert (
            "do not establish trusted artifact provenance or write authority" in joined
        )
        assert (
            "existence, effective availability, and release are not established"
            in joined
        )
        assert finding.context_tags == (
            "workflow-run-artifact-consumer",
            "origin-unresolved",
        )
        assert "untrusted artifact contents as data" in finding.remediation
    assert "PREVIEW_SECRET" in "\n".join(by_name[CASE_IDS[0]].context_notes)
    assert "REGISTRY_TOKEN" in "\n".join(by_name[CASE_IDS[2]].context_notes)


def test_fixed_jq_control_is_data_not_an_artifact_code_candidate(
    tmp_path: Path,
) -> None:
    result = _analyze(tmp_path, _case_consumer("workflow_run_pr_json_parse_only"))
    assert result.findings == ()
    assert result.incomplete == ()


def test_even_available_captured_producer_does_not_claim_origin_without_member_binding(
    tmp_path: Path,
) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "consumer.yml").write_text(
        CONSUMERS[CASE_IDS[0]], encoding="utf-8", newline="\n"
    )
    (workflow_dir / "producer.yml").write_text(PRODUCER, encoding="utf-8", newline="\n")
    result = analyze_corpus(build_corpus(str(tmp_path)))
    assert len(result.findings) == 1
    assert (
        "producer identity, artifact member mapping, file bytes, successful execution, and PR origin remain unresolved"
        in "\n".join(result.findings[0].context_notes)
    )


@pytest.mark.parametrize(
    "old,new",
    [
        ("run-id: ${{ github.event.workflow_run.id }}", "run-id: ${{ github.run_id }}"),
        (
            "repository: ${{ github.repository }}",
            "repository: ${{ github.event.repository.full_name }}",
        ),
        ("path: incoming", "path: ${{ github.workspace }}"),
        ("actions/download-artifact@v5", "actions/download-artifact@v3"),
        ("path: incoming\n", "path: ../incoming\n"),
    ],
)
def test_unproven_transfer_binding_is_incomplete_not_promoted(
    tmp_path: Path, old: str, new: str
) -> None:
    source = _case_consumer(CASE_IDS[0])
    assert source.count(old) == 1
    result = _analyze(tmp_path, source.replace(old, new))
    assert result.findings == ()
    assert result.incomplete


@pytest.mark.parametrize(
    "old,new",
    [
        (
            "        uses: actions/download-artifact@v5\n",
            "        uses: actions/download-artifact@v5\n        with: {}\n",
        ),
        (
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    container: alpine:latest\n",
        ),
        (
            "      - name: Execute downloaded PR-owned script\n",
            "      - name: Execute downloaded PR-owned script\n        working-directory: incoming\n",
        ),
        (
            "      - name: Execute downloaded PR-owned script\n",
            "      - name: Execute downloaded PR-owned script\n        shell: pwsh\n",
        ),
    ],
)
def test_duplicate_owner_or_unmodeled_execution_context_stays_incomplete(
    tmp_path: Path, old: str, new: str
) -> None:
    source = _case_consumer(CASE_IDS[0])
    assert source.count(old) == 1
    result = _analyze(tmp_path, source.replace(old, new))
    assert result.findings == ()
    assert result.incomplete


def test_duplicate_download_input_is_rejected(tmp_path: Path) -> None:
    source = _case_consumer(CASE_IDS[0])
    marker = "          path: incoming\n"
    assert source.count(marker) == 1
    result = _analyze(
        tmp_path, source.replace(marker, marker + "          path: alternate\n")
    )
    assert result.findings == ()
    assert result.incomplete


def test_intervening_executable_step_blocks_file_binding(tmp_path: Path) -> None:
    source = _case_consumer(CASE_IDS[0])
    marker = "      - name: Execute downloaded PR-owned script\n"
    inserted = "      - name: Transform download\n        run: cp replacement.sh incoming/preview.sh\n"
    result = _analyze(tmp_path, source.replace(marker, inserted + marker))
    assert result.findings == ()
    assert any(
        "intervening executable step" in issue.reason for issue in result.incomplete
    )


def test_candidate_requires_later_same_job_invocation_under_destination(
    tmp_path: Path,
) -> None:
    source = _case_consumer(CASE_IDS[0])
    # Move execution before the download, then leave no later consumer.
    run_block = "      - name: Execute downloaded PR-owned script\n        env:\n          PREVIEW_SECRET: ${{ secrets.PREVIEW_SECRET }}\n        run: bash incoming/preview.sh\n"
    download_block = "      - name: Download exact triggering run artifact\n        uses: actions/download-artifact@v5\n        with:\n          name: pr-preview\n          run-id: ${{ github.event.workflow_run.id }}\n          github-token: ${{ github.token }}\n          repository: ${{ github.repository }}\n          path: incoming\n"
    assert source.count(run_block) == source.count(download_block) == 1
    reordered = source.replace(download_block + run_block, run_block + download_block)
    result = _analyze(tmp_path, reordered)
    assert result.findings == ()
    assert result.incomplete == ()


def test_unknown_event_guard_retains_candidate_and_false_guard_suppresses(
    tmp_path: Path,
) -> None:
    source = _case_consumer(CASE_IDS[0])
    unknown = source.replace(
        "if: github.event.workflow_run.event == 'pull_request' && github.event.workflow_run.conclusion == 'success'",
        "if: needs.approval.result == 'success'",
    )
    candidate = _analyze(tmp_path / "unknown", unknown)
    assert len(candidate.findings) == 1
    assert any(
        "requires runtime evaluation" in note
        for note in candidate.findings[0].context_notes
    )

    false_source = source.replace(
        "if: github.event.workflow_run.event == 'pull_request' && github.event.workflow_run.conclusion == 'success'",
        "if: false",
    )
    suppressed = _analyze(tmp_path / "false", false_source)
    assert suppressed.findings == ()


def test_single_literal_action_and_workflow_profile_are_required(
    tmp_path: Path,
) -> None:
    source = _case_consumer(CASE_IDS[0])
    duplicate_job = source + "jobs: {}\n"
    duplicate = _analyze(tmp_path / "duplicate", duplicate_job)
    assert duplicate.findings == ()
    assert duplicate.incomplete

    mixed_event = source.replace("jobs:\n", "  push:\n    branches: [main]\njobs:\n")
    mixed = _analyze(tmp_path / "mixed", mixed_event)
    assert mixed.findings == ()
    assert mixed.incomplete


def test_fixed_jq_exception_does_not_hide_other_destination_commands(
    tmp_path: Path,
) -> None:
    source = _case_consumer(CASE_IDS[1]).replace(
        "jq -r '.status, .summary' incoming/preview.json",
        "jq -r 'env | .SECRET' incoming/preview.json",
    )
    result = _analyze(tmp_path, source)
    assert result.findings == ()
    assert result.incomplete


@pytest.mark.parametrize(
    "operand",
    [
        "incoming/report.json;id",
        "incoming/report.json&&id",
        "incoming/$(id)",
    ],
)
def test_jq_shell_syntax_cannot_borrow_fixed_data_control(
    tmp_path: Path, operand: str
) -> None:
    source = _case_consumer(CASE_IDS[1]).replace(
        "jq -r '.status, .summary' incoming/preview.json",
        f"jq -r '.status, .summary' {operand}",
    )
    result = _analyze(tmp_path, source)
    assert result.findings == ()
    assert result.incomplete


def test_false_download_step_cannot_bind_a_later_consumer(tmp_path: Path) -> None:
    source = _case_consumer(CASE_IDS[0]).replace(
        "      - name: Download exact triggering run artifact\n",
        "      - name: Download exact triggering run artifact\n        if: false\n",
    )
    result = _analyze(tmp_path, source)
    assert result.findings == ()
    assert result.incomplete == ()


def test_download_event_guard_is_evaluated_for_workflow_run(tmp_path: Path) -> None:
    source = _case_consumer(CASE_IDS[0]).replace(
        "      - name: Download exact triggering run artifact\n",
        "      - name: Download exact triggering run artifact\n        if: github.event_name == 'push'\n",
    )
    result = _analyze(tmp_path, source)
    assert result.findings == ()


def test_unknown_download_guard_retains_conditional_candidate(tmp_path: Path) -> None:
    source = _case_consumer(CASE_IDS[0]).replace(
        "      - name: Download exact triggering run artifact\n",
        "      - name: Download exact triggering run artifact\n        if: needs.approval.result == 'success'\n",
    )
    result = _analyze(tmp_path, source)
    assert len(result.findings) == 1
    assert any(
        "download action guard" in note for note in result.findings[0].context_notes
    )


def test_download_action_combined_with_run_is_incomplete(tmp_path: Path) -> None:
    source = _case_consumer(CASE_IDS[0]).replace(
        "        uses: actions/download-artifact@v5\n",
        "        uses: actions/download-artifact@v5\n        run: echo unrelated\n",
    )
    result = _analyze(tmp_path, source)
    assert result.findings == ()
    assert result.incomplete


@pytest.mark.parametrize(
    "scope,prefix",
    [
        ("workflow", "defaults: [pwsh]\n"),
        ("workflow", "defaults: pwsh\n"),
        ("workflow", "defaults: []\n"),
        ("workflow", "defaults: {}\n"),
        ("workflow", "defaults:\n  run: [pwsh]\n"),
        ("workflow", "defaults:\n  run: pwsh\n"),
        ("job", "defaults: [pwsh]\n"),
        ("job", "defaults: pwsh\n"),
    ],
)
def test_non_mapping_defaults_never_fall_back_to_hosted_bash(
    tmp_path: Path, scope: str, prefix: str
) -> None:
    source = _case_consumer(CASE_IDS[0])
    if scope == "job":
        # Insert a job-level malformed defaults owner before the first step.
        marker = "    steps:\n"
        assert marker in source
        job_defaults = "".join(
            "    " + line for line in prefix.splitlines(keepends=True)
        )
        source = source.replace(marker, job_defaults + marker, 1)
    else:
        source = source.replace("jobs:\n", prefix + "jobs:\n", 1)
    result = _analyze(tmp_path, source)
    assert result.findings == ()
    assert result.incomplete


def test_fixed_jq_data_control_requires_supported_shell(tmp_path: Path) -> None:
    source = _case_consumer(CASE_IDS[1]).replace(
        "        run: jq -r '.status, .summary' incoming/preview.json\n",
        "        shell: pwsh\n        run: jq -r '.status, .summary' incoming/preview.json\n",
    )
    result = _analyze(tmp_path, source)
    assert result.findings == ()
    assert result.incomplete


@pytest.mark.parametrize(
    "scope",
    ["step", "job", "workflow"],
)
def test_explicit_supported_shell_shapes_preserve_consumer_candidate(
    tmp_path: Path, scope: str
) -> None:
    source = _case_consumer(CASE_IDS[0])
    if scope == "step":
        source = source.replace(
            "        run: bash incoming/preview.sh\n",
            "        shell: bash\n        run: bash incoming/preview.sh\n",
        )
    elif scope == "job":
        source = source.replace(
            "    steps:\n",
            "    defaults:\n      run:\n        shell: bash\n    steps:\n",
            1,
        )
    else:
        source = source.replace(
            "jobs:\n", "defaults:\n  run:\n    shell: bash\njobs:\n", 1
        )
    result = _analyze(tmp_path, source)
    assert len(result.findings) == 1
    assert result.incomplete == ()


@pytest.mark.parametrize(
    "guard,expected",
    [("false", 0), ("true", 1), ("needs.approval.result == 'success'", 1)],
)
def test_single_line_flow_consumer_guards_use_structural_owner(
    tmp_path: Path, guard: str, expected: int
) -> None:
    result = _analyze(tmp_path, _single_line_flow(guard))
    assert len(result.findings) == expected
    if expected:
        assert result.findings[0].snippet.startswith("steps: [")
        assert "echo true sibling" in result.findings[0].snippet
        assert "echo unknown sibling" in result.findings[0].snippet
    if guard == "needs.approval.result == 'success'":
        assert any(
            "consuming job/step guard requires runtime evaluation" in note
            for note in result.findings[0].context_notes
        )


def test_unsupported_whole_document_json_profile_stays_incomplete(
    tmp_path: Path,
) -> None:
    source = json.dumps(
        {
            "on": {
                "workflow_run": {
                    "workflows": ["PR Preview"],
                    "types": ["completed"],
                }
            },
            "jobs": {
                "consume": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "uses": "actions/download-artifact@v5",
                            "with": {
                                "name": "pr-preview",
                                "run-id": "${{ github.event.workflow_run.id }}",
                                "repository": "${{ github.repository }}",
                                "github-token": "${{ github.token }}",
                                "path": "incoming",
                            },
                        },
                        {"if": "false", "run": "bash incoming/preview.sh"},
                    ],
                }
            },
        },
        separators=(",", ":"),
    )
    result = _analyze(tmp_path, source)
    assert result.findings == ()
    assert any(
        "trigger profile is malformed" in issue.reason for issue in result.incomplete
    )
