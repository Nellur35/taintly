from __future__ import annotations

from dataclasses import replace
from unittest.mock import patch

from taintly.models import _SHELL_USE_PROFILE_CACHE, scan_session
from taintly.shell_use import (
    ShellUse,
    classify_shell_use,
    validate_shell_use,
)
from taintly.taint import TaintHop, TaintPath, analyze


def _workflow(run: str, *, runner: str = "ubuntu-latest", shell: str = "bash") -> str:
    shell_line = f"      shell: {shell}\n" if shell else ""
    return (
        "on: pull_request_target\n"
        "jobs:\n"
        "  greet:\n"
        f"    runs-on: {runner}\n"
        "    env:\n"
        "      TITLE: ${{ github.event.pull_request.title }}\n"
        "    steps:\n"
        "      - name: consume\n"
        f"        run: {run}\n"
        f"{shell_line}"
    )


def _path(content: str):
    paths = analyze(content, content.splitlines())
    matches = [path for path in paths if path.env_var == "TITLE" and path.sink_kind == "run"]
    assert len(matches) == 1
    return matches[0]


def test_fixed_format_printf_argument_is_data_and_revalidates():
    content = _workflow("printf '%s\\n' $TITLE")
    path = _path(content)

    evidence = classify_shell_use(content, path, "workflow.yml")

    assert evidence.disposition is ShellUse.DATA
    assert evidence.owner_path == ("jobs", "greet", "steps", 0)
    assert evidence.command_sha256
    assert validate_shell_use(evidence, content, "workflow.yml", path.sink_line)


def test_fixed_format_printf_argument_with_literal_eval_word_is_data():
    content = _workflow("printf '%s\\n' 'eval' \"$TITLE\"")
    path = _path(content)

    evidence = classify_shell_use(content, path, "workflow.yml")

    assert evidence.disposition is ShellUse.DATA


def test_printf_option_in_format_position_is_unknown():
    content = _workflow('printf -v "$TITLE" value')
    path = _path(content)

    evidence = classify_shell_use(content, path, "workflow.yml")

    assert evidence.disposition is ShellUse.UNKNOWN


def test_dynamic_runner_does_not_infer_default_shell():
    content = _workflow(
        'printf \'%s\\n\' "$TITLE"', runner="ubuntu-${{ inputs.runner }}", shell=""
    )
    path = _path(content)

    evidence = classify_shell_use(content, path, "workflow.yml")

    assert evidence.disposition is ShellUse.UNKNOWN
    assert evidence.shell_basis == "configured shell is unresolved"


def test_actual_eval_operand_and_expanded_command_position_are_code():
    for command in ('eval "$TITLE"', '"$TITLE" --flag'):
        content = _workflow(command)
        path = _path(content)
        evidence = classify_shell_use(content, path, "workflow.yml")
        assert evidence.disposition is ShellUse.CODE


def test_repeated_reference_keeps_code_precedence_when_one_is_eval_operand():
    content = _workflow("printf '%s\\n' \"$TITLE\"; eval \"$TITLE\"")
    path = _path(content)

    evidence = classify_shell_use(content, path, "workflow.yml")

    assert evidence.disposition is ShellUse.CODE


def test_tainted_printf_pipeline_to_shell_is_code_even_when_quoted():
    for pipeline in (
        'printf \'%s\\n\' "$TITLE" | sh',
        'printf \'%s\\n\' "$TITLE" | bash -s',
        'printf \'%s\\n\' "$TITLE" | cat | sh',
    ):
        content = _workflow(pipeline)
        path = _path(content)

        evidence = classify_shell_use(content, path, "workflow.yml")

        assert evidence.disposition is ShellUse.CODE


def test_quoted_argument_to_unprofiled_external_command_is_unknown():
    content = _workflow('echo "$TITLE"')
    path = _path(content)

    evidence = classify_shell_use(content, path, "workflow.yml")

    assert evidence.disposition is ShellUse.UNKNOWN
    assert "insufficient" in evidence.reason or "did not establish" in evidence.reason


def test_exact_single_assignment_copy_is_data():
    content = _workflow("COPY=$TITLE")
    path = _path(content)

    evidence = classify_shell_use(content, path, "workflow.yml")

    assert evidence.disposition is ShellUse.DATA


def test_unmatched_quote_cannot_receive_data_certificate():
    content = _workflow('printf \'%s\\n\' "$TITLE')
    path = _path(content)

    evidence = classify_shell_use(content, path, "workflow.yml")

    assert evidence.disposition is ShellUse.UNKNOWN


def test_extended_parameter_operators_are_unknown():
    for expansion in ("${TITLE@P}", "${TITLE^^}"):
        content = _workflow(f'eval "$TITLE" {expansion}')
        path = _path(content)

        evidence = classify_shell_use(content, path, "workflow.yml")

        assert evidence.disposition is ShellUse.UNKNOWN


def test_unprofiled_printf_pipeline_is_unknown():
    dispositions = []
    for command in (
        "printf 'fixed' \"$TITLE\" | sh",
        "printf 'fixed' \"$TITLE\" | cat | sh",
        "printf '%.0s' \"$TITLE\" | sh",
    ):
        content = _workflow(command)
        path = _path(content)

        evidence = classify_shell_use(content, path, "workflow.yml")
        dispositions.append(evidence.disposition)

    # An unrelated printf must not suppress a separately tracked shell input.
    content = _workflow('printf \'fixed\' | sh -c "$TITLE"')
    path = _path(content)
    evidence = classify_shell_use(content, path, "workflow.yml")
    assert evidence.disposition is ShellUse.CODE
    assert dispositions == [ShellUse.UNKNOWN] * 3


def test_exact_actions_source_expression_splice_is_code_even_inside_quotes():
    content = _workflow("printf '%s\\n' \"${{ github.event.pull_request.title }}\"")
    path = TaintPath(
        source_expr="github.event.pull_request.title",
        source_line=6,
        env_var="TITLE",
        sink_line=9,
        sink_snippet="        run: printf '%s\\n' \"${{ github.event.pull_request.title }}\"",
        hops=[TaintHop(kind="sink", line=9, name="TITLE", detail="source splice")],
    )

    evidence = classify_shell_use(content, path, "workflow.yml")

    assert evidence.disposition is ShellUse.CODE
    assert "spliced" in evidence.reason


def test_exact_env_expression_provenance_is_code_before_shell_parsing():
    content = _workflow("printf '%s\\n' \"${{ env.TITLE }}\"")
    path = TaintPath(
        source_expr="github.event.pull_request.title",
        source_line=6,
        env_var="TITLE",
        sink_line=9,
        sink_snippet="        run: printf '%s\\n' \"${{ env.TITLE }}\"",
        hops=[TaintHop(kind="sink", line=9, name="TITLE", detail="env splice")],
    )

    evidence = classify_shell_use(content, path, "workflow.yml")

    assert evidence.disposition is ShellUse.CODE


def test_needs_output_splice_matches_exact_producer_identity():
    content = _workflow("printf '%s\\n' \"${{ needs.build.outputs.title }}\"")
    path = TaintPath(
        source_expr="github.event.pull_request.title",
        source_line=6,
        env_var="needs.build.outputs.title",
        sink_line=9,
        sink_snippet="        run: printf '%s\\n' \"${{ needs.build.outputs.title }}\"",
        kind="cross_job",
        hops=[TaintHop(kind="sink", line=9, name="needs.build.outputs.title", detail="output")],
    )
    mismatch = TaintPath(
        source_expr="github.event.pull_request.title",
        source_line=6,
        env_var="needs.other.outputs.title",
        sink_line=9,
        sink_snippet=path.sink_snippet,
        kind="cross_job",
        hops=[TaintHop(kind="sink", line=9, name="needs.other.outputs.title", detail="output")],
    )

    assert classify_shell_use(content, path, "workflow.yml").disposition is ShellUse.CODE
    assert classify_shell_use(content, mismatch, "workflow.yml").disposition is ShellUse.UNKNOWN


def test_validator_rejects_forged_semantic_disposition():
    content = _workflow("printf '%s\\n' $TITLE")
    path = _path(content)
    evidence = classify_shell_use(content, path, "workflow.yml")
    forged = replace(evidence, disposition=ShellUse.CODE, reason="forged")
    forged_string = replace(evidence)
    object.__setattr__(forged_string, "disposition", "data")

    assert not validate_shell_use(forged, content, "workflow.yml", path.sink_line)
    assert not validate_shell_use(forged_string, content, "workflow.yml", path.sink_line)


def test_windows_default_shell_is_unknown():
    content = _workflow("printf '%s\\n' \"$TITLE\"", runner="windows-latest", shell="")
    path = _path(content)

    evidence = classify_shell_use(content, path, "workflow.yml")

    assert evidence.disposition is ShellUse.UNKNOWN
    assert "shell" in evidence.reason


def test_container_and_shell_startup_overrides_stay_unknown():
    variants = (
        _workflow("printf '%s\\n' $TITLE").replace(
            "    env:\n", "    container: python:3.13\n    env:\n"
        ),
        _workflow("printf '%s\\n' $TITLE").replace(
            "    env:\n", "    env:\n      PATH: /custom/bin\n"
        ),
    )
    for content in variants:
        path = _path(content)
        evidence = classify_shell_use(content, path, "workflow.yml")
        assert evidence.disposition is ShellUse.UNKNOWN


def test_folded_command_mapping_is_unknown():
    content = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  greet:\n"
        "    runs-on: ubuntu-latest\n"
        "    env:\n"
        "      TITLE: ${{ github.event.pull_request.title }}\n"
        "    steps:\n"
        "      - name: consume\n"
        "        shell: bash\n"
        "        run: >\n"
        "          printf '%s\\n' $TITLE\n"
    )
    path = _path(content)

    evidence = classify_shell_use(content, path, "workflow.yml")

    assert evidence.disposition is ShellUse.UNKNOWN
    assert "folded" in evidence.reason


def test_literal_block_with_exact_single_line_mapping_is_data():
    content = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  greet:\n"
        "    runs-on: ubuntu-latest\n"
        "    env:\n"
        "      TITLE: ${{ github.event.pull_request.title }}\n"
        "    steps:\n"
        "      - name: consume\n"
        "        shell: bash\n"
        "        run: |\n"
        "          printf '%s\\n' $TITLE\n"
    )
    path = _path(content)

    evidence = classify_shell_use(content, path, "workflow.yml")

    assert evidence.disposition is ShellUse.DATA
    assert evidence.owner_path == ("jobs", "greet", "steps", 0)
    assert evidence.command_sha256


def test_evidence_rejects_stale_foreign_or_wrong_line_binding():
    content = _workflow("printf '%s\\n' $TITLE")
    path = _path(content)
    evidence = classify_shell_use(content, path, "workflow.yml")

    assert not validate_shell_use(evidence, content + "# changed\n", "workflow.yml", path.sink_line)
    assert not validate_shell_use(evidence, content, "other.yml", path.sink_line)
    assert not validate_shell_use(evidence, content, "workflow.yml", path.sink_line + 1)


def test_structural_profile_cache_reuses_only_within_scan_session():
    from taintly.local_call_graph import _Document

    content = _workflow('printf \'%s\\n\' "$TITLE"')
    path = _path(content)
    constructions = 0

    def count_document(file, source, kind):
        nonlocal constructions
        constructions += 1
        return _Document(file, source, kind)

    with patch("taintly.local_call_graph._Document", side_effect=count_document):
        classify_shell_use(content, path, "workflow.yml")
        classify_shell_use(content, path, "workflow.yml")
        assert constructions == 2
        assert _SHELL_USE_PROFILE_CACHE.get() is None

        with scan_session():
            assert _SHELL_USE_PROFILE_CACHE.get() == {}
            classify_shell_use(content, path, "workflow.yml")
            classify_shell_use(content, path, "workflow.yml")
            assert constructions == 3
            profile_cache = _SHELL_USE_PROFILE_CACHE.get()
            assert profile_cache is not None
            assert len(profile_cache) == 1
        assert _SHELL_USE_PROFILE_CACHE.get() is None

        with scan_session():
            classify_shell_use(content, path, "workflow.yml")
            classify_shell_use(content, path, "workflow.yml")
            assert constructions == 4


def test_long_printf_formats_are_bounded_and_keep_classification():
    import json
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    child = """import json, sys
sys.path.insert(0, sys.argv[1])
from taintly.shell_use import classify_shell_use
from taintly.taint import analyze
content = json.load(sys.stdin)
paths = [p for p in analyze(content, content.splitlines()) if p.env_var == 'TITLE' and p.sink_kind == 'run']
if len(paths) != 1:
    raise RuntimeError(f'expected one TITLE run path, got {len(paths)}')
print(classify_shell_use(content, paths[0], 'workflow.yml').disposition.value)
"""
    repeated_format = "%s" + r"\n" * 128
    cases = (
        (repeated_format, False, ShellUse.DATA),
        (repeated_format + "%", False, ShellUse.UNKNOWN),
        (repeated_format, True, ShellUse.CODE),
        (repeated_format + "%", True, ShellUse.UNKNOWN),
    )
    results = []
    for format_word, pipeline, expected in cases:
        argument = '"$TITLE"' if pipeline else "$TITLE"
        command = f"printf '{format_word}' {argument}" + (" | sh" if pipeline else "")
        content = (
            "on: pull_request_target\n"
            "jobs:\n"
            "  greet:\n"
            "    runs-on: ubuntu-latest\n"
            "    env:\n"
            "      TITLE: ${{ github.event.pull_request.title }}\n"
            "    steps:\n"
            "      - name: consume\n"
            "        shell: bash\n"
            "        run: |\n"
            f"          {command}\n"
        )
        try:
            result = subprocess.run(
                [sys.executable, "-I", "-B", "-S", "-c", child, str(root)],
                input=json.dumps(content),
                text=True,
                capture_output=True,
                timeout=3,
                check=False,
                cwd=root,
            )
            actual = result.stdout.strip() if result.returncode == 0 else f"exit {result.returncode}"
        except subprocess.TimeoutExpired:
            actual = "timeout"
        results.append((actual, expected.value))

    assert results == [(expected.value, expected.value) for _, _, expected in cases]
