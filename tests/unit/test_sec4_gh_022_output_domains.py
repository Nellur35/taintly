"""SEC4-GH-022 safe-domain proof across one resolved job-output edge.

Only a job output that maps uniquely to one safe, literal GITHUB_OUTPUT write
may suppress the review cue. Unknown, mixed, ambiguous, or out-of-scope
producers must continue to produce SEC4-GH-022.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file

_REF = "${{ needs.producer.outputs.status }}"


def _workflow(
    producer_script: str | None = 'echo "status=failure" >> "$GITHUB_OUTPUT"',
    consumer_script: str | None = None,
    *,
    producer_mapping: str = "${{ steps.write.outputs.status }}",
    needs: str = "producer",
    runs_on: str = "ubuntu-latest",
    workflow_shell: str | None = None,
    workflow_env: str | None = None,
    producer_job_shell: str | None = None,
    producer_job_env: str | None = None,
    producer_step_shell: str | None = None,
    producer_step_env: str | None = None,
    producer_container: str | None = None,
    producer_container_env: str | None = None,
    producer_step_if: str | None = None,
    producer_steps_before: str = "",
    producer_action_metadata: str = "",
    producer_steps_extra: str = "",
    producer_outputs: str | None = None,
    producer_matrix: str | None = None,
    producer_reusable: str | None = None,
) -> str:
    if consumer_script is None:
        consumer_script = f'test "{_REF}" = success'

    lines = ["name: output-domain", "on: push", "permissions:", "  contents: read"]
    if workflow_shell is not None:
        lines += ["defaults:", "  run:", f"    shell: {workflow_shell}"]
    if workflow_env is not None:
        lines += ["env:", *[f"  {line}" for line in workflow_env.splitlines()]]
    lines += ["jobs:", "  producer:"]
    if producer_reusable is not None:
        lines += [f"    uses: {producer_reusable}"]
    else:
        lines += [f"    runs-on: {runs_on}"]
        if producer_container is not None:
            lines += ["    container:", f"      image: {producer_container}"]
            if producer_container_env is not None:
                lines += [
                    "      env:",
                    *[f"        {line}" for line in producer_container_env.splitlines()],
                ]
        if producer_job_shell is not None:
            lines += ["    defaults:", "      run:", f"        shell: {producer_job_shell}"]
        if producer_job_env is not None:
            lines += ["    env:", *[f"      {line}" for line in producer_job_env.splitlines()]]
        if producer_matrix is not None:
            lines += ["    strategy:", "      matrix:", f"        value: {producer_matrix}"]
        lines += ["    outputs:"]
        lines += (
            producer_outputs.splitlines()
            if producer_outputs is not None
            else [f"      status: {producer_mapping}"]
        )
        lines += ["    steps:"]
        if producer_steps_before:
            lines += producer_steps_before.splitlines()
        if producer_script is None:
            lines += ["      - id: write", "        uses: example/action@v1"]
            if producer_action_metadata:
                lines += ["        with:"]
                lines += [f"          {line}" for line in producer_action_metadata.splitlines()]
        else:
            lines += ["      - id: write"]
            if producer_step_if is not None:
                lines += [f"        if: {producer_step_if}"]
            if producer_step_shell is not None:
                lines += [f"        shell: {producer_step_shell}"]
            if producer_step_env is not None:
                lines += [
                    "        env:",
                    *[f"          {line}" for line in producer_step_env.splitlines()],
                ]
            lines += [
                "        run: |",
                *[f"          {line}" for line in producer_script.splitlines()],
            ]
        if producer_steps_extra:
            lines += producer_steps_extra.splitlines()

    lines += [
        "  consumer:",
        f"    needs: {needs}",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - run: |",
        *[f"          {line}" for line in consumer_script.splitlines()],
    ]
    return "\n".join(lines) + "\n"


def _ids(tmp_path: Path, github_rules, content: str) -> set[str]:
    path = tmp_path / "workflow.yml"
    path.write_text(content, encoding="utf-8")
    return {finding.rule_id for finding in scan_file(str(path), github_rules)}


def test_literal_enum_job_output_is_safe_when_resolved_through_needs(tmp_path, github_rules):
    """A unique job output mapped to one fixed status write has a closed domain."""
    assert "SEC4-GH-022" not in _ids(tmp_path, github_rules, _workflow())


def test_job_output_key_may_alias_a_differently_named_step_output(tmp_path, github_rules):
    content = _workflow(
        producer_script='echo "flag=failure" >> "$GITHUB_OUTPUT"',
        producer_mapping="${{ steps.write.outputs.flag }}",
    )
    assert "SEC4-GH-022" not in _ids(tmp_path, github_rules, content)


@pytest.mark.parametrize(
    ("scope", "container"),
    [("workflow", False), ("job", False), ("step", False), ("container", True)],
)
def test_bash_env_startup_hook_keeps_warning(tmp_path, github_rules, scope, container):
    """A visible BASH_ENV can change echo before the fixed-looking writer runs."""
    options = {
        "workflow_env": "BASH_ENV: /tmp/workflow-hook.sh" if scope == "workflow" else None,
        "producer_job_env": "BASH_ENV: /tmp/job-hook.sh" if scope == "job" else None,
        "producer_step_env": "BASH_ENV: /tmp/step-hook.sh" if scope == "step" else None,
        "producer_container": "ubuntu:22.04" if container else None,
        "producer_container_env": ("BASH_ENV: /tmp/container-hook.sh" if container else None),
    }
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, _workflow(**options))


def test_prior_github_env_bash_env_write_keeps_warning(tmp_path, github_rules):
    prior = (
        "      - name: Set shell startup file\n"
        '        run: echo "BASH_ENV=/tmp/runner-hook.sh" >> "$GITHUB_ENV"'
    )
    content = _workflow(producer_steps_before=prior)
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, content)


def test_standalone_env_startup_hook_keeps_warning(tmp_path, github_rules):
    content = _workflow(producer_step_env="ENV: /tmp/runner-hook.sh")
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, content)


def test_prior_github_path_write_keeps_warning(tmp_path, github_rules):
    prior = '      - name: Extend shell path\n        run: echo "/tmp/runner-bin" >> "$GITHUB_PATH"'
    content = _workflow(producer_steps_before=prior)
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, content)


def test_imported_echo_function_keeps_warning(tmp_path, github_rules):
    env = "BASH_FUNC_echo%%: '() { printf \"status=$PR_TITLE\\n\"; }'"
    content = _workflow(producer_step_env=env)
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, content)


def test_safe_writer_allows_blank_lines_and_comments_around_one_echo(tmp_path, github_rules):
    script = '# fixed status only\n\necho "status=failure" >> "$GITHUB_OUTPUT"\n# end'
    assert "SEC4-GH-022" not in _ids(tmp_path, github_rules, _workflow(script))


def test_nonmatrix_container_outcome_enum_status_relay_is_safe(tmp_path, github_rules):
    """Fantom's action outcome controls only whether the fixed literal is written."""
    prior_action = (
        "      - name: Run Fantom Tests\n"
        "        id: run-tests\n"
        "        uses: ./.github/actions/run-fantom-tests"
    )
    content = _workflow(
        producer_script='echo "status=failure" >> "$GITHUB_OUTPUT"',
        producer_step_if="${{ always() && steps.run-tests.outcome == 'failure' }}",
        producer_steps_before=prior_action,
        runs_on="8-core-ubuntu",
        producer_container="reactnativecommunity/react-native-android:latest",
    )
    assert "SEC4-GH-022" not in _ids(tmp_path, github_rules, content)


@pytest.mark.parametrize(
    ("workflow_shell", "producer_job_shell", "producer_step_shell"),
    [("bash", None, None), (None, "bash", None), (None, None, "bash")],
)
def test_supported_shell_priority_proves_fixed_output(
    tmp_path, github_rules, workflow_shell, producer_job_shell, producer_step_shell
):
    content = _workflow(
        workflow_shell=workflow_shell,
        producer_job_shell=producer_job_shell,
        producer_step_shell=producer_step_shell,
    )
    assert "SEC4-GH-022" not in _ids(tmp_path, github_rules, content)


@pytest.mark.parametrize(
    ("runs_on", "producer_container"),
    [("ubuntu-latest", None), ("macos-latest", None), ("ubuntu-latest", "ubuntu:22.04")],
)
def test_known_unix_or_container_default_proves_fixed_output(
    tmp_path, github_rules, runs_on, producer_container
):
    assert "SEC4-GH-022" not in _ids(
        tmp_path,
        github_rules,
        _workflow(runs_on=runs_on, producer_container=producer_container),
    )


def test_safe_step_shell_overrides_unknown_workflow_default(tmp_path, github_rules):
    content = _workflow(workflow_shell="custom-shell", producer_step_shell="bash")
    assert "SEC4-GH-022" not in _ids(tmp_path, github_rules, content)


@pytest.mark.parametrize(
    ("runs_on", "workflow_shell", "producer_job_shell", "producer_step_shell"),
    [
        ("windows-latest", None, None, None),
        ("ubuntu-latest", None, "custom-shell", None),
        ("ubuntu-latest", None, "bash", "custom-shell"),
        ("ubuntu-latest", None, None, "python"),
        ("ubuntu-latest", None, None, "pwsh"),
        ("ubuntu-latest", "bash", None, "null"),
        ("ubuntu-latest", "bash", None, "${{ inputs.shell }}"),
    ],
)
def test_unknown_or_winning_custom_shell_keeps_warning(
    tmp_path, github_rules, runs_on, workflow_shell, producer_job_shell, producer_step_shell
):
    content = _workflow(
        runs_on=runs_on,
        workflow_shell=workflow_shell,
        producer_job_shell=producer_job_shell,
        producer_step_shell=producer_step_shell,
    )
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, content)


@pytest.mark.parametrize(
    "script",
    [
        'echo "status=$PR_TITLE" >> "$GITHUB_OUTPUT"',
        'echo "status=$(date +%s)" >> "$GITHUB_OUTPUT"',
        'echo "status=failure" >> "$GITHUB_OUTPUT"; echo done',
        'echo "status=failure" >> "$GITHUB_OUTPUT"\necho "status=success" >> "$GITHUB_OUTPUT"',
    ],
)
def test_dynamic_multiple_or_unrecognized_writer_keeps_warning(tmp_path, github_rules, script):
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, _workflow(script))


def test_unknown_action_output_keeps_warning(tmp_path, github_rules):
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, _workflow(producer_script=None))


def test_interpolated_shell_comment_before_literal_write_keeps_warning(tmp_path, github_rules):
    script = '# ${{ github.event.pull_request.title }}\necho "status=failure" >> "$GITHUB_OUTPUT"'
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, _workflow(script))


def test_action_metadata_cannot_masquerade_as_direct_run_writer(tmp_path, github_rules):
    metadata = 'run: echo "status=failure" >> "$GITHUB_OUTPUT"'
    content = _workflow(producer_script=None, producer_action_metadata=metadata)
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, content)


def test_each_needs_output_reference_on_sink_must_be_proven_safe(tmp_path, github_rules):
    script = 'echo "status=failure" >> "$GITHUB_OUTPUT"'
    consumer = f'test "{_REF}" = failure && test "${{{{ needs.other.outputs.status }}}}" = success'
    content = _workflow(script, consumer)
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, content)


def test_fixed_bracket_key_output_reference_is_proven_safe(tmp_path, github_rules):
    consumer = "test \"${{ needs.producer.outputs['status'] }}\" = failure"
    assert "SEC4-GH-022" not in _ids(tmp_path, github_rules, _workflow(consumer_script=consumer))


def test_computed_or_compound_output_expression_keeps_warning(tmp_path, github_rules):
    # Keep a direct output reference on the sink next to an unsupported
    # computed reference; proof of one exact mapping must not erase the cue.
    consumer = f'echo "{_REF} ${{{{ needs.producer.outputs[github.event.inputs.key] }}}}"'
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, _workflow(consumer_script=consumer))


def test_safe_dot_output_plus_unknown_bracketed_needs_ref_keeps_warning(tmp_path, github_rules):
    consumer = f"echo \"{_REF} ${{{{ needs['other']['outputs']['raw'] }}}}\""
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, _workflow(consumer_script=consumer))


def test_literal_output_from_unlisted_need_keeps_warning(tmp_path, github_rules):
    content = _workflow(needs="other")
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, content)


def test_compound_producer_mapping_keeps_review_warning(tmp_path, github_rules):
    content = _workflow(producer_mapping="${{ steps.write.outputs.status || 'success' }}")
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, content)


def test_computed_producer_index_keeps_review_warning(tmp_path, github_rules):
    content = _workflow(producer_mapping="${{ steps.write.outputs[inputs.output] }}")
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, content)


def test_every_safe_reference_on_sink_can_be_proven(tmp_path, github_rules):
    second = (
        "  second:\n"
        "    runs-on: ubuntu-latest\n"
        "    outputs:\n"
        "      state: ${{ steps.write.outputs.state }}\n"
        "    steps:\n"
        "      - id: write\n"
        '        run: echo "state=success" >> "$GITHUB_OUTPUT"\n'
    )
    consumer = f'echo "{_REF} ${{{{ needs.second.outputs.state }}}}"'
    content = _workflow(
        consumer_script=consumer,
        needs="[producer, second]",
    ).replace("  consumer:\n", second + "  consumer:\n")
    assert "SEC4-GH-022" not in _ids(tmp_path, github_rules, content)


def test_same_output_name_in_unrelated_job_does_not_control_resolution(tmp_path, github_rules):
    content = _workflow(
        producer_steps_extra=(
            "  other:\n"
            "    runs-on: ubuntu-latest\n"
            "    outputs:\n"
            "      status: ${{ steps.write.outputs.status }}\n"
            "    steps:\n"
            "      - id: write\n"
            '        run: echo "status=$PR_TITLE" >> "$GITHUB_OUTPUT"'
        )
    )
    assert "SEC4-GH-022" not in _ids(tmp_path, github_rules, content)


@pytest.mark.parametrize(
    "producer_mapping",
    [
        "${{ steps.other.outputs.status }}",
        "${{ steps.write.outputs.other }}",
        "null",
    ],
)
def test_unresolved_or_malformed_job_output_mapping_keeps_warning(
    tmp_path, github_rules, producer_mapping
):
    content = _workflow(producer_mapping=producer_mapping)
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, content)


def test_ambiguous_duplicate_step_id_keeps_warning(tmp_path, github_rules):
    extra = '      - id: write\n        run: echo "status=success" >> "$GITHUB_OUTPUT"'
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, _workflow(producer_steps_extra=extra))


def test_ambiguous_duplicate_job_output_key_keeps_warning(tmp_path, github_rules):
    outputs = (
        "      status: ${{ steps.write.outputs.status }}\n"
        "      status: ${{ steps.write.outputs.other }}"
    )
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, _workflow(producer_outputs=outputs))


def test_matrix_producer_keeps_warning(tmp_path, github_rules):
    content = _workflow(producer_matrix="[one, two]")
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, content)


def test_reusable_workflow_producer_keeps_warning(tmp_path, github_rules):
    content = _workflow(producer_reusable="./.github/workflows/producer.yml")
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, content)


def test_mixed_safe_and_unsafe_job_outputs_on_same_sink_keep_warning(tmp_path, github_rules):
    consumer = f'echo "{_REF} ${{{{ needs.producer.outputs.title }}}}"'
    assert "SEC4-GH-022" in _ids(
        tmp_path,
        github_rules,
        _workflow(
            consumer_script=consumer,
            producer_script=(
                'echo "status=failure" >> "$GITHUB_OUTPUT"\n'
                'echo "title=$PR_TITLE" >> "$GITHUB_OUTPUT"'
            ),
            producer_outputs=(
                "      status: ${{ steps.write.outputs.status }}\n"
                "      title: ${{ steps.write.outputs.title }}"
            ),
        ),
    )


def test_fixed_job_output_literal_without_step_mapping_keeps_warning(tmp_path, github_rules):
    content = _workflow(producer_outputs="      status: failure")
    assert "SEC4-GH-022" in _ids(tmp_path, github_rules, content)


def test_structural_cutoff_suffix_after_safe_shaped_output_keeps_warning(tmp_path, github_rules):
    # A terminal unsupported node after the producer/consumer must not permit
    # partial structural proof to suppress an earlier pattern finding.
    content = _workflow() + "probe: !!binary YQ==\n"
    ids = _ids(tmp_path, github_rules, content)
    assert "SEC4-GH-022" in ids
    assert "ENGINE-ERR" in ids
