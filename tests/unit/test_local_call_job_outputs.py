"""Controls for job-output values passed into local calls.

GitHub job outputs map step outputs; consumers directly depend on producers
and read needs.<job>.outputs. The needs context contains direct
dependencies only. Tests inspect static flow and never execute workflows.

Contracts: https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
https://docs.github.com/en/actions/reference/workflows-and-actions/contexts
https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/pass-job-outputs
"""

from taintly.cross_artifact_facts import find_cross_artifact_taint
from taintly.cross_workflow_facts import find_cross_file_taint
from taintly.workflow_corpus import build_corpus


def _repo(root, files):
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def _producer(output="${{ steps.capture.outputs.payload }}", guarded=""):
    guard = f"    if: {guarded}\n" if guarded else ""
    return f"""  produce:
    runs-on: ubuntu-latest
    outputs:
      payload: {output}
{guard}    steps:
      - id: capture
        env:
          ISSUE_TITLE: ${{{{ github.event.issue.title }}}}
        run: echo "payload=$ISSUE_TITLE" >> "$GITHUB_OUTPUT"
"""


def _consumer(call, needs="produce", value="${{ needs.produce.outputs.payload }}"):
    return f"""  consume:
    needs: {needs}
    permissions:
      contents: read
      pull-requests: read
{call.format(value=value)}
"""


def _workflow_target():
    return """    uses: ./.github/workflows/reusable.yml
    with:
      payload: {value}
"""


def _action_target():
    return """    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/terminal
        with:
          payload: {value}
"""


def _workflow_callee():
    return """on:
  workflow_call:
    inputs:
      payload: {type: string, required: true}
jobs:
  sink:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - env:
          GH_TOKEN: ${{ github.token }}
        run: eval "${{ inputs.payload }}"
"""


def _action_callee():
    return """inputs:
  payload: {required: true}
runs:
  using: composite
  steps:
    - env:
        GH_TOKEN: ${{ github.token }}
      run: eval "${{ inputs.payload }}"
      shell: bash
"""


def _flows(root, kind):
    corpus = build_corpus(str(root))
    return (
        find_cross_file_taint(corpus) if kind == "workflow" else find_cross_artifact_taint(corpus)
    )


def _case(
    root, kind, producer, call, value="${{ needs.produce.outputs.payload }}", needs="produce"
):
    caller = f"""on: issues
permissions:
  contents: write
jobs:
{producer}{_consumer(call, needs=needs, value=value)}
"""
    callee_path = (
        ".github/workflows/reusable.yml"
        if kind == "workflow"
        else ".github/actions/terminal/action.yml"
    )
    callee = _workflow_callee() if kind == "workflow" else _action_callee()
    _repo(root, {".github/workflows/caller.yml": caller, callee_path: callee})
    return _flows(root, kind)


def test_needs_job_output_crosses_explicit_local_workflow_call_with_source_witness(tmp_path):
    flows = _case(tmp_path, "workflow", _producer(), _workflow_target())
    assert len(flows) == 1
    flow = flows[0]
    assert flow.source_expr == "github.event.issue.title"
    assert flow.event == "issues"
    assert flow.source_file.endswith("caller.yml")
    assert flow.source_line == 12
    assert flow.callee.endswith("reusable.yml")
    assert ("caller.yml", 21, "payload") in [
        (file.rsplit("/", 1)[-1].rsplit("\\", 1)[-1], line, name)
        for file, line, name in flow.argument_lines
    ]
    assert flow.sink_line == 13
    assert {(line, kind) for _, line, kind, _ in flow.propagation_lines} >= {
        (12, "env_static"),
        (13, "step_output"),
        (8, "job_output"),
        (21, "needs_ref"),
    }
    assert flow.sink_snippet == 'eval "${{ inputs.payload }}"'
    assert any(
        "caller.yml" in note and "permission" in note.lower()
        for note in flow.authority.context_notes()
    )
    assert any(
        "reusable.yml" in note and "token" in note.lower()
        for note in flow.authority.context_notes()
    )


def test_needs_job_output_crosses_explicit_local_action_call_with_hop_lines(tmp_path):
    flows = _case(tmp_path, "action", _producer(), _action_target())
    assert len(flows) == 1
    flow = flows[0]
    assert flow.source_expr == "github.event.issue.title"
    assert flow.event == "issues"
    assert flow.source_file.endswith("caller.yml")
    assert flow.source_line == 12
    assert flow.callee.endswith("action.yml")
    assert ("caller.yml", 23, "payload") in [
        (file.rsplit("/", 1)[-1].rsplit("\\", 1)[-1], line, name)
        for file, line, name in flow.argument_lines
    ]
    assert flow.sink_snippet == 'eval "${{ inputs.payload }}"'
    assert flow.sink_line == 8
    assert {(line, kind) for _, line, kind, _ in flow.propagation_lines} >= {
        (12, "env_static"),
        (13, "step_output"),
        (8, "job_output"),
        (23, "needs_ref"),
    }


def test_literal_job_output_passed_to_local_call_is_not_attacker_bytes(tmp_path):
    assert _case(tmp_path, "workflow", _producer(output="fixed-value"), _workflow_target()) == []


def test_boolean_result_of_job_output_expression_is_not_original_bytes(tmp_path):
    value = "${{ needs.produce.outputs.payload == 'safe' }}"
    assert _case(tmp_path, "workflow", _producer(), _workflow_target(), value=value) == []


def test_job_output_reference_without_explicit_needs_is_not_confirmed(tmp_path):
    assert _case(tmp_path, "workflow", _producer(), _workflow_target(), needs="") == []


def test_missing_declared_job_output_does_not_inherit_step_output(tmp_path):
    producer = _producer().replace(
        "    outputs:\n      payload: ${{ steps.capture.outputs.payload }}\n", ""
    )
    assert _case(tmp_path, "workflow", producer, _workflow_target()) == []


def test_needs_output_from_sibling_not_in_declared_needs_is_not_donated(tmp_path):
    producer = (
        _producer()
        + "  other:\n    runs-on: ubuntu-latest\n    outputs:\n      payload: ${{ steps.capture.outputs.payload }}\n    steps:\n      - id: capture\n        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n        run: echo payload=$ISSUE_TITLE >> $GITHUB_OUTPUT\n"
    )
    value = "${{ needs.other.outputs.payload }}"
    assert _case(tmp_path, "workflow", producer, _workflow_target(), value=value) == []


def test_false_producer_guard_blocks_job_output_call_flow(tmp_path):
    assert _case(tmp_path, "workflow", _producer(guarded="false"), _workflow_target()) == []


def test_unknown_producer_guard_retains_flow_with_review_note(tmp_path):
    flows = _case(
        tmp_path, "workflow", _producer(guarded="${{ vars.ENABLE_PRODUCER }}"), _workflow_target()
    )
    assert len(flows) == 1
    assert any(
        "guard" in note.lower() or "runtime" in note.lower() for note in flows[0].review_notes
    )
