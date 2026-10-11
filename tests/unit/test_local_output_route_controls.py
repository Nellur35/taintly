"""Writer-state and byte-result controls for cross-job local-call bridges."""

import pytest

from tests.unit.test_local_call_job_outputs import _case, _producer, _workflow_target, _repo, _workflow_callee
from taintly.local_call_graph import find_local_flows
from taintly.workflow_corpus import build_corpus

_WRITE = 'run: echo "payload=$ISSUE_TITLE" >> "$GITHUB_OUTPUT"'


@pytest.mark.parametrize("replacement", [
    'run: ISSUE_TITLE=safe; echo "payload=$ISSUE_TITLE" >> "$GITHUB_OUTPUT"',
    'run: |\n          ISSUE_TITLE=safe\n          echo "payload=$ISSUE_TITLE" >> "$GITHUB_OUTPUT"',
    'run: |\n          echo "payload=$ISSUE_TITLE" >> "$GITHUB_OUTPUT"\n          printf \'payload=safe\\n\' > "$GITHUB_OUTPUT"',
    'run: |\n          echo "payload=$ISSUE_TITLE" >> "$GITHUB_OUTPUT"\n          echo "payload=safe" >> "$GITHUB_OUTPUT"',
    'run: |\n          unset ISSUE_TITLE\n          echo "payload=$ISSUE_TITLE" >> "$GITHUB_OUTPUT"',
    'run: |\n          read ISSUE_TITLE\n          echo "payload=$ISSUE_TITLE" >> "$GITHUB_OUTPUT"',
    'run: |\n          source ./prepare.sh\n          echo "payload=$ISSUE_TITLE" >> "$GITHUB_OUTPUT"',
    'run: echo \'echo "payload=${{ github.event.issue.title }}" >> "$GITHUB_OUTPUT"\'',
])
def test_uncertain_writer_state_cannot_confirm_attacker_bytes(tmp_path, replacement):
    producer = _producer().replace(_WRITE, replacement)
    flows = _case(tmp_path, "workflow", producer, _workflow_target())
    assert len(flows) == 1
    assert flows[0].review_notes
    assert any("writer" in n.lower() or "binding-state" in n.lower() for n in flows[0].review_notes)


def test_boolean_writer_cannot_borrow_unrelated_expression_in_same_run(tmp_path):
    producer = _producer().replace(_WRITE,
        'run: |\n          echo "payload=${{ github.event.issue.title == \'safe\' }}" >> "$GITHUB_OUTPUT"\n          echo "${{ github.event.issue.title }}"')
    assert _case(tmp_path, "workflow", producer, _workflow_target()) == []


def test_boolean_source_env_is_not_a_byte_source(tmp_path):
    producer = _producer().replace('ISSUE_TITLE: ${{ github.event.issue.title }}',
        "ISSUE_TITLE: ${{ github.event.issue.title == 'safe' }}")
    assert _case(tmp_path, "workflow", producer, _workflow_target()) == []


def test_boolean_declared_output_is_not_a_byte_bridge(tmp_path):
    producer = _producer(output="${{ steps.capture.outputs.payload == 'safe' }}")
    assert _case(tmp_path, "workflow", producer, _workflow_target()) == []


def test_inline_boolean_sibling_does_not_erase_real_source(tmp_path):
    producer = _producer().replace('env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}',
        "env: {ISSUE_TITLE: '${{ github.event.issue.title }}', CHECK: \"${{ github.event.issue.title == 'safe' }}\"}")
    flows = _case(tmp_path, "workflow", producer, _workflow_target())
    assert len(flows) == 1
    assert not flows[0].review_notes


@pytest.mark.parametrize("shell", ["pwsh", "custom {0}"])
def test_unresolved_writer_shell_is_review_only(tmp_path, shell):
    producer = _producer().replace(_WRITE, f"shell: {shell}\n        {_WRITE}")
    flows = _case(tmp_path, "workflow", producer, _workflow_target())
    assert len(flows) == 1
    assert any("shell" in n.lower() for n in flows[0].review_notes)


def test_false_writer_step_guard_blocks_flow(tmp_path):
    producer = _producer().replace("- id: capture", "- id: capture\n        if: false")
    assert _case(tmp_path, "workflow", producer, _workflow_target()) == []


def test_matrix_writer_remains_review_only(tmp_path):
    producer = _producer().replace("    runs-on: ubuntu-latest", "    strategy:\n      matrix: {variant: [one, two]}\n    runs-on: ubuntu-latest")
    flows = _case(tmp_path, "workflow", producer, _workflow_target())
    assert len(flows) == 1
    assert any("matrix" in n.lower() for n in flows[0].review_notes)


@pytest.mark.parametrize("declared", [True, False])
def test_transitive_output_bridge_requires_each_actual_dependency(tmp_path, declared):
    middle = """  forward:
    needs: produce
    runs-on: ubuntu-latest
    outputs:
      forwarded: ${{ needs.produce.outputs.payload }}
    steps:
      - run: echo ready
"""
    if not declared:
        middle = middle.replace("    needs: produce\n", "")
    flows = _case(tmp_path, "workflow", _producer() + middle, _workflow_target(),
                  needs="[forward]", value="${{ needs.forward.outputs.forwarded }}")
    assert len(flows) == int(declared)
    if declared:
        assert not flows[0].review_notes
        assert sum(kind == "job_output" for _, _, kind, _ in flows[0].propagation_lines) == 2


def test_symbolic_job_output_resolves_inputs_per_nested_invocation(tmp_path):
    caller = """on: issues
permissions: {contents: read}
jobs:
  unsafe:
    uses: ./.github/workflows/middle.yml
    with:
      title: ${{ github.event.issue.title }}
  safe:
    uses: ./.github/workflows/middle.yml
    with:
      title: fixed
"""
    producer = _producer().replace("${{ github.event.issue.title }}", "${{ inputs.title }}")
    middle = """on:
  workflow_call:
    inputs:
      title: {type: string}
jobs:
""" + producer + """  consume:
    needs: produce
    uses: ./.github/workflows/reusable.yml
    with:
      payload: ${{ needs.produce.outputs.payload }}
"""
    _repo(tmp_path, {".github/workflows/caller.yml": caller,
        ".github/workflows/middle.yml": middle,
        ".github/workflows/reusable.yml": _workflow_callee()})
    flows = find_local_flows(build_corpus(str(tmp_path)))
    assert len(flows) == 1
    flow = flows[0]
    assert flow.source_expr == "github.event.issue.title"
    assert flow.source_file.endswith("caller.yml")
    assert len(flow.hop_chain) == 2
    assert any(file.endswith("middle.yml") and kind == "job_output" for file, _, kind, _ in flow.propagation_lines)
