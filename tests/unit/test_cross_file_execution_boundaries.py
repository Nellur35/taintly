"""Execution-boundary regressions for cross-file workflow/action flows."""
from pathlib import Path

from taintly.cross_artifact_facts import find_cross_artifact_taint
from taintly.cross_workflow_facts import find_cross_file_taint
from taintly.workflow_corpus import build_corpus


def _repo(tmp_path, files):
    for rel, content in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return tmp_path


def _artifact_flows(tmp_path):
    return find_cross_artifact_taint(build_corpus(str(tmp_path)))


def test_workflow_run_string_does_not_create_local_action_edge(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/ci.yml": """on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat <<'EOF'
          - uses: ./.github/actions/ghost
            with:
              payload: ${{ github.event.pull_request.title }}
          EOF
""",
        ".github/actions/ghost/action.yml": """runs:
  using: composite
  steps:
    - run: echo ${{ inputs.payload }}
      shell: bash
""",
    })
    assert _artifact_flows(tmp_path) == []


def test_action_description_does_not_create_nested_edge_or_sink(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/ci.yml": """on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/wrapper
        with:
          payload: ${{ github.event.pull_request.title }}
""",
        ".github/actions/wrapper/action.yml": """name: wrapper
description: |
  Example only:
    - uses: ./.github/actions/inner
      with:
        payload: ${{ inputs.payload }}
runs:
  using: composite
  steps:
    - run: echo fixed
      shell: bash
""",
        ".github/actions/inner/action.yml": """runs:
  using: composite
  steps:
    - run: echo ${{ inputs.payload }}
      shell: bash
""",
    })
    assert _artifact_flows(tmp_path) == []


def test_javascript_action_description_run_example_is_not_a_sink(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/ci.yml": """on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/javascript
        with:
          payload: ${{ github.event.pull_request.title }}
""",
        ".github/actions/javascript/action.yml": """name: javascript
description: |
  Composite example:
    - run: echo ${{ inputs.payload }}
runs:
  using: node20
  main: index.js
""",
    })
    assert _artifact_flows(tmp_path) == []


def test_expression_inside_run_heredoc_remains_a_substitution_source(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/ci.yml": """on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/show
        with:
          payload: ${{ github.event.pull_request.title }}
""",
        ".github/actions/show/action.yml": """runs:
  using: composite
  steps:
    - run: |
        cat <<'EOF'
        echo "${{ inputs.payload }}"
        EOF
      shell: bash
""",
    })
    # GitHub substitutes expressions before shell parsing; retain this as a taint candidate.
    flows = _artifact_flows(tmp_path)
    assert len(flows) == 1
    assert flows[0].input == "payload"


def test_reusable_input_quoted_print_is_not_execution_but_eval_is(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/call.yml": """on: pull_request_target
jobs:
  reusable:
    uses: ./.github/workflows/reusable.yml
    with:
      payload: ${{ github.event.pull_request.title }}
""",
        ".github/workflows/reusable.yml": """on:
  workflow_call:
    inputs:
      payload: {type: string}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - env:
          VALUE: ${{ inputs.payload }}
        run: printf '%s' "$VALUE"
      - env:
          VALUE: ${{ inputs.payload }}
        run: eval "$VALUE"
      - if: ${{ inputs.payload != '' }}
        run: echo fixed
      - run: echo 'inputs.payload'
""",
    })
    flows = find_cross_file_taint(build_corpus(str(tmp_path)))
    assert len(flows) == 1
    assert flows[0].sink_snippet.strip() == 'run: eval "$VALUE"'


def test_independent_workflow_roots_remain_distinct(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/issues.yml": """on: pull_request_target
jobs:
  reusable:
    uses: ./.github/workflows/reusable.yml
    with:
      payload: ${{ github.event.pull_request.title }}
""",
        ".github/workflows/comments.yml": """on: [issue_comment]
jobs:
  reusable:
    uses: ./.github/workflows/reusable.yml
    with:
      payload: ${{ github.event.comment.body }}
""",
        ".github/workflows/reusable.yml": """on:
  workflow_call:
    inputs:
      payload: {type: string}
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      VALUE: ${{ inputs.payload }}
    steps:
      - run: eval "$VALUE"
""",
    })
    flows = find_cross_file_taint(build_corpus(str(tmp_path)))
    assert len(flows) == 2
    assert {Path(flow.caller).name for flow in flows} == {"issues.yml", "comments.yml"}
    assert {flow.source_expr for flow in flows} == {
        "github.event.pull_request.title", "github.event.comment.body"
    }


def test_workflow_reusable_composite_full_route_is_joined(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/caller.yml": """on: pull_request_target
jobs:
  reusable:
    uses: ./.github/workflows/reusable.yml
    with:
      payload: ${{ github.event.pull_request.title }}
""",
        ".github/workflows/reusable.yml": """on:
  workflow_call:
    inputs:
      payload: {type: string}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/terminal
        with:
          payload: ${{ inputs.payload }}
""",
        ".github/actions/terminal/action.yml": """name: terminal
inputs:
  payload: {description: value, required: true}
runs:
  using: composite
  steps:
    - env:
        PAYLOAD: ${{ inputs.payload }}
      run: eval "$PAYLOAD"
      shell: bash
""",
    })
    flows = _artifact_flows(tmp_path)
    assert len(flows) == 1
    flow = flows[0]
    assert flow.caller.endswith("caller.yml")
    assert flow.callee.endswith("terminal/action.yml")
    assert flow.source_expr == "github.event.pull_request.title"
    assert flow.input == "payload"
    assert flow.sink_line == 9
    assert len(flow.hop_chain) == 2
    assert flow.hop_chain[0][0].endswith("caller.yml")
    assert flow.hop_chain[1][0].endswith("reusable.yml")


def test_if_false_call_and_action_sink_do_not_form_reachable_flow(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/ci.yml": """on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - if: false
        uses: ./.github/actions/terminal
        with:
          payload: ${{ github.event.pull_request.title }}
""",
        ".github/actions/terminal/action.yml": """runs:
  using: composite
  steps:
    - if: false
      run: eval "${{ inputs.payload }}"
      shell: bash
""",
    })
    assert _artifact_flows(tmp_path) == []
