"""Provenance and shell-binding source semantics for local call flows."""
from taintly.cross_artifact_facts import find_cross_artifact_taint
from taintly.cross_workflow_facts import find_cross_file_taint
from taintly.workflow_corpus import build_corpus


def _repo(root, files):
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def _workflow_call(declared="      payload: {type: string}\n", event="issues"):
    return f"""on: {event}
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    with:
      payload: ${{{{ github.event.issue.title }}}}
"""


def _reusable(declaration):
    return """on:
  workflow_call:
    inputs:
""" + declaration + """jobs:
  consume:
    runs-on: ubuntu-latest
    steps:
      - run: eval "${{ inputs.payload }}"
"""


def _workflow_flows(root):
    return find_cross_file_taint(build_corpus(str(root)))


def _action_flows(root):
    return find_cross_artifact_taint(build_corpus(str(root)))


def _composite(run_body, *, producer_guard="", append=""):
    guard = f"      if: {producer_guard}\n" if producer_guard else ""
    return f"""name: provenance
inputs:
  payload: {{required: true}}
runs:
  using: composite
  steps:
    - id: producer
      env:
        VALUE: ${{{{ inputs.payload }}}}
{guard}      run: {run_body}
      shell: bash
{append}"""


def _action_repo(tmp_path, action):
    return _repo(tmp_path, {
        ".github/workflows/caller.yml": """on: issues
jobs:
  call:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/provenance
        with:
          payload: ${{ github.event.issue.title }}
""",
        ".github/actions/provenance/action.yml": action,
    })


def test_reusable_declared_number_and_boolean_do_not_prove_arbitrary_bytes(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/caller.yml": """on: issues
jobs:
  number_call:
    uses: ./.github/workflows/reusable.yml
    with:
      payload: ${{ github.event.issue.title }}
  boolean_call:
    uses: ./.github/workflows/reusable.yml
    with:
      payload: ${{ github.event.issue.title }}
""",
        ".github/workflows/reusable.yml": """on:
  workflow_call:
    inputs:
      payload:
        type: number
jobs:
  consume:
    runs-on: ubuntu-latest
    steps:
      - run: eval "${{ inputs.payload }}"
""",
    })
    flows = _workflow_flows(tmp_path)
    # A schema type mismatch is not evidence that an arbitrary string survives
    # GitHub input coercion. If retained as a candidate, it must be qualified.
    assert not flows or all(any("type" in note.lower() or "contract" in note.lower() for note in flow.review_notes) for flow in flows)


def test_boolean_typed_input_is_not_confirmed_arbitrary_text(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/caller.yml": _workflow_call(),
        ".github/workflows/reusable.yml": _reusable("      payload: {type: boolean}\n"),
    })
    flows = _workflow_flows(tmp_path)
    assert not flows or all(any("type" in note.lower() or "contract" in note.lower() for note in flow.review_notes) for flow in flows)


def test_undeclared_or_missing_type_input_is_explicitly_uncertain(tmp_path):
    cases = ["", "      payload: {description: payload}\n"]
    for index, declaration in enumerate(cases):
        repo = tmp_path / str(index)
        _repo(repo, {
            ".github/workflows/caller.yml": _workflow_call(),
            ".github/workflows/reusable.yml": _reusable(declaration),
        })
        flows = _workflow_flows(repo)
        assert not flows or all(any("type" in note.lower() or "contract" in note.lower() for note in flow.review_notes) for flow in flows)


def test_false_github_env_producer_does_not_taint_later_step(tmp_path):
    action = _composite(
        'echo "VALUE=$VALUE" >> "$GITHUB_ENV"',
        producer_guard="false",
        append="""    - run: eval "$VALUE"
      shell: bash
""",
    )
    _action_repo(tmp_path, action)
    assert _action_flows(tmp_path) == []


def test_dynamic_github_env_producer_guard_is_reviewed(tmp_path):
    action = _composite(
        'echo "VALUE=$VALUE" >> "$GITHUB_ENV"',
        producer_guard="${{ vars.ALLOW_EXPORT }}",
        append="""    - run: eval "$VALUE"
      shell: bash
""",
    )
    _action_repo(tmp_path, action)
    flows = _action_flows(tmp_path)
    assert len(flows) == 1
    assert any("runtime evaluation" in note for note in flows[0].review_notes)


def test_literal_eval_text_in_printf_does_not_reparse_tainted_binding(tmp_path):
    _action_repo(tmp_path, _composite("printf 'eval \"$VALUE\" %s' \"$VALUE\""))
    assert _action_flows(tmp_path) == []


def test_eval_of_unrelated_variable_does_not_reparse_tainted_binding(tmp_path):
    _action_repo(tmp_path, _composite('eval "$OTHER"; printf \'%s\' "$VALUE"'))
    assert _action_flows(tmp_path) == []


def test_actual_eval_of_tainted_binding_remains_candidate(tmp_path):
    _action_repo(tmp_path, _composite('eval "$VALUE"'))
    flows = _action_flows(tmp_path)
    assert len(flows) == 1
    assert flows[0].input == "payload"


def test_tainted_printf_piped_to_bash_remains_candidate(tmp_path):
    _action_repo(tmp_path, _composite('printf \'%s\' "$VALUE" | bash'))
    flows = _action_flows(tmp_path)
    assert len(flows) == 1
    assert flows[0].input == "payload"


def test_single_quoted_literal_variable_does_not_expand_tainted_value(tmp_path):
    _action_repo(tmp_path, _composite("printf '%s' '$VALUE'"))
    assert _action_flows(tmp_path) == []
