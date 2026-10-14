"""Expanded, source-labeled controls for local workflow/action call analysis."""

import pytest

from taintly import local_call_graph
from taintly.cross_artifact_facts import find_cross_artifact_taint
from taintly.cross_workflow_facts import find_cross_file_taint
from taintly.engine import scan_repo
from taintly.local_call_graph import find_local_flows
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform
from taintly.workflow_corpus import build_corpus


def _repo(root, files):
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def _flows(root):
    return find_local_flows(build_corpus(str(root)))


def _engine_findings(root):
    reports = scan_repo(
        str(root), load_rules_for_platform(Platform.GITHUB), Platform.GITHUB
    )
    return [finding for report in reports for finding in report.findings]


def _caller(uses, expression="${{ github.event.issue.title }}", guard=""):
    guarded = f"    if: {guard}\n" if guard else ""
    return f"""on: issues
jobs:
  run:
{guarded}    uses: {uses}
    with:
      payload: {expression}
"""


def test_with_mapping_before_uses_is_owned_by_same_step(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/caller.yml": """on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - with:
          payload: ${{ github.event.issue.title }}
        uses: ./.github/actions/terminal
""",
        ".github/actions/terminal/action.yml": """inputs:
  payload: {required: true}
runs:
  using: composite
  steps:
    - run: eval "${{ inputs.payload }}"
      shell: bash
""",
    })
    flows = find_cross_artifact_taint(build_corpus(str(tmp_path)))
    assert len(flows) == 1
    assert flows[0].source_expr == "github.event.issue.title"
    assert flows[0].input == "payload"


def test_boolean_expression_is_quiet_but_format_and_fallback_keep_bytes(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/caller.yml": _caller("./.github/workflows/reusable.yml"),
        ".github/workflows/reusable.yml": """on:
  workflow_call:
    inputs:
      payload: {type: string}
jobs:
  consume:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ inputs.payload != '' }}
      - run: eval ${{ format('{0}', inputs.payload) }}
      - run: eval ${{ inputs.payload || 'safe' }}
""",
    })
    flows = find_cross_file_taint(build_corpus(str(tmp_path)))
    assert len(flows) == 2
    assert {flow.sink_line for flow in flows} == {10, 11}


def test_distinct_call_sites_in_one_root_file_are_not_collapsed(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/caller.yml": """on: issues
jobs:
  first:
    uses: ./.github/workflows/reusable.yml
    with:
      payload: ${{ github.event.issue.title }}
  second:
    uses: ./.github/workflows/reusable.yml
    with:
      payload: ${{ github.event.issue.body }}
""",
        ".github/workflows/reusable.yml": """on:
  workflow_call:
    inputs:
      payload: {type: string}
jobs:
  consume:
    runs-on: ubuntu-latest
    steps:
      - run: eval "${{ inputs.payload }}"
""",
    })
    flows = find_cross_file_taint(build_corpus(str(tmp_path)))
    assert len(flows) == 2
    assert len({flow.caller_line for flow in flows}) == 2
    assert {flow.source_expr for flow in flows} == {
        "github.event.issue.title", "github.event.issue.body"
    }


def test_push_event_does_not_source_pull_request_title(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/push.yml": _caller(
            "./.github/workflows/reusable.yml",
            expression="${{ github.event.pull_request.title }}",
        ).replace("on: issues", "on: push"),
        ".github/workflows/reusable.yml": """on:
  workflow_call:
    inputs:
      payload: {type: string}
jobs:
  consume:
    runs-on: ubuntu-latest
    steps:
      - run: eval "${{ inputs.payload }}"
""",
    })
    assert find_cross_file_taint(build_corpus(str(tmp_path))) == []


def test_dead_call_dead_sink_and_dead_owning_job_are_filtered(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/caller.yml": """on: issues
jobs:
  dead_call:
    if: false
    uses: ./.github/workflows/dead.yml
    with:
      payload: ${{ github.event.issue.title }}
  live_call:
    uses: ./.github/workflows/mixed.yml
    with:
      payload: ${{ github.event.issue.title }}
""",
        ".github/workflows/dead.yml": """on:
  workflow_call:
    inputs:
      payload: {type: string}
jobs:
  consume:
    runs-on: ubuntu-latest
    steps:
      - run: eval "${{ inputs.payload }}"
""",
        ".github/workflows/mixed.yml": """on:
  workflow_call:
    inputs:
      payload: {type: string}
jobs:
  dead_job:
    if: false
    runs-on: ubuntu-latest
    steps:
      - run: eval "${{ inputs.payload }}"
  live_job:
    runs-on: ubuntu-latest
    steps:
      - if: false
        run: eval "${{ inputs.payload }}"
      - run: eval "${{ inputs.payload }}"
""",
    })
    flows = find_cross_file_taint(build_corpus(str(tmp_path)))
    assert len(flows) == 1
    assert flows[0].callee.endswith("mixed.yml")
    assert flows[0].sink_line == 16


def test_dynamic_guard_is_retained_with_review_note(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/caller.yml": _caller(
            "./.github/workflows/reusable.yml", guard="${{ vars.ALLOW_CALL }}"
        ),
        ".github/workflows/reusable.yml": """on:
  workflow_call:
    inputs:
      payload: {type: string}
jobs:
  consume:
    runs-on: ubuntu-latest
    steps:
      - run: eval "${{ inputs.payload }}"
""",
    })
    flows = find_cross_file_taint(build_corpus(str(tmp_path)))
    assert len(flows) == 1
    assert any("runtime evaluation" in note for note in flows[0].review_notes)


def test_orphan_local_action_does_not_create_flow(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/ci.yml": """on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo safe
""",
        ".github/actions/orphan/action.yml": """inputs:
  payload: {required: true}
runs:
  using: composite
  steps:
    - run: eval "${{ inputs.payload }}"
      shell: bash
""",
    })
    assert _flows(tmp_path) == []
    assert find_cross_artifact_taint(build_corpus(str(tmp_path))) == []


def test_composite_quoted_printf_is_data_but_eval_is_reparse(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/caller.yml": """on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/terminal
        with:
          payload: ${{ github.event.issue.title }}
""",
        ".github/actions/terminal/action.yml": """name: terminal
inputs:
  payload: {required: true}
runs:
  using: composite
  steps:
    - id: quoted
      env:
        VALUE: ${{ inputs.payload }}
      run: printf '%s' "$VALUE"
      shell: bash
    - id: executed
      env:
        VALUE: ${{ inputs.payload }}
      run: eval "$VALUE"
      shell: bash
""",
    })
    flows = find_cross_artifact_taint(build_corpus(str(tmp_path)))
    assert len(flows) == 1
    assert flows[0].sink_snippet.strip() == 'run: eval "$VALUE"'
    assert flows[0].sink_line == 15


def test_composite_env_to_github_output_to_later_sink_is_traced(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/caller.yml": """on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/terminal
        with:
          payload: ${{ github.event.issue.title }}
""",
        ".github/actions/terminal/action.yml": """name: terminal
inputs:
  payload: {required: true}
runs:
  using: composite
  steps:
    - id: export
      env:
        VALUE: ${{ inputs.payload }}
      run: echo "forwarded=$VALUE" >> "$GITHUB_OUTPUT"
      shell: bash
    - env:
        FORWARDED: ${{ steps.export.outputs.forwarded }}
      run: eval "$FORWARDED"
      shell: bash
""",
    })
    flows = find_cross_artifact_taint(build_corpus(str(tmp_path)))
    assert len(flows) == 1
    assert flows[0].sink_line == 14


def test_symlinked_action_outside_repo_is_not_opened(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir()
    outside_action = outside / "action.yml"
    outside_action.write_text("""runs:\n  using: composite\n  steps:\n    - run: eval '${{ inputs.payload }}'\n""", encoding="utf-8")
    link = tmp_path / ".github/actions/escape"
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlinks unavailable on this host: {exc}")
    _repo(tmp_path, {
        ".github/workflows/caller.yml": """on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/escape
        with:
          payload: ${{ github.event.issue.title }}
""",
    })
    assert _flows(tmp_path) == []
    assert outside_action.read_text(encoding="utf-8").startswith("runs:")


def test_traversal_action_ref_does_not_escape_repo(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-traversal")
    outside.mkdir()
    (outside / "action.yml").write_text("""runs:\n  using: composite\n  steps:\n    - run: eval '${{ inputs.payload }}'\n""", encoding="utf-8")
    _repo(tmp_path, {
        ".github/workflows/caller.yml": """on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./../""" + outside.name + "\n        with:\n          payload: ${{ github.event.issue.title }}\n",
    })
    assert _flows(tmp_path) == []


def test_cycle_limit_surfaces_as_engine_err(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/caller.yml": """on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/a
        with:
          payload: ${{ github.event.issue.title }}
""",
        ".github/actions/a/action.yml": """runs:
  using: composite
  steps:
    - uses: ./.github/actions/b
      with:
        payload: ${{ inputs.payload }}
""",
        ".github/actions/b/action.yml": """runs:
  using: composite
  steps:
    - uses: ./.github/actions/a
      with:
        payload: ${{ inputs.payload }}
""",
    })
    findings = _engine_findings(tmp_path)
    errors = [f for f in findings if f.rule_id == "ENGINE-ERR"]
    assert errors
    assert any("Cyclic local call" in f.title for f in errors)
    assert any("coverage incomplete" in f.title for f in errors)


def test_size_limit_surfaces_as_engine_err(tmp_path):
    large = "# padded metadata\n" + ("#" + "z" * 100 + "\n") * 4001
    _repo(tmp_path, {
        ".github/workflows/caller.yml": """on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/large
""",
        ".github/actions/large/action.yml": """runs:
  using: composite
  steps:
    - run: echo done
      shell: bash
""" + large,
    })
    findings = _engine_findings(tmp_path)
    errors = [f for f in findings if f.rule_id == "ENGINE-ERR"]
    assert errors
    assert any("Local call graph file size limit" in f.title for f in errors)


def test_engine_evidence_has_source_sink_authority_caveat_and_review_title(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/caller.yml": """on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/terminal
        with:
          payload: ${{ github.event.issue.title }}
""",
        ".github/actions/terminal/action.yml": """inputs:
  payload: {required: true}
runs:
  using: composite
  steps:
    - run: eval "${{ inputs.payload }}"
      shell: bash
""",
    })
    findings = [f for f in _engine_findings(tmp_path) if f.rule_id == "XF-GH-006"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.review_needed is True
    assert "Confirmed" not in finding.title
    assert "execution-context review" in finding.title
    assert "caller.yml:" in finding.remediation
    assert "action.yml:" in finding.remediation
    assert any("Token permissions" in note and "not established" in note for note in finding.context_notes)


def test_multiline_expression_and_sibling_steps_preserve_sink_lines(tmp_path):
    _repo(tmp_path, {
        ".github/workflows/caller.yml": """on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/terminal
        with:
          payload: ${{ github.event.issue.title }}
""",
        ".github/actions/terminal/action.yml": """inputs:
  payload: {required: true}
runs:
  using: composite
  steps:
    - run: |
        echo fixed
        eval "${{
          inputs.payload
        }}"
      shell: bash
    - run: echo sibling
      shell: bash
""",
    })
    flows = find_cross_artifact_taint(build_corpus(str(tmp_path)))
    assert len(flows) == 1
    assert flows[0].sink_line == 8
    assert flows[0].input == "payload"


@pytest.mark.parametrize(("kind", "rule_id"), [("workflow", "XF-GH-005"), ("action", "XF-GH-006")])
def test_new_cross_file_findings_keep_severity_with_deliberate_medium_confidence(tmp_path, kind, rule_id):
    if kind == "workflow":
        caller = _caller("./.github/workflows/reusable.yml")
        target = ".github/workflows/reusable.yml"
        body = """on:
  workflow_call:
    inputs:
      payload: {type: string}
jobs:
  consume:
    runs-on: ubuntu-latest
    steps:
      - run: eval "${{ inputs.payload }}"
"""
    else:
        caller = """on: issues
jobs:
  consume:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/terminal
        with:
          payload: ${{ github.event.issue.title }}
"""
        target = ".github/actions/terminal/action.yml"
        body = """inputs:
  payload: {required: true}
runs:
  using: composite
  steps:
    - run: eval "${{ inputs.payload }}"
      shell: bash
"""
    _repo(tmp_path, {".github/workflows/caller.yml": caller, target: body})
    findings = [f for f in _engine_findings(tmp_path) if f.rule_id == rule_id]
    assert len(findings) == 1
    assert findings[0].severity.name == "HIGH"
    assert findings[0].confidence == "medium"
    assert findings[0].review_needed is (kind == "action")


@pytest.mark.parametrize(
    ("uses", "action_path"),
    [
        ("./.github/actions/check", ".github/actions/check/action.yml"),
        ("./.github/actions/check/", ".github/actions/check/action.yml"),
        ("./", "action.yml"),
    ],
)
def test_local_action_root_and_single_trailing_slash_paths_keep_flow(
    tmp_path, uses, action_path
):
    _repo(
        tmp_path,
        {
            ".github/workflows/caller.yml": f"""on: issues
permissions: {{contents: read}}
jobs:
  audit:
    if: github.event.action == 'opened'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: {uses}
        with:
          payload: ${{{{ github.event.issue.body }}}}
""",
            action_path: """inputs:
  payload: {required: true}
runs:
  using: composite
  steps:
    - env:
        PAYLOAD: ${{ inputs.payload }}
      run: eval "$PAYLOAD"
      shell: bash
""",
        },
    )

    flows = _flows(tmp_path)

    assert len(flows) == 1
    assert flows[0].source_expr == "github.event.issue.body"
    assert flows[0].input == "payload"
    assert flows[0].callee.endswith(action_path)
    assert flows[0].sink_snippet.strip() == 'run: eval "$PAYLOAD"'


def test_root_local_action_data_only_step_does_not_create_sink_flow(tmp_path):
    _repo(
        tmp_path,
        {
            ".github/workflows/caller.yml": """on: issues
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: ./
        with:
          payload: ${{ github.event.issue.body }}
""",
            "action.yml": """inputs:
  payload: {required: true}
runs:
  using: composite
  steps:
    - env:
        PAYLOAD: ${{ inputs.payload }}
      run: printf '%s' "$PAYLOAD"
      shell: bash
""",
        },
    )

    assert _flows(tmp_path) == []


def test_root_action_path_does_not_expand_reusable_workflow_resolution(tmp_path):
    _repo(tmp_path, {"action.yml": "runs: {using: composite, steps: []}\n"})

    assert local_call_graph._resolve(str(tmp_path), "./", "workflow") is None


@pytest.mark.parametrize(
    "ref",
    [
        "./.github/actions/check//",
        "./.github//actions/check",
        "./.github/actions/./check",
        "./.github/actions/../check",
        "./.github/actions/$dynamic",
        "./.github\\actions\\check",
    ],
)
def test_local_action_paths_keep_rejecting_ambiguous_components(tmp_path, ref):
    _repo(
        tmp_path,
        {
            ".github/workflows/caller.yml": f"""on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: {ref}
        with:
          payload: ${{{{ github.event.issue.body }}}}
""",
            ".github/actions/check/action.yml": """inputs:
  payload: {required: true}
runs:
  using: composite
  steps:
    - run: eval "${{ inputs.payload }}"
      shell: bash
""",
        },
    )

    assert _flows(tmp_path) == []
