"""Finite authority counterexamples; no scanned commands are executed."""
import pytest

from taintly.authority_context import _Index
from taintly.local_call_graph import find_local_flows
from taintly.workflow_corpus import build_corpus


def _flows(root, files):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return find_local_flows(build_corpus(str(root)))


def _caller(*, extra="", grants="permissions: {contents: write}"):
    return """on: issues
""" + grants + """
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    with:
      payload: ${{ github.event.issue.title }}
""" + extra


def _callee(*, extra="", step="", run='eval "${{ inputs.payload }}"', declarations=""):
    return """on:
  workflow_call:
    inputs:
      payload: {type: string}
""" + declarations + """jobs:
  sink:
    runs-on: ubuntu-latest
""" + extra + """    steps:
      - run: """ + run + "\n" + step


@pytest.mark.parametrize("value,id_level,vuln_level", [("read-all", "none", "read"), ("write-all", "write", "read"), ("{}", "none", "none")])
def test_permission_vectors_respect_scope_specific_levels(value, id_level, vuln_level):
    index = _Index(f"permissions: {value}\njobs:\n  build:\n    runs-on: ubuntu-latest\n")
    grants = index.grants("build")
    assert grants.known
    assert dict(grants.levels)["id-token"] == id_level
    assert dict(grants.levels)["vulnerability-alerts"] == vuln_level


@pytest.mark.parametrize("grants", ["", "permissions: ${{ inputs.grants }}"])
def test_missing_or_dynamic_caller_ceiling_cannot_confirm_callee_write(tmp_path, grants):
    flows = _flows(tmp_path, {
        ".github/workflows/caller.yml": _caller(grants=grants),
        ".github/workflows/reusable.yml": _callee(extra="    permissions: {contents: write}\n", step="        env: {TOKEN: '${{ github.token }}'}\n"),
    })
    assert len(flows) == 1
    assert flows[0].authority.state == "unresolved"
    assert not flows[0].authority.token_permissions


def test_nested_secret_rename_keeps_each_edge_and_sink_witness(tmp_path):
    flows = _flows(tmp_path, {
        ".github/workflows/caller.yml": _caller(extra="    secrets: {first: '${{ secrets.ORIGINAL }}'}\n"),
        ".github/workflows/reusable.yml": """on:
  workflow_call:
    inputs:
      payload: {type: string}
    secrets:
      first: {required: true}
jobs:
  next:
    uses: ./.github/workflows/leaf.yml
    with:
      payload: ${{ inputs.payload }}
    secrets:
      final: ${{ secrets.first }}
""",
        ".github/workflows/leaf.yml": _callee(declarations="    secrets:\n      final: {required: true}\n", step="        env:\n          TOKEN: ${{ secrets.final }}\n"),
    })
    assert len(flows) == 1
    authority = flows[0].authority
    assert authority.state == "configured"
    assert len(authority.secret_access) == 1
    binding = authority.secret_access[0]
    assert binding.source == "secrets.original"
    assert [w.file.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] for w in binding.witnesses] == ["caller.yml", "reusable.yml", "leaf.yml"]
    assert [w.detail for w in binding.witnesses] == ["secret mapping first", "secret mapping final", "env TOKEN"]


def test_secret_forwarded_but_not_bound_at_sink_is_not_exposure(tmp_path):
    flows = _flows(tmp_path, {
        ".github/workflows/caller.yml": _caller(extra="    secrets: {deploy: '${{ secrets.PAT }}'}\n"),
        ".github/workflows/reusable.yml": _callee(declarations="    secrets:\n      deploy: {required: true}\n", extra="    permissions: {contents: read}\n"),
    })
    assert len(flows) == 1
    assert not flows[0].authority.secret_access
    assert flows[0].authority.state == "limited"


def test_environment_selected_secret_is_not_assumed_released_or_same_value(tmp_path):
    flows = _flows(tmp_path, {
        ".github/workflows/caller.yml": _caller(extra="    secrets: {deploy: '${{ secrets.PAT }}'}\n"),
        ".github/workflows/reusable.yml": _callee(declarations="    secrets:\n      deploy: {required: true}\n", extra="    environment: production\n", step="        env:\n          TOKEN: ${{ secrets.deploy }}\n"),
    })
    assert len(flows) == 1
    assert flows[0].authority.state == "unresolved"
    assert not flows[0].authority.secret_access
    assert any("precedence/release" in note for note in flows[0].authority.notes)


def test_secret_bound_only_in_earlier_step_not_donated_to_sink(tmp_path):
    callee = _callee(declarations="    secrets:\n      deploy: {required: true}\n", extra="    permissions: {contents: read}\n")
    callee = callee.replace("    steps:\n", "    steps:\n      - run: echo earlier\n        env:\n          TOKEN: ${{ secrets.deploy }}\n")
    flows = _flows(tmp_path, {".github/workflows/caller.yml": _caller(extra="    secrets: {deploy: '${{ secrets.PAT }}'}\n"), ".github/workflows/reusable.yml": callee})
    assert len(flows) == 1
    assert not flows[0].authority.secret_access
    assert flows[0].authority.state == "limited"


def test_credential_input_alias_consumed_in_env_is_traced(tmp_path):
    caller = _caller().replace("      payload:", "      credential: ${{ github.token }}\n      payload:")
    callee = _callee(step="        env:\n          TOKEN: ${{ inputs.credential }}\n").replace("      payload: {type: string}", "      payload: {type: string}\n      credential: {type: string}")
    flows = _flows(tmp_path, {".github/workflows/caller.yml": caller, ".github/workflows/reusable.yml": callee})
    assert len(flows) == 1
    assert flows[0].authority.state == "configured"
    assert len(flows[0].authority.token_access) == 1
    assert [w.detail for w in flows[0].authority.token_access[0].witnesses] == ["input credential", "env TOKEN"]


def test_incompatible_grant_retains_reviewable_execution_candidate(tmp_path):
    flows = _flows(tmp_path, {
        ".github/workflows/caller.yml": _caller(grants="permissions: {contents: read}"),
        ".github/workflows/reusable.yml": _callee(extra="    permissions: {contents: write}\n"),
    })
    assert len(flows) == 1
    assert flows[0].authority.invocation_unresolved
    assert flows[0].review_notes


@pytest.mark.parametrize("directory", ["plain", "unresolved-directory"])
def test_step_literal_override_removes_environment_secret_ambiguity(tmp_path, directory):
    flows = _flows(tmp_path / directory, {
        ".github/workflows/caller.yml": _caller(extra="    secrets: {deploy: '${{ secrets.PAT }}'}\n"),
        ".github/workflows/reusable.yml": _callee(declarations="    secrets:\n      deploy: {required: true}\n", extra="    permissions: {contents: read}\n    environment: production\n    env:\n      TOKEN: ${{ secrets.deploy }}\n", step="        env:\n          TOKEN: fixed\n"),
    })
    assert len(flows) == 1
    assert flows[0].authority.state == "limited"
    assert not flows[0].authority.secret_access


def test_opaque_caller_env_cannot_be_certified_limited_inside_composite(tmp_path):
    caller = """on: issues
permissions: {contents: read}
jobs:
  call:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/a
        env:
          TOKEN: ${{ vars.DYNAMIC }}
        with:
          payload: ${{ github.event.issue.title }}
"""
    flows = _flows(tmp_path, {
        ".github/workflows/caller.yml": caller,
        ".github/actions/a/action.yml": """inputs:
  payload: {required: true}
runs:
  using: composite
  steps:
    - run: eval "${{ inputs.payload }}"
      shell: bash
""",
    })
    assert len(flows) == 1
    assert flows[0].authority.state == "unresolved"


def test_credential_input_nonstring_contract_retains_invocation_review(tmp_path):
    caller = _caller().replace("      payload:", "      credential: ${{ github.token }}\n      payload:")
    callee = _callee(step="        env:\n          TOKEN: ${{ inputs.credential }}\n").replace("      payload: {type: string}", "      payload: {type: string}\n      credential: {type: number}")
    flows = _flows(tmp_path, {".github/workflows/caller.yml": caller, ".github/workflows/reusable.yml": callee})
    assert len(flows) == 1
    assert flows[0].authority.invocation_unresolved
    assert flows[0].review_notes
    assert not flows[0].authority.token_access


def test_literal_required_secret_is_supplied_even_without_external_provenance(tmp_path):
    flows = _flows(tmp_path, {
        ".github/workflows/caller.yml": _caller(extra="    secrets: {deploy: synthetic-literal}\n"),
        ".github/workflows/reusable.yml": _callee(declarations="    secrets:\n      deploy: {required: true}\n", step="        env:\n          TOKEN: ${{ secrets.deploy }}\n"),
    })
    assert len(flows) == 1
    assert not flows[0].authority.invocation_unresolved
    assert not flows[0].review_notes
    assert not flows[0].authority.secret_access
    assert not any("forwarding stopped" in note or "no configured incoming binding" in note for note in flows[0].authority.notes)


def test_run_template_access_witness_cites_expression_not_block_header(tmp_path):
    callee = _callee(run='|\n          echo first\n          eval "${{ inputs.payload }}"\n          echo "${{ github.token }}"')
    token_line = next(n for n, line in enumerate(callee.splitlines(), 1) if "github.token" in line)
    flows = _flows(tmp_path, {".github/workflows/caller.yml": _caller(), ".github/workflows/reusable.yml": callee})
    assert len(flows) == 1
    assert len(flows[0].authority.token_access) == 1
    assert flows[0].authority.token_access[0].witnesses[-1].line == token_line
