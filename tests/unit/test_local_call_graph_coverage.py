"""Cross-file coverage diagnostics and original-line propagation evidence."""

import pytest

from taintly import local_call_graph
from taintly.engine import _run_corpus_rules
from taintly.rules.github.cross_artifact import RULES
from taintly.rules.github.cross_workflow import RULES as WORKFLOW_RULES
from taintly.workflow_corpus import build_corpus


def _write(root, rel, content):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _repo(root, guard=""):
    _write(root, ".github/workflows/caller.yml", """on: issues
jobs:
  caller:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/forward
        with:
          payload: ${{ github.event.issue.title }}
""")
    _write(root, ".github/actions/forward/action.yml", """inputs:
  payload: {required: true}
runs:
  using: composite
  steps:
    - id: export
      env:
        VALUE: ${{ inputs.payload }}
""" + (f"      if: {guard}\n" if guard else "") + """      run: echo "forwarded=$VALUE" >> "$GITHUB_OUTPUT"
      shell: bash
    - env:
        FORWARDED: ${{ steps.export.outputs.forwarded }}
      run: eval "$FORWARDED"
      shell: bash
""")


def test_missing_local_target_reports_incomplete_coverage(tmp_path):
    _repo(tmp_path)
    (tmp_path / ".github/actions/forward/action.yml").unlink()
    findings = _run_corpus_rules(str(tmp_path), RULES)
    assert any(
        f.rule_id == "ENGINE-ERR"
        and f.file == str(tmp_path / ".github/workflows/caller.yml")
        and "Line 6: Referenced local action './.github/actions/forward' is unavailable" in f.description
        for f in findings
    )
    assert not any(f.rule_id == "XF-GH-006" for f in findings)


def test_reusable_flow_survives_missing_sibling_sources(tmp_path):
    caller = ".github/workflows/caller.yml"
    callee = ".github/workflows/callee.yml"
    _write(tmp_path, caller, """on: issues
jobs:
  unrelated:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/missing
  missing:
    uses: ./.github/workflows/missing.yml
    with:
      label: ${{ github.event.issue.title }}
  known:
    if: ${{ vars.ALLOW_CALL }}
    uses: ./.github/workflows/callee.yml
    with:
      label: ${{ github.event.issue.title }}
  literal:
    uses: ./.github/workflows/callee.yml
    with:
      label: fixed
""")
    _write(tmp_path, callee, """on:
  workflow_call:
    inputs:
      label: {type: string}
jobs:
  display:
    runs-on: ubuntu-latest
    steps:
      - run: printf '%s' "${{ inputs.label }}"
""")
    rule = next(rule for rule in WORKFLOW_RULES if rule.id == "XF-GH-005")
    findings = _run_corpus_rules(str(tmp_path), [rule])
    path, = [f for f in findings if f.rule_id == rule.id]
    assert path.file == str(tmp_path / caller)
    assert path.line == 13
    assert path.review_needed
    assert f"Input 'label' supplied at {tmp_path / caller}:15." in path.context_notes
    assert f"Configured sink: {tmp_path / callee}:9." in path.context_notes
    assert f"Guard at {tmp_path / caller}:12 needs runtime evaluation." in path.context_notes
    gap, = [f for f in findings if f.rule_id == "ENGINE-ERR"]
    assert gap.file == path.file
    assert "Line 6: Referenced local action" in gap.description
    assert "Line 8: Referenced local workflow" in gap.description


def test_total_binding_limit_reports_incomplete_coverage(tmp_path, monkeypatch):
    _repo(tmp_path)
    monkeypatch.setattr(local_call_graph, "_MAX_BINDINGS", 0)
    findings = _run_corpus_rules(str(tmp_path), RULES)
    assert any(f.rule_id == "ENGINE-ERR" and "binding limit" in f.title for f in findings)


@pytest.mark.parametrize("guard", ["false", "${{ vars.ALLOW_OUTPUT }}", ""])
def test_output_hops_preserve_owning_guard_and_original_lines(tmp_path, guard):
    _repo(tmp_path, guard)
    flows = local_call_graph.find_local_flows(build_corpus(str(tmp_path)))
    if guard == "false":
        assert flows == []
        return
    assert len(flows) == 1
    flow = flows[0]
    source = (tmp_path / ".github/actions/forward/action.yml").read_text(encoding="utf-8").splitlines()
    writer = next(n for n, line in enumerate(source, 1) if "GITHUB_OUTPUT" in line)
    reader = next(n for n, line in enumerate(source, 1) if "FORWARDED:" in line)
    assert any(line == writer and kind == "step_output" for _, line, kind, _ in flow.propagation_lines)
    assert any(line == reader and kind == "env_indirect" for _, line, kind, _ in flow.propagation_lines)
    assert any("runtime evaluation" in note for note in flow.review_notes) == bool(guard)
    evidence = local_call_graph.flow_evidence(flow, "probe")
    assert any(f":{writer}:" in note and "step_output" in note for note in evidence.context_notes)
