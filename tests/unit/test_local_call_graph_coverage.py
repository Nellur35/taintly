"""Cross-file coverage diagnostics and original-line propagation evidence."""

import pytest

from taintly import local_call_graph
from taintly.engine import _run_corpus_rules
from taintly.rules.github.cross_artifact import RULES
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
    assert any(f.rule_id == "ENGINE-ERR" and "unavailable" in f.title for f in findings)
    assert not any(f.rule_id == "XF-GH-006" for f in findings)


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
