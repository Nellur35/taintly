"""Cross-file coverage diagnostics and original-line propagation evidence."""

import json
import subprocess
import sys

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
    with pytest.raises(local_call_graph.LocalGraphLimitError, match="is unavailable"):
        local_call_graph.find_local_flows(build_corpus(str(tmp_path)))


@pytest.mark.parametrize("fail_first", [False, True])
def test_local_rules_share_success_and_retry_failure(tmp_path, monkeypatch, fail_first):
    _repo(tmp_path)
    caller = tmp_path / ".github/workflows/caller.yml"
    with caller.open("a", encoding="utf-8") as stream:
        stream.write("      - uses: ./.github/actions/missing\n")
    original = local_call_graph.find_local_flows
    calls = 0

    def traverse(corpus, *, source_gaps=None):
        nonlocal calls
        calls += 1
        if fail_first and calls == 1:
            raise OSError("unavailable during first traversal")
        return original(corpus, source_gaps=source_gaps)

    monkeypatch.setattr(local_call_graph, "find_local_flows", traverse)
    workflow_rule = next(rule for rule in WORKFLOW_RULES if rule.id == "XF-GH-005")
    rules = [workflow_rule, *RULES]
    findings = _run_corpus_rules(str(tmp_path), rules)
    assert calls == (2 if fail_first else 1)
    assert any(f.rule_id == "XF-GH-006" for f in findings)
    workflow_gap, action_gap = [f for f in findings if f.rule_id == "ENGINE-ERR"]
    assert "XF-GH-005" in workflow_gap.title + workflow_gap.description
    assert ("unavailable during first traversal" if fail_first else "actions/missing") in (
        workflow_gap.description
    )
    assert "XF-GH-006" in action_gap.description
    assert "actions/missing" in action_gap.description

    caller.write_text(caller.read_text(encoding="utf-8").replace("      - uses: ./.github/actions/missing\n", ""),
                      encoding="utf-8")
    rescanned = _run_corpus_rules(str(tmp_path), rules)
    assert calls == (3 if fail_first else 2)
    assert [f.rule_id for f in rescanned] == ["XF-GH-006"]


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


def test_cli_reports_full_missing_source_evidence(tmp_path):
    header = """on: push
permissions: {}
jobs:
  check:
    runs-on: ubuntu-latest
    timeout-minutes: 1
    steps:
"""
    refs = [f"./.github/actions/example-local-action-{index:02d}" for index in range(14)]
    _write(tmp_path, ".github/workflows/check.yml", header + "".join(f"      - uses: {ref}\n" for ref in refs))
    args = [sys.executable, "-X", "utf8", "-m", "taintly", str(tmp_path), "--platform", "github",
            "--no-config", "--no-color", "--min-severity", "HIGH", "--format"]
    terminal = subprocess.run([*args, "text"], capture_output=True, encoding="utf-8", timeout=30)
    sarif = subprocess.run([*args, "sarif"], capture_output=True, encoding="utf-8", timeout=30)
    assert terminal.returncode == sarif.returncode == 11
    for line, ref in enumerate(refs, start=8):
        expected = f"Line {line}: Referenced local action {ref!r}"
        assert expected in terminal.stdout
        assert expected in terminal.stderr

    run, = json.loads(sarif.stdout)["runs"]
    assert run["properties"]["coverage_status"] == "incomplete"
    results = [row for row in run["results"] if row["ruleId"] == "ENGINE-ERR"]
    assert len(results) == 2
    assert len({row["partialFingerprints"]["taintlyFingerprintV1"] for row in results}) == 2
    notifications = run["invocations"][0]["toolExecutionNotifications"]
    messages = [note["message"]["text"] for note in notifications]
    assert {message.splitlines()[0] for message in messages} == {
        "Source acquisition incomplete: Rule XF-GH-005.",
        "Source acquisition incomplete: Rule XF-GH-006.",
    }
    assert all(refs[-1] in message for message in messages)


def test_acquisition_redaction_preserves_later_gaps(tmp_path):
    _write(tmp_path, ".github/workflows/check.yml", """on: push
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: "./.github/actions/token='test-placeholder"
      - uses: ./.github/actions/ordinary-source
""")
    gap, = _run_corpus_rules(str(tmp_path), RULES)
    assert gap.rule_id == "ENGINE-ERR"
    assert "token=[REDACTED]" in gap.description
    assert "test-placeholder" not in gap.description
    assert "Line 7: Referenced local action './.github/actions/ordinary-source'" in gap.description


@pytest.mark.parametrize("checkout", [False, True])
def test_missing_and_unbound_sources_share_the_gap_budget(tmp_path, monkeypatch, checkout):
    step = "      - uses: ./.github/actions/fixture\n"
    if checkout:
        step = "      - uses: actions/checkout@v5\n        with:\n          repository: example/fixture\n" + step
    workflow = "on: push\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n" + step
    _write(tmp_path, ".github/workflows/first.yml", workflow)
    _write(tmp_path, ".github/workflows/second.yml", workflow)
    monkeypatch.setattr(local_call_graph, "_MAX_SOURCE_GAPS", 1)

    findings = _run_corpus_rules(str(tmp_path), RULES)
    gap, = findings
    assert gap.rule_id == "ENGINE-ERR"
    assert "source gap limit reached" in gap.title


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
