"""Interpreter arguments are source only under their actual command contract."""

import pytest

from taintly.local_call_graph import _shell_sink, find_local_flows
from taintly.workflow_corpus import build_corpus

CASES = [
    ('eval "$VALUE"', True),
    ('VALUE=printf; eval "$VALUE"', False),
    ('bash -e "$VALUE"', None),  # A script filename, whose contents are unknown.
    ('node -c "$VALUE"', False),  # Syntax checking a file, not executing source.
    ('node -e "$VALUE"', True),
    ('python -c "$VALUE"', True),
    ('bash -lc "$VALUE"', True),
    ('bash -o noexec -c "$VALUE"', False),
    ('bash -c "$VALUE" fixed -n', True),
    ('bash --unresolved-option -c "$VALUE"', None),
    ('env bash -c "$VALUE"', True),
    ('printf "%s" "$VALUE" | bash', True),
    ('printf "%s" "$VALUE" | cat | bash', True),
    ('printf "%s" "$VALUE" | tr a b | bash', None),
    ('printf "%s" "$VALUE" | sh -n', False),
    ('printf "%s" "$VALUE" > /dev/null | sh', None),
    ('bash -c \'printf "%s" "$1"\' fixed "$VALUE"', False),
    ('printf \'eval "$VALUE" %s\' "$VALUE"', False),
    ('eval "$OTHER"; printf "%s" "$VALUE"', False),
]


@pytest.mark.parametrize(("command", "expected"), CASES)
def test_shell_source_contract(command, expected):
    assert _shell_sink(command, "VALUE") is expected


@pytest.mark.parametrize(("command", "expected"), CASES)
def test_real_workflow_flow_preserves_shell_contract(tmp_path, command, expected):
    folder = tmp_path / ".github/workflows"
    folder.mkdir(parents=True)
    (folder / "caller.yml").write_text("""on: issues
jobs:
  call:
    uses: ./.github/workflows/worker.yml
    with:
      payload: ${{ github.event.issue.title }}
""", encoding="utf-8")
    (folder / "worker.yml").write_text("""on:
  workflow_call:
    inputs:
      payload: {type: string}
jobs:
  work:
    runs-on: ubuntu-latest
    steps:
      - env:
          VALUE: ${{ inputs.payload }}
        run: """ + command + "\n", encoding="utf-8")
    flows = find_local_flows(build_corpus(str(tmp_path)))
    if expected is False:
        assert flows == []
    else:
        assert len(flows) == 1
        assert bool(flows[0].review_notes) is (expected is None)
