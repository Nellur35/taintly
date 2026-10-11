"""SEC6-GH-005 applies only to secret interpolation in shell scripts."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.parsers.structural import EventKind, walk_workflow
from taintly.rules.github import sec1_sec5_sec6_sec7_sec9
from taintly.rules.registry import load_rules_for_platform

_SECRET_EXPR = "${{ secrets.API_TOKEN }}"
_DOCUMENTED_SCRIPT_INPUTS = (
    ("actions/github-script", "script"),
    ("nick-fields/retry", "command"),
    ("nick-fields/retry", "new_command"),
    ("nick-fields/retry", "on_retry_command"),
    ("azure/cli", "inlinescript"),
    ("azure/powershell", "inlinescript"),
    ("appleboy/ssh-action", "script"),
    ("garygrossgarten/github-action-ssh", "command"),
    ("testdriverai/action", "prerun"),
)


def _sec6_findings(tmp_path: Path, content: str):
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(content, encoding="utf-8")
    rules = load_rules_for_platform(Platform.GITHUB)
    return [
        finding for finding in scan_file(str(workflow), rules) if finding.rule_id == "SEC6-GH-005"
    ]


def test_interpolated_secret_in_action_data_is_not_a_shell_script(tmp_path):
    findings = _sec6_findings(
        tmp_path,
        """name: action-data
on: push
jobs:
  request:
    runs-on: ubuntu-latest
    steps:
      - uses: example/http-request@v1
        with:
          authorization: "Bearer ${{ secrets.API_TOKEN }}"
""",
    )

    assert findings == []


def test_multiline_secret_action_input_is_not_a_shell_script(tmp_path):
    findings = _sec6_findings(
        tmp_path,
        """name: multiline-action-data
on: push
jobs:
  request:
    runs-on: ubuntu-latest
    steps:
      - uses: example/http-request@v1
        with:
          authorization: |
            Bearer ${{ secrets.API_TOKEN }}
""",
    )

    assert findings == []


def test_direct_run_interpolation_remains_a_positive(tmp_path):
    findings = _sec6_findings(
        tmp_path,
        """name: shell-secret
on: push
jobs:
  request:
    runs-on: ubuntu-latest
    steps:
      - run: curl https://api.example.test/${{ secrets.API_TOKEN }}
""",
    )

    assert len(findings) == 1


def test_quoted_shell_interpolation_remains_a_positive(tmp_path):
    findings = _sec6_findings(
        tmp_path,
        """name: shell-secret
on: push
jobs:
  request:
    runs-on: ubuntu-latest
    steps:
      - run: echo "token=${{ secrets.API_TOKEN }}"
""",
    )

    assert len(findings) == 1


def test_folded_run_scalar_expression_split_across_lines_is_detected(tmp_path):
    findings = _sec6_findings(
        tmp_path,
        """name: folded-shell-secret
on: push
jobs:
  request:
    runs-on: ubuntu-latest
    steps:
      - run: >-
          curl https://api.example.test/${{
          secrets.API_TOKEN
          }}
""",
    )

    assert len(findings) == 1
    assert findings[0].line == 8


def test_flow_style_step_run_is_a_shell_sink(tmp_path):
    findings = _sec6_findings(
        tmp_path,
        """name: flow-shell-secret
on: push
jobs:
  request:
    runs-on: ubuntu-latest
    steps: [{run: 'echo "token=${{ secrets.API_TOKEN }}"'}]
""",
    )

    assert len(findings) == 1


@pytest.mark.parametrize(("action", "input_name"), _DOCUMENTED_SCRIPT_INPUTS)
def test_documented_action_script_input_is_an_executable_sink(tmp_path, action, input_name):
    findings = _sec6_findings(
        tmp_path,
        f"""name: action-script-secret
on: push
jobs:
  request:
    runs-on: ubuntu-latest
    steps:
      - uses: {action}@v1
        with:
          {input_name}: |
            echo "token={_SECRET_EXPR}"
""",
    )

    assert len(findings) == 1


@pytest.mark.parametrize("input_name", ["script", "run", "data"])
def test_unknown_action_input_names_remain_data(tmp_path, input_name):
    findings = _sec6_findings(
        tmp_path,
        f"""name: unknown-action-input
on: push
jobs:
  request:
    runs-on: ubuntu-latest
    steps:
      - uses: example/unknown-action@v1
        with:
          {input_name}: |
            echo "token={_SECRET_EXPR}"
""",
    )

    assert findings == []


def test_documented_action_script_input_survives_flow_and_uses_alias(tmp_path):
    findings = _sec6_findings(
        tmp_path,
        f"""name: action-script-flow-alias
on: push
action: &github_script actions/github-script@v7
jobs:
  request:
    runs-on: ubuntu-latest
    steps:
      - uses: *github_script
        with: {{script: 'console.log("token={_SECRET_EXPR}")'}}
""",
    )

    assert len(findings) == 1


def test_run_alias_replay_is_still_a_shell_sink(tmp_path):
    findings = _sec6_findings(
        tmp_path,
        """name: aliased-shell-secret
on: push
shell: &shell 'echo "token=${{ secrets.API_TOKEN }}"'
jobs:
  request:
    runs-on: ubuntu-latest
    steps:
      - run: *shell
""",
    )

    assert len(findings) == 1


def test_nested_with_run_is_action_data_not_a_shell_sink(tmp_path):
    findings = _sec6_findings(
        tmp_path,
        """name: nested-action-data
on: push
jobs:
  request:
    runs-on: ubuntu-latest
    steps:
      - uses: example/action@v1
        with:
          run: 'echo "token=${{ secrets.API_TOKEN }}"'
""",
    )

    assert findings == []


def test_multiple_secret_shell_lines_each_produce_a_finding(tmp_path):
    findings = _sec6_findings(
        tmp_path,
        """name: multiple-shell-secrets
on: push
jobs:
  request:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl https://one.example/${{ secrets.ONE }}
          curl https://two.example/${{ secrets.TWO }}
""",
    )

    assert [finding.line for finding in findings] == [8, 9]


def test_env_mediation_and_comment_only_run_remain_quiet(tmp_path):
    findings = _sec6_findings(
        tmp_path,
        """name: safe-shell
on: push
jobs:
  request:
    runs-on: ubuntu-latest
    steps:
      - env:
          API_TOKEN: ${{ secrets.API_TOKEN }}
        run: curl https://api.example.test/$API_TOKEN
      - run: |
          # echo "token=${{ secrets.API_TOKEN }}"
          echo "request complete"
""",
    )

    assert findings == []


def test_incomplete_structure_uses_conservative_legacy_match(tmp_path):
    content = """name: incomplete
on: push
jobs:
  request:
    runs-on: ubuntu-latest
    steps:
      - uses: example/http-request@v1
        with:
          authorization: |
            Bearer ${{ secrets.API_TOKEN }}
      - name: unsupported tag after the input
        custom: !unsupported value
"""
    events = list(walk_workflow("ci.yml", content=content, include_keys=True, recover=True))
    assert events[-1].kind is EventKind.CUTOFF

    findings = _sec6_findings(tmp_path, content)

    assert len(findings) == 1


def test_injected_error_status_uses_conservative_legacy_match(tmp_path, monkeypatch):
    monkeypatch.setattr(
        sec1_sec5_sec6_sec7_sec9,
        "walk_workflow",
        lambda *_args, **_kwargs: iter([SimpleNamespace(kind=EventKind.ERROR)]),
    )
    content = """name: parser-error
on: push
jobs:
  request:
    runs-on: ubuntu-latest
    steps:
      - uses: example/action@v1
        with:
          authorization: |
            Bearer ${{ secrets.API_TOKEN }}
"""

    findings = _sec6_findings(tmp_path, content)

    assert len(findings) == 1
