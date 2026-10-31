"""Provider conditions are not shell commands or automatic quote-edit targets.

These are authored contracts, not estimates of field accuracy.
"""

from __future__ import annotations

import pytest

from taintly.engine import scan_file
from taintly.fixes import fix_quote_gitlab_ci_vars, fix_quote_gitlab_refs
from taintly.rules.registry import load_all_rules


def _selected(tmp_path, source):
    path = tmp_path / ".gitlab-ci.yml"
    path.write_text(source, encoding="utf-8")
    rules = [r for r in load_all_rules() if r.id in {"SEC4-GL-001", "SEC4-GL-003"}]
    return path, scan_file(str(path), rules)


@pytest.mark.parametrize("key", ["if", "if ", "'if'", '"if"'])
@pytest.mark.parametrize("value", ["$CI_COMMIT_BRANCH", "$CI_COMMIT_REF_NAME"])
def test_owned_rules_condition_is_not_shell(tmp_path, key, value):
    source = f"job:\n  rules:\n    - {key}: {value} == null\n  script: echo ok\n"
    path, findings = _selected(tmp_path, source)
    assert findings == []
    for fixer in (fix_quote_gitlab_ci_vars, fix_quote_gitlab_refs):
        assert fixer(str(path), dry_run=False) == []
        assert path.read_text(encoding="utf-8") == source


@pytest.mark.parametrize("key", ["only", "except"])
@pytest.mark.parametrize("prefix", ["", "other:\n  script: *missing\n"])
def test_literal_legacy_condition_keeps_local_owner(tmp_path, key, prefix):
    source = prefix + f"job:\n  {key}:\n    variables:\n      - ($CI_COMMIT_BRANCH == $DEFAULT_BRANCH)\n  script: echo ok\n"
    path, findings = _selected(tmp_path, source)
    assert findings == []
    assert fix_quote_gitlab_ci_vars(str(path), dry_run=False) == []
    assert path.read_text(encoding="utf-8") == source


def test_script_text_resembling_if_is_still_analyzed(tmp_path):
    source = "job:\n  script: |\n    if: $CI_COMMIT_BRANCH\n      echo $CI_COMMIT_BRANCH\n"
    _, findings = _selected(tmp_path, source)
    assert [(f.rule_id, f.line) for f in findings] == [
        ("SEC4-GL-001", 3), ("SEC4-GL-001", 4)
    ]


@pytest.mark.parametrize("key", ["rules: [{if: $CI_COMMIT_BRANCH == null}]", "except: {variables: [($CI_COMMIT_BRANCH == $DEFAULT_BRANCH)]}"])
def test_mixed_flow_row_is_not_excluded_or_rewritten(tmp_path, key):
    source = f"job: {{{key}, script: [echo $CI_COMMIT_BRANCH]}}\n"
    path, findings = _selected(tmp_path, source)
    assert any(f.rule_id == "SEC4-GL-001" for f in findings)
    assert fix_quote_gitlab_ci_vars(str(path), dry_run=False) == []
    assert path.read_text(encoding="utf-8") == source


@pytest.mark.parametrize("field", ["script", "before_script", "after_script"])
def test_real_command_remains_an_edit_opportunity(tmp_path, field):
    source = f"job:\n  {field}:\n    - echo $CI_COMMIT_BRANCH\n"
    path, findings = _selected(tmp_path, source)
    assert any(f.rule_id == "SEC4-GL-001" for f in findings)
    result = fix_quote_gitlab_ci_vars(str(path), dry_run=False)
    assert len(result) == 1
    assert path.read_text(encoding="utf-8") == source.replace("$CI_COMMIT_BRANCH", '"$CI_COMMIT_BRANCH"')


def test_unknown_metadata_is_not_an_edit_opportunity(tmp_path):
    source = "job:\n  custom: $CI_COMMIT_BRANCH\n  script: echo ok\n"
    path, _ = _selected(tmp_path, source)
    assert fix_quote_gitlab_ci_vars(str(path), dry_run=False) == []
    assert path.read_text(encoding="utf-8") == source


def test_executable_selection_keeps_existing_severity(tmp_path):
    _, findings = _selected(tmp_path, "job:\n  script:\n    - $CI_COMMIT_MESSAGE\n")
    assert [f.rule_id for f in findings] == ["SEC4-GL-001"]
    assert findings[0].severity.value == "HIGH"


def test_unrelated_script_alias_does_not_change_literal_condition_role(tmp_path):
    source = "job:\n  script: *missing\n  except:\n    variables:\n      - ($CI_COMMIT_BRANCH == $DEFAULT_BRANCH)\n"
    path, findings = _selected(tmp_path, source)
    assert not any(f.rule_id == "SEC4-GL-001" for f in findings)
    assert fix_quote_gitlab_ci_vars(str(path), dry_run=False) == []
    assert path.read_text(encoding="utf-8") == source


@pytest.mark.parametrize("source", [
    "job:\n  script: echo $CI_COMMIT_BRANCH\n  script: echo $CI_COMMIT_BRANCH\n",
    "job:\n  script: echo $CI_COMMIT_BRANCH\njob:\n  script: echo $CI_COMMIT_BRANCH\n",
    "job:\n  script: 'echo $CI_COMMIT_BRANCH'\n",
    "job:\n  script: >\n    echo $CI_COMMIT_BRANCH\n",
    "job:\n  script:\n    - echo hello\n      $CI_COMMIT_BRANCH\n",
    "job:\n  script:\n    - 'echo \"'\n    - echo $CI_COMMIT_BRANCH\n",
    "job:\n  script:\n    - echo hello\\\n    - echo $CI_COMMIT_BRANCH\n",
    "job:\n  script: |\n    cat <<EOF\n    $CI_COMMIT_BRANCH\n    EOF\n",
    "job:\n  script: |\n    cat <<'EOF'\n    $CI_COMMIT_BRANCH\n    EOF\n",
    "job:\n  script: &commands echo $CI_COMMIT_BRANCH\nother:\n  script: *commands\n",
])
def test_unsupported_physical_or_shell_state_refuses_edits(tmp_path, source):
    path, _ = _selected(tmp_path, source)
    assert fix_quote_gitlab_ci_vars(str(path), dry_run=False) == []
    assert path.read_text(encoding="utf-8") == source


@pytest.mark.parametrize("header", ["before_script", "after_script", "default:\n  before_script", "default:\n  after_script"])
def test_global_and_default_phase_edit_ownership(tmp_path, header):
    indent = "    " if header.startswith("default") else "  "
    source = header + ":\n" + indent + "- echo $CI_COMMIT_BRANCH\n"
    path, _ = _selected(tmp_path, source)
    assert len(fix_quote_gitlab_ci_vars(str(path), dry_run=False)) == 1


def test_cutoff_is_not_an_exclusion_or_edit_proof(tmp_path, monkeypatch):
    from dataclasses import replace
    from taintly.parsers import structural
    source = "job:\n  rules:\n    - if: $CI_COMMIT_BRANCH == null\n  script: echo $CI_COMMIT_BRANCH\n"
    events = tuple(structural.walk_workflow(".gitlab-ci.yml", content=source, include_keys=True))
    cutoff = replace(events[0], kind=structural.EventKind.CUTOFF, line=1)
    monkeypatch.setattr(structural, "walk_workflow", lambda *a, **k: iter([cutoff, *events]))
    # fixes.py imports the walker directly; its consumer must observe the same cutoff.
    monkeypatch.setattr("taintly.fixes.walk_workflow", structural.walk_workflow, raising=False)
    path, findings = _selected(tmp_path, source)
    assert any(f.rule_id == "SEC4-GL-001" and f.line == 3 for f in findings)
    assert fix_quote_gitlab_ci_vars(str(path), dry_run=False) == []
    assert path.read_text(encoding="utf-8") == source


def test_multiline_edit_requires_a_separate_supported_profile(tmp_path):
    source = "job:\n  script: |\n    echo $CI_COMMIT_BRANCH\n"
    path, _ = _selected(tmp_path, source)
    assert fix_quote_gitlab_ci_vars(str(path), dry_run=False) == []
    assert path.read_text(encoding="utf-8") == source


@pytest.mark.parametrize("same_owner", [False, True])
def test_rules_condition_reuses_local_alias_ownership(tmp_path, same_owner):
    prefix = "job:\n  script: *missing\n" if same_owner else "other:\n  script: *missing\njob:\n"
    source = prefix + "  rules:\n    - if: $CI_COMMIT_BRANCH == null\n"
    _, findings = _selected(tmp_path, source)
    assert not any(f.rule_id == "SEC4-GL-001" for f in findings)


def test_alias_dependent_duplicate_condition_is_not_exclusion_proof(tmp_path):
    source = "job:\n  rules: *missing\n  rules:\n    - if: $CI_COMMIT_BRANCH == null\n"
    _, findings = _selected(tmp_path, source)
    assert any(f.rule_id == "SEC4-GL-001" for f in findings)


def test_distinct_alias_item_does_not_retype_a_literal_rule(tmp_path):
    source = "job:\n  rules:\n    - *missing\n    - if: $CI_COMMIT_BRANCH == null\n  script: echo ok\n"
    _, findings = _selected(tmp_path, source)
    assert not any(f.rule_id == "SEC4-GL-001" for f in findings)


@pytest.mark.parametrize("key", ["script", "cache"])
def test_literal_multiline_condition_after_other_field_alias(tmp_path, key):
    source = "job:\n  " + key + ": *missing\n  rules:\n    - if: |\n        $CI_COMMIT_BRANCH == null\n        && $CI_COMMIT_REF_NAME == null\n"
    _, findings = _selected(tmp_path, source)
    assert not any(f.rule_id in {"SEC4-GL-001", "SEC4-GL-003"} for f in findings)


def test_mapping_ownership_is_not_an_automatic_role_or_skip(tmp_path):
    from taintly.models import RegexPattern
    source = "metadata: prefix-$CI_COMMIT_BRANCH\n"
    lines = source.splitlines()
    ordinary = RegexPattern(match=r"\$CI_COMMIT_BRANCH")
    gated = RegexPattern(match=r"\$CI_COMMIT_BRANCH", gitlab_mapping_exclude=[r"^metadata:"])
    assert ordinary.check(source, lines)
    assert not gated.check(source, lines)


def test_mapping_like_script_text_cannot_use_a_metadata_exclusion(tmp_path):
    source = "job:\n  script: |\n    name: prefix-$CI_COMMIT_REF_NAME\n"
    _, findings = _selected(tmp_path, source)
    assert any(f.rule_id == "SEC4-GL-003" for f in findings)



def test_quoted_metadata_like_prefix_in_script_is_not_an_exclusion(tmp_path):
    source = 'job:\n  script: |\n    name: "prefix$OTHER" $CI_COMMIT_REF_NAME\n'
    _, findings = _selected(tmp_path, source)
    assert any(f.rule_id == "SEC4-GL-003" for f in findings)


def test_unknown_child_context_cannot_authorize_an_inherited_template_edit(tmp_path):
    source = '.base:\n  script:\n    - echo $CI_COMMIT_BRANCH\njob:\n  extends: .base\n  before_script:\n    - \'echo "\'\n'
    path, _ = _selected(tmp_path, source)
    assert fix_quote_gitlab_ci_vars(str(path), dry_run=False) == []
    assert path.read_text(encoding='utf8') == source


@pytest.mark.parametrize('command', [
    '$CI_COMMIT_MESSAGE', 'prefix$CI_COMMIT_MESSAGE', '"$OTHER" $CI_COMMIT_MESSAGE',
    'FLAG=1 $CI_COMMIT_MESSAGE', 'command $CI_COMMIT_MESSAGE',
    'builtin $CI_COMMIT_MESSAGE', 'env $CI_COMMIT_MESSAGE', 'env.exe $CI_COMMIT_MESSAGE', 'exec $CI_COMMIT_MESSAGE',
    'tool* $CI_COMMIT_MESSAGE', 'tool? $CI_COMMIT_MESSAGE',
    'tool[ab] $CI_COMMIT_MESSAGE', '~/tool $CI_COMMIT_MESSAGE', 'tool{a,b} $CI_COMMIT_MESSAGE',
    'sh -c $CI_COMMIT_MESSAGE', '/bin/bash -c $CI_COMMIT_MESSAGE',
    'python3.13 -c $CI_COMMIT_MESSAGE', 'node -e $CI_COMMIT_MESSAGE',
])
def test_quoting_cannot_hide_executable_or_code_input_opportunities(tmp_path, command):
    source = 'job:\n  script:\n    - ' + command + '\n'
    path, before = _selected(tmp_path, source)
    assert any(f.rule_id == 'SEC4-GL-001' for f in before)
    assert fix_quote_gitlab_ci_vars(str(path), dry_run=False) == []
    assert path.read_text(encoding='utf8') == source
    _, after = _selected(tmp_path, source)
    assert before == after


@pytest.mark.parametrize('command', ['some-tool $CI_COMMIT_MESSAGE', "tool'$LITERAL_TOOL' $CI_COMMIT_MESSAGE", 'echo $CI_COMMIT_MESSAGE'])
def test_literal_tool_argument_grouping_profile_is_preserved(tmp_path, command):
    source = 'job:\n  script:\n    - ' + command + '\n'
    path, _ = _selected(tmp_path, source)
    assert len(fix_quote_gitlab_ci_vars(str(path), dry_run=False)) == 1
    assert '"$CI_COMMIT_MESSAGE"' in path.read_text(encoding='utf8')


def test_literal_head_does_not_authorize_an_invalid_yaml_scalar_suffix(tmp_path):
    source = "job:\n  script:\n    - '$LITERAL_TOOL' $CI_COMMIT_MESSAGE\n"
    path, _ = _selected(tmp_path, source)
    assert fix_quote_gitlab_ci_vars(str(path), dry_run=False) == []
    assert path.read_text(encoding='utf8') == source


def test_a_variable_named_extends_is_not_a_job_inheritance_edge(tmp_path):
    source = 'variables:\n  extends: literal\njob:\n  script: echo $CI_COMMIT_MESSAGE\n'
    path, _ = _selected(tmp_path, source)
    assert len(fix_quote_gitlab_ci_vars(str(path), dry_run=False)) == 1
