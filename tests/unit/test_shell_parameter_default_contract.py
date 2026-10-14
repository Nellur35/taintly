"""Red contract for one conditional shell parameter-default relation.

These inputs model original workflow bytes. A classifier role is conditional:
TITLE contributes only when set and nonempty; otherwise the fixed fallback is used.
"""

from __future__ import annotations

import hashlib

import pytest

from taintly.composer import run_composer
from taintly.engine import scan_file
from taintly.models import Severity
from taintly.rules.github.chain_compose import _compose_chain_gh_103
from taintly.shell_use import ShellUse, classify_shell_use, validate_shell_use
from taintly.taint import analyze
from taintly.workflow_corpus import WorkflowCorpus, _summarize_workflow


_SOURCE_HASHES = {
    'default_eval': '92a32c374559f50f9288f6c866d037b4fa133d6b1e4250ed06170dea976dfec7',
    'defaulted_eval': '8d6a159dc2be50809efe911637a96f069a6817e8d7ac4de0358f99b32fba905c',
    'defaulted_printf': '57f253001fcf8bd30040f411fd49dc0530f6aa6386a1be8d755136b22c658e13',
    'alternate_eval': '655834694b7f814394b588a70ae2d308fa6468eddf9f347d935b748c1719e54f',
}


def _workflow(command: str) -> str:
    return (
        'on: pull_request_target\n'
        'jobs:\n'
        '  greet:\n'
        '    runs-on: ubuntu-latest\n'
        '    env:\n'
        '      TITLE: ${{ github.event.pull_request.title }}\n'
        '    steps:\n'
        '      - name: consume\n'
        '        run: |\n'
        f'          {command}\n'
        '        shell: bash\n'
    )


def _source_path(content: str):
    paths = [
        path
        for path in analyze(content, content.splitlines())
        if path.env_var == 'TITLE' and path.sink_kind == 'run'
    ]
    assert len(paths) == 1
    return paths[0]


def _rule(github_rules, rule_id: str):
    matches = [rule for rule in github_rules if rule.id == rule_id]
    assert len(matches) == 1
    return matches[0]


def _finding(content: str, rule, filepath: str):
    findings = scan_file(filepath, [rule], _content=content)
    return [finding for finding in findings if finding.rule_id == rule.id]


def _has_nonempty_condition(text: str) -> bool:
    normalized = text.casefold()
    return 'title' in normalized and 'set' in normalized and 'nonempty' in normalized


@pytest.mark.parametrize(
    ('case', 'command', 'expected'),
    [
        ('defaulted_eval', 'eval "${TITLE:-literal}"', ShellUse.CODE),
        ('defaulted_printf', "printf '%s\\n' \"${TITLE:-literal}\"", ShellUse.DATA),
    ],
)
def test_parameter_default_role_is_conditional_and_revalidates(case, command, expected):
    content = _workflow(command)
    assert hashlib.sha256(content.encode('utf-8')).hexdigest() == _SOURCE_HASHES[case]
    path = _source_path(content)

    evidence = classify_shell_use(content, path, 'workflow.yml')

    assert evidence.disposition is expected
    assert validate_shell_use(evidence, content, 'workflow.yml', path.sink_line)
    assert evidence.source_sha256 == _SOURCE_HASHES[case]
    assert evidence.command_sha256 == hashlib.sha256(command.encode('utf-8')).hexdigest()
    assert _has_nonempty_condition(' '.join(evidence.notes))


def test_conditional_eval_serializes_review_and_chain_condition(tmp_path, github_rules):
    taint = _rule(github_rules, 'TAINT-GH-001')
    chain_path = tmp_path / '.github' / 'workflows' / 'defaulted.yml'
    chain_path.parent.mkdir(parents=True)

    conditional_content = _workflow('eval "${TITLE:-literal}"')
    chain_path.write_text(conditional_content, encoding='utf-8')
    (conditional,) = _finding(conditional_content, taint, str(chain_path))
    assert conditional._shell_use.disposition is ShellUse.CODE
    assert conditional.severity is Severity.CRITICAL
    assert conditional.confidence == 'high'
    assert conditional.review_needed is True

    plain_content = _workflow('eval "$TITLE"')
    assert hashlib.sha256(plain_content.encode('utf-8')).hexdigest() == _SOURCE_HASHES['default_eval']
    plain_path = tmp_path / '.github' / 'workflows' / 'plain.yml'
    plain_path.write_text(plain_content, encoding='utf-8')
    (plain,) = _finding(plain_content, taint, str(plain_path))
    assert plain._shell_use.disposition is ShellUse.CODE
    assert plain.severity is conditional.severity
    assert plain.confidence == conditional.confidence
    assert plain.exploitability == conditional.exploitability
    assert plain.review_needed is False

    payload = conditional.to_dict()
    assert '_shell_use' not in payload
    assert _has_nonempty_condition(payload['description'] + ' ' + payload['threat_narrative'])
    assert any(_has_nonempty_condition(note) for note in payload['context_notes'])

    corpus = WorkflowCorpus(
        repo_path=str(tmp_path),
        workflows={conditional.file: _summarize_workflow(conditional.file, conditional_content)},
    )
    chains = run_composer(corpus, [conditional], [_compose_chain_gh_103])
    (chain,) = chains
    assert chain.chain_id == 'CHAIN-GH-103'
    assert _has_nonempty_condition(chain.snippet)
    assert 'Review:' in chain.snippet
    assert 'remain unverified' in chain.snippet


def test_conditional_printf_keeps_reviewable_taint_candidate(tmp_path, github_rules):
    content = _workflow("printf '%s\\n' \"${TITLE:-literal}\"")
    assert hashlib.sha256(content.encode('utf-8')).hexdigest() == _SOURCE_HASHES['defaulted_printf']
    path = tmp_path / '.github' / 'workflows' / 'printf.yml'
    path.parent.mkdir(parents=True)
    path.write_text(content, encoding='utf-8')

    (finding,) = _finding(content, _rule(github_rules, 'TAINT-GH-012'), str(path))

    assert finding._shell_use.disposition is ShellUse.DATA
    assert finding.review_needed is True
    assert finding.severity is Severity.MEDIUM
    assert 'shell-use-data' in finding.context_tags
    assert any(_has_nonempty_condition(note) for note in finding.context_notes)
    assert '_shell_use' not in finding.to_dict()


def test_unsupported_parameter_forms_remain_unknown_and_visible(github_rules):
    commands = (
        'eval "${TITLE:+literal}"',
        'eval "${TITLE:-${OTHER}}"',
        'eval "${TITLE:-}"',
        'eval "${TITLE:=literal}"',
        'eval "${TITLE:?missing}"',
        'eval "${TITLE:-$(printf fallback)}"',
        'eval "${TITLE:-literal"',
    )
    rule = _rule(github_rules, 'TAINT-GH-001')

    for command in commands:
        content = _workflow(command)
        if command == 'eval "${TITLE:+literal}"':
            assert hashlib.sha256(content.encode('utf-8')).hexdigest() == _SOURCE_HASHES['alternate_eval']
        path = _source_path(content)
        evidence = classify_shell_use(content, path, 'workflow.yml')
        assert evidence.disposition is ShellUse.UNKNOWN, command
        assert validate_shell_use(evidence, content, 'workflow.yml', path.sink_line), command
        (finding,) = _finding(content, rule, 'workflow.yml')
        assert finding.review_needed is True, command
        assert finding.severity is Severity.MEDIUM, command
        assert 'shell-use-unknown' in finding.context_tags, command
