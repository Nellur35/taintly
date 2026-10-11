"""SEC4-JK-004 must bind approval findings to executable input steps."""

from taintly.rules.jenkins.sec_jenkins import RULES


def _hits(source: str) -> list[tuple[int, str]]:
    rule = next(rule for rule in RULES if rule.id == "SEC4-JK-004")
    return rule.pattern.check(source, source.splitlines())


def test_parameter_description_build_input_is_not_an_approval_step() -> None:
    source = """pipeline {
  parameters {
    string(name: 'COMMAND', description: 'Build input')
  }
}
"""
    assert _hits(source) == []


def test_input_mentioned_in_string_or_comment_is_not_an_approval_step() -> None:
    source = """def message = "input message: 'Deploy?'"
// input message: 'Deploy?'
"""
    assert _hits(source) == []


def test_unrestricted_input_command_and_closure_remain_findings() -> None:
    command = "input message: 'Deploy?', ok: 'Proceed'\n"
    closure = "input {\n  message 'Deploy?'\n}\n"
    assert len(_hits(command)) == 1
    assert len(_hits(closure)) == 1


def test_submitter_restricted_input_is_not_a_finding() -> None:
    source = "input message: 'Deploy?', submitter: 'release-team'\n"
    assert _hits(source) == []


def test_submitter_restricted_input_closure_is_not_a_finding() -> None:
    source = "input {\n  message 'Deploy?'\n  submitter 'release-team'\n}\n"
    assert _hits(source) == []
