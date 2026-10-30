"""Injected failures verify diagnostics, not real-world crash frequency."""

import json
import sys
from dataclasses import asdict
from unittest.mock import patch

import pytest

from taintly.__main__ import main
from taintly.engine import scan_repo
from taintly.models import IncompletePatternMatches, Platform
from taintly.rules.jenkins.taint import _JenkinsfileMultiHopPattern
from taintly.rules.registry import load_rules_for_platform

SOURCE = 'node {\n  def branch = env.CHANGE_BRANCH\n  sh "echo ${branch}"\n}\n'
TARGET = "taintly.parsers.jenkinsfile.multihop.resolve_multihop_flows"


def test_resolver_failure_is_incomplete_without_leaking_exception_text():
    with patch(TARGET, side_effect=RuntimeError("concealed_exception_value")):
        result = _JenkinsfileMultiHopPattern().check(SOURCE, SOURCE.splitlines())
    assert not result and isinstance(result, IncompletePatternMatches)
    assert "concealed_exception_value" not in result.reason


def test_import_failure_is_incomplete():
    with patch.dict("sys.modules", {"taintly.parsers.jenkinsfile.multihop": None}):
        result = _JenkinsfileMultiHopPattern().check(SOURCE, SOURCE.splitlines())
    assert not result and isinstance(result, IncompletePatternMatches)


def test_a_completed_miss_does_not_become_a_failure():
    with patch(TARGET, return_value=[]):
        result = _JenkinsfileMultiHopPattern().check(SOURCE, SOURCE.splitlines())
    assert result == [] and not isinstance(result, IncompletePatternMatches)


def test_independent_finding_survives_the_failed_question(tmp_path):
    source = SOURCE.replace(
        '  sh "echo ${branch}"',
        '  sh "echo ${env.CHANGE_BRANCH}"\n  sh "echo ${branch}"',
    )
    (tmp_path / "Jenkinsfile").write_text(source, encoding="utf8")
    rules = load_rules_for_platform(Platform.JENKINS)
    before = scan_repo(str(tmp_path), rules, platform=Platform.JENKINS)[0]
    with patch(TARGET, side_effect=RuntimeError("concealed_exception_value")):
        after = scan_repo(str(tmp_path), rules, platform=Platform.JENKINS)[0]
    direct = lambda r: [asdict(f) for f in r.findings if f.rule_id == "TAINT-JK-001"]
    assert direct(before) and direct(before) == direct(after)
    assert any(f.rule_id == "ENGINE-ERR" and "TAINT-JK-003" in f.title for f in after.findings)
    assert "concealed_exception_value" not in str(after.findings)


def test_cli_failure_stays_visible_at_critical_filter(tmp_path, capsys):
    (tmp_path / "Jenkinsfile").write_text(SOURCE, encoding="utf8")
    argv = [
        "taintly", str(tmp_path), "--platform", "jenkins", "--no-config",
        "--format", "json", "--min-severity", "CRITICAL",
    ]
    with (
        patch(TARGET, side_effect=RuntimeError("concealed_exception_value")),
        patch.object(sys, "argv", argv),
        pytest.raises(SystemExit) as stopped,
    ):
        main()
    report = json.loads(capsys.readouterr().out)
    assert stopped.value.code == 11
    assert any(
        f["rule_id"] == "ENGINE-ERR" and "TAINT-JK-003" in f["title"]
        for f in report["findings"]
    )
    assert "concealed_exception_value" not in json.dumps(report)
