"""Defined budget contracts; authored probes are not field-accuracy evidence."""
from __future__ import annotations

import sys

import pytest

from taintly import __main__ as cli, engine
from taintly.models import Platform, Rule, Severity


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), -1.0])
def test_invalid_budget_is_rejected_before_source_acquisition(value, monkeypatch):
    def forbidden(*_, **__):
        pytest.fail("invalid limits must fail before source acquisition")
    monkeypatch.setattr(engine, "_normalize_input_path", forbidden)
    with pytest.raises(ValueError, match="finite and nonnegative"):
        engine.scan_repo("missing-source", [], max_scan_seconds=value)
    # The actual missing path would otherwise become an ENGINE-ERR result.
    with pytest.raises(ValueError, match="finite and nonnegative"):
        engine.scan_file("missing-source", [], max_scan_seconds=value)


@pytest.mark.parametrize("value", ["nan", "NaN", "inf", "-inf", "1e999", "-1", "nonsense"])
def test_cli_rejects_invalid_budget_before_scanning(value, monkeypatch, capsys):
    def forbidden(*_, **__):
        pytest.fail("invalid limits must not start scanning")
    monkeypatch.setattr(cli, "scan_repo", forbidden)
    monkeypatch.setattr(sys, "argv", ["taintly", "--max-scan-seconds=" + value])
    with pytest.raises(SystemExit) as raised:
        cli.main()
    assert raised.value.code == 2
    output = capsys.readouterr()
    assert "--max-scan-seconds" in output.err
    assert not output.out


@pytest.mark.parametrize("value", [0.0, -0.0, 0.001, 30.0, 1e100])
def test_supported_numeric_limits_are_retained(value):
    assert engine.validate_scan_seconds(value) == value
    assert cli._scan_seconds(str(value)) == value
    assert engine.validate_scan_seconds(None) == 30.0


def _rule(name, pattern):
    return Rule(id=name, title="Authored budget probe", severity=Severity.HIGH,
                platform=Platform.GITHUB, owasp_cicd="CICD-SEC-4",
                description="Authored supported witness", pattern=pattern,
                remediation="Review", reference="")


def test_work_starts_then_expiry_keeps_evidence_and_discloses_remaining_rules(monkeypatch):
    now = [0.0]
    calls = []

    class First:
        def check(self, content, lines):
            calls.append("first")
            now[0] = 6.0
            return [(1, "supported observation")]

    class Second:
        def check(self, content, lines):
            pytest.fail("expired rule must not start")

    monkeypatch.setattr(engine.time, "monotonic", lambda: now[0])
    result = engine.scan_file("workflow.yml", [_rule("PROBE-1", First()), _rule("PROBE-2", Second())],
                              _content="on: push\njobs: {}\n", max_scan_seconds=5.0)
    assert calls == ["first"]
    assert [f.rule_id for f in result] == ["PROBE-1", "ENGINE-ERR"]
    assert "1 of 2 rules not evaluated" in result[-1].title
    assert result[0].severity == Severity.HIGH


def test_each_independent_file_receives_its_own_budget(monkeypatch):
    now = [0.0]
    calls = []

    class Work:
        def check(self, content, lines):
            calls.append(content)
            now[0] += 2.0
            return [(1, "supported observation")]

    rules = [_rule("PROBE-1", Work()), _rule("PROBE-2", Work())]
    monkeypatch.setattr(engine.time, "monotonic", lambda: now[0])
    for name in ("one", "two"):
        result = engine.scan_file(name, rules, _content=name, max_scan_seconds=5.0)
        assert [f.rule_id for f in result] == ["PROBE-1", "PROBE-2"]
    assert calls == ["one", "one", "two", "two"]
