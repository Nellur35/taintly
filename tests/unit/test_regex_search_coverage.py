"""A bounded search can report a match while still disclosing incomplete coverage."""

import json
import re
import sys
from types import SimpleNamespace

import pytest

from taintly import __main__ as cli
from taintly import models
from taintly.engine import scan_file
from taintly.models import ContextPattern, Platform, RegexPattern, Rule, Severity
from taintly.rules.github import sec10_logging_visibility

WORKFLOW = """name: coverage-check
on: push
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"""


def _source(tmp_path, content=WORKFLOW):
    path = tmp_path / ".github" / "workflows" / "ci.yml"
    path.parent.mkdir(parents=True)
    path.write_text(content, encoding="utf-8")
    return path


def _rule(pattern, rule_id="TEST-GH-001"):
    return Rule(
        id=rule_id,
        title="Test search coverage",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-10",
        description="Test search coverage",
        pattern=pattern,
        remediation="Test",
        reference="https://example.invalid",
    )


class _Interrupted:
    def search(self, _text):
        raise models._PatternTimeout()


@pytest.fixture
def simulated_alarm(monkeypatch):
    # Replace only the model's platform and signal bindings. The matcher
    # raises the real timeout exception without using process-wide alarms.
    monkeypatch.setattr(models, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(
        models, "signal",
        SimpleNamespace(
            SIGALRM=14,
            getsignal=lambda _: models._pattern_timeout_handler,
            signal=lambda *_: None,
            alarm=lambda _: None,
        ),
    )


def test_rule_does_not_claim_absent_timeout_after_skipping_line(tmp_path):
    rule = next(rule for rule in sec10_logging_visibility.RULES if rule.id == "SEC10-GH-001")
    path = _source(tmp_path, WORKFLOW + "    # " + "x" * models._MAX_SAFE_TEXT_LEN + "\n")
    assert [item.rule_id for item in scan_file(str(path), [rule])] == ["ENGINE-ERR"]
    path.write_text(WORKFLOW, encoding="utf-8")
    assert [item.rule_id for item in scan_file(str(path), [rule])] == [rule.id]


@pytest.mark.parametrize("mode", ("file", "job", "positive", "line", "mixed"))
def test_timeout_reaches_cli_report_and_exit(tmp_path, monkeypatch, capsys, simulated_alarm, mode):
    path = _source(tmp_path)
    if mode == "line":
        pattern = RegexPattern(match="placeholder")
        pattern._compiled = _Interrupted()
    else:
        pattern = ContextPattern(
            anchor=r"\bruns-on:", requires="steps:",
            requires_absent="" if mode == "positive" else "timeout-minutes:",
            scope="job" if mode == "job" else "file",
        )
        if mode == "positive":
            pattern._requires_re = _Interrupted()
        else:
            pattern._requires_absent_re = _Interrupted()
    rules = [_rule(pattern)]
    if mode == "mixed":
        rules.append(_rule(RegexPattern(match="echo hello"), rule_id="TEST-GH-002"))
    monkeypatch.setattr(cli, "load_rules_for_platform", lambda _: rules)
    for report_format in ("json", "sarif", "text"):
        monkeypatch.setattr(
            sys, "argv",
            ["taintly", str(tmp_path), "--no-config", "--no-color", "--platform", "github",
             "--min-severity", "HIGH", "--format", report_format],
        )
        with pytest.raises(SystemExit) as outcome:
            cli.main()
        assert outcome.value.code == (1 if mode == "mixed" else 11)
        captured = capsys.readouterr()
        assert str(path) in captured.err
        if report_format == "json":
            report = json.loads(captured.out)
            assert report["coverage_status"] == "incomplete"
            assert report["engine_error_count"] == 1
            assert {row["rule_id"] for row in report["findings"]} == (
                {"ENGINE-ERR", "TEST-GH-002"} if mode == "mixed" else {"ENGINE-ERR"}
            )
        elif report_format == "sarif":
            run = json.loads(captured.out)["runs"][0]
            assert run["properties"]["coverage_status"] == "incomplete"
            notification, = run["invocations"][0]["toolExecutionNotifications"]
            assert notification["descriptor"]["id"] == "ENGINE-ERR"
        else:
            assert "Coverage degraded" in captured.out


@pytest.mark.parametrize("later_match", (False, True))
def test_timeout_in_one_chunk_allows_searching_the_next(monkeypatch, simulated_alarm, later_match):
    class MatchOnLaterChunk:
        def search(self, text):
            if "first" in text:
                raise models._PatternTimeout()
            return re.search("marker", text)

    monkeypatch.setattr(models, "_MAX_SAFE_TEXT_LEN", 8)
    monkeypatch.setattr(models, "_CHUNK_OVERLAP_LINES", 0)
    models._reset_regex_search_coverage()
    try:
        result = models._safe_search_chunked(
            MatchOnLaterChunk(), "first\n" + ("marker\n" if later_match else "second\n")
        )
        if later_match:
            assert result.group() == "marker"
        else:
            assert result is models._INCOMPLETE_REGEX_SEARCH
        assert models._regex_search_coverage_incomplete()
        assert models._safe_search_chunked(re.compile("marker"), "other\n") is None
    finally:
        models._reset_regex_search_coverage()
