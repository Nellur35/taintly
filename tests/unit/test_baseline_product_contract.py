"""Snapshot adoption must compose with real reporting and incomplete outcomes."""
from __future__ import annotations

import json
import sys

import pytest

from taintly import __main__ as cli
from taintly.models import AuditReport, Finding, Severity


def _finding(path, diagnostic=False):
    return Finding(rule_id="ENGINE-ERR" if diagnostic else "AUTHORED-RISK",
                   severity=Severity.LOW if diagnostic else Severity.HIGH,
                   title="Unavailable source" if diagnostic else "Reviewable security risk",
                   description="Authored contract", file=str(path))


def _reports(tmp_path, count, diagnostic):
    result = []
    for provider in ("github", "codebuild")[:count]:
        report = AuditReport(repo_path=str(tmp_path), platform=provider, files_scanned=1)
        report.add(_finding(tmp_path / (provider + ".yml")))
        if diagnostic:
            report.add(_finding(tmp_path / (provider + ".yml"), diagnostic=True))
        result.append(report)
    return result


def _call(tmp_path, monkeypatch, capsys, reports, extra=()):
    target = tmp_path / "snapshot.json"
    monkeypatch.setattr(cli, "scan_repo", lambda *_, **__: reports)
    monkeypatch.setattr(cli, "load_all_rules", lambda: [])
    monkeypatch.setattr(sys, "argv", ["taintly", str(tmp_path), "--baseline", str(target),
                                     "--no-config", "--format", "json", *extra])
    with pytest.raises(SystemExit) as raised:
        cli.main()
    return target, raised.value.code, capsys.readouterr()


@pytest.mark.parametrize("count", [1, 2])
@pytest.mark.parametrize("diagnostic", [False, True])
def test_snapshot_keeps_parseable_reports_accepts_risk_but_not_incomplete_analysis(
    tmp_path, monkeypatch, capsys, count, diagnostic
):
    reports = _reports(tmp_path, count, diagnostic)
    target, code, output = _call(tmp_path, monkeypatch, capsys, reports)
    assert code == (11 if diagnostic else 0)
    assert target.is_file()
    document = json.loads(output.out)
    emitted = document["reports"] if count > 1 else [document]
    assert len(emitted) == count
    assert [d["platform"] for d in emitted] == [r.platform for r in reports]
    for item in emitted:
        assert any(f["rule_id"] == "AUTHORED-RISK" for f in item["findings"])
        assert len(item["errors"]) == int(diagnostic)
    assert "baseline" in output.err.lower()
    # Storage already fingerprints all observations. Its separate diff contract
    # must keep diagnostics reportable even if their fingerprint was recorded.
    from taintly.baseline import apply_diff, load_baseline
    assert len(json.loads(target.read_text())["fingerprints"]) == count * (1 + int(diagnostic))
    saved = load_baseline(str(target))
    for report in reports:
        remaining, _ = apply_diff(report.findings, saved, str(tmp_path))
        assert len(remaining) == int(diagnostic)
        assert all(f.rule_id == "ENGINE-ERR" for f in remaining)


def test_baseline_score_request_uses_the_report_path(tmp_path, monkeypatch, capsys):
    _, code, output = _call(tmp_path, monkeypatch, capsys, _reports(tmp_path, 1, False), ["--score"])
    assert code == 0
    assert "score" in json.loads(output.out)


def test_snapshot_and_diff_are_distinct_operations(tmp_path, monkeypatch, capsys):
    target = tmp_path / "snapshot.json"
    monkeypatch.setattr(sys, "argv", ["taintly", str(tmp_path), "--baseline", str(target),
                                     "--diff", str(target)])
    with pytest.raises(SystemExit) as raised:
        cli.main()
    assert raised.value.code == 2
    assert not target.exists()
    assert "not allowed with argument" in capsys.readouterr().err


def test_missing_transitive_authority_prevents_incomplete_snapshot(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    target, code, output = _call(tmp_path, monkeypatch, capsys, _reports(tmp_path, 1, False), ["--transitive"])
    assert code == 3
    assert "GITHUB_TOKEN" in output.err
    assert not target.exists()


def test_requested_transitive_result_reaches_snapshot_and_incomplete_exit(tmp_path, monkeypatch, capsys):
    from taintly import engine, transitive
    from taintly.baseline import fingerprint

    monkeypatch.setenv("GITHUB_TOKEN", "inert-test-token")
    monkeypatch.setattr(engine, "discover_files", lambda *_, **__: [str(tmp_path / "ci.yml")])
    extra = [_finding(tmp_path / "action.yml"), _finding(tmp_path / "action.yml", diagnostic=True)]
    calls = []
    def analyze(files, token, root):
        calls.append((files, token, root))
        return extra
    monkeypatch.setattr(transitive, "run_transitive_analysis", analyze)
    target, code, output = _call(tmp_path, monkeypatch, capsys, _reports(tmp_path, 1, False), ["--transitive"])
    assert len(calls) == 1
    assert code == 11
    assert fingerprint(extra[0], str(tmp_path)) in json.loads(target.read_text())["fingerprints"]
    assert len(json.loads(output.out)["errors"]) == 1
