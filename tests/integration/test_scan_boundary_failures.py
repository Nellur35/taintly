"""Product regressions for refused sources and incomplete security analysis."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

import pytest

from taintly import engine
from taintly.__main__ import main


def _scan(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["taintly", "--no-config", "--format", "json", *args])
    with pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()
    return exc.value.code, json.loads(captured.out), captured


@pytest.mark.parametrize(
    "fixture, filename",
    [
        ("github/mechanical/dead_job_literal_false.yml", ".github/workflows/ci.yml"),
        ("gitlab/mechanical/dead_job_literal_never.yml", ".gitlab-ci.yml"),
        ("jenkins/mechanical/dead_stage_literal_false.Jenkinsfile", "Jenkinsfile"),
    ],
)
def test_dead_pipeline_retains_budget_diagnostic(tmp_path, monkeypatch, capsys, fixture, filename):
    source = tmp_path / filename
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes((Path(__file__).resolve().parents[1] / "fixtures" / fixture).read_bytes())

    code, report, _ = _scan(
        monkeypatch, capsys, str(tmp_path), "--max-scan-seconds", "0", "--fail-on", "INFO"
    )
    assert code == 11
    assert report["coverage_status"] == "incomplete"
    assert report["errors"]
    assert all(finding["rule_id"] == "ENGINE-ERR" for finding in report["findings"])


def test_clean_empty_scan_at_info_threshold(tmp_path, monkeypatch, capsys):
    code, report, _ = _scan(monkeypatch, capsys, str(tmp_path), "--fail-on", "INFO")
    assert code == 0
    assert report["findings"] == []


def _link(path, target):
    try:
        path.symlink_to(target)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("Creating symlinks requires additional privileges on this Windows host")
        raise


def test_jenkins_links_respect_repository_boundary(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.write_text(
        'node {\n  def t = params.FOO\n  sh "echo external_test_marker $t"\n}\n', encoding="utf-8"
    )
    named = repo / "Jenkinsfile"
    _link(named, outside)
    weak = repo / "jenkins" / "candidate.groovy"
    weak.parent.mkdir()
    _link(weak, outside)

    def unexpected_sniff(_path):
        pytest.fail("External content reached the Jenkins discovery content probe")

    monkeypatch.setattr(engine, "_groovy_looks_like_pipeline", unexpected_sniff)
    code, report, captured = _scan(monkeypatch, capsys, str(repo), "--platform", "jenkins")
    assert code == 11
    assert report["files_scanned"] == 0
    assert report["coverage_status"] == "incomplete"
    assert {Path(entry["file"]).name for entry in report["findings"]} == {
        "Jenkinsfile",
        "candidate.groovy",
    }
    assert "external_test_marker" not in captured.out + captured.err
    assert str(outside) not in captured.out + captured.err

    # Mixed-repo auto-detection must keep the refused Jenkins source visible.
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("on: push\npermissions: {}\njobs: {}\n", encoding="utf-8")
    code, mixed, _ = _scan(monkeypatch, capsys, str(repo))
    assert code == 11
    reports = {item["platform"]: item for item in mixed["reports"]}
    assert reports["github"]["files_scanned"] == 1
    assert reports["jenkins"]["files_scanned"] == 0
    assert reports["jenkins"]["coverage_status"] == "incomplete"

    # A refused explicitly named path must not fall back to another file.
    code, report, _ = _scan(monkeypatch, capsys, str(named))
    assert code == 11
    assert report["files_scanned"] == 0
    assert len(report["errors"]) == 1

    weak.unlink()
    named.unlink()
    inside = repo / "pipeline.txt"
    inside.write_bytes(
        outside.read_bytes().replace(b"external_test_marker", b"internal_test_marker")
    )
    _link(named, inside)
    code, report, _ = _scan(monkeypatch, capsys, str(repo), "--platform", "jenkins")
    assert code == 2
    assert report["files_scanned"] == 1
    assert any(finding["rule_id"] == "TAINT-JK-003" for finding in report["findings"])
    assert not report["errors"]


class _Response(io.BytesIO):
    status = 200


@pytest.mark.parametrize(
    "mode, expected_code, expected_incomplete",
    [("healthy", 0, False), ("offline", 11, True), ("partial", 1, True)],
)
def test_jenkins_posture_preserves_transport_status(
    monkeypatch, capsys, mode, expected_code, expected_incomplete
):
    monkeypatch.setenv("JENKINS_USER", "fixture-user")
    monkeypatch.setenv("JENKINS_TOKEN", "fixture-token")

    def urlopen(request, **_kwargs):
        url = request.full_url
        target = urlsplit(url)
        if target.hostname == "raw.githubusercontent.com":
            return _Response(b"[]")

        assert target.hostname == "example.test"
        if mode == "offline":
            raise URLError("private transport text")
        if target.path == "/script" or (
            target.path == "/api/json" and not request.has_header("Authorization")
        ):
            raise HTTPError(url, 403, "forbidden", {}, None)
        if target.path == "/computer/api/json" and mode == "partial":
            raise URLError("private transport text")
        if target.path == "/crumbIssuer/api/json":
            return _Response(b"{}" if mode == "partial" else b'{"crumb": "dummy"}')
        return _Response(b"{}")

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    code, report, captured = _scan(
        monkeypatch,
        capsys,
        "--jenkins-url",
        "https://example.test",
        "--min-severity",
        "HIGH",
    )
    assert code == expected_code
    assert bool(report["errors"]) == expected_incomplete
    assert (report["coverage_status"] == "incomplete") == expected_incomplete
    assert "private transport text" not in captured.out + captured.err
    if mode == "partial":
        assert any(finding["rule_id"] == "PLAT-JK-005" for finding in report["findings"])
        assert any(
            "PLAT-JK-003" in f["title"] for f in report["findings"] if f["rule_id"] == "ENGINE-ERR"
        )
