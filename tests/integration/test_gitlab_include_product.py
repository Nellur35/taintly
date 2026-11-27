"""Public GitLab include discovery and shell ownership through the CLI."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

import pytest

from taintly.models import _MAX_SAFE_TEXT_LEN


def _run(root, report_format, *options):
    shell_env = dict(os.environ, PYTHONUTF8="1")
    for name in ("CI_PIPELINE_SOURCE", "CI_COMMIT_BRANCH", "CI_DEFAULT_BRANCH"):
        shell_env.pop(name, None)
    result = subprocess.run(
        [
            sys.executable, "-m", "taintly", str(root), "--no-config",
            "--platform", "gitlab", "--format", report_format, *options,
        ],
        env=shell_env,
        capture_output=True,
        encoding="utf-8",
        timeout=30,
    )
    assert result.stdout, result.stderr
    return result


def _scan(root):
    result = _run(root, "json")
    return result.returncode, json.loads(result.stdout)


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_transitive_local_include_retains_the_missing_source_and_the_scan(tmp_path):
    entry = tmp_path / ".gitlab-ci.yml"
    entry.write_text(
        "include: /templates/outer.yml\nentry:\n  script: echo entry\n", encoding="utf-8"
    )
    directory = tmp_path / "templates"
    directory.mkdir()
    outer = directory / "outer.yml"
    outer.write_text(
        "include: {local: /templates/inner.yml}\nverify:\n  script: echo verify\n", encoding="utf-8"
    )

    code, report = _scan(tmp_path)
    assert code == 11
    assert report["files_scanned"] == 2
    assert report["coverage_status"] == "incomplete"
    assert len(report["errors"]) == 1
    diagnostic = report["errors"][0]
    assert diagnostic["title"] == "Source acquisition incomplete"
    assert diagnostic["file"] == str(outer)
    assert "'/templates/inner.yml'" in diagnostic["description"]

    (directory / "inner.yml").write_text("smoke:\n  script: echo smoke\n", encoding="utf-8")
    code, report = _scan(tmp_path)
    assert code == 0
    assert report["files_scanned"] == 3
    assert not report["errors"]


def test_dynamic_include_has_a_coverage_diagnostic_and_preserves_real_shell_use(tmp_path):
    entry = tmp_path / ".gitlab-ci.yml"
    source = (
        "include:\n"
        "  - local: 'templates/$CI_COMMIT_BRANCH.yml'\n"
        "  - local: templates/$CI_COMMIT_REF_NAME.yml\n"
        "verify:\n"
        "  script: echo ready\n"
    )
    entry.write_text(source, encoding="utf-8")

    code, report = _scan(tmp_path)
    assert code == 11
    assert report["files_scanned"] == 1
    assert report["coverage_status"] == "incomplete"
    assert len(report["errors"]) == 1
    assert "2 GitLab include(s) interpolate" in report["errors"][0]["title"]
    shell_rules = {"SEC4-GL-001", "SEC4-GL-003"}
    assert not any(row["rule_id"] in shell_rules for row in report["findings"])
    coverage_errors = report["errors"]

    entry.write_text(
        source.replace("echo ready", "echo $CI_COMMIT_BRANCH $CI_COMMIT_REF_NAME"),
        encoding="utf-8",
    )
    code, report = _scan(tmp_path)
    assert code == 1
    assert report["coverage_status"] == "incomplete"
    assert report["errors"] == coverage_errors
    assert {
        (row["rule_id"], row["line"]) for row in report["findings"] if row["rule_id"] in shell_rules
    } == {("SEC4-GL-001", 5), ("SEC4-GL-003", 5)}


def test_wildcard_with_no_matches_can_select_no_includes(tmp_path):
    entry = tmp_path / ".gitlab-ci.yml"
    entry.write_text(
        "include: 'templates/*.yml'\nverify:\n  script: echo verified\n", encoding="utf-8"
    )
    code, report = _scan(tmp_path)
    assert code == 0
    assert report["files_scanned"] == 1
    assert not report["errors"]



def test_explicit_scan_does_not_run_an_unrelated_corpus(tmp_path):
    selected = _write(tmp_path / "ci" / "selected.yml", "selected:\n  script: echo ready\n")
    _write(tmp_path / ".gitlab" / ".gitlab-ci.yml", "fallback:\n  script: echo ready\n")
    digest = hashlib.sha256(selected.read_bytes()).digest()
    initial_code, initial = _scan(selected)
    sibling = _write(
        tmp_path / ".gitlab-ci.yml",
        ".message_job:\n  variables:\n    MESSAGE: $CI_COMMIT_MESSAGE\n"
        "  script:\n    - echo $MESSAGE\nexample:\n  extends: .message_job\n",
    )
    scoped_code, scoped = _scan(selected)
    repo_code, repository = _scan(tmp_path)
    assert hashlib.sha256(selected.read_bytes()).digest() == digest
    assert initial_code == scoped_code == 0
    assert initial == scoped
    assert scoped["files_scanned"] == 1
    assert repo_code == 1
    assert any(
        row["rule_id"] == "TAINT-GL-008" and row["file"] == str(sibling)
        for row in repository["findings"]
    )


def test_weak_source_does_not_own_a_pipeline_acquisition_error(tmp_path):
    entry = _write(tmp_path / ".gitlab-ci.yml", "entry:\n  script: echo ready\n")
    weak = _write(
        tmp_path / "ci" / "settings.yml", "include: /config/settings-extra.yml\napp: {color: blue}\n"
    )
    code, report = _scan(tmp_path)
    assert code == 0
    assert report["files_scanned"] == 2
    assert not report["errors"]

    body = entry.read_text(encoding="utf-8")
    _write(entry, "include: /ci/settings.yml\n" + body)
    code, report = _scan(tmp_path)
    assert code == 11
    assert report["files_scanned"] == 2
    assert report["errors"][0]["file"] == str(weak)
    assert "settings-extra.yml" in report["errors"][0]["description"]


def test_cutoff_recognizes_complete_block_without_claiming_partial_path_is_missing(tmp_path):
    entry = tmp_path / ".gitlab-ci.yml"
    local = "/templates/available.yml"
    _write(tmp_path / local.lstrip("/"), "fragment:\n  script: echo ready\n")
    include = f"include: {local}\n"
    job = "job:\n  script: echo ready\n"
    _write(entry, include + job + "#" + " " * _MAX_SAFE_TEXT_LEN)
    code, report = _scan(tmp_path)
    assert code == 11
    assert report["files_scanned"] == 2
    assert sum("read limit" in row["description"] for row in report["errors"]) == 1

    before_include = "#" + " " * (_MAX_SAFE_TEXT_LEN - len("include: /templates/av") - 2) + "\n"
    source = before_include + include + job
    assert source[:_MAX_SAFE_TEXT_LEN].endswith("include: /templates/av")
    _write(entry, source)
    code, report = _scan(tmp_path)
    assert code == 11
    assert report["files_scanned"] == 1
    assert sum("read limit" in row["description"] for row in report["errors"]) == 1
    assert not any("has no available file" in row["description"] for row in report["errors"])


@pytest.mark.parametrize(
    "layout",
    [
        "  include: {ref}\n  job:\n    script: echo ready\n",
        "{{\n  include: {ref},\n  job: {{script: 'echo ready'}}\n}}\n",
        "{{\ninclude: {ref},\njob: {{script: 'echo ready'}}\n}}\n",
    ],
)
def test_root_mapping_presentations_keep_include_acquisition(tmp_path, layout):
    entry = tmp_path / ".gitlab-ci.yml"
    _write(tmp_path / "templates" / "child.yml", "child:\n  script: echo ready\n")
    _write(entry, layout.format(ref="'/templates/child.yml'"))
    code, report = _scan(tmp_path)
    assert code == 0
    assert report["files_scanned"] == 2
    assert not report["errors"]

    _write(entry, layout.format(ref="'/templates/$CI_COMMIT_BRANCH.yml'"))
    code, report = _scan(tmp_path)
    assert code == 11
    assert report["files_scanned"] == 1
    assert "runtime variable" in report["errors"][0]["title"]


def test_local_include_without_star_resolves_the_literal_filename(tmp_path):
    entry = tmp_path / ".gitlab-ci.yml"
    _write(entry, "include: '/templates/part-[ab].yml'\njob:\n  script: echo ready\n")
    _write(tmp_path / "templates" / "part-a.yml", "wrong:\n  script: echo ready\n")
    code, report = _scan(tmp_path)
    assert code == 11
    assert report["files_scanned"] == 1
    assert "part-[ab].yml" in report["errors"][0]["description"]
    literal = _write(
        tmp_path / "templates" / "part-[ab].yml", "actual:\n  script: echo ready\n"
    )
    code, report = _scan(tmp_path)
    assert code == 0
    assert report["files_scanned"] == 2
    assert not report["errors"]
    assert any(finding["file"] == str(literal) for finding in report["findings"])
    assert not any(finding["file"].endswith("part-a.yml") for finding in report["findings"])


@pytest.mark.parametrize(
    ("script", "hits", "expected_exit"),
    [
        ("script: echo ready", set(), 0),
        ("variables:\n    MESSAGE: *shared\n  script: echo ready", set(), 0),
        ("variables: {MESSAGE: *shared}\n  script: echo ready", set(), 11),
        ("script: *shared", {5}, 1),
    ],
)
def test_include_value_replayed_as_script_keeps_source_signal(
    tmp_path, script, hits, expected_exit
):
    _write(tmp_path / "templates" / "input.yml",
           "spec:\n  inputs:\n    sample:\n      type: array\n---\nchild:\n  script: echo ready\n")
    _write(
        tmp_path / ".gitlab-ci.yml",
        "include:\n  - local: /templates/input.yml\n    inputs:\n      sample:\n"
        "        - &shared echo $CI_COMMIT_BRANCH $CI_COMMIT_REF_NAME\n"
        f"verify:\n  {script}\n",
    )
    code, report = _scan(tmp_path)
    assert {
        (row["rule_id"], row["line"])
        for row in report["findings"]
        if row["rule_id"] in {"SEC4-GL-001", "SEC4-GL-003"}
    } == {(rule, line) for rule in ("SEC4-GL-001", "SEC4-GL-003") for line in hits}
    assert code == expected_exit
    if expected_exit:
        assert report["coverage_status"] == "incomplete"
    else:
        assert not report["errors"]


def test_two_missing_includes_have_distinct_evidence_across_reporters(tmp_path):
    _write(
        tmp_path / ".gitlab-ci.yml",
        "include: [/templates/one.yml, /templates/two.yml]\nverify:\n  script: echo ready\n",
    )
    filtered = ("--min-severity", "HIGH")
    terminal = _run(tmp_path, "text", *filtered)
    sarif = _run(tmp_path, "sarif", *filtered)
    assert terminal.returncode == sarif.returncode == 11
    for path in ("/templates/one.yml", "/templates/two.yml"):
        assert path in terminal.stdout
        assert path in terminal.stderr

    run, = json.loads(sarif.stdout)["runs"]
    errors = [row for row in run["results"] if row["ruleId"] == "ENGINE-ERR"]
    assert len(errors) == 2
    assert len({row["partialFingerprints"]["taintlyFingerprintV1"] for row in errors}) == 2
    notifications = run["invocations"][0]["toolExecutionNotifications"]
    assert len({row["message"]["text"] for row in notifications}) == 2


def test_sarif_notification_preserves_unresolved_project_ref_reason(tmp_path):
    _write(
        tmp_path / ".gitlab-ci.yml",
        "include:\n"
        "  - project: example/pipeline\n"
        "    file: /compile.yml\n"
        "    ref: main\n"
        "  - project: example/other\n"
        "    file: /lint.yml\n"
        "    ref: $OTHER_REVISION\n"
        "check:\n"
        "  script: echo ready\n",
    )
    code, report = _scan(tmp_path)
    assert report["coverage_status"] == "incomplete"
    error, = report["errors"]
    assert "project include revision could not be resolved" in error["description"]
    assert [row["line"] for row in report["findings"] if row["rule_id"] == "SEC3-GL-002"] == [2]

    sarif = _run(tmp_path, "sarif")
    assert sarif.returncode == code
    run, = json.loads(sarif.stdout)["runs"]
    assert run["properties"]["coverage_status"] == "incomplete"
    notification, = run["invocations"][0]["toolExecutionNotifications"]
    assert error["description"] in notification["message"]["text"]



@pytest.mark.parametrize(
    ("module", "limit", "scanned", "diagnostic"),
    [
        ("taintly.engine", "_INCLUDE_GRAPH_MAX_FILES", 3, "include discovery reached"),
        ("taintly.gitlab_workflow_corpus", "_MAX_INCLUDE_DEPTH", 4, "depth limit"),
        ("taintly.gitlab_workflow_corpus", "_MAX_INCLUDE_FILES", 4, "cross-file analysis reached"),
    ],
)
def test_reached_gitlab_include_limit_cannot_look_complete(
    tmp_path, monkeypatch, module, limit, scanned, diagnostic
):
    from importlib import import_module

    from taintly.engine import scan_repo
    from taintly.models import Platform
    from taintly.rules.registry import load_rules_for_platform

    _write(tmp_path / ".gitlab-ci.yml", "include: /parts/a.yml\na:\n  script: echo ready\n")
    _write(tmp_path / "parts/a.yml", "include: /parts/b.yml\nb:\n  script: echo ready\n")
    _write(tmp_path / "parts/b.yml", "include: /parts/c.yml\nc:\n  script: echo ready\n")
    _write(tmp_path / "parts/c.yml", "include: /.gitlab-ci.yml\nd:\n  script: echo ready\n")
    rules = load_rules_for_platform(Platform.GITLAB)

    def scan():
        report, = scan_repo(str(tmp_path), rules, platform=Platform.GITLAB)
        return report

    control = scan()
    assert control.files_scanned == 4
    assert not control.engine_errors()

    monkeypatch.setattr(import_module(module), limit, 2)
    limited = scan()
    assert limited.files_scanned == scanned
    matches = [error for error in limited.engine_errors() if diagnostic in error.description]
    assert len(matches) == 1



@pytest.mark.parametrize("report_format", ["text", "json", "sarif"])
def test_acquisition_diagnostic_redacts_token_shaped_ref(tmp_path, report_format):
    # A local placeholder shaped like a recognized token, never a credential.
    token_marker = "gh" + "p_" + "A" * 36
    _write(
        tmp_path / ".gitlab-ci.yml",
        f"include: /templates/{token_marker}.yml\nverify:\n  script: echo ready\n",
    )

    result = _run(tmp_path, report_format, "--min-severity", "HIGH")
    assert result.returncode == 11
    for stream in (result.stdout, result.stderr):
        assert token_marker not in stream
        assert "/templates/[REDACTED].yml" in stream
        assert "has no available file" in stream
