"""Unit tests for taintly/engine.py.

Verifies the failure modes that were silent before:
- ENGINE-ERR is a proper Severity enum (not a string "INFO")
- ENGINE-ERR on unreadable file is filterable and doesn't crash filter_severity
- A crashing rule produces ENGINE-ERR, not an unhandled exception
- Line numbers in findings are accurate
- discover_files finds both .yml and .yaml, deduplicates, sorts
- scan_file with _content= and from disk produce identical findings
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from taintly.engine import discover_files, scan_file, scan_repo
from taintly.models import Platform, RegexPattern, Rule, Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _make_rule(rule_id: str, pattern: str) -> Rule:
    return Rule(
        id=rule_id,
        title="Test rule",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description="Test",
        pattern=RegexPattern(match=pattern),
        remediation="Fix it",
        reference="https://example.com",
    )


# =============================================================================
# ENGINE-ERR severity is a proper enum
# =============================================================================


def test_engine_err_on_missing_file_has_enum_severity(tmp_path):
    """ENGINE-ERR severity must be Severity.INFO (enum), not string 'INFO'.
    If it's a string, filter_severity() will crash with AttributeError.
    """
    findings = scan_file(str(tmp_path / "nonexistent.yml"), rules=[])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "ENGINE-ERR"
    assert isinstance(f.severity, Severity), (
        f"ENGINE-ERR severity is {type(f.severity).__name__!r}, expected Severity enum. "
        "filter_severity() will crash on this."
    )
    assert f.severity == Severity.LOW  # LOW so it survives --min-severity LOW filters


def test_engine_err_survives_filter_severity(tmp_path):
    """ENGINE-ERR must survive every --min-severity filter.

    Regression guard for the v1.1 behaviour change: previously a CI
    gate set to ``--min-severity HIGH`` silently dropped engine errors,
    so a green run could hide that scanning never happened.  The
    severity floor now applies only to real findings; ENGINE-ERR is
    exempt and is additionally surfaced via stderr and the JSON
    ``errors`` / SARIF ``toolExecutionNotifications`` channels.
    """
    from taintly.models import AuditReport

    findings = scan_file(str(tmp_path / "nonexistent.yml"), rules=[])
    report = AuditReport(repo_path="/test", platform="github")
    for f in findings:
        report.add(f)
    report.summarize()
    report.filter_severity(Severity.HIGH)
    assert any(f.rule_id == "ENGINE-ERR" for f in report.findings), (
        "ENGINE-ERR must survive --min-severity HIGH so silent coverage "
        "loss is never hidden by the CI gate."
    )


def test_oversize_file_emits_engine_err_and_appears_in_text_banner(tmp_path):
    """Field-test regression (gitlabhq's 129KB rules.gitlab-ci.yml,
    wireshark's 68KB .gitlab-ci.yml): files larger than the scanner cap
    silently lost file-scope rule coverage. The cap still applies (it's
    a ReDoS guard) but the loss is now visible: ENGINE-ERR is emitted
    AND the text reporter shows a ``! Coverage degraded`` banner."""
    from taintly.models import AuditReport
    from taintly.reporters.text import format_text

    big_file = tmp_path / "big.yml"
    # 60_000 chars > _MAX_SAFE_TEXT_LEN (50_000)
    big_file.write_text("on: push\njobs:\n" + ("  comment: " + "x" * 50 + "\n") * 1500)

    findings = scan_file(str(big_file), rules=[])
    assert any(f.rule_id == "ENGINE-ERR" and "exceeds scanner cap" in f.title for f in findings)

    report = AuditReport(repo_path="/test", platform="github")
    for f in findings:
        report.add(f)
    report.summarize()

    text = format_text(report, use_color=False)
    assert "Coverage degraded" in text, (
        "Text reporter must surface a coverage-degradation banner so the "
        "signal isn't lost when a user pipes or saves the report (stderr "
        "alone is too easy to miss). Got:\n" + text
    )


def test_engine_err_on_crashing_rule(tmp_path):
    """A rule whose pattern.check() raises must produce ENGINE-ERR, not propagate."""
    import taintly.models as models_module

    broken_rule = _make_rule("BROKEN", r"test")

    # Patch the pattern to raise
    original_check = broken_rule.pattern.check

    def _crash(content, lines):
        raise RuntimeError("deliberate crash in test")

    broken_rule.pattern.check = _crash

    yaml_file = tmp_path / "test.yml"
    yaml_file.write_text("name: Test\non: push\n")

    findings = scan_file(str(yaml_file), rules=[broken_rule])
    engine_errs = [f for f in findings if f.rule_id == "ENGINE-ERR"]
    assert len(engine_errs) == 1
    assert "BROKEN" in engine_errs[0].title


# =============================================================================
# Line number accuracy
# =============================================================================


def test_line_numbers_are_1_indexed(tmp_path):
    """First line of file must be reported as line 1, not 0."""
    content = "uses: actions/checkout@v4\n"
    yaml_file = tmp_path / "ci.yml"
    yaml_file.write_text(content)
    rule = _make_rule("R1", r"uses:.*@v\d")
    findings = scan_file(str(yaml_file), rules=[rule])
    assert len(findings) == 1
    assert findings[0].line == 1, f"Expected line 1, got {findings[0].line}"


def test_line_numbers_accurate_on_multiline_file(tmp_path):
    """Rule firing on line 5 must report line 5."""
    content = "name: Test\non: push\npermissions:\n  contents: read\nuses: actions/checkout@v4\n"
    yaml_file = tmp_path / "ci.yml"
    yaml_file.write_text(content)
    rule = _make_rule("R1", r"uses:.*@v\d")
    findings = scan_file(str(yaml_file), rules=[rule])
    assert len(findings) == 1
    assert findings[0].line == 5, f"Expected line 5, got {findings[0].line}"


# =============================================================================
# _content= vs disk read produce identical results
# =============================================================================


def test_scan_file_content_kwarg_matches_disk_read(tmp_path):
    content = "uses: actions/checkout@v4\npermissions: write-all\n"
    yaml_file = tmp_path / "ci.yml"
    yaml_file.write_text(content)
    rule1 = _make_rule("R1", r"uses:.*@v\d")
    rule2 = _make_rule("R2", r"permissions:\s*write-all")

    from_disk = scan_file(str(yaml_file), rules=[rule1, rule2])
    from_content = scan_file(str(yaml_file), rules=[rule1, rule2], _content=content)

    assert [(f.rule_id, f.line) for f in from_disk] == [(f.rule_id, f.line) for f in from_content]


# =============================================================================
# Empty file
# =============================================================================


def test_empty_file_returns_no_findings():
    empty = str(FIXTURES / "github" / "edge_cases" / "empty.yml")
    rule = _make_rule("R1", r"uses:.*@v\d")
    findings = scan_file(empty, rules=[rule])
    assert findings == []


# =============================================================================
# discover_files
# =============================================================================


def test_discover_files_github_finds_yml_and_yaml(tmp_path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text("name: CI\n")
    (wf_dir / "release.yaml").write_text("name: Release\n")
    (wf_dir / "not_a_workflow.txt").write_text("ignore me\n")

    files = discover_files(str(tmp_path), Platform.GITHUB)
    names = [os.path.basename(f) for f in files]
    assert "ci.yml" in names
    assert "release.yaml" in names
    assert "not_a_workflow.txt" not in names


def test_discover_files_github_no_duplicates(tmp_path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text("name: CI\n")

    files = discover_files(str(tmp_path), Platform.GITHUB)
    assert len(files) == len(set(files)), "discover_files returned duplicate paths"


def test_discover_files_returns_sorted(tmp_path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    for name in ["z.yml", "a.yml", "m.yml"]:
        (wf_dir / name).write_text("name: x\n")

    files = discover_files(str(tmp_path), Platform.GITHUB)
    assert files == sorted(files)


def test_discover_files_missing_dir_returns_empty(tmp_path):
    files = discover_files(str(tmp_path), Platform.GITHUB)
    assert files == []


def test_discover_files_jenkins_nested_paths(tmp_path):
    """Jenkinsfiles can live under ci/, scripts/, or per-vendor subtrees;
    discover_files must walk those, not just the repo root and jenkins/.
    """
    (tmp_path / "Jenkinsfile").write_text("pipeline {}\n")
    (tmp_path / "Jenkinsfile.coverage").write_text("pipeline {}\n")
    (tmp_path / "ci").mkdir()
    (tmp_path / "ci" / "Jenkinsfile.nightly").write_text("pipeline {}\n")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "Jenkinsfile").write_text("pipeline {}\n")
    (tmp_path / "Vendor" / "NeMo").mkdir(parents=True)
    (tmp_path / "Vendor" / "NeMo" / "Jenkinsfile").write_text("pipeline {}\n")
    (tmp_path / "jenkins").mkdir()
    (tmp_path / "jenkins" / "build.groovy").write_text("// build\n")

    files = discover_files(str(tmp_path), Platform.JENKINS)
    names = sorted(os.path.relpath(f, str(tmp_path)) for f in files)
    assert "Jenkinsfile" in names
    assert "Jenkinsfile.coverage" in names
    assert os.path.join("ci", "Jenkinsfile.nightly") in names
    assert os.path.join("scripts", "Jenkinsfile") in names
    assert os.path.join("Vendor", "NeMo", "Jenkinsfile") in names
    assert os.path.join("jenkins", "build.groovy") in names


def test_discover_files_jenkins_excludes_vendor_dirs(tmp_path):
    """Third-party dependency trees shouldn't be scanned — they're noise
    and slow. Verify node_modules/.git/vendor/__pycache__ are pruned even
    when they contain Jenkinsfile-shaped files.
    """
    for vendor in ("node_modules", ".git", "vendor", "__pycache__"):
        d = tmp_path / vendor / "nested"
        d.mkdir(parents=True)
        (d / "Jenkinsfile").write_text("pipeline {}\n")
    # Legitimate file to anchor the assertion.
    (tmp_path / "Jenkinsfile").write_text("pipeline {}\n")

    files = discover_files(str(tmp_path), Platform.JENKINS)
    rel_names = [os.path.relpath(f, str(tmp_path)) for f in files]
    assert rel_names == ["Jenkinsfile"]


def test_discover_files_jenkins_node_modules_prefix_not_excluded(tmp_path):
    """Segment-check (not substring) — ``node_modules_archive`` is a
    legitimate directory name and must not be pruned.
    """
    d = tmp_path / "node_modules_archive"
    d.mkdir()
    (d / "Jenkinsfile").write_text("pipeline {}\n")

    files = discover_files(str(tmp_path), Platform.JENKINS)
    rel_names = [os.path.relpath(f, str(tmp_path)) for f in files]
    assert os.path.join("node_modules_archive", "Jenkinsfile") in rel_names


# =============================================================================
# Fixture file smoke tests
# =============================================================================


def test_vulnerable_ppe_fixture_fires(github_rules):
    findings = scan_file(
        str(FIXTURES / "github" / "vulnerable" / "ppe_classic.yml"),
        rules=github_rules,
    )
    rule_ids = {f.rule_id for f in findings}
    assert "SEC4-GH-001" in rule_ids or "SEC4-GH-011" in rule_ids, (
        f"PPE fixture should trigger at least SEC4-GH-001 or SEC4-GH-011; got: {rule_ids}"
    )


def test_deeply_nested_fixture_fires_unpinned(github_rules):
    findings = scan_file(
        str(FIXTURES / "github" / "edge_cases" / "deeply_nested.yml"),
        rules=github_rules,
    )
    rule_ids = {f.rule_id for f in findings}
    assert "SEC3-GH-001" in rule_ids, (
        f"4-space-indented unpinned action should fire SEC3-GH-001; got: {rule_ids}"
    )


# =============================================================================
# Path normalization (scope-narrowing inputs)
# =============================================================================


def test_scope_normalize_workflows_dir(tmp_path):
    """Passing <repo>/.github/workflows must scan, not silently return 0."""
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
    )

    from taintly.rules.registry import load_rules_for_platform
    rules = load_rules_for_platform(Platform.GITHUB)
    reports = scan_repo(str(wf_dir), rules)
    assert reports, "scan_repo returned no reports"
    assert reports[0].files_scanned == 1, (
        f"expected 1 file scanned, got {reports[0].files_scanned}"
    )


def test_scope_normalize_dotgithub_dir(tmp_path):
    """Passing <repo>/.github must scan."""
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps: []\n"
    )

    from taintly.rules.registry import load_rules_for_platform
    rules = load_rules_for_platform(Platform.GITHUB)
    reports = scan_repo(str(tmp_path / ".github"), rules)
    assert reports[0].files_scanned == 1


def test_scope_normalize_single_file(tmp_path, capsys):
    """Passing a single .yml file scans only that file and warns to stderr."""
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps: []\n"
    )
    (wf_dir / "other.yml").write_text(
        "on: push\njobs:\n  y:\n    runs-on: ubuntu-latest\n    steps: []\n"
    )

    from taintly.rules.registry import load_rules_for_platform
    rules = load_rules_for_platform(Platform.GITHUB)
    reports = scan_repo(str(wf_dir / "ci.yml"), rules)
    assert reports[0].files_scanned == 1
    err = capsys.readouterr().err
    assert "scoped" in err.lower(), (
        f"expected scoped-mode warning on stderr, got: {err}"
    )


def test_scope_normalize_repo_root_unchanged(tmp_path):
    """Passing the repo root behaves exactly as before — regression guard."""
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps: []\n"
    )
    (wf_dir / "release.yaml").write_text(
        "on: push\njobs:\n  r:\n    runs-on: ubuntu-latest\n    steps: []\n"
    )

    from taintly.rules.registry import load_rules_for_platform
    rules = load_rules_for_platform(Platform.GITHUB)
    reports = scan_repo(str(tmp_path), rules)
    assert reports[0].files_scanned == 2


def test_scope_normalize_nonexistent_path_does_not_crash(tmp_path):
    """Bogus paths should produce an empty/error report, never a crash."""
    from taintly.rules.registry import load_rules_for_platform
    rules = load_rules_for_platform(Platform.GITHUB)
    # Should not raise.
    reports = scan_repo(str(tmp_path / "does-not-exist"), rules)
    assert reports, "expected at least one report (possibly empty) for nonexistent path"


def test_scope_normalize_jenkinsfile_single(tmp_path):
    """Passing a single Jenkinsfile path scans Jenkins-platform rules only."""
    (tmp_path / "Jenkinsfile").write_text("pipeline { agent any }\n")
    from taintly.rules.registry import load_rules_for_platform
    rules = load_rules_for_platform(Platform.JENKINS)
    reports = scan_repo(str(tmp_path / "Jenkinsfile"), rules)
    assert reports[0].files_scanned == 1


def test_anchor_merge_does_not_fire_sec4_gh_005(github_rules):
    """A workflow that sets persist-credentials: false via YAML anchor
    merge (`<<: *checkout_opts`) must NOT trigger SEC4-GH-005.  The
    rule's lookahead window can't see the anchor body, so the
    anchor-aware suppression in scan_file (Task 5) is what carries
    the load.  Regression guard: if this fixture starts firing again,
    the anchor expander or the per-rule opt-in regressed."""
    fixture = FIXTURES / "github" / "safe" / "anchor_merge_inject.yml"
    findings = scan_file(str(fixture), rules=github_rules)
    fired = {f.rule_id for f in findings if f.rule_id != "ENGINE-ERR"}
    assert "SEC4-GH-005" not in fired, (
        "SEC4-GH-005 fired on a workflow that DOES set persist-credentials: "
        f"false via YAML anchor — anchor-aware suppression regressed.  Fired: {fired}"
    )


def test_lazy_loading_skips_other_platforms():
    """Loading GitHub rules must not import GitLab or Jenkins rule modules.

    Cheap proxy for the cold-start win: assert no taintly.rules.gitlab.* or
    taintly.rules.jenkins.* modules are present in sys.modules after a
    targeted GitHub-only load.  Run in a subprocess so the test isn't
    polluted by previous imports in the test session.
    """
    import subprocess
    import sys
    import textwrap
    code = textwrap.dedent("""
        import sys
        from taintly.models import Platform
        from taintly.rules.registry import load_rules_for_platform
        load_rules_for_platform(Platform.GITHUB)
        gl = [m for m in sys.modules if m.startswith('taintly.rules.gitlab.')]
        jk = [m for m in sys.modules if m.startswith('taintly.rules.jenkins.')]
        assert not gl, f'GitLab rule modules leaked into GitHub-only load: {gl}'
        assert not jk, f'Jenkins rule modules leaked into GitHub-only load: {jk}'
        print('OK')
    """)
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert "OK" in r.stdout, f"stdout={r.stdout!r}, stderr={r.stderr!r}"
