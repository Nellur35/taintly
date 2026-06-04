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
    wireshark's 68KB .gitlab-ci.yml): files larger than the per-regex
    cap previously lost file-scope rule coverage silently.  Adding
    chunked search restored coverage; ENGINE-ERR still emits as an
    informational banner ("content scanned in chunks") AND the text
    reporter shows a ``! Coverage degraded`` banner so the signal
    stays visible."""
    from taintly.models import AuditReport
    from taintly.reporters.text import format_text

    big_file = tmp_path / "big.yml"
    # 60_000 chars > _MAX_SAFE_TEXT_LEN (50_000)
    big_file.write_text("on: push\njobs:\n" + ("  comment: " + "x" * 50 + "\n") * 1500)

    findings = scan_file(str(big_file), rules=[])
    assert any(f.rule_id == "ENGINE-ERR" and "per-chunk cap" in f.title for f in findings)

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


def test_multiline_quoted_scalar_does_not_emit_structural_engine_err(tmp_path):
    """Valid YAML multi-line quoted scalars should not degrade
    structural coverage.  This mirrors LangChain's reusable release
    workflow input description shape.
    """
    workflow = tmp_path / "release.yml"
    workflow.write_text(
        "on:\n"
        "  workflow_call:\n"
        "    inputs:\n"
        "      allow-prereleases:\n"
        "        type: boolean\n"
        '        description: "Pass `--prerelease=allow` to wheel-install steps so\n'
        "          transitive prerelease deps resolve. Use only when the release itself\n"
        '          is a prerelease."\n'
        "jobs:\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo release\n"
    )

    findings = scan_file(str(workflow), rules=[])

    assert not [f for f in findings if f.rule_id == "ENGINE-ERR"]


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
    # Real scripted pipeline — the loose-.groovy pickup is now content-gated,
    # so the file needs a pipeline marker to be discovered.  The old fixture
    # used a bare ``// build`` comment, which encoded the pre-gate behavior
    # (a non-pipeline .groovy being parsed as a pipeline).
    (tmp_path / "jenkins" / "build.groovy").write_text(
        "node {\n    stage('build') { sh 'make' }\n}\n"
    )

    files = discover_files(str(tmp_path), Platform.JENKINS)
    names = sorted(os.path.relpath(f, str(tmp_path)) for f in files)
    assert "Jenkinsfile" in names
    assert "Jenkinsfile.coverage" in names
    assert os.path.join("ci", "Jenkinsfile.nightly") in names
    assert os.path.join("scripts", "Jenkinsfile") in names
    assert os.path.join("Vendor", "NeMo", "Jenkinsfile") in names
    assert os.path.join("jenkins", "build.groovy") in names


def test_discover_files_jenkins_groovy_package_namespace_not_pipeline(tmp_path):
    """A non-pipeline ``.groovy`` under a ``jenkins`` *package* path must NOT be
    discovered.  jenkinsci/jenkins ships UI views and plain classes under
    ``.../jenkins/model/...`` — ``jenkins`` there is a Java/Groovy namespace,
    not a CI directory.  Content-gating drops these; a ``Jenkinsfile`` in the
    same tree is still discovered (strong signal, never gated).
    """
    pkg = tmp_path / "core" / "src" / "main" / "resources" / "jenkins" / "model"
    pkg.mkdir(parents=True)
    # A UI view / form field — exactly the SEC4-JK-004 false positive source.
    (pkg / "config.groovy").write_text(
        'f.entry(field: "x") {\n    input(type: "hidden", name: "x")\n}\n'
    )
    (tmp_path / "Jenkinsfile").write_text("pipeline {\n    agent any\n}\n")

    files = discover_files(str(tmp_path), Platform.JENKINS)
    rel = sorted(os.path.relpath(f, str(tmp_path)) for f in files)
    assert "Jenkinsfile" in rel
    assert (
        os.path.join("core", "src", "main", "resources", "jenkins", "model", "config.groovy")
        not in rel
    )


def test_discover_files_jenkins_real_groovy_pipeline_under_jenkins_dir(tmp_path):
    """A real scripted ``.groovy`` pipeline (``node {}`` / ``stage()``) under a
    ``jenkins/`` directory is still discovered — content-gating keeps genuine
    pipelines, it only drops non-pipeline package files.
    """
    (tmp_path / "jenkins").mkdir()
    (tmp_path / "jenkins" / "deploy.groovy").write_text(
        "node {\n    stage('deploy') { sh './deploy.sh' }\n}\n"
    )

    files = discover_files(str(tmp_path), Platform.JENKINS)
    rel = sorted(os.path.relpath(f, str(tmp_path)) for f in files)
    assert os.path.join("jenkins", "deploy.groovy") in rel


def test_discover_files_gitlab_duo_config_not_ci(tmp_path):
    """``.gitlab/duo/agent-config.yml`` (a GitLab Duo tool config carrying only
    ``image:``) must NOT be discovered as CI.  ``.gitlab/`` is a weak signal —
    a bare ``image:`` is exactly what tool YAMLs carry, so it is not enough.
    ``.gitlab-ci.yml`` (entry file, never gated) is still discovered.
    """
    duo = tmp_path / ".gitlab" / "duo"
    duo.mkdir(parents=True)
    (duo / "agent-config.yml").write_text(
        "image: registry.example.com/duo/agent:1.2.3\nname: duo-agent\n"
    )
    (tmp_path / ".gitlab-ci.yml").write_text("stages:\n  - build\nbuild:\n  script:\n    - make\n")

    files = discover_files(str(tmp_path), Platform.GITLAB)
    rel = sorted(os.path.relpath(f, str(tmp_path)) for f in files)
    assert ".gitlab-ci.yml" in rel
    assert os.path.join(".gitlab", "duo", "agent-config.yml") not in rel


def test_discover_files_gitlab_dotgitlab_ci_fragment_discovered(tmp_path):
    """A genuine CI fragment under ``.gitlab/`` (carrying a job-shaped
    ``script:`` block) IS still discovered — content-gating keeps real CI YAML.
    """
    ci = tmp_path / ".gitlab" / "ci"
    ci.mkdir(parents=True)
    (ci / "build.yml").write_text("build:\n  stage: build\n  script:\n    - make all\n")

    files = discover_files(str(tmp_path), Platform.GITLAB)
    rel = sorted(os.path.relpath(f, str(tmp_path)) for f in files)
    assert os.path.join(".gitlab", "ci", "build.yml") in rel


def test_discover_files_jenkins_descends_hidden_directories(tmp_path):
    """``.jenkins/Jenkinsfile`` and similar dot-prefixed CI dirs must be
    discovered.  apache/cassandra and many Apache projects use
    ``.jenkins/Jenkinsfile`` as the canonical path; ``glob.glob(recursive
    =True)`` SKIPS hidden directories by default (``include_hidden=True``
    is 3.11+), so the old recursive-glob implementation silently missed
    them.  Surfaced by 2026-05-18 audit on apache/cassandra (667-line
    Jenkinsfile completely invisible to taintly).
    """
    (tmp_path / ".jenkins").mkdir()
    (tmp_path / ".jenkins" / "Jenkinsfile").write_text("pipeline {}\n")
    (tmp_path / ".ci").mkdir()
    (tmp_path / ".ci" / "Jenkinsfile.nightly").write_text("pipeline {}\n")

    files = discover_files(str(tmp_path), Platform.JENKINS)
    rel = sorted(os.path.relpath(f, str(tmp_path)) for f in files)
    assert os.path.join(".jenkins", "Jenkinsfile") in rel
    assert os.path.join(".ci", "Jenkinsfile.nightly") in rel


def test_discover_files_jenkins_underscore_and_dash_variants(tmp_path):
    """``Jenkinsfile_k8s`` / ``Jenkinsfile-prod`` are the documented
    convention for per-platform / per-environment pipelines.
    jenkinsci/jenkins.io ships a ``Jenkinsfile_k8s`` for the Kubernetes
    runner variant; the old ``Jenkinsfile.*`` glob (literal dot) missed
    underscore- and dash-suffixed variants.  Surfaced by 2026-05-18
    audit on jenkinsci/jenkins.io.
    """
    (tmp_path / "Jenkinsfile").write_text("pipeline {}\n")
    (tmp_path / "Jenkinsfile_k8s").write_text("pipeline {}\n")
    (tmp_path / "Jenkinsfile-prod").write_text("pipeline {}\n")

    files = discover_files(str(tmp_path), Platform.JENKINS)
    rel = sorted(os.path.relpath(f, str(tmp_path)) for f in files)
    assert "Jenkinsfile" in rel
    assert "Jenkinsfile_k8s" in rel
    assert "Jenkinsfile-prod" in rel


def test_discover_files_jenkins_rejects_doc_extensions(tmp_path):
    """``jenkinsfile.adoc`` is the asciidoc filename used by
    jenkinsci/jenkins.io to document the Jenkinsfile syntax — NOT a
    pipeline script.  On case-insensitive filesystems (Windows, macOS)
    a naive ``Jenkinsfile.*`` glob slurped these and produced CUTOFF
    events from the structural reader.  Reject documented doc-format
    extensions explicitly.
    """
    (tmp_path / "Jenkinsfile.adoc").write_text("= Jenkinsfile syntax\n")
    (tmp_path / "Jenkinsfile.md").write_text("# Jenkinsfile\n")
    (tmp_path / "Jenkinsfile.html").write_text("<html/>\n")
    # Anchor the assertion with a real one.
    (tmp_path / "Jenkinsfile").write_text("pipeline {}\n")

    files = discover_files(str(tmp_path), Platform.JENKINS)
    rel = [os.path.relpath(f, str(tmp_path)) for f in files]
    assert rel == ["Jenkinsfile"]


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


def test_discover_gitlab_follows_local_include_outside_glob_roots(tmp_path):
    """Include-graph closure: a fragment referenced via ``include: local:``
    that lives OUTSIDE ci/ and .gitlab/ (so no glob would find it) must be
    discovered. An explicit include is authoritative CI."""
    (tmp_path / ".gitlab-ci.yml").write_text(
        "include:\n  - local: 'pipelines/build.yml'\nstages: [build]\n"
    )
    frag = tmp_path / "pipelines"
    frag.mkdir()
    (frag / "build.yml").write_text("build:\n  script:\n    - make\n")

    rel = [os.path.relpath(f, str(tmp_path)) for f in discover_files(str(tmp_path), Platform.GITLAB)]
    assert os.path.join("pipelines", "build.yml") in rel


def test_discover_gitlab_include_graph_is_transitive(tmp_path):
    """A includes B, B includes C — all three must be discovered."""
    (tmp_path / ".gitlab-ci.yml").write_text("include:\n  - local: '/a.yml'\n")
    (tmp_path / "a.yml").write_text("include:\n  - local: '/b.yml'\na:\n  script: [echo a]\n")
    (tmp_path / "b.yml").write_text("b:\n  script:\n    - echo b\n")

    rel = [os.path.relpath(f, str(tmp_path)) for f in discover_files(str(tmp_path), Platform.GITLAB)]
    assert "a.yml" in rel
    assert "b.yml" in rel


def test_discover_gitlab_include_glob_is_expanded(tmp_path):
    """``include: local: 'templates/*.yml'`` expands the glob (the 5->50 case)."""
    (tmp_path / ".gitlab-ci.yml").write_text("include:\n  - local: 'templates/*.yml'\n")
    t = tmp_path / "templates"
    t.mkdir()
    (t / "one.yml").write_text("one:\n  script: [echo 1]\n")
    (t / "two.yml").write_text("two:\n  script: [echo 2]\n")

    rel = [os.path.relpath(f, str(tmp_path)) for f in discover_files(str(tmp_path), Platform.GITLAB)]
    assert os.path.join("templates", "one.yml") in rel
    assert os.path.join("templates", "two.yml") in rel


def test_discover_gitlab_dynamic_include_does_not_crash_or_overreach(tmp_path):
    """A runtime-interpolated include target (``$[[ inputs.x ]]``) is
    unresolvable — discovery must not crash and must not invent a file."""
    (tmp_path / ".gitlab-ci.yml").write_text(
        "include:\n  - local: 'pipelines/$[[ inputs.kind ]].yml'\nstages: [build]\n"
    )
    (tmp_path / "pipelines").mkdir()
    (tmp_path / "pipelines" / "build.yml").write_text("build:\n  script: [make]\n")

    rel = [os.path.relpath(f, str(tmp_path)) for f in discover_files(str(tmp_path), Platform.GITLAB)]
    assert os.path.join("pipelines", "build.yml") not in rel
    assert ".gitlab-ci.yml" in rel


def test_discovery_confidence_gitlab_tiers(tmp_path):
    """Entry files + include-reached fragments are authoritative ("high");
    a .gitlab/** glob pickup is weak ("low")."""
    from taintly.engine import _discovery_confidence

    (tmp_path / ".gitlab-ci.yml").write_text(
        "include:\n  - local: 'pipelines/inc.yml'\nstages: [build]\n"
    )
    (tmp_path / "pipelines").mkdir()
    (tmp_path / "pipelines" / "inc.yml").write_text("a:\n  script:\n    - echo a\n")
    gl = tmp_path / ".gitlab" / "ci"
    gl.mkdir(parents=True)
    (gl / "weak.yml").write_text("b:\n  script:\n    - echo b\n")

    files = discover_files(str(tmp_path), Platform.GITLAB)
    conf = _discovery_confidence(str(tmp_path), Platform.GITLAB, files)

    def tier(*parts):
        return conf[os.path.normpath(os.path.join(str(tmp_path), *parts))]

    assert tier(".gitlab-ci.yml") == "high"
    assert tier("pipelines", "inc.yml") == "high"  # include-reached
    assert tier(".gitlab", "ci", "weak.yml") == "low"  # weak glob pickup


def test_discovery_confidence_gitlab_ci_named_file_is_high(tmp_path):
    """A file NAMED *.gitlab-ci.yml under .gitlab/ci/ (a child-pipeline config,
    triggered not root-included) is authoritative by filename -> high."""
    from taintly.engine import _discovery_confidence

    (tmp_path / ".gitlab-ci.yml").write_text("stages: [build]\n")
    child = tmp_path / ".gitlab" / "ci" / "cng"
    child.mkdir(parents=True)
    (child / "main.gitlab-ci.yml").write_text("job:\n  script:\n    - make\n")
    (child / "random.yml").write_text("other:\n  script:\n    - echo hi\n")

    files = discover_files(str(tmp_path), Platform.GITLAB)
    conf = _discovery_confidence(str(tmp_path), Platform.GITLAB, files)

    def tier(*parts):
        return conf[os.path.normpath(os.path.join(str(tmp_path), *parts))]

    assert tier(".gitlab", "ci", "cng", "main.gitlab-ci.yml") == "high"
    assert tier(".gitlab", "ci", "cng", "random.yml") == "low"


def test_scan_repo_caps_low_confidence_findings_at_review(tmp_path):
    """A finding on a weakly-discovered file is tagged discovery_confidence
    "low" and forced to review-needed."""
    from taintly.rules.registry import load_rules_for_platform

    (tmp_path / ".gitlab-ci.yml").write_text("stages: [build]\n")  # entry, no finding
    gl = tmp_path / ".gitlab" / "ci"
    gl.mkdir(parents=True)
    (gl / "x.yml").write_text("job:\n  image: alpine:3.19\n  script:\n    - make\n")

    reports = scan_repo(str(tmp_path), load_rules_for_platform(Platform.GITLAB))
    weak = [
        f
        for r in reports
        for f in r.findings
        if f.rule_id == "SEC3-GL-005" and "x.yml" in f.file
    ]
    assert weak, "expected SEC3-GL-005 on the weak .gitlab/ci/x.yml pickup"
    assert all(f.discovery_confidence == "low" for f in weak)
    assert all(f.review_needed for f in weak)


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
    assert reports[0].files_scanned == 1, f"expected 1 file scanned, got {reports[0].files_scanned}"


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
    assert "scoped" in err.lower(), f"expected scoped-mode warning on stderr, got: {err}"


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


# =============================================================================
# Structural CUTOFF disclosure
# =============================================================================


def test_structural_cutoff_emits_file_level_engine_err(tmp_path, github_rules):
    """When the structural reader hits CUTOFF mid-file, scan_file
    surfaces a single file-level ENGINE-ERR documenting the
    coverage degradation.

    Per-rule structural-pattern markers continue to fire for the
    rules that ran; the file-level finding ensures the disclosure
    is visible regardless of which rule types the file exercised.
    """
    from taintly.engine import scan_file

    wf = tmp_path / "wf.yml"
    # ``%YAML`` directive is the simplest CUTOFF trigger -- the
    # tokenizer treats it as an unsupported construct in recover
    # mode (verified at tests/unit/test_structural_walker.py:183).
    wf.write_text(
        "name: ci\n"
        "%YAML 1.2\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    findings = scan_file(str(wf), github_rules)
    cutoff_findings = [
        f
        for f in findings
        if f.rule_id == "ENGINE-ERR" and "Structural coverage degraded" in f.title
    ]
    assert len(cutoff_findings) == 1, (
        f"expected exactly one CUTOFF disclosure; got "
        f"{[(f.rule_id, f.title) for f in findings if f.rule_id == 'ENGINE-ERR']}"
    )
    assert cutoff_findings[0].line == 2  # the directive line


def test_clean_yaml_does_not_emit_cutoff_disclosure(tmp_path, github_rules):
    """A well-formed workflow doesn't produce a CUTOFF ENGINE-ERR."""
    from taintly.engine import scan_file

    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    )
    findings = scan_file(str(wf), github_rules)
    cutoff = [
        f
        for f in findings
        if f.rule_id == "ENGINE-ERR" and "Structural coverage degraded" in f.title
    ]
    assert cutoff == []


def test_jenkinsfile_does_not_run_cutoff_check(tmp_path, jenkins_rules):
    """Jenkinsfiles don't go through the structural reader; the
    CUTOFF check is gated on YAML extensions and must not fire on
    Jenkinsfile inputs (which would always produce a spurious
    cutoff because the structural reader doesn't handle Groovy).
    """
    from taintly.engine import scan_file

    jf = tmp_path / "Jenkinsfile"
    jf.write_text(
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('build') {\n"
        "      steps { sh 'echo hi' }\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    findings = scan_file(str(jf), jenkins_rules)
    cutoff = [
        f
        for f in findings
        if f.rule_id == "ENGINE-ERR" and "Structural coverage degraded" in f.title
    ]
    assert cutoff == []
