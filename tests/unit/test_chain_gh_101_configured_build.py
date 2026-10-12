"""Configured attack paths require same-source checkout/build/credential evidence."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from taintly.authority_context import calibrate_lotp_authority
from taintly.composer import run_composer
from taintly.engine import scan_repo
from taintly.models import AuditReport, Platform, Severity
from taintly.reporters.json_report import format_json
from taintly.reporters.sarif import format_sarif
from taintly.rules.github.chain_compose import COMPOSER_RULES
from taintly.rules.registry import load_all_rules
from taintly.workflow_corpus import build_corpus

BASE = """on: pull_request_target
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: true
      - run: npm ci
"""


@pytest.fixture(scope="module")
def rules():
    return load_all_rules()


def scan(tmp_path: Path, rules, content: str = BASE):
    path = tmp_path / ".github/workflows/build.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    reports = scan_repo(str(tmp_path), rules, Platform.GITHUB)
    assert not [f for report in reports for f in report.engine_errors()]
    return path, [f for report in reports for f in report.findings]


def chain(findings):
    return [f for f in findings if f.rule_id == "CHAIN-GH-101"]


@pytest.mark.parametrize(
    "command", ["npm ci", "npm install", "npm run build", "make test", "cargo test"]
)
def test_configured_build_without_git_consumer_has_one_source_linked_chain(
    tmp_path, rules, command
):
    content = BASE.replace("npm ci", command)
    path, findings = scan(tmp_path, rules, content)
    assert not [f for f in findings if f.rule_id == "SEC4-GH-005"]
    (finding,) = chain(findings)
    assert finding.file == str(path)
    assert finding.line == 8
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence == "medium"
    assert finding.review_needed
    assert "checkout-build-path-evidenced" in finding.context_tags
    assert "execution-unproven" not in finding.context_tags
    assert "runtime-execution-unverified" in finding.context_tags
    assert "effective-token-policy-unresolved" in finding.context_tags
    assert "repository/ref at lines 10/11" in finding.snippet
    assert f"local build `{command}` at line 13" in finding.snippet
    assert "contents:write (line 3)" in finding.snippet
    assert "line 12" in finding.snippet
    assert "checkout at line 8" in finding.remediation
    assert "build at line 13" in finding.remediation
    assert "permissions at line 2" in finding.remediation
    assert "remain unverified" in finding.snippet
    assert "Hook existence" in finding.calibration_reason


def test_consumer_and_two_lotp_rules_do_not_duplicate_the_chain(tmp_path, rules):
    _, findings = scan(tmp_path, rules, BASE + "      - run: git push origin HEAD:main\n")
    assert [f for f in findings if f.rule_id == "SEC4-GH-005"]
    assert len([f for f in findings if f._checkout_build is not None]) == 2
    (finding,) = chain(findings)
    assert "checkout-build-path-evidenced" in finding.context_tags


def test_unrelated_later_bot_step_does_not_hide_the_configured_path(tmp_path, rules):
    content = BASE + (
        "      - run: echo trusted automation\n        if: github.actor == 'dependabot[bot]'\n"
    )
    _, findings = scan(tmp_path, rules, content)
    (finding,) = chain(findings)
    assert "checkout-build-path-evidenced" in finding.context_tags
    assert finding.review_needed


@pytest.mark.parametrize("owner", ["job", "checkout", "build"])
@pytest.mark.parametrize("fork_compatible", [True, False])
def test_only_positively_compatible_owning_guards_get_a_path(
    tmp_path, rules, owner, fork_compatible
):
    guard = "github.actor == 'dependabot[bot]'"
    if fork_compatible:
        guard = "github.event_name == 'pull_request_target' || " + guard
    if owner == "job":
        content = BASE.replace("    runs-on:", f"    if: {guard}\n    runs-on:")
    elif owner == "checkout":
        content = BASE.replace("        with:", f"        if: {guard}\n        with:")
    else:
        content = BASE.replace("      - run: npm ci", f"      - if: {guard}\n        run: npm ci")
    _, findings = scan(tmp_path, rules, content)
    assert bool([f for f in findings if f._checkout_build is not None]) == fork_compatible
    assert bool(chain(findings)) == fork_compatible
    assert all(f.review_needed for f in chain(findings))


def test_consumer_only_candidate_keeps_existing_bot_heuristic(tmp_path, rules):
    content = (
        BASE.replace(
            "          repository: ${{ github.event.pull_request.head.repo.full_name }}\n", ""
        ).replace("          ref: ${{ github.event.pull_request.head.sha }}\n", "")
        + "      - run: git push origin HEAD:main\n        if: github.actor == 'dependabot[bot]'\n"
    )
    _, findings = scan(tmp_path, rules, content)
    assert [f for f in findings if f.rule_id == "SEC4-GH-005"]
    assert not [f for f in findings if f._checkout_build is not None]
    assert chain(findings) == []


@pytest.mark.parametrize(
    "old,new",
    [
        ("npm ci", "npm ci --ignore-scripts"),
        ("npm ci", "npm --prefix other ci"),
        ("npm ci", "make -f /tmp/other"),
        ("npm ci", "make -n"),
        ("npm ci", "make --help"),
        ("npm ci", "npm run --help"),
        ("npm ci", "cargo test --manifest-path /tmp/other/Cargo.toml"),
        ("npm ci", "npm ci > output"),
        ("npm ci", "npm ci | cat"),
        ("npm ci", "npm ci && git push"),
        ("run: npm ci", "run: |\n          npm ci\n          git push origin HEAD:main"),
        ("run: npm ci", "run: |\n          cd other\n          npm ci"),
        ("run: npm ci", "run: npm ci\n        shell: pwsh"),
        ("run: npm ci", "run: npm ci\n        env:\n          NPM_CONFIG_IGNORE_SCRIPTS: true"),
        ("run: npm ci", "run: npm ci\n        env:\n          PATH: /tmp/tools"),
        ("run: npm ci", "run: npm ci\n        env:\n          MAKEFLAGS: --dry-run"),
        ("persist-credentials: true", "persist-credentials: false"),
        ("persist-credentials: true", "token: ${{ secrets.PAT }}"),
        ("ref: ${{ github.event.pull_request.head.sha }}", "ref: main"),
        ("contents: write", "contents: read"),
        ("contents: write", "id-token: write"),
        ("permissions:\n  contents: write\n", ""),
        ("on: pull_request_target", "on: pull_request"),
        ("uses: actions/checkout@v4", "uses: actions/checkout@v7"),
        ("run: npm ci", "if: github.event_name == 'push'\n        run: npm ci"),
        ("run: npm ci", "if: inputs.run\n        run: npm ci"),
        ("run: npm ci", "run: echo setup\n      - run: npm ci"),
    ],
)
def test_unsupported_or_incompatible_paths_do_not_gain_a_witness(tmp_path, rules, old, new):
    _, findings = scan(tmp_path, rules, BASE.replace(old, new))
    assert not [f for f in findings if f._checkout_build is not None]
    # A downstream Git command may still seed the preexisting broad candidate.
    assert all("checkout-build-path-evidenced" not in f.context_tags for f in chain(findings))


def test_block_scalar_comments_and_default_persistence_are_supported(tmp_path, rules):
    content = BASE.replace("          persist-credentials: true\n", "").replace(
        "run: npm ci", "run: |\n          # build the configured checkout\n          npm ci"
    )
    _, findings = scan(tmp_path, rules, content)
    (finding,) = chain(findings)
    assert "candidate (line 8)" in finding.snippet
    assert "`npm ci` at line 14" in finding.snippet


def test_current_content_and_owners_are_required_not_tags_or_old_witnesses(tmp_path, rules):
    path, findings = scan(tmp_path, rules)
    lotp = next(f for f in findings if f.rule_id == "LOTP-GH-001")
    assert lotp._checkout_build is not None
    corpus = build_corpus(str(tmp_path))

    def composed(finding, source=corpus):
        return [
            f
            for f in run_composer(source, [finding], COMPOSER_RULES)
            if f.chain_id == "CHAIN-GH-101"
        ]

    assert len(composed(lotp)) == 1
    assert composed(replace(lotp, _checkout_build=None)) == []  # tags/prose are insufficient
    assert composed(replace(lotp, file="other.yml")) == []
    assert composed(replace(lotp, line=8)) == []
    assert composed(replace(lotp, origin="platform")) == []
    assert composed(replace(lotp, rule_id="SEC4-GH-005B")) == []
    bad = replace(lotp._checkout_build, job="other")
    assert composed(replace(lotp, _checkout_build=bad)) == []
    path.write_text(BASE.replace("npm ci", "npm ci --ignore-scripts"), encoding="utf-8")
    assert composed(lotp, build_corpus(str(tmp_path))) == []
    calibrate_lotp_authority([lotp], BASE.replace("contents: write", "contents: read"))
    assert lotp._checkout_build is None  # recalibration clears stale state


def test_cross_job_checkout_build_and_permission_do_not_form_a_path(tmp_path, rules):
    content = BASE.replace(
        "      - run: npm ci",
        "  other:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci",
    )
    _, findings = scan(tmp_path, rules, content)
    assert not [f for f in findings if f._checkout_build is not None]
    assert chain(findings) == []


def test_reports_keep_static_evidence_and_unknowns_without_internal_objects(tmp_path, rules):
    _, findings = scan(tmp_path, rules)
    (finding,) = chain(findings)
    report = AuditReport(str(tmp_path), "github", findings=[finding], files_scanned=1)
    payload = json.loads(format_json(report))
    encoded = payload["findings"][0]
    assert encoded["review_needed"]
    assert "runtime-execution-unverified" in encoded["context_tags"]
    assert "_checkout_build" not in encoded
    assert payload["distinct_risk_count"] == 0
    sarif = json.loads(format_sarif(report))
    result = sarif["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 8
    assert result["properties"]["review_needed"]
