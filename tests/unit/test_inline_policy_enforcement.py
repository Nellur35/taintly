"""Authored enforcement contracts, separate from field accuracy evidence."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import taintly
from taintly.engine import scan_file
from taintly.models import IncompletePatternMatches, Platform, RegexPattern, Rule, Severity
from taintly.rules.registry import load_rules_for_platform
from taintly.suppressions import zizmor_compat

SOURCE_ROOT = Path(taintly.__file__).resolve().parents[1]
WORKFLOW = (
    "on: workflow_dispatch\n"
    "permissions: {contents: read}\n"
    "jobs:\n"
    "  check:\n"
    "    runs-on: ubuntu-latest\n"
    "    timeout-minutes: 10\n"
    "    steps:\n"
    "      - uses: example/action@main # taintly: ignore[SEC3-GH-002]\n"
)


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    workflow = target / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(WORKFLOW, encoding="utf-8")
    (target / ".taintly.yml").write_text("version: 1\nignore:\n  - SEC3-GH-002\n", encoding="utf-8")
    return target


def _cli(target: Path, policy: Path, *flags: str):
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "taintly",
            str(target),
            "--platform",
            "github",
            "--config",
            str(policy),
            "--min-severity",
            "HIGH",
            "--fail-on",
            "HIGH",
            "--format",
            "json",
            "--no-color",
            *flags,
        ],
        cwd=SOURCE_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_trusted_config_and_inline_control_are_independent(tmp_path):
    target = _target(tmp_path)
    policy = tmp_path / "trusted-policy.yml"
    policy.write_text("version: 1\n", encoding="utf-8")
    before = _cli(target, policy)
    assert before.returncode == 0, before.stderr
    assert not json.loads(before.stdout)["findings"]

    result = _cli(target, policy, "--no-inline-suppressions")
    assert result.returncode > 0, result.stderr
    findings = json.loads(result.stdout)["findings"]
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SEC3-GH-002", 8)]

    # The flag is not a replacement for choosing a trusted config.
    target_policy = _cli(target, target / ".taintly.yml", "--no-inline-suppressions")
    assert target_policy.returncode == 0, target_policy.stderr
    assert not json.loads(target_policy.stdout)["findings"]


def test_trusted_config_can_still_make_a_scoped_exception(tmp_path):
    target = _target(tmp_path)
    policy = tmp_path / "trusted-policy.yml"
    policy.write_text(
        "version: 1\nignore:\n  - id: SEC3-GH-002\n"
        "    path: .github/workflows/ci.yml\n    reason: reviewed exception\n",
        encoding="utf-8",
    )
    result = _cli(target, policy, "--no-inline-suppressions")
    assert result.returncode == 0, result.stderr
    assert not json.loads(result.stdout)["findings"]


@pytest.mark.parametrize("disable_first", [False, True])
def test_cli_disabling_inline_waivers_dominates_foreign_opt_in(tmp_path, disable_first):
    target = _target(tmp_path)
    workflow = target / ".github/workflows/ci.yml"
    workflow.write_text(
        WORKFLOW.replace("taintly: ignore[SEC3-GH-002]", "zizmor: ignore[unpinned-uses]"),
        encoding="utf-8",
    )
    policy = tmp_path / "trusted-policy.yml"
    policy.write_text("version: 1\n", encoding="utf-8")
    flags = ["--respect-zizmor-ignores", "--no-inline-suppressions"]
    if disable_first:
        flags.reverse()
    result = _cli(target, policy, *flags)
    assert result.returncode > 0, result.stderr
    assert any(f["rule_id"] == "SEC3-GH-002" for f in json.loads(result.stdout)["findings"])


@pytest.mark.parametrize("invalid", [False, True], ids=["missing", "invalid"])
def test_explicit_policy_failure_does_not_fall_back_to_target(tmp_path, invalid):
    target = _target(tmp_path)
    policy = tmp_path / "trusted-policy.yml"
    if invalid:
        policy.write_text("version: 999\n", encoding="utf-8")
    result = _cli(target, policy, "--no-inline-suppressions")
    assert result.returncode == 3, result.stderr
    assert "Config error" in result.stderr


def _rule(platform, pattern):
    return Rule(
        id="POLICY-TEST-001",
        title="Authored policy contract",
        severity=Severity.HIGH,
        platform=platform,
        owasp_cicd="CICD-SEC-3",
        description="Authored contract.",
        pattern=pattern,
        remediation="Review the selected input.",
        reference="",
    )


@pytest.mark.parametrize("platform", list(Platform))
def test_inline_policy_is_per_call_and_shared_across_platforms(tmp_path, platform):
    source = "echo unsafe # taintly: ignore[POLICY-TEST-001]\n"
    rule = _rule(platform, RegexPattern(r"unsafe"))
    path = str(tmp_path / "Jenkinsfile")
    assert not scan_file(path, [rule], _content=source)
    assert [
        f.rule_id
        for f in scan_file(path, [rule], _content=source, respect_inline_suppressions=False)
    ] == [rule.id]
    assert not scan_file(path, [rule], _content=source)


def test_no_inline_policy_preserves_incomplete_diagnostics(tmp_path):
    class PartialPattern:
        def check(self, content, lines):
            return IncompletePatternMatches([(1, lines[0])], reason="authored coverage gap")

    rule = _rule(Platform.GITHUB, PartialPattern())
    source = "unsafe # taintly: ignore\n"
    for policy in (True, False):
        result = scan_file(
            str(tmp_path / "workflow.yml"),
            [rule],
            _content=source,
            respect_inline_suppressions=policy,
        )
        assert any(f.rule_id == "ENGINE-ERR" for f in result)
        assert any(f.rule_id == rule.id for f in result) is (not policy)


@pytest.mark.parametrize("marker", ["ignore", "ignore[unpinned-uses]"])
def test_disable_overrides_foreign_inline_waivers_without_mutating_their_state(tmp_path, marker):
    rules = [r for r in load_rules_for_platform(Platform.GITHUB) if r.id == "SEC3-GH-002"]
    source = WORKFLOW.replace("taintly: ignore[SEC3-GH-002]", f"zizmor: {marker}")
    prior = zizmor_compat.is_respect_zizmor_ignores_enabled()
    zizmor_compat.set_respect_zizmor_ignores(True)
    try:
        assert not scan_file(str(tmp_path / "workflow.yml"), rules, _content=source)
        assert any(
            f.rule_id == "SEC3-GH-002"
            for f in scan_file(
                str(tmp_path / "workflow.yml"),
                rules,
                _content=source,
                respect_inline_suppressions=False,
            )
        )
        assert zizmor_compat.is_respect_zizmor_ignores_enabled()
        assert not scan_file(str(tmp_path / "workflow.yml"), rules, _content=source)
    finally:
        zizmor_compat.set_respect_zizmor_ignores(prior)
