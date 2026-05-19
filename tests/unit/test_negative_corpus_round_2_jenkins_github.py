"""Round-2 negative-corpus harvest for Jenkins and GitHub posture.

Small fixtures are sanitized from public CI files.  They protect
family-level behavior rather than one rule at a time.
"""

from __future__ import annotations

import os
from pathlib import Path

from taintly.engine import discover_files, scan_file
from taintly.models import Platform

FIXTURES = Path(__file__).parent.parent / "fixtures"

JENKINS_SUPPLY_CHAIN_FAMILY = {
    "LOTP-JK-001",
    "LOTP-JK-003",
    "LOTP-JK-005",
    "SEC9-JK-001",
    "SEC9-JK-003",
    "SEC9-JK-004",
}

GITHUB_CACHE_WRITE_FAMILY = {"SEC4-GH-026", "SEC9-GH-005", "XF-GH-001", "XF-GH-001A"}
GITHUB_CREDENTIAL_FAMILY = {"SEC4-GH-005", "CHAIN-GH-101"}


def _ids(path: Path, rules) -> set[str]:
    return {finding.rule_id for finding in scan_file(str(path), rules)}


def test_jenkins_round2_discovery_keeps_variants_and_skips_markdown_docs():
    root = FIXTURES / "jenkins" / "negative_corpus" / "discovery"

    files = discover_files(str(root), Platform.JENKINS)
    rel = {os.path.relpath(path, root) for path in files}

    assert os.path.join("release", "Jenkinsfile-prod") in rel
    assert os.path.join("library", "release.jenkinsfile") in rel
    assert os.path.join("docs", "Jenkinsfile.md") not in rel


def test_jenkins_round2_safe_multiline_shell_idioms_do_not_fire_supply_chain_family(
    jenkins_rules,
):
    root = FIXTURES / "jenkins" / "negative_corpus" / "safe_lotp"

    for fixture in root.glob("*.Jenkinsfile"):
        fired = _ids(fixture, jenkins_rules)
        unexpected = fired & JENKINS_SUPPLY_CHAIN_FAMILY
        assert not unexpected, f"{fixture.name} fired {sorted(unexpected)}"


def test_jenkins_round2_positive_sec9_family_anchor_still_fires(jenkins_rules):
    fixture = FIXTURES / "jenkins" / "vulnerable" / "sec9_jk_004_curl_pipe_interpreter.Jenkinsfile"

    assert _ids(fixture, jenkins_rules) & {"SEC9-JK-001", "SEC9-JK-003", "SEC9-JK-004"}


def test_github_round2_prt_restore_only_does_not_fire_cache_write_family(github_rules):
    fixture = FIXTURES / "github" / "negative_corpus" / "safe_prt_cache_restore_only.yml"

    fired = _ids(fixture, github_rules)

    assert not (fired & GITHUB_CACHE_WRITE_FAMILY)
    assert not (fired & GITHUB_CREDENTIAL_FAMILY)


def test_github_round2_push_restore_save_hashfiles_does_not_fire_cache_posture_family(
    github_rules,
):
    fixture = FIXTURES / "github" / "negative_corpus" / "safe_push_cache_restore_save_hashfiles.yml"

    fired = _ids(fixture, github_rules)

    assert "SEC9-GH-005" not in fired
    assert not (fired & GITHUB_CACHE_WRITE_FAMILY)
    assert not (fired & GITHUB_CREDENTIAL_FAMILY)


def test_github_round2_prt_cache_save_attacker_key_still_fires(github_rules):
    fixture = FIXTURES / "github" / "negative_corpus" / "positive_prt_cache_save_head_ref.yml"

    fired = _ids(fixture, github_rules)

    assert "SEC4-GH-026" in fired
    assert "SEC9-GH-005" in fired


def test_github_round2_missing_permissions_semantics_remain_pinned(github_rules):
    positive = FIXTURES / "github" / "negative_corpus" / "positive_missing_permissions_job_level.yml"
    safe = FIXTURES / "github" / "negative_corpus" / "safe_top_level_permissions.yml"

    assert "SEC2-GH-002" not in _ids(positive, github_rules)
    assert "SEC2-GH-002" not in _ids(safe, github_rules)
