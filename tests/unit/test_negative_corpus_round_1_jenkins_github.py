"""Round-1 negative-corpus harvest for Jenkins and GitHub.

These fixtures are small, sanitized snippets extracted from public CI files.
They protect the platform-specific bug classes that normal rule-local samples
missed: Jenkins discovery/comment/segmentation edges and GitHub cache/checkout
safe posture.
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

GITHUB_CACHE_CREDENTIAL_FAMILY = {
    "CHAIN-GH-101",
    "SEC4-GH-005",
    "SEC4-GH-026",
    "SEC9-GH-005",
    "XF-GH-001",
}


def _ids(path: Path, rules) -> set[str]:
    return {finding.rule_id for finding in scan_file(str(path), rules)}


def test_jenkins_negative_corpus_discovery_keeps_real_files_and_skips_docs():
    root = FIXTURES / "jenkins" / "negative_corpus" / "discovery"

    files = discover_files(str(root), Platform.JENKINS)
    rel = {os.path.relpath(path, root) for path in files}

    assert os.path.join(".jenkins", "Jenkinsfile") in rel
    assert os.path.join("k8s", "Jenkinsfile_k8s") in rel
    assert os.path.join("docs", "jenkinsfile.adoc") not in rel
    assert os.path.join("docs", "Jenkinsfile.txt") not in rel


def test_jenkins_negative_corpus_safe_lotp_idioms_do_not_fire_supply_chain_family(
    jenkins_rules,
):
    root = FIXTURES / "jenkins" / "negative_corpus" / "safe_lotp"

    for fixture in root.glob("*.Jenkinsfile"):
        fired = _ids(fixture, jenkins_rules)
        unexpected = fired & JENKINS_SUPPLY_CHAIN_FAMILY
        assert not unexpected, f"{fixture.name} fired {sorted(unexpected)}"


def test_jenkins_negative_corpus_positive_anchor_still_fires_supply_chain_family(
    jenkins_rules,
):
    fixtures = [
        FIXTURES / "jenkins" / "vulnerable" / "curl_pipe_bash.Jenkinsfile",
        FIXTURES / "jenkins" / "vulnerable" / "sec9_jk_004_curl_pipe_interpreter.Jenkinsfile",
    ]

    for fixture in fixtures:
        assert _ids(fixture, jenkins_rules) & JENKINS_SUPPLY_CHAIN_FAMILY


def test_github_negative_corpus_safe_cache_and_checkout_do_not_fire_high_blast_family(
    github_rules,
):
    fixture = FIXTURES / "github" / "negative_corpus" / "safe_cache_checkout.yml"

    fired = _ids(fixture, github_rules)

    assert not (fired & GITHUB_CACHE_CREDENTIAL_FAMILY)


def test_github_negative_corpus_cache_poison_positive_anchor_still_fires(github_rules):
    fixture = FIXTURES / "github" / "negative_corpus" / "positive_cache_poison.yml"

    fired = _ids(fixture, github_rules)

    assert {"SEC4-GH-026", "SEC9-GH-005"} <= fired
