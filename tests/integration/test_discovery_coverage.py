"""Discovery & coverage gate — the layer the rest of the suite never tests.

self_test / mutation run ``rule.pattern.check`` in isolation; the other
integration tests scan a single hand-placed file.  NONE exercises the
discovery -> platform-detection -> scoping -> discovery-confidence path that
decides *what actually gets scanned* and *whether a finding survives to the
user*.  A regression there fails silently: files simply aren't scanned (so the
repo reads "clean"), or real findings are demoted to review-needed — and every
existing test stays green.

This module is the missing oracle.  It locks:
  * the files-scanned count against an independent file-count,
  * the two documented discovery bugs that currently have no regression test
    (CORPUS-JK-001 GH+JK coexistence; hidden ``.jenkins``/``.ci`` dirs),
  * vendor-dir pruning (so a prune-list change can't start eating real files),
  * the discovery-confidence demotion machinery (so a change can't silently
    demote canonical-location findings to review-needed).
"""

from __future__ import annotations

import os

from taintly.engine import (
    _apply_discovery_confidence,
    _discovery_confidence,
    detect_platform,
    discover_files,
    scan_repo,
)
from taintly.models import Finding, Platform, Severity
from taintly.rules.registry import load_all_rules

_PIPELINE = "pipeline {\n  agent any\n  stages {\n    stage('s') {\n      steps {\n        sh 'echo hi'\n      }\n    }\n  }\n}\n"
_WORKFLOW = "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"


def _gh(repo, name):
    d = repo / ".github" / "workflows"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(_WORKFLOW)


# --- GitHub discovery -----------------------------------------------------


def test_github_discovers_both_yml_and_yaml(tmp_path):
    _gh(tmp_path, "a.yml")
    _gh(tmp_path, "b.yaml")
    found = discover_files(str(tmp_path), Platform.GITHUB)
    names = {f.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] for f in found}
    assert {"a.yml", "b.yaml"} <= names, f"both extensions must be discovered, got {names}"


def test_files_scanned_oracle_matches_discovery(tmp_path):
    # The report's files_scanned must equal what discovery actually returns —
    # the guard against "scanned 0 of N and reported clean".
    for n in ("a.yml", "b.yml", "c.yaml"):
        _gh(tmp_path, n)
    oracle = len(discover_files(str(tmp_path), Platform.GITHUB))
    assert oracle == 3
    reports = scan_repo(str(tmp_path), load_all_rules())
    gh = [r for r in reports if r.platform == "github"]
    assert gh, "github report missing"
    assert gh[0].files_scanned == oracle


# --- the two documented discovery bugs (regression locks) -----------------


def test_github_and_jenkins_coexist_both_scanned(tmp_path):
    # CORPUS-JK-001: a repo with BOTH .github/workflows/ and a Jenkinsfile
    # must scan BOTH platforms.  detect_platform returns None on multi-signal
    # so scan_repo probes all three.  A regression here silently drops one.
    _gh(tmp_path, "wf.yml")
    (tmp_path / "Jenkinsfile").write_text(_PIPELINE)
    assert detect_platform(str(tmp_path)) is None  # multi-signal -> probe-all
    reports = scan_repo(str(tmp_path), load_all_rules())
    platforms = {r.platform for r in reports if r.files_scanned > 0}
    assert {"github", "jenkins"} <= platforms, f"both must be scanned, got {platforms}"


def test_jenkins_hidden_dirs_are_discovered(tmp_path):
    # apache/cassandra-class layout: Jenkinsfiles under dot-prefixed dirs that
    # the old recursive glob skipped entirely.
    (tmp_path / ".jenkins").mkdir()
    (tmp_path / ".jenkins" / "Jenkinsfile").write_text(_PIPELINE)
    (tmp_path / ".ci").mkdir()
    (tmp_path / ".ci" / "Jenkinsfile").write_text(_PIPELINE)
    found = {f.replace("\\", "/") for f in discover_files(str(tmp_path), Platform.JENKINS)}
    assert any("/.jenkins/Jenkinsfile" in f for f in found)
    assert any("/.ci/Jenkinsfile" in f for f in found)


# --- pruning correctness --------------------------------------------------


def test_jenkins_discovery_prunes_vendor_dirs_but_keeps_real(tmp_path):
    (tmp_path / "Jenkinsfile").write_text(_PIPELINE)
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "Jenkinsfile").write_text(_PIPELINE)
    found = {f.replace("\\", "/") for f in discover_files(str(tmp_path), Platform.JENKINS)}
    assert any(f.endswith("/Jenkinsfile") and "node_modules" not in f for f in found)
    assert not any("node_modules" in f for f in found), "vendor dir must be pruned"


# --- GitLab discovery -----------------------------------------------------


def test_gitlab_ci_file_discovered(tmp_path):
    (tmp_path / ".gitlab-ci.yml").write_text("stages: [build]\nbuild:\n  script: echo hi\n")
    found = discover_files(str(tmp_path), Platform.GITLAB)
    assert any(f.endswith(".gitlab-ci.yml") for f in found)


# --- discovery-confidence tiers + demotion machinery ----------------------


def test_discovery_confidence_tiers(tmp_path):
    # Jenkinsfile name = authoritative (high); a .groovy admitted only by the
    # jenkins-dir path heuristic = weak (low).
    (tmp_path / "Jenkinsfile").write_text(_PIPELINE)
    (tmp_path / "jenkins").mkdir()
    (tmp_path / "jenkins" / "deploy.groovy").write_text(_PIPELINE)
    files = discover_files(str(tmp_path), Platform.JENKINS)
    conf = _discovery_confidence(str(tmp_path), Platform.JENKINS, files)
    tiers = {k.replace("\\", "/").rsplit("/", 1)[-1]: v for k, v in conf.items()}
    assert tiers.get("Jenkinsfile") == "high"
    assert tiers.get("deploy.groovy") == "low"


def _finding(path):
    return Finding(rule_id="X", severity=Severity.HIGH, title="t", description="d", file=path)


def test_demotion_caps_low_confidence_only(tmp_path):
    # The machinery must demote LOW-confidence findings to review_needed and
    # leave HIGH (canonical-location) findings untouched.  A regression that
    # demotes a high-confidence finding would silently bury a real result.
    high = _finding("Jenkinsfile")
    low = _finding("jenkins/deploy.groovy")
    unmapped = _finding("somewhere/else.yml")  # not in map -> defaults high
    # keys normalized the way _apply_discovery_confidence looks them up
    conf_map = {
        os.path.normpath(k): v
        for k, v in {"Jenkinsfile": "high", "jenkins/deploy.groovy": "low"}.items()
    }
    _apply_discovery_confidence([high, low, unmapped], conf_map)
    assert high.review_needed is False, "canonical-location finding must NOT be demoted"
    assert low.review_needed is True, "weak-heuristic finding must be review-flagged"
    assert unmapped.review_needed is False, "unmapped finding must default to high (not buried)"
