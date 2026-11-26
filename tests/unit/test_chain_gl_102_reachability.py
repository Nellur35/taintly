"""Root-scoped MR evidence must not become a confirmed include execution chain."""

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.parsers.structural import EventKind, walk_workflow
from taintly.rules.registry import load_all_rules
from taintly.testing.self_test import _mutation_applicable


INCLUDE = """include:
  - project: org/templates
    file: build.yml
    ref: main
"""


def scan(tmp_path: Path, content: str):
    (tmp_path / ".gitlab-ci.yml").write_text(content, encoding="utf-8")
    return [f for r in scan_repo(str(tmp_path), load_all_rules(), Platform.GITLAB) for f in r.findings]


@pytest.mark.parametrize("rules", [
    '- if: \'$CI_PIPELINE_SOURCE == "merge_request_event"\'\n      when: never\n    - when: always',
    '- if: \'$CI_PIPELINE_SOURCE == "push"\'',
    '- if: \'$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\'\n    - when: never',
    '- when: never\n    - if: \'$CI_PIPELINE_SOURCE == "merge_request_event"\'',
])
def test_root_workflow_denial_keeps_only_include_posture(tmp_path: Path, rules: str):
    findings = scan(tmp_path, INCLUDE + "workflow:\n  rules:\n    " + rules + "\nbuild:\n  script: make\n")
    assert not [f for f in findings if f.rule_id == "CHAIN-GL-102"]
    assert [f for f in findings if f.rule_id == "SEC3-GL-002"]


@pytest.mark.parametrize("extra", [
    "build:\n  script: make\n",
    '# $CI_PIPELINE_SOURCE == "merge_request_event"\nbuild:\n  script: make\n',
    'build:\n  script: echo \'$CI_PIPELINE_SOURCE == "merge_request_event"\'\n',
    'workflow:\n  rules:\n    - if: \'$CUSTOM_ENABLE && $CI_PIPELINE_SOURCE == "merge_request_event"\'\n',
])
def test_unknown_is_review_candidate_not_proven_fork(tmp_path: Path, extra: str):
    findings = [f for f in scan(tmp_path, INCLUDE + extra) if f.rule_id == "CHAIN-GL-102"]
    assert len(findings) == 1
    assert findings[0].review_needed is True
    assert "unknown" in findings[0].snippet.lower()
    assert "parent" in findings[0].snippet.lower()
    assert "runs in the next MR pipeline" not in findings[0].snippet


def test_explicit_root_mr_still_warns_without_claiming_parent_secrets(tmp_path: Path):
    findings = [f for f in scan(tmp_path, INCLUDE + 'workflow:\n  rules:\n    - if: \'$CI_PIPELINE_SOURCE == "merge_request_event"\'\n') if f.rule_id == "CHAIN-GL-102"]
    assert len(findings) == 1
    assert findings[0].review_needed is True
    assert "root" in findings[0].snippet.lower()
    assert "include body" in findings[0].snippet.lower()


def test_included_trigger_is_not_root_mr_evidence(tmp_path: Path):
    (tmp_path / "child.yml").write_text('child:\n  rules:\n    - if: \'$CI_PIPELINE_SOURCE == "merge_request_event"\'\n  script: make\n', encoding="utf-8")
    findings = scan(tmp_path, INCLUDE.replace("include:\n", "include:\n  - local: child.yml\n") + "build:\n  script: make\n")
    candidate = next(f for f in findings if f.rule_id == "CHAIN-GL-102")
    assert candidate.review_needed is True
    assert "unknown" in candidate.snippet.lower()


@pytest.mark.parametrize("policy", [
    "workflow:\n  rules:\n    - if: null\n    - when: never\n",
    'build:\n  rules:\n    - if: \'$CI_PIPELINE_SOURCE == "merge_request_event"\'\n  script: make\nbuild:\n  script: make\n',
    'workflow:\n  rules:\n    - if: \'$CUSTOM\'\n    - if: \'$CI_PIPELINE_SOURCE == "merge_request_event"\'\n      when: never\n',
    'workflow:\n  rules:\n    - if: \'$CI_PIPELINE_SOURCE == "merge_request_event"\'\n      changes: [src/**]\n      when: never\n    - when: always\n',
])
def test_consumed_verification_edges_remain_unknown(tmp_path: Path, policy: str):
    candidate = next(f for f in scan(tmp_path, INCLUDE + policy) if f.rule_id == "CHAIN-GL-102")
    assert candidate.review_needed
    assert "unknown" in candidate.snippet


def test_truncated_corpus_prefix_cannot_prove_denial(tmp_path: Path):
    content = INCLUDE + "workflow:\n  rules:\n    - when: never\n" + "# padding\n" * 7000
    content += 'workflow:\n  rules:\n    - if: \'$CI_PIPELINE_SOURCE == "merge_request_event"\'\n'
    candidate = next(f for f in scan(tmp_path, content) if f.rule_id == "CHAIN-GL-102")
    assert candidate.review_needed
    assert "unknown" in candidate.snippet


def test_external_only_pipeline_does_not_prove_native_fork_mr(tmp_path: Path):
    findings = scan(tmp_path, INCLUDE + 'workflow:\n  rules:\n    - if: \'$CI_PIPELINE_SOURCE == "external_pull_request_event"\'\n')
    assert not [f for f in findings if f.rule_id == "CHAIN-GL-102"]
    assert [f for f in findings if f.rule_id == "SEC3-GL-002"]


SHA = "a7" * 20


@pytest.mark.parametrize(
    "suffix",
    [
        f"  - project: org/pinned\n    file: /ci.yml\n    ref: {SHA}\n",
        f"    inputs:\n      ref: {SHA}\n",
        f"    # ref: {SHA}\n",
    ],
)
def test_only_include_item_ref_can_pin_both_decisions(tmp_path: Path, suffix: str):
    findings = scan(tmp_path, INCLUDE + suffix + "build:\n  script: echo check\n")
    matches = [finding for finding in findings if finding.rule_id in {"SEC3-GL-002", "CHAIN-GL-102"}]
    assert {(finding.rule_id, finding.line) for finding in matches} == {
        ("SEC3-GL-002", 2), ("CHAIN-GL-102", 2)
    }
    assert "@main" in next(finding.snippet for finding in matches if finding.rule_id == "CHAIN-GL-102")


@pytest.mark.parametrize(
    "include",
    [
        f'include: [{{"project": "org/templates", "file": "/ci.yml", "ref": "{SHA}"}}]\n',
        f"include:\n  - project: org/templates\n    file: /ci.yml\n    ref: {SHA}\n",
    ],
)
def test_literal_owning_commit_excludes_mutable_include(tmp_path: Path, include: str):
    findings = scan(tmp_path, include + "build:\n  script: echo check\n")
    assert not any(finding.rule_id in {"SEC3-GL-002", "CHAIN-GL-102", "ENGINE-ERR"} for finding in findings)


@pytest.mark.parametrize("ref", ["$SELECTED_REVISION", "[main]", "null", "main\n    ref: " + SHA])
def test_unresolved_ref_keeps_other_include_decision(tmp_path: Path, ref: str):
    content = INCLUDE + f"  - project: org/unknown\n    file: /ci.yml\n    ref: {ref}\n"
    findings = scan(tmp_path, content + "build:\n  script: echo check\n")
    matches = [finding for finding in findings if finding.rule_id in {"SEC3-GL-002", "CHAIN-GL-102"}]
    assert {(finding.rule_id, finding.line) for finding in matches} == {
        ("SEC3-GL-002", 2), ("CHAIN-GL-102", 2)
    }
    assert any(
        f.rule_id == "ENGINE-ERR" and "project include revision could not be resolved" in f.description
        for f in findings
    )


def test_yaml_whitespace_mutation_preserves_required_mapping():
    rule = next(rule for rule in load_all_rules() if rule.id == "SEC3-GL-002")
    removed = INCLUDE.replace(": ", ":")
    padded = INCLUDE.replace(": ", ":  ")
    owner = ("include", 0, "project")
    for source in (INCLUDE, padded):
        assert any(
            e.kind is EventKind.LEAF_SCALAR and e.path == owner
            for e in walk_workflow(".gitlab-ci.yml", content=source)
        )
        assert rule.pattern.check(source, source.splitlines())
    assert not any(
        e.kind is EventKind.LEAF_SCALAR and e.path == owner
        for e in walk_workflow(".gitlab-ci.yml", content=removed)
    )
    assert not _mutation_applicable(rule, INCLUDE, removed, "whitespace_pad")
    assert _mutation_applicable(rule, INCLUDE, padded, "whitespace_pad")
