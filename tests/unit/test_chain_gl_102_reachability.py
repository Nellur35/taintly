"""Root-scoped MR evidence must not become a confirmed include execution chain."""

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_all_rules


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
