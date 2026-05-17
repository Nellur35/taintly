"""Integration tests for the CHAIN-GL-* composer rules.

GitLabCorpusPattern rules don't fit the single-file self-test harness
(positive/negative samples are full GitLab CI repos with the entry
file plus any local includes), so they're tested here against
tmp_path repos with realistic `.gitlab-ci.yml` layouts.  Each test
asserts both the positive case (rule fires) and the relevant
single-conjunct-missing case (rule does NOT fire when one precondition
is absent).
"""

from __future__ import annotations

from pathlib import Path

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_all_rules


def _write_entry(tmp_path: Path, content: str) -> Path:
    p = tmp_path / ".gitlab-ci.yml"
    p.write_text(content)
    return p


def _chain_findings(tmp_path: Path, rule_id: str) -> list:
    rules = load_all_rules()
    reports = scan_repo(str(tmp_path), rules, Platform.GITLAB)
    return [f for r in reports for f in r.findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# CHAIN-GL-101 — MR-deploy + fork-reachable + id_tokens
# ---------------------------------------------------------------------------


_TP_CHAIN_101 = """\
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

deploy-prod:
  id_tokens:
    AWS_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - aws sts assume-role-with-web-identity --web-identity-token $AWS_TOKEN
    - docker push registry.example.com/app:$CI_COMMIT_SHA
"""


def test_chain_gl_101_fires_on_tp(tmp_path: Path) -> None:
    _write_entry(tmp_path, _TP_CHAIN_101)
    findings = _chain_findings(tmp_path, "CHAIN-GL-101")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity.value == "CRITICAL"
    assert f.origin == "cross-workflow"
    assert "docker push" in _TP_CHAIN_101.splitlines()[f.line - 1] or "deploy" in f.snippet


def test_chain_gl_101_does_not_fire_without_id_tokens(tmp_path: Path) -> None:
    # Same shape as the TP but the id_tokens block is removed —
    # the OIDC write-token precondition is absent, so the composite
    # escalation must not fire.
    content = """\
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

deploy-prod:
  script:
    - docker push registry.example.com/app:$CI_COMMIT_SHA
"""
    _write_entry(tmp_path, content)
    assert _chain_findings(tmp_path, "CHAIN-GL-101") == []


def test_chain_gl_101_does_not_fire_when_protected_branch_gated(tmp_path: Path) -> None:
    # id_tokens + deploy command present BUT the workflow is gated to
    # protected branches — the fork-attacker primitive is severed.
    content = """\
workflow:
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

deploy-prod:
  id_tokens:
    AWS_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - docker push registry.example.com/app:$CI_COMMIT_SHA
"""
    _write_entry(tmp_path, content)
    assert _chain_findings(tmp_path, "CHAIN-GL-101") == []


# ---------------------------------------------------------------------------
# CHAIN-GL-102 — unpinned project include + fork-reachable trigger
# ---------------------------------------------------------------------------


def test_chain_gl_102_fires_when_unpinned_include_and_fork_trigger(tmp_path: Path) -> None:
    content = """\
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

include:
  - project: 'my-group/ci-templates'
    file: '/templates/build.yml'
    ref: main

build:
  script:
    - make
"""
    _write_entry(tmp_path, content)
    findings = _chain_findings(tmp_path, "CHAIN-GL-102")
    assert len(findings) == 1
    assert findings[0].severity.value == "HIGH"
    assert "ci-templates" in findings[0].snippet


def test_chain_gl_102_does_not_fire_when_include_pinned_to_sha(tmp_path: Path) -> None:
    content = """\
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

include:
  - project: 'my-group/ci-templates'
    file: '/templates/build.yml'
    ref: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
"""
    _write_entry(tmp_path, content)
    assert _chain_findings(tmp_path, "CHAIN-GL-102") == []


def test_chain_gl_102_does_not_fire_when_no_fork_trigger(tmp_path: Path) -> None:
    content = """\
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "push"

include:
  - project: 'my-group/ci-templates'
    file: '/templates/build.yml'
    ref: main
"""
    _write_entry(tmp_path, content)
    assert _chain_findings(tmp_path, "CHAIN-GL-102") == []


# ---------------------------------------------------------------------------
# CHAIN-GL-103 — tainted-variable laundering + fork-reachable + id_tokens
# ---------------------------------------------------------------------------


_TP_CHAIN_103 = """\
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

variables:
  PR_TITLE: $CI_MERGE_REQUEST_TITLE

build:
  id_tokens:
    AWS_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - echo $PR_TITLE
    - aws sts assume-role-with-web-identity
"""


def test_chain_gl_103_fires_on_tp(tmp_path: Path) -> None:
    _write_entry(tmp_path, _TP_CHAIN_103)
    findings = _chain_findings(tmp_path, "CHAIN-GL-103")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity.value == "HIGH"
    assert "id_tokens" in f.snippet


def test_chain_gl_103_does_not_fire_without_id_tokens(tmp_path: Path) -> None:
    content = """\
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

variables:
  PR_TITLE: $CI_MERGE_REQUEST_TITLE

build:
  script:
    - echo $PR_TITLE
"""
    _write_entry(tmp_path, content)
    assert _chain_findings(tmp_path, "CHAIN-GL-103") == []


def test_chain_gl_103_does_not_fire_when_var_quoted(tmp_path: Path) -> None:
    # Tainted variable assigned but referenced only inside double-quotes —
    # no unquoted script reference, so the conjunct is absent.
    content = """\
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

variables:
  PR_TITLE: $CI_MERGE_REQUEST_TITLE

build:
  id_tokens:
    AWS_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - echo "${PR_TITLE}"
"""
    _write_entry(tmp_path, content)
    assert _chain_findings(tmp_path, "CHAIN-GL-103") == []
