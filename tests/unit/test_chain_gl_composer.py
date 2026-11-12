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

import pytest

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
# CHAIN-GL-101 — source-owned MR publication and credential context
# ---------------------------------------------------------------------------


_TP_CHAIN_101 = """\
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

deploy-prod:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
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
    assert f.severity.value == "HIGH"
    assert f.review_needed
    assert f.origin == "cross-workflow"
    assert "docker push" in _TP_CHAIN_101.splitlines()[f.line - 1]
    assert any(
        "AWS_TOKEN" in note and "write grants are unverified" in note for note in f.context_notes
    )


def test_chain_gl_101_does_not_fire_without_id_tokens(tmp_path: Path) -> None:
    # Native MR publication without a supported credential relation.
    content = """\
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

deploy-prod:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
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
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  id_tokens:
    AWS_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - docker push registry.example.com/app:$CI_COMMIT_SHA
"""
    _write_entry(tmp_path, content)
    assert _chain_findings(tmp_path, "CHAIN-GL-101") == []


def test_chain_gl_101_does_not_borrow_sibling_oidc(tmp_path: Path) -> None:
    content = (
        _TP_CHAIN_101.replace(
            "  id_tokens:\n    AWS_TOKEN:\n      aud: https://sts.amazonaws.com\n", ""
        )
        + "\nsibling:\n  id_tokens:\n    SIGNING_TOKEN:\n      aud: sigstore\n  script: echo ok\n"
    )
    _write_entry(tmp_path, content)
    assert _chain_findings(tmp_path, "CHAIN-GL-101") == []


@pytest.mark.parametrize(
    "replacement",
    [
        '    - echo "docker push image"',
        "    - docker push --help",
        "    - |\n      cat <<EOF\n      docker push image\n      EOF",
    ],
)
def test_chain_gl_101_requires_a_supported_publication_command(
    tmp_path: Path, replacement: str
) -> None:
    _write_entry(
        tmp_path,
        _TP_CHAIN_101.replace(
            "    - docker push registry.example.com/app:$CI_COMMIT_SHA", replacement
        ),
    )
    assert _chain_findings(tmp_path, "CHAIN-GL-101") == []


def test_chain_gl_101_uses_workflow_admission_with_own_job_rules(tmp_path: Path) -> None:
    _write_entry(
        tmp_path,
        _TP_CHAIN_101.replace(
            'deploy-prod:\n  rules:\n    - if: $CI_PIPELINE_SOURCE == "merge_request_event"',
            "deploy-prod:\n  rules:\n    - when: always",
        ),
    )
    (finding,) = _chain_findings(tmp_path, "CHAIN-GL-101")
    assert "event rule at line 3" in finding.context_notes[0]


@pytest.mark.parametrize(
    "job_rules",
    [
        "",
        '  rules:\n    - if: $CI_PIPELINE_SOURCE == "merge_request_event"\n      when: never\n    - when: always\n',
        "  rules:\n    - if: $COMMENT == 'text $CI_PIPELINE_SOURCE == \"merge_request_event\"'\n",
    ],
)
def test_chain_gl_101_requires_owned_mr_admission(tmp_path: Path, job_rules: str) -> None:
    _write_entry(
        tmp_path,
        _TP_CHAIN_101[_TP_CHAIN_101.index("deploy-prod:") :].replace(
            'deploy-prod:\n  rules:\n    - if: $CI_PIPELINE_SOURCE == "merge_request_event"\n',
            "deploy-prod:\n" + job_rules,
        ),
    )
    assert _chain_findings(tmp_path, "CHAIN-GL-101") == []


def test_chain_gl_101_signing_audience_is_only_a_declaration(tmp_path: Path) -> None:
    _write_entry(
        tmp_path,
        _TP_CHAIN_101.replace("AWS_TOKEN", "SIGNING_TOKEN")
        .replace("https://sts.amazonaws.com", "sigstore")
        .replace(
            "    - aws sts assume-role-with-web-identity --web-identity-token $SIGNING_TOKEN\n", ""
        ),
    )
    (finding,) = _chain_findings(tmp_path, "CHAIN-GL-101")
    assert finding.review_needed and finding.severity.value == "HIGH"
    assert any(
        "SIGNING_TOKEN" in note and "write grants are unverified" in note
        for note in finding.context_notes
    )


_MR_IMAGE_PUBLISH = """\
.skip-schedules:
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule" && $SOLO != ""
      when: never

preview:
  rules:
    - !reference [.skip-schedules, rules]
    - if: $CI_PIPELINE_SOURCE == "merge_request_event" || $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      changes: [preview/Containerfile]
  script:
    - echo "$CI_REGISTRY_PASSWORD" | docker login -u "$CI_REGISTRY_USER" --password-stdin "$CI_REGISTRY"
    - TAG=$(sha256sum preview/Containerfile | cut -c1-8)
    - IMAGE="${CI_REGISTRY_IMAGE}/preview"
    - docker build -t "${IMAGE}:${TAG}" -f preview/Containerfile preview
    - docker push "${IMAGE}:${TAG}"
"""


def test_chain_gl_101_registry_publication_without_oidc(tmp_path: Path) -> None:
    _write_entry(tmp_path, _MR_IMAGE_PUBLISH)
    (finding,) = _chain_findings(tmp_path, "CHAIN-GL-101")
    assert finding.review_needed
    assert "docker push" in _MR_IMAGE_PUBLISH.splitlines()[finding.line - 1]
    evidence = " ".join(finding.context_notes)
    assert "CI_REGISTRY_PASSWORD" in evidence and "preview/Containerfile" in evidence
    assert "Actual checkout, granted access" in evidence
    assert "OIDC declarations" not in evidence


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        (
            '"merge_request_event" || $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH',
            '"push" && $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH',
        ),
        (".skip-schedules, rules", ".missing, rules"),
        ("CI_REGISTRY_PASSWORD", "OTHER_PASSWORD"),
        ("-f preview/Containerfile preview", "-f other/Containerfile preview"),
        ("preview:\n  rules:", "preview:\n  variables: {CI_REGISTRY_IMAGE: other/image}\n  rules:"),
    ],
)
def test_chain_gl_101_does_not_infer_registry_relationship(
    tmp_path: Path, original: str, replacement: str
) -> None:
    assert original in _MR_IMAGE_PUBLISH
    _write_entry(tmp_path, _MR_IMAGE_PUBLISH.replace(original, replacement))
    assert _chain_findings(tmp_path, "CHAIN-GL-101") == []


def test_chain_gl_101_requires_oidc_on_the_deploy_job(tmp_path: Path) -> None:
    """A scheduled OIDC sibling does not empower the MR deploy job."""
    content = """\
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

deploy-prod:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - docker push registry.example.com/app:$CI_COMMIT_SHA

scheduled-oidc:
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
  id_tokens:
    AWS_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - echo maintenance
"""
    _write_entry(tmp_path, content)
    assert _chain_findings(tmp_path, "CHAIN-GL-101") == []


def test_chain_gl_101_ignores_protected_or_bot_gates_in_sibling_jobs(tmp_path: Path) -> None:
    """A sibling's gate cannot make the exposed deploy job safe."""
    content = """\
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

deploy-prod:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  id_tokens:
    AWS_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - docker push registry.example.com/app:$CI_COMMIT_SHA

protected-maintenance:
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  script:
    - echo maintenance

bot-maintenance:
  rules:
    - if: '$GITLAB_USER_LOGIN == "renovate-bot"'
  script:
    - echo maintenance
"""
    _write_entry(tmp_path, content)
    assert len(_chain_findings(tmp_path, "CHAIN-GL-101")) == 1


def test_chain_gl_101_does_not_treat_pipeline_source_inequality_as_mr_reachable(
    tmp_path: Path,
) -> None:
    """An expression that excludes MR pipelines cannot establish the chain."""
    content = """\
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE != "merge_request_event"

deploy-prod:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
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
    # eval is the code-reparsing sink; ordinary expansion is not a code sink.
    - eval "$PR_TITLE"
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
