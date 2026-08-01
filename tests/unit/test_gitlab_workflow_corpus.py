"""Unit tests for taintly.gitlab_workflow_corpus.

Covers:
  * Entry-file discovery (.gitlab-ci.yml + .gitlab/.gitlab-ci.yml).
  * `include: local:` resolution (bare list + block-mapping shapes).
  * Bounded include recursion (depth + file count + cycle).
  * Cross-project include capture without network fetch (project /
    remote / template / component).
  * Unpinned-project-include subset extraction.
  * Trigger classification from `$CI_PIPELINE_SOURCE` compares.
  * id_tokens detection (workflow- and job-level).
  * Protected-branch-only detection.
  * Trusted-bot-gate detection.
"""

from __future__ import annotations

from pathlib import Path

from taintly.gitlab_workflow_corpus import (
    _MAX_INCLUDE_FILES,
    GitLabIncludeRef,
    build_gitlab_corpus,
)
from taintly.workflow_corpus import TriggerFamily


def _write_entry(tmp_path: Path, content: str, alt: bool = False) -> Path:
    if alt:
        (tmp_path / ".gitlab").mkdir(parents=True, exist_ok=True)
        p = tmp_path / ".gitlab" / ".gitlab-ci.yml"
    else:
        p = tmp_path / ".gitlab-ci.yml"
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# Entry-file discovery
# ---------------------------------------------------------------------------


def test_build_corpus_returns_empty_when_no_entry_file(tmp_path: Path) -> None:
    corpus = build_gitlab_corpus(str(tmp_path))
    assert corpus.workflows == {}


def test_build_corpus_finds_root_entry_file(tmp_path: Path) -> None:
    entry = _write_entry(tmp_path, "stages:\n  - test\n")
    corpus = build_gitlab_corpus(str(tmp_path))
    assert len(corpus.workflows) == 1
    assert str(entry) in corpus.workflows or any(
        Path(p).samefile(entry) for p in corpus.workflows
    )


def test_build_corpus_falls_back_to_dotgitlab_entry(tmp_path: Path) -> None:
    entry = _write_entry(tmp_path, "stages:\n  - test\n", alt=True)
    corpus = build_gitlab_corpus(str(tmp_path))
    assert len(corpus.workflows) == 1
    assert any(Path(p).samefile(entry) for p in corpus.workflows)


# ---------------------------------------------------------------------------
# `include: local:` resolution
# ---------------------------------------------------------------------------


def test_include_local_block_mapping_resolves(tmp_path: Path) -> None:
    (tmp_path / "ci").mkdir()
    (tmp_path / "ci" / "build.yml").write_text("build:\n  script:\n    - make\n")
    _write_entry(
        tmp_path,
        "include:\n  - local: /ci/build.yml\nstages:\n  - build\n",
    )
    corpus = build_gitlab_corpus(str(tmp_path))
    assert len(corpus.workflows) == 2


def test_include_local_recursive_chain(tmp_path: Path) -> None:
    (tmp_path / "ci").mkdir()
    (tmp_path / "ci" / "step1.yml").write_text(
        "include:\n  - local: /ci/step2.yml\n",
    )
    (tmp_path / "ci" / "step2.yml").write_text("build:\n  script:\n    - make\n")
    _write_entry(tmp_path, "include:\n  - local: /ci/step1.yml\n")
    corpus = build_gitlab_corpus(str(tmp_path))
    assert len(corpus.workflows) == 3


def test_include_local_cycle_terminates(tmp_path: Path) -> None:
    # a.yml -> b.yml -> a.yml — the walker must terminate.
    (tmp_path / "ci").mkdir()
    (tmp_path / "ci" / "a.yml").write_text("include:\n  - local: /ci/b.yml\n")
    (tmp_path / "ci" / "b.yml").write_text("include:\n  - local: /ci/a.yml\n")
    _write_entry(tmp_path, "include:\n  - local: /ci/a.yml\n")
    corpus = build_gitlab_corpus(str(tmp_path))
    # Each file visited at most once.
    assert len(corpus.workflows) == 3  # entry + a + b


def test_include_local_recursion_bounded_by_file_count(tmp_path: Path) -> None:
    # Create N+10 mutually-referenced files and confirm the walker
    # stops at _MAX_INCLUDE_FILES.  Each file points to the next.
    (tmp_path / "ci").mkdir()
    n = _MAX_INCLUDE_FILES + 10
    for i in range(n):
        nxt = i + 1
        body = (
            f"include:\n  - local: /ci/f{nxt}.yml\n" if nxt < n else "build:\n  script:\n    - make\n"
        )
        (tmp_path / "ci" / f"f{i}.yml").write_text(body)
    _write_entry(tmp_path, "include:\n  - local: /ci/f0.yml\n")
    corpus = build_gitlab_corpus(str(tmp_path))
    assert len(corpus.workflows) <= _MAX_INCLUDE_FILES


# ---------------------------------------------------------------------------
# Cross-project include capture (NO network fetch)
# ---------------------------------------------------------------------------


def test_include_project_captured_but_not_fetched(tmp_path: Path) -> None:
    _write_entry(
        tmp_path,
        "include:\n"
        "  - project: 'my-group/templates'\n"
        "    file: '/ci.yml'\n"
        "    ref: main\n",
    )
    corpus = build_gitlab_corpus(str(tmp_path))
    assert len(corpus.workflows) == 1
    summary = list(corpus.workflows.values())[0]
    assert any(r.kind == "project" for r in summary.cross_project_includes)


def test_include_remote_template_component_captured(tmp_path: Path) -> None:
    _write_entry(
        tmp_path,
        "include:\n"
        "  - remote: 'https://example.com/ci.yml'\n"
        "  - template: 'Auto-DevOps.gitlab-ci.yml'\n"
        "  - component: 'gitlab.com/my-org/my-component@1.0'\n",
    )
    corpus = build_gitlab_corpus(str(tmp_path))
    summary = list(corpus.workflows.values())[0]
    kinds = {r.kind for r in summary.cross_project_includes}
    assert kinds == {"remote", "template", "component"}


def test_unpinned_project_includes_subset(tmp_path: Path) -> None:
    _write_entry(
        tmp_path,
        "include:\n"
        "  - project: 'my-group/a'\n"
        "    file: '/ci.yml'\n"
        "    ref: main\n"
        "  - project: 'my-group/b'\n"
        "    file: '/ci.yml'\n"
        "    ref: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n",
    )
    corpus = build_gitlab_corpus(str(tmp_path))
    summary = list(corpus.workflows.values())[0]
    unpinned = list(summary.unpinned_project_includes)
    assert len(unpinned) == 1
    assert "a" in unpinned[0].target


# ---------------------------------------------------------------------------
# Trigger classification
# ---------------------------------------------------------------------------


def test_trigger_classification_merge_request_event_is_fork_reachable(tmp_path: Path) -> None:
    _write_entry(
        tmp_path,
        "workflow:\n"
        "  rules:\n"
        "    - if: $CI_PIPELINE_SOURCE == \"merge_request_event\"\n",
    )
    corpus = build_gitlab_corpus(str(tmp_path))
    summary = list(corpus.workflows.values())[0]
    assert TriggerFamily.FORK_REACHABLE in summary.triggers


def test_trigger_classification_push_is_privileged(tmp_path: Path) -> None:
    _write_entry(
        tmp_path,
        "workflow:\n"
        "  rules:\n"
        "    - if: $CI_PIPELINE_SOURCE == \"push\"\n",
    )
    corpus = build_gitlab_corpus(str(tmp_path))
    summary = list(corpus.workflows.values())[0]
    assert TriggerFamily.PRIVILEGED in summary.triggers


def test_trigger_classification_schedule_is_scheduled(tmp_path: Path) -> None:
    _write_entry(
        tmp_path,
        "workflow:\n"
        "  rules:\n"
        "    - if: $CI_PIPELINE_SOURCE == \"schedule\"\n",
    )
    corpus = build_gitlab_corpus(str(tmp_path))
    summary = list(corpus.workflows.values())[0]
    assert TriggerFamily.SCHEDULED in summary.triggers


def test_trigger_classification_ignores_pipeline_source_inequality(tmp_path: Path) -> None:
    _write_entry(
        tmp_path,
        'workflow:\n  rules:\n    - if: $CI_PIPELINE_SOURCE != "merge_request_event"\n',
    )
    corpus = build_gitlab_corpus(str(tmp_path))
    summary = next(iter(corpus.workflows.values()))
    assert TriggerFamily.FORK_REACHABLE not in summary.triggers


def test_no_pipeline_source_compare_means_all_families_reachable(tmp_path: Path) -> None:
    # No `$CI_PIPELINE_SOURCE` compare anywhere → conservative worst case:
    # every family is potentially reachable.
    _write_entry(tmp_path, "build:\n  script:\n    - make\n")
    corpus = build_gitlab_corpus(str(tmp_path))
    summary = list(corpus.workflows.values())[0]
    assert TriggerFamily.FORK_REACHABLE in summary.triggers
    assert TriggerFamily.PRIVILEGED in summary.triggers


# ---------------------------------------------------------------------------
# id_tokens detection
# ---------------------------------------------------------------------------


def test_id_tokens_detection_job_level(tmp_path: Path) -> None:
    _write_entry(
        tmp_path,
        "build:\n"
        "  id_tokens:\n"
        "    AWS_TOKEN:\n"
        "      aud: https://sts.amazonaws.com\n"
        "  script:\n"
        "    - make\n",
    )
    corpus = build_gitlab_corpus(str(tmp_path))
    summary = list(corpus.workflows.values())[0]
    assert summary.id_tokens_declared


def test_id_tokens_absent_when_not_declared(tmp_path: Path) -> None:
    _write_entry(tmp_path, "build:\n  script:\n    - make\n")
    corpus = build_gitlab_corpus(str(tmp_path))
    summary = list(corpus.workflows.values())[0]
    assert not summary.id_tokens_declared


# ---------------------------------------------------------------------------
# Protected-branch-only gate detection
# ---------------------------------------------------------------------------


def test_protected_branch_only_gate_detected(tmp_path: Path) -> None:
    _write_entry(
        tmp_path,
        "deploy:\n"
        "  rules:\n"
        "    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'\n"
        "  script:\n"
        "    - deploy.sh\n",
    )
    corpus = build_gitlab_corpus(str(tmp_path))
    summary = list(corpus.workflows.values())[0]
    assert summary.protected_branch_only


def test_protected_branch_absent_when_not_gated(tmp_path: Path) -> None:
    _write_entry(tmp_path, "build:\n  script:\n    - make\n")
    corpus = build_gitlab_corpus(str(tmp_path))
    summary = list(corpus.workflows.values())[0]
    assert not summary.protected_branch_only


# ---------------------------------------------------------------------------
# Trusted-bot-gate detection
# ---------------------------------------------------------------------------


def test_bot_gate_detected_for_renovate(tmp_path: Path) -> None:
    _write_entry(
        tmp_path,
        "deploy:\n"
        "  rules:\n"
        "    - if: '$GITLAB_USER_LOGIN == \"renovate-bot\"'\n"
        "  script:\n"
        "    - deploy.sh\n",
    )
    corpus = build_gitlab_corpus(str(tmp_path))
    summary = list(corpus.workflows.values())[0]
    assert summary.bot_gate_pattern


def test_bot_gate_not_detected_for_arbitrary_user(tmp_path: Path) -> None:
    _write_entry(
        tmp_path,
        "deploy:\n"
        "  rules:\n"
        "    - if: '$GITLAB_USER_LOGIN == \"alice\"'\n"
        "  script:\n"
        "    - deploy.sh\n",
    )
    corpus = build_gitlab_corpus(str(tmp_path))
    summary = list(corpus.workflows.values())[0]
    assert not summary.bot_gate_pattern


# ---------------------------------------------------------------------------
# GitLabIncludeRef dataclass sanity
# ---------------------------------------------------------------------------


def test_gitlab_include_ref_is_immutable() -> None:
    ref = GitLabIncludeRef(
        kind="project",
        target="my-group/x:/ci.yml@main",
        ref="main",
        filepath="/tmp/a",
        line=10,
    )
    # frozen dataclass — assignment must raise.
    try:
        ref.kind = "remote"  # type: ignore[misc]
    except Exception:
        return
    raise AssertionError("GitLabIncludeRef must be frozen")
