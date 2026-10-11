"""Bounded GitLab include parsing and nested canonical discovery contracts."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from taintly.engine import _discover_gitlab_files, _discovery_confidence, scan_repo
from taintly.gitlab_workflow_corpus import (
    _extract_cross_project_includes,
    _extract_local_include_paths,
    build_gitlab_corpus,
)
from taintly.models import Platform, RegexPattern, Rule, Severity


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _relative_files(root: Path) -> list[str]:
    files, _dynamic = _discover_gitlab_files(str(root))
    return [Path(path).relative_to(root).as_posix() for path in files]


def test_project_include_file_list_is_not_a_local_include(tmp_path: Path) -> None:
    """A cross-project ``file:`` array must not pull a colliding local file."""
    _write(
        tmp_path / ".gitlab-ci.yml",
        "include:\n"
        "  - project: group/shared\n"
        "    file:\n"
        "      - /shared.yml\n"
        "  - local: ci/local.yml\n",
    )
    _write(tmp_path / "shared.yml", "foreign:\n  script: [echo foreign]\n")
    _write(tmp_path / "ci/local.yml", "local:\n  script: [echo local]\n")

    paths = _extract_local_include_paths((tmp_path / ".gitlab-ci.yml").read_text())
    assert paths == ["ci/local.yml"]
    assert set(_relative_files(tmp_path)) == {".gitlab-ci.yml", "ci/local.yml"}
    corpus = build_gitlab_corpus(str(tmp_path))
    assert {Path(path).relative_to(tmp_path).as_posix() for path in corpus.workflows} == {
        ".gitlab-ci.yml",
        "ci/local.yml",
    }
    cross = _extract_cross_project_includes(
        str(tmp_path / ".gitlab-ci.yml"), (tmp_path / ".gitlab-ci.yml").read_text()
    )
    assert [(item.kind, item.target) for item in cross] == [("project", "group/shared")]


def test_local_include_resolution_cannot_escape_repository_root(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(repo / ".gitlab-ci.yml", "include:\n  - local: ../neighbor.yml\n")
    _write(tmp_path / "neighbor.yml", "outside:\n  script: [echo outside]\n")

    assert _relative_files(repo) == [".gitlab-ci.yml"]
    corpus = build_gitlab_corpus(str(repo))
    assert [Path(path).relative_to(repo).as_posix() for path in corpus.workflows] == [
        ".gitlab-ci.yml"
    ]


def test_only_local_dynamic_refs_count_as_unresolved_local_includes(tmp_path: Path) -> None:
    _write(
        tmp_path / ".gitlab-ci.yml",
        "include:\n"
        "  - project: '$CI_PROJECT_NAMESPACE/shared'\n"
        "    file:\n"
        "      - '/$CI_PROJECT_NAME/ci.yml'\n"
        "  - local: 'ci/$CI_COMMIT_BRANCH.yml'\n",
    )

    _files, dynamic = _discover_gitlab_files(str(tmp_path))
    # The project path is cross-project metadata. Only the explicit local ref
    # is a dynamic local include and should contribute to this count.
    assert dynamic == 1
    reports = scan_repo(str(tmp_path), [], platform=Platform.GITLAB)
    assert any(
        finding.rule_id == "ENGINE-ERR"
        and "1 GitLab include(s) interpolate" in finding.title
        for report in reports
        for finding in report.findings
    )


def test_mixed_block_local_forms_are_resolved_without_project_file_values(
    tmp_path: Path,
) -> None:
    content = (
        "include:\n"
        "  - project: group/shared\n"
        "    file:\n"
        "      - /foreign.yml\n"
        "  - local: ci/block.yml\n"
        "  - ci/bare.yml\n"
    )
    assert _extract_local_include_paths(content) == ["ci/block.yml", "ci/bare.yml"]


def test_indentless_include_sequence_keeps_its_local_items(tmp_path: Path) -> None:
    content = (
        "include:\n"
        "- project: group/shared\n"
        "  file:\n"
        "  - /foreign.yml\n"
        "- local: ci/block.yml\n"
        "- ci/bare.yml\n"
    )
    assert _extract_local_include_paths(content) == ["ci/block.yml", "ci/bare.yml"]


def test_multiline_flow_include_does_not_leak_values_out_as_local_paths() -> None:
    content = (
        "include: [\n"
        "  { project: group/shared, file: [\"/foreign.yml\"] },\n"
        "  \"ci/local.yml\",\n"
        "]\n"
        "job:\n"
        "  needs: [after-include.yml]\n"
    )
    # Resolve the direct local string while keeping the project file and
    # following job data outside the local-include set.
    assert _extract_local_include_paths(content) == ["ci/local.yml"]


def test_project_file_paths_with_yaml_punctuation_do_not_leak_into_local_refs() -> None:
    content = (
        "include:\n"
        "  - project: group/shared\n"
        "    file:\n"
        "      - '/foreign/a,[b]#fragment.yml'\n"
        "  - local: ci/real.yml\n"
        "job:\n"
        "  needs:\n"
        "    - unrelated.yml\n"
    )
    assert _extract_local_include_paths(content) == ["ci/real.yml"]


def test_nested_inputs_values_are_not_local_refs(tmp_path: Path) -> None:
    content = (
        "include:\n"
        "  - project: group/shared\n"
        "    file: /foreign.yml\n"
        "    inputs:\n"
        "      local: not-an-include.yml\n"
        "      options:\n"
        "        local: nested-not-an-include.yml\n"
        "      files:\n"
        "        - input-array.yml\n"
        "  - local: ci/real.yml\n"
    )
    assert _extract_local_include_paths(content) == ["ci/real.yml"]


def test_quoted_project_file_with_yaml_punctuation_is_not_a_local_path() -> None:
    content = (
        "include:\n"
        "  - project: group/shared\n"
        "    file:\n"
        "      - '/foreign/a,[b]#fragment.yml'\n"
        "job:\n"
        "  needs:\n"
        "    - unrelated.yml\n"
    )
    assert _extract_local_include_paths(content) == []


def test_include_context_ends_before_tagged_job_and_document_boundary() -> None:
    content = (
        "include:\n"
        "  - project: group/shared\n"
        "    file:\n"
        "      - /foreign.yml\n"
        "  - local: ci/real.yml\n"
        "---\n"
        "job: !reference [.defaults, job]\n"
        "  needs:\n"
        "    - unrelated.yml\n"
        "outside_alias: *some_anchor.yml\n"
    )
    assert _extract_local_include_paths(content) == ["ci/real.yml"]


@pytest.mark.parametrize("suffix", [".gitlab-ci.yml", ".gitlab-ci.yaml"])
def test_nested_canonical_hidden_entry_is_discovered_and_scanned(
    tmp_path: Path, suffix: str
) -> None:
    _write(tmp_path / ".gitlab-ci.yml", "stages: [test]\nroot:\n  script: [echo root]\n")
    nested = _write(
        tmp_path / ".gitlab" / "workflows" / "nightly" / suffix,
        "stages: [test]\nnightly:\n  script:\n    - echo nested\n",
    )

    files, _dynamic = _discover_gitlab_files(str(tmp_path))
    confidence = _discovery_confidence(str(tmp_path), Platform.GITLAB, files)
    assert os.path.normpath(str(nested)) in confidence
    assert confidence[os.path.normpath(str(nested))] == "high"

    canary_rule = Rule(
        id="TEST-GL-DISCOVERY",
        title="Nested discovery canary",
        severity=Severity.LOW,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description="Test-only discovery marker.",
        pattern=RegexPattern(match=r"echo nested"),
        remediation="Test only.",
        reference="https://example.invalid/",
    )
    reports = scan_repo(str(tmp_path), [canary_rule], platform=Platform.GITLAB)
    report = next(item for item in reports if item.platform == Platform.GITLAB)
    assert report.files_scanned == 2
    assert any(
        finding.rule_id == canary_rule.id
        and finding.file.replace("\\", "/").endswith(nested.relative_to(tmp_path).as_posix())
        for finding in report.findings
    )
