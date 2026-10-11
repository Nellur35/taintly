"""GitLab ``extends`` array replacement and hash-merge contracts.

GitLab deep-merges hashes across parents, but replaces arrays and scalar
keywords as whole values. A leaf-only inheritance resolver must not keep an
unmatched tail from an inherited shell list after a child replaces it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.gitlab_inherit import find_cross_file_taint, resolve_pipeline
from taintly.models import Platform
from taintly.rules.registry import load_all_rules


def _resolved_job(content: str):
    return resolve_pipeline([(".gitlab-ci.yml", content)]).jobs["build"]


def _resolved_job_in_files(files: list[tuple[str, str]]):
    return resolve_pipeline(files).jobs["build"]


def _flows(content: str):
    return find_cross_file_taint([(".gitlab-ci.yml", content)])


def _flows_in_files(files: list[tuple[str, str]]):
    return find_cross_file_taint(files)


def _write_engine_content(tmp_path: Path, content: str, rule_id: str = "TAINT-GL-008") -> list:
    (tmp_path / ".gitlab-ci.yml").write_text(content, encoding="utf-8")
    reports = scan_repo(str(tmp_path), load_all_rules(), Platform.GITLAB)
    return [finding for report in reports for finding in report.findings if finding.rule_id == rule_id]


def _script_values(content: str, key: str = "script") -> list[str]:
    return [
        leaf.value
        for leaf in _resolved_job(content).leaves
        if leaf.path and leaf.path[0] == key
    ]


def _script_values_in_files(files: list[tuple[str, str]], key: str = "script") -> list[str]:
    return [
        leaf.value
        for leaf in _resolved_job_in_files(files).leaves
        if leaf.path and leaf.path[0] == key
    ]


def _array_case(key: str, child_definition: str) -> str:
    return (
        ".base:\n"
        "  variables:\n"
        "    CMD: $CI_COMMIT_TITLE\n"
        f"  {key}:\n"
        '    - echo "safe parent prefix"\n'
        '    - eval "$CMD"\n'
        "build:\n"
        "  extends: .base\n"
        + "\n".join(f"  {line}" for line in child_definition.rstrip().splitlines())
        + "\n"
    )


@pytest.mark.parametrize("key", ["script", "before_script", "after_script"])
def test_shorter_child_shell_array_replaces_parent_tainted_tail(tmp_path: Path, key: str) -> None:
    content = _array_case(key, f'{key}:\n  - echo "safe child"\n')

    assert _write_engine_content(tmp_path, content) == []
    assert all('eval "$CMD"' not in value for value in _script_values(content, key))
    assert _flows(content) == []


def test_child_scalar_replaces_parent_script_list(tmp_path: Path) -> None:
    content = _array_case("script", 'script: echo "safe child"\n')

    assert _write_engine_content(tmp_path, content) == []
    assert _script_values(content) == ['echo "safe child"']
    assert _flows(content) == []


@pytest.mark.parametrize(
    "child_definition",
    [
        'script:\n  - echo "safe child"\n',
        'script: echo "safe child"\n',
    ],
    ids=["block-to-list", "block-to-scalar"],
)
def test_child_list_or_scalar_replaces_parent_block_script(
    tmp_path: Path, child_definition: str
) -> None:
    content = (
        ".base:\n"
        "  variables:\n"
        "    CMD: $CI_COMMIT_TITLE\n"
        "  script: |-\n"
        '    echo "safe parent prefix"\n'
        '    eval "$CMD"\n'
        "build:\n"
        "  extends: .base\n"
        + "\n".join(f"  {line}" for line in child_definition.rstrip().splitlines())
        + "\n"
    )

    assert _write_engine_content(tmp_path, content) == []
    assert all('eval "$CMD"' not in value for value in _script_values(content))
    assert _flows(content) == []


def test_later_parent_replaces_earlier_parent_shell_array(tmp_path: Path) -> None:
    content = (
        ".unsafe:\n"
        "  variables:\n"
        "    CMD: $CI_COMMIT_TITLE\n"
        "  script:\n"
        '    - echo "unsafe parent prefix"\n'
        '    - eval "$CMD"\n'
        ".safe:\n"
        "  script:\n"
        '    - echo "safe later parent"\n'
        "build:\n"
        "  extends:\n"
        "    - .unsafe\n"
        "    - .safe\n"
    )

    assert _write_engine_content(tmp_path, content) == []
    assert _script_values(content) == ['echo "safe later parent"']
    assert _flows(content) == []


def test_empty_script_array_replacement_survives_intermediate_parent(tmp_path: Path) -> None:
    content = (
        ".base:\n"
        "  variables:\n"
        "    CMD: $CI_COMMIT_TITLE\n"
        '  script:\n    - echo "safe parent prefix"\n    - eval "$CMD"\n'
        ".middle:\n"
        "  extends: .base\n"
        "  script: []\n"
        "build:\n"
        "  extends:\n"
        "    - .base\n"
        "    - .middle\n"
    )

    assert _write_engine_content(tmp_path, content) == []
    assert _script_values(content) == []
    assert _flows(content) == []


def test_later_unsafe_parent_replaces_earlier_safe_parent_shell_array(tmp_path: Path) -> None:
    content = (
        ".safe:\n"
        '  script:\n    - echo "safe first parent"\n'
        ".unsafe:\n"
        "  variables:\n"
        "    CMD: $CI_COMMIT_TITLE\n"
        '  script:\n    - eval "$CMD"\n'
        "build:\n"
        "  extends:\n"
        "    - .safe\n"
        "    - .unsafe\n"
    )

    findings = _write_engine_content(tmp_path, content)
    assert findings
    assert 'eval "$CMD"' in _script_values(content)
    assert 'eval "$CMD"' in _script_values(content)


def test_inherited_parent_array_without_child_replacement_still_fires(tmp_path: Path) -> None:
    content = (
        ".base:\n"
        "  variables:\n"
        "    CMD: $CI_COMMIT_TITLE\n"
        "  script:\n"
        '    - echo "safe parent prefix"\n'
        '    - eval "$CMD"\n'
        "build:\n"
        "  extends: .base\n"
    )

    assert 'eval "$CMD"' in _script_values(content)
    assert any(flow.source_var == "CI_COMMIT_TITLE" for flow in _flows(content))
    assert _write_engine_content(tmp_path, content)


def test_empty_child_variables_hash_deep_merges_parent_variables(tmp_path: Path) -> None:
    content = (
        ".base:\n"
        "  variables:\n"
        "    CMD: $CI_COMMIT_TITLE\n"
        '  script:\n    - echo "safe parent prefix"\n    - eval "$CMD"\n'
        "build:\n"
        "  extends: .base\n"
        "  variables: {}\n"
    )

    findings = _write_engine_content(tmp_path, content)
    assert findings
    assert any(
        leaf.path == ("variables", "CMD") and leaf.value == "$CI_COMMIT_TITLE"
        for leaf in _resolved_job(content).leaves
    )
    assert 'eval "$CMD"' in _script_values(content)


def test_missing_parent_does_not_erase_inherited_shell_warning() -> None:
    content = (
        ".base:\n"
        "  variables:\n"
        "    CMD: $CI_COMMIT_TITLE\n"
        '  script:\n    - echo "safe parent prefix"\n    - eval "$CMD"\n'
        "build:\n"
        '  script:\n    - echo "safe child"\n'
        "  extends:\n"
        "    - .base\n"
        "    - .missing\n"
    )

    assert 'eval "$CMD"' in _script_values(content)


def test_unknown_script_reference_does_not_erase_inherited_shell_warning() -> None:
    content = (
        ".alternate:\n"
        '  script:\n    - echo "alternate script"\n'
        ".base:\n"
        "  variables:\n"
        "    CMD: $CI_COMMIT_TITLE\n"
        '  script:\n    - echo "safe parent prefix"\n    - eval "$CMD"\n'
        "build:\n"
        "  extends: .base\n"
        "  script: !reference [.unknown, script]\n"
    )

    assert any(flow.source_var == "CI_COMMIT_TITLE" for flow in _flows(content))


def test_same_named_job_definitions_across_files_keep_legacy_shell_warning() -> None:
    files = [
        (
            "base.yml",
            ".base:\n"
            "  variables:\n"
            "    CMD: $CI_COMMIT_TITLE\n"
            '  script:\n    - echo "safe parent prefix"\n    - eval "$CMD"\n'
            "build:\n"
            "  extends: .base\n",
        ),
        ("included.yml", 'build:\n  script:\n    - echo "safe child"\n'),
    ]

    assert 'eval "$CMD"' in _script_values_in_files(files)


@pytest.mark.parametrize("shape", ["cycle", "depth"])
def test_incomplete_extends_ancestry_keeps_legacy_shell_warning(shape: str) -> None:
    if shape == "cycle":
        ancestry = (
            ".a:\n"
            "  extends: .b\n"
            "  variables:\n"
            "    CMD: $CI_COMMIT_TITLE\n"
            '  script:\n    - echo "safe parent prefix"\n    - eval "$CMD"\n'
            ".b:\n"
            "  extends: .a\n"
        )
        parent = ".a"
    else:
        parts = []
        for index in range(15):
            parts.append(f".p{index}:\n  extends: .p{index + 1}\n")
        parts.append(
            ".p15:\n"
            "  extends: .p16\n"
            "  variables:\n"
            "    CMD: $CI_COMMIT_TITLE\n"
            '  script:\n    - echo "safe parent prefix"\n    - eval "$CMD"\n'
            ".p16:\n  extends: .p17\n"
            ".p17:\n  variables:\n    OTHER: fixed\n"
        )
        ancestry = "".join(parts)
        parent = ".p0"
    content = (
        ancestry
        + "build:\n"
        + f"  extends: {parent}\n"
        + '  script:\n    - echo "safe child"\n'
    )

    assert 'eval "$CMD"' in _script_values(content)


def test_shallow_cached_parent_does_not_hide_deep_depth_cutoff() -> None:
    content = (
        ".x:\n"
        "  extends: .y\n"
        "  variables:\n"
        "    CMD: $CI_COMMIT_TITLE\n"
        '  script:\n    - echo "safe parent prefix"\n    - eval "$CMD"\n'
        ".y:\n  extends: .z\n"
        ".z:\n  variables:\n    OTHER: fixed\n"
        "shallow:\n  extends: .x\n"
    )
    for index in range(14):
        content += f".d{index}:\n  extends: .d{index + 1}\n"
    content += ".d14:\n  extends: .x\nbuild:\n  extends: .d0\n  script:\n    - echo safe\n"

    assert 'eval "$CMD"' in _script_values(content)
