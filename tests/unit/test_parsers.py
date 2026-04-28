"""Unit tests for the parsers package.

The parsers/ modules were previously untested; these tests bring them
up to coverage parity and lock in the regex shapes so drive-by edits
don't silently break the extraction contract.
"""

from __future__ import annotations

from taintly.parsers.common import (
    extract_yaml_key,
    find_block,
    normalize_line_endings,
    strip_comments,
)
from taintly.parsers.github import (
    extract_jobs,
    extract_triggers,
    extract_uses_refs,
    has_permission_block,
    is_github_workflow,
)
from taintly.parsers.gitlab import extract_includes


# =============================================================================
# common.py
# =============================================================================


def test_strip_comments_removes_comment_lines():
    src = "key: value\n# comment\nother: thing\n  # indented comment\n"
    assert strip_comments(src) == "key: value\nother: thing"


def test_strip_comments_keeps_inline_hash():
    """Inline hashes are not comment starters; only leading `#` counts."""
    src = "url: https://example.com/#fragment\n"
    assert "example.com/#fragment" in strip_comments(src)


def test_extract_yaml_key_returns_value():
    assert extract_yaml_key("name: ci\nother: x\n", "name") == "ci"


def test_extract_yaml_key_missing_returns_none():
    assert extract_yaml_key("other: x\n", "name") is None


def test_find_block_returns_indented_children():
    src = "jobs:\n  build:\n    runs-on: ubuntu-latest\nother: x\n"
    block = find_block(src, "jobs")
    assert block is not None
    assert "build:" in block
    assert "other: x" not in block


def test_find_block_missing_returns_none():
    assert find_block("key: value\n", "jobs") is None


def test_normalize_line_endings_crlf_to_lf():
    assert normalize_line_endings("a\r\nb\rc\n") == "a\nb\nc\n"


# =============================================================================
# github.py
# =============================================================================


def test_is_github_workflow_true_for_on_and_jobs():
    assert is_github_workflow("on: push\n")
    assert is_github_workflow("jobs:\n  build:\n")
    assert not is_github_workflow("name: thing\n")


def test_extract_triggers_inline_array():
    src = "on: [push, pull_request]\n"
    assert extract_triggers(src) == ["push", "pull_request"]


def test_extract_triggers_block_form():
    src = "on:\n  push:\n    branches: [main]\n  pull_request:\n"
    got = extract_triggers(src)
    assert "push" in got
    assert "pull_request" in got


def test_extract_triggers_simple_form():
    assert extract_triggers("on: push\n") == ["push"]


def test_extract_jobs_finds_two_space_indented_keys():
    src = "jobs:\n  build:\n  test:\n    runs-on: x\n"
    assert set(extract_jobs(src)) == {"build", "test"}


def test_has_permission_block():
    assert has_permission_block("permissions:\n  contents: read\n")
    assert not has_permission_block("jobs:\n  build:\n")


def test_extract_uses_refs():
    src = "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: org/act@abcd\n"
    refs = extract_uses_refs(src)
    assert ("actions/checkout", "v4", 4) in refs
    assert ("org/act", "abcd", 5) in refs


def test_extract_uses_refs_ignores_comments():
    src = "      # - uses: actions/checkout@v4\n      - uses: actions/checkout@v4\n"
    refs = extract_uses_refs(src)
    assert len(refs) == 1


# =============================================================================
# gitlab.py
# =============================================================================


def test_extract_includes_local():
    src = "include:\n  - local: /scripts/ci.yml\n"
    includes = extract_includes(src)
    assert {"type": "local", "value": "/scripts/ci.yml"} in includes


def test_extract_includes_project_with_ref():
    src = "include:\n  - project: org/shared\n    file: /ci.yml\n    ref: main\n"
    includes = extract_includes(src)
    assert any(i["type"] == "project" and "org/shared" in i["value"] for i in includes)


def test_extract_includes_empty_when_absent():
    assert extract_includes("jobs:\n  build:\n    script:\n      - echo hi\n") == []
