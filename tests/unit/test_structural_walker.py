"""Walker test pack — path-tracking, leaf emission, cutoff
recovery, and the anchor-merge-key contract.

Phase 1 of the structural CI YAML reader.
"""

from __future__ import annotations

import pytest

from taintly.parsers.structural.tokenizer import TokenizerError
from taintly.parsers.structural.walker import Event, EventKind, walk


def _leaves(content: str, **kwargs) -> list[Event]:
    return [e for e in walk(content, **kwargs) if e.kind == EventKind.LEAF_SCALAR]


def _paths(content: str, **kwargs) -> list[tuple[object, ...]]:
    return [e.path for e in _leaves(content, **kwargs)]


# ---------------------------------------------------------------------------
# Basic path resolution
# ---------------------------------------------------------------------------


def test_top_level_keys_become_singleton_paths():
    src = "name: ci\non: push\n"
    paths = _paths(src)
    assert ("name",) in paths
    assert ("on",) in paths


def test_nested_path_for_step_uses():
    src = (
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: echo hello\n"
    )
    paths = _paths(src)
    assert ("jobs", "build", "runs-on") in paths
    assert ("jobs", "build", "steps", 0, "uses") in paths
    assert ("jobs", "build", "steps", 1, "run") in paths


def test_leaf_value_and_value_kind():
    src = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
    )
    leaves = _leaves(src)
    target = next(
        e for e in leaves if e.path == ("jobs", "build", "steps", 0, "uses")
    )
    assert target.value == "actions/checkout@v4"
    assert target.value_kind == "plain"


# ---------------------------------------------------------------------------
# Glob queries
# ---------------------------------------------------------------------------


def test_glob_matches_step_uses():
    src = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/setup-python@v5\n"
    )
    leaves = _leaves(src, query="jobs.*.steps[*].uses")
    values = [e.value for e in leaves]
    assert "actions/checkout@v4" in values
    assert "actions/setup-python@v5" in values
    assert len(values) == 2


def test_glob_double_star_at_depth():
    src = (
        "jobs:\n"
        "  a:\n"
        "    steps:\n"
        "      - run: echo a\n"
        "  b:\n"
        "    steps:\n"
        "      - run: echo b\n"
    )
    leaves = _leaves(src, query="**.run")
    values = [e.value for e in leaves]
    assert "echo a" in values
    assert "echo b" in values


def test_glob_exact_top_level():
    src = "on: push\nname: ci\n"
    leaves = _leaves(src, query="on")
    assert len(leaves) == 1
    assert leaves[0].value == "push"


# ---------------------------------------------------------------------------
# Flow style
# ---------------------------------------------------------------------------


def test_flow_sequence_indexed():
    src = "runs-on: [ubuntu-latest, windows-latest]\n"
    paths = _paths(src)
    assert ("runs-on", 0) in paths
    assert ("runs-on", 1) in paths


def test_flow_mapping_keys():
    src = "with: {token: tok-value, retries: 3}\n"
    paths = _paths(src)
    assert ("with", "token") in paths
    assert ("with", "retries") in paths


# ---------------------------------------------------------------------------
# Block scalars
# ---------------------------------------------------------------------------


def test_block_scalar_literal_is_one_leaf():
    src = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - run: |\n"
        "          echo hello\n"
        "          echo world\n"
    )
    leaves = _leaves(src, query="jobs.*.steps[*].run")
    assert len(leaves) == 1
    assert "echo hello" in leaves[0].value
    assert "echo world" in leaves[0].value
    assert leaves[0].value_kind == "block_literal"


# ---------------------------------------------------------------------------
# Anchor / alias / merge-key
# ---------------------------------------------------------------------------


def test_merge_key_replays_at_alias_line():
    """Merged leaves must report at the alias line, not the
    anchor-definition line.  Rules report findings using these
    line numbers; the alias line is what the maintainer wrote."""
    src = (
        "defaults: &defs\n"
        "  persist-credentials: false\n"
        "\n"
        "steps:\n"
        "  - uses: actions/checkout@v4\n"
        "    with:\n"
        "      <<: *defs\n"
    )
    leaves = _leaves(src, query="**.persist-credentials")
    persist_credentials = [e for e in leaves if e.value == "false"]
    # At least one leaf is reported; the line is the alias line
    # (line 7 in the fixture, where ``<<: *defs`` sits).
    assert any(e.line == 7 for e in persist_credentials), (
        f"merged leaf must report at the alias line; got lines "
        f"{[e.line for e in persist_credentials]}"
    )


# ---------------------------------------------------------------------------
# Cutoff recovery
# ---------------------------------------------------------------------------


def test_corrupt_file_emits_cutoff_in_recover_mode():
    """When the tokenizer hits an unsupported construct in
    ``recover=True`` mode, the walker yields events for what was
    parsed before the cutoff, then a single CUTOFF event with the
    cutoff line number, then nothing.
    """
    src = (
        "name: ci\n"
        "%YAML 1.2\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
    )
    events = list(walk(src, recover=True))
    cutoffs = [e for e in events if e.kind == EventKind.CUTOFF]
    assert len(cutoffs) == 1
    assert cutoffs[0].line == 2
    # No further events after the cutoff.
    cutoff_index = events.index(cutoffs[0])
    assert cutoff_index == len(events) - 1


def test_corrupt_file_raises_in_strict_mode():
    src = "%YAML 1.2\nname: ci\n"
    with pytest.raises(TokenizerError):
        list(walk(src, recover=False))


# ---------------------------------------------------------------------------
# Quoted-key resolution
# ---------------------------------------------------------------------------


def test_quoted_keys_resolve():
    src = "'foo': bar\n"
    paths = _paths(src)
    assert ("foo",) in paths


# ---------------------------------------------------------------------------
# Plain-scalar value with embedded colon
# ---------------------------------------------------------------------------


def test_plain_scalar_with_colon_in_value_walks_correctly():
    src = "homepage: https://example.com\n"
    leaves = _leaves(src, query="homepage")
    assert len(leaves) == 1
    assert leaves[0].value == "https://example.com"
