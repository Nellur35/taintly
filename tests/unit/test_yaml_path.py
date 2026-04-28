"""Tests for taintly.yaml_path.extract_paths.

The extractor underpins every ``PathPattern`` rule.  A quote-unaware
comment stripper in the original implementation truncated valid
scalars like ``"release #1 candidate"`` at the hash, which caused
structural rules to see the wrong value.  These tests lock down the
fix so the bug can't regress without a failing test.
"""

from __future__ import annotations

from taintly.yaml_path import extract_paths


def _value_at(paths, target):
    for p, v, _ in paths:
        if p == target:
            return v
    raise AssertionError(f"path {target!r} not extracted")


def test_double_quoted_hash_preserved():
    """The reviewer's exact reproducer — the value must stay intact."""
    yaml = (
        'on:\n'
        '  workflow_dispatch:\n'
        '    inputs:\n'
        '      note:\n'
        '        description: "release #1 candidate"\n'
    )
    paths = extract_paths(yaml)
    assert _value_at(paths, "on.workflow_dispatch.inputs.note.description") == (
        "release #1 candidate"
    )


def test_single_quoted_hash_preserved():
    yaml = "msg: 'release #1'\n"
    assert _value_at(extract_paths(yaml), "msg") == "release #1"


def test_url_fragment_preserved():
    """A bare (unquoted) URL containing # was NOT safe under the old
    regex either.  Once quoted, it must round-trip verbatim."""
    yaml = 'env:\n  LINK: "https://example.com/x#section"\n'
    assert _value_at(extract_paths(yaml), "env.LINK") == "https://example.com/x#section"


def test_trailing_comment_still_stripped_after_unquoted_value():
    """The fix must not break the common case: a trailing comment on
    a plain unquoted scalar should still be removed."""
    yaml = "env:\n  SAFE: hello # this is a comment\n"
    assert _value_at(extract_paths(yaml), "env.SAFE") == "hello"


def test_trailing_comment_stripped_after_quoted_value():
    """Once the quoted scalar closes, a following ``# comment`` is a
    real comment and should still be stripped."""
    yaml = 'env:\n  X: "v1.0" # tagged release\n'
    assert _value_at(extract_paths(yaml), "env.X") == "v1.0"


def test_github_actions_expression_preserved():
    """${{ ... }} expressions must survive the comment stripper even
    when they precede other content."""
    yaml = (
        "jobs:\n"
        "  x:\n"
        "    env:\n"
        "      MSG: ${{ github.event.pull_request.head.sha }}\n"
    )
    assert _value_at(extract_paths(yaml), "jobs.x.env.MSG") == (
        "${{ github.event.pull_request.head.sha }}"
    )


def test_expression_then_comment_strips_only_the_comment():
    yaml = (
        "jobs:\n"
        "  x:\n"
        "    env:\n"
        "      MSG: ${{ github.sha }} # the sha\n"
    )
    assert _value_at(extract_paths(yaml), "jobs.x.env.MSG") == "${{ github.sha }}"


def test_hash_at_start_of_value_is_not_mistaken_for_comment():
    """A value that starts with ``#`` (quoted) is a valid scalar, not
    a comment line — the regex used ``\\s+#`` which accidentally did
    the right thing here, but the replacement should too."""
    yaml = 'msg: "#hashtag"\n'
    assert _value_at(extract_paths(yaml), "msg") == "#hashtag"


def test_no_path_pattern_rule_queries_steps_path():
    """Silent-failure guard on yaml_path.py's sequence collapse.

    extract_paths() emits sequence items at the parent path without
    an index component, so `jobs.build.steps[0].uses` and
    `jobs.build.steps[1].uses` both collapse to `jobs.build.steps.uses`.
    See the yaml_path.py docstring ("Sequence items... do NOT create a
    persistent path component for subsequent sibling keys").

    Any PathPattern rule that tries to distinguish between steps via a
    `steps\\.` path regex will silently observe the wrong behaviour. No
    registered rule today queries a `steps\\.` path; this test fails
    loudly if anyone adds one before the extractor is taught to emit
    per-index components.
    """
    from taintly.models import PathPattern
    from taintly.rules.registry import load_all_rules

    offenders: list[tuple[str, str]] = []
    for rule in load_all_rules():
        if not isinstance(rule.pattern, PathPattern):
            continue
        if "steps" in rule.pattern.path:
            offenders.append((rule.id, rule.pattern.path))

    assert not offenders, (
        "PathPattern rule queries a `steps.` path, but extract_paths() "
        "collapses all sequence items at the parent path without index "
        "components — the rule will observe the wrong value silently. "
        "Either teach yaml_path.extract_paths() to emit per-index "
        "components, or express the rule via ContextPattern / "
        "SequencePattern on the raw lines.\n"
        f"Offending rules: {offenders}"
    )
