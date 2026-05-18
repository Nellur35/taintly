"""Tests for the regex-based shell-body fallback emitted when the
tree-sitter-groovy parse is mostly errors.

The fallback supplements walker output ONLY when
``error_byte_ratio > 0.5``.  Clean parses (jenkins.io, maven, jcasc)
pay zero overhead — the regex pass doesn't run.  Cassandra-class
files (~100% error coverage) get the lift.

Events emitted via the fallback carry ``degraded=True`` so
consumers can choose whether to act on them.
"""

from __future__ import annotations

import pytest

# Gate the module on the optional ``[jenkins-structural]`` extra so a
# CI run without tree-sitter-groovy installed skips this file rather
# than failing at import time.
pytest.importorskip("tree_sitter_groovy")

from taintly.parsers.jenkinsfile import EventKind, walk_jenkinsfile
from taintly.parsers.jenkinsfile.fallback import regex_fallback_leaves


def _shell_events(content: str):
    return [
        ev
        for ev in walk_jenkinsfile(content)
        if ev.kind == EventKind.LEAF and ev.value_kind == "shell"
    ]


def test_clean_parse_emits_no_degraded_events():
    """A trivial Jenkinsfile that tree-sitter parses cleanly must not
    invoke the fallback — every shell LEAF is from the walker."""
    content = (
        "pipeline {\n"
        "    agent any\n"
        "    stages {\n"
        "        stage('Build') { steps { sh 'echo hi' } }\n"
        "    }\n"
        "}\n"
    )
    events = _shell_events(content)
    assert events, "walker must yield at least one shell LEAF"
    assert all(not ev.degraded for ev in events), (
        f"clean parse must not emit degraded events; got "
        f"{[(ev.value, ev.degraded) for ev in events]}"
    )


def test_fallback_emits_degraded_leaf_for_shell_body():
    """``regex_fallback_leaves`` direct invocation must produce a
    ``LEAF`` event with ``value_kind="shell"`` and ``degraded=True``
    for each recognised shell-step body."""
    content = "sh 'echo hi'\n"
    leaves = list(regex_fallback_leaves(content))
    assert len(leaves) == 1
    ev = leaves[0]
    assert ev.kind == EventKind.LEAF
    assert ev.value_kind == "shell"
    assert ev.value == "echo hi"
    assert ev.degraded is True
    assert ev.line == 1


def test_fallback_recovers_shell_body_walker_misses(monkeypatch):
    """Integration check: lower the activation threshold to 0 and
    construct content whose ERROR span hides the ``sh`` call from the
    walker (it doesn't form a recognisable ``method_invocation`` /
    ``juxt_function_call`` node).  The regex fallback must recover
    the shell body and emit it with ``degraded=True``."""
    import taintly.parsers.jenkinsfile.fallback as fallback_mod

    monkeypatch.setattr(fallback_mod, "_ERROR_RATIO_THRESHOLD", 0.0)
    # A bare ``def f(\n…\n)`` puts the ``sh '...'`` inside a
    # parser-recovered ERROR region; tree-sitter-groovy doesn't
    # produce a method-invocation node for it, so the walker yields
    # zero shell LEAFs.  The fallback recovers it.
    content = "def f(\nsh 'echo found me'\n) {}\n"
    events = _shell_events(content)
    walker_events = [ev for ev in events if not ev.degraded]
    fallback_events = [ev for ev in events if ev.degraded]
    assert not walker_events, f"setup invariant: walker must miss this shape; got {walker_events}"
    assert fallback_events, f"expected a degraded fallback event; got {events}"
    assert fallback_events[0].value == "echo found me"


def test_fallback_ignores_sh_inside_string_literal():
    """``sh`` mentioned inside a Groovy string literal is not a shell
    call.  The regex pass must consult the code mask and skip
    string-internal positions."""
    content = "echo 'avoid using sh \"rm -rf\" patterns'\n"
    leaves = list(regex_fallback_leaves(content))
    assert leaves == [], f"sh inside a string must not be emitted; got {leaves}"


def test_fallback_ignores_sh_inside_line_comment():
    """``sh`` mentioned inside a ``//`` comment is not a call."""
    content = "// example: sh 'echo hi'\n"
    leaves = list(regex_fallback_leaves(content))
    assert leaves == [], f"sh inside a // comment must not be emitted; got {leaves}"


def test_fallback_ignores_sh_inside_block_comment():
    """``sh`` mentioned inside a ``/* */`` comment is not a call."""
    content = "/* example: sh 'echo hi' */\n"
    leaves = list(regex_fallback_leaves(content))
    assert leaves == [], f"sh inside a /* */ comment must not be emitted; got {leaves}"


def test_fallback_handles_triple_quoted_body():
    """Triple-quoted shell bodies span multiple lines — the regex
    must match the longest form first so the body isn't truncated
    at the first inner ``'`` or ``\"``."""
    content = "sh '''\nwget -q ${url}\nbash downloaded.sh\n'''\n"
    leaves = list(regex_fallback_leaves(content))
    assert len(leaves) == 1
    ev = leaves[0]
    assert "wget -q" in (ev.value or "")
    assert "bash downloaded.sh" in (ev.value or "")
    assert ev.degraded is True


def test_fallback_dedupes_against_walker():
    """If the walker already saw a shell LEAF at (line, value), the
    fallback must not emit the same one again."""
    seen = {(1, "echo hi")}
    content = "sh 'echo hi'\n"
    leaves = list(regex_fallback_leaves(content, exclude_keys=seen))
    assert leaves == []


def test_fallback_rejects_substring_call_names():
    """``bash`` and ``ash`` are NOT shell-step calls — the word
    boundary on ``sh`` must reject them."""
    content = "bash -c 'echo hi'\nash -c 'echo bye'\n"
    leaves = list(regex_fallback_leaves(content))
    assert leaves == [], f"substring matches leaked; got {leaves}"
