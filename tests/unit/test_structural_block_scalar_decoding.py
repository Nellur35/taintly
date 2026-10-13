from __future__ import annotations

from taintly.parsers.structural import EventKind, walk_workflow


def leaves(content: str):
    return [
        event
        for event in walk_workflow(
            "workflow.yml", content=content, include_keys=True, include_merge_origins=True
        )
        if event.kind is EventKind.LEAF_SCALAR
    ]


def test_folded_block_scalar_decodes_adjacent_lines_and_keeps_physical_lines():
    content = "run: >\n  npm run\n  build\n"
    (event,) = leaves(content)

    assert event.value == "npm run build\n"
    assert event.value_kind == "block_folded"
    assert event.block_lines == ((2, "npm run"), (3, "build"))


def test_folded_blocks_preserve_paragraph_breaks_and_more_indentation():
    content = "run: >\n  first paragraph\n  \n  second paragraph\n    indented\n  final\n"
    (event,) = leaves(content)

    assert event.value == "first paragraph\nsecond paragraph\n  indented\nfinal\n"


def test_literal_and_folded_chomping_and_eof_line_endings():
    cases = {
        "run: |\n  a\n  b\n": ("a\nb\n", "block_literal"),
        "run: |-\n  a\n  b": ("a\nb", "block_literal"),
        "run: |+\n  a\n\n": ("a\n\n", "block_literal"),
        "run: >-\n  npm run\n  build": ("npm run build", "block_folded"),
        "run: >+\n  npm run\n  build\n\n": ("npm run build\n\n", "block_folded"),
    }
    for content, expected in cases.items():
        (event,) = leaves(content)
        assert (event.value, event.value_kind) == expected


def test_blank_only_scalar_and_whitespace_lines_follow_chomping_rules():
    cases = {
        "run: |\n  \n  \n": "",
        "run: |-\n  \n  \n": "",
        "run: |+\n  \n  \n": "\n\n",
        "run: >+\n  a\n    \n  b\n": "a\n  \nb\n",
    }
    for content, expected in cases.items():
        (event,) = leaves(content)
        assert event.value == expected


def test_explicit_indent_preserves_excess_spaces_on_blank_only_lines():
    for newline in ("\n", "\r\n"):
        for header in ("|2+", ">2+", "|2", ">2"):
            (event,) = leaves(f"run: {header}{newline}    {newline}")
            assert event.value == "  \n"
            assert event.value_kind == (
                "block_folded" if header.startswith(">") else "block_literal"
            )


def test_explicit_indent_modifiers_work_in_compact_sequence_mappings():
    for header in (">2", ">2+", ">+2", "|2-", "|-2"):
        content = f"steps:\n  - run: {header}\n      npm run\n      build\n"
        events = leaves(content)
        (event,) = [item for item in events if item.path == ("steps", 0, "run")]
        folded = header.startswith(">")
        chomps_to_strip = "-" in header
        expected = "npm run build" if folded else "npm run\nbuild"
        if not chomps_to_strip:
            expected += "\n"
        assert event.value == expected
        assert event.value_kind == ("block_folded" if folded else "block_literal")

    dash_gap = "   "
    body_indent = 2 + 1 + len(dash_gap) + 2
    content = (
        f"steps:\n  -{dash_gap}run: >2\n{' ' * body_indent}npm run\n{' ' * body_indent}build\n"
    )
    (event,) = [item for item in leaves(content) if item.path == ("steps", 0, "run")]
    assert event.value == "npm run build\n"
    assert event.value_kind == "block_folded"

    quoted_key = "steps:\n  - 'run:note': >2\n      first\n      second\n"
    (event,) = [item for item in leaves(quoted_key) if item.path == ("steps", 0, "run:note")]
    assert event.value == "first second\n"
    assert event.value_kind == "block_folded"


def test_folded_block_alias_keeps_decoded_value_and_merge_origin():
    content = """base: &base
  run: >
    npm run
    build
jobs:
  build:
    steps:
      - <<: *base
"""
    event = next(
        event for event in leaves(content) if event.path == ("jobs", "build", "steps", 0, "run")
    )

    assert event.value == "npm run build\n"
    assert event.value_kind == "block_folded"
    assert event.merge_origins


def test_folded_run_value_reaches_the_artifact_rule_as_one_command():
    content = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: >
          npm run
          build
"""
    from taintly.engine import scan_file
    from taintly.rules.registry import load_all_rules

    findings = [
        finding
        for finding in scan_file("workflow.yml", load_all_rules(), _content=content)
        if finding.rule_id == "SEC10-GH-002"
    ]
    assert len(findings) == 1
