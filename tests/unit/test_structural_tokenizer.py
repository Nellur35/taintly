"""Tokenizer test pack — every supported shape and rejection case
gets a named test so the contract is documented in code.

Phase 1 of the structural CI YAML reader.  See
``docs/STRUCTURAL_READER_SCOPE.md`` for the supported feature
list.
"""

from __future__ import annotations

import pytest

from taintly.parsers.structural.tokenizer import (
    Token,
    TokenKind,
    TokenizerError,
    tokenize,
)


def _tokens(content: str) -> list[Token]:
    return [t for t in tokenize(content) if t.kind != TokenKind.INDENT]


def _kinds(content: str) -> list[TokenKind]:
    return [t.kind for t in _tokens(content)]


# ---------------------------------------------------------------------------
# Mappings, sequences, nesting
# ---------------------------------------------------------------------------


def test_simple_mapping():
    src = "name: ci\non: push\n"
    kinds = _kinds(src)
    assert kinds == [
        TokenKind.KEY,
        TokenKind.SCALAR_PLAIN,
        TokenKind.KEY,
        TokenKind.SCALAR_PLAIN,
        TokenKind.EOF,
    ]


def test_nested_mapping_with_sequence():
    src = (
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: echo hello\n"
    )
    tokens = _tokens(src)
    dashes = [t for t in tokens if t.kind == TokenKind.SEQUENCE_DASH]
    assert len(dashes) == 2


def test_flow_sequence():
    src = "runs-on: [ubuntu-latest, windows-latest]\n"
    kinds = _kinds(src)
    assert TokenKind.FLOW_OPEN_SEQ in kinds
    assert TokenKind.FLOW_CLOSE_SEQ in kinds
    assert kinds.count(TokenKind.FLOW_COMMA) == 1


def test_flow_mapping():
    src = "with: {token: ${{ secrets.X }}}\n"
    kinds = _kinds(src)
    assert TokenKind.FLOW_OPEN_MAP in kinds
    assert TokenKind.FLOW_CLOSE_MAP in kinds


# ---------------------------------------------------------------------------
# Plain scalars — explicit edge cases the tokenizer must handle
# ---------------------------------------------------------------------------


def test_plain_scalar_with_colon_in_value():
    """``key: foo:bar:baz`` — the value is the literal string with
    embedded colons, not a nested mapping.  A naive tokenizer that
    treats every ``:`` as a key marker would mis-parse this.
    """
    src = "key: foo:bar:baz\n"
    tokens = _tokens(src)
    keys = [t for t in tokens if t.kind == TokenKind.KEY]
    scalars = [t for t in tokens if t.kind == TokenKind.SCALAR_PLAIN]
    assert len(keys) == 1
    assert keys[0].value == "key"
    assert len(scalars) == 1
    assert scalars[0].value == "foo:bar:baz"


def test_plain_scalar_with_url_value():
    """A URL is a real-world common form of the colon-in-value case."""
    src = "homepage: https://example.com/path\n"
    scalars = [t for t in _tokens(src) if t.kind == TokenKind.SCALAR_PLAIN]
    assert scalars[0].value == "https://example.com/path"


def test_norway_problem_no_to_false():
    """``no``/``yes``/``on``/``off`` are preserved as plain scalars
    by the tokenizer; type coercion is the schema layer's job.
    Tokenising must not eagerly cast them to booleans (the Norway
    problem — country code ``NO`` collapses to False without the
    schema's veto).
    """
    src = "country: NO\nactive: yes\nshape: off\n"
    scalars = [t.value for t in _tokens(src) if t.kind == TokenKind.SCALAR_PLAIN]
    assert scalars == ["NO", "yes", "off"]


def test_multi_line_plain_scalar_inside_flow_seq():
    """Plain scalars inside a flow sequence don't fold across
    lines, but the items are read individually.
    """
    src = "runs-on: [\n  ubuntu-latest,\n  windows-latest,\n]\n"
    tokens = _tokens(src)
    scalars = [t.value for t in tokens if t.kind == TokenKind.SCALAR_PLAIN]
    assert "ubuntu-latest" in scalars
    assert "windows-latest" in scalars


# ---------------------------------------------------------------------------
# Quoted scalars and quoted keys
# ---------------------------------------------------------------------------


def test_quoted_key_single_quotes():
    src = "'key': value\n"
    tokens = _tokens(src)
    assert tokens[0].kind == TokenKind.KEY
    assert tokens[0].value == "key"


def test_quoted_key_double_quotes():
    src = '"key": value\n'
    tokens = _tokens(src)
    assert tokens[0].kind == TokenKind.KEY
    assert tokens[0].value == "key"


def test_quoted_value_with_colon_inside():
    """``key: 'foo:bar'`` — the colon is inside the quoted string,
    not a key marker.
    """
    src = "key: 'foo:bar'\n"
    tokens = _tokens(src)
    quoted = [t for t in tokens if t.kind == TokenKind.SCALAR_QUOTED]
    assert len(quoted) == 1
    assert quoted[0].value == "foo:bar"


def test_double_quoted_value_with_escape():
    """Backslash escapes are preserved as raw text by the
    tokenizer; the value-coercion layer is responsible for
    decoding them.
    """
    src = 'key: "line1\\nline2"\n'
    quoted = [t for t in _tokens(src) if t.kind == TokenKind.SCALAR_QUOTED]
    assert quoted[0].value == "line1\\nline2"


def test_multiline_double_quoted_value_continues_until_closing_quote():
    """Real GitHub workflows use YAML's multi-line quoted scalar
    form for long input descriptions. The tokenizer should treat
    the whole quoted run as one scalar instead of cutting off at the
    first physical line.
    """
    src = (
        'description: "Pass `--prerelease=allow` to wheel-install steps so\n'
        "  transitive prerelease deps resolve. Use only when the release itself\n"
        '  is a prerelease."\n'
        "type: string\n"
    )
    quoted = [t for t in _tokens(src) if t.kind == TokenKind.SCALAR_QUOTED]
    assert len(quoted) == 1
    assert "transitive prerelease deps resolve" in quoted[0].value
    assert quoted[0].line == 1


# ---------------------------------------------------------------------------
# Block scalars — chomping and indentation indicators
# ---------------------------------------------------------------------------


def test_block_scalar_literal():
    src = (
        "script: |\n"
        "  echo hello\n"
        "  echo world\n"
    )
    tokens = _tokens(src)
    headers = [t for t in tokens if t.kind == TokenKind.SCALAR_BLOCK_HEADER]
    body = [t for t in tokens if t.kind == TokenKind.SCALAR_BLOCK_LINE]
    assert len(headers) == 1
    assert headers[0].value == "|"
    assert [t.value for t in body] == ["echo hello", "echo world"]


def test_block_scalar_folded():
    src = (
        "description: >\n"
        "  this is line one\n"
        "  this is line two\n"
    )
    headers = [t for t in _tokens(src) if t.kind == TokenKind.SCALAR_BLOCK_HEADER]
    assert headers[0].value == ">"


def test_block_scalar_chomping_strip():
    """``|-`` strips the trailing newline.  Tokenizer just records
    the indicator; decoding semantics are higher up."""
    src = "script: |-\n  echo hi\n"
    headers = [t for t in _tokens(src) if t.kind == TokenKind.SCALAR_BLOCK_HEADER]
    assert headers[0].value == "|-"


def test_block_scalar_chomping_keep():
    """``|+`` keeps trailing newlines."""
    src = "script: |+\n  echo hi\n"
    headers = [t for t in _tokens(src) if t.kind == TokenKind.SCALAR_BLOCK_HEADER]
    assert headers[0].value == "|+"


def test_block_scalar_explicit_indent_indicator():
    """``|2`` pins the body indent at +2 from the header line."""
    src = "script: |2\n  echo hi\n  echo two\n"
    body = [t for t in _tokens(src) if t.kind == TokenKind.SCALAR_BLOCK_LINE]
    assert [t.value for t in body] == ["echo hi", "echo two"]


# ---------------------------------------------------------------------------
# Anchors, aliases, merge keys
# ---------------------------------------------------------------------------


def test_anchor_and_alias():
    src = (
        "defaults: &defs\n"
        "  ref: main\n"
        "\n"
        "job:\n"
        "  with:\n"
        "    <<: *defs\n"
    )
    kinds = _kinds(src)
    assert TokenKind.ANCHOR in kinds
    assert TokenKind.MERGE_KEY in kinds
    assert TokenKind.ALIAS in kinds


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------


def test_comment_to_eol():
    src = "name: ci  # this is a comment\n"
    tokens = _tokens(src)
    comments = [t for t in tokens if t.kind == TokenKind.COMMENT]
    assert len(comments) == 1
    assert comments[0].value.startswith("# this is")


def test_comment_only_line():
    src = "# preamble\nname: ci\n"
    tokens = _tokens(src)
    comments = [t for t in tokens if t.kind == TokenKind.COMMENT]
    assert len(comments) == 1


# ---------------------------------------------------------------------------
# Line / column tracking
# ---------------------------------------------------------------------------


def test_line_and_column_correct():
    src = "name: ci\non:\n  push:\n    branches: [main]\n"
    tokens = _tokens(src)
    branches = [
        t
        for t in tokens
        if t.kind == TokenKind.KEY and t.value == "branches"
    ]
    assert len(branches) == 1
    assert branches[0].line == 4
    assert branches[0].column == 5  # 4 spaces of indent + 1


def test_crlf_line_endings_normalised():
    src = "name: ci\r\non: push\r\n"
    tokens = _tokens(src)
    keys = [t for t in tokens if t.kind == TokenKind.KEY]
    # CRLF should produce the same line numbers as LF — the
    # tokenizer normalises line endings before splitting.
    assert keys[0].line == 1
    assert keys[1].line == 2


# ---------------------------------------------------------------------------
# Rejected constructs — recoverable error per fixture
# ---------------------------------------------------------------------------


def test_directive_rejected():
    src = "%YAML 1.2\nname: ci\n"
    with pytest.raises(TokenizerError):
        list(tokenize(src))


def test_document_separator_skipped():
    """Document-start markers are valid YAML and common in workflow
    files (`---\\nname: ...`).  The tokenizer treats them as no-ops
    rather than aborting tokenization, so single-document content
    after the marker tokenizes normally.

    Bug history: previously raised TokenizerError, which bubbled up
    as ENGINE-ERR ('Structural coverage degraded: file partially
    unparseable from line 1') across ~17 of 18 ENGINE-ERRs in the
    Phase 8 corpus baseline scan (2026-05-03).  All affected files
    were valid GHA workflows that started with `---`.
    """
    src = "---\nname: ci\non: push\n"
    tokens = list(tokenize(src))
    # Should produce normal tokens for `name: ci` and `on: push`
    # (plus EOF), with no error.
    kinds = [t.kind for t in tokens]
    from taintly.parsers.structural.tokenizer import TokenKind
    assert TokenKind.EOF in kinds
    # `name` and `on` should appear as KEY tokens.
    keys = [t.value for t in tokens if t.kind == TokenKind.KEY]
    assert "name" in keys
    assert "on" in keys


def test_document_end_skipped():
    """`...` document-end marker is also a no-op for our scanner."""
    src = "name: ci\non: push\n...\n"
    tokens = list(tokenize(src))
    from taintly.parsers.structural.tokenizer import TokenKind
    assert TokenKind.EOF in [t.kind for t in tokens]


def test_document_separator_mid_stream_skipped():
    """A `---` mid-file (multi-document YAML) is also skipped silently.

    Workflow YAML is single-document by convention; if a multi-doc
    file is encountered, the second document's content tokenizes as
    if it were part of the first.  The scanner doesn't try to
    differentiate documents — it scans all tokens it sees.
    """
    src = "name: a\non: push\n---\nname: b\non: pull_request\n"
    tokens = list(tokenize(src))
    from taintly.parsers.structural.tokenizer import TokenKind
    keys = [t.value for t in tokens if t.kind == TokenKind.KEY]
    # Both `name` keys appear (one per document); both `on` keys too.
    assert keys.count("name") == 2
    assert keys.count("on") == 2


def test_custom_tag_rejected():
    src = "name: !!str ci\n"
    with pytest.raises(TokenizerError):
        list(tokenize(src))


def test_gitlab_reference_tag_consumed_as_opaque_scalar():
    """``!reference [section, key]`` is the GitLab CI cross-section
    value reference.  Treat it as an opaque scalar so the walker
    doesn't bail — the structural reader can't resolve the reference,
    but per-line rules see the source text and the rest of the file
    keeps tokenizing.
    """
    src = (
        "rules:\n"
        "  - if: '$DAP_RELEASE_NOTES_TOKEN == null'\n"
        "    when: never\n"
        "  - !reference [.ai-gateway:rules:tagging, rules]\n"
        "allow_failure: true\n"
    )
    tokens = list(tokenize(src))
    refs = [t for t in tokens if "!reference" in t.value]
    assert len(refs) == 1
    assert refs[0].kind == TokenKind.SCALAR_PLAIN
    assert refs[0].value == "!reference [.ai-gateway:rules:tagging, rules]"
    keys = [t.value for t in tokens if t.kind == TokenKind.KEY]
    assert "allow_failure" in keys


def test_gitlab_reference_tag_handles_nested_brackets():
    """Some GitLab !reference values contain nested flow sequences."""
    src = "extends:\n  - !reference [.foo, [bar, baz]]\n"
    tokens = list(tokenize(src))
    refs = [t for t in tokens if "!reference" in t.value]
    assert len(refs) == 1
    assert refs[0].kind == TokenKind.SCALAR_PLAIN
    assert refs[0].value == "!reference [.foo, [bar, baz]]"


def test_other_custom_tags_still_rejected():
    """The !reference allowance is narrowly scoped — other ``!``-prefixed
    tags continue to raise so the caller falls back to regex scanning.
    """
    for src in (
        "name: !!str ci\n",
        "config: !CustomTag value\n",
        "value: !MyApp/Tag thing\n",
    ):
        with pytest.raises(TokenizerError):
            list(tokenize(src))


def test_complex_key_rejected():
    src = "?\n  - a\n  - b\n: value\n"
    with pytest.raises(TokenizerError):
        list(tokenize(src))


def test_unterminated_quoted_scalar_raises():
    src = 'name: "unterminated\n'
    with pytest.raises(TokenizerError):
        list(tokenize(src))
