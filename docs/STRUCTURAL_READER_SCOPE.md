# Structural CI YAML reader — scope and contract

The structural reader at `taintly/parsers/structural/` is a
schema-bounded path-extraction reader for the YAML shapes that
GitHub Actions and GitLab CI workflow files actually produce.
**It is not a full YAML parser.**

This document is the supported/unsupported boundary, the
cutoff-recovery contract, the anchor-merge-key behaviour, the
Jenkins decision, and the schema-lookup performance choice.

## What the reader does

Walks a CI YAML file and yields a stream of events:

- **`LEAF_SCALAR`** — a scalar value at a fully-resolved structural
  path.  Path components are strings (mapping keys) or integers
  (sequence indices).
- **`CUTOFF`** — the underlying tokenizer hit an unsupported
  construct.  Events for what was parsed before the cutoff are
  valid; no further events follow.
- **`ERROR`** — a recoverable parse-time problem the walker
  surfaces but continues past (e.g., a dangling alias).

## What the reader does NOT do

- **Does not produce a full YAML AST.**  Event-streaming, not
  tree-building.
- **Does not round-trip.**  Read-only.  `--fix` stays regex-based.
- **Does not introduce a YAML library dependency.**  Hand-rolled
  reader; the project's zero-runtime-dependency promise is
  preserved.
- **Does not migrate any existing rules in Phase 1.**  Pure
  addition.  Phase 2 (separate PR) migrates the first three rules
  and measures F1 delta.

## Supported features

Each supported feature has at least one named test in
`tests/unit/test_structural_tokenizer.py` or
`tests/unit/test_structural_walker.py`:

- Block-style mappings, sequences, and arbitrary nesting
  (`test_simple_mapping`, `test_nested_mapping_with_sequence`).
- Flow-style sequences and mappings
  (`test_flow_sequence`, `test_flow_mapping`).
- Plain scalars including the colon-in-value case
  (`test_plain_scalar_with_colon_in_value`).
- URLs as plain scalars (`test_plain_scalar_with_url_value`).
- The Norway problem (`test_norway_problem_no_to_false`):
  `no` / `yes` / `on` / `off` are preserved as plain scalars by
  the tokenizer; type coercion is the schema layer's job.
- Single- and double-quoted scalars
  (`test_quoted_value_with_colon_inside`,
  `test_double_quoted_value_with_escape`).
- Quoted keys (`test_quoted_key_single_quotes`,
  `test_quoted_key_double_quotes`).
- Block scalars: `|` / `>` with chomping indicators (`|+`/`|-`/
  `>+`/`>-`) and explicit indent indicators (`|2`/`>3-`)
  (`test_block_scalar_literal`, `test_block_scalar_folded`,
  `test_block_scalar_chomping_strip`,
  `test_block_scalar_chomping_keep`,
  `test_block_scalar_explicit_indent_indicator`).
- Comments to end-of-line (`test_comment_to_eol`,
  `test_comment_only_line`).
- Anchors, aliases, merge keys (`test_anchor_and_alias`,
  `test_merge_key_replays_at_alias_line`).
- CRLF line endings normalised to LF for stable line numbers
  (`test_crlf_line_endings_normalised`).
- Path globs: `*` (single segment), `**` (multi-segment), `[*]`
  (integer / sequence index)
  (`test_glob_matches_step_uses`,
  `test_glob_double_star_at_depth`,
  `test_glob_exact_top_level`).

## Unsupported features (rejected with a `TokenizerError`)

Each unsupported feature has a named rejection test confirming
the recoverable error fires:

- YAML directives (`%YAML 1.2`) — `test_directive_rejected`.
- Document separators (`---`, `...`) — `test_document_separator_rejected`,
  `test_document_end_rejected`.
- Multi-document files — same rejection path as document
  separators.
- Custom tags (`!!str`, `!CustomTag`) — `test_custom_tag_rejected`.
- Complex / explicit keys (`? mapping-as-key`) —
  `test_complex_key_rejected`.
- Set notation (`!!set`) — falls under custom-tag rejection.
- Unterminated quoted scalars —
  `test_unterminated_quoted_scalar_raises`.

When the reader is invoked with `recover=True` (default), the
tokenizer's exception is caught and surfaced as a single
`CUTOFF` event whose `line` is the line where the unsupported
construct was found; events for what was parsed before the cutoff
remain valid.

## Cutoff-recovery contract

```
... LEAF_SCALAR (line < cutoff) ...
... LEAF_SCALAR (line < cutoff) ...
CUTOFF (line == cutoff)
[no further events]
```

The contract is load-bearing for the engine's coverage-warning
exit-11 path:

- A `StructuralPattern` rule that completes its query before any
  `CUTOFF` returns its finding (or "no finding") normally.
- A `StructuralPattern` rule that hits a `CUTOFF` before it
  resolved its query returns "could-not-evaluate" — distinct
  from "no finding here".  The engine surfaces this as a
  `STRUCTURAL-COVERAGE-WARNING` finding (the structural
  counterpart of the existing `ENGINE-ERR` mechanism), and the
  process exits 11 (coverage degraded) rather than 0 (clean).

Phase 2 wires the `STRUCTURAL-COVERAGE-WARNING` mechanism when
the first rule migrates.  Phase 1 ships the `CUTOFF` event
without a consumer.

## Anchor / alias / merge-key behaviour

- **Anchor capture** (`&name`) records every leaf encountered
  inside the anchor's body.  Capture stops when the walker
  returns to the indent of the anchor's defining line.
- **Bare alias** (`*name` outside a merge-key context) — Phase 1
  surfaces as an `ERROR` event without expanding.  Bare aliases
  are uncommon in CI YAML in practice; expansion lands in Phase
  1.5 if Phase 2 migrations need it.
- **Merge key** (`<<: *name`) — every captured leaf under the
  named anchor is replayed at the alias's line under the alias's
  current path.  This matches the line a rule's report should
  cite: the alias is what the maintainer wrote, the anchor is a
  helper definition above.

## Jenkinsfile

Out of scope for Phase 1.  Jenkinsfile is Groovy DSL, not YAML;
the tokenizer's invariants (indent-driven structure, key-colon
disambiguation, etc.) don't hold.  Jenkins rules continue to use
regex-based detection.  A Groovy-DSL structural reader is a
separate decision (Phase 1.5 or later) and is not a
half-supporting variant of this reader.

## Schema-lookup performance

The schema layer is consulted via path-glob lookup at query time.
Phase 1 uses linear iteration over the schema dict's entries
(O(N) per leaf for an N-entry schema).  At the current schema size
(~80 entries) and typical workflow depth, this is negligible.

If profiling under Phase 2 reveals it as a hot path, the schema
will switch to a path-trie representation (O(depth) per leaf).
The choice will be recorded as a separate decision-log entry; no
runtime work is done speculatively.

## What changes in Phase 2 / Phase 3

- **Phase 2** (separate PR, gated on Phase 1 success): migrates
  the top-3 rules from the audit (locked by
  `(use_count desc, known_precision_issue_rank desc)` lex sort
  recorded in this PR's body) to a `StructuralPattern` form;
  measures F1 delta on a labelled corpus.
- **Phase 3** (decision point, gated on Phase 2 measurement):
  expands migrations if F1 delta ≥ +2pp; parks the reader
  otherwise (the three migrated rules stay migrated as sunk
  cost).
