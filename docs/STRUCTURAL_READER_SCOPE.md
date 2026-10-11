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
- **`CUTOFF`** — the reader hit an unsupported construct, active
  alias recursion, or its anchor-work limit. Events for what was parsed
  before the cutoff are valid; no further events follow.
- **`ERROR`** — a recoverable parse-time problem the walker
  surfaces but continues past (e.g., a dangling alias).

## What the reader does NOT do

- **Does not produce a full YAML AST.** Event-streaming, not
  tree-building.
- **The default stream does not resolve effective merge precedence.** Inherited defaults and
  explicit overrides can emit multiple events at one path. Consumers must
  retain uncertainty for duplicate bindings rather than select an arbitrary
  first or last value.
- **Does not round-trip.**  Read-only.  `--fix` stays regex-based.
- **Does not introduce a YAML library dependency.**  Hand-rolled
  reader; the project's zero-runtime-dependency promise is
  preserved.

### GitLab effective merge values

The GitLab single-file taint extractor and inheritance resolver share
`taintly/_gitlab_effective.py`. It applies explicit-over-merged precedence
for supported single mapping-alias merges, regardless of source order.
An explicit key replaces the whole child subtree, including an empty or
null value. This follows [GitLab's YAML optimization documentation](https://docs.gitlab.com/ci/yaml/yaml_optimization/).

The internal `include_merge_origins=True` walker option records each merged
leaf's defining mapping and immediate child key. Nested anchor capture and
bare aliases preserve those original coordinates. This is opt-in; ordinary
raw consumers retain their existing event stream. Origin-chain copying and
storage are charged to the same structural work budget, and the parse cache
separates this option from ordinary walks.

Repeated explicit keys or merge sites, unsupported flow aliases/merges,
non-mapping merges, errors and cutoffs make the effective view incomplete.
The view then returns the ordinary raw stream without new precedence
suppression. This also retains old detections if metadata alone exhausts
the budget. The fallback retains the existing raw consumer limitations,
including first-writer inheritance misses; it does not resolve unknown YAML.
Merge lists and `extends` array replacement are outside this change.

The inheritance resolver applies whole-value replacement only to the
`script`, `before_script`, and `after_script` roots. It requires a complete,
unambiguous effective view across the target's full `extends` ancestry and a
structurally observed explicit root; empty and null roots are supported when
their mapping key is directly visible. Missing parents, cycles, depth limits,
same-name jobs accumulated from multiple files, incomplete views, and shell
roots containing `!reference` retain the legacy leaf merge for the entire
target ancestry. Empty roots hidden inside whole-job anchor replay are not
proved. `variables` and other roots keep their existing merge behavior.

## Supported features

Each supported feature has at least one named test in
`tests/unit/test_structural_tokenizer.py` or
`tests/unit/test_structural_walker.py`:

- Block-style mappings, sequences, and arbitrary nesting
  (`test_simple_mapping`, `test_nested_mapping_with_sequence`).
- Flow-style sequences and mappings
  (`test_flow_sequence`, `test_flow_mapping`).
- Flow-style mappings nested inside flow-style sequences and
  vice versa, with leaves emitted at the correct indexed/keyed
  paths
  (`test_flow_mapping_inside_flow_sequence_yields_keyed_leaves`,
  `test_flow_sequence_inside_flow_mapping`).  `_consume_flow` is
  recursion-based, pushing and popping a frame per nested
  container so leaves at any depth land at the correct path.
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
- Block scalars carry per-line breakdown via the `block_lines`
  field on `LEAF_SCALAR` events, so consumers can land findings
  at the specific source line containing a match rather than at
  the block-scalar header
  (`test_block_scalar_carries_per_line_breakdown`).
  `StructuralPattern` uses this to run its predicate against
  each body line individually for block-scalar leaves.
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

## Anchor / alias / merge-key behaviour

- **Anchor capture** (`&name`) records leaves under every active anchor,
  including nested anchors. Capture stops at the defining line's indent.
- **Bare alias** (`*name`) replays captured leaves at the alias destination
  and line. Scalar aliases replay at the exact destination path. Unresolved
  aliases surface as `ERROR`; recursive aliases and exhausted shared replay
  work surface as terminal `CUTOFF` events.
- **Merge key** (`<<: *name`) replays mapping leaves beneath the current path.
  A scalar anchor used as a merge source surfaces as `ERROR`. Replay uses a
  snapshot so nested aliases cannot mutate their source template while it is
  being expanded.
- **Expansion limits:** all capture appends and alias emissions share a
  100,000-unit per-walk budget, charged as `1 + len(path)`. Recursion into an
  active anchor or exhausted work terminates recovery with one `CUTOFF`;
  strict mode raises `TokenizerError`. No trailing events are emitted.

## Jenkinsfile

Out of scope.  Jenkinsfile is Groovy DSL, not YAML; the
tokenizer's invariants (indent-driven structure, key-colon
disambiguation, etc.) don't hold.  Jenkins rules continue to use
regex-based detection.

## Schema-lookup performance

The schema layer is consulted via path-glob lookup at query time.
Lookup is linear iteration over the schema dict's entries
(O(N) per leaf for an N-entry schema).  At the current schema size
(~80 entries) and typical workflow depth, this is negligible.  If
profiling ever reveals it as a hot path, a path-trie representation
(O(depth) per leaf) is the natural escape hatch.
