# Structural Jenkinsfile reader — scope and contract

The structural Jenkinsfile reader at `taintly/parsers/jenkinsfile/`
is an optional path-extraction reader for the Groovy DSL shapes
that real Jenkinsfile workflows actually use.  Backed by
tree-sitter-groovy; ships under the `[jenkins-structural]` extra.

**The default install is zero-runtime-dependency.**  Jenkins rules
that depend on this reader must guard their import with
`try/except ImportError` and fall back to regex-based detection
when the extra isn't available.

```bash
# Default install — no Jenkinsfile structural support.
pip install taintly

# Opt-in to Jenkinsfile structural support.
pip install 'taintly[jenkins-structural]'
```

## What the reader does

Parses a Jenkinsfile (declarative pipeline primarily; scripted
pipeline best-effort) and yields a stream of events:

- **`LEAF`** — a scalar value at a fully-resolved structural path.
  Path components are strings (block names) or stage names prefixed
  with `stage:` (e.g. `stage:Build`).
- **`CUTOFF`** — the underlying parser hit unrecoverable errors.
  Events emitted before this point are valid; no further events
  follow.  Consumers should treat any unresolved query as
  could-not-evaluate (mirrors the YAML reader's exit-11 contract).
- **`ERROR`** — a recoverable parse-time problem the walker chose
  to surface but continue past.

## What the reader does NOT do

- **Does not produce a full Groovy AST.** Event-streaming, not
  tree-building.
- **Does not round-trip.** Read-only.  Jenkins rules with
  auto-fixes stay regex-based.
- **Does not introduce a runtime dependency for the default
  install.** tree-sitter is only loaded when the optional extra is
  installed AND a rule actually walks a Jenkinsfile.

## Supported scalar shapes (LEAF events fire for)

| Source shape | Path | `value_kind` |
|---|---|---|
| `sh '<cmd>'` | `(..., 'sh')` | `shell` |
| `bat '<cmd>'` | `(..., 'bat')` | `shell` |
| `powershell '<cmd>'` | `(..., 'powershell')` | `shell` |
| `tool '<name>'` | `(..., 'tool')` | `string` |
| `stage('<name>') { ... }` | `(..., 'stage')` | `string` |
| `agent any` / `agent none` | `(..., 'agent')` | `identifier` |
| `<KEY> = '<value>'` inside `environment { }` | `(..., 'environment', '<KEY>')` | `string` |
| `echo '<msg>'` | `(..., 'echo')` | `string` |

Block-only directives (`pipeline { }`, `stages { }`, `steps { }`,
`environment { }`, `options { }`, `triggers { }`, `parameters
{ }`, `post { }`) push their name onto the path but emit no LEAF
of their own — they're navigational.

## Cutoff-recovery contract

tree-sitter is error-recovering: a malformed Jenkinsfile still
produces a partial parse tree.  The walker emits LEAF events for
the recovered subtree, then a single CUTOFF event on the line of
the first ERROR node.  Consumers receive valid events up to that
line and an explicit signal that downstream content is unknown.

```
... LEAF events from the recovered subtree ...
CUTOFF (line = first ERROR line)
[no further events]
```

This matches the YAML reader's contract so rule code that handles
structural events from either reader is uniform.

## Scripted pipeline

Best-effort.  Scripted pipeline (`node { ... }` blocks) parses
correctly via tree-sitter-groovy, but the structural-path shape is
different from declarative (no `stages`/`stage`/`steps` wrappers).
The walker still emits LEAF events for recognised calls (`sh`,
`bat`, etc.), but the path attribution is shallower.  Rules that
need full declarative-pipeline path awareness should check the
path shape and skip when it doesn't match.

## Out of scope

- **Groovy-specific syntax beyond Jenkinsfile use.** Classes,
  generics, lambdas, list/map literals are parsed by tree-sitter
  but not surfaced as LEAFs (the surface area for Jenkins rules
  is narrow).
- **GString interpolation extraction.** `"${env.FOO}"` is emitted
  as a single string LEAF; rules that care about the interpolation
  shape parse the value themselves.
- **Library imports** (`@Library('shared') _`). Tracked as a
  future extension; not in the MVP scope.

## Adding new LEAF shapes

Add the call name to `_SHELL_CALLS` or `_STRING_FIRST_ARG_CALLS`
in `taintly/parsers/jenkinsfile/walker.py` if it's a one-string-arg
shape.  For more complex shapes (multi-arg calls, named arguments),
add a `_handle_<shape>` helper and a dispatch entry in `_walk`.
Pair every addition with a test in
`tests/unit/test_jenkinsfile_walker.py`.
