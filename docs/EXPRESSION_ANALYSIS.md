# GitHub Actions expression value provenance

Taintly keeps syntactic context references separate from values that can reach
an expression result. `context_paths()` reports every parsed reference,
including references in short-circuit branches. Result provenance can omit a
right-hand branch only when a bounded literal-truthiness analysis proves that
GitHub Actions would skip it.

The analysis recognizes `null`, boolean literals, and strings: empty strings
are falsy, while nonempty strings are truthy (so the string `'false'` is
truthy). It combines those facts through `!`, `&&`, and `||`. Numeric literals,
runtime values, function calls, and comparisons remain unknown. Unknown
conditions keep their possible value provenance.

Each truthiness query is limited to 64 AST visits. Exhausted queries return
unknown, and no result is cached across expressions. This is a narrow value
provenance rule; it does not remove syntactic references or claim to evaluate
all GitHub Actions expressions.
