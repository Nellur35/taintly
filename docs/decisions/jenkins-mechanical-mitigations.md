# Jenkins mechanical mitigations

## Status

Phase 4 ships a Declarative-first Jenkins stage suppressor for literal dead
`when` blocks. It is a post-detection pass: Jenkins rules still report raw
matches first, and the engine removes only findings whose source lines fall
inside a stage proven unreachable.

## What ships now

- Declarative `stage('name') { ... }` line-range extraction.
- Literal dead `when` forms:
  - `when { expression { false } }`
  - `when { expression { return false } }`
  - `when { not { expression { true } } }`
- Conservative handling for optional `beforeAgent`, `beforeInput`, and
  `beforeOptions` flags around the literal expression.

## What is deferred

- Scripted Pipeline semantic analysis.
- General Groovy expression evaluation.
- Parameter-aware severity calibration.
- Branch, changelog, changeRequest, environment, equals, anyOf, allOf, and
  nested condition modeling.
- Jenkins deployment-aware rescoring.

## Non-goals

This evaluator does not execute Groovy and does not infer Jenkins controller
authorization. Unsupported `when` syntax means `RUNTIME`, not suppressed.

## Reopening criteria

Revisit the design when field evidence shows one of these patterns is common
enough to justify the added taxonomy and test surface:

- Dead Jenkins stages are mostly expressed through non-literal `when` forms.
- Parameter-only stages need consistent severity calibration.
- Scripted Pipeline blocks produce material false positives that cannot be
  handled by Declarative stage suppression.
- A safe Groovy parser becomes available without adding a runtime dependency.
