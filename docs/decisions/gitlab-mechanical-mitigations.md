# GitLab mechanical mitigations

## Status

Phase 3 ships a conservative GitLab dead-job evaluator for `rules:` entries that
make a job impossible to execute. It is post-detection logic: rules still report
raw matches first, and the engine suppresses only findings whose source lines
fall inside a job proven dead.

## What ships now

- Literal `rules:if` values: `true` and `false`.
- Equality and inequality checks for observable GitLab facts:
  - `$CI_PIPELINE_SOURCE`
  - `$CI_COMMIT_BRANCH`
  - `$CI_DEFAULT_BRANCH`
- Dead-job suppression when a matching rule uses `when: never`.
- Runtime fallback for missing context, unsupported variables, compound
  expressions, function-like expressions, regex expressions, and manual jobs.

## What is deferred

- Full GitLab expression parsing.
- Ordered rule-result modeling beyond the `when: never` dead-job case.
- Manual pipeline input severity calibration.
- Deployment-aware rescoring.
- Cross-file include expansion for GitLab CI.

## Non-goals

The evaluator does not execute GitLab expressions and does not infer private
deployment policy. Unsupported syntax means `RUNTIME`, not suppressed.

## Reopening criteria

Revisit this design when field measurements show one of these patterns causing
meaningful false positives or false negatives:

- `rules:if` boolean compounds dominate GitLab false positives.
- Manual-only pipeline findings need consistent severity calibration.
- Included GitLab CI fragments produce line-range suppression gaps.
- GitLab expression variants can be supported without adding a YAML dependency
  or unsafe semantic guessing.
