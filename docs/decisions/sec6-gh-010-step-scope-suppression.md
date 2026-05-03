# SEC6-GH-010: step-scope suppression

## Status

Accepted.

## Context

SEC6-GH-010 detects credentials routed through a step's `with:`
input rather than through the step's `env:` block. The `with:`
route bypasses the runner's log-redactor; the `env:` route
registers the value with the redactor at process start.

The rule originally used `anchor_job_exclude` to suppress its
findings when any step in the same job declared an `env:` block
routing a `${{ secrets.X }}` reference. The intent was to avoid
false positives on workflows that genuinely use the safe pattern
but mix `with:` and `env:` across steps.

## Decision

Migrate the rule to step-scope suppression via a new
`anchor_step_exclude` field on `ContextPattern`. The suppression
now activates only when the same step that contains the matched
`with:` line also contains an `env:` block routing a secret.

The existing `anchor_job_exclude` field stays on the model.
Future rules where the safe-pattern signal is genuinely
job-scoped (rather than step-scoped) can continue to use it.
The rule covered by this entry is migrated because its
semantics match the runner's actual masking behavior at step
granularity, not job granularity.

The companion rule SEC7-GH-003 — which also uses
`anchor_job_exclude` — was reviewed during this work and stays
job-scoped. Its suppression checks for a job-level `if:` event
guard (e.g., `if: github.event_name == 'push'`). The `if:`
directive applies at job granularity in GitHub Actions, so the
job-scope match is correct for that rule.

## Alternatives considered

**Keep job-scope.** The original tradeoff documented in the
rule's comments described job-scope as "a small amount of
precision tradeoff." Reviewing real-world rule behavior showed
the precision loss was wider than the comment suggested:
workflows that route one secret safely in a sibling step would
suppress legitimate findings on unrelated steps. Step-scope
better reflects the runner's masking semantics (the redactor
registration is per-process / per-step).

**Drop the suppression entirely.** A version with no
suppression would over-fire on workflows that genuinely use the
safe pattern. Step-scope retains the legitimate suppression
while narrowing the scope to where the co-location actually
matters.

## Consequences

- The rule now consults per-step content rather than per-job
  content for its safe-pattern suppression check.
- A new `_split_into_step_segments` helper is added to
  `taintly/models.py`, mirroring the existing
  `_split_into_job_segments` but built on the structural
  reader so YAML anchors and merge keys are handled correctly.
- Existing test corpus continues to pass; new test cases
  exercise the step-scope semantics.
- `anchor_job_exclude` remains available for future rules
  that need job-scope (SEC7-GH-003 keeps using it).
