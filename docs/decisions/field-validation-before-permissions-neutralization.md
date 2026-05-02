# Field validation before permissions neutralization

## Status

Accepted for Phase 8.

## Decision

Run empirical field validation before implementing permissions-neutralization
behavior.

Phase 5 stays design-only until reviewed corpus evidence satisfies the
reopening thresholds in `docs/decisions/permissions-neutralization-design.md`.

## Rationale

Permissions neutralization can remove or downgrade findings based on inferred
capability absence. That is useful only when the capability model is proven. A
wrong model can create silent false negatives, so the next step after the
roadmap stabilization is evidence collection rather than new suppression logic.

Field validation gives the project a reviewable basis for:

- recurring false-positive classes,
- likely false-negative classes,
- whether context notes helped triage,
- whether dead-path suppression reduced noise safely,
- whether reporting terminology confused reviewers,
- whether permissions-neutralization has enough evidence to reopen.

## Scope

Phase 8 adds:

- a small local-corpus validation harness,
- machine-readable summary output,
- a Markdown review queue for human triage,
- initial local evidence from available CI-heavy repositories.

Phase 8 does not add runtime scanner behavior, new suppression rules, or score
changes.

## Privacy and ethics boundary

Committed field-validation artifacts must not publish third-party repository
identities, local filesystem paths, filenames, or raw per-repository finding
inventories. Evidence is for scanner tuning, not public calling-out of scanned
repositories.

The validation harness therefore writes stable target aliases by default
(`github-target-01`, `gitlab-target-01`, etc.) and redacts sampled snippets and
file identities in committed artifacts. Full raw outputs may be used locally for
private review, but they should not be committed.

## Scanner contract check

Every proposed future suppression must answer:

> Could this hide a real exploit path in another deployment?

If yes, the candidate remains context or triage metadata until stronger
evidence proves suppression is safe.

## Reopening Phase 5

Permissions-neutralization implementation remains deferred unless the Phase 8
evidence meets the thresholds already documented in the Phase 5 design:

- at least 30 reviewed false positives,
- at least 3 independent repositories,
- at least 5 distinct affected rule IDs or one dominant rule with more than 15
  reviewed false positives,
- documented capability needs with positive and negative examples,
- offline-determinable effective permissions,
- negative tests proving unknown permission state remains reportable.

## Reviewer checklist

- No detector semantics changed.
- No new suppression behavior added.
- Findings remain reportable when semantics are uncertain.
- Evidence artifacts distinguish scan output from human assessment.
- Committed artifacts use target aliases and redacted samples only.
- Any future Phase 5 work cites reviewed corpus evidence, not intuition.
