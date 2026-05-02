# Field validation before permissions neutralization

## Status

Accepted for Phase 8.

## Decision

Run empirical field validation before implementing permissions-neutralization
behavior, but keep field-validation operations and generated evidence in
`taintly-private`.

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

## Public scope

Public `taintly` keeps only the sanitized methodology:

- the decision that field evidence must come before permissions-neutralization,
- the safety contract for future suppression candidates,
- reopening criteria for Phase 5,
- the public/private repository boundary.

The validation harness, reviewer notes, raw outputs, corpus inventories, and
Phase 8 reopening evidence belong in `taintly-private`.

Phase 8 does not add runtime scanner behavior, new suppression rules, or score
changes in public `taintly`.

## Privacy and ethics boundary

Public `taintly` must not publish third-party repository identities, local
filesystem paths, filenames, raw per-repository finding inventories, or
reviewer adjudication notes. Evidence is for scanner tuning, not public
calling-out of scanned repositories.

Full raw outputs may be used in `taintly-private` for private review, but they
must not be committed to public `taintly`.

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
- Public artifacts contain methodology only, not corpus evidence.
- Any future Phase 5 work cites reviewed corpus evidence, not intuition.
