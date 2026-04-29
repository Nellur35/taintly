# Decision: threat-model disclosure, not auto-adjustment

**Status**: accepted (current behaviour)

## Context

The score is computed against a fixed implicit threat model
(public-OSS deployment). Several proposals to make the score
deployment-aware were considered:

1. **User-declared context modifiers.** A `.taintly-context.yml`
   file describing deployment characteristics (PR policy, runner
   topology, secret scoping); the scorer multiplies exploitability
   by per-family modifiers.
2. **Tiered deployment profiles.** A `--profile=internal-org` or
   similar flag picking from 3-4 named profiles, each with a
   different scoring table.
3. **Threat-model disclosure.** A line in the score output naming
   the assumed threat model; documentation explaining what changes
   for other deployments; user does the rest.

## Decision

Ship (3). Hold (1) and (2).

## Why

Both auto-adjustment proposals require modifier values calibrated
against labelled examples from non-public-OSS deployments. The
available labelled corpus is public-OSS-only:

- For (1), corpus analysis showed 53% of policy-class disagreements
  were out of scope for the proposed modifier table; the in-scope
  half couldn't be calibrated against any rows in the corpus.
- For (2), the same calibration deficit applies in different shape
  — profiles are bundles of modifiers, and validating the bundle
  needs more data than validating individual modifiers, not less.

Disclosure makes no claim that requires validation. It states what
the score assumes; the user does the rest. The "user assessment is
required, not optional" wording assigns responsibility to the role
best positioned to discharge it.

## Why not "ship something narrower instead"

A `--threat-model=internal` flag with hardcoded modifiers was
considered as a middle ground. Same calibration problem: even
hardcoded values are policy claims that can't be measured against
the data we have.

## What disclosure does NOT do

- Does not change the score number.
- Does not silence findings.
- Does not introduce a second "adjusted" score.
- Does not introduce a `--profile` or `--threat-model` flag.

## Reopening criteria

This decision is revisited when all three are true:

1. ≥30 labelled rows from non-public-OSS deployments become
   available in a corpus the project can use.
2. ≥30% of policy-class disagreements in those rows map to families
   where modifiers could meaningfully resolve the disagreement.
3. Second-reviewer spot-check on at least 10% of the contributed
   rows.

When the criteria are met, modifier values for the in-scope
families can be calibrated against the corpus and the auto-
adjustment proposal becomes a falsifiable feature spec rather than
a policy claim.

## Related artifacts

- `docs/SCORING.md` — user-facing version of this decision.
- Score-text, JSON, and HTML reporters carry the threat-model
  disclosure adjacent to the score (or above the summary card in
  HTML; placement differs by surface and the difference is
  intentional).
