# Permissions neutralization design

## Status

Design only. This branch intentionally makes no runtime behavior changes.

Permissions neutralization is the idea that a finding may be mechanically
non-exploitable when the job token or platform permission set cannot perform the
capability the rule depends on. That can reduce false positives, but it is also
one of the easiest ways to create silent false negatives if the capability map
is wrong.

## Proposed model

The implementation should treat capability needs as exploitability metadata,
not detector logic:

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class CapabilityNeed:
    rule_id: str
    platform: str
    requires: tuple[str, ...]
    evidence: tuple[str, ...] = ()
```

Example entries once evidence exists:

```python
CapabilityNeed(
    rule_id="SEC6-GH-008",
    platform="github",
    requires=("id-token:write", "contents:read"),
    evidence=("exfil primitive requires minted OIDC token",),
)
```

The detector still emits the finding. A later post-processing pass may attach a
`neutralization_reason` or suppress only when every required capability is
provably absent from the effective permission set.

## Required implementation boundaries

- Detection rules remain unchanged.
- Capability metadata lives outside the rule regex/pattern definition.
- Unknown, inherited, expression-derived, organization-default, or externally
  configured permissions mean `UNKNOWN`, not neutralized.
- A rule may be neutralized only when all required capabilities are mapped and
  all are provably unavailable.
- Reporters must explain the neutralization reason; they must not recompute it.

## Reopening thresholds

Implementation should remain closed until all of these are true:

- At least 30 reviewed false positives across at least 3 independent
  repositories are attributable primarily to missing effective permissions.
- At least 5 distinct rule IDs are affected, or one rule ID accounts for more
  than 15 reviewed false positives on its own.
- Each candidate rule has a documented capability need with reviewer-approved
  positive and negative examples.
- The engine can determine effective permissions for the relevant platform
  without network access and without relying on hidden repository settings.
- The test suite includes one negative test per mapped rule proving the finding
  is not suppressed when permission state is unknown.

## Explicit non-goals

- No deployment-aware rescoring in this phase.
- No permission inference from private organization policy.
- No suppression based on comments, naming conventions, or guessed defaults.
- No broad per-platform suppression such as "read-only token means safe" unless
  the rule-specific capability need proves that claim.

## Future implementation sketch

If reopened, add a post-processing pass after mechanical dead-path suppression
and before reporting calibration:

```python
POST_PROCESSORS = [
    suppress_dead_findings,
    apply_permissions_neutralization,
    downgrade_maintainer_gated_findings,
    apply_context_notes,
]
```

The pass should return structured evidence:

```python
finding.suppression_reason = (
    "Neutralized: rule SEC6-GH-008 requires id-token:write, but this job has "
    "id-token:none and no inherited write grant."
)
```

## Reviewer checklist

- No runtime behavior changed.
- No rule pack behavior changed.
- No hidden score or severity mutation added.
- Reopening thresholds are measurable.
- Unknown permission states remain reportable.
