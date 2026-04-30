# Decision: ship a pointer to AI-assisted triage, not the triage itself

**Status**: accepted (current behaviour)

## Context

The threat-model disclosure decision
(`docs/decisions/threat-model-disclosure-not-adjustment.md`) records
why taintly does not auto-adjust scores to the user's deployment:
the labelled corpus needed to calibrate per-deployment modifiers
isn't available, and disclosure assigns the assessment job to the
role best positioned to discharge it (the user).

That decision leaves an open question: how does the user actually
discharge the assessment in practice?  For maintainers who already
use a coding-agent (Claude Code, Cursor, etc.) to read their
codebase, a paste-ready prompt that hands taintly's JSON output to
the agent for recalibration is a low-cost help.  Three concrete
shapes were considered:

1. **Pointer to a paste-ready prompt.** A doc page with one
   recalibration prompt; one-line pointers from each reporter
   surface to the doc.  No taintly behaviour changes; users opt in
   by reading the doc and pasting the prompt into their agent of
   choice.
2. **Built-in agent integration.** A `--triage-with-claude` flag
   (or similar) that calls an external API.
3. **Multiple prompt variants.** Recalibration plus false-positive
   hunting plus threat-model drafting, all in the same doc.

## Decision

Ship (1).  Hold (2).  Drop (3).

## Why

(2) makes taintly responsible for picking an agent vendor, handling
API keys, and absorbing prompt-engineering iteration on a vendor's
moving target.  Each of those is a maintenance commitment that
trades against the zero-runtime-dependency promise and the policy
that taintly takes no position on which agent the user runs.  The
labelled corpus to evaluate "did the agent's recalibration improve
on the raw score?" doesn't exist either, so the integration
couldn't be measured against anything.

(3) loses the focus of (1).  False-positive hunting overlaps the
existing foreign-marker suppression machinery (`--respect-zizmor-
ignores` and the in-tree `nosec` / `nosemgrep` recogniser) and
should be served there if it gets served at all.  Threat-model
drafting is a different product (greenfield generation, not triage)
with its own concerns.  Bundling all three dilutes the one prompt
that does close a real loop.

(1) is cheap to ship, cheap to remove if it doesn't get used, and
makes no claim that requires validation: the prompt is a starting
point the user adapts to their own deployment, not a measurement
that taintly stakes its honesty on.

## What this decision does NOT do

- Does not introduce an agent SDK dependency.
- Does not change the score number.
- Does not endorse a specific agent vendor.
- Does not promise the prompt produces a better recalibration than
  the user would arrive at unaided.

## Reopening criteria

This decision is revisited when any of the following holds:

1. A labelled corpus of recalibration outcomes (agent-suggested vs.
   maintainer-final) for ≥30 findings becomes available.  At that
   point the prompt's wording can be tuned against measured agent
   accuracy rather than first-principles intuition.
2. A maintainer survey reports the pointer is unused after at least
   one minor release in the field.  Park the prompt; remove the
   pointer lines from the reporters; the decision flips to "ship
   nothing here" until evidence that AI-assisted triage helps in
   practice.
3. Pointer (3) — bundling false-positive hunting and threat-model
   drafting — gets re-proposed with a measurable claim attached
   (e.g., a labelled FP-hunt benchmark).  Re-evaluate the bundle
   on the basis of that benchmark, not on first-principles
   plausibility.

## Related artifacts

- `docs/AI_TRIAGE.md` — the user-facing prompt page.
- `docs/decisions/threat-model-disclosure-not-adjustment.md` — the
  upstream decision this entry extends.  AI-assisted triage is a
  way to operationalise the disclosure, not a substitute for it;
  the disclosure stands on its own merits regardless of whether
  this prompt page exists.
- Score-text, JSON, and HTML reporters carry a one-line pointer to
  `docs/AI_TRIAGE.md` adjacent to the existing threat-model
  disclosure.
