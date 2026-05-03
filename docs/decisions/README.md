# Decision log

This directory records design decisions that crossed thresholds
worth documenting: rule-pack policy choices, engine-level
suppression scope changes, threat-model framing, and
contribution-pipeline conventions.

## Convention

Each entry is a single Markdown file with these sections:

- **Status** — Accepted / Superseded / Reopened.
- **Context** — what prompted the decision.
- **Decision** — what we chose.
- **Alternatives considered** — what we declined and why.
- **Consequences** — code touched, tests added, follow-ups.

Entries are written when a decision (a) changes a load-bearing
default, (b) settles a recurring tradeoff, or (c) records why a
seemingly natural extension was deliberately deferred. The point
is to give a future contributor (or auditor) an entry-point to
"why is it like this?" without having to reconstruct the
discussion from commit logs.

## Entries

- [Mechanical mitigations taxonomy](./mechanical-mitigations-taxonomy.md)
  — the framework for which classes of false positive can be
  suppressed by post-processing vs. which require user input.
  Plus addenda for whole-workflow / whole-pipeline suppression
  on each platform and for the wiring/coverage follow-ups.
- [GitLab mechanical mitigations](./gitlab-mechanical-mitigations.md)
  — GitLab-specific dead-job suppression model.
- [Jenkins mechanical mitigations](./jenkins-mechanical-mitigations.md)
  — Jenkins-specific dead-stage suppression model.
- [SEC6-GH-010 step-scope suppression](./sec6-gh-010-step-scope-suppression.md)
  — migrated the secret-routing suppression from job-scope to
  step-scope to match the runner's per-process masking semantics.
- [Maintainer-gated severity downgrade](./maintainer-gated-severity-downgrade.md)
  — when triggers are maintainer-only, attacker-presumed
  exploitability tiers down to the next severity.
- [Threat model: disclosure, not adjustment](./threat-model-disclosure-not-adjustment.md)
  — taintly scores against a fixed public-OSS threat model and
  surfaces it; the user assesses fit to their deployment.
- [AI-assisted triage pointer](./ai-assisted-triage-pointer.md)
  — why we ship a paste-ready prompt rather than auto-running
  any agent.
- [AI-triage untrusted-evidence framing](./ai-triage-untrusted-evidence-framing.md)
  — wrap pasted finding bytes in `<untrusted_evidence>` tags
  with explicit data-only instructions; emit `match_text`
  alongside `snippet` for LLM-bound output paths.
- [Post-processing pipeline](./post-processing-pipeline.md)
  — order, scope, and contract of suppression / downgrade
  passes after rules emit findings.
- [Permissions neutralization design](./permissions-neutralization-design.md)
  — design-only entry: what a future capability-aware
  suppression layer would look like and why we haven't shipped
  it.
- [Structural reader Phase 2 migration](./structural-reader-phase-2-migration.md)
  — moving rules from line-walking regex to path-based
  predicates against the structural reader.

## Process

A decision-log entry is required when:

- A rule changes severity outside the documented `recall` /
  `precision` knobs.
- A suppression scope changes (job → step, file → workflow, etc.).
- A new model field affects serialization (JSON, SARIF, CSV).
- A rule's `description` or `threat_narrative` changes the
  attacker model (not just wording).

The entry lands in the same commit as the change. The PR body
links to it. Reviewers can refuse a PR that asks for any of the
above without an accompanying entry.

When a future PR reverses or extends a prior decision, append
an `## Addendum` section to the existing file rather than
creating a new one. The history reads cleaner that way.
