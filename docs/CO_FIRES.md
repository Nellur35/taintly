# Rule co-fire matrix

Several rules in the taintly pack are designed to *intentionally co-fire* on
the same line. This document explains why so users don't read the duplication
as the tool double-counting.

It also lists **same-condition rule pairs that have been retired** —
duplicates that used to co-fire and were collapsed.

---

## Retired duplicates

Three GitHub-side same-condition pairs have been collapsed:

| Retired pair | Reason | Surviving rule |
|---|---|---|
| `SEC8-GL-002` (HIGH) | identical condition to `SEC3-GL-002`, same severity | `SEC3-GL-002` |
| `SEC6-GH-011` (MEDIUM) | identical condition to `SEC4-GH-012`, latter is HIGH | `SEC4-GH-012` |
| `SEC8-GH-003` on branch refs | covered by `SEC3-GH-002` (CRITICAL); SEC8-GH-003 retains the tag-pin case | `SEC3-GH-002` for branches; `SEC8-GH-003` for tags |

After these retires, the only remaining co-fires are *intentional layered
findings* — different threat angles on the same line.

## Intentional co-fires (NOT duplicates)

### AI agent on PR cluster

When an AI coding agent step appears in a workflow with PR-reachable triggers
and broad permissions, multiple AI rules layer up to convey *what* makes the
configuration risky:

| Rule | Layer it adds |
|---|---|
| `AI-GH-006` | "agent runs on a fork-triggerable event" |
| `AI-GH-008` | "agent runs in a job that checks out PR code" |
| `AI-GH-015` | "agent has repo-write permission on a fork-reachable trigger" |
| `AI-GH-020` | "agent has no tool allowlist" |
| `AI-GH-021` | "agent runs in a job that checks out PR head code (settings-file poisoning vector)" |
| `PSE-GH-001` | "agent has cloud credential grant on a fork-reachable event" |

These are *intentionally additive* — each fires only when its specific
condition is met, but on a sufficiently misconfigured workflow several can
fire simultaneously. The reporter clusters them into the
`prompt_injection_into_agent_action` family so a user sees one cluster with N
findings rather than N independent alerts.

### LOTP cluster

`LOTP-GH-001`, `LOTP-GH-004`, `SEC4-GH-011` all share the build-tool anchor
regex but check different *conditions* on the surrounding job:

| Rule | Condition |
|---|---|
| `LOTP-GH-001` | build tool runs in a job that checks out PR code |
| `LOTP-GH-004` | build tool runs after `actions/download-artifact` (untrusted artifact) |
| `SEC4-GH-011` | build tool runs in a `pull_request_target` workflow |

A workflow that does ALL THREE (PR-target trigger, PR checkout, then
download-artifact + build) trips all three rules. That's the correct
behavior — each rule names a distinct attack path.

### Hardcoded-secret + secret-in-shell

`SEC6-GH-001` (hardcoded secret detector) and `SEC6-GH-005` (secret in shell
command) are deliberately separate rules; one catches the value at rest in
YAML, the other catches it as it reaches the shell.

---

## Engine-level severity calibration

Some rules fire at one severity but get *downgraded* by an engine
postprocessor when context demands it. These are not duplicates either — they
fire once and get rescored:

| Rule | Original | Downgraded to | Trigger condition for downgrade |
|---|---|---|---|
| `SEC4-GH-018` | HIGH | MEDIUM | workflow only triggers on `push: tags` / `release:` / `workflow_dispatch` / `schedule` (maintainer-gated) |

See `taintly/engine.py::_downgrade_maintainer_gated_findings` for the full
list.

---

## Adding a new rule that intentionally co-fires

When designing a rule that will share an anchor or condition with an existing
rule:

1. **Assert the rules add distinct information.** If two rules say the same
   thing about the same line at different OWASP categories, retire one
   (see the retired-duplicates list above).
2. **Name the layer in the title.** A user reading two findings on one line
   should be able to distinguish "agent has PR checkout" from "agent has
   write permissions" from "agent has no tool allowlist" without reading the
   full description.
3. **Add the new rule to the relevant `FindingFamily.members` set in
   `taintly/families.py`** so the reporter clusters them.
4. **Add a regression test in `tests/unit/test_precision_fixtures.py`** that
   pins the co-fire shape — both rules MUST fire together on the same
   minimal fixture.

## Reporting bugs

If you see two rules firing on the same line at *different severities for
identical conditions*, that's a dedup candidate. File an issue with:

- The two rule IDs
- The minimal fixture that triggers both
- Which severity you'd expect to win

Prior audits surfaced three such pairs; future passes will close the
ones below INFO threshold that automated auditing didn't surface.
