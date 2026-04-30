# Decision: Phase 2 of the structural reader — three migrations + measurement framing

**Status**: accepted (current behaviour as of Phase 2 PR)

## Context

Phase 1 of the structural CI YAML reader shipped a path-extraction
reader without migrating any existing rules (see
`docs/STRUCTURAL_READER_SCOPE.md`).  The Phase 2 contract was: pick
the top-3 rules by use-count from the audit, migrate them to
`StructuralPattern`, measure F1 delta against a labelled corpus,
and decide based on the data whether to expand or park.

## What Phase 2 actually shipped

Three rule migrations, locked in advance by the
`(use_count desc, known_precision_issue_rank desc)` ranking:

1. **`jobs.*.steps[*].run` (rank 1, 77 rules)** — first migration
   target was specified as **SEC4-GH-004** (script injection via
   attacker-controlled GitHub context).  Migrated to a structural
   form that scopes the query to ``**.run`` directly; the path
   filter does the structural job the original regex's three
   exclude clauses (comment lines, ``if:`` context,
   value-is-the-whole-expression) were approximating.
2. **`jobs.*.runs-on` (rank 2, 55 rules)** — first migration
   target was specified as SEC8-GH-001 in the Phase 1 PR body.
   That was a misread: SEC8-GH-001 is the ``image: latest`` rule;
   the actual self-hosted-runner rule is **SEC7-GH-001**.  Phase
   2 migrated SEC7-GH-001 instead and recorded the correction
   here.  The migrated form queries both ``**.runs-on`` and
   ``**.runs-on[*]`` so the string and flow-sequence shapes both
   resolve cleanly.
3. **`jobs.*.steps[*].uses` (rank 3, 54 rules)** — first migration
   target **SEC3-GH-001** (unpinned action).  The migration sketch
   from the Phase 1 PR body landed verbatim; the predicate's
   conditions match the original RegexPattern's exclude list.

A new module `taintly/structural_pattern.py` holds the
`StructuralPattern` class.  Two API choices made during the build
that aren't pre-committed in Phase 1:

- **Multiple path globs.**  ``StructuralPattern.path`` accepts
  either a single glob or a list.  The list shape is the right
  primitive for keys with ``string-or-sequence-of-string``
  schemas (``runs-on`` is the canonical case).  String form
  remains the dominant shape; the list form is opt-in per rule.
- **CUTOFF-only-with-leaves.**  The walker emits a CUTOFF event
  whenever the tokenizer hits an unsupported construct.  The
  pattern only forwards CUTOFF as a `STRUCTURAL-CUTOFF` finding
  when at least one leaf was emitted before the cutoff —
  otherwise the file is wholly unparseable and the rule silently
  no-ops.  This avoids spurious findings on Jenkinsfiles fed
  through GitHub-only rules by the no-rules-change gate.

## Behavior diffs surfaced by the no-rules-change gate

After the three migrations, the gate flagged ONE fixture drift
across the 102-file corpus:

- **`github/edge_cases/crlf_endings.yml`**: the fixture's bytes
  contain literal `\r\n` text (four characters: backslash, r,
  backslash, n) — NOT real CR+LF line endings.  The original
  regex form fired SEC3-GH-001 because its match window saw a
  single 177-byte "line" with `uses:` somewhere in it.  The
  structural form correctly identifies the content as
  unparseable as YAML and silently no-ops.

This is a precision improvement, not a regression, and the
baseline at `tests/_rule_pack_hashes.json` is updated to reflect
the new (correct) behaviour.

## What this PR is NOT a measurement of

The Phase 2 contract specified an F1-delta measurement against a
**private labelled corpus** (the maintainer's benchmark, not in
this repo).  The public fixture corpus + self-test pack confirm
**equivalent or improved precision** on every case the open repo
exercises, but they don't constitute the F1 measurement the
Phase 3 decision was supposed to gate on.

That measurement is on the maintainer to run.  The decision shape
remains as recorded in the Phase 1 plan:

- ≥ +2pp F1 delta average → Phase 3 expands migrations.
- +1 to +2pp → reassess scope before Phase 3.
- ≤ +1pp → park the reader.  The three migrated rules stay
  migrated as sunk cost; no further migrations until new evidence.

## Reopening criteria for the parking decision

If the F1 measurement comes in below +1pp, the reader is parked
and these conditions trigger reopening:

1. A new rule's threat shape genuinely requires structural access
   (e.g., reasoning about path-relative properties that no regex
   can express cleanly).  Migrate that one rule using the
   existing infrastructure; don't re-evaluate the whole reader.
2. A regex-rule precision issue in the cross-tool benchmark
   surfaces a path the structural form would obviously help.
   Migrate that rule; don't re-evaluate the whole reader.
3. Schema-driven shape disambiguation (Phase 1.5) lands and
   measurably reduces predicate complexity in already-migrated
   rules.  Re-evaluate the broad expansion.

Without one of these, the parking decision stands.

## Related artifacts

- `taintly/structural_pattern.py` — the StructuralPattern class.
- `taintly/parsers/structural/` — the Phase 1 reader.
- `docs/STRUCTURAL_READER_SCOPE.md` — supported/unsupported scope.
- `scripts/audit_rule_paths.py` — the audit ranking that locked
  the Phase 2 rule choice.
- `scripts/no_rules_change_gate.py` — the rule-output stability
  gate that surfaced the CRLF precision change.
