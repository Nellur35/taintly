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

## Addendum — corrective measurement and follow-up

After Phase 2 shipped, an adversarial-fixture measurement against
YAML shapes the schema-bounded reader's spec called supported
surfaced three behaviour differences vs. the regex form that the
Phase 2 audit corpus had not exercised.  The Phase 2 audit corpus
contained zero anchors, zero merge keys, and zero flow-style step
sequences across all 17 fixtures for the three migrated rules, so
the +0.0pp Δ F1 measurement on it could not have distinguished the
regex form from the structural form on those shapes.

Three behaviour differences and their resolutions:

- **Real precision improvement** (kept and locked in): merge keys
  on `runs-on:` now produce findings at every effectively-merged
  job, not just the anchor definition.  A YAML file defining
  `runs-on: self-hosted` once in an anchor body and merging that
  anchor into two jobs produces three SEC7-GH-001 findings
  (anchor body + both merge sites) under the structural form;
  the regex form fired only on the anchor body.  Locked in by
  `tests/fixtures/github/edge_cases/runs_on_via_merge_key.yml`
  and a line-level regression test at
  `tests/unit/test_structural_pattern_merge_keys.py`.

- **Real precision regression, fixed**: flow-style step lists
  (`steps: [{uses: ...}, ...]`) yielded no leaves for the inner
  mapping's keys.  `_consume_flow` incremented its depth counter
  on nested `FLOW_OPEN_*` tokens but never pushed a frame or
  recursed, so `KEY` tokens inside the nested mapping had no
  surrounding mapping frame to attach to and the rule glob
  `**.uses` never matched.  Rebuilt `_consume_flow` around
  recursion: nested flow containers reserve their slot in the
  outer container (next sequence index OR pending mapping key),
  pre-set the inner container's base key, and recurse.  Locked
  in by `tests/fixtures/github/edge_cases/flow_style_step_uses.yml`
  (positive) and `flow_style_step_uses_pinned.yml` (negative)
  plus three walker-level tests in `test_structural_walker.py`.

- **Triage regression, fixed**: multi-line `run: |` block scalars
  reported findings at the block-scalar header line rather than
  the line containing the dangerous match.  `LEAF_SCALAR` events
  for block scalars now carry a `block_lines` field — a tuple
  of `(source_line, body_text)` pairs — so consumers can run a
  predicate per body line and emit findings at the specific
  source line a match comes from.  `StructuralPattern` uses
  this; `Event.block_lines` defaults to `None` so existing
  call sites continue to construct events without modification.
  Locked in by
  `tests/fixtures/github/edge_cases/block_scalar_run_with_pr_title.yml`
  and three line-level tests in
  `tests/unit/test_structural_pattern_block_scalars.py`.

### Phase 3 status

The +0.0pp Δ F1 against the Phase 2 audit corpus briefly suggested
a "park reader" outcome.  The corrected picture (one real win,
one real bug, one triage regression — all addressed in this PR)
plus the observation that the audit corpus contained none of the
YAML shapes the structural reader was built for makes parking no
longer the best read of the data.  Whether to expand to more
migrations remains gated on:

1. A migration of at least one TAINT-class rule (where structural
   access has the highest theoretical payoff for nested-variable
   analysis).
2. A measurement on an expanded fixture set that exercises the
   shapes the reader is for, including the five new fixtures
   under `tests/fixtures/github/edge_cases/`.

Phase 3 stays open pending that experiment.
