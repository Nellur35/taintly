# Repository boundary

taintly uses a two-repo boundary.

## `taintly-private`

`taintly-private` is the internal engineering and R&D source of truth.

Keep these artifacts private:

- unreleased features and work-in-progress implementation notes,
- benchmark harnesses and corpus runners,
- cross-tool evaluation,
- field-validation operations,
- reviewer notes and adjudication sheets,
- raw scan outputs,
- raw corpus inventories,
- third-party repository names, paths, or identifying details,
- Phase 8 reopening evidence for permissions-neutralization,
- private experiments and exploratory docs.

## Public `taintly`

Public `taintly` is the sanitized product and tool repository.

It may contain:

- the scanner package,
- CLI and integration files,
- public docs,
- safe examples,
- tests safe to publish,
- sanitized design and decision docs,
- methodology that explains how evidence should be collected without exposing
  the evidence itself.

## Never push to public

Do not commit these to public `taintly`:

- raw third-party scan results,
- repo-identifying field-validation artifacts,
- local filesystem paths from validation runs,
- private reviewer notes,
- corpus inventories,
- benchmark output,
- labels or adjudications tied to named third-party repositories,
- unreleased feature plans that depend on private evidence.

If an artifact exists to operate a corpus, evaluate another scanner, record
reviewer judgments, or decide whether to reopen a deferred suppression feature,
it belongs in `taintly-private`.
