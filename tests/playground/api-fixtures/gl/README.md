# GitLab API replay fixtures

**Status: scaffold — fixtures not yet recorded.**

This directory is referenced by `tests/playground/README.md` and by the
playground harness's drift gate (`scripts/check_doc_impl_drift.py`).
Recording real fixtures requires a GitLab token + test project, which
is out of scope for the audit pass that created this scaffold.

## What goes here

Canned GitLab REST/GraphQL responses for taintly's posture-audit code
paths (`--platform-audit` against a GitLab project). Format mirrors
`api-fixtures/gh/`: one JSON file per endpoint slug containing the
recorded response body.

## How to record

```bash
# Against a real test project you own:
GITLAB_TOKEN=... python -m taintly \
  --gitlab-project your-test-namespace/test-project \
  --platform-audit \
  --debug-record tests/playground/api-fixtures/gl/
```

(`--debug-record` is a tooling hook — see `tests/playground/README.md`
for the runtime mock pattern that doesn't need recording. Both shapes
are valid; record-once-and-replay is preferred for stability.)

## Why this README exists

So the directory exists (which the drift gate verifies) without
shipping placeholder JSON that would silently pass posture-rule
tests. The right way to fill this directory is to record real
responses; until that happens, this README documents the expected
contents.
