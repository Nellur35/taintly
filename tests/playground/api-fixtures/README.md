# api-fixtures/ — canned REST responses for posture-rule tests

Recorded HTTP responses replayed by ``test_platform_audit_replay.py``
so platform-audit checks (PLAT-GH-*, PLAT-GL-*) can be exercised in CI
without real auth tokens or live API calls.

## Naming convention

Endpoint path → filename slug, ``/`` replaced with ``__``, leading slash
dropped.  ``null`` and ``[]`` are valid contents (404 absence signal /
empty list).

```
GET /repos/test-org/unprotected-repo
  → api-fixtures/gh/repos__test-org__unprotected-repo.json
GET /repos/test-org/unprotected-repo/branches/main/protection
  → api-fixtures/gh/repos__test-org__unprotected-repo__branches__main__protection.json
```

## Adding a new fixture

1. Pick the test scenario (e.g. "repo with classic branch protection").
2. Write canned JSON for every endpoint the check function calls.
3. Wire it into a new test in ``test_platform_audit_replay.py`` —
   the harness below uses a tiny ``RecordedClient`` that maps endpoints
   onto these files.
4. Optional: capture real responses one-time by running a recording
   wrapper around ``GitHubClient._request`` against a real test repo
   (we don't ship a recorder — recording is rare; hand-curating works
   for the test scenarios we care about).

## Why hand-curated, not VCR-recorded

VCR-style recording captures a moment in time; real API responses
have rate-limit headers, request IDs, timestamps that drift and
make diffs noisy.  Hand-curated fixtures are the minimal data the
check function needs to reach its decision — ~5 lines of JSON each,
audit-friendly, version-controlled without churn.
