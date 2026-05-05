# tests/playground/ — light e2e

End-to-end coverage for taintly that **doesn't** require Docker, real
servers, or real auth tokens.

## Layout

```
fixtures/
  github/<rule-or-family>/
    vulnerable.yml         # MUST trigger the named rule(s)
    fixed.yml              # post-fix golden — MUST be clean (or list residuals)
    expect.json            # {"must_fire": [...], "must_not_fire": [...]}
  gitlab/<rule-or-family>/
  jenkins/<rule-or-family>/
  ai-gh/<rule-or-family>/  # may need a repo-root layout (CLAUDE.md + .github/)
  fake-secrets/            # canonical-fake credentials (allowlisted in .gitleaks.toml)

api-fixtures/
  gh/<endpoint-slug>.json  # canned GitHub REST responses for replay-mode tests
  gl/<endpoint-slug>.json  # same for GitLab

test_playground.py             # walks fixtures/, scans, asserts must_fire
test_platform_audit_replay.py  # mocks API client, replays api-fixtures/
```

## Why this exists

We can't test taintly's network-dependent flags (`--platform-audit`,
`--check-imposter-commits`) against the real APIs in CI without
real tokens.  We can't run real GitHub/GitLab/Jenkins instances in CI
without heavy Docker.  But taintly is a **static analyzer** — its only
network surface is a small set of REST API calls.  Recording those
responses once and replaying them in tests covers ~95% of behavioural
correctness at ~5% of the infrastructure cost.

## Adding a fixture

1. Pick a rule (or rule family) you want to lock in.
2. Make a directory under `fixtures/<platform>/<rule-id-lower>/`.
3. Drop a single `vulnerable.{yml,Jenkinsfile,...}` that fires the rule.
4. (Optional) Add a `fixed.{yml,...}` showing the post-fix shape.
5. Write `expect.json`:
   ```json
   {
     "must_fire": ["SEC4-GH-001"],
     "must_not_fire": ["SEC6-GH-001"],
     "fix_invariants": {
       "still_parses": true,
       "jobs": ["build", "test"]
     }
   }
   ```
6. Run `pytest tests/playground/`.

## Recording an API fixture

For posture-rule e2e (`--platform-audit`):

```bash
# Record once against a real test org
GITHUB_TOKEN=... python -m taintly --github-repo your-test-org/test-repo --platform-audit --debug-record tests/playground/api-fixtures/gh/
```

(`--debug-record` is a tooling hook — see the test harness for the
runtime mock pattern that doesn't need recording.)

## Fake credentials policy

Use ONLY the canonical-fake patterns documented in `fake-secrets/`:
AWS `AKIAIOSFODNN7EXAMPLE`, GitHub `ghp_FAKE...`, etc.  Real-shape but
documented-fake values are allowlisted in `.gitleaks.toml` and ignored
by GitHub push protection.
