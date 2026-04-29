# taintly

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

Security scanner for CI/CD pipelines. Reads GitHub Actions, GitLab CI, and Jenkins configuration and reports misconfigurations mapped to the [OWASP CI/CD Top 10](https://owasp.org/www-project-top-10-ci-cd-security-risks/).

- Multi-stage taint analysis with provenance — traces attacker-controlled values through `env`, `$GITHUB_ENV`, `$GITHUB_OUTPUT`, and AI-agent step outputs across steps, with full source-to-sink chains.
- Contextual exploitability — same rule, different verdict depending on whether the job has secrets, write permissions, or a fork-reachable trigger.
- AI / ML category — pickle deserialization, `trust_remote_code=True`, agent-output taint, MCP server hygiene.

Pure Python 3.10+. Zero runtime dependencies. No telemetry.

**The score is computed against a fixed threat model:** public-OSS deployment, fork PRs reachable, runners shared, secrets repo-scoped, no OIDC-only posture. Whether a flagged pattern is actually exploitable in your deployment depends on context taintly cannot see — your network topology, your contributor policy, your runner posture. The score is a starting point for assessment, not a verdict. For details, see [docs/SCORING.md](docs/SCORING.md).

## Install

Pure stdlib, zero deps — clone and run:

```bash
git clone https://github.com/Nellur35/taintly.git
cd taintly
python -m taintly /path/to/your/repo
```

No build step, no install step, no PyPI dependency.

## Usage

```bash
python -m taintly [path] [options]
```

Common flags:

| Flag | What it does |
|---|---|
| `--score` | Print a 0–100 grade and a debt profile |
| `--format {text,json,csv,sarif,html}` | Report format |
| `--fix` / `--fix-dry-run` | Apply or preview safe auto-fixes |
| `--platform-audit` | API-based posture check (with `--github-repo` or `--gitlab-project`) |
| `--baseline [FILE]` / `--diff [FILE]` | Save a baseline, then later report only new findings |
| `--transitive` | Walk into composite actions and check sub-actions |
| `--guide [RULE_ID]` | Step-by-step remediation guide |
| `--token-stdin` | Read API token from stdin |
| `--check-imposter-commits` | Verify pinned action SHAs are reachable in their upstream repo's ref history (opt-in, network) |
| `--respect-zizmor-ignores` | Honor zizmor's inline suppression markers (opt-in) |

Run `python -m taintly --help` for the full list.

### Config file

Drop a `.taintly.yml` at the repo root:

```yaml
version: 1
min-severity: HIGH
fail-on: CRITICAL

exclude-rules:
  - SEC2-GH-001

ignore:
  - id: SEC3-GH-001
    path: legacy/
```

CLI flags override config values.

### Inline suppressions

```yaml
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # taintly: ignore
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # taintly: ignore[SEC4-GH-005]
```

`--respect-zizmor-ignores` extends recognition to zizmor's `# zizmor: ignore` / `# zizmor: ignore[<rule>]` form via a small mapped allowlist; default off.

### Remote scans

```bash
GITHUB_TOKEN=ghp_... taintly --github-org my-org
GITLAB_TOKEN=glpat-... taintly --gitlab-group my-group
taintly /path/to/repo --platform jenkins
```

## CI integration

**GitHub Actions**

```yaml
- uses: Nellur35/taintly@08298f9dd1458ecc892d4753ab08aa8fb5814f4c  # pin to a release SHA
  with:
    fail-on: HIGH
```

**GitLab CI (16.11+)**

```yaml
include:
  - component: $CI_SERVER_FQDN/nellur35/taintly/taintly@v1
    inputs:
      fail-on: HIGH
```

### SARIF output

```yaml
- run: python -m taintly . --format sarif > taintly.sarif
- uses: github/codeql-action/upload-sarif@181d5eefc20863364f96762470ba6f862bdef56b  # v3.29.2
  with:
    sarif_file: taintly.sarif
```

## Using taintly as a CI gate

The right gating shape depends on whether the codebase has existing
findings. Three patterns, each with a recipe.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed cleanly (no findings above the configured threshold, or `--fail-on` not set) |
| `1` | Scan completed with HIGH-severity findings (or with findings at or above `--fail-on` severity) |
| `2` | CLI argument error OR scan completed with CRITICAL-severity findings — distinguish via stderr (argparse usage on argument error vs. severity summary on findings) |
| `3` | Configuration error (missing config file, invalid YAML, unknown rule ID) |
| `10` | `--self-test` failed: a positive sample didn't fire, or a negative sample did, or `--integration-test` reported a non-bypass failure |
| `11` | Scan completed but coverage was degraded — at least one `ENGINE-ERR` finding present (file unreadable, ReDoS cap hit, rule crashed) |
| `12` | `--self-test --mutate` detected a surviving mutation |

CI gates should distinguish `0` from non-zero. Treating any non-zero
as "scan failed" is correct; treating non-zero as "findings exist" is
wrong because it conflates findings with scanner errors.

### Pattern A — fail-fast for clean codebases

Run on every PR. Fail the build on any HIGH-or-above finding. No
baseline. Works only if the codebase already has zero findings at the
threshold.

```yaml
# .github/workflows/security.yml
on: [pull_request]
jobs:
  taintly:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - uses: Nellur35/taintly@08298f9dd1458ecc892d4753ab08aa8fb5814f4c  # pin to a release SHA
        with:
          fail-on: HIGH
```

### Pattern B — diff-only for repos with existing findings

The realistic pattern for any non-greenfield codebase. Maintain a
baseline file in the repo; per-PR runs only fail on **new** findings.
The baseline ratchets down over time as findings get fixed.

**One-time setup** (run locally, commit the baseline):

```bash
python -m taintly . --baseline .taintly-baseline.json
git add .taintly-baseline.json
git commit -m "Add taintly baseline"
```

**Per-PR workflow:**

```yaml
on: [pull_request]
jobs:
  taintly-diff:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - uses: Nellur35/taintly@08298f9dd1458ecc892d4753ab08aa8fb5814f4c  # pin to a release SHA
        with:
          extra-args: --diff .taintly-baseline.json --fail-on HIGH
```

The baseline should be regenerated periodically (e.g., monthly) so
fixed findings don't keep counting toward the silent-acceptance set.
Don't regenerate it from a feature branch — the baseline represents
the team's agreed acceptance state of `main`.

### Pattern C — scheduled deep scan

`--check-imposter-commits` and `--platform-audit` make network calls
and shouldn't run on every PR (rate limits, latency). Run them weekly
on a schedule with results either feeding back into a tracking issue
or posting to a security channel.

```yaml
# .github/workflows/taintly-deep-scan.yml
on:
  schedule:
    - cron: '0 6 * * 1'  # Mondays 06:00 UTC
  workflow_dispatch:

jobs:
  deep-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write  # for SARIF upload
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          persist-credentials: false
      - name: Imposter-commit + platform-audit scan
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          python -m taintly . \
            --check-imposter-commits \
            --platform-audit --github-repo ${{ github.repository }} \
            --format sarif > deep-scan.sarif
      - uses: github/codeql-action/upload-sarif@181d5eefc20863364f96762470ba6f862bdef56b  # v3.29.2
        with:
          sarif_file: deep-scan.sarif
          category: taintly-deep-scan
```

The default `GITHUB_TOKEN` works for repository-scoped `--platform-audit`
checks. Org-level checks (CODEOWNERS coverage at the org level, default
workflow-permission settings) need a personal access token with
`read:org` scope; pipe it via `--token-stdin` rather than embedding in
the workflow.

For most teams, **Pattern B + Pattern C is the right combination**:
fast offline gate on every PR, slow networked check on a schedule.

### Pre-commit hook (individual contributors)

For local feedback before pushing, add a pre-commit hook to your
project's `.pre-commit-config.yaml`. taintly's CLI takes a single
positional path, not a list of files, so the hook scans the whole
repo on every commit (with `pass_filenames: false`):

```yaml
repos:
  - repo: local
    hooks:
      - id: taintly
        name: taintly (full repo, fail on HIGH)
        entry: python -m taintly .
        language: system
        pass_filenames: false
        args: [--min-severity=HIGH, --no-color]
```

This runs on every commit and fails fast if a HIGH or CRITICAL
appears anywhere in the repo's CI configuration.

### Configuration sources, in priority order

When using taintly in CI, three sources can configure it:

1. **CLI flags** (highest priority) — what the workflow sets via
   `extra-args` or `with:`.
2. **`.taintly.yml`** at the repo root — versioned config the team
   agrees on.
3. **Defaults** — what taintly does without configuration.

For CI gates, prefer `.taintly.yml` for stable settings (severity
threshold, excluded rules) and CLI flags for run-specific behavior
(`--diff`, `--check-imposter-commits`). This way the CI workflow stays
focused on invocation; the policy lives in the repo.

## How findings are reported

Findings are grouped into **families** by root cause, not by rule ID. A workflow that pins a reusable workflow to `@main` typically trips three related rules; taintly shows one family with the rule IDs underneath.

Each finding carries three signals:

| Signal | Meaning |
|---|---|
| Severity | How serious the policy violation is |
| Confidence | How sure the detector is it found a real instance |
| Exploitability | How much damage is reachable in this particular workflow |

`--score` prints a 0–100 grade and a debt profile labelling each family Strong, Moderate, Weak, Needs review, or Not applicable. "Not applicable" is reserved for families whose rules had no candidate location to evaluate in this scan — distinct from "Strong" (rules ran, nothing was wrong).

## Coverage

<!-- AUTOGEN:summary -->
231 file-based rules and 29 platform-posture checks across GitHub Actions, GitLab CI, and Jenkins. Includes a dedicated AI / ML category for workflows that load models or run AI coding agents.
<!-- /AUTOGEN:summary -->

<!-- AUTOGEN:coverage -->
| Category | GitHub | GitLab | Jenkins |
|----------|--------|--------|---------|
| SEC-1 — Insufficient Flow Control | 1 | 2 | 2 |
| SEC-2 — Inadequate IAM | 3 | 3 | 3 |
| SEC-3 — Dependency Chain Abuse | 9 | 5 | 5 |
| SEC-4 — Poisoned Pipeline Execution | 20 | 7 | 6 |
| SEC-5 — Insufficient PBAC | 2 | 1 | 1 |
| SEC-6 — Insufficient Credential Hygiene | 9 | 9 | 8 |
| SEC-7 — Insecure System Configuration | 4 | 1 | 3 |
| SEC-8 — Ungoverned 3rd Party Services | 4 | 3 | 4 |
| SEC-9 — Improper Artifact Integrity | 5 | 3 | 3 |
| SEC-10 — Insufficient Logging | 4 | 2 | 1 |
| AI / ML | 35 | 16 | 12 |
| TAINT — Multi-stage taint flows | 13 | 4 | 2 |
<!-- /AUTOGEN:coverage -->

Plus 29 platform-posture rules in `--platform-audit` mode.

## Network behaviour

Local scans make no network calls. `--fix` calls `git ls-remote` to resolve action tags to commit SHAs. `--platform-audit`, `--github-org`, `--gitlab-group`, `--transitive`, and `--check-imposter-commits` call the GitHub or GitLab API and need a token.

## Requirements

Python 3.10+. No third-party dependencies.

## License

MIT
