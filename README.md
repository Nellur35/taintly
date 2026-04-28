# taintly

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

Security scanner for CI/CD pipelines. Reads GitHub Actions, GitLab CI, and Jenkins configuration and reports misconfigurations mapped to the [OWASP CI/CD Top 10](https://owasp.org/www-project-top-10-ci-cd-security-risks/).

- Multi-stage taint analysis with provenance — traces attacker-controlled values through `env`, `$GITHUB_ENV`, `$GITHUB_OUTPUT`, and AI-agent step outputs across steps, with full source-to-sink chains.
- Contextual exploitability — same rule, different verdict depending on whether the job has secrets, write permissions, or a fork-reachable trigger.
- AI / ML category — pickle deserialization, `trust_remote_code=True`, agent-output taint, MCP server hygiene.

Pure Python 3.10+. Zero runtime dependencies. No telemetry.

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
- uses: actions/checkout@v4  # taintly: ignore
- uses: actions/checkout@v4  # taintly: ignore[SEC4-GH-005]
```

### Remote scans

```bash
GITHUB_TOKEN=ghp_... taintly --github-org my-org
GITLAB_TOKEN=glpat-... taintly --gitlab-group my-group
taintly /path/to/repo --platform jenkins
```

## CI integration

**GitHub Actions**

```yaml
- uses: Nellur35/taintly@v1
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
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: taintly.sarif
```

## How findings are reported

Findings are grouped into **families** by root cause, not by rule ID. A workflow that pins a reusable workflow to `@main` typically trips three related rules; taintly shows one family with the rule IDs underneath.

Each finding carries three signals:

| Signal | Meaning |
|---|---|
| Severity | How serious the policy violation is |
| Confidence | How sure the detector is it found a real instance |
| Exploitability | How much damage is reachable in this particular workflow |

`--score` prints a 0–100 grade and a debt profile labelling each family Strong, Moderate, Weak, or Needs review.

## Coverage

<!-- AUTOGEN:summary -->
229 file-based rules and 21 platform-posture checks across GitHub Actions, GitLab CI, and Jenkins. Includes a dedicated AI / ML category for workflows that load models or run AI coding agents.
<!-- /AUTOGEN:summary -->

<!-- AUTOGEN:coverage -->
| Category | GitHub | GitLab | Jenkins |
|----------|--------|--------|---------|
| SEC-1 — Insufficient Flow Control | 2 | 2 | 2 |
| SEC-2 — Inadequate IAM | 4 | 3 | 3 |
| SEC-3 — Dependency Chain Abuse | 11 | 6 | 6 |
| SEC-4 — Poisoned Pipeline Execution | 25 | 9 | 8 |
| SEC-5 — Insufficient PBAC | 2 | 1 | 1 |
| SEC-6 — Insufficient Credential Hygiene | 8 | 9 | 8 |
| SEC-7 — Insecure System Configuration | 4 | 1 | 3 |
| SEC-8 — Ungoverned 3rd Party Services | 4 | 3 | 4 |
| SEC-9 — Improper Artifact Integrity | 5 | 3 | 3 |
| SEC-10 — Insufficient Logging | 4 | 2 | 1 |
| AI / ML | 35 | 16 | 12 |
| TAINT — Multi-stage taint flows | 13 | 4 | 2 |
<!-- /AUTOGEN:coverage -->

Plus 21 platform-posture rules in `--platform-audit` mode.

## Network behaviour

Local scans make no network calls. `--fix` calls `git ls-remote` to resolve action tags to commit SHAs. `--platform-audit`, `--github-org`, `--gitlab-group`, and `--transitive` call the GitHub or GitLab API and need a token.

## Requirements

Python 3.10+. No third-party dependencies.

## License

MIT
