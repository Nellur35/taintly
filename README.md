# taintly

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

Taintly scans CI/CD configuration for GitHub Actions, GitLab CI, Jenkins and
AWS CodeBuild. It follows supported inputs to the commands and other consumers
that use them, records where the evidence comes from, and reports known gaps
in analysis. Checks include [secret-derived HTTP transfers](docs/SECRET_NETWORK_FLOW.md)
and selected risks in AI-agent pipelines and MCP configuration.

Python 3.10+. Zero mandatory runtime dependencies. No telemetry. Local scans
read configuration offline. Runtime execution, effective permissions, and
external sources can require additional evidence.

## Install

Pure stdlib, zero deps — clone and run:

```bash
git clone https://github.com/Nellur35/taintly.git
cd taintly
git checkout --detach e6e494d105693187b3d9c91b4c966e96e22d0610
python -m taintly /path/to/your/repo
```

No build step, no install step, no PyPI dependency. This pins the scanner source
to the reviewed commit used below; no release tag is assumed.

## Usage

### Read a finding and confirm the fix

Put this example in a separate target repository as `.github/workflows/ci.yml`.
The scanner reads the file locally.

```yaml
name: Example
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
```

Run `python -m taintly /path/to/your/repo` from the scanner checkout. In
the text report, SEC10-GH-001 points to the job missing an explicit timeout.
Add `timeout-minutes: 10` at the same indentation as `runs-on`, then run the
same scan again. That finding clears. Read other findings and coverage
diagnostics separately.

Use `python -m taintly /path/to/your/repo --format json` for machine-readable results. A
finding describes the supported configuration evidence and includes remediation.
The report distinguishes review-needed findings and incomplete analysis.

## CI integration

**GitHub Actions** — after checking out the target repository:

```yaml
- uses: Nellur35/taintly@e6e494d105693187b3d9c91b4c966e96e22d0610  # reviewed commit
  with:
    version: e6e494d105693187b3d9c91b4c966e96e22d0610
    fail-on: HIGH
```

The `uses:` SHA selects the Action wrapper; `version` independently selects the
installed scanner source. Both inputs use immutable commits. Review each
component before updating its pin; they need not share a commit. The Action
sets up Python and installs from GitHub, which needs network access during
setup. Its local configuration scan is offline unless network options are
explicitly enabled.

See [CI integration](docs/CI_INTEGRATION.md) for GitLab CI, SARIF, trusted policy and baseline examples.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No HIGH or CRITICAL findings, no configured `--fail-on` threshold reached, and no coverage error |
| `1` | HIGH finding or configured `--fail-on` threshold reached; coverage may also be degraded |
| `2` | CLI argument error OR CRITICAL-severity findings — distinguish via stderr (argparse usage on argument error vs. severity summary on findings) |
| `3` | Initialization or configuration error (rule module failed to load, missing config file, invalid YAML, unknown rule ID) |
| `10` | `--self-test` failed: a positive sample didn't fire, or a negative sample did, or `--integration-test` reported a non-bypass failure |
| `11` | Reported coverage error, unless a severity exit (`1` or `2`) takes precedence — at least one `ENGINE-ERR` finding present (file unreadable, ReDoS cap hit, rule crashed) |
| `12` | `--self-test --mutate` detected a surviving mutation |

The table describes the default severity gate. With `--review-advisory`, the
gate considers findings without the review-needed marker. Review findings stay
in the report and coverage errors still apply. Creating a baseline accepts
existing security findings rather than fixing them. It returns
`0` when creation succeeds without a reported coverage error; incomplete analysis
still returns `11`, even when the snapshot was written.

CI gates should distinguish `0` from non-zero. A non-zero result can mean
findings, a scanner error, or both. Inspect JSON `errors`
as well as the exit code: a HIGH/CRITICAL finding and a coverage error can
coexist. Exit `0` does not prove complete semantic coverage.

When an explicitly selected file resolves outside the repository, taintly
refuses it and reports a coverage error. Jenkins discovery also reports
refused pipeline paths. During a Jenkins controller audit, check failures
are reported as coverage errors alongside findings from successful checks.

## Platform support

| Platform | Examples of supported analysis | Important boundary |
|---|---|---|
| GitHub Actions | Expressions, environment and output propagation, local action/workflow calls, permissions and source-to-consumer paths | Available source and supported ownership/condition profiles determine which paths can be joined. |
| GitLab CI | Owned job/script structure, variable consumers, artifact selections and bounded job-token transfers | Includes, variable precedence, runner behavior and external settings can leave questions unresolved. |
| Jenkins | Jenkinsfile structure, credential bindings, Groovy/shell boundaries and bounded HTTP consumers | Plugin/job configuration, checkout identity and unsupported Groovy remain separate evidence requirements. |
| AWS CodeBuild | Buildspec configuration, secret declarations, bounded shell/body transfers and secret build arguments. An optional project snapshot identifies a configured buildspec at a pinned commit. | Runtime overrides, effective IAM and actual execution require separate evidence. |

The platforms have different supported profiles. A rule inventory is not a
measure of equal coverage, precision or recall. See the exact
[secret-transfer profiles](docs/SECRET_NETWORK_FLOW.md),
[structural-reader scope](docs/STRUCTURAL_READER_SCOPE.md) and
[Jenkinsfile-reader scope](docs/JENKINSFILE_READER_SCOPE.md).

## Coverage

<!-- AUTOGEN:summary -->
336 file-based rules and 32 platform-posture checks across GitHub Actions, GitLab CI, Jenkins, and AWS CodeBuild. Includes a dedicated AI / ML category for workflows that load models or run AI coding agents.
<!-- /AUTOGEN:summary -->

<!-- AUTOGEN:coverage -->
| Category | GitHub | GitLab | Jenkins | CodeBuild |
|----------|--------|--------|---------|-----------|
| SEC-1 — Insufficient Flow Control | 6 | 3 | 2 | 0 |
| SEC-2 — Inadequate IAM | 7 | 4 | 3 | 0 |
| SEC-3 — Dependency Chain Abuse | 35 | 19 | 14 | 4 |
| SEC-4 — Poisoned Pipeline Execution | 77 | 30 | 24 | 2 |
| SEC-5 — Insufficient PBAC | 3 | 1 | 2 | 0 |
| SEC-6 — Insufficient Credential Hygiene | 17 | 13 | 14 | 5 |
| SEC-7 — Insecure System Configuration | 4 | 1 | 4 | 0 |
| SEC-8 — Ungoverned 3rd Party Services | 6 | 3 | 5 | 0 |
| SEC-9 — Improper Artifact Integrity | 7 | 5 | 4 | 2 |
| SEC-10 — Insufficient Logging | 5 | 3 | 2 | 0 |
| AI / ML | 0 | 0 | 0 | 0 |
| TAINT — Multi-stage taint flows | 0 | 0 | 0 | 0 |
<!-- /AUTOGEN:coverage -->

The table groups rules by their primary OWASP category. AI and taint rules
mapped into those categories are counted there, so zero in their separate rows
does not mean those analyses are absent. Counts describe the inventory, not
verified coverage of every question or every standard.

The 32 API-based platform-posture checks cover GitHub, GitLab and Jenkins
settings; they do not imply a CodeBuild project/IAM posture audit.

## Documentation

- [CI patterns, configuration, and report interpretation](docs/CI_INTEGRATION.md)
- [Saved publication, build, and deployment observations](docs/SAVED_OBSERVATIONS.md)
- [Scoring and review status](docs/SCORING.md) and [deployment context](docs/CONTEXT.md)
- [Expression analysis](docs/EXPRESSION_ANALYSIS.md)
- [Secret-derived HTTP transfers](docs/SECRET_NETWORK_FLOW.md)
- [Structural-reader limits](docs/STRUCTURAL_READER_SCOPE.md) and [Jenkinsfile-reader limits](docs/JENKINSFILE_READER_SCOPE.md)
- [Canaries](tests/canaries), [mutation checks](taintly/testing/mutations.py),
  and [public repository finding budgets](scripts/check_public_repo_fp_budget.py).
  The budgets detect changes in finding volume on pinned inputs.

## License

[MIT](LICENSE)
