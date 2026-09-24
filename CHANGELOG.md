# Changelog

All notable changes to taintly are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

taintly is pre-1.0 and has **no tagged releases yet** — everything below is `Unreleased`. When the
first version is tagged, its entries move under a dated `[x.y.z]` heading and the
[GitHub Releases page](https://github.com/Nellur35/taintly/releases) mirrors them.

## [Unreleased]

### Added
- Multi-stage taint analysis with provenance across GitHub Actions, GitLab CI, and Jenkins.
- Cross-artifact and cross-workflow taint tracking (composite actions, reusable workflows).
- Kill-chain composition — individually-lower-severity findings correlated into an exploitable-chain
  CRITICAL.
- Contextual exploitability — same rule, different verdict depending on job context (secrets, write
  permissions, fork-reachable trigger).
- AI / ML category — pickle deserialization, `trust_remote_code=True`, agent-output taint, MCP
  server hygiene.
- Distribution surfaces: composite GitHub Action (`action.yml`), pre-commit hooks
  (`.pre-commit-hooks.yaml`), and a pip-installable package with a `taintly` console entry point.

### Changed
- Refined CI findings with job-level permission coverage, ordered PR-source checks,
  executable reusable-workflow input sinks, and same-job output value proofs.
- `SEC9-GL-001` now requires a strongly sensitive artifact path and still asks for
  project visibility review. `SEC4-GH-026` is retired; `SEC4-GH-026A` reports
  explicit write-capable cache access on low-trust GitHub workflows.

### Notes
- Pure Python 3.10+, zero runtime dependencies, no telemetry.
- Maturity: **TRL 7** (demonstrated on a real corpus, CI-green, stranger-reproducible clone-and-run).
  Not yet `Production/Stable` — the Development Status classifier is `4 - Beta` until releases exist.
