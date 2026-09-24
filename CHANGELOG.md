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
  project visibility review. Inherited settings alone no longer prove restricted
  access. `SEC4-GH-026` is retired; `SEC4-GH-026A` reports a visible cache write
  with explicit write access, and `SEC4-GH-026B` marks uncapped or write-capable
  reusable calls for callee review without claiming a cache write is proved.
- A static ref in a contributor repository no longer proves a trusted checkout.
  A later branch switch keeps that repository provenance, and source changes
  in steps excluded from PR execution do not affect PR builds. Package install
  findings follow source changes in step order. Shell-looking
  action inputs no longer prove that a step output is safe for shell use.
- Cache-write findings use the parsed workflow trigger, so trigger-looking
  text in a push-only shell script does not create a false warning.
- PR-source findings now track side-by-side checkout paths and the build step's
  working directory, including simple `cd` chains and run defaults. Unresolved
  paths stay visible. Cache-write rules recognize quoted literal modes and
  quoted cache action references.
- The path tracker reads source changes only from executable `run:` text outside
  shell quotes, and keeps workspace-root builds visible when command arguments
  can select an untrusted side checkout. GitHub LOTP rules also recognize
  `npm --prefix <path> ci/install` before the install verb.

### Notes
- Pure Python 3.10+, zero runtime dependencies, no telemetry.
- Maturity: **TRL 7** (demonstrated on a real corpus, CI-green, stranger-reproducible clone-and-run).
  Not yet `Production/Stable` — the Development Status classifier is `4 - Beta` until releases exist.
