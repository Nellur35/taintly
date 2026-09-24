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
  shell quotes, comments, and static heredoc data. A trusted root build stays
  silent beside an unrelated untrusted checkout; a literal npm `--prefix`
  selects the source path for that build. Unresolved paths stay visible.
  GitHub LOTP rules also recognize `npm --prefix <path> ci/install` before the
  install verb.
- Complete static heredoc delimiters and their closing indentation are checked
  before suppressing data lines. Local pip project and requirements paths select
  the source checkout; multiple local paths stay visible. Build text in inline
  shell comments or action inputs no longer counts as an executed command.
- Local pip editable installs with named checkout paths are recognized. PR
  source proof comes from checkout fields or executable Git changes, so PR
  metadata logged by a trusted workflow does not create a build finding.
- Multiple static heredocs are read in order; pip local-path options accept
  separated and equals forms. `HEAD` and fetch-derived Git refs do not prove
  trusted source. Executable Git PR switches can establish source evidence
  without a checkout `ref` value; an unresolved default checkout stays visible.
- PR-ref `git fetch` now carries source provenance into `FETCH_HEAD` and named
  remote branches across steps. Git source checks read the checkout argument,
  and compact pip `-e`/`-r` paths select the correct checkout.
- GitHub's `pull/ID/head` fetch form is recognized. Later fetches update
  `FETCH_HEAD` provenance, and printed Git text does not change it. Pip local
  installs are found after other options without treating output directories
  or named package installs as local source builds.
- Every build command on a shell line is checked in order. Conditional Git
  fallbacks preserve uncertain source provenance; pip certificate paths are
  not install targets, and quoted `bash -c`/`sh -c` pip installs are inspected.
- Pip global flags before `install` and literal nested shell commands are
  inspected in source order. Printed build commands stay silent.
- Literal child shell scripts are inspected when followed by outer commands
  or prefixed with `env`; their directory changes stay local to the child.
  Non-install pip subcommands no longer count as builds.
- Child shells inherit the outer working directory at their execution point;
  repeated pip verbosity flags preserve the local install path.
- Executable Git fetch commands parse options and forced refspecs for PR head
  and merge refs; GitHub CLI PR checkout changes source provenance.
- Git global options, GitHub CLI PR URLs and worktree destinations are
  tracked; dry-run fetches do not alter source provenance.
- Git global options before checkout and changed fetch-remote URLs now carry
  repository provenance into later local builds.
- PR fork fetches through a new remote or direct URL, including `clone_url`,
  now retain untrusted source provenance; appended fetch URLs keep their order.
- Fetched refs now retain provenance through Git reset, merge, and
  remote-tracking branch checkout; known base-repository fetches stay trusted.
- Local branch changes, Git pull and clone paths, and exact fetched refs now
  preserve source provenance through later local builds.

### Notes
- Pure Python 3.10+, zero runtime dependencies, no telemetry.
- Maturity: **TRL 7** (demonstrated on a real corpus, CI-green, stranger-reproducible clone-and-run).
  Not yet `Production/Stable` — the Development Status classifier is `4 - Beta` until releases exist.
