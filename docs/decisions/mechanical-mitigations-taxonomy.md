# Mechanical Mitigations Taxonomy

Status: Phase 1 partial implementation.

## Context

Some CI/CD findings are syntactically valid but mechanically unreachable or materially less exploitable because the workflow itself constrains execution. These mitigations belong after raw detection. Rule definitions keep describing the unsafe primitive; the engine decides whether workflow mechanics suppress or calibrate the emitted finding.

## Taxonomy

1. Static dead execution
   Jobs or steps whose `if:` expression is provably false from literals or repository identity.

2. Runtime-gated execution
   Jobs or steps whose `if:` expression depends on event payloads, inputs, matrix values, functions, status checks, secrets, or other runtime facts.

3. Maintainer-gated attacker input
   Values that can be chosen only by a maintainer-equivalent actor in the scanned workflow's trigger set, such as tag names or `workflow_dispatch` inputs when no fork-reachable companion trigger is present.

4. Deployment-context mitigation
   Facts outside the workflow file, such as external PRs being blocked or runners being isolated. This is deferred to context intelligence because it must not be guessed from YAML alone.

5. Capability neutralization
   Permissions or token scopes that make a detected primitive non-exploitable. This is deferred until rule-to-capability metadata is designed and validated.

## Shipped Now

- Literal static `if:` handling for `true`, `false`, `! true`, and `! false`.
- Repository and repository-owner equality handling when repo identity is known.
- Dead job and dead step suppression for GitHub Actions findings.
- Maintainer-gated severity downgrade for existing `github.ref_name` script-injection cases.
- Maintainer-gated severity downgrade for `SEC4-GH-008` workflow-dispatch input shell interpolation.

## Deferred

- General GitHub Actions expression evaluation.
- Matrix, status-function, secret, env, input, and event-payload evaluation.
- Trigger-level suppression for dead-only workflows.
- Deployment-context scoring.
- Permissions-neutralization suppression.

## Reopening Criteria

Reopen this taxonomy when field measurement shows any of the following:

- Dead-job or dead-step false positives persist because a common static expression form is unsupported.
- A maintainer-gated downgrade hides a confirmed externally reachable exploit path.
- A deployment-specific mitigation appears repeatedly enough to justify structured context input.
- Capability neutralization can be mapped per rule with reviewable evidence and regression tests.

## Addendum — wiring and coverage follow-up

The initial implementation of mechanical-mitigation suppression
shipped with several silent feature-incompleteness gaps surfaced
by field testing:

- The `--github-repo` CLI flag was registered for `--platform-audit`
  only; the scan path used `git remote` auto-detection exclusively.
  Users running on non-git directories or repositories whose remote
  is not named `origin` saw no static-guard suppression and no
  warning explaining why.
- `evaluate_if` did not strip outer YAML quotes around `${{ }}`
  expressions, so a syntactically equivalent but YAML-quoted `if:`
  value (recommended by some style guides to disambiguate from
  `${{` syntax) fell through to RUNTIME.
- `find_dead_line_ranges` walked the file line-by-line to extract
  job and step `if:` values, which does not resolve YAML anchors or
  merge keys. Jobs inheriting `if:` via `<<: *anchor` were treated
  as having no guard.
- `_github_dead_postprocessor` ran on every scanned file, including
  GitLab CI files and Jenkinsfiles, where the GitHub-shaped walk
  produced no suppressions but performed wasted work and was
  inconsistent with the GitLab and Jenkins postprocessors that gate
  on platform.
- `GitLabContext` and `JenkinsContext` dataclasses defined fields
  that suggest context-aware suppression is wired up, but the
  engine constructed both with all defaults on every scan; a reader
  could reasonably assume otherwise.

The follow-up addressed all of the above by extending the flag's
semantics to cover the scan path (with explicit-flag-wins-over-
auto-detection precedence), fixing the strip helper to unwrap
YAML-quoted `${{ }}` expressions while leaving bare quoted strings
as RUNTIME, migrating `find_dead_line_ranges` to the structural
reader (which already resolves merge keys correctly), adding a
platform guard to `_github_dead_postprocessor` parallel to the
GitLab and Jenkins counterparts, and documenting the GitLab and
Jenkins context dataclasses as currently-unwired with a note that
they should be populated when corpus evidence demands.

The conservatism principle held throughout: each gap was a false
negative (failure to suppress where suppression was warranted),
never a false positive. No silent loss of coverage was introduced;
the fixes only added coverage that the architecture was designed
to support.

The lesson worth carrying forward: spec rounds for features with
multiple input paths (CLI flag + auto-detection, multiple
syntactic forms of the same construct) need explicit
**negative-path verification** — tests that assert "the flag
actually does something" or "the equivalent form actually produces
the same result." Those tests now live in
`tests/unit/test_staticguard.py` and
`tests/integration/test_github_repo_flag_scan_path.py`.

## Addendum — whole-workflow suppression for fully-dead workflows

The original taxonomy entry deferred whole-workflow suppression:
when every job in a workflow is statically dead (`if: false` or
repo-mismatch), per-job suppression removes findings inside the
job bodies but leaves trigger-level findings on the `on:` block
alone.  The reopening criterion was field-testing evidence —
enough real-world FPs in this shape to justify the soundness
margin.

Field testing on real-world repositories produced trigger-level
FPs across multiple workflows that share this exact shape: each
workflow has a fully-dead job whose body is suppressed correctly,
but the `on:` block's `pull_request_target:` declaration produces
SEC4-GH-001 / SEC4-GH-002 findings despite the workflow never
being able to run.  That meets the threshold.

The follow-up adds `is_workflow_whole_dead` to
`taintly/staticguard.py`.  The function enumerates every job in a
workflow via the structural reader and returns `True` only when
every job's `if:` guard evaluates to STATIC_FALSE.  The engine's
GitHub post-processor calls it before per-job suppression; when
true, all findings in the file are cleared.

The conservatism principle holds by construction:

- A workflow is "whole-dead" only when every job is STATIC_FALSE.
- Any RUNTIME job (the default for runtime-dependent expressions
  like `${{ inputs.deploy }}` or function calls) prevents
  whole-dead classification.
- Any STATIC_TRUE job (a guard that resolves true purely from
  literals — e.g., `if: github.repository == 'self'` when the
  repository matches) prevents whole-dead classification.
- A workflow with no jobs is not "whole-dead" — there is nothing
  to call dead.

The static evaluator's own conservatism (literal-only,
repo-match only when context is known) carries through.  A
workflow with three `if: false` jobs and one `if: ${{ inputs.deploy
}}` job is not whole-dead, even though the fourth job's RUNTIME
outcome is unknown.

The platform analog for GitLab and Jenkins is intentionally not
shipped here.  Each platform's "whole-dead" condition has different
semantics (GitLab `rules:` chains, Jenkins declarative `when {}`
blocks).  When field testing surfaces equivalent FP volume in
either platform's corpus, those follow-ups have clear shape.

## Addendum — whole-pipeline suppression for GitLab and Jenkins

The previous addendum deferred the GitLab and Jenkins analogs of
whole-workflow suppression pending field-test evidence and
platform-specific semantic clarity.  Both shipped together in this
follow-up.

GitLab: `is_pipeline_whole_dead` in `taintly/gitlabguard.py` walks
every job in `.gitlab-ci.yml` and returns true iff every job's
`rules:` chain evaluates to `GuardVerdict.DEAD`.  The dead
determination respects GitLab's rule-chain semantics: a bare
`when: never` rule means "skip"; an `if: 'false'; when: never`
chain matches no rule and falls through to the default
`when: on_success`, which is LIVE — so that shape correctly
prevents whole-dead classification.

Jenkins: `is_jenkinsfile_whole_dead` in
`taintly/jenkinsguard.py` walks every stage in a declarative
pipeline and returns true iff every stage's `when` block
evaluates to `GuardVerdict.DEAD`.  Scripted Groovy pipelines
(without an explicit `stages { ... }` block) return false —
there is no structural enumeration target for them and the
conservative answer is "not whole-dead."

Each platform's postprocessor calls its whole-pipeline check
before per-job/per-stage suppression: `findings.clear()`
short-circuits the file when whole-dead.  Conservatism holds by
construction — any RUNTIME job/stage prevents whole-dead
classification.

The platform contexts (`GitLabContext`, `JenkinsContext`) remain
unwired — their fields exist for extensibility (e.g.,
`$CI_PIPELINE_SOURCE`, build-parameter values) but the engine
does not currently populate them.  When field testing surfaces a
meaningful volume of context-dependent suppression cases on
either platform, those wirings are clear follow-ups.
