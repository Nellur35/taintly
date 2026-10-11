# Secret-bearing output and shared caches

`SEC6-GH-015` reports a **MEDIUM, review-needed** finding when a GitHub Actions
job gives a recognized process a secret environment, that process produces
output under a cached path, and the job can save that cache.

This checks how tools are used in the workflow. It does not identify installed
tool versions or maintain a third-party vulnerability catalog.

## What is recognized

- Explicit environment dumps and simple secret writes using POSIX shell
  redirection or a supported `tee` output.
- Cargo build/test/check/bench/run/rustc/clippy and Miri test/run output under
  the inferred target directory. Giving Cargo a secret environment is a reason
  to review the output; it does **not** prove the output contains secret bytes.
- `actions/cache`, its separate save/restore actions, and supported
  `Swatinem/rust-cache` save, path and filtering controls.
- Workflow, job and step environment overrides; supported `export`, `unset`,
  `env` controls and writes to `GITHUB_ENV` that affect later steps.
- Static working directories, output paths, ordered saves and definite cleanup.
  Cache restore alone does not establish a save. Separate jobs are not joined.

For example, a job that runs `env > build/environment.txt` with a secret in its
environment and then saves `build/` exposes a direct output-to-cache route.
Keeping the secret in a separate step that does not produce cached output
removes that route, provided the secret is not persisted into later steps.

## Cache access and events

The default cache-write events are `push`, `workflow_dispatch`,
`repository_dispatch`, `delete`, `registry_package`, `page_build` and `schedule`.
Other events, including `release`, need an explicit `cache-mode: write` or
`write-only` override for this rule to consider a save. Job mode overrides
workflow mode; `read` and `none` disable saves. Literal event guards are applied
per event so output and save steps from different event paths are not joined.

Normal `pull_request` merge-ref caches are excluded from this shared-cache
profile even with a write override. The rule does not establish the branch of
a particular run, repository PR access rules, an actual cache miss/save, or
whether a specific PR can restore the resulting cache.

See [GitHub's cache scope and access policy](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)
and [actions/cache usage](https://github.com/actions/cache).

## Reviewing a finding

1. Check whether the process actually wrote sensitive values to the saved path.
2. Check the run's branch, cache scope and who can read it.
3. Scope secrets to the steps that need them, keep sensitive output outside
   saved caches, or disable cache saving for that job.
4. For a confirmed exposure, clear the affected caches and rotate exposed
   secrets after removing the route.

## Limits

The shell model is a bounded, linear POSIX command sequence. Dynamic paths,
arbitrary child scripts, shell functions/loops/branch blocks, PowerShell and
arbitrary tool output are outside this profile. Unknown guards remain possible
execution paths. Action internals are not executed or interpreted.

Cargo workspace manifests, configuration and custom build behavior can change
output locations; verify inferred target paths. A quiet scan does not prove
that cache contents are safe. Parser coverage warnings must be reviewed too.
