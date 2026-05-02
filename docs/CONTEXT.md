# Deployment Context

taintly scores against the public-OSS threat model documented in
`docs/SCORING.md`. A repository can optionally add `.taintly-context.yml`
to attach deployment interpretation notes to findings.

Context notes do not change rule detection, severity, exploitability, or
score. They mark findings for triage when the deployment may differ from
the default assumptions.

## Example

```yaml
repo_visibility: private
external_prs: blocked
runner_topology: isolated_self_hosted
secret_scoping: oidc_only
```

## Fields

`repo_visibility`
: `unknown`, `public`, `private`, or `internal`

`external_prs`
: `unknown`, `allowed`, `blocked`, or `restricted`

`runner_topology`
: `unknown`, `github_hosted`, `shared_self_hosted`, or `isolated_self_hosted`

`secret_scoping`
: `unknown`, `repo_scoped`, `environment_scoped`, or `oidc_only`

Unsupported values are treated as `unknown` with a warning.

## Current Notes

- `privileged_pr_trigger` findings get a note when `external_prs` is
  `blocked` or `restricted`.
- `credential_persistence` findings get a note when `secret_scoping` is
  `oidc_only`.
- `ungoverned_services` findings get a note when `runner_topology` is
  `isolated_self_hosted`.

These notes are intentionally conservative. They say the finding may fit
the deployment differently; they do not suppress or rescore it.
