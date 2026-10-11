# Deployment Context

taintly scores against the public-OSS threat model documented in
`docs/SCORING.md`. A repository can optionally add `.taintly-context.yml`
to attach deployment interpretation notes to findings.

Notes from `.taintly-context.yml` do not change rule detection, severity,
exploitability, or score. They mark findings for triage when deployment may differ from
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

## Execution and authority evidence

Workflow source also provides context independently of `.taintly-context.yml`.
For `LOTP-GH-001` and `LOTP-GH-003`, Taintly retains the execution candidate
and separately evaluates configured authority on supported direct GitHub
PR-head checkout/build paths. Findings include source, build, permission and
credential-access lines where established.

| Context tag | Meaning | Finding treatment |
|---|---|---|
| `authority-evidenced` | A supported PR-target path has a specific configured write-token access mechanism. | Preserve rule severity and execution confidence. Provider permission policy still applies. |
| `authority-limited` | Ordinary PR, explicit effective read/none grants, known hosted runner, disabled checkout persistence and no unresolved credential or secret exposure in the supported profile. | MEDIUM, low exploitability and review-needed; retain the execution candidate. |
| `authority-unresolved` | At least one execution, credential, permission or ownership link is unknown or unsupported. | Preserve rule severity, cap high exploitability at medium and require review. |

Job permission blocks replace workflow permissions. Environment precedence is
evaluated at each step; same-job earlier/later secret bindings can prevent a
limited conclusion. Custom PAT/SSH authority is separate from GITHUB_TOKEN;
matrix-derived credentials and service-container secrets remain reviewable.
Neither a secret expression nor OIDC mint permission proves a released secret
value or cloud role.

This initial profile requires one adjacent checkout/build, exact PR-head
repository/ref expressions, a supported action-major contract and a known
workspace/script shape. Unknown refs, ambiguous structure, custom execution
boundaries and profile budgets remain unresolved. Checkout v7's default
privileged-fork block requires execution verification unless explicitly opted
out. A candidate headline is not evidence that the workflow actually ran.

Limited authority is not a certificate of harmlessness. These source-derived
calibrations can affect the score through finding metadata; deployment notes
from `.taintly-context.yml` retain their annotation-only behavior above.
