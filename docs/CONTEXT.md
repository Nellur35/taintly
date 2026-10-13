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

## Source-derived execution context for composed findings

`CHAIN-GH-101` through `CHAIN-GH-105` also inspect workflow source. This is
separate from the optional deployment notes above. Complete supported event
declarations and the actual owning job/step guards can exclude an impossible
external-event combination. Cross-job candidates require compatible events for
the producer, reader and recognized consumer authority scope. A push-only step
does not gain PR reachability merely because another job handles PRs.

Missing, malformed, duplicated, aliased or unsupported context cannot prove a
path impossible. Unknown conditions retain the review candidate. A trusted bot
name in a guard does not establish that event content, fetched bytes or a
third-party action is trustworthy; an unrelated guarded step cannot suppress
another step's finding.

These composites remain review-needed. Requested permissions, secret references
and authority-operation indicators describe candidates, rather than proving
runtime access or exploitation. Review the source, actual guards, approvals,
credential identity and provider permissions. Passing a secret through `env:`
does not isolate it from an action that receives it, and quoting a variable
passed to `eval` does not prevent reevaluation as code.

## Authority across local workflow and action calls

For `XF-GH-005` and `XF-GH-006`, source-derived context follows each local call
separately. Findings can connect attacker input and execution to configured token
permissions and explicit credential bindings, with file/line witnesses.

| Context tag | Meaning |
|---|---|
| `call-authority-configured` | Supported declarations and explicit token/secret references establish a configured access profile. |
| `call-authority-limited` | The supported explicit token/binding profile is bounded; this does not establish globally credential-free execution. |
| `call-authority-unresolved` | At least one permission, forwarding, credential provenance or environment link is unknown or unsupported. |

Caller permissions bound called jobs; incompatible escalation leaves the
invocation unresolved. Named secret/input aliases and per-hop inheritance retain
their own source lines. A missing forwarding edge differs from a supplied value
whose provenance is unknown. Caller workflow env resets at reusable workflow
boundaries; composite steps use the owning job's effective env and overrides.
Separate calls and jobs do not share credential evidence.

These tags describe configuration. They do not prove the workflow ran, a secret
was released, runtime action bytes match repository source, external credential
privileges or a cloud role. Invalid invocation contracts retain execution review;
ordinary authority uncertainty does not erase a supported input-to-sink path.
HIGH severity and MEDIUM confidence are retained. Review the cited permission,
forwarding and sink lines before deciding impact or remediation.

## Declared outputs and direct dependencies

For `CHAIN-GH-105`, a supported complete declaration can exclude a reference
to a nonexistent named output or a producer that is not a direct dependency of
the consumer. A transitive dependency alone does not make its outputs available
in the consumer's `needs` context. Supported literal block declarations and a
narrow flat inline-output form are checked.

Incomplete, duplicate, aliased, merged, malformed or unsupported declarations
remain unknown. A case-only name mismatch also remains unknown. These cases
keep an existing review candidate; an incomplete parse cannot prove absence.
A declared output and dependency establish a possible connection, without
proving attacker control, runtime success or effective credential authority.
