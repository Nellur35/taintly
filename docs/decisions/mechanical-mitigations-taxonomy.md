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
