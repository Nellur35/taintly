# Maintainer-Gated Severity Downgrade

Status: Implemented for Phase 1 GitHub cases.

## Decision

When a script-injection finding depends on a value that is only supplied through maintainer-gated workflow execution, downgrade severity by one tier instead of changing the rule or suppressing the finding.

## Rationale

The base detector remains correct: direct shell interpolation is unsafe. The exploitability claim changes when the only actor who can choose the value is already maintainer-equivalent. In that case a HIGH finding overstates external attacker reachability, while complete suppression would hide a real hardening issue.

## Current Pattern Table

- Any script-injection finding citing `$GITHUB_REF_NAME` or `github.ref_name`.
- `SEC4-GH-008` findings citing `${{ inputs.* }}` or `${{ github.event.inputs.* }}`.

The downgrade applies only when the workflow trigger set is maintainer-gated and no fork-reachable event is present.

## Non-Goals

- No rule-pack behavior changes.
- No downgrade when `pull_request`, `pull_request_target`, `issue_comment`, `issues`, `discussion`, `fork`, `workflow_run`, or `workflow_call` is present.
- No attempt to prove who has maintainer access in a live GitHub organization.

## Review Notes

This is a calibration pass, not a detector pass. Dead paths are suppressed first; surviving maintainer-only paths are downgraded second.
