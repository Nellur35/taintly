# How taintly scores

taintly produces a single 0–100 score per scan, with a letter grade.
This document explains what that number means, what it assumes, and
what assessment is on you rather than on the tool.

## 1. What the score assumes

taintly's score is computed against a fixed default threat model.
Every exploitability weight, severity grading, and family clustering
decision was made against this model:

- **Fork PRs are reachable.** External contributors can open PRs that
  trigger workflows. Workflows triggered by `pull_request_target` or
  `workflow_run` ingest fork-controlled artifacts.
- **Runners are shared.** A compromised job on one runner can affect
  subsequent jobs on the same runner; self-hosted runner findings are
  weighted accordingly.
- **Secrets are repo-scoped.** Repository-level or group-level
  secrets are reachable from any job in the workflow, not gated by
  environment reviewer rules.
- **No OIDC-only posture.** Long-lived credentials (PATs, deploy
  keys, publish tokens) are present and persist across job
  boundaries.
- **No corporate-VPN gating.** External services contacted by
  workflows are reachable over the open internet, not via an
  allowlist.

Together these constitute the **public-OSS profile** — the most
attacker-favourable common deployment. Scoring against this profile
means the score is conservative for stricter deployments and
calibrated for less-strict ones.

## 2. What changes for other deployment shapes

If your deployment differs from the default in any of these ways,
the score may be over- or under-weighted relative to your actual
risk. Direction of effect (no specific magnitudes; see Section 4):

- **Internal-only repository, no external contributors.** Findings
  in the *privileged-PR-trigger* and *script-injection* families are
  exploitability-overweighted. Real exploitability still depends on
  whether org members can be hostile (insider threat).
- **OIDC-only posture, no long-lived credentials.** Findings in the
  *credential-persistence* family are exploitability-overweighted.
  Some findings may be structurally inapplicable (no token to
  persist).
- **Self-hosted isolated runners with no shared state.** Findings
  in the *ungoverned-services* family are exploitability-
  overweighted.
- **Air-gapped CI with no external network egress.** Most data-exfil
  attack chains are infeasible; many findings still describe risks
  inside the network boundary.
- **Strict environment-scoped secrets with reviewer gates.** Blast
  radius from any single compromised job is bounded; multi-step
  pivot findings are exploitability-overweighted.

These adjustments don't compound cleanly and they don't apply
uniformly across families. taintly does not currently calculate them
for you — see Section 4.

## 3. What's your responsibility, not taintly's

For every finding taintly produces, ask:

1. **Is this trigger reachable in our deployment?** A
   `pull_request_target` finding on an internal-only repo where no
   forks exist is materially different from the same finding on a
   public OSS repo. taintly cannot tell which yours is.
2. **What's the blast radius if exploited?** Repo-scoped secret
   leak versus environment-scoped secret leak versus OIDC-token
   misuse are not the same outcome.
3. **What does our existing detection or response cover?** Some
   findings are theoretical risks taintly should flag for
   completeness even when your detection-and-response posture would
   catch the exploitation in practice. taintly cannot model your
   blue team.
4. **Has the deployment shape changed since the last review?** A
   repo that was internal-only six months ago and is now public has
   different real-world exploitability than the score reflects until
   the next scan. taintly cannot detect deployment changes outside
   the workflow YAML.

Reviewing each finding against these questions is **required, not
optional**. The score is what taintly contributes; assessment is
what you contribute.

## 4. Why taintly doesn't auto-adjust the score

Auto-adjustment based on declared deployment context would require a
modifier table calibrated against labelled examples from non-public-
OSS deployments. The available labelled corpus is public-OSS-only.
Validating modifier values against data we don't have would produce
a feature whose behavior couldn't be measured.

Disclosure makes no claim that requires validation — it states what
the score assumes, and the user does the rest. That's the honest
version of the loop until the data exists to do more.

The conditions for revisiting are concrete:

- ≥30 labelled rows from non-public-OSS deployments are available in
  a corpus the project can use.
- ≥30% of policy-class disagreements in those rows map to families
  where modifiers could meaningfully resolve the disagreement.
- Second-reviewer spot-check on at least 10% of the contributed
  rows.

Until then, disclosure is what we ship.
