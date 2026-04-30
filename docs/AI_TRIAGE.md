# AI-assisted triage of taintly findings

taintly scores against a fixed public-OSS threat model
(`docs/SCORING.md`) and does not auto-adjust to your deployment
(`docs/decisions/threat-model-disclosure-not-adjustment.md`).
Closing the "does this apply to me?" loop is the user's job.

Below is one paste-ready prompt for handing taintly's JSON output
to a coding-agent of your choice so the agent can help recalibrate
findings against context the tool can't see.  Adjust to taste; the
wording is deliberately generic.

## RECALIBRATE

```
You have taintly's JSON report and this repository's source.

taintly scores against a fixed public-OSS threat model: fork PRs
reachable, runners shared, secrets repo-scoped.  My deployment
may differ on any of those axes.

Walk the findings.  For each, identify whether the public-OSS
assumption holds in MY deployment based on what's visible in the
repo (workflow triggers, runner labels, environment rules, branch
protection if exposed) and the deployment notes below.

Output a triage table: rule_id, file, line, one of {applies-as-
scored, over-weighted, under-weighted, not-applicable}, and a
one-sentence reason citing specific evidence.  Do NOT invent
context — flag "needs human input" if the deciding factor isn't
visible.

Deployment context (fill in):
  - PR policy: <fork PRs allowed / internal only / unknown>
  - Runner topology: <github-hosted / self-hosted / mixed>
  - Secret scoping: <repo / org / environment-gated>
  - Other: <anything else taintly couldn't see>
```
