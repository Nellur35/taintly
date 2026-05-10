# Platform posture audit — rule reference

Pipeline static analysis catches *what the pipeline does*. Posture audit
catches *how the controller / forge is configured*. Two different surfaces;
both matter.

This page lists every posture rule taintly ships, what it checks, what
attack class it addresses, and how to interpret findings. For an overview
and the commands to run, see the
[README's Platform posture audit section](../README.md#platform-posture-audit).

## How to run

| Platform | Command | Auth |
|---|---|---|
| GitHub | `taintly --github-repo OWNER/REPO --platform-audit` | `GITHUB_TOKEN` env (PAT or fine-grained token with repo + admin:read scopes) |
| GitLab | `taintly --gitlab-project ID_OR_PATH --platform-audit` | `GITLAB_TOKEN` env (project access token, `api` scope; `read_user` for member checks) |
| Jenkins | `taintly --jenkins-url https://jenkins.example.com` | `JENKINS_USER` + `JENKINS_TOKEN` env (user API token with Overall/Read minimum; some checks need Administer) |

The audit is read-only — it queries documented REST endpoints
(`/api/v3/repos/*`, `/api/v4/projects/*`, `/api/json`). No scraping, no
auth bypass attempts, no test logins. Tokens with insufficient scope
produce `PLAT-*-ERR` findings rather than silently skipping checks.

---

## GitHub posture rules (`PLAT-GH-*`)

12 rules; covers branch protection, fork-PR controls, CODEOWNERS, Dependabot,
deploy keys, webhooks, and secret scanning.

### `PLAT-GH-001` — Default branch has no protection (**CRITICAL**)

Checks for *both* classic branch protection AND active rulesets on the
default branch. Fires only when neither exists. Without protection, anyone
with push access can rewrite the branch's history without review, and any
push to default can trigger workflows running with secrets.

**Catches:** unprotected default branch — the precondition for almost every
"merged a malicious PR and CI ran with secrets" attack class.
**API:** `GET /repos/{owner}/{repo}/branches/{default}/protection`,
`GET /repos/{owner}/{repo}/rules/branches/{default}`.

### `PLAT-GH-002` — Branch protection without required reviews (**HIGH**)

Classic branch protection exists but `required_pull_request_reviews` is
absent, OR `required_approving_review_count` is 0. A branch that's
"protected" only against deletion/force-push but not unreviewed merges is
not actually protected against malicious commits.

**Catches:** review-bypass via direct push to a "protected" branch; trivial
self-approval scenarios.
**API:** `GET /repos/{owner}/{repo}/branches/{default}/protection`.

### `PLAT-GH-005` — Fork PR workflows run without approval gate (**HIGH**)

Fork PRs auto-execute workflows on the first commit. Without
`require_actions_approval_for_first_time_contributors`, an attacker who
opens a PR triggers any non-`pull_request_target` workflow immediately,
running their code on your runners with whatever secrets the workflow has.

**Catches:** the entry point for fork-PR pwn-request attacks
(tj-actions, Ultralytics, etc.).
**API:** `GET /repos/{owner}/{repo}/actions/permissions`.

### `PLAT-GH-007` — Default `GITHUB_TOKEN` permission is read/write (**HIGH**)

Repo-level setting: when `default_workflow_permissions == "write"`, every
workflow that omits a `permissions:` block inherits write-grade access to
contents/issues/PRs. Pairs with the `SEC2-GH-002` static rule
(no-permissions-block in a workflow file). When this posture rule fires,
SEC2-GH-002 escalates from MEDIUM to HIGH — the omission is now actively
dangerous.

**Catches:** workflows that look "secure" because they omit permissions
but actually run with full repo write because of the org-level default.
**API:** `GET /repos/{owner}/{repo}/actions/permissions/workflow`.

### `PLAT-GH-008` — CODEOWNERS missing or doesn't cover `.github/workflows/` (**MEDIUM**)

Two failure modes: (a) no CODEOWNERS file at all, (b) CODEOWNERS exists but
no rule matches `.github/workflows/`. Workflow file changes are
disproportionately privileged — they decide what runs with your secrets —
so they deserve mandatory owner review.

**Catches:** workflow file edits sneaking through review; the human
counterpart of branch protection.

### `PLAT-GH-009` — Dependabot security updates disabled (**MEDIUM**)

The repo has not enabled the auto-updates that ship security advisories
into PRs. Dependabot's vulnerability alerts (PLAT-GH-010) tell you about
risk; this setting is the auto-remediation arm.

**Catches:** repos sitting on known-vulnerable dependency versions
indefinitely.
**API:** `GET /repos/{owner}/{repo}/automated-security-fixes`.

### `PLAT-GH-010` — Dependabot vulnerability alerts disabled (**MEDIUM**)

The advisory feed itself is off. No alerts means no signal that you're
affected by a published CVE.

**Catches:** silent zero-disclosure on dependency CVEs.
**API:** `GET /repos/{owner}/{repo}/vulnerability-alerts`.

### `PLAT-GH-011` — Wiki enabled (potential unnecessary attack surface) (**LOW**)

Wikis are repo-scoped writeable surfaces that few projects actually use
but which expand the attack surface (markdown injection, content abuse).
LOW because shutting off the wiki is rarely a security crisis on its own.

### `PLAT-GH-012` — Deploy key with write access (**HIGH**)

Per-repo deploy key with `read_only: false`. Deploy keys bypass user-level
auth and 2FA; a write-grade deploy key in compromised CI is equivalent to
an unscoped admin token. Read-only deploy keys are fine.

**Catches:** the long-tail "we set up CI ages ago" credential drift.
**API:** `GET /repos/{owner}/{repo}/keys`.

### `PLAT-GH-013` — Webhook uses non-HTTPS URL or has SSL verification disabled (**MEDIUM**)

Two sub-cases under one rule ID. HTTP webhooks deliver event payloads
(possibly including secrets) over the wire in cleartext. SSL-verification-off
defeats the purpose of HTTPS.

**Catches:** legacy webhook endpoints that haven't been re-pointed.
**API:** `GET /repos/{owner}/{repo}/hooks`.

### `PLAT-GH-014` — Outside collaborator with admin permission (**HIGH**)

Anyone outside the org with `admin` repo permission can change branch
protection, manage secrets, and add other collaborators. Almost always a
mistake or stale grant.

**Catches:** the kind of permission drift compliance audits flag.
**API:** `GET /repos/{owner}/{repo}/collaborators?affiliation=outside`.

### `PLAT-GH-016` — Secret scanning push protection disabled (**MEDIUM**)

Push protection is the "block the push if it contains a secret" feature.
Without it, secret scanning is reactive (alert after the fact); with it,
it's preventive.

**Catches:** secrets that would have been blocked at push time.
**API:** `GET /repos/{owner}/{repo}` (`security_and_analysis` block).

---

## GitLab posture rules (`PLAT-GL-*`)

8 rules; covers branch protection, MR approvals, CI/CD variable hardening,
public-pipeline exposure, deploy keys, webhooks, and member access.

### `PLAT-GL-001` — Default branch is not protected (**CRITICAL**)

Same threat class as `PLAT-GH-001`. Without protection, anyone with
Developer role can push to the default branch.
**API:** `GET /projects/{id}/protected_branches`.

### `PLAT-GL-002` — Merge requests require zero approvals (**HIGH**)

The project's MR approval rules require 0 approvers — anyone can self-merge.
Equivalent to `PLAT-GH-002`.
**API:** `GET /projects/{id}/approval_rules`.

### `PLAT-GL-003` — Some CI/CD variables are not Protected (**HIGH**)

CI/CD variables in GitLab have a `protected` flag; when off, the variable
is exposed to runners on every branch including unprotected feature
branches (and fork MRs if `Settings > CI/CD > Public pipelines` is on).
The Protected flag scopes the variable to protected refs only.

**Catches:** secrets bleeding into non-default-branch CI runs.
**API:** `GET /projects/{id}/variables`.

### `PLAT-GL-004` — Some CI/CD variables are not Masked (**HIGH**)

The `masked` flag is GitLab's runner-side log redactor. Unmasked CI/CD
variable values appear in `echo $VAR` job logs and any other
verbose-build-tool output. Different concern from Protected but same
configuration site.

**Catches:** secrets in job logs.
**API:** `GET /projects/{id}/variables`.

### `PLAT-GL-008` — Public project exposes job logs to unauthenticated users (**HIGH**)

Project visibility is `public` AND `public_jobs: true` (or — in newer
GitLab — `Settings > General > Visibility, project features, permissions
> CI/CD: Everyone With Access`). Any environment value not masked
appears in job logs that anonymous users can read.

**Catches:** the failure mode the always-fires `SEC10-GL-002` static
rule was a placeholder for; this is the real, queried-from-the-API
version.
**API:** `GET /projects/{id}` (`public_jobs`, `visibility`).

### `PLAT-GL-009` — Deploy key with write access (**HIGH**)

GitLab equivalent of `PLAT-GH-012`. A project deploy key with
`can_push: true`.
**API:** `GET /projects/{id}/deploy_keys`.

### `PLAT-GL-010` — Webhook uses non-HTTPS URL or has SSL verification disabled (**MEDIUM**)

Same shape as `PLAT-GH-013`.
**API:** `GET /projects/{id}/hooks`.

### `PLAT-GL-011` — Project has unexpected member with elevated access (**LOW**)

Surfaces individual users with Owner/Maintainer access for review. Not
"there's a bug" — fires informationally so a maintainer can confirm the
list. LOW because it's audit signal, not an alarm.
**API:** `GET /projects/{id}/members/all`.

### `PLAT-GL-012` — Group variable not protected (**HIGH**)

Same shape as `PLAT-GL-003` but at the group scope. Group-level variables
that aren't Protected propagate the same exposure across every project
in the group.
**API:** `GET /groups/{id}/variables` (requires `--gitlab-group`, not
`--gitlab-project`).

---

## Jenkins posture rules (`PLAT-JK-*`)

5 rules; covers the controller surface attackers actually probe — anonymous
access, script console, plugins, agent transport, CSRF.

### `PLAT-JK-001` — Anonymous read access enabled (**CRITICAL**)

The Jenkins controller serves the dashboard, job list, build logs, and
plugin list to unauthenticated requests. From there, an attacker
fingerprints the version, lists plugins for known CVEs, and probes for
exposed admin functions. Often the first signal in DDoS-botnet recruitment
scans.

**Catches:** the most common Jenkins-controller initial-access pattern.
**API:** `GET /` and `GET /asynchPeople/api/json` without auth.

### `PLAT-JK-002` — Outdated plugins with available updates (**HIGH**)

Lists installed plugins where `hasUpdate: true` and the plugin is active.
Jenkins plugin CVEs are actively exploited; an unpatched RCE plugin gives
controller-level code execution.

**Catches:** "behind on updates" — proxy for "running a known-CVE version."
The proxy isn't perfect: a plugin with `hasUpdate: false` could still have
an active advisory if no patched version has shipped yet
([known gap](#known-gaps-and-roadmap)).
**API:** `GET /pluginManager/api/json?depth=1`.

### `PLAT-JK-003` — Build agents on insecure transport, or builds running on the controller (**HIGH** / **LOW**)

Two sub-cases:

- **HIGH** — `Builds run on the Jenkins controller`: a job is configured
  to execute on the controller node (`master`/`built-in`). Build code
  shouldn't run with controller privileges; even non-malicious builds with
  bugs can compromise the controller's secrets store.
- **LOW** — Offline agents (informational; surfaces operationally-stale
  agents that should be removed from inventory).

A separate sub-case fires HIGH for agents using the legacy JNLP protocol
without TLS — agent tokens in cleartext on the wire.
**API:** `GET /computer/api/json?depth=1`.

### `PLAT-JK-004` — Groovy Script Console is accessible (**HIGH**)

The `/script` endpoint executes arbitrary Groovy with controller-level
permissions. Even with auth, exposing this endpoint to anyone but
Administer-scoped users is the Jenkins equivalent of leaving an SSH root
shell open.

**Catches:** the canonical RCE primitive. If `PLAT-JK-001` fires too,
this is full unauthenticated RCE — the path most DDoS-botnet
recruitment uses.
**API:** `GET /script` reachability.

### `PLAT-JK-005` — CSRF protection may be disabled (**HIGH**)

Jenkins's CSRF crumb mechanism wasn't always default. Older controllers
have it off; combined with stored XSS or a tricked admin browser, an
attacker can issue privileged API calls.

**Catches:** legacy controllers that haven't been hardened.
**API:** `GET /api/json` (`useCrumbs` field).

---

## Known gaps and roadmap

The posture audit isn't comprehensive. Documented gaps:

### Jenkins

- **Known-vulnerable plugin versions vs advisory feed.** `PLAT-JK-002`
  uses `hasUpdate` as a proxy. Adding a cross-check against
  `https://www.jenkins.io/security/advisories/jenkins-data.json` would
  catch the disclosed-but-not-yet-patched window. ~1 day of work.
- **Setup-wizard-skipped state.** Jenkins controllers that disabled the
  first-run wizard (`useSecurity: false`) accept anonymous admin. Not
  currently checked.
- **Default credentials.** `admin/admin`, `jenkins/jenkins` etc. Most
  DDoS-botnet scanners try these first. We deliberately don't probe
  this from our side (operational concern: lockouts, security alerts);
  could be done as an OPT-IN check with explicit user consent.

### GitHub

- **GitHub Apps with broad permissions.** `PLAT-GH-014` covers outside
  collaborators with admin; the equivalent for GitHub Apps is not yet
  audited.
- **Required status checks.** Branch protection details beyond
  required-reviews (status checks, signed commits, linear history) are
  not flagged today.
- **Repository ruleset coverage of forked branches.** Distinct from the
  default-branch check.

### GitLab

- **Group-level access tokens.** GitLab issues group/project access
  tokens that don't appear in the per-project members API; surveying
  these requires admin-scope token.
- **Runner registration tokens.** Public projects sometimes leak runner
  tokens via job-log dumps; not currently audited via API.

### Cross-platform

- **Cross-product correlation.** A workflow that grants
  `id-token: write` AND a deploy key with write access AND no fork-PR
  approval gate is dramatically more dangerous than any one finding
  alone. The scoring engine clusters within a platform but doesn't yet
  combine pipeline-static + posture findings into a single
  exploitability story.

---

## Operational notes

- **Token scope matters.** Insufficient scope produces `PLAT-*-ERR`
  findings (not silent skips). Read the `description` field — it names
  the missing scope.
- **Rate limits.** GitHub's REST limit is 5,000/hour for PATs. A full
  repo audit hits ~10 endpoints; org-wide audits with `--github-org`
  parallelise carefully.
- **Read-only.** No posture rule writes, modifies settings, or attempts
  authentication probes. If your security team needs to audit what
  taintly does, the call list is in `taintly/platform/{github,gitlab,
  jenkins}_client.py` — every API call is documented at the call site.
- **CI usage.** Posture audit results are JSON-serialisable; use
  `--format json` and pipe into your existing alert / dashboard
  pipeline. Exit codes follow the same convention as static scans
  (`0` clean, `1` HIGH, `2` CRITICAL).
