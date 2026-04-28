"""GitHub platform-posture checks.

Each check function receives a :class:`GitHubClient` and a repository
full-name (``owner/repo``) and returns a list of :class:`Finding` objects
with ``origin="platform"``.

Rule IDs follow the PLAT-GH-NN scheme established in the v2 requirements.
The five rules in this module are the highest-value subset of the v2
catalog; the remaining nine GitHub platform rules are tracked for a
follow-up increment.

Rulesets awareness
------------------
Classic branch protection (``/branches/{branch}/protection``) has been
gradually superseded by **repository rulesets**
(``/repos/{owner}/{repo}/rulesets``) since mid-2023.  A modern repository
can have no classic branch protection but full coverage via a ruleset and
be perfectly safe — PLAT-GH-001 checks BOTH endpoints and only fires
when neither provides protection for the default branch.

Annotation over downgrade
-------------------------
The v2 requirements document includes a cross-correlation table that
*downgrades* file-level severities based on platform state (for example,
"SEC2-GH-002 → LOW when PLAT-GH-007 shows read-only default").  The
critical review of that design flagged it as dangerous: the API snapshot
is point-in-time, an admin can flip the org setting minutes after the
scan.  This module therefore **annotates** findings with platform
context via the ``description`` field but never rewrites severity.
"""

from __future__ import annotations

from typing import Any

from taintly.families import classify_rule, default_confidence, default_review_needed
from taintly.models import Finding, Severity

from .github_client import APIError, GitHubClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    rule_id: str,
    severity: Severity,
    title: str,
    description: str,
    repo: str,
    remediation: str,
    reference: str,
    owasp_cicd: str,
    *,
    threat_narrative: str = "",
    stride: list[str] | None = None,
) -> Finding:
    """Construct a platform-origin Finding with the standard shape."""
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        description=description,
        file=repo,  # Platform findings use the repo name as their "file".
        line=0,
        snippet="",
        remediation=remediation,
        reference=reference,
        owasp_cicd=owasp_cicd,
        stride=stride or [],
        threat_narrative=threat_narrative,
        origin="platform",
        finding_family=classify_rule(rule_id, owasp_cicd),
        confidence=default_confidence(rule_id),
        # Platform posture findings are org/repo-level settings — no per-file
        # workflow context applies, so we record a neutral "medium"
        # exploitability tier and let severity carry the weight.
        exploitability="medium",
        review_needed=default_review_needed(rule_id),
    )


# ---------------------------------------------------------------------------
# PLAT-GH-001 — default branch has no protection (ruleset OR classic)
# ---------------------------------------------------------------------------


def _ruleset_targets_default_branch(ruleset: dict[str, Any]) -> bool:
    """Heuristic: does this ruleset target the default branch?

    Rulesets can include branches via explicit names, patterns, or the
    special ``~DEFAULT_BRANCH`` / ``~ALL`` include tokens.  We treat any
    of those as "covers the default branch"; precision would require
    resolving glob patterns against the default branch name, which
    isn't worth the complexity for a posture check.
    """
    if ruleset.get("enforcement") != "active":
        return False
    conditions = ruleset.get("conditions") or {}
    ref_name = conditions.get("ref_name") or {}
    includes = ref_name.get("include") or []
    if not includes:
        # Per GitHub's ruleset semantics, an empty `include` list means
        # "match no refs" — NOT "match everything". A ruleset with no
        # includes is effectively inert, so it cannot be claimed to
        # cover the default branch. Treating it as covering-everything
        # produces a silent false-negative: the org appears protected
        # while nothing is actually gated.
        return False
    for inc in includes:
        if inc in ("~ALL", "~DEFAULT_BRANCH"):
            return True
        if "refs/heads/" in inc or "*" in inc:
            # Broad patterns — assume they cover the default branch.
            return True
    return False


def check_default_branch_protected(repo: str, client: GitHubClient) -> list[Finding]:
    """PLAT-GH-001: default branch has neither classic protection nor an active ruleset."""
    default_branch = client.default_branch(repo)
    if default_branch is None:
        return []

    classic = client.branch_protection(repo, default_branch)
    if classic is not None:
        return []

    # Fall back to rulesets — a repo can have zero classic protection but
    # full coverage via a ruleset (GitHub's modern recommendation).
    for rs in client.rulesets(repo):
        rs_id = rs.get("id")
        detail = client.ruleset_detail(repo, rs_id) if isinstance(rs_id, int) else rs
        if detail and _ruleset_targets_default_branch(detail):
            return []

    return [
        _finding(
            rule_id="PLAT-GH-001",
            severity=Severity.CRITICAL,
            title="Default branch has no protection",
            description=(
                f"The default branch ('{default_branch}') of {repo} has neither "
                "classic branch protection (/branches/{branch}/protection) nor an "
                "active repository ruleset targeting it. Anyone with write access "
                "can push directly, force-push, or delete the branch — bypassing "
                "every review and status-check enforcement."
            ),
            repo=repo,
            remediation=(
                "Configure one of:\n"
                "  - A repository ruleset (Settings > Rules > Rulesets) targeting "
                "~DEFAULT_BRANCH with required pull-request reviews and status "
                "checks; OR\n"
                "  - Classic branch protection (Settings > Branches) on the "
                "default branch with the same requirements.\n"
                "\n"
                "Rulesets are GitHub's recommended modern mechanism; both are "
                "equally protective for this check."
            ),
            reference="https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets",
            owasp_cicd="CICD-SEC-1",
            threat_narrative=(
                "Without branch protection or a ruleset, a compromised contributor "
                "account can push malicious commits directly to the branch that "
                "feeds your CI/CD pipeline, bypassing all PR-based review and "
                "status checks."
            ),
            stride=["T", "E"],
        )
    ]


# ---------------------------------------------------------------------------
# PLAT-GH-002 — branch protection does not require pull-request reviews
# ---------------------------------------------------------------------------


def check_branch_protection_requires_reviews(repo: str, client: GitHubClient) -> list[Finding]:
    """PLAT-GH-002: classic branch protection exists but without required reviews.

    Intentionally does NOT inspect rulesets for review requirements —
    rulesets have a different shape and this check is focused on the
    classic case, which is still the most common.  A follow-up rule can
    cover ruleset-based reviews.
    """
    default_branch = client.default_branch(repo)
    if default_branch is None:
        return []

    classic = client.branch_protection(repo, default_branch)
    if classic is None:
        # No classic protection — PLAT-GH-001 covers that case.
        return []

    reviews = classic.get("required_pull_request_reviews") or {}
    required = reviews.get("required_approving_review_count", 0)
    if isinstance(required, int) and required >= 1:
        return []

    return [
        _finding(
            rule_id="PLAT-GH-002",
            severity=Severity.HIGH,
            title="Branch protection does not require pull-request reviews",
            description=(
                f"The default branch of {repo} has classic branch protection, "
                "but required_approving_review_count is 0 or unset. Any user "
                "with push access can merge their own code without a second "
                "pair of eyes."
            ),
            repo=repo,
            remediation=(
                "In Settings > Branches > Edit (default branch), enable "
                "'Require a pull request before merging' and set "
                "'Required approvals' to at least 1. Enforce 'Dismiss stale "
                "approvals' and 'Require review from Code Owners' if a "
                "CODEOWNERS file is in use."
            ),
            reference="https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-protected-branches",
            owasp_cicd="CICD-SEC-1",
            threat_narrative=(
                "A branch-protection rule without a review requirement is "
                "effectively a type enforcement that doesn't check its own "
                "invariants — the pipeline runs whatever was pushed, "
                "including a commit authored moments ago by the same user."
            ),
            stride=["T"],
        )
    ]


# ---------------------------------------------------------------------------
# PLAT-GH-005 — fork PR workflows run without approval gate
# ---------------------------------------------------------------------------


def check_fork_pr_approval_gate(repo: str, client: GitHubClient) -> list[Finding]:
    """PLAT-GH-005: fork-PR workflow approval is not required.

    The API field is ``access_level`` under ``/actions/permissions/access``
    for org-owned repos, or ``approval_for_external_contributors`` /
    ``fork_pr_workflows_from_fork_contributors_permitted`` under
    ``/actions/permissions``.  Different GitHub versions expose different
    shapes; we check the most stable fields and treat anything other than
    the strict options as a finding.
    """
    perms = client.actions_permissions_repo(repo)
    if perms is None:
        return []  # API not available or repo has Actions disabled

    # The key field on many recent responses: fork PR workflows from first-
    # time contributors can run without approval when this boolean is True.
    #
    # Field names observed across GitHub versions:
    #   - fork_pr_workflows_from_fork_contributors_permitted (newer)
    #   - allow_fork_pr_workflows_from_fork_collaborators (older)
    #
    # Normalise by checking any field whose name suggests allowance.
    suspicious_allowed = any(
        key.startswith(("allow_fork_pr", "fork_pr_workflows_from_fork")) and perms.get(key) is True
        for key in perms
    )

    # "access level" shape — repositories can require approval based on
    # organization membership tier.
    access = client.actions_permissions_access(repo)
    permissive_access = False
    if access:
        level = access.get("access_level")
        # "none" = no cross-repo access is the tightest; anything else is
        # already broader. We flag "organization" and "enterprise" only if
        # they coincide with the boolean above.
        permissive_access = level not in (None, "none")

    if not (suspicious_allowed or permissive_access):
        return []

    return [
        _finding(
            rule_id="PLAT-GH-005",
            severity=Severity.HIGH,
            title="Fork pull-request workflows run without approval gate",
            description=(
                f"{repo}'s Actions settings permit workflows from fork "
                "pull-requests to run without requiring approval from a "
                "maintainer. An attacker can trigger any workflow simply "
                "by opening a PR — the workflow runs with the same access "
                "to repository secrets and tokens that a regular push "
                "would have, unless the workflow itself gates that access."
            ),
            repo=repo,
            remediation=(
                "Settings > Actions > General > 'Approval for running fork "
                "pull request workflows from contributors' > select "
                "'Require approval for all outside collaborators' "
                "(or 'Require approval for all external contributors' for "
                "stricter policy). This is the setting that gates fork-PR "
                "workflow execution; branch protection does NOT."
            ),
            reference="https://docs.github.com/en/actions/how-tos/manage-workflow-runs/approve-runs-from-forks",
            owasp_cicd="CICD-SEC-4",
            threat_narrative=(
                "Without the approval gate, a contributor who has never "
                "pushed to the repository can execute arbitrary workflow "
                "steps by crafting a PR. Combined with any secret the "
                "workflow holds, this is the Ultralytics-shape attack path."
            ),
            stride=["E", "T"],
        )
    ]


# ---------------------------------------------------------------------------
# PLAT-GH-007 — default GITHUB_TOKEN permission is read-write
# ---------------------------------------------------------------------------


def check_default_token_permission(repo: str, client: GitHubClient) -> list[Finding]:
    """PLAT-GH-007: default GITHUB_TOKEN permission is the permissive
    (read/write) level, not the restricted (read) level.

    Since Feb 2023 new repos default to read-only, but older repos and
    repos under orgs still configured with the legacy "permissive" default
    inherit write-all across every scope — visible only via this API.
    """
    wperms = client.actions_permissions_workflow(repo)
    if wperms is None:
        return []

    default = wperms.get("default_workflow_permissions")
    # Valid values are "read" and "write".  "write" is the permissive default.
    if default != "write":
        return []

    return [
        _finding(
            rule_id="PLAT-GH-007",
            severity=Severity.HIGH,
            title="Default GITHUB_TOKEN permission is read/write",
            description=(
                f"{repo} has its workflow permissions configured so that "
                "GITHUB_TOKEN defaults to read/write access across every "
                "scope. Any workflow in the repo that does not declare "
                "its own explicit `permissions:` block inherits write "
                "access to contents, issues, pull_requests, actions, "
                "packages, and pages."
            ),
            repo=repo,
            remediation=(
                "Settings > Actions > General > 'Workflow permissions' > "
                "select 'Read repository contents and packages permissions'. "
                "The same setting exists at the org/enterprise level and "
                "inherits to new repos; flip it there first so new "
                "workflows start on the safe default.\n"
                "\n"
                "Existing workflows can still declare their own "
                "`permissions: write-all` if they genuinely need write; "
                "this setting only changes the DEFAULT for workflows that "
                "omit the block."
            ),
            reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#setting-the-github_token-permissions-for-an-entire-workflow",
            owasp_cicd="CICD-SEC-2",
            threat_narrative=(
                "Over-provisioned defaults are the standard failure mode "
                "for CI tokens. A workflow that forgets to set "
                "`permissions:` inherits write access to every scope the "
                "token supports — enough to push to branches, open "
                "releases, or modify workflows in-place."
            ),
            stride=["E"],
        )
    ]


# ---------------------------------------------------------------------------
# PLAT-GH-008 — no CODEOWNERS for workflow files
# ---------------------------------------------------------------------------


def check_codeowners_covers_workflows(repo: str, client: GitHubClient) -> list[Finding]:
    """PLAT-GH-008: CODEOWNERS is missing, or does not cover workflow files.

    A CODEOWNERS entry for .github/workflows means workflow edits require
    review from the listed owners — a critical control because an attacker
    who can modify a workflow can otherwise silently tamper with every
    future CI run.
    """
    exists, content = client.codeowners_exists(repo)
    if not exists:
        return [
            _finding(
                rule_id="PLAT-GH-008",
                severity=Severity.MEDIUM,
                title="No CODEOWNERS file",
                description=(
                    f"{repo} has no CODEOWNERS file in any of the canonical "
                    "locations (root, .github/, docs/). Without CODEOWNERS, "
                    "branch-protection's 'Require review from Code Owners' "
                    "setting has no effect, and workflow-file edits "
                    "receive no mandatory review by security owners."
                ),
                repo=repo,
                remediation=(
                    "Create .github/CODEOWNERS with at least one entry "
                    "covering the workflow directory:\n"
                    "\n"
                    "  .github/workflows/   @your-org/security-team\n"
                    "\n"
                    "Then enable 'Require review from Code Owners' in the "
                    "default-branch protection rule."
                ),
                reference="https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners",
                owasp_cicd="CICD-SEC-1",
                threat_narrative=(
                    "An attacker with write access who modifies a workflow "
                    "can exfiltrate every secret the repo holds at the "
                    "next trigger. CODEOWNERS is the mandatory-review "
                    "mechanism that stops such edits from landing silently."
                ),
                stride=["T", "R"],
            )
        ]

    # CODEOWNERS exists — does any rule cover .github/workflows?
    covers = _codeowners_covers_workflows(content or "")
    if covers:
        return []

    return [
        _finding(
            rule_id="PLAT-GH-008",
            severity=Severity.MEDIUM,
            title="CODEOWNERS does not cover workflow files",
            description=(
                f"{repo} has a CODEOWNERS file but no rule in it matches "
                ".github/workflows/. Workflow-file edits can be merged "
                "without security review even with 'Require review from "
                "Code Owners' enabled."
            ),
            repo=repo,
            remediation=(
                "Add an explicit rule for the workflows directory near the "
                "top of CODEOWNERS (later rules override earlier ones):\n"
                "\n"
                "  .github/workflows/   @your-org/security-team"
            ),
            reference="https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners",
            owasp_cicd="CICD-SEC-1",
            stride=["T"],
        )
    ]


def _codeowners_covers_workflows(content: str) -> bool:
    """Return True if any non-comment CODEOWNERS entry matches workflow files."""
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # First token is the path pattern.
        pattern = line.split()[0]
        # The CODEOWNERS matcher is gitignore-like; be permissive.  We
        # treat any pattern that mentions "workflow", "workflows", or ".github"
        # as "probably covers workflows".
        low = pattern.lower()
        if (
            "workflows" in low
            or low in (".github/", ".github/*", "*", "**")
            or low.startswith(".github/workflows")
        ):
            # Must also have at least one owner on the line.
            tokens = line.split()
            if len(tokens) >= 2:
                return True
    return False


# ---------------------------------------------------------------------------
# PLAT-GH-009 — Dependabot security updates disabled
# ---------------------------------------------------------------------------


def check_dependabot_security_updates(repo: str, client: GitHubClient) -> list[Finding]:
    """PLAT-GH-009: Dependabot security updates not enabled."""
    repo_data = client.repo(repo)
    if repo_data is None:
        return []

    sa = repo_data.get("security_and_analysis") or {}
    dep_updates = sa.get("dependabot_security_updates") or {}
    if dep_updates.get("status") == "enabled":
        return []

    return [
        _finding(
            rule_id="PLAT-GH-009",
            severity=Severity.MEDIUM,
            title="Dependabot security updates disabled",
            description=(
                f"{repo} does not have Dependabot security updates enabled. "
                "Known-vulnerable dependencies will not be automatically "
                "patched via pull requests."
            ),
            repo=repo,
            remediation=(
                "Settings > Code security > Dependabot > Enable "
                "'Dependabot security updates'. Or via API:\n"
                "  PUT /repos/{owner}/{repo}/automated-security-fixes"
            ),
            reference="https://docs.github.com/en/code-security/dependabot/dependabot-security-updates",
            owasp_cicd="CICD-SEC-3",
            threat_narrative=(
                "Without automated security updates, known CVEs in "
                "dependencies remain unpatched until a human notices. "
                "Supply-chain attackers count on this latency."
            ),
            stride=["T"],
        )
    ]


# ---------------------------------------------------------------------------
# PLAT-GH-010 — Vulnerability alerts disabled
# ---------------------------------------------------------------------------


def check_vulnerability_alerts(repo: str, client: GitHubClient) -> list[Finding]:
    """PLAT-GH-010: Dependabot vulnerability alerts not enabled."""
    enabled = client.vulnerability_alerts_enabled(repo)
    if enabled is None or enabled is True:
        return []

    return [
        _finding(
            rule_id="PLAT-GH-010",
            severity=Severity.MEDIUM,
            title="Vulnerability alerts disabled",
            description=(
                f"{repo} does not have Dependabot vulnerability alerts "
                "enabled. Known CVEs in dependencies will not generate "
                "alerts or appear in the Security tab."
            ),
            repo=repo,
            remediation=(
                "Settings > Code security > Dependabot > Enable "
                "'Dependabot alerts'. Or via API:\n"
                "  PUT /repos/{owner}/{repo}/vulnerability-alerts"
            ),
            reference="https://docs.github.com/en/code-security/dependabot/dependabot-alerts",
            owasp_cicd="CICD-SEC-3",
            threat_narrative=(
                "Without vulnerability alerts, the team has no automated "
                "signal when a dependency they ship has a published CVE."
            ),
            stride=["I"],
        )
    ]


# ---------------------------------------------------------------------------
# PLAT-GH-011 — Wiki enabled but likely unused (attack surface)
# ---------------------------------------------------------------------------


def check_wiki_attack_surface(repo: str, client: GitHubClient) -> list[Finding]:
    """PLAT-GH-011: Wiki is enabled, expanding the attack surface unnecessarily.

    GitHub wikis are a separate git repo that anyone with push access can
    edit. If not actively used, they are an unmonitored writable surface.
    """
    repo_data = client.repo(repo)
    if repo_data is None or not repo_data.get("has_wiki"):
        return []

    return [
        _finding(
            rule_id="PLAT-GH-011",
            severity=Severity.LOW,
            title="Wiki enabled (potential unnecessary attack surface)",
            description=(
                f"{repo} has the wiki feature enabled. GitHub wikis are "
                "a separate git repository with independent push access. "
                "If not actively maintained, they are an unmonitored "
                "writable surface that can host phishing content or "
                "SEO spam under your repository's domain."
            ),
            repo=repo,
            remediation=(
                "If the wiki is not in active use, disable it:\n"
                "  Settings > General > Features > uncheck 'Wikis'\n"
                "Or via API: PATCH /repos/{owner}/{repo} "
                '{"has_wiki": false}'
            ),
            reference="https://docs.github.com/en/communities/documenting-your-project-with-wikis",
            owasp_cicd="CICD-SEC-1",
            stride=["T"],
        )
    ]


# ---------------------------------------------------------------------------
# PLAT-GH-012 — Deploy keys with write access
# ---------------------------------------------------------------------------


def check_deploy_keys_write(repo: str, client: GitHubClient) -> list[Finding]:
    """PLAT-GH-012: Deploy key with write access found."""
    keys = client.deploy_keys(repo)
    findings: list[Finding] = []
    for key in keys:
        if key.get("read_only") is False:
            findings.append(
                _finding(
                    rule_id="PLAT-GH-012",
                    severity=Severity.HIGH,
                    title=f"Deploy key with write access: {key.get('title', 'unnamed')}",
                    description=(
                        f"{repo} has a deploy key '{key.get('title', 'unnamed')}' "
                        "with write access. A compromised key can push commits "
                        "directly to any branch, bypassing branch protection "
                        "rules that apply to user accounts."
                    ),
                    repo=repo,
                    remediation=(
                        "Rotate the key to a read-only deploy key unless write "
                        "access is explicitly required. If write is needed, "
                        "document the justification and set up key rotation."
                    ),
                    reference="https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys",
                    owasp_cicd="CICD-SEC-2",
                    threat_narrative=(
                        "Deploy keys with write access bypass branch protection. "
                        "A stolen key grants silent push access to any branch — "
                        "no PR, no review, no audit trail beyond the git log."
                    ),
                    stride=["T", "E"],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# PLAT-GH-013 — Webhooks sending to non-HTTPS URLs
# ---------------------------------------------------------------------------


def check_webhook_security(repo: str, client: GitHubClient) -> list[Finding]:
    """PLAT-GH-013: Webhook configured with non-HTTPS URL."""
    hooks = client.webhooks(repo)
    findings: list[Finding] = []
    for hook in hooks:
        config = hook.get("config") or {}
        url = config.get("url") or ""
        if url and not url.startswith("https://"):
            findings.append(
                _finding(
                    rule_id="PLAT-GH-013",
                    severity=Severity.MEDIUM,
                    title="Webhook uses non-HTTPS URL",
                    description=(
                        f"{repo} has a webhook sending to {url[:60]}... "
                        "over an unencrypted connection. Webhook payloads "
                        "may contain commit data, branch names, and "
                        "repository metadata."
                    ),
                    repo=repo,
                    remediation=(
                        "Update the webhook URL to use HTTPS. Also ensure "
                        "a webhook secret is configured to verify payload "
                        "authenticity."
                    ),
                    reference="https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks",
                    owasp_cicd="CICD-SEC-6",
                    threat_narrative=(
                        "Webhook payloads sent over HTTP can be intercepted "
                        "by a network-level attacker, leaking repository "
                        "metadata and potentially triggering replay attacks."
                    ),
                    stride=["I", "T"],
                )
            )
        # Also check for missing webhook secret
        if not config.get("secret"):
            findings.append(
                _finding(
                    rule_id="PLAT-GH-013",
                    severity=Severity.MEDIUM,
                    title="Webhook has no secret configured",
                    description=(
                        f"{repo} has a webhook to {url[:60]} without a "
                        "secret. Without a secret, the receiver cannot "
                        "verify that payloads actually came from GitHub."
                    ),
                    repo=repo,
                    remediation=(
                        "Configure a webhook secret in Settings > Webhooks > "
                        "Edit, and validate the X-Hub-Signature-256 header "
                        "on the receiving end."
                    ),
                    reference="https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries",
                    owasp_cicd="CICD-SEC-6",
                    stride=["S", "T"],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# PLAT-GH-014 — Outside collaborators with admin access
# ---------------------------------------------------------------------------


def check_outside_collaborators(repo: str, client: GitHubClient) -> list[Finding]:
    """PLAT-GH-014: Outside collaborator with admin permissions."""
    collabs = client.collaborators(repo, affiliation="outside")
    findings: list[Finding] = []
    for collab in collabs:
        perms = collab.get("permissions") or {}
        if perms.get("admin"):
            findings.append(
                _finding(
                    rule_id="PLAT-GH-014",
                    severity=Severity.HIGH,
                    title=f"Outside collaborator with admin: {collab.get('login', '?')}",
                    description=(
                        f"{repo} has outside collaborator "
                        f"'{collab.get('login', '?')}' with admin permissions. "
                        "Admin access includes ability to change branch "
                        "protection, manage secrets, add deploy keys, and "
                        "delete the repository."
                    ),
                    repo=repo,
                    remediation=(
                        "Review whether admin access is required. Downgrade "
                        "to 'write' or 'maintain' if full admin is not needed. "
                        "Settings > Collaborators > change role."
                    ),
                    reference="https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories",
                    owasp_cicd="CICD-SEC-2",
                    threat_narrative=(
                        "An outside collaborator with admin access can disable "
                        "branch protection, add their own deploy keys, modify "
                        "secrets, and push directly to any branch — the full "
                        "blast radius of a compromised owner account."
                    ),
                    stride=["E", "T"],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# PLAT-GH-016 — Secret scanning advanced features disabled
# ---------------------------------------------------------------------------


def check_secret_scanning_advanced(repo: str, client: GitHubClient) -> list[Finding]:
    """PLAT-GH-016: Secret scanning validity checks or non-provider patterns disabled."""
    repo_data = client.repo(repo)
    if repo_data is None:
        return []

    sa = repo_data.get("security_and_analysis") or {}
    findings: list[Finding] = []

    push_protection = sa.get("secret_scanning_push_protection") or {}
    if push_protection.get("status") != "enabled":
        findings.append(
            _finding(
                rule_id="PLAT-GH-016",
                severity=Severity.MEDIUM,
                title="Secret scanning push protection disabled",
                description=(
                    f"{repo} does not have secret scanning push protection "
                    "enabled. Secrets can be pushed to the repository "
                    "without being blocked at push time."
                ),
                repo=repo,
                remediation=(
                    "Settings > Code security > Secret scanning > Enable 'Push protection'."
                ),
                reference="https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations",
                owasp_cicd="CICD-SEC-6",
                threat_narrative=(
                    "Without push protection, a developer who accidentally "
                    "commits a secret gets no pre-push warning. The secret "
                    "enters git history permanently."
                ),
                stride=["I"],
            )
        )

    secret_scanning = sa.get("secret_scanning") or {}
    if secret_scanning.get("status") != "enabled":
        findings.append(
            _finding(
                rule_id="PLAT-GH-016",
                severity=Severity.MEDIUM,
                title="Secret scanning disabled",
                description=(
                    f"{repo} does not have secret scanning enabled. "
                    "Leaked secrets in the repository will not be detected."
                ),
                repo=repo,
                remediation=("Settings > Code security > Secret scanning > Enable."),
                reference="https://docs.github.com/en/code-security/secret-scanning",
                owasp_cicd="CICD-SEC-6",
                stride=["I"],
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Public runner
# ---------------------------------------------------------------------------


ALL_CHECKS = {
    "PLAT-GH-001": check_default_branch_protected,
    "PLAT-GH-002": check_branch_protection_requires_reviews,
    "PLAT-GH-005": check_fork_pr_approval_gate,
    "PLAT-GH-007": check_default_token_permission,
    "PLAT-GH-008": check_codeowners_covers_workflows,
    "PLAT-GH-009": check_dependabot_security_updates,
    "PLAT-GH-010": check_vulnerability_alerts,
    "PLAT-GH-011": check_wiki_attack_surface,
    "PLAT-GH-012": check_deploy_keys_write,
    "PLAT-GH-013": check_webhook_security,
    "PLAT-GH-014": check_outside_collaborators,
    "PLAT-GH-016": check_secret_scanning_advanced,
}


# ===========================================================================
# Account-level checks (ACCT-GH-*)
# ===========================================================================


def check_account_2fa(owner: str, client: GitHubClient) -> list[Finding]:
    """ACCT-GH-001: Account does not have 2FA enabled."""
    user_data = client.user(owner)
    if user_data is None:
        return []

    # two_factor_authentication is only visible when querying the
    # authenticated user (GET /user), not arbitrary users. Try the
    # authenticated endpoint first.
    auth_user = client._request("/user")
    if auth_user is None:
        return []

    # Only check if the authenticated user IS the owner being scanned
    if auth_user.get("login", "").lower() != owner.lower():
        return []  # Can't check 2FA for other users

    if auth_user.get("two_factor_authentication") is True:
        return []

    return [
        _finding(
            rule_id="ACCT-GH-001",
            severity=Severity.CRITICAL,
            title="Two-factor authentication is not enabled",
            description=(
                f"The GitHub account '{owner}' does not have 2FA enabled. "
                "A compromised password grants full access to all "
                "repositories, secrets, deploy keys, and organization "
                "memberships."
            ),
            repo=f"account:{owner}",
            remediation=(
                "Enable 2FA immediately:\n"
                "  GitHub > Settings > Password and authentication > "
                "Enable two-factor authentication.\n"
                "Use a hardware key (YubiKey) or TOTP app, not SMS."
            ),
            reference="https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa",
            owasp_cicd="CICD-SEC-2",
            threat_narrative=(
                "Without 2FA, a single leaked or phished password gives "
                "an attacker full control of every repository the account "
                "owns or has write access to — including the ability to "
                "push malicious commits, modify CI workflows, and "
                "exfiltrate secrets."
            ),
            stride=["S", "E"],
        )
    ]


def check_org_2fa_requirement(owner: str, client: GitHubClient) -> list[Finding]:
    """ACCT-GH-002: Organization does not require 2FA for members."""
    org_data = client.org(owner)
    if org_data is None:
        return []  # Not an org, or not accessible

    if org_data.get("two_factor_requirement_enabled") is True:
        return []

    return [
        _finding(
            rule_id="ACCT-GH-002",
            severity=Severity.HIGH,
            title="Organization does not require 2FA for members",
            description=(
                f"The organization '{owner}' does not enforce 2FA for "
                "its members. Any member without 2FA is a single-password "
                "compromise away from a supply-chain attack on every "
                "repository they can push to."
            ),
            repo=f"org:{owner}",
            remediation=(
                "Organization > Settings > Authentication security > "
                "Require two-factor authentication for everyone in the "
                "organization."
            ),
            reference="https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization",
            owasp_cicd="CICD-SEC-2",
            threat_narrative=(
                "An org member without 2FA who reuses their password on "
                "a breached service gives attackers push access to every "
                "repo that member can write to."
            ),
            stride=["S", "E"],
        )
    ]


def check_org_default_permissions(owner: str, client: GitHubClient) -> list[Finding]:
    """ACCT-GH-003: Organization default repository permission is too broad."""
    org_data = client.org(owner)
    if org_data is None:
        return []

    default_perm = org_data.get("default_repository_permission")
    if default_perm in (None, "none", "read"):
        return []

    return [
        _finding(
            rule_id="ACCT-GH-003",
            severity=Severity.MEDIUM,
            title=f"Org default repository permission is '{default_perm}'",
            description=(
                f"The organization '{owner}' grants '{default_perm}' "
                "access to all members on all repositories by default. "
                "This means every org member can push to every repo "
                "unless explicitly restricted."
            ),
            repo=f"org:{owner}",
            remediation=(
                "Organization > Settings > Member privileges > "
                "Base permissions > set to 'Read' or 'No permission'. "
                "Grant write access per-repo or per-team."
            ),
            reference="https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/setting-base-permissions-for-an-organization",
            owasp_cicd="CICD-SEC-2",
            threat_narrative=(
                "Broad default permissions mean a compromised org member "
                "account has write access to repos it has no business "
                "touching — the blast radius of one credential leak "
                "scales to the entire organization."
            ),
            stride=["E"],
        )
    ]


ACCOUNT_CHECKS = {
    "ACCT-GH-001": check_account_2fa,
    "ACCT-GH-002": check_org_2fa_requirement,
    "ACCT-GH-003": check_org_default_permissions,
}


def run_account_checks(
    owner: str,
    client: GitHubClient,
    *,
    checks: list[str] | None = None,
) -> list[Finding]:
    """Run account/org-level checks against the owner."""
    results: list[Finding] = []
    selected = checks or list(ACCOUNT_CHECKS.keys())
    for rule_id in selected:
        fn = ACCOUNT_CHECKS.get(rule_id)
        if fn is None:
            continue
        try:
            results.extend(fn(owner, client))
        except APIError:
            continue  # nosec B112 — best-effort
    return results


def run_all_checks(
    repo: str,
    client: GitHubClient,
    *,
    checks: list[str] | None = None,
) -> list[Finding]:
    """Run every (or the selected subset of) platform checks against ``repo``.

    API errors on individual checks are captured and emitted as MEDIUM
    findings with ``rule_id='PLAT-GH-ERR'`` so the scan does not abort
    silently on a single 401/403/500.
    """
    results: list[Finding] = []
    selected = checks or list(ALL_CHECKS.keys())
    for rule_id in selected:
        fn = ALL_CHECKS.get(rule_id)
        if fn is None:
            continue
        try:
            results.extend(fn(repo, client))
        except APIError as e:
            results.append(
                _finding(
                    rule_id="PLAT-GH-ERR",
                    severity=Severity.MEDIUM,
                    title=f"Platform check {rule_id} failed (HTTP {e.status})",
                    description=(
                        f"The {rule_id} check returned HTTP {e.status} from "
                        f"{e.endpoint}. This usually means the token is "
                        "missing a required scope, or the endpoint is "
                        "unavailable in your GitHub plan / version."
                    ),
                    repo=repo,
                    remediation=(
                        "Verify the token has the required scopes (repo, "
                        "read:org for classic PATs; Administration, Actions, "
                        "Environments for fine-grained PATs)."
                    ),
                    reference="",
                    owasp_cicd="",
                )
            )
    return results
