"""GitLab platform-posture checks.

Five rules, matching the GitHub platform module's shape:

    PLAT-GL-001 (CRITICAL)  Default branch is not protected
    PLAT-GL-002 (HIGH)      Merge requests require zero approvals
    PLAT-GL-003 (HIGH)      At least one CI/CD variable is not Protected
    PLAT-GL-004 (HIGH)      At least one CI/CD variable is not Masked
    PLAT-GL-008 (HIGH)      Public-pipelines visibility enabled on a public project

Every finding carries ``origin="platform"``.

Deferred to a follow-up increment (tracked, not lost):
    PLAT-GL-005/006/007/009  (group variables, shared runners on sensitive
                              pipelines, push rules, forking outside the
                              group hierarchy).

Annotation over downgrade policy: same as the GitHub module — the
findings here are standalone platform-origin findings and do NOT rewrite
any file-finding severities based on API-observed state.
"""

from __future__ import annotations

import re
from typing import Any

from taintly.families import classify_rule, default_confidence, default_review_needed
from taintly.models import Finding, Severity

from .gitlab_client import APIError, GitLabClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    rule_id: str,
    severity: Severity,
    title: str,
    description: str,
    project: str,
    remediation: str,
    reference: str,
    owasp_cicd: str,
    *,
    threat_narrative: str = "",
    stride: list[str] | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        description=description,
        file=f"gitlab:{project}",
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
        exploitability="medium",
        review_needed=default_review_needed(rule_id),
    )


# ---------------------------------------------------------------------------
# PLAT-GL-001 — default branch is not protected
# ---------------------------------------------------------------------------


def check_default_branch_protected(project: str, client: GitLabClient) -> list[Finding]:
    """Fires when the project's default branch has no entry in
    ``/projects/:id/protected_branches/:branch``.
    """
    proj = client.project(project)
    if not proj:
        return []
    default_branch = proj.get("default_branch")
    if not default_branch:
        return []

    pb = client.protected_branch(project, default_branch)
    if pb is not None:
        return []

    return [
        _finding(
            rule_id="PLAT-GL-001",
            severity=Severity.CRITICAL,
            title="Default branch is not protected",
            description=(
                f"The default branch ('{default_branch}') of project '{project}' "
                "is not in the protected branches list. Anyone with Developer "
                "access can push directly, and protected CI/CD variables are "
                "exposed to pipelines triggered by any push."
            ),
            project=project,
            remediation=(
                "In Settings > Repository > Protected branches, add the default "
                "branch with 'Allowed to push' set to 'Maintainers' (or "
                "'No one' for release branches) and 'Allowed to merge' set to "
                "'Maintainers'. Protected variables (the Protected flag in "
                "Settings > CI/CD > Variables) are ONLY injected on protected "
                "refs — without branch protection, that safeguard does nothing."
            ),
            reference="https://docs.gitlab.com/user/project/repository/branches/protected/",
            owasp_cicd="CICD-SEC-1",
            threat_narrative=(
                "An unprotected default branch means a Developer-level user "
                "(or a compromised account) can push directly, and Protected "
                "variables that guard production credentials are exposed to "
                "that push because Protected enforcement keys on branch "
                "protection status."
            ),
            stride=["T", "E"],
        )
    ]


# ---------------------------------------------------------------------------
# PLAT-GL-002 — MR approvals required
# ---------------------------------------------------------------------------


def check_mr_requires_approval(project: str, client: GitLabClient) -> list[Finding]:
    """Fires when no approval rule requires at least one approver.

    Checks both the modern ``/approval_rules`` endpoint (Premium+) and the
    legacy ``/approvals`` summary.  A project with no approval rules at
    all, OR with all rules at count 0, fires the finding.
    """
    rules = client.approval_rules(project)
    if rules:
        max_count = max(
            (r.get("approvals_required", 0) for r in rules if isinstance(r, dict)),
            default=0,
        )
        if max_count >= 1:
            return []
    else:
        # Fall back to the legacy summary.
        summary = client.approvals_summary(project)
        if summary and summary.get("approvals_before_merge", 0) >= 1:
            return []

    return [
        _finding(
            rule_id="PLAT-GL-002",
            severity=Severity.HIGH,
            title="Merge requests require zero approvals",
            description=(
                f"Project '{project}' has no approval rule requiring at least "
                "one reviewer. Authors can merge their own MRs without a second "
                "pair of eyes — the most common code-review bypass."
            ),
            project=project,
            remediation=(
                "In Settings > Merge requests > Approval rules, add an "
                "'All eligible users' (or Code Owners) rule with approvals "
                "required >= 1. Consider setting 'Prevent approval by author' "
                "and 'Prevent approval by commit author' in the same section."
            ),
            reference="https://docs.gitlab.com/user/project/merge_requests/approvals/settings/",
            owasp_cicd="CICD-SEC-1",
            threat_narrative=(
                "Self-approval of MRs turns branch protection into a no-op: "
                "anyone with write access can author a change, approve it "
                "themselves, and merge to the protected branch — bypassing "
                "the review gate entirely."
            ),
            stride=["T"],
        )
    ]


# ---------------------------------------------------------------------------
# PLAT-GL-003 / PLAT-GL-004 — CI/CD variable Protected / Masked flags
# ---------------------------------------------------------------------------


# GitLab 17.x added "Masked and hidden" variables whose value is not
# returned by the API after creation. A value-length filter would drop
# every hidden variable — exactly the highest-risk class. Filter by
# *name* instead so hidden vars stay in scope regardless of visibility.
_SECRET_NAME_RE = re.compile(
    r"(?i)(token|secret|key|password|pwd|pass|auth|credential|cred|"
    r"api[_-]?key|cert|private|signing|license)"
)


def _non_trivial_variables(variables: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter out the variables that shouldn't trigger the flags check.

    GitLab uses CI/CD variables for both secrets and non-secret config
    (e.g. Helm chart version, feature flags).  Two signals keep a
    variable in scope:

    * ``hidden: true`` — GitLab 17.x "Masked and hidden" variables never
      expose their value via the API, so a value-length heuristic would
      drop them. They're the highest-risk class and must always be
      checked.
    * Name matches a common secret-term regex — keeps coverage stable
      even when the value is elided or short.

    Low-risk config variables (short values, numeric, boolean flags,
    non-secret names) are still pruned so we don't nag users about
    ``ENABLE_FOO=true``.
    """
    out = []
    for v in variables:
        name = str(v.get("key", ""))
        # Always keep hidden variables — API returns no value, but they
        # are definitionally secrets (GitLab requires masking to hide).
        if v.get("hidden") or v.get("masked_and_hidden"):
            out.append(v)
            continue
        # Name-based match is stable across visibility states.
        if _SECRET_NAME_RE.search(name):
            out.append(v)
            continue
        value = str(v.get("value", ""))
        if len(value) < 8:
            continue  # too short to be a typical secret
        if value.isdigit():
            continue
        if value.lower() in ("true", "false"):
            continue
        out.append(v)
    return out


def check_variables_protected(project: str, client: GitLabClient) -> list[Finding]:
    """PLAT-GL-003: at least one non-trivial variable is not Protected."""
    variables = client.variables(project)
    if not variables:
        return []  # No vars or 403 (token lacks scope) — silently skip

    unprotected = [v for v in _non_trivial_variables(variables) if not v.get("protected", False)]
    if not unprotected:
        return []

    names = ", ".join(sorted(v.get("key", "?") for v in unprotected)[:5])
    more = f" (+{len(unprotected) - 5} more)" if len(unprotected) > 5 else ""

    return [
        _finding(
            rule_id="PLAT-GL-003",
            severity=Severity.HIGH,
            title="Some CI/CD variables are not Protected",
            description=(
                f"Project '{project}' has variables that look like secrets but "
                f"are not flagged Protected: {names}{more}. Non-protected "
                "variables are injected into pipelines running on ANY ref, "
                "including forks' merge-request pipelines (if fork MR "
                "pipelines are enabled) and ad-hoc API triggers."
            ),
            project=project,
            remediation=(
                "In Settings > CI/CD > Variables, edit each credential-like "
                "variable and tick 'Protect variable'. GitLab will then inject "
                "the variable only on protected refs — ensure the default "
                "branch and release tags are themselves protected first "
                "(otherwise Protected becomes a no-op)."
            ),
            reference="https://docs.gitlab.com/ci/variables/",
            owasp_cicd="CICD-SEC-6",
            threat_narrative=(
                "An unprotected credential-like variable is reachable from any "
                "fork MR pipeline, scheduled job, or API-triggered pipeline; "
                "the combination with fork-MR pipelines is the GitLab flavour "
                "of the Ultralytics attack path."
            ),
            stride=["I"],
        )
    ]


def check_variables_masked(project: str, client: GitLabClient) -> list[Finding]:
    """PLAT-GL-004: at least one non-trivial variable is not Masked."""
    variables = client.variables(project)
    if not variables:
        return []

    unmasked = [v for v in _non_trivial_variables(variables) if not v.get("masked", False)]
    if not unmasked:
        return []

    names = ", ".join(sorted(v.get("key", "?") for v in unmasked)[:5])
    more = f" (+{len(unmasked) - 5} more)" if len(unmasked) > 5 else ""

    return [
        _finding(
            rule_id="PLAT-GL-004",
            severity=Severity.HIGH,
            title="Some CI/CD variables are not Masked",
            description=(
                f"Project '{project}' has variables that look like secrets but "
                f"are not flagged Masked: {names}{more}. Unmasked values "
                "appear as plain text in job logs the moment any script "
                "command echoes them — intentionally or by accident (e.g. "
                "`set -x`, `env`, `printenv`)."
            ),
            project=project,
            remediation=(
                "In Settings > CI/CD > Variables, edit each credential-like "
                "variable and set Visibility to 'Masked' (or 'Masked and "
                "hidden' on GitLab 18.3+). Note: CI_DEBUG_TRACE bypasses "
                "masking — if debug trace is ever enabled, rotate affected "
                "secrets after the run."
            ),
            reference="https://docs.gitlab.com/ci/variables/#mask-a-cicd-variable",
            owasp_cicd="CICD-SEC-10",
            threat_narrative=(
                "An unmasked variable shows up verbatim in the job log on any "
                "accidental echo; anyone with log access reads the secret. "
                "This is a far cheaper attack than exfiltrating via the "
                "runner environment and works retroactively against logs "
                "already stored by log-aggregation systems."
            ),
            stride=["I"],
        )
    ]


# ---------------------------------------------------------------------------
# PLAT-GL-008 — public pipelines on a public project
# ---------------------------------------------------------------------------


def check_public_pipelines(project: str, client: GitLabClient) -> list[Finding]:
    """Fires when the project is public AND public-pipelines visibility is on.

    GitLab calls the field ``public_jobs`` in the API response (sometimes
    also rendered as ``public_builds``), so we check both.  The finding
    is scoped to public projects — on internal/private projects, exposed
    pipelines are still only visible to authenticated users.
    """
    proj = client.project(project)
    if not proj:
        return []
    if proj.get("visibility") != "public":
        return []

    # Two field names across GitLab versions.
    public = proj.get("public_jobs")
    if public is None:
        public = proj.get("public_builds")
    if public is None:
        return []
    if public is False:
        return []

    return [
        _finding(
            rule_id="PLAT-GL-008",
            severity=Severity.HIGH,
            title="Public project exposes job logs to unauthenticated users",
            description=(
                f"Project '{project}' has public visibility AND has public "
                "pipeline/job visibility enabled. Job logs are readable by "
                "anyone on the internet, including any variable value that "
                "is echoed, any script output, and any error message that "
                "leaks internal paths or service hostnames."
            ),
            project=project,
            remediation=(
                "Two controls work together:\n"
                "\n"
                "1. Primary — Settings > General > Visibility, project "
                "   features, permissions > 'CI/CD': set to "
                "   'Only Project Members'. This hides pipelines regardless "
                "   of project visibility.\n"
                "\n"
                "2. Secondary — Settings > CI/CD > General pipelines > "
                "   'Project-based pipeline visibility' (formerly 'Public "
                "   pipelines'): clear the checkbox.\n"
                "\n"
                "If the project does not need to be public, lowering project "
                "visibility to Internal or Private is the most effective "
                "mitigation."
            ),
            reference="https://docs.gitlab.com/ci/pipelines/settings/#change-pipeline-visibility-for-non-project-members",
            owasp_cicd="CICD-SEC-10",
            threat_narrative=(
                "Public job logs are an information-disclosure primitive: "
                "unauthenticated readers harvest non-masked variable values, "
                "internal hostnames, dependency versions, and stack traces — "
                "fuel for a targeted attack and free recon."
            ),
            stride=["I", "R"],
        )
    ]


# ---------------------------------------------------------------------------
# PLAT-GL-009 — Deploy keys with write access
# ---------------------------------------------------------------------------


def check_deploy_keys_write(project: str, client: GitLabClient) -> list[Finding]:
    """PLAT-GL-009: Deploy key with write access."""
    keys = client.deploy_keys(project)
    findings: list[Finding] = []
    for key in keys:
        if key.get("can_push") is True:
            findings.append(
                _finding(
                    rule_id="PLAT-GL-009",
                    severity=Severity.HIGH,
                    title=f"Deploy key with write access: {key.get('title', 'unnamed')}",
                    description=(
                        f"{project} has deploy key '{key.get('title', 'unnamed')}' "
                        "with push (write) access. A compromised key can push "
                        "commits directly, bypassing merge-request approvals."
                    ),
                    project=project,
                    remediation=(
                        "Rotate the key to read-only unless write is explicitly "
                        "required. Settings > Repository > Deploy keys."
                    ),
                    reference="https://docs.gitlab.com/user/project/deploy_keys/",
                    owasp_cicd="CICD-SEC-2",
                    threat_narrative=(
                        "A stolen deploy key with push access bypasses MR approval "
                        "gates — silent push to any branch."
                    ),
                    stride=["T", "E"],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# PLAT-GL-010 — Webhooks without SSL verification
# ---------------------------------------------------------------------------


def check_webhook_security(project: str, client: GitLabClient) -> list[Finding]:
    """PLAT-GL-010: Webhook with SSL verification disabled or insecure URL."""
    hooks = client.hooks(project)
    findings: list[Finding] = []
    for hook in hooks:
        url = hook.get("url") or ""
        if url and not url.startswith("https://"):
            findings.append(
                _finding(
                    rule_id="PLAT-GL-010",
                    severity=Severity.MEDIUM,
                    title="Webhook uses non-HTTPS URL",
                    description=(
                        f"{project} has a webhook sending to {url[:60]}... "
                        "over an unencrypted connection."
                    ),
                    project=project,
                    remediation="Update the webhook URL to use HTTPS.",
                    reference="https://docs.gitlab.com/user/project/integrations/webhooks/",
                    owasp_cicd="CICD-SEC-6",
                    stride=["I", "T"],
                )
            )
        if hook.get("enable_ssl_verification") is False:
            findings.append(
                _finding(
                    rule_id="PLAT-GL-010",
                    severity=Severity.MEDIUM,
                    title="Webhook has SSL verification disabled",
                    description=(
                        f"{project} has a webhook to {url[:60]} with SSL "
                        "verification disabled. Payloads can be intercepted "
                        "via MITM."
                    ),
                    project=project,
                    remediation=("Enable SSL verification in Settings > Webhooks > Edit."),
                    reference="https://docs.gitlab.com/user/project/integrations/webhooks/",
                    owasp_cicd="CICD-SEC-6",
                    stride=["I", "T"],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# PLAT-GL-011 — External members with Owner/Maintainer access
# ---------------------------------------------------------------------------


def check_member_access(project: str, client: GitLabClient) -> list[Finding]:
    """PLAT-GL-011: Project member with Owner (50) or Maintainer (40) access."""
    members = client.members(project)
    findings: list[Finding] = []
    for member in members:
        access = member.get("access_level", 0)
        # 50 = Owner, 40 = Maintainer
        if access >= 40 and member.get("state") == "active":
            username = member.get("username", "?")
            level = "Owner" if access >= 50 else "Maintainer"
            # Only flag if this looks like an external/bot account
            # (no way to distinguish org vs external in GitLab API for
            # self-managed, so we flag all Owners as informational)
            if access >= 50:
                findings.append(
                    _finding(
                        rule_id="PLAT-GL-011",
                        severity=Severity.LOW,
                        title=f"Project has {level} member: {username}",
                        description=(
                            f"{project} has {level}-level member '{username}'. "
                            f"{level} access includes ability to change protected "
                            "branches, manage variables, and delete the project."
                        ),
                        project=project,
                        remediation=(
                            "Review whether Owner access is required. Downgrade "
                            "to Maintainer or Developer if full owner is not needed."
                        ),
                        reference="https://docs.gitlab.com/user/permissions.html",
                        owasp_cicd="CICD-SEC-2",
                        stride=["E"],
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# PLAT-GL-012 — Group-level CI/CD variables not protected
# ---------------------------------------------------------------------------


def check_group_variables_protected(group: str, client: GitLabClient) -> list[Finding]:
    """PLAT-GL-012: Group-level CI/CD variables without Protected flag."""
    variables = client.group_variables(group)
    findings: list[Finding] = []
    for var in variables:
        if var.get("protected") is not True:
            findings.append(
                _finding(
                    rule_id="PLAT-GL-012",
                    severity=Severity.HIGH,
                    title=f"Group variable not protected: {var.get('key', '?')}",
                    description=(
                        f"Group '{group}' has CI/CD variable "
                        f"'{var.get('key', '?')}' without the Protected flag. "
                        "It is exposed to pipelines on ALL branches, including "
                        "unprotected feature branches where untrusted code runs."
                    ),
                    project=f"group:{group}",
                    remediation=(
                        "Group > Settings > CI/CD > Variables > Edit > "
                        "enable 'Protected'. This limits exposure to pipelines "
                        "running on protected branches only."
                    ),
                    reference="https://docs.gitlab.com/ci/variables/#protect-a-cicd-variable",
                    owasp_cicd="CICD-SEC-6",
                    threat_narrative=(
                        "A group variable without the Protected flag is available "
                        "to every pipeline in every project — including MR "
                        "pipelines from forks on unprotected branches."
                    ),
                    stride=["I", "E"],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Public runner
# ---------------------------------------------------------------------------


ALL_CHECKS = {
    "PLAT-GL-001": check_default_branch_protected,
    "PLAT-GL-002": check_mr_requires_approval,
    "PLAT-GL-003": check_variables_protected,
    "PLAT-GL-004": check_variables_masked,
    "PLAT-GL-008": check_public_pipelines,
    "PLAT-GL-009": check_deploy_keys_write,
    "PLAT-GL-010": check_webhook_security,
    "PLAT-GL-011": check_member_access,
}

# Group-level checks run once per group, not per project.
GROUP_CHECKS = {
    "PLAT-GL-012": check_group_variables_protected,
}


def run_group_checks(
    group: str,
    client: GitLabClient,
    *,
    checks: list[str] | None = None,
) -> list[Finding]:
    """Run group-level checks against a GitLab group."""
    results: list[Finding] = []
    selected = checks or list(GROUP_CHECKS.keys())
    for rule_id in selected:
        fn = GROUP_CHECKS.get(rule_id)
        if fn is None:
            continue
        try:
            results.extend(fn(group, client))
        except APIError:
            continue  # nosec B112
    return results


def run_all_checks(
    project: str,
    client: GitLabClient,
    *,
    checks: list[str] | None = None,
) -> list[Finding]:
    """Run every platform check against ``project``.

    API errors on individual checks are captured as PLAT-GL-ERR findings
    so a single 401/403/500 does not abort the scan.
    """
    results: list[Finding] = []
    selected = checks or list(ALL_CHECKS.keys())
    for rule_id in selected:
        fn = ALL_CHECKS.get(rule_id)
        if fn is None:
            continue
        try:
            results.extend(fn(project, client))
        except APIError as e:
            results.append(
                _finding(
                    rule_id="PLAT-GL-ERR",
                    severity=Severity.MEDIUM,
                    title=f"Platform check {rule_id} failed (HTTP {e.status})",
                    description=(
                        f"The {rule_id} check returned HTTP {e.status} from "
                        f"{e.endpoint}. This usually means the token lacks a "
                        "required scope (read_api is the minimum; "
                        "/projects/:id/variables requires Maintainer access)."
                    ),
                    project=project,
                    remediation=(
                        "Verify the token scope is at least `read_api`, and "
                        "that the user holds Maintainer access for checks "
                        "that read CI/CD variables."
                    ),
                    reference="",
                    owasp_cicd="",
                )
            )
    return results
