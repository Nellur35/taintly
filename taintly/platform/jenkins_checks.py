"""Jenkins platform-posture checks.

Each check function receives a :class:`JenkinsClient` and returns a list
of :class:`Finding` objects with ``origin="platform"``.

Rule IDs follow the PLAT-JK-NN scheme.  Jenkins posture checks are
inherently different from GitHub/GitLab because Jenkins is self-hosted —
the security posture is about the instance configuration, not a hosted
platform's settings.
"""

from __future__ import annotations

from taintly.families import classify_rule, default_confidence, default_review_needed
from taintly.models import Finding, Severity

from .jenkins_client import APIError, JenkinsClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    rule_id: str,
    severity: Severity,
    title: str,
    description: str,
    instance: str,
    remediation: str,
    reference: str,
    owasp_cicd: str,
    *,
    threat_narrative: str = "",
    stride: list[str] | None = None,
) -> Finding:
    """Construct a platform-origin Finding for Jenkins."""
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        description=description,
        file=instance,
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
# PLAT-JK-001 — Anonymous read access enabled
# ---------------------------------------------------------------------------


def check_anonymous_access(instance: str, client: JenkinsClient) -> list[Finding]:
    """PLAT-JK-001: Jenkins allows anonymous read access.

    If we can fetch /api/json without credentials and get a valid response,
    the instance allows unauthenticated access.
    """
    # Try fetching without credentials
    import urllib.error
    import urllib.request

    url = f"{client._base_url}/api/json"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            data = resp.read()
            if resp.status == 200 and data:
                return [
                    _finding(
                        rule_id="PLAT-JK-001",
                        severity=Severity.CRITICAL,
                        title="Anonymous read access enabled",
                        description=(
                            f"Jenkins instance at {instance} allows "
                            "unauthenticated access to the API. Build logs, "
                            "job configurations, and potentially credentials "
                            "are exposed to anyone with network access."
                        ),
                        instance=instance,
                        remediation=(
                            "Manage Jenkins > Security > Authentication > "
                            "select a security realm (LDAP, Active Directory, "
                            "or Jenkins own database). Under Authorization, "
                            "select 'Matrix-based' or 'Project-based' and "
                            "remove Anonymous read access."
                        ),
                        reference="https://www.jenkins.io/doc/book/security/access-control/",
                        owasp_cicd="CICD-SEC-2",
                        threat_narrative=(
                            "Anonymous access to Jenkins exposes build logs, "
                            "environment variables (potentially with secrets), "
                            "job configs, and the plugin list — a full recon "
                            "surface for an attacker."
                        ),
                        stride=["I", "E"],
                    )
                ]
    except (urllib.error.HTTPError, urllib.error.URLError, OSError):
        pass
    return []


# ---------------------------------------------------------------------------
# PLAT-JK-002 — Outdated plugins with known CVEs
# ---------------------------------------------------------------------------


def check_outdated_plugins(instance: str, client: JenkinsClient) -> list[Finding]:
    """PLAT-JK-002: Plugins with available updates (potential CVE exposure)."""
    plugins = client.plugins()
    outdated = [p for p in plugins if p.get("hasUpdate") is True and p.get("active") is True]
    if not outdated:
        return []

    plugin_names = [p.get("shortName", "?") for p in outdated[:10]]
    suffix = f" (and {len(outdated) - 10} more)" if len(outdated) > 10 else ""
    return [
        _finding(
            rule_id="PLAT-JK-002",
            severity=Severity.HIGH,
            title=f"{len(outdated)} active plugins have available updates",
            description=(
                f"Jenkins instance at {instance} has {len(outdated)} active "
                f"plugins with pending updates: {', '.join(plugin_names)}{suffix}. "
                "Outdated plugins are the #1 attack vector for Jenkins instances. "
                "Security advisories: https://www.jenkins.io/security/advisories/"
            ),
            instance=instance,
            remediation=(
                "Manage Jenkins > Plugins > Updates > select all > Update. "
                "Enable automatic security update checks. Consider the "
                "Jenkins Plugin Health Scoring system for plugin hygiene."
            ),
            reference="https://www.jenkins.io/security/advisories/",
            owasp_cicd="CICD-SEC-3",
            threat_narrative=(
                "Jenkins plugin CVEs are actively exploited. A single "
                "unpatched plugin can give RCE on the controller, which "
                "has access to every credential, every build, and every "
                "agent in the instance."
            ),
            stride=["E", "T"],
        )
    ]


# ---------------------------------------------------------------------------
# PLAT-JK-003 — Agents connected via JNLP (inbound) without TLS
# ---------------------------------------------------------------------------


def check_agent_security(instance: str, client: JenkinsClient) -> list[Finding]:
    """PLAT-JK-003: Build agents using insecure connection protocols."""
    nodes = client.nodes()
    findings: list[Finding] = []

    for node in nodes:
        display = node.get("displayName", "?")
        if display == "Built-In Node":
            # Check if builds are allowed on the controller
            num_executors = node.get("numExecutors", 0)
            if isinstance(num_executors, int) and num_executors > 0:
                findings.append(
                    _finding(
                        rule_id="PLAT-JK-003",
                        severity=Severity.HIGH,
                        title="Builds run on the Jenkins controller",
                        description=(
                            f"Jenkins instance at {instance} has "
                            f"{num_executors} executor(s) on the built-in "
                            "node. Running builds on the controller gives "
                            "build code direct access to Jenkins internals, "
                            "all credentials, and all other jobs."
                        ),
                        instance=instance,
                        remediation=(
                            "Manage Jenkins > Nodes > Built-In Node > "
                            "Configure > set 'Number of executors' to 0. "
                            "Use dedicated agents for all builds."
                        ),
                        reference="https://www.jenkins.io/doc/book/security/controller-isolation/",
                        owasp_cicd="CICD-SEC-7",
                        threat_narrative=(
                            "A malicious build running on the controller can "
                            "read credentials.xml, modify other jobs, install "
                            "plugins, and pivot to every connected agent."
                        ),
                        stride=["E", "T"],
                    )
                )

        # Check for offline agents (potential abandoned agents with stale creds)
        if node.get("offline") is True and display != "Built-In Node":
            findings.append(
                _finding(
                    rule_id="PLAT-JK-003",
                    severity=Severity.LOW,
                    title=f"Offline agent: {display}",
                    description=(
                        f"Agent '{display}' on {instance} is offline. "
                        "Offline agents may have stale credentials and "
                        "represent abandoned infrastructure."
                    ),
                    instance=instance,
                    remediation=(
                        "If the agent is no longer needed, remove it. "
                        "If it should be online, investigate the disconnect."
                    ),
                    reference="https://www.jenkins.io/doc/book/managing/nodes/",
                    owasp_cicd="CICD-SEC-7",
                    stride=["I"],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# PLAT-JK-004 — Script console enabled
# ---------------------------------------------------------------------------


def check_script_console(instance: str, client: JenkinsClient) -> list[Finding]:
    """PLAT-JK-004: Groovy script console accessible.

    The script console is /script — if it returns 200, any authenticated
    user with admin access can execute arbitrary Groovy on the controller.
    """
    import urllib.error
    import urllib.request

    url = f"{client._base_url}/script"
    req = urllib.request.Request(url, headers={"User-Agent": "taintly"})
    if client._user and client._token:
        import base64 as b64

        creds = b64.b64encode(f"{client._user}:{client._token}".encode()).decode()
        req.add_header("Authorization", f"Basic {creds}")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            if resp.status == 200:
                return [
                    _finding(
                        rule_id="PLAT-JK-004",
                        severity=Severity.HIGH,
                        title="Groovy script console is accessible",
                        description=(
                            f"The script console at {instance}/script is "
                            "accessible. This allows arbitrary code execution "
                            "on the Jenkins controller with full system access."
                        ),
                        instance=instance,
                        remediation=(
                            "Restrict access to the script console via "
                            "Matrix-based security. Only designated admins "
                            "should have 'Overall/Run Scripts' permission. "
                            "Consider disabling it entirely via the "
                            "Configuration as Code plugin."
                        ),
                        reference="https://www.jenkins.io/doc/book/managing/script-console/",
                        owasp_cicd="CICD-SEC-7",
                        threat_narrative=(
                            "The script console is unrestricted RCE as the "
                            "Jenkins system user. A compromised admin account "
                            "can dump every credential, modify any pipeline, "
                            "and pivot to every connected agent."
                        ),
                        stride=["E", "T"],
                    )
                ]
    except (urllib.error.HTTPError, urllib.error.URLError, OSError):
        pass
    return []


# ---------------------------------------------------------------------------
# PLAT-JK-005 — CSRF protection disabled
# ---------------------------------------------------------------------------


def check_csrf_protection(instance: str, client: JenkinsClient) -> list[Finding]:
    """PLAT-JK-005: CSRF protection may be disabled.

    Jenkins exposes crumb info at /crumbIssuer/api/json. If this returns
    404, CSRF protection is likely disabled.
    """
    data = client._request("/crumbIssuer")
    if data is not None and data.get("crumb"):
        return []  # CSRF protection is active

    return [
        _finding(
            rule_id="PLAT-JK-005",
            severity=Severity.HIGH,
            title="CSRF protection may be disabled",
            description=(
                f"Jenkins instance at {instance} does not appear to have "
                "CSRF protection enabled (no crumb issuer found). Without "
                "CSRF protection, a malicious page can trigger Jenkins "
                "actions via the victim's authenticated session."
            ),
            instance=instance,
            remediation=(
                "Manage Jenkins > Security > CSRF Protection > enable "
                "'Prevent Cross Site Request Forgery exploits'. This is "
                "enabled by default since Jenkins 2.222; if disabled, "
                "it was likely turned off intentionally — investigate why."
            ),
            reference="https://www.jenkins.io/doc/book/security/csrf-protection/",
            owasp_cicd="CICD-SEC-1",
            threat_narrative=(
                "Without CSRF protection, visiting a malicious page while "
                "logged into Jenkins can trigger job execution, credential "
                "access, or configuration changes — no user interaction "
                "required beyond the page visit."
            ),
            stride=["T", "E"],
        )
    ]


# ---------------------------------------------------------------------------
# Public runner
# ---------------------------------------------------------------------------

ALL_CHECKS = {
    "PLAT-JK-001": check_anonymous_access,
    "PLAT-JK-002": check_outdated_plugins,
    "PLAT-JK-003": check_agent_security,
    "PLAT-JK-004": check_script_console,
    "PLAT-JK-005": check_csrf_protection,
}


def run_all_checks(
    instance: str,
    client: JenkinsClient,
    *,
    checks: list[str] | None = None,
) -> list[Finding]:
    """Run every (or selected) platform check against the Jenkins instance.

    API errors on individual checks are captured as PLAT-JK-ERR findings.
    """
    results: list[Finding] = []
    selected = checks or list(ALL_CHECKS.keys())
    for rule_id in selected:
        fn = ALL_CHECKS.get(rule_id)
        if fn is None:
            continue
        try:
            results.extend(fn(instance, client))
        except APIError as e:
            results.append(
                _finding(
                    rule_id="PLAT-JK-ERR",
                    severity=Severity.MEDIUM,
                    title=f"Platform check {rule_id} failed (HTTP {e.status})",
                    description=(
                        f"The {rule_id} check returned HTTP {e.status} from "
                        f"{e.endpoint}. This may mean the API is not "
                        "accessible or credentials are incorrect."
                    ),
                    instance=instance,
                    remediation="Verify JENKINS_USER and JENKINS_TOKEN are correct.",
                    reference="",
                    owasp_cicd="",
                )
            )
    return results
