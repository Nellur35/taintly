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
# PLAT-JK-006 — Plugin advisory-feed cross-check
# ---------------------------------------------------------------------------


# The Jenkins infrastructure team publishes a machine-readable feed of
# security warnings at this URL — confirmed against
# github.com/jenkins-infra/update-center2 (the project that produces the
# update center index). The feed is a flat JSON array of warning entries.
#
# Schema (verified 2026-05-09 against the published feed):
#   [
#     {
#       "id": "SECURITY-208",
#       "type": "plugin" | "core",
#       "name": "<plugin-short-name>",       # for type=plugin; "core" for type=core
#       "message": "<advisory description>",
#       "url": "https://jenkins.io/security/advisory/<date>/",
#       "versions": [
#         {
#           "firstVersion": "1.3.0",          # optional, inclusive lower bound
#           "lastVersion":  "2.5.1",          # optional, inclusive upper bound
#           "pattern": "(1[.][34]|2[.][012])(|[.-].*)"  # regex matching vulnerable versions
#         },
#         ...
#       ]
#     },
#     ...
#   ]
#
# The ``pattern`` regex is the most precise check — it directly matches
# the version string. ``firstVersion`` / ``lastVersion`` are looser
# bounds. Severity is NOT in the feed; it lives on the linked HTML
# advisory page, so this rule defaults to HIGH and can't auto-escalate.
_JENKINS_ADVISORY_FEED = (
    "https://raw.githubusercontent.com/jenkins-infra/update-center2"
    "/master/resources/warnings.json"
)


def _version_matches_warning_entry(installed: str, entry: dict) -> bool:
    """Return True when ``installed`` falls in the warning entry's
    affected version range.

    Tries ``pattern`` (regex) first — the most precise; the published
    feed uses regex patterns to encode complex range-and-exclusion
    rules. Falls back to ``firstVersion`` / ``lastVersion`` tuple
    comparison when ``pattern`` is absent or unparseable.

    Conservative bias: matches when uncertain. Better to surface a
    finding the user can verify against the linked advisory than to
    silently miss a CVE.
    """
    import re

    pattern = entry.get("pattern")
    if pattern:
        try:
            # The feed's patterns anchor implicitly at start (they're
            # used with Java's Pattern.matches semantics). Match from
            # start, allow trailing.
            if re.match(pattern + r"$", installed):
                return True
            if re.match(pattern + r"(?:\s|$)", installed):
                return True
        except re.error:
            # Bad regex in the feed — fall through to bound check.
            pass

    def _to_tuple(v: str) -> tuple:
        head = v.split("-", 1)[0]
        parts = []
        for p in head.split("."):
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(0)
        return tuple(parts)

    first = entry.get("firstVersion")
    last = entry.get("lastVersion")
    if not first and not last:
        # No bounds AND pattern didn't match — no signal we can act on.
        return False

    try:
        inst_t = _to_tuple(installed)
        if first and inst_t < _to_tuple(first):
            return False
        if last and inst_t > _to_tuple(last):
            return False
        return True
    except Exception:
        return False


def check_plugin_advisories(instance: str, client: JenkinsClient) -> list[Finding]:
    """PLAT-JK-006: Installed plugin matches a published security advisory.

    Pairs with PLAT-JK-002 to close the disclosed-but-not-yet-patched
    window. PLAT-JK-002 catches "behind on updates" via the runtime
    ``hasUpdate`` flag; this rule catches "running a known-bad version"
    directly against the published advisory feed.

    Network: fetches the Jenkins update-center2 warnings feed. Failure
    to fetch produces a single LOW operational finding (feed
    unavailable); the rule does not silently skip.

    Severity: defaults to HIGH for every match. The feed does NOT carry
    severity — it lives on the linked advisory HTML page. We don't
    parse HTML to escalate; reviewers should read the linked page.
    Core (Jenkins itself) CVEs are out of scope for this rule and
    intentionally skipped — a separate rule could check
    ``instance_info().version`` against ``type:"core"`` entries.
    """
    feed = client.fetch_external(_JENKINS_ADVISORY_FEED, timeout=15)
    if feed is None:
        return [
            _finding(
                rule_id="PLAT-JK-006",
                severity=Severity.LOW,
                title="Jenkins security warnings feed unavailable",
                description=(
                    f"Could not fetch {_JENKINS_ADVISORY_FEED}. The plugin "
                    "advisory cross-check (PLAT-JK-006) cannot run. This is "
                    "operational signal, not a security finding — verify "
                    "the audit host can reach raw.githubusercontent.com, "
                    "or run the audit from a host that can. PLAT-JK-002 "
                    "(outdated-plugins) still ran and provides partial "
                    "coverage."
                ),
                instance=instance,
                remediation=(
                    "Manually verify installed plugin versions against the "
                    "published advisories at "
                    "https://www.jenkins.io/security/advisories/, or "
                    "re-run the posture audit from a host with outbound "
                    "HTTPS to githubusercontent.com."
                ),
                reference=_JENKINS_ADVISORY_FEED,
                owasp_cicd="CICD-SEC-3",
                threat_narrative=(
                    "Without the advisory cross-check, PLAT-JK-002's "
                    "``hasUpdate`` flag is the only signal that a plugin "
                    "is at risk. Between disclosure and patch, that flag "
                    "is false even on actively-exploited versions."
                ),
                stride=["I"],
            )
        ]

    plugins = client.plugins()
    if not plugins:
        return []

    # Normalise installed plugins into {short_name: version} for O(1) lookup.
    installed_index: dict[str, str] = {}
    for p in plugins:
        if not p.get("active"):
            continue
        short = p.get("shortName") or ""
        version = p.get("version") or ""
        if short and version:
            installed_index[short] = version

    # The feed is a flat list of warning entries. Defensive: also accept
    # an envelope shape ``{"warnings": [...]}`` in case the feed structure
    # ever changes.
    if isinstance(feed, list):
        warnings = feed
    elif isinstance(feed, dict):
        warnings = feed.get("warnings") or feed.get("advisories") or []
    else:
        warnings = []

    findings: list[Finding] = []
    seen_pairs: set[tuple[str, str]] = set()
    for warn in warnings:
        if not isinstance(warn, dict):
            continue
        warn_type = warn.get("type", "")
        if warn_type != "plugin":
            # Skip core and unknown types — out of scope for this rule.
            continue
        plugin_name = warn.get("name") or ""
        if not plugin_name or plugin_name not in installed_index:
            continue
        installed_version = installed_index[plugin_name]
        warn_id = warn.get("id") or "unknown"
        affected_versions = warn.get("versions") or []
        if not isinstance(affected_versions, list):
            continue

        # The plugin is in some affected range if ANY of the version
        # entries match the installed version.
        matched = False
        for entry in affected_versions:
            if isinstance(entry, dict) and _version_matches_warning_entry(
                installed_version, entry
            ):
                matched = True
                break
        if not matched:
            continue

        key = (plugin_name, warn_id)
        if key in seen_pairs:
            continue
        seen_pairs.add(key)

        warn_url = warn.get("url") or (
            f"https://www.jenkins.io/security/advisory/"
        )
        warn_message = warn.get("message") or ""

        findings.append(
            _finding(
                rule_id="PLAT-JK-006",
                severity=Severity.HIGH,
                title=(
                    f"Plugin '{plugin_name}' v{installed_version} matches "
                    f"security advisory {warn_id}"
                ),
                description=(
                    f"Plugin '{plugin_name}' is installed at version "
                    f"'{installed_version}'. The Jenkins security team "
                    f"has published advisory {warn_id} affecting this "
                    f"version: {warn_message}. Plugin RCE is the most-"
                    "exploited initial-access vector for Jenkins "
                    "controllers. Patch immediately or disable the "
                    "plugin. Severity is not carried in the feed JSON; "
                    "read the linked advisory for the upstream rating."
                ),
                instance=instance,
                remediation=(
                    f"Read the advisory at {warn_url}. If a patched "
                    "version exists, update via Manage Jenkins > "
                    "Plugins > Updates. If no patch exists, disable "
                    "the plugin until one ships."
                ),
                reference=warn_url,
                owasp_cicd="CICD-SEC-3",
                threat_narrative=(
                    "An installed plugin matches a published Jenkins "
                    "security advisory. Plugin CVEs are actively "
                    "exploited — this is the surface DDoS-botnet "
                    "recruitment scanners probe after fingerprinting "
                    "an exposed controller. Closing this gap is the "
                    "highest-priority action."
                ),
                stride=["E", "T"],
            )
        )

    return findings


# ---------------------------------------------------------------------------
# PLAT-JK-007 — Setup wizard skipped / security disabled
# ---------------------------------------------------------------------------


def check_setup_wizard_completed(instance: str, client: JenkinsClient) -> list[Finding]:
    """PLAT-JK-007: Jenkins controller has authentication entirely
    disabled (``useSecurity: false``).

    Setup-wizard-skipped state. Jenkins's first-run wizard creates an
    admin user and turns ``useSecurity`` on; controllers where the wizard
    was bypassed (or security was later turned off) accept anonymous
    admin operations. Most DDoS-botnet recruitment scanners look for this
    exact state.

    PLAT-JK-001 covers anonymous READ; this rule fires when authentication
    is off entirely (which is strictly worse — anonymous WRITE).
    """
    info = client.instance_info()
    if info is None:
        return []

    # Jenkins's top-level API exposes ``useSecurity`` as a boolean. When
    # absent, default to True (modern Jenkins enables security by default).
    use_security = info.get("useSecurity", True)
    if use_security is False:
        return [
            _finding(
                rule_id="PLAT-JK-007",
                severity=Severity.CRITICAL,
                title="Jenkins controller has authentication disabled",
                description=(
                    f"Jenkins instance at {instance} has ``useSecurity: "
                    "false`` — authentication is entirely disabled. Any "
                    "unauthenticated request can manage jobs, run "
                    "Groovy via the Script Console, install plugins, "
                    "and read/write all credentials. This is the most "
                    "egregious misconfiguration; setup-wizard-skipped "
                    "state, or a deliberate ``useSecurity: false`` set "
                    "via config-as-code or the script console."
                ),
                instance=instance,
                remediation=(
                    "Manage Jenkins > Configure Global Security > enable "
                    "Security and configure an authentication realm. If "
                    "the instance is publicly reachable, treat any data "
                    "or build artefacts on it as compromised — assume an "
                    "attacker has had unauthenticated admin access."
                ),
                reference=(
                    "https://www.jenkins.io/doc/book/security/securing-jenkins/"
                ),
                owasp_cicd="CICD-SEC-1",
                threat_narrative=(
                    "An attacker can run arbitrary Groovy via Script "
                    "Console without any credentials. Common DDoS-botnet "
                    "scanners specifically look for this state — it's "
                    "the highest-yield target on the public internet "
                    "(direct controller takeover, no credential probing "
                    "required)."
                ),
                stride=["S", "T", "E"],
            )
        ]
    return []


# ---------------------------------------------------------------------------
# PLAT-JK-010 — Update Center URL integrity
# ---------------------------------------------------------------------------


_CANONICAL_UPDATE_CENTERS = frozenset(
    {
        # Default Jenkins update center.
        "https://updates.jenkins.io/update-center.json",
        # Long-Term Support (LTS) update center.
        "https://updates.jenkins.io/stable/update-center.json",
        # Versioned LTS branches use stable-{version}/. Pattern check
        # below covers these without enumerating every major version.
    }
)


def _is_canonical_update_center(url: str) -> bool:
    """Return True for known-good update center URLs.

    Allows ``https://updates.jenkins.io/...`` (any path) since that's
    the canonical host. Anything else — custom host, plain HTTP, an
    on-prem mirror — fires the rule.
    """
    if not url:
        return False
    if url.startswith("https://updates.jenkins.io/"):
        return True
    if url in _CANONICAL_UPDATE_CENTERS:
        return True
    return False


def check_update_center_integrity(
    instance: str, client: JenkinsClient
) -> list[Finding]:
    """PLAT-JK-010: Configured Update Center URL is non-canonical.

    Every plugin install pulls its descriptor (and signing key chain)
    from the configured update center. A replaced URL — pointing at a
    custom or compromised mirror — turns every "Manage Jenkins >
    Plugins > Available" click into RCE.

    The default update center is ``https://updates.jenkins.io/...``.
    Custom on-prem mirrors are sometimes legitimate in air-gapped
    environments; this rule fires HIGH so a maintainer reviews the
    URL and confirms (or fixes).
    """
    sites = client.update_sites()
    if not sites:
        return []

    findings: list[Finding] = []
    for site in sites:
        url = site.get("url", "")
        site_id = site.get("id", "default")
        if _is_canonical_update_center(url):
            continue
        # Non-canonical — fire HIGH.
        findings.append(
            _finding(
                rule_id="PLAT-JK-010",
                severity=Severity.HIGH,
                title=f"Non-canonical Update Center URL: {site_id}",
                description=(
                    f"Update Center site '{site_id}' points to "
                    f"'{url}' instead of the canonical "
                    "https://updates.jenkins.io/update-center.json. "
                    "Every plugin install fetches its descriptor and "
                    "signing-key chain from this URL — a replaced or "
                    "compromised update center turns plugin "
                    "installation into a remote-code-execution "
                    "primitive. Custom on-prem mirrors are sometimes "
                    "legitimate (air-gapped controllers); this rule "
                    "asks a maintainer to verify."
                ),
                instance=instance,
                remediation=(
                    "Manage Jenkins > Manage Plugins > Advanced > "
                    "Update Site URL. Set to "
                    "https://updates.jenkins.io/update-center.json "
                    "unless an air-gapped mirror is required and the "
                    "mirror's signing-key chain is independently "
                    "verified."
                ),
                reference=(
                    "https://www.jenkins.io/doc/book/managing/plugins/"
                ),
                owasp_cicd="CICD-SEC-3",
                threat_narrative=(
                    "An attacker who can replace the update center URL "
                    "(via a prior compromise, social engineering, or a "
                    "malicious config-as-code commit) controls every "
                    "subsequent plugin install — the descriptor JSON "
                    "names the .hpi to download, and the controller "
                    "fetches and runs whatever the URL returns."
                ),
                stride=["T", "E"],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Public runner
# ---------------------------------------------------------------------------

ALL_CHECKS = {
    "PLAT-JK-001": check_anonymous_access,
    "PLAT-JK-002": check_outdated_plugins,
    "PLAT-JK-003": check_agent_security,
    "PLAT-JK-004": check_script_console,
    "PLAT-JK-005": check_csrf_protection,
    "PLAT-JK-006": check_plugin_advisories,
    "PLAT-JK-007": check_setup_wizard_completed,
    "PLAT-JK-010": check_update_center_integrity,
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
