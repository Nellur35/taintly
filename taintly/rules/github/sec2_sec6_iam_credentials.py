"""GitHub Actions security rules — Identity/Access Management and Credential Hygiene."""

from taintly.models import (
    AbsencePattern,
    Platform,
    RegexPattern,
    Rule,
    Severity,
)

RULES: list[Rule] = [
    # =========================================================================
    # CICD-SEC-2: Inadequate Identity and Access Management
    # =========================================================================
    Rule(
        id="SEC2-GH-001",
        title="Workflow grants write-all permissions",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-2",
        description=(
            "Workflow grants write access to ALL scopes. If any step is compromised, "
            "the attacker has full read/write access to the repository and all resources."
        ),
        pattern=RegexPattern(
            match=r"^\s*permissions:\s*write-all(\s*(#.*)?)?\s*$",
            exclude=[r"^\s*#"],
        ),
        remediation="Replace with minimal required permissions per job.",
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication",
        test_positive=["permissions: write-all", "  permissions: write-all"],
        test_negative=["permissions:\n  contents: read", "# permissions: write-all"],
        stride=["E"],
        threat_narrative=(
            "write-all grants the GITHUB_TOKEN read/write access to every repository scope — "
            "code, issues, packages, deployments, and secrets. "
            "Any step that is compromised, including a single malicious third-party action, inherits "
            "the ability to modify branches, create releases, or read and exfiltrate the token."
        ),
    ),
    Rule(
        id="SEC2-GH-002",
        title="No explicit permissions defined",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-2",
        description=(
            "Workflow does not define explicit permissions. Since February 2023 GitHub "
            "defaults the GITHUB_TOKEN to read-only for newly-created repositories, "
            "organisations, and enterprises. However, repositories created before that "
            "change — and any repository under an org/enterprise still set to the legacy "
            "'permissive (read/write)' workflow permissions option — inherit write-all "
            "across every scope. Declare explicit permissions so the effective scope "
            "does not silently depend on an org/enterprise toggle that can change under "
            "you."
        ),
        pattern=AbsencePattern(absent=r"^\s*permissions:", scope="file"),
        remediation=("Add a top-level permissions block:\npermissions:\n  contents: read"),
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token",
        test_positive=[
            "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest",
        ],
        test_negative=[
            "name: CI\npermissions:\n  contents: read\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest",
        ],
        stride=["E"],
        threat_narrative=(
            "Without an explicit permissions block, GITHUB_TOKEN defaults to the "
            "repository's base permission level. Repositories created before February "
            "2023 and repositories under organisations/enterprises still configured for "
            "'permissive' workflow permissions get write access across every scope. "
            "Omitting `permissions:` is a silent over-provisioning that gives every "
            "action in the workflow more access than it requires, and it breaks the "
            "moment an admin flips the org-level setting."
        ),
    ),
    # =========================================================================
    # CICD-SEC-6: Insufficient Credential Hygiene
    # =========================================================================
    Rule(
        id="SEC6-GH-001",
        title="Potential hardcoded secret in workflow",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-6",
        description="Potential hardcoded secret or credential detected in workflow file.",
        pattern=RegexPattern(
            match=r"""(?i)(password|passwd|secret|token|api_key|apikey|access_key|private_key)\s*[:=]\s*['"][^${\s][^'"]{8,}['"]""",
            exclude=[r"^\s*#", r"\$\{\{", r"secrets\."],
        ),
        remediation=(
            "Treat as a confirmed leak: rotate the secret at the upstream "
            "provider first (the value is already in git history and every "
            "fork/mirror/cache has a copy), audit its access scope, then "
            "move the value to GitHub Actions secrets and reference via "
            "${{ secrets.NAME }}. Run `taintly --guide SEC6-GH-001` for "
            "the full rotation/audit/history-scrub checklist."
        ),
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions",
        test_positive=[
            '        password: "MyS3cretP@ssw0rd!"',
            "        api_key: 'sk-1234567890abcdef1234'",
        ],
        test_negative=[
            "        password: ${{ secrets.DB_PASSWORD }}",
            "        # password: 'old_password'",
            '        api_key: ""',
        ],
        stride=["I"],
        threat_narrative=(
            "Secrets committed to workflow files are stored in git history permanently — even after "
            "removal they remain accessible in prior revisions to anyone who clones the repository. "
            "Every contributor, fork, and automated bot inherits the leaked credential."
        ),
    ),
    Rule(
        id="SEC6-GH-003",
        title="Long-lived cloud credentials instead of OIDC",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "Workflow uses long-lived cloud credentials (AWS access keys, GCP service account keys) "
            "instead of OIDC-based short-lived tokens. Long-lived credentials can be exfiltrated "
            "and reused — OIDC tokens are scoped and ephemeral."
        ),
        pattern=RegexPattern(
            match=r"(?i)(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GOOGLE_CREDENTIALS|AZURE_CREDENTIALS)\s*:",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Use OIDC for cloud authentication:\n"
            "permissions:\n  id-token: write\n"
            "- uses: aws-actions/configure-aws-credentials@<sha>\n"
            "  with:\n    role-to-assume: arn:aws:iam::123456:role/GitHubActions"
        ),
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect",
        test_positive=[
            "        AWS_ACCESS_KEY_ID: ${{ secrets.AWS_KEY }}",
            "        AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET }}",
        ],
        test_negative=[
            "        role-to-assume: arn:aws:iam::123456:role/GitHubActions",
            "        # AWS_ACCESS_KEY_ID: old",
        ],
        stride=["I", "E"],
        threat_narrative=(
            "Long-lived cloud credentials that are exfiltrated from a compromised pipeline run "
            "remain valid indefinitely — unlike OIDC tokens which expire within minutes. "
            "An attacker who reads an AWS access key from a build log or environment dump has "
            "persistent cloud access until the key is manually rotated."
        ),
    ),
    Rule(
        id="SEC7-GH-001",
        title="Self-hosted runner detected",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-7",
        description=(
            "Self-hosted runners are not ephemeral by default. They persist state between "
            "workflow runs — a compromised job can leave malware or stolen credentials for the next job."
        ),
        pattern=RegexPattern(
            match=r"runs-on:.*self-hosted",
            exclude=[r"^\s*#"],
        ),
        remediation="Use ephemeral runners (--ephemeral flag) or GitHub-hosted runners.",
        reference="https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners",
        test_positive=[
            "    runs-on: [self-hosted, linux]",
            "    runs-on: self-hosted",
        ],
        test_negative=[
            "    runs-on: ubuntu-latest",
            "    # runs-on: self-hosted",
        ],
        stride=["T", "I"],
        threat_narrative=(
            "Non-ephemeral self-hosted runners accumulate state between jobs — a compromised build "
            "can leave malware, modified tool binaries, or stolen credentials cached on the runner "
            "that affect every subsequent job on that machine. "
            "Unlike GitHub-hosted runners, self-hosted runners are not wiped between workflow runs."
        ),
    ),
]
