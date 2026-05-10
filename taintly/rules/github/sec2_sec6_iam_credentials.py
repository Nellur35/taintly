"""GitHub Actions security rules — Identity/Access Management and Credential Hygiene."""

import re

from taintly.models import (
    AbsencePattern,
    Platform,
    RegexPattern,
    Rule,
    Severity,
)
from taintly.structural_pattern import StructuralPattern


class _NoExplicitPermissionsPattern(AbsencePattern):
    """SEC2-GH-002 variant of AbsencePattern.

    Fires when a workflow has no ``permissions:`` block AT ANY LEVEL
    (file or job), UNLESS the workflow's only top-level trigger is
    ``workflow_call`` — i.e. it is a pure reusable workflow.

    Reusable workflows (``workflow_call``-only) inherit GITHUB_TOKEN
    permissions from the calling workflow.  When the caller's
    ``permissions:`` block is the policy boundary, a redundant
    declaration in the called workflow adds no security value and
    risks divergence from the caller's intent.  GitHub explicitly
    documents this inheritance:
    https://docs.github.com/en/actions/sharing-automations/reusing-workflows#access-and-permissions

    Subclassing AbsencePattern keeps this rule on the documented
    sentinel-snippet exception list in ``test_pattern_contract``
    (``isinstance`` succeeds for subclasses).
    """

    _ON_INLINE_RE = re.compile(r"^on[ \t]*:[ \t]*(\S[^\n]*)$", re.MULTILINE)
    # The two alternatives are mutually exclusive — content lines
    # require ``\S`` after the indent, blank lines require only
    # whitespace before the newline — so the engine doesn't have to
    # backtrack between them on adversarial whitespace-heavy input.
    _ON_BLOCK_RE = re.compile(
        r"(?ms)^on[ \t]*:[ \t]*\n((?:[ \t]+\S[^\n]*\n|[ \t]*\n)+?)(?=^\S|\Z)"
    )
    _KEY_RE = re.compile(r"^\s*([\w-]+)\s*:")

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if self._is_workflow_call_only(content):
            return []
        return super().check(content, lines)

    def _is_workflow_call_only(self, content: str) -> bool:
        """Return True iff the file's ``on:`` declaration names
        ``workflow_call`` and no other top-level trigger."""
        # Inline form — ``on: workflow_call`` or ``on: [workflow_call]``.
        m = self._ON_INLINE_RE.search(content)
        if m:
            value = m.group(1).split("#", 1)[0].strip()
            if value.startswith("["):
                triggers = re.findall(r"[a-z_]+", value)
                return triggers == ["workflow_call"]
            return value == "workflow_call"
        # Block form — collect top-level keys at the on: block's
        # minimum indent.  Comment-only lines and blank lines are
        # ignored; deeper-indented body keys (``inputs:``, ``branches:``)
        # are not top-level triggers and don't count.
        m = self._ON_BLOCK_RE.search(content)
        if not m:
            return False
        body = m.group(1)
        body_lines = body.splitlines()
        meaningful = []
        for line in body_lines:
            stripped = line.lstrip(" \t")
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(line) - len(stripped)
            meaningful.append((indent, stripped))
        if not meaningful:
            return False
        min_indent = min(ind for ind, _ in meaningful)
        block_triggers: list[str] = []
        for indent, stripped in meaningful:
            if indent != min_indent:
                continue
            km = self._KEY_RE.match(stripped)
            if km:
                block_triggers.append(km.group(1))
        return block_triggers == ["workflow_call"]


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
        pattern=_NoExplicitPermissionsPattern(absent=r"^\s*permissions:", scope="file"),
        remediation=(
            "Add a top-level permissions block:\npermissions:\n  contents: read\n\n"
            "Reusable workflows (``on: workflow_call``-only) inherit the calling "
            "workflow's permissions and do not need their own block — the rule already "
            "skips that shape."
        ),
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
        # Phase 2 migration: was ``RegexPattern(match=r"runs-on:.*self-hosted", ...)``;
        # the structural form queries the ``runs-on`` key at any
        # depth and fires when the value contains ``self-hosted``.
        # Handles string, flow-sequence, and block-sequence shapes
        # uniformly because the walker emits a leaf per scalar
        # element regardless of the surrounding container shape.
        pattern=StructuralPattern(
            # Both globs needed: ``runs-on: self-hosted`` (string
            # leaf at ``**.runs-on``) and ``runs-on: [self-hosted,
            # linux]`` (sequence-element leaves at
            # ``**.runs-on[*]``).
            path=["**.runs-on", "**.runs-on[*]"],
            predicate=lambda v, _vk, _p: "self-hosted" in v,
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
