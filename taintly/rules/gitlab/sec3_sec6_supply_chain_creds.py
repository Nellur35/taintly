"""GitLab CI security rules — Dependency Chain, Credential Hygiene, System Config."""

from taintly.models import (
    AbsencePattern,
    Platform,
    RegexPattern,
    Rule,
    SequencePattern,
    Severity,
)

RULES: list[Rule] = [
    # =========================================================================
    # CICD-SEC-3: Dependency Chain Abuse (GitLab)
    # =========================================================================
    Rule(
        id="SEC3-GL-001",
        title="Remote include without integrity verification",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "Pipeline includes a remote YAML file. Remote includes can be tampered with "
            "at the source — equivalent to unpinned GitHub Actions."
        ),
        pattern=RegexPattern(
            match=r"include:\s*\n\s*-\s*remote:|^\s*-\s*remote:",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Download the file and store it in your repository instead. "
            "If remote include is required, pin to a specific ref/SHA."
        ),
        reference="https://docs.gitlab.com/ci/pipeline_security/",
        test_positive=[
            "include:\n  - remote: 'https://example.com/ci.yml'",
        ],
        test_negative=[
            "include:\n  - local: '/ci/build.yml'",
            "# include:\n#   - remote: 'https://example.com/ci.yml'",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "A remote CI configuration included without integrity verification can be "
            "modified by anyone who controls the remote server, injecting arbitrary jobs or "
            "overriding existing stages in your pipeline with no change visible in your "
            "repository. The injected configuration runs with your project's runner token "
            "and protected variable access."
        ),
    ),
    # =========================================================================
    # SEC3-GL-006 — third-party include inventory (review-needed)
    # =========================================================================
    #
    # Fires INFO once per external ``include: project:`` or ``include:
    # component:`` reference.  Built for the ``--baseline`` / ``--diff``
    # workflow: initial scan lists every external CI dependency for
    # one-time review; subsequent scans surface only NEW dependencies
    # in diff output.  Distinct from SEC3-GL-001 (remote URL — HIGH;
    # different threat shape) and SEC3-GL-002 (project include without
    # pinned ref — HIGH).  Inventory has zero implicit threat assessment
    # — surfaces the dependency surface so a human can decide.
    Rule(
        id="SEC3-GL-006",
        title="Third-party include used (inventory; review-needed)",
        severity=Severity.INFO,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        review_needed=True,
        finding_family="Mutable dependency references",
        description=(
            "The pipeline includes CI configuration from another GitLab "
            "project (``include: project:``) or a CI Component "
            "(``include: component:``).  External includes are "
            "supply-chain dependencies — every fetch executes whatever "
            "stages the included project defines, with this project's "
            "runner token and protected-variable scope.  Use "
            "``--baseline`` to snapshot the current set of external "
            "includes and ``--diff`` on subsequent scans to surface "
            "only new dependencies that need review."
        ),
        pattern=RegexPattern(
            # Fires on either:
            #   project: 'group/project'        (or " or no quotes)
            #   component: '$CI_SERVER_FQDN/group/project/component@version'
            # Local includes (`local:`) and remote-URL includes
            # (`remote:`) are handled by SEC3-GL-001 with stricter
            # severity, so excluded here.
            match=r"^\s*-?\s*(?:project|component):\s*['\"]?(\S+)",
            exclude=[
                r"^\s*#",
                r"^\s*-?\s*(?:local|remote|file|inputs):",
            ],
        ),
        remediation=(
            "Each finding is the *first* occurrence of an external CI "
            "include in this scan; review the source project's owner, "
            "recent commits, and how it pins its own dependencies, then "
            "snapshot the inventory with ``--baseline``.  After "
            "baseline, only NEW external includes surface in ``--diff`` "
            "output.  Consider also gating includes via "
            "``ref: <commit-sha>`` (see SEC3-GL-002) so a force-pushed "
            "tag cannot silently change the included content."
        ),
        reference="https://docs.gitlab.com/ee/ci/yaml/includes.html",
        test_positive=[
            "  - project: 'mygroup/ci-templates'",
            '  - project: "acme-corp/shared"',
            "  - component: '$CI_SERVER_FQDN/group/component-project/component@1.0'",
        ],
        test_negative=[
            # Local include — not a third-party dep.
            "  - local: '/ci/build.yml'",
            # Remote URL — handled by SEC3-GL-001.
            "  - remote: 'https://example.com/ci.yml'",
            # `file:` is a sibling key inside a project block, not the
            # include source itself — the project: key in the same
            # block fires the finding.
            "    file: '/templates/build.yml'",
            # `inputs:` is the params block for a CI Component, not a
            # source.
            "    inputs:",
            # Comment.
            "  # - project: 'mygroup/ci-templates'",
        ],
        stride=["T"],
        threat_narrative=(
            "External CI includes execute their declared stages with "
            "this project's runner token and protected-variable scope. "
            "An attacker who compromises the included project, or "
            "force-pushes a tag the include resolves to, gains "
            "execution in every consumer's pipeline.  This rule does "
            "not claim any specific include is malicious — it surfaces "
            "the external dependency set so a human reviewer can make "
            "the trust decision once, with ``--baseline`` / ``--diff`` "
            "ensuring new additions don't slip through."
        ),
        confidence="medium",
    ),
    Rule(
        id="SEC3-GL-002",
        title="Project include without pinned ref",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "Pipeline includes a file from another project without pinning to a specific "
            "commit SHA. The included file can change without notice, and mutable branch/tag "
            "refs can be force-pushed to point at malicious content."
        ),
        pattern=SequencePattern(
            # Fire when project: key is NOT followed by a SHA ref within 5 lines.
            # RegexPattern(exclude=[r"ref:"]) cannot work here because ref: is on a
            # *different line* than project: in GitLab YAML include blocks.
            pattern_a=r"project:\s*['\"][^'\"]+['\"]",
            absent_within=r"ref:\s*['\"]?[a-f0-9]{40}['\"]?",
            lookahead_lines=5,
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Pin the include to a full 40-character commit SHA. Quote the SHA so YAML "
            "parses it as a string regardless of leading digits:\n"
            "\n"
            "include:\n"
            "  - project: 'my-group/my-project'\n"
            '    ref: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"\n'
            "    file: '/templates/ci.yml'\n"
            "\n"
            "Find the current SHA:\n"
            "  git ls-remote https://gitlab.com/my-group/my-project refs/heads/main"
        ),
        reference="https://docs.gitlab.com/ci/yaml/includes/",
        test_positive=[
            "  - project: 'my-group/my-project'\n    file: '/templates/ci.yml'",
            "  - project: 'my-group/my-project'\n    ref: main\n    file: '/templates/ci.yml'",
            "  - project: 'my-group/my-project'\n    ref: v1.2.3\n    file: '/templates/ci.yml'",
        ],
        test_negative=[
            "  - project: 'my-group/my-project'\n    ref: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n    file: '/templates/ci.yml'",
            "  # project: 'my-group/my-project'",
        ],
        stride=["T"],
        threat_narrative=(
            "A project include without a pinned ref changes with every commit to the "
            "included project, meaning a contributor to that project can silently modify "
            "what your pipeline executes on the next run. Pin includes to specific commit "
            "SHAs to ensure the included configuration is immutable."
        ),
    ),
    Rule(
        id="SEC3-GL-005",
        title="Docker image without digest pinning",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "Docker image referenced by tag instead of SHA256 digest. "
            "Image tags are mutable and can be overwritten on the registry."
        ),
        pattern=RegexPattern(
            match=r"^\s*image:\s*['\"]?[a-zA-Z0-9._/-]+:[a-zA-Z0-9._-]+['\"]?(\s*(#.*)?)?\s*$",
            exclude=[r"^\s*#", r"@sha256:"],
        ),
        remediation="Pin to digest: image: alpine@sha256:abcdef...",
        reference="https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier",
        test_positive=[
            "  image: alpine:3.18",
            "  image: node:20-slim",
            "  image: 'registry.example.com/app:latest'",
        ],
        test_negative=[
            "  image: alpine@sha256:abcdef1234567890",
            "  # image: alpine:3.18",
        ],
        stride=["T"],
        threat_narrative=(
            "Docker image tags are mutable: a registry push under the same tag silently "
            "replaces the execution environment for your jobs, giving the image publisher "
            "arbitrary code execution with access to all CI/CD variables and runner-mounted "
            "secrets. Pinning to a SHA256 digest makes the image reference immutable."
        ),
    ),
    # =========================================================================
    # SEC3-GL-004: pip --extra-index-url without --index-url — dependency
    # confusion.  GitLab port of SEC3-GH-008.  The resolver bug is a pip
    # property (highest-version-wins merge across indexes), so the attack
    # class is identical on any platform that shells out to pip.  Incident
    # reference: PyTorch dependency confusion, December 2022.
    # =========================================================================
    Rule(
        id="SEC3-GL-004",
        title="pip --extra-index-url used without --index-url (dependency confusion, GitLab)",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A GitLab CI ``script:`` line invokes pip install with "
            "``--extra-index-url`` (adds a secondary index) without "
            "``--index-url`` (replaces the primary).  pip's resolver "
            "merges both indexes with highest-version-wins semantics, "
            "and public PyPI names are first-party-registerable.  An "
            "attacker who registers your private package name on "
            "public PyPI with a higher version number wins the "
            "resolution — the PyTorch dependency-confusion incident "
            "of December 2022 used this exact shape."
        ),
        pattern=RegexPattern(
            match=r"pip\s+install[^\n]*--extra-index-url",
            exclude=[
                r"^\s*#",
                # Paired with --index-url is the safe form (private index
                # only, extra is an explicit secondary — and not public PyPI).
                r"--index-url\b(?!\s*=?\s*https?://pypi\.org)",
            ],
        ),
        remediation=(
            "Use --index-url to point pip at your private index\n"
            "exclusively, and mirror required public packages into it.\n"
            "If you must consult public PyPI, use a tool that supports\n"
            "explicit package-to-index pinning (uv, poetry's source\n"
            "priority='explicit', or pip-tools with hash-locking):\n\n"
            "# BAD — public PyPI can win resolution for private names\n"
            "pip install --extra-index-url https://pypi.internal.corp/ mypackage\n\n"
            "# GOOD — only the private index is consulted; mirror\n"
            "# public packages into it via Artifactory or Nexus\n"
            "pip install --index-url https://pypi.internal.corp/ mypackage"
        ),
        reference="https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
        test_positive=[
            "install:\n  script:\n    - pip install --extra-index-url https://pypi.internal.corp/ mypackage",
            "build:\n  script:\n    - pip install -r requirements.txt --extra-index-url https://internal/",
        ],
        test_negative=[
            "install:\n  script:\n    - pip install --index-url https://pypi.internal.corp/ mypackage",
            "# legacy: pip install --extra-index-url https://internal/",
            "install:\n  script:\n    - pip install requests",
        ],
        stride=["T", "S"],
        threat_narrative=(
            "Dependency confusion exploits pip's permissive resolver: "
            "when a private package name is also registerable on public "
            "PyPI, an attacker uploads a same-named package with a "
            "higher version number and pip silently prefers it.  The "
            "malicious package's install hooks execute as the build "
            "user with access to ``CI_JOB_TOKEN`` and any CI/CD "
            "variables visible to the job."
        ),
        incidents=["PyTorch dependency confusion (Dec 2022, GH analog)"],
    ),
    # =========================================================================
    # CICD-SEC-6: Insufficient Credential Hygiene (GitLab)
    # =========================================================================
    Rule(
        id="SEC6-GL-001",
        title="Potential hardcoded secret in pipeline config",
        severity=Severity.CRITICAL,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        description="Potential hardcoded secret or credential detected in .gitlab-ci.yml.",
        pattern=RegexPattern(
            match=r"""(?i)(password|passwd|secret|token|api_key|apikey|access_key|private_key)\s*[:=]\s*['"][^${\s][^'"]{8,}['"]""",
            exclude=[r"^\s*#", r"\$\{", r"\$CI_"],
        ),
        remediation="Move secrets to GitLab CI/CD variables (Settings > CI/CD > Variables) with protected + masked flags.",
        reference="https://docs.gitlab.com/ci/pipeline_security/",
        test_positive=[
            '    password: "MyS3cretP@ssw0rd!"',
            "    api_key: 'sk-1234567890abcdef1234'",
        ],
        test_negative=[
            "    password: $CI_DB_PASSWORD",
            "    # password: 'old_password'",
        ],
        stride=["I"],
        threat_narrative=(
            "Secrets committed to pipeline configuration are stored permanently in git "
            "history and readable by anyone who clones the repository, including all "
            "contributors and, in public projects, the entire internet. Every fork, mirror, "
            "and backup of the repository permanently contains the leaked credential."
        ),
    ),
    Rule(
        id="SEC6-GL-002",
        title="curl piped to shell in script block",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "Script downloads and executes remote code in one step. If the remote resource "
            "is compromised, arbitrary code executes in the pipeline runner."
        ),
        pattern=RegexPattern(
            match=r"curl\s.*\|\s*(bash|sh|zsh|python|perl)",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Download the script first, verify its checksum, then execute:\n"
            "curl -o script.sh https://...\n"
            "echo '<expected_hash>  script.sh' | sha256sum -c -\n"
            "bash script.sh"
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/",
        test_positive=[
            "    - curl -sSL https://install.example.com | bash",
            "    - curl https://raw.githubusercontent.com/org/repo/main/setup.sh | sh",
        ],
        test_negative=[
            "    - curl -o script.sh https://example.com/setup.sh",
            "    # curl https://example.com | bash",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Piping a remote URL directly to bash with no integrity check grants the server "
            "operator — or any attacker who can hijack the connection via DNS or BGP — "
            "arbitrary code execution in your pipeline with access to all GitLab CI "
            "variables. Supply chain attacks frequently target popular install scripts "
            "precisely because this pattern is so common."
        ),
    ),
    Rule(
        id="SEC6-GL-003",
        title="TLS verification disabled",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        description="TLS verification is disabled, enabling man-in-the-middle attacks.",
        pattern=RegexPattern(
            match=r"(--insecure|--no-check-certificate|verify\s*=\s*False|SSL_CERT_FILE=/dev/null|GIT_SSL_NO_VERIFY|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0)",
            exclude=[r"^\s*#"],
        ),
        remediation="Remove TLS bypass flags. Fix certificate issues properly.",
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/",
        test_positive=[
            "    - curl --insecure https://internal.example.com",
            "    - wget --no-check-certificate https://example.com",
            "    GIT_SSL_NO_VERIFY: true",
        ],
        test_negative=[
            "    - curl https://example.com",
            "    # --insecure",
        ],
        stride=["I", "T"],
        threat_narrative=(
            "Disabling TLS verification removes the only cryptographic guarantee that the "
            "server you are talking to is who it claims to be, opening the connection to "
            "MITM attacks that can silently read credentials in transit and substitute "
            "malicious responses. This is especially dangerous when credentials are sent as "
            "part of the same request."
        ),
    ),
    Rule(
        id="SEC6-GL-004",
        title="eval usage in script block",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "eval executes arbitrary strings as code. If the evaluated string includes "
            "user-controlled input, it enables code injection."
        ),
        pattern=RegexPattern(
            match=r"^\s*-?\s*eval\s+",
            exclude=[r"^\s*#", r"echo", r"do not"],
        ),
        remediation="Replace eval with direct command execution. Avoid evaluating dynamic strings.",
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/",
        test_positive=[
            '    - eval "$DYNAMIC_COMMAND"',
            "    - eval $(generate_config)",
        ],
        test_negative=[
            "    # eval is dangerous",
            "    - echo 'do not eval this'",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "eval() executes any string as shell code at runtime, making the pipeline's "
            "behavior dependent on data that may be influenced by external inputs or "
            "environment variables. Attackers who can influence the evaluated string — "
            "through environment injection, compromised scripts, or attacker-controlled CI "
            "variables — gain arbitrary code execution."
        ),
    ),
    Rule(
        id="SEC6-GL-005",
        title="chmod 777 in script block",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        description="World-writable permissions set on files. Any process can modify them.",
        pattern=RegexPattern(
            match=r"chmod\s+777",
            exclude=[r"^\s*#"],
        ),
        remediation="Use minimal permissions: chmod 755 for executables, chmod 644 for files.",
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/",
        test_positive=["    - chmod 777 /app/deploy.sh"],
        test_negative=["    - chmod 755 /app/deploy.sh", "    # chmod 777"],
        stride=["E"],
        threat_narrative=(
            "chmod 777 grants read, write, and execute permission to every user on the "
            "runner system, including other jobs running concurrently on a shared runner. "
            "On self-hosted runners, world-writable files are a common persistence "
            "mechanism used after initial code execution — modified scripts survive across "
            "jobs."
        ),
    ),
    # =========================================================================
    # CICD-SEC-10: Insufficient Logging and Visibility (GitLab)
    # =========================================================================
    Rule(
        id="SEC10-GL-002",
        title="Public pipelines may expose job logs",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-10",
        description=(
            "In public (and internal) GitLab projects, pipeline and job log visibility "
            "is controlled by the CI/CD feature visibility setting, not by the pipeline "
            "YAML. Logs may contain sensitive output (dependency versions, internal "
            "hostnames, non-masked environment values) and be readable by unauthenticated "
            "users. This is a GitLab project setting, not a pipeline config — the rule is "
            "a reminder to verify the project configuration outside the repository."
        ),
        pattern=AbsencePattern(
            absent=r"THIS_RULE_NEVER_MATCHES_INTENTIONALLY_DISABLED",
        ),
        remediation=(
            "Pipeline/log visibility is governed by two GitLab project settings, both "
            "outside the YAML:\n"
            "\n"
            "1. Primary control — Settings > General > Visibility, project features, "
            "permissions > 'CI/CD': set to 'Only Project Members' if non-members should "
            "not see pipelines or logs. This applies regardless of project visibility.\n"
            "\n"
            "2. Secondary control — Settings > CI/CD > General pipelines > "
            "'Project-based pipeline visibility' (formerly labelled 'Public pipelines'). "
            "Clear this checkbox to further restrict pipeline viewing beyond what the "
            "feature-visibility dropdown allows.\n"
            "\n"
            "If the project does not need to be public, lowering project visibility to "
            "Internal or Private under Settings > General > Visibility is the most "
            "effective mitigation."
        ),
        reference="https://docs.gitlab.com/ci/pipelines/settings/#change-pipeline-visibility-for-non-project-members",
        test_positive=[],  # This is a reminder rule, not a pattern match
        test_negative=[],
        stride=["I", "R"],
        threat_narrative=(
            "In public GitLab projects, job logs are accessible to unauthenticated users, "
            "meaning any CI/CD variable value printed to a log — even non-masked ones — is "
            "publicly readable. Verbose build output, dependency resolution logs, and "
            "environment dumps can all expose internal paths, package versions, and "
            "configuration values useful for targeted attacks."
        ),
    ),
]
