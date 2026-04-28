"""GitLab CI rules — IAM, PPE (extended), credential hygiene, 3rd-party services,
artifact integrity, and logging/visibility.

Covers OWASP CICD-SEC-2, SEC-4 (extended), SEC-6 (extended), SEC-8 (extended),
SEC-9 (extended), SEC-10 (extended).
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
    # CICD-SEC-2: Inadequate Identity and Access Management
    # =========================================================================
    Rule(
        id="SEC2-GL-001",
        title="Docker registry credentials defined in pipeline YAML (DOCKER_AUTH_CONFIG)",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-2",
        description=(
            "DOCKER_AUTH_CONFIG is defined in the pipeline YAML, embedding Docker registry "
            "credentials directly in version-controlled configuration. "
            "DOCKER_AUTH_CONFIG contains base64-encoded registry credentials — anyone with "
            "read access to the repository can decode and reuse them. "
            "Registry credentials should be stored as masked, protected CI/CD variables in "
            "GitLab project or group settings, never in the pipeline file."
        ),
        pattern=RegexPattern(
            match=r"DOCKER_AUTH_CONFIG\s*:",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Move DOCKER_AUTH_CONFIG to GitLab CI/CD variables (Settings > CI/CD > Variables) "
            "with 'Masked' and 'Protected' flags enabled. The variable is injected at runtime "
            "without being stored in the pipeline YAML."
        ),
        reference="https://docs.gitlab.com/ee/ci/docker/using_docker_images.html#configure-a-registry-authentication-file",
        test_positive=[
            'variables:\n  DOCKER_AUTH_CONFIG: \'{"auths": {"registry.example.com": {"auth": "abc"}}}\'',
            "  DOCKER_AUTH_CONFIG: $MY_ENCODED_AUTH",
        ],
        test_negative=[
            "  # DOCKER_AUTH_CONFIG: should be a protected CI/CD variable",
            "  DOCKER_HOST: tcp://docker:2376",
        ],
        stride=["I", "E"],
        threat_narrative=(
            "DOCKER_AUTH_CONFIG contains base64-encoded registry credentials that are decoded "
            "and reused by anyone with read access to the repository or its git history. "
            "An attacker with these credentials can push backdoored images to your private "
            "registry that your pipelines then pull and execute."
        ),
    ),
    Rule(
        id="SEC2-GL-002",
        title="Docker-in-Docker service without TLS certificate directory — daemon socket exposed",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-2",
        description=(
            "A job uses docker:dind (Docker-in-Docker) without setting DOCKER_TLS_CERTDIR "
            "to a non-empty path. Without TLS, the Docker daemon socket is exposed "
            "unencrypted on TCP port 2375, reachable by any process in the same runner "
            "network namespace. An attacker who can execute code in a co-tenant container "
            "or inject a malicious script step can connect to the unprotected daemon and "
            "escape to the runner host."
        ),
        pattern=ContextPattern(
            anchor=r"docker[:/][a-zA-Z0-9._-]*dind",
            requires=r"docker[:/][a-zA-Z0-9._-]*dind",
            requires_absent=r"DOCKER_TLS_CERTDIR\s*:",
            scope="file",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Set all four variables that GitLab's canonical DinD example specifies so "
            "the Docker CLI in the job container can find and validate the TLS client "
            "certificate material published by the dind service:\n"
            "\n"
            "variables:\n"
            '  DOCKER_TLS_CERTDIR: "/certs"\n'
            "  DOCKER_HOST: tcp://docker:2376\n"
            '  DOCKER_TLS_VERIFY: "1"\n'
            '  DOCKER_CERT_PATH: "$DOCKER_TLS_CERTDIR/client"\n'
            "\n"
            "services:\n"
            "  - docker:dind\n"
            "\n"
            "Omitting DOCKER_CERT_PATH leaves the client-side of the connection "
            "unauthenticated even though the daemon listens on the TLS port."
        ),
        reference="https://docs.gitlab.com/ci/docker/using_docker_build/",
        test_positive=[
            "services:\n  - docker:dind\nbuild:\n  script:\n    - docker build .",
            "services:\n  - docker:24.0-dind\nvariables:\n  DOCKER_HOST: tcp://docker:2375",
        ],
        test_negative=[
            "variables:\n  DOCKER_TLS_CERTDIR: '/certs'\nservices:\n  - docker:dind",
            "services:\n  - postgres:15",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "A DinD daemon without TLS exposes the Docker socket unencrypted on TCP port 2375, "
            "reachable by any process in the same runner network namespace. "
            "An attacker who can execute code in a co-tenant container or inject a malicious "
            "script step can connect to the unprotected daemon, spawn privileged containers, "
            "and escape to the runner host."
        ),
    ),
    # =========================================================================
    # SEC2-GL-003: hardcoded service-instance password in variables/services.
    # GitLab port of SEC2-GH-004. GitLab jobs use ``services:`` for sidecars
    # (postgres, mysql, redis, etc.) and pass instance credentials through
    # a ``variables:`` block.  The canonical insecure shape is a literal
    # string in a ``*_PASSWORD`` variable.  The safe shape is ``$CI_...``
    # or ``$VAR_NAME`` that resolves to a masked/protected CI/CD variable.
    # =========================================================================
    Rule(
        id="SEC2-GL-003",
        title="Hardcoded database / service password in pipeline YAML",
        severity=Severity.CRITICAL,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-2",
        description=(
            "A ``*_PASSWORD`` / ``*_USER`` variable is assigned a literal "
            "string value (not a ``$VAR`` reference) in a GitLab pipeline "
            "file.  Common targets: ``POSTGRES_PASSWORD``, "
            "``MYSQL_PASSWORD``, ``MARIADB_PASSWORD``, ``MONGO_PASSWORD``, "
            "``REDIS_PASSWORD``, ``RABBITMQ_DEFAULT_PASS``, "
            "``MINIO_ROOT_PASSWORD``, ``ADMIN_PASSWORD``, ``DB_PASSWORD``, "
            "``DATABASE_PASSWORD``, ``ROOT_PASSWORD``.  These feed the "
            "matching ``services:`` sidecar image (or the job's own "
            "``image:``) at runtime — a literal here means anyone with "
            "read access to the repository sees the credential, including "
            "every fork and every git-history clone.  Safe form: move "
            "the value to a Masked + Protected CI/CD variable under "
            "Settings > CI/CD > Variables and reference it as ``$VAR``."
        ),
        pattern=RegexPattern(
            # Anchor on the literal-string shape: key with a password
            # suffix, colon, optional quote, then a value whose literal
            # portion is 4+ contiguous non-whitespace, non-quote,
            # non-comment characters.  ``(?![\$#{])`` excludes the three
            # reference shapes GitLab uses for variable expansion:
            # ``$VAR``, ``${VAR}``, and ``${{ ... }}`` (the last is rare
            # in GL but documented).  Allow optional trailing whitespace
            # and a ``# comment`` so we fire on
            # ``POSTGRES_PASSWORD: hunter2  # testing`` (still a leaked
            # literal) but do not fire on
            # ``POSTGRES_PASSWORD: x  # dev placeholder``
            # because ``x`` is < 4 chars and obviously a placeholder.
            match=(
                r"^\s*(?:POSTGRES|MYSQL|MARIADB|MONGO|MONGODB|REDIS|"
                r"RABBITMQ(?:_DEFAULT)?|MINIO(?:_ROOT)?|ELASTIC|"
                r"NEO4J|COUCHDB|KEYCLOAK|GRAFANA|PGADMIN|ADMIN|ROOT|"
                r"DB|DATABASE|SQL|MQTT|SMTP|LDAP|API)_(?:PASSWORD|PASS)"
                r"\s*:\s*['\"]?(?![\$#{])[^\s'\"#]{4,}['\"]?"
                r"\s*(?:#[^\n]*)?\s*$"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Move the credential to a GitLab CI/CD variable (Settings >\n"
            "CI/CD > Variables) with Masked + Protected flags, then\n"
            "reference it:\n"
            "\n"
            "variables:\n"
            "  POSTGRES_PASSWORD: $POSTGRES_PASSWORD   # resolved at runtime\n"
            "\n"
            "For per-service credentials (GitLab 12.3+):\n"
            "\n"
            "services:\n"
            "  - name: postgres:15\n"
            "    variables:\n"
            "      POSTGRES_PASSWORD: $POSTGRES_PASSWORD\n"
            "      POSTGRES_USER: $POSTGRES_USER\n"
            "\n"
            "If the value is a local-dev fixture that never authenticates\n"
            "to anything real, add ``# taintly: ignore[SEC2-GL-003]``\n"
            "on the line with a comment explaining why."
        ),
        reference=("https://docs.gitlab.com/ee/ci/variables/#add-a-cicd-variable-to-a-project"),
        test_positive=[
            "variables:\n  POSTGRES_PASSWORD: myrealpassword123",
            "  MYSQL_PASSWORD: 'p@ssw0rd!'",
            '  REDIS_PASSWORD: "hardcoded_secret"',
            "services:\n  - name: postgres:15\n    variables:\n      POSTGRES_PASSWORD: literal_value",
            "variables:\n  RABBITMQ_DEFAULT_PASS: guestpass123",
        ],
        test_negative=[
            # $VAR reference — GitLab-variable form, safe.
            "variables:\n  POSTGRES_PASSWORD: $POSTGRES_PASSWORD",
            # ${} expansion — also a variable reference.
            "  MYSQL_PASSWORD: ${DB_PASSWORD}",
            # $CI_* — GitLab-provided variable.
            "  ADMIN_PASSWORD: $CI_REGISTRY_PASSWORD",
            # Comment.
            "  # POSTGRES_PASSWORD: old_dev_password",
            # Unrelated key — not one of the targeted suffixes.
            "  POSTGRES_DB: mydb",
            # Too short — not worth flagging literals that short are
            # almost certainly placeholders like "x" or "a".
            "  POSTGRES_PASSWORD: x",
        ],
        stride=["I", "E"],
        threat_narrative=(
            "Service credentials hardcoded in ``.gitlab-ci.yml`` are "
            "readable by every collaborator, every fork, and every "
            "archived copy of the repository — forever, since removing "
            "them from a future commit doesn't erase them from git "
            "history.  An attacker with the password can authenticate "
            "to the named service from anywhere it's reachable: a "
            "test-database password used in CI often matches a dev or "
            "staging database that's exposed to the corporate network, "
            "and a hardcoded admin password in a Keycloak / Grafana / "
            "MinIO sidecar is reused by default on the staged "
            "deployment of the same service.  Move every "
            "``*_PASSWORD`` through the CI/CD variables store with "
            "Masked + Protected flags."
        ),
    ),
    # =========================================================================
    # CICD-SEC-4: Poisoned Pipeline Execution (extended)
    # =========================================================================
    Rule(
        id="SEC4-GL-004",
        title="CI_PIPELINE_SOURCE used as sole access control gate — bypassable via API trigger",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A rules:if expression gates a job solely on CI_PIPELINE_SOURCE == 'push'. "
            "CI_PIPELINE_SOURCE can also be 'api', 'trigger', 'schedule', or 'web' — each "
            "is an orthogonal dimension to 'who triggered the pipeline'. CI_PIPELINE_SOURCE "
            "tells you how the pipeline was started, NOT who can run it. Real access "
            "control for sensitive jobs comes from running them only on protected "
            "branches/tags and marking their secrets as Protected (so the secrets are "
            "only injected on protected refs)."
        ),
        pattern=RegexPattern(
            match=r'if:\s*["\']?\s*\$CI_PIPELINE_SOURCE\s*==\s*["\']push["\'](?!\s*&&)',
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Do not rely on CI_PIPELINE_SOURCE for access control. Gate sensitive jobs "
            "on the protected default branch, and mark their credentials as Protected so "
            "the variables are not injected into pipelines running on unprotected refs:\n"
            "\n"
            "deploy:\n"
            "  rules:\n"
            "    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'\n"
            "      when: on_success\n"
            "    - when: never\n"
            "\n"
            "In Settings > CI/CD > Variables, flip every deployment secret to 'Protect "
            "variable' — GitLab then only exposes the variable to jobs running on "
            "protected branches or tags (which branch protection controls who can push to). "
            "For extra safety on production deploys, also add `when: manual`."
        ),
        reference="https://docs.gitlab.com/ee/ci/jobs/job_control.html#cicd-variable-expressions",
        test_positive=[
            "    - if: '$CI_PIPELINE_SOURCE == \"push\"'",
            "    - if: \"$CI_PIPELINE_SOURCE == 'push'\"\n      when: on_success",
        ],
        test_negative=[
            '    - if: \'$CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH == "main"\'',
            "    - if: '$CI_MERGE_REQUEST_IID'",
            "    # if: '$CI_PIPELINE_SOURCE == \"push\"'",
        ],
        stride=["S", "E"],
        threat_narrative=(
            "CI_PIPELINE_SOURCE can be spoofed via the API — an attacker can trigger a "
            "pipeline via the API while setting source=merge_request_event to impersonate "
            "legitimate MR conditions, bypassing gates that check this variable alone. "
            "Access controls must be layered with branch protection and project membership "
            "checks."
        ),
    ),
    Rule(
        id="SEC4-GL-005",
        title="Merge request pipeline runs deploy or publish command — fork code executes with project secrets",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A job restricted to merge request pipelines (via the legacy "
            "`only: [merge_requests]` keyword or a modern `rules:` clause matching "
            "`$CI_PIPELINE_SOURCE == 'merge_request_event'`) contains deployment or "
            "publishing commands. When a contributor forks the project and opens an MR, "
            "GitLab runs a pipeline using the fork's code with the upstream project's "
            "unprotected CI/CD variables. If that pipeline deploys or publishes, the "
            "attacker's fork code executes with access to production credentials, "
            "container registry tokens, and cloud provider access keys."
        ),
        pattern=ContextPattern(
            anchor=(
                r"\b(docker\s+push|kubectl\s+apply|helm\s+upgrade|npm\s+publish"
                r"|pip\s+upload|twine\s+upload|cargo\s+publish|gem\s+push|mvn\s+deploy)\b"
            ),
            requires=r"\bmerge_requests?\b",
            scope="job",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Do not run deploy or publish steps in MR pipelines. Gate those jobs on the "
            "protected default branch only, using modern `rules:` syntax:\n"
            "\n"
            "deploy:\n"
            "  rules:\n"
            "    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'\n"
            "      when: on_success\n"
            "    - when: never\n"
            "\n"
            "Mark every production secret as Protected in Settings > CI/CD > Variables "
            "so GitLab only exposes it on protected branches/tags — fork MR pipelines "
            "(which always run on unprotected refs) will not receive the value."
        ),
        reference="https://docs.gitlab.com/ci/pipelines/merge_request_pipelines/",
        test_positive=[
            "publish:\n  only:\n    - merge_requests\n  script:\n    - docker push registry/image:$CI_COMMIT_SHA",
            "release:\n  only:\n    - merge_requests\n  script:\n    - npm publish",
        ],
        test_negative=[
            "test:\n  only:\n    - merge_requests\n  script:\n    - pytest",
            "deploy:\n  only:\n    - main\n  script:\n    - docker push registry/image:latest",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "Merge request pipelines run on the contributor's branch code, giving any "
            "contributor who opens an MR the ability to execute deploy or publish commands "
            "that reach production infrastructure or the package registry with the "
            "project's runner token. Deployment steps should only run on protected branches "
            "after merge, not on MR pipelines."
        ),
    ),
    # =========================================================================
    # CICD-SEC-6: Insufficient Credential Hygiene (extended)
    # =========================================================================
    Rule(
        id="SEC6-GL-008",
        title="Package manager registry or index URL overridden — dependency confusion risk",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "Pipeline configuration overrides the default package registry or index URL "
            "for pip (PIP_INDEX_URL, PIP_EXTRA_INDEX_URL), npm (NPM_CONFIG_REGISTRY), "
            "Go modules (GOPROXY), Cargo (CARGO_REGISTRIES_*_INDEX), or Bundler. This is "
            "a known dependency confusion attack vector: an attacker who controls the "
            "mirror can serve malicious packages with the same names as your private "
            "dependencies. HTTP mirrors additionally allow MITM injection of malicious "
            "packages in transit."
        ),
        pattern=RegexPattern(
            match=(
                r"(?i)(PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|NPM_CONFIG_REGISTRY"
                r"|BUNDLE_MIRROR__\w+|GOPROXY|CARGO_REGISTRIES_\w+_INDEX"
                r"|NUGET_PACKAGES_DIRECTORY)\s*:"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Verify any configured mirror is an internal, trusted proxy (Artifactory, Nexus) "
            "over HTTPS. Ensure private package namespaces cannot be shadowed by public "
            "packages with the same name.\n"
            "\n"
            "- pip: prefer `--index-url` with a private proxy and `--no-extra-index-url`; "
            "pin dependencies with a lock file (pip-tools, uv, poetry).\n"
            "- npm: lock registries per-scope in `.npmrc` (e.g. `@mycorp:registry=https://…`) "
            "rather than overriding the global NPM_CONFIG_REGISTRY.\n"
            "- Bundler: configure mirrors via `bundle config mirror.https://rubygems.org "
            "<internal-mirror>` or `.bundle/config`; Bundler's `BUNDLE_MIRROR__*` env-var "
            "form has a non-obvious key mapping (dots become `__`, full-URL keys are "
            "awkward) and is easy to misconfigure.\n"
            "- Cargo: define registries in `.cargo/config.toml` under `[registries]`; "
            "`CARGO_REGISTRIES_<name>_INDEX` overrides at build time."
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse/",
        test_positive=[
            "  PIP_INDEX_URL: http://my-mirror.internal/simple/",
            "variables:\n  NPM_CONFIG_REGISTRY: https://private-registry.example.com/",
            "  GOPROXY: https://proxy.example.com,direct",
        ],
        test_negative=[
            "  PIP_NO_BINARY: ':all:'",
            "  # PIP_INDEX_URL: http://old-mirror/",
            "  NODE_ENV: production",
        ],
        stride=["T"],
        threat_narrative=(
            "Overriding a package registry URL redirects dependency resolution to an "
            "attacker-controlled server, which can serve backdoored packages that appear "
            "identical to legitimate ones — a dependency confusion attack. This pattern was "
            "used to compromise dozens of organisations by registering internal package "
            "names on public registries."
        ),
        incidents=["Dependency confusion attacks (2021, widespread)"],
    ),
    # =========================================================================
    # CICD-SEC-8: Ungoverned Usage of 3rd Party Services (extended)
    # =========================================================================
    Rule(
        id="SEC8-GL-003",
        title="Service container uses mutable :latest tag",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-8",
        description=(
            "A job's services: block references a Docker image with the ':latest' tag. "
            "Service containers (databases, message brokers, etc.) run alongside the job "
            "and share its network namespace. A compromised service image can intercept "
            "queries, inject data, or escalate via shared volumes. Mutable ':latest' tags "
            "mean the service image can change silently between pipeline runs. "
            "Pin service images to specific version tags or SHA256 digests."
        ),
        pattern=ContextPattern(
            anchor=r"^\s*-\s*['\"]?[a-zA-Z0-9][a-zA-Z0-9._\-/]*:latest['\"]?\s*(#.*)?$",
            requires=r"\bservices\s*:",
            scope="job",
            exclude=[r"^\s*#", r"@sha256:"],
        ),
        remediation=(
            "Pin service images to explicit version tags or SHA256 digests:\n\n"
            "services:\n"
            "  - postgres:15.4        # was postgres:latest\n"
            "  - redis:7.2-alpine     # was redis:latest\n"
            "  - docker:24.0-dind     # was docker:dind or docker:latest"
        ),
        reference="https://docs.gitlab.com/ee/ci/services/",
        test_positive=[
            "services:\n  - postgres:latest",
            "services:\n  - redis:latest",
        ],
        test_negative=[
            "services:\n  - postgres:15.4",
            "services:\n  - redis:7.2-alpine",
            "services:\n  - postgres@sha256:abc123",
            "  # - redis:latest",
        ],
        stride=["T"],
        threat_narrative=(
            "A service container with a :latest tag changes with every upstream push, "
            "silently replacing the service your job depends on. A compromised service "
            "image can intercept requests from the main job, inject malicious responses, or "
            "exfiltrate data passed through shared volumes."
        ),
    ),
    # =========================================================================
    # CICD-SEC-9: Improper Artifact Integrity Validation (extended)
    # =========================================================================
    Rule(
        id="SEC9-GL-003",
        title="Cache block without explicit key — cross-branch or cross-MR cache poisoning risk",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-9",
        # 2026-04-27 audit: route to review-needed. The fork-MR
        # cache-poisoning threat requires the project to actually
        # accept fork MRs, which is a project-settings concern not
        # visible from the CI YAML. On internal projects where every
        # MR comes from a trusted contributor, this rule is hygiene-
        # only. Field test (gitlabhq, 2026-04) flagged this as a
        # major source of finding-volume noise.
        review_needed=True,
        confidence="low",
        description=(
            "A cache: block does not specify a key:. Without an explicit key GitLab uses "
            "a default cache key that may be shared across branches and merge requests, "
            "including those from forks. An attacker who can run a fork pipeline can "
            "poison the shared cache with malicious build artifacts, test fixtures, or "
            "executables that are later restored by the target branch's build."
        ),
        pattern=SequencePattern(
            pattern_a=r"^\s*cache:\s*$",
            absent_within=r"\bkey\s*:",
            lookahead_lines=10,
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Set an explicit cache key scoped to the branch:\n\n"
            "cache:\n"
            "  key: $CI_COMMIT_REF_SLUG\n"
            "  paths:\n"
            "    - .cache/\n"
            "    - node_modules/\n\n"
            "For MR pipelines use a combined key:\n"
            '  key: "$CI_COMMIT_REF_SLUG-$CI_JOB_NAME"'
        ),
        reference="https://docs.gitlab.com/ee/ci/caching/#cache-key",
        test_positive=[
            "build:\n  script:\n    - make build\n  cache:\n    paths:\n      - dist/",
            "test:\n  cache:\n    paths:\n      - node_modules/",
        ],
        test_negative=[
            "build:\n  cache:\n    key: $CI_COMMIT_REF_SLUG\n    paths:\n      - dist/",
            'test:\n  cache:\n    key: "$CI_JOB_NAME-$CI_COMMIT_REF_SLUG"\n    paths:\n      - .cache/',
        ],
        stride=["T"],
        threat_narrative=(
            "A cache without an explicit key can be shared across branches and merge "
            "requests, allowing an attacker who can open an MR to poison the cache consumed "
            "by protected branch pipelines. Injected cache content — modified node_modules, "
            "compiled objects, or tool binaries — persists into builds that run with higher "
            "privileges."
        ),
    ),
    # =========================================================================
    # CICD-SEC-10: Insufficient Logging and Visibility (extended)
    # =========================================================================
    Rule(
        id="SEC10-GL-001",
        title="CI_JOB_TOKEN or OIDC id_token printed to job log",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-10",
        description=(
            "A script block prints CI_JOB_TOKEN, CI_JOB_JWT (legacy), or a JWT-style "
            "id_token to the job log. CI_JOB_TOKEN grants access to the GitLab API, "
            "container registry, and package registry with the permissions of the "
            "triggering project. CI_JOB_JWT was the legacy OIDC variable — it was "
            "deprecated in GitLab 15.9 and removed in GitLab 17.0 (May 2024) in favour "
            "of the `id_tokens:` keyword, but the rule still flags it because legacy "
            "pipelines may retain references. Any user-named id_token (e.g. "
            "AWS_OIDC_TOKEN, VAULT_ID_TOKEN) should be treated with the same care. "
            "Printing any of these to the log — especially in public or internal "
            "projects — creates a window where anyone with log access can extract and "
            "reuse the token before it expires."
        ),
        pattern=RegexPattern(
            match=r"(echo|print|printf|cat)\s.*\$\{?(CI_JOB_TOKEN|CI_JOB_JWT|CI_JOB_JWT_V2)\}?",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Never print CI_JOB_TOKEN or CI_JOB_JWT. Pass the token directly to the "
            "command that needs it:\n\n"
            "# BAD\n"
            "- echo $CI_JOB_TOKEN\n\n"
            "# GOOD — inline without printing\n"
            "- docker login -u gitlab-ci-token -p $CI_JOB_TOKEN $CI_REGISTRY\n\n"
            "# To check presence without printing:\n"
            "- test -n \"$CI_JOB_TOKEN\" && echo 'Token is set' || exit 1"
        ),
        reference="https://docs.gitlab.com/ee/ci/jobs/ci_job_token.html",
        test_positive=[
            "    - echo $CI_JOB_TOKEN",
            '    - echo "Token: ${CI_JOB_JWT}"',
            "    - printf '%s' $CI_JOB_TOKEN",
        ],
        test_negative=[
            "    - docker login -u gitlab-ci-token -p $CI_JOB_TOKEN $CI_REGISTRY",
            "    # echo $CI_JOB_TOKEN",
            '    - test -n "$CI_JOB_TOKEN"',
        ],
        stride=["I", "R"],
        threat_narrative=(
            "CI_JOB_TOKEN and CI_JOB_JWT printed to a job log are accessible to anyone with "
            "read access to the job trace, including pipeline participants who are not "
            "project maintainers. CI_JOB_TOKEN grants API-level access to the project for "
            "the duration of the job and can be used to read protected variables, trigger "
            "pipelines, or access the package registry."
        ),
    ),
]
