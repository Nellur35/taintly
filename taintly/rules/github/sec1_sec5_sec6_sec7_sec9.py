"""GitHub Actions rules — Flow Control, PBAC, Credential Hygiene, System Config, Artifact Integrity.

Covers OWASP CICD-SEC-1, SEC-2 (extended), SEC-5, SEC-6, SEC-7, SEC-9.
These were entirely missing from initial implementation.
"""

from taintly.models import (
    _YAML_BOOL_FALSE,
    _YAML_BOOL_TRUE,
    BlockPattern,
    ContextPattern,
    PathPattern,
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
        id="SEC1-GH-001",
        title="Deploy/publish job missing environment approval gate",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-1",
        description=(
            "A job named 'deploy', 'release', 'publish', or similar does not reference an "
            "'environment:' key. Without an environment, there is no approval gate — any "
            "workflow trigger causes immediate deployment. GitHub Environments allow requiring "
            "manual approval from designated reviewers before sensitive jobs run."
        ),
        pattern=SequencePattern(
            pattern_a=r"^\s{2,4}(deploy|release|publish|production|prod)[_-]?\w*:\s*$",
            absent_within=r"environment:",
            lookahead_lines=20,
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Add an environment: key to deployment jobs:\n"
            "jobs:\n  deploy:\n    environment: production\n    steps: ..."
            "\nThen configure environment protection rules in GitHub settings "
            "(Settings > Environments) to require reviewers."
        ),
        reference="https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/managing-environments-for-deployment",
        test_positive=[
            "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./deploy.sh",
            "jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./publish.sh",
        ],
        test_negative=[
            "jobs:\n  deploy:\n    environment: production\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./deploy.sh",
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "Any automated trigger — including a webhook from an attacker who merged a malicious "
            "dependency — can deploy directly to production with no human review. "
            "Approval gates are the last barrier between CI/CD automation and production scope."
        ),
    ),
    # =========================================================================
    # CICD-SEC-2: Hardcoded container/service registry credentials
    # =========================================================================
    Rule(
        id="SEC2-GH-004",
        title="Hardcoded credentials in container or services block",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-2",
        description=(
            "A container: or services: block contains username/password credentials "
            "as literal string values rather than secrets references. Container registry "
            "credentials committed to workflow files are exposed to anyone with read access "
            "to the repository."
        ),
        pattern=ContextPattern(
            anchor=r"(username|password):\s*['\"]?(?!\$\{\{)[A-Za-z0-9@._!#$%^&*()\-]{4,}['\"]?",
            requires=r"(container:|services:)",
            exclude=[r"^\s*#"],
            scope="job",  # Both patterns are job-level; prevents cross-job false positives
        ),
        remediation=(
            "Use secrets for container registry authentication:\n"
            "container:\n  image: private-registry.example.com/app:latest\n"
            "  credentials:\n    username: ${{ secrets.REGISTRY_USERNAME }}\n"
            "    password: ${{ secrets.REGISTRY_PASSWORD }}"
        ),
        reference="https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/running-jobs-in-a-container",
        test_positive=[
            "    container:\n      image: private-registry.example.com/app:latest\n      credentials:\n        username: myuser\n        password: mypassword123",
        ],
        test_negative=[
            "    container:\n      image: ubuntu:22.04",
            "    container:\n      credentials:\n        username: ${{ secrets.REG_USER }}\n        password: ${{ secrets.REG_PASS }}",
        ],
        stride=["I", "E"],
        threat_narrative=(
            "Registry credentials stored as literal values are readable by anyone with repository access, "
            "including contributors who cannot normally view secrets. "
            "An attacker with these credentials can push a backdoored image to the private registry "
            "that your pipelines then pull and execute."
        ),
    ),
    # =========================================================================
    # CICD-SEC-5: Insufficient PBAC
    # =========================================================================
    Rule(
        id="SEC5-GH-001",
        title="id-token: write granted without any OIDC action present",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-5",
        description=(
            "The workflow grants 'id-token: write' permission — which allows minting "
            "OIDC tokens that can authenticate to cloud providers or a package registry "
            "via trusted publishing — but does not use any OIDC-consuming action "
            "(aws-actions/configure-aws-credentials, google-github-actions/auth, "
            "azure/login, pypa/gh-action-pypi-publish, sigstore/gh-action-sigstore-python, etc.). "
            "The permission is over-provisioned and unnecessarily expands token capabilities."
        ),
        pattern=ContextPattern(
            anchor=r"id-token:\s*write",
            requires=r"id-token:\s*write",
            # Known OIDC consumers. Expanded to include PyPI trusted publishing
            # and sigstore signing — both of which ARE OIDC-consuming and
            # legitimately need id-token: write. Previously flagged release
            # workflows that used these as false positives.
            requires_absent=(
                r"role-to-assume|workload_identity_provider|azure/login|"
                r"google-github-actions/auth|configure-aws-credentials|"
                r"pypa/gh-action-pypi-publish|sigstore/gh-action-sigstore|"
                r"actions/attest-build-provenance"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Remove 'id-token: write' if OIDC is not used. "
            "If OIDC is used, ensure the consuming action is present and pinned to a SHA."
        ),
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect",
        test_positive=[
            "permissions:\n  id-token: write\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest",
        ],
        test_negative=[
            "permissions:\n  id-token: write\nsteps:\n  - uses: aws-actions/configure-aws-credentials@v4\n    with:\n      role-to-assume: arn:aws:iam::123:role/GitHubActions",
            "permissions:\n  id-token: write\nsteps:\n  - uses: pypa/gh-action-pypi-publish@76f52bc884231f62b9a034ebfe128415bbaabdfc",
            "permissions:\n  id-token: write\nsteps:\n  - uses: sigstore/gh-action-sigstore-python@abc",
            "permissions:\n  contents: read",
        ],
        stride=["E"],
        threat_narrative=(
            "An over-provisioned id-token: write permission that isn't consumed by a legitimate "
            "OIDC action is available for any compromised step to mint and exchange for cloud credentials. "
            "Attackers who compromise a single step in a workflow with this permission can silently "
            "obtain persistent cloud access beyond the workflow run."
        ),
    ),
    # =========================================================================
    # SEC5-GH-002: toJSON(secrets) passes the FULL secrets context into env
    # or an action input.  Every secret the workflow can see becomes visible
    # to the step — including ones the step doesn't need.  Zizmor catches
    # this as `overprovisioned-secrets`; poutine as `job_all_secrets`.
    # The shape is rare but catastrophic: a compromised step or action in
    # the same workflow gets all of them.
    # =========================================================================
    Rule(
        id="SEC5-GH-002",
        title="toJSON(secrets) passes full secrets context to a step",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-5",
        description=(
            "The workflow interpolates ``${{ toJSON(secrets) }}`` into an "
            "env var, a with: input, or a run: body.  That expression "
            "serialises EVERY secret the workflow can see into the target "
            "— including secrets the step doesn't use.  Any compromise of "
            "the receiving step (malicious action version, injected "
            "log-dumping code, memory-scrape attack) exposes the full set. "
            "The idiomatic alternative is an explicit list:\n"
            "    env:\n"
            "      DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}\n"
            "      CLOUDFLARE_TOKEN: ${{ secrets.CLOUDFLARE_TOKEN }}"
        ),
        pattern=RegexPattern(
            match=(r"\$\{\{\s*toJSON\s*\(\s*secrets\s*\)\s*\}\}"),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Replace `${{ toJSON(secrets) }}` with an explicit list of the\n"
            "secrets this step actually needs.  If the step genuinely needs\n"
            "many secrets, enumerate them — the enumeration IS the threat\n"
            "model.  If the step is a reusable workflow call, use\n"
            "`secrets:` with one entry per forwarded secret (and pass\n"
            "`inherit` sparingly — see SEC4-GH-012).  Never pass\n"
            "`toJSON(secrets)` to a third-party action.\n"
            "Run `taintly --guide SEC5-GH-002` for the full checklist."
        ),
        reference=(
            "https://docs.zizmor.sh/audits/#overprovisioned-secrets; "
            "https://github.com/boostsecurityio/poutine/blob/main/opa/rego/rules/job_all_secrets.rego"
        ),
        test_positive=[
            # env block interpolation — the classic form
            "    env:\n      ALL_SECRETS: ${{ toJSON(secrets) }}",
            # with: input to a reusable workflow or action
            "      with:\n        secrets-json: ${{ toJSON(secrets) }}",
            # Direct use in a run: block (rarer but dangerous)
            '      run: echo "${{ toJSON(secrets) }}" > /tmp/all-secrets.json',
            # Whitespace variant
            "      env:\n        X: ${{ toJSON( secrets ) }}",
        ],
        test_negative=[
            # Explicit single-secret enumeration — safe
            "    env:\n      DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}",
            # toJSON of a specific secret (narrow, not the full set)
            "    env:\n      KEY: ${{ toJSON(secrets.DEPLOY_KEY) }}",
            # toJSON of a different context — NOT secrets
            "    env:\n      MATRIX: ${{ toJSON(matrix) }}",
            "    env:\n      INPUTS: ${{ toJSON(inputs) }}",
            # Commented out
            "    # env:\n    #   ALL: ${{ toJSON(secrets) }}",
        ],
        stride=["I", "E"],
        threat_narrative=(
            "A workflow that serialises `toJSON(secrets)` into a step "
            "makes every secret visible to every subsequent compromise. "
            "A malicious action update or a third-party action with a "
            "log-dumping regression reads the env var and posts it to "
            "an attacker-controlled endpoint — the attacker gets the "
            "complete secret inventory in one request.  The fix is "
            "enumeration: name each secret the step needs and pass "
            "them individually so the compromise surface is bounded "
            "to the enumerated set."
        ),
        confidence="high",
        incidents=[],
    ),
    # =========================================================================
    # CICD-SEC-6: Insufficient Credential Hygiene — extended
    # =========================================================================
    Rule(
        id="SEC6-GH-004",
        title="All secrets serialized via toJSON(secrets)",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "toJSON(secrets) serializes every secret the runner holds into a single "
            "JSON blob and passes it to a step. GitHub's per-secret log redactor still "
            "runs, but it matches literal secret values — once secrets are "
            "JSON-escaped, concatenated, or transformed, the matcher can fail and "
            "leakage becomes partial or total. Even when redaction succeeds, this "
            "pattern grants the step access to every secret the caller holds, "
            "violating least privilege. GitHub's own docs explicitly warn: 'avoid "
            "using structured data as the values of secrets ... this significantly "
            "reduces the probability that the secrets will be properly redacted.'"
        ),
        pattern=RegexPattern(
            match=r"\$\{\{\s*toJSON\(\s*secrets\s*\)\s*\}\}",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Pass only the specific secrets each step needs:\n"
            "env:\n  DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}"
        ),
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions",
        test_positive=[
            "        env:\n          ALL_SECRETS: ${{ toJSON(secrets) }}",
            "        run: echo '${{ toJSON(secrets) }}'",
        ],
        test_negative=[
            "        env:\n          API_KEY: ${{ secrets.API_KEY }}",
            "        # ALL_SECRETS: ${{ toJSON(secrets) }}",
        ],
        stride=["I"],
        threat_narrative=(
            "toJSON(secrets) serializes every secret into a single JSON blob and hands "
            "the entire secret store to the receiving step. GitHub's log-redaction "
            "still fires on literal secret values, but JSON-escaping, base64, or any "
            "downstream transform can defeat the matcher — partial or total log "
            "leakage becomes likely, and in every case a single compromised action "
            "walks away with every secret the caller holds."
        ),
    ),
    Rule(
        id="SEC6-GH-005",
        title="Secret interpolated directly into shell command (not via env var)",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A ${{ secrets.X }} expression is used inline in a context beyond a simple "
            "YAML key-value assignment. When secrets are interpolated directly into shell "
            "commands, the value is written to the generated script file on disk before "
            "execution, increasing exposure risk. It may also appear in shell history or "
            "process listings. Prefer mediation through an env: variable."
        ),
        pattern=RegexPattern(
            # Anchor on ${{ secrets.X }} directly (O(n) scan).
            # The old pattern `[^:]*\$\{\{` had O(n²) catastrophic backtracking on
            # lines without ${{ because the leading quantifier retried every position.
            match=r"\$\{\{\s*secrets\.[a-zA-Z0-9_]+\s*\}\}",
            exclude=[
                r"^\s*#",
                # Exclude YAML key: ${{ secrets.X }} assignments — both unquoted and quoted forms.
                # `token: ${{ secrets.GITHUB_TOKEN }}` and `token: "${{ secrets.GITHUB_TOKEN }}"` are
                # safe: the value is passed as a string parameter to an action (with:) or set as an
                # environment variable (env:). The dangerous pattern is embedding ${{ }} inside a
                # larger shell string (e.g. inside a `run:` command).
                r"""^\s*[\w.-]+:\s*["']?\$\{\{\s*secrets\.[a-zA-Z0-9_]+\s*\}\}["']?\s*(#.*)?$""",
            ],
        ),
        remediation=(
            "Route the secret through an env: variable so it never reaches "
            "the generated step script file on disk:\n"
            "env:\n  API_TOKEN: ${{ secrets.API_TOKEN }}\n"
            'run: curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com\n'
            "Most publish tools accept an env-var form of their credential "
            "flag (NUGET_API_KEY, UV_PUBLISH_TOKEN, NPM_TOKEN, TWINE_PASSWORD) "
            "— prefer that over the --token CLI flag. Run "
            "`taintly --guide SEC6-GH-005` for the full exposure model "
            "and scoping advice."
        ),
        reference="https://woodruffw.github.io/zizmor/audits/secrets-outside-env/",
        test_positive=[
            '        run: curl -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" https://api.example.com',
            "        run: ./deploy.sh ${{ secrets.DEPLOY_KEY }}",
        ],
        test_negative=[
            "        env:\n          API_TOKEN: ${{ secrets.API_TOKEN }}",
            "        with:\n          token: ${{ secrets.GITHUB_TOKEN }}",
            '        with:\n          repoToken: "${{ secrets.GITHUB_TOKEN }}"',
            "        # run: curl ${{ secrets.TOKEN }}",
        ],
        stride=["I", "R"],
        threat_narrative=(
            "Secrets interpolated directly into shell commands are written to the generated runner "
            "script on disk and may appear in process listings, shell history, and debug logs before "
            "GitHub's redaction can act. "
            "Using env: variables passes the secret through a protected channel that keeps it out of "
            "the command string itself."
        ),
    ),
    Rule(
        id="SEC6-GH-006",
        title="Base64-encoded payload decoded and executed",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A base64-encoded string is decoded and piped directly to a shell or eval. "
            "This is a known obfuscation technique used in supply chain attacks — "
            "Base64-encoded payloads have been used in documented supply chain attacks "
            "against popular GitHub Actions to evade static analysis. "
            "Legitimate workflows have no need to execute base64-encoded commands."
        ),
        pattern=RegexPattern(
            match=r"(base64\s+(-d|--decode|-D)[^\n]*\|\s*(bash|sh|eval|python|perl|ruby))|(echo\s+[A-Za-z0-9+/=]{16,}\s*\|\s*base64\s+(-d|--decode))",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Do not execute base64-encoded payloads. "
            "If you need to pass data to a script, write a named script file to the repo "
            "and execute it directly. Inline encoded payloads cannot be audited or reviewed."
        ),
        reference="https://woodruffw.github.io/zizmor/audits/obfuscation/",
        test_positive=[
            "        run: echo 'aGVsbG8gd29ybGQ=' | base64 --decode | bash",
            "        run: base64 -d payload.b64 | sh",
            "        run: echo 'aGVsbG8gd29ybGQ=' | base64 -d | python",
        ],
        test_negative=[
            "        run: base64 -d certificate.pem > cert.pem",
            "        run: openssl enc -base64 -d -in encrypted.bin > decrypted.bin",
            "        # run: echo 'cGF5bG9hZA==' | base64 -d | bash",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Base64-encoded payloads are the canonical fingerprint of supply chain attack code: "
            "the 2024 Ultralytics and 2025 Trivy compromises both used encoded shells to evade "
            "diff reviewers and static scanners. "
            "Executing any decoded payload gives an attacker arbitrary code execution inside the "
            "runner with access to all secrets and write permissions."
        ),
        incidents=["Ultralytics (Dec 2024)", "Trivy supply chain (Mar 2026)"],
    ),
    Rule(
        id="SEC6-GH-007",
        title="curl/wget output piped directly to shell (GitHub Actions)",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "Script downloads and executes remote code in a single pipeline with no integrity "
            "verification. Covers curl|bash, wget|sh, bash <(curl ...), and PowerShell iex() "
            "patterns. If the remote server or CDN is compromised, arbitrary code runs with "
            "full access to the runner, including all mounted secrets."
        ),
        pattern=RegexPattern(
            # The iex() branch must require the body to pull a remote
            # payload — bare `iex (Get-Content ./local.ps1)` is local
            # dynamic dispatch, not curl-pipe-bash, and firing on it
            # produces a high-severity FP with no remote-fetch risk.
            match=(
                r"(curl\s[^|\n]*\|\s*(bash|sh|zsh|python|perl|ruby))"
                r"|(wget\s[^|\n]*\|\s*(bash|sh|zsh|python|perl))"
                r"|(bash\s*<\s*\(\s*curl)"
                r"|(iex\s*\([^)]*(Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile|WebClient|Net\.Http))"
                r"|(\|\s*python\s+-c\s+['\"])"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Download the script first, verify its checksum, then execute:\n"
            "curl -fsSL -o install.sh https://example.com/install.sh\n"
            "echo '<expected_sha256>  install.sh' | sha256sum -c -\n"
            "bash install.sh"
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/",
        test_positive=[
            "        run: curl -sSL https://get.example.com/install.sh | bash",
            "        run: wget -q -O - https://example.com/setup.sh | sh",
            "        run: bash <(curl -s https://example.com/bootstrap.sh)",
        ],
        test_negative=[
            "        run: curl -fsSL -o install.sh https://example.com/install.sh",
            "        run: wget -O script.sh https://example.com/setup.sh",
            "        # run: curl https://example.com | bash",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Piping a remote script to the shell with no integrity check grants the CDN operator — "
            "or any attacker who compromises it via DNS hijacking or BGP route injection — "
            "arbitrary code execution in your pipeline. "
            "A hijacked installer runs with the runner's full permissions and secret access before "
            "any audit mechanism can detect it."
        ),
    ),
    # =========================================================================
    # CICD-SEC-7: Insecure System Configuration — extended
    # =========================================================================
    Rule(
        id="SEC7-GH-002",
        title="GitHub Actions debug mode enabled",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-7",
        description=(
            "ACTIONS_RUNNER_DEBUG or ACTIONS_STEP_DEBUG is set to true. "
            "Debug mode dramatically increases log verbosity and frequently causes secrets "
            "to be printed to job logs in plain text. "
            "Debug mode being enabled in victim environments has been observed in supply chain "
            "attacks to confirm credential capture. This setting should never be hardcoded in workflows."
        ),
        pattern=RegexPattern(
            match=rf"(ACTIONS_RUNNER_DEBUG|ACTIONS_STEP_DEBUG)\s*:\s*{_YAML_BOOL_TRUE}",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Remove ACTIONS_RUNNER_DEBUG and ACTIONS_STEP_DEBUG from workflow files. "
            "If debug logging is needed temporarily, set it as a repository secret "
            "(GitHub will redact it from logs) or enable it via the Actions UI for a single run."
        ),
        reference="https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/troubleshooting-workflows/enabling-debug-logging",
        test_positive=[
            "        ACTIONS_RUNNER_DEBUG: true",
            "        ACTIONS_STEP_DEBUG: true",
            "        ACTIONS_RUNNER_DEBUG: 'true'",
            "        ACTIONS_RUNNER_DEBUG: yes",
            "        ACTIONS_STEP_DEBUG: on",
        ],
        test_negative=[
            "        RUNNER_OS: ubuntu",
            "        # ACTIONS_RUNNER_DEBUG: true",
        ],
        stride=["I"],
        threat_narrative=(
            "Debug mode dramatically increases log verbosity and frequently causes secrets to appear "
            "in plain text in job logs, bypassing GitHub's runtime redaction for values not pre-registered "
            "as masked. "
            "Supply chain attackers have been observed enabling debug mode in victim environments "
            "specifically to capture credentials from log output."
        ),
    ),
    Rule(
        id="SEC7-GH-003",
        title="Self-hosted runner used for pull_request from external contributors",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-7",
        description=(
            "Workflow uses the pull_request trigger (which runs for external fork PRs) "
            "combined with runs-on: self-hosted. This allows external contributors to "
            "execute arbitrary code directly on your persistent self-hosted runner infrastructure. "
            "Unlike GitHub-hosted runners, self-hosted runners persist state between jobs "
            "and have network access to internal resources."
        ),
        pattern=ContextPattern(
            anchor=r"runs-on:.*self-hosted",
            requires=r"pull_request[^_]",
            exclude=[r"^\s*#"],
            # Suppress findings in jobs explicitly gated to non-pull_request events.
            # A self-hosted runner job with `if: github.event_name == 'push'` (or
            # schedule, workflow_dispatch, etc.) never runs for external PRs.
            anchor_job_exclude=(
                r"if:.*github\.event_name\s*==\s*['\"]"
                r"(?:push|schedule|workflow_dispatch|workflow_call|merge_group"
                r"|release|deployment|pull_request_target)['\"]"
                r"|if:.*github\.event_name\s*!=\s*['\"]pull_request['\"]"
            ),
        ),
        remediation=(
            "Use GitHub-hosted runners for pull_request workflows from external forks. "
            "If self-hosted runners are required, restrict fork-PR workflow execution via:\n"
            "  Settings > Actions > General > 'Approval for running fork pull request "
            "workflows from contributors' > select 'Require approval for all outside "
            "collaborators' (or, stricter, 'Require approval for all external contributors').\n"
            "\n"
            "Note: branch protection rules govern who can push to protected branches — "
            "they do NOT gate fork-PR workflow execution. The approval gate lives under "
            "Settings > Actions."
        ),
        reference="https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security",
        test_positive=[
            "on:\n  pull_request:\njobs:\n  build:\n    runs-on: [self-hosted, linux]",
            "on:\n  pull_request:\njobs:\n  test:\n    runs-on: self-hosted",
        ],
        test_negative=[
            "on:\n  push:\njobs:\n  build:\n    runs-on: [self-hosted, linux]",
            "on:\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-latest",
            "on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: self-hosted",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "External contributors who open a pull request gain arbitrary code execution on your "
            "persistent self-hosted runner infrastructure, with access to internal network resources "
            "and environment state from other jobs. "
            "Unlike GitHub-hosted runners, self-hosted runners retain their filesystem state between "
            "jobs, allowing attackers to plant backdoors that affect subsequent runs."
        ),
    ),
    # =========================================================================
    # CICD-SEC-9: Improper Artifact Integrity Validation
    # =========================================================================
    Rule(
        id="SEC9-GH-001",
        title="Binary or script downloaded without checksum verification",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-9",
        description=(
            "Workflow downloads a binary or script file using curl/wget and executes it "
            "without verifying a checksum (sha256sum, shasum, cosign, gpg). "
            "If the download source is compromised or the CDN is hijacked, "
            "arbitrary code runs in the pipeline with access to all secrets. "
            "This is the supply chain entry point pattern — verify every binary you execute."
        ),
        pattern=SequencePattern(
            pattern_a=r"(curl|wget)\s+[^\n]*\.(sh|py|tar\.gz|tgz|zip|exe|bin|deb|rpm|appimage)\b",
            absent_within=r"(sha256sum|sha512sum|shasum|md5sum|cosign\s+verify|gpg\s+--verify)",
            lookahead_lines=5,
            exclude=[r"^\s*#", r"\|\s*(bash|sh|zsh|python|perl)"],
        ),
        remediation=(
            "Always verify checksums after downloading:\n"
            "curl -fsSL -o tool.tar.gz https://example.com/tool-v1.0.tar.gz\n"
            "echo 'abc123def456...  tool.tar.gz' | sha256sum -c -\n"
            "tar xzf tool.tar.gz"
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09:_Improper_Artifact_Integrity_Validation",
        test_positive=[
            "        run: |\n          curl -fsSL -o tool.bin https://example.com/releases/v1.0/tool.bin\n          chmod +x tool.bin",
            "        run: wget -q https://example.com/installer.sh && bash installer.sh",
        ],
        test_negative=[
            "        run: |\n          curl -fsSL -o tool.tar.gz https://example.com/tool.tar.gz\n          echo 'abc123  tool.tar.gz' | sha256sum -c -",
            "        run: curl -fsSL https://get.helm.sh/helm-v3.14.0-linux-amd64.tar.gz | sha256sum",
        ],
        stride=["T"],
        threat_narrative=(
            "Downloading a binary or script without verifying its checksum allows a CDN compromise, "
            "DNS hijacking, or BGP route injection to silently substitute a malicious payload. "
            "The pipeline executes attacker code with full runner access before any integrity check "
            "can detect the substitution."
        ),
    ),
    Rule(
        id="SEC9-GH-002",
        title="Mutable cache used in release or tag workflow (cache poisoning risk)",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-9",
        description=(
            "A caching action is used in a workflow triggered by a release event "
            "or tag push. Cache scope is per-branch: caches written by unmerged "
            "PR workflows are keyed to refs/pull/<n>/merge and are NOT restorable "
            "by release/tag workflows running on the default branch. The real "
            "poisoning vector is writes to the default-branch cache after a "
            "malicious PR merges — those entries are then inherited by later "
            "release/tag workflows, and by feature branches that fall back to "
            "the parent ref cache.\n\n"
            "Anchor list policy (precision): actions for which caching is "
            "ALWAYS on OR on by DEFAULT. Explicit-opt-in setups "
            "(`actions/setup-python`, `actions/setup-node`, `actions/setup-java`, "
            "`actions/setup-dotnet`, `actions/setup-ruby`) only cache when "
            "`with: cache:` is set — using them without `cache:` is the common "
            "case and firing on bare `uses: actions/setup-python@` produces FPs "
            "everywhere someone just wants an interpreter. Those cases are "
            "tracked as a follow-up recall gap (see ROADMAP Phase 1.5)."
        ),
        pattern=ContextPattern(
            # actions/cache — caching is the action's whole purpose.
            # actions/setup-go — caches the module cache by default since v4
            #                    (requires explicit `cache: false` to disable).
            # Other setup-* actions require explicit `cache:` input and are
            # deliberately EXCLUDED here to avoid the release.yml FP.
            anchor=r"uses:\s*(actions/cache|actions/setup-go)@",
            requires=r"(release:|tags:)",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Disable caching in release/tag workflows, or use a cache key that "
            "includes the full commit SHA so the release workflow cannot fall "
            "back to a cache entry written by a prior default-branch push:\n"
            "\n"
            "key: release-${{ github.sha }}-${{ hashFiles('**/package-lock.json') }}\n"
            "\n"
            "For actions/setup-go specifically, pass `cache: false` in the "
            "release-workflow invocation to opt out of the default cache.\n"
            "\n"
            "If you must share cache across workflows, review every job that "
            "writes to the default-branch cache and ensure a merged malicious "
            "PR cannot place hostile content there."
        ),
        reference="https://docs.zizmor.sh/audits/cache-poisoning/",
        test_positive=[
            # actions/cache — caching is the whole point.
            "on:\n  push:\n    tags:\n      - 'v*'\njobs:\n  release:\n    steps:\n      - uses: actions/cache@v4",
            # actions/setup-go — caches by default since v4.
            "on:\n  release:\n    types: [published]\njobs:\n  build:\n    steps:\n      - uses: actions/setup-go@v5",
        ],
        test_negative=[
            # No release/tag trigger.
            "on:\n  push:\n    branches: [main]\njobs:\n  build:\n    steps:\n      - uses: actions/cache@v4",
            # PR trigger, not release/tag.
            "on:\n  pull_request:\njobs:\n  test:\n    steps:\n      - uses: actions/cache@v4",
            # setup-python without cache: is fine — no cache created.
            # This was the FP case the suppression in release.yml worked around.
            "on:\n  release:\n    types: [published]\njobs:\n  build:\n    steps:\n      - uses: actions/setup-python@v5\n        with:\n          python-version: '3.12'",
            # Same for setup-node, setup-java, setup-dotnet, setup-ruby.
            "on:\n  release:\n    types: [published]\njobs:\n  build:\n    steps:\n      - uses: actions/setup-node@v4",
        ],
        stride=["T"],
        threat_narrative=(
            "After a malicious PR merges, its follow-up default-branch workflow "
            "runs write to the default-branch cache entries that release/tag "
            "workflows later restore. Injected dependency caches — modified "
            "node_modules, compiled objects, or tool binaries — then flow "
            "directly into the release artefacts that ship to production or "
            "the package registry, with no integrity check between cache write "
            "and cache restore."
        ),
    ),
    # =========================================================================
    # SEC9-GH-003: Opt-in setup-<lang> cache in release/tag workflow
    # =========================================================================
    # Closes the SEC9-GH-002 recall gap documented inline in that rule
    # ("Those cases are tracked as a follow-up recall gap"). setup-python /
    # setup-node / setup-java / setup-dotnet / setup-ruby only cache when
    # `with: cache:` is explicitly set and not `false`; firing on the bare
    # `uses: actions/setup-*` form produces FPs everywhere someone just
    # wants an interpreter. This rule targets only the attack-relevant
    # shape: the explicit `cache:` input line, gated by file-scope
    # co-occurrence of the setup-* step AND a release/tag trigger.
    Rule(
        id="SEC9-GH-003",
        title="Opt-in setup-<lang> cache configured in release or tag workflow",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-9",
        description=(
            "A setup-* action (`actions/setup-python`, `actions/setup-node`, "
            "`actions/setup-java`, `actions/setup-dotnet`, `actions/setup-ruby`) "
            "is configured with an explicit `cache:` input in a workflow "
            "triggered by a release or tag push. These actions only cache when "
            "`cache:` is set and not `false`. The cache-poisoning surface is "
            "identical to SEC9-GH-002: entries written by default-branch "
            "workflows after a malicious PR merges are restored by later "
            "release/tag runs. This rule targets the explicit-opt-in case "
            "SEC9-GH-002 deliberately excludes to keep its anchor from firing "
            "on bare `uses: actions/setup-python@` (interpreter-only) usage."
        ),
        pattern=ContextPattern(
            # Anchor on the `cache:` input line itself. Matches an indented
            # `cache:` with a non-empty non-false value; the negative
            # lookahead suppresses every YAML 1.1 falsy spelling (`false`,
            # `False`, `no`, `off`, `0`, quoted variants) so a case-mutated
            # `cache: False` still reads as the explicit opt-out.
            # `\s*` after the colon (not `\s+`) tolerates whitespace-pad
            # mutations that strip the space, matching `cache:npm`.
            anchor=r"^\s+cache:\s*(?!" + _YAML_BOOL_FALSE + r"\s*(?:#|$))\S",
            # File-scope trigger gate. The initial version matched on a
            # bare `release:` or `tags:` substring, which produced FPs on
            # real workflows where:
            #   - `release:` appeared as a `workflow_call:` input name or
            #     job-name suffix (`create-release:`, `publish-release:`)
            #   - `tags:` appeared under `push:` as a negation pattern
            #     (`tags: ['!**']`) — which explicitly EXCLUDES tag events
            #
            # This version requires the trigger to appear as a direct YAML
            # child of `on:`:
            #
            #   1. `release:` at 2-space indent directly under `on:` (any types)
            #   2. `push:` with `tags:` at 4-space indent AND a value that
            #      does not start with `!` (real tag pattern, not exclusion)
            #   3. List form `on: [..., release, ...]`
            #
            # Bounded repetitions ({0,30}, {0,20}) prevent catastrophic
            # backtracking on whitespace-heavy adversarial input — measured
            # < 1ms on the 17KB real-world workflow that the unbounded form
            # timed out on.
            requires=(
                r"(?="
                # Direct `on:\n <indent>release:` child. Indent range
                # 1-4 spaces covers the 2-space GitHub convention,
                # half-scale indent_shift mutations (1-space), and
                # double-scale (4-space). Excludes `release:` as an
                # input name inside `workflow_call:\n  inputs:\n`
                # (which sits at 6+ spaces under 2-space convention,
                # 3+ under 1-space) — that was a FP on real
                # workflows per the corpus dogfood.
                # 30-line bounded window prevents catastrophic
                # backtracking on whitespace-heavy adversarial input.
                r"(?:\A|\n)on:[^\n]*\n(?:[^\n]*\n){0,30}?[ ]{1,4}release:[ \t\n]"
                r"|"
                # `on:\n <indent>push:\n <deeper>tags:` whose first value
                # is not a `!`-negation. GitHub Actions uses `!pattern`
                # to EXCLUDE refs; a `tags:` list whose first entry is
                # `!**` means no tag events ever trigger the workflow,
                # so the cache-poisoning surface is not exposed.
                r"(?:\A|\n)on:[^\n]*\n(?:[^\n]*\n){0,30}?[ ]{1,4}push:[^\n]*\n"
                r"(?:[^\n]*\n){0,20}?[ ]{2,8}tags:[ \t]*"
                r"(?:"
                # Bracket form `tags: [v*, ...]` — first item not `!`
                r"\[[ \t]*(?!['\"]?!)[^\]\s]"
                # List form `tags:\n  - 'v*'` — first value char not `!`
                r"|\n[ ]+-[ \t]+(?!['\"]?!)\S"
                r")"
                r"|"
                # List form `on: [..., release, ...]`
                r"\bon:[ \t]*\[[^\]]*\brelease\b[^\]]*\]"
                r")"
                # `\s*` (not `\s+`) tolerates whitespace_pad mutation that
                # strips the space between `uses:` and the action name.
                r"(?=[\s\S]*?uses:\s*actions/setup-(?:python|node|java|dotnet|ruby)@)"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "In release or tag workflows, either disable the cache:\n"
            "\n"
            "  - uses: actions/setup-node@v4\n"
            "    with:\n"
            "      cache: false\n"
            "\n"
            "or scope the cache key to the full commit SHA so the release "
            "workflow cannot restore an entry written by a prior default-branch "
            "push:\n"
            "\n"
            "  - uses: actions/setup-node@v4\n"
            "    with:\n"
            "      cache: npm\n"
            "      cache-dependency-path: 'package-lock.json'\n"
            "\n"
            "Note: setup-* actions do not expose a per-step cache-key override; "
            "the safest posture in release pipelines is `cache: false` and a "
            "separate `actions/cache@` block keyed on `${{ github.sha }}`."
        ),
        reference="https://docs.zizmor.sh/audits/cache-poisoning/",
        test_positive=[
            (
                "on:\n  release:\n    types: [published]\n"
                "jobs:\n  build:\n    steps:\n      - uses: actions/setup-node@v4\n"
                "        with:\n          cache: npm"
            ),
            (
                "on:\n  push:\n    tags:\n      - 'v*'\n"
                "jobs:\n  build:\n    steps:\n      - uses: actions/setup-python@v5\n"
                "        with:\n          python-version: '3.12'\n          cache: pip"
            ),
        ],
        test_negative=[
            # No release/tag trigger — requires fails.
            (
                "on:\n  push:\n    branches: [main]\n"
                "jobs:\n  build:\n    steps:\n      - uses: actions/setup-node@v4\n"
                "        with:\n          cache: npm"
            ),
            # Setup-X without cache: — anchor does not fire.
            (
                "on:\n  release:\n    types: [published]\n"
                "jobs:\n  build:\n    steps:\n      - uses: actions/setup-python@v5\n"
                "        with:\n          python-version: '3.12'"
            ),
            # Explicit opt-out — cache: false suppressed by anchor lookahead.
            (
                "on:\n  release:\n    types: [published]\n"
                "jobs:\n  build:\n    steps:\n      - uses: actions/setup-node@v4\n"
                "        with:\n          cache: false"
            ),
            # Comment.
            (
                "on:\n  release:\n    types: [published]\n"
                "jobs:\n  build:\n    steps:\n      - uses: actions/setup-node@v4\n"
                "        with:\n          # cache: npm"
            ),
            # FP guard (dogfood): workflow_dispatch-only file with a job
            # named `create-release:` — the substring `release:` appears
            # but the workflow does not run on a release event.
            (
                "on:\n  workflow_dispatch:\n"
                "jobs:\n  create-release:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/setup-node@v4\n"
                "        with:\n          cache: npm"
            ),
            # FP guard (dogfood): push with `tags: ['!**']` — the literal
            # `tags:` keyword is present but it excludes ALL tag events.
            (
                "on:\n  push:\n    branches:\n      - '**'\n"
                "    tags:\n      - '!**'\n"
                "jobs:\n  build:\n    steps:\n      - uses: actions/setup-node@v4\n"
                "        with:\n          cache: pnpm"
            ),
        ],
        stride=["T"],
        threat_narrative=(
            "setup-<lang>'s opt-in cache uses the same GitHub Actions cache "
            "backend as actions/cache, so entries written from the default "
            "branch after a malicious merge are restorable by later release "
            "and tag workflows. The opt-in form is where real projects "
            "actually store language-specific dependency caches (node_modules "
            "via setup-node, pip wheels via setup-python), making this the "
            "highest-traffic cache-poisoning surface in practice."
        ),
    ),
    # =========================================================================
    # SEC7-GH-004: Unconstrained workflow_dispatch string input
    # =========================================================================
    Rule(
        id="SEC7-GH-004",
        title="workflow_dispatch string input has no allowlist (options:) constraint",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-7",
        description=(
            "A workflow_dispatch trigger defines an input with `type: string` but no "
            "`options:` list. Without an allowlist, the input accepts arbitrary free-text "
            "from anyone who can trigger the workflow manually or via the GitHub API. "
            "If the input value is used in a shell step, environment variable, or passed "
            "to another workflow, it becomes an injection vector. "
            "The `type: choice` input type restricts accepted values to a predefined "
            "list and is the correct choice for any input that influences execution logic "
            "rather than purely informational fields."
        ),
        pattern=PathPattern(
            path=r"on\.workflow_dispatch\.inputs\.[^.]+\.type",
            value=r"^string$",
            sibling_absent=r"^options$",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Replace `type: string` with `type: choice` and enumerate allowed values:\n\n"
            "on:\n"
            "  workflow_dispatch:\n"
            "    inputs:\n"
            "      environment:\n"
            "        type: choice          # was: string\n"
            "        options:\n"
            "          - staging\n"
            "          - production\n\n"
            "For inputs that genuinely require free text (e.g. a commit message), "
            "validate and sanitize the value before use in any shell command:\n"
            "  run: |\n"
            "    if [[ ! '${{ inputs.message }}' =~ ^[a-zA-Z0-9 .,!?-]+$ ]]; then\n"
            "      echo 'Invalid input' && exit 1\n"
            "    fi"
        ),
        reference="https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/events-that-trigger-workflows#providing-inputs",
        test_positive=[
            "on:\n  workflow_dispatch:\n    inputs:\n      environment:\n        type: string\n        description: Target",
            "on:\n  workflow_dispatch:\n    inputs:\n      branch:\n        type: string",
        ],
        test_negative=[
            "on:\n  workflow_dispatch:\n    inputs:\n      environment:\n        type: choice\n        options:\n          - staging\n          - production",
            "on:\n  workflow_dispatch:\n    inputs:\n      environment:\n        type: string\n        options:\n          - staging",
            "on:\n  push:\n    branches: [main]",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "Unconstrained string inputs accept any value, including shell metacharacters, from anyone "
            "who can trigger the workflow via the UI or GitHub API with the workflow scope. "
            "When the input value reaches a shell command, an authorized user or attacker with a "
            "compromised token can inject arbitrary commands that run with the workflow's full permissions."
        ),
    ),
    # =========================================================================
    # SEC8-GH-004: Service container with --privileged flag
    # =========================================================================
    Rule(
        id="SEC8-GH-004",
        title="Service container runs with --privileged flag",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-8",
        description=(
            "A GitHub Actions service container is started with the `--privileged` "
            "Docker flag in its `options:` field. Privileged containers have full "
            "access to all Linux kernel capabilities and host devices — they can "
            "mount the host filesystem, escape the container namespace, load kernel "
            "modules, and interact with the Docker socket.\n"
            "\n"
            "On GitHub-hosted runners (ephemeral single-job VMs), a privileged "
            "container can compromise the runner VM itself — reading in-memory "
            "secrets, the OIDC token, and other artefacts of the current job. The VM "
            "is destroyed after the job, so other tenants' jobs are not directly "
            "reachable, but any secret or token exposed to this job is.\n"
            "\n"
            "On self-hosted runners, especially non-ephemeral ones, privileged mode "
            "can additionally compromise the underlying host and persist across "
            "subsequent jobs, poisoning future workflows that land on the same "
            "runner.\n"
            "\n"
            "Service containers rarely require privileged mode — most use cases "
            "(databases, caches, message queues) work correctly without it."
        ),
        pattern=BlockPattern(
            block_anchor=r"^\s*services:\s*$",
            match=r"options:.*--privileged",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Remove the --privileged flag. Most service containers work without it:\n\n"
            "services:\n"
            "  postgres:\n"
            "    image: postgres:16\n"
            "    options: >-\n"
            "      --health-cmd pg_isready\n"
            "      --health-interval 10s\n"
            "    # removed: --privileged\n\n"
            "If your service genuinely requires elevated capabilities, request only the "
            "specific Linux capability it needs:\n"
            "  options: --cap-add SYS_PTRACE  # instead of --privileged"
        ),
        reference="https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities",
        test_positive=[
            "services:\n  db:\n    image: postgres:16\n    options: --privileged",
            "services:\n  redis:\n    image: redis:7\n    options: --health-cmd 'redis-cli ping' --privileged",
        ],
        test_negative=[
            "services:\n  db:\n    image: postgres:16\n    options: --health-cmd pg_isready",
            "container:\n  image: ubuntu:22.04\n  options: --privileged",
            "# services:\n#   db:\n#     options: --privileged",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "A privileged container has full access to all host kernel capabilities "
            "and can escape the container namespace into the runner itself. On "
            "GitHub-hosted runners (ephemeral single-job VMs) the attacker gains the "
            "current job's secrets, OIDC token, and artefacts. On self-hosted "
            "runners this compromises the host machine — and on non-ephemeral "
            "self-hosted runners, subsequent jobs from other workflows that land on "
            "the same host."
        ),
    ),
    # =========================================================================
    # SEC9-GH-005: Cache key derived from attacker-controlled context
    # =========================================================================
    Rule(
        id="SEC9-GH-005",
        title="Cache key derived from attacker-controlled context (cache poisoning)",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-9",
        description=(
            "An actions/cache or actions/cache/restore step builds its cache key from "
            "an attacker-controlled GitHub context — github.head_ref, "
            "github.event.pull_request.head.ref/sha, github.event.issue.title, or "
            "github.event.comment.body. The attacker opens a PR whose head_ref / PR "
            "body crafts the exact cache key that a downstream privileged workflow "
            "later restores, overwriting the cache with attacker-controlled build "
            "artefacts before it ever reaches a protected branch."
        ),
        pattern=ContextPattern(
            anchor=r"uses:\s*actions/cache(?:/restore|/save)?@",
            requires=(
                r"key\s*:.*\$\{\{\s*(?:"
                r"github\.head_ref"
                r"|github\.event\.pull_request\.head\.(?:ref|sha|label)"
                r"|github\.event\.issue\.(?:title|body)"
                r"|github\.event\.comment\.body"
                r"|github\.event\.pull_request\.(?:title|body)"
                r")"
            ),
            scope="file",
        ),
        remediation=(
            "Cache keys must be derived from content hashes or repo-trusted "
            "refs only — never from PR-author-controlled context. Replace the "
            "tainted key input with hashFiles() over lock files, or with the "
            "SHA of the base branch:\n\n"
            "# BAD — attacker picks the cache key by naming their PR branch\n"
            "- uses: actions/cache@v4\n"
            "  with:\n"
            "    key: deps-${{ github.head_ref }}-${{ hashFiles('**/lock') }}\n\n"
            "# GOOD — content-addressed; attacker can't influence the key\n"
            "- uses: actions/cache@v4\n"
            "  with:\n"
            "    key: deps-${{ runner.os }}-${{ hashFiles('**/lock') }}"
        ),
        reference="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
        test_positive=[
            (
                "jobs:\n  build:\n    steps:\n      - uses: actions/cache@v4\n"
                "        with:\n          key: deps-${{ github.head_ref }}\n"
            ),
            (
                "steps:\n  - uses: actions/cache/restore@v4\n"
                "    with:\n      key: build-${{ github.event.pull_request.head.sha }}\n"
            ),
        ],
        test_negative=[
            (
                "steps:\n  - uses: actions/cache@v4\n"
                "    with:\n      key: deps-${{ runner.os }}-${{ hashFiles('**/lock') }}\n"
            ),
            ("steps:\n  - uses: actions/cache@v4\n    with:\n      key: build-${{ github.sha }}\n"),
        ],
        stride=["T", "S"],
        threat_narrative=(
            "Caches persist across workflow runs and branches. If the key is derived "
            "from attacker-controlled context, the attacker can choose what key the "
            "cache is stored under and later trigger a privileged workflow that "
            "restores that exact key — silently substituting a poisoned build into "
            "the trusted pipeline. This bypasses signed-commit gates because the "
            "cache restore happens before any verification step observes the inputs."
        ),
        incidents=[],
    ),
    # =========================================================================
    # SEC3-GH-008: pip --extra-index-url dependency-confusion shape
    # =========================================================================
    Rule(
        id="SEC3-GH-008",
        title="pip --extra-index-url used without --index-url (dependency confusion)",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "pip install is invoked with --extra-index-url (adds a secondary index) "
            "without --index-url (replaces the primary). pip's resolver merges both "
            "indexes with highest-version-wins semantics, and public PyPI names are "
            "first-party-registerable. An attacker who registers your private "
            "package name on public PyPI with a higher version number wins the "
            "resolution — the PyTorch dependency-confusion incident of December 2022 "
            "used this exact shape."
        ),
        pattern=RegexPattern(
            match=r"pip\s+install[^\n]*--extra-index-url",
            exclude=[
                r"^\s*#",
                # Paired with --index-url is the safe form (private index
                # only, extra is an explicit secondary).
                r"--index-url\b(?!\s*=?\s*https?://pypi\.org)",
            ],
        ),
        remediation=(
            "Use --index-url to point pip at your private index exclusively, "
            "and mirror required public packages into it. If you must consult "
            "public PyPI, use a tool that supports explicit package-to-index "
            "pinning (uv, poetry's source priority='explicit', or pip-tools "
            "with hash-locking):\n\n"
            "# BAD — public PyPI can win resolution for private names\n"
            "pip install --extra-index-url https://pypi.internal.corp/ mypackage\n\n"
            "# GOOD — only the private index is consulted; mirror public\n"
            "# packages into it via a proxy like Artifactory or Nexus\n"
            "pip install --index-url https://pypi.internal.corp/ mypackage"
        ),
        reference="https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
        test_positive=[
            "      - run: pip install --extra-index-url https://pypi.internal.corp/ mypackage",
            "      - run: pip install -r requirements.txt --extra-index-url https://internal/",
        ],
        test_negative=[
            "      - run: pip install --index-url https://pypi.internal.corp/ mypackage",
            "      # legacy: pip install --extra-index-url https://internal/",
            "      - run: pip install requests",
        ],
        stride=["T", "S"],
        threat_narrative=(
            "Dependency confusion exploits pip's permissive resolver: when a "
            "private package name is also registerable on public PyPI, an "
            "attacker uploads a same-named package with a higher version number "
            "and pip silently prefers it. The malicious package's install hooks "
            "execute as the build user with access to all workflow secrets."
        ),
        incidents=["PyTorch dependency confusion (Dec 2022)"],
    ),
    # =========================================================================
    # SEC10-GH-003: Actions debug logging enabled — unmasks secrets in logs
    # =========================================================================
    Rule(
        id="SEC10-GH-003",
        title="Actions debug logging enabled — mask bypass, secrets visible in logs",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-10",
        description=(
            "ACTIONS_STEP_DEBUG or ACTIONS_RUNNER_DEBUG is set to true in a workflow's "
            "env: block (or jobs.*.env:, or a step env:). When either variable is "
            "true, the runner logs the pre-mask expansion of expressions — including "
            "secret values — to the job log. On a public repository, or any private "
            "repo whose logs are available to more people than the secret holder, "
            "this is a direct credential disclosure vector."
        ),
        pattern=RegexPattern(
            match=(
                r"^\s*(ACTIONS_STEP_DEBUG|ACTIONS_RUNNER_DEBUG)\s*:\s*"
                r"(?i:true|'true'|\"true\"|1|'1'|\"1\")"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Never set ACTIONS_STEP_DEBUG or ACTIONS_RUNNER_DEBUG in committed "
            "workflow YAML. If you need a debug run, enable debug logging on a "
            "single workflow execution via the GitHub UI (Re-run jobs → Enable "
            "debug logging) — the setting is per-run and doesn't persist. For "
            "persistent debug on a self-hosted runner, set it as a repo-scoped "
            "secret so only maintainers with secret access can read the unmasked "
            "logs:\n\n"
            "# BAD — committed YAML, anyone with read access sees unmasked logs\n"
            "env:\n"
            "  ACTIONS_STEP_DEBUG: true\n\n"
            "# GOOD — scoped to secret holders only, or enable per-run via UI\n"
            "# (no YAML change; use the Re-run-with-debug option)"
        ),
        reference="https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/enabling-debug-logging",
        test_positive=[
            "env:\n  ACTIONS_STEP_DEBUG: true",
            "env:\n  ACTIONS_RUNNER_DEBUG: 'true'",
            '    env:\n      ACTIONS_STEP_DEBUG: "true"',
            "  env:\n    ACTIONS_RUNNER_DEBUG: 1",
        ],
        test_negative=[
            "env:\n  ACTIONS_STEP_DEBUG: false",
            "# env:\n#   ACTIONS_STEP_DEBUG: true",
            "env:\n  MY_VAR: true",
        ],
        stride=["I", "R"],
        threat_narrative=(
            "Debug logging bypasses the runner's secret-masking layer: secret "
            "values appear in the job log as plaintext wherever they would "
            "otherwise be redacted to ***. On public repos, a pushed YAML change "
            "that flips ACTIONS_STEP_DEBUG on is equivalent to publishing the "
            "repo's secrets — the logs are indexed by GitHub search, scraped by "
            "third-party log archivers, and cached by the CDN."
        ),
        incidents=[],
    ),
    # =========================================================================
    # SEC6-GH-008: Exfil-shaped primitives in a CI run: block.  Wiz's
    # "prt-scan" campaign (6 sockpuppet accounts, Mar-Apr 2026, 475+
    # malicious PRs in 26h per the Eriksen Apr 2 disclosure) used
    # EXFIL-SHAPED primitives with zero attacker-owned infrastructure:
    # (a) `gh gist create` / `gh api /repos/.../issues` to drop stolen
    #     data into a public gist or issue the attacker then reads,
    # (b) `curl 169.254.169.254` to IMDS for cloud-runner metadata,
    # (c) `gh api /repos/.../actions/runners/registration-token` to
    #     enrol new self-hosted runners on the victim's infra.
    # These primitives don't need DNS/IP blocklists to work — every
    # defensive layer that looks at "outbound to attacker.com" misses
    # them.  Static-audit-time rule: surface their presence in a
    # workflow `run:` block so a reviewer can verify the primitive is
    # there for a legitimate reason (publishing release artifacts,
    # fetching IMDS for an intentional runner-role pivot).
    # =========================================================================
    Rule(
        id="SEC6-GH-008",
        title="Exfil-shaped primitive in run: block (gh gist / IMDS / runner-registration)",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A workflow ``run:`` block invokes a primitive that matches "
            "the exfiltration signature used by the Wiz-disclosed "
            "prt-scan campaign (Mar-Apr 2026) and the Stawinski / "
            "Praetorian self-hosted runner compromises.  The primitives "
            "are:\n"
            "  - ``gh gist create`` / ``gh api /gists`` — public-gist "
            "drop channel; attacker reads the gist later without ever "
            "touching your repo.\n"
            "  - ``gh api /repos/<org>/<repo>/issues`` POST — issue-body "
            "drop channel, similar shape.\n"
            "  - ``curl 169.254.169.254`` / ``wget 169.254.169.254`` — "
            "IMDS (cloud instance metadata).  On a runner with an "
            "instance profile, this returns temporary AWS credentials "
            "that can be chained to the cloud account.\n"
            "  - ``gh api .../actions/runners/registration-token`` — "
            "self-hosted-runner enrolment, letting an attacker register "
            "their own machine as a runner for the victim's org.\n"
            "These primitives have legitimate uses (releasing artefacts "
            "to a gist, intentional IMDS queries, dynamic runner "
            "orchestration).  The rule surfaces them so a reviewer can "
            "verify intent.  Signal quality is especially high when "
            "the workflow also has a fork-reachable trigger or runs "
            "PR-author code."
        ),
        pattern=RegexPattern(
            match=(
                r"(?:"
                # gist drop channels
                r"\bgh\s+gist\s+create\b"
                r"|\bgh\s+api\s+/gists\b"
                # issue-body drop channel — POST-verb gh api to /issues
                # or /issues/<n>/comments.  POST must be explicit via
                # `-X POST` / `--method POST` — a plain `gh api /repos/
                # .../issues/42` is a GET (read) and doesn't exfiltrate.
                r"|\bgh\s+api\s+(?:-X\s+POST\s+|--method\s+POST\s+|-f\s+)[^\n#]*"
                r"/repos/[^\s/]+/[^\s/]+/issues(?:/\d+/comments)?\b"
                # IMDS — IPv4 and IPv6 link-local forms
                r"|\b(?:curl|wget|http)\s+[^#\n]*169\.254\.169\.254"
                r"|\b(?:curl|wget|http)\s+[^#\n]*\[fd00:ec2::254\]"
                # Self-hosted runner enrolment
                r"|\bgh\s+api\s+[^\s]*/actions/runners/(?:registration|remove)-token"
                r")"
            ),
            exclude=[
                r"^\s*#",
                r"^\s*//",
                # Allow legitimate release-asset uploads that use
                # `gh release create`/`upload` — distinct shape from
                # `gh gist create`.  Nothing to exclude here; the
                # anchor already narrows.
            ],
            heredoc_aware=True,
        ),
        remediation=(
            "Each primitive has a legitimate use, so the remediation is\n"
            "specific to why you're running it:\n"
            "  - `gh gist create` — if you're dropping a report, use\n"
            "    `gh release upload` to a tagged release instead; gist\n"
            "    creation is public-by-default and appends to the org's\n"
            "    attack surface.\n"
            "  - `gh api .../issues` POST — only legitimate if the job\n"
            "    runs on a trusted trigger (push to main, scheduled);\n"
            "    NEVER on fork-reachable triggers where the posted\n"
            "    body could include attacker-steered content.\n"
            "  - `curl 169.254.169.254` (IMDS) — verify the job runs\n"
            "    on a runner you control and the instance role is\n"
            "    narrow.  On GitHub-hosted runners, IMDS shouldn't be\n"
            "    needed at all.\n"
            "  - `gh api .../runners/registration-token` — this should\n"
            "    only run in an ops-only workflow (workflow_dispatch,\n"
            "    protected environment).  Presence on fork-reachable\n"
            "    triggers means an attacker can register their own\n"
            "    runner and hijack future jobs.\n"
            "Run `taintly --guide SEC6-GH-008` for the full checklist."
        ),
        reference=(
            "https://www.wiz.io/blog/six-accounts-one-actor-inside-the-prt-scan-supply-chain-campaign; "
            "https://safedep.io/prt-scan-github-actions-exfiltration-campaign/; "
            "https://johnstawinski.com/2024/01/11/playing-with-fire-how-we-executed-a-critical-supply-chain-attack-on-pytorch/"
        ),
        test_positive=[
            # gist drop
            "      - run: gh gist create secrets.txt --public",
            # gist via gh api
            "      - run: gh api /gists -f 'files[payload.json][content]=@data.json'",
            # issue-body drop via POST
            '      - run: gh api -X POST /repos/owner/repo/issues -f title=x -f body="$LOOT"',
            # Issue comment drop
            "      - run: gh api --method POST /repos/owner/repo/issues/1/comments -f body=x",
            # IMDS curl
            "      - run: curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            # IMDS wget
            "      - run: wget -q -O - http://169.254.169.254/latest/meta-data/",
            # Runner registration token
            "      - run: gh api /repos/org/repo/actions/runners/registration-token",
        ],
        test_negative=[
            # gh release upload — legitimate, different primitive
            "      - run: gh release upload v1.2.3 artifact.zip",
            # Issue create (no POST, no body drop) — a GET read of issues
            "      - run: gh api /repos/owner/repo/issues/42",
            # IMDS IP in an unrelated context (comment, string literal)
            "      # curl to 169.254.169.254 is IMDS — don't do this",
            # curl to a normal URL
            "      - run: curl https://api.example.com/health",
            # gh api to an unrelated endpoint
            "      - run: gh api /user",
        ],
        stride=["I", "E", "R"],
        threat_narrative=(
            "Zero-infrastructure exfiltration: the attacker never "
            "owns a DNS name or an IP address.  They publish a "
            "sockpuppet GitHub account, open a fork PR whose workflow "
            "runs ``gh gist create`` or posts to an issue, then reads "
            "the resulting artefact from their own account.  Defensive "
            "layers that scan outbound DNS or IP destinations see "
            "nothing — the traffic is all to github.com or to IMDS, "
            "both of which are on every allowlist.  Wiz's prt-scan "
            "disclosure (April 2026) named this pattern explicitly; "
            "the Stawinski PyTorch / Praetorian TensorFlow post-"
            "mortems name IMDS + runner registration-token as the "
            "pivot primitives for self-hosted-runner compromise."
        ),
        confidence="low",
        incidents=[
            "prt-scan (Wiz, Apr 2026)",
            "PyTorch supply chain (Stawinski, Jan 2024)",
            "TensorFlow self-hosted runner (Praetorian, 2024)",
        ],
    ),
    # =========================================================================
    # SEC6-GH-009: Long-lived package-registry publishing token used instead
    # of OIDC Trusted Publishers.  Source incident: Cycode's LiteLLM PyPI
    # compromise (March 2026) — ``PYPI_PUBLISH_PASSWORD`` was exfiltrated
    # via a compromised Trivy action, and two backdoored wheels (1.82.7,
    # 1.82.8) were published before rotation.  The risk is structural:
    # any long-lived publishing token is a magnet for supply-chain exfil
    # because a single pull of the token from any step in any workflow
    # permanently owns the package.
    #
    # Trusted Publishers (PyPI), provenance-signed publish (npm 9+), and
    # OIDC-federated Cargo tokens close this gap by binding publish
    # authority to a specific workflow+environment+repo trio — a stolen
    # token is useless outside that context.
    # =========================================================================
    Rule(
        id="SEC6-GH-009",
        title=(
            "Package registry publish uses a long-lived secret instead of OIDC Trusted Publishers"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A workflow publishes to PyPI, npm, Cargo, or RubyGems and "
            "authenticates with a long-lived secret "
            "(``TWINE_PASSWORD``, ``PYPI_API_TOKEN``, ``NPM_TOKEN``, "
            "``NODE_AUTH_TOKEN``, ``CARGO_REGISTRY_TOKEN``, "
            "``CRATES_IO_TOKEN``, ``GEM_HOST_API_KEY``) rather than "
            "OIDC-federated publish (PyPI Trusted Publishers, "
            "``npm publish --provenance`` with OIDC, Cargo's GitHub-"
            "Actions-issued registry token).  A long-lived token is a "
            "single-shot supply-chain primitive: any compromise of any "
            "workflow step that can read the secret permanently owns "
            "the package until the token is rotated.  The LiteLLM "
            "compromise (March 2026) exfiltrated ``PYPI_PUBLISH_PASSWORD`` "
            "via a compromised Trivy action and published two backdoored "
            "wheels before the token was rotated."
        ),
        pattern=ContextPattern(
            # Anchor (the location of the finding): a publish command
            # or the ``password:`` input of a publish action.
            anchor=(
                r"(?:"
                # Shell-form publish commands on a run: line
                r"\btwine\s+upload\b"
                r"|\bnpm\s+publish\b"
                r"|\byarn\s+publish\b"
                r"|\bpnpm\s+publish\b"
                r"|\bcargo\s+publish\b"
                r"|\bgem\s+push\b"
                # Action-form: pypa/gh-action-pypi-publish with a
                # password: input (the OIDC form omits password:).
                r"|\bpypa/gh-action-pypi-publish\b"
                r")"
            ),
            # Job-scope requires: a long-lived publishing-token secret
            # appears in the same job.  This ties the publish command
            # to the specific secret rather than firing on every
            # workflow that happens to have one defined somewhere else.
            requires=(
                r"\$\{\{\s*secrets\.(?:"
                r"TWINE_PASSWORD|TWINE_API_TOKEN"
                r"|PYPI_API_TOKEN|PYPI_TOKEN|PYPI_PUBLISH_PASSWORD"
                r"|NPM_TOKEN|NPM_AUTH_TOKEN|NODE_AUTH_TOKEN"
                r"|CARGO_REGISTRY_TOKEN|CRATES_IO_TOKEN"
                r"|GEM_HOST_API_KEY|RUBYGEMS_API_KEY"
                r")\s*\}\}"
            ),
            scope="job",
            exclude=[
                r"^\s*#",
            ],
        ),
        remediation=(
            "Switch to OIDC-federated publishing.  Each registry has a\n"
            "native mechanism:\n"
            "\n"
            "PyPI — Trusted Publishers.  Register the repository on\n"
            "pypi.org (Your projects > publishing > Add pending publisher),\n"
            "then:\n"
            "\n"
            "    permissions:\n"
            "      id-token: write\n"
            "    steps:\n"
            "      - uses: pypa/gh-action-pypi-publish@76f52bc884231f62b9a034ebfe128415bbaabdfc\n"
            "        # omit password: — the action mints an OIDC token\n"
            "\n"
            "npm — ``--provenance`` + OIDC (npm 9+):\n"
            "\n"
            "    permissions:\n"
            "      id-token: write\n"
            "    steps:\n"
            "      - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af\n"
            "        with:\n"
            "          registry-url: 'https://registry.npmjs.org'\n"
            "      - run: npm publish --provenance --access public\n"
            "\n"
            "Cargo — GitHub-Actions-issued registry token (2026-ready)\n"
            "or delegate to crates.io's OIDC when available.\n"
            "\n"
            "If you must keep a long-lived token today (e.g., Cargo on\n"
            "a registry that doesn't federate yet), at minimum scope the\n"
            "publish workflow to a protected environment with required\n"
            "reviewers, so a compromise of any OTHER workflow in the\n"
            "repo can't exfiltrate the publish secret."
        ),
        reference=(
            "https://docs.pypi.org/trusted-publishers/; "
            "https://docs.npmjs.com/generating-provenance-statements; "
            "https://cycode.com/blog/lite-llm-supply-chain-attack/"
        ),
        test_positive=[
            # Shell twine upload + TWINE_PASSWORD secret in same job
            (
                "jobs:\n  publish:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: twine upload dist/*\n"
                "        env:\n          TWINE_USERNAME: __token__\n"
                "          TWINE_PASSWORD: ${{ secrets.TWINE_PASSWORD }}"
            ),
            # npm publish + NPM_TOKEN secret
            (
                "jobs:\n  release:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: npm publish\n"
                "        env:\n"
                "          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}"
            ),
            # cargo publish with CARGO_REGISTRY_TOKEN
            (
                "jobs:\n  release:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: cargo publish\n"
                "        env:\n"
                "          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}"
            ),
            # pypa/gh-action-pypi-publish + password: input
            (
                "jobs:\n  publish:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: pypa/gh-action-pypi-publish@v1\n"
                "        with:\n"
                "          password: ${{ secrets.PYPI_API_TOKEN }}"
            ),
            # gem push + GEM_HOST_API_KEY
            (
                "jobs:\n  release:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: gem push mygem-1.0.gem\n"
                "        env:\n"
                "          GEM_HOST_API_KEY: ${{ secrets.RUBYGEMS_API_KEY }}"
            ),
        ],
        test_negative=[
            # OIDC PyPI publish — no password: input, id-token: write.
            (
                "permissions:\n  id-token: write\n"
                "jobs:\n  publish:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: pypa/gh-action-pypi-publish@v1"
            ),
            # npm provenance + OIDC (no NPM_TOKEN secret)
            (
                "permissions:\n  id-token: write\n"
                "jobs:\n  release:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: npm publish --provenance --access public"
            ),
            # Unrelated secret + unrelated run
            (
                "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: pytest\n"
                "        env:\n"
                "          API_TOKEN: ${{ secrets.APP_API_TOKEN }}"
            ),
            # Publish command in one job, publishing token in a
            # different job — scope="job" prevents a false positive.
            (
                "jobs:\n  docs:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: twine upload dist/*\n"
                "  seed:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: echo hi\n"
                "        env:\n"
                "          TWINE_PASSWORD: ${{ secrets.TWINE_PASSWORD }}"
            ),
            # Comment
            "# twine upload dist/* with TWINE_PASSWORD: ${{ secrets.TWINE_PASSWORD }}",
        ],
        stride=["I", "E"],
        threat_narrative=(
            "A long-lived package-registry publishing token is readable "
            "by every step in every workflow that references it, including "
            "any compromised third-party action that runs in that job.  "
            "Unlike an OIDC-minted token (which binds to a specific "
            "workflow+repo+environment trio at mint time and expires in "
            "minutes), a classic ``TWINE_PASSWORD`` or ``NPM_TOKEN`` "
            "remains valid until rotated and can be replayed from any "
            "host — meaning the attacker can publish a backdoored version "
            "from their own infrastructure immediately after exfil.  The "
            "LiteLLM March 2026 compromise took this exact path: a "
            "compromised Trivy action exfiltrated ``PYPI_PUBLISH_PASSWORD`` "
            "and two backdoored wheels were published before anyone "
            "noticed."
        ),
        incidents=[
            "LiteLLM PyPI compromise (Cycode, March 2026)",
            "tj-actions/changed-files — lateral token exfil (Mar 2025)",
        ],
        confidence="medium",
    ),
    # =========================================================================
    # SEC9-GH-004: Tainted `actions/cache` key — a workflow restores an
    # `actions/cache` entry whose `key:` or `restore-keys:` interpolates
    # attacker-controlled context (github.event.*, github.head_ref,
    # github.actor).  This was the PERSISTENCE leg of the Ultralytics
    # compromise (Dec 2024): the attacker's pull_request_target shell
    # injection wrote a poisoned cache entry keyed on the PR head_ref;
    # the next release workflow restored it and executed the stored
    # payload.  Because the restore happens before any script-level
    # integrity check, the cache is a persistence channel that survives
    # PR closure.
    # =========================================================================
    Rule(
        id="SEC9-GH-004",
        title="actions/cache key or restore-keys sourced from attacker-controlled context",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-9",
        description=(
            "An ``actions/cache`` step uses a ``key:`` or "
            "``restore-keys:`` value that interpolates attacker-"
            "controlled GitHub context — ``github.event.pull_request."
            "head.{ref,sha}``, ``github.head_ref``, ``github.actor``, "
            "``github.event.pull_request.title``, or any "
            "``inputs.*``.  An attacker who controls the context "
            "(via a fork PR or a crafted issue body) picks the cache "
            "key, which means they can WRITE a poisoned cache entry "
            "in one workflow run and have a later run RESTORE it.  "
            "Because cache restore happens before any script-level "
            "integrity check, poisoned contents land in the workspace "
            "and then whatever the workflow does with them (``pip "
            "install``, ``npm ci``, ``docker build``) runs attacker "
            "code.  This is the persistence leg of the Ultralytics "
            "supply-chain compromise (Dec 2024)."
        ),
        pattern=ContextPattern(
            # ANCHOR — a line defining `key:` or `restore-keys:` whose
            # value interpolates attacker-controlled GitHub context.
            # Exclude `github.sha` / `github.ref` / `github.repository` /
            # `github.event.number` — those are server-minted /
            # deterministic and aren't attacker-controllable.
            anchor=(
                r"(?:^|\s)(?:key|restore-keys):\s*[\"']?[^\"'\n]*"
                r"\$\{\{[^}]*"
                r"(?:github\.event\.(?:pull_request\.(?:head\.|title|body)"
                r"|issue\.(?:title|body)|comment\.body"
                r"|head_commit\.message)"
                r"|github\.head_ref"
                r"|github\.actor"
                r"|inputs\.[a-zA-Z_])"
                r"[^}]*\}\}"
            ),
            # REQUIRES — the workflow uses `actions/cache` somewhere.
            # Without this, a `key:` that happens to be attacker-tainted
            # in an unrelated YAML structure (e.g. a Docker environment)
            # wouldn't be cache-relevant.  Matches the module prefix so
            # `actions/cache@v4` / `actions/cache/restore@v4` /
            # `actions/cache/save@v4` all satisfy the check.
            requires=r"uses:\s*actions/cache(?:/[a-z]+)?@",
            scope="job",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Build `actions/cache` keys from stable, server-side data —\n"
            "hashes of lockfiles (`hashFiles('**/package-lock.json')`),\n"
            "the workflow SHA (`${{ github.sha }}`), OS name, matrix\n"
            "parameters.  If you need a per-PR cache, scope by the PR\n"
            "number not the ref:\n"
            "  key: ${{ github.repository }}-${{ github.event.number }}-deps\n"
            "  (the number is server-minted; ref/title/actor are attacker-\n"
            "  controlled).  For the Ultralytics-class persistence bug:\n"
            "  never share a cache between fork-PR build jobs and a\n"
            "  release job — cache scope defaults to the branch, which\n"
            "  is enough isolation if you don't restore-keys across\n"
            "  branches.\n"
            "Run `taintly --guide SEC9-GH-004` for the full checklist."
        ),
        reference=(
            "https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/; "
            "https://github.com/actions/cache#security"
        ),
        test_positive=[
            # head_ref directly in key
            (
                "      - uses: actions/cache@v4\n"
                "        with:\n"
                "          path: ~/.npm\n"
                "          key: deps-${{ github.head_ref }}"
            ),
            # pull_request head ref
            (
                "      - uses: actions/cache@v4\n"
                "        with:\n"
                "          key: cache-${{ github.event.pull_request.head.ref }}"
            ),
            # Actor — lower-impact but still attacker-controlled
            (
                "      - uses: actions/cache@v4\n"
                "        with:\n"
                "          key: deps-${{ github.actor }}"
            ),
            # restore-keys prefix using attacker context
            (
                "      - uses: actions/cache@v4\n"
                "        with:\n"
                "          key: main\n"
                "          restore-keys: deps-${{ github.head_ref }}-"
            ),
            # PR title in key — silly but exploitable
            (
                "      - uses: actions/cache@v4\n"
                "        with:\n"
                "          key: ${{ github.event.pull_request.title }}"
            ),
        ],
        test_negative=[
            # Stable hash-based key — safe
            (
                "      - uses: actions/cache@v4\n"
                "        with:\n"
                "          key: deps-${{ hashFiles('package-lock.json') }}"
            ),
            # Matrix + OS + SHA — all server-side
            (
                "      - uses: actions/cache@v4\n"
                "        with:\n"
                "          key: ${{ runner.os }}-${{ matrix.node }}-${{ github.sha }}"
            ),
            # PR NUMBER (server-minted) — safe despite looking like event data
            (
                "      - uses: actions/cache@v4\n"
                "        with:\n"
                "          key: pr-${{ github.event.number }}-build"
            ),
            # Unrelated field — repository is safe
            (
                "      - uses: actions/cache@v4\n"
                "        with:\n"
                "          key: ${{ github.repository }}-build"
            ),
            # Commented out
            (
                "      - uses: actions/cache@v4\n"
                "        with:\n"
                "          # key: deps-${{ github.head_ref }}\n"
                "          key: deps-${{ hashFiles('lock') }}"
            ),
        ],
        stride=["T", "I", "E"],
        threat_narrative=(
            "A fork-PR attacker writes a cache entry keyed on a "
            "value they control (branch name, PR title, actor).  A "
            "later release workflow restores the entry before any "
            "integrity check and executes it via the next build "
            "step.  The cache becomes a persistence channel: the "
            "attacker's PR can be closed and the attack still fires "
            "on the next release.  Ultralytics (December 2024) used "
            "this exact pattern — the pull_request_target injection "
            "wrote the poisoned cache, the release job restored it "
            "hours later."
        ),
        confidence="medium",
        incidents=["Ultralytics (Dec 2024)"],
    ),
]
