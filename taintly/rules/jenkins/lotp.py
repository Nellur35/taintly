"""Jenkins LOTP — Living Off The Pipeline.

Detects build tools that execute lifecycle scripts or build hooks against
attacker-controlled code in Jenkins pipelines.

Jenkins' risk model is structurally different from GitHub/GitLab:

- There is no single declarative "trigger" field that tells us whether the
  job processes external input. Multibranch Pipelines and the GitHub
  Branch Source plugin expose PR context via ``env.CHANGE_*`` variables,
  and the (now-legacy) GitHub PR Builder plugin uses ``ghprb*`` variables.
  Freestyle and classic Pipeline jobs may build parameterised branches
  supplied by an external trigger.

- The Jenkinsfile does not declare whether it runs in a Multibranch PR
  context. A Jenkinsfile that references ``env.CHANGE_ID`` / ``CHANGE_BRANCH``
  / ``ghprbActualCommit`` is strong evidence the author expects PR builds;
  combined with a build-tool invocation in the same file, this is the
  LOTP-risky shape.

This rule therefore fires on ``build tool + PR-context variable in the
same Jenkinsfile``. File-scoped because we cannot reliably segment a
Jenkinsfile into per-stage scopes the way we do for YAML job keys.
"""

import re
import shlex

from taintly.models import ContextPattern, Platform, Rule, Severity

from .._build_tools import BUILD_TOOL_ANCHOR as _BUILD_TOOL_ANCHOR

# Evidence the Jenkinsfile is PR-context aware. Any of these references
# strongly implies the pipeline can be triggered by a PR build, meaning
# the checked-out source may be attacker-controlled.
_PR_CONTEXT = (
    r"(?:"
    # Multibranch Pipeline / GitHub Branch Source plugin
    r"\benv\.CHANGE_(?:ID|BRANCH|TARGET|URL|AUTHOR|TITLE|FORK)\b"
    # Legacy GitHub Pull Request Builder plugin
    r"|\bghprb(?:ActualCommit|PullId|PullTitle|SourceBranch|TargetBranch|PullAuthorEmail)\b"
    # Gerrit Trigger plugin (change-based triggering)
    r"|\bGERRIT_(?:CHANGE_ID|BRANCH|REFSPEC|PATCHSET_REVISION)\b"
    r")"
)


class _JenkinsInstallerLeafPattern:
    """Match an unsafe package installer in an actual Jenkins shell step.

    LOTP-JK-003 used to search Jenkinsfile lines, which also matched stage
    names and variable values that merely contained words like ``yarn``.
    Island LEAF events constrain the search to executable ``sh``/``bat``/
    ``powershell``/``pwsh`` bodies while retaining the call site's line.
    """

    _INSTALLER_RE = re.compile(
        r"(?i)^\s*(?:(?:env\s+)?(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*)"
        r"(?P<tool>npm\s+(?:install|i|ci)|yarn(?:\s+install)?|pnpm\s+(?:install|i))"
        r"(?=\s|$)"
    )

    def __init__(self) -> None:
        # Share Jenkins' existing island-shell matcher for LEAF selection and
        # call-site attribution; only this rule's body predicate is new.
        from .sec_jenkins import _JenkinsfileShellLeafPattern

        self._shell_pattern = _JenkinsfileShellLeafPattern(self._body_matches)

    @staticmethod
    def _pr_context(content: str) -> bool:
        """Read PR signals from Groovy code or live GString expressions.

        Comments and ordinary string data cannot donate file-level PR
        context; the common ``"${env.CHANGE_BRANCH}"`` form remains covered.
        """
        from taintly.parsers.jenkinsfile.groovy_lex import TokKind, tokenize

        tokens = list(tokenize(content))
        significant = [
            token
            for token in tokens
            if token.kind not in (TokKind.COMMENT, TokKind.NEWLINE, TokKind.SEMI)
        ]
        for index, token in enumerate(significant):
            if token.kind == TokKind.IDENT and re.search(
                r"(?i)^(?:ghprb(?:ActualCommit|PullId|PullTitle|SourceBranch|TargetBranch|PullAuthorEmail)|GERRIT_(?:CHANGE_ID|BRANCH|REFSPEC|PATCHSET_REVISION))$",
                token.value,
            ):
                return True
            if (
                token.kind == TokKind.IDENT
                and token.value == "env"
                and index + 2 < len(significant)
                and significant[index + 1].kind == TokKind.OP
                and significant[index + 1].value == "."
                and significant[index + 2].kind == TokKind.IDENT
                and re.fullmatch(
                    r"CHANGE_(?:ID|BRANCH|TARGET|URL|AUTHOR|TITLE|FORK)",
                    significant[index + 2].value,
                )
            ):
                return True
            if token.kind == TokKind.STRING and any(
                re.search(_PR_CONTEXT, span.expr) for span in (token.interpolations or ())
            ):
                return True
        return False

    @staticmethod
    def _commands(body: str):
        """Yield shell command segments, respecting quotes and comments."""
        body = _JenkinsInstallerLeafPattern._remove_active_continuations(body)
        start = 0
        quote: str | None = None
        escaped = False
        i = 0
        while i < len(body):
            char = body[i]
            if (
                char == "$"
                and i + 1 < len(body)
                and body[i + 1] == "("
                and quote != "'"
                and not escaped
            ):
                end = _JenkinsInstallerLeafPattern._command_substitution_end(body, i)
                if end is not None:
                    yield from _JenkinsInstallerLeafPattern._commands(body[i + 2 : end])
                    i = end
                    continue
            if escaped:
                escaped = False
            elif char == "\\" and quote != "'":
                escaped = True
            elif quote:
                if char == quote:
                    quote = None
            elif char in ("'", '"'):
                quote = char
            elif char == "#" and (i == start or body[i - 1].isspace()):
                end = body.find("\n", i)
                if end < 0:
                    end = len(body)
                yield body[start:i]
                start = end + 1
                i = end
            elif char in ";|&\n":
                yield body[start:i]
                start = i + 1
            i += 1
        yield body[start:]

    @staticmethod
    def _remove_active_continuations(body: str) -> str:
        """Remove shell line continuations except inside single-quoted data."""
        output: list[str] = []
        quote: str | None = None
        escaped = False
        i = 0
        while i < len(body):
            char = body[i]
            if char == "\\" and quote != "'" and i + 1 < len(body):
                if body[i + 1] == "\n" and not escaped:
                    i += 2
                    while i < len(body) and body[i] in " \t":
                        i += 1
                    continue
                if (
                    body[i + 1] == "\r"
                    and i + 2 < len(body)
                    and body[i + 2] == "\n"
                    and not escaped
                ):
                    i += 3
                    while i < len(body) and body[i] in " \t":
                        i += 1
                    continue
            if escaped:
                escaped = False
            elif char == "\\" and quote != "'":
                escaped = True
            elif quote:
                if char == quote:
                    quote = None
            elif char in ("'", '"'):
                quote = char
            output.append(char)
            i += 1
        return "".join(output)

    @staticmethod
    def _command_substitution_end(body: str, start: int) -> int | None:
        depth = 1
        quote: str | None = None
        escaped = False
        i = start + 2
        while i < len(body):
            char = body[i]
            if escaped:
                escaped = False
            elif char == "\\" and quote != "'":
                escaped = True
            elif quote:
                if char == quote:
                    quote = None
            elif char in ("'", '"'):
                quote = char
            elif body.startswith("$(", i):
                depth += 1
                i += 1
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return i
            i += 1
        return None

    @classmethod
    def _has_ignore_scripts(cls, command: str) -> bool:
        try:
            args = shlex.split(command, posix=True)
        except ValueError:
            return False
        return any(
            arg == "--ignore-scripts" or arg.lower() == "--ignore-scripts=true" for arg in args
        )

    @classmethod
    def _body_matches(cls, body: str, _interpolated: bool = False) -> bool:
        for command in cls._commands(body):
            command = command.strip()
            # Shell compound commands put executable commands after control
            # words such as ``then``; discard only these leading keywords.
            command = re.sub(
                r"^(?:(?:then|else|elif|if|while|until|do)\b\s*)+", "", command, flags=re.I
            )
            match = cls._INSTALLER_RE.match(command)
            if not match or cls._has_ignore_scripts(command):
                continue
            # Bare ``yarn`` means install; ``yarn test`` / ``yarn run``
            # execute scripts and are not package installation sinks.
            if (
                match.group("tool").lower() == "yarn"
                and command[match.end() :].strip()
                and not command[match.end() :].lstrip().startswith("-")
            ):
                continue
            return True
        return False

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if not self._pr_context(content):
            return []
        return self._shell_pattern.check(content, lines)


RULES: list[Rule] = [
    # =========================================================================
    # LOTP-JK-001: Build tool + PR-context in Jenkinsfile
    # =========================================================================
    Rule(
        id="LOTP-JK-001",
        finding_family="pipeline_tool_execution",
        title="Build tool invoked in Jenkinsfile that references PR-context variables (LOTP)",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkinsfile references PR-context variables — "
            "env.CHANGE_ID/CHANGE_BRANCH (Multibranch / GitHub Branch Source), "
            "ghprb* (legacy PR Builder), or GERRIT_CHANGE_* (Gerrit trigger) — "
            "and also runs a build tool (npm, pip, make, cargo, mvn, gradle, "
            "docker, etc.). In Multibranch and PR-builder configurations, "
            "Jenkins auto-checks-out the PR's source branch, so the build "
            "tool operates on attacker-controlled code. Lifecycle scripts or "
            "build hooks declared in the PR's package.json, setup.py, "
            "Makefile, pom.xml, or Dockerfile execute with the Jenkins "
            "agent's identity — including any credentials bound by "
            "withCredentials or exported into the environment block."
        ),
        pattern=ContextPattern(
            anchor=_BUILD_TOOL_ANCHOR,
            requires=_PR_CONTEXT,
            scope="file",
            exclude=[
                r"^\s*//",  # Groovy single-line comment
                r"^\s*/\*",  # `/*` block-comment opener (single-line
                # `/* ... */` or multi-line opener)
                r"^\s*\*",  # Javadoc-style block-comment body
                r"^\s*#",  # Shebang or shell-style comment (rare in Groovy)
                # Suppress the common English prose "make sure"
                r"\bmake\s+sure\b",
            ],
        ),
        remediation=(
            "Do not run build tools in a Jenkinsfile that can be triggered "
            "by an untrusted PR. Mitigations, in order of preference:\n"
            "\n"
            "1. Move build-tool invocation out of PR builds. In declarative "
            "   Pipeline, gate the stage on the base branch:\n"
            "\n"
            "     stage('Build') {\n"
            "         when { branch 'main' }\n"
            "         steps { sh 'npm ci' }\n"
            "     }\n"
            "\n"
            "2. Run PR builds on an isolated agent with no credentials and "
            "   no network access to internal systems. Use `agent { label "
            "   'pr-sandbox' }` for the stage, and bind no credentials via "
            "   withCredentials inside it.\n"
            "\n"
            "3. For JavaScript builds, add `--ignore-scripts` to npm/yarn/"
            "   pnpm install commands to disable lifecycle hooks.\n"
            "\n"
            "4. Verify that PR trust settings on the GitHub Branch Source / "
            "   Multibranch configuration only build PRs from trusted "
            "   contributors — in the job configuration, set 'Trust' to "
            "   'From users with Admin or Write permission'."
        ),
        reference="https://www.jenkins.io/doc/book/security/securing-jenkins/#ci-cd-security",
        test_positive=[
            # Multibranch PR-aware Jenkinsfile running npm install
            "pipeline {\n    agent any\n    stages {\n"
            "        stage('build') {\n"
            "            when { changeRequest() }\n"
            "            steps {\n"
            '                echo "Building PR #${env.CHANGE_ID}"\n'
            "                sh 'npm install'\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}",
            # ghprb-plugin build running pip install .
            "node {\n    if (env.ghprbPullId) {\n        sh 'pip install .'\n    }\n}",
            # CHANGE_BRANCH + docker build
            "pipeline {\n    agent any\n    stages {\n"
            "        stage('pr-image') {\n"
            "            steps {\n"
            '                echo "branch ${env.CHANGE_BRANCH}"\n'
            "                sh 'docker build -t review .'\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}",
        ],
        test_negative=[
            # No PR context — build tool is safe (runs only on trusted refs)
            "pipeline {\n    agent any\n    stages {\n"
            "        stage('build') { steps { sh 'npm install' } }\n"
            "    }\n"
            "}",
            # PR context but no build tool — posting a status comment only
            "pipeline {\n    agent any\n    stages {\n"
            "        stage('note') { steps { echo \"PR ${env.CHANGE_ID}\" } }\n"
            "    }\n"
            "}",
            # PR context but the stage only runs a non-build-tool command
            "pipeline {\n    agent any\n    stages {\n"
            "        stage('status') {\n"
            "            when { changeRequest() }\n"
            "            steps {\n"
            '                echo "PR ${env.CHANGE_ID} on ${env.CHANGE_BRANCH}"\n'
            "                sh 'curl -X POST https://status.internal/ping'\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker opens a pull request that edits package.json's "
            "postinstall script, setup.py's cmdclass, a Makefile target, or "
            "a Dockerfile RUN directive to execute their payload. Jenkins' "
            "Multibranch / PR-builder machinery checks out the PR's branch "
            "and runs the Jenkinsfile — when the build tool fires against "
            "the attacker's manifest, the payload executes with the "
            "agent's full environment. Credentials bound inside the stage "
            "(withCredentials, the environment block's credentials() helper, "
            "SSH agent keys for SCM) are all reachable."
        ),
        incidents=["Ultralytics (Dec 2024)"],
    ),
    # =========================================================================
    # LOTP-JK-005: npm/yarn/pnpm install in a Jenkins pipeline that binds an
    # npm publishing credential.  Jenkins port of LOTP-GH-005 / LOTP-GL-005
    # (Shai-Hulud class).
    #
    # Jenkins' model differs from the hosted runners on two key axes:
    #   1. Self-hosted by default.  A compromised postinstall script runs
    #      on the agent's host, not an ephemeral container the cloud
    #      destroys after the job.  That amplifies the blast radius:
    #      persistent filesystem on the agent, shared build caches, and
    #      often SSH keys / secondary credentials the agent already
    #      holds.
    #   2. Credentials are bound by ``withCredentials([...])`` block or
    #      the declarative ``environment { X = credentials('id') }``
    #      helper.  Unlike GH/GL, there's no "permissions: write" block
    #      to signal — the credential itself IS the signal.
    #
    # Shape: a Jenkinsfile runs ``npm/yarn/pnpm install`` without
    # ``--ignore-scripts`` AND references a publish-token variable name
    # (``NPM_TOKEN`` / ``NODE_AUTH_TOKEN`` / ``NPM_CONFIG_AUTH_TOKEN`` /
    # ``YARN_NPM_AUTH_TOKEN``) anywhere in the same file.  The variable
    # name is the signal regardless of whether the binding is a
    # ``withCredentials`` block, an ``environment {}`` declaration, or
    # an explicit ``env.NPM_TOKEN = ...`` statement.
    #
    # File-scoped because ``_split_into_job_segments`` already treats a
    # Jenkinsfile as a single segment (no 0-indent YAML keys).
    #
    # References: Shai-Hulud (Sep 2025) + Shai-Hulud 2.0 (Nov 2025).
    # Jenkins-specific hardening guidance:
    # https://www.jenkins.io/doc/book/pipeline/pipeline-best-practices/
    # =========================================================================
    Rule(
        id="LOTP-JK-005",
        finding_family="pipeline_tool_execution",
        title=(
            "npm/yarn/pnpm install in a Jenkinsfile that binds an "
            "npm publishing credential (Shai-Hulud class)"
        ),
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A Jenkins pipeline runs ``npm install`` / ``npm ci`` / "
            "``yarn install`` / ``pnpm install`` WITHOUT "
            "``--ignore-scripts``, and the same Jenkinsfile references "
            "a publish-token variable — ``NPM_TOKEN`` / ``NODE_AUTH_TOKEN`` / "
            "``NPM_CONFIG_AUTH_TOKEN`` / ``YARN_NPM_AUTH_TOKEN`` — "
            "typically through a ``withCredentials([string(credentialsId: "
            "'npm-token', variable: 'NPM_TOKEN')])`` block or an "
            "``environment { NPM_TOKEN = credentials('npm-token') }`` "
            "declaration.  Every direct and transitive dependency's "
            "``postinstall`` / ``preinstall`` / ``prepare`` hook runs "
            "in the agent's shell with the credential in process env.  "
            "On Jenkins this is especially dangerous because agents are "
            "self-hosted by default — a compromised script persists on "
            "the filesystem, may read SSH keys the agent uses for SCM, "
            "and can pivot to other credentials the same agent is "
            "trusted to bind in later builds.  The exploit class is "
            "the same as Shai-Hulud (Sep 2025) and Shai-Hulud 2.0 "
            "(Nov 2025)."
        ),
        pattern=ContextPattern(
            # Anchor: per-line install invocation NOT already carrying
            # ``--ignore-scripts``.  Matches inside Groovy ``sh 'npm
            # install'`` strings (the common shape) as well as bare
            # invocations in shell ``script:`` blocks.
            anchor=(
                r"\b(?:"
                r"npm\s+(?:install|i|ci)"
                r"|yarn\s+(?:install|add)"
                r"|pnpm\s+(?:install|i|add)"
                r")\b(?:(?!--ignore-scripts).)*$"
            ),
            # Requires (per-file): publish-token variable reference.
            # The variable name is the signal — its source (credentials
            # binding, environment block, explicit assignment) doesn't
            # change the threat shape.
            requires=(
                r"(?:"
                r"\bNPM_TOKEN\b"
                r"|\bNODE_AUTH_TOKEN\b"
                r"|\bNPM_CONFIG_AUTH_?TOKEN\b"
                r"|\bYARN_NPM_AUTH_?TOKEN\b"
                r")"
            ),
            scope="file",
            exclude=[
                r"^\s*//",  # Groovy line comment
                r"^\s*/\*",  # `/*` block-comment opener (single-line
                # `/* ... */` or multi-line opener)
                r"^\s*\*",  # Javadoc block-comment body
                r"^\s*#",  # Shell-style comment (rare in Groovy)
                # Lines already passing --ignore-scripts are safe.
                r"--ignore-scripts",
            ],
        ),
        remediation=(
            "Pass `--ignore-scripts` to every `npm install` / `npm ci`\n"
            "/ `yarn install` / `pnpm install` in a Jenkinsfile that\n"
            "binds an npm publishing credential.  This blocks the\n"
            "postinstall / preinstall lifecycle hooks that Shai-Hulud-\n"
            "class attacks abuse.  For pipelines that genuinely need\n"
            "lifecycle scripts (native-addon builds), split into two\n"
            "stages: a `build` stage on an isolated agent (no\n"
            "`withCredentials`, no bound publish token) that installs\n"
            "and stashes node_modules; and a `publish` stage that\n"
            "unstashes and publishes with `--ignore-scripts` and the\n"
            "credential scoped as tightly as possible.\n"
            "\n"
            "Prefer single-quoted Groovy strings inside `sh '...'` so\n"
            "the token is resolved by the shell from the environment,\n"
            "not interpolated into the command string by Groovy (see\n"
            "SEC4-JK-001 / SEC6-JK-002 for the general class).\n"
            "Run `taintly --guide LOTP-GH-005` for the\n"
            "remediation checklist (it applies directly to Jenkins\n"
            "with the obvious credential-binding substitutions)."
        ),
        reference=(
            "https://www.sysdig.com/blog/shai-hulud-the-novel-self-replicating-worm-infecting-hundreds-of-npm-packages; "
            "https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/; "
            "https://www.jenkins.io/doc/pipeline/steps/credentials-binding/"
        ),
        test_positive=[
            # withCredentials string-binding + npm install
            (
                "pipeline {\n    agent any\n    stages {\n"
                "        stage('publish') {\n"
                "            steps {\n"
                "                withCredentials([string(credentialsId: 'npm', variable: 'NPM_TOKEN')]) {\n"
                "                    sh 'npm install'\n"
                "                    sh 'npm publish'\n"
                "                }\n"
                "            }\n"
                "        }\n"
                "    }\n"
                "}"
            ),
            # environment {} credentials() + yarn install
            (
                "pipeline {\n    agent any\n"
                "    environment {\n"
                "        NPM_TOKEN = credentials('npm-publish-token')\n"
                "    }\n"
                "    stages {\n"
                "        stage('release') {\n"
                "            steps {\n"
                "                sh 'yarn install --frozen-lockfile'\n"
                "                sh 'yarn publish'\n"
                "            }\n"
                "        }\n"
                "    }\n"
                "}"
            ),
            # Scripted pipeline + pnpm install + NODE_AUTH_TOKEN
            (
                "node {\n"
                "    stage('publish') {\n"
                "        withCredentials([string(credentialsId: 'n', variable: 'NODE_AUTH_TOKEN')]) {\n"
                "            sh 'pnpm install --frozen-lockfile'\n"
                "            sh 'pnpm publish'\n"
                "        }\n"
                "    }\n"
                "}"
            ),
            # Explicit env assignment form
            (
                "pipeline {\n    agent any\n    stages {\n"
                "        stage('x') {\n"
                "            steps {\n"
                "                script { env.NPM_CONFIG_AUTHTOKEN = credentials('n') }\n"
                "                sh 'npm ci'\n"
                "            }\n"
                "        }\n"
                "    }\n"
                "}"
            ),
        ],
        test_negative=[
            # --ignore-scripts — safe even with NPM_TOKEN in scope
            (
                "pipeline {\n    agent any\n    stages {\n"
                "        stage('p') {\n"
                "            steps {\n"
                "                withCredentials([string(credentialsId: 'n', variable: 'NPM_TOKEN')]) {\n"
                "                    sh 'npm install --ignore-scripts'\n"
                "                    sh 'npm publish --ignore-scripts'\n"
                "                }\n"
                "            }\n"
                "        }\n"
                "    }\n"
                "}"
            ),
            # npm install without any publish-token reference — non-publishing pipeline
            (
                "pipeline {\n    agent any\n    stages {\n"
                "        stage('test') { steps { sh 'npm install' } }\n"
                "    }\n"
                "}"
            ),
            # NPM_TOKEN referenced but no install in the pipeline
            (
                "pipeline {\n    agent any\n"
                "    environment { NPM_TOKEN = credentials('n') }\n"
                "    stages {\n"
                "        stage('publish') { steps { sh 'npm publish' } }\n"
                "    }\n"
                "}"
            ),
            # Commented-out install
            (
                "pipeline {\n    agent any\n    stages {\n"
                "        stage('p') {\n"
                "            steps {\n"
                "                withCredentials([string(credentialsId: 'n', variable: 'NPM_TOKEN')]) {\n"
                "                    // sh 'npm install'\n"
                "                    sh 'echo hi'\n"
                "                }\n"
                "            }\n"
                "        }\n"
                "    }\n"
                "}"
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "On a self-hosted Jenkins agent, a compromised npm "
            "dependency's ``postinstall`` script runs with the agent's "
            "full environment: the ``NPM_TOKEN`` bound for this "
            "publish, the SSH key the agent uses for SCM, any "
            "workspace artefacts from previous builds, and any "
            "credential cached in the agent's keyring.  Unlike GH/GL "
            "hosted runners, the filesystem persists across builds — "
            "a script that writes a backdoor to "
            "``~/.bashrc`` or ``/var/jenkins_home/secrets/`` survives "
            "the job and waits for the next privileged pipeline to "
            "run.  The Shai-Hulud worm's self-propagation behaviour "
            "makes every compromised agent a candidate to attack the "
            "rest of the maintainer's npm namespace."
        ),
        incidents=["Shai-Hulud (Sep 2025)", "Shai-Hulud 2.0 (Nov 2025)"],
        confidence="low",
    ),
    # =========================================================================
    # LOTP-JK-003: npm / yarn / pnpm install without --ignore-scripts in a
    # Jenkinsfile that references PR-context env vars.  Jenkins port of
    # LOTP-GH-003 / LOTP-GL-003.  Lifecycle scripts from the PR's
    # ``package.json`` run during install under the Jenkins agent's
    # identity + any active ``withCredentials`` scope.
    # =========================================================================
    Rule(
        id="LOTP-JK-003",
        finding_family="pipeline_tool_execution",
        title=("npm / yarn / pnpm install without --ignore-scripts in a PR-reachable Jenkinsfile"),
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkinsfile runs ``npm install`` / ``npm ci`` / "
            "``yarn install`` / ``pnpm install`` in a file that "
            "references PR-context env vars (``env.CHANGE_*``, "
            "``ghprb*``, or ``GERRIT_*``) without the "
            "``--ignore-scripts`` flag.  npm / yarn / pnpm execute "
            "``preinstall`` / ``install`` / ``postinstall`` "
            "lifecycle scripts from every ``package.json`` by "
            "default — including the one checked out from the PR "
            "branch in a Multibranch Pipeline.  Adding "
            "``--ignore-scripts`` disables this path and closes the "
            "most common LOTP vector for JavaScript builds on "
            "Jenkins."
        ),
        pattern=_JenkinsInstallerLeafPattern(),
        remediation=(
            "Add ``--ignore-scripts`` to every npm / yarn / pnpm\n"
            "install command in a Jenkinsfile that can run on PR\n"
            "context.  Declarative:\n\n"
            "    pipeline {\n"
            "        agent any\n"
            "        stages {\n"
            "            stage('install') {\n"
            "                steps { sh 'npm ci --ignore-scripts' }\n"
            "            }\n"
            "        }\n"
            "    }\n\n"
            "For pnpm, also set ``ignore-scripts=true`` in the\n"
            "checked-out ``.npmrc`` so the default is sticky across\n"
            "future contributors and tool versions."
        ),
        reference=("https://docs.npmjs.com/cli/v10/using-npm/scripts#ignoring-scripts"),
        test_positive=[
            # Multibranch + npm install
            (
                "pipeline {\n    agent any\n"
                "    environment {\n"
                '        PR_BRANCH = "${env.CHANGE_BRANCH}"\n'
                "    }\n    stages { stage('install') { steps {\n"
                "        sh 'npm install'\n"
                "    } } }\n}"
            ),
            # Legacy GHPRB + npm ci
            (
                "pipeline {\n    agent any\n"
                "    environment {\n"
                '        PR = "${env.ghprbPullId}"\n'
                "    }\n    stages { stage('build') { steps {\n"
                "        sh 'npm ci'\n"
                "    } } }\n}"
            ),
            # Gerrit + pnpm install
            (
                "pipeline {\n    agent any\n"
                "    environment {\n"
                '        REF = "${env.GERRIT_REFSPEC}"\n'
                "    }\n    stages { stage('install') { steps {\n"
                "        sh 'pnpm install'\n"
                "    } } }\n}"
            ),
        ],
        test_negative=[
            # --ignore-scripts present → safe
            (
                "pipeline {\n    agent any\n"
                "    environment {\n"
                '        PR_BRANCH = "${env.CHANGE_BRANCH}"\n'
                "    }\n    stages { stage('install') { steps {\n"
                "        sh 'npm ci --ignore-scripts'\n"
                "    } } }\n}"
            ),
            # No PR-context env var — not a Multibranch / PR-reachable build
            (
                "pipeline {\n    agent any\n"
                "    stages { stage('install') { steps {\n"
                "        sh 'npm install'\n"
                "    } } }\n}"
            ),
            # Comment
            "// sh 'npm install'",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "npm's default lifecycle-script execution is the single "
            "most exploited LOTP vector.  An attacker who opens a PR "
            "editing ``package.json``'s ``postinstall`` field gets "
            "their command executed during ``npm install`` — before "
            "any test, lint, or security gate runs — so the payload "
            "fires regardless of what the rest of the Jenkinsfile "
            "does.  On a long-lived Jenkins agent, the payload also "
            "has the opportunity to persist into subsequent builds "
            "that land on the same host."
        ),
        incidents=["Ultralytics (Dec 2024, GH analog)"],
    ),
]
