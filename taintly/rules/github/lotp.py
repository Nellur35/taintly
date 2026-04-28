"""LOTP — Living Off The Pipeline.

Detects build tools and package managers that execute lifecycle scripts or
build hooks against attacker-controlled code checked out from a pull request
or other external source.  This is the category of attack that compromised
Ultralytics YOLO in December 2024: the workflow checked out a fork PR and
ran `pip install`, which executed `setup.py` from the fork — arbitrary
attacker code in a privileged job.

Rule IDs use the LOTP-<PLATFORM>-<NN> scheme so the category stays
recognisable once GitLab and Jenkins LOTP rules land in follow-up PRs.
"""

from taintly.models import ContextPattern, Platform, Rule, Severity

from .._build_tools import BUILD_TOOL_ANCHOR as _BUILD_TOOL_ANCHOR

# ---------------------------------------------------------------------------
# Shared patterns
# ---------------------------------------------------------------------------

# Evidence the job has checked out attacker-controlled code.  Matching any of
# these in the same job segment as a build tool means the tool is operating
# on untrusted source.
_PR_HEAD_CHECKOUT = (
    r"(?:github\.event\.pull_request\.head\.(?:sha|ref)"
    r"|github\.head_ref"
    r"|github\.event\.workflow_run\.head_branch)"
)

# Evidence untrusted artefacts have been pulled into the job workspace.
_UNTRUSTED_ARTIFACT = r"uses:\s*actions/download-artifact"


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

RULES: list[Rule] = [
    # =========================================================================
    # LOTP-GH-001: Build tool runs in same job that checks out PR code
    # =========================================================================
    Rule(
        id="LOTP-GH-001",
        title="Build tool executed in job that checks out pull-request code (LOTP)",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A build tool (npm, pip, make, cargo, mvn, gradle, docker, etc.) "
            "runs in the same job that checks out attacker-controlled "
            "pull-request code — via `github.event.pull_request.head.sha`, "
            "`github.head_ref`, or `github.event.workflow_run.head_branch`. "
            "Build tools execute lifecycle scripts or build hooks from the "
            "checked-out source — `postinstall` scripts in package.json, "
            "`cmdclass` handlers in setup.py, `build.rs` in Rust, "
            "//go:generate directives in Go, plugin execution via pom.xml, "
            "RUN directives in a Dockerfile — so the attacker's code runs "
            "with the workflow's permissions and secrets. This is the pattern "
            "that compromised Ultralytics YOLO in December 2024: a workflow "
            "checked out a fork PR and ran `pip install`, which executed "
            "setup.py from the fork."
        ),
        pattern=ContextPattern(
            anchor=_BUILD_TOOL_ANCHOR,
            requires=_PR_HEAD_CHECKOUT,
            scope="job",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Do not run build tools in a job that has checked out untrusted "
            "PR code alongside your secrets. Apply one of the following:\n"
            "\n"
            "1. Split the workflow: use `pull_request` (no secrets, no write "
            "   token) to build and test fork code; use a separate workflow "
            "   gated on `workflow_run` or a protected branch push to run "
            "   the privileged steps — and have that privileged workflow "
            "   check out the BASE repo SHA, not the fork head.\n"
            "\n"
            "2. If the job must run in a privileged context, build the "
            "   untrusted code in a sandboxed container with no secrets and "
            "   no network access to internal resources.\n"
            "\n"
            "3. For `npm install` / `npm ci` specifically, add "
            "   `--ignore-scripts` to skip lifecycle hooks. This stops the "
            "   most common JS lifecycle vector but does NOT protect against "
            "   native-addon compilation or other build-time execution.\n"
            "\n"
            "See also the GitHub Security Lab write-up on preventing "
            "`pull_request_target` pwn requests."
        ),
        reference="https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        test_positive=[
            # pull_request_target + PR head checkout + pip install .
            "on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: pip install .",
            # PR head + npm install
            "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.ref }}\n"
            "      - run: npm install",
            # workflow_run head_branch + make
            "jobs:\n  deploy:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.event.workflow_run.head_branch }}\n"
            "      - run: make build",
        ],
        test_negative=[
            # Build tool in a job that does NOT check out PR code
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: npm install",
            # PR head checkout but no build tool
            "jobs:\n  comment:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: echo 'hello'",
            # Commented out
            "jobs:\n  build:\n    steps:\n      # - run: npm install\n      - run: echo ok",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker opens a pull request that modifies a manifest the "
            "build tool reads (package.json, setup.py, Makefile, pom.xml, "
            "Dockerfile, etc.). When the workflow checks out the PR head and "
            "runs the build tool, the manifest's lifecycle hooks execute "
            "with the workflow's full permissions and bound secrets — "
            "typically a write-scoped GITHUB_TOKEN, cloud OIDC tokens, and "
            "any repo/org secrets the job can see."
        ),
        incidents=["Ultralytics (Dec 2024)"],
    ),
    # =========================================================================
    # LOTP-GH-002 is intentionally NOT defined.
    #
    # The v2 requirements list a rule "build tool invoked in any
    # pull_request_target workflow" as LOTP-002.  The existing rule
    # SEC4-GH-011 already covers that scope at CRITICAL severity with a
    # well-tuned false-positive filter (anchor_job_exclude for jobs gated
    # to non-PRT events, exclusions for English prose like "make sure",
    # narrower pip-install pattern that skips `pip install PackageName`).
    # Shipping a second rule at the same scope would only duplicate
    # findings.  Expanding SEC4-GH-011's build-tool regex to match LOTP's
    # broader tool list is tracked as a follow-up.
    # =========================================================================
    # =========================================================================
    # LOTP-GH-003: npm install / npm ci without --ignore-scripts
    # =========================================================================
    Rule(
        id="LOTP-GH-003",
        title="npm install / npm ci without --ignore-scripts in externally-triggered workflow",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A workflow runs `npm install`, `npm ci`, `yarn install`, or "
            "`pnpm install` without the `--ignore-scripts` flag in a job "
            "that also processes untrusted pull-request input. npm executes "
            "`preinstall`, `install`, and `postinstall` lifecycle scripts "
            "from every dependency's package.json by default — including "
            "scripts declared by the top-level package.json checked out "
            "from the PR. Adding `--ignore-scripts` disables this "
            "behaviour and closes the most common LOTP vector for "
            "JavaScript builds."
        ),
        pattern=ContextPattern(
            anchor=r"\b(?:npm\s+(?:install|ci|i)|yarn(?:\s+install)?|pnpm\s+(?:install|i))\b",
            requires=_PR_HEAD_CHECKOUT,
            scope="job",
            exclude=[
                r"^\s*#",
                r"--ignore-scripts",  # already mitigated — don't fire
            ],
        ),
        remediation=(
            "Add `--ignore-scripts` to every npm / yarn / pnpm install "
            "command in workflows that process pull-request input:\n"
            "\n"
            "  - run: npm ci --ignore-scripts\n"
            "  - run: npm install --ignore-scripts\n"
            "\n"
            "If some scripts are genuinely needed (e.g. a native-addon "
            "build step you own), run them explicitly after the install "
            "against a known allowlist — do not opt back in to implicit "
            "lifecycle execution.\n"
            "\n"
            "For pnpm, additionally set the `ignore-scripts=true` config "
            "key in `.npmrc` to make the default sticky."
        ),
        reference="https://docs.npmjs.com/cli/v10/using-npm/scripts#ignoring-scripts",
        test_positive=[
            "jobs:\n  test:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: npm install",
            "jobs:\n  test:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.head_ref }}\n"
            "      - run: npm ci",
        ],
        test_negative=[
            # --ignore-scripts present → safe
            "jobs:\n  test:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: npm ci --ignore-scripts",
            # No PR-head checkout → base repo code only, not LOTP
            "jobs:\n  build:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: npm install",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "npm's default lifecycle-script execution is the single most "
            "exploited LOTP vector. An attacker can trigger the workflow "
            "by opening a PR that edits package.json's `postinstall` "
            "field; npm runs the attacker's command during `npm install` "
            "before any test or lint step ever executes, so the payload "
            "runs regardless of what the rest of the workflow does."
        ),
        incidents=["Ultralytics (Dec 2024)"],
    ),
    # =========================================================================
    # LOTP-GH-004: Build tool after actions/download-artifact
    # =========================================================================
    Rule(
        id="LOTP-GH-004",
        title="Build tool executed after actions/download-artifact (untrusted artefact LOTP)",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A build tool runs in the same job as `actions/download-artifact`. "
            "Artifacts downloaded from another workflow — especially one "
            "triggered by `pull_request` that could have been influenced by "
            "a fork — carry no provenance guarantee. If the downloaded "
            "artefact contains a manifest or source tree the build tool "
            "reads, the build becomes a LOTP sink for whatever code produced "
            "the artefact."
        ),
        pattern=ContextPattern(
            anchor=_BUILD_TOOL_ANCHOR,
            requires=_UNTRUSTED_ARTIFACT,
            scope="job",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Treat every downloaded artefact as untrusted input. Before "
            "running a build tool against it:\n"
            "\n"
            "- Verify artefact provenance — the producing workflow must not "
            "  have been triggered by fork PRs. Check "
            "  `github.event.workflow_run.event` inside the consumer.\n"
            "- Verify artefact integrity — compare a signed hash, or "
            "  require the artefact to be signed (e.g. with Sigstore "
            "  cosign) by the CI identity.\n"
            "- Extract the artefact into a scratch directory and validate "
            "  its shape before letting a build tool loose on it.\n"
            "\n"
            "If verification is not feasible, move the build step into the "
            "producing workflow where the input provenance is clear."
        ),
        reference="https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        test_positive=[
            "jobs:\n  release:\n    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "        with:\n          name: build-output\n"
            "      - run: npm publish",
            "jobs:\n  deploy:\n    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "      - run: docker build -t myapp .",
        ],
        test_negative=[
            # No build tool after download — just using the artefact content as data
            "jobs:\n  deploy:\n    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "      - run: aws s3 cp dist/ s3://bucket/ --recursive",
            # Build tool without download-artifact
            "jobs:\n  build:\n    steps:\n      - run: npm install",
        ],
        stride=["T"],
        threat_narrative=(
            "The `workflow_run` trigger is GitHub's official escape hatch "
            "from pull_request_target's dangers — but the common shape is "
            "'fork-PR workflow uploads artefact, privileged workflow "
            "downloads it and does the release.' Without artefact-provenance "
            "verification the fix becomes its own LOTP: attacker-controlled "
            "artefact content flows into a privileged build step and the "
            "lifecycle-script / build-hook problem is back."
        ),
    ),
    # =========================================================================
    # LOTP-GH-005: npm/yarn/pnpm install runs lifecycle scripts in a job
    # holding an exfil-worthy secret.  Shai-Hulud class (Sep 2025 + Nov 2025
    # variants — worm-like self-propagation via postinstall scripts).  The
    # specific attack: an npm package you depend on gets compromised at
    # publish time; its `postinstall` script reads process env + ~/.npmrc +
    # ~/.aws / ~/.config / .git/config and exfiltrates via HTTP to an
    # attacker-controlled collector.  Any workflow that (a) runs
    # `npm install` / `npm ci` / `yarn install` / `pnpm install` WITHOUT
    # `--ignore-scripts`, AND (b) holds a secret with exfil value
    # (NPM_TOKEN, id-token: write, contents: write, packages: write) in
    # the same job is on the attack surface.
    #
    # References: https://www.sysdig.com/blog/shai-hulud-the-novel-self-
    # replicating-worm-infecting-hundreds-of-npm-packages ;
    # https://unit42.paloaltonetworks.com/npm-supply-chain-attack/ ;
    # https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-
    # 2-0-guidance-for-detecting-investigating-and-defending-against-the-
    # supply-chain-attack/
    # =========================================================================
    Rule(
        id="LOTP-GH-005",
        title=(
            "npm/yarn/pnpm install runs lifecycle scripts in a job "
            "holding an exfil-worthy secret (Shai-Hulud class)"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A job runs ``npm install`` / ``npm ci`` / ``yarn install`` / "
            "``pnpm install`` WITHOUT ``--ignore-scripts``, and that same "
            "job holds an exfil-worthy secret — ``NPM_TOKEN`` in env, "
            "``id-token: write``, or a package-write permission "
            "(``contents: write`` / ``packages: write`` / "
            "``deployments: write``).  Every direct and transitive "
            "dependency's ``postinstall`` / ``preinstall`` hook runs in "
            "that shell, with the secret visible in the process env.  "
            "This is the attack surface Shai-Hulud (Sep 2025) and its "
            "Shai-Hulud 2.0 variant (Nov 2025, 25,000+ repos infected) "
            "weaponised: one compromised dependency publishes a new "
            "version whose postinstall script reads ``$NPM_TOKEN`` / "
            "``$GITHUB_TOKEN`` / `~/.aws/credentials` and uses the "
            "stolen token to republish every other package the maintainer "
            "owns with the same payload.  The CI workflow doesn't need "
            "to look exotic — a plain `npm publish` job is enough."
        ),
        pattern=ContextPattern(
            # Anchor: a `run:` line invoking the install, NOT ignoring
            # lifecycle scripts.  Per-line so the finding points at the
            # install command.  `(?!...)` negative lookahead excludes
            # lines that already pass `--ignore-scripts` on the same
            # line.  Doesn't catch cases where --ignore-scripts is on
            # a continuation line, but that's a small gap (the rule
            # fires at HIGH, so a reviewer reads the job anyway).
            anchor=(
                r"\b(?:"
                r"npm\s+(?:install|i|ci)"
                r"|yarn\s+(?:install|add)"
                r"|pnpm\s+(?:install|i|add)"
                r")\b(?:(?!--ignore-scripts).)*$"
            ),
            # Requires (per-job): exfil-worthy secret.  NPM_TOKEN is
            # explicit because it's the canonical Shai-Hulud target.
            # `id-token: write` enables OIDC federation → cloud creds.
            # `contents: write` / `packages: write` / `deployments:
            # write` let a compromised postinstall push code / publish
            # packages / trigger deployments using the GITHUB_TOKEN.
            requires=(
                r"(?:"
                r"\bNPM_TOKEN\b"
                r"|\bid-token:\s*write\b"
                r"|\b(?:contents|packages|deployments):\s*write\b"
                r"|\bsecrets\.NPM_TOKEN\b"
                r")"
            ),
            scope="job",
            exclude=[
                r"^\s*#",
                # Lines where --ignore-scripts is paired with the
                # install command are already safe on this axis.
                r"--ignore-scripts",
                # Lines that are clearly documentation in `name:` /
                # `description:` / `title:` keys.  Allow optional
                # `- ` list-item marker before the key (steps use
                # `      - name: Foo` inline).
                r"^\s*-?\s*(?:name|description|title):",
            ],
        ),
        remediation=(
            "Pass `--ignore-scripts` to every `npm install` / `npm ci` /\n"
            "`yarn install` / `pnpm install` in a job that holds an\n"
            "exfil-worthy secret.  This blocks the postinstall / preinstall\n"
            "lifecycle hooks that Shai-Hulud-class attacks abuse.  For\n"
            "workflows that genuinely need lifecycle scripts (native-addon\n"
            "builds, husky, electron-builder), split into two jobs: one\n"
            "without secrets that runs the install and caches node_modules,\n"
            "and a second that restores the cache and runs the privileged\n"
            "step.  Also lock the lockfile (`npm ci` over `npm install`,\n"
            "`yarn install --frozen-lockfile`, `pnpm install\n"
            "--frozen-lockfile`) so a dependency's new version can't be\n"
            "silently pulled.\n"
            "Run `taintly --guide LOTP-GH-005` for the full checklist.\n"
            "Or apply the opt-in fix: `taintly --fix-npm-ignore-scripts`."
        ),
        reference=(
            "https://www.sysdig.com/blog/shai-hulud-the-novel-self-replicating-worm-infecting-hundreds-of-npm-packages; "
            "https://unit42.paloaltonetworks.com/npm-supply-chain-attack/; "
            "https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/"
        ),
        test_positive=[
            # npm install + NPM_TOKEN — the classic Shai-Hulud surface
            (
                "jobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - run: npm install\n"
                "        env:\n          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}"
            ),
            # npm ci + contents: write
            (
                "jobs:\n  release:\n    runs-on: ubuntu-latest\n"
                "    permissions:\n      contents: write\n"
                "    steps:\n      - run: npm ci"
            ),
            # yarn install + id-token: write (OIDC publish via trusted-publishing)
            (
                "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
                "    permissions:\n      id-token: write\n"
                "    steps:\n      - run: yarn install"
            ),
            # pnpm install + packages: write
            (
                "jobs:\n  pub:\n    runs-on: ubuntu-latest\n"
                "    permissions:\n      packages: write\n"
                "    steps:\n      - run: pnpm install"
            ),
        ],
        test_negative=[
            # Install explicitly with --ignore-scripts — safe
            (
                "jobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - run: npm install --ignore-scripts\n"
                "        env:\n          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}"
            ),
            # npm install in a job without any exfil-worthy secret — safe
            (
                "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
                "    permissions:\n      contents: read\n"
                "    steps:\n      - run: npm install"
            ),
            # NPM_TOKEN in job but install is commented out
            (
                "jobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      # - run: npm install\n"
                "      - run: echo 'deploy skipped'\n"
                "        env:\n          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}"
            ),
            # Descriptive text that mentions npm install in a name field
            (
                "jobs:\n  publish:\n    runs-on: ubuntu-latest\n"
                "    permissions:\n      contents: write\n"
                "    steps:\n      - name: Skip npm install for cached deps\n"
                "        run: echo noop"
            ),
        ],
        stride=["I", "T", "S"],
        threat_narrative=(
            "A transitive npm / yarn / pnpm dependency gets compromised "
            "at publish time (stolen maintainer token, typosquat, legit "
            "maintainer account takeover).  The new version's "
            "``postinstall`` script reads process env and the runner's "
            "home directory (``~/.npmrc``, ``~/.aws/credentials``, "
            "``.git/config``) and exfiltrates via HTTP POST.  When the "
            "install runs in a job that holds ``NPM_TOKEN`` — or any "
            "write-scoped secret — the secret is visible in the "
            "environment the postinstall script executes in.  "
            "Shai-Hulud (September 2025) spread worm-style through "
            "~200 packages in 24 hours; Shai-Hulud 2.0 (November 2025) "
            "affected 25,000+ repos and 350+ maintainers."
        ),
        confidence="medium",
        incidents=[
            "Shai-Hulud (Sep 2025)",
            "Shai-Hulud 2.0 (Nov 2025, 25k+ repos)",
        ],
    ),
]
