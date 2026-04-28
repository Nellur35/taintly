"""GitHub Actions SEC-10 rules — Insufficient Logging and Visibility.

Covers pipeline configurations that reduce the auditability of builds:
missing job timeouts (allowing indefinite runtime), and workflows that
produce build outputs without retaining them for post-incident review.

A job that runs without a timeout can silently exfiltrate data for hours
if a step is compromised. A build that never uploads artefacts leaves no
evidence trail for forensics after a supply chain incident.
"""

from taintly.models import ContextPattern, Platform, Rule, Severity

RULES: list[Rule] = [
    # =========================================================================
    # SEC10-GH-001: Job missing timeout-minutes
    # =========================================================================
    Rule(
        id="SEC10-GH-001",
        title="GitHub Actions job has no timeout — unlimited runtime allowed",
        severity=Severity.LOW,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-10",
        description=(
            "A GitHub Actions job does not set 'timeout-minutes'. Without a timeout, "
            "a compromised or hung step can run up to the GitHub-imposed caps: 6 hours "
            "per job on GitHub-hosted runners, 5 days per job on self-hosted runners "
            "(since April 2024; previously 35 days), and 35 days for any single "
            "workflow run end-to-end. An attacker who achieves code execution in a "
            "step could exfiltrate secrets, interact with downstream systems, or mine "
            "cryptocurrency for the full duration without triggering any time-based "
            "alert. Setting an explicit timeout bounds the impact and makes "
            "anomalous run durations immediately visible in the Actions UI."
        ),
        pattern=ContextPattern(
            # Anchor: any job-level 'runs-on:' (marks a real job)
            anchor=r"^\s{2,4}runs-on:",
            # Requires: steps: is always present in a real job — ensures this
            # is a real workflow file, not a fragment
            requires=r"steps\s*:",
            # Fires only when the file has NO timeout-minutes anywhere
            requires_absent=r"timeout-minutes\s*:",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Set an explicit 'timeout-minutes' on each job (or at workflow level):\n\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    timeout-minutes: 30   # Fail the job if it exceeds 30 minutes\n"
            "    steps:\n"
            "      - ...\n\n"
            "Choose a timeout that is at least 2x your typical build duration. "
            "GitHub's default is 360 minutes (6 hours) — far too long for most jobs."
        ),
        reference="https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes",
        test_positive=[
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4",
        ],
        test_negative=[
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 30\n    steps:\n      - uses: actions/checkout@v4",
        ],
        stride=["D", "R"],
        threat_narrative=(
            "Without a timeout, a compromised step can run up to GitHub's caps — "
            "6 hours per job on GitHub-hosted runners, 5 days per job on self-hosted — "
            "exfiltrating secrets, interacting with downstream systems, or mining "
            "cryptocurrency before any time-based alert fires. An explicit timeout "
            "bounds the impact and makes anomalous build durations immediately "
            "visible in the Actions UI."
        ),
    ),
    # =========================================================================
    # SEC10-GH-002: Workflow uploads no artifacts — no evidence trail
    # =========================================================================
    Rule(
        id="SEC10-GH-002",
        title="Workflow produces build output but retains no artifacts for audit",
        severity=Severity.LOW,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-10",
        description=(
            "A workflow that builds, packages, or deploys software does not upload "
            "any build artifacts. Without retained artifacts, there is no evidence "
            "trail to support post-incident forensics after a supply chain compromise. "
            "Investigators cannot verify what binaries were produced at a given commit, "
            "compare them to what was deployed, or detect tampering that occurred "
            "inside the build. "
            "At minimum, upload build manifests, SBOMs, or signed digests as artifacts "
            "to establish a verifiable record tied to the workflow run."
        ),
        pattern=ContextPattern(
            # Anchor: build/package/deploy steps suggest output is produced
            anchor=(
                r"run:.*(?:npm\s+(?:run\s+build|build|pack)|"
                r"yarn\s+build|pnpm\s+build|"
                r"go\s+build|cargo\s+build|"
                r"mvn\s+(?:package|install)|gradle\s+build|"
                r"docker\s+build|docker\s+push|"
                r"make\s+(?:build|dist|release))"
            ),
            # Requires: any run: step exists (ensures this is a real workflow).
            # Anchor via a literal newline so the leading \s+ cannot walk the
            # whole file; the bare `\s+-\s+run:` form is quadratic on
            # whitespace-heavy adversarial YAML.
            requires=r"\n\s+-\s+run:",
            # Fires when build steps exist but upload-artifact does NOT
            requires_absent=r"uses:\s+actions/upload-artifact",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Upload build outputs and manifests as workflow artifacts:\n\n"
            "- name: Upload build artifacts\n"
            "  uses: actions/upload-artifact@v4\n"
            "  with:\n"
            "    name: build-${{ github.sha }}\n"
            "    path: dist/\n"
            "    retention-days: 90\n\n"
            "For stronger integrity, also generate and upload an SBOM:\n"
            "- uses: anchore/sbom-action@v0\n"
            "  with:\n"
            "    artifact-name: sbom-${{ github.sha }}.spdx.json"
        ),
        reference="https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/storing-and-sharing-data-from-a-workflow",
        test_positive=[
            "steps:\n  - run: npm run build\n  - run: echo done",
            "steps:\n  - run: go build ./...\n  - run: echo done",
        ],
        test_negative=[
            "steps:\n  - run: npm run build\n  - uses: actions/upload-artifact@v4\n    with:\n      path: dist/",
            "steps:\n  - run: echo hello",
        ],
        stride=["R"],
        threat_narrative=(
            "Without retained build artifacts there is no evidence trail to support post-incident "
            "forensics — investigators cannot verify what binaries were produced at a given commit "
            "or compare them to what was deployed. "
            "Artifact deletion or tampering that occurred inside the build cannot be detected "
            "through logs alone."
        ),
    ),
    # =========================================================================
    # SEC10-GH-004: Workflow uploads a debug log / step summary / runner
    # home directory as an artifact — post-failure secret-exfil primitive.
    #
    # Source: Praetorian — CodeQLEAKED (CVE-2025-24362).  CodeQL Action
    # uploaded ``$RUNNER_DEBUG`` contents as an artifact after a failed
    # run; ``GITHUB_TOKEN`` was captured in the debug log and the
    # artifact was downloadable by anyone with read access (which on
    # public repos means everyone).  The root cause is broader than
    # CodeQL: any workflow that uploads debug output, step-summary
    # files, runner-home contents, or wildcarded path globs after a
    # failure risks capturing in-memory secret material.
    # =========================================================================
    Rule(
        id="SEC10-GH-004",
        title=(
            "actions/upload-artifact uploads debug log / step summary / "
            "runner home — post-failure secret-exfil primitive"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-10",
        description=(
            "An ``actions/upload-artifact`` step's ``path:`` resolves "
            "to content that likely contains secret material: a debug "
            "log (``$RUNNER_DEBUG``, ``**/*.log``, ``/tmp/*.log``), the "
            "step summary (``$GITHUB_STEP_SUMMARY``), the runner's "
            "home directory (``~/``, ``$HOME``, ``/home/runner``), or "
            "the runner's temp directory (``$RUNNER_TEMP``, "
            "``/tmp/**``).  After a workflow failure — or even on "
            "success — the artifact is downloadable by anyone with "
            "read access to the repository (which on public repos is "
            "the whole internet).  Praetorian's CodeQLEAKED "
            "(CVE-2025-24362) landed exactly this way: CodeQL uploaded "
            "its debug log on failure, ``GITHUB_TOKEN`` was echoed into "
            "the log, and anyone could download it and replay the "
            "token.  The primitive is agnostic of CodeQL — any "
            "workflow can land the same way."
        ),
        # BlockPattern's indent-walk requires a deeper indent after the
        # anchor, but ``with:`` sits at the SAME indent as ``uses:`` in
        # a GH Actions step (they're sibling keys of the step dict), so
        # the block exits before seeing ``path:``.  Use ContextPattern
        # with scope="job" instead: fire the finding on the risky
        # ``path:`` line when an ``actions/upload-artifact`` call also
        # appears in the same job.  False-positive risk is low because
        # the risky path shapes below only legitimately appear as
        # artifact sources — nothing else in a workflow legitimately
        # refers to ``$RUNNER_DEBUG`` / ``$GITHUB_STEP_SUMMARY`` / etc.
        # in a ``path:`` key.
        pattern=ContextPattern(
            anchor=(
                r"^\s*(?:-\s*)?path\s*:\s*['\"]?"
                r"(?:"
                # Debug / log content
                r".*\$\{?RUNNER_DEBUG\}?"
                r"|.*\$\{?GITHUB_STEP_SUMMARY\}?"
                r"|.*\$\{?RUNNER_TEMP\}?"
                # Wildcard log globs
                r"|.*\*\*/\*\.log\b"
                r"|.*\*\.log(?:\b|$)"
                r"|/tmp/\*"
                r"|/var/log/"
                # Runner home / temp-dir dumps
                r"|\$\{?HOME\}?(?:/|\s|['\"]|$)"
                r"|~/?(?:\s|['\"]|$)"
                r"|/home/runner(?:/|\s|['\"]|$)"
                # Wildcard-everything — catches ``**/*`` and ``**``.
                r"|\*\*/\*(?:\s|['\"]|$)"
                r"|\*\*(?:\s|['\"]|$)"
                # Classic credential file paths.  Require end-of-value
                # (quote, space, newline) to avoid matching
                # ``${{ matrix.env.PROTOCOL }}`` or similar context
                # refs inside otherwise-legitimate artefact paths.
                r"|.*\.?npmrc(?:\s|['\"]|$)"
                r"|.*\.?pypirc(?:\s|['\"]|$)"
                r"|.*\.env(?:\s|['\"]|$)"
                r")"
            ),
            requires=r"uses:\s+actions/upload-artifact@",
            scope="job",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Narrow the artifact path to a specific, curated build\n"
            "output directory.  Never upload ``$RUNNER_DEBUG``,\n"
            "``$GITHUB_STEP_SUMMARY``, ``$HOME``, ``~``, ``/tmp/**``,\n"
            "or wildcarded globs as an artifact.\n"
            "\n"
            "BAD:\n"
            "  - name: Capture debug on failure\n"
            "    if: failure()\n"
            "    uses: actions/upload-artifact@<sha>\n"
            "    with:\n"
            "      path: $RUNNER_DEBUG\n"
            "\n"
            "GOOD:\n"
            "  - name: Upload build output\n"
            "    uses: actions/upload-artifact@<sha>\n"
            "    with:\n"
            "      name: dist-${{ github.sha }}\n"
            "      path: dist/\n"
            "      retention-days: 7\n"
            "\n"
            "If you genuinely need post-failure logs, redact secrets\n"
            "BEFORE upload (``sed -i 's/ghp_[A-Za-z0-9]*/REDACTED/g'``\n"
            "against known token shapes) and limit ``retention-days`` to\n"
            "the shortest practical window.  Better still: route debug\n"
            "output to an internal logging system that enforces access\n"
            "controls, not GitHub artifacts (public on public repos)."
        ),
        reference=(
            "https://www.praetorian.com/blog/codeqleaked-public-secrets-"
            "exposure-leads-to-supply-chain-attack-on-github-codeql/"
        ),
        test_positive=[
            (
                "steps:\n"
                "  - name: Capture debug\n"
                "    if: failure()\n"
                "    uses: actions/upload-artifact@v4\n"
                "    with:\n      name: debug\n      path: $RUNNER_DEBUG"
            ),
            (
                "steps:\n"
                "  - uses: actions/upload-artifact@v4\n"
                "    with:\n      path: $GITHUB_STEP_SUMMARY"
            ),
            (
                "steps:\n"
                "  - uses: actions/upload-artifact@v4\n"
                "    with:\n      path: /home/runner/work/logs"
            ),
            # Classic wildcard-log glob
            ("steps:\n  - uses: actions/upload-artifact@v4\n    with:\n      path: '**/*.log'"),
            # HOME dump
            ("steps:\n  - uses: actions/upload-artifact@v4\n    with:\n      path: $HOME"),
        ],
        test_negative=[
            # Normal build-output upload
            (
                "steps:\n"
                "  - uses: actions/upload-artifact@v4\n"
                "    with:\n      name: dist\n      path: dist/"
            ),
            # SBOM / manifest
            ("steps:\n  - uses: actions/upload-artifact@v4\n    with:\n      path: sbom.spdx.json"),
            # Coverage report
            ("steps:\n  - uses: actions/upload-artifact@v4\n    with:\n      path: coverage/"),
            # Comment line
            (
                "steps:\n"
                "  - uses: actions/upload-artifact@v4\n"
                "    with:\n"
                "      # path: $RUNNER_DEBUG   # disabled after CodeQLEAKED\n"
                "      path: build/"
            ),
        ],
        stride=["I"],
        threat_narrative=(
            "GitHub artifact uploads are accessible to anyone with "
            "repository read access — on a public repo, the entire "
            "internet.  When the uploaded path resolves to "
            "``$RUNNER_DEBUG``, ``$GITHUB_STEP_SUMMARY``, a wildcard "
            "log glob, or the runner's home / temp directory, "
            "``GITHUB_TOKEN`` / OIDC artefacts / cached credential "
            "files / .env fragments / SSH known-hosts entries can be "
            "captured verbatim.  CodeQLEAKED (CVE-2025-24362) used the "
            "``$RUNNER_DEBUG`` arm of this exact primitive to exfil a "
            "``GITHUB_TOKEN`` that anyone could then replay."
        ),
        confidence="medium",
        incidents=[
            "CodeQLEAKED (Praetorian, CVE-2025-24362)",
        ],
    ),
]
