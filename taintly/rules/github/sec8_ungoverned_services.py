"""GitHub Actions SEC-8 rules — Ungoverned Usage of 3rd Party Services.

Covers CI/CD execution environments (job containers, service containers)
that pull from mutable image references, and reusable workflow calls
from external repositories without commit-SHA pinning.

These are distinct from SEC-3 (action supply chain) — the concern here is
the runtime ENVIRONMENT in which the job executes, not the tooling steps.
A compromised container image has read access to all secrets, source code,
and build artefacts within the job.
"""

import re

from taintly.models import Platform, RegexPattern, Rule, Severity


class DependabotMissingCooldownPattern:
    _VERSION_2_RE = re.compile(r"^version:\s*[\"']?2[\"']?\s*(?:#.*)?$", re.MULTILINE)
    _PACKAGE_RE = re.compile(r"^(\s*)-\s+package-ecosystem:")
    _COOLDOWN_RE = re.compile(r"^\s+cooldown:")

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if not self._VERSION_2_RE.search(content):
            return []
        results: list[tuple[int, str]] = []
        for i, line in enumerate(lines):
            if line.lstrip().startswith("#"):
                continue
            m = self._PACKAGE_RE.match(line)
            if not m:
                continue
            item_indent = len(m.group(1))
            block: list[str] = []
            for following in lines[i + 1 :]:
                stripped = following.strip()
                indent = len(following) - len(following.lstrip(" \t"))
                if stripped and indent <= item_indent:
                    break
                block.append(following)
            if not any(self._COOLDOWN_RE.match(block_line) for block_line in block):
                results.append((i + 1, line.strip()))
        return results


class DependabotHardcodedRegistryCredPattern:
    """Fire on a ``password:`` / ``token:`` / ``key:`` field inside a
    ``.github/dependabot.yml`` ``registries:`` block whose value is a
    plaintext literal rather than a ``${{ secrets.X }}`` reference.  The
    ``registries:`` marker gates the rule to dependabot config so the
    common ``token:``/``password:`` keys in ordinary workflow ``with:``
    blocks are not swept in."""

    _MARKER_RE = re.compile(r"^registries:", re.MULTILINE)
    # value, after an optional opening quote, must NOT begin a ``${{ ``
    # expression and must be a real literal character.
    _CRED_RE = re.compile(r"^\s+(?:password|token|key|auth-key):\s+['\"]?(?!\$\{\{)[^\s'\"#]")

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if not self._MARKER_RE.search(content):
            return []
        results: list[tuple[int, str]] = []
        for i, line in enumerate(lines):
            if line.lstrip().startswith("#"):
                continue
            if self._CRED_RE.match(line):
                results.append((i + 1, line.strip()))
        return results


RULES: list[Rule] = [
    # =========================================================================
    # SEC8-GH-001: Container / service image pinned to :latest
    # =========================================================================
    Rule(
        id="SEC8-GH-001",
        title="Job or service container image uses mutable :latest tag",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-8",
        description=(
            "A job container or service container references a Docker image with the "
            "':latest' tag. ':latest' resolves to whatever the registry currently points "
            "at — it changes silently on every push to the image repository. "
            "If the upstream image is compromised or updated unexpectedly, the new image "
            "executes inside your job with full access to all runner secrets and artefacts. "
            "Pin to a specific digest to guarantee the exact image version."
        ),
        pattern=RegexPattern(
            match=(
                # Covers both forms:
                #   container:                       container: ubuntu:latest
                #     image: ubuntu:latest
                # Also catches services.X.image: postgres:latest
                r"^\s+(?:image|container):\s+['\"]?[a-zA-Z0-9][^@'\"\s]*:latest['\"]?"
                r"\s*(#.*)?$"
            ),
            exclude=[r"^\s*#", r"@sha256:"],
        ),
        remediation=(
            "Pin container images to a SHA256 digest:\n"
            "  container:\n"
            "    image: ubuntu@sha256:abc123...   # was ubuntu:latest\n\n"
            "Find the current digest with:\n"
            "  docker pull ubuntu:latest && docker inspect ubuntu:latest | grep RepoDigests"
        ),
        reference="https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier",
        test_positive=[
            "    container:\n      image: ubuntu:latest",
            "    container: node:latest",
            "        image: postgres:latest",
            '        image: "python:latest"',
        ],
        test_negative=[
            "    container:\n      image: ubuntu@sha256:abc1234",
            "      image: ubuntu:22.04",
            "      image: postgres:14-alpine",
            "      # image: ubuntu:latest",
        ],
        stride=["T"],
        threat_narrative=(
            "A registry operator or attacker who compromises the image repository can push a new "
            "malicious image under the :latest tag, replacing your job's execution environment "
            "without any visible change in your workflow file. "
            "The substituted image executes with full access to all runner secrets, mounted volumes, "
            "and source code."
        ),
    ),
    # =========================================================================
    # SEC8-GH-002: Container / service image with no version tag (implicit latest)
    # =========================================================================
    Rule(
        id="SEC8-GH-002",
        title="Job or service container image has no version tag (implicit :latest)",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-8",
        description=(
            "A job container or service container references a Docker image with no tag "
            "or digest. Docker resolves untagged references to ':latest' by default — "
            "effectively the same risk as ':latest' but less visible. "
            "The image version is uncontrolled and changes without any signal in the workflow."
        ),
        pattern=RegexPattern(
            match=(
                # image: name_with_no_colon_or_digest — bare image name
                # Must have at least one slash or be a well-known image name pattern
                # Excludes names containing : (tagged) or @ (digest) or / (path, caught separately)
                r"^\s+(?:image|container):\s+['\"]?"
                r"[a-zA-Z0-9][a-zA-Z0-9._/-]+"  # image name (no colon, no @)
                r"['\"]?\s*(#.*)?$"
            ),
            exclude=[
                r"^\s*#",
                r"@sha256:",  # digest-pinned — safe
                r":(?!latest)[a-zA-Z0-9]",  # has a non-latest tag — specific version, acceptable
                r"uses:",  # action references, not container images
            ],
        ),
        remediation=(
            "Always specify an explicit version tag and prefer digest pinning:\n"
            "  container:\n"
            "    image: ubuntu:22.04   # explicit tag\n"
            "    # or\n"
            "    image: ubuntu@sha256:abc123...   # digest pinned (best)"
        ),
        reference="https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier",
        test_positive=[
            "    container:\n      image: ubuntu",
            "      image: postgres",
            "    container: node",
        ],
        test_negative=[
            "      image: ubuntu:22.04",
            "      image: ubuntu:latest",
            "      image: ubuntu@sha256:abc123",
            "      # image: ubuntu",
        ],
        stride=["T"],
        threat_narrative=(
            "Untagged image references silently resolve to :latest, meaning the pulled image changes "
            "with every upstream push to the registry with no signal in your workflow file. "
            "An attacker who can push to the image repository can substitute any payload as the "
            "job's execution environment on the next run."
        ),
    ),
    # =========================================================================
    # SEC8-GH-003: External reusable workflow called without commit-SHA pinning
    # =========================================================================
    Rule(
        id="SEC8-GH-003",
        title="External reusable workflow called without commit-SHA pinning",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-8",
        description=(
            "A reusable workflow from an external repository is referenced by a mutable "
            "tag or branch instead of a full 40-character commit SHA. "
            "Reusable workflows run with the CALLER's secrets and permissions — "
            "a compromised or force-pushed tag gives an attacker access to every secret "
            "available to your workflow. The risk is higher than unpinned actions because "
            "the called workflow can itself call further nested workflows."
        ),
        pattern=RegexPattern(
            match=(
                # Matches: uses: org/repo/.github/workflows/file.yml@non-sha-ref
                # The .github/workflows/ path distinguishes reusable workflows from actions.
                r"uses:\s+[a-zA-Z0-9_-][a-zA-Z0-9_.-]*/[a-zA-Z0-9_.-]+"
                r"/\.github/workflows/[^@\s]+@(?![a-f0-9]{40}\b)\S+"
            ),
            exclude=[
                r"^\s*#",
                # When a reusable workflow is pinned to a *branch*
                # (main/master/develop/dev), SEC3-GH-002 already
                # fires CRITICAL on the same line; letting
                # SEC8-GH-003 also fire HIGH would be a 1:1 dup.
                # SEC8-GH-003 keeps the tag-pin case (e.g.
                # ``@v2.1.0``) which SEC3-GH-002 doesn't cover —
                # that's where the rules diverge.
                r"@(?:main|master|develop|dev)\s*(?:#.*)?$",
            ],
        ),
        remediation=(
            "Pin reusable workflow calls to a full commit SHA:\n"
            "  uses: org/shared-workflows/.github/workflows/deploy.yml"
            "@abc123def456abc123def456abc123def456abc1  # v2.1.0\n\n"
            "Find the current SHA with:\n"
            "  git ls-remote https://github.com/org/shared-workflows refs/tags/v2.1.0"
        ),
        reference="https://docs.github.com/en/actions/sharing-automations/reusing-workflows",
        test_positive=[
            # Branch pins are handled by SEC3-GH-002 (CRITICAL);
            # SEC8-GH-003 owns the tag-pin case (HIGH).
            "      uses: org/shared-workflows/.github/workflows/deploy.yml@v2",
            "      uses: my-org/pipelines/.github/workflows/release.yml@v1.2.3",
            "      uses: org/shared-workflows/.github/workflows/lint.yml@release-2026",
        ],
        test_negative=[
            "      uses: org/shared-workflows/.github/workflows/deploy.yml"
            "@abc123def456abc123def456abc123def456abc1",
            "      uses: ./.github/workflows/local-reusable.yml",
            "      # uses: org/shared-workflows/.github/workflows/deploy.yml@v2",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Reusable workflows referenced by mutable tags run with the caller's secrets and "
            "permissions; a force-pushed tag silently substitutes attacker code that executes "
            "with access to every secret available to your workflow. "
            "The risk exceeds unpinned actions because called workflows can themselves call "
            "further nested workflows, multiplying the scope."
        ),
    ),
    # =========================================================================
    # SEC8-GH-005: dependabot.yml update spec missing ``cooldown:``
    # =========================================================================
    Rule(
        id="SEC8-GH-005",
        title="Dependabot update spec missing ``cooldown:`` — no post-release window",
        severity=Severity.LOW,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-8",
        review_needed=True,
        confidence="low",
        description=(
            "A ``.github/dependabot.yml`` update spec does not declare "
            "a ``cooldown:`` block.  Without cooldown, Dependabot "
            "opens a PR within minutes of a new release — including "
            "releases that turn out to be compromised hours later "
            "(tj-actions, xz-utils, several Node ecosystem incidents).  "
            "Set a short cooldown (3-7 days) to bound the window where "
            "a freshly-published malicious version can reach your "
            "main branch through automated bump PRs."
        ),
        pattern=DependabotMissingCooldownPattern(),
        remediation=(
            "Add a ``cooldown:`` block to each update spec.  3-7 days "
            "covers the common-case where a malicious release is "
            "spotted within a week:\n"
            "\n"
            "  version: 2\n"
            "  updates:\n"
            "    - package-ecosystem: npm\n"
            "      directory: /\n"
            "      schedule:\n"
            "        interval: daily\n"
            "      cooldown:\n"
            "        default-days: 5\n"
            "        semver-major-days: 7\n"
        ),
        reference="https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference#cooldown",
        test_positive=[
            (
                "version: 2\nupdates:\n  - package-ecosystem: npm\n"
                "    directory: /\n    schedule:\n      interval: daily\n"
            ),
            (
                "version: 2\nupdates:\n  - package-ecosystem: pip\n"
                "    directory: /backend\n    schedule:\n      interval: weekly\n"
            ),
        ],
        test_negative=[
            (
                "version: 2\nupdates:\n  - package-ecosystem: npm\n"
                "    directory: /\n    schedule:\n      interval: daily\n"
                "    cooldown:\n      default-days: 5\n"
            ),
            (
                "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: pytest\n"
            ),
        ],
        stride=["T"],
        threat_narrative=(
            "Several documented supply-chain compromises (tj-actions, "
            "xz-utils, lottie-player, ua-parser-js, event-stream) "
            "published malicious versions that were detected within "
            "hours-to-days of release.  Repositories without "
            "Dependabot cooldown auto-opened bump PRs on the "
            "compromised version inside that detection window — and "
            "any repo with auto-merge enabled merged before the alarm "
            "was raised.  A short cooldown converts an "
            "intra-minute exposure window into an intra-week one, "
            "during which community detection routinely flags the "
            "bad release."
        ),
        incidents=[
            "tj-actions/changed-files (Mar 2025)",
            "xz-utils (Mar 2024)",
            "lottie-player (Oct 2024)",
            "event-stream (Nov 2018)",
        ],
    ),
    # =========================================================================
    # SEC8-GH-009: hardcoded credential in a Dependabot registries: block
    # =========================================================================
    Rule(
        id="SEC8-GH-009",
        title="Hardcoded credential in a Dependabot ``registries:`` block",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-8",
        description=(
            "A ``registries:`` entry in ``.github/dependabot.yml`` "
            "declares a ``password``, ``token``, ``key`` or ``auth-key`` "
            "as a plaintext literal instead of a ``${{ secrets.X }}`` "
            "reference.  Authentication material in this file is "
            "committed to the repository in clear text, exposing the "
            "private-registry credential to anyone with read access and "
            "to the full git history."
        ),
        pattern=DependabotHardcodedRegistryCredPattern(),
        remediation=(
            "Store the credential as an encrypted Dependabot secret and "
            "reference it:\n"
            "\n"
            "    registries:\n"
            "      my-registry:\n"
            "        type: npm-registry\n"
            "        url: https://npm.example.com\n"
            "        token: ${{secrets.NPM_REGISTRY_TOKEN}}\n"
            "\n"
            "Add the secret under Settings > Secrets and variables > "
            "Dependabot."
        ),
        reference=(
            "https://docs.github.com/en/code-security/dependabot/working-with-dependabot/"
            "configuring-access-to-private-registries-for-dependabot"
        ),
        test_positive=[
            "registries:\n  my-npm:\n    type: npm-registry\n"
            '    url: https://npm.example.com\n    token: "ghp_abc123HARDCODED"\n',
            "registries:\n  maven:\n    type: maven-repository\n"
            "    url: https://maven.example.com\n    password: hunter2\n",
        ],
        test_negative=[
            "registries:\n  my-npm:\n    type: npm-registry\n"
            "    url: https://npm.example.com\n    token: ${{secrets.NPM_REGISTRY_TOKEN}}\n",
            "registries:\n  my-npm:\n    type: npm-registry\n"
            '    url: https://npm.example.com\n    password: "${{ secrets.PW }}"\n',
            # token: in an ordinary workflow with: block — not a dependabot file.
            "      - uses: actions/checkout@v4\n        with:\n          token: abc123\n",
        ],
        stride=["I"],
        threat_narrative=(
            "A registry token committed in plaintext to dependabot.yml is "
            "readable by every collaborator and lives forever in git "
            "history; a single repo-read compromise hands the attacker "
            "standing access to the private package registry."
        ),
    ),
]
