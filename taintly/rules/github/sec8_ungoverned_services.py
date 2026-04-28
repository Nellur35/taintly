"""GitHub Actions SEC-8 rules — Ungoverned Usage of 3rd Party Services.

Covers CI/CD execution environments (job containers, service containers)
that pull from mutable image references, and reusable workflow calls
from external repositories without commit-SHA pinning.

These are distinct from SEC-3 (action supply chain) — the concern here is
the runtime ENVIRONMENT in which the job executes, not the tooling steps.
A compromised container image has read access to all secrets, source code,
and build artefacts within the job.
"""

from taintly.models import Platform, RegexPattern, Rule, Severity

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
            exclude=[r"^\s*#"],
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
            "      uses: org/shared-workflows/.github/workflows/deploy.yml@v2",
            "      uses: company/ci-templates/.github/workflows/test.yml@main",
            "      uses: my-org/pipelines/.github/workflows/release.yml@v1.2.3",
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
]
