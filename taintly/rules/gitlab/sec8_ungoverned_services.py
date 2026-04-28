"""GitLab CI SEC-8 rules — Ungoverned Usage of 3rd Party Services.

Covers the Docker image used as the CI execution environment (global and
job-level `image:`) and external CI configuration included via `project:`.

In GitLab CI, the `image:` key defines the Docker container every job runs
inside — it is the execution environment, not just a tool. A compromised
or unexpectedly-updated image has access to all job secrets, variables,
artefacts, and the GitLab token. This makes image pinning more critical
in GitLab than in GitHub Actions (where job containers are optional).
"""

from taintly.models import Platform, RegexPattern, Rule, SequencePattern, Severity

RULES: list[Rule] = [
    # =========================================================================
    # SEC8-GL-001: Global or job image with :latest or no tag
    # =========================================================================
    Rule(
        id="SEC8-GL-001",
        title="GitLab CI image uses mutable :latest tag or has no version tag",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-8",
        description=(
            "A GitLab CI global or job-level `image:` references a Docker image with the "
            "':latest' tag or no tag at all. In GitLab CI, the image is the execution "
            "environment for the job — all job scripts, secrets ($CI_JOB_TOKEN, masked "
            "variables, vault secrets), source code, and artefacts run inside this container. "
            "A mutable image tag means the execution environment can change silently between "
            "pipeline runs. If the upstream image is compromised, every subsequent pipeline "
            "run executes attacker code with full access to your CI secrets. "
            "Pin images to SHA256 digests to guarantee a reproducible, auditable environment."
        ),
        pattern=RegexPattern(
            match=(
                # Covers:
                #   image: ubuntu:latest       (explicit :latest)
                #   image: ubuntu              (no tag — implicit :latest)
                #   image: python:latest
                #   image:
                #     name: ubuntu:latest      (expanded form)
                # Both global (indent 0) and job-level (indent 2).
                r"^\s*(?:image|name):\s+['\"]?"
                r"(?:"
                r"[a-zA-Z0-9][a-zA-Z0-9._/@-]*:latest"  # explicit :latest
                r"|[a-zA-Z0-9][a-zA-Z0-9._/-]+"  # no colon — no tag
                r")"
                r"['\"]?\s*(#.*)?$"
            ),
            exclude=[
                r"^\s*#",
                r"@sha256:",  # digest-pinned — safe
                r":(?!latest)[a-zA-Z0-9]",  # has non-latest tag — acceptable
                r"^\s*(?:stage|script|before_script|after_script|extends|needs"
                r"|dependencies|artifacts|cache|rules|when|allow_failure"
                r"|environment|coverage|retry|timeout|tags|only|except"
                r"|parallel|trigger|inherit|interruptible|resource_group"
                r"|pages|variables|services|include|default|workflow"
                r"|before_script|after_script):",  # YAML keys that aren't image names
                # name: with a simple word (no / or :) is almost always an artifact/cache
                # name, not a container image. Container images via name: always have a
                # registry path (contains /) or an explicit :latest tag (caught above).
                r"^\s*name:\s+['\"]?[a-zA-Z][a-zA-Z0-9_./ -]*['\"]?\s*(#.*)?\s*$",
            ],
        ),
        remediation=(
            "Pin the image to a SHA256 digest for a reproducible execution environment:\n"
            "  image: ubuntu@sha256:abc123...   # was ubuntu:latest\n\n"
            "Or specify an explicit version tag as a minimum:\n"
            "  image: ubuntu:22.04\n\n"
            "Find the current digest:\n"
            "  docker pull ubuntu:latest && docker inspect ubuntu:latest | grep RepoDigests\n\n"
            "For CI templates, consider using a private registry mirror with image scanning "
            "and approval workflows before promoting new versions."
        ),
        reference="https://docs.gitlab.com/ee/ci/docker/using_docker_images.html",
        test_positive=[
            "image: ubuntu:latest",
            "image: python:latest",
            "  image: ubuntu",
            "  image: postgres",
            "    name: ubuntu:latest",
        ],
        test_negative=[
            "image: ubuntu:22.04",
            "image: python:3.11-slim",
            "image: ubuntu@sha256:abc1234def5678",
            "  # image: ubuntu:latest",
            "  stage: test",
        ],
        stride=["T"],
        threat_narrative=(
            "A :latest tag or bare image name resolves to whatever the registry currently "
            "holds, meaning any push to the image repository silently changes the execution "
            "environment for every subsequent pipeline run. A compromised upstream image "
            "executes with full access to all CI/CD variables, source code, and build "
            "artifacts in the job."
        ),
    ),
    # =========================================================================
    # SEC8-GL-002: External project include without pinned ref
    # =========================================================================
    Rule(
        id="SEC8-GL-002",
        title="External CI configuration included from project without pinned ref",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-8",
        description=(
            "A GitLab CI `include: project:` directive pulls CI configuration from an "
            "external project without specifying a commit SHA as the `ref:`. "
            "Without a pinned ref, GitLab resolves the include against the default branch "
            "at pipeline creation time — any push to that branch immediately affects all "
            "pipelines that include it. "
            "A branch name or tag ref is mutable: the branch can be force-pushed, the tag "
            "can be recreated to point at different content. "
            "Pin to a full 40-character commit SHA so the included configuration is "
            "immutable and auditable."
        ),
        pattern=SequencePattern(
            # Fires when `project:` appears in an include block but is NOT followed
            # by a `ref:` containing a full 40-char commit SHA within the next 4 lines.
            pattern_a=r"^\s+-?\s*project:\s+['\"]?[a-zA-Z0-9]",
            absent_within=r"ref:\s+['\"]?[a-f0-9]{40}['\"]?",
            lookahead_lines=4,
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Pin the included configuration to a commit SHA:\n\n"
            "include:\n"
            "  - project: my-group/shared-ci\n"
            "    ref: abc123def456abc123def456abc123def456abc1   # was: main\n"
            "    file: /templates/default.yml\n\n"
            "Find the current SHA:\n"
            "  git ls-remote https://gitlab.com/my-group/shared-ci refs/heads/main"
        ),
        reference="https://docs.gitlab.com/ee/ci/yaml/includes.html",
        test_positive=[
            "include:\n  - project: my-group/shared-ci\n    file: /templates/ci.yml",
            "include:\n  - project: org/ci-templates\n    ref: main\n    file: /ci.yml",
            "include:\n  - project: org/ci-templates\n    ref: v1.2.3\n    file: /ci.yml",
        ],
        test_negative=[
            "include:\n  - project: org/ci-templates\n"
            "    ref: abc123def456abc123def456abc123def456abc1\n    file: /ci.yml",
            "include:\n  - remote: https://example.com/ci.yml",
            "include:\n  - local: /templates/ci.yml",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An external CI configuration file included from another project without a "
            "pinned commit ref changes with every push to that project, meaning any "
            "contributor to the included configuration can silently modify what your "
            "pipeline executes. A compromised or malicious configuration file has full "
            "access to your project's runner tokens and protected CI/CD variables."
        ),
    ),
]
