"""GitLab CI security rules — Dependency Chain, Credential Hygiene, System Config."""

import re

from taintly.models import (
    AbsencePattern,
    Platform,
    RegexPattern,
    Rule,
    Severity,
)
from taintly.platform import gitlab_archived_check

# ---------------------------------------------------------------------------
# SEC3-GL-008 — archived include:project detection (opt-in)
# ---------------------------------------------------------------------------
#
# Mirrors SEC3-GH-010: an ``include:`` referencing an archived GitLab
# project is supply-chain risk (read-only, no maintainer response).
# Opt-in via ``--check-archived-gitlab-projects``.

_INCLUDE_PROJECT_RE = re.compile(
    r"\bproject:\s*['\"]?([A-Za-z0-9][\w.-]*(?:/[A-Za-z0-9][\w.-]*)+)['\"]?"
)


class ArchivedIncludeProjectPattern:
    """Pattern for SEC3-GL-008.  Gated by
    :func:`gitlab_archived_check.is_enabled`."""

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        if not gitlab_archived_check.is_enabled():
            return []
        seen: set[tuple[str, int]] = set()
        results: list[tuple[int, str]] = []
        for i, line in enumerate(lines):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            m = _INCLUDE_PROJECT_RE.search(line)
            if not m:
                continue
            project = m.group(1)
            key = (project.lower(), i + 1)
            if key in seen:
                continue
            seen.add(key)
            verdict = gitlab_archived_check.is_archived(project)
            if verdict is True:
                snippet = (
                    f"{project} is archived on GitLab — no new releases, "
                    f"no maintainer response to compromise."
                )
                results.append((i + 1, snippet))
        return results


_LINE_COMMENT_RE = re.compile(r"^\s*#")


_INCLUDE_HEADER_RE = re.compile(r"^include:\s*(?:#.*)?$")


_TOP_LEVEL_KEY_RE = re.compile(r"^[A-Za-z_][\w-]*\s*:")


_SHA_REF_RE = re.compile(r"ref:\s*['\"]?[a-f0-9]{40}['\"]?")


class _IncludeProjectMutableRefPattern:
    """SEC3-GL-002 walker.

    Fires when a ``project:`` key INSIDE an ``include:`` block is
    not followed by a SHA-pinned ``ref:`` within 5 lines.

    The ``include:`` ancestry requirement prevents accidental fires
    on ``trigger: project:`` cross-project triggers (which use
    ``branch:`` instead of ``ref:`` and live under a job, not under
    a top-level ``include:`` block).  The previous regex-only
    pattern matched any ``project:`` line regardless of context;
    widening to support unquoted values made the trigger-context
    FP recurrent.  Walker form scopes to include blocks only.

    Block tracking: ``include:`` is always a top-level key (column
    0).  The block ends at the next top-level key (any non-
    whitespace start) or end-of-file.
    """

    _PROJECT_RE = re.compile(r"project:\s*['\"]?[\w.-]+/[\w./-]+['\"]?")

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        i = 0
        n = len(lines)
        while i < n:
            line = lines[i]
            stripped = line.lstrip(" \t")
            if not stripped or stripped.startswith("#"):
                i += 1
                continue
            if not _INCLUDE_HEADER_RE.match(line):
                i += 1
                continue
            # Found an include: block header at column 0.  Walk
            # forward until the next top-level key or EOF.
            block_end = n
            for k in range(i + 1, n):
                kline = lines[k]
                kstripped = kline.lstrip(" \t")
                if not kstripped or kstripped.startswith("#"):
                    continue
                kindent = len(kline) - len(kstripped)
                if kindent == 0 and _TOP_LEVEL_KEY_RE.match(kline):
                    block_end = k
                    break
            # Walk the include block looking for project: keys.
            for j in range(i + 1, block_end):
                jline = lines[j]
                jstripped = jline.lstrip(" \t")
                if not jstripped or jstripped.startswith("#"):
                    continue
                if not self._PROJECT_RE.search(jline):
                    continue
                # Found a project: in include scope.  Look ahead
                # 5 lines for a SHA-pinned ref.
                lookahead_end = min(j + 6, block_end)
                pinned = False
                for k in range(j, lookahead_end):
                    if _LINE_COMMENT_RE.match(lines[k]):
                        continue
                    if _SHA_REF_RE.search(lines[k]):
                        pinned = True
                        break
                if not pinned:
                    results.append((j + 1, jline.strip()))
            i = block_end
        return results


class _PoisonableCacheKeyPattern:
    """SEC3-GL-009 walker — a cache key predictable across a trust boundary.

    Fires when a ``cache:`` block's ``key:`` is a scalar built only from
    predictable, branch/project-scoped variables (``$CI_COMMIT_REF_SLUG``,
    ``$CI_COMMIT_REF_NAME``, ``$CI_PROJECT_*`` …) WITHOUT a per-commit/job/
    pipeline uniqueness component (``$CI_COMMIT_SHA``, ``$CI_JOB_ID``,
    ``$CI_RUNNER_ID``, ``$CI_PIPELINE_ID``). Such a key is shared across every
    MR / fork pipeline on the same branch name, so a malicious MR can populate a
    cache that a later trusted pipeline restores — the cache-poisoning shape of
    gitlab-org/gitlab#330047.

    Does NOT fire on a key that includes a uniqueness component, on the
    content-hash ``key: { files: [...] }`` form (the documented safe pattern,
    which has no inline scalar), or on a purely static literal key (a different,
    intentional shared-cache concern — kept out to hold FP near zero).
    """

    _PREDICTABLE = re.compile(
        r"CI_COMMIT_REF_SLUG|CI_COMMIT_REF_NAME|CI_COMMIT_BRANCH|"
        r"CI_DEFAULT_BRANCH|CI_PROJECT_(?:NAME|PATH|PATH_SLUG|ID|NAMESPACE|TITLE)|"
        r"CI_MERGE_REQUEST_(?:SOURCE|TARGET)_BRANCH_NAME"
    )
    _UNIQUE = re.compile(
        r"CI_COMMIT_SHA|CI_COMMIT_SHORT_SHA|CI_JOB_ID|CI_RUNNER_ID|"
        r"CI_PIPELINE_ID|CI_PIPELINE_IID"
    )
    _CACHE_HEADER_RE = re.compile(r"^(\s*)-?\s*cache:\s*(?:#.*)?$")
    _KEY_RE = re.compile(r"^\s*-?\s*key:\s*(\S.*?)\s*(?:#.*)?$")

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        i, n = 0, len(lines)
        while i < n:
            m = self._CACHE_HEADER_RE.match(lines[i])
            if not m:
                i += 1
                continue
            indent = len(m.group(1))
            j = i + 1
            while j < n:
                line = lines[j]
                stripped = line.lstrip(" \t")
                if not stripped or stripped.startswith("#"):
                    j += 1
                    continue
                if (len(line) - len(stripped)) <= indent:
                    break  # cache block ended (dedented to a sibling/parent key)
                km = self._KEY_RE.match(line)
                if km:
                    val = km.group(1).strip().strip("'\"")
                    if (
                        "$" in val
                        and self._PREDICTABLE.search(val)
                        and not self._UNIQUE.search(val)
                    ):
                        results.append((j + 1, line.strip()))
                j += 1
            i = j
        return results


RULES: list[Rule] = [
    # =========================================================================
    # CICD-SEC-3: Dependency Chain Abuse (GitLab)
    # =========================================================================
    Rule(
        id="SEC3-GL-001",
        title="Remote include without integrity verification",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "Pipeline includes a remote YAML file. Remote includes can be tampered with "
            "at the source — equivalent to unpinned GitHub Actions."
        ),
        pattern=RegexPattern(
            match=r"include:\s*\n\s*-\s*remote:|^\s*-\s*remote:",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Download the file and store it in your repository instead. "
            "If remote include is required, pin to a specific ref/SHA."
        ),
        reference="https://docs.gitlab.com/ci/pipeline_security/",
        test_positive=[
            "include:\n  - remote: 'https://example.com/ci.yml'",
        ],
        test_negative=[
            "include:\n  - local: '/ci/build.yml'",
            "# include:\n#   - remote: 'https://example.com/ci.yml'",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "A remote CI configuration included without integrity verification can be "
            "modified by anyone who controls the remote server, injecting arbitrary jobs or "
            "overriding existing stages in your pipeline with no change visible in your "
            "repository. The injected configuration runs with your project's runner token "
            "and protected variable access."
        ),
    ),
    # =========================================================================
    # SEC3-GL-006 — third-party include inventory (review-needed)
    # =========================================================================
    #
    # Fires INFO once per external ``include: project:`` or ``include:
    # component:`` reference.  Built for the ``--baseline`` / ``--diff``
    # workflow: initial scan lists every external CI dependency for
    # one-time review; subsequent scans surface only NEW dependencies
    # in diff output.  Distinct from SEC3-GL-001 (remote URL — HIGH;
    # different threat shape) and SEC3-GL-002 (project include without
    # pinned ref — HIGH).  Inventory has zero implicit threat assessment
    # — surfaces the dependency surface so a human can decide.
    Rule(
        id="SEC3-GL-006",
        title="Third-party include used (inventory; review-needed)",
        severity=Severity.INFO,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        review_needed=True,
        finding_family="Mutable dependency references",
        description=(
            "The pipeline includes CI configuration from another GitLab "
            "project (``include: project:``) or a CI Component "
            "(``include: component:``).  External includes are "
            "supply-chain dependencies — every fetch executes whatever "
            "stages the included project defines, with this project's "
            "runner token and protected-variable scope.  Use "
            "``--baseline`` to snapshot the current set of external "
            "includes and ``--diff`` on subsequent scans to surface "
            "only new dependencies that need review."
        ),
        pattern=RegexPattern(
            # Fires on either:
            #   project: 'group/project'        (or " or no quotes)
            #   component: '$CI_SERVER_FQDN/group/project/component@version'
            # Local includes (`local:`) and remote-URL includes
            # (`remote:`) are handled by SEC3-GL-001 with stricter
            # severity, so excluded here.
            match=r"^\s*(?:-\s*)?(?:project|component):\s*['\"]?(\S+)",
            exclude=[
                r"^\s*#",
                r"^\s*(?:-\s*)?(?:local|remote|file|inputs):",
            ],
        ),
        remediation=(
            "Each finding is the *first* occurrence of an external CI "
            "include in this scan; review the source project's owner, "
            "recent commits, and how it pins its own dependencies, then "
            "snapshot the inventory with ``--baseline``.  After "
            "baseline, only NEW external includes surface in ``--diff`` "
            "output.  Consider also gating includes via "
            "``ref: <commit-sha>`` (see SEC3-GL-002) so a force-pushed "
            "tag cannot silently change the included content."
        ),
        reference="https://docs.gitlab.com/ee/ci/yaml/includes.html",
        test_positive=[
            "  - project: 'mygroup/ci-templates'",
            '  - project: "acme-corp/shared"',
            "  - component: '$CI_SERVER_FQDN/group/component-project/component@1.0'",
        ],
        test_negative=[
            # Local include — not a third-party dep.
            "  - local: '/ci/build.yml'",
            # Remote URL — handled by SEC3-GL-001.
            "  - remote: 'https://example.com/ci.yml'",
            # `file:` is a sibling key inside a project block, not the
            # include source itself — the project: key in the same
            # block fires the finding.
            "    file: '/templates/build.yml'",
            # `inputs:` is the params block for a CI Component, not a
            # source.
            "    inputs:",
            # Comment.
            "  # - project: 'mygroup/ci-templates'",
        ],
        stride=["T"],
        threat_narrative=(
            "External CI includes execute their declared stages with "
            "this project's runner token and protected-variable scope. "
            "An attacker who compromises the included project, or "
            "force-pushes a tag the include resolves to, gains "
            "execution in every consumer's pipeline.  This rule does "
            "not claim any specific include is malicious — it surfaces "
            "the external dependency set so a human reviewer can make "
            "the trust decision once, with ``--baseline`` / ``--diff`` "
            "ensuring new additions don't slip through."
        ),
        confidence="medium",
    ),
    Rule(
        id="SEC3-GL-002",
        title="Project include without pinned ref",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "Pipeline includes a file from another project without pinning to a specific "
            "commit SHA. The included file can change without notice, and mutable branch/tag "
            "refs can be force-pushed to point at malicious content."
        ),
        # Walker-based pattern requiring ``include:`` block ancestry.
        # The previous SequencePattern fired on any ``project:`` line
        # in the file; widening it to accept unquoted values introduced
        # FPs on ``trigger: project:`` cross-project triggers (which
        # use ``branch:`` instead of ``ref:``, not ``include:``-scoped).
        # The walker is the smallest fix that handles the unquoted
        # form correctly without bleeding into trigger context.
        # See docs/lab/sec3-gl-002-unquoted-project-note.md (2026-05-11).
        pattern=_IncludeProjectMutableRefPattern(),
        remediation=(
            "Pin the include to a full 40-character commit SHA. Quote the SHA so YAML "
            "parses it as a string regardless of leading digits:\n"
            "\n"
            "include:\n"
            "  - project: 'my-group/my-project'\n"
            '    ref: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"\n'
            "    file: '/templates/ci.yml'\n"
            "\n"
            "Find the current SHA:\n"
            "  git ls-remote https://gitlab.com/my-group/my-project refs/heads/main"
        ),
        reference="https://docs.gitlab.com/ci/yaml/includes/",
        test_positive=[
            "include:\n  - project: 'my-group/my-project'\n    file: '/templates/ci.yml'",
            "include:\n  - project: 'my-group/my-project'\n    ref: main\n    file: '/templates/ci.yml'",
            "include:\n  - project: 'my-group/my-project'\n    ref: v1.2.3\n    file: '/templates/ci.yml'",
            # 2026-05-11 widening: unquoted project paths (the shape
            # GitLab's own docs use most often) must also fire.
            "include:\n  - project: my-group/my-project\n    file: /templates/ci.yml",
            "include:\n  - project: my-group/my-project\n    ref: latest\n    file: /templates/ci.yml",
        ],
        test_negative=[
            "include:\n  - project: 'my-group/my-project'\n    ref: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n    file: '/templates/ci.yml'",
            "include:\n  # - project: 'my-group/my-project'",
            # 2026-05-11: unquoted SHA pin must also silence.
            "include:\n  - project: my-group/my-project\n    ref: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n    file: /templates/ci.yml",
            # 2026-05-11: trigger: project: (cross-project trigger) must
            # NOT fire — the walker requires include: ancestry.
            "build_job:\n  trigger:\n    project: my-group/my-project\n    branch: main",
        ],
        stride=["T"],
        threat_narrative=(
            "A project include without a pinned ref changes with every commit to the "
            "included project, meaning a contributor to that project can silently modify "
            "what your pipeline executes on the next run. Pin includes to specific commit "
            "SHAs to ensure the included configuration is immutable."
        ),
    ),
    # =========================================================================
    # SEC3-GL-007 — CI Component included at a mutable ref.
    # SEC3-GL-002's walker only inspects ``include: - project:`` entries;
    # the newer ``include: - component:`` form (a single
    # ``host/group/project/component@VERSION`` string) is not pin-checked
    # by it.  SEC3-GL-006 lists components as INFO inventory, but there is
    # no HIGH "this component floats on a mutable ref" finding — the
    # component analogue of SEC3-GL-002.  This rule fills that gap, firing
    # only on the well-known mutable refs (``@main``, ``@~latest``, …) so
    # FP stays near zero; pinned semver tags and commit SHAs do not fire.
    Rule(
        id="SEC3-GL-007",
        title="CI Component included at a mutable ref",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        finding_family="Mutable dependency references",
        description=(
            "Pipeline includes a CI Component pinned to a mutable ref "
            "(``@main``, ``@master``, ``@~latest``, …) instead of a released "
            "version tag or commit SHA. ``~latest`` floats to the newest "
            "published version and branch refs can be force-pushed, so the "
            "component's job definitions can change underneath the pipeline "
            "with no commit visible in this repository. This is the component "
            "analogue of SEC3-GL-002 (which only checks ``include: project:``)."
        ),
        pattern=RegexPattern(
            # component value is a single string `HOST/group/proj/comp@REF`.
            # Fire only on the known-mutable REFs; pinned semver (`@1.2.3`,
            # `@v1.2`) and 40-char SHAs fall through.  `~?latest` covers
            # both `@latest` and GitLab's special `@~latest`.
            match=(
                r"^\s*(?:-\s*)?component:\s*['\"]?"
                r"[^\s'\"]+@(?:main|master|develop|trunk|HEAD|~?latest)\b"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Pin the component to a released version tag or, for the strongest "
            "guarantee, a commit SHA:\n"
            "\n"
            "include:\n"
            "  - component: $CI_SERVER_FQDN/my-org/security/scan@1.4.2\n"
            "\n"
            "Released tags are immutable in the CI/CD Catalog; ``~latest`` and "
            "branch refs are not. Renovate/Dependabot can keep the pinned "
            "version current via reviewed merge requests."
        ),
        reference="https://docs.gitlab.com/ci/components/#use-a-component",
        test_positive=[
            "include:\n  - component: $CI_SERVER_FQDN/my-org/security/scan@main",
            "include:\n  - component: 'gitlab.com/components/sast/sast@~latest'",
            "  - component: gitlab.example.com/group/comp@master",
            "  - component: $CI_SERVER_FQDN/g/p/comp@latest",
        ],
        test_negative=[
            # Released semver tag — immutable in the catalog.
            "include:\n  - component: $CI_SERVER_FQDN/my-org/security/scan@1.2.3",
            "  - component: gitlab.com/components/sast/sast@v1.4",
            # Commit SHA pin.
            "  - component: gitlab.com/components/sast/sast@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            # Comment.
            "  # - component: gitlab.com/comp@main",
            # Project include (not a component) is SEC3-GL-002's territory.
            "include:\n  - project: 'g/p'\n    ref: main\n    file: '/ci.yml'",
        ],
        stride=["T"],
        threat_narrative=(
            "A component on a mutable ref re-resolves on every pipeline run. A "
            "maintainer of the component project (or anyone who can force-push "
            "the branch / publish a new ``~latest`` release) can change the "
            "jobs that execute in every consumer pipeline, with this project's "
            "runner token and protected-variable scope, and no diff in the "
            "consumer's repository to review."
        ),
    ),
    Rule(
        id="SEC3-GL-005",
        title="Docker image without digest pinning",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "Docker image referenced by tag instead of SHA256 digest. "
            "Image tags are mutable and can be overwritten on the registry."
        ),
        pattern=RegexPattern(
            match=r"^\s*image:\s*['\"]?[a-zA-Z0-9._/-]+:[a-zA-Z0-9._-]+['\"]?(\s*(#.*)?)?\s*$",
            exclude=[r"^\s*#", r"@sha256:"],
        ),
        remediation="Pin to digest: image: alpine@sha256:abcdef...",
        reference="https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier",
        test_positive=[
            "  image: alpine:3.18",
            "  image: node:20-slim",
            "  image: 'registry.example.com/app:latest'",
        ],
        test_negative=[
            "  image: alpine@sha256:abcdef1234567890",
            "  # image: alpine:3.18",
        ],
        stride=["T"],
        threat_narrative=(
            "Docker image tags are mutable: a registry push under the same tag silently "
            "replaces the execution environment for your jobs, giving the image publisher "
            "arbitrary code execution with access to all CI/CD variables and runner-mounted "
            "secrets. Pinning to a SHA256 digest makes the image reference immutable."
        ),
    ),
    # =========================================================================
    # SEC3-GL-004: pip --extra-index-url without --index-url — dependency
    # confusion.  GitLab port of SEC3-GH-008.  The resolver bug is a pip
    # property (highest-version-wins merge across indexes), so the attack
    # class is identical on any platform that shells out to pip.  Incident
    # reference: PyTorch dependency confusion, December 2022.
    # =========================================================================
    Rule(
        id="SEC3-GL-004",
        title="pip --extra-index-url used without --index-url (dependency confusion, GitLab)",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A GitLab CI ``script:`` line invokes pip install with "
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
                r"^\s*#",
                # Paired with --index-url is the safe form (private index
                # only, extra is an explicit secondary — and not public PyPI).
                r"--index-url\b(?!\s*=?\s*https?://pypi\.org)",
            ],
        ),
        remediation=(
            "Use --index-url to point pip at your private index\n"
            "exclusively, and mirror required public packages into it.\n"
            "If you must consult public PyPI, use a tool that supports\n"
            "explicit package-to-index pinning (uv, poetry's source\n"
            "priority='explicit', or pip-tools with hash-locking):\n\n"
            "# BAD — public PyPI can win resolution for private names\n"
            "pip install --extra-index-url https://pypi.internal.corp/ mypackage\n\n"
            "# GOOD — only the private index is consulted; mirror\n"
            "# public packages into it via Artifactory or Nexus\n"
            "pip install --index-url https://pypi.internal.corp/ mypackage"
        ),
        reference="https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
        test_positive=[
            "install:\n  script:\n    - pip install --extra-index-url https://pypi.internal.corp/ mypackage",
            "build:\n  script:\n    - pip install -r requirements.txt --extra-index-url https://internal/",
        ],
        test_negative=[
            "install:\n  script:\n    - pip install --index-url https://pypi.internal.corp/ mypackage",
            "# legacy: pip install --extra-index-url https://internal/",
            "install:\n  script:\n    - pip install requests",
        ],
        stride=["T", "S"],
        threat_narrative=(
            "Dependency confusion exploits pip's permissive resolver: "
            "when a private package name is also registerable on public "
            "PyPI, an attacker uploads a same-named package with a "
            "higher version number and pip silently prefers it.  The "
            "malicious package's install hooks execute as the build "
            "user with access to ``CI_JOB_TOKEN`` and any CI/CD "
            "variables visible to the job."
        ),
        incidents=["PyTorch dependency confusion (Dec 2022, GH analog)"],
    ),
    # =========================================================================
    # CICD-SEC-6: Insufficient Credential Hygiene (GitLab)
    # =========================================================================
    Rule(
        id="SEC6-GL-001",
        title="Potential hardcoded secret in pipeline config",
        severity=Severity.CRITICAL,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        description="Potential hardcoded secret or credential detected in .gitlab-ci.yml.",
        pattern=RegexPattern(
            match=r"""(?i)(password|passwd|secret|token|api_key|apikey|access_key|private_key)\s*[:=]\s*['"][^${\s][^'"]{8,}['"]""",
            exclude=[r"^\s*#", r"\$\{", r"\$CI_"],
        ),
        remediation="Move secrets to GitLab CI/CD variables (Settings > CI/CD > Variables) with protected + masked flags.",
        reference="https://docs.gitlab.com/ci/pipeline_security/",
        test_positive=[
            '    password: "MyS3cretP@ssw0rd!"',
            "    api_key: 'sk-1234567890abcdef1234'",
        ],
        test_negative=[
            "    password: $CI_DB_PASSWORD",
            "    # password: 'old_password'",
        ],
        stride=["I"],
        threat_narrative=(
            "Secrets committed to pipeline configuration are stored permanently in git "
            "history and readable by anyone who clones the repository, including all "
            "contributors and, in public projects, the entire internet. Every fork, mirror, "
            "and backup of the repository permanently contains the leaked credential."
        ),
    ),
    Rule(
        id="SEC6-GL-002",
        title="curl piped to shell in script block",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "Script downloads and executes remote code in one step. If the remote resource "
            "is compromised, arbitrary code executes in the pipeline runner."
        ),
        pattern=RegexPattern(
            match=r"curl\s.*\|\s*(bash|sh|zsh|python|perl)",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Download the script first, verify its checksum, then execute:\n"
            "curl -o script.sh https://...\n"
            "echo '<expected_hash>  script.sh' | sha256sum -c -\n"
            "bash script.sh"
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/",
        test_positive=[
            "    - curl -sSL https://install.example.com | bash",
            "    - curl https://raw.githubusercontent.com/org/repo/main/setup.sh | sh",
        ],
        test_negative=[
            "    - curl -o script.sh https://example.com/setup.sh",
            "    # curl https://example.com | bash",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Piping a remote URL directly to bash with no integrity check grants the server "
            "operator — or any attacker who can hijack the connection via DNS or BGP — "
            "arbitrary code execution in your pipeline with access to all GitLab CI "
            "variables. Supply chain attacks frequently target popular install scripts "
            "precisely because this pattern is so common."
        ),
    ),
    Rule(
        id="SEC6-GL-003",
        title="TLS verification disabled",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        description="TLS verification is disabled, enabling man-in-the-middle attacks.",
        pattern=RegexPattern(
            match=r"(--insecure|--no-check-certificate|verify\s*=\s*False|SSL_CERT_FILE=/dev/null|GIT_SSL_NO_VERIFY|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0)",
            exclude=[r"^\s*#"],
        ),
        remediation="Remove TLS bypass flags. Fix certificate issues properly.",
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/",
        test_positive=[
            "    - curl --insecure https://internal.example.com",
            "    - wget --no-check-certificate https://example.com",
            "    GIT_SSL_NO_VERIFY: true",
        ],
        test_negative=[
            "    - curl https://example.com",
            "    # --insecure",
        ],
        stride=["I", "T"],
        threat_narrative=(
            "Disabling TLS verification removes the only cryptographic guarantee that the "
            "server you are talking to is who it claims to be, opening the connection to "
            "MITM attacks that can silently read credentials in transit and substitute "
            "malicious responses. This is especially dangerous when credentials are sent as "
            "part of the same request."
        ),
    ),
    Rule(
        id="SEC6-GL-004",
        title="eval usage in script block",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "eval executes arbitrary strings as code. If the evaluated string includes "
            "user-controlled input, it enables code injection."
        ),
        pattern=RegexPattern(
            # Require a non-space argument after eval (eval\s+\S): a bare
            # ``eval`` followed only by whitespace is a no-op, not a dangerous
            # dynamic-string eval. The old ``eval\s+`` fired on ``eval  ``
            # (trailing-whitespace-only) — a latent false positive. The
            # tightened pattern is invariant to trailing-whitespace reformatting.
            match=r"^\s*(?:-\s*)?eval\s+\S",
            exclude=[r"^\s*#", r"echo", r"do not"],
        ),
        remediation="Replace eval with direct command execution. Avoid evaluating dynamic strings.",
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/",
        test_positive=[
            '    - eval "$DYNAMIC_COMMAND"',
            "    - eval $(generate_config)",
        ],
        test_negative=[
            "    # eval is dangerous",
            "    - echo 'do not eval this'",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "eval() executes any string as shell code at runtime, making the pipeline's "
            "behavior dependent on data that may be influenced by external inputs or "
            "environment variables. Attackers who can influence the evaluated string — "
            "through environment injection, compromised scripts, or attacker-controlled CI "
            "variables — gain arbitrary code execution."
        ),
    ),
    Rule(
        id="SEC6-GL-005",
        title="chmod 777 in script block",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        description="World-writable permissions set on files. Any process can modify them.",
        pattern=RegexPattern(
            # Also catch `chmod -R 777` (recursive) and `chmod a+rwx` (symbolic
            # world-writable) — the recursive form is the dominant real shape.
            match=r"chmod\s+(-R\s+)?(0?777|a\+rwx)",
            exclude=[r"^\s*#"],
        ),
        remediation="Use minimal permissions: chmod 755 for executables, chmod 644 for files.",
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/",
        test_positive=["    - chmod 777 /app/deploy.sh", "    - chmod -R 777 ."],
        test_negative=["    - chmod 755 /app/deploy.sh", "    # chmod 777"],
        stride=["E"],
        threat_narrative=(
            "chmod 777 grants read, write, and execute permission to every user on the "
            "runner system, including other jobs running concurrently on a shared runner. "
            "On self-hosted runners, world-writable files are a common persistence "
            "mechanism used after initial code execution — modified scripts survive across "
            "jobs."
        ),
    ),
    # =========================================================================
    # CICD-SEC-10: Insufficient Logging and Visibility (GitLab)
    # =========================================================================
    Rule(
        id="SEC10-GL-002",
        title="Public pipelines may expose job logs",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-10",
        description=(
            "In public (and internal) GitLab projects, pipeline and job log visibility "
            "is controlled by the CI/CD feature visibility setting, not by the pipeline "
            "YAML. Logs may contain sensitive output (dependency versions, internal "
            "hostnames, non-masked environment values) and be readable by unauthenticated "
            "users. This is a GitLab project setting, not a pipeline config — the rule is "
            "a reminder to verify the project configuration outside the repository."
        ),
        pattern=AbsencePattern(
            absent=r"THIS_RULE_NEVER_MATCHES_INTENTIONALLY_DISABLED",
        ),
        remediation=(
            "Pipeline/log visibility is governed by two GitLab project settings, both "
            "outside the YAML:\n"
            "\n"
            "1. Primary control — Settings > General > Visibility, project features, "
            "permissions > 'CI/CD': set to 'Only Project Members' if non-members should "
            "not see pipelines or logs. This applies regardless of project visibility.\n"
            "\n"
            "2. Secondary control — Settings > CI/CD > General pipelines > "
            "'Project-based pipeline visibility' (formerly labelled 'Public pipelines'). "
            "Clear this checkbox to further restrict pipeline viewing beyond what the "
            "feature-visibility dropdown allows.\n"
            "\n"
            "If the project does not need to be public, lowering project visibility to "
            "Internal or Private under Settings > General > Visibility is the most "
            "effective mitigation."
        ),
        reference="https://docs.gitlab.com/ci/pipelines/settings/#change-pipeline-visibility-for-non-project-members",
        test_positive=[],  # This is a reminder rule, not a pattern match
        test_negative=[],
        stride=["I", "R"],
        threat_narrative=(
            "In public GitLab projects, job logs are accessible to unauthenticated users, "
            "meaning any CI/CD variable value printed to a log — even non-masked ones — is "
            "publicly readable. Verbose build output, dependency resolution logs, and "
            "environment dumps can all expose internal paths, package versions, and "
            "configuration values useful for targeted attacks."
        ),
    ),
    # =========================================================================
    # SEC3-GL-008: Archived include:project (opt-in, network-dependent)
    # =========================================================================
    Rule(
        id="SEC3-GL-008",
        title="``include:`` references an archived GitLab project",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        review_needed=True,
        confidence="high",
        description=(
            "A ``include:project:`` reference points to a GitLab "
            "project that is archived (read-only).  Archived projects "
            "receive no new releases, no security patches, and the "
            "maintainer is not actively monitoring compromise reports.  "
            "Continuing to depend on an archived include is a deferred "
            "supply-chain risk: a CVE disclosed against it is unlikely "
            "to be fixed.\n"
            "\n"
            "This rule is opt-in via ``--check-archived-gitlab-projects`` "
            "because verification requires a per-include GitLab API "
            "call (``GET /projects/{namespace}/{project}`` reading the "
            "``archived`` flag).  Requires ``GITLAB_TOKEN`` in the "
            "environment.  Mirrors SEC3-GH-010's shape for GitHub."
        ),
        pattern=ArchivedIncludeProjectPattern(),
        remediation=(
            "Migrate to a maintained alternative include — check the "
            "archived project's README for a recommended successor, or "
            "fork it into your own namespace so security patches can be "
            "applied in-house.  Pin the include to a specific ref "
            "(``ref: <sha>``) once you've moved off the archived path."
        ),
        reference="https://docs.gitlab.com/ee/api/projects.html#get-single-project",
        test_positive=[],
        test_negative=[],
        stride=["T", "I"],
        threat_narrative=(
            "Archived GitLab projects are abandoned supply-chain "
            "surface.  When a CVE is published against an archived "
            "include, the disclosure-to-patch interval is unbounded.  "
            "Even though archived projects can't accept external MRs, "
            "the project owner themselves can still push fresh content "
            "— so a maintainer-account compromise on a dormant "
            "archived project leaks straight through."
        ),
        finding_family="action_pin_drift",
    ),
    # =========================================================================
    # SEC3-GL-009 — predictable cache key poisonable across a trust boundary
    # (gitlab-org/gitlab#330047).
    # =========================================================================
    Rule(
        id="SEC3-GL-009",
        title="Predictable cache key poisonable across a trust boundary",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A cache:key built only from predictable branch/project-scoped "
            "variables (e.g. $CI_COMMIT_REF_SLUG) with no per-commit/job/pipeline "
            "uniqueness component is shared across every merge-request and fork "
            "pipeline on the same branch name. A malicious MR can populate that "
            "cache with poisoned contents that a later trusted pipeline restores "
            "and trusts — the cache-poisoning shape of gitlab-org/gitlab#330047."
        ),
        pattern=_PoisonableCacheKeyPattern(),
        remediation=(
            "Add a uniqueness component to the cache key so MR/fork pipelines "
            "cannot share a trusted pipeline's cache, or key on content:\n"
            "\n"
            "  cache:\n"
            '    key: "$CI_COMMIT_REF_SLUG-$CI_COMMIT_SHA"   # per-commit\n'
            "    paths: [vendor/]\n"
            "\n"
            "or the content-hash form (rebuilds only when inputs change):\n"
            "\n"
            "  cache:\n"
            "    key:\n"
            "      files: [Gemfile.lock]\n"
            "    paths: [vendor/]"
        ),
        reference="https://docs.gitlab.com/ci/caching/#cache-key-names",
        test_positive=[
            'build:\n  cache:\n    key: "$CI_COMMIT_REF_SLUG"\n    paths:\n      - vendor/',
            "cache:\n  key: $CI_COMMIT_REF_NAME\n  paths:\n    - node_modules/",
            'test:\n  cache:\n    key: "deps-$CI_PROJECT_PATH_SLUG"\n    paths:\n      - .cache/',
        ],
        test_negative=[
            # uniqueness component -> not shareable across MRs/forks
            'build:\n  cache:\n    key: "$CI_COMMIT_SHA"\n    paths:\n      - vendor/',
            'build:\n  cache:\n    key: "$CI_COMMIT_REF_SLUG-$CI_COMMIT_SHA"\n    paths:\n      - vendor/',
            # content-hash key form (the documented safe pattern; no inline scalar)
            "build:\n  cache:\n    key:\n      files:\n        - Gemfile.lock\n    paths:\n      - vendor/",
            # static literal key (intentional shared cache; out of scope)
            'build:\n  cache:\n    key: "static-build-cache"\n    paths:\n      - vendor/',
        ],
        stride=["T"],
        threat_narrative=(
            "GitLab CI caches are restored before a job runs. When the cache key "
            "is predictable and shared across trust boundaries, an attacker who "
            "can open a merge request or fork pipeline writes the cache that the "
            "next trusted (default-branch or maintainer) pipeline restores, "
            "smuggling poisoned dependencies or build artifacts into a privileged "
            "run. A per-commit/job uniqueness component, or a content-hash key, "
            "removes the shared-key window."
        ),
    ),
]
