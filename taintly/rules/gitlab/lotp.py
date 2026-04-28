"""GitLab LOTP — Living Off The Pipeline.

Detects build tools that execute lifecycle scripts or build hooks against
attacker-controlled code in GitLab merge-request pipelines.

GitLab's risk model differs from GitHub in two important ways:

1. No explicit checkout step. GitLab CI auto-clones the pipeline's source
   ref — for a fork-MR pipeline that ref is the fork's branch, so any
   build tool in a job triggered by a merge-request event is operating on
   attacker-controlled source.

2. Fork MR pipelines are opt-in at project level. "Run pipelines for merge
   requests from forks" (Settings > Merge requests) must be enabled for
   this attack to be reachable from external contributors. The rule flags
   the code pattern regardless — static analysis cannot observe the
   project-level toggle.

Rule IDs follow the LOTP-<PLATFORM>-<NN> scheme established in the GitHub
LOTP rules.
"""

from taintly.models import ContextPattern, Platform, Rule, Severity

from .._build_tools import BUILD_TOOL_ANCHOR as _BUILD_TOOL_ANCHOR

# Evidence the job runs in an MR-event context. Matches both the legacy
# ``only: merge_requests`` syntax and the modern ``rules: - if:
# $CI_PIPELINE_SOURCE == 'merge_request_event'`` form.
_MR_EVENT = (
    r"(?:"
    r"merge_request_event"  # rules: if clause
    r"|only\s*:\s*(?:\[[^\]]*merge_requests|\n(?:\s*-\s*)?merge_requests)"  # only: merge_requests
    r"|\bmerge_requests\b"  # loose fallback
    r")"
)


RULES: list[Rule] = [
    # =========================================================================
    # LOTP-GL-001: Build tool in merge-request-event job
    # =========================================================================
    Rule(
        id="LOTP-GL-001",
        title="Build tool executed in GitLab merge-request pipeline (LOTP)",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A GitLab CI job runs a build tool (npm, pip, make, cargo, mvn, "
            "gradle, docker, etc.) in a pipeline triggered by a merge-request "
            "event. Unlike GitHub Actions, GitLab CI auto-checks-out the "
            "pipeline's source ref — for a fork-MR pipeline that source is "
            "the fork's branch, so the build tool operates on "
            "attacker-controlled source. If the project has "
            "'Run pipelines for merge requests from forks' enabled "
            "(Settings > Merge requests), any external contributor who opens "
            "an MR can trigger lifecycle-script execution via a manipulated "
            "package.json, setup.py, Makefile, or Dockerfile."
        ),
        pattern=ContextPattern(
            anchor=_BUILD_TOOL_ANCHOR,
            requires=_MR_EVENT,
            scope="job",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Do not run build tools in MR-event jobs that could be triggered "
            "by a fork. Options:\n"
            "\n"
            "1. Disable fork-MR pipelines at the project level: Settings > "
            "   Merge requests > 'Run pipelines for merge requests from "
            "   forks' — unset it unless you have a specific need.\n"
            "\n"
            "2. Move build-tool invocations into jobs gated on the protected "
            "   default branch:\n"
            "\n"
            "     build:\n"
            "       rules:\n"
            "         - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'\n"
            "       script:\n"
            "         - npm ci\n"
            "\n"
            "3. If the MR build must exist, run it in an isolated runner "
            "   with no protected variables and no network access to "
            "   internal resources; treat its output as untrusted.\n"
            "\n"
            "For npm/yarn/pnpm specifically, add `--ignore-scripts` (same "
            "mitigation as LOTP-GH-003) to disable lifecycle hooks."
        ),
        reference="https://docs.gitlab.com/ci/pipelines/merge_request_pipelines/",
        test_positive=[
            # Modern rules: if form
            "test:\n  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n  script:\n    - npm install",
            # Legacy only: merge_requests list form
            "build:\n  only:\n    - merge_requests\n  script:\n    - pip install -r requirements.txt",
            # Inline flow-sequence form
            "build:\n  only: [merge_requests]\n  script:\n    - make build",
            # Docker build under MR event
            "image_build:\n  rules:\n    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'\n  script:\n    - docker build -t app .",
        ],
        test_negative=[
            # Job gated to main-branch push — build tool is safe
            "deploy:\n  rules:\n    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'\n  script:\n    - npm ci --production",
            # MR-event job without a build tool (lint-only)
            "lint:\n  only:\n    - merge_requests\n  script:\n    - echo linting",
            # Build tool in a push-triggered job (not MR)
            "build:\n  only:\n    - main\n  script:\n    - cargo build",
            # pip install of a named PyPI package — does NOT read repo manifest
            "review:\n  rules:\n    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'\n  script:\n    - pip install PyGithub",
            # Commented-out line
            "job:\n  only:\n    - merge_requests\n  script:\n    # - npm install\n    - echo hi",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker forks the project, edits package.json / setup.py / "
            "Makefile / Dockerfile to run their payload as a lifecycle hook, "
            "and opens a merge request. If 'Run pipelines for merge requests "
            "from forks' is enabled, GitLab starts a pipeline in the upstream "
            "project using the fork's code; when a job runs `npm install` or "
            "`pip install .` or `docker build`, the attacker's hook executes "
            "with access to every CI/CD variable the job can see — masked "
            "values, anything not marked Protected, and any shared-runner "
            "state."
        ),
        incidents=["Ultralytics (Dec 2024)"],
    ),
    # =========================================================================
    # LOTP-GL-005: npm/yarn/pnpm install in a GitLab job holding an
    # exfil-worthy credential.  GitLab port of LOTP-GH-005 (Shai-Hulud
    # class).
    #
    # GitLab has no granular "permissions" block like GitHub Actions.
    # The exfil-worthy credentials on GitLab are:
    #   - ``NPM_TOKEN`` (identical name; project/group variable that
    #     publishes to npm).
    #   - ``NODE_AUTH_TOKEN`` (legacy setup-node-ish convention that
    #     some GitLab templates adopted).
    #   - ``NPM_CONFIG_AUTH_TOKEN`` / ``YARN_NPM_AUTH_TOKEN`` (explicit
    #     auth env used by `.npmrc` config).
    #   - A job-level ``id_tokens:`` block — GitLab's OIDC-federation
    #     primitive (analog of GitHub's ``id-token: write``).  Commonly
    #     paired with ``aud: 'npm:registry.npmjs.org'`` for trusted-
    #     publishing to npm.
    #
    # Skipped-on-purpose (too low signal / too high FP on GitLab):
    #   - ``CI_JOB_TOKEN``: every GitLab job holds one, so its presence
    #     is not a signal.  (The SEC6-GL-005 family already handles its
    #     misuse as a credential-propagation primitive.)
    #   - ``CI_REGISTRY_PASSWORD``: container-registry creds, not
    #     npm-registry.  Not a Shai-Hulud surface.
    #
    # Known gap: GitLab's ``extends:`` / ``include:`` mechanism lets a
    # job inherit a ``script:`` from another job OR file.  When the
    # install lives in ``.abstract-job:`` and the concrete job adds
    # ``id_tokens:`` via ``extends:``, the two legs of the rule live in
    # different top-level segments and the scope="job" co-occurrence
    # check misses the case.  The gl-eslint-plugin `.publish npm
    # package:` / `publish npm package:` pair hits this.  Extends
    # resolution is a scanner-wide change (parser/resolver), not a
    # per-rule fix, and would be a follow-up PR.
    #
    # References: the attack shape is identical to the GitHub rule —
    # Shai-Hulud (Sep 2025) + Shai-Hulud 2.0 (Nov 2025).
    # =========================================================================
    Rule(
        id="LOTP-GL-005",
        title=(
            "npm/yarn/pnpm install runs lifecycle scripts in a GitLab "
            "job holding an exfil-worthy secret (Shai-Hulud class)"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A GitLab CI job runs ``npm install`` / ``npm ci`` / "
            "``yarn install`` / ``pnpm install`` WITHOUT "
            "``--ignore-scripts``, and that same job holds an exfil-"
            "worthy credential — ``NPM_TOKEN`` / ``NODE_AUTH_TOKEN`` / "
            "``NPM_CONFIG_AUTH_TOKEN`` / ``YARN_NPM_AUTH_TOKEN`` in "
            "env, or a job-level ``id_tokens:`` block (GitLab's OIDC-"
            "federation primitive, commonly configured with "
            "``aud: 'npm:registry.npmjs.org'`` for trusted publishing).  "
            "Every direct and transitive dependency's ``postinstall`` / "
            "``preinstall`` / ``prepare`` hook runs in that shell with "
            "the credential in process env.  This is the attack "
            "surface Shai-Hulud (Sep 2025) and Shai-Hulud 2.0 "
            "(Nov 2025, 25,000+ repos infected) weaponised on the "
            "GitHub side; GitLab pipelines that publish to npm are the "
            "same class of target."
        ),
        pattern=ContextPattern(
            # Anchor: per-line invocation of the install, NOT already
            # carrying --ignore-scripts on the same line.  Mirrors
            # LOTP-GH-005's anchor — continuation-line forms are a
            # known small gap (the rule still fires at HIGH, so a
            # reviewer reads the job anyway).
            anchor=(
                r"\b(?:"
                r"npm\s+(?:install|i|ci)"
                r"|yarn\s+(?:install|add)"
                r"|pnpm\s+(?:install|i|add)"
                r")\b(?:(?!--ignore-scripts).)*$"
            ),
            # Requires (per-job): exfil-worthy credential reachable
            # from this job's shell.  ``id_tokens:`` is matched as a
            # YAML key (with trailing colon) to avoid false positives
            # on plain text mentions.
            requires=(
                r"(?:"
                r"\bNPM_TOKEN\b"
                r"|\bNODE_AUTH_TOKEN\b"
                r"|\bNPM_CONFIG_AUTH_?TOKEN\b"
                r"|\bYARN_NPM_AUTH_?TOKEN\b"
                # YAML key for GitLab's OIDC-federation primitive.
                # Not line-anchored because ContextPattern.requires is
                # matched against the joined segment content without
                # re.MULTILINE, so `^` would only match string-start.
                r"|\bid_tokens\s*:"
                r")"
            ),
            scope="job",
            exclude=[
                r"^\s*#",
                # Lines where --ignore-scripts is paired with the
                # install command are already safe on this axis.
                r"--ignore-scripts",
            ],
        ),
        remediation=(
            "Pass `--ignore-scripts` to every `npm install` / `npm ci`\n"
            "/ `yarn install` / `pnpm install` in a GitLab job that\n"
            "holds an exfil-worthy credential — either an `NPM_TOKEN`-\n"
            "family variable, or a job-level `id_tokens:` block.  This\n"
            "blocks the postinstall / preinstall lifecycle hooks that\n"
            "Shai-Hulud-class attacks abuse.  For jobs that genuinely\n"
            "need lifecycle scripts (native-addon builds), split into\n"
            "two jobs: one without credentials that runs the install\n"
            "and uploads `node_modules/` as a `cache:` or `artifacts:`,\n"
            "and a second that restores it and runs the privileged\n"
            "publish step.  Also lock the lockfile (`npm ci` over\n"
            "`npm install`, `yarn install --frozen-lockfile` /\n"
            "`--immutable`, `pnpm install --frozen-lockfile`).\n"
            "Run `taintly --guide LOTP-GH-005` for the full\n"
            "checklist (the GitHub guide applies directly)."
        ),
        reference=(
            "https://www.sysdig.com/blog/shai-hulud-the-novel-self-replicating-worm-infecting-hundreds-of-npm-packages; "
            "https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/; "
            "https://docs.gitlab.com/ci/secrets/id_token_authentication/; "
            "https://docs.gitlab.com/ci/examples/publish_npm_package/"
        ),
        test_positive=[
            # npm install + NPM_TOKEN — the classic surface
            (
                "publish:\n  stage: deploy\n  script:\n"
                "    - npm install\n"
                "    - npm publish\n"
                "  variables:\n    NPM_TOKEN: $NPM_TOKEN"
            ),
            # yarn install + id_tokens: (OIDC trusted-publishing)
            (
                "publish:\n  stage: deploy\n"
                "  id_tokens:\n    NPM_ID_TOKEN:\n      aud: 'npm:registry.npmjs.org'\n"
                "  script:\n    - yarn install --frozen-lockfile"
            ),
            # pnpm install + NODE_AUTH_TOKEN
            (
                "release:\n  stage: release\n  script:\n"
                "    - pnpm install --frozen-lockfile\n"
                "    - pnpm publish\n"
                "  variables:\n    NODE_AUTH_TOKEN: $NPM_TOKEN"
            ),
            # npm ci + NPM_CONFIG_AUTH_TOKEN
            (
                "ship:\n  script:\n"
                "    - npm ci\n"
                "    - npm publish\n"
                "  variables:\n    NPM_CONFIG_AUTHTOKEN: $TOK"
            ),
        ],
        test_negative=[
            # --ignore-scripts — safe even with NPM_TOKEN
            (
                "publish:\n  script:\n"
                "    - npm install --ignore-scripts\n"
                "  variables:\n    NPM_TOKEN: $NPM_TOKEN"
            ),
            # npm install in a job without any exfil-worthy credential
            ("test:\n  script:\n    - npm install\n    - npm test"),
            # NPM_TOKEN in a sibling job — no same-job co-occurrence
            (
                "publish:\n  script:\n    - echo publish\n"
                "  variables:\n    NPM_TOKEN: $NPM_TOKEN\n"
                "test:\n  script:\n    - npm install"
            ),
            # id_tokens: in a sibling job — no same-job co-occurrence
            (
                "build:\n  script:\n    - npm install\n"
                "publish:\n  id_tokens:\n    NPM_ID_TOKEN:\n      aud: 'npm:registry.npmjs.org'\n"
                "  script:\n    - npm publish"
            ),
            # Commented-out install
            (
                "publish:\n  script:\n    # - npm install\n    - echo hi\n"
                "  variables:\n    NPM_TOKEN: $NPM_TOKEN"
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker compromises one dependency in a GitLab "
            "repo's npm tree — typically by stealing a publish "
            "token from another maintainer and pushing a new patch "
            "version.  The new version's ``postinstall`` reads "
            "process env (``$NPM_TOKEN`` / minted "
            "``$NPM_ID_TOKEN`` from ``id_tokens:``) and uses it to "
            "republish every other package the pipeline's maintainers "
            "can reach, infecting the supply chain in a self-"
            "propagating loop.  The GitLab pipeline doesn't need to "
            "look exotic — a plain ``npm publish`` job with "
            "``yarn install`` in front of it is enough."
        ),
        incidents=["Shai-Hulud (Sep 2025)", "Shai-Hulud 2.0 (Nov 2025)"],
        confidence="low",
    ),
]
