"""GitHub Actions — Permission Slip Effect (PSE) family.

The PSE family flags workflows where three conditions co-exist:

  1. A fork-reachable trigger (anyone can send input)
  2. An AI coding agent or LLM SDK call (the input sink)
  3. A grant that lets the job mint or assume cloud credentials
     (``permissions: id-token: write``, or an explicit OIDC login
     action like ``aws-actions/configure-aws-credentials``,
     ``google-github-actions/auth``, ``azure/login``)

Existing rules treat (1)+(2) and (2)+(3) separately: ``AI-GH-005``
/ ``AI-GH-006`` flag the agent-plus-untrusted-input shape, and other
rules flag credential handling.  PSE fires only when all three
co-occur — an attacker who can steer the agent via prompt injection
reaches a step that already holds a valid OIDC grant.

Starter version:
  - Severity is ``HIGH`` because the IAM scope of the OIDC role
    is unknown at this layer (no IAM policy parsing yet).  A follow-up
    PR parses local IAM JSON and upgrades to ``CRITICAL`` when the
    role grants sensitive actions (``s3:*``, ``sts:AssumeRole``,
    ``secretsmanager:*``, etc.).
  - The third ingredient is intentionally broad: both explicit OIDC
    auth actions AND bare ``id-token: write`` grants fire the rule.
    The grant alone is a slip — any agent with a shell tool can
    request a federated token and trade it for cloud credentials.
"""

import re

from taintly.models import ContextPattern, Platform, Rule, Severity
from taintly.parsers.structural import Event, EventKind, walk_workflow
from taintly.taint import AI_AGENT_USES_PATTERN

# Fork-reachable events — any of these means external contributors
# can influence workflow inputs.
_FORK_REACHABLE_TRIGGER = (
    r"(?:"
    r"(?:^|\n)on:\s*(?:\n\s+)?(?:-\s*)?"
    r"(?:pull_request|pull_request_target|issue_comment|issues|discussion|workflow_run)\b"
    r"|\[\s*[^\]]*"
    r"(?:pull_request|pull_request_target|issue_comment|issues|discussion|workflow_run)[^\]]*\]"
    r"|\bpull_request_target\b"
    r")"
)

# Cloud-credential grant — either a minted-token permission or an
# explicit OIDC auth action.  Matching either form is the point: bare
# `id-token: write` without an auth action is still a slip because a
# compromised agent with shell tools can request the JWT directly.
_OIDC_CAPABILITY = (
    r"(?:"
    r"\bid-token:\s*write\b"
    r"|aws-actions/configure-aws-credentials"
    r"|google-github-actions/auth"
    r"|\bazure/login\b"
    r"|\brole-to-assume:"
    r"|\bworkload_identity_provider:"
    r")"
)

# AI-agent / LLM-SDK anchor — kept in sync with AI-GH-005's anchor.
# Either a direct SDK / API call (openai, anthropic, LangChain, etc.)
# or a `uses:` reference to a known coding-agent action, OR a CI-side
# install of an agent package (`npm install -g @anthropic-ai/claude-code`,
# `pip install aider-chat`, `gh extension install github/gh-copilot`).
# The anchor is per-line because we want the finding to point at the
# agent invocation specifically.
#
# Refactored from the narrower "SDK + uses:-action" anchor after a
# corpus scan surfaced two concrete problems:
#
#   1. False negative — trycua/cua's egregious claude-auto-fix.yml
#      installs Claude Code via `npm install -g @anthropic-ai/claude-code`
#      and then invokes the CLI.  The original anchor missed this
#      shape entirely, letting AI-GH-015 / PSE-GH-001 under-fire.
#   2. False positive — zama-ai/fhevm's claude-review.yml has a curl
#      to `https://api.anthropic.com/api/github/github-app-token-exchange`
#      (a GitHub App token exchange, NOT an LLM call).  The anchor's
#      `api.anthropic.com` substring match over-fires on this.
#
# Both classes are documented by the research agent corpus scan
# (April 2026).  This refactor widens coverage for the install shape
# and narrows the `api.anthropic.com` match to exclude known non-LLM
# paths (/api/github/, /api/claude-app/).  The refactor is shared
# across 9 consuming rules: AI-GH-005, 006, 008, 009, 014, 015, 017,
# TAINT-GH-005, PSE-GH-001.
_AI_AGENT_ANCHOR = (
    r"(?i:"
    # ----- SDK / LangChain / client-library shapes ---------------------------
    # `anthropic.messages.create(...)` / `openai.chat.completions.create(...)`
    # / `OpenAI()` / `Anthropic()` constructor calls.  The dot form MUST NOT
    # be followed by `com` / `ai` — that's a hostname (`api.anthropic.com`)
    # which the host-substring arm below handles with its own path
    # narrowing.  Without this guard, the SDK arm fires on any curl URL
    # containing `anthropic.com` (fhevm line-209 FP).
    r"\b(?:open_?ai|anthropic)\s*(?:\.(?!com\b|ai\b)|\()"
    r"|\bChatOpenAI\b"
    r"|\bChatAnthropic\b"
    r"|\bChatCompletionsClient\b"
    # ----- Provider API host substrings (narrowed to exclude non-LLM paths) --
    # `api.anthropic.com/api/github/...` is the Claude Code GitHub App
    # token-exchange endpoint, NOT an LLM call; same for
    # `/api/claude-app/` which is an internal non-inference path.
    # The negative lookahead `(?!/api/(?:github|claude-app)/)` after
    # the host prunes those specific paths without losing /v1/messages
    # or /v1/chat/completions coverage.
    r"|api\.anthropic\.com(?!/api/(?:github|claude-app)/)"
    r"|api\.(?:openai|cohere|mistral|groq|perplexity)\.(?:com|ai)"
    r"|generativelanguage\.googleapis\.com"
    # ----- CLI invocations of provider tooling (openai api, llm) -------------
    r"|\bopenai\s+api\s+(?:chat|complet|image)"
    r"|\bllm\s+(?:chat|prompt|-m)\b"
    # ----- `uses:` to a known coding-agent action ----------------------------
    rf"|{AI_AGENT_USES_PATTERN}"
    # ----- CI-side install of agent packages (NEW in this refactor) ---------
    # Installing the agent binary from a package manager is a strong
    # signal even before the CLI invocation happens — and the CLI
    # invocation often lives in a separate `run:` step that the
    # existing anchor missed (trycua/cua's claude-auto-fix.yml is
    # exactly this shape).  Matching the install line means we flag
    # the workflow wherever the agent is introduced.
    r"|\bnpm\s+(?:install|i)\s+(?:-g\s+)?"
    r"(?:@anthropic-ai/claude-code|@anthropic-ai/sandbox-runtime"
    r"|aider-chat|@openai/codex-cli|@cursor/cli|claude-code)\b"
    r"|\bpip\s+install\s+(?:aider-chat|claude-code-sdk|anthropic|"
    r"openai|langchain|litellm)\b"
    r"|\bpipx\s+install\s+(?:aider-chat|claude-code-sdk)\b"
    r"|\bgh\s+extension\s+install\s+github/gh-copilot\b"
    r")"
)


RULES: list[Rule] = [
    # =========================================================================
    # PSE-GH-001: Permission Slip Effect — agent reachable from untrusted
    # input holds a valid cloud-credential grant (starter, no IAM parsing).
    # =========================================================================
    Rule(
        id="PSE-GH-001",
        title="AI agent with cloud-credential grant on a fork-reachable event",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A workflow combines three ingredients: "
            "(1) a fork-reachable trigger (pull_request, pull_request_target, "
            "issue_comment, issues, discussion, workflow_run), "
            "(2) an AI coding agent action or LLM SDK call, and "
            "(3) a grant that lets the job mint or assume cloud credentials — "
            "either `permissions: id-token: write` or an explicit OIDC auth "
            "action (aws-actions/configure-aws-credentials, "
            "google-github-actions/auth, azure/login). "
            "The agent is reachable from attacker-controlled input (PR body, "
            "issue comment, etc.) and holds a valid OIDC grant. An attacker "
            "who steers the agent via prompt injection can use the federated "
            "token for any action the IAM role permits — reading "
            "terraform.tfstate, exfiltrating via allowed side channels, etc. "
            "Distinct from AI-GH-005 (untrusted input reaches agent) and "
            "AI-GH-006 (agent on fork trigger) — this rule fires when both "
            "conditions hold AND the agent sits on a credential grant."
        ),
        pattern=ContextPattern(
            anchor=_AI_AGENT_ANCHOR,
            # Two file-level preconditions AND'd via zero-width lookaheads.
            # `\A` anchors the whole pattern at position 0 so `.search()`
            # only evaluates the lookaheads once (not once per starting
            # position), giving O(N) total work on the file.  Without the
            # anchor, `.search()` would retry at every position — O(N²)
            # on adversarial inputs (the `extremely_many_steps` fuzz case).
            # `[\s\S]*?` (lazy) further keeps each lookahead from
            # over-consuming before the precondition pattern matches.
            requires=(
                r"\A"
                r"(?=[\s\S]*?" + _FORK_REACHABLE_TRIGGER + r")"
                r"(?=[\s\S]*?" + _OIDC_CAPABILITY + r")"
            ),
            scope="file",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Treat the AI agent on a fork-reachable trigger as an arbitrary\n"
            "code-execution primitive holding your cloud permission slip.\n"
            "Break at least one leg of the triangle:\n"
            "  1. Gate the agent job by same-repo identity so fork PRs can't\n"
            "     reach it (`github.event.pull_request.head.repo.full_name\n"
            "     == github.repository`), OR\n"
            "  2. Drop the `id-token: write` / OIDC step from the agent job\n"
            "     and move credential-using work to a separate job that has\n"
            "     no AI agent, OR\n"
            "  3. Narrow the agent's `allowedTools` to forbid shell / file\n"
            "     write / `gh` tools — the federated token is useless to\n"
            "     the agent without a way to use it.\n"
            "Run `taintly --guide PSE-GH-001` for the full checklist."
        ),
        reference=(
            "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/; "
            "https://docs.github.com/en/actions/security-for-github-actions/"
            "security-hardening-your-deployments/about-security-hardening-with-openid-connect"
        ),
        test_positive=[
            # The ai_agent_on_pr.yml shape — bare id-token:write + agent + fork trigger.
            (
                "on: pull_request\n"
                "permissions:\n  contents: read\n  id-token: write\n"
                "jobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: anthropics/claude-code-action@v1"
            ),
            # Explicit OIDC auth action instead of the bare permission grant.
            (
                "on: pull_request_target\n"
                "jobs:\n  triage:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: aws-actions/configure-aws-credentials@<SHA>\n"
                "        with:\n          role-to-assume: arn:aws:iam::...:role/Triage\n"
                "      - uses: anthropics/claude-code-action@v1"
            ),
            # issue_comment trigger + LLM SDK + GCP auth.
            (
                "on: issue_comment\n"
                "jobs:\n  respond:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: google-github-actions/auth@<SHA>\n"
                "        with:\n          workload_identity_provider: projects/.../providers/gh\n"
                '      - run: python -c "from openai import OpenAI; OpenAI().chat.completions.create(...)"'
            ),
        ],
        test_negative=[
            # Agent on fork trigger but NO cloud-credential grant — AI-GH-006
            # territory, not PSE.
            (
                "on: pull_request\n"
                "permissions:\n  contents: read\n  pull-requests: write\n"
                "jobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: anthropics/claude-code-action@v1"
            ),
            # OIDC + fork trigger but NO agent — plain OIDC use, unrelated to PSE.
            (
                "on: pull_request\n"
                "permissions:\n  id-token: write\n"
                "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: aws-actions/configure-aws-credentials@<SHA>\n"
                "        with:\n          role-to-assume: arn:aws:iam::...:role/Deploy\n"
                "      - run: aws s3 sync ./dist s3://bucket"
            ),
            # Agent + OIDC but workflow_dispatch only — maintainer-triggered,
            # not fork-reachable.
            (
                "on: workflow_dispatch\n"
                "permissions:\n  id-token: write\n"
                "jobs:\n  release:\n    runs-on: ubuntu-latest\n    environment: release\n"
                "    steps:\n"
                "      - uses: anthropics/claude-code-action@v1"
            ),
            # Agent step is commented out.
            (
                "on: pull_request\n"
                "permissions:\n  id-token: write\n"
                "jobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      # - uses: anthropics/claude-code-action@v1\n"
                "      - run: echo placeholder"
            ),
        ],
        stride=["E", "T", "I"],
        threat_narrative=(
            "An attacker opens a PR, issue, or comment carrying a "
            "prompt-injection payload. The payload reaches the agent "
            "step in a workflow that has `id-token: write` or an "
            "explicit OIDC auth action. With shell or file-system tools "
            "enabled, the agent mints the federated token, trades it "
            "for cloud credentials, and uses those credentials for an "
            "action the workflow author never intended but the IAM "
            "role permits."
        ),
        confidence="medium",
        incidents=[],
    ),
]


# =============================================================================
# PSE-GH-006 — tokened checkout of fork PR head + shell run = RCE
# =============================================================================
#
# Detects the classic ``pwn_request`` shape: a workflow runs on a fork-
# reachable, write-context trigger (``pull_request_target`` / a
# ``workflow_run`` chained off PR context / an ``issue_comment`` carrying
# ``pull-requests: write``); a job inside has a write-capable token
# (workflow-level or job-level ``permissions:`` granting write, or no
# ``permissions:`` block at all — in which case the default ``GITHUB_TOKEN``
# is write-capable for that event); the job checks out the attacker's
# fork-head via ``ref: ${{ github.event.pull_request.head.{ref,sha} }}``
# or ``repository: ${{ github.event.pull_request.head.repo.full_name }}``;
# and a later step in the same job runs attacker-controlled code through
# a shell.  Once those five preconditions co-occur, the workflow author
# has effectively handed every fork PR opener an RCE primitive holding
# the host repo's write token.
#
# Sample-label evidence (n=3) gave 2/3 precision.  The two TPs
# were canonical pwn_request shapes on ActionsTOCTOU's
# ``deployment_victim.yml`` and ``label_victim.yml``.  The FP was
# the dependabot-autoapprove shape (aws-actions's
# configure-aws-credentials repo) — the job's ``if:`` gated on
# ``user.login == 'dependabot[bot]'``, so attacker-fork PRs cannot
# reach the tokened checkout in the first place.  Hence the
# negative bot-user gate below.
#
# Design choice — flat-join over the structural reader's leaf
# stream.  Public taintly is dependency-free Python and uses
# ``WorkflowAwarePattern`` style flat joins on leaf paths, hence
# the ~250-line plain-joins form below rather than a closure
# substrate.
# =============================================================================


# Fork-reachable, write-context triggers.  Matched against the file text
# because the structural reader does not emit a leaf event for empty
# block-form keys like ``on:\n  pull_request_target:`` (no scalar value
# under the key means no LEAF_SCALAR).  A line-window regex covers all
# three legal YAML shapes (bare string, block-form, flow-list).
_PSE6_FORK_TRIGGER_RE = re.compile(
    r"(?:"
    # bare string form: ``on: pull_request_target`` / ``on: workflow_run`` / ``on: issue_comment``
    r"(?:^|\n)on:\s*(?:pull_request_target|workflow_run|issue_comment)\s*(?:#.*)?$"
    # block form: ``on:\n  pull_request_target:`` (and the same for the other two events).
    # Accept ANY whitespace indent (``\s+``) rather than ``\s{2,}`` so the
    # ``indent_shift`` mutator's 1-space indent variant still resolves.
    r"|(?:^|\n)\s+(?:pull_request_target|workflow_run|issue_comment)\s*:"
    # flow-list form: ``on: [push, pull_request_target]``
    r"|(?:^|\n)on:\s*\[[^\]]*(?:pull_request_target|workflow_run|issue_comment)[^\]]*\]"
    r")",
    re.MULTILINE,
)


# Reserved GitHub Actions ``on:`` event names that are NOT fork-reachable
# in the threat model — used to filter false matches when the broadened
# ``\s+`` block-form arm above happens to match an indented ``push:`` or
# ``schedule:`` key.  We only need this as a sanity check on the leaf-
# path detection below; the regex above already restricts to the three
# events we care about so this is mostly for documentation.
_PSE6_FORK_REACHABLE_TRIGGERS: frozenset[str] = frozenset(
    {"pull_request_target", "workflow_run", "issue_comment"}
)


def _has_fork_reachable_trigger(content: str, leaves: list[Event]) -> bool:
    """Detect a fork-reachable write-context trigger.

    Two paths stacked so neither is load-bearing:

      * Structural leaves under ``('on', <event-name>, ...)`` — works
        for the block-form trigger shape with sub-keys (``on:\\n
        pull_request_target:\\n  types: [labeled]``) including the
        1-space ``indent_shift`` mutator's variant, because the
        structural reader's tokenizer is whitespace-insensitive on
        indent depth.
      * Text regex (:data:`_PSE6_FORK_TRIGGER_RE`) — works for the
        bare-string form (``on: pull_request_target``) and the
        empty-block form (``on:\\n  pull_request_target:`` with no
        sub-keys), neither of which surfaces a structural leaf event.

    Either path firing means the trigger is present.
    """
    for ev in leaves:
        path = ev.path
        # Block form with sub-keys: leaf path is ``('on', <event>, ...)``.
        if len(path) >= 2 and path[0] == "on" and path[1] in _PSE6_FORK_REACHABLE_TRIGGERS:
            return True
        # Bare-string form: ``on: pull_request_target`` →
        # leaf path == ``('on',)``, value is the event name.
        if path == ("on",) and (ev.value or "") in _PSE6_FORK_REACHABLE_TRIGGERS:
            return True
        # Flow-list form: ``on: [push, pull_request_target]`` →
        # leaf path == ``('on', <int>)``, value is the event name.
        if (
            len(path) == 2
            and path[0] == "on"
            and isinstance(path[1], int)
            and (ev.value or "") in _PSE6_FORK_REACHABLE_TRIGGERS
        ):
            return True
    return bool(_PSE6_FORK_TRIGGER_RE.search(content))


# Tainted checkout — attacker-fork-head ref / sha / repo splice into
# ``actions/checkout`` inputs.  Values seen by the structural reader
# carry the ``${{ ... }}`` syntax verbatim, so a substring check is
# enough and avoids re-implementing GitHub's expression grammar.
_PSE6_TAINTED_REF_RE = re.compile(
    r"\$\{\{\s*github\.event\.pull_request\.head\.(?:ref|sha)\s*\}\}",
)
_PSE6_TAINTED_REPO_RE = re.compile(
    r"\$\{\{\s*github\.event\.pull_request\.head\.repo\.full_name\s*\}\}",
)


# Shell-run heuristic — ``run:`` body that exercises a shell.  A pure
# substring check on the leaf value would over-fire on ``run: echo hi``
# (echo is shell-form-safe but the broader corpus shows echo lines are
# rarely the only step).  Instead we match a small allowlist of build
# verbs and package managers that map to attacker-arbitrary execution
# in the canonical ``pwn_request`` corpus:
#
#   * package managers (npm, yarn, pnpm, pip, poetry, uv, pipx) running
#     install / run / build / test / publish — install runs lifecycle
#     scripts from a fork-controlled ``package.json``
#   * compiler/build drivers (make, bazel, ninja, cmake) — Makefile is
#     attacker-controlled in a fork checkout
#   * language test/run drivers (go test, go run, cargo test, cargo run,
#     cargo build, python <file>, ruby <file>, node <file>)
#   * generic ``bash`` / ``sh`` / ``./<script>`` shell drivers
#
# Plain echo / printf / cat with literal arguments do NOT count: they
# do not execute fork-controlled code on their own.
_PSE6_SHELL_RUN_RE = re.compile(
    r"(?:"
    r"\b(?:npm|yarn|pnpm)\s+(?:install|i|ci|run|test|build|publish|exec)\b"
    r"|\bpip\s+install\b"
    r"|\bpoetry\s+(?:install|run|build|publish)\b"
    r"|\b(?:uv|pipx)\s+(?:install|run|sync|tool\s+install)\b"
    r"|\bmake(?:\s+\S+)?\b"
    r"|\b(?:bazel|ninja|cmake)\b"
    r"|\bgo\s+(?:test|run|build|generate|install)\b"
    r"|\bcargo\s+(?:test|run|build|install|publish)\b"
    r"|\bpython3?\s+[\w./-]+\.py\b"
    r"|\bnode\s+[\w./-]+\.(?:js|mjs|cjs|ts)\b"
    r"|\bruby\s+[\w./-]+\.rb\b"
    r"|\bbash\s+[\w./-]+\b"
    r"|\bsh\s+[\w./-]+\b"
    r"|(?:^|\s|&&\s*)\./[\w./-]+\b"
    r")",
    re.IGNORECASE,
)


# Trusted-bot user.login allowlist — exact match (case-insensitive)
# against the actor / user.login slot.  Documented for the rule body
# even though the predicate's broader user-gate suppression below
# subsumes the bot allowlist: when reviewers ask "why didn't the rule
# fire on this dependabot workflow?" the answer is this list.  Adding
# to this list does not change the predicate's behaviour; it only
# documents which bot accounts the rule explicitly considers safe.
_PSE6_TRUSTED_BOTS = (
    "dependabot[bot]",
    "renovate[bot]",
    "github-actions[bot]",
    "pre-commit-ci[bot]",
)


# Any literal-equality user gate in the job's ``if:`` value — covers
# both the documented trusted-bot allowlist (the canonical
# dependabot-autoapprove FP) and the more general case where the
# workflow author restricts execution to a named maintainer /
# org-member ``github.actor`` literal.  Either
# shape excludes attacker-fork PRs at the engine boundary, so the
# rule must not fire on it.
#
# The regex matches ``github.actor == '<literal>'`` and the per-event
# ``user.login == '<literal>'`` shapes.  We deliberately accept ANY
# literal here — a maintainer literal is just as restrictive as a
# bot literal as far as fork-PR reachability is concerned.  Match
# both quote styles and tolerate inline whitespace.
_PSE6_USER_GATE_RE = re.compile(
    r"(?i:"
    r"(?:github\.actor|github\.event\.(?:pull_request|issue|comment|review)\.user\.login)"
    r"\s*==\s*"
    r"['\"][^'\"]+['\"]"
    r")",
)


class _Pse006Pattern:
    """Flat-join detector for PSE-GH-006.

    Walks the workflow's LEAF_SCALAR stream once, groups leaves by job,
    and emits one finding per job whose evidence satisfies all five
    preconditions (fork-reachable + write-context, write-token,
    tainted checkout, in-job shell run, no trusted-bot gate).

    Conforms to ``PatternProtocol.check(content, lines) -> list[(line,
    snippet)]`` so the engine dispatches it without special-casing.

    Implementation notes:

    * Fork-reachable trigger detection runs over the file text via
      ``_PSE6_FORK_TRIGGER_RE`` because the structural reader does
      not surface empty block-form trigger keys.
    * Write-token detection inspects both workflow-level
      ``('permissions', ...)`` leaves and job-level
      ``('jobs', <id>, 'permissions', ...)`` leaves; absence of any
      ``permissions`` leaf means the default token applies (write for
      most events).
    * The tainted-checkout anchor cites the line of the offending
      ``ref:`` / ``sha:`` / ``repository:`` splice, since that line is
      the most actionable for the reviewer (it's the input that needs
      to be removed or replaced with ``github.event.pull_request.base.sha``).
    * Bot-user gate matches ``github.actor == '<bot>'`` and the
      per-event ``user.login == '<bot>'`` shapes.  Anything OTHER than
      a trusted-bot equality (a maintainer-actor gate, a label gate,
      an organisation-member gate) leaves the rule firing — that is
      the design: the known-weak ``safe-to-test`` label gate is the
      canonical TP in ActionsTOCTOU's ``label_victim.yml``.
    """

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        try:
            leaves = [
                ev
                for ev in walk_workflow("anonymous.yml", content=content, recover=True)
                if ev.kind is EventKind.LEAF_SCALAR
            ]
        except Exception:
            # Conservative on parser failure: structural read broken —
            # don't fire on the structural path.  The text-fallback
            # below covers the YAML-unparseable case (zero-space
            # ``whitespace_pad`` mutant collapses every ``key:value``
            # into a single scalar that the reader can't tokenize).
            leaves = []

        # Stacked detection: structural-leaf check first (handles the
        # ``indent_shift`` mutant whose 1-space indent breaks textual
        # regexes), text-regex fallback for the bare-string and
        # empty-block-form shapes the structural reader doesn't
        # surface as leaf events.
        if not _has_fork_reachable_trigger(content, leaves):
            return []

        # Structural pass returned no leaves — fall through to the
        # text-only join.  Happens when the YAML is malformed in a way
        # the recoverable reader can't tokenize (zero-space
        # ``key:value`` shapes the ``whitespace_pad`` mutator
        # produces), but the threat shape is still apparent in the
        # raw text.
        if not leaves:
            return self._text_fallback(content, lines)

        # Structural pass produced leaves but no ``steps`` paths.
        # That means the YAML tokenizer choked partway through (the
        # canonical ``whitespace_pad`` mutant where ``key:value``
        # collapse forces the reader to treat each job's body as a
        # single scalar value).  Fall through to the text-only join
        # — the same threat shape is still apparent in the raw text
        # and would otherwise be missed.
        has_step_leaf = any(
            len(ev.path) >= 4 and ev.path[0] == "jobs" and ev.path[2] == "steps" for ev in leaves
        )
        if not has_step_leaf:
            return self._text_fallback(content, lines)

        # Workflow-level permissions: any ``('permissions', ...)`` leaf
        # — covers both the bare-string ``permissions: write-all`` shape
        # and the block-form individual scopes.
        wf_permissions_leaves = [ev for ev in leaves if ev.path and ev.path[0] == "permissions"]
        wf_has_permissions_block = bool(wf_permissions_leaves)
        wf_has_write_token = self._permissions_imply_write(wf_permissions_leaves, root_path_len=1)

        # Group job leaves by job-id.  A leaf is "in job J" when its
        # path starts with ``('jobs', J, ...)``.
        jobs: dict[str, list[Event]] = {}
        for ev in leaves:
            p = ev.path
            if len(p) >= 2 and p[0] == "jobs" and isinstance(p[1], str):
                jobs.setdefault(p[1], []).append(ev)

        results: list[tuple[int, str]] = []
        seen: set[tuple[int, str]] = set()
        for job_leaves in jobs.values():
            anchor = self._evaluate_job(
                job_leaves=job_leaves,
                wf_has_permissions_block=wf_has_permissions_block,
                wf_has_write_token=wf_has_write_token,
                lines=lines,
            )
            if anchor is None:
                continue
            key = (anchor[0], anchor[1])
            if key in seen:
                continue
            seen.add(key)
            results.append(anchor)
        results.sort(key=lambda r: r[0])
        return results

    # ------------------------------------------------------------------
    # Text-only fallback
    #
    # Used when the structural reader produces zero leaves (the
    # ``whitespace_pad`` mutator's ``:`` → ``:`` collapse breaks YAML
    # tokenization at every key).  In that case every ingredient of
    # the 5-way join is still apparent in the raw text — we just
    # can't bucket it by job-id any more, so we fire conservatively
    # only when ALL five ingredients are present anywhere in the
    # file AND no user-gate equality is present anywhere.  The
    # fallback's precision boundary is necessarily wider than the
    # structural path's because we can't tie the ingredients to the
    # same job; documented as a documented mutation-resilience
    # tradeoff rather than a load-bearing precision claim.
    # ------------------------------------------------------------------

    @staticmethod
    def _text_fallback(content: str, lines: list[str]) -> list[tuple[int, str]]:
        # User-gate suppression in the text fallback uses the same
        # ``_PSE6_USER_GATE_RE`` as the structural path; the trade-
        # off is that ANY user-gate anywhere in the file suppresses,
        # not just the user-gate of the same job.  Acceptable here
        # because the alternative (no fire) is also conservative.
        if _PSE6_USER_GATE_RE.search(content):
            return []
        # Tainted ref / repo splice anywhere in the content.
        ref_match = _PSE6_TAINTED_REF_RE.search(content) or _PSE6_TAINTED_REPO_RE.search(content)
        if not ref_match:
            return []
        # ``actions/checkout`` substring.  Required so the tainted
        # ref-splice isn't a coincidental string in a deploy comment.
        if "actions/checkout" not in content:
            return []
        # Shell-running ``run:`` body anywhere in the file.
        if not _PSE6_SHELL_RUN_RE.search(content):
            return []
        # Write-token signal: either an explicit write-permission
        # token, or no ``permissions`` key at all.  In the
        # ``whitespace_pad`` mutant, ``permissions:contents:write``
        # collapses to a single scalar but the substring is preserved.
        has_write_permission = bool(
            re.search(
                r"permissions?\s*:?\s*(?:write-all|write\b|contents\s*:?\s*write|"
                r"pull-requests\s*:?\s*write)",
                content,
                re.IGNORECASE,
            )
        )
        no_permissions_block = "permissions" not in content.lower()
        if not (has_write_permission or no_permissions_block):
            return []
        # Cite the line carrying the tainted splice — same anchor
        # rationale as the structural path.
        for i, line in enumerate(lines, 1):
            if _PSE6_TAINTED_REF_RE.search(line) or _PSE6_TAINTED_REPO_RE.search(line):
                return [(i, line.strip())]
        # Defensive: a finding was deserved but no line carried the
        # splice; fall back to the first line of the file.
        return [(1, lines[0].strip() if lines else "")]

    # ------------------------------------------------------------------
    # Per-job evaluation
    # ------------------------------------------------------------------

    def _evaluate_job(
        self,
        *,
        job_leaves: list[Event],
        wf_has_permissions_block: bool,
        wf_has_write_token: bool,
        lines: list[str],
    ) -> tuple[int, str] | None:
        # (1) Job-level permissions override workflow-level.  Spec:
        #     a job-level ``permissions:`` block REPLACES the workflow
        #     default for that job, so if the job sets ``permissions:
        #     read-all`` it has no write token even if the workflow
        #     grants write.  Same logic for absence: job-level absent
        #     falls back to workflow level.
        job_permissions_leaves = [
            ev for ev in job_leaves if len(ev.path) >= 3 and ev.path[2] == "permissions"
        ]
        job_has_permissions_block = bool(job_permissions_leaves)
        if job_has_permissions_block:
            has_write_token = self._permissions_imply_write(job_permissions_leaves, root_path_len=3)
        elif wf_has_permissions_block:
            has_write_token = wf_has_write_token
        else:
            # Neither workflow- nor job-level permissions: default
            # token applies.  The default has write for the event
            # triggers this rule cares about (pull_request_target,
            # workflow_run, issue_comment).
            has_write_token = True
        if not has_write_token:
            return None

        # (2) Trusted-bot gate suppression — if the job's ``if:`` value
        #     contains an equality comparison against a known-trusted
        #     bot user, attacker-fork PRs cannot reach the job in the
        #     first place.  Mirrors the dependabot-autoapprove FP.
        if_leaf = next(
            (ev for ev in job_leaves if len(ev.path) == 3 and ev.path[2] == "if"),
            None,
        )
        if if_leaf and _PSE6_USER_GATE_RE.search(if_leaf.value or ""):
            return None

        # (3) Tainted-checkout anchor — find a step whose ``uses:`` is
        #     ``actions/checkout@*`` AND whose ``with:`` injects an
        #     attacker-fork-head reference into ``ref`` / ``repository``.
        anchor = self._find_tainted_checkout(job_leaves, lines)
        if anchor is None:
            return None

        # (4) Same-job shell run — any step in the same job whose
        #     ``run:`` body exercises a shell verb.  Position relative
        #     to the checkout does not matter: a ``run: npm install``
        #     in step 0 followed by ``actions/checkout`` with tainted
        #     ref in step 1 is the same threat shape (the install
        #     reads the checked-out package.json on a subsequent step,
        #     or the install IS the attacker-controlled code via a
        #     pre-existing fork checkout).  Keeping the in-job
        #     co-occurrence loose matches the canonical pwn_request
        #     corpus on which precision was measured.
        if not self._has_shell_run(job_leaves):
            return None

        return anchor

    # ------------------------------------------------------------------
    # Predicates
    # ------------------------------------------------------------------

    @staticmethod
    def _permissions_imply_write(perm_leaves: list[Event], *, root_path_len: int) -> bool:
        """True when the permissions block grants write on at least one
        scope.  Accepts both bare-string forms (``permissions: write-all``
        / ``permissions: write``) and per-scope block forms.

        ``root_path_len`` is the path-prefix length of the permissions
        block itself: 1 for workflow-level (``('permissions',)``), 3
        for job-level (``('jobs', <id>, 'permissions')``).  Used to
        recognise the bare-string form whose leaf path has length
        equal to ``root_path_len``.
        """
        for ev in perm_leaves:
            value = (ev.value or "").strip().strip("'\"").lower()
            if len(ev.path) == root_path_len:
                # Bare scalar form.  ``write-all`` / ``write`` →
                # workflow-wide write.  ``read-all`` / ``read`` →
                # explicitly no write.
                if value in {"write-all", "write"}:
                    return True
                continue
            # Per-scope form: ``permissions.<scope>: <level>``.
            if value == "write":
                return True
        return False

    @staticmethod
    def _find_tainted_checkout(job_leaves: list[Event], lines: list[str]) -> tuple[int, str] | None:
        """Return the (line, snippet) anchor for a step that checks out
        a fork-attacker-controlled ref.  None if no such step exists.

        A step satisfies the predicate when BOTH hold:
          * its ``uses:`` value matches ``actions/checkout@<ref>``
          * one of its ``with:`` sub-keys (``ref`` / ``repository``)
            splices ``github.event.pull_request.head.{ref,sha}`` or
            ``head.repo.full_name``
        """
        # Bucket leaves by step index using two parallel typed maps
        # — keeps the mypy story clean (no ``dict[str, object]``)
        # and the access pattern direct.
        step_uses: dict[int, str] = {}
        step_with: dict[int, dict[str, tuple[str, int]]] = {}
        for ev in job_leaves:
            p = ev.path
            if not (len(p) >= 5 and p[2] == "steps" and isinstance(p[3], int)):
                continue
            step_i = p[3]
            if p[4] == "uses" and len(p) == 5 and ev.value:
                step_uses[step_i] = ev.value
            elif p[4] == "with" and len(p) >= 6 and isinstance(p[5], str):
                step_with.setdefault(step_i, {})[p[5]] = (ev.value or "", ev.line)

        for step_i in sorted(step_uses.keys()):
            if not step_uses[step_i].startswith("actions/checkout@"):
                continue
            with_map = step_with.get(step_i)
            if not with_map:
                continue
            for slot_name, (value, line_no) in with_map.items():
                if slot_name == "ref" and _PSE6_TAINTED_REF_RE.search(value):
                    snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else value
                    return (line_no, snippet)
                if slot_name == "repository" and _PSE6_TAINTED_REPO_RE.search(value):
                    snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else value
                    return (line_no, snippet)
        return None

    @staticmethod
    def _has_shell_run(job_leaves: list[Event]) -> bool:
        """True if any step in the job has a ``run:`` body matching
        ``_PSE6_SHELL_RUN_RE``."""
        for ev in job_leaves:
            p = ev.path
            if len(p) == 5 and p[2] == "steps" and isinstance(p[3], int) and p[4] == "run":
                value = ev.value or ""
                # Block-scalar bodies may carry multiple lines: the
                # walker emits them either inline or via ``block_lines``;
                # check both representations through a substring search
                # on the flattened value.
                if _PSE6_SHELL_RUN_RE.search(value):
                    return True
        return False


RULES.append(
    Rule(
        id="PSE-GH-006",
        title="Tokened checkout of fork PR head + shell run = RCE",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-1",
        description=(
            "A workflow runs on a fork-reachable, write-context trigger "
            "(``pull_request_target``, ``workflow_run`` chained off a PR-"
            "context build, or ``issue_comment`` carrying ``pull-requests: "
            "write``) and a job inside the workflow combines four further "
            "ingredients into a single executable RCE chain: "
            "(a) a write-capable token — either an explicit ``permissions: "
            "write-all`` / ``contents: write`` / ``pull-requests: write`` "
            "grant, or no ``permissions:`` block at all (in which case the "
            "default ``GITHUB_TOKEN`` for these triggers is write-capable); "
            "(b) an ``actions/checkout`` step that splices the attacker's "
            "fork head into ``ref`` / ``repository`` via "
            "``github.event.pull_request.head.{ref,sha}`` or "
            "``github.event.pull_request.head.repo.full_name``; "
            "(c) a later step in the SAME job whose ``run:`` body executes "
            "fork-controlled code through a shell (``npm install``, "
            "``npm run`` / ``test`` / ``build``, ``make``, ``go test``, "
            "``cargo`` …); "
            "(d) NO job-level ``if:`` gate that restricts execution to a "
            "trusted-bot ``user.login`` "
            "(``dependabot[bot]``, ``renovate[bot]``, ``github-actions[bot]``, "
            "``pre-commit-ci[bot]``). "
            "When all five hold, every fork-PR opener has a one-shot RCE "
            "primitive on the host repository while holding its write "
            "token — they can commit to ``main``, mint releases, publish "
            "packages, or trade GITHUB_TOKEN for any OIDC role the workflow "
            "can assume. "
            "Three canonical pwn_request shapes drove the design: "
            "(1) ``deployment_victim`` — ``pull_request_target`` + a "
            "deployment workflow that needs ``contents: write`` to push "
            "build artifacts; "
            "(2) ``label_victim`` — ``pull_request_target`` gated on the "
            "known-weak ``safe-to-test`` label (the label itself is "
            "attacker-suggestible via the maintainer who reviews the PR); "
            "(3) ``workflow_run_chain`` — a ``workflow_run`` listener that "
            "checks out the fork-head from the triggering PR build. "
            "The trusted-bot ``if:`` gate is the only ``if:`` shape that "
            "structurally excludes fork-PR reachability: dependabot / "
            "renovate / github-actions / pre-commit-ci PRs come from the "
            "host repo's own bot accounts, never from external forks."
        ),
        pattern=_Pse006Pattern(),
        remediation=(
            "PSE-GH-006 is a 5-ingredient chain.  Remove ANY one ingredient\n"
            "to break the RCE primitive:\n"
            "  1. Drop the tainted checkout.  In a ``pull_request_target``\n"
            "     workflow, never check out ``github.event.pull_request.head.\n"
            "     {ref,sha}`` — use the base ref (``github.sha``) for repo-\n"
            "     trusted code, and run fork-PR code in a SEPARATE\n"
            "     ``pull_request`` workflow that has no write token.\n"
            "  2. Remove the write token.  Add ``permissions:\\n  contents:\n"
            "     read\\n  pull-requests: read`` at the workflow level.\n"
            "  3. Gate the job on same-repo identity:\n"
            "     ``if: github.event.pull_request.head.repo.full_name ==\n"
            "       github.repository`` — same-repo PRs only, fork PRs\n"
            "     short-circuit before the tainted steps run.\n"
            "  4. Replace the shell ``run:`` with a no-shell action that\n"
            "     consumes the fork-head as plain data (artifact upload,\n"
            "     diff comment, build-status post — no install / run /\n"
            "     test verbs).\n"
            "  5. Move the trusted-bot equality gate inwards: an explicit\n"
            "     ``if: github.event.pull_request.user.login ==\n"
            "       'dependabot[bot]'`` (or one of the other three\n"
            "     trusted bots) means no fork PR can reach the job.\n"
            "Run ``taintly --guide PSE-GH-006`` for the full checklist."
        ),
        reference=(
            "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/; "
            "https://github.com/actions/runner/issues/2347"
        ),
        test_positive=[
            # (1) ActionsTOCTOU deployment_victim shape — pull_request_target
            # with a write-context trigger, contents: write, tainted ref
            # checkout, npm install in a later step.
            (
                "on: pull_request_target\n"
                "permissions:\n  contents: write\n"
                "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
                "      - run: npm install\n"
                "      - run: npm run build\n"
            ),
            # (2) ActionsTOCTOU label_victim shape — pull_request_target
            # with the known-weak ``safe-to-test`` label gate, tainted
            # ref checkout, make-driven build.  Label gates do NOT
            # qualify as trusted-bot user.login gates, so the rule fires.
            (
                "on:\n  pull_request_target:\n    types: [labeled]\n"
                "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
                "    if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')\n"
                "    permissions:\n      contents: write\n    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "        with:\n          ref: ${{ github.event.pull_request.head.ref }}\n"
                "      - run: make test\n"
            ),
            # (3) workflow_run chain with default token, tainted repo
            # checkout, shell-driven test runner.
            (
                "on:\n  workflow_run:\n    workflows: [Build]\n    types: [completed]\n"
                "jobs:\n  rerun:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "        with:\n"
                "          repository: ${{ github.event.pull_request.head.repo.full_name }}\n"
                "      - run: go test ./...\n"
            ),
        ],
        test_negative=[
            # (1) dependabot-autoapprove shape — canonical FP.  Same
            # pwn_request anatomy but the trusted-bot gate makes
            # attacker-fork PRs unreachable.
            (
                "on: pull_request_target\n"
                "permissions:\n  contents: write\n  pull-requests: write\n"
                "jobs:\n  autoapprove:\n    runs-on: ubuntu-latest\n"
                "    if: github.actor == 'dependabot[bot]'\n    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
                "      - run: npm install\n"
                "      - run: npm test\n"
            ),
            # (2) Same anatomy but ``pull_request`` (not ``pull_request_target``).
            # The default token for ``pull_request`` from a fork is READ-ONLY,
            # so there is no write-token RCE primitive even if every other
            # ingredient is present.
            (
                "on: pull_request\n"
                "permissions:\n  contents: write\n"
                "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
                "      - run: npm install\n"
                "      - run: npm test\n"
            ),
            # (3) Same anatomy but the job is gated on a non-bot actor —
            # ``maintainer`` is not on the trusted-bot allowlist, but
            # ``github.actor == '<literal-username>'`` IS a user-gate
            # restriction (fork PRs can't satisfy it because the actor
            # is the PR opener, not a maintainer).  We model the user
            # gate by mirroring the bot-allowlist shape: any
            # ``user.login`` / ``github.actor`` equality against a
            # literal string restricts reachability.  For PSE-GH-006
            # we treat ALL such equalities as restrictive — bot or not.
            (
                "on: pull_request_target\n"
                "permissions:\n  contents: write\n"
                "jobs:\n  scoped:\n    runs-on: ubuntu-latest\n"
                "    if: github.actor == 'maintainer'\n    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
                "      - run: npm install\n"
            ),
        ],
        stride=["E", "T", "I"],
        threat_narrative=(
            "An external contributor opens a fork PR.  The host workflow "
            "runs in the host repo's privilege context (``pull_request_"
            "target`` / ``workflow_run`` / ``issue_comment``) with a "
            "write-capable ``GITHUB_TOKEN``, checks out the attacker's "
            "fork-head, and immediately executes attacker-controlled code "
            "via ``npm install`` (lifecycle scripts), ``make`` (Makefile "
            "rules), or any similar shell-running build step.  The "
            "attacker-supplied code inherits the workflow's write token "
            "and can push to ``main``, publish releases, exfiltrate "
            "secrets via repo-write side channels, or trade the token "
            "for any OIDC role the workflow can assume."
        ),
        confidence="high",
        review_needed=False,
        incidents=[
            # ActionsTOCTOU pwn_request corpus — deployment_victim,
            # label_victim shapes; documented at
            # https://github.com/AdnaneKhan/ActionsTOCTOU
            "https://github.com/AdnaneKhan/ActionsTOCTOU",
        ],
    )
)
