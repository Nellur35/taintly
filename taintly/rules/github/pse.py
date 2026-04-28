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

from taintly.models import ContextPattern, Platform, Rule, Severity
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
