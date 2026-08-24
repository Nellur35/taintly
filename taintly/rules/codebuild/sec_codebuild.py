"""AWS CodeBuild (buildspec.yml) security rules.

This module scans buildspec YAML. CodeBuild project definitions remain out of scope because IAM roles, privileged mode, VPC settings, and webhook filters are not visible in a buildspec.

Rules map to the OWASP CI/CD Top 10 (``owasp_cicd``) using the same
``SEC<n>-CB-0XX`` numbering convention GH/GL/JK already use.
"""

import re

from taintly.models import Platform, Rule, Severity

# ---------------------------------------------------------------------------
# SEC6-CB-001 — plaintext secret-shaped name in buildspec env.variables
# ---------------------------------------------------------------------------
# AWS's own buildspec reference states env.variables "can be displayed in
# plain text using tools such as the CodeBuild console and the AWS CLI" and
# explicitly recommends parameter-store/secrets-manager instead for
# sensitive values (docs.aws.amazon.com/codebuild/latest/userguide/
# build-spec-ref.html). A key name matching a credential-shaped suffix bound
# directly under env.variables (never under the sibling parameter-store:/
# secrets-manager: blocks, which hold references, not values) is a
# plaintext-credential exposure.

_ENV_KEY_RE = re.compile(r"^(\s*)env\s*:\s*(?:#.*)?$")
_VARIABLES_KEY_RE = re.compile(r"^(\s*)variables\s*:\s*(?:#.*)?$")
_KEY_LINE_RE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$")

# Suffix-anchored so a merely-descriptive name (TOKEN_ENDPOINT_URL,
# PASSWORD_POLICY_ARN) doesn't match — only a name that itself LOOKS LIKE
# the secret binding does. Covers AWS_SECRET_ACCESS_KEY (ends _ACCESS_KEY)
# and GCP/Azure-style *_CREDENTIALS names alongside the threat model's
# explicit list.
_CREDENTIAL_SUFFIX_RE = re.compile(
    r"(?i)(?:^|_)(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIALS)$"
)


class _PlaintextSecretInEnvVariablesPattern:
    """Fire on a credential-shaped key bound directly under ``env.variables``.

    Only walks lines nested under a confirmed ``env: -> variables:`` block
    (verified by walking backward from each ``variables:`` line to its
    nearest shallower-indented ancestor). The sibling ``parameter-store:``/
    ``secrets-manager:`` blocks hold key aliases / ARNs, not plaintext
    values, and are never visited — this is the primary false-positive
    guard the threat model calls for (a credential-shaped name used as
    a parameter-store *key* alias must not fire).
    """

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        n = len(lines)
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if not _VARIABLES_KEY_RE.match(line):
                continue
            variables_indent = len(line) - len(line.lstrip(" "))

            # Confirm the nearest shallower-indented, non-blank, non-comment
            # ancestor line is `env:` — otherwise this `variables:` isn't
            # the one buildspec cares about.
            parent_is_env = False
            for j in range(i - 1, -1, -1):
                prev = lines[j]
                prev_stripped = prev.strip()
                if not prev_stripped or prev_stripped.startswith("#"):
                    continue
                prev_indent = len(prev) - len(prev.lstrip(" "))
                if prev_indent < variables_indent:
                    parent_is_env = bool(_ENV_KEY_RE.match(prev))
                    break
            if not parent_is_env:
                continue

            # Walk forward collecting this block's key: lines until dedent.
            for j in range(i + 1, n):
                nxt = lines[j]
                nxt_stripped = nxt.strip()
                if not nxt_stripped:
                    continue
                nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                if nxt_indent <= variables_indent:
                    break
                if nxt_stripped.startswith("#"):
                    continue
                key_m = _KEY_LINE_RE.match(nxt)
                if not key_m:
                    continue
                key_name = key_m.group(2)
                if _CREDENTIAL_SUFFIX_RE.search(key_name):
                    results.append((j + 1, nxt.strip()))
        return results


# ---------------------------------------------------------------------------
# SEC3-CB-001 — curl/wget piped directly to a shell interpreter
# ---------------------------------------------------------------------------
# No shared cross-platform helper exists for this pattern: GitHub
# (sec1_sec5_sec6_sec7_sec9.py), GitLab (SEC6-GL-002), and Jenkins
# (SEC9-JK-001/004, structural) each independently reimplement their own
# curl-pipe regex tuned to that platform's syntax rather than calling a
# shared function/class. "Reuse" here means porting the same PATTERN SHAPE
# (GitHub's most complete version: curl|wget piped to an interpreter,
# `bash <(curl ...)` process substitution, and the PowerShell
# `iex(Invoke-WebRequest ...)` equivalent for Windows CodeBuild images),
# not a shared code object — this is itself the finding the design notes
# asked this task to check for.
_SEC3_CB_001_RE = (
    # Interpreter names need a trailing \b so `sh`/`bash` don't prefix-match
    # longer identifiers piped from the same command (`| sha256sum -c -`,
    # `| shellcheck`, `| shasum` are legitimate integrity/lint tools, not
    # shell invocations — confirmed false-fire without the boundary).
    # `python` is split out since `\b` alone would reject `python3` (both
    # `n` and `3` are word characters, so there's no boundary between them)
    # — `python[23]?\b` allows the bare/2/3 forms without opening the door
    # to arbitrary python-prefixed identifiers.
    r"(?:curl|wget)\s+[^|\n#]*\|\s*(?:(?:bash|sh|zsh|fish|perl|ruby|node)\b|python[23]?\b)"
    r"|bash\s*<\s*\(\s*(?:curl|wget)"
    r"|(?i:iex)\s*\(\s*(?:Invoke-WebRequest|iwr)\b"
    r"|(?:curl|wget)\s+[^|\n#]*\|\s*python\s+-c\s+['\"]"
)


# ---------------------------------------------------------------------------
# SEC6-CB-002 — secret bound via parameter-store/secrets-manager run through
# an encode/obfuscate transform (the CodeBuild log-masking bypass).
# ---------------------------------------------------------------------------
# Empirically confirmed against a live AWS CodeBuild build (2026-08-03, real
# account, torn down after): a parameter-store-bound value echoed directly
# appeared in the build log as `direct=***` (masked), but the SAME value
# piped through `base64` appeared as the plaintext value, base64-encoded,
# fully decodable. AWS's own buildspec reference states masking "matches the
# exact value stored" and that a transformed secret is NOT masked. Mirrors
# SEC6-JK-011's design shape: key on the TRANSFORM applied to a bound-secret
# variable, never on "a secret reaches a sink" generally — a bound secret
# passed unmodified to an authenticated sink (`curl --user "$VAR"`) is the
# dominant legitimate shape and must stay clean.
#
# Unlike env.variables (SEC6-CB-001, where the KEY NAME's shape is the
# signal since the value itself is plaintext already), every key under
# parameter-store:/secrets-manager: IS a real secret reference regardless of
# its own name — so this rule collects ALL keys under those two blocks, not
# just credential-shaped ones.
_PS_OR_SM_KEY_RE = re.compile(r"^(\s*)(?:parameter-store|secrets-manager)\s*:\s*(?:#.*)?$")
_PRIVATE_OUTPUT_REDIRECT_RE = re.compile(
    r"(?<!\d)>{1,2}\s*(?!&[12]\b|/dev/(?:stdout|stderr)\b)[^\s|;&]+"
)

_MASKING_BYPASS_TRANSFORM_RE = re.compile(
    r"(?:"
    # base64 ENCODE (no -d / --decode flag anywhere before the next pipe/
    # semicolon) — the masking-bypass direction. precision review found
    # the original `(?!\s+(?:-d\b|--decode\b))` only checked the FIRST flag
    # position, so `base64 -w0 -d` (decode flag not first) was misread as
    # an encode. `[^|;\n]*` scans the rest of that command segment (up to
    # the next pipe/semicolon/newline) for a `-d`/`--decode` flag anywhere
    # in it, not just immediately after the command name.
    r"\bbase64\b(?![^|;\n]*\s(?:-d\b|--decode\b))"
    # byte/hex obfuscators.
    r"|\bxxd\b|\bod\b|\bhexdump\b"
    # reverse — classic two-echo masking dodge.
    r"|\brev\b"
    # tr-based transliteration / ROT.
    r"|\btr\s+['\"]?[A-Za-z0-9]"
    # openssl symmetric ENCODE (exclude the -d decrypt direction).
    r"|\bopenssl\s+enc\b(?![^|\n]*\s-d\b)"
    # gpg symmetric / asymmetric encrypt of the secret.
    r"|\bgpg\b[^|\n]*(?:-c\b|--symmetric\b|-e\b|--encrypt\b)"
    r")"
)


def _collect_bound_secret_vars(lines: list[str]) -> frozenset[str]:
    """Key names bound under ``env.parameter-store:`` / ``env.secrets-manager:``.

    Unlike ``env.variables:``, every key here IS a real secret reference —
    the value is a Parameter Store name or Secrets Manager ARN/name, never
    the plaintext itself — so no name-shape filter is needed, just block
    membership (verified the same way SEC6-CB-001 confirms `variables:`'s
    parent is `env:`: walk backward to the nearest shallower-indented,
    non-blank, non-comment ancestor line).
    """
    names: set[str] = set()
    n = len(lines)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not _PS_OR_SM_KEY_RE.match(line):
            continue
        block_indent = len(line) - len(line.lstrip(" "))

        parent_is_env = False
        for j in range(i - 1, -1, -1):
            prev = lines[j]
            prev_stripped = prev.strip()
            if not prev_stripped or prev_stripped.startswith("#"):
                continue
            prev_indent = len(prev) - len(prev.lstrip(" "))
            if prev_indent < block_indent:
                parent_is_env = bool(_ENV_KEY_RE.match(prev))
                break
        if not parent_is_env:
            continue

        for j in range(i + 1, n):
            nxt = lines[j]
            nxt_stripped = nxt.strip()
            if not nxt_stripped:
                continue
            nxt_indent = len(nxt) - len(nxt.lstrip(" "))
            if nxt_indent <= block_indent:
                break
            if nxt_stripped.startswith("#"):
                continue
            key_m = _KEY_LINE_RE.match(nxt)
            if key_m:
                names.add(key_m.group(2))
    return frozenset(names)


class _SecretMaskingBypassPattern:
    """Fire when a ``parameter-store``/``secrets-manager``-bound variable is
    run through an encode/obfuscate transform on the same command line.

    Same-line co-occurrence (transform token + a reference to a collected
    bound-secret variable) is the precision device, mirroring SEC6-JK-011's
    same-shell-body requirement — adapted to a line grain rather than a
    parsed shell-body grain, since buildspec.yml has no structural shell
    parser and its ``commands:`` entries are conventionally one command per
    YAML list item (unlike Jenkins' multi-line triple-quoted ``sh`` blocks).
    A command deliberately split across a YAML block-scalar spanning
    multiple physical lines is a known v1 gap, not handled here.

    Variable-reference matching requires a word boundary between the
    variable name and an optional closing ``}`` — placing ``\\b`` after the
    optional ``\\}?`` would never match, since a non-word char (``}``)
    followed by another non-word char (space/quote) has no boundary between
    them.
    """

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if "parameter-store" not in content and "secrets-manager" not in content:
            return []
        cred_vars = _collect_bound_secret_vars(lines)
        if not cred_vars:
            return []
        var_res = [re.compile(r"\$\{?" + re.escape(v) + r"\b\}?") for v in cred_vars]
        results: list[tuple[int, str]] = []
        for start, end in _phases_commands_line_ranges(lines):
            for i in range(start, end):
                stripped = lines[i].strip()
                if not stripped or stripped.startswith("#"):
                    continue
                command = stripped[1:].lstrip() if stripped.startswith("-") else stripped
                code = _strip_shell_comment(command)
                transform = _MASKING_BYPASS_TRANSFORM_RE.search(code)
                if transform is None:
                    continue
                if not any(vr.search(code) for vr in var_res):
                    continue
                if _PRIVATE_OUTPUT_REDIRECT_RE.search(code, transform.end()):
                    continue
                results.append((i + 1, stripped))
        return results


# ---------------------------------------------------------------------------
# THEATRE-CB-001 — security/quality-gate phase configured on-failure: CONTINUE
# ---------------------------------------------------------------------------
# AWS's buildspec reference defines `on-failure: CONTINUE` as "continue to
# the next phase" even after a command in this phase fails (default/ABORT
# stops the build). A phase whose commands look like a security or quality
# gate (a scanner or test-runner invocation) configured to CONTINUE on
# failure can fail and the build proceeds anyway — the same "check exists
# but cannot block" shape as THEATRE-GH-001/GL-001 (conceptual precedent;
# those detect a *vacuous* runner via corpus discovery-convention analysis,
# a different mechanism than this rule needs, since `on-failure` is a
# single-file YAML flag, not a cross-file discovery question).
#
# Footnote: AWS's docs note `on-failure` "is not supported when using Lambda
# compute or reserved capacity" — buildspec.yml alone can't tell which
# compute type a project uses, so this is an accuracy note, not an FP guard.
_PHASE_NAME_RE = re.compile(r"^(\s*)(install|pre_build|build|post_build)\s*:\s*(?:#.*)?$")
_PHASE_ORDER = {"install": 0, "pre_build": 1, "build": 2, "post_build": 3}
_ON_FAILURE_CONTINUE_RE = re.compile(
    r"^\s*on-failure\s*:\s*['\"]?CONTINUE['\"]?\s*(?:#.*)?$", re.IGNORECASE
)

# Deliberately narrow, documented list of security-scanner / test-runner
# names — the threat model's own examples (npm audit, bandit, trivy,
# snyk, test suites) plus the other platforms' equivalent tool sets. An
# ordinary build/cleanup/notify command must never match this list; that is
# the primary false-positive guard (a legitimately optional phase — e.g. a
# best-effort cleanup or Slack notification — configured CONTINUE is NOT
# flagged, since its commands never match this list).
#
# `(?![-.])` after the closing `\b` — precision review found a bare `\b`
# lets the keyword prefix-match a longer hyphen/dot-joined identifier, since
# `-`/`.` are non-word characters and already satisfy a plain `\b`:
# `aws s3 cp bandit-report.json s3://...` matched `\bbandit\b`. Blocking an
# immediately-following `-` or `.` excludes report/artifact filenames
# (`bandit-report.json`, `trivy.txt`) while still matching the tool
# invoked as its own shell token.
_SECURITY_GATE_KEYWORDS_RE = re.compile(
    r"(?i)\b(?:npm\s+audit|bandit|trivy|snyk|semgrep|checkov|tfsec|grype|"
    r"gitleaks|trufflehog|pytest|go\s+test|npm\s+test|jest|mocha|vitest|"
    r"rspec)\b(?![-.])"
)


class _TheatreOnFailureContinuePattern:
    """Fire when a phase mixing a security/quality-gate-shaped command with
    ``on-failure: CONTINUE`` means that gate can fail and the build proceeds
    anyway.

    Walks each ``phases.<name>`` block; within it, both an
    ``on-failure: CONTINUE`` line and at least one line matching the
    security-gate keyword list must be present (order-independent — AWS
    does not require ``on-failure`` before ``commands``). A phase with only
    ``on-failure: CONTINUE`` (no gate-shaped command) is not flagged; a
    phase with a gate-shaped command but the default/ABORT behavior is not
    flagged.
    """

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        n = len(lines)
        configured_phases = {
            match.group(2) for line in lines if (match := _PHASE_NAME_RE.match(line)) is not None
        }
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            phase_match = _PHASE_NAME_RE.match(line)
            if phase_match is None:
                continue
            phase_name = phase_match.group(2)
            phase_indent = len(line) - len(line.lstrip(" "))

            continue_line_no: int | None = None
            has_gate_command = False
            for j in range(i + 1, n):
                nxt = lines[j]
                nxt_stripped = nxt.strip()
                if not nxt_stripped:
                    continue
                nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                if nxt_indent <= phase_indent:
                    break
                if nxt_stripped.startswith("#"):
                    continue
                if _ON_FAILURE_CONTINUE_RE.match(nxt):
                    continue_line_no = j + 1
                # Strip a trailing `# comment` before keyword-matching —
                # precision review found `- make scan  # wraps trivy`
                # false-fired since the comment text was never excluded.
                elif _SECURITY_GATE_KEYWORDS_RE.search(nxt.split("#", 1)[0]):
                    has_gate_command = True

            has_later_phase = any(
                _PHASE_ORDER[name] > _PHASE_ORDER[phase_name] for name in configured_phases
            )
            if continue_line_no is not None and has_gate_command and has_later_phase:
                results.append((continue_line_no, lines[continue_line_no - 1].strip()))
        return results


# ---------------------------------------------------------------------------
# SEC3-CB-002 — floating/unpinned runtime-versions
# ---------------------------------------------------------------------------
# AWS recommends specifying a runtime version to avoid inheriting default-version changes. Floating .x and latest values remain mutable supply-chain inputs. A `.x` major-version pin or the literal
# `latest` is itself a "specified" value that still floats across minor/
# patch (or, for `latest`, major) releases over time — the same moving-
# target supply-chain shape as an unpinned action tag (SEC3-GH-*) or an
# unpinned GitLab `include:` ref (SEC3-GL-*).
#
# `runtime-versions` values can be env-var indirection (e.g.
# `ruby: "$MY_RUBY_VAR"`) — neither a floating nor a pinned literal, and
# indeterminate from this file alone. Treated as silently indeterminate
# (skipped, no fire), never as a crash or a false floating-version match.
_INSTALL_KEY_RE = re.compile(r"^(\s*)install\s*:\s*(?:#.*)?$")
_RUNTIME_VERSIONS_KEY_RE = re.compile(r"^(\s*)runtime-versions\s*:\s*(?:#.*)?$")
_FLOATING_DOT_X_RE = re.compile(r"^\d+(?:\.\d+)*\.x$", re.IGNORECASE)
_LATEST_RE = re.compile(r"^latest$", re.IGNORECASE)


def _strip_value_quotes(value: str) -> str:
    value = value.split("#", 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


class _FloatingRuntimeVersionPattern:
    """Fire on a ``.x``-suffixed or ``latest`` value under
    ``phases.install.runtime-versions``.

    Confirms the nearest shallower-indented, non-blank, non-comment
    ancestor of ``runtime-versions:`` is ``install:`` — the same backward-
    walk FP guard ``_PlaintextSecretInEnvVariablesPattern`` uses to confirm
    ``variables:``'s parent is ``env:`` — so an unrelated ``runtime-
    versions``-named key elsewhere in the file is never visited. Env-var
    indirection (a value starting with ``$``) is skipped as indeterminate,
    never flagged and never mistaken for a floating-version literal.
    """

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        n = len(lines)
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if not _RUNTIME_VERSIONS_KEY_RE.match(line):
                continue
            block_indent = len(line) - len(line.lstrip(" "))

            parent_is_install = False
            for j in range(i - 1, -1, -1):
                prev = lines[j]
                prev_stripped = prev.strip()
                if not prev_stripped or prev_stripped.startswith("#"):
                    continue
                prev_indent = len(prev) - len(prev.lstrip(" "))
                if prev_indent < block_indent:
                    parent_is_install = bool(_INSTALL_KEY_RE.match(prev))
                    break
            if not parent_is_install:
                continue

            for j in range(i + 1, n):
                nxt = lines[j]
                nxt_stripped = nxt.strip()
                if not nxt_stripped:
                    continue
                nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                if nxt_indent <= block_indent:
                    break
                if nxt_stripped.startswith("#"):
                    continue
                key_m = _KEY_LINE_RE.match(nxt)
                if not key_m:
                    continue
                raw_value = _strip_value_quotes(key_m.group(3))
                if not raw_value or raw_value.startswith("$"):
                    continue
                if _LATEST_RE.match(raw_value) or _FLOATING_DOT_X_RE.match(raw_value):
                    results.append((j + 1, nxt.strip()))
        return results


# ---------------------------------------------------------------------------
# LOTP-CB-001 — build-tool install without integrity flags
# ---------------------------------------------------------------------------
# A buildspec cannot reveal whether the CodeBuild project accepts external or fork-authored source; that context lives in the project definition. This context-free posture check is therefore low confidence and review-needed. Promote it only when reliable context or labeled precision evidence supports stronger confidence.
_LOTP_CB_001_RE = re.compile(
    # yarn requires an explicit install/add subcommand — precision review
    # found the earlier optional-subcommand form (`yarn(?:\s+...)?\b`) fires
    # on the bare `yarn` token anywhere: a `cache.key: yarn-$(codebuild-hash-
    # files yarn.lock)` line, `yarn.lock`/`.yarn-cache` entries under
    # `artifacts.files`/`cache.paths`, and `yarn run build`/`test`/`lint`.
    # This is the exact "FP-audit Class B" shape `_build_tools.py` already
    # documents (its own guarded fragment excludes `.yarn-cache`/`yarn.lock`
    # via lookaround, but ALSO allows a bare `run|build|test` subcommand,
    # broader than this rule's "install-type invocation only" scope) —
    # LOTP-JK-005's context-free sibling instead simply REQUIRES the
    # subcommand (`yarn\s+(?:install|add)`), which is the correct precedent
    # to mirror here since this rule has no PR-context gate of its own to
    # lean on.
    r"\b(?:npm\s+(?:install|ci|i)\b|yarn\s+(?:global\s+)?(?:install|add)\b|pnpm\s+(?:install|i|add)\b)"
    r"|\bpip[23]?\s+install\b"
)


# ---------------------------------------------------------------------------
# SEC4-CB-001 — webhook-derived value passed to a second shell evaluation
# ---------------------------------------------------------------------------
# Ordinary parameter expansion is not reparsed as shell syntax: metacharacters
# produced by ``$VAR`` remain data. A real command-injection sink appears only
# when the expanded value becomes shell source again, such as ``eval "$VAR"``
# or ``bash -c "$VAR"``. AWS documents webhook refs as branch/tag references
# and pull-request source versions as ``pr/<number>``; plain use remains clean.
_WEBHOOK_VAR_RE = re.compile(
    r"\$\{?(CODEBUILD_WEBHOOK_HEAD_REF|CODEBUILD_SOURCE_VERSION"
    r"|CODEBUILD_WEBHOOK_BASE_REF|CODEBUILD_WEBHOOK_TRIGGER)\b\}?"
)
_SECOND_EVAL_RE = re.compile(r"(?:^|[;&|])\s*eval\b")
_SHELL_HEAD_RE = re.compile(r"(?:^|[;&|])\s*(?:bash|dash|ksh|sh|zsh)\b")
_SHELL_OPTION_TERMINATOR = "--"
_ENV_EXECUTABLE = "env"


def _iter_shell_c_sinks(code: str, stop: int) -> list[tuple[int, int]]:
    """Return shell-command starts and the end of their ``-c`` option."""
    sinks: list[tuple[int, int]] = []
    for head in _SHELL_HEAD_RE.finditer(code, 0, stop):
        cursor = head.end()
        while cursor < stop:
            while cursor < stop and code[cursor].isspace():
                cursor += 1
            if cursor >= stop or code[cursor] != "-":
                break
            token_end = cursor + 1
            while token_end < stop and not code[token_end].isspace():
                token_end += 1
            token = code[cursor:token_end]
            if token == _SHELL_OPTION_TERMINATOR:
                break
            if not token.startswith("--") and "c" in token[1:]:
                sinks.append((head.start(), token_end))
                break
            cursor = token_end
    return sinks


_COMMANDS_KEY_RE = re.compile(r"^(\s*)commands\s*:\s*(?:#.*)?$")


def _phases_commands_line_ranges(lines: list[str]) -> list[tuple[int, int]]:
    """0-based half-open ``(start, end)`` line ranges covering every
    ``phases.<name>.commands:`` list body — the only structural sink
    SEC4-CB-001 is scoped to.

    A ``commands:`` block whose nearest shallower-indented, non-blank,
    non-comment ancestor line isn't a recognised phase name (``install``/
    ``pre_build``/``build``/``post_build``) is not a shell-command sink and
    is excluded — mirrors the single-level backward-walk convention every
    other pattern in this module uses (e.g.
    ``_PlaintextSecretInEnvVariablesPattern`` confirming ``variables:``'s
    parent is exactly ``env:``).
    """
    ranges: list[tuple[int, int]] = []
    n = len(lines)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not _COMMANDS_KEY_RE.match(line):
            continue
        commands_indent = len(line) - len(line.lstrip(" "))

        parent_is_phase = False
        for j in range(i - 1, -1, -1):
            prev = lines[j]
            prev_stripped = prev.strip()
            if not prev_stripped or prev_stripped.startswith("#"):
                continue
            prev_indent = len(prev) - len(prev.lstrip(" "))
            if prev_indent < commands_indent:
                parent_is_phase = bool(_PHASE_NAME_RE.match(prev))
                break
        if not parent_is_phase:
            continue

        end = n
        for j in range(i + 1, n):
            nxt = lines[j]
            nxt_stripped = nxt.strip()
            if not nxt_stripped:
                continue
            nxt_indent = len(nxt) - len(nxt.lstrip(" "))
            if nxt_indent <= commands_indent:
                end = j
                break
        ranges.append((i + 1, end))
    return ranges


class _DownloadedScriptExecutionPattern:
    """Match remote-script execution only in executable phase commands."""

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        regex = re.compile(_SEC3_CB_001_RE)
        for start, end in _phases_commands_line_ranges(lines):
            for index in range(start, end):
                stripped = lines[index].strip()
                if not stripped or stripped.startswith("#"):
                    continue
                command = stripped[1:].lstrip() if stripped.startswith("-") else stripped
                if regex.search(_strip_shell_comment(command)):
                    results.append((index + 1, stripped))
        return results


def _is_quoted_at(text: str, position: int, quote: str) -> bool:
    """Return whether ``position`` is inside a simple shell quote span."""
    escaped = False
    opened = False
    for char in text[:position]:
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote == '"':
            escaped = True
            continue
        if char == quote:
            opened = not opened
    return opened


def _strip_shell_comment(command: str) -> str:
    """Strip a real shell comment while preserving quoted hash bytes."""
    single = False
    double = False
    escaped = False
    for index, char in enumerate(command):
        if escaped:
            escaped = False
            continue
        if char == "\\" and not single:
            escaped = True
            continue
        if char == "'" and not double:
            single = not single
            continue
        if char == '"' and not single:
            double = not double
            continue
        if (
            char == "#"
            and not single
            and not double
            and (index == 0 or command[index - 1].isspace())
        ):
            return command[:index]
    return command


def _command_segment_start(code: str, position: int) -> int:
    """Return the start of the shell command segment containing the position."""
    single = False
    double = False
    escaped = False
    start = 0
    for index, char in enumerate(code[:position]):
        if escaped:
            escaped = False
            continue
        if char == "\\" and not single:
            escaped = True
            continue
        if char == "'" and not double:
            single = not single
            continue
        if char == '"' and not single:
            double = not double
            continue
        if not single and not double and char in ";&|\n":
            start = index + 1
    return start


def _command_segment_end(code: str, position: int) -> int:
    """Return the end of the shell command segment containing the position."""
    single = False
    double = False
    escaped = False
    for index, char in enumerate(code):
        if escaped:
            escaped = False
            continue
        if char == "\\" and not single:
            escaped = True
            continue
        if char == "'" and not double:
            single = not single
            continue
        if char == '"' and not single:
            double = not double
            continue
        if index >= position and not single and not double and char in ";&|\n":
            return index
    return len(code)


_COMMAND_PREFIX_WORDS = frozenset(
    {
        "!",
        "if",
        "then",
        "elif",
        "else",
        "do",
        "while",
        "until",
        "command",
        "builtin",
        "exec",
        "time",
        "nohup",
    }
)
_PATH_PREFIX_CHARS = frozenset("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")


def _is_assignment_token(token: str) -> bool:
    name, separator, value = token.partition("=")
    return bool(
        separator
        and value
        and name
        and (name[0].isalpha() or name[0] == "_")
        and all(char.isalnum() or char == "_" for char in name[1:])
    )


def _is_install_command_prefix(prefix: str) -> bool:
    """Recognize bounded shell prefixes that still invoke the matched installer."""
    tokens = prefix.split()
    index = 0
    seen_env = False
    while index < len(tokens):
        token = tokens[index]
        if token in _COMMAND_PREFIX_WORDS or _is_assignment_token(token):
            index += 1
            continue
        if token == _ENV_EXECUTABLE and not seen_env:
            seen_env = True
            index += 1
            while index < len(tokens) and (
                tokens[index].startswith("-") or _is_assignment_token(tokens[index])
            ):
                index += 1
            continue
        break

    remainder = tokens[index:]
    if not remainder:
        return True
    return bool(
        len(remainder) == 1
        and remainder[0].endswith("/")
        and all(char in _PATH_PREFIX_CHARS for char in remainder[0])
    )


def _is_executed_install(code: str, match: re.Match[str]) -> bool:
    """Distinguish a command invocation from inert text passed as data."""
    for sink_start, sink_end in _iter_shell_c_sinks(code, match.start()):
        if _is_quoted_at(code, sink_start, "'") or _is_quoted_at(code, sink_start, '"'):
            continue
        span = _shell_c_command_span(code, sink_end)
        if span is not None and span[0] <= match.start() < span[1]:
            return True

    if _is_quoted_at(code, match.start(), "'") or _is_quoted_at(code, match.start(), '"'):
        return False
    prefix = code[_command_segment_start(code, match.start()) : match.start()]
    normalized_prefix = prefix.lstrip()
    return _is_install_command_prefix(normalized_prefix)


class _BuildToolInstallPattern:
    """Find install invocations only inside executable CodeBuild commands."""

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        for start, end in _phases_commands_line_ranges(lines):
            for index in range(start, end):
                stripped = lines[index].strip()
                if not stripped or stripped.startswith("#"):
                    continue
                command = stripped[1:].lstrip() if stripped.startswith("-") else stripped
                code = _strip_shell_comment(command)
                unsafe_install = False
                for match in _LOTP_CB_001_RE.finditer(code):
                    if not _is_executed_install(code, match):
                        continue
                    segment = code[
                        _command_segment_start(code, match.start()) : _command_segment_end(
                            code, match.end()
                        )
                    ]
                    mitigation = (
                        "--require-hashes"
                        if match.group(0).lstrip().startswith("pip")
                        else "--ignore-scripts"
                    )
                    if mitigation not in segment:
                        unsafe_install = True
                        break
                if unsafe_install:
                    results.append((index + 1, stripped))
        return results


def _has_unquoted_control_operator(code: str, start: int, end: int) -> bool:
    """Return whether a shell command separator occurs outside quotes."""
    single = False
    double = False
    escaped = False
    for char in code[start:end]:
        if escaped:
            escaped = False
            continue
        if char == "\\" and not single:
            escaped = True
            continue
        if char == "'" and not double:
            single = not single
            continue
        if char == '"' and not single:
            double = not double
            continue
        if not single and not double and char in ";&|\n":
            return True
    return False


def _shell_c_command_span(code: str, start: int) -> tuple[int, int, str] | None:
    """Return the first argument after ``shell -c`` as (start, end, quote)."""
    while start < len(code) and code[start].isspace():
        start += 1
    if start >= len(code):
        return None
    quote = code[start] if code[start] in "'\"" else ""
    if not quote:
        end = start
        while end < len(code) and not code[end].isspace():
            end += 1
        return start, end, quote
    end = start + 1
    escaped = False
    while end < len(code):
        char = code[end]
        if escaped:
            escaped = False
        elif char == "\\" and quote == '"':
            escaped = True
        elif char == quote:
            return start + 1, end, quote
        end += 1
    return start + 1, len(code), quote


class _SecondEvaluationWebhookRefPattern:
    """Fire only when a CodeBuild ref becomes shell source a second time.

    ``eval`` reparses all of its expanded arguments. Shell ``-c`` reparses
    only its first argument; later arguments are positional data and stay
    clean. A variable inside a single-quoted command string is expanded by
    the inner shell after parsing, so its value is not parsed as syntax.
    """

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        for start, end in _phases_commands_line_ranges(lines):
            for i in range(start, end):
                stripped = lines[i].strip()
                if not stripped or stripped.startswith("#"):
                    continue
                command = stripped[1:].lstrip() if stripped.startswith("-") else stripped
                code = _strip_shell_comment(command)
                for variable in _WEBHOOK_VAR_RE.finditer(code):
                    eval_sink = next(
                        (
                            sink
                            for sink in _SECOND_EVAL_RE.finditer(code, 0, variable.start())
                            if not _is_quoted_at(code, sink.start(), "'")
                            and not _is_quoted_at(code, sink.start(), '"')
                        ),
                        None,
                    )
                    if (
                        eval_sink is not None
                        and not _has_unquoted_control_operator(
                            code, eval_sink.end(), variable.start()
                        )
                        and not _is_quoted_at(code, variable.start(), "'")
                    ):
                        results.append((i + 1, stripped))
                        break

                    for sink_start, sink_end in _iter_shell_c_sinks(code, variable.start()):
                        if _is_quoted_at(code, sink_start, "'") or _is_quoted_at(
                            code, sink_start, '"'
                        ):
                            continue
                        span = _shell_c_command_span(code, sink_end)
                        if span is None:
                            continue
                        arg_start, arg_end, quote = span
                        if quote != "'" and arg_start <= variable.start() < arg_end:
                            results.append((i + 1, stripped))
                            break
                    else:
                        continue
                    break
        return results


# ---------------------------------------------------------------------------
# SEC9-CB-001 — overbroad artifacts.files glob (walks secondary-artifacts too)
# ---------------------------------------------------------------------------
# AWS's buildspec reference shows `artifacts.files: ['**/*']` as a real,
# common example, and it appears verbatim in aws-samples/aws-codebuild-
# samples/buildspec.yml — capturing the whole build directory recursively
# (.git/, .env, incidentally-written credential/config files) into the
# uploaded artifact, which may have broader read access than the build
# itself. Mirrors SEC9-GH-*/SEC9-GL-001/004.
#
# Maximal artifact globs are often intentional. This broad posture check starts at low confidence and review-needed; stronger confidence requires labeled precision evidence.
_ARTIFACTS_KEY_RE = re.compile(r"^(\s*)artifacts\s*:\s*(?:#.*)?$")
_FILES_KEY_RE = re.compile(r"^(\s*)files\s*:\s*(?:#.*)?$")
_MAXIMAL_GLOB_RE = re.compile(r"^(?:\*\*/\*|\*\*|\*)$")
_LIST_ITEM_RE = re.compile(r"^(\s*)-\s*(.*)$")


def _is_nested_under_artifacts(lines: list[str], idx: int, start_indent: int) -> bool:
    """True if the ``files:`` line at ``idx`` is nested (at ANY depth) under
    an ``artifacts:`` block.

    Unlike the single-level backward-walks elsewhere in this module
    (``variables:``'s parent must be exactly ``env:``), ``files:`` can sit
    directly under ``artifacts:`` OR two levels deeper under
    ``artifacts.secondary-artifacts.<name>:`` — so this walks past each
    shallower ancestor that ISN'T ``artifacts:`` rather than stopping at the
    first one, continuing upward until ``artifacts:`` is found or indent 0
    is reached without a match.
    """
    current_indent = start_indent
    for j in range(idx - 1, -1, -1):
        prev = lines[j]
        prev_stripped = prev.strip()
        if not prev_stripped or prev_stripped.startswith("#"):
            continue
        prev_indent = len(prev) - len(prev.lstrip(" "))
        if prev_indent < current_indent:
            if _ARTIFACTS_KEY_RE.match(prev):
                return True
            current_indent = prev_indent
            if current_indent == 0:
                return False
    return False


class _OverbroadArtifactsGlobPattern:
    """Fire on a maximal glob (``**/*``, ``**``, or bare ``*``) as a
    ``files:`` list item nested anywhere under ``artifacts:`` — including
    ``artifacts.secondary-artifacts.<name>.files``.
    """

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        n = len(lines)
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if not _FILES_KEY_RE.match(line):
                continue
            files_indent = len(line) - len(line.lstrip(" "))
            if not _is_nested_under_artifacts(lines, i, files_indent):
                continue

            for j in range(i + 1, n):
                nxt = lines[j]
                nxt_stripped = nxt.strip()
                if not nxt_stripped:
                    continue
                nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                if nxt_indent <= files_indent:
                    break
                if nxt_stripped.startswith("#"):
                    continue
                item_m = _LIST_ITEM_RE.match(nxt)
                if not item_m:
                    continue
                value = _strip_value_quotes(item_m.group(2))
                if _MAXIMAL_GLOB_RE.match(value):
                    results.append((j + 1, nxt.strip()))
        return results


# ---------------------------------------------------------------------------
# SEC9-CB-002 — cache key/fallback-keys poisoning via an attacker-influenceable
# webhook-derived variable
# ---------------------------------------------------------------------------
# AWS's buildspec reference documents `cache.key`, `cache.fallback-keys`
# (matched by prefix search), `cache.action: restore|save`, and `cache.paths`.
# Direct analog of SEC9-GH-005 ("cache key derived from attacker-controlled
# context") — here the attacker-influenceable source is the same webhook-
# derived variable list SEC4-CB-001 already tracks (branch/tag names are
# attacker-choosable on a fork PR or pushed branch). A `cache.key` or
# `cache.fallback-keys` entry that interpolates one of these lets a build on
# an attacker-influenced branch write (or select) a cache entry that a
# trusted build later restores — PPE-adjacent when PR builds and main-branch
# builds share a cache scope.
#
# Same load-bearing caveat as SEC4-CB-001: whether a PR-triggered build and a
# trusted build actually SHARE a cache scope is CodeBuild-project-level
# configuration, invisible from buildspec.yml alone — hence MEDIUM severity
# (not HIGH) and confidence "medium" + review_needed=True, mirroring
# SEC4-CB-001 exactly rather than defaulting fresh.
_CACHE_TOP_KEY_RE = re.compile(r"^(\s*)cache\s*:\s*(?:#.*)?$")
_CACHE_KEY_LINE_RE = re.compile(r"^(\s*)key\s*:\s*(.*)$")
_CACHE_FALLBACK_KEYS_RE = re.compile(r"^(\s*)fallback-keys\s*:\s*(?:#.*)?$")
_CACHE_ACTION_LINE_RE = re.compile(r"^(\s*)action\s*:\s*(.*)$")


class _CacheKeyPoisoningPattern:
    """Fire when ``cache.key`` (or a ``cache.fallback-keys`` list entry)
    interpolates an attacker-influenceable webhook-derived variable.

    Scoped precisely to ``key:`` lines and list items nested specifically
    under a ``fallback-keys:`` sub-block (tracked by indent) — a webhook var
    merely mentioned elsewhere under ``cache:`` (e.g. inside ``paths:``) is
    not a cache-key poisoning shape and must not fire. Reuses
    ``_WEBHOOK_VAR_RE`` (SEC4-CB-001's attacker-influenceable variable list)
    rather than duplicating it.
    """

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        n = len(lines)
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if not _CACHE_TOP_KEY_RE.match(line):
                continue
            cache_indent = len(line) - len(line.lstrip(" "))

            block_end = n
            child_indent: int | None = None
            for j in range(i + 1, n):
                nxt = lines[j]
                nxt_stripped = nxt.strip()
                if not nxt_stripped or nxt_stripped.startswith("#"):
                    continue
                nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                if nxt_indent <= cache_indent:
                    block_end = j
                    break
                if child_indent is None or nxt_indent < child_indent:
                    child_indent = nxt_indent

            restore_only = False
            if child_indent is not None:
                for j in range(i + 1, block_end):
                    action_match = _CACHE_ACTION_LINE_RE.match(lines[j])
                    if action_match is None or len(action_match.group(1)) != child_indent:
                        continue
                    action = _strip_value_quotes(action_match.group(2)).lower()
                    if action == "restore":
                        restore_only = True
                    break
            if restore_only:
                continue

            fallback_keys_indent: int | None = None
            for j in range(i + 1, block_end):
                nxt = lines[j]
                nxt_stripped = nxt.strip()
                if not nxt_stripped:
                    continue
                nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                if nxt_indent <= cache_indent:
                    break
                if nxt_stripped.startswith("#"):
                    continue
                if fallback_keys_indent is not None and nxt_indent <= fallback_keys_indent:
                    fallback_keys_indent = None
                if _CACHE_FALLBACK_KEYS_RE.match(nxt):
                    fallback_keys_indent = nxt_indent
                    continue
                key_match = _CACHE_KEY_LINE_RE.match(nxt)
                in_fallback_list = fallback_keys_indent is not None and nxt_stripped.startswith("-")
                if not (key_match or in_fallback_list):
                    continue
                code = nxt.split("#", 1)[0]
                if _WEBHOOK_VAR_RE.search(code):
                    results.append((j + 1, nxt.strip()))
        return results


RULES: list[Rule] = [
    Rule(
        id="SEC3-CB-001",
        title="Script downloaded and piped directly to a shell interpreter",
        severity=Severity.HIGH,
        platform=Platform.CODEBUILD,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A buildspec `phases.*.commands` entry downloads a script with "
            "curl/wget and pipes it directly into a shell or interpreter "
            "(`curl ... | bash`, `wget ... | sh`, `bash <(curl ...)`, or the "
            "PowerShell `iex(Invoke-WebRequest ...)` equivalent on Windows "
            "build images) with no integrity verification. Whoever controls "
            "the remote URL controls what runs in the build container. "
            "CodeBuild's own sample buildspecs show package-manager installs "
            "in exactly this shape under `phases.install`/`phases.pre_build`."
        ),
        pattern=_DownloadedScriptExecutionPattern(),
        remediation=(
            "Download the script separately, verify its checksum, then "
            "execute:\n"
            "  - curl -fsSL -o install.sh https://example.com/install.sh\n"
            "  - echo '<expected_sha256>  install.sh' | sha256sum -c -\n"
            "  - bash install.sh"
        ),
        reference="https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html",
        test_positive=[
            "phases:\n  install:\n    commands:\n      - curl -fsSL https://get.example.com/install.sh | bash\n",
            "phases:\n  pre_build:\n    commands:\n      - wget -qO- https://install.example.com | sh\n",
            "phases:\n  install:\n    commands:\n      - bash <(curl -s https://example.com/bootstrap.sh)\n",
            "phases:\n  build:\n    commands:\n      - iex(Invoke-WebRequest -Uri https://chocolatey.org/install.ps1)\n",
            "phases:\n  install:\n    commands:\n      - curl -x https://example.com/get.py | python3\n",
        ],
        test_negative=[
            "phases:\n  install:\n    commands:\n      - curl -fsSL -o install.sh https://example.com/install.sh\n      - bash install.sh\n",
            "phases:\n  pre_build:\n    commands:\n      - wget -O setup.sh https://example.com/setup.sh\n",
            "phases:\n  install:\n    commands:\n      # - curl https://example.com/install.sh | bash\n",
            "phases:\n  build:\n    commands:\n      - cat install.sh | bash\n",
            "env:\n  variables:\n    DOC: curl https://example.com/install.sh | bash\n",
            # Regression guard for the interpreter-boundary fix: `sh`/`bash`
            # must not prefix-match a longer piped command name.
            "phases:\n  install:\n    commands:\n      - curl -fsSL https://example.com/install.sh.sha256 | sha256sum -c -\n",
            "phases:\n  install:\n    commands:\n      - curl -fsSL https://example.com/install.sh | shellcheck\n",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Piping a remote script straight to a shell with no integrity "
            "check grants the CDN operator — or any attacker who compromises "
            "it via DNS hijacking, BGP route injection, or a supply-chain "
            "breach of the hosting server — arbitrary code execution inside "
            "the build container, with access to whatever credentials and "
            "network reach that container has."
        ),
        finding_family="untrusted_code_execution",
        # P3.6 policy (PL-216 precedent): a new rule must not sit at the
        # bare "high" default un-validated — confidence="high" here would
        # be indistinguishable from "never set" to the confidence-
        # grandfather gate. The design notes's HIGH guess is a mechanical-
        # pattern hypothesis, not field validation; start at MEDIUM like
        # SEC6-CB-001/SEC4-JK-01x/SEC6-JK-011 did, promote once corpus
        # sample-labeling confirms the low-FP profile GH/GL/JK already show.
        confidence="medium",
    ),
    Rule(
        id="SEC6-CB-001",
        title="Plaintext secret-shaped value bound in buildspec env.variables",
        severity=Severity.HIGH,
        platform=Platform.CODEBUILD,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A credential-shaped variable name (matching *_SECRET, *_PASSWORD, "
            "*_TOKEN, *_API_KEY, *_PRIVATE_KEY, *_ACCESS_KEY, or *_CREDENTIALS) "
            "is bound directly under buildspec `env.variables`, which AWS's own "
            "documentation states is plain text and readable via the CodeBuild "
            "console or AWS CLI. Sensitive values belong under "
            "`env.parameter-store` or `env.secrets-manager` instead."
        ),
        pattern=_PlaintextSecretInEnvVariablesPattern(),
        remediation=(
            "Move the value to AWS Systems Manager Parameter Store or Secrets "
            "Manager and reference it under `env.parameter-store` / "
            "`env.secrets-manager` instead of `env.variables`."
        ),
        reference="https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html",
        test_positive=[
            "env:\n  variables:\n    DB_PASSWORD: hunter2\n",
            "env:\n  variables:\n    BUILD_ENV: prod\n    STRIPE_API_KEY: sk_live_abc123\n",
            "env:\n  variables:\n    AWS_SECRET_ACCESS_KEY: AKIAEXAMPLE0000000000\n",
            "env:\n  variables:\n    TOKEN: plaintext-token\n",
        ],
        test_negative=[
            # Same credential-shaped name, but under parameter-store: (a key
            # ALIAS, not a plaintext value) — the primary FP guard.
            "env:\n  parameter-store:\n    DB_PASSWORD: /myapp/db-password\n",
            # Same shape under secrets-manager: (an ARN, not a value).
            "env:\n  secrets-manager:\n    DB_PASSWORD: arn:aws:secretsmanager:us-east-1:123456789012:secret:myapp-db-password\n",
            # Non-credential-shaped name under variables: — no match.
            "env:\n  variables:\n    BUILD_ENV: prod\n",
            # Commented out — must not fire.
            "env:\n  variables:\n    # DB_PASSWORD: hunter2\n    BUILD_ENV: prod\n",
            # Credential-shaped word appears outside any env.variables block.
            "phases:\n  build:\n    commands:\n      - echo DB_PASSWORD\n",
        ],
        stride=["I"],
        threat_narrative=(
            "AWS's buildspec reference states env.variables values 'can be "
            "displayed in plain text using tools such as the CodeBuild console "
            "and the AWS CLI.' A credential bound there is readable by anyone "
            "with console/CLI access to the project and is committed to the "
            "repo in plain text for any PR reviewer to see, unlike a "
            "parameter-store/secrets-manager reference which only names an "
            "external resource."
        ),
        finding_family="credential_hygiene",
        confidence="medium",
    ),
    Rule(
        id="SEC6-CB-002",
        title="Bound secret transformed and emitted to CodeBuild logs",
        severity=Severity.HIGH,
        platform=Platform.CODEBUILD,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A secret bound via `env.parameter-store` or `env.secrets-manager` "
            "is run through an encode/obfuscate transform whose output is "
            "left on stdout inside a "
            "`phases.*.commands` entry: `base64` (encode), `rev`, `xxd`, `od`, "
            "`hexdump`, `tr`, `openssl enc`, or `gpg --encrypt`.\n\n"
            "CodeBuild masks the *verbatim* secret value in the build log on a "
            "best-effort basis. It cannot mask a *transformed* secret — "
            "`echo $TOKEN | base64` emits bytes the masking matcher never "
            "sees, so the encoded secret appears in the log (and in any "
            "downstream log-aggregation sink) in plain view of anyone with "
            "build-log access. The decoded value is trivially recoverable, so "
            "this is a full credential disclosure masking does not catch.\n\n"
            "Confirmed empirically against a live AWS CodeBuild build "
            "(2026-08-03): a parameter-store-bound value echoed directly "
            "appeared in the log as `***` (masked), but the same value piped "
            "through `base64` appeared in the clear, fully decodable. Plain "
            "`curl`/`wget` of a bound secret is deliberately NOT flagged here "
            "— passing a secret to its intended authenticated endpoint over "
            "TLS is the dominant, legitimate shape; only an encode/obfuscate "
            "transform of the secret is the finding."
        ),
        pattern=_SecretMaskingBypassPattern(),
        remediation=(
            "Never emit a transformed bound secret to build logs. If the value "
            "must be encoded for a downstream API, do it inside the tool that "
            "consumes it so the plaintext never enters a shell command line:\n\n"
            "# BAD — base64 of the secret defeats CodeBuild log masking\n"
            "env:\n"
            "  parameter-store:\n"
            "    TOKEN: /myapp/token\n"
            "phases:\n"
            "  build:\n"
            "    commands:\n"
            "      - echo $TOKEN | base64\n\n"
            "# GOOD — pass the secret directly to the consuming tool, "
            "never through a shell transform\n"
            "      - my-upload-tool --token-file <(echo $TOKEN)"
        ),
        reference="https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html",
        test_positive=[
            "env:\n  parameter-store:\n    DB_PASSWORD: /myapp/db-password\nphases:\n  build:\n    commands:\n      - echo $DB_PASSWORD | base64\n",
            "env:\n  secrets-manager:\n    API_TOKEN: myapp/api-token\nphases:\n  build:\n    commands:\n      - echo $API_TOKEN | rev\n",
        ],
        test_negative=[
            # Bound secret passed unmodified to an authenticated sink — the
            # dominant legitimate shape, must stay clean.
            'env:\n  parameter-store:\n    DB_PASSWORD: /myapp/db-password\nphases:\n  build:\n    commands:\n      - curl --user "user:$DB_PASSWORD" https://example.com/api\n',
            # Non-secret variable (env.variables:, not parameter-store:/
            # secrets-manager:) base64-encoded for a legitimate reason — the
            # rule keys on the BOUND-SECRET variable, not on "any base64".
            "env:\n  variables:\n    BUILD_ENV: prod\nphases:\n  build:\n    commands:\n      - echo $BUILD_ENV | base64\n",
            # Decode direction excluded (mirrors SEC6-JK-011 — this rule owns
            # the encode/obfuscate direction only).
            "env:\n  parameter-store:\n    DB_PASSWORD: /myapp/db-password\nphases:\n  build:\n    commands:\n      - echo $DB_PASSWORD | base64 -d\n",
            # Transform present but the bound-secret variable isn't referenced
            # on that line.
            "env:\n  parameter-store:\n    DB_PASSWORD: /myapp/db-password\nphases:\n  build:\n    commands:\n      - cat file.txt | base64\n",
            # Commented out — must not fire.
            "env:\n  parameter-store:\n    DB_PASSWORD: /myapp/db-password\nphases:\n  build:\n    commands:\n      # - echo $DB_PASSWORD | base64\n      - npm test\n",
            "env:\n  parameter-store:\n    TOKEN: /myapp/token\n  variables:\n    DOC: echo $TOKEN | base64\nphases:\n  build:\n    commands:\n      - echo ok\n",
            "env:\n  parameter-store:\n    TOKEN: /myapp/token\nphases:\n  build:\n    commands:\n      - echo $TOKEN | base64 > token.b64\n",
        ],
        stride=["I"],
        threat_narrative=(
            "CodeBuild's best-effort log masking only recognizes the "
            "verbatim secret value. Encoding it first (base64, rev, hex, "
            "openssl, gpg) produces a different byte string the masker "
            "never matches, so the encoded secret is written to the build "
            "log when left on stdout — recoverable by anyone with build-log access "
            "with one decode step, a full credential disclosure that the "
            "platform's own masking feature was supposed to prevent."
        ),
        finding_family="secret_exposure",
        # New rule, zero real-corpus validation yet (no buildspec.yml corpus
        # exists — see the design notes). The live-AWS test confirms the
        # THREAT MODEL is real; it says nothing about field precision on
        # real-world buildspecs. Same P3.6 discipline as SEC6-CB-001/
        # SEC3-CB-001/SEC6-JK-011: never default an unvalidated new rule to
        # "high".
        confidence="medium",
    ),
    Rule(
        id="THEATRE-CB-001",
        title="Security/quality-gate phase configured on-failure: CONTINUE",
        severity=Severity.MEDIUM,
        platform=Platform.CODEBUILD,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A `phases.*` block runs a recognised security-scanner or "
            "test-runner command (`npm audit`, `bandit`, `trivy`, `snyk`, "
            "`semgrep`, `checkov`, `tfsec`, `grype`, `gitleaks`, "
            "`trufflehog`, or a test-suite runner such as `pytest`/"
            "`go test`/`npm test`/`jest`/`mocha`/`vitest`/`rspec`) and sets "
            "`on-failure: CONTINUE` on that same phase. AWS's buildspec "
            "reference defines `CONTINUE` as proceeding to the next phase "
            "even after a command in this phase fails — the default, "
            "`ABORT`, stops the build instead. A security or quality gate "
            "that cannot stop configured later phases is validation theatre: "
            "the check runs, can fail, and deployment or publication commands "
            "in later phases still execute. The final build status may remain failed.\n"
            "\n"
            "Mirrors the existing THEATRE-GH-001/GL-001 'check exists but "
            "cannot block' shape, adapted to a single-file YAML flag rather "
            "than cross-file discovery-convention analysis."
        ),
        pattern=_TheatreOnFailureContinuePattern(),
        remediation=(
            "Either remove `on-failure: CONTINUE` from this phase so a "
            "failing scan/test blocks the build (the default `ABORT` "
            "behavior), or move the non-blocking check to its own phase "
            "clearly separated from phases that must gate the build."
        ),
        reference="https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html",
        test_positive=[
            "phases:\n  build:\n    on-failure: CONTINUE\n    commands:\n      - npm audit\n  post_build:\n    commands:\n      - ./publish.sh\n",
            "phases:\n  pre_build:\n    commands:\n      - bandit -r .\n    on-failure: CONTINUE\n  build:\n    commands:\n      - npm run build\n",
        ],
        test_negative=[
            # Legitimately optional phase (best-effort notification) with
            # CONTINUE — no gate-shaped command, must not fire.
            "phases:\n  post_build:\n    on-failure: CONTINUE\n    commands:\n      - curl -X POST https://hooks.slack.com/services/T000/B000/XXX -d 'build finished'\n",
            # Gate-shaped command with the default/ABORT behavior (no
            # on-failure present at all) — must not fire.
            "phases:\n  build:\n    commands:\n      - npm audit\n      - npm run build\n",
            # Gate-shaped command with explicit ABORT — must not fire.
            "phases:\n  build:\n    on-failure: ABORT\n    commands:\n      - bandit -r .\n",
            # Gate command commented out inside a CONTINUE phase — must not
            # fire (the only active command is an ordinary build step).
            "phases:\n  build:\n    on-failure: CONTINUE\n    commands:\n      # - npm audit\n      - npm run build\n",
            # A CONTINUE gate in the final configured phase has no later phase
            # to keep running, so this rule does not claim a bypass.
            "phases:\n  build:\n    on-failure: CONTINUE\n    commands:\n      - npm audit\n",
        ],
        stride=["R", "T"],
        threat_narrative=(
            "A maintainer sees a `bandit` or `npm audit` step in the "
            "pipeline and assumes a finding there would block the build. "
            "Because the phase is configured `on-failure: CONTINUE`, the "
            "scanner can report a CRITICAL vulnerability or a hardcoded "
            "secret and the build proceeds to publish an artifact anyway — "
            "the gate's green status represents an assertion ('this was "
            "scanned and passed') that was never actually enforced."
        ),
        finding_family="resource_controls",
        confidence="medium",
        # Keyword-based "looks like a gate" heuristic has the same FP-risk
        # shape as THEATRE-GH-001's convention-based detection (non-standard
        # tool names/wrappers won't be recognised); mirror its review_needed.
        review_needed=True,
    ),
    Rule(
        id="SEC3-CB-002",
        title="Floating/unpinned runtime-versions in buildspec install phase",
        severity=Severity.LOW,
        platform=Platform.CODEBUILD,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A `phases.install.runtime-versions` entry pins a runtime to a "
            "`.x` major-version wildcard (e.g. `nodejs: 18.x`) or the "
            "literal `latest` rather than an exact version. AWS's buildspec "
            "reference recommends specifying a runtime version to avoid "
            "inheriting an EOL-driven default-version change; a `.x`/"
            "`latest` value still floats across minor/patch (or, for "
            "`latest`, major) releases over time — the same moving-target "
            "shape as an unpinned action tag or `include:` ref on the other "
            "platforms."
        ),
        pattern=_FloatingRuntimeVersionPattern(),
        remediation=(
            "Pin `runtime-versions` to an exact version (e.g. `nodejs: "
            "18.20.4` instead of `nodejs: 18.x` or `nodejs: latest`) and "
            "bump it deliberately as part of a reviewed change."
        ),
        reference="https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html",
        test_positive=[
            "phases:\n  install:\n    runtime-versions:\n      nodejs: 18.x\n",
            "phases:\n  install:\n    runtime-versions:\n      java: latest\n",
        ],
        test_negative=[
            # Fully pinned exact version — must not fire.
            "phases:\n  install:\n    runtime-versions:\n      nodejs: 18.20.4\n",
            # Env-var indirection — indeterminate, not a floating literal,
            # must not fire and must not crash.
            'phases:\n  install:\n    runtime-versions:\n      ruby: "$MY_RUBY_VAR"\n',
            # `runtime-versions`-shaped key outside `install:` — parent
            # confirmation must reject it.
            "phases:\n  post_build:\n    commands:\n      - echo 'runtime-versions: not a real block'\n",
            # Commented out — must not fire.
            "phases:\n  install:\n    runtime-versions:\n      # nodejs: 18.x\n      python: 3.11.4\n",
        ],
        stride=["T"],
        threat_narrative=(
            "A `.x`/`latest` runtime pin means the exact toolchain version "
            "used to build the artifact silently changes whenever AWS "
            "updates the managed image's default — a build that passed "
            "yesterday can behave differently tomorrow with no reviewed "
            "change, and a compromised or vulnerable point release lands "
            "in the build environment without anyone deciding to adopt it."
        ),
        finding_family="dependency_pinning",
        # Purely syntactic once env-var indirection is excluded, but P3.6
        # policy (PL-216 precedent, applied consistently to every rule in
        # this pack) holds regardless of pattern simplicity: a new,
        # zero-corpus-validated rule never defaults to "high" — start
        # medium, promote once real buildspec sample-labeling confirms the
        # low-FP profile.
        confidence="medium",
    ),
    Rule(
        id="LOTP-CB-001",
        title="Build-tool install without integrity flags",
        severity=Severity.MEDIUM,
        platform=Platform.CODEBUILD,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A `phases.*.commands` entry runs `npm install`/`npm ci`/`yarn "
            "install`/`yarn add`/`pnpm install`/`pnpm add` without "
            "`--ignore-scripts`, or `pip`/`pip3 install` without "
            "`--require-hashes`. npm-family installers execute every "
            "dependency's `preinstall`/`install`/`postinstall` lifecycle "
            "script by default; pip without hash-checking accepts whatever "
            "package version the index currently serves with no integrity "
            "guarantee. This is a direct port of the LOTP-GH/GL/JK family's "
            "detection logic to a new sink location, with one honest "
            "difference: those rules gate on PR/external-trigger context "
            "evidence in the same file, which CodeBuild's buildspec.yml "
            "cannot express (trigger/webhook configuration lives in the "
            "project definition, out of this pass's scope) — so this v1 "
            "rule is a context-free posture check and will fire on "
            "ordinary, trusted-context installs too, not just externally-"
            "triggered ones."
        ),
        pattern=_BuildToolInstallPattern(),
        remediation=(
            "Add `--ignore-scripts` to every npm/yarn/pnpm install command "
            "to disable lifecycle-script execution:\n"
            "  - npm ci --ignore-scripts\n"
            "For pip, pin dependencies with hashes and require them:\n"
            "  - pip install --require-hashes -r requirements.txt\n"
            "If lifecycle scripts are genuinely needed (native-addon "
            "builds), run them explicitly afterward against a reviewed "
            "allowlist rather than accepting implicit execution."
        ),
        reference="https://docs.npmjs.com/cli/v10/using-npm/scripts#ignoring-scripts",
        test_positive=[
            "phases:\n  install:\n    commands:\n      - npm install\n",
            "phases:\n  build:\n    commands:\n      - npm ci --ignore-scripts && pip install requests\n",
            "phases:\n  install:\n    commands:\n      - npm ci\n",
            "phases:\n  pre_build:\n    commands:\n      - pip install requests\n",
            "phases:\n  install:\n    commands:\n      - yarn add lodash\n",
            # `yarn global add` — the false negative a real-corpus sample
            # (a corpus sample) surfaced: "global" sits between "yarn" and "add",
            # which the earlier subcommand-only regex missed.
            "phases:\n  install:\n    commands:\n      - yarn global add @unly/slack-codebuild\n",
        ],
        test_negative=[
            # --ignore-scripts present — safe.
            "phases:\n  install:\n    commands:\n      - npm ci --ignore-scripts\n",
            # --require-hashes present — safe.
            "phases:\n  pre_build:\n    commands:\n      - pip install --require-hashes -r requirements.txt\n",
            # Commented out — must not fire.
            "phases:\n  install:\n    commands:\n      # - npm install\n      - echo ok\n",
            # A different pip subcommand — must not fire.
            "phases:\n  build:\n    commands:\n      - pip show requests\n",
            # No install command at all.
            "phases:\n  build:\n    commands:\n      - npm run build\n",
            # yarn global subcommands that aren't installs — must not fire.
            "phases:\n  build:\n    commands:\n      - yarn global upgrade\n",
            "phases:\n  build:\n    commands:\n      - yarn global remove somepkg\n",
            # Installer text used as configuration or display data is inert.
            "env:\n  variables:\n    DOC: npm install\nphases:\n  build:\n    commands:\n      - echo ok\n",
            'phases:\n  build:\n    commands:\n      - echo "npm install"\n',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker who can influence any dependency manifest the "
            "build reads — a compromised transitive npm package's "
            "postinstall script, or a pip install with no hash pin "
            "resolving to a maliciously-republished version — gets their "
            "code executed inside the build container with whatever "
            "credentials and network reach that container holds. This is "
            "the exact mechanism class behind the Ultralytics YOLO (Dec "
            "2024) and Shai-Hulud (Sep/Nov 2025) npm supply-chain "
            "incidents; CodeBuild's ephemeral containers make it no less "
            "exploitable, just without the persistent-host aggravation "
            "Jenkins agents carry."
        ),
        finding_family="pipeline_tool_execution",
        # Threat-model doc guessed HIGH confidence ("same profile as the
        # shipped LOTP rules elsewhere") — overridden per this pack's P3.6
        # discipline at ship time (new + zero-corpus-validated never
        # defaults to high), then DEMOTED FURTHER to low after real-corpus
        # calibration (see module comment above): a 20-file diverse sample
        # of public buildspec.yml files showed 7/8 to 7/7 (depending on
        # whether a delegated `npm run <script>` install counts) firing —
        # near-universal, directionally matching the SEC9-GL-001 precedent
        # for a mechanically-accurate-but-universal posture check, though
        # that precedent's own evidence was a labeled n=30 review, not a
        # bare fire-rate count like this one. review_needed=True still
        # flags the missing context gate (see module comment above).
        confidence="low",
        review_needed=True,
    ),
    Rule(
        id="SEC4-CB-001",
        title="Webhook-derived ref passed to a second shell evaluation",
        severity=Severity.MEDIUM,
        platform=Platform.CODEBUILD,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A `phases.*.commands` entry places a CodeBuild webhook/source "
            "variable inside shell source passed to `eval` or as the first "
            "command-string argument to `sh -c`, `bash -c`, `dash -c`, "
            "`ksh -c`, or `zsh -c`. Those constructs parse the expanded "
            "value a second time, so shell metacharacters can become syntax. "
            "Ordinary unquoted parameter expansion is deliberately clean: "
            "the shell does not recursively parse expansion output. AWS "
            "documents webhook heads as branch/tag refs and pull-request "
            "source versions as `pr/<number>`. Whether an external actor can "
            "influence the selected ref depends on project webhook settings "
            "outside the buildspec, so analyst review remains required."
        ),
        pattern=_SecondEvaluationWebhookRefPattern(),
        remediation=(
            "Do not build shell source from CodeBuild ref variables. Invoke "
            "the target tool directly, or pass the value as positional data "
            "outside the `-c` command string, for example: "
            '`bash -c \'deploy "$1"\' -- "$CODEBUILD_WEBHOOK_HEAD_REF"`. '
            "If second evaluation is unavoidable, validate the value against "
            "the exact accepted ref format before evaluation and confirm the "
            "project's webhook filters exclude untrusted contributors."
        ),
        reference="https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-env-vars.html",
        test_positive=[
            'phases:\n  build:\n    commands:\n      - eval "deploy --ref $CODEBUILD_WEBHOOK_HEAD_REF"\n',
            'phases:\n  post_build:\n    commands:\n      - bash -c "docker build -t app:${CODEBUILD_SOURCE_VERSION} ."\n',
            'phases:\n  build:\n    commands:\n      - bash -lc "deploy $CODEBUILD_SOURCE_VERSION"\n',
            "phases:\n  build:\n    commands:\n      - bash -c \"printf '#'; $CODEBUILD_SOURCE_VERSION\"\n",
        ],
        test_negative=[
            # Ordinary expansion remains data; it is not parsed as shell syntax.
            "phases:\n  build:\n    commands:\n      - docker build -t myapp:$CODEBUILD_WEBHOOK_HEAD_REF .\n",
            "phases:\n  post_build:\n    commands:\n      - echo Deploying ${CODEBUILD_SOURCE_VERSION}\n",
            # A positional argument after the -c command string is data.
            'phases:\n  build:\n    commands:\n      - bash -c \'deploy "$1"\' -- "$CODEBUILD_WEBHOOK_HEAD_REF"\n',
            # Inner-shell expansion occurs after parsing, so it is not reparsed.
            "phases:\n  build:\n    commands:\n      - bash -c 'echo \"$CODEBUILD_WEBHOOK_HEAD_REF\"'\n",
            # Direct quoted use is also data.
            'phases:\n  build:\n    commands:\n      - git checkout "$CODEBUILD_WEBHOOK_HEAD_REF"\n',
            # A different CodeBuild variable is outside this rule.
            'phases:\n  build:\n    commands:\n      - eval "echo $CODEBUILD_BUILD_ID"\n',
            # Non-command contexts are not shell sinks.
            "cache:\n  key: build-$CODEBUILD_WEBHOOK_HEAD_REF\n  paths:\n    - node_modules/**/*\n",
            "env:\n  variables:\n    DEPLOY_REF: $CODEBUILD_WEBHOOK_HEAD_REF\nphases:\n  build:\n    commands:\n      - npm run build\n",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "A project accepts a contributor-influenceable ref and embeds it "
            "in a string passed to `eval` or a shell's `-c` option. The outer "
            "shell expands the variable before the second evaluator parses "
            "the resulting string, allowing metacharacters in the value to "
            "become commands inside the build container."
        ),
        finding_family="script_injection",
        confidence="medium",
        review_needed=True,
    ),
    Rule(
        id="SEC9-CB-001",
        title="Overbroad artifacts.files glob captures the entire build directory",
        severity=Severity.LOW,
        platform=Platform.CODEBUILD,
        owasp_cicd="CICD-SEC-9",
        description=(
            "An `artifacts.files` (or `artifacts.secondary-artifacts.<name>."
            "files`) list contains a maximal glob (`**/*`, `**`, or bare `*`) "
            "that captures every file in the build directory — including "
            "`.git/`, `.env`, or any incidentally-written credential/config "
            "file — into the uploaded artifact (S3 or CodePipeline output), "
            "which may have broader read access than the build itself.\n\n"
            "Shipped at LOW severity and confidence='low' from day one: the "
            "closest sibling rule (SEC9-GL-001, GitLab's artifact-access-"
            "restriction rule) was field-tested against a real corpus and "
            "found to fire on every job that produces an artifact, "
            "dominating finding volume — it now ships at this same reduced "
            "posture. CodeBuild has no corpus yet to run that field test "
            "against, and a maximal glob is a common, often-legitimate "
            "pattern for static-site builds where the whole output tree IS "
            "the deployable artifact."
        ),
        pattern=_OverbroadArtifactsGlobPattern(),
        remediation=(
            "Scope `artifacts.files` to only the directories the artifact "
            "consumer actually needs, e.g. `dist/**/*` instead of `**/*`. If "
            "the entire build output genuinely is the artifact, add a "
            "`.gitignore`-aware pre-artifact cleanup step (or a "
            "`base-directory` pointing at a dedicated output folder) so "
            "`.git/`, `.env`, and build-cache directories are excluded."
        ),
        reference="https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html",
        test_positive=[
            "artifacts:\n  files:\n    - '**/*'\n",
            "artifacts:\n  secondary-artifacts:\n    logs:\n      files:\n        - '**/*'\n      base-directory: build\n",
        ],
        test_negative=[
            # Scoped glob — must not fire.
            "artifacts:\n  files:\n    - 'dist/**/*'\n",
            # Maximal glob under cache.paths, NOT artifacts — the ancestor
            # walk must reject it.
            "cache:\n  paths:\n    - '**/*'\n",
            # Commented out — must not fire.
            "artifacts:\n  # files:\n  #   - '**/*'\n  files:\n    - 'dist/**/*'\n",
        ],
        stride=["I"],
        threat_narrative=(
            "A build directory routinely accumulates files never meant for "
            "distribution — a `.env` used only for local test config, a "
            "`.git/` directory with full history, cached package-manager "
            "credentials, or a stray backup file. `artifacts.files: ['**/*']` "
            "sweeps all of it into the artifact with no per-file review, "
            "handing anyone with artifact-download access (a scope that may "
            "be broader than build-log access) whatever ended up in that "
            "directory, intentionally or not."
        ),
        finding_family="artifact_integrity",
        confidence="low",
        review_needed=True,
    ),
    Rule(
        id="SEC9-CB-002",
        title="Cache key/fallback-keys derived from attacker-controlled webhook context",
        severity=Severity.MEDIUM,
        platform=Platform.CODEBUILD,
        owasp_cicd="CICD-SEC-9",
        description=(
            "A buildspec `cache.key` or `cache.fallback-keys` entry (matched "
            "by prefix search) interpolates an attacker-influenceable "
            "webhook-derived variable — `$CODEBUILD_WEBHOOK_HEAD_REF`, "
            "`$CODEBUILD_SOURCE_VERSION`, `$CODEBUILD_WEBHOOK_BASE_REF`, or "
            "`$CODEBUILD_WEBHOOK_TRIGGER` (the same attacker-influenceable "
            "list SEC4-CB-001 tracks). Direct analog of SEC9-GH-005 (GitHub "
            "Actions cache key derived from attacker-controlled context).\n\n"
            "This rule sees only the cache-key SINK; whether a PR-triggered "
            "build and a trusted build actually share a cache scope is "
            "CodeBuild-project-level configuration invisible from "
            "buildspec.yml alone — hence MEDIUM severity and "
            "`review_needed=True`, mirroring SEC4-CB-001's precedent."
        ),
        pattern=_CacheKeyPoisoningPattern(),
        remediation=(
            "Derive cache keys from content hashes or repo-trusted refs "
            "only — never from webhook-sourced branch/tag/PR context:\n\n"
            "# BAD — attacker picks the cache key by naming their branch\n"
            "cache:\n"
            "  key: build-$CODEBUILD_WEBHOOK_HEAD_REF\n\n"
            "# GOOD — content-addressed; attacker can't influence the key\n"
            "cache:\n"
            "  key: build-$(codebuild-hash-files package-lock.json)"
        ),
        reference="https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html",
        test_positive=[
            "cache:\n  key: build-$CODEBUILD_WEBHOOK_HEAD_REF\n  paths:\n    - node_modules/**/*\n",
            "cache:\n  fallback-keys:\n    - 'build-${CODEBUILD_SOURCE_VERSION}'\n  paths:\n    - node_modules/**/*\n",
        ],
        test_negative=[
            # Stable, content-addressed key — must not fire.
            "cache:\n  key: build-$(codebuild-hash-files package-lock.json)\n  paths:\n    - node_modules/**/*\n",
            # Webhook var mentioned only under paths:, not key/fallback-keys —
            # must not fire.
            "cache:\n  key: build-stable\n  paths:\n    - '$CODEBUILD_WEBHOOK_HEAD_REF/**/*'\n",
            # Commented out — must not fire.
            "cache:\n  # key: build-$CODEBUILD_WEBHOOK_HEAD_REF\n  key: build-stable\n  paths:\n    - node_modules/**/*\n",
            # Restore-only caches cannot write attacker-selected entries.
            "cache:\n  action: restore\n  key: build-$CODEBUILD_WEBHOOK_HEAD_REF\n  paths:\n    - node_modules/**/*\n",
        ],
        stride=["T", "S"],
        threat_narrative=(
            "Caches persist across builds. If the key is derived from "
            "webhook-sourced context, an attacker who can push a branch or "
            "open a fork PR chooses what key their build's cache is stored "
            "under, then later triggers (or waits for) a trusted build that "
            "restores that exact key — silently substituting a poisoned "
            "dependency cache into the trusted pipeline before any "
            "verification step observes it."
        ),
        finding_family="artifact_integrity",
        confidence="medium",
        review_needed=True,
    ),
]
