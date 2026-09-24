"""LOTP — Living Off The Pipeline.

Detects build tools and package managers that execute lifecycle scripts or
build hooks against attacker-controlled code checked out from a pull request
or other external source.  This is the category of attack that compromised
Ultralytics YOLO in December 2024: the workflow checked out a fork PR and
ran `pip install`, which executed `setup.py` from the fork — arbitrary
attacker code in a privileged job.

Rule IDs use the LOTP-<PLATFORM>-<NN> scheme so the category stays
recognisable once GitLab and Jenkins LOTP rules land in follow-up PRs.
"""

import posixpath
import re
import shlex
from collections import deque
from collections.abc import Sequence

from taintly.models import ContextPattern, Platform, Rule, Severity
from taintly.parsers.gha_expr import ExprSyntaxError, context_paths, iter_expression_bodies
from taintly.parsers.segmentation import JobSegment, StepSegment, for_each_job, for_each_step

from .._build_tools import BUILD_TOOL_ANCHOR as _BUILD_TOOL_ANCHOR

# ---------------------------------------------------------------------------
# Shared patterns
# ---------------------------------------------------------------------------

# Candidate PR source context. The ordered source model below verifies that
# it controls a checkout field or an executable Git source change.
_PR_HEAD_CHECKOUT = (
    r"(?:github\.event\.pull_request\.head\.(?:sha|ref)"
    r"|github\.event\.pull_request\.head\.repo\.(?:full_name|clone_url)"
    r"|github\.event\.pull_request\.number|(?:refs/)?pull/\d+/(?:head|merge)"
    r"|gh\s+pr\s+checkout\s+\d+|github\.com/\S+/pull/\d+"
    r"|github\.head_ref"
    r"|github\.event\.workflow_run\.head_branch)"
)

# Evidence untrusted artefacts have been pulled into the job workspace.
_UNTRUSTED_ARTIFACT = r"uses:\s*actions/download-artifact"

# Provenance-qualified untrusted artefact: a download-artifact step that pulls
# from ANOTHER workflow run (download-artifact v4 needs ``run-id`` to cross runs;
# a same-run handoff has neither) keyed to ``github.event.workflow_run`` — the
# attacker-influenceable cross-workflow source. Written as ``download-artifact``
# FOLLOWED BY ``github.event.workflow_run`` (the reliable ``uses:``-before-
# ``with: run-id:`` text order) rather than two ``(?=[\s\S]*…)`` lookaheads,
# which are O(n^2) under ``.search`` on a large no-match segment (a fuzz hang).
# Same-run upload->download handoffs (trusted) carry no workflow_run reference
# and so do not fire — they were the dominant false-positive class for this rule.
_CROSS_WORKFLOW_UNTRUSTED_ARTIFACT = (
    r"uses:\s*actions/download-artifact[\s\S]*?github\.event\.workflow_run"
)


# ---------------------------------------------------------------------------
# LOTP-GH-001 execution-path model
# ---------------------------------------------------------------------------

_PR_HEAD_PATH_RE = re.compile(
    r"(?:github\.event\.pull_request\.head\.(?:sha|ref|repo\.(?:full_name|clone_url))|github\.head_ref)",
    re.IGNORECASE,
)
_WORKFLOW_RUN_HEAD_BRANCH_RE = re.compile(r"github\.event\.workflow_run\.head_branch", re.I)
_CHECKOUT_ACTION_RE = re.compile(
    r"^\s*(?:-\s*)?uses\s*:\s*['\"]?actions/checkout@", re.IGNORECASE | re.MULTILINE
)
_REF_LINE_RE = re.compile(r"^\s*ref\s*:\s*(.*?)\s*(?:#.*)?$", re.MULTILINE)
_REPOSITORY_LINE_RE = re.compile(r"^\s*repository\s*:\s*(.*?)\s*(?:#.*)?$", re.MULTILINE)
_CHECKOUT_PATH_LINE_RE = re.compile(r"^\s*path\s*:\s*(.*?)\s*(?:#.*)?$", re.MULTILINE)
_WORKING_DIRECTORY_LINE_RE = re.compile(r"^\s*(?:-\s*)?working-directory\s*:\s*(.*?)\s*$")
_SHELL_CD_RE = re.compile(
    r"(?:^\s*(?:-\s*)?run\s*:\s*|^\s*|[;&|]\s*)(?P<command>cd)\s+(?P<path>[^\s;&|]+)",
    re.IGNORECASE,
)
_RUN_LINE_RE = re.compile(r"^\s*(?:-\s*)?run\s*:\s*(?P<body>.*)$")
_USES_LINE_RE = re.compile(r"^\s*(?:-\s*)?uses\s*:")
_HEREDOC_OPEN_RE = re.compile(
    r"(?P<operator><<-?)\s*(?P<quote>['\"]?)(?P<delimiter>[A-Za-z_][A-Za-z0-9_.-]*)(?P=quote)(?=\s|[;&|]|$)"
)
_NPM_PREFIX_PATH_RE = re.compile(r"(?<!\S)--prefix(?:=|\s+)(?P<path>[^\s;&|]+)")
_PIP_COMMAND_RE = re.compile(r"pip\d*(?:\.\d+)?\b", re.IGNORECASE)
_SHELL_WRAPPER_RE = re.compile(r"\b(?:bash|sh)\s+-(?:l)?c\s+(?P<quote>['\"])", re.IGNORECASE)
_STATIC_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*\Z")
_STATIC_PATH_RE = re.compile(r"[A-Za-z0-9._/-]+\Z")
_NPM_PREFIX_INSTALL_ANCHOR = r"\bnpm\s+--prefix(?:=|\s+)\S+\s+(?:install|ci|i)\b"
_NPM_PREFIX_BUILD_ANCHOR = (
    r"\bnpm\s+--prefix(?:=|\s+)\S+\s+"
    r"(?:install|ci|i|update|pack|publish|run|build|test)\b"
)
# Parsed arguments below decide whether pip installs local code.  Matching
# only the first argument misses valid forms such as ``--no-deps -e./fork``.
_PIP_INSTALL_ANCHOR = r"\bpip\d*(?:\.\d+)?\b[^\n;&|#]*?\binstall\b"
_PIP_NON_SOURCE_VALUE_OPTIONS = frozenset(
    {
        "--target",
        "-t",
        "--prefix",
        "--root",
        "--cache-dir",
        "--cert",
        "--client-cert",
        "--index-url",
        "-i",
        "--extra-index-url",
        "--find-links",
        "-f",
        "--trusted-host",
        "--log",
        "--src",
        "--report",
        "--config-settings",
        "-C",
    }
)
_PIP_GLOBAL_VALUE_OPTIONS = _PIP_NON_SOURCE_VALUE_OPTIONS | {
    "--python",
    "--proxy",
    "--retries",
    "--timeout",
    "--exists-action",
}
_PIP_GLOBAL_SWITCH_OPTIONS = frozenset(
    {
        "--isolated",
        "--require-virtualenv",
        "--no-input",
        "--no-cache-dir",
        "--disable-pip-version-check",
        "--no-color",
        "--quiet",
        "--verbose",
        "--help",
        "--version",
        "-q",
        "-v",
        "-h",
        "-V",
    }
)
_GIT_TRANSIENT_REFS = frozenset(
    {"HEAD", "FETCH_HEAD", "ORIG_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REBASE_HEAD"}
)
_GIT_SOURCE_CHANGE_RE = re.compile(
    r"(?:^|[;&|])\s*git\s+(?:checkout|switch)\s+(?:(?:--detach|--force)\s+)?"
    r"(?P<ref>['\"]?\$\{\{[^}]*\}\}['\"]?|[^\s;&|]+)",
    re.IGNORECASE,
)
_PR_NUMBER_EXPRESSION_RE = re.compile(
    r"\$\{\{\s*github\.event\.pull_request\.number\s*\}\}", re.IGNORECASE
)
_REPOSITORY_EXPRESSION_RE = re.compile(r"\$\{\{\s*github\.repository\s*\}\}", re.I)
_PR_HEAD_REPO_EXPRESSION_RE = re.compile(
    r"\$\{\{\s*github\.event\.pull_request\.head\.repo\.(?:full_name|clone_url)\s*\}\}",
    re.I,
)
_PR_FETCH_SOURCE_RE = re.compile(
    r"(?:refs/)?pull/(?:\d+|__PR_NUMBER__)/(?:head|merge)\Z", re.IGNORECASE
)
_GH_PR_URL_RE = re.compile(
    r"https://github\.com/(?:__GITHUB_REPOSITORY__|[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/"
    r"pull/(?:\d+|__PR_NUMBER__)\Z",
    re.IGNORECASE,
)
_GIT_FETCH_VALUE_OPTIONS = frozenset(
    {
        "--depth",
        "--filter",
        "--refmap",
        "--upload-pack",
        "--jobs",
        "--server-option",
        "--shallow-since",
        "--shallow-exclude",
        "--negotiation-tip",
        "-j",
    }
)
_STEP_IF_RE = re.compile(r"^\s*(?:-\s*)?if\s*:\s*(.*?)\s*$")
_EVENT_EQ_RE = re.compile(
    r"github\.event_name\s*==\s*['\"](?P<event>[A-Za-z_]+)['\"]"
    r"|['\"](?P<reverse>[A-Za-z_]+)['\"]\s*==\s*github\.event_name",
    re.IGNORECASE,
)

_TRUSTED = "trusted"
_UNTRUSTED = "untrusted"
_UNKNOWN = "unknown"


def _contains_pr_head_reference(text: str) -> bool:
    """Return whether text carries a PR-head source reference.

    The structural path handles bracket access and context-name casing.  The
    regex fallback preserves coverage when an expression is incomplete or the
    structural parser declines it.
    """

    if _PR_HEAD_PATH_RE.search(text):
        return True
    try:
        return any(
            _PR_HEAD_PATH_RE.search(path)
            for body in iter_expression_bodies(text)
            for path in context_paths(body)
        )
    except ExprSyntaxError:
        return False


def _direct_if(step: StepSegment) -> str:
    """Return a step's direct scalar ``if:`` value, or empty on ambiguity."""

    if not step.body_lines:
        return ""
    first = step.body_lines[0]
    first_indent = len(first) - len(first.lstrip())
    body_indent = first_indent + 2
    for line in step.body_lines:
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if indent not in {first_indent, body_indent}:
            continue
        match = _STEP_IF_RE.match(line)
        if not match:
            continue
        value = match.group(1).strip()
        if value in {"|", "|-", "|+", ">", ">-", ">+"}:
            return ""
        return value
    return ""


def _excludes_pr_path(condition: str) -> bool:
    """Prove that a simple condition cannot execute on a PR event.

    Only a conjunctive exact event comparison is accepted.  Disjunctions,
    functions, dynamic comparands, and malformed expressions fail closed.
    """

    expr = condition.strip()
    if not expr:
        return False
    if expr.startswith("${{") and expr.endswith("}}"):
        expr = expr[3:-2].strip()
    if "||" in expr:
        return False
    matches = list(_EVENT_EQ_RE.finditer(expr))
    if not matches:
        return False
    if any("!" in expr[: match.start()] for match in matches):
        return False
    events = {(m.group("event") or m.group("reverse") or "").lower() for m in matches}
    return bool(events) and events.isdisjoint({"pull_request", "pull_request_target"})


def _literal_workspace_path(value: str, base: str = ".") -> str | None:
    """Resolve a simple relative workspace path; ambiguity must stay visible."""

    value = value.strip().strip("'\"").replace("\\", "/")
    if not value or not _STATIC_PATH_RE.fullmatch(value) or value.startswith("/"):
        return None
    path = posixpath.normpath(posixpath.join(base, value))
    if path == ".." or path.startswith("../"):
        return None
    return path


def _checkout_action_state(step: StepSegment) -> tuple[str, bool, str | None] | None:
    """Return source state, repository provenance, and checkout path."""

    if not _CHECKOUT_ACTION_RE.search(step.text):
        return None
    paths = [match.group(1) for match in _CHECKOUT_PATH_LINE_RE.finditer(step.text)]
    path = "." if not paths else _literal_workspace_path(paths[0]) if len(paths) == 1 else None
    repositories = [
        match.group(1).strip().strip("'\"") for match in _REPOSITORY_LINE_RE.finditer(step.text)
    ]
    if repositories:
        if len(repositories) != 1:
            return _UNKNOWN, True, path
        if _contains_pr_head_reference(repositories[0]):
            return _UNTRUSTED, True, path
        if repositories[0] != "${{ github.repository }}":
            # A fixed branch in another repository cannot prove base trust.
            return _UNKNOWN, True, path
    refs = [match.group(1).strip().strip("'\"") for match in _REF_LINE_RE.finditer(step.text)]
    if any(
        _contains_pr_head_reference(ref) or _WORKFLOW_RUN_HEAD_BRANCH_RE.search(ref) for ref in refs
    ):
        return _UNTRUSTED, False, path
    if len(refs) == 1 and _STATIC_REF_RE.fullmatch(refs[0]):
        return _TRUSTED, False, path
    # Default checkout and dynamic refs depend on the event and repository
    # state.  Retain findings until that state can be proved.
    return _UNKNOWN, False, path


def _checkout_may_use_pr_source(step: StepSegment) -> bool:
    """Require PR source evidence in checkout fields, not adjacent metadata."""

    if not _CHECKOUT_ACTION_RE.search(step.text):
        return False
    values = [
        match.group(1).strip().strip("'\"")
        for pattern in (_REF_LINE_RE, _REPOSITORY_LINE_RE)
        for match in pattern.finditer(step.text)
    ]
    return any(
        _contains_pr_head_reference(value)
        or _WORKFLOW_RUN_HEAD_BRANCH_RE.search(value)
        or "${{" in value
        for value in values
    )


def _step_working_path(step: StepSegment, default_path: str | None) -> str | None:
    """Return a direct step working directory, or the inherited default."""

    if not step.body_lines:
        return default_path
    first_indent = len(step.body_lines[0]) - len(step.body_lines[0].lstrip())
    child_indents = [
        len(line) - len(line.lstrip())
        for line in step.body_lines[1:]
        if line.strip() and len(line) - len(line.lstrip()) > first_indent
    ]
    direct_indent = min(child_indents) if child_indents else first_indent + 2
    matches = [
        match.group(1)
        for line in step.body_lines
        if len(line) - len(line.lstrip()) in {first_indent, direct_indent}
        if (match := _WORKING_DIRECTORY_LINE_RE.match(line))
    ]
    return (
        default_path
        if not matches
        else _literal_workspace_path(matches[0])
        if len(matches) == 1
        else None
    )


def _default_working_path(
    lines: Sequence[str], defaults_indent: int, fallback: str | None
) -> str | None:
    """Read only ``defaults.run.working-directory`` at the expected scope."""

    active_defaults: int | None = None
    active_run: int | None = None
    values: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if active_run is not None and indent <= active_run:
            active_run = None
        if active_defaults is not None and indent <= active_defaults:
            active_defaults = None
        if stripped == "defaults:" and indent == defaults_indent:
            active_defaults = indent
        elif active_defaults is not None and stripped == "run:" and indent > active_defaults:
            active_run = indent
        elif active_run is not None and indent > active_run:
            match = _WORKING_DIRECTORY_LINE_RE.match(line)
            if match:
                values.append(match.group(1))
    return (
        fallback if not values else _literal_workspace_path(values[0]) if len(values) == 1 else None
    )


def _source_key(sources: dict[str, tuple[str, bool]], cwd: str) -> str:
    """Find the nearest checkout root containing a working directory."""

    path = cwd
    while path not in sources and path != ".":
        path = posixpath.dirname(path) or "."
    return path


def _shell_child_spans(line: str) -> list[tuple[int, int, int]]:
    """Find executable, literal child-shell bodies and their wrapper starts."""

    spans: list[tuple[int, int, int]] = []
    mask, _, _ = _shell_quote_mask(line, None)
    for match in _SHELL_WRAPPER_RE.finditer(line):
        if mask[match.start()] or not _at_shell_command_start(line, mask, match.start()):
            continue
        command_start = max(
            (
                index + 1
                for index, char in enumerate(line[: match.start()])
                if char in ";&|" and not mask[index]
            ),
            default=0,
        )
        wrapper_start = (
            command_start if line[command_start : match.start()].strip() else match.start()
        )
        quote = match.group("quote")
        start = match.end()
        index = start
        while index < len(line):
            if line[index] == "\\" and quote == '"':
                index += 2
            elif line[index] == quote:
                spans.append((wrapper_start, start, index))
                break
            else:
                index += 1
    return spans


def _static_shell_script(line: str) -> str:
    """Expose literal child-shell bodies while preserving source columns."""

    rendered = list(line)
    for wrapper_start, start, end in _shell_child_spans(line):
        rendered[wrapper_start:start] = " " * (start - wrapper_start)
        rendered[end] = " "
    return "".join(rendered)


def _run_shell_lines(
    step: StepSegment, child_scopes: dict[int, list[tuple[int, int]]] | None = None
) -> dict[int, str]:
    """Return executable run lines, preserving columns for ordered events."""

    if not step.body_lines:
        return {}
    first_indent = len(step.body_lines[0]) - len(step.body_lines[0].lstrip())
    child_indents = [
        len(line) - len(line.lstrip())
        for line in step.body_lines[1:]
        if line.strip() and len(line) - len(line.lstrip()) > first_indent
    ]
    direct_indent = min(child_indents) if child_indents else first_indent + 2
    script: dict[int, str] = {}
    for offset, line in enumerate(step.body_lines):
        indent = len(line) - len(line.lstrip())
        if indent not in {first_indent, direct_indent}:
            continue
        match = _RUN_LINE_RE.match(line)
        if not match:
            continue
        body = match.group("body")
        if body.strip() in {"|", "|-", "|+", ">", ">-", ">+"}:
            for next_offset in range(offset + 1, len(step.body_lines)):
                next_line = step.body_lines[next_offset]
                if next_line.strip() and len(next_line) - len(next_line.lstrip()) <= indent:
                    break
                if child_scopes is not None:
                    child_scopes[next_offset] = [
                        (start, end) for _, start, end in _shell_child_spans(next_line)
                    ]
                script[next_offset] = _static_shell_script(next_line)
        else:
            prefix_len = match.start("body")
            # YAML's outer scalar quotes are delimiters, not shell quotes.
            if len(body) >= 2 and body[0] in "'\"" and body[-1] == body[0]:
                body = " " + body[1:-1] + " "
            shell_body = " " * prefix_len + body
            if child_scopes is not None:
                child_scopes[offset] = [
                    (start, end) for _, start, end in _shell_child_spans(shell_body)
                ]
            script[offset] = _static_shell_script(shell_body)
    return script


def _shell_quote_mask(line: str, initial: str | None) -> tuple[list[bool], str | None, int | None]:
    """Mark shell quotes and comments; return the comment start separately."""

    quote = initial
    escaped = False
    mask: list[bool] = []
    comment_start: int | None = None
    for index, char in enumerate(line):
        mask.append(quote is not None)
        if quote == "'":
            if char == "'":
                quote = None
        elif escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote is not None:
            if char == quote:
                quote = None
        elif char == "#" and (index == 0 or line[index - 1].isspace() or line[index - 1] in ";&|("):
            comment_start = index
            mask[-1] = True
            mask.extend([True] * (len(line) - index - 1))
            break
        elif char in "'\"":
            quote = char
    return mask, quote, comment_start


def _shell_command_segments(line: str, mask: list[bool]) -> list[tuple[int, str]]:
    """Split a shell line at executable command separators."""

    segments: list[tuple[int, str]] = []
    start = 0
    for index, char in enumerate(line):
        if char not in ";&|" or mask[index]:
            continue
        part = line[start:index]
        if part.strip():
            segments.append((start + len(part) - len(part.lstrip()), part.strip()))
        start = index + 1
    part = line[start:]
    if part.strip():
        segments.append((start + len(part) - len(part.lstrip()), part.strip()))
    return segments


def _shell_command_tokens(command: str) -> list[str] | None:
    """Keep GitHub's PR-number expression intact while splitting arguments."""

    normalized = _PR_NUMBER_EXPRESSION_RE.sub("__PR_NUMBER__", command)
    normalized = _REPOSITORY_EXPRESSION_RE.sub("__GITHUB_REPOSITORY__", normalized)
    normalized = _PR_HEAD_REPO_EXPRESSION_RE.sub("__PR_HEAD_REPOSITORY__", normalized)
    try:
        return shlex.split(normalized, comments=True)
    except ValueError:
        return None


def _git_command_index(tokens: list[str]) -> tuple[int, tuple[str, ...]] | None:
    """Skip supported Git global options and retain temporary ``-C`` paths."""

    if not tokens or tokens[0].lower() != "git":
        return None
    index = 1
    paths: list[str] = []
    while index < len(tokens) and tokens[index].startswith("-"):
        option = tokens[index]
        index += 1
        if option in {"-C", "-c"}:
            if index >= len(tokens):
                return None
            if option == "-C":
                paths.append(tokens[index])
            index += 1
        elif option.startswith("-C") and len(option) > 2:
            paths.append(option[2:])
        elif (option.startswith("-c") and len(option) > 2) or option in {
            "--no-pager",
            "--no-replace-objects",
            "--no-lazy-fetch",
        }:
            continue
        else:
            return None
    return index, tuple(paths)


def _git_fetch_events(
    line: str, mask: list[bool]
) -> list[tuple[int, str, str | None, tuple[str, ...], bool, str]]:
    """Parse fetch options and refspecs, including PR head and merge refs."""

    events: list[tuple[int, str, str | None, tuple[str, ...], bool, str]] = []
    for column, command in _shell_command_segments(line, mask):
        tokens = _shell_command_tokens(command)
        if tokens is None:
            continue
        invocation = _git_command_index(tokens)
        if invocation is None:
            continue
        index, paths = invocation
        if index >= len(tokens) or tokens[index].lower() != "fetch":
            continue
        index += 1
        if "--dry-run" in tokens[index:]:
            continue
        write_fetch_head = "--no-write-fetch-head" not in tokens[index:]
        while index < len(tokens) and tokens[index].startswith("-"):
            option, inline_value, _ = tokens[index].partition("=")
            index += 1
            if option in _GIT_FETCH_VALUE_OPTIONS and not inline_value:
                index += 1
        if index >= len(tokens):
            continue
        remote = tokens[index]
        index += 1
        candidates: list[tuple[str, str | None]] = []
        while index < len(tokens):
            token = tokens[index]
            index += 1
            if token.startswith("-"):
                option, inline_value, _ = token.partition("=")
                if option in _GIT_FETCH_VALUE_OPTIONS and not inline_value:
                    index += 1
                continue
            source, _, destination = token.lstrip("+").partition(":")
            candidates.append((source, destination or None))
        if not candidates:
            continue
        pr_candidates = [
            (source, destination)
            for source, destination in candidates
            if _PR_FETCH_SOURCE_RE.fullmatch(source)
        ]
        if pr_candidates:
            pr_destination = pr_candidates[0][1]
            if write_fetch_head or pr_destination:
                events.append((column, _UNTRUSTED, pr_destination, paths, write_fetch_head, remote))
        else:
            source, target_ref = candidates[-1]
            state = (
                _TRUSTED
                if _STATIC_REF_RE.fullmatch(source) and source.upper() not in _GIT_TRANSIENT_REFS
                else _UNKNOWN
            )
            if "__PR_HEAD_REPOSITORY__" in remote:
                state = _UNTRUSTED
            elif "://" in remote or remote.startswith("git@"):
                state = _UNKNOWN
            if write_fetch_head or target_ref:
                events.append((column, state, target_ref, paths, write_fetch_head, remote))
    return events


def _git_remote_events(
    line: str, mask: list[bool]
) -> list[tuple[int, str, str, tuple[str, ...], str]]:
    """Track remote changes that can alter the provenance of a later fetch."""

    events: list[tuple[int, str, str, tuple[str, ...], str]] = []
    for column, command in _shell_command_segments(line, mask):
        tokens = _shell_command_tokens(command)
        if tokens is None:
            continue
        invocation = _git_command_index(tokens)
        if invocation is None:
            continue
        index, paths = invocation
        if index + 1 >= len(tokens) or tokens[index].lower() != "remote":
            continue
        operation = tokens[index + 1].lower()
        if operation not in {"add", "set-url"}:
            continue
        args = tokens[index + 2 :]
        mode = "replace"
        if operation == "set-url" and args and args[0] in {"--push", "--add", "--delete"}:
            if args[0] == "--push":
                continue  # Push URL does not affect fetch provenance.
            mode = "append" if args[0] == "--add" else "delete"
            args = args[1:]
        if len(args) < 2:
            continue
        remote, url = args[:2]
        state = _UNTRUSTED if "__PR_HEAD_REPOSITORY__" in url else _UNKNOWN
        events.append((column, remote, state, paths, mode))
    return events


def _gh_pr_checkout_changes(line: str, mask: list[bool]) -> list[tuple[int, str, str, str | None]]:
    """Recognize an executable GitHub CLI pull-request checkout."""

    changes: list[tuple[int, str, str, str | None]] = []
    for column, command in _shell_command_segments(line, mask):
        tokens = _shell_command_tokens(command)
        if (
            tokens is None
            or len(tokens) < 4
            or [token.lower() for token in tokens[:3]]
            != [
                "gh",
                "pr",
                "checkout",
            ]
        ):
            continue
        index = 3
        selector: str | None = None
        worktree: str | None = None
        while index < len(tokens):
            option = tokens[index]
            index += 1
            name, inline_value, value = option.partition("=")
            if name in {"--repo", "-R", "--branch", "-b", "--worktree"}:
                if not inline_value:
                    if index >= len(tokens):
                        break
                    value = tokens[index]
                    index += 1
                if name == "--worktree":
                    worktree = value
            elif option.startswith("-"):
                continue
            elif selector is None:
                selector = option
        if selector and (
            selector.isdigit() or selector == "__PR_NUMBER__" or _GH_PR_URL_RE.fullmatch(selector)
        ):
            changes.append((column, _UNTRUSTED, "GH_PR_CHECKOUT", worktree))
    return changes


def _build_source_path(
    shell_line: str | None, mask: list[bool], anchor_column: int, cwd: str | None
) -> tuple[str | None, bool]:
    """Resolve a local build path and whether this command builds local code."""

    if shell_line is None or cwd is None:
        return cwd, True
    separators = [
        index for index, char in enumerate(shell_line) if char in ";&|" and not mask[index]
    ]
    start = max((index + 1 for index in separators if index < anchor_column), default=0)
    end = min((index for index in separators if index > anchor_column), default=len(shell_line))
    segment = shell_line[start:end]
    if _PIP_COMMAND_RE.match(shell_line[anchor_column:]):
        command = shell_line[anchor_column:end]
        prefix = shell_line[start:anchor_column].rstrip()
        if prefix.endswith(("'", '"')) and command.rstrip().endswith(prefix[-1]):
            command = command.rstrip()[:-1]
        try:
            tokens = shlex.split(command, comments=True)
        except ValueError:
            return None, True
        index = 1
        while index < len(tokens) and tokens[index].startswith("-"):
            option = tokens[index]
            index += 1
            option_name, has_inline_value, _ = option.partition("=")
            if option_name in _PIP_GLOBAL_VALUE_OPTIONS and not has_inline_value:
                index += 1
            elif (
                option_name not in _PIP_GLOBAL_VALUE_OPTIONS
                and option not in _PIP_GLOBAL_SWITCH_OPTIONS
                and not re.fullmatch(r"-[vq]+", option)
            ):
                return None, True
        if index >= len(tokens) or tokens[index].lower() != "install":
            return cwd, False
        paths: list[str] = []
        index += 1
        while index < len(tokens):
            argument = tokens[index]
            if argument in {"-e", "--editable", "-r", "--requirement"}:
                index += 1
                if index >= len(tokens):
                    return None, True
                paths.append(tokens[index])
            elif argument.startswith(("-e=", "--editable=", "-r=", "--requirement=")):
                paths.append(argument.split("=", 1)[1])
            elif argument.startswith(("-e", "-r")) and len(argument) > 2:
                paths.append(argument[2:])
            elif argument in _PIP_NON_SOURCE_VALUE_OPTIONS:
                index += 1
                if index >= len(tokens):
                    return None, True
            elif argument == "." or argument.startswith(("./", "../", "/")):
                paths.append(argument)
            index += 1
        if not paths:
            return cwd, False
        return (_literal_workspace_path(paths[0], cwd) if len(paths) == 1 else None), True
    prefix_paths = [
        match.group("path")
        for match in _NPM_PREFIX_PATH_RE.finditer(segment)
        if not mask[start + match.start()]
    ]
    if not prefix_paths:
        return cwd, True
    if len(prefix_paths) != 1:
        return None, True
    return _literal_workspace_path(prefix_paths[0], cwd), True


def _source_after_ref_change(state: str, foreign_repository: bool, target: str) -> str:
    """A branch switch cannot turn a foreign repository into the base repo."""

    if target == _TRUSTED and foreign_repository:
        return _UNTRUSTED if state == _UNTRUSTED else _UNKNOWN
    return target


def _at_shell_command_start(line: str, mask: list[bool], column: int) -> bool:
    """Reject pip text printed as an argument to another shell command."""

    start = max(
        (
            index + 1
            for index, char in enumerate(line[:column])
            if char in ";&|" and not mask[index]
        ),
        default=0,
    )
    prefix = line[start:column].strip()
    return (
        not prefix
        or bool(re.fullmatch(r"(?:env\s+)?(?:[A-Za-z_]\w*=\S+\s*)+", prefix))
        or bool(re.fullmatch(r"(?:bash|sh)\s+-(?:l)?c\s+['\"]", prefix))
        or bool(re.fullmatch(r"python\d*(?:\.\d+)?\s+-m", prefix))
    )


def _printed_build_text(line: str, mask: list[bool], column: int) -> bool:
    """A build-tool word in a plain print command is not executed."""

    start = max(
        (
            index + 1
            for index, char in enumerate(line[:column])
            if char in ";&|" and not mask[index]
        ),
        default=0,
    )
    prefix = line[start:column].strip()
    return bool(re.match(r"(?:echo|printf)\b", prefix)) and "$(" not in prefix and "`" not in prefix


def _conditional_before_command(line: str, column: int) -> bool:
    """A command after ``&&`` or ``||`` may be skipped by the shell."""

    return (column > 0 and line[column] in "&|" and line[column - 1] == line[column]) or line[
        :column
    ].rstrip().endswith(("&&", "||"))


def _join_source_states(first: str, second: str) -> str:
    return first if first == second else _UNKNOWN


def _git_source_changes(line: str, mask: list[bool]) -> list[tuple[int, str, str, tuple[str, ...]]]:
    """Return ordered shell Git ref changes with target-only provenance."""

    changes: list[tuple[int, str, str, tuple[str, ...]]] = []
    for match in _GIT_SOURCE_CHANGE_RE.finditer(line):
        ref = match.group("ref").strip("'\"")
        if ref == "--":
            # ``git checkout -- path`` restores a path; it does not select a ref.
            continue
        if _contains_pr_head_reference(ref):
            state = _UNTRUSTED
        elif ref.upper() in _GIT_TRANSIENT_REFS:
            state = _UNKNOWN
        elif _STATIC_REF_RE.fullmatch(ref) and not ref.startswith("-"):
            state = _TRUSTED
        else:
            state = _UNKNOWN
        changes.append((match.start(), state, ref, ()))
    for column, command in _shell_command_segments(line, mask):
        tokens = _shell_command_tokens(command)
        if tokens is None:
            continue
        invocation = _git_command_index(tokens)
        if invocation is None:
            continue
        index, paths = invocation
        if not paths and index == 1:
            continue  # The existing matcher handles plain Git commands.
        if index >= len(tokens) or tokens[index].lower() not in {"checkout", "switch"}:
            continue
        args = tokens[index + 1 :]
        while args and args[0] in {"--detach", "--force"}:
            args = args[1:]
        if not args or args[0] == "--":
            continue
        ref = args[0]
        if _contains_pr_head_reference(ref):
            state = _UNTRUSTED
        elif ref.upper() in _GIT_TRANSIENT_REFS:
            state = _UNKNOWN
        elif _STATIC_REF_RE.fullmatch(ref) and not ref.startswith("-"):
            state = _TRUSTED
        else:
            state = _UNKNOWN
        changes.append((column, state, ref, paths))
    changes.extend(
        (column, state, ref, ()) for column, state, ref, _ in _gh_pr_checkout_changes(line, mask)
    )
    return changes


def _run_may_select_pr_source(step: StepSegment) -> bool:
    """Keep a job visible when executable Git text selects a PR source."""

    quote: str | None = None
    for _, line in sorted(_run_shell_lines(step).items()):
        mask, quote, _ = _shell_quote_mask(line, quote)
        if any(
            state == _UNTRUSTED and not mask[column]
            for column, state, _, _ in _git_source_changes(line, mask)
        ):
            return True
        if any(state == _UNTRUSTED for _, state, _, _, _, _ in _git_fetch_events(line, mask)):
            return True
        if any(state == _UNTRUSTED for _, _, state, _, _ in _git_remote_events(line, mask)):
            return True
    return False


def _job_for_line(jobs: list[JobSegment], line: int) -> JobSegment | None:
    return next((job for job in jobs if job.start_line <= line <= job.end_line), None)


class _OrderedPrBuildPattern(ContextPattern):
    """Keep build matches only on a feasible PR-head execution path.

    ``ContextPattern`` supplies the existing mutation-hardened anchor and
    source evidence.  This wrapper adds two conservative facts that the
    job-wide join cannot express: source-revision state in step order and a
    step guard that is mutually exclusive with PR events.
    """

    def __init__(
        self,
        anchor: str = (
            rf"(?:{_BUILD_TOOL_ANCHOR}|{_NPM_PREFIX_BUILD_ANCHOR}|{_PIP_INSTALL_ANCHOR})"
        ),
        exclude: list[str] | None = None,
    ) -> None:
        super().__init__(
            anchor=anchor,
            requires=_PR_HEAD_CHECKOUT,
            scope="job",
            exclude=exclude or [r"^\s*#"],
            expr_augment_requires=True,
        )
        self._source_anchor_re = re.compile(anchor)

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        raw = super().check(content, lines)
        if not raw:
            return []

        jobs = [job for job in for_each_job(content) if job.name]
        steps = for_each_step(content)
        if not jobs or not steps:
            return raw

        raw_by_line = dict(raw)
        kept: set[int] = set()
        resolved: set[int] = set()
        workflow_default = _default_working_path(lines, 0, ".")

        for job in jobs:
            job_lines = {line for line in raw_by_line if job.start_line <= line <= job.end_line}
            if not job_lines:
                continue
            job_steps = [step for step in steps if step.job_name == job.name]
            if not any(
                (_checkout_may_use_pr_source(step) or _run_may_select_pr_source(step))
                and not _excludes_pr_path(_direct_if(step))
                for step in job_steps
            ):
                resolved.update(job_lines)
                continue
            first_step_line = min((step.start_line for step in job_steps), default=job.end_line + 1)
            job_header_indent = len(job.body_lines[0]) - len(job.body_lines[0].lstrip())
            pre_step_lines = job.body_lines[: first_step_line - job.start_line]
            child_indents = [
                len(line) - len(line.lstrip())
                for line in pre_step_lines[1:]
                if line.strip() and len(line) - len(line.lstrip()) > job_header_indent
            ]
            default_path = _default_working_path(
                pre_step_lines,
                min(child_indents) if child_indents else job_header_indent + 2,
                workflow_default,
            )
            sources: dict[str, tuple[str, bool]] = {".": (_TRUSTED, False)}
            fetched_refs: dict[str, dict[str, str]] = {}
            remote_states: dict[str, dict[str, str]] = {}
            uncertain_layout = False
            for step in job_steps:
                step_candidates = {
                    line for line in job_lines if step.start_line <= line <= step.end_line
                }
                pr_excluded = _excludes_pr_path(_direct_if(step))
                checkout_state = _checkout_action_state(step)
                cwd = _step_working_path(step, default_path)
                child_scopes: dict[int, list[tuple[int, int]]] = {}
                shell_lines = _run_shell_lines(step, child_scopes)
                script_indent = min(
                    (
                        len(line) - len(line.lstrip(" "))
                        for line in shell_lines.values()
                        if line.strip()
                    ),
                    default=0,
                )
                action_input_step = any(
                    _USES_LINE_RE.match(line) for line in step.body_lines
                ) and not any(_RUN_LINE_RE.match(line) for line in step.body_lines)
                shell_quote: str | None = None
                heredoc_queue: deque[tuple[str, bool]] = deque()

                for offset, source_line in enumerate(step.body_lines):
                    absolute_line = step.start_line + offset
                    shell_line = shell_lines.get(offset)
                    if heredoc_queue and shell_line is not None:
                        heredoc_delimiter, heredoc_strip_tabs = heredoc_queue[0]
                        body = shell_line[script_indent:]
                        if heredoc_strip_tabs:
                            body = body.lstrip("\t")
                        if body == heredoc_delimiter:
                            heredoc_queue.popleft()
                        if absolute_line in step_candidates:
                            resolved.add(absolute_line)
                        continue
                    shell_mask: list[bool] = []
                    comment_start: int | None = None
                    if shell_line is not None:
                        shell_mask, shell_quote, comment_start = _shell_quote_mask(
                            shell_line, shell_quote
                        )
                    openers = (
                        [
                            match
                            for match in _HEREDOC_OPEN_RE.finditer(shell_line)
                            if not shell_mask[match.start()]
                        ]
                        if shell_line is not None
                        else []
                    )
                    if shell_line is not None:
                        opener_columns = {match.start() for match in openers}
                        if any(
                            shell_line[index : index + 2] == "<<"
                            and not shell_mask[index]
                            and index not in opener_columns
                            for index in range(len(shell_line) - 1)
                        ):
                            uncertain_layout = True
                    transitions = (
                        _git_source_changes(shell_line, shell_mask)
                        if shell_line is not None
                        else []
                    )
                    anchors = list(self._source_anchor_re.finditer(source_line))
                    events: list[tuple[int, str, str | None]] = []
                    git_states = {column: state for column, state, _, _ in transitions}
                    git_paths = {column: paths for column, _, _, paths in transitions}
                    fetch_states: dict[int, str] = {}
                    fetch_paths: dict[int, tuple[str, ...]] = {}
                    fetch_writes: dict[int, bool] = {}
                    fetch_remotes: dict[int, str] = {}
                    changed_remotes: dict[int, tuple[str, str, tuple[str, ...], str]] = {}
                    gh_worktrees: dict[int, str | None] = {}
                    if shell_line is not None:
                        for cd_match in _SHELL_CD_RE.finditer(shell_line):
                            if not shell_mask[cd_match.start()]:
                                events.append(
                                    (cd_match.start("command"), "cd", cd_match.group("path"))
                                )
                        for column, state, destination, paths, writes, remote in _git_fetch_events(
                            shell_line, shell_mask
                        ):
                            fetch_states[column] = state
                            fetch_paths[column] = paths
                            fetch_writes[column] = writes
                            fetch_remotes[column] = remote
                            events.append((column, "fetch", destination))
                        for column, remote, state, paths, mode in _git_remote_events(
                            shell_line, shell_mask
                        ):
                            changed_remotes[column] = remote, state, paths, mode
                            events.append((column, "remote", None))
                        gh_worktrees = {
                            column: path
                            for column, _, _, path in _gh_pr_checkout_changes(
                                shell_line, shell_mask
                            )
                        }
                    for column, _, ref, _ in transitions:
                        if not shell_mask[column]:
                            events.append((column, "git", ref))
                    if (
                        shell_line is None
                        and action_input_step
                        and absolute_line in step_candidates
                    ):
                        resolved.add(absolute_line)
                    for anchor in anchors:
                        if absolute_line not in step_candidates:
                            continue
                        if comment_start is not None and anchor.start() >= comment_start:
                            resolved.add(absolute_line)
                        elif shell_line is not None:
                            if _printed_build_text(shell_line, shell_mask, anchor.start()) or (
                                _PIP_COMMAND_RE.match(shell_line[anchor.start() :])
                                and not _at_shell_command_start(
                                    shell_line, shell_mask, anchor.start()
                                )
                            ):
                                resolved.add(absolute_line)
                            else:
                                events.append((anchor.start(), "build", None))
                    outer_cwd: str | None = cwd
                    scoped_cwds: dict[tuple[int, int], str | None] = {}
                    line_child_scopes = child_scopes.get(offset, [])
                    for column, kind, value in sorted(events):
                        if pr_excluded:
                            if kind == "build":
                                resolved.add(absolute_line)
                            continue
                        child_span = next(
                            (span for span in line_child_scopes if span[0] <= column < span[1]),
                            None,
                        )
                        if child_span is not None and child_span not in scoped_cwds:
                            scoped_cwds[child_span] = outer_cwd
                        cwd = scoped_cwds[child_span] if child_span is not None else outer_cwd
                        if kind == "cd":
                            next_cwd = _literal_workspace_path(value or "", cwd) if cwd else None
                            if shell_line is not None and _conditional_before_command(
                                shell_line, column
                            ):
                                cwd = next_cwd if next_cwd == cwd else None
                            else:
                                cwd = next_cwd
                        elif kind == "remote":
                            remote, state, paths, mode = changed_remotes[column]
                            remote_cwd = cwd
                            for git_path in paths:
                                remote_cwd = (
                                    _literal_workspace_path(git_path, remote_cwd)
                                    if remote_cwd is not None
                                    else None
                                )
                            if remote_cwd is None:
                                uncertain_layout = True
                            else:
                                source_key = _source_key(sources, remote_cwd)
                                states = remote_states.setdefault(source_key, {})
                                previous = states.get(
                                    remote, _TRUSTED if remote == "origin" else _UNKNOWN
                                )
                                next_state = (
                                    previous
                                    if mode == "append"
                                    else _UNKNOWN
                                    if mode == "delete"
                                    else state
                                )
                                states[remote] = (
                                    _join_source_states(previous, next_state)
                                    if shell_line is not None
                                    and _conditional_before_command(shell_line, column)
                                    else next_state
                                )
                        elif kind == "fetch":
                            fetch_cwd = cwd
                            for git_path in fetch_paths.get(column, ()):
                                fetch_cwd = (
                                    _literal_workspace_path(git_path, fetch_cwd)
                                    if fetch_cwd is not None
                                    else None
                                )
                            if fetch_cwd is None:
                                uncertain_layout = True
                            else:
                                source_key = _source_key(sources, fetch_cwd)
                                refs = fetched_refs.setdefault(source_key, {})
                                state, foreign = sources.get(source_key, (_UNKNOWN, False))
                                remote = fetch_remotes.get(column, "")
                                remote_state = remote_states.get(source_key, {}).get(
                                    remote, _TRUSTED if remote == "origin" else _UNKNOWN
                                )
                                fetched_state = fetch_states.get(column, _UNKNOWN)
                                if remote_state == _UNTRUSTED:
                                    fetched_state = _UNTRUSTED
                                elif remote_state == _UNKNOWN and fetched_state != _UNTRUSTED:
                                    fetched_state = _UNKNOWN
                                target_state = _source_after_ref_change(
                                    state, foreign, fetched_state
                                )
                                conditional = (
                                    shell_line is not None
                                    and _conditional_before_command(shell_line, column)
                                )
                                if fetch_writes.get(column, True):
                                    refs["FETCH_HEAD"] = (
                                        _join_source_states(
                                            refs.get("FETCH_HEAD", _UNKNOWN), target_state
                                        )
                                        if conditional
                                        else target_state
                                    )
                                if value:
                                    named_state = (
                                        _join_source_states(refs.get(value, _UNKNOWN), target_state)
                                        if conditional
                                        else target_state
                                    )
                                    refs[value] = named_state
                                    if value.startswith("refs/remotes/"):
                                        refs[value.removeprefix("refs/remotes/")] = named_state
                                    elif value.startswith("refs/heads/"):
                                        refs[value.removeprefix("refs/heads/")] = named_state
                        elif kind == "git":
                            git_cwd = cwd
                            for git_path in git_paths.get(column, ()):
                                git_cwd = (
                                    _literal_workspace_path(git_path, git_cwd)
                                    if git_cwd is not None
                                    else None
                                )
                            if git_cwd is None:
                                uncertain_layout = True
                            elif value == "GH_PR_CHECKOUT" and column in gh_worktrees:
                                worktree = gh_worktrees[column]
                                if worktree is None:
                                    source_key = _source_key(sources, git_cwd)
                                    sources[source_key] = (_UNTRUSTED, False)
                                else:
                                    checkout_path = _literal_workspace_path(worktree, git_cwd)
                                    if checkout_path is None:
                                        uncertain_layout = True
                                    else:
                                        sources[checkout_path] = (_UNTRUSTED, False)
                            else:
                                source_key = _source_key(sources, git_cwd)
                                state, foreign = sources.get(source_key, (_UNKNOWN, False))
                                target_state = git_states.get(column, _UNKNOWN)
                                target_state = fetched_refs.get(source_key, {}).get(
                                    value or "", target_state
                                )
                                target_state = _source_after_ref_change(
                                    state, foreign, target_state
                                )
                                if shell_line is not None and _conditional_before_command(
                                    shell_line, column
                                ):
                                    target_state = _join_source_states(state, target_state)
                                sources[source_key] = (
                                    target_state,
                                    foreign,
                                )
                        else:
                            resolved.add(absolute_line)
                            build_path, local_build = _build_source_path(
                                shell_line, shell_mask, column, cwd
                            )
                            build_source_key = (
                                _source_key(sources, build_path) if build_path else None
                            )
                            if local_build and (
                                uncertain_layout
                                or build_path is None
                                or sources.get(build_source_key or ".", (_UNKNOWN, False))[0]
                                != _TRUSTED
                            ):
                                kept.add(absolute_line)
                        if child_span is not None:
                            scoped_cwds[child_span] = cwd
                        else:
                            outer_cwd = cwd

                    cwd = outer_cwd

                    heredoc_queue.extend(
                        (opener.group("delimiter"), opener.group("operator") == "<<-")
                        for opener in openers
                    )

                if checkout_state is not None and not pr_excluded:
                    state, foreign_repository, checkout_path = checkout_state
                    if checkout_path is None:
                        uncertain_layout = True
                    else:
                        sources[checkout_path] = state, foreign_repository

        # Any match outside a resolvable step remains visible.  Parser gaps must
        # never become silent suppressions.
        kept.update(set(raw_by_line) - resolved)
        return [(line, snippet) for line, snippet in raw if line in kept]


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

RULES: list[Rule] = [
    # =========================================================================
    # LOTP-GH-001: Build tool runs in same job that checks out PR code
    # =========================================================================
    Rule(
        id="LOTP-GH-001",
        finding_family="pipeline_tool_execution",
        title="Build tool executed in job that checks out pull-request code (LOTP)",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A build tool (npm, pip, make, cargo, mvn, gradle, docker, etc.) "
            "runs in the same job that checks out attacker-controlled "
            "pull-request code — via `github.event.pull_request.head.sha`, "
            "`github.head_ref`, or `github.event.workflow_run.head_branch`. "
            "Build tools execute lifecycle scripts or build hooks from the "
            "checked-out source — `postinstall` scripts in package.json, "
            "`cmdclass` handlers in setup.py, `build.rs` in Rust, "
            "//go:generate directives in Go, plugin execution via pom.xml, "
            "RUN directives in a Dockerfile — so the attacker's code runs "
            "with the workflow's permissions and secrets. This is the pattern "
            "that compromised Ultralytics YOLO in December 2024: a workflow "
            "checked out a fork PR and ran `pip install`, which executed "
            "setup.py from the fork. Taintly follows explicit checkout and "
            "branch-switch operations in step order, and excludes a build "
            "step only when a fixed trusted ref or a mutually exclusive "
            "non-PR event guard is proven. Dynamic source changes and complex "
            "guards remain visible for review."
        ),
        pattern=_OrderedPrBuildPattern(),
        remediation=(
            "Do not run build tools in a job that has checked out untrusted "
            "PR code alongside your secrets. Apply one of the following:\n"
            "\n"
            "1. Split the workflow: use `pull_request` (no secrets, no write "
            "   token) to build and test fork code; use a separate workflow "
            "   gated on `workflow_run` or a protected branch push to run "
            "   the privileged steps — and have that privileged workflow "
            "   check out the BASE repo SHA, not the fork head.\n"
            "\n"
            "2. If the job must run in a privileged context, build the "
            "   untrusted code in a sandboxed container with no secrets and "
            "   no network access to internal resources.\n"
            "\n"
            "3. For `npm install` / `npm ci` specifically, add "
            "   `--ignore-scripts` to skip lifecycle hooks. This stops the "
            "   most common JS lifecycle vector but does NOT protect against "
            "   native-addon compilation or other build-time execution.\n"
            "\n"
            "See also the GitHub Security Lab write-up on preventing "
            "`pull_request_target` pwn requests."
        ),
        reference="https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        test_positive=[
            # pull_request_target + PR head checkout + pip install .
            "on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: pip install .",
            # PR head + npm install
            "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.ref }}\n"
            "      - run: npm install",
            # workflow_run head_branch + make
            "jobs:\n  deploy:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.event.workflow_run.head_branch }}\n"
            "      - run: make build",
        ],
        test_negative=[
            # Build tool in a job that does NOT check out PR code
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: npm install",
            # PR head checkout but no build tool
            "jobs:\n  comment:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: echo 'hello'",
            # Commented out
            "jobs:\n  build:\n    steps:\n      # - run: npm install\n      - run: echo ok",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker opens a pull request that modifies a manifest the "
            "build tool reads (package.json, setup.py, Makefile, pom.xml, "
            "Dockerfile, etc.). When the workflow checks out the PR head and "
            "runs the build tool, the manifest's lifecycle hooks execute "
            "with the workflow's full permissions and bound secrets — "
            "typically a write-scoped GITHUB_TOKEN, cloud OIDC tokens, and "
            "any repo/org secrets the job can see."
        ),
        incidents=["Ultralytics (Dec 2024)"],
    ),
    # =========================================================================
    # LOTP-GH-002 is intentionally NOT defined.
    #
    # The v2 requirements list a rule "build tool invoked in any
    # pull_request_target workflow" as LOTP-002.  The existing rule
    # SEC4-GH-011 already covers that scope at CRITICAL severity with a
    # well-tuned false-positive filter (anchor_job_exclude for jobs gated
    # to non-PRT events, exclusions for English prose like "make sure",
    # narrower pip-install pattern that skips `pip install PackageName`).
    # Shipping a second rule at the same scope would only duplicate
    # findings.  Expanding SEC4-GH-011's build-tool regex to match LOTP's
    # broader tool list is tracked as a follow-up.
    # =========================================================================
    # =========================================================================
    # LOTP-GH-003: npm install / npm ci without --ignore-scripts
    # =========================================================================
    Rule(
        id="LOTP-GH-003",
        finding_family="pipeline_tool_execution",
        title="npm install / npm ci without --ignore-scripts in externally-triggered workflow",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A workflow runs `npm install`, `npm ci`, `yarn install`, or "
            "`pnpm install` without the `--ignore-scripts` flag in a job "
            "that also processes untrusted pull-request input. npm executes "
            "`preinstall`, `install`, and `postinstall` lifecycle scripts "
            "from every dependency's package.json by default — including "
            "scripts declared by the top-level package.json checked out "
            "from the PR. Adding `--ignore-scripts` disables this "
            "behaviour and closes the most common LOTP vector for "
            "JavaScript builds."
        ),
        pattern=_OrderedPrBuildPattern(
            anchor=(
                r"\b(?:npm\s+(?:install|ci|i)|yarn(?:\s+install)?|pnpm\s+(?:install|i))\b"
                "|" + _NPM_PREFIX_INSTALL_ANCHOR
            ),
            exclude=[
                r"^\s*#",
                r"--ignore-scripts",  # already mitigated — don't fire
            ],
        ),
        remediation=(
            "Add `--ignore-scripts` to every npm / yarn / pnpm install "
            "command in workflows that process pull-request input:\n"
            "\n"
            "  - run: npm ci --ignore-scripts\n"
            "  - run: npm install --ignore-scripts\n"
            "\n"
            "If some scripts are genuinely needed (e.g. a native-addon "
            "build step you own), run them explicitly after the install "
            "against a known allowlist — do not opt back in to implicit "
            "lifecycle execution.\n"
            "\n"
            "For pnpm, additionally set the `ignore-scripts=true` config "
            "key in `.npmrc` to make the default sticky."
        ),
        reference="https://docs.npmjs.com/cli/v10/using-npm/scripts#ignoring-scripts",
        test_positive=[
            "jobs:\n  test:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: npm install",
            "jobs:\n  test:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.head_ref }}\n"
            "      - run: npm ci",
        ],
        test_negative=[
            # --ignore-scripts present → safe
            "jobs:\n  test:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: npm ci --ignore-scripts",
            # No PR-head checkout → base repo code only, not LOTP
            "jobs:\n  build:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: npm install",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "npm's default lifecycle-script execution is the single most "
            "exploited LOTP vector. An attacker can trigger the workflow "
            "by opening a PR that edits package.json's `postinstall` "
            "field; npm runs the attacker's command during `npm install` "
            "before any test or lint step ever executes, so the payload "
            "runs regardless of what the rest of the workflow does."
        ),
        incidents=["Ultralytics (Dec 2024)"],
    ),
    # =========================================================================
    # LOTP-GH-004: Build tool after actions/download-artifact
    # =========================================================================
    Rule(
        id="LOTP-GH-004",
        finding_family="pipeline_tool_execution",
        title="Build tool executed after actions/download-artifact (untrusted artefact LOTP)",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A build tool runs in the same job as `actions/download-artifact`. "
            "Artifacts downloaded from another workflow — especially one "
            "triggered by `pull_request` that could have been influenced by "
            "a fork — carry no provenance guarantee. If the downloaded "
            "artefact contains a manifest or source tree the build tool "
            "reads, the build becomes a LOTP sink for whatever code produced "
            "the artefact."
        ),
        pattern=ContextPattern(
            anchor=_BUILD_TOOL_ANCHOR,
            requires=_CROSS_WORKFLOW_UNTRUSTED_ARTIFACT,
            scope="job",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Treat every downloaded artefact as untrusted input. Before "
            "running a build tool against it:\n"
            "\n"
            "- Verify artefact provenance — the producing workflow must not "
            "  have been triggered by fork PRs. Check "
            "  `github.event.workflow_run.event` inside the consumer.\n"
            "- Verify artefact integrity — compare a signed hash, or "
            "  require the artefact to be signed (e.g. with Sigstore "
            "  cosign) by the CI identity.\n"
            "- Extract the artefact into a scratch directory and validate "
            "  its shape before letting a build tool loose on it.\n"
            "\n"
            "If verification is not feasible, move the build step into the "
            "producing workflow where the input provenance is clear."
        ),
        reference="https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        test_positive=[
            # Cross-workflow download (run-id from github.event.workflow_run —
            # the artefact came from another, possibly fork-influenced, run) +
            # build tool: the genuine untrusted-artefact LOTP shape.
            "jobs:\n  release:\n    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "        with:\n          name: build-output\n"
            "          run-id: ${{ github.event.workflow_run.id }}\n"
            "          github-token: ${{ secrets.GITHUB_TOKEN }}\n"
            "      - run: npm publish",
            "jobs:\n  deploy:\n    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "        with:\n          run-id: ${{ github.event.workflow_run.id }}\n"
            "      - run: docker build -t myapp .",
        ],
        test_negative=[
            # Same-run upload->download handoff (no run-id / workflow_run) —
            # the artefact was produced by a trusted earlier job in THIS run.
            # This was the dominant false positive before the provenance gate.
            "jobs:\n  release:\n    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "        with:\n          name: build-output\n"
            "      - run: npm publish",
            # No build tool after download — just using the artefact content as data
            "jobs:\n  deploy:\n    steps:\n"
            "      - uses: actions/download-artifact@v4\n"
            "        with:\n          run-id: ${{ github.event.workflow_run.id }}\n"
            "      - run: aws s3 cp dist/ s3://bucket/ --recursive",
            # Build tool without download-artifact
            "jobs:\n  build:\n    steps:\n      - run: npm install",
        ],
        stride=["T"],
        threat_narrative=(
            "The `workflow_run` trigger is GitHub's official escape hatch "
            "from pull_request_target's dangers — but the common shape is "
            "'fork-PR workflow uploads artefact, privileged workflow "
            "downloads it and does the release.' Without artefact-provenance "
            "verification the fix becomes its own LOTP: attacker-controlled "
            "artefact content flows into a privileged build step and the "
            "lifecycle-script / build-hook problem is back."
        ),
    ),
    # =========================================================================
    # LOTP-GH-005: npm/yarn/pnpm install runs lifecycle scripts in a job
    # holding an exfil-worthy secret.  Shai-Hulud class (Sep 2025 + Nov 2025
    # variants — worm-like self-propagation via postinstall scripts).  The
    # specific attack: an npm package you depend on gets compromised at
    # publish time; its `postinstall` script reads process env + ~/.npmrc +
    # ~/.aws / ~/.config / .git/config and exfiltrates via HTTP to an
    # attacker-controlled collector.  Any workflow that (a) runs
    # `npm install` / `npm ci` / `yarn install` / `pnpm install` WITHOUT
    # `--ignore-scripts`, AND (b) holds a secret with exfil value
    # (NPM_TOKEN, id-token: write, contents: write, packages: write) in
    # the same job is on the attack surface.
    #
    # References: https://www.sysdig.com/blog/shai-hulud-the-novel-self-
    # replicating-worm-infecting-hundreds-of-npm-packages ;
    # https://unit42.paloaltonetworks.com/npm-supply-chain-attack/ ;
    # https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-
    # 2-0-guidance-for-detecting-investigating-and-defending-against-the-
    # supply-chain-attack/
    # =========================================================================
    Rule(
        id="LOTP-GH-005",
        finding_family="pipeline_tool_execution",
        title=(
            "npm/yarn/pnpm install runs lifecycle scripts in a job "
            "holding an exfil-worthy secret (Shai-Hulud class)"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A job runs ``npm install`` / ``npm ci`` / ``yarn install`` / "
            "``pnpm install`` WITHOUT ``--ignore-scripts``, and that same "
            "job holds an exfil-worthy secret — ``NPM_TOKEN`` in env, "
            "``id-token: write``, or a package-write permission "
            "(``contents: write`` / ``packages: write`` / "
            "``deployments: write``).  Every direct and transitive "
            "dependency's ``postinstall`` / ``preinstall`` hook runs in "
            "that shell, with the secret visible in the process env.  "
            "This is the attack surface Shai-Hulud (Sep 2025) and its "
            "Shai-Hulud 2.0 variant (Nov 2025, 25,000+ repos infected) "
            "weaponised: one compromised dependency publishes a new "
            "version whose postinstall script reads ``$NPM_TOKEN`` / "
            "``$GITHUB_TOKEN`` / `~/.aws/credentials` and uses the "
            "stolen token to republish every other package the maintainer "
            "owns with the same payload.  The CI workflow doesn't need "
            "to look exotic — a plain `npm publish` job is enough."
        ),
        pattern=ContextPattern(
            # Anchor: a `run:` line invoking the install, NOT ignoring
            # lifecycle scripts.  Per-line so the finding points at the
            # install command.  `(?!...)` negative lookahead excludes
            # lines that already pass `--ignore-scripts` on the same
            # line.  Doesn't catch cases where --ignore-scripts is on
            # a continuation line, but that's a small gap (the rule
            # fires at HIGH, so a reviewer reads the job anyway).
            anchor=(
                r"\b(?:"
                r"npm\s+(?:install|i|ci)"
                r"|yarn\s+(?:install|add)"
                r"|pnpm\s+(?:install|i|add)"
                r")\b(?:(?!--ignore-scripts).)*$"
            ),
            # Requires (per-job): exfil-worthy secret.  NPM_TOKEN is
            # explicit because it's the canonical Shai-Hulud target.
            # `id-token: write` enables OIDC federation → cloud creds.
            # `contents: write` / `packages: write` / `deployments:
            # write` let a compromised postinstall push code / publish
            # packages / trigger deployments using the GITHUB_TOKEN.
            requires=(
                r"(?:"
                r"\bNPM_TOKEN\b"
                r"|\bid-token:\s*write\b"
                r"|\b(?:contents|packages|deployments):\s*write\b"
                r"|\bsecrets\.NPM_TOKEN\b"
                r")"
            ),
            scope="job",
            exclude=[
                r"^\s*#",
                # Lines where --ignore-scripts is paired with the
                # install command are already safe on this axis.
                r"--ignore-scripts",
                # Lines that are clearly documentation in `name:` /
                # `description:` / `title:` keys.  Allow optional
                # `- ` list-item marker before the key (steps use
                # `      - name: Foo` inline).
                r"^\s*(?:-\s*)?(?:name|description|title):",
                # Exclude package-manager self-bootstraps
                # (``npm install -g npm@x``, ``npm install -g
                # pnpm`` etc.). These install the package manager
                # itself from the registry; they don't run
                # lifecycle scripts of an attacker-controlled
                # dependency. Bumping npm to enable trusted
                # publishing is the recommended hardening, not the
                # attack vector. Also covers the analogous
                # ``npm install -g yarn`` / ``-g pnpm`` shapes.
                r"\b(?:npm|yarn|pnpm)\s+(?:install|i|add)\s+-g\s+(?:npm|pnpm|yarn|corepack)\b",
            ],
        ),
        remediation=(
            "Pass `--ignore-scripts` to every `npm install` / `npm ci` /\n"
            "`yarn install` / `pnpm install` in a job that holds an\n"
            "exfil-worthy secret.  This blocks the postinstall / preinstall\n"
            "lifecycle hooks that Shai-Hulud-class attacks abuse.  For\n"
            "workflows that genuinely need lifecycle scripts (native-addon\n"
            "builds, husky, electron-builder), split into two jobs: one\n"
            "without secrets that runs the install and caches node_modules,\n"
            "and a second that restores the cache and runs the privileged\n"
            "step.  Also lock the lockfile (`npm ci` over `npm install`,\n"
            "`yarn install --frozen-lockfile`, `pnpm install\n"
            "--frozen-lockfile`) so a dependency's new version can't be\n"
            "silently pulled.\n"
            "Run `taintly --guide LOTP-GH-005` for the full checklist.\n"
            "Or apply the opt-in fix: `taintly --fix-npm-ignore-scripts`."
        ),
        reference=(
            "https://www.sysdig.com/blog/shai-hulud-the-novel-self-replicating-worm-infecting-hundreds-of-npm-packages; "
            "https://unit42.paloaltonetworks.com/npm-supply-chain-attack/; "
            "https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/"
        ),
        test_positive=[
            # npm install + NPM_TOKEN — the classic Shai-Hulud surface
            (
                "jobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - run: npm install\n"
                "        env:\n          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}"
            ),
            # npm ci + contents: write
            (
                "jobs:\n  release:\n    runs-on: ubuntu-latest\n"
                "    permissions:\n      contents: write\n"
                "    steps:\n      - run: npm ci"
            ),
            # yarn install + id-token: write (OIDC publish via trusted-publishing)
            (
                "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
                "    permissions:\n      id-token: write\n"
                "    steps:\n      - run: yarn install"
            ),
            # pnpm install + packages: write
            (
                "jobs:\n  pub:\n    runs-on: ubuntu-latest\n"
                "    permissions:\n      packages: write\n"
                "    steps:\n      - run: pnpm install"
            ),
        ],
        test_negative=[
            # Install explicitly with --ignore-scripts — safe
            (
                "jobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - run: npm install --ignore-scripts\n"
                "        env:\n          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}"
            ),
            # npm install in a job without any exfil-worthy secret — safe
            (
                "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
                "    permissions:\n      contents: read\n"
                "    steps:\n      - run: npm install"
            ),
            # Package-manager self-bootstrap — ``npm install -g
            # npm@x`` in a job with id-token: write.  This installs
            # the package manager itself (foundational
            # infrastructure published by npm Inc.) and doesn't
            # run lifecycle scripts of an attacker-controlled
            # dependency.  Bumping npm to a specific version to
            # enable trusted publishing is the recommended
            # hardening, not a supply-chain risk.
            (
                "jobs:\n  publish:\n    runs-on: ubuntu-latest\n"
                "    permissions:\n      id-token: write\n"
                "    steps:\n      - run: npm install -g npm@11.12.0"
            ),
            # NPM_TOKEN in job but install is commented out
            (
                "jobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      # - run: npm install\n"
                "      - run: echo 'deploy skipped'\n"
                "        env:\n          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}"
            ),
            # Descriptive text that mentions npm install in a name field
            (
                "jobs:\n  publish:\n    runs-on: ubuntu-latest\n"
                "    permissions:\n      contents: write\n"
                "    steps:\n      - name: Skip npm install for cached deps\n"
                "        run: echo noop"
            ),
        ],
        stride=["I", "T", "S"],
        threat_narrative=(
            "A transitive npm / yarn / pnpm dependency gets compromised "
            "at publish time (stolen maintainer token, typosquat, legit "
            "maintainer account takeover).  The new version's "
            "``postinstall`` script reads process env and the runner's "
            "home directory (``~/.npmrc``, ``~/.aws/credentials``, "
            "``.git/config``) and exfiltrates via HTTP POST.  When the "
            "install runs in a job that holds ``NPM_TOKEN`` — or any "
            "write-scoped secret — the secret is visible in the "
            "environment the postinstall script executes in.  "
            "Shai-Hulud (September 2025) spread worm-style through "
            "~200 packages in 24 hours; Shai-Hulud 2.0 (November 2025) "
            "affected 25,000+ repos and 350+ maintainers."
        ),
        confidence="medium",
        incidents=[
            "Shai-Hulud (Sep 2025)",
            "Shai-Hulud 2.0 (Nov 2025, 25k+ repos)",
        ],
    ),
]
