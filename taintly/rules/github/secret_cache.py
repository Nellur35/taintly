"""Bounded secret -> process output -> cache-save analysis.

This checks workflow usage, not tool internals or installed versions. Direct
environment serialization is evidence of secret-bearing output. Cargo's target
directory is an output convention: a build with secrets is a review candidate,
not proof that a tool leaked them. Branch scope and PR access require review.

Supported shell is a linear POSIX command sequence. Dynamic paths, child scripts,
PowerShell, workspace manifests and arbitrary tool output are outside this model.
The structural reader/engine discloses YAML cutoffs independently.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass
from types import SimpleNamespace

from taintly.eventguard import (
    UNCONSTRAINED,
    GuardConstraints,
    event_guard_verdict,
    guard_constraints,
    intersect_constraints,
    union_constraints,
)
from taintly.models import IncompletePatternMatches, Platform, Rule, Severity
from taintly.parsers.gha_expr import (
    ExprSyntaxError,
    iter_expression_bodies,
    result_provenance_paths,
)
from taintly.parsers.structural import Event, EventKind, triggers, walk_workflow
from taintly.parsers.structural.tokenizer import Token, TokenizerError, TokenKind, tokenize

_ROOT = "/__workspace__"
_HOME = "/__home__"
_GITHUB_ENV = "/__github_env__"
_SECRET = "__taintly_secret__"  # nosec B105 - analysis marker, not a credential
_UNKNOWN = "__taintly_unknown__"
_LITERAL_DOLLAR = "__literal_dollar__"
_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))")
_ASSIGNMENT = re.compile(r"^([A-Za-z_]\w*)=(.*)$", re.DOTALL)
# GitHub default cache-write triggers, verified 2026-10-11:
# https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching
# Other events need an explicit workflow/job cache-mode write override.
_WRITE_EVENTS = {
    "push",
    "workflow_dispatch",
    "repository_dispatch",
    "delete",
    "registry_package",
    "page_build",
    "schedule",
}


def _render(value: str, env: dict[str, str]) -> str:
    """Resolve literal path contexts and secret value provenance, not comparisons."""
    folded = {name.lower(): val for name, val in env.items()}
    pieces: list[str] = []
    offset = 0
    for body in iter_expression_bodies(value):
        try:
            paths = result_provenance_paths(body)
        except ExprSyntaxError:
            paths = []
        replacement = _UNKNOWN
        if any(
            path == "secrets"
            or path.startswith("secrets.")
            or path == "github.token"
            or (path.startswith("env.") and _SECRET in folded.get(path[4:], ""))
            for path in paths
        ):
            replacement = _SECRET
        elif body.strip().lower() == "github.workspace":
            replacement = _ROOT
        elif re.fullmatch(r"\s*env\.[\w]+\s*", body, re.IGNORECASE):
            replacement = folded.get(body.strip()[4:].lower(), _UNKNOWN)
        expression = "${{" + body + "}}"
        start = value.find(expression, offset)
        pieces.extend((value[offset:start], replacement))
        offset = start + len(expression)
    pieces.append(value[offset:])
    return "".join(pieces)


def _expand(value: str, variables: dict[str, str]) -> str:
    return _VARIABLE.sub(lambda match: variables.get(match[1] or match[2], _UNKNOWN), value)


def _path(value: str, cwd: str, env: dict[str, str], *, shell: bool = True) -> str | None:
    value = _render(value, env)
    if shell:
        value = _expand(value, env)
    value = value.replace("\\", "/").strip()
    if not value or any(
        mark in value for mark in (_UNKNOWN, _SECRET, _LITERAL_DOLLAR, "${{", "$", "`")
    ):
        return None
    if value == "~" or value.startswith("~/"):
        value = _HOME + value[1:]
    return posixpath.normpath(posixpath.join(cwd, value))


def _false(value: str) -> bool:
    return value.strip().removeprefix("${{").removesuffix("}}").strip().lower() == "false"


@dataclass(frozen=True)
class _Output:
    path: str
    line: int
    directory: bool = False
    folded_origin: bool = False


def _output_snippet(output: _Output, lines: list[str]) -> str:
    source = lines[output.line - 1].strip()
    if output.folded_origin:
        source += " [decoded folded run body; line is the YAML scalar header]"
    return source


@dataclass(frozen=True)
class _Cache:
    paths: tuple[str, ...]
    line: int
    post_job: bool
    filtered_targets: tuple[str, ...] = ()
    supports_save_if: bool = False
    save_if_present: bool = False

    def contains(self, output: _Output) -> bool:
        if not output.directory and any(
            _overlaps(output.path, path) for path in self.filtered_targets
        ):
            # rust-cache cleans target before saving. File survival requires
            # cleanup semantics outside this profile; retain only directory risk.
            return False

        def matches(pattern: str) -> bool:
            if any(char in pattern for char in "*?["):
                if fnmatch.fnmatchcase(output.path, pattern):
                    return True
                # A directory producer needs a concrete cached subtree; an
                # unconstrained '*.env' pattern does not prove Cargo output.
                prefix = re.split(r"[*?\[]", pattern, maxsplit=1)[0].rstrip("/")
                return bool(output.directory and prefix and _overlaps(prefix, output.path))
            return (
                output.path == pattern
                or output.path.startswith(pattern + "/")
                or (output.directory and pattern.startswith(output.path + "/"))
            )

        included = any(matches(pattern) for pattern in self.paths if not pattern.startswith("!"))

        def excludes(pattern: str) -> bool:
            if not output.directory:
                return matches(pattern)
            root = pattern.removesuffix("/**").rstrip("/")
            return not any(char in root for char in "*?[") and (
                output.path == root or output.path.startswith(root + "/")
            )

        excluded = any(excludes(pattern[1:]) for pattern in self.paths if pattern.startswith("!"))
        return included and not excluded


@dataclass(frozen=True)
class _AnalysisState:
    """One possible whole-job execution, with its correlated guard domain."""

    domain: GuardConstraints
    persisted: tuple[tuple[str, str], ...] = ()
    outputs: tuple[_Output, ...] = ()
    post_caches: tuple[_Cache, ...] = ()


def _state_payload(state: _AnalysisState) -> tuple[object, ...]:
    return state.persisted, state.outputs, state.post_caches


def _merge_states(states: list[_AnalysisState]) -> list[_AnalysisState]:
    """Union domains only when the complete execution payload is identical."""
    merged: dict[tuple[object, ...], _AnalysisState] = {}
    for state in states:
        if not state.domain:
            continue
        payload = _state_payload(state)
        previous = merged.get(payload)
        if previous is None:
            merged[payload] = state
        else:
            merged[payload] = _AnalysisState(
                union_constraints((previous.domain, state.domain)),
                state.persisted,
                state.outputs,
                state.post_caches,
            )
    return list(merged.values())


def _token_span(tokens: list[Token], line: int, key_name: str) -> list[Token] | None:
    starts = [
        position
        for position, token in enumerate(tokens)
        if token.kind is TokenKind.KEY and token.value == key_name and token.line == line
    ]
    if len(starts) != 1:
        return None
    start = starts[0]
    key = tokens[start]
    flow_end = next(
        (
            position
            for position in range(start + 1, len(tokens))
            if tokens[position].line == key.line
            and tokens[position].kind
            in {TokenKind.FLOW_COMMA, TokenKind.FLOW_CLOSE_MAP, TokenKind.FLOW_CLOSE_SEQ}
        ),
        None,
    )
    if flow_end is not None:
        return tokens[start + 1 : flow_end]
    end = next(
        (
            position
            for position in range(start + 1, len(tokens))
            if tokens[position].line > key.line
            and (
                (
                    tokens[position].kind is TokenKind.KEY
                    and tokens[position].indent <= key.column - 1
                )
                or (
                    tokens[position].kind is TokenKind.SEQUENCE_DASH
                    and tokens[position].indent <= key.indent
                )
            )
        ),
        len(tokens),
    )
    return tokens[start + 1 : end]


def _scalar_span(span: list[Token] | None) -> bool:
    if not span or any(
        token.kind in {TokenKind.ANCHOR, TokenKind.ALIAS, TokenKind.MERGE_KEY} for token in span
    ):
        return False
    if span[0].kind in {
        TokenKind.SCALAR_PLAIN,
        TokenKind.SCALAR_QUOTED,
    } and all(
        token.kind in {TokenKind.FLOW_CLOSE_MAP, TokenKind.FLOW_CLOSE_SEQ, TokenKind.FLOW_COMMA}
        for token in span[1:]
    ):
        return True
    return bool(
        span[0].kind is TokenKind.SCALAR_BLOCK_HEADER
        and all(token.kind is TokenKind.SCALAR_BLOCK_LINE for token in span[1:])
    )


def _owning_value_span(tokens: list[Token], line: int, key_name: str) -> list[Token] | None:
    """Return a key's complete value through its next structural sibling."""
    starts = [
        position
        for position, token in enumerate(tokens)
        if token.kind is TokenKind.KEY and token.value == key_name and token.line == line
    ]
    if len(starts) != 1:
        return None
    start = starts[0]
    key = tokens[start]
    end = next(
        (
            position
            for position in range(start + 1, len(tokens))
            if tokens[position].line > key.line
            and (
                (
                    tokens[position].kind is TokenKind.KEY
                    and tokens[position].indent <= key.column - 1
                )
                or (
                    tokens[position].kind is TokenKind.SEQUENCE_DASH
                    and tokens[position].indent <= key.indent
                )
            )
        ),
        len(tokens),
    )
    return tokens[start + 1 : end]


def _certified_flat_flow_map(tokens: list[Token], line: int) -> bool:
    """Accept only a complete, flat flow map around a same-line ``with`` value."""
    with_keys = [
        position
        for position, token in enumerate(tokens)
        if token.kind is TokenKind.KEY and token.value == "with" and token.line == line
    ]
    if len(with_keys) != 1:
        return False
    value_span = _owning_value_span(tokens, line, "with")
    if not value_span or value_span[0].kind is not TokenKind.FLOW_OPEN_MAP:
        return False
    entries: list[Token] = []
    depth = 1
    end = 1
    while end < len(value_span) and depth:
        token = value_span[end]
        if token.kind in {TokenKind.FLOW_OPEN_MAP, TokenKind.FLOW_OPEN_SEQ}:
            depth += 1
        elif token.kind in {TokenKind.FLOW_CLOSE_MAP, TokenKind.FLOW_CLOSE_SEQ}:
            depth -= 1
            if depth == 0:
                if token.kind is not TokenKind.FLOW_CLOSE_MAP:
                    return False
                break
        if depth == 1:
            entries.append(token)
        end += 1
    if depth or not entries or end != len(value_span) - 1:
        return False

    # A flat mapping alternates key/value pairs with one comma between pairs.
    # Restrict values to scalar tokens so nested or malformed flow syntax stays
    # unknown rather than supplying a negative proof.
    index = 0
    seen_save_if = 0
    while index < len(entries):
        key = entries[index]
        if key.kind is not TokenKind.KEY or index + 1 >= len(entries):
            return False
        value = entries[index + 1]
        if value.kind not in {TokenKind.SCALAR_PLAIN, TokenKind.SCALAR_QUOTED}:
            return False
        seen_save_if += key.value == "save-if"
        index += 2
        if index == len(entries):
            break
        if entries[index].kind is not TokenKind.FLOW_COMMA:
            return False
        index += 1
        if index == len(entries):
            return False
    return seen_save_if == 1


def _with_value_is_flow_map(tokens: list[Token], line: int) -> bool:
    positions = [
        position
        for position, token in enumerate(tokens)
        if token.kind is TokenKind.KEY and token.value == "with" and token.line == line
    ]
    return (
        len(positions) == 1
        and positions[0] + 1 < len(tokens)
        and tokens[positions[0] + 1].kind is TokenKind.FLOW_OPEN_MAP
    )


def _certified_guard_values(
    content: str, events: tuple[Event, ...]
) -> tuple[dict[tuple[object, ...], str], set[tuple[object, ...]], bool]:
    """Return only unique, fully represented scalar if/save-if guards."""
    invalid_structure = any(event.kind in {EventKind.CUTOFF, EventKind.ERROR} for event in events)
    key_events: dict[tuple[object, ...], list[Event]] = {}
    leaf_events: dict[tuple[object, ...], list[Event]] = {}
    for event in events:
        if event.kind is EventKind.MAP_KEY:
            key_events.setdefault(event.path, []).append(event)
        elif event.kind is EventKind.LEAF_SCALAR:
            leaf_events.setdefault(event.path, []).append(event)
    key_paths = set(key_events)
    if invalid_structure:
        return {}, key_paths, False
    try:
        tokens = [
            token
            for token in tokenize(content)
            if token.kind not in {TokenKind.INDENT, TokenKind.COMMENT, TokenKind.EOF}
        ]
    except TokenizerError:
        return {}, key_paths, False
    values = {
        path: leaves[-1].value
        for path, leaves in leaf_events.items()
        if len(leaves) == 1 and leaves[0].value is not None
    }
    duplicate_key_paths = {
        path for path, occurrences in key_events.items() if len(occurrences) != 1
    }

    def has_ambiguous_ancestor(path: tuple[object, ...]) -> bool:
        return any(
            path[:prefix_length] in duplicate_key_paths for prefix_length in range(1, len(path) + 1)
        )

    keys = {path: key_events[path][0].line for path in key_paths if len(key_events[path]) == 1}
    from taintly.composer import _certified_guards

    certified = dict(_certified_guards(content, SimpleNamespace(values=values, keys=keys)))
    result: dict[tuple[object, ...], str] = {}
    for path, name in ((path, "if") for path in key_paths if path[-1:] == ("if",)):
        key_events_for_path = key_events[path]
        leaves = leaf_events.get(path, [])
        if (
            len(key_events_for_path) != 1
            or len(leaves) != 1
            or leaves[0].value is None
            or leaves[0].merge_origins
            or path not in certified
            or has_ambiguous_ancestor(path)
        ):
            continue
        span = _token_span(tokens, key_events_for_path[0].line, name)
        if _scalar_span(span):
            result[path] = leaves[0].value
    for path in key_paths:
        if path[-2:] != ("with", "save-if"):
            continue
        key_events_for_path = key_events[path]
        leaves = leaf_events.get(path, [])
        if (
            len(key_events_for_path) != 1
            or len(leaves) != 1
            or leaves[0].value is None
            or leaves[0].merge_origins
            or has_ambiguous_ancestor(path)
        ):
            continue
        span = _token_span(tokens, key_events_for_path[0].line, "save-if")
        with_path = path[:-1]
        with_keys = key_events.get(with_path, [])
        in_flow_map = len(with_keys) == 1 and _with_value_is_flow_map(tokens, with_keys[0].line)
        if (
            _scalar_span(span)
            and not has_ambiguous_ancestor(path)
            and (not in_flow_map or _certified_flat_flow_map(tokens, with_keys[0].line))
        ):
            result[path] = leaves[0].value
    return result, key_paths, True


def _negated_guard(guard: str) -> str:
    source = guard.strip()
    if source.startswith("${{") and source.endswith("}}"):
        source = source[3:-2].strip()
    return f"!({source})"


def _guard_alternatives(
    state: _AnalysisState,
    path: tuple[object, ...],
    *,
    key_paths: set[tuple[object, ...]],
    guards: dict[tuple[object, ...], str],
    structure_valid: bool,
    event: str,
) -> tuple[_AnalysisState | None, _AnalysisState | None]:
    """Split one state into execute/skip domains without complementing a widened DNF."""
    if not structure_valid:
        return state, state
    if path not in key_paths:
        return state, None
    guard = guards.get(path)
    if guard is None:
        return state, state
    verdict = event_guard_verdict(guard, event)
    if verdict is True:
        return state, None
    if verdict is False:
        return None, state
    execute_domain = intersect_constraints(state.domain, guard_constraints((guard,), event))
    skip_domain = intersect_constraints(
        state.domain, guard_constraints((_negated_guard(guard),), event)
    )
    execute = (
        _AnalysisState(execute_domain, state.persisted, state.outputs, state.post_caches)
        if execute_domain
        else None
    )
    skip = (
        _AnalysisState(skip_domain, state.persisted, state.outputs, state.post_caches)
        if skip_domain
        else None
    )
    return execute, skip


def _state_with(
    state: _AnalysisState,
    *,
    persisted: dict[str, str] | None = None,
    outputs: list[_Output] | None = None,
    post_caches: list[_Cache] | None = None,
) -> _AnalysisState:
    return _AnalysisState(
        state.domain,
        tuple((persisted if persisted is not None else dict(state.persisted)).items()),
        tuple(outputs if outputs is not None else state.outputs),
        tuple(post_caches if post_caches is not None else state.post_caches),
    )


def _overlaps(left: str, right: str) -> bool:
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def _scoped_env(
    fields: dict[tuple[object, ...], dict[str, str]],
    scope: tuple[object, ...],
    inherited: dict[str, str],
) -> dict[str, str]:
    result = dict(inherited)
    for name, value in fields.get(scope, {}).items():
        result[name] = _render(value, inherited)
    return result


def _value(
    leaves: dict[tuple[object, ...], Event], path: tuple[object, ...], default: str = ""
) -> str:
    event = leaves.get(path)
    return event.value or "" if event is not None else default


def _cache(
    leaves: dict[tuple[object, ...], Event],
    scope: tuple[object, ...],
    env: dict[str, str],
) -> _Cache | None:
    uses = leaves.get(scope + ("uses",))
    if uses is None:
        return None
    action = (uses.value or "").split("@", 1)[0].lower()

    def get(name: str, default: str = "") -> str:
        return _value(leaves, scope + ("with", name), default)

    paths: list[str] = []
    filtered_targets: list[str] = []
    if action in {"actions/cache", "actions/cache/save"}:
        paths = get("path").splitlines()
    elif action == "swatinem/rust-cache":
        if get("cache-provider", "github").lower() != "github":
            return None
        cargo_home = env.get("CARGO_HOME", "~/.cargo")
        paths = [posixpath.join(cargo_home, part) for part in ("registry", "git")]
        if not _false(get("cache-bin")):
            paths.append(posixpath.join(cargo_home, "bin"))
        if not _false(get("cache-targets")):
            for workspace in get("workspaces", ". -> target").splitlines():
                parts = workspace.split("->", 1)
                target = posixpath.join(
                    parts[0].strip(), parts[1].strip() if len(parts) == 2 else "target"
                )
                paths.append(target)
                resolved = _path(target, _ROOT, env, shell=False)
                if resolved is not None:
                    filtered_targets.append(resolved)
        paths.extend(get("cache-directories").split())
    else:
        return None
    normalized = []
    for path in paths:
        excluded = path.strip().startswith("!")
        resolved = _path(path.strip()[1:] if excluded else path, _ROOT, env, shell=False)
        if resolved is not None:
            normalized.append(("!" if excluded else "") + resolved)
    return _Cache(
        tuple(normalized),
        uses.line,
        action != "actions/cache/save",
        tuple(filtered_targets),
        action == "swatinem/rust-cache",
        action == "swatinem/rust-cache" and scope + ("with", "save-if") in leaves,
    )


def _literal_dollars(script: str) -> str:
    """Keep shell single quotes/escaped dollars as data after shlex removes quotes."""
    quote = ""
    escaped = False
    result = []
    for char in script:
        if char == "$" and (quote == "'" or escaped):
            result.append(_LITERAL_DOLLAR)
        else:
            result.append(char)
        if quote == "'":
            if char == "'":
                quote = ""
        elif escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            quote = ""
        elif char in "'\"" and not quote:
            quote = char
    return "".join(result)


def _redirect_tags(script: str) -> str:
    """Distinguish adjacent descriptor numbers from ordinary numeric arguments."""
    quote = ""
    escaped = False
    result: list[str] = []
    index = 0
    while index < len(script):
        char = script[index]
        if (
            char.isdigit()
            and not quote
            and not escaped
            and (index == 0 or script[index - 1].isspace() or script[index - 1] in ";&|")
        ):
            match = re.match(r"([0-9]+)(?=>)", script[index:])
            if match:
                result.append(" __fd" + match[1] + "__ ")
                index += len(match[1])
                continue
        result.append(char)
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif char == quote:
            quote = ""
        elif char in "'\"" and not quote:
            quote = char
        index += 1
    return "".join(result)


def _commands(event: Event, env: dict[str, str]) -> Iterator[tuple[int, list[str], bool]]:
    """Read linear commands; ignore heredoc bodies and quoted/commented command text."""
    folded = event.value_kind == "block_folded"
    if folded:
        # YAML has already folded soft physical breaks into spaces in value.
        # Only LF characters left in that decoded value are shell line breaks.
        decoded_lines = (event.value or "").split("\n")

        def trailing_backslashes(value: str) -> int:
            return len(value) - len(value.rstrip("\\"))

        # Backslash + a retained LF is shell line continuation, whose exact
        # command text needs source-aware handling. Decline the whole scalar
        # before yielding anything rather than infer from a partial command.
        if any(trailing_backslashes(line) % 2 for line in decoded_lines):
            return
        source = tuple((event.line, line) for line in decoded_lines)
    else:
        # Literal block lines are shell command boundaries and retain exact
        # physical line provenance.
        source = event.block_lines or ((event.line, event.value or ""),)
    heredocs: list[str] = []
    continued = ""
    start = event.line
    for line, raw in source:
        if heredocs:
            if raw.strip() == heredocs[0]:
                heredocs.pop(0)
            continue
        if not continued:
            start = line
        continued += raw
        if continued.endswith("\\") and (
            not folded or (len(continued) - len(continued.rstrip("\\"))) % 2 == 1
        ):
            continued = continued[:-1] + " "
            continue
        current = continued
        script = _redirect_tags(_literal_dollars(_render(current, env)))
        continued = ""
        try:
            lexer = shlex.shlex(script, posix=True, punctuation_chars=";&|<>()")
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            continued = current + "\n"  # quoted multiline text is one shell word.
            continue
        for index, token in enumerate(tokens[:-1]):
            if token in {"<<", "<<-"}:
                heredocs.append(tokens[index + 1])
        command: list[str] = []
        incoming: str | None = None
        statuses: set[bool] = set()
        for token in [*tokens, ";"]:
            if token in {";", "&&", "||", "&"}:
                if command:
                    # Do not treat branch-local cleanup as unconditional state.
                    if command[0] in {"if", "for", "while", "case", "function"} or "(" in command:
                        return
                    command_status = (
                        {command[0] in {"true", ":"}}
                        if command[0] in {"true", ":", "false"}
                        else {True, False}
                    )
                    # AND/OR lists associate left to right. A skipped command
                    # preserves the list's status, rather than supplying its own.
                    if incoming == "&&":
                        reachable, definite = True in statuses, statuses == {True}
                        result = ({False} if False in statuses else set()) | (
                            command_status if reachable else set()
                        )
                    elif incoming == "||":
                        reachable, definite = False in statuses, statuses == {False}
                        result = ({True} if True in statuses else set()) | (
                            command_status if reachable else set()
                        )
                    else:
                        reachable, definite, result = True, True, command_status
                    if reachable:
                        yield start, command, definite and token != "&"  # nosec B105 - shell operator
                    incoming = token if token in {"&&", "||"} else None
                    statuses = result
                command = []
            else:
                command.append(token)


def _process(
    tokens: list[str], variables: dict[str, str], exported: dict[str, str]
) -> tuple[list[str], dict[str, str]]:
    """Apply command-local assignments and env -u/-i without changing later steps."""
    process = dict(exported)
    tokens = list(tokens)
    while tokens and (match := _ASSIGNMENT.fullmatch(tokens[0])):
        process[match[1]] = _expand(match[2], variables)
        tokens.pop(0)
    if tokens and tokens[0] == "env":
        index = 1
        while index < len(tokens):
            token = tokens[index]
            if token in {"-i", "--ignore-environment"}:
                process.clear()
            elif token in {"-u", "--unset"} and index + 1 < len(tokens):
                index += 1
                process.pop(tokens[index], None)
            elif token.startswith("--unset="):
                process.pop(token.split("=", 1)[1], None)
            elif match := _ASSIGNMENT.fullmatch(token):
                process[match[1]] = _expand(match[2], variables)
            else:
                break
            index += 1
        if index > 1:
            remaining = tokens[index:]
            tokens = (
                ["env", *remaining]
                if not remaining
                or remaining[0] in {">", ">>", "|"}
                or remaining[0].startswith("__fd")
                else remaining
            )
    return tokens, process


def _cargo_path(tokens: list[str], process: dict[str, str], cwd: str) -> str | None:
    if (
        not tokens
        or posixpath.basename(tokens[0]) != "cargo"
        or not any(_SECRET in value for value in process.values())
    ):
        return None
    args = tokens[1:]
    if args and args[0].startswith("+"):
        args = args[1:]
    while args and args[0] in {
        "-v",
        "-vv",
        "--verbose",
        "-q",
        "--quiet",
        "--locked",
        "--offline",
        "--frozen",
    }:
        args = args[1:]
    if not args or args[0] not in {
        "build",
        "test",
        "check",
        "bench",
        "run",
        "rustc",
        "clippy",
        "miri",
    }:
        return None
    if args[0] == "miri" and (len(args) < 2 or args[1] not in {"test", "run"}):
        return None
    target = process.get("CARGO_TARGET_DIR", "target")
    for index, arg in enumerate(args):
        if arg == "--":
            break
        if arg in {"--help", "-h"}:
            return None
        if arg.startswith("--target-dir="):
            target = arg.split("=", 1)[1]
        elif arg == "--target-dir" and index + 1 < len(args):
            target = args[index + 1]
    return _path(target, cwd, process)


def _serialized_path(
    tokens: list[str], process: dict[str, str], variables: dict[str, str], cwd: str
) -> tuple[str, str, bool] | None:
    """Return an explicit output path plus serialized text for GITHUB_ENV handling."""
    if not tokens or tokens[0] not in {"env", "printenv", "echo", "printf"}:
        return None
    destination: str | None = None
    truncates = True
    arguments: list[str] = []
    index = 1
    descriptor = "1"
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("__fd") and token.endswith("__"):
            descriptor = token[4:-2]
            index += 1
            continue
        if token in {">", ">>", ">|", ">&"} and index + 1 < len(tokens):
            if descriptor == "1":
                destination = tokens[index + 1] if token != ">&" else None  # nosec B105 - shell operator
                truncates = token != ">>"  # nosec B105 - shell operator
            descriptor = "1"
            index += 2
            continue
        if token == "|":  # nosec B105 - shell operator
            remaining = tokens[index + 1 :]
            if remaining and remaining[0] == "tee" and destination is None:
                paths = []
                for part in remaining[1:]:
                    if part in {">", ">>", ">&"} or part.startswith("__fd"):
                        break  # tee's stdout redirect does not change its file.
                    if not part.startswith("-"):
                        paths.append(part)
                if len(paths) == 1:
                    destination, truncates = paths[0], "-a" not in remaining
            break
        arguments.append(_expand(token, variables))
        index += 1
    if destination is None:
        return None
    payload = " ".join(arguments)
    if tokens[0] == "printf" and arguments:
        template = arguments[0]
        values = iter(arguments[1:])
        conversions = re.findall(r"%%|%[sb]", template)
        payload = re.sub(
            r"%%|%[sb]", lambda match: "%" if match[0] == "%%" else next(values, ""), template
        )
        if any(conversion != "%%" for conversion in conversions):
            payload += " ".join(values)  # printf repeats the format for extra args.
    if tokens[0] in {"env", "printenv"}:
        names = [token for token in arguments if not token.startswith("-")]
        selected = (
            process if not names else {name: process[name] for name in names if name in process}
        )
        payload = (
            "\n".join(f"{name}={value}" for name, value in selected.items())
            if not names
            else "\n".join(selected.values())
        )
    resolved = _path(destination, cwd, variables)
    return (resolved, payload, truncates) if resolved is not None else None


class SecretCachePattern:
    """Join effective secrets, recognized output, and an ordered cache save per job."""

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if not any(
            anchor in content.lower() for anchor in ("actions/cache", "swatinem/rust-cache")
        ):
            return []
        events = tuple(
            walk_workflow("workflow.yml", content=content, include_keys=True, recover=True)
        )
        guards, key_paths, structure_valid = _certified_guard_values(content, events)
        leaves = {event.path: event for event in events if event.kind == EventKind.LEAF_SCALAR}
        env_fields: dict[tuple[object, ...], dict[str, str]] = {}
        job_steps: dict[str, set[int]] = {}
        for yaml_path, event in leaves.items():
            if len(yaml_path) >= 2 and yaml_path[-2] == "env":
                env_fields.setdefault(yaml_path[:-2], {})[str(yaml_path[-1])] = event.value or ""
            if (
                len(yaml_path) > 4
                and yaml_path[0] == "jobs"
                and yaml_path[2] == "steps"
                and isinstance(yaml_path[3], int)
            ):
                job_steps.setdefault(str(yaml_path[1]), set()).add(yaml_path[3])
        base = {"GITHUB_WORKSPACE": _ROOT, "HOME": _HOME, "GITHUB_ENV": _GITHUB_ENV}
        workflow_env = _scoped_env(env_fields, (), base)
        workflow_mode = _value(leaves, ("cache-mode",)).lower()
        event_names = set(triggers(content)) - {"pull_request"}
        if not structure_valid and not event_names:
            # A cutoff may hide an otherwise valid trigger from the query view.
            # Keep the incomplete source under every known default write event.
            event_names = set(_WRITE_EVENTS)
        jobs = sorted(job_steps)
        hits: dict[int, str] = {}
        incomplete: list[str] = []
        for job in jobs:
            for event_name in sorted(event_names):
                job_scope = ("jobs", job)
                mode = _value(leaves, job_scope + ("cache-mode",), workflow_mode).lower()
                if mode in {"read", "none"} or (
                    event_name not in _WRITE_EVENTS and mode not in {"write", "write-only"}
                ):
                    continue
                job_env = _scoped_env(env_fields, job_scope, workflow_env)
                initial = _AnalysisState(UNCONSTRAINED)
                job_state, _job_skip = _guard_alternatives(
                    initial,
                    ("jobs", job, "if"),
                    key_paths=key_paths,
                    guards=guards,
                    structure_valid=structure_valid,
                    event=event_name,
                )
                if job_state is None:
                    continue
                states = [job_state]
                transitions = 0
                cutoff: str | None = None
                steps = sorted(job_steps[job])
                for step in steps:
                    scope = ("jobs", job, "steps", step)
                    next_states: list[_AnalysisState] = []
                    for state in states:
                        transitions += 1
                        if transitions > 4096:
                            cutoff = (
                                f"SEC6-GH-015 guard-state transition limit exceeded "
                                f"for job {job!r} on {event_name!r}"
                            )
                            break
                        execute, skip = _guard_alternatives(
                            state,
                            scope + ("if",),
                            key_paths=key_paths,
                            guards=guards,
                            structure_valid=structure_valid,
                            event=event_name,
                        )
                        if skip is not None:
                            next_states.append(skip)
                        if execute is None:
                            continue
                        env = _scoped_env(
                            env_fields,
                            scope,
                            {**job_env, **dict(execute.persisted)},
                        )
                        cache = _cache(leaves, scope, env)
                        action_states = [execute]
                        if (
                            cache is not None
                            and cache.supports_save_if
                            and (cache.save_if_present or not structure_valid)
                        ):
                            save_state, no_save_state = _guard_alternatives(
                                execute,
                                scope + ("with", "save-if"),
                                key_paths=key_paths,
                                guards=guards,
                                structure_valid=structure_valid,
                                event=event_name,
                            )
                            action_states = []
                            if no_save_state is not None:
                                next_states.append(no_save_state)
                            if save_state is not None:
                                action_states.append(save_state)
                        for action_state in action_states:
                            current = action_state
                            if cache is not None:
                                if cache.post_job:
                                    current = _state_with(
                                        current,
                                        post_caches=[*current.post_caches, cache],
                                    )
                                else:
                                    for output in current.outputs:
                                        if cache.contains(output) and 0 < output.line <= len(lines):
                                            hits.setdefault(
                                                output.line,
                                                _output_snippet(output, lines)
                                                + f" [cache save at line {cache.line}; "
                                                + f"output {output.path.replace(_ROOT, '.').replace(_HOME, '~')}]",
                                            )
                            run = leaves.get(scope + ("run",))
                            runner = _value(leaves, ("jobs", job, "runs-on")).lower()
                            default_shell = "pwsh" if "windows" in runner else "bash"
                            shell = _value(
                                leaves,
                                scope + ("shell",),
                                _value(
                                    leaves,
                                    ("jobs", job, "defaults", "run", "shell"),
                                    _value(leaves, ("defaults", "run", "shell"), default_shell),
                                ),
                            )
                            if run is not None and shell.split(" ", 1)[0] in {"bash", "sh"}:
                                directory = _value(
                                    leaves,
                                    scope + ("working-directory",),
                                    _value(
                                        leaves,
                                        ("jobs", job, "defaults", "run", "working-directory"),
                                        _value(
                                            leaves, ("defaults", "run", "working-directory"), "."
                                        ),
                                    ),
                                )
                                cwd = _path(directory, _ROOT, env)
                                if cwd is not None:
                                    variables, exported = dict(env), dict(env)
                                    persisted = dict(current.persisted)
                                    outputs = list(current.outputs)
                                    pending: dict[str, str] = {}
                                    for line, raw_tokens, definite in _commands(run, env):
                                        if raw_tokens[0] in {"export", "unset"} or all(
                                            _ASSIGNMENT.fullmatch(token) for token in raw_tokens
                                        ):
                                            operation = raw_tokens[0]
                                            for token in (
                                                raw_tokens[1:]
                                                if operation in {"export", "unset"}
                                                else raw_tokens
                                            ):
                                                if operation == "unset" and definite:
                                                    variables.pop(token, None)
                                                    exported.pop(token, None)
                                                elif match := _ASSIGNMENT.fullmatch(token):
                                                    value = _expand(match[2], variables)
                                                    if not definite and _SECRET in variables.get(
                                                        match[1], ""
                                                    ):
                                                        value = _SECRET
                                                    variables[match[1]] = value
                                                    if (
                                                        operation == "export"
                                                        or match[1] in exported
                                                    ):
                                                        exported[match[1]] = variables[match[1]]
                                                elif operation == "export" and token in variables:
                                                    exported[token] = variables[token]
                                            continue
                                        tokens, process = _process(raw_tokens, variables, exported)
                                        if not tokens:
                                            continue
                                        if tokens[0] == "cd" and len(tokens) == 2:
                                            if not definite:
                                                break
                                            cwd = _path(tokens[1], cwd, variables)
                                            if cwd is None:
                                                break
                                        elif tokens[0] == "rm" and definite:
                                            recursive = any(
                                                token == "--recursive"  # nosec B105 - command option
                                                or (
                                                    token.startswith("-")
                                                    and not token.startswith("--")
                                                    and ("r" in token or "R" in token)
                                                )
                                                for token in tokens[1:]
                                            )
                                            removed = [
                                                _path(token, cwd, variables)
                                                for token in tokens[1:]
                                                if not token.startswith("-")
                                            ]
                                            outputs = [
                                                output
                                                for output in outputs
                                                if not any(
                                                    path is not None
                                                    and (not output.directory or recursive)
                                                    and (
                                                        output.path == path
                                                        or output.path.startswith(path + "/")
                                                    )
                                                    for path in removed
                                                )
                                            ]
                                        else:
                                            target = _cargo_path(
                                                [_expand(token, variables) for token in tokens],
                                                process,
                                                cwd,
                                            )
                                            if target is not None:
                                                outputs.append(
                                                    _Output(
                                                        target,
                                                        line,
                                                        directory=True,
                                                        folded_origin=run.value_kind
                                                        == "block_folded",
                                                    )
                                                )
                                            serialized = _serialized_path(
                                                tokens, process, variables, cwd
                                            )
                                            if serialized is not None:
                                                path, payload, truncates = serialized
                                                if path == _GITHUB_ENV:
                                                    if truncates and definite:
                                                        pending.clear()
                                                    for entry in payload.replace(
                                                        "\\n", "\n"
                                                    ).splitlines():
                                                        assignment = _ASSIGNMENT.fullmatch(
                                                            entry.strip()
                                                        )
                                                        if assignment:
                                                            value = assignment[2]
                                                            if (
                                                                not definite
                                                                and _SECRET
                                                                in pending.get(assignment[1], "")
                                                            ):
                                                                value = _SECRET
                                                            pending[assignment[1]] = value
                                                else:
                                                    if truncates and definite:
                                                        outputs = [
                                                            output
                                                            for output in outputs
                                                            if output.directory
                                                            or output.path != path
                                                        ]
                                                    if _SECRET in payload:
                                                        outputs.append(
                                                            _Output(
                                                                path,
                                                                line,
                                                                folded_origin=run.value_kind
                                                                == "block_folded",
                                                            )
                                                        )
                                    persisted.update(pending)
                                    current = _state_with(
                                        current,
                                        persisted=persisted,
                                        outputs=outputs,
                                    )
                            next_states.append(current)
                    if cutoff is not None:
                        break
                    states = _merge_states(next_states)
                    if len(states) > 64:
                        cutoff = (
                            f"SEC6-GH-015 guard-state limit exceeded "
                            f"for job {job!r} on {event_name!r}"
                        )
                        break
                if cutoff is not None:
                    incomplete.append(cutoff)
                    continue
                for state in states:
                    for cache in state.post_caches:
                        for output in state.outputs:
                            if cache.contains(output) and 0 < output.line <= len(lines):
                                hits.setdefault(
                                    output.line,
                                    _output_snippet(output, lines)
                                    + f" [cache save at line {cache.line}; "
                                    + f"output {output.path.replace(_ROOT, '.').replace(_HOME, '~')}]",
                                )
        matches = sorted(hits.items())
        if incomplete:
            return IncompletePatternMatches(matches, reason="; ".join(incomplete))
        return matches


# JSON is valid YAML. Quoted flow keys remain valid when the generic whitespace
# mutator removes colon spaces; bare `uses:actions/cache` would be invalid YAML.
# Block and same-indent workflows are covered by test_secret_cache.py.
_POSITIVE = """{"on": "push", "jobs": {"build": {
"runs-on": "ubuntu-latest", "steps": [
{"uses": "actions/cache@v4", "with": {"path": "target", "key": "build-v1"}},
{"run": "cargo miri test", "env": {"TOKEN": "${{ secrets.TOKEN }}"}}
]}}}
"""

RULES = [
    Rule(
        id="SEC6-GH-015",
        title="Secret-bearing process output may enter a shared cache",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "An environment dump, explicit secret write, or Cargo build with an effective "
            "secret environment writes under a path saved by this job's cache. Cargo output "
            "is inferred from its target-directory convention; this does not prove secret "
            "bytes were written. A cache saved on a PR base/default branch can be read by "
            "PR workflows, including forks. Review branch scope, PR access policy and output "
            "contents. A private repository or read-only PR cache access alone is not proof "
            "that secret-bearing caches are inaccessible."
        ),
        pattern=SecretCachePattern(),
        remediation=(
            "Scope secrets to the steps that require them. Keep secret-bearing process "
            "output outside saved caches, or disable cache saving for that job. After "
            "removing a confirmed exposure, clear affected caches and rotate exposed secrets."
        ),
        reference="https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching",
        finding_family="credential_persistence",
        confidence="medium",
        review_needed=True,
        stride=["I"],
        threat_narrative=(
            "A tool persists its secret-bearing environment into build output. A PR job "
            "restores the producer's base/default-branch cache and reads the saved secrets."
        ),
        test_positive=[_POSITIVE],
        test_negative=[_POSITIVE.replace("secrets.TOKEN", "vars.PUBLIC_VALUE")],
    ),
]
