"""Bounded JavaScript code-use checks for step-local environment values.

This module deliberately covers one narrow path: a unique step-local ``env``
binding from a tracked GitHub source, consumed by a literal Node ``-e`` /
``--eval`` command in that same step. Other scopes, shells and JavaScript
constructs are not inferred safe by this rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from taintly.models import IncompletePatternMatches, Platform, Rule, Severity
from taintly.parsers.gha_expr import (
    ExprSyntaxError,
    iter_expression_bodies,
    result_provenance_paths,
)
from taintly.parsers.shell_words import shell_words_with_expansion
from taintly.parsers.structural import Event, EventKind, walk_workflow
from taintly.taint import _TAINTED_CONTEXTS

_TRACKED_CONTEXTS = tuple(re.compile(pattern) for pattern in _TAINTED_CONTEXTS)
_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_STRING_LITERAL = "<string-literal>"


def _js_tokens(source: str) -> list[str] | None:
    """Tokenize identifiers and punctuation while skipping JS strings/comments.

    Template literals, regular expressions, and slash operators are outside
    this bounded lexer. Returning ``None`` means the code shape is unsupported,
    never that it is safe.
    """
    tokens: list[str] = []
    index = 0
    while index < len(source):
        char = source[index]
        if char.isspace():
            index += 1
            continue
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                return None
            index = end + 2
            continue
        if char in "'\"":
            quote = char
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == quote:
                    index += 1
                    break
                else:
                    index += 1
            else:
                return None
            tokens.append(_STRING_LITERAL)
            continue
        if char == "`" or char == "/":
            return None
        match = _IDENT.match(source, index)
        if match:
            tokens.append(match.group())
            index = match.end()
            continue
        if char in "()[]{}.,;=?:!+-*%<>&|^~":
            tokens.append(char)
            index += 1
            continue
        return None
    return tokens


def _matching_close(tokens: list[str], start: int, opener: str, closer: str) -> int | None:
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index] == opener:
            depth += 1
        elif tokens[index] == closer:
            depth -= 1
            if depth == 0:
                return index
    return None


def _env_references(tokens: list[str]) -> set[str]:
    refs: set[str] = set()
    for index in range(len(tokens) - 4):
        if tokens[index : index + 4] == ["process", ".", "env", "."]:
            name = tokens[index + 4]
            if _IDENT.fullmatch(name):
                refs.add(name)
    return refs


def _code_sinks(tokens: list[str], source_env_names: set[str]) -> bool:
    """Prove only a complete one-expression invocation with a direct env arg."""
    expression = list(tokens)
    if expression and expression[-1] == ";":
        expression.pop()
    while (
        len(expression) >= 2
        and expression[0] == "("
        and _matching_close(expression, 0, "(", ")") == len(expression) - 1
    ):
        expression = expression[1:-1]
    if len(expression) >= 3 and expression[0] == "eval" and expression[1] == "(":
        close = _matching_close(expression, 1, "(", ")")
        return close == len(expression) - 1 and _is_direct_env_argument(
            expression[2:close], source_env_names
        )
    if len(expression) >= 7 and expression[:3] == ["new", "Function", "("]:
        close = _matching_close(expression, 2, "(", ")")
        return (
            close is not None
            and close + 3 == len(expression)
            and expression[close + 1 : close + 3] == ["(", ")"]
            and _is_direct_env_argument(expression[3:close], source_env_names)
        )
    return False


def _is_direct_env_argument(tokens: list[str], source_env_names: set[str]) -> bool:
    """Prove only a direct env reference, optionally parenthesized.

    Any transform, concatenation, string operand or multi-argument call is
    unknown to this rule. Mere occurrence of a tainted value somewhere inside
    an evaluator's argument does not prove that the value itself is code.
    """
    expression = tokens
    while (
        len(expression) >= 2
        and expression[0] == "("
        and _matching_close(expression, 0, "(", ")") == len(expression) - 1
    ):
        expression = expression[1:-1]
    return (
        len(expression) == 5
        and expression[:4] == ["process", ".", "env", "."]
        and expression[4] in source_env_names
    )


def _source_paths(value: str) -> list[str] | None:
    paths: list[str] = []
    try:
        bodies = list(iter_expression_bodies(value))
        if "${{" in value and not bodies:
            return None
        for body in bodies:
            paths.extend(result_provenance_paths(body))
    except (ExprSyntaxError, RecursionError):
        return None
    return paths


def _is_tracked_source(value: str) -> bool:
    paths = _source_paths(value)
    return bool(paths) and any(
        pattern.fullmatch(path) for path in paths or () for pattern in _TRACKED_CONTEXTS
    )


def _step_path(path: tuple[object, ...]) -> tuple[str, int] | None:
    if (
        len(path) >= 5
        and path[0] == "jobs"
        and isinstance(path[1], str)
        and path[2] == "steps"
        and isinstance(path[3], int)
    ):
        return path[1], path[3]
    return None


def _strict_shell_argv(command: str) -> list[tuple[str, bool]] | None:
    """Parse one literal command with balanced quotes and no shell expansion.

    The boolean records whether the word was quoted. This intentionally rejects
    shell syntax outside the supported three-word Node form instead of relying
    on the more permissive shared lexer to establish literal arguments.
    """
    # YAML block scalars commonly include one final line terminator. Strip
    # only trailing CR/LF here; an interior unquoted newline is a shell command
    # boundary, not an argv separator.
    command = command.rstrip("\r\n")
    words: list[tuple[str, bool]] = []
    value: list[str] = []
    quote: str | None = None
    started = False
    quoted = False
    index = 0

    def flush() -> None:
        nonlocal value, started, quoted
        if started:
            words.append(("".join(value), quoted))
        value = []
        started = False
        quoted = False

    while index < len(command):
        char = command[index]
        if quote == "'":
            if char == "'":
                quote = None
            else:
                value.append(char)
            index += 1
            continue
        if quote == '"':
            if char == '"':
                quote = None
                index += 1
                continue
            if char in "$`":
                return None
            if char == "\\":
                if index + 1 >= len(command) or command[index + 1] not in {'"', "\\"}:
                    return None
                value.append(command[index + 1])
                index += 2
                continue
            value.append(char)
            index += 1
            continue
        if char in "\r\n":
            return None
        if char.isspace():
            flush()
            index += 1
            continue
        if char in "'\"":
            quote = char
            started = True
            quoted = True
            index += 1
            continue
        if char in "$`\\#;|&<>(){}[]*?~":
            return None
        value.append(char)
        started = True
        index += 1
    if quote is not None:
        return None
    flush()
    return words


def _node_eval_hint(command: str) -> bool:
    """Identify likely Node eval commands for unknown-coverage reporting only."""
    if re.search(r"(?:^|[;&|\r\n])\s*node(?:\.exe)?[\t ]*\r?\n[\t ]*-e\b", command):
        return True
    try:
        words = shell_words_with_expansion(command, re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*"))
    except (IndexError, RecursionError):
        return False
    values = [word for word, _, separator in words if not separator]
    return any(
        values[index] in {"node", "node.exe"}
        and index + 1 < len(values)
        and values[index + 1] in {"-e", "--eval"}
        for index in range(len(values) - 1)
    )


def _node_eval_source(command: str) -> tuple[str | None, bool, bool]:
    words = _strict_shell_argv(command)
    if words is None:
        return None, False, _node_eval_hint(command)
    values = [word for word, _ in words]
    candidate = bool(
        values
        and values[0] in {"node", "node.exe"}
        and len(values) >= 2
        and values[1] in {"-e", "--eval"}
    )
    if not candidate:
        return None, False, False
    if (
        len(values) == 3
        and words[0] == (values[0], False)
        and words[1] == (values[1], False)
        and words[2][1]
    ):
        return values[2], True, True
    return None, False, True


def _unique_scalar(
    path: tuple[object, ...],
    values: dict[tuple[object, ...], list[Event]],
    keys: dict[tuple[object, ...], list[Event]],
    ancestors: tuple[tuple[object, ...], ...] = (),
) -> tuple[str | None, bool, str | None]:
    """Return (value, present, error) for one uniquely owned scalar key."""
    key_events = keys.get(path, [])
    leaf_events = values.get(path, [])
    if not key_events and not leaf_events:
        return None, False, None
    if any(len(keys.get(owner, [])) != 1 for owner in ancestors):
        return None, True, "duplicate ancestor mapping key makes ownership ambiguous"
    if len(key_events) != 1 or len(leaf_events) != 1:
        return None, True, "duplicate or non-scalar shell configuration key"
    value = leaf_events[0].value
    if not isinstance(value, str):
        return None, True, "shell configuration is not a scalar"
    return value, True, None


def _mapping_owners_unique(
    paths: tuple[tuple[object, ...], ...],
    keys: dict[tuple[object, ...], list[Event]],
) -> bool:
    return all(len(keys.get(path, [])) == 1 for path in paths)


def _shell_supported(
    loc: tuple[str, int],
    values: dict[tuple[object, ...], list[Event]],
    keys: dict[tuple[object, ...], list[Event]],
) -> str | None:
    """Resolve effective step/job/workflow shell or explain unknown coverage."""
    job_id = loc[0]
    common_owners = (("jobs",), ("jobs", job_id))
    container_path = ("jobs", job_id, "container")
    if any(len(keys.get(owner, [])) != 1 for owner in common_owners):
        return "duplicate jobs/job mapping key makes execution ownership ambiguous"
    if len(keys.get(container_path, [])) != 1 and (
        container_path in values or container_path in keys
    ):
        return "duplicate job container keys make execution ownership ambiguous"

    step_shell_path = ("jobs", job_id, "steps", loc[1], "shell")
    job_shell_path = ("jobs", job_id, "defaults", "run", "shell")
    workflow_shell_path = ("defaults", "run", "shell")

    step_owners = (*common_owners, ("jobs", job_id, "steps"))
    job_owners = (*common_owners, ("jobs", job_id, "defaults"), ("jobs", job_id, "defaults", "run"))
    workflow_owners = (("defaults",), ("defaults", "run"))
    shell_value, present, error = _unique_scalar(step_shell_path, values, keys, step_owners)
    if error:
        return error
    if not present:
        shell_value, present, error = _unique_scalar(job_shell_path, values, keys, job_owners)
        if error:
            return error
    if not present:
        shell_value, present, error = _unique_scalar(
            workflow_shell_path, values, keys, workflow_owners
        )
        if error:
            return error
    if present:
        if shell_value not in {"bash", "bash {0}"}:
            return "effective configured shell is outside the supported Bash profile"
        return None

    runner_path = ("jobs", job_id, "runs-on")
    runner, runner_present, error = _unique_scalar(runner_path, values, keys, common_owners)
    if error:
        return error
    if not runner_present or runner is None:
        return "default shell cannot be established without a unique scalar runner"
    if not runner.startswith(("ubuntu-", "macos-")):
        return "default runner shell is outside the supported Bash profile"
    return None


@dataclass
class _StepEvents:
    run: Event | None = None
    shell: Event | None = None
    source_envs: dict[str, Event] = field(default_factory=dict)


@dataclass
class JavaScriptEnvCodePattern:
    """Match known direct JavaScript compilation of a tainted step env value."""

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        return self.check_with_filepath(content, lines, "workflow.yml")

    def check_with_filepath(
        self, content: str, lines: list[str], filepath: str
    ) -> list[tuple[int, str]]:
        if not filepath.lower().endswith((".yml", ".yaml")):
            return []
        events = list(walk_workflow(filepath, content=content, include_keys=True))
        if any(event.kind in {EventKind.CUTOFF, EventKind.ERROR} for event in events):
            return IncompletePatternMatches(
                [], reason="structural YAML parsing reported an error or cutoff"
            )
        by_path: dict[tuple[object, ...], list[Event]] = {}
        keys_by_path: dict[tuple[object, ...], list[Event]] = {}
        for event in events:
            if event.kind == EventKind.LEAF_SCALAR:
                by_path.setdefault(event.path, []).append(event)
            elif event.kind == EventKind.MAP_KEY:
                keys_by_path.setdefault(event.path, []).append(event)
        matches: list[tuple[int, str]] = []
        incomplete: list[str] = []
        steps: dict[tuple[str, int], _StepEvents] = {}
        for event in events:
            if event.kind != EventKind.LEAF_SCALAR:
                continue
            loc = _step_path(event.path)
            if loc is None or len(event.path) != 5:
                continue
            leaf_name = event.path[4]
            if leaf_name in {"run", "shell"}:
                owners = steps.setdefault(loc, _StepEvents())
                if leaf_name == "run":
                    owners.run = event
                else:
                    owners.shell = event
            elif leaf_name == "env" and isinstance(event.value, str):
                # Nested environment leaves are collected below.
                continue
        for event in events:
            if event.kind != EventKind.LEAF_SCALAR or len(event.path) != 6:
                continue
            loc = _step_path(event.path)
            if loc is None or event.path[4] != "env" or not isinstance(event.value, str):
                continue
            env_owner_path = event.path[:5]
            required_owners = (
                ("jobs",),
                ("jobs", loc[0]),
                ("jobs", loc[0], "steps"),
                env_owner_path,
            )
            if not _mapping_owners_unique(required_owners, keys_by_path):
                incomplete.append("duplicate ancestor mapping key makes source ownership ambiguous")
                continue
            if len(keys_by_path.get(env_owner_path, ())) != 1:
                incomplete.append("duplicate step env mapping; source ownership is ambiguous")
                continue
            if len(by_path.get(event.path, ())) != 1 or len(keys_by_path.get(event.path, ())) != 1:
                incomplete.append("duplicate step environment key; source ownership is ambiguous")
                continue
            if _is_tracked_source(event.value):
                steps.setdefault(loc, _StepEvents()).source_envs[str(event.path[5])] = event

        for loc, owned in steps.items():
            run_event = owned.run
            if run_event is None or not isinstance(run_event.value, str):
                continue
            source_names = set(owned.source_envs)
            if not source_names:
                continue
            if (
                len(by_path.get(run_event.path, ())) != 1
                or len(keys_by_path.get(run_event.path, ())) != 1
            ):
                incomplete.append("duplicate run key; JavaScript command ownership is ambiguous")
                continue
            run_owners = (
                ("jobs",),
                ("jobs", loc[0]),
                ("jobs", loc[0], "steps"),
            )
            if not _mapping_owners_unique(run_owners, keys_by_path):
                incomplete.append(
                    "duplicate ancestor mapping key makes command ownership ambiguous"
                )
                continue
            shell_error = _shell_supported(loc, by_path, keys_by_path)
            if shell_error:
                if _node_eval_hint(run_event.value):
                    incomplete.append(shell_error)
                continue
            run_source, recognized, candidate = _node_eval_source(run_event.value)
            if not candidate:
                continue
            if not recognized or run_source is None:
                incomplete.append("Node eval command is not a balanced literal invocation")
                continue
            tokens = _js_tokens(run_source)
            if tokens is None:
                if any(name in run_source for name in source_names):
                    incomplete.append(
                        "Node JavaScript source uses an unsupported lexical construct"
                    )
                continue
            if _code_sinks(tokens, source_names):
                source_line = run_event.line
                if run_event.block_lines:
                    # The whole decoded scalar is already proved to be one
                    # literal Node invocation. Folded YAML may put its first
                    # two argv words on separate physical lines.
                    source_line = next(
                        (
                            line_number
                            for line_number, block_line in run_event.block_lines
                            if block_line.strip()
                        ),
                        source_line,
                    )
                matches.append(
                    (
                        source_line,
                        lines[source_line - 1].strip(),
                    )
                )
                continue
            # A computed global handler can invoke arbitrary functions. The
            # receiver and its semantics are unresolved, so disclose incomplete
            # coverage rather than certifying this as a safe data consumer.
            if "globalThis" in tokens and "[" in tokens and _env_references(tokens) & source_names:
                incomplete.append(
                    "tainted environment value reaches unresolved computed JavaScript dispatch"
                )
            elif _env_references(tokens) & source_names and ({"eval", "Function"} & set(tokens)):
                incomplete.append(
                    "transformed JavaScript eval/Function argument; possible JavaScript "
                    "code-constructor alias/override requires review"
                )

        if incomplete:
            return IncompletePatternMatches(matches, reason="; ".join(dict.fromkeys(incomplete)))
        return matches


RULES = [
    Rule(
        id="TAINT-GH-020",
        title="Tracked workflow data reaches a direct JavaScript code constructor",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        confidence="high",
        finding_family="script_injection",
        review_needed=True,
        description=(
            "A tracked GitHub context is bound through a unique step-local env value and reaches a direct "
            "``eval`` or immediately invoked ``new Function`` consumer in a literal Node ``-e``/``--eval`` "
            "command. This identifies configured code use only: triggering, guard satisfiability, attacker "
            "control in the specific repository, successful execution and effective credentials remain "
            "conditional or unknown. Unsupported JavaScript dispatch and scopes are not treated as safe."
        ),
        pattern=JavaScriptEnvCodePattern(),
        remediation=(
            "Keep the value as data and remove dynamic code construction. For example, parse a structured "
            "format or pass the string to a function that validates and handles it as a value; do not call "
            "``eval``/``Function`` on it. Environment indirection does not sanitize or isolate the value. "
            "If the input must select behavior, validate it against a finite allowlist. Review event guards, "
            "repository control and effective token/secrets separately."
        ),
        reference="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
        # Flow fixtures keep colon-padding mutations valid YAML; original block
        # sources remain in unit/native controls. Mutation count is format-dependent.
        test_positive=[
            '{"on": "pull_request", "jobs": {"test": {"runs-on": "ubuntu-latest", "steps": [{"env": {"TITLE": "${{ github.event.pull_request.title }}"}, "run": node -e \'eval(process.env.TITLE)\'}]}}}\n',
            '{"on": "pull_request", "jobs": {"test": {"runs-on": "ubuntu-latest", "steps": [{"env": {"TITLE": "${{ github.head_ref }}"}, "run": node --eval \'new Function(process.env.TITLE)()\'}]}}}\n',
        ],
        test_negative=[
            "on: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          TITLE: ${{ github.event.pull_request.title }}\n        run: |\n          node -e 'console.log(JSON.stringify({title: process.env.TITLE}))'\n",
            "on: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          TITLE: ${{ github.event.pull_request.title }}\n        run: |\n          node -e '/* eval(process.env.TITLE) */ console.log(process.env.TITLE)'\n",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An untrusted event field reaches JavaScript source compilation through a step-local environment "
            "binding. If the workflow runs and the source is attacker-controlled, the value may affect the "
            "JavaScript executed by that Node process; effective credentials and successful execution require review."
        ),
    )
]
