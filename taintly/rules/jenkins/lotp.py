"""Jenkins LOTP — Living Off The Pipeline.

Detects build tools that execute lifecycle scripts or build hooks against
attacker-controlled code in Jenkins pipelines.

Jenkins' risk model is structurally different from GitHub/GitLab:

- There is no single declarative "trigger" field that tells us whether the
  job processes external input. Multibranch Pipelines and the GitHub
  Branch Source plugin expose PR context via ``env.CHANGE_*`` variables,
  and the (now-legacy) GitHub PR Builder plugin uses ``ghprb*`` variables.
  Freestyle and classic Pipeline jobs may build parameterised branches
  supplied by an external trigger.

- The Jenkinsfile does not declare whether it runs in a Multibranch PR
  context. A Jenkinsfile that references ``env.CHANGE_ID`` / ``CHANGE_BRANCH``
  / ``ghprbActualCommit`` is strong evidence the author expects PR builds;
  combined with a build-tool invocation in the same file, this is the
  LOTP-risky shape.

These rules retain shell build/install candidates when PR-context signals
also appear in the Jenkinsfile. That co-occurrence is a review lead, not
proof of the configured job trigger, checked-out revision, or credentials.
"""

import re
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from taintly.models import ContextPattern, Platform, Rule, Severity
from taintly.parsers.jenkinsfile.events import Event
from taintly.parsers.jenkinsfile.groovy_lex import TokKind

from .._build_tools import BUILD_TOOL_ANCHOR as _BUILD_TOOL_ANCHOR

# Evidence the Jenkinsfile is PR-context aware. Any of these references
# strongly implies the pipeline can be triggered by a PR build, meaning
# the checked-out source may be attacker-controlled.
_PR_CONTEXT = (
    r"(?:"
    # Multibranch Pipeline / GitHub Branch Source plugin
    r"\benv\.CHANGE_(?:ID|BRANCH|TARGET|URL|AUTHOR|TITLE|FORK)\b"
    # Legacy GitHub Pull Request Builder plugin
    r"|\bghprb(?:ActualCommit|PullId|PullTitle|SourceBranch|TargetBranch|PullAuthorEmail)\b"
    # Gerrit Trigger plugin (change-based triggering)
    r"|\bGERRIT_(?:CHANGE_ID|BRANCH|REFSPEC|PATCHSET_REVISION)\b"
    r")"
)


_BUILD_TOOL_AT_COMMAND_START = re.compile(r"^(?:" + _BUILD_TOOL_ANCHOR + r")", re.IGNORECASE)


class _JenkinsBuildLeafPattern:
    """Match a build tool only at executable command position in a shell leaf."""

    def __init__(self) -> None:
        from .sec_jenkins import _JenkinsfileShellLeafPattern

        self._shell_pattern = _JenkinsfileShellLeafPattern(self._body_matches)

    _CONTROL_PREFIX = re.compile(r"^(?:(?:then|else|elif|if|while|until|do)\b\s*)+", re.I)
    _ASSIGNMENT_PREFIX = re.compile(r"^(?:env\s+)?(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*")

    @classmethod
    def _normalize_command(cls, command: str) -> tuple[str, int]:
        leading = len(command) - len(command.lstrip())
        command = command.strip()
        control = cls._CONTROL_PREFIX.match(command)
        if control:
            leading += control.end()
            command = command[control.end() :]
        assignment = cls._ASSIGNMENT_PREFIX.match(command)
        if assignment:
            leading += assignment.end()
            command = command[assignment.end() :]
        final_leading = len(command) - len(command.lstrip())
        return command.strip(), leading + final_leading

    @staticmethod
    def _command_segments_with_offsets(body: str) -> list[tuple[str, int]] | None:
        """Return top-level shell segments with body offsets when mapping is exact."""
        if _JenkinsInstallerLeafPattern._remove_active_continuations(body) != body:
            return None
        segments: list[tuple[str, int]] = []
        start = 0
        quote: str | None = None
        escaped = False
        i = 0
        while i < len(body):
            char = body[i]
            if (
                char == "$"
                and i + 1 < len(body)
                and body[i + 1] == "("
                and quote != "'"
                and not escaped
            ):
                # The existing detector recursively inspects substitutions. Their
                # decoded-to-source span semantics are outside this mapper.
                return None
            if escaped:
                escaped = False
            elif char == "\\" and quote != "'":
                escaped = True
            elif quote:
                if char == quote:
                    quote = None
            elif char in ("'", '"'):
                quote = char
            elif char == "#" and (i == start or body[i - 1].isspace()):
                segments.append((body[start:i], start))
                end = body.find("\n", i)
                if end < 0:
                    return segments
                start = end + 1
                i = end
            elif char in ";|&\n":
                segments.append((body[start:i], start))
                start = i + 1
            i += 1
        segments.append((body[start:], start))
        return segments

    @classmethod
    def _located_build_commands(cls, body: str) -> list[tuple[str, int]] | None:
        segments = cls._command_segments_with_offsets(body)
        if segments is None:
            return None
        located: list[tuple[str, int]] = []
        for segment, segment_start in segments:
            command, prefix_length = cls._normalize_command(segment)
            if _BUILD_TOOL_AT_COMMAND_START.match(command):
                located.append((command, segment_start + prefix_length))
        return located

    @classmethod
    def _distinct_build_leaf_lines(cls, events: Sequence[Event]) -> frozenset[int]:
        """Return lines with multiple build leaves carrying distinct commands."""
        grouped: dict[int, tuple[int, set[str]]] = {}
        for event in events:
            commands = cls._build_commands(event.value or "")
            if not commands:
                continue
            count, seen = grouped.setdefault(event.line, (0, set()))
            seen.update(commands)
            grouped[event.line] = (count + 1, seen)
        return frozenset(
            line for line, (count, commands) in grouped.items() if count > 1 and len(commands) > 1
        )

    @staticmethod
    def _matching_literal_token(content: str, event, tokens=None):
        from taintly.parsers.jenkinsfile.groovy_lex import TokKind, tokenize

        if tokens is None:
            tokens = tuple(tokenize(content))

        matches = [
            token
            for token in tokens
            if token.kind is TokKind.STRING
            and token.line == event.line
            and token.value == event.value
            and token.raw is not None
            and token.quote is not None
            and token.raw.startswith(token.quote)
            and token.raw.endswith(token.quote)
            and token.raw[len(token.quote) : -len(token.quote)] == token.value
        ]
        return matches[0] if len(matches) == 1 else None

    @classmethod
    def _finding_locations(
        cls,
        content: str,
        lines: list[str],
        event,
        tokens=None,
        distinct_same_line_leaves: bool = False,
    ) -> list[tuple[int, str]]:
        commands = cls._build_commands(event.value or "")
        if not commands:
            return []
        token = cls._matching_literal_token(content, event, tokens)
        located = cls._located_build_commands(event.value or "")
        if token is None or located is None or [command for command, _ in located] != commands:
            # Keep one visible call-site candidate when exact source mapping is
            # unavailable; never manufacture repeated evidence at that location.
            return (
                [(event.line, lines[event.line - 1].strip())]
                if 0 < event.line <= len(lines)
                else []
            )

        body_start_line = token.line
        source_lines = content.splitlines()
        records: list[tuple[int, str, str]] = []
        for command, offset in located:
            line = body_start_line + (event.value or "")[:offset].count("\n")
            records.append((line, command, source_lines[line - 1].strip()))
        counts_by_line = {
            line: sum(other == line for other, _command, _snippet in records)
            for line, _, _ in records
        }
        results: list[tuple[int, str]] = []
        for line, command, physical_snippet in records:
            snippet = (
                command
                if counts_by_line[line] > 1 or distinct_same_line_leaves
                else physical_snippet
            )
            result = (line, snippet)
            if result not in results:
                results.append(result)
        return results

    @staticmethod
    def _build_commands(body: str) -> list[str]:
        matches: list[str] = []
        for command in _JenkinsInstallerLeafPattern._commands(body):
            command, _prefix_length = _JenkinsBuildLeafPattern._normalize_command(command)
            if _BUILD_TOOL_AT_COMMAND_START.match(command):
                matches.append(command)
        return matches

    @classmethod
    def _body_matches(cls, body: str, _interpolated: bool = False) -> bool:
        return bool(cls._build_commands(body))

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if not _JenkinsInstallerLeafPattern._pr_context(content):
            return []
        try:
            from taintly.parsers.jenkinsfile import EventKind, walk_jenkinsfile
            from taintly.parsers.jenkinsfile.groovy_lex import tokenize
        except ImportError:
            # Preserve the existing cold fallback on installations where the
            # default island reader cannot be imported.
            return self._shell_pattern.check(content, lines)

        results: list[tuple[int, str]] = []
        try:
            source_tokens = tuple(tokenize(content))
            events = tuple(walk_jenkinsfile(content, recover=True))
            shell_events_list = []
            for event in events:
                if event.kind is EventKind.CUTOFF:
                    break
                if event.kind is EventKind.LEAF and event.value_kind == "shell":
                    shell_events_list.append(event)
            shell_events = tuple(shell_events_list)
            distinct_leaf_lines = self._distinct_build_leaf_lines(shell_events)
            for event in shell_events:
                if event.kind is EventKind.CUTOFF:
                    break
                if not event.value or not self._build_commands(event.value):
                    continue
                results.extend(
                    self._finding_locations(
                        content,
                        lines,
                        event,
                        source_tokens,
                        distinct_same_line_leaves=event.line in distinct_leaf_lines,
                    )
                )
        except Exception:
            return []
        # Several ambiguous leaves on one line can share one visible source
        # record. Keep that review lead once, without inventing distinct spans.
        return list(dict.fromkeys(results))


@dataclass(frozen=True)
class _JenkinsLoptOccurrence:
    """Source-derived, scan-local facts for one visible LOTP shell candidate."""

    unique_shell_leaf: bool
    source_checkout: bool
    enclosing_credential: bool
    literal_main_checkout: bool


@dataclass(frozen=True)
class _JenkinsLoptBlock:
    name: str
    head: int
    start: int
    parent: int | None
    has_arguments: bool
    end: int | None


@dataclass(frozen=True)
class _JenkinsLoptToken:
    kind: TokKind
    value: str
    line: int
    col: int
    quote: str | None
    unterminated: bool


@dataclass(frozen=True)
class JenkinsLoptProfile:
    """Immutable source index shared by both LOTP rules within one file scan."""

    content: str
    tokens: tuple[_JenkinsLoptToken, ...]
    blocks: tuple[_JenkinsLoptBlock, ...]
    owners: tuple[int | None, ...]
    shell_events: tuple[Event, ...]
    shell_event_locations: tuple[tuple[Event, tuple[tuple[int, str], ...]], ...]
    token_indices_by_line: Mapping[int, tuple[int, ...]]
    block_by_start: Mapping[int, _JenkinsLoptBlock]
    checkout_indices: tuple[int, ...]
    skip_default_checkout: bool
    complete: bool


def build_jenkins_lotp_profile(content: str) -> JenkinsLoptProfile:
    """Build the bounded Groovy/island index once for this file scan."""
    from taintly.parsers.jenkinsfile import EventKind, walk_jenkinsfile
    from taintly.parsers.jenkinsfile.groovy_lex import TokKind

    from .sec_jenkins import _jenkins_block_index

    try:
        events = tuple(walk_jenkinsfile(content, recover=True))
        raw_tokens, raw_blocks, owners = _jenkins_block_index(content)
        tokens = tuple(
            _JenkinsLoptToken(
                token.kind,
                token.value,
                token.line,
                token.col,
                token.quote,
                token.unterminated,
            )
            for token in raw_tokens
        )
        complete = not any(event.kind in (EventKind.CUTOFF, EventKind.ERROR) for event in events)
        complete = complete and not any(
            token.kind is TokKind.STRING and token.unterminated for token in raw_tokens
        )
        complete = complete and not any(block.end is None for block in raw_blocks)
        blocks = tuple(
            _JenkinsLoptBlock(
                block.name,
                block.head,
                block.start,
                block.parent,
                block.has_arguments,
                block.end,
            )
            for block in raw_blocks
        )
        token_indices_by_line_mutable: dict[int, list[int]] = {}
        checkout_indices: list[int] = []
        skip_default_checkout = False
        by_start = {block.start: block for block in blocks}
        for index, token in enumerate(tokens):
            token_indices_by_line_mutable.setdefault(token.line, []).append(index)
            if (
                token.kind is TokKind.IDENT
                and token.value == "checkout"
                and (index == 0 or tokens[index - 1].value != ".")
            ):
                checkout_indices.append(index)
            if (
                token.kind is TokKind.IDENT
                and token.value == "skipDefaultCheckout"
                and index + 3 < len(tokens)
                and tokens[index + 1].kind is TokKind.LPAREN
                and tokens[index + 2].kind is TokKind.IDENT
                and tokens[index + 2].value == "true"
                and tokens[index + 3].kind is TokKind.RPAREN
                and _direct_statement(tokens, index)
            ):
                owner_start = owners[index]
                option_owner = by_start.get(owner_start) if owner_start is not None else None
                parent_start = option_owner.parent if option_owner is not None else None
                option_parent = by_start.get(parent_start) if parent_start is not None else None
                if (
                    option_owner is not None
                    and option_owner.name == "options"
                    and not option_owner.has_arguments
                    and option_parent is not None
                    and option_parent.name in {"pipeline", "stage"}
                ):
                    skip_default_checkout = True
        shell_events = tuple(
            event
            for event in events
            if event.kind is EventKind.LEAF and event.value_kind == "shell"
        )
        source_lines = content.splitlines()
        distinct_leaf_lines = _JenkinsBuildLeafPattern._distinct_build_leaf_lines(shell_events)
        shell_event_locations = tuple(
            (
                event,
                tuple(
                    _JenkinsBuildLeafPattern._finding_locations(
                        content,
                        source_lines,
                        event,
                        raw_tokens,
                        distinct_same_line_leaves=event.line in distinct_leaf_lines,
                    )
                ),
            )
            for event in shell_events
        )
        return JenkinsLoptProfile(
            content,
            tokens,
            blocks,
            tuple(owners),
            shell_events,
            shell_event_locations,
            MappingProxyType(
                {line: tuple(indices) for line, indices in token_indices_by_line_mutable.items()}
            ),
            MappingProxyType({block.start: block for block in blocks}),
            tuple(checkout_indices),
            skip_default_checkout,
            complete,
        )
    except Exception:
        return JenkinsLoptProfile(
            content,
            (),
            (),
            (),
            (),
            (),
            MappingProxyType({}),
            MappingProxyType({}),
            (),
            False,
            False,
        )


def _token_pair_end(
    tokens: Sequence[_JenkinsLoptToken], start: int, opening: TokKind, closing: TokKind
) -> int | None:
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index].kind is opening:
            depth += 1
        elif tokens[index].kind is closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def _direct_items(
    tokens: Sequence[_JenkinsLoptToken], start: int, end: int
) -> list[tuple[int, int]] | None:
    """Split an inclusive argument range only at balanced direct commas."""
    pairs = {
        TokKind.LBRACKET: TokKind.RBRACKET,
        TokKind.LPAREN: TokKind.RPAREN,
        TokKind.LBRACE: TokKind.RBRACE,
    }
    stack: list[TokKind] = []
    items: list[tuple[int, int]] = []
    item_start = start
    for index in range(start, end + 1):
        token = tokens[index]
        if token.kind in pairs:
            stack.append(pairs[token.kind])
        elif token.kind in pairs.values():
            if not stack or stack.pop() is not token.kind:
                return None
        elif token.value == "," and not stack:
            if item_start == index:
                return None
            items.append((item_start, index - 1))
            item_start = index + 1
    if stack:
        return None
    if item_start <= end:
        items.append((item_start, end))
    return items


def _named_value_spans(
    tokens: Sequence[_JenkinsLoptToken], start: int, end: int
) -> dict[str, tuple[int, int]] | None:
    """Accept unique, direct named arguments; spread/dynamic shapes stay unknown."""
    items = _direct_items(tokens, start, end)
    if items is None:
        return None
    values: dict[str, tuple[int, int]] = {}
    for first, last in items:
        if (
            last < first + 2
            or tokens[first].kind is not TokKind.IDENT
            or tokens[first + 1].value != ":"
            or tokens[first].value in values
        ):
            return None
        values[tokens[first].value] = (first + 2, last)
    return values


def _direct_map_value_span(
    tokens: Sequence[_JenkinsLoptToken], start: int, end: int, key: str, tok_kind: type[TokKind]
) -> tuple[int, int] | None:
    if (
        start >= end
        or tokens[start].kind is not tok_kind.LBRACKET
        or tokens[end].kind is not tok_kind.RBRACKET
    ):
        return None
    values = _named_value_spans(tokens, start + 1, end - 1)
    return values.get(key) if values is not None else None


def _checkout_branch_values(
    tokens: Sequence[_JenkinsLoptToken],
    branches_start: int,
    branches_end: int,
    tok_kind: type[TokKind],
) -> list[tuple[_JenkinsLoptToken, ...]]:
    """Read only direct branch maps, preserving literal versus expression kinds."""
    if (
        branches_start >= branches_end
        or tokens[branches_start].kind is not tok_kind.LBRACKET
        or tokens[branches_end].kind is not tok_kind.RBRACKET
    ):
        return []
    items = _direct_items(tokens, branches_start + 1, branches_end - 1)
    if items is None:
        return []
    values: list[tuple[_JenkinsLoptToken, ...]] = []
    for start, end in items:
        span = _direct_map_value_span(tokens, start, end, "name", tok_kind)
        if span is None:
            return []
        first, last = span
        values.append(tuple(tokens[first : last + 1]))
    return values


def _direct_statement(tokens: Sequence[_JenkinsLoptToken], index: int) -> bool:
    """Exclude receiver calls, assignments and nested argument expressions."""
    if index == 0:
        return True
    previous = tokens[index - 1]
    if previous.kind in (TokKind.LBRACE, TokKind.RBRACE, TokKind.SEMI):
        return True
    return previous.line < tokens[index].line and previous.kind in (
        TokKind.RPAREN,
        TokKind.RBRACKET,
        TokKind.STRING,
        TokKind.IDENT,
    )


def _jenkins_lotp_occurrence(
    content: str,
    line: int,
    snippet: str,
    rule_id: str,
    profile: JenkinsLoptProfile | None = None,
) -> _JenkinsLoptOccurrence:
    """Derive bounded same-occurrence facts; unsupported structure stays unknown."""
    from taintly.parsers.jenkinsfile.groovy_lex import TokKind

    if profile is None:
        profile = build_jenkins_lotp_profile(content)
    if type(profile) is not JenkinsLoptProfile or profile.content != content:
        return _JenkinsLoptOccurrence(False, False, False, False)
    tokens, owners = profile.tokens, profile.owners
    source_lines = content.splitlines()
    shell_events = []
    for event, locations in profile.shell_event_locations:
        if event.degraded or event.value is None:
            continue
        callsite_location = (
            event.line,
            source_lines[event.line - 1].strip()
            if 0 < event.line <= len(source_lines)
            else event.value.strip(),
        )
        if (line, snippet) in locations or (
            rule_id == "LOTP-JK-003" and (line, snippet) == callsite_location
        ):
            shell_events.append(event)
    if not profile.complete or len(shell_events) != 1 or shell_events[0].degraded:
        return _JenkinsLoptOccurrence(False, False, False, False)
    shell_event = shell_events[0]

    shell_indices = [
        index
        for index in profile.token_indices_by_line.get(shell_event.line, ())
        for token in (tokens[index],)
        if token.line == shell_event.line
        and token.kind is TokKind.IDENT
        and token.value in {"sh", "bat", "powershell", "pwsh"}
        and (index == 0 or tokens[index - 1].value != ".")
    ]
    if len(shell_indices) != 1:
        return _JenkinsLoptOccurrence(False, False, False, False)
    shell_index = shell_indices[0]

    by_start = profile.block_by_start

    def ancestry(index: int) -> list[_JenkinsLoptBlock]:
        result = []
        owner = owners[index]
        while owner is not None:
            block = by_start.get(owner)
            if block is None:
                return []
            result.append(block)
            owner = block.parent
        return result

    shell_chain = ancestry(shell_index)
    if not shell_chain:
        return _JenkinsLoptOccurrence(True, False, False, False)

    def workspace_scope(index: int):
        for block in ancestry(index):
            if block.name in {"stage", "node"}:
                return block
        return None

    shell_scope = workspace_scope(shell_index)
    if shell_scope is None:
        return _JenkinsLoptOccurrence(True, False, False, False)

    def checkout_shape(index: int) -> tuple[bool, bool]:
        if (
            not _direct_statement(tokens, index)
            or index + 1 >= len(tokens)
            or tokens[index + 1].kind is not TokKind.LPAREN
        ):
            return False, False
        end = _token_pair_end(tokens, index + 1, TokKind.LPAREN, TokKind.RPAREN)
        if end is None:
            return False, False
        argument_start = index + 2
        argument_end = end - 1
        if (
            argument_start >= argument_end
            or tokens[argument_start].kind is not TokKind.LBRACKET
            or tokens[argument_end].kind is not TokKind.RBRACKET
        ):
            return False, False
        class_span = _direct_map_value_span(tokens, argument_start, argument_end, "$class", TokKind)
        branches_span = _direct_map_value_span(
            tokens, argument_start, argument_end, "branches", TokKind
        )
        if class_span is None or branches_span is None:
            return False, False
        class_start, class_end = class_span
        git_scm = (
            class_start == class_end
            and tokens[class_start].kind is TokKind.STRING
            and tokens[class_start].value == "GitSCM"
            and tokens[class_start].quote in ("'", "'''")
        )
        branch_start, branch_end = branches_span
        branch_values = _checkout_branch_values(tokens, branch_start, branch_end, TokKind)
        provider_ref = any(
            len(value) == 3
            and value[0].kind is TokKind.IDENT
            and value[0].value == "env"
            and value[1].kind is TokKind.OP
            and value[1].value == "."
            and value[2].kind is TokKind.IDENT
            and value[2].value in {"CHANGE_BRANCH", "ghprbSourceBranch", "GERRIT_REFSPEC"}
            for value in branch_values
        )
        explicit_main = any(
            len(value) == 1
            and value[0].kind is TokKind.STRING
            and value[0].value == "main"
            and value[0].quote in ("'", "'''", '"', '"""')
            for value in branch_values
        )
        return git_scm and provider_ref, git_scm and explicit_main

    checkout_indices = [
        index
        for index in profile.checkout_indices
        if index < shell_index and workspace_scope(index) is shell_scope
    ]
    recognized = [index for index in checkout_indices if checkout_shape(index)[0]]
    literal_main = profile.skip_default_checkout and any(
        checkout_shape(index)[1] for index in profile.checkout_indices
    )
    source_checkout = len(recognized) == 1 and len(checkout_indices) == 1
    if source_checkout:
        checkout_index = recognized[0]
        checkout_chain = ancestry(checkout_index)
        common_blocks = [block for block in checkout_chain if block in shell_chain]
        common_owner = common_blocks[0] if common_blocks else None
        if (
            common_owner is None
            or owners[checkout_index] != common_owner.start
            or common_owner.name not in {"stage", "node", "steps"}
        ):
            source_checkout = False
        if any(
            token.kind is TokKind.IDENT
            and token.value
            in {
                "checkout",
                "ws",
                "dir",
                "deleteDir",
                "cleanWs",
                "parallel",
                "node",
                "load",
                "library",
            }
            for token in tokens[checkout_index + 1 : shell_index]
        ):
            source_checkout = False

    credential = False
    for block in shell_chain:
        if block.name != "withCredentials" or not block.has_arguments:
            continue
        if block.head >= len(tokens) or tokens[block.head].value != "withCredentials":
            continue
        opening = block.head + 1
        if opening >= block.start or tokens[opening].kind is not TokKind.LPAREN:
            continue
        closing = _token_pair_end(tokens, opening, TokKind.LPAREN, TokKind.RPAREN)
        if closing is None or closing >= block.start:
            continue
        list_start, list_end = opening + 1, closing - 1
        if (
            list_start >= list_end
            or tokens[list_start].kind is not TokKind.LBRACKET
            or tokens[list_end].kind is not TokKind.RBRACKET
        ):
            continue
        entries = _direct_items(tokens, list_start + 1, list_end - 1)
        if entries is None:
            continue
        binding_types = {
            "string": ("credentialsId", "variable"),
            "file": ("credentialsId", "variable"),
            "usernamePassword": ("credentialsId", "usernameVariable", "passwordVariable"),
            "sshUserPrivateKey": ("credentialsId", "keyFileVariable"),
        }
        for first, last in entries:
            if (
                last < first + 3
                or tokens[first].kind is not TokKind.IDENT
                or tokens[first].value not in binding_types
                or tokens[first + 1].kind is not TokKind.LPAREN
                or _token_pair_end(tokens, first + 1, TokKind.LPAREN, TokKind.RPAREN) != last
            ):
                continue
            values = _named_value_spans(tokens, first + 2, last - 1)
            if values is None:
                continue
            required = binding_types[tokens[first].value]
            if all(
                key in values
                and values[key][0] == values[key][1]
                and tokens[values[key][0]].kind is TokKind.STRING
                and tokens[values[key][0]].quote in ("'", "'''")
                and bool(tokens[values[key][0]].value)
                for key in required
            ):
                credential = True
                break
        if credential:
            break

    return _JenkinsLoptOccurrence(True, source_checkout, credential, literal_main)


def qualify_jenkins_lotp(finding, content: str, profile: JenkinsLoptProfile | None = None) -> None:
    """Calibrate LOTP candidates as conditional; add only same-occurrence facts."""
    if finding.rule_id not in {"LOTP-JK-001", "LOTP-JK-003"}:
        return
    occurrence = _jenkins_lotp_occurrence(
        content, finding.line, finding.snippet, finding.rule_id, profile
    )
    finding.confidence = "medium"
    finding.review_needed = True
    if finding.exploitability == "high":
        finding.exploitability = "medium"
    finding.context_notes.append(
        "This is a source-to-build candidate, not proof of effective PR material, job triggering, "
        "or runtime authority. Verify provider/plugin configuration, checkout revision, workspace "
        "changes, and credential availability and permissions."
    )
    if not occurrence.unique_shell_leaf:
        finding.context_notes.append(
            "The shell occurrence or lexical owner is ambiguous or recovered; occurrence-specific "
            "checkout and credential scope could not be established."
        )
        return
    if occurrence.source_checkout:
        finding.context_notes.append(
            "The build shell occurrence follows a literal provider-ref GitSCM checkout in the same "
            "lexical stage or node. Effective revision, plugin behavior, and intervening runtime "
            "workspace changes remain unverified."
        )
    elif occurrence.literal_main_checkout:
        finding.context_notes.append(
            "The file declares skipDefaultCheckout(true) and a literal GitSCM main branch checkout. "
            "That is a mutable branch declaration, not proof that PR content is absent, that the "
            "build uses this checkout, or that source is pinned."
        )
    if occurrence.enclosing_credential:
        finding.context_notes.append(
            "This shell occurrence is lexically enclosed by a direct withCredentials binding with "
            "literal credential and variable names. Actual credential availability and permissions "
            "are unverified."
        )


class _JenkinsInstallerLeafPattern:
    """Match an unsafe package installer in an actual Jenkins shell step.

    LOTP-JK-003 used to search Jenkinsfile lines, which also matched stage
    names and variable values that merely contained words like ``yarn``.
    Island LEAF events constrain the search to executable ``sh``/``bat``/
    ``powershell``/``pwsh`` bodies while retaining the call site's line.
    """

    _INSTALLER_RE = re.compile(
        r"(?i)^\s*(?:(?:env\s+)?(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*)"
        r"(?P<tool>npm\s+(?:install|i|ci)|yarn(?:\s+install)?|pnpm\s+(?:install|i))"
        r"(?=\s|$)"
    )

    def __init__(self) -> None:
        # Share Jenkins' existing island-shell matcher for LEAF selection and
        # call-site attribution; only this rule's body predicate is new.
        from .sec_jenkins import _JenkinsfileShellLeafPattern

        self._shell_pattern = _JenkinsfileShellLeafPattern(self._body_matches)

    @staticmethod
    def _pr_context(content: str) -> bool:
        """Read PR signals from Groovy code or live GString expressions.

        Comments and ordinary string data cannot donate file-level PR
        context; the common ``"${env.CHANGE_BRANCH}"`` form remains covered.
        """
        from taintly.parsers.jenkinsfile.groovy_lex import TokKind, tokenize

        tokens = list(tokenize(content))
        significant = [
            token
            for token in tokens
            if token.kind not in (TokKind.COMMENT, TokKind.NEWLINE, TokKind.SEMI)
        ]
        for index, token in enumerate(significant):
            if token.kind == TokKind.IDENT and re.search(
                r"(?i)^(?:ghprb(?:ActualCommit|PullId|PullTitle|SourceBranch|TargetBranch|PullAuthorEmail)|GERRIT_(?:CHANGE_ID|BRANCH|REFSPEC|PATCHSET_REVISION))$",
                token.value,
            ):
                return True
            if (
                token.kind == TokKind.IDENT
                and token.value == "env"
                and index + 2 < len(significant)
                and significant[index + 1].kind == TokKind.OP
                and significant[index + 1].value == "."
                and significant[index + 2].kind == TokKind.IDENT
                and re.fullmatch(
                    r"CHANGE_(?:ID|BRANCH|TARGET|URL|AUTHOR|TITLE|FORK)",
                    significant[index + 2].value,
                )
            ):
                return True
            if token.kind == TokKind.STRING and any(
                re.search(_PR_CONTEXT, span.expr) for span in (token.interpolations or ())
            ):
                return True
        return False

    @staticmethod
    def _commands(body: str):
        """Yield shell command segments, respecting quotes and comments."""
        body = _JenkinsInstallerLeafPattern._remove_active_continuations(body)
        start = 0
        quote: str | None = None
        escaped = False
        i = 0
        while i < len(body):
            char = body[i]
            if (
                char == "$"
                and i + 1 < len(body)
                and body[i + 1] == "("
                and quote != "'"
                and not escaped
            ):
                end = _JenkinsInstallerLeafPattern._command_substitution_end(body, i)
                if end is not None:
                    yield from _JenkinsInstallerLeafPattern._commands(body[i + 2 : end])
                    i = end
                    continue
            if escaped:
                escaped = False
            elif char == "\\" and quote != "'":
                escaped = True
            elif quote:
                if char == quote:
                    quote = None
            elif char in ("'", '"'):
                quote = char
            elif char == "#" and (i == start or body[i - 1].isspace()):
                end = body.find("\n", i)
                if end < 0:
                    end = len(body)
                yield body[start:i]
                start = end + 1
                i = end
            elif char in ";|&\n":
                yield body[start:i]
                start = i + 1
            i += 1
        yield body[start:]

    @staticmethod
    def _remove_active_continuations(body: str) -> str:
        """Remove shell line continuations except inside single-quoted data."""
        output: list[str] = []
        quote: str | None = None
        escaped = False
        i = 0
        while i < len(body):
            char = body[i]
            if char == "\\" and quote != "'" and i + 1 < len(body):
                if body[i + 1] == "\n" and not escaped:
                    i += 2
                    while i < len(body) and body[i] in " \t":
                        i += 1
                    continue
                if (
                    body[i + 1] == "\r"
                    and i + 2 < len(body)
                    and body[i + 2] == "\n"
                    and not escaped
                ):
                    i += 3
                    while i < len(body) and body[i] in " \t":
                        i += 1
                    continue
            if escaped:
                escaped = False
            elif char == "\\" and quote != "'":
                escaped = True
            elif quote:
                if char == quote:
                    quote = None
            elif char in ("'", '"'):
                quote = char
            output.append(char)
            i += 1
        return "".join(output)

    @staticmethod
    def _command_substitution_end(body: str, start: int) -> int | None:
        depth = 1
        quote: str | None = None
        escaped = False
        i = start + 2
        while i < len(body):
            char = body[i]
            if escaped:
                escaped = False
            elif char == "\\" and quote != "'":
                escaped = True
            elif quote:
                if char == quote:
                    quote = None
            elif char in ("'", '"'):
                quote = char
            elif body.startswith("$(", i):
                depth += 1
                i += 1
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return i
            i += 1
        return None

    @classmethod
    def _has_ignore_scripts(cls, command: str) -> bool:
        try:
            args = shlex.split(command, posix=True)
        except ValueError:
            return False
        return any(
            arg == "--ignore-scripts" or arg.lower() == "--ignore-scripts=true" for arg in args
        )

    @classmethod
    def _body_matches(cls, body: str, _interpolated: bool = False) -> bool:
        for command in cls._commands(body):
            command = command.strip()
            # Shell compound commands put executable commands after control
            # words such as ``then``; discard only these leading keywords.
            command = re.sub(
                r"^(?:(?:then|else|elif|if|while|until|do)\b\s*)+", "", command, flags=re.I
            )
            match = cls._INSTALLER_RE.match(command)
            if not match or cls._has_ignore_scripts(command):
                continue
            # Bare ``yarn`` means install; ``yarn test`` / ``yarn run``
            # execute scripts and are not package installation sinks.
            if (
                match.group("tool").lower() == "yarn"
                and command[match.end() :].strip()
                and not command[match.end() :].lstrip().startswith("-")
            ):
                continue
            return True
        return False

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if not self._pr_context(content):
            return []
        return self._shell_pattern.check(content, lines)


RULES: list[Rule] = [
    # =========================================================================
    # LOTP-JK-001: Build tool + PR-context in Jenkinsfile
    # =========================================================================
    Rule(
        id="LOTP-JK-001",
        confidence="medium",
        review_needed=True,
        finding_family="pipeline_tool_execution",
        title="Build tool invoked in Jenkinsfile with PR-context signals (LOTP review)",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkins shell leaf contains an executable build-tool command and the Jenkinsfile "
            "also references PR-context variables — "
            "env.CHANGE_ID/CHANGE_BRANCH (Multibranch / GitHub Branch Source), "
            "ghprb* (legacy PR Builder), or GERRIT_CHANGE_* (Gerrit trigger) — "
            "This source co-occurrence does not establish that the job is PR-triggered, "
            "checks out the PR revision, or makes credentials available to the build. "
            "If untrusted source is checked out and a build tool consumes its manifests, "
            "lifecycle scripts or build hooks may execute with the agent's runtime identity. "
            "Verify the actual job/plugin configuration, checkout revision, workspace changes, "
            "credential scope, and permissions."
        ),
        pattern=_JenkinsBuildLeafPattern(),
        remediation=(
            "Review whether the Jenkins job can run an untrusted change and what source the "
            "build consumes. Mitigations, in order of preference:\n"
            "\n"
            "1. Move build-tool invocation out of PR builds. In declarative "
            "   Pipeline, gate the stage on the base branch:\n"
            "\n"
            "     stage('Build') {\n"
            "         when { branch 'main' }\n"
            "         steps { sh 'npm ci' }\n"
            "     }\n"
            "\n"
            "2. Run PR builds on an isolated agent with no credentials and "
            "   no network access to internal systems. Use `agent { label "
            "   'pr-sandbox' }` for the stage, and bind no credentials via "
            "   withCredentials inside it.\n"
            "\n"
            "3. For JavaScript builds, add `--ignore-scripts` to npm/yarn/"
            "   pnpm install commands to disable lifecycle hooks.\n"
            "\n"
            "4. Verify PR trigger and trust settings in the GitHub Branch Source / "
            "   Multibranch configuration only build PRs from trusted "
            "   contributors — in the job configuration, set 'Trust' to "
            "   'From users with Admin or Write permission'."
        ),
        reference="https://www.jenkins.io/doc/book/security/securing-jenkins/#ci-cd-security",
        test_positive=[
            # Multibranch PR-aware Jenkinsfile running npm install
            "pipeline {\n    agent any\n    stages {\n"
            "        stage('build') {\n"
            "            when { changeRequest() }\n"
            "            steps {\n"
            '                echo "Building PR #${env.CHANGE_ID}"\n'
            "                sh 'npm install'\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}",
            # ghprb-plugin build running pip install .
            "node {\n    if (env.ghprbPullId) {\n        sh 'pip install .'\n    }\n}",
            # CHANGE_BRANCH + docker build
            "pipeline {\n    agent any\n    stages {\n"
            "        stage('pr-image') {\n"
            "            steps {\n"
            '                echo "branch ${env.CHANGE_BRANCH}"\n'
            "                sh 'docker build -t review .'\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}",
        ],
        test_negative=[
            # No PR context — build tool is safe (runs only on trusted refs)
            "pipeline {\n    agent any\n    stages {\n"
            "        stage('build') { steps { sh 'npm install' } }\n"
            "    }\n"
            "}",
            # PR context but no build tool — posting a status comment only
            "pipeline {\n    agent any\n    stages {\n"
            "        stage('note') { steps { echo \"PR ${env.CHANGE_ID}\" } }\n"
            "    }\n"
            "}",
            # PR context but the stage only runs a non-build-tool command
            "pipeline {\n    agent any\n    stages {\n"
            "        stage('status') {\n"
            "            when { changeRequest() }\n"
            "            steps {\n"
            '                echo "PR ${env.CHANGE_ID} on ${env.CHANGE_BRANCH}"\n'
            "                sh 'curl -X POST https://status.internal/ping'\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "If the configured Jenkins job accepts an untrusted change and checks out its "
            "revision, a build tool that consumes attacker-controlled package.json, setup.py, "
            "Makefile, pom.xml, or Dockerfile content may execute its hooks with the agent's "
            "runtime identity. This source candidate does not establish job triggering, checkout "
            "revision, credential scope, or effective permissions; review those settings and the "
            "specific shell occurrence."
        ),
        incidents=["Ultralytics (Dec 2024)"],
    ),
    # =========================================================================
    # LOTP-JK-005: npm/yarn/pnpm install in a Jenkins pipeline that binds an
    # npm publishing credential.  Jenkins port of LOTP-GH-005 / LOTP-GL-005
    # (Shai-Hulud class).
    #
    # Jenkins' model differs from the hosted runners on two key axes:
    #   1. Self-hosted by default.  A compromised postinstall script runs
    #      on the agent's host, not an ephemeral container the cloud
    #      destroys after the job.  That amplifies the blast radius:
    #      persistent filesystem on the agent, shared build caches, and
    #      often SSH keys / secondary credentials the agent already
    #      holds.
    #   2. Credentials are bound by ``withCredentials([...])`` block or
    #      the declarative ``environment { X = credentials('id') }``
    #      helper.  Unlike GH/GL, there's no "permissions: write" block
    #      to signal — the credential itself IS the signal.
    #
    # Shape: a Jenkinsfile runs ``npm/yarn/pnpm install`` without
    # ``--ignore-scripts`` AND references a publish-token variable name
    # (``NPM_TOKEN`` / ``NODE_AUTH_TOKEN`` / ``NPM_CONFIG_AUTH_TOKEN`` /
    # ``YARN_NPM_AUTH_TOKEN``) anywhere in the same file.  The variable
    # name is the signal regardless of whether the binding is a
    # ``withCredentials`` block, an ``environment {}`` declaration, or
    # an explicit ``env.NPM_TOKEN = ...`` statement.
    #
    # File-scoped because ``_split_into_job_segments`` already treats a
    # Jenkinsfile as a single segment (no 0-indent YAML keys).
    #
    # References: Shai-Hulud (Sep 2025) + Shai-Hulud 2.0 (Nov 2025).
    # Jenkins-specific hardening guidance:
    # https://www.jenkins.io/doc/book/pipeline/pipeline-best-practices/
    # =========================================================================
    Rule(
        id="LOTP-JK-005",
        finding_family="pipeline_tool_execution",
        title=(
            "npm/yarn/pnpm install in a Jenkinsfile that binds an "
            "npm publishing credential (Shai-Hulud class)"
        ),
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A Jenkins pipeline runs ``npm install`` / ``npm ci`` / "
            "``yarn install`` / ``pnpm install`` WITHOUT "
            "``--ignore-scripts``, and the same Jenkinsfile references "
            "a publish-token variable — ``NPM_TOKEN`` / ``NODE_AUTH_TOKEN`` / "
            "``NPM_CONFIG_AUTH_TOKEN`` / ``YARN_NPM_AUTH_TOKEN`` — "
            "typically through a ``withCredentials([string(credentialsId: "
            "'npm-token', variable: 'NPM_TOKEN')])`` block or an "
            "``environment { NPM_TOKEN = credentials('npm-token') }`` "
            "declaration.  Every direct and transitive dependency's "
            "``postinstall`` / ``preinstall`` / ``prepare`` hook runs "
            "in the agent's shell with the credential in process env.  "
            "On Jenkins this is especially dangerous because agents are "
            "self-hosted by default — a compromised script persists on "
            "the filesystem, may read SSH keys the agent uses for SCM, "
            "and can pivot to other credentials the same agent is "
            "trusted to bind in later builds.  The exploit class is "
            "the same as Shai-Hulud (Sep 2025) and Shai-Hulud 2.0 "
            "(Nov 2025)."
        ),
        pattern=ContextPattern(
            # Anchor: per-line install invocation NOT already carrying
            # ``--ignore-scripts``.  Matches inside Groovy ``sh 'npm
            # install'`` strings (the common shape) as well as bare
            # invocations in shell ``script:`` blocks.
            anchor=(
                r"\b(?:"
                r"npm\s+(?:install|i|ci)"
                r"|yarn\s+(?:install|add)"
                r"|pnpm\s+(?:install|i|add)"
                r")\b(?:(?!--ignore-scripts).)*$"
            ),
            # Requires (per-file): publish-token variable reference.
            # The variable name is the signal — its source (credentials
            # binding, environment block, explicit assignment) doesn't
            # change the threat shape.
            requires=(
                r"(?:"
                r"\bNPM_TOKEN\b"
                r"|\bNODE_AUTH_TOKEN\b"
                r"|\bNPM_CONFIG_AUTH_?TOKEN\b"
                r"|\bYARN_NPM_AUTH_?TOKEN\b"
                r")"
            ),
            scope="file",
            exclude=[
                r"^\s*//",  # Groovy line comment
                r"^\s*/\*",  # `/*` block-comment opener (single-line
                # `/* ... */` or multi-line opener)
                r"^\s*\*",  # Javadoc block-comment body
                r"^\s*#",  # Shell-style comment (rare in Groovy)
                # Lines already passing --ignore-scripts are safe.
                r"--ignore-scripts",
            ],
        ),
        remediation=(
            "Pass `--ignore-scripts` to every `npm install` / `npm ci`\n"
            "/ `yarn install` / `pnpm install` in a Jenkinsfile that\n"
            "binds an npm publishing credential.  This blocks the\n"
            "postinstall / preinstall lifecycle hooks that Shai-Hulud-\n"
            "class attacks abuse.  For pipelines that genuinely need\n"
            "lifecycle scripts (native-addon builds), split into two\n"
            "stages: a `build` stage on an isolated agent (no\n"
            "`withCredentials`, no bound publish token) that installs\n"
            "and stashes node_modules; and a `publish` stage that\n"
            "unstashes and publishes with `--ignore-scripts` and the\n"
            "credential scoped as tightly as possible.\n"
            "\n"
            "Prefer single-quoted Groovy strings inside `sh '...'` so\n"
            "the token is resolved by the shell from the environment,\n"
            "not interpolated into the command string by Groovy (see\n"
            "SEC4-JK-001 / SEC6-JK-002 for the general class).\n"
            "Run `taintly --guide LOTP-GH-005` for the\n"
            "remediation checklist (it applies directly to Jenkins\n"
            "with the obvious credential-binding substitutions)."
        ),
        reference=(
            "https://www.sysdig.com/blog/shai-hulud-the-novel-self-replicating-worm-infecting-hundreds-of-npm-packages; "
            "https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/; "
            "https://www.jenkins.io/doc/pipeline/steps/credentials-binding/"
        ),
        test_positive=[
            # withCredentials string-binding + npm install
            (
                "pipeline {\n    agent any\n    stages {\n"
                "        stage('publish') {\n"
                "            steps {\n"
                "                withCredentials([string(credentialsId: 'npm', variable: 'NPM_TOKEN')]) {\n"
                "                    sh 'npm install'\n"
                "                    sh 'npm publish'\n"
                "                }\n"
                "            }\n"
                "        }\n"
                "    }\n"
                "}"
            ),
            # environment {} credentials() + yarn install
            (
                "pipeline {\n    agent any\n"
                "    environment {\n"
                "        NPM_TOKEN = credentials('npm-publish-token')\n"
                "    }\n"
                "    stages {\n"
                "        stage('release') {\n"
                "            steps {\n"
                "                sh 'yarn install --frozen-lockfile'\n"
                "                sh 'yarn publish'\n"
                "            }\n"
                "        }\n"
                "    }\n"
                "}"
            ),
            # Scripted pipeline + pnpm install + NODE_AUTH_TOKEN
            (
                "node {\n"
                "    stage('publish') {\n"
                "        withCredentials([string(credentialsId: 'n', variable: 'NODE_AUTH_TOKEN')]) {\n"
                "            sh 'pnpm install --frozen-lockfile'\n"
                "            sh 'pnpm publish'\n"
                "        }\n"
                "    }\n"
                "}"
            ),
            # Explicit env assignment form
            (
                "pipeline {\n    agent any\n    stages {\n"
                "        stage('x') {\n"
                "            steps {\n"
                "                script { env.NPM_CONFIG_AUTHTOKEN = credentials('n') }\n"
                "                sh 'npm ci'\n"
                "            }\n"
                "        }\n"
                "    }\n"
                "}"
            ),
        ],
        test_negative=[
            # --ignore-scripts — safe even with NPM_TOKEN in scope
            (
                "pipeline {\n    agent any\n    stages {\n"
                "        stage('p') {\n"
                "            steps {\n"
                "                withCredentials([string(credentialsId: 'n', variable: 'NPM_TOKEN')]) {\n"
                "                    sh 'npm install --ignore-scripts'\n"
                "                    sh 'npm publish --ignore-scripts'\n"
                "                }\n"
                "            }\n"
                "        }\n"
                "    }\n"
                "}"
            ),
            # npm install without any publish-token reference — non-publishing pipeline
            (
                "pipeline {\n    agent any\n    stages {\n"
                "        stage('test') { steps { sh 'npm install' } }\n"
                "    }\n"
                "}"
            ),
            # NPM_TOKEN referenced but no install in the pipeline
            (
                "pipeline {\n    agent any\n"
                "    environment { NPM_TOKEN = credentials('n') }\n"
                "    stages {\n"
                "        stage('publish') { steps { sh 'npm publish' } }\n"
                "    }\n"
                "}"
            ),
            # Commented-out install
            (
                "pipeline {\n    agent any\n    stages {\n"
                "        stage('p') {\n"
                "            steps {\n"
                "                withCredentials([string(credentialsId: 'n', variable: 'NPM_TOKEN')]) {\n"
                "                    // sh 'npm install'\n"
                "                    sh 'echo hi'\n"
                "                }\n"
                "            }\n"
                "        }\n"
                "    }\n"
                "}"
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "On a self-hosted Jenkins agent, a compromised npm "
            "dependency's ``postinstall`` script runs with the agent's "
            "full environment: the ``NPM_TOKEN`` bound for this "
            "publish, the SSH key the agent uses for SCM, any "
            "workspace artefacts from previous builds, and any "
            "credential cached in the agent's keyring.  Unlike GH/GL "
            "hosted runners, the filesystem persists across builds — "
            "a script that writes a backdoor to "
            "``~/.bashrc`` or ``/var/jenkins_home/secrets/`` survives "
            "the job and waits for the next privileged pipeline to "
            "run.  The Shai-Hulud worm's self-propagation behaviour "
            "makes every compromised agent a candidate to attack the "
            "rest of the maintainer's npm namespace."
        ),
        incidents=["Shai-Hulud (Sep 2025)", "Shai-Hulud 2.0 (Nov 2025)"],
        confidence="low",
    ),
    # =========================================================================
    # LOTP-JK-003: npm / yarn / pnpm install without --ignore-scripts in a
    # Jenkinsfile that references PR-context env vars.  Jenkins port of
    # LOTP-GH-003 / LOTP-GL-003.  Lifecycle scripts from the PR's
    # ``package.json`` run during install under the Jenkins agent's
    # identity + any active ``withCredentials`` scope.
    # =========================================================================
    Rule(
        id="LOTP-JK-003",
        confidence="medium",
        review_needed=True,
        finding_family="pipeline_tool_execution",
        title=("npm / yarn / pnpm install with PR-context signals (LOTP review)"),
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkins shell leaf runs ``npm install`` / ``npm ci`` / "
            "``yarn install`` / ``pnpm install`` in a file that "
            "references PR-context env vars (``env.CHANGE_*``, "
            "``ghprb*``, or ``GERRIT_*``) without the "
            "``--ignore-scripts`` flag.  npm / yarn / pnpm execute "
            "``preinstall`` / ``install`` / ``postinstall`` "
            "lifecycle scripts from every ``package.json`` by "
            "default — including the one checked out from the PR "
            "branch if the job checks out that source. This file-level PR context does not prove "
            "the effective revision, job trigger, or credential scope. Adding ``--ignore-scripts`` "
            "disables the package lifecycle-script path in the supported install invocation."
        ),
        pattern=_JenkinsInstallerLeafPattern(),
        remediation=(
            "Add ``--ignore-scripts`` to every npm / yarn / pnpm\n"
            "install command in a Jenkinsfile that can run on PR\n"
            "context.  Declarative:\n\n"
            "    pipeline {\n"
            "        agent any\n"
            "        stages {\n"
            "            stage('install') {\n"
            "                steps { sh 'npm ci --ignore-scripts' }\n"
            "            }\n"
            "        }\n"
            "    }\n\n"
            "For pnpm, also set ``ignore-scripts=true`` in the\n"
            "checked-out ``.npmrc`` so the default is sticky across\n"
            "future contributors and tool versions."
        ),
        reference=("https://docs.npmjs.com/cli/v10/using-npm/scripts#ignoring-scripts"),
        test_positive=[
            # Multibranch + npm install
            (
                "pipeline {\n    agent any\n"
                "    environment {\n"
                '        PR_BRANCH = "${env.CHANGE_BRANCH}"\n'
                "    }\n    stages { stage('install') { steps {\n"
                "        sh 'npm install'\n"
                "    } } }\n}"
            ),
            # Legacy GHPRB + npm ci
            (
                "pipeline {\n    agent any\n"
                "    environment {\n"
                '        PR = "${env.ghprbPullId}"\n'
                "    }\n    stages { stage('build') { steps {\n"
                "        sh 'npm ci'\n"
                "    } } }\n}"
            ),
            # Gerrit + pnpm install
            (
                "pipeline {\n    agent any\n"
                "    environment {\n"
                '        REF = "${env.GERRIT_REFSPEC}"\n'
                "    }\n    stages { stage('install') { steps {\n"
                "        sh 'pnpm install'\n"
                "    } } }\n}"
            ),
        ],
        test_negative=[
            # --ignore-scripts present → safe
            (
                "pipeline {\n    agent any\n"
                "    environment {\n"
                '        PR_BRANCH = "${env.CHANGE_BRANCH}"\n'
                "    }\n    stages { stage('install') { steps {\n"
                "        sh 'npm ci --ignore-scripts'\n"
                "    } } }\n}"
            ),
            # No PR-context env var — not a Multibranch / PR-reachable build
            (
                "pipeline {\n    agent any\n"
                "    stages { stage('install') { steps {\n"
                "        sh 'npm install'\n"
                "    } } }\n}"
            ),
            # Comment
            "// sh 'npm install'",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "When a Jenkins job checks out untrusted package content, npm's default lifecycle "
            "scripts may run during an install command. This candidate identifies an installer "
            "shell occurrence and a separate PR-context signal; it does not establish the job's "
            "trigger, effective checkout, agent persistence, or available credentials. Review "
            "the job configuration and the install's enclosing scope."
        ),
        incidents=["Ultralytics (Dec 2024, GH analog)"],
    ),
]
