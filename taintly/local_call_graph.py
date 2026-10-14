"""Invocation-sensitive input flows through local workflow and action calls.

Only structural executable slots create edges. Each invocation carries its own
inputs and originating event; different callers cannot donate inputs to one
another. This proves configured byte flow, not runtime execution or authority.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field

from .authority_context import _Index
from .call_authority import AuthorityInvocation, CallAuthorityEvidence, CallAuthorityResolver
from .eventguard import event_guard_verdict
from .parsers.gha_expr import ExprSyntaxError, iter_expression_bodies, result_provenance_paths
from .parsers.shell_words import shell_words_with_expansion
from .parsers.structural import Event, EventKind, triggers, walk_workflow
from .path_safety import is_within_repo
from .taint import (
    _TAINTED_IN_EXPR_RE,
    _shell_quote_context_at,
    _sink_is_bare_assignment,
    analyze_job_outputs,
)
from .taint import analyze as analyze_taint
from .workflow_corpus import CorpusEvidence, WorkflowCorpus

_MAX_FILES = 512
_MAX_FRAMES = 4096
_MAX_DEPTH = 20
_MAX_EVENTS = 20_000
_MAX_BYTES = 400_000
_MAX_FLOWS = 8192
_MAX_BINDINGS = 16_384
_INPUT = re.compile(r"inputs\.([a-z_][a-z0-9_-]*)\Z", re.I)
_NEEDS = re.compile(r"needs\.([a-z_][a-z0-9_-]*)\.outputs\.([a-z_][a-z0-9_-]*)\Z", re.I)
_STEP_OUTPUT = re.compile(r"steps\.([a-z_][a-z0-9_-]*)\.outputs\.([a-z_][a-z0-9_-]*)\Z", re.I)
_FALLBACK_PATH = re.compile(r"(?:inputs\.[\w-]+|needs(?:\.[\w-]+)+|github(?:\.[\w-]+)+)", re.I)


class LocalGraphLimitError(ValueError):
    """The configured graph could not be completely evaluated within bounds."""


@dataclass(frozen=True)
class LocalFlow:
    caller: str
    caller_line: int
    callee: str
    input: str
    source_expr: str
    sink_line: int
    sink_snippet: str
    hop_chain: tuple[tuple[str, int, str], ...]
    callee_kind: str = "workflow"
    source_file: str = ""
    source_line: int = 0
    argument_lines: tuple[tuple[str, int, str], ...] = ()
    review_notes: tuple[str, ...] = ()
    event: str = ""
    propagation_lines: tuple[tuple[str, int, str, str], ...] = ()
    authority: CallAuthorityEvidence = field(default_factory=CallAuthorityEvidence)


def flow_evidence(flow: LocalFlow, snippet: str) -> CorpusEvidence:
    """Project configured byte flow without inventing runtime authority."""
    notes = (
        f"Originating event: {flow.event}; source: {flow.source_file}:{flow.source_line} ({flow.source_expr}).",
        *(f"Input '{name}' supplied at {file}:{line}." for file, line, name in flow.argument_lines),
        *(
            f"Propagation {kind} at {file}:{line}: {detail}."
            for file, line, kind, detail in flow.propagation_lines
        ),
        f"Configured sink: {flow.callee}:{flow.sink_line}.",
        *flow.authority.context_notes(),
        *flow.review_notes,
    )
    review = bool(flow.review_notes)
    title = (
        "Configured cross-file input flow needs execution-context review"
        if review
        else "Attacker-controlled input reaches shell source through local calls"
    )
    remediation = (
        f"Review the value supplied at {flow.source_file}:{flow.source_line}. "
        f"At {flow.callee}:{flow.sink_line}, bind input '{flow.input}' to an environment variable "
        "and consume it as quoted data; avoid template substitution into shell source or eval/shell -c reinterpretation. "
        "Verify the originating event, call guards, runtime file revision and effective token/secret grants before assessing impact."
    )
    return CorpusEvidence(
        flow.caller,
        flow.caller_line,
        snippet,
        title,
        remediation,
        review,
        notes,
        ("configured-input-flow", "call-authority-" + flow.authority.state),
        "; ".join(flow.review_notes),
    )


@dataclass(frozen=True)
class _Value:
    source: str
    file: str
    line: int
    hops: tuple[tuple[str, int, str], ...]
    arguments: tuple[tuple[str, int, str], ...]
    notes: tuple[str, ...] = ()
    propagation: tuple[tuple[str, int, str, str], ...] = ()


@dataclass(frozen=True)
class _Sink:
    name: str
    line: int
    snippet: str
    owner: tuple[object, ...]
    notes: tuple[str, ...] = ()
    propagation: tuple[tuple[str, int, str, str], ...] = ()


def _paths(value: str) -> tuple[list[str], tuple[str, ...]]:
    paths: dict[str, None] = {}
    notes: list[str] = []
    for body in iter_expression_bodies(value):
        if len(body) > 8192:
            paths.update(dict.fromkeys(m.group().lower() for m in _FALLBACK_PATH.finditer(body)))
            notes.append("Expression result provenance exceeds the profile limit.")
            continue
        try:
            paths.update(dict.fromkeys(result_provenance_paths(body)))
        except (ExprSyntaxError, RecursionError):
            paths.update(dict.fromkeys(m.group().lower() for m in _FALLBACK_PATH.finditer(body)))
            notes.append("Expression result provenance is unresolved.")
    if "${{" in value and not list(iter_expression_bodies(value)):
        notes.append("Unterminated expression is unresolved.")
        paths.update(dict.fromkeys(m.group().lower() for m in _FALLBACK_PATH.finditer(value)))
    return list(paths), tuple(notes)


def _available(source: str, event: str) -> bool | None:
    """Known event-object availability, independent of token/secret policy."""
    if event == "?":
        return None
    if source == "github.head_ref":
        return event in {"pull_request", "pull_request_target"}
    groups = {
        "pull_request": {
            "pull_request",
            "pull_request_target",
            "pull_request_review",
            "pull_request_review_comment",
        },
        "issue": {"issues", "issue_comment"},
        "comment": {"issue_comment", "pull_request_review_comment", "discussion_comment"},
        "review": {"pull_request_review"},
        "discussion": {"discussion", "discussion_comment"},
        "head_commit": {"push"},
        "commits": {"push"},
        "pages": {"gollum"},
        "workflow_run": {"workflow_run"},
    }
    parts = source.split(".")
    if len(parts) >= 3 and parts[:2] == ["github", "event"]:
        supported = groups.get(parts[2])
        return event in supported if supported else None
    return None


def _interpreter_source(
    command: str, args: list[tuple[str, bool, bool]]
) -> tuple[bool | None, bool]:
    """Bound source operands in a declared argv profile; stop at code/filename."""
    shells = {"bash", "sh", "dash", "zsh", "ksh"}
    noexec = False
    stdin_mode = False
    index = 0
    while index < len(args):
        arg, expanded, _ = args[index]
        if expanded:
            return None, False  # Unknown option/filename, not established code bytes.
        if arg == "--":
            index += 1
            break
        if command in shells:
            if arg in {"-o", "+o"}:
                if index + 1 >= len(args) or args[index + 1][1]:
                    return None, False
                option = args[index + 1][0]
                if option == "noexec":
                    noexec = arg == "-o"
                elif command != "bash" or option not in {"errexit", "nounset", "pipefail"}:
                    return None, False
                index += 2
                continue
            if command == "bash" and arg in {"--noprofile", "--norc", "--posix", "--login"}:
                index += 1
                continue
            if re.fullmatch(r"[-+][A-Za-z]+", arg):
                supported = "abefhkmnptuvxBCEHPTlrsc" if command == "bash" else "aefnuvxsc"
                if any(char not in supported for char in arg[1:]):
                    return None, False
                if "n" in arg:
                    noexec = arg.startswith("-")
                stdin_mode |= "s" in arg
                if "c" in arg:
                    if arg.startswith("+") or index + 1 >= len(args):
                        return None, False
                    return False if noexec else args[index + 1][1], False
                index += 1
                continue
        else:
            code_flags = {"-c"} if command in {"python", "python3"} else {"-e", "--eval"}
            if command == "node" and arg in {"-c", "--check"}:
                return False, False
            if arg in code_flags:
                return (args[index + 1][1], False) if index + 1 < len(args) else (None, False)
            supported_flags = (
                {"-I", "-S", "-E", "-B", "-u"} if command in {"python", "python3"} else {"-w"}
            )
            if arg in supported_flags:
                index += 1
                continue
        if arg.startswith(("-", "+")):
            return None, False
        break
    if noexec:
        return False, False
    if command in shells and (stdin_mode or index == len(args)):
        return False, True
    if index < len(args) and args[index][1]:
        return None, False
    return False, False


def _shell_sink(snippet: str, variable: str) -> bool | None:
    """True: bound code source; False: inert data; None: unsupported semantics."""
    line = re.sub(r"^\s*(?:-\s+)?run:\s*", "", snippet)
    refs, unknown = _paths(line)
    source_refs = {f"env.{variable.lower()}"}
    if "." in variable:
        step, output = variable.split(".", 1)
        source_refs.add(f"steps.{step.lower()}.outputs.{output.lower()}")
    if source_refs.intersection(refs):
        return None if unknown else True  # GitHub renders bytes before shell parsing.
    if any(token in line for token in ("\n", "$(", "`", "<<")):
        return None
    try:
        shlex.split(line, posix=True)  # Malformed quotes cannot establish a proof.
    except ValueError:
        return None
    pattern = re.compile(rf"\$\{{?{re.escape(variable)}(?![A-Za-z0-9_])\}}?")
    words = shell_words_with_expansion(line, pattern)
    groups: list[tuple[list[tuple[str, bool, bool]], str]] = []
    current: list[tuple[str, bool, bool]] = []
    for word in words:
        if word[2]:
            groups.append((current, word[0]))
            current = []
        else:
            current.append(word)
    groups.append((current, ""))
    stdin_tainted: bool | None = False
    expanded_any = False
    binding_live: bool | None = True
    shells = {"bash", "sh", "dash", "zsh", "ksh"}
    redirected = any(
        _shell_quote_context_at(line, m.start()) == "unquoted"
        and (len(line[: m.start()]) - len(line[: m.start()].rstrip("\\"))) % 2 == 0
        for m in re.finditer(r"[<>]", line)
    )
    for group, separator in groups:
        assignments = group[1:] if group and group[0][0] == "export" else group
        if assignments and all(re.match(r"[A-Za-z_]\w*=", word) for word, _, _ in assignments):
            for assignment_text, expanded, _ in assignments:
                name, value = assignment_text.split("=", 1)
                if name == variable:
                    binding_live = binding_live if expanded else (None if "$" in value else False)
            stdin_tainted = False
            continue
        if any(
            word in {"if", "then", "else", "elif", "do", "while", "for"} for word, _, _ in group
        ):
            return None  # Shell control flow requires a separate execution proof.
        while group and (
            group[0][0] in {"command", "builtin", "exec"} or re.match(r"[A-Za-z_]\w*=", group[0][0])
        ):
            group = group[1:]
        if group and group[0][0] == "env":
            group = group[1:]
            while group and (
                group[0][0] in {"--", "-i", "--ignore-environment"}
                or re.match(r"[A-Za-z_]\w*=", group[0][0])
            ):
                group = group[1:]
            if group and group[0][0].startswith("-"):
                return None
        if not group:
            stdin_tainted = False
            continue
        command, expanded, _ = group[0]
        args = group[1:]
        carries = any(item[1] for item in args)
        if binding_live is False:
            carries = expanded = False
        elif binding_live is None and (carries or expanded):
            return None
        expanded_any |= expanded or carries
        if expanded:
            return True  # Even a quoted variable in command position chooses code.
        if command == "eval" and carries:
            return True
        if command in shells | {"python", "python3", "node", "perl", "ruby"}:
            bound_args = (
                args if binding_live is not False else [(arg, False, op) for arg, _, op in args]
            )
            source, stdin_mode = _interpreter_source(command, bound_args)
            if source is not False:
                return source
            if stdin_mode and stdin_tainted is not False:
                return stdin_tainted
        # Plain cat is a byte-preserving stdin relay; other pipeline transforms
        # remain unknown instead of disappearing as safely quoted arguments.
        if separator != "|":
            stdin_tainted = False
        elif redirected:
            stdin_tainted = None if carries or stdin_tainted is not False else False
        elif command in {"printf", "echo"} and carries:
            stdin_tainted = True
        elif command == "cat" and not args:
            pass
        elif stdin_tainted is not False or carries:
            stdin_tainted = None
        else:
            stdin_tainted = False
    if not expanded_any:
        return False
    if _sink_is_bare_assignment(line, variable):
        return False
    matches = [
        m for m in pattern.finditer(line) if _shell_quote_context_at(line, m.start()) != "single"
    ]
    if matches and all(_shell_quote_context_at(line, m.start()) == "double" for m in matches):
        return False
    return None


@dataclass
class _Document:
    file: str
    content: str
    kind: str
    leaves: dict[tuple[object, ...], Event] = field(default_factory=dict)
    keys: set[tuple[object, ...]] = field(default_factory=set)
    key_lines: dict[tuple[object, ...], int] = field(default_factory=dict)
    notes: tuple[str, ...] = ()
    events: list[Event] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.content) > _MAX_BYTES:
            raise LocalGraphLimitError(f"Local call graph file size limit at {self.file}")
        ambiguous = False
        for count, item in enumerate(
            walk_workflow(
                self.file, content=self.content, include_keys=True, include_merge_origins=True
            )
        ):
            if count >= _MAX_EVENTS:
                raise LocalGraphLimitError(
                    f"Local call graph structural event limit at {self.file}"
                )
            if item.kind in {EventKind.ERROR, EventKind.CUTOFF}:
                raise LocalGraphLimitError(
                    f"Local call graph structural coverage incomplete at {self.file}:{item.line}"
                )
            if item.merge_origins:
                ambiguous = True
            self.events.append(item)
            if item.kind == EventKind.MAP_KEY:
                if item.path in self.keys:
                    ambiguous = True
                self.keys.add(item.path)
                self.key_lines[item.path] = item.line
            elif item.kind == EventKind.LEAF_SCALAR:
                if item.path in self.leaves:
                    ambiguous = True
                self.leaves[item.path] = item
        if ambiguous:
            self.notes = ("Structural ownership or merge coverage is unresolved.",)

    def value(self, path: tuple[object, ...]) -> str | None:
        leaf = self.leaves.get(path)
        return leaf.value if leaf else None

    def owner(self, path: tuple[object, ...]) -> tuple[object, ...] | None:
        if self.kind == "workflow" and len(path) == 3 and path[0] == "jobs":
            return path[:2]
        if (
            self.kind == "workflow"
            and len(path) == 5
            and path[0] == "jobs"
            and path[2] == "steps"
            and isinstance(path[3], int)
        ):
            return path[:4]
        if (
            self.kind == "action"
            and len(path) == 4
            and path[:2] == ("runs", "steps")
            and isinstance(path[2], int)
        ):
            return path[:3]
        return None

    def guard(self, owner: tuple[object, ...], event: str) -> tuple[bool, tuple[str, ...]]:
        scopes = [owner]
        if owner[0] == "jobs" and len(owner) == 4:
            scopes.insert(0, owner[:2])
        notes = list(self.notes)
        for scope in scopes:
            result = event_guard_verdict(self.value(scope + ("if",)), event)
            if result is False:
                return False, ()
            if result is None:
                notes.append(
                    f"Guard at {self.file}:{self.leaves[scope + ('if',)].line} needs runtime evaluation."
                )
        return True, tuple(notes)

    def provenance_guards(self, lines: list[int], event: str) -> tuple[bool, tuple[str, ...]]:
        """Validate the owners of every source, bridge and sink in a proof."""
        notes: list[str] = []
        owners: set[tuple[object, ...]] = set()
        for line in lines:
            leaves = [
                (path, leaf)
                for path, leaf in self.leaves.items()
                if leaf.line == line or any(n == line for n, _ in leaf.block_lines or ())
            ]
            if not leaves:
                notes.append(f"Propagation owner at {self.file}:{line} is unresolved.")
            for path, _leaf in leaves:
                if path[:1] == ("jobs",) and len(path) >= 2:
                    owner = path[:4] if len(path) >= 4 and path[2] == "steps" else path[:2]
                elif path[:2] == ("runs", "steps") and len(path) >= 3:
                    owner = path[:3]
                else:
                    continue
                owners.add(owner)
        for owner in sorted(owners, key=str):
            allowed, guards = self.guard(owner, event)
            if not allowed:
                return False, ()
            notes.extend(guards)
        return True, tuple(dict.fromkeys(notes))

    def input_contract(self, name: str) -> tuple[bool, tuple[str, ...]]:
        """Only declared string workflow inputs establish arbitrary-byte flow."""
        if self.kind == "action":
            return True, ()
        prefix = ("on", "workflow_call", "inputs", name)
        declared = any(path[: len(prefix)] == prefix for path in self.keys | self.leaves.keys())
        declared_type = self.value(prefix + ("type",))
        if declared_type in {"boolean", "number"} and not self.notes:
            return False, ()
        if declared_type == "string" and not self.notes:
            return True, ()
        detail = "undeclared" if not declared else "missing or unresolved type"
        return True, (
            f"Input '{name}' in {self.file} has an {detail} workflow-call contract; execution is unresolved.",
        )

    def calls(self):
        for path, leaf in self.leaves.items():
            if path[-1] != "uses" or (owner := self.owner(path)) is None:
                continue
            value = leaf.value or ""
            if not value.startswith("./"):
                continue
            kind = "workflow" if len(owner) == 2 and owner[0] == "jobs" else "action"
            args = {
                str(p[-1]).lower(): e for p, e in self.leaves.items() if p[:-1] == owner + ("with",)
            }
            yield owner, leaf, kind, args

    def needs(self, consumer: str, producer: str) -> bool:
        """Only explicit direct dependencies supply the needs context."""
        path = ("jobs", consumer, "needs")
        if self.value(path) == producer:
            return True
        return any(
            p[:-1] == path and isinstance(p[-1], int) and e.value == producer
            for p, e in self.leaves.items()
        )

    def output_route(self, ref: str, owner: tuple[object, ...], event: str):
        """Validate a symbolic solver witness in this invocation's context.

        The solver deliberately includes influence-only facts. Reject boolean
        results and unavailable contracts; retain uncertain writers explicitly
        for review instead of promoting them to configured byte-flow proofs.
        """
        match = _NEEDS.fullmatch(ref)
        if self.kind != "workflow" or not match or owner[:1] != ("jobs",):
            return None
        producer, output = match.groups()
        if producer == owner[1] or not self.needs(str(owner[1]), producer):
            return None
        facts = analyze_job_outputs(self.content, self.content.splitlines())
        bindings = {(b.job, b.name): b for b in facts.bindings}
        binding = bindings.get((producer, output))
        if binding is None:
            return None
        notes = list(self.notes)
        visited: set[tuple[str, str]] = set()

        def validate(job: str, name: str) -> bool:
            key = (job, name)
            if key in visited:
                raise LocalGraphLimitError("Cyclic job-output provenance; coverage incomplete")
            visited.add(key)
            if len(visited) > _MAX_DEPTH:
                raise LocalGraphLimitError("Job-output depth limit; coverage incomplete")
            current = bindings.get(key)
            if current is None:
                return False
            job_path = ("jobs", job)
            if job_path not in self.keys:
                return False
            refs, unknown = _paths(current.declaration)
            notes.extend(unknown)
            if not refs and not unknown:
                return False
            if job_path + ("uses",) in self.keys or any(
                p[:4] == job_path + ("strategy", "matrix") for p in self.keys
            ):
                notes.append(
                    f"Output producer {job} uses a reusable workflow or matrix; writer selection is unresolved."
                )
            for path in refs:
                if upstream := _NEEDS.fullmatch(path):
                    parent, parent_name = upstream.groups()
                    if (
                        parent == job
                        or not self.needs(job, parent)
                        or not validate(parent, parent_name)
                    ):
                        return False
                elif step := _STEP_OUTPUT.fullmatch(path):
                    step_id, output_name = step.groups()
                    owners = [
                        p[:-1]
                        for p, e in self.leaves.items()
                        if p[:3] == job_path + ("steps",) and p[-1] == "id" and e.value == step_id
                    ]
                    if not owners:
                        return False
                    writers = [
                        w
                        for w in facts.writers
                        if w.job == job and w.step_id == step_id and w.name == output_name
                    ]
                    if len(owners) != 1 or len(writers) != 1:
                        notes.append(
                            f"Output {job}.{step_id}.{output_name} has multiple or unsupported writers; binding state is unresolved."
                        )
                    for step_owner in owners:
                        run = self.leaves.get(step_owner + ("run",))
                        if run is None:
                            notes.append(
                                f"Output writer {job}.{step_id} is an action with an unresolved output contract."
                            )
                            continue
                        shell = (
                            self.value(step_owner + ("shell",))
                            or self.value(job_path + ("defaults", "run", "shell"))
                            or self.value(("defaults", "run", "shell"))
                        )
                        runner = self.value(job_path + ("runs-on",)) or ""
                        if shell not in {"bash", "sh"} and not (
                            shell is None and runner.startswith(("ubuntu-", "macos-"))
                        ):
                            notes.append(
                                f"Output writer shell at {self.file}:{run.line} is unresolved."
                            )
                        text = run.value or ""
                        for statement in text.splitlines():
                            words = shell_words_with_expansion(
                                statement, re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[^}]+\})")
                            )
                            if words and (words[0][0] != "echo" or any(sep for _, _, sep in words)):
                                notes.append(
                                    f"Output writer script at {self.file}:{run.line} contains commands outside the simple echo profile; binding state is unresolved."
                                )
                        step_writers = [
                            w
                            for w in facts.writers
                            if w.job == job and w.step_index == step_owner[-1]
                        ]
                        target_mentions = len(re.findall(r"GITHUB_OUTPUT|::set-output\b", text))
                        if target_mentions != len(step_writers):
                            notes.append(
                                f"Output writer script at {self.file}:{run.line} has unmodeled output mutations; binding state is unresolved."
                            )
                        if re.search(
                            r"(?:^|[;\n])\s*(?:if|for|while|until|case|function)\b|&&|\|\||\w+\s*\(\)\s*\{",
                            text,
                        ):
                            notes.append(
                                f"Output writer command control at {self.file}:{run.line} requires review."
                            )
                        if re.search(r"\$\(|`|\$\{[A-Za-z_][A-Za-z0-9_]*[:/%#?+-]", text):
                            notes.append(
                                f"Output writer transformation at {self.file}:{run.line} requires review."
                            )
                        for writer in writers:
                            statement = next(
                                (
                                    t
                                    for n, t in run.block_lines or ((run.line, text),)
                                    if n == writer.line
                                ),
                                "",
                            )
                            simple_write = (
                                r"echo\s+(?P<quote>['\"]?)"
                                + re.escape(writer.name + "=" + writer.value)
                                + r"(?P=quote)\s*>>\s*(?P<target_quote>\"?)\$(?:GITHUB_OUTPUT|\{GITHUB_OUTPUT\})(?P=target_quote)\s*(?:#.*)?"
                            )
                            if not re.fullmatch(simple_write, statement.strip()):
                                notes.append(
                                    f"Output write at {self.file}:{writer.line} is outside the direct echo/redirect profile; exact writer execution is unresolved."
                                )
                            writer_refs, writer_unknown = _paths(writer.value)
                            notes.extend(writer_unknown)
                            if (
                                "${{" in writer.value
                                and not writer_refs
                                and not writer_unknown
                                and not re.search(r"\$(?:[A-Za-z_]|\{[A-Za-z_])", writer.value)
                            ):
                                return False
                            prior = "\n".join(
                                t
                                for n, t in run.block_lines or ((run.line, text),)
                                if n <= writer.line
                            )
                            if re.search(
                                r"(?:^|[;\s])(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=", prior
                            ):
                                notes.append(
                                    f"Shell-local assignments before output write at {self.file}:{writer.line} require binding-state review."
                                )
                elif path != current.source_expr.lower() and not path.startswith("env."):
                    notes.append(f"Output expression {path} requires value-provenance review.")
            visited.remove(key)
            return True

        if not validate(producer, output):
            return None
        # Every expression-bearing source/bridge must carry result values,
        # rather than merely mention a source in a comparison or predicate.
        source_found = False
        for hop in binding.hops:
            line = hop.line
            if hop.kind == "step_output":
                # Values are checked above against the exact output write;
                # another expression in this run scalar cannot donate bytes.
                leaves = []
                for writer in facts.writers:
                    if writer.line == line and f"{writer.step_id}.{writer.name}" == hop.name:
                        writer_refs, _ = _paths(writer.value)
                        if binding.source_expr.lower() in writer_refs:
                            source_found = True
                continue
            leaves = [
                e
                for p, e in self.leaves.items()
                if e.line == line
                and (
                    (
                        hop.kind in {"env_static", "env_indirect"}
                        and p[-1] == hop.name
                        and "env" in p
                    )
                    or (
                        hop.kind == "job_output"
                        and len(p) == 4
                        and p[:1] == ("jobs",)
                        and p[2] == "outputs"
                        and f"{p[1]}.{p[3]}" == hop.name
                    )
                )
            ]
            if not leaves and hop.kind not in {"env_static", "env_indirect", "job_output"}:
                notes.append(
                    f"Propagation {hop.kind} at {self.file}:{line} requires value-state review."
                )
            for leaf in leaves:
                value = leaf.value or ""
                refs, unknown = _paths(value)
                notes.extend(unknown)
                if line == binding.source_line and binding.source_expr.lower() in refs:
                    source_found = True
                if "${{" in value and not refs and not unknown:
                    return None
        if not source_found:
            notes.append(
                f"Source result provenance at {self.file}:{binding.source_line} is unresolved."
            )
        allowed, guards = self.provenance_guards(
            [binding.source_line, *(hop.line for hop in binding.hops)], event
        )
        if not allowed:
            return None
        notes.extend(guards)
        if any(
            re.search(r"\b(?:BASH_ENV|ENV|BASH_FUNC_[A-Za-z0-9_]*)\b", str(p[-1]))
            for p in self.leaves
            if "env" in p
        ):
            notes.append(
                "Shell startup environment may alter output writers; execution requires review."
            )
        propagation = tuple((self.file, hop.line, hop.kind, hop.detail) for hop in binding.hops)
        return binding, tuple(dict.fromkeys(notes)), propagation

    def runs(self):
        for path, leaf in self.leaves.items():
            if path[-1] == "run" and (owner := self.owner(path)) is not None and len(owner) > 2:
                yield owner, leaf

    def run_lines(self) -> dict[int, tuple[tuple[object, ...], Event]]:
        result = {}
        for owner, leaf in self.runs():
            result[leaf.line] = (owner, leaf)
            for line, _ in leaf.block_lines or ():
                result[line] = (owner, leaf)
        return result

    def taint_view(self) -> tuple[str, int]:
        """Reuse workflow taint on an owned composite body with line mapping."""
        if self.kind == "workflow":
            return self.content, 0
        start = self.key_lines.get(("runs", "steps"))
        if start is None:
            return "", 0
        end = start
        for path, leaf in self.leaves.items():
            if path[:2] == ("runs", "steps"):
                end = max(end, leaf.line, *(n for n, _ in leaf.block_lines or ()))
        lines = self.content.splitlines()
        body = "\n".join("  " + text for text in lines[start - 1 : end])
        return (
            "on: workflow_call\njobs:\n  composite:\n    runs-on: ubuntu-latest\n" + body + "\n",
            start - 5,
        )


def _resolve(root: str, ref: str, kind: str) -> str | None:
    rel = ref[2:]
    if kind == "action":
        if rel == "":
            parts = []
        else:
            if rel.endswith("/"):
                rel = rel[:-1]
            parts = rel.split("/")
    else:
        parts = rel.split("/")
    if any(p in {"", ".", ".."} for p in parts) or any(c in rel for c in "\\:$*?["):
        return None
    if kind == "workflow" and (
        len(parts) != 3
        or parts[:2] != [".github", "workflows"]
        or not rel.endswith((".yml", ".yaml"))
    ):
        return None
    base = os.path.join(root, *parts)
    candidates = (
        [base]
        if kind == "workflow"
        else [os.path.join(base, "action.yml"), os.path.join(base, "action.yaml")]
    )
    for path in candidates:
        if is_within_repo(root, path) and os.path.isfile(path):
            normalized = os.path.normpath(path)
            return normalized.replace(os.sep, "/") if kind == "action" else normalized
    if all(is_within_repo(root, path) for path in candidates):
        raise LocalGraphLimitError(
            f"Referenced local {kind} {ref!r} is unavailable; coverage incomplete"
        )
    return None


def find_local_flows(corpus: WorkflowCorpus) -> list[LocalFlow]:
    """Follow actual local invocations with isolated input bindings and traces."""
    root = corpus.repo_path
    if not root:
        return []
    docs: dict[str, _Document] = {}
    for wf in corpus.all():
        if is_within_repo(root, wf.filepath):
            docs[os.path.normcase(os.path.abspath(wf.filepath))] = _Document(
                wf.filepath, wf.content, "workflow"
            )
    if len(docs) > _MAX_FILES:
        raise LocalGraphLimitError("Local call graph file limit")
    flows: list[LocalFlow] = []
    frames = 0
    binding_count = 0
    authority_indexes: dict[str, _Index] = {}

    def authority_index(file: str) -> _Index:
        key = os.path.normcase(os.path.abspath(file))
        if key not in authority_indexes:
            document = docs[key]
            authority_indexes[key] = _Index(document.content, events=document.events)
        return authority_indexes[key]

    authority_resolver = CallAuthorityResolver(authority_index)

    def load(path: str, kind: str) -> _Document:
        key = os.path.normcase(os.path.abspath(path))
        if key not in docs:
            if len(docs) >= _MAX_FILES:
                raise LocalGraphLimitError("Local call graph file limit")
            with open(path, encoding="utf-8", errors="replace") as stream:
                content = stream.read(_MAX_BYTES + 1)
            if len(content) > _MAX_BYTES:
                raise LocalGraphLimitError(f"Local call graph file size limit at {path}")
            docs[key] = _Document(path, content, kind)
        return docs[key]

    def visit(
        doc: _Document,
        event: str,
        inputs: dict[str, list[_Value]],
        trail: tuple[tuple[str, int, str], ...],
        seen: tuple[str, ...],
        inherited: tuple[str, ...],
        authority: AuthorityInvocation,
    ) -> None:
        nonlocal frames, binding_count
        frames += 1
        if frames > _MAX_FRAMES or len(seen) > _MAX_DEPTH:
            raise LocalGraphLimitError(
                "Local call graph invocation/depth limit; coverage incomplete"
            )
        notes = inherited + doc.notes
        sites = doc.run_lines()
        candidates: list[_Sink] = []
        # Direct template substitution happens before shell parsing, including
        # quoted strings and heredocs. Boolean/literal expression results do not
        # carry the input's bytes.
        for owner, leaf in doc.runs():
            emitted = set()
            for line, text in leaf.block_lines or ((leaf.line, leaf.value or ""),):
                refs, unknown = _paths(text)
                for ref in refs:
                    if match := _INPUT.fullmatch(ref):
                        candidates.append(_Sink(match[1], line, text.strip(), owner, unknown))
                        emitted.add(match[1])
            refs, unknown = _paths(leaf.value or "")
            for ref in refs:
                if (match := _INPUT.fullmatch(ref)) and match[1] not in emitted:
                    line = next(
                        (n for n, text in leaf.block_lines or () if "${{" in text), leaf.line
                    )
                    candidates.append(
                        _Sink(match[1], line, (leaf.value or "").strip(), owner, unknown)
                    )
        # Reuse existing workflow env/output propagation; its generic candidates
        # need sink and source validation before becoming cross-file evidence.
        if inputs:
            view, offset = doc.taint_view()
            for path in analyze_taint(view, view.splitlines()):
                sink_line, source_line = path.sink_line + offset, path.source_line + offset
                match = _INPUT.fullmatch(path.source_expr)
                if not match or path.sink_kind != "run" or sink_line not in sites:
                    continue
                owner, leaf = sites[sink_line]
                source_events = [
                    e
                    for e in doc.leaves.values()
                    if e.line == source_line
                    or any(n == source_line for n, _ in e.block_lines or ())
                ]
                if not any(
                    path.source_expr.lower() in _paths(e.value or "")[0] for e in source_events
                ):
                    continue
                allowed, propagation_notes = doc.provenance_guards(
                    [source_line, *(hop.line + offset for hop in path.hops)], event
                )
                if not allowed:
                    continue
                snippet = path.sink_snippet
                shell = doc.value(owner + ("shell",))
                if doc.kind == "workflow":
                    shell = (
                        shell
                        or doc.value(owner[:2] + ("defaults", "run", "shell"))
                        or doc.value(("defaults", "run", "shell"))
                    )
                runner = doc.value(owner[:2] + ("runs-on",)) or ""
                posix = shell in {"bash", "sh"} or (
                    shell is None and runner.startswith(("ubuntu-", "macos-"))
                )
                verdict = _shell_sink(snippet, path.env_var) if posix else None
                prior = "\n".join(text for n, text in leaf.block_lines or () if n < sink_line)
                if verdict is not False and re.search(
                    rf"(?:^|[;\s])(?:export\s+)?{re.escape(path.env_var)}\s*=", prior
                ):
                    verdict = None
                    propagation_notes += (
                        f"Shell-local reassignment before {doc.file}:{sink_line} requires binding-state review.",
                    )
                if verdict is False:
                    continue
                extra: tuple[str, ...] = (
                    ()
                    if verdict is True
                    else (
                        "Shell argument use is observed; command reinterpretation is unresolved.",
                    )
                )
                candidates.append(
                    _Sink(
                        match[1],
                        sink_line,
                        snippet,
                        owner,
                        extra + propagation_notes,
                        tuple(
                            (doc.file, hop.line + offset, hop.kind, hop.detail) for hop in path.hops
                        ),
                    )
                )
        for sink in candidates:
            allowed, guards = doc.guard(sink.owner, event)
            if not allowed:
                continue
            impact = authority_resolver.sink(authority, doc.file, doc.kind, sink.owner, event)
            for value in inputs.get(sink.name.lower(), []):
                reasons = tuple(dict.fromkeys(value.notes + notes + guards + sink.notes))
                if impact.invocation_unresolved:
                    reasons += (
                        "Local invocation validity is unresolved; inspect the authority/contract witnesses.",
                    )
                flows.append(
                    LocalFlow(
                        value.hops[0][0],
                        value.hops[0][1],
                        doc.file,
                        sink.name,
                        value.source,
                        sink.line,
                        sink.snippet,
                        value.hops,
                        doc.kind,
                        value.file,
                        value.line,
                        value.arguments,
                        reasons,
                        event,
                        value.propagation + sink.propagation,
                        impact,
                    )
                )
                if len(flows) > _MAX_FLOWS:
                    raise LocalGraphLimitError(
                        "Local call graph finding limit; coverage incomplete"
                    )
        for owner, call, kind, args in doc.calls():
            allowed, guards = doc.guard(owner, event)
            if not allowed:
                continue
            target = _resolve(root, call.value or "", kind)
            if target is None:
                continue
            key = os.path.normcase(os.path.abspath(target))
            if key in seen:
                raise LocalGraphLimitError(
                    f"Cyclic local call at {doc.file}:{call.line}; coverage incomplete"
                )
            callee = load(target, kind)
            if kind == "action" and callee.value(("runs", "using")) not in {None, "composite"}:
                continue
            if kind == "workflow" and "workflow_call" not in triggers(callee.content):
                continue
            call_notes = notes + guards
            if kind == "action":
                call_notes += (
                    "Local action checkout revision and workspace correspondence require verification.",
                )
            bindings: dict[str, list[_Value]] = {}

            def bind(
                name: str, value: _Value, target_bindings: dict[str, list[_Value]] = bindings
            ) -> None:
                nonlocal binding_count
                binding_count += 1
                if binding_count > _MAX_BINDINGS:
                    raise LocalGraphLimitError(
                        "Local call graph binding limit; coverage incomplete"
                    )
                target_bindings.setdefault(name, []).append(value)

            for name, arg in args.items():
                accepted, contract_notes = callee.input_contract(name)
                if not accepted:
                    continue
                refs, unknown = _paths(arg.value or "")
                for ref in refs:
                    if _TAINTED_IN_EXPR_RE.fullmatch(ref):
                        available = _available(ref, event)
                        if available is False:
                            continue
                        reason = (
                            ()
                            if available is True
                            else ("Source availability for the originating event is unresolved.",)
                        )
                        hop = (doc.file, call.line, ref)
                        bind(
                            name,
                            _Value(
                                ref,
                                doc.file,
                                arg.line,
                                trail + (hop,),
                                ((doc.file, arg.line, name),),
                                call_notes + unknown + reason + contract_notes,
                            ),
                        )
                    elif match := _INPUT.fullmatch(ref):
                        for value in inputs.get(match[1].lower(), []):
                            bind(
                                name,
                                _Value(
                                    value.source,
                                    value.file,
                                    value.line,
                                    value.hops + ((doc.file, call.line, ref),),
                                    value.arguments + ((doc.file, arg.line, name),),
                                    value.notes + call_notes + unknown + contract_notes,
                                    value.propagation,
                                ),
                            )
                    elif _NEEDS.fullmatch(ref):
                        route = doc.output_route(ref, owner, event)
                        if route is None:
                            continue
                        output, output_notes, propagation = route
                        source = output.source_expr.lower()
                        source_values: list[_Value] = []
                        if _TAINTED_IN_EXPR_RE.fullmatch(source):
                            available = _available(source, event)
                            if available is False:
                                continue
                            reason = (
                                ()
                                if available is True
                                else (
                                    "Source availability for the originating event is unresolved.",
                                )
                            )
                            source_values = [
                                _Value(source, doc.file, output.source_line, trail, (), reason)
                            ]
                        elif symbolic := _INPUT.fullmatch(source):
                            source_values = inputs.get(symbolic[1].lower(), [])
                        for value in source_values:
                            bind(
                                name,
                                _Value(
                                    value.source,
                                    value.file,
                                    value.line,
                                    value.hops + ((doc.file, call.line, ref),),
                                    value.arguments + ((doc.file, arg.line, name),),
                                    value.notes
                                    + call_notes
                                    + unknown
                                    + contract_notes
                                    + output_notes,
                                    value.propagation
                                    + propagation
                                    + ((doc.file, arg.line, "needs_ref", ref),),
                                ),
                            )
            # Traverse untainted calls as well: a nested workflow/action may
            # itself forward an event context. Only reachable actions are read.
            visit(
                callee,
                event,
                bindings,
                trail + ((doc.file, call.line, "local call"),),
                seen + (key,),
                call_notes,
                authority_resolver.call(
                    authority, doc.file, doc.kind, owner, callee.file, kind, call.line
                ),
            )

    for doc in tuple(docs.values()):
        events = triggers(doc.content)
        roots = sorted(events - {"workflow_call"})
        if not events:
            roots = ["?"]
        for event in roots:
            visit(
                doc,
                event,
                {},
                (),
                (os.path.normcase(os.path.abspath(doc.file)),),
                (),
                AuthorityInvocation(),
            )
    # Direct and env propagation can describe the same sink; preserve independent
    # call sites/sources, not duplicate projections of one proof.
    unique: dict[tuple[object, ...], LocalFlow] = {}
    for flow in flows:
        key = (
            flow.callee,
            flow.sink_line,
            flow.input,
            flow.source_expr,
            flow.hop_chain,
            flow.event,
        )
        old = unique.get(key)
        if old is None or len(flow.review_notes) < len(old.review_notes):
            unique[key] = flow
    return sorted(
        unique.values(),
        key=lambda f: (f.callee, f.sink_line, f.input, f.caller, f.caller_line, f.event),
    )
