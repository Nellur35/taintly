"""Bounded evidence for how one tracked value is used by a GitHub run step.

This is a narrow classifier, not a shell interpreter. Unsupported or ambiguous
ownership and grammar stay UNKNOWN.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

from .parsers.shell_words import shell_words_with_expansion
from .taint import TaintPath, _shell_quote_context_at, _sink_is_bare_assignment

if TYPE_CHECKING:
    from .local_call_graph import _Document


class ShellUse(str, Enum):
    CODE = "code"
    DATA = "data"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class NonemptyParameterDefault:
    """A bounded ``${NAME:-literal}`` condition attached to source evidence."""

    variable: str
    fallback: str

    @property
    def note(self) -> str:
        return (
            f"{self.variable} contributes only when it is set and nonempty; "
            "otherwise the fixed fallback literal is used."
        )


@dataclass(frozen=True)
class ShellUseEvidence:
    disposition: ShellUse
    reason: str
    file: str
    source_sha256: str
    sink_line: int
    owner_path: tuple[object, ...]
    path_key: tuple[object, ...]
    command_sha256: str
    shell_basis: str
    parameter_default: NonemptyParameterDefault | None = None

    @property
    def notes(self) -> tuple[str, ...]:
        if not _valid_nonempty_parameter_default(self.parameter_default):
            return (self.reason,)
        condition = cast("NonemptyParameterDefault", self.parameter_default)
        return (self.reason, condition.note)


_SHELL_VAR = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_SHELL_WORD_VAR = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")
_STARTUP_NAMES = {"BASH_ENV", "ENV", "BASH_FUNC_"}
_PRINTF_FORMAT = re.compile(r"(?:[^%]|%(?:[0-9.-]*s))*\Z")
_PRINTF_CODE_FORMAT = re.compile(r"(?:[^%]|%s)*\Z")
_PARAMETER_DEFAULT = re.compile(
    r"\$\{(?P<variable>[A-Za-z_][A-Za-z0-9_]*):-(?P<fallback>[A-Za-z0-9_]+)\}"
)
_PARAMETER_DEFAULT_FALLBACK = re.compile(r"[A-Za-z0-9_]+\Z")


def _valid_nonempty_parameter_default(value: object) -> bool:
    return (
        isinstance(value, NonemptyParameterDefault)
        and isinstance(value.variable, str)
        and _SHELL_VAR.fullmatch(value.variable) is not None
        and isinstance(value.fallback, str)
        and _PARAMETER_DEFAULT_FALLBACK.fullmatch(value.fallback) is not None
    )


def _path_key(path: TaintPath) -> tuple[object, ...]:
    return (
        path.source_expr,
        path.source_line,
        path.env_var,
        path.kind,
        path.sink_kind,
        path.sink_line,
        path.sink_snippet,
        tuple((hop.kind, hop.line, hop.name, hop.detail) for hop in path.hops),
    )


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _make_evidence(
    disposition: ShellUse,
    reason: str,
    file: str,
    source_sha256: str,
    path: TaintPath,
    owner_path: tuple[object, ...] = (),
    command: str = "",
    shell_basis: str = "unresolved",
    parameter_default: NonemptyParameterDefault | None = None,
) -> ShellUseEvidence:
    return ShellUseEvidence(
        disposition=disposition,
        reason=reason,
        file=file,
        source_sha256=source_sha256,
        sink_line=path.sink_line,
        owner_path=owner_path,
        path_key=_path_key(path),
        command_sha256=_sha(command) if command else "",
        shell_basis=shell_basis,
        parameter_default=parameter_default,
    )


def _parameter_default_projection(
    command: str, variable: str
) -> tuple[str, NonemptyParameterDefault] | None:
    """Project one exact quoted default operand for existing bounded role checks."""
    if not _SHELL_VAR.fullmatch(variable) or not _shell_quotes_are_complete(command):
        return None
    matches = list(_PARAMETER_DEFAULT.finditer(command))
    if len(matches) != 1:
        return None
    match = matches[0]
    if (
        match.group("variable") != variable
        or _shell_quote_context_at(command, match.start()) != "double"
        or command.count("$") != 1
        or any(char in match.group("fallback") for char in "\\'\"$`{} \t\r\n")
    ):
        return None
    projected = command[: match.start()] + f"${variable}" + command[match.end() :]
    words = shell_words_with_expansion(projected, re.compile(rf"\$\{{?{re.escape(variable)}\}}?"))
    if (
        not words
        or any(separator for _, _, separator in words)
        or sum(1 for _, expanded, _ in words if expanded) != 1
        or not any(token == f"${variable}" and expanded for token, expanded, _ in words)
    ):
        return None
    if words[0][0] == "eval":
        if len(words) != 2 or words[1][0] != f"${variable}":
            return None
    elif words[0][0] == "printf":
        if len(words) < 3 or not any(
            token == f"${variable}" and expanded for token, expanded, _ in words[2:]
        ):
            return None
    else:
        return None
    return projected, NonemptyParameterDefault(variable, match.group("fallback"))


@dataclass(frozen=True)
class _StructuralProfile:
    document: _Document
    notes: tuple[str, ...]
    owners_by_line: Mapping[int, tuple[tuple[tuple[object, ...], object], ...]]


def _build_structural_profile(document: _Document) -> _StructuralProfile:
    by_line: dict[int, list[tuple[tuple[object, ...], object]]] = {}
    for owner, leaf in document.runs():
        lines = {leaf.line}
        lines.update(number for number, _ in leaf.block_lines or ())
        for line in lines:
            by_line.setdefault(line, []).append((owner, leaf))
    frozen_lines = MappingProxyType({line: tuple(items) for line, items in by_line.items()})
    return _StructuralProfile(document, tuple(document.notes), frozen_lines)


def _structural_profile(content: str, file: str, document_type: type) -> _StructuralProfile:
    # The cache is installed only by models.scan_session. Outside that boundary
    # every caller receives a fresh structural document.
    from .models import _SHELL_USE_PROFILE_CACHE

    cache = _SHELL_USE_PROFILE_CACHE.get()
    key = (content, file, id(document_type))
    if cache is not None:
        existing = cache.get(key)
        if isinstance(existing, _StructuralProfile):
            return existing
    profile = _build_structural_profile(document_type(file, content, "workflow"))
    if cache is not None:
        if len(cache) >= 4:
            cache.pop(next(iter(cache)))
        cache[key] = profile
    return profile


def _configured_shell(doc: _Document, owner: tuple[object, ...]) -> tuple[str | None, str]:
    job = owner[:2]
    candidates = (
        (owner + ("shell",), "step"),
        (job + ("defaults", "run", "shell"), "job default"),
        (("defaults", "run", "shell"), "workflow default"),
    )
    for shell_path, label in candidates:
        if shell_path not in doc.keys and shell_path not in doc.leaves:
            continue
        configured = doc.value(shell_path)
        if configured not in {"bash", "sh"}:
            return None, "unsupported or dynamic configured shell"
        return configured, f"{label} shell={configured}"

    runner = doc.value(job + ("runs-on",)) or ""
    if isinstance(runner, str) and "${{" not in runner and runner.startswith(("ubuntu-", "macos-")):
        return "bash", f"runner default inferred from {runner}"
    return None, "configured shell is unresolved"


def _has_startup_or_container_override(doc: _Document, owner: tuple[object, ...]) -> bool:
    job = owner[:2]
    if job + ("container",) in doc.keys or job + ("container",) in doc.leaves:
        return True
    scopes = {(), job, owner}
    for path in doc.leaves:
        if len(path) >= 2 and path[-2] == "env" and path[:-2] in scopes:
            name = str(path[-1]).upper()
            if name in _STARTUP_NAMES or name.startswith("BASH_FUNC_") or name == "PATH":
                return True
    return False


def _logical_command(leaf: object, line: int) -> tuple[str | None, str]:
    block_lines = getattr(leaf, "block_lines", None)
    if block_lines:
        if getattr(leaf, "value_kind", None) != "block_literal":
            return None, "folded block command mapping is unsupported"
        matching = [text for number, text in block_lines if number == line]
        if len(matching) != 1:
            return None, "literal block line does not map uniquely to sink"
        executable = [
            text for _, text in block_lines if text.strip() and not text.lstrip().startswith("#")
        ]
        if len(executable) != 1:
            return None, "multi-command literal block is unsupported"
        return matching[0], "literal block has exact single-command line mapping"
    if getattr(leaf, "line", None) != line:
        return None, "inline run line does not match sink line"
    value = getattr(leaf, "value", None)
    if not isinstance(value, str):
        return None, "run command text is unavailable"
    return value, "inline run command has exact line mapping"


def _expression_splices_path(command: str, path: TaintPath) -> bool:
    """Use parsed expression-result provenance, not substring name matching."""
    from .parsers.gha_expr import ExprSyntaxError, iter_expression_bodies, result_provenance_paths

    expected = {path.source_expr.lower()}
    identity = path.env_var.lower()
    if identity.startswith("needs.") or identity.startswith("steps."):
        expected.add(identity)
    elif "." in identity:
        step, output = identity.split(".", 1)
        expected.add(f"steps.{step}.outputs.{output}")
    elif _SHELL_VAR.fullmatch(identity):
        expected.add(f"env.{identity}")
    try:
        bodies = tuple(iter_expression_bodies(command))
        return any(expected.intersection(result_provenance_paths(body)) for body in bodies)
    except (ExprSyntaxError, RecursionError):
        return False


def _local_shell_sink(command: str, variable: str) -> bool | None:
    # Keep local_call_graph out of import-time rule loading. Reuse its bounded
    # profile only when a caller asks for occurrence classification.
    from .local_call_graph import _shell_sink

    return _shell_sink(command, variable)


def _tracked_shell_refs(command: str, variable: str) -> list[re.Match[str]]:
    if not _SHELL_VAR.fullmatch(variable):
        return []
    name = re.escape(variable)
    pattern = re.compile(rf"(?:\$\{{{name}\}}|\$(?!\{{){name}(?![A-Za-z0-9_]))")
    return [
        m
        for m in pattern.finditer(command)
        if _shell_quote_context_at(command, m.start()) != "single"
    ]


def _has_unsupported_braced_parameter_operator(command: str, variable: str) -> bool:
    if not _SHELL_VAR.fullmatch(variable):
        return False
    pattern = re.compile(rf"\$\{{{re.escape(variable)}(?![A-Za-z0-9_])(?!\}})")
    return any(
        _shell_quote_context_at(command, match.start()) != "single"
        for match in pattern.finditer(command)
    )


def _pipeline_groups(
    command: str, variable: str
) -> tuple[list[list[tuple[str, bool, bool]]], list[str]]:
    pattern = re.compile(
        rf"(?:\$\{{{re.escape(variable)}\}}|\$(?!\{{){re.escape(variable)}(?![A-Za-z0-9_]))"
    )
    groups: list[list[tuple[str, bool, bool]]] = []
    separators: list[str] = []
    current: list[tuple[str, bool, bool]] = []
    for word in shell_words_with_expansion(command, pattern):
        if word[2]:
            groups.append(current)
            separators.append(word[0])
            current = []
        else:
            current.append(word)
    groups.append(current)
    return groups, separators


def _effective_command(group: list[tuple[str, bool, bool]]) -> tuple[str, int]:
    index = 0
    while index < len(group):
        word = group[index][0]
        if word in {"command", "builtin", "exec"}:
            index += 1
            continue
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", word):
            index += 1
            continue
        if word == "env":
            index += 1
            while index < len(group) and (
                group[index][0] in {"--", "-i", "--ignore-environment"}
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", group[index][0])
            ):
                index += 1
        break
    return (group[index][0], index) if index < len(group) else ("", index)


def _printf_pipeline_profile(command: str, variable: str) -> bool | None:
    """Return a producer-role proof for a bounded printf-to-shell pipeline."""
    if not _SHELL_VAR.fullmatch(variable):
        return None
    groups, separators = _pipeline_groups(command, variable)
    shells = {"bash", "sh", "dash", "zsh", "ksh"}
    for index, group in enumerate(groups[:-1]):
        effective, command_index = _effective_command(group)
        if effective != "printf" or "|" not in separators[index]:
            continue
        producer_args = group[command_index + 1 :]
        tracked_arg_indexes = [n for n, (_, expanded, _) in enumerate(producer_args) if expanded]
        if not tracked_arg_indexes:
            continue
        pipe_end = index + 1
        while pipe_end < len(groups):
            consumer, _ = _effective_command(groups[pipe_end])
            if consumer in shells:
                break
            if pipe_end >= len(separators) or separators[pipe_end] != "|":
                break
            pipe_end += 1
        if pipe_end >= len(groups) or _effective_command(groups[pipe_end])[0] not in shells:
            continue
        # A printf wrapper or an unprofiled relay/consumer is recognized as a
        # candidate but remains unsupported by this producer-role profile.
        relays = groups[index + 1 : pipe_end]
        if (
            index != 0
            or command_index != 0
            or pipe_end != len(groups) - 1
            or separators != ["|"] * pipe_end
            or any(relay != [("cat", False, False)] for relay in relays)
        ):
            return False
        if not _shell_quotes_are_complete(command) or any(
            token in command for token in ("\n", "\r", "<", ">", "`", "$(")
        ):
            return False
        if len(group) < 3 or group[0] != ("printf", False, False):
            return False
        format_word, format_expanded, _ = group[1]
        if (
            format_expanded
            or not _literal_printf_format(command)
            or format_word.startswith("-")
            or not _PRINTF_CODE_FORMAT.fullmatch(format_word)
            or "%s" not in format_word
        ):
            return False
        expanded = [n for n, (_, has_expansion, _) in enumerate(group) if has_expansion]
        if len(expanded) != 1 or expanded[0] < 2:
            return False
        if group[expanded[0]][0] not in {f"${variable}", f"${{{variable}}}"}:
            return False
        return not any(
            has_expansion
            for downstream in groups[index + 1 :]
            for _, has_expansion, _ in downstream
        )
    return None


def _shell_quotes_are_complete(command: str) -> bool:
    quote: str | None = None
    escaped = False
    for char in command:
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
    return quote is None and not escaped


def _literal_printf_format(command: str) -> bool:
    """Mark every dollar expansion at the format slot, respecting shell quotes."""
    words = shell_words_with_expansion(command, re.compile(r"\$"))
    return (
        len(words) >= 2
        and words[0] == ("printf", False, False)
        and not words[1][1]
        and not words[1][2]
    )


def _strict_printf_data(command: str, variable: str) -> bool:
    """Accept only fixed-format printf arguments as a DATA certificate."""
    if not _shell_quotes_are_complete(command) or any(
        token in command for token in ("\n", "\r", "$(", "`", "<", ">", ";", "|", "&")
    ):
        return False
    refs = _tracked_shell_refs(command, variable)
    if len(refs) != 1:
        return False
    if _local_shell_sink(command, variable) is True:
        return False
    # Do not let another expansion or command-like construct hide in an
    # otherwise supported printf profile.
    remainder = _SHELL_WORD_VAR.sub("", command)
    if "$" in remainder:
        return False
    words = shell_words_with_expansion(command, re.compile(rf"\$\{{?{re.escape(variable)}\}}?"))
    if any(separator for _, _, separator in words) or len(words) < 3:
        return False
    if words[0][0] != "printf" or words[0][1]:
        return False
    format_word, format_expanded, _ = words[1]
    if (
        format_expanded
        or not _literal_printf_format(command)
        or format_word.startswith("-")
        or not _PRINTF_FORMAT.fullmatch(format_word)
    ):
        return False
    expanded_words = [index for index, (_, expanded, _) in enumerate(words) if expanded]
    if len(expanded_words) != 1 or expanded_words[0] < 2:
        return False
    # The sole expansion must be the tracked variable, not just any expansion
    # that happened to set the lexer flag.
    return words[expanded_words[0]][1]


def _strict_assignment_data(command: str, variable: str) -> bool:
    if (
        not _shell_quotes_are_complete(command)
        or not _SHELL_VAR.fullmatch(variable)
        or not _sink_is_bare_assignment(command, variable)
    ):
        return False
    reference = rf"(?:\$\{{{re.escape(variable)}\}}|\${re.escape(variable)})"
    match = re.fullmatch(
        rf"(?:export\s+)?(?P<target>[A-Za-z_][A-Za-z0-9_]*)=(?:{reference}|\"{reference}\")",
        command.strip(),
    )
    if match is None:
        return False
    return match.group("target").upper() not in _STARTUP_NAMES | {"PATH"}


def classify_shell_use(content: str, path: TaintPath, file: str = "") -> ShellUseEvidence:
    """Classify one analyzer path as CODE, DATA, or UNKNOWN.

    Only uniquely owned GitHub workflow ``run`` commands in a supported
    configured bash/sh profile are considered. All other surfaces remain
    UNKNOWN rather than inheriting the local-call analyzer's ``False`` result.
    """
    identity = file or "<memory>"
    source_sha = _sha(content)
    if path.sink_kind != "run":
        return _make_evidence(
            ShellUse.UNKNOWN, "non-run sink is outside this classifier", identity, source_sha, path
        )
    try:
        from .local_call_graph import _Document

        profile = _structural_profile(content, identity, _Document)
        doc = profile.document
        if profile.notes:
            return _make_evidence(
                ShellUse.UNKNOWN,
                "workflow structural ownership is unresolved",
                identity,
                source_sha,
                path,
            )
        candidates = profile.owners_by_line.get(path.sink_line, ())
    except (ValueError, OSError, RecursionError):
        return _make_evidence(
            ShellUse.UNKNOWN, "workflow structure could not be bounded", identity, source_sha, path
        )
    if len(candidates) != 1:
        return _make_evidence(
            ShellUse.UNKNOWN, "run owner is absent or ambiguous", identity, source_sha, path
        )

    owner, leaf = candidates[0]
    command, mapping_reason = _logical_command(leaf, path.sink_line)
    if command is None:
        return _make_evidence(ShellUse.UNKNOWN, mapping_reason, identity, source_sha, path, owner)
    parameter_projection = _parameter_default_projection(command, path.env_var)
    role_command, parameter_default = (
        parameter_projection if parameter_projection is not None else (command, None)
    )
    shell, basis = _configured_shell(doc, owner)
    if shell is None:
        return _make_evidence(
            ShellUse.UNKNOWN, basis, identity, source_sha, path, owner, command, basis
        )
    if _has_startup_or_container_override(doc, owner):
        return _make_evidence(
            ShellUse.UNKNOWN,
            "container, startup environment, or PATH override is present",
            identity,
            source_sha,
            path,
            owner,
            command,
            basis,
        )
    if re.search(
        r"\b(?:alias|function|command_not_found_handle)\b|\b(?:export\s+)?PATH\s*=", command
    ):
        return _make_evidence(
            ShellUse.UNKNOWN,
            "command or shell binding may be redefined",
            identity,
            source_sha,
            path,
            owner,
            command,
            basis,
        )

    if parameter_default is None and _has_unsupported_braced_parameter_operator(
        command, path.env_var
    ):
        return _make_evidence(
            ShellUse.UNKNOWN,
            "unsupported braced parameter operator is present",
            identity,
            source_sha,
            path,
            owner,
            command,
            basis,
        )

    if _expression_splices_path(role_command, path):
        return _make_evidence(
            ShellUse.CODE,
            "tracked Actions expression is spliced into shell source",
            identity,
            source_sha,
            path,
            owner,
            command,
            basis,
        )

    refs = _tracked_shell_refs(role_command, path.env_var)
    if not refs:
        return _make_evidence(
            ShellUse.UNKNOWN,
            "tracked shell reference is absent",
            identity,
            source_sha,
            path,
            owner,
            command,
            basis,
        )

    printf_pipeline = _printf_pipeline_profile(role_command, path.env_var)
    if printf_pipeline is False:
        return _make_evidence(
            ShellUse.UNKNOWN,
            "printf pipeline producer role is unsupported or unresolved",
            identity,
            source_sha,
            path,
            owner,
            command,
            basis,
        )

    verdict = _local_shell_sink(role_command, path.env_var)
    if verdict is True:
        return _make_evidence(
            ShellUse.CODE,
            "bounded argv profile places tracked value in command or code input",
            identity,
            source_sha,
            path,
            owner,
            command,
            basis,
            parameter_default,
        )
    if _strict_assignment_data(role_command, path.env_var):
        return _make_evidence(
            ShellUse.DATA,
            "tracked value is only copied by one shell assignment",
            identity,
            source_sha,
            path,
            owner,
            command,
            basis,
            parameter_default,
        )
    if _strict_printf_data(role_command, path.env_var):
        return _make_evidence(
            ShellUse.DATA,
            "tracked value is a fixed-format printf argument",
            identity,
            source_sha,
            path,
            owner,
            command,
            basis,
            parameter_default,
        )
    reason = "bounded local-call profile did not establish a supported data or code role"
    if verdict is False:
        reason = "local-call False is insufficient for a DATA certificate"
    return _make_evidence(
        ShellUse.UNKNOWN, reason, identity, source_sha, path, owner, command, basis
    )


def validate_shell_use(evidence: ShellUseEvidence, content: str, file: str, line: int) -> bool:
    """Re-derive the exact analyzer path and classification for this evidence."""
    if not isinstance(cast("object", evidence.disposition), ShellUse):
        return False
    if evidence.parameter_default is not None and not _valid_nonempty_parameter_default(
        evidence.parameter_default
    ):
        return False
    if evidence.disposition is ShellUse.UNKNOWN and not evidence.owner_path:
        return False
    if (
        evidence.file != file
        or evidence.sink_line != line
        or evidence.source_sha256 != _sha(content)
    ):
        return False
    try:
        from .taint import analyze

        paths = [
            p for p in analyze(content, content.splitlines()) if _path_key(p) == evidence.path_key
        ]
    except (ValueError, OSError, RecursionError):
        return False
    if len(paths) != 1:
        return False
    current = classify_shell_use(content, paths[0], file)
    return current == evidence
