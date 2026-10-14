"""Bounded source and shell-role evidence for GitLab shallow taint.

This is deliberately GitLab-specific.  It recognizes a small set of exact
command forms; anything outside that profile stays unresolved for review.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import cast

from taintly.gitlab_taint import TaintHop, TaintPath, _taint_backend
from taintly.gitlab_taint import analyze as analyze_gitlab_taint
from taintly.parsers.structural import Event, EventKind, walk_workflow
from taintly.parsers.structural.tokenizer import TokenKind, tokenize


class GitLabShellRole(str, Enum):
    CODE = "code"
    DATA = "data"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class GitLabShellEvidence:
    """Private occurrence witness; its reason is never published directly."""

    role: GitLabShellRole
    reason: str
    filepath: str
    content_sha256: str
    source_var: str
    source_line: int
    source_path: tuple[object, ...]
    sink_var: str
    sink_line: int
    raw_command: str
    owner_path: tuple[object, ...]
    path_identity: tuple[object, ...]

    @property
    def notes(self) -> list[str]:
        # The engine validates this evidence before it creates role notes.
        return []


@dataclass(frozen=True)
class _PathRecord:
    identity: tuple[object, ...]
    count: int
    owner: tuple[tuple[object, ...], tuple[object, ...], str] | None
    binding_reason: str | None


@dataclass(frozen=True)
class _GitLabSourceProfile:
    content_sha256: str
    filepath: str
    backend: str
    path_identities: tuple[tuple[object, ...], ...]
    records: Mapping[tuple[object, ...], _PathRecord]
    events: tuple[Event, ...]
    events_by_line: Mapping[int, tuple[Event, ...]]
    events_by_path: Mapping[tuple[object, ...], tuple[Event, ...]]
    structure_valid: bool


_PROFILE_CACHE_LIMIT = 4


_SOURCE_VALUE = re.compile(
    r"\s*(?:\$\{(?P<braced>CI_[A-Z0-9_]+)\}|\$(?P<plain>CI_[A-Z0-9_]+))\s*\Z"
)
_SINK_REF = re.compile(
    r"\$\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|\$(?P<plain>[A-Za-z_][A-Za-z0-9_]*)"
)


def _path_identity(path: TaintPath) -> tuple[object, ...]:
    return (
        path.kind,
        path.sink_kind,
        path.source_var,
        path.source_line,
        path.laundered_var,
        path.sink_line,
        path.sink_snippet,
        tuple((hop.kind, hop.line, hop.name, hop.detail) for hop in path.hops),
    )


def _unique_owner_from_profile(
    path: TaintPath,
    structure_valid: bool,
    events_by_line: Mapping[int, tuple[Event, ...]],
    events_by_path: Mapping[tuple[object, ...], tuple[Event, ...]],
) -> tuple[tuple[object, ...], tuple[object, ...], str] | None:
    if path.kind != "shallow" or path.sink_kind != "script" or len(path.hops) != 2:
        return None
    source_hop, sink_hop = path.hops
    if (
        source_hop.kind != "var_static"
        or source_hop.line != path.source_line
        or source_hop.name != path.laundered_var
        or sink_hop.kind != "sink"
        or sink_hop.line != path.sink_line
        or sink_hop.name != path.laundered_var
    ):
        return None
    if not structure_valid:
        return None

    sink_candidates = [
        event
        for event in events_by_line.get(path.sink_line, ())
        if event.kind is EventKind.LEAF_SCALAR
        and len(event.path) == 3
        and isinstance(event.path[0], str)
        and event.path[1] in {"script", "before_script", "after_script"}
        and isinstance(event.path[2], int)
        and event.value == path.sink_snippet
        and not event.merge_origins
    ]
    if len(sink_candidates) != 1:
        return None
    sink_event = sink_candidates[0]
    owner_path = sink_event.path
    job_name = owner_path[0]
    # Includes, defaults, and extends can change the effective source or
    # executable body without a unique local source-to-item mapping.
    if events_by_path.get(("include",)) or events_by_path.get(("default",)):
        return None
    if events_by_path.get((job_name, "extends")):
        return None
    source_candidates = [
        event
        for event in events_by_line.get(path.source_line, ())
        if event.kind is EventKind.LEAF_SCALAR
        and event.path[-1:] == (path.laundered_var,)
        and event.path
        in {
            ("variables", path.laundered_var),
            (job_name, "variables", path.laundered_var),
        }
        and not event.merge_origins
    ]
    if len(source_candidates) != 1:
        return None
    source_event = source_candidates[0]
    source_match = _SOURCE_VALUE.fullmatch(source_event.value or "")
    if source_match is None:
        return None
    if (source_match.group("braced") or source_match.group("plain")) != path.source_var:
        return None

    source_path = source_event.path
    if len(source_path) == 3 and source_path[0] != job_name:
        return None
    # Ensure the exact sink command carries the tracked variable reference.
    refs = [m.group("braced") or m.group("plain") for m in _SINK_REF.finditer(path.sink_snippet)]
    if path.laundered_var not in refs:
        return None
    return source_path, owner_path, path.sink_snippet


def _path_has_tracked_binding(
    events_by_path: Mapping[tuple[object, ...], tuple[Event, ...]],
    prefix: tuple[object, ...],
    name: str,
) -> bool:
    return any(
        len(path) > len(prefix) and path[: len(prefix)] == prefix and path[-1] == name
        for path in events_by_path
    )


def _binding_prefix_is_neutral(command: str, tracked_var: str) -> bool:
    text = command.strip()
    if text in {":", "true"}:
        return True
    if re.fullmatch(rf"export\s+{re.escape(tracked_var)}", text):
        return True
    role, _reason = _role_for_command(text, tracked_var)
    if role is GitLabShellRole.DATA:
        return True
    # This exact producer/interpreter form runs its assignment effects in the
    # child shell; arbitrary eval and command forms remain unresolved.
    return (
        role is GitLabShellRole.CODE
        and re.fullmatch(
            rf"\s*printf\s+'%s\\n'\s+(?:\"\$\{{{re.escape(tracked_var)}\}}\"|"
            rf"\"\${re.escape(tracked_var)}\"|\$\{{{re.escape(tracked_var)}\}}|"
            rf"\${re.escape(tracked_var)})\s*\|\s*sh\s*",
            text,
        )
        is not None
    )


def _sequence_prefix_commands(
    events_by_path: Mapping[tuple[object, ...], tuple[Event, ...]],
    prefix: tuple[object, ...],
    limit: int | None = None,
) -> tuple[str, ...] | None:
    direct = [
        event for event in events_by_path.get(prefix, ()) if event.kind is EventKind.LEAF_SCALAR
    ]
    if direct:
        return None
    indexes = sorted(
        cast("int", path[len(prefix)])
        for path in events_by_path
        if len(path) == len(prefix) + 1
        and path[: len(prefix)] == prefix
        and isinstance(path[-1], int)
        and not isinstance(path[-1], bool)
        and (limit is None or path[-1] < limit)
    )
    if not indexes:
        return ()
    if indexes != list(range(indexes[-1] + 1)):
        return None
    commands: list[str] = []
    for index in indexes:
        rows = [
            event
            for event in events_by_path.get(prefix + (index,), ())
            if event.kind is EventKind.LEAF_SCALAR
        ]
        if len(rows) != 1 or not isinstance(rows[0].value, str):
            return None
        commands.append(rows[0].value)
    return tuple(commands)


def _binding_unknown_reason(
    events_by_path: Mapping[tuple[object, ...], tuple[Event, ...]],
    source_path: tuple[object, ...],
    owner_path: tuple[object, ...],
    tracked_var: str,
) -> str | None:
    job_name, section, sink_index = owner_path
    if len(source_path) == 2 and source_path[0] == "variables":
        if events_by_path.get((job_name, "inherit")):
            return "owning job inheritance may exclude the root source binding"
        if _path_has_tracked_binding(events_by_path, ("workflow", "rules"), tracked_var) and any(
            len(path) >= 4
            and path[:2] == ("workflow", "rules")
            and "variables" in path[2:-1]
            and path[-1] == tracked_var
            for path in events_by_path
        ):
            return "workflow rule variables may replace the root source binding"

    if any(
        len(path) >= 4
        and path[:2] == (job_name, "rules")
        and "variables" in path[2:-1]
        and path[-1] == tracked_var
        for path in events_by_path
    ):
        return "owning job rules may replace the tracked binding"
    if _path_has_tracked_binding(events_by_path, (job_name, "parallel", "matrix"), tracked_var):
        return "owning job matrix may replace the tracked binding"

    prefixes: list[tuple[object, ...]] = []
    if section == "script":
        prefixes.extend(
            [
                ("before_script",),
                (job_name, "before_script"),
                (job_name, "script"),
            ]
        )
        limits: list[int | None] = [None, None, cast("int", sink_index)]
    elif section == "before_script":
        prefixes.extend([("before_script",), (job_name, "before_script")])
        limits = [None, cast("int", sink_index)]
    else:
        prefixes.extend([("after_script",), (job_name, "after_script")])
        limits = [None, cast("int", sink_index)]

    for prefix, limit in zip(prefixes, limits, strict=True):
        commands = _sequence_prefix_commands(events_by_path, prefix, limit)
        if commands is None:
            return "an earlier shell item has unresolved structure"
        if any(not _binding_prefix_is_neutral(command, tracked_var) for command in commands):
            return "an earlier shell item may replace the tracked binding"
    return None


def _build_source_profile(content: str, filepath: str, backend: str) -> _GitLabSourceProfile:
    paths = analyze_gitlab_taint(content, content.splitlines())
    identities = tuple(_path_identity(path) for path in paths)
    counts = Counter(identities)

    structure_valid = True
    try:
        tokens = tuple(tokenize(content))
        if any(
            token.kind in {TokenKind.ANCHOR, TokenKind.ALIAS, TokenKind.MERGE_KEY}
            for token in tokens
        ):
            structure_valid = False
        events = tuple(
            walk_workflow(
                filepath or ".gitlab-ci.yml",
                schema="gitlab_ci",
                content=content,
                include_keys=True,
                include_merge_origins=True,
            )
        )
    except Exception:
        events = ()
        structure_valid = False
    if any(event.kind in {EventKind.CUTOFF, EventKind.ERROR} for event in events):
        structure_valid = False

    key_counts = Counter(event.path for event in events if event.kind is EventKind.MAP_KEY)
    if any(count > 1 for count in key_counts.values()):
        structure_valid = False

    by_line: defaultdict[int, list[Event]] = defaultdict(list)
    by_path: defaultdict[tuple[object, ...], list[Event]] = defaultdict(list)
    for event in events:
        by_line[event.line].append(event)
        by_path[event.path].append(event)
    events_by_line = MappingProxyType({line: tuple(rows) for line, rows in by_line.items()})
    events_by_path = MappingProxyType({path: tuple(rows) for path, rows in by_path.items()})

    owners: dict[tuple[object, ...], tuple[tuple[object, ...], tuple[object, ...], str] | None] = {}
    for path, identity in zip(paths, identities, strict=True):
        if counts[identity] != 1:
            owners[identity] = None
        elif identity not in owners:
            owners[identity] = _unique_owner_from_profile(
                path, structure_valid, events_by_line, events_by_path
            )

    records_by_identity: dict[tuple[object, ...], _PathRecord] = {}
    for identity in counts:
        owner = owners.get(identity)
        binding_reason = None
        if owner is not None:
            source_path, owner_path, _command = owner
            binding_reason = _binding_unknown_reason(
                events_by_path, source_path, owner_path, cast("str", identity[4])
            )
        records_by_identity[identity] = _PathRecord(
            identity, counts[identity], owner, binding_reason
        )
    records = MappingProxyType(records_by_identity)
    return _GitLabSourceProfile(
        content_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        filepath=filepath,
        backend=backend,
        path_identities=identities,
        records=records,
        events=events,
        events_by_line=events_by_line,
        events_by_path=events_by_path,
        structure_valid=structure_valid,
    )


def _source_profile(content: str, filepath: str) -> _GitLabSourceProfile:
    backend = _taint_backend()
    key = (content, filepath, backend)
    from taintly.models import _GITLAB_SHELL_PROFILE_CACHE

    cache = _GITLAB_SHELL_PROFILE_CACHE.get()
    if cache is None:
        return _build_source_profile(content, filepath, backend)
    cached = cache.get(key)
    if isinstance(cached, _GitLabSourceProfile):
        return cached
    profile = _build_source_profile(content, filepath, backend)
    if len(cache) >= _PROFILE_CACHE_LIMIT:
        oldest = next(iter(cache))
        cache.pop(oldest, None)
    cache[key] = profile
    return profile


def _path_from_identity(identity: tuple[object, ...]) -> TaintPath:
    kind = cast("str", identity[0])
    sink_kind = cast("str", identity[1])
    source_var = cast("str", identity[2])
    source_line = cast("int", identity[3])
    sink_var = cast("str", identity[4])
    sink_line = cast("int", identity[5])
    snippet = cast("str", identity[6])
    hops = cast("tuple[tuple[str, int, str, str], ...]", identity[7])
    return TaintPath(
        source_var=source_var,
        source_line=source_line,
        laundered_var=sink_var,
        sink_line=sink_line,
        sink_snippet=snippet,
        kind=kind,
        hops=[TaintHop(kind=hop[0], line=hop[1], name=hop[2], detail=hop[3]) for hop in hops],
        sink_kind=sink_kind,
    )


def _profile_paths(profile: _GitLabSourceProfile) -> tuple[TaintPath, ...]:
    """Recreate ephemeral paths from the immutable source-derived profile."""
    return tuple(_path_from_identity(identity) for identity in profile.path_identities)


def _balanced_quotes(command: str) -> bool:
    quote: str | None = None
    escaped = False
    for char in command:
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
            continue
        if quote is None and char in {"'", '"'}:
            quote = char
        elif quote == char:
            quote = None
    return quote is None and not escaped


def _role_for_command(command: str, sink_var: str) -> tuple[GitLabShellRole, str]:
    if not _balanced_quotes(command) or "\n" in command or "\r" in command:
        return GitLabShellRole.UNKNOWN, "unsupported or incomplete shell quoting"
    var = re.escape(sink_var)
    operand = rf'(?:"\$(?:\{{{var}\}}|{var})"|\$(?:\{{{var}\}}|{var}))'
    if re.fullmatch(rf"\s*eval\s+{operand}\s*", command):
        return GitLabShellRole.CODE, "exact eval operand reparses the tracked value"
    fixed_printf = rf"\s*printf\s+'%s\\n'\s+{operand}"
    if re.fullmatch(fixed_printf + r"\s*", command):
        return GitLabShellRole.DATA, "fixed printf format receives the tracked value as an argument"
    if re.fullmatch(fixed_printf + r"\s*\|\s*sh\s*", command):
        return GitLabShellRole.CODE, "fixed printf output is supplied to a literal sh interpreter"
    return GitLabShellRole.UNKNOWN, "command form is outside the bounded GitLab shell profile"


def classify_gitlab_shallow_use(
    content: str, filepath: str, path: TaintPath
) -> GitLabShellEvidence:
    """Classify one exact shallow taint path, defaulting to UNKNOWN."""
    profile = _source_profile(content, filepath)
    identity = _path_identity(path)
    record = profile.records.get(identity)
    if record is None:
        return GitLabShellEvidence(
            role=GitLabShellRole.UNKNOWN,
            reason="source path is not present in the trusted analysis profile",
            filepath=filepath,
            content_sha256=profile.content_sha256,
            source_var=path.source_var,
            source_line=path.source_line,
            source_path=(),
            sink_var=path.laundered_var,
            sink_line=path.sink_line,
            raw_command=path.sink_snippet,
            owner_path=(),
            path_identity=identity,
        )
    if record.count != 1 or record.owner is None:
        return _evidence_for_identity(profile, identity, force_unknown=True)
    return _evidence_for_identity(profile, identity)


def _evidence_for_identity(
    profile: _GitLabSourceProfile,
    identity: tuple[object, ...],
    *,
    force_unknown: bool = False,
) -> GitLabShellEvidence:
    source_var = cast("str", identity[2])
    source_line = cast("int", identity[3])
    sink_var = cast("str", identity[4])
    sink_line = cast("int", identity[5])
    command = cast("str", identity[6])
    record = profile.records[identity]
    role = GitLabShellRole.UNKNOWN
    reason = "source or unique script ownership is unresolved"
    source_path: tuple[object, ...] = ()
    owner_path: tuple[object, ...] = ()
    if record.count == 1 and record.owner is not None:
        source_path, owner_path, owner_command = record.owner
        role, reason = _role_for_command(owner_command, str(sink_var))
        if record.binding_reason is not None:
            role = GitLabShellRole.UNKNOWN
            reason = record.binding_reason
    if force_unknown:
        role = GitLabShellRole.UNKNOWN
        reason = "source identity is duplicated or structural ownership is unresolved"
    return GitLabShellEvidence(
        role=role,
        reason=reason,
        filepath=profile.filepath,
        content_sha256=profile.content_sha256,
        source_var=source_var,
        source_line=source_line,
        source_path=source_path,
        sink_var=sink_var,
        sink_line=sink_line,
        raw_command=command,
        owner_path=owner_path,
        path_identity=identity,
    )


def validate_gitlab_shallow_use(evidence: object, content: str, filepath: str, line: int) -> bool:
    """Re-derive the complete path and structural ownership before use."""
    if type(evidence) is not GitLabShellEvidence:
        return False
    if (
        not isinstance(evidence.role, GitLabShellRole)
        or not isinstance(evidence.reason, str)
        or not isinstance(evidence.filepath, str)
        or not isinstance(evidence.content_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", evidence.content_sha256)
        or not isinstance(evidence.source_var, str)
        or not re.fullmatch(r"CI_[A-Z0-9_]+", evidence.source_var)
        or not isinstance(evidence.source_line, int)
        or isinstance(evidence.source_line, bool)
        or evidence.source_line < 1
        or not isinstance(evidence.source_path, tuple)
        or not isinstance(evidence.sink_var, str)
        or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", evidence.sink_var)
        or not isinstance(evidence.sink_line, int)
        or isinstance(evidence.sink_line, bool)
        or evidence.sink_line < 1
        or not isinstance(evidence.raw_command, str)
        or not isinstance(evidence.owner_path, tuple)
        or len(evidence.owner_path) != 3
        or not isinstance(evidence.owner_path[0], str)
        or not isinstance(evidence.owner_path[1], str)
        or evidence.owner_path[1] not in {"script", "before_script", "after_script"}
        or not isinstance(evidence.owner_path[2], int)
        or isinstance(evidence.owner_path[2], bool)
        or evidence.owner_path[2] < 0
        or not isinstance(evidence.path_identity, tuple)
        or len(evidence.path_identity) != 8
    ):
        return False
    if not all(
        isinstance(part, (str, int)) and not isinstance(part, bool) for part in evidence.source_path
    ):
        return False
    if not all(
        isinstance(part, (str, int)) and not isinstance(part, bool)
        for part in evidence.path_identity[:7]
    ):
        return False
    hops = evidence.path_identity[7]
    if (
        not isinstance(hops, tuple)
        or len(hops) != 2
        or any(
            not isinstance(hop, tuple)
            or len(hop) != 4
            or not isinstance(hop[0], str)
            or not isinstance(hop[1], int)
            or isinstance(hop[1], bool)
            or not isinstance(hop[2], str)
            or not isinstance(hop[3], str)
            for hop in hops
        )
    ):
        return False
    if evidence.filepath != filepath or evidence.sink_line != line:
        return False
    profile = _source_profile(content, filepath)
    if evidence.content_sha256 != profile.content_sha256:
        return False
    if evidence.path_identity not in profile.records:
        return False
    record = profile.records[evidence.path_identity]
    if record.count != 1:
        return False
    expected = _evidence_for_identity(profile, evidence.path_identity)
    return expected == evidence


def is_possible_interpreter_input(command: str, sink_var: str) -> bool:
    """Retain ambiguous tracked pipelines as review candidates."""
    if not re.search(rf"\$\{{?{re.escape(sink_var)}\}}?", command):
        return False
    return bool(re.search(r"\|\s*(?:sh|bash)(?:\s|$)", command))
