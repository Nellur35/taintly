"""GitHub Actions SEC-10 rules — Insufficient Logging and Visibility.

This module covers timeout posture and a narrow build-output retention review
lint. The latter reports a missing same-owner Actions artifact declaration; it
does not infer whether outputs are retained through another mechanism.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from taintly.models import (
    ContextPattern,
    IncompletePatternMatches,
    Platform,
    Rule,
    Severity,
)
from taintly.parsers.shell_words import shell_words_with_expansion
from taintly.parsers.structural import Event, EventKind

_MAX_ARTIFACT_EVENTS = 20_000
_BUILD_COMMANDS: dict[str, set[tuple[str, ...]]] = {
    "npm": {("build",), ("run", "build"), ("pack",)},
    "yarn": {("build",)},
    "pnpm": {("build",)},
    "go": {("build",)},
    "cargo": {("build",)},
    "mvn": {("package",), ("install",)},
    "gradle": {("build",)},
    "docker": {("build",), ("push",)},
    "make": {("build",), ("dist",), ("release",)},
}
_CONTROL_COMMANDS = frozenset(
    {
        "if",
        "then",
        "else",
        "elif",
        "fi",
        "for",
        "while",
        "until",
        "do",
        "done",
        "case",
        "esac",
        "function",
    }
)
_UPLOAD_ACTION_RE = re.compile(r"actions/upload-artifact(?:@[^\s]+)?\Z", re.IGNORECASE)
_RELEASE_ACTIONS = ("softprops/action-gh-release@", "ncipollo/release-action@")
_SHELL_VARIABLE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[^}]*\})")


@dataclass(frozen=True)
class _BuildSite:
    event: Event
    family: str
    owner: tuple[object, ...]
    line_owner: tuple[object, ...]
    line_number: int
    location_note: str | None


@dataclass(frozen=True)
class _ArtifactMatchContext:
    notes: list[str]
    owner_path: tuple[object, ...] | None
    line_owner_count: int | None


class _ArtifactMatches(list[tuple[int, str]]):
    """List-compatible matches carrying their already-built source context."""

    contexts: list[_ArtifactMatchContext]

    def __init__(self, matches: list[tuple[int, str]], contexts: list[_ArtifactMatchContext]):
        super().__init__(matches)
        self.contexts = contexts


class _IncompleteArtifactMatches(IncompletePatternMatches):
    __slots__ = ("contexts",)

    def __init__(
        self,
        matches: list[tuple[int, str]],
        *,
        reason: str,
        contexts: list[_ArtifactMatchContext],
    ) -> None:
        super().__init__(matches, reason=reason)
        self.contexts = contexts


def _artifact_owner(path: tuple[object, ...]) -> tuple[object, ...] | None:
    if len(path) >= 2 and path[0] == "jobs" and isinstance(path[1], str):
        return path[:2]
    if len(path) >= 1 and path[0] == "steps":
        return ("steps",)
    if len(path) >= 3 and path[:2] == ("runs", "steps") and isinstance(path[2], int):
        return ("runs",)
    return None


def _artifact_line_owner(path: tuple[object, ...]) -> tuple[object, ...] | None:
    if len(path) >= 4 and path[0] == "jobs" and isinstance(path[1], str):
        if path[2] == "steps" and isinstance(path[3], int):
            return path[:4]
        return path[:2]
    if len(path) >= 2 and path[0] == "steps" and isinstance(path[1], int):
        return path[:2]
    if len(path) >= 3 and path[:2] == ("runs", "steps") and isinstance(path[2], int):
        return path[:3]
    return None


def _line_owner_counts(events: list[Event]) -> dict[int, int]:
    owners_by_line: dict[int, set[tuple[object, ...]]] = {}
    for event in events:
        if event.kind is not EventKind.LEAF_SCALAR:
            continue
        owner = _artifact_line_owner(event.path)
        if owner is not None:
            owners_by_line.setdefault(event.line, set()).add(owner)
    counts: dict[int, int] = {}
    for line, owners in owners_by_line.items():
        ancestors = {owner[:depth] for owner in owners for depth in range(1, len(owner))}
        counts[line] = len(owners - ancestors)
    return counts


def _command_tokens(line: str) -> list[list[str]]:
    """Split with the shared bounded lexer, preserving real separator provenance."""

    commands: list[list[str]] = []
    current: list[str] = []
    for word, _expanded, separator in shell_words_with_expansion(line, _SHELL_VARIABLE):
        if separator:
            if current:
                commands.append(current)
                current = []
        else:
            current.append(word)
    if current:
        commands.append(current)
    return commands


def _build_family(tokens: list[str]) -> str | None:
    if not tokens:
        return None
    command = tokens[0]
    args = tuple(tokens[1:3])
    for family, forms in _BUILD_COMMANDS.items():
        if command != family:
            continue
        if any(args[: len(form)] == form for form in forms):
            return family
        if family == "npm" and len(tokens) > 2 and tokens[1] == "run":
            script = tokens[2]
            if script.startswith("build:") and len(script) > len("build:"):
                return family
        if family in {"yarn", "pnpm"} and len(tokens) > 1:
            script = tokens[1]
            if script.startswith("build:") and len(script) > len("build:"):
                return family
    return None


def _alternative_effect(tokens: list[str]) -> str | None:
    if not tokens:
        return None
    words = tokens
    if words[0] == "git" and len(words) > 1 and words[1] in {"add", "commit", "push"}:
        return "git publication command candidate"
    if words[:2] == ["gh", "release"] and len(words) > 2 and words[2] in {"upload", "create"}:
        return "GitHub release command candidate"
    if words[:2] == ["aws", "s3"] and len(words) > 2 and words[2] in {"cp", "sync"}:
        if len(words) > 4 and words[4].startswith("s3://") and not words[3].startswith("s3://"):
            return "AWS S3 outbound storage command candidate"
        if len(words) > 4 and words[3].startswith("s3://") and not words[4].startswith("s3://"):
            return "AWS S3 inbound copy command candidate (not evidence of build-output retention)"
        return "AWS S3 copy direction is unknown"
    if words[:2] == ["gsutil", "cp"]:
        if len(words) > 3 and words[3].startswith("gs://"):
            return "Google Cloud outbound storage command candidate"
        if len(words) > 3 and words[2].startswith("gs://"):
            return "Google Cloud inbound copy command candidate (not evidence of build-output retention)"
        return "Google Cloud copy direction is unknown"
    if words[:2] == ["gcloud", "storage"] and len(words) > 2 and words[2] == "cp":
        if len(words) > 4 and words[4].startswith(("gs://", "https://storage.googleapis.com/")):
            return "Google Cloud outbound storage command candidate"
        if len(words) > 4 and words[3].startswith(("gs://", "https://storage.googleapis.com/")):
            return "Google Cloud inbound copy command candidate (not evidence of build-output retention)"
        return "Google Cloud copy direction is unknown"
    if words[:2] == ["az", "storage"] and len(words) > 3 and words[2:4] == ["blob", "upload"]:
        return "Azure Blob storage command candidate"
    return None


def _shell_kind(
    step: tuple[object, ...],
    shell_values: dict[tuple[object, ...], list[Event]],
    runner_values: dict[tuple[object, ...], list[Event]],
    default_shell_values: dict[tuple[object, ...], list[Event]],
    declared_shells: set[tuple[object, ...]],
    declared_runners: set[tuple[object, ...]],
) -> tuple[bool, str | None]:
    shells = shell_values.get(step, [])
    if len(shells) > 1 or any(event.merge_origins for event in shells):
        return False, "shell declaration is duplicated or merged"
    if step in declared_shells and not shells:
        return False, "step shell is declared without a resolvable scalar value"
    defaults = default_shell_values.get(step[:2], [])
    if len(defaults) > 1 or any(event.merge_origins for event in defaults):
        return False, "owning job default shell is duplicated or merged"
    if step[:2] in declared_shells and not defaults:
        return False, "owning job default shell is declared without a resolvable scalar value"
    workflow_defaults = default_shell_values.get((), [])
    if len(workflow_defaults) > 1 or any(event.merge_origins for event in workflow_defaults):
        return False, "workflow default shell is duplicated or merged"
    if () in declared_shells and not workflow_defaults:
        return False, "workflow default shell is declared without a resolvable scalar value"
    effective_shell = shells or defaults or workflow_defaults
    if effective_shell:
        value = (effective_shell[0].value or "").strip().lower()
        if value in {"bash", "sh"}:
            return True, None
        return False, "declared shell is not a supported POSIX shell"
    if step[:2] == ("runs", "steps"):
        return False, "composite action step shell is not declared"
    job = step[:2]
    runners = runner_values.get(job, [])
    if job in declared_runners and not runners:
        return False, "runner is declared without a resolvable scalar value"
    if len(runners) > 1 or any(event.merge_origins for event in runners):
        return False, "runner declaration is duplicated or merged"
    if runners:
        runner = (runners[0].value or "").strip().lower()
        if "${{" in runner:
            return False, "runner is dynamic"
        if runner.startswith(("ubuntu-", "macos-")) and "windows-" not in runner:
            return True, None
        if runner.startswith("windows-"):
            return False, "Windows default shell is not POSIX"
    return False, "POSIX shell could not be established from the owning job"


def _commands_for_run(
    event: Event,
) -> tuple[list[tuple[int, list[str], str | None]], list[str]]:
    # The parser's decoded value carries folded/literal YAML semantics. Physical
    # block lines are source presentation and must not replace that value.
    decoded_lines = (event.value or "").splitlines()
    location_note: str | None = None
    if event.value_kind == "block_literal":
        if event.block_lines is not None and len(event.block_lines) >= len(decoded_lines):
            source = tuple(
                (event.block_lines[offset][0], value, None)
                for offset, value in enumerate(decoded_lines)
            )
        else:
            source = tuple((event.line, value, None) for value in decoded_lines)
            if decoded_lines:
                location_note = (
                    f"Commands were decoded from the YAML scalar at line {event.line}; "
                    "that line is the scalar origin because physical body-line mapping was unavailable."
                )
    elif event.value_kind == "block_folded":
        source = tuple((event.line, value, None) for value in decoded_lines)
        location_note = (
            f"Commands were decoded from the folded YAML scalar at line {event.line}; "
            "that line is the scalar origin, not a physical command-body line."
        )
    elif len(decoded_lines) > 1:
        source = tuple((event.line, value, None) for value in decoded_lines)
        location_note = (
            f"Commands were decoded from the YAML scalar at line {event.line}; "
            "that line is the scalar origin, not a physical command-body line."
        )
    else:
        source = tuple((event.line, value, None) for value in decoded_lines)
    commands: list[tuple[int, list[str], str | None]] = []
    physical = list(source)
    logical: list[tuple[int, str, str | None]] = []
    continued = ""
    continued_line = event.line
    for line_number, raw, source_note in physical:
        if not continued:
            continued_line = line_number
        # Only a final unescaped backslash joins lines; do not strip spaces.
        trailing_slashes = len(raw) - len(raw.rstrip("\\"))
        if trailing_slashes % 2 == 1:
            continued += raw[:-1]
            continue
        logical.append((continued_line, continued + raw, source_note))
        continued = ""
    if continued:
        return [], ["shell line continuation is incomplete"]

    # This is a deliberately narrow command recognizer, not a shell evaluator.
    # If any logical line uses unsupported syntax, treat the entire run as
    # unresolved so later text cannot be promoted out of a heredoc/quote.
    for line_number, text, source_note in logical:
        try:
            shlex.split(text, comments=True, posix=True)
        except ValueError:
            return [], ["shell quoting is incomplete or unsupported"]
        if any(marker in text for marker in ("<<", "<<<", "$(", "${", "`", "(", ")")):
            return [], ["heredoc, expansion or grouped shell syntax was not interpreted"]
        parsed = _command_tokens(text)
        if any(command and command[0].lower() in _CONTROL_COMMANDS for command in parsed):
            return [], ["shell control flow was not interpreted"]
        if any(
            command
            and command[0].lower()
            in {"env", "sudo", "command", "bash", "sh", "pwsh", "powershell", "cmd"}
            for command in parsed
        ):
            return [], ["shell wrapper or alternate interpreter was not interpreted"]
        commands.extend((line_number, command, source_note or location_note) for command in parsed)
    if "${{" in (event.value or ""):
        return [], ["run command contains a runtime expression"]
    return commands, []


class _ArtifactRetentionPattern:
    """Review missing same-owner artifact declarations from structural workflow events."""

    preserve_shared_line_liveness = True

    def check(
        self, content: str, lines: list[str]
    ) -> _ArtifactMatches | _IncompleteArtifactMatches:
        return self._check(content, lines, "workflow.yml")

    def check_with_filepath(
        self, content: str, lines: list[str], filepath: str
    ) -> list[tuple[int, str]] | _IncompleteArtifactMatches:
        if not filepath.lower().endswith((".yml", ".yaml")):
            return []
        return self._check(content, lines, filepath)

    def _check(
        self, content: str, lines: list[str], filepath: str
    ) -> _ArtifactMatches | _IncompleteArtifactMatches:
        from taintly.parsers.structural import walk_workflow

        events: list[Event] = []
        for event in walk_workflow(
            filepath,
            content=content,
            recover=True,
            include_keys=True,
            include_merge_origins=True,
        ):
            if len(events) >= _MAX_ARTIFACT_EVENTS:
                return _IncompleteArtifactMatches(
                    [],
                    reason=f"structural event bound reached ({_MAX_ARTIFACT_EVENTS})",
                    contexts=[],
                )
            events.append(event)
        if any(event.kind in {EventKind.ERROR, EventKind.CUTOFF} for event in events):
            return _IncompleteArtifactMatches(
                [],
                reason="structural YAML parsing reported an error or cutoff",
                contexts=[],
            )

        runs: dict[tuple[object, ...], list[Event]] = {}
        uses: dict[tuple[object, ...], list[Event]] = {}
        shell_values: dict[tuple[object, ...], list[Event]] = {}
        runner_values: dict[tuple[object, ...], list[Event]] = {}
        default_shell_values: dict[tuple[object, ...], list[Event]] = {}
        declared_shells: set[tuple[object, ...]] = set()
        declared_runners: set[tuple[object, ...]] = set()
        owner_ambiguous: dict[tuple[object, ...], set[str]] = {}
        seen_keys: set[tuple[object, ...]] = set()
        line_owner_count = _line_owner_counts(events)
        composite_action = any(
            event.kind is EventKind.LEAF_SCALAR
            and event.path == ("runs", "using")
            and (event.value or "").strip().lower() == "composite"
            and not event.merge_origins
            for event in events
        )

        for event in events:
            owner = _artifact_owner(event.path)
            if owner is not None:
                relevant_key = event.path[-1:] in {("run",), ("uses",), ("shell",), ("runs-on",)}
                if event.kind is EventKind.MAP_KEY and relevant_key and event.path in seen_keys:
                    owner_ambiguous.setdefault(owner, set()).add("duplicate structural key")
                if event.kind is EventKind.MAP_KEY and relevant_key:
                    seen_keys.add(event.path)
                    if event.path[-1:] == ("shell",):
                        if (
                            len(event.path) == 5
                            and event.path[0] == "jobs"
                            and event.path[2] == "steps"
                            and isinstance(event.path[3], int)
                        ):
                            declared_shells.add(event.path[:4])
                        elif event.path in {("defaults", "run", "shell")}:
                            declared_shells.add(())
                        elif (
                            len(event.path) == 5
                            and event.path[0] == "jobs"
                            and event.path[2:] == ("defaults", "run", "shell")
                        ):
                            declared_shells.add(event.path[:2])
                        elif len(event.path) == 4 and event.path[:2] == ("runs", "steps"):
                            declared_shells.add(event.path[:3])
                    if event.path[-1:] == ("runs-on",) and len(event.path) >= 3:
                        declared_runners.add(event.path[:2])
                if event.merge_origins and event.path[-1:] in {
                    ("run",),
                    ("uses",),
                    ("shell",),
                }:
                    owner_ambiguous.setdefault(owner, set()).add("merged structural value")
            if event.kind is not EventKind.LEAF_SCALAR:
                continue
            path = event.path
            if (
                len(path) == 5
                and path[0] == "jobs"
                and isinstance(path[1], str)
                and path[2] == "steps"
                and isinstance(path[3], int)
            ):
                owner = path[:2]
                step_path = path[:4]
                if path[4] == "run":
                    runs.setdefault(owner, []).append(event)
                elif path[4] == "uses":
                    uses.setdefault(owner, []).append(event)
                elif path[4] == "shell":
                    shell_values.setdefault(step_path, []).append(event)
            elif len(path) == 3 and path[0] == "jobs" and isinstance(path[1], str):
                owner = path[:2]
                if path[2] == "uses":
                    uses.setdefault(owner, []).append(event)
                elif path[2] == "runs-on":
                    runner_values.setdefault(owner, []).append(event)
            elif (
                len(path) == 5
                and path[0] == "jobs"
                and path[2:]
                == (
                    "defaults",
                    "run",
                    "shell",
                )
            ):
                default_shell_values.setdefault(path[:2], []).append(event)
            elif path == ("defaults", "run", "shell"):
                default_shell_values.setdefault((), []).append(event)
            elif (
                len(path) == 4
                and path[0] == "jobs"
                and isinstance(path[1], str)
                and path[2] == "runs-on"
                and isinstance(path[3], int)
            ):
                runner_values.setdefault(path[:2], []).append(event)
            elif len(path) == 2 and path[0] == "steps" and isinstance(path[1], int):
                owner = ("steps",)
                if path[1] >= 0:
                    # Top-level step fragments are supported by the self-test API.
                    pass
            elif len(path) == 3 and path[0] == "steps" and isinstance(path[1], int):
                owner = ("steps",)
                if path[2] == "run":
                    runs.setdefault(owner, []).append(event)
                elif path[2] == "uses":
                    uses.setdefault(owner, []).append(event)
            elif (
                composite_action
                and len(path) == 4
                and path[:2] == ("runs", "steps")
                and isinstance(path[2], int)
            ):
                owner = ("runs",)
                composite_step_path = path[:3]
                if path[3] == "run":
                    runs.setdefault(owner, []).append(event)
                elif path[3] == "uses":
                    uses.setdefault(owner, []).append(event)
                elif path[3] == "shell":
                    shell_values.setdefault(composite_step_path, []).append(event)

        sites: dict[tuple[object, ...], list[_BuildSite]] = {}
        command_unknown: dict[tuple[object, ...], set[str]] = {}
        alternative_notes: dict[tuple[object, ...], set[str]] = {}
        for owner, owner_runs in runs.items():
            for event in owner_runs:
                step: tuple[object, ...]
                if len(event.path) == 5 and event.path[0] == "jobs":
                    step = event.path[:4]
                    posix, shell_unknown = _shell_kind(
                        step,
                        shell_values,
                        runner_values,
                        default_shell_values,
                        declared_shells,
                        declared_runners,
                    )
                elif len(event.path) == 4 and event.path[:2] == ("runs", "steps"):
                    step = event.path[:3]
                    posix, shell_unknown = _shell_kind(
                        step,
                        shell_values,
                        runner_values,
                        default_shell_values,
                        declared_shells,
                        declared_runners,
                    )
                else:
                    step = ("steps",)
                    posix, shell_unknown = True, None
                if not posix:
                    command_unknown.setdefault(owner, set()).add(
                        shell_unknown or "shell is unknown"
                    )
                    continue
                commands, parse_unknown = _commands_for_run(event)
                if parse_unknown:
                    command_unknown.setdefault(owner, set()).update(parse_unknown)
                for line_number, tokens, location_note in commands:
                    family = _build_family(tokens)
                    if family:
                        sites.setdefault(owner, []).append(
                            _BuildSite(
                                event,
                                family,
                                owner,
                                _artifact_line_owner(event.path) or owner,
                                line_number,
                                location_note,
                            )
                        )
                    alternative = _alternative_effect(tokens)
                    if alternative:
                        alternative_notes.setdefault(owner, set()).add(alternative)

        literal_upload_owners: set[tuple[object, ...]] = set()
        dynamic_use_owners: set[tuple[object, ...]] = set()
        release_steps: set[tuple[object, ...]] = set()
        for owner, owner_uses in uses.items():
            for event in owner_uses:
                value = (event.value or "").strip()
                if "${{" in value:
                    dynamic_use_owners.add(owner)
                    continue
                if _UPLOAD_ACTION_RE.fullmatch(value):
                    literal_upload_owners.add(owner)
                if value.lower().startswith(_RELEASE_ACTIONS):
                    step_owner = _artifact_line_owner(event.path)
                    if step_owner is not None:
                        release_steps.add(step_owner)

        # A release-action reference plus an owning `with.files` value is only
        # a configured publication candidate; neither execution nor retention
        # is inferred from the declaration.
        for event in events:
            if event.kind is EventKind.LEAF_SCALAR and event.path[-1:] == ("files",):
                owner = _artifact_owner(event.path)
                step_owner = _artifact_line_owner(event.path)
                if step_owner in release_steps and owner is not None:
                    alternative_notes.setdefault(owner, set()).add(
                        "release action files configuration candidate"
                    )

        results: list[tuple[int, str]] = []
        contexts: list[_ArtifactMatchContext] = []
        for owner, owner_sites in sites.items():
            reasons = owner_ambiguous.get(owner, set())
            if reasons:
                continue
            if owner in literal_upload_owners:
                continue
            # Keep separate run-step sites; deduplicate recognized families
            # within one scalar so one build step yields at most one finding.
            by_step: dict[tuple[object, ...], _BuildSite] = {}
            for site in owner_sites:
                by_step.setdefault(site.event.path, site)
            for first in sorted(by_step.values(), key=lambda site: (site.line_number, site.family)):
                line_number = first.line_number
                snippet = (
                    lines[line_number - 1].strip()
                    if 0 < line_number <= len(lines)
                    else f"{first.family} build command"
                )
                owner_label = ".".join(str(part) for part in owner)[:120]
                notes = [
                    f"Observed executable {first.family} build-command candidate in owner {owner_label}.",
                    f"No literal actions/upload-artifact declaration was found in owner {owner_label}; this is declaration-presence only, not proof of missing or failed retention.",
                    "Output path coverage, conditions, ordering, action execution, alternate retention and forensic availability remain unknown and need review.",
                ]
                if first.location_note:
                    notes.append(first.location_note)
                notes.extend(
                    f"Observed {candidate}; successful publication or retention is unknown."
                    for candidate in sorted(alternative_notes.get(owner, set()))
                )
                if owner in dynamic_use_owners:
                    notes.append(
                        "A dynamic action reference is present in this owner; its behavior and any retention effect are unknown."
                    )
                foreign_uploads = literal_upload_owners - {owner}
                if foreign_uploads:
                    foreign_names = sorted(
                        ".".join(str(part) for part in item)[:80] for item in foreign_uploads
                    )
                    names = ", ".join(foreign_names[:5])
                    notes.append(
                        f"A literal upload-artifact declaration occurs in another owner ({names}); it does not establish coverage for this build owner."
                    )
                    if len(foreign_names) > 5:
                        notes.append(
                            f"{len(foreign_names) - 5} additional foreign declaration owners omitted from context."
                        )
                unknown = sorted(command_unknown.get(owner, set()))
                if unknown:
                    displayed_unknown = unknown[:5]
                    notes.append(
                        "Some run-command context was not interpreted ("
                        + ", ".join(displayed_unknown)
                        + "); command effects remain unresolved."
                    )
                    if len(unknown) > 5:
                        notes.append(
                            f"{len(unknown) - 5} additional unresolved command notes omitted from context."
                        )
                results.append((line_number, snippet))
                contexts.append(
                    _ArtifactMatchContext(
                        notes,
                        first.line_owner,
                        line_owner_count.get(line_number),
                    )
                )

        if owner_ambiguous:
            reason_parts = sorted(
                {reason for values in owner_ambiguous.values() for reason in values}
            )
            # A known build candidate can still be reported with an explicit
            # uncertainty note; this diagnostic discloses incomplete owners.
            return _IncompleteArtifactMatches(
                results,
                reason="; ".join(reason_parts),
                contexts=contexts,
            )
        return _ArtifactMatches(results, contexts)

    def context_notes_for_matches(
        self,
        _content: str,
        _filepath: str,
        matches: list[tuple[int, str]],
    ) -> list[_ArtifactMatchContext]:
        contexts = getattr(matches, "contexts", [])
        if len(contexts) != len(matches):
            return [
                _ArtifactMatchContext(
                    ["Owner context could not be bound to this match; retention is unresolved."],
                    None,
                    None,
                )
                for _ in matches
            ]
        return contexts


RULES: list[Rule] = [
    # =========================================================================
    # SEC10-GH-001: Job missing timeout-minutes
    # =========================================================================
    Rule(
        id="SEC10-GH-001",
        title="GitHub Actions job has no explicit timeout-minutes",
        severity=Severity.LOW,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-10",
        description=(
            "A GitHub Actions job does not set 'timeout-minutes' explicitly. GitHub "
            "uses a 360-minute default, subject to runner execution limits. A hung or "
            "compromised step may continue longer than the repository intends. An "
            "explicit per-job timeout can set a shorter bound."
        ),
        pattern=ContextPattern(
            # Anchor: any job-level 'runs-on:' (marks a real job)
            anchor=r"^\s{2,4}runs-on:",
            # Requires: steps: is always present in a real job — ensures this
            # is a real workflow file, not a fragment
            requires=r"steps\s*:",
            # Fires only when the file has NO timeout-minutes anywhere
            requires_absent=r"timeout-minutes\s*:",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Set an explicit 'timeout-minutes' on each job:\n\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    timeout-minutes: 30   # Fail the job if it exceeds 30 minutes\n"
            "    steps:\n"
            "      - ...\n\n"
            "Choose a timeout that allows the job to finish under expected conditions "
            "while limiting the duration of an unexpected run."
        ),
        reference="https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes",
        test_positive=[
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4",
        ],
        test_negative=[
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 30\n    steps:\n      - uses: actions/checkout@v4",
        ],
        stride=["D", "R"],
        threat_narrative=(
            "Without an explicit timeout, the job uses GitHub's 360-minute default, "
            "subject to runner execution limits. A shorter per-job limit can bound "
            "how long a hung or compromised step continues running."
        ),
        confidence="high",
    ),
    # =========================================================================
    # SEC10-GH-002: Workflow uploads no artifacts — no evidence trail
    # =========================================================================
    Rule(
        id="SEC10-GH-002",
        confidence="low",
        review_needed=True,
        title="Build command has no same-owner Actions artifact declaration (review)",
        severity=Severity.LOW,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-10",
        description=(
            "A supported executable build-command family was found in this job, but no "
            "literal actions/upload-artifact declaration was found in the same job. "
            "This is a declaration-presence review lint only: it does not establish "
            "whether outputs are retained elsewhere, whether an upload covers the "
            "relevant paths, or whether any configured action or command executes "
            "successfully. Review output paths and available retention mechanisms."
        ),
        pattern=_ArtifactRetentionPattern(),
        remediation=(
            "Review generated outputs and decide whether they need a retained "
            "workflow artifact, repository commit, release asset, or external store. "
            "A configured retention mechanism does not by itself establish path "
            "coverage or successful execution. For an Actions artifact, declare "
            "actions/upload-artifact in the same job as the build:\n\n"
            "- name: Upload build artifacts\n"
            "  uses: actions/upload-artifact@v4\n"
            "  with:\n"
            "    name: build-${{ github.sha }}\n"
            "    path: dist/\n"
            "    retention-days: 90\n\n"
            "For stronger integrity, also generate and upload an SBOM:\n"
            "- uses: anchore/sbom-action@v0\n"
            "  with:\n"
            "    artifact-name: sbom-${{ github.sha }}.spdx.json"
        ),
        reference="https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/storing-and-sharing-data-from-a-workflow",
        test_positive=[
            "steps:\n  - run: npm run build\n  - run: echo done",
            "steps:\n  - run: go build ./...\n  - run: echo done",
        ],
        test_negative=[
            "steps:\n  - run: npm run build\n  - uses: actions/upload-artifact@v4\n    with:\n      path: dist/",
            "steps:\n  - run: echo hello",
        ],
        stride=["R"],
        threat_narrative=(
            "When a build has no retained output or provenance, incident review may lack evidence "
            "to compare produced binaries with deployed artifacts. This rule only checks for a "
            "same-owner Actions artifact declaration; repository commits, release assets, external "
            "storage, path coverage, and runtime success require separate review."
        ),
    ),
    # =========================================================================
    # SEC10-GH-004: Workflow uploads a debug log / step summary / runner
    # home directory as an artifact — post-failure secret-exfil primitive.
    #
    # Source: Praetorian — CodeQLEAKED (CVE-2025-24362).  CodeQL Action
    # uploaded ``$RUNNER_DEBUG`` contents as an artifact after a failed
    # run; ``GITHUB_TOKEN`` was captured in the debug log and the
    # artifact was downloadable by anyone with read access (which on
    # public repos means everyone).  The root cause is broader than
    # CodeQL: any workflow that uploads debug output, step-summary
    # files, runner-home contents, or wildcarded path globs after a
    # failure risks capturing in-memory secret material.
    # =========================================================================
    Rule(
        id="SEC10-GH-004",
        title=(
            "actions/upload-artifact uploads debug log / step summary / "
            "runner home — post-failure secret-exfil primitive"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-10",
        description=(
            "An ``actions/upload-artifact`` step's ``path:`` resolves "
            "to content that likely contains secret material: a debug "
            "log (``$RUNNER_DEBUG``, ``**/*.log``, ``/tmp/*.log``), the "
            "step summary (``$GITHUB_STEP_SUMMARY``), the runner's "
            "home directory (``~/``, ``$HOME``, ``/home/runner``), or "
            "the runner's temp directory (``$RUNNER_TEMP``, "
            "``/tmp/**``).  After a workflow failure — or even on "
            "success — the artifact is downloadable by anyone with "
            "read access to the repository (which on public repos is "
            "the whole internet).  Praetorian's CodeQLEAKED "
            "(CVE-2025-24362) landed exactly this way: CodeQL uploaded "
            "its debug log on failure, ``GITHUB_TOKEN`` was echoed into "
            "the log, and anyone could download it and replay the "
            "token.  The primitive is agnostic of CodeQL — any "
            "workflow can land the same way."
        ),
        # BlockPattern's indent-walk requires a deeper indent after the
        # anchor, but ``with:`` sits at the SAME indent as ``uses:`` in
        # a GH Actions step (they're sibling keys of the step dict), so
        # the block exits before seeing ``path:``.  Use ContextPattern
        # with scope="job" instead: fire the finding on the risky
        # ``path:`` line when an ``actions/upload-artifact`` call also
        # appears in the same job.  False-positive risk is low because
        # the risky path shapes below only legitimately appear as
        # artifact sources — nothing else in a workflow legitimately
        # refers to ``$RUNNER_DEBUG`` / ``$GITHUB_STEP_SUMMARY`` / etc.
        # in a ``path:`` key.
        pattern=ContextPattern(
            anchor=(
                r"^\s*(?:-\s*)?path\s*:\s*['\"]?"
                r"(?:"
                # Debug / log content
                r".*\$\{?RUNNER_DEBUG\}?"
                r"|.*\$\{?GITHUB_STEP_SUMMARY\}?"
                r"|.*\$\{?RUNNER_TEMP\}?"
                # Wildcard log globs
                r"|.*\*\*/\*\.log\b"
                r"|.*\*\.log(?:\b|$)"
                r"|/tmp/\*"
                r"|/var/log/"
                # Runner home / temp-dir dumps
                r"|\$\{?HOME\}?(?:/|\s|['\"]|$)"
                r"|~/?(?:\s|['\"]|$)"
                r"|/home/runner(?:/|\s|['\"]|$)"
                # Wildcard-everything — catches ``**/*`` and ``**``.
                r"|\*\*/\*(?:\s|['\"]|$)"
                r"|\*\*(?:\s|['\"]|$)"
                # Classic credential file paths.  Require end-of-value
                # (quote, space, newline) to avoid matching
                # ``${{ matrix.env.PROTOCOL }}`` or similar context
                # refs inside otherwise-legitimate artefact paths.
                r"|.*\.?npmrc(?:\s|['\"]|$)"
                r"|.*\.?pypirc(?:\s|['\"]|$)"
                r"|.*\.env(?:\s|['\"]|$)"
                r")"
            ),
            requires=r"uses:\s+actions/upload-artifact@",
            scope="job",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Narrow the artifact path to a specific, curated build\n"
            "output directory.  Never upload ``$RUNNER_DEBUG``,\n"
            "``$GITHUB_STEP_SUMMARY``, ``$HOME``, ``~``, ``/tmp/**``,\n"
            "or wildcarded globs as an artifact.\n"
            "\n"
            "BAD:\n"
            "  - name: Capture debug on failure\n"
            "    if: failure()\n"
            "    uses: actions/upload-artifact@<sha>\n"
            "    with:\n"
            "      path: $RUNNER_DEBUG\n"
            "\n"
            "GOOD:\n"
            "  - name: Upload build output\n"
            "    uses: actions/upload-artifact@<sha>\n"
            "    with:\n"
            "      name: dist-${{ github.sha }}\n"
            "      path: dist/\n"
            "      retention-days: 7\n"
            "\n"
            "If you genuinely need post-failure logs, redact secrets\n"
            "BEFORE upload (``sed -i 's/ghp_[A-Za-z0-9]*/REDACTED/g'``\n"
            "against known token shapes) and limit ``retention-days`` to\n"
            "the shortest practical window.  Better still: route debug\n"
            "output to an internal logging system that enforces access\n"
            "controls, not GitHub artifacts (public on public repos)."
        ),
        reference=(
            "https://www.praetorian.com/blog/codeqleaked-public-secrets-"
            "exposure-leads-to-supply-chain-attack-on-github-codeql/"
        ),
        test_positive=[
            (
                "steps:\n"
                "  - name: Capture debug\n"
                "    if: failure()\n"
                "    uses: actions/upload-artifact@v4\n"
                "    with:\n      name: debug\n      path: $RUNNER_DEBUG"
            ),
            (
                "steps:\n"
                "  - uses: actions/upload-artifact@v4\n"
                "    with:\n      path: $GITHUB_STEP_SUMMARY"
            ),
            (
                "steps:\n"
                "  - uses: actions/upload-artifact@v4\n"
                "    with:\n      path: /home/runner/work/logs"
            ),
            # Classic wildcard-log glob
            ("steps:\n  - uses: actions/upload-artifact@v4\n    with:\n      path: '**/*.log'"),
            # HOME dump
            ("steps:\n  - uses: actions/upload-artifact@v4\n    with:\n      path: $HOME"),
        ],
        test_negative=[
            # Normal build-output upload
            (
                "steps:\n"
                "  - uses: actions/upload-artifact@v4\n"
                "    with:\n      name: dist\n      path: dist/"
            ),
            # SBOM / manifest
            ("steps:\n  - uses: actions/upload-artifact@v4\n    with:\n      path: sbom.spdx.json"),
            # Coverage report
            ("steps:\n  - uses: actions/upload-artifact@v4\n    with:\n      path: coverage/"),
            # Comment line
            (
                "steps:\n"
                "  - uses: actions/upload-artifact@v4\n"
                "    with:\n"
                "      # path: $RUNNER_DEBUG   # disabled after CodeQLEAKED\n"
                "      path: build/"
            ),
        ],
        stride=["I"],
        threat_narrative=(
            "GitHub artifact uploads are accessible to anyone with "
            "repository read access — on a public repo, the entire "
            "internet.  When the uploaded path resolves to "
            "``$RUNNER_DEBUG``, ``$GITHUB_STEP_SUMMARY``, a wildcard "
            "log glob, or the runner's home / temp directory, "
            "``GITHUB_TOKEN`` / OIDC artefacts / cached credential "
            "files / .env fragments / SSH known-hosts entries can be "
            "captured verbatim.  CodeQLEAKED (CVE-2025-24362) used the "
            "``$RUNNER_DEBUG`` arm of this exact primitive to exfil a "
            "``GITHUB_TOKEN`` that anyone could then replay."
        ),
        confidence="medium",
        incidents=[
            "CodeQLEAKED (Praetorian, CVE-2025-24362)",
        ],
    ),
]
