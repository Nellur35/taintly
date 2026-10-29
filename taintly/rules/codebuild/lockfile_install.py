"""Bounded CodeBuild npm install-to-publish lockfile review.

Only buildspec 0.2 phase commands with direct npm invocations are supported.
CodeBuild project settings and per-build overrides can select another buildspec;
this rule describes the supplied source file, not a verified running project.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass

from taintly.models import IncompletePatternMatches, Platform, Rule, Severity
from taintly.npm_release_commands import (
    _CWD_CHANGE,
    _NPM_INSTALL_ANY,
    _NPM_PUBLISH_ANY,
    _SHELL_FLOW,
    _SHELL_INDIRECTION,
    _classify_command,
    _directory,
)
from taintly.parsers.structural import Event, EventKind, walk_workflow

_PHASE_ORDER = {"install": 0, "pre_build": 1, "build": 2, "post_build": 3}
_SUPPORTED_SHELLS = {"bash", "sh", "/bin/sh"}
_NPM_I_ANY = re.compile(r"\bnpm\s+i\b")
_NPM_I_START = re.compile(r"^\s*npm\s+i\b")


@dataclass(frozen=True)
class _Command:
    line: int
    snippet: str
    verb: str
    directory: str


def _source_lines(event: Event) -> tuple[tuple[int, str], ...] | None:
    if event.block_lines is not None:
        return event.block_lines
    if event.value_kind == "block_folded":
        return None
    return ((event.line, event.value or ""),)


class NonFrozenNpmPublishPattern:
    """Find a direct project install before direct publish in one buildspec."""

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if (
            not lines
            or not (_NPM_INSTALL_ANY.search(content) or _NPM_I_ANY.search(content))
            or not _NPM_PUBLISH_ANY.search(content)
        ):
            return []

        events = tuple(walk_workflow("buildspec.yml", content=content, recover=True))
        if any(event.kind in {EventKind.ERROR, EventKind.CUTOFF} for event in events):
            return IncompletePatternMatches(
                [], reason="CodeBuild release-install profile could not parse the buildspec"
            )

        versions: list[str] = []
        shells: list[str] = []
        commands: list[tuple[int, int, Event]] = []
        incomplete = False
        has_finally = False
        seen_commands: set[tuple[str, int]] = set()
        for event in events:
            if event.kind is not EventKind.LEAF_SCALAR or event.value is None:
                continue
            path = event.path
            if path == ("version",):
                versions.append(event.value)
            elif path == ("env", "shell"):
                shells.append(event.value)
            elif len(path) >= 3 and path[0] == "phases" and path[1] in _PHASE_ORDER:
                if path[2] == "finally":
                    has_finally = True
                if path[2] != "commands":
                    continue
                if len(path) != 4 or not isinstance(path[3], int):
                    incomplete = True
                    continue
                key = (path[1], path[3])
                if key in seen_commands:
                    return IncompletePatternMatches(
                        [],
                        reason="CodeBuild release-install profile found duplicate command ownership",
                    )
                seen_commands.add(key)
                commands.append((_PHASE_ORDER[path[1]], path[3], event))

        if versions != ["0.2"] or (
            shells and (len(shells) != 1 or shells[0] not in _SUPPORTED_SHELLS)
        ):
            return IncompletePatternMatches(
                [],
                reason="CodeBuild release-install profile requires buildspec 0.2 and a supported shell",
            )
        if has_finally:
            return IncompletePatternMatches(
                [], reason="CodeBuild release-install profile does not model phase finally commands"
            )

        results: list[tuple[int, str]] = []
        pending: dict[str, _Command] = {}
        reported: set[int] = set()
        shell_unknown = False
        for _, _, event in sorted(commands, key=lambda item: (item[0], item[1])):
            source_rows = _source_lines(event)
            if source_rows is None:
                shell_unknown = True
                incomplete = True
                pending.clear()
                continue
            for line, source in source_rows:
                if _NPM_I_START.match(source):
                    incomplete = True
                    continue
                if (
                    _CWD_CHANGE.match(source)
                    or _SHELL_FLOW.match(source)
                    or _SHELL_INDIRECTION.search(source)
                ):
                    shell_unknown = True
                    incomplete = True
                    pending.clear()
                    continue
                classified = _classify_command(source)
                if classified is None:
                    continue
                verb, prefix = classified
                if prefix is None or shell_unknown:
                    incomplete = True
                    continue
                directory = _directory(posixpath.join(".", prefix))
                if directory is None:
                    incomplete = True
                    continue
                command = _Command(line, source.strip(), verb, directory)
                if verb == "install":
                    pending[directory] = command
                elif verb == "publish":
                    install = pending.get(directory)
                    if install is not None and install.line not in reported:
                        results.append((install.line, install.snippet))
                        reported.add(install.line)

        if incomplete:
            return IncompletePatternMatches(
                results,
                reason="CodeBuild npm release-install profile could not resolve shell or command context",
            )
        return results


RULES: list[Rule] = [
    Rule(
        id="LOTP-CB-002",
        title="Non-frozen npm project install precedes publish in one CodeBuild buildspec",
        severity=Severity.MEDIUM,
        platform=Platform.CODEBUILD,
        owasp_cicd="CICD-SEC-3",
        finding_family="dependency_lock_integrity",
        review_needed=True,
        confidence="medium",
        description=(
            "A buildspec 0.2 file configures a direct npm project install before "
            "a later direct npm publish in the same literal package directory. "
            "Unlike npm ci, npm install does not fail closed when the package "
            "manifest and lockfile disagree; it can update resolution. This is "
            "a reviewable source-configuration fact, not evidence that this "
            "buildspec was selected, either command ran, dependency drift "
            "occurred, or a package was published. The supported profile "
            "covers direct phase commands without unresolved shell state."
        ),
        pattern=NonFrozenNpmPublishPattern(),
        remediation=(
            "For a release build that consumes a committed lockfile, use npm ci "
            "in the same package directory so a manifest/lock mismatch fails "
            "the build. Verify the CodeBuild project or build override actually "
            "selects this buildspec. Review lifecycle scripts and publication "
            "authority separately."
        ),
        reference="https://docs.npmjs.com/cli/v11/commands/npm-ci/",
        test_positive=[
            "version: 0.2\nphases:\n  install:\n    commands:\n      - npm install\n"
            "  build:\n    commands:\n      - npm publish\n",
            "version: 0.2\nphases:\n  build:\n    commands:\n      - npm install\n"
            "      - npm publish\n",
        ],
        test_negative=[
            "version: 0.2\nphases:\n  install:\n    commands:\n      - npm ci\n"
            "  build:\n    commands:\n      - npm publish\n",
            "version: 0.2\nphases:\n  build:\n    commands:\n      - echo npm install\n"
            "      - npm publish\n",
        ],
        stride=["T"],
    )
]
