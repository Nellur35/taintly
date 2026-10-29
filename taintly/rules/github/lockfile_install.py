"""Source-bound npm lockfile-install review for GitHub release jobs.

This is a deliberately narrow SPVS 1.6 V3.1.1 profile: direct npm project
install commands followed by npm publish in the same job and directory. It
does not model executed dependency bytes or establish publication.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass

from taintly.models import IncompletePatternMatches, Platform, Rule, Severity
from taintly.npm_release_commands import (
    _CWD_CHANGE,
    _NPM_PUBLISH_ANY,
    _SHELL_FLOW,
    _SHELL_INDIRECTION,
    _classify_command,
    _directory,
)
from taintly.parsers.structural import Event, EventKind, walk_workflow


@dataclass(frozen=True)
class _Command:
    job: str
    step: int
    line: int
    snippet: str
    verb: str
    directory: str


class NonFrozenNpmPublishPattern:
    """Match a direct project ``npm install`` that survives to publish."""

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if not lines or "jobs" not in content or not _NPM_PUBLISH_ANY.search(content):
            return []
        job_defaults: dict[str, str] = {}
        step_dirs: dict[tuple[str, int], str] = {}
        step_if: set[tuple[str, int]] = set()
        run_events: list[tuple[tuple[str, int], Event]] = []
        default_dir = "."
        incomplete = False

        for event in walk_workflow("workflow.yml", content=content, recover=True):
            if event.kind in {EventKind.ERROR, EventKind.CUTOFF}:
                incomplete = True
                continue
            if event.kind is not EventKind.LEAF_SCALAR or event.value is None:
                continue
            path = event.path
            if path == ("defaults", "run", "working-directory"):
                default_dir = event.value
            elif (
                len(path) == 5
                and path[0] == "jobs"
                and isinstance(path[1], str)
                and path[2:]
                == (
                    "defaults",
                    "run",
                    "working-directory",
                )
            ):
                job_defaults[str(path[1])] = event.value
            elif (
                len(path) == 5
                and path[0] == "jobs"
                and isinstance(path[1], str)
                and path[2] == "steps"
                and isinstance(path[3], int)
            ):
                step_key: tuple[str, int] = (path[1], path[3])
                if path[4] == "working-directory":
                    step_dirs[step_key] = event.value
                elif path[4] == "if":
                    step_if.add(step_key)
                elif path[4] == "run":
                    run_events.append((step_key, event))

        commands: list[_Command] = []
        for (job, step), event in run_events:
            step_key = (job, step)
            base = _directory(step_dirs.get(step_key, job_defaults.get(job, default_dir)))
            if event.block_lines is not None:
                source_lines = event.block_lines
            elif event.value_kind == "block_folded":
                incomplete = True
                continue
            else:
                source_lines = ((event.line, event.value or ""),)
            shell_flow = any(
                _SHELL_FLOW.match(source) or _SHELL_INDIRECTION.search(source)
                for _, source in source_lines
            )
            cwd_unknown = False
            for line, source in source_lines:
                if _CWD_CHANGE.match(source):
                    cwd_unknown = True
                    incomplete = True
                    continue
                classified = _classify_command(source)
                if classified is None:
                    continue
                verb, prefix = classified
                if (
                    cwd_unknown
                    or shell_flow
                    or step_key in step_if
                    or base is None
                    or prefix is None
                ):
                    incomplete = True
                    continue
                directory = _directory(posixpath.join(base, prefix))
                if directory is None:
                    incomplete = True
                    continue
                commands.append(
                    _Command(
                        job,
                        step,
                        line,
                        source.strip(),
                        verb,
                        directory,
                    )
                )

        pending: dict[tuple[str, str], _Command] = {}
        results: list[tuple[int, str]] = []
        reported: set[tuple[str, int]] = set()
        for command in sorted(commands, key=lambda item: (item.job, item.step, item.line)):
            package_key = (command.job, command.directory)
            if command.verb == "install":
                pending[package_key] = command
            elif command.verb == "publish":
                install = pending.get(package_key)
                if install is None or (install.job, install.line) in reported:
                    continue
                reported.add((install.job, install.line))
                results.append((install.line, install.snippet))
        if incomplete:
            return IncompletePatternMatches(
                results,
                reason="npm release-install profile could not resolve YAML, shell, or directory context",
            )
        return results


RULES: list[Rule] = [
    Rule(
        id="LOTP-GH-007",
        title="Non-frozen npm project install precedes publish in one job",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        finding_family="dependency_lock_integrity",
        review_needed=True,
        confidence="medium",
        description=(
            "A direct npm project install is configured before npm publish in the "
            "same GitHub job and literal working directory. Unlike npm ci, "
            "npm install does not fail closed when the package manifest and "
            "lockfile disagree; it can update resolution. This is a reviewable "
            "release configuration fact, not evidence that drift occurred, "
            "the published artifact changed, or either command executed. "
            "The rule covers literal direct npm commands in supported run steps."
        ),
        pattern=NonFrozenNpmPublishPattern(),
        remediation=(
            "For a release job that consumes a committed lockfile, use npm ci "
            "in the relevant package directory so a manifest/lock mismatch "
            "fails the job. Review separately whether lifecycle scripts are "
            "permitted and whether the publish stage has appropriate authority."
        ),
        reference="https://docs.npmjs.com/cli/v11/commands/npm-ci/",
        test_positive=[
            "jobs:\n  publish:\n    steps:\n      - run: npm install\n      - run: npm publish",
        ],
        test_negative=[
            "jobs:\n  publish:\n    steps:\n      - run: npm ci\n      - run: npm publish",
            "jobs:\n  publish:\n    steps:\n      - run: npm install -g npm@latest\n      - run: npm publish",
        ],
        stride=["T"],
    )
]
