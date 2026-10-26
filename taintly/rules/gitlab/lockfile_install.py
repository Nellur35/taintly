"""Bounded GitLab npm install-to-publish lockfile review."""

from __future__ import annotations

import posixpath
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

_PHASE_ORDER = {"before_script": 0, "script": 1}
_RESERVED_TOP_LEVEL = {
    "after_script",
    "before_script",
    "cache",
    "default",
    "image",
    "include",
    "services",
    "stages",
    "variables",
    "workflow",
}


@dataclass(frozen=True)
class _Command:
    job: str
    phase: str
    index: int
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
    """Find a direct npm project install before direct publish in one job."""

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if not lines or not _NPM_PUBLISH_ANY.search(content):
            return []

        events = tuple(walk_workflow(".gitlab-ci.yml", content=content, recover=True))
        incomplete = any(event.kind in {EventKind.ERROR, EventKind.CUTOFF} for event in events)
        job_runs: dict[str, list[tuple[str, int, Event]]] = {}
        local_before_script: set[str] = set()
        inherited_jobs: set[str] = set()
        global_install = False
        includes = False
        after_script_publish: set[str] = set()

        for event in events:
            if event.kind is not EventKind.LEAF_SCALAR or event.value is None:
                continue
            path = event.path
            if path and path[0] == "include":
                includes = True
            if (
                len(path) in {2, 3}
                and path[0] in {"before_script", "default"}
                and "before_script" in path
                and _NPM_INSTALL_ANY.search(event.value)
            ):
                global_install = True
            if len(path) < 2 or not isinstance(path[0], str):
                continue
            job = path[0]
            if job in _RESERVED_TOP_LEVEL or job.startswith("."):
                continue
            if path[1] == "extends":
                inherited_jobs.add(job)
            elif path[1] == "after_script" and _NPM_PUBLISH_ANY.search(event.value):
                after_script_publish.add(job)
            elif path[1] in _PHASE_ORDER and len(path) in {2, 3}:
                phase = path[1]
                if phase == "before_script":
                    local_before_script.add(job)
                index = path[2] if len(path) == 3 and isinstance(path[2], int) else 0
                job_runs.setdefault(job, []).append((phase, index, event))

        results: list[tuple[int, str]] = []
        for job, entries in job_runs.items():
            entries.sort(key=lambda item: (_PHASE_ORDER[item[0]], item[1], item[2].line))
            source_rows: list[tuple[str, int, int, str]] = []
            for phase, index, event in entries:
                rows = _source_lines(event)
                if rows is None:
                    incomplete = True
                    continue
                source_rows.extend((phase, index, line, text) for line, text in rows)
            if not any(_NPM_PUBLISH_ANY.search(text) for _, _, _, text in source_rows):
                if job in after_script_publish and any(
                    _NPM_INSTALL_ANY.search(text) for _, _, _, text in source_rows
                ):
                    incomplete = True
                continue
            if any(
                _SHELL_FLOW.match(text) or _SHELL_INDIRECTION.search(text)
                for _, _, _, text in source_rows
            ):
                incomplete = True
                continue

            commands: list[_Command] = []
            cwd_unknown = False
            for phase, index, line, source in source_rows:
                if _CWD_CHANGE.match(source):
                    cwd_unknown = True
                    incomplete = True
                    continue
                classified = _classify_command(source)
                if classified is None:
                    continue
                verb, prefix = classified
                if cwd_unknown or prefix is None:
                    incomplete = True
                    continue
                directory = _directory(posixpath.join(".", prefix))
                if directory is None:
                    incomplete = True
                    continue
                commands.append(_Command(job, phase, index, line, source.strip(), verb, directory))

            pending: dict[str, _Command] = {}
            reported: set[int] = set()
            for command in commands:
                if command.verb == "install":
                    pending[command.directory] = command
                elif command.verb == "publish":
                    install = pending.get(command.directory)
                    if install is not None and install.line not in reported:
                        results.append((install.line, install.snippet))
                        reported.add(install.line)

            has_install = any(command.verb == "install" for command in commands)
            has_publish = any(command.verb == "publish" for command in commands)
            if (
                has_publish
                and not has_install
                and (
                    (global_install and job not in local_before_script)
                    or job in inherited_jobs
                    or includes
                )
            ):
                incomplete = True
            if has_install and job in after_script_publish:
                incomplete = True

        if incomplete:
            return IncompletePatternMatches(
                results,
                reason="GitLab npm release-install profile could not resolve inherited YAML, shell, or directory context",
            )
        return results


RULES: list[Rule] = [
    Rule(
        id="LOTP-GL-006",
        title="Non-frozen npm project install precedes publish in one GitLab job",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        finding_family="dependency_lock_integrity",
        review_needed=True,
        confidence="medium",
        description=(
            "A direct npm project install is configured before npm publish in "
            "the same GitLab job and unchanged relative working directory. "
            "Unlike npm ci, npm install does not fail closed when the package "
            "manifest and lockfile disagree; it can update resolution. This "
            "is a reviewable configuration fact, not evidence that dependency "
            "drift occurred, publication succeeded, or either command ran. "
            "The supported profile is job-local before_script and script "
            "with standalone direct npm commands."
        ),
        pattern=NonFrozenNpmPublishPattern(),
        remediation=(
            "For a release job that consumes a committed lockfile, use npm ci "
            "in the same package directory so a manifest/lock mismatch fails "
            "the job. Review separately whether lifecycle scripts are allowed "
            "and whether the publish operation has appropriate authority."
        ),
        reference="https://docs.npmjs.com/cli/v11/commands/npm-ci/",
        test_positive=[
            "publish:\n  before_script:\n    - npm install\n  script:\n    - npm publish",
            "publish:\n  script:\n    - npm install\n    - npm publish",
        ],
        test_negative=[
            "publish:\n  script:\n    - npm ci\n    - npm publish",
            "build:\n  script:\n    - npm install\npublish:\n  script:\n    - npm publish",
        ],
        stride=["T"],
    )
]
