from __future__ import annotations

import posixpath
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from taintly._local_invocation import (
    LocalFileInvocation,
    recognize_local_file_invocation,
)
from taintly.eventguard import event_guard_verdict
from taintly.github_event_availability import (
    _contains_alias_or_anchor,
    _explicit_trigger_names,
)
from taintly.parsers.gha_expr import Deref, ExprSyntaxError, Var, parse
from taintly.parsers.structural import Event, EventKind, walk_workflow
from taintly.workflow_corpus import CorpusEvidence, WorkflowCorpus, WorkflowSummary

SUPPORTED_DOWNLOAD_USES = frozenset(
    {"actions/download-artifact@v4", "actions/download-artifact@v5"}
)
_REQUIRED_INPUTS = frozenset({"name", "run-id", "github-token", "path"})
_SUPPORTED_INPUTS = _REQUIRED_INPUTS | {"repository"}
_RUN_ID_PATH = "github.event.workflow_run.id"
_REPOSITORY_PATH = "github.repository"
_TOKEN_PATHS = frozenset({"github.token", "secrets.GITHUB_TOKEN"})
_LITERAL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_STATIC_DIR = re.compile(r"(?:\.{1,2}/)?[A-Za-z0-9._/-]+\Z")
_SUPPORTED_RUNNERS = frozenset({"ubuntu-latest", "ubuntu-20.04", "ubuntu-22.04", "ubuntu-24.04"})


@dataclass(frozen=True)
class CoverageIssue:
    filepath: str
    reason: str


@dataclass(frozen=True)
class PrototypeResult:
    findings: tuple[CorpusEvidence, ...]
    incomplete: tuple[CoverageIssue, ...]


@dataclass(frozen=True)
class _Download:
    job: str
    step: int
    name: str
    destination: str
    token: str
    line: int
    guard_unknown: bool = False


@dataclass(frozen=True)
class _Step:
    job: str
    index: int
    run: Event | None
    uses: str | None
    fields: dict[str, Event]


@dataclass
class _Index:
    events: tuple[Event, ...]
    values: dict[tuple[object, ...], list[Event]]
    keys: dict[tuple[object, ...], list[Event]]
    error: str | None

    @classmethod
    def build(cls, workflow: WorkflowSummary) -> _Index:
        events: list[Event] = []
        for count, event in enumerate(
            walk_workflow(
                workflow.filepath,
                content=workflow.content,
                recover=True,
                include_keys=True,
                include_merge_origins=True,
            )
        ):
            if count >= 20_000:
                return cls(tuple(events), {}, {}, "structural event budget exceeded")
            events.append(event)
        values: dict[tuple[object, ...], list[Event]] = defaultdict(list)
        keys: dict[tuple[object, ...], list[Event]] = defaultdict(list)
        error = None
        for event in events:
            if event.kind in {EventKind.ERROR, EventKind.CUTOFF}:
                error = "workflow YAML has an error or cutoff"
            elif event.kind is EventKind.LEAF_SCALAR:
                values[event.path].append(event)
            elif event.kind is EventKind.MAP_KEY:
                keys[event.path].append(event)
        if error is None and _contains_alias_or_anchor(workflow.content):
            error = "aliases or anchors make workflow ownership unresolved"
        return cls(tuple(events), dict(values), dict(keys), error)


def _unique_scalar(
    index: _Index, path: tuple[object, ...], owners: Iterable[tuple[object, ...]]
) -> tuple[str | None, Event | None, str | None]:
    keys = index.keys.get(path, ())
    leaves = index.values.get(path, ())
    if not keys and not leaves:
        # Optional fields may be absent, but a repeated empty owner mapping is
        # still ambiguous (for example two empty ``defaults`` maps).  Reject
        # duplicate ancestors without treating an absent optional ancestor as
        # an error.
        if any(len(index.keys.get(owner, ())) > 1 for owner in owners):
            return None, None, "duplicate ancestor mapping owner"
        return None, None, None
    if any(len(index.keys.get(owner, ())) != 1 for owner in owners):
        return None, None, "duplicate or missing ancestor mapping owner"
    if len(keys) != 1 or len(leaves) != 1:
        return None, None, "duplicate or non-scalar owned field"
    event = leaves[0]
    if event.merge_origins or event.value_kind not in {"plain", "quoted"}:
        return None, None, "merged or unsupported scalar field"
    if not isinstance(event.value, str):
        return None, None, "owned field is not a string scalar"
    return event.value, event, None


def _safe_directory(value: str) -> str | None:
    candidate = value.strip()
    if (
        not candidate
        or not _STATIC_DIR.fullmatch(candidate)
        or candidate.startswith("/")
        or "${{" in candidate
    ):
        return None
    normalized = posixpath.normpath(candidate)
    if normalized in {".", ".."} or normalized.startswith("../"):
        return None
    return normalized


def _under_directory(operand: str, destination: str) -> bool:
    normalized = posixpath.normpath(operand)
    try:
        return (
            posixpath.commonpath((destination, normalized)) == destination
            and normalized != destination
        )
    except ValueError:
        return False


def _step_owners(job: str, _index: int) -> tuple[tuple[object, ...], ...]:
    return (("jobs",), ("jobs", job), ("jobs", job, "steps"))


def _steps(
    index: _Index, job_names: set[str], issues: list[CoverageIssue], filepath: str
) -> list[_Step]:
    results: list[_Step] = []
    for job in sorted(job_names):
        if len(index.keys.get(("jobs", job), ())) != 1:
            issues.append(CoverageIssue(filepath, f"duplicate job mapping `{job}`"))
            continue
        step_indexes = sorted(
            {
                path[3]
                for path in set(index.keys) | set(index.values)
                if len(path) >= 5
                and path[:3] == ("jobs", job, "steps")
                and isinstance(path[3], int)
            }
        )
        for step_index in step_indexes:
            step_path = ("jobs", job, "steps", step_index)
            owners = _step_owners(job, step_index)
            fields: dict[str, Event] = {}
            for field in ("run", "uses", "shell", "working-directory", "if"):
                _value, event, error = _unique_scalar(index, step_path + (field,), owners)
                if error:
                    issues.append(
                        CoverageIssue(filepath, f"step {job}[{step_index}] {field}: {error}")
                    )
                elif event is not None:
                    fields[field] = event
            run_event = fields.get("run")
            uses_event = fields.get("uses")
            results.append(
                _Step(
                    job,
                    step_index,
                    run_event,
                    uses_event.value if uses_event and isinstance(uses_event.value, str) else None,
                    fields,
                )
            )
    return results


def _is_exact_identifier_expression(value: str, expected_path: str) -> bool:
    """Accept one direct identifier path with bounded ASCII spacing only."""
    if not value.startswith("${{") or not value.endswith("}}"):
        return False
    body = value[3:-2]
    if (
        len(body) > 128
        or not body.isascii()
        or any(character.isspace() and character not in " \t" for character in body)
    ):
        return False
    try:
        node = parse(body)
    except ExprSyntaxError:
        return False
    properties: list[str] = []
    while isinstance(node, Deref):
        properties.append(node.prop)
        node = node.recv
    if not isinstance(node, Var):
        return False
    properties.append(node.name)
    return ".".join(reversed(properties)) == expected_path


def _download_for_step(
    index: _Index, step: _Step, filepath: str, issues: list[CoverageIssue]
) -> _Download | None:
    if step.uses not in SUPPORTED_DOWNLOAD_USES:
        issues.append(
            CoverageIssue(
                filepath,
                f"unsupported download-artifact action version at {step.job}[{step.index}]",
            )
        )
        return None
    with_path = ("jobs", step.job, "steps", step.index, "with")
    owners = (*_step_owners(step.job, step.index), with_path)
    inputs: dict[str, tuple[str, Event]] = {}
    for name in _REQUIRED_INPUTS:
        value, event, error = _unique_scalar(index, with_path + (name,), owners)
        if error or event is None or value is None:
            issues.append(
                CoverageIssue(filepath, f"download input `{name}` is missing or ambiguous")
            )
            return None
        inputs[name] = (value, event)
    # v4/v5 action.yml defaults a genuinely absent repository input to
    # github.repository. Present empty, non-scalar, merged or duplicate
    # inputs cannot borrow that default. Other transfer inputs stay explicit.
    repository, repository_event, error = _unique_scalar(index, with_path + ("repository",), owners)
    if error:
        issues.append(CoverageIssue(filepath, "download repository input is ambiguous"))
        return None
    if repository_event is None:
        repository = "${{ github.repository }}"
    input_keys = {
        str(path[-1])
        for path in index.keys
        if len(path) == len(with_path) + 1 and path[: len(with_path)] == with_path
    }
    if not _REQUIRED_INPUTS <= input_keys <= _SUPPORTED_INPUTS:
        issues.append(
            CoverageIssue(filepath, "download action has unsupported or duplicate inputs")
        )
        return None
    name, path = inputs["name"][0], inputs["path"][0]
    run_id, token = inputs["run-id"][0], inputs["github-token"][0]
    destination = _safe_directory(path)
    if not _LITERAL_NAME.fullmatch(name):
        issues.append(
            CoverageIssue(filepath, "artifact name is not a single literal supported value")
        )
        return None
    if destination is None:
        issues.append(
            CoverageIssue(
                filepath,
                "download destination is dynamic or outside the supported relative path profile",
            )
        )
        return None
    if (
        not _is_exact_identifier_expression(run_id, _RUN_ID_PATH)
        or repository is None
        or not _is_exact_identifier_expression(repository, _REPOSITORY_PATH)
        or not any(_is_exact_identifier_expression(token, path) for path in _TOKEN_PATHS)
    ):
        issues.append(
            CoverageIssue(
                filepath,
                "run-id, repository, or token binding is not an exact supported expression",
            )
        )
        return None
    return _Download(step.job, step.index, name, destination, token, inputs["path"][1].line)


def _effective_shell(
    index: _Index, step: _Step, filepath: str, issues: list[CoverageIssue]
) -> bool:
    job = step.job
    if not _validate_defaults_shapes(index, job, filepath, issues):
        return False
    paths = [
        (("jobs", job, "steps", step.index, "shell"), _step_owners(job, step.index)),
        (
            ("jobs", job, "defaults", "run", "shell"),
            (
                ("jobs",),
                ("jobs", job),
                ("jobs", job, "defaults"),
                ("jobs", job, "defaults", "run"),
            ),
        ),
        (("defaults", "run", "shell"), (("defaults",), ("defaults", "run"))),
    ]
    shell = None
    for path, owners in paths:
        value, event, error = _unique_scalar(index, path, owners)
        if error:
            issues.append(CoverageIssue(filepath, "effective shell configuration is ambiguous"))
            return False
        if event is not None:
            shell = value
            break
    if shell is not None:
        if shell not in {"bash", "sh"}:
            issues.append(CoverageIssue(filepath, "effective shell is outside bash/sh profile"))
            return False
        return True
    runner, event, error = _unique_scalar(
        index, ("jobs", job, "runs-on"), (("jobs",), ("jobs", job))
    )
    if error or event is None or runner not in _SUPPORTED_RUNNERS:
        issues.append(
            CoverageIssue(
                filepath,
                "default shell cannot be established from a unique supported runner",
            )
        )
        return False
    return True


def _validate_defaults_shapes(
    index: _Index, job: str, filepath: str, issues: list[CoverageIssue]
) -> bool:
    """Refuse present defaults owners whose mapping shape is not established."""
    scopes = (
        ("workflow", ("defaults",)),
        ("job", ("jobs", job, "defaults")),
    )
    for label, path in scopes:
        direct_keys = index.keys.get(path, ())
        direct_values = index.values.get(path, ())
        child_keys = [
            candidate
            for candidate in index.keys
            if len(candidate) > len(path) and candidate[: len(path)] == path
        ]
        child_values = [
            candidate
            for candidate in index.values
            if len(candidate) > len(path) and candidate[: len(path)] == path
        ]
        present = bool(direct_keys or direct_values or child_keys or child_values)
        if not present:
            continue
        if (
            len(direct_keys) != 1
            or direct_values
            or any(isinstance(candidate[len(path)], int) for candidate in child_values)
        ):
            issues.append(CoverageIssue(filepath, f"{label} defaults is not a unique mapping"))
            return False
        child_names = {
            str(candidate[len(path)]) for candidate in child_keys if len(candidate) == len(path) + 1
        }
        if child_names != {"run"}:
            issues.append(CoverageIssue(filepath, f"{label} defaults mapping shape is unsupported"))
            return False

        run_path = path + ("run",)
        run_keys = index.keys.get(run_path, ())
        run_values = index.values.get(run_path, ())
        run_child_keys = [
            candidate
            for candidate in index.keys
            if len(candidate) > len(run_path) and candidate[: len(run_path)] == run_path
        ]
        run_child_values = [
            candidate
            for candidate in index.values
            if len(candidate) > len(run_path) and candidate[: len(run_path)] == run_path
        ]
        if (
            len(run_keys) != 1
            or run_values
            or any(isinstance(candidate[len(run_path)], int) for candidate in run_child_values)
            or not run_child_keys
        ):
            issues.append(
                CoverageIssue(filepath, f"{label} defaults.run is not a nonempty mapping")
            )
            return False
        run_names = {
            str(candidate[len(run_path)])
            for candidate in run_child_keys
            if len(candidate) == len(run_path) + 1
        }
        if not run_names <= {"shell", "working-directory"}:
            issues.append(CoverageIssue(filepath, f"{label} defaults.run has unsupported fields"))
            return False
    return True


def _owner_event_guard(index: _Index, step: _Step, filepath: str) -> tuple[bool, bool, str | None]:
    """Return exclusion and uncertainty for this job/step on workflow_run."""
    del filepath
    guards: list[str] = []
    job_guard, _event, error = _unique_scalar(
        index,
        ("jobs", step.job, "if"),
        (("jobs",), ("jobs", step.job)),
    )
    if error:
        return False, True, f"job guard is ambiguous: {error}"
    if job_guard is not None:
        guards.append(job_guard)
    step_guard_value, step_guard, error = _unique_scalar(
        index,
        ("jobs", step.job, "steps", step.index, "if"),
        _step_owners(step.job, step.index),
    )
    if error:
        return False, True, f"step guard is ambiguous: {error}"
    if step_guard is not None:
        if step_guard.value_kind not in {"plain", "quoted"} or not isinstance(
            step_guard_value, str
        ):
            return False, True, "step guard is not a supported scalar"
        guards.append(step_guard_value)
    unknown = False
    for guard in guards:
        verdict = event_guard_verdict(guard, "workflow_run")
        if verdict is False:
            return True, False, None
        unknown = unknown or verdict is None
    return False, unknown, None


def _environment_secret(index: _Index, step: _Step) -> tuple[str, ...]:
    env_path = ("jobs", step.job, "steps", step.index, "env")
    if len(index.keys.get(env_path, ())) != 1:
        return ()
    refs: list[str] = []
    for path, leaves in index.values.items():
        if len(path) != len(env_path) + 1 or path[: len(env_path)] != env_path or len(leaves) != 1:
            continue
        event = leaves[0]
        if event.merge_origins or not isinstance(event.value, str):
            continue
        match = re.fullmatch(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*}}", event.value)
        if match:
            refs.append(match.group(1))
    return tuple(sorted(set(refs)))


def _is_fixed_jq_data(command: str, destination: str) -> bool:
    """Recognize the sealed fixed-field jq data control, not code execution."""
    match = re.fullmatch(
        r"[ \t]*jq[ \t]+-r[ \t]+(?P<quote>['\"])\.status, \.summary(?P=quote)[ \t]+(?P<operand>(?:\./)?[A-Za-z0-9._/-]+)[ \t]*",
        command,
    )
    return bool(match and _under_directory(match.group("operand"), destination))


def _is_literal_digest_data(command: str, destination: str) -> bool:
    """Recognize one literal digest read; this establishes no trust check."""
    match = re.fullmatch(
        r"[ \t]*sha256sum[ \t]+(?P<operand>(?:\./)?[A-Za-z0-9._/-]+)[ \t]*",
        command,
    )
    return bool(
        match
        and not match.group("operand").startswith("-")
        and _under_directory(match.group("operand"), destination)
    )


def _possible_download_jobs(index: _Index) -> set[str]:
    """Return jobs with a structurally visible plausible download action.

    Relevance is established before trigger or unrelated command diagnostics:
    workflow_run and API/logging steps alone do not make this rule applicable.
    A plausible but unsupported action reference remains in scope for UNKNOWN.
    """
    jobs: set[str] = set()
    for event in index.events:
        path = event.path
        if (
            event.kind is EventKind.LEAF_SCALAR
            and len(path) >= 5
            and path[0] == "jobs"
            and isinstance(path[1], str)
            and path[2] == "steps"
            and isinstance(path[3], int)
            and path[4] == "uses"
            and isinstance(event.value, str)
            and "download-artifact" in event.value.casefold()
        ):
            jobs.add(path[1])
    return jobs


def _analyze_workflow(
    workflow: WorkflowSummary,
) -> tuple[list[CorpusEvidence], list[CoverageIssue]]:
    filepath = workflow.filepath
    issues: list[CoverageIssue] = []
    if "workflow_run" not in workflow.raw_event_names:
        return [], []
    index = _Index.build(workflow)
    possible_jobs = _possible_download_jobs(index)
    if index.error:
        # When ownership is damaged, keep a possible artifact endpoint UNKNOWN.
        # Otherwise an unrelated malformed workflow_run file is out of scope.
        if possible_jobs or "download-artifact" in workflow.content.casefold():
            return [], [CoverageIssue(filepath, index.error)]
        return [], []
    if not possible_jobs:
        return [], []
    if _explicit_trigger_names(workflow.content, supported_events=frozenset({"workflow_run"})) != (
        "workflow_run",
    ):
        return [], [
            CoverageIssue(
                filepath,
                "workflow_run trigger profile is malformed, aliased, or has unsupported event union",
            )
        ]
    if len(index.keys.get(("jobs",), ())) != 1:
        return [], [CoverageIssue(filepath, "jobs mapping is missing or duplicated")]
    steps = _steps(index, possible_jobs, issues, filepath)
    downloads: list[_Download] = []
    for step in steps:
        if step.uses and "download-artifact" in step.uses.casefold():
            if step.run is not None:
                issues.append(
                    CoverageIssue(
                        filepath,
                        f"download action step {step.job}[{step.index}] combines `uses` and `run`",
                    )
                )
                continue
            excluded, guard_unknown, guard_error = _owner_event_guard(index, step, filepath)
            if guard_error:
                issues.append(CoverageIssue(filepath, guard_error))
                continue
            if excluded:
                continue
            download = _download_for_step(index, step, filepath, issues)
            if download:
                download = _Download(
                    download.job,
                    download.step,
                    download.name,
                    download.destination,
                    download.token,
                    download.line,
                    guard_unknown,
                )
                downloads.append(download)
    if len(downloads) != 1:
        if len(downloads) > 1:
            issues.append(
                CoverageIssue(
                    filepath,
                    "multiple artifact downloads make source selection ambiguous",
                )
            )
        return [], issues
    download = downloads[0]
    # No container or working-directory translation is modeled.
    for path in index.keys:
        if path == ("container",) or (
            len(path) == 3
            and path[0] == "jobs"
            and path[1] == download.job
            and path[2] == "container"
        ):
            issues.append(
                CoverageIssue(
                    filepath,
                    "container execution context is outside prototype coverage",
                )
            )
            return [], issues
        if path[-1:] == ("working-directory",) and (
            path[:2] == ("defaults", "run")
            or (len(path) >= 3 and path[0] == "jobs" and path[1] == download.job)
        ):
            issues.append(
                CoverageIssue(filepath, "working-directory changes are outside prototype coverage")
            )
            return [], issues
    by_job: dict[str, list[_Step]] = defaultdict(list)
    for step in steps:
        by_job[step.job].append(step)
    candidates: list[tuple[_Step, Event, LocalFileInvocation, bool]] = []
    for step in by_job.get(download.job, []):
        if step.run is None or not isinstance(step.run.value, str):
            continue
        invocation = recognize_local_file_invocation(step.run.value)
        if invocation is None:
            if _is_fixed_jq_data(step.run.value, download.destination) or _is_literal_digest_data(
                step.run.value, download.destination
            ):
                if step.fields.get("uses") is not None:
                    issues.append(
                        CoverageIssue(
                            filepath,
                            "data run step is combined with an action invocation",
                        )
                    )
                else:
                    _effective_shell(index, step, filepath, issues)
                continue
            if download.destination in step.run.value:
                issues.append(
                    CoverageIssue(
                        filepath,
                        "command mentioning download destination uses unsupported wrapper or shell form",
                    )
                )
            continue
        if step.index <= download.step or not _under_directory(
            invocation.normalized_operand, download.destination
        ):
            continue
        excluded, guard_unknown, guard_error = _owner_event_guard(index, step, filepath)
        if guard_error:
            issues.append(CoverageIssue(filepath, guard_error))
            continue
        if excluded:
            continue
        candidates.append((step, step.run, invocation, guard_unknown))
    if len(candidates) != 1:
        if len(candidates) > 1:
            issues.append(
                CoverageIssue(
                    filepath,
                    "multiple same-job scripts under one download destination are ambiguous",
                )
            )
        return [], issues
    consumer, run_event, invocation, consumer_guard_unknown = candidates[0]
    if consumer.fields.get("uses") is not None:
        issues.append(CoverageIssue(filepath, "run step is combined with an action invocation"))
        return [], issues
    if not _effective_shell(index, consumer, filepath, issues):
        return [], issues
    intervening = [
        step for step in by_job.get(download.job, []) if download.step < step.index < consumer.index
    ]
    if any(step.run is not None or step.uses is not None for step in intervening):
        issues.append(
            CoverageIssue(
                filepath,
                "intervening executable step could change the downloaded file or path",
            )
        )
        return [], issues
    notes = [
        f"The consumer selects artifact `{download.name}` from the triggering run and invokes `{invocation.normalized_operand}` beneath `{download.destination}` in the same job.",
        "Consumer-side candidate only: producer identity, artifact member mapping, file bytes, successful execution, and PR origin remain unresolved by this prototype.",
        "A workflow_run success conclusion and actions:read permission do not establish trusted artifact provenance or write authority.",
    ]
    if download.guard_unknown:
        notes.append(
            "The download action guard requires runtime evaluation for workflow_run; the transfer is conditional."
        )
    if consumer_guard_unknown:
        notes.append(
            "The consuming job/step guard requires runtime evaluation for workflow_run; execution is conditional."
        )
    refs = _environment_secret(index, consumer)
    if refs:
        notes.append(
            "The execution step explicitly references secret(s) "
            + ", ".join(refs)
            + "; existence, effective availability, and release are not established."
        )
    line = run_event.line
    snippet = (
        workflow.lines[line - 1].strip()
        if 0 < line <= len(workflow.lines)
        else str(run_event.value)
    )
    evidence = CorpusEvidence(
        file=filepath,
        line=line,
        snippet=snippet,
        title="Downloaded workflow-run artifact is selected for script execution",
        remediation=(
            "Keep untrusted artifact contents as data, or execute them only in an isolated job without sensitive credentials. "
            "If privileged execution is required, independently verify the intended producer, event/ref/revision, artifact member and digest. "
            "A successful workflow_run conclusion, artifact name, or actions:read permission alone does not establish trusted contents."
        ),
        review_needed=True,
        context_notes=tuple(notes),
        context_tags=("workflow-run-artifact-consumer", "origin-unresolved"),
    )
    return [evidence], issues


def analyze_corpus(corpus: WorkflowCorpus) -> PrototypeResult:
    """Return bounded consumer candidates and explicit coverage gaps."""
    findings: list[CorpusEvidence] = []
    incomplete: list[CoverageIssue] = []
    for workflow in corpus.all():
        evidence, issues = _analyze_workflow(workflow)
        findings.extend(evidence)
        incomplete.extend(issues)
    return PrototypeResult(tuple(findings), tuple(incomplete))
