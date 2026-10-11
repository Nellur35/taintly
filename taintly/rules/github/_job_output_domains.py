"""Small, fail-closed proofs for fixed GitHub job-output domains.

The proof is limited to a unique job output mapped directly to one step
output, whose uniquely identified direct run step consists only of comments
or blank lines plus one fixed GITHUB_OUTPUT echo. The consumer must explicitly
need that producer. Expressions, shell programs, matrices, reusable workflows,
and ambiguous structure are not interpreted.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable

from taintly.parsers.structural import Event, EventKind, walk_workflow

_Path = tuple[object, ...]
_MISSING = object()
_EXPRESSION_OPEN_RE = re.compile(r"\x24\x7b\x7b")

_STEP_OUTPUT_MAPPING_RE = re.compile(
    r"^\x24\x7b\x7b\s*steps\.(?P<step>[A-Za-z_][A-Za-z0-9_-]*)"
    r"\.outputs\.(?P<output>[A-Za-z_][A-Za-z0-9_-]*)\s*\}\}$"
)
_FIXED_OUTPUT_ECHO_RE = re.compile(
    r"""^echo\s+(?P<quote>['"])(?P<name>[A-Za-z_][A-Za-z0-9_-]*)="""
    r"""(?P<value>[A-Za-z0-9._-]*)(?P=quote)\s*>>\s*"""
    r"""(?:"\$(?:GITHUB_OUTPUT|\{GITHUB_OUTPUT\})"|'"""
    r"""\$(?:GITHUB_OUTPUT|\{GITHUB_OUTPUT\})'|\$(?:GITHUB_OUTPUT|\{GITHUB_OUTPUT\}))$"""
)
_HOSTED_POSIX_RUNNER_RE = re.compile(r"^(?:ubuntu|macos)-(?:latest|[0-9]+(?:\.[0-9]+)?)$")
_SHELL_STARTUP_HOOK_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:BASH_ENV|ENV)(?![A-Za-z0-9_])"
    r"|(?<![A-Za-z0-9_])BASH_FUNC_"
    r"|(?<![A-Za-z0-9_])GITHUB_(?:ENV|PATH)(?![A-Za-z0-9_])"
)


class WorkflowOutputView:
    """Unique key/scalar projection of a structurally parsed workflow."""

    def __init__(self, events: Iterable[Event]) -> None:
        keys: dict[_Path, Event] = {}
        key_counts: Counter[_Path] = Counter()
        values: dict[_Path, Event] = {}
        value_counts: Counter[_Path] = Counter()

        for event in events:
            if event.kind in {EventKind.ERROR, EventKind.CUTOFF}:
                raise ValueError("workflow structure is incomplete")
            if event.kind is EventKind.MAP_KEY:
                key_counts[event.path] += 1
                keys[event.path] = event
            elif event.kind is EventKind.LEAF_SCALAR:
                value_counts[event.path] += 1
                values[event.path] = event

        # Duplicate YAML keys and alias-expanded paths have no safe
        # first/last-value interpretation for a trust proof.
        if any(count > 1 for count in key_counts.values()):
            raise ValueError("workflow contains duplicate structural keys")
        if any(count > 1 for count in value_counts.values()):
            raise ValueError("workflow contains duplicate structural values")
        self.keys = keys
        self.values = values

    def has_key(self, path: _Path) -> bool:
        return path in self.keys

    def scalar_event(self, path: _Path) -> Event | None:
        if path not in self.keys:
            return None
        event = self.values.get(path)
        return event if event is not None and isinstance(event.value, str) else None

    def scalar(self, path: _Path) -> str | object:
        event = self.scalar_event(path)
        return event.value if event is not None else _MISSING

    def direct_values(self, prefix: _Path) -> list[tuple[_Path, Event]]:
        size = len(prefix) + 1
        return [
            (path, event)
            for path, event in self.values.items()
            if len(path) == size and path[: len(prefix)] == prefix
        ]

    def has_descendant_key(self, prefix: _Path) -> bool:
        size = len(prefix)
        return any(len(path) > size and path[:size] == prefix for path in self.keys)

    def step_indices(self, job: str) -> set[int]:
        prefix = ("jobs", job, "steps")
        return {
            path[3]
            for path in self.keys
            if len(path) >= 5 and path[:3] == prefix and isinstance(path[3], int)
        }

    def needs_producer(self, consumer: str, producer: str) -> bool:
        path = ("jobs", consumer, "needs")
        if not self.has_key(path):
            return False

        scalar = self.scalar(path)
        if scalar is not _MISSING:
            return scalar == producer and not self.has_descendant_key(path)

        children = self.direct_values(path)
        if (
            not children
            or self.has_descendant_key(path)
            or any(not isinstance(child_path[-1], int) for child_path, _ in children)
        ):
            return False
        return any(event.value == producer for _, event in children)

    def shell_is_known_posix(self, job: str, step_index: int) -> bool:
        for path in (
            ("jobs", job, "steps", step_index, "shell"),
            ("jobs", job, "defaults", "run", "shell"),
            ("defaults", "run", "shell"),
        ):
            if self.has_key(path):
                value = self.scalar(path)
                return value in {"bash", "sh"} if isinstance(value, str) else False

        container_path = ("jobs", job, "container")
        if self.has_key(container_path):
            container = self.scalar(container_path)
            if container is _MISSING:
                image = self.scalar(container_path + ("image",))
                return (
                    isinstance(image, str)
                    and bool(image)
                    and _EXPRESSION_OPEN_RE.search(image) is None
                )
            return (
                isinstance(container, str)
                and bool(container)
                and _EXPRESSION_OPEN_RE.search(container) is None
            )

        runner = self.scalar(("jobs", job, "runs-on"))
        return isinstance(runner, str) and _HOSTED_POSIX_RUNNER_RE.fullmatch(runner) is not None

    def fixed_output_step(self, job: str, step_id: str, output_name: str) -> bool:
        steps_prefix = ("jobs", job, "steps")
        matching_indices: list[int] = []
        ids: list[str] = []

        for index in self.step_indices(job):
            step_prefix = steps_prefix + (index,)
            id_path = step_prefix + ("id",)
            if not self.has_key(id_path):
                continue
            value = self.scalar(id_path)
            if (
                not isinstance(value, str)
                or not value
                or _EXPRESSION_OPEN_RE.search(value) is not None
            ):
                return False
            ids.append(value)
            if value == step_id:
                matching_indices.append(index)

        if len(matching_indices) != 1 or len(set(ids)) != len(ids):
            return False

        index = matching_indices[0]
        step_prefix = steps_prefix + (index,)
        if self.has_key(step_prefix + ("uses",)):
            return False
        if not self.shell_is_known_posix(job, index):
            return False

        run_event = self.scalar_event(step_prefix + ("run",))
        if (
            run_event is None
            or run_event.value is None
            or _EXPRESSION_OPEN_RE.search(run_event.value) is not None
        ):
            return False

        commands = [
            line.strip()
            for line in run_event.value.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if len(commands) != 1:
            return False
        write = _FIXED_OUTPUT_ECHO_RE.fullmatch(commands[0])
        return bool(write and write.group("name") == output_name)

    def proves(self, consumer: str, producer: str, output_name: str) -> bool:
        if (
            not consumer
            or not producer
            or consumer == producer
            or not self.has_key(("jobs",))
            or not self.has_key(("jobs", consumer))
            or not self.has_key(("jobs", producer))
            or self.has_key(("jobs", producer, "uses"))
            or self.has_key(("jobs", producer, "strategy", "matrix"))
            or not self.needs_producer(consumer, producer)
        ):
            return False

        output_path = ("jobs", producer, "outputs", output_name)
        mapping = self.scalar(output_path)
        if not isinstance(mapping, str):
            return False
        match = _STEP_OUTPUT_MAPPING_RE.fullmatch(mapping)
        return bool(
            match and self.fixed_output_step(producer, match.group("step"), match.group("output"))
        )


def build_workflow_output_view(content: str) -> WorkflowOutputView | None:
    """Build a unique structural projection, or None when parsing is uncertain."""

    # Visible startup hooks can redefine echo or select a different shell
    # before the nominally fixed writer runs. This is suppression-only and
    # intentionally does not interpret action scripts or shell commands.
    if _SHELL_STARTUP_HOOK_TOKEN_RE.search(content):
        return None
    try:
        events = walk_workflow("anonymous.yml", content=content, recover=True, include_keys=True)
        return WorkflowOutputView(events)
    except (ValueError, TypeError):
        return None
