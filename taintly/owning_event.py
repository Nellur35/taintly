"""Bounded event incompatibility at direct owned Actions code inputs.

This is a liveness exclusion, not an outside-actor or credential proof. Unknown
structure, event profiles and expressions cannot justify dropping a finding.
Reusable workflows require caller context and are deliberately unsupported.
"""

from .agentguards import AgentGuardIndex
from .eventguard import event_guard_verdict
from .github_event_availability import _contains_alias_or_anchor, _explicit_trigger_names
from .parsers.structural import EventKind, walk_workflow
from .staticguard import Verdict, WorkflowContext, evaluate_if

_DIRECT_EVENTS = frozenset(
    {
        "push",
        "issues",
        "pull_request",
        "pull_request_target",
        "pull_request_review",
        "pull_request_review_comment",
        "issue_comment",
        "workflow_run",
        "workflow_dispatch",
        "repository_dispatch",
        "schedule",
        "release",
    }
)


class OwningEventExclusion:
    """One per-file structural index; only exact code-input lines can exclude."""

    def __init__(self, content: str, repoctx: WorkflowContext | None = None) -> None:
        self._repoctx = repoctx
        self._events = _explicit_trigger_names(content, supported_events=_DIRECT_EVENTS)
        self._index: AgentGuardIndex | None = None
        self._valid = False
        self._code_lines: set[int] = set()
        self._guard_kinds: dict[tuple[object, ...], str | None] = {}
        if not self._events or _contains_alias_or_anchor(content):
            return
        self._index = AgentGuardIndex(content)
        self._valid = self._index.valid
        if not self._valid:
            return
        for leaf in walk_workflow("workflow.yml", content=content, include_keys=True):
            if leaf.kind is not EventKind.LEAF_SCALAR:
                continue
            path = leaf.path
            if path[-1:] == ("if",):
                self._guard_kinds[path] = leaf.value_kind
            if (
                len(path) < 5
                or path[0] != "jobs"
                or not isinstance(path[1], str)
                or path[2] != "steps"
                or not isinstance(path[3], int)
            ):
                continue
            owner = path[:4]
            is_run = path[4:] == ("run",) and owner + ("uses",) not in self._index.keys
            uses = self._index.values.get(owner + ("uses",)) or ""
            is_script = path[4:] == ("with", "script") and uses.startswith(
                ("actions/github-script@", "actions/github-script/")
            )
            if is_run or is_script:
                self._code_lines.update((leaf.line, *(n for n, _ in (leaf.block_lines or ()))))

    def _guard_verdicts(self, line: int) -> dict[str, bool | None]:
        if (
            not self._valid
            or not self._events
            or self._index is None
            or line not in self._code_lines
        ):
            return {}
        owner = self._index.owner(line)
        if owner is None:
            return {}
        guards: list[str] = []
        for scope in (owner[:2], owner):
            path = scope + ("if",)
            if path not in self._index.keys:
                continue
            value = self._index.values.get(path)
            if (
                self._guard_kinds.get(path) not in {"plain", "quoted"}
                or value is None
                or value.strip().casefold() in {"", "null", "~"}
            ):
                return {}
            guards.append(value)
        if not guards:
            return {}
        verdicts: dict[str, bool | None] = {}
        for event in self._events:
            values: list[bool | None] = []
            for guard in guards:
                static = evaluate_if(guard, self._repoctx)
                values.append(
                    True
                    if static is Verdict.STATIC_TRUE
                    else False
                    if static is Verdict.STATIC_FALSE
                    else event_guard_verdict(guard, event)
                )
            verdicts[event] = False if False in values else None if None in values else True
        return verdicts

    def excludes_line(self, line: int) -> bool:
        """Prove job or step false on every complete declared invocation."""
        verdicts = self._guard_verdicts(line)
        return bool(verdicts) and all(verdict is False for verdict in verdicts.values())

    def unresolved_guard_note(self, line: int) -> str | None:
        """Expose unknown owning conditions without asserting execution."""
        events = [event for event, verdict in self._guard_verdicts(line).items() if verdict is None]
        if not events:
            return None
        return (
            "Owning job/step guard requires runtime evaluation for declared events: "
            + ", ".join(events)
            + ". Execution and effective consuming credentials remain unverified."
        )
