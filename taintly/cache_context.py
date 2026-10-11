"""Direct Actions cache sites and conservative event/access prerequisites.

Uses the shared structural index and expression AST. This is the current
GitHub.com cache-access profile, not a historical GHES policy inference.
Unresolved syntax, branch identity and cache versions remain explicit unknowns.
Reusable invocation ceilings are outside this direct-job profile.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, cast

from .authority_context import _Index
from .eventguard import event_guard_verdict

if TYPE_CHECKING:
    from .workflow_corpus import CacheRef, WorkflowSummary

_MODES = {
    "read": (True, False),
    "write": (True, True),
    "write-only": (False, True),
    "none": (False, False),
}
_DEFAULT_WRITERS = frozenset(
    {
        "push",
        "workflow_dispatch",
        "repository_dispatch",
        "delete",
        "registry_package",
        "page_build",
        "schedule",
    }
)
# The provider's event table fixes these refs to the default branch. This is
# stronger than merely requiring the workflow file to exist on that branch.
_DEFAULT_REF_EVENTS = frozenset(
    {"issue_comment", "issues", "discussion", "discussion_comment", "fork", "watch", "workflow_run"}
)
_NONDEFAULT_BASE = {
    frozenset({base, "github.event.repository.default_branch"}): False
    for base in ("github.base_ref", "github.event.pull_request.base.ref", "github.ref_name")
}


@dataclass(frozen=True)
class CacheSite:
    key: str
    restore_keys: tuple[str, ...]
    role: str
    line: int
    job: str = "?"
    guards: tuple[tuple[str, int], ...] = ()
    mode: str = "?"
    mode_line: int = 0
    ambiguous: bool = True
    lookup_only: str = ""

    def access(self, event: str, *, save: bool) -> tuple[bool | None, tuple[str, ...]]:
        """Prove absence only within complete owning context."""
        notes = [
            f"Job '{self.job}', event '{event}', cache-mode '{self.mode or 'implicit'}'"
            + (f" at line {self.mode_line}." if self.mode_line else ".")
        ]
        if self.ambiguous:
            return None, (*notes, "Cache ownership/guard/mode context is structurally unresolved.")
        if not save and self.lookup_only.lower() == "true":
            return False, (
                *notes,
                "Owned lookup-only: true checks existence without restoring content.",
            )
        if not save and self.lookup_only and self.lookup_only.lower() != "false":
            notes.append("Lookup-only value is unresolved; content restoration is conditional.")
        for guard, line in self.guards:
            verdict = event_guard_verdict(guard, event)
            notes.append(f"Owning guard at line {line}: {guard} ({verdict}).")
            if verdict is False:
                return False, tuple(notes)
        if self.mode in _MODES:
            return _MODES[self.mode][1 if save else 0], tuple(notes)
        if self.mode:
            return None, (
                *notes,
                "Cache mode is unresolved; platform schema acceptance is not established.",
            )
        if not save or event in _DEFAULT_WRITERS or event == "pull_request":
            return True, tuple(notes)
        if event in _DEFAULT_REF_EVENTS:
            return False, (
                *notes,
                "Documented event ref is the default branch; implicit low-trust cache access is read-only in the current GitHub.com profile.",
            )
        if event == "pull_request_target" and any(
            event_guard_verdict(guard, event, path_equalities=_NONDEFAULT_BASE) is False
            for guard, _ in self.guards
        ):
            return False, (
                *notes,
                "Owning guard proves default-branch base; current GitHub.com implicit low-trust cache access is read-only.",
            )
        return None, (
            *notes,
            "Default-branch identity/access restriction is unresolved; an external trigger alone does not prove a writable cache.",
        )


@lru_cache(maxsize=64)
def _sites(content: str) -> tuple[tuple[CacheSite, ...], bool, frozenset[int]]:
    index = _Index(content)
    sites = []
    for job, steps in index.steps.items():
        for step in sorted(steps, key=lambda p: cast("int", p[3])):
            uses = index.value(step + ("uses",)).lower().split("@", 1)[0]
            if uses not in {"actions/cache", "actions/cache/save", "actions/cache/restore"}:
                continue
            key_path = step + ("with", "key")
            key = index.value(key_path)
            if not key:
                continue
            key_event = index.leaves[key_path]
            mode_path: tuple[object, ...] = ("jobs", job, "cache-mode")
            if not index.has(mode_path):
                mode_path = ("cache-mode",)
            mode_event = index.keys.get(mode_path) or index.leaves.get(mode_path)
            mode = index.value(mode_path, "?") if index.has(mode_path) else ""
            guards = []
            for path in (("jobs", job, "if"), step + ("if",)):
                if index.has(path):
                    event = index.leaves.get(path) or index.keys[path]
                    guards.append((index.value(path, "?"), event.line))
            sites.append(
                CacheSite(
                    key,
                    tuple(
                        s.strip()
                        for s in index.value(step + ("with", "restore-keys")).splitlines()
                        if s.strip()
                    ),
                    {
                        "actions/cache": "both",
                        "actions/cache/save": "write",
                        "actions/cache/restore": "read",
                    }[uses],
                    key_event.line,
                    job,
                    tuple(guards),
                    mode,
                    mode_event.line if mode_event else 0,
                    index.ambiguous,
                    index.value(step + ("with", "lookup-only")),
                )
            )
    opaque = frozenset(
        line for event in index.leaves.values() for line, _ in (event.block_lines or ())
    )
    return tuple(sites), index.ambiguous, opaque


def cache_sites(workflow: WorkflowSummary) -> tuple[CacheSite, ...]:
    """Retain legacy candidates missed by an incomplete structural read."""
    structural, ambiguous, opaque = _sites(workflow.content)
    sites = list(structural)
    lines = {site.line for site in sites}
    if ambiguous:
        sites.extend(
            _unresolved(ref)
            for ref in workflow.cache_keys
            if ref.line not in lines and ref.line not in opaque
        )
    return tuple(sites)


def _unresolved(ref: CacheRef) -> CacheSite:
    return CacheSite(ref.key, ref.restore_keys, ref.role, ref.line)
