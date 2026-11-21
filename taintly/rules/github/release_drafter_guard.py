"""Review an ineffective release guard for verified Release Drafter bundles."""

from dataclasses import dataclass

from taintly.eventguard import event_guard_verdict
from taintly.github_event_availability import _explicit_trigger_names
from taintly.models import IncompletePatternMatches, Platform, Rule, Severity
from taintly.workflow_corpus import PermissionBlock, _read_permission_blocks

from ._workflow_run_artifact import (
    _Index,
    _is_exact_identifier_expression,
    _step_owners,
    _unique_scalar,
)

_ROOT = "release-drafter/release-drafter@"
# These exact root bundles never read this input. v7.0.0 and v7.1.0 still
# advertise it. v7.2.0 and v7.3.1 have removed it from the manifest.
_AFFECTED = frozenset(
    {
        _ROOT + "3a7fb5c85b80b1dda66e1ccb94009adbbd32fce3",
        _ROOT + "44a942e465867c7465b76aa808ddca6e0acae5da",
        _ROOT + "5de93583980a40bd78603b6dfdcda5b4df377b32",
        _ROOT + "693d20e7c1ce1a81d3a41962f85914253b518449",
    }
)
_PR_EVENTS = frozenset({"pull_request", "pull_request_target"})
_EVENTS = _PR_EVENTS | {"push"}
_BOOL = {"true", "false"}


def _contents(block: PermissionBlock | None) -> str:
    if block is None:
        return "unknown"
    if block.is_write_all:
        return "write"
    if block.is_read_all:
        return "read"
    return block.grants.get("contents", "none")


def _guard(index: _Index, path: tuple[object, ...]) -> tuple[str | None, bool]:
    keys = index.keys.get(path, ())
    values = index.values.get(path, ())
    if not keys and not values:
        return None, True
    if len(keys) != 1 or len(values) != 1:
        return None, False
    leaf = values[0]
    if (
        not isinstance(leaf.value, str)
        or leaf.merge_origins
        or leaf.value_kind not in {"plain", "quoted", "block_folded"}
    ):
        return None, False
    return leaf.value, True


@dataclass(frozen=True)
class _Notes:
    notes: tuple[str, ...]


class IgnoredReleaseDrafterGuard:
    def _review(
        self, content: str, lines: list[str]
    ) -> tuple[list[tuple[int, str]], list[_Notes], str | None]:
        lowered = content.lower()
        if _ROOT not in lowered or "disable-releaser" not in lowered:
            return [], [], None
        index = _Index.from_source("workflow.yml", content)
        if index.error:
            return [], [], index.error
        candidates = [
            (job, step, path)
            for path, leaves in index.values.items()
            if len(path) == 5
            and path[0] == "jobs"
            and isinstance(job := path[1], str)
            and path[2] == "steps"
            and isinstance(step := path[3], int)
            and path[4] == "uses"
            and any(
                isinstance(leaf.value, str) and leaf.value.lower() in _AFFECTED for leaf in leaves
            )
            and path[:4] + ("with", "disable-releaser") in index.keys
        ]
        if not candidates:
            return [], [], None
        triggers = _explicit_trigger_names(content, supported_events=_EVENTS)
        if triggers is None:
            return [], [], "Release Drafter trigger ownership is unresolved"
        pr_events = sorted(_PR_EVENTS.intersection(triggers))
        if not pr_events:
            return [], [], None

        permissions = _read_permission_blocks(content)
        findings: list[tuple[int, str]] = []
        notes: list[_Notes] = []
        incomplete = False
        for job, step, uses_path in candidates:
            owner = uses_path[:4]
            owners = _step_owners(job, step)
            _, uses, uses_error = _unique_scalar(index, uses_path, owners)
            inputs = (*owner, "with")
            flag_path = (*inputs, "disable-releaser")
            flag, _, flag_error = _unique_scalar(index, flag_path, (*owners, inputs))
            dry_run, _, dry_error = _unique_scalar(index, (*inputs, "dry-run"), (*owners, inputs))
            publish, _, publish_error = _unique_scalar(
                index, (*inputs, "publish"), (*owners, inputs)
            )
            token, _, token_error = _unique_scalar(index, (*inputs, "token"), (*owners, inputs))
            job_guard, job_guard_ok = _guard(index, ("jobs", job, "if"))
            step_guard, step_guard_ok = _guard(index, (*owner, "if"))
            if (
                uses_error
                or flag_error
                or dry_error
                or publish_error
                or token_error
                or uses is None
                or flag is None
                or not job_guard_ok
                or not step_guard_ok
                or (*owner, "run") in index.keys
            ):
                incomplete = True
                continue
            if dry_run == "true" or publish == "true":
                continue
            if (dry_run is not None and dry_run not in _BOOL) or (
                publish is not None and publish not in _BOOL
            ):
                incomplete = True
                continue
            active = [
                event
                for event in pr_events
                if event_guard_verdict(job_guard, event) is not False
                and event_guard_verdict(step_guard, event) is not False
            ]
            if flag.lower() in _BOOL:
                flag = flag.lower()
            if flag not in _BOOL and not (flag.startswith("${{") and flag.endswith("}}")):
                incomplete |= bool(active)
                continue
            verdicts = {event: event_guard_verdict(flag, event) for event in active}
            disabled = [event for event, verdict in verdicts.items() if verdict is True]
            incomplete |= any(verdict is None for verdict in verdicts.values())
            if not disabled:
                continue
            block = permissions.get(("jobs", job, "permissions"), permissions.get(("permissions",)))
            location = f" at line {block.line}" if block is not None else ""
            job_token = token is None or any(
                _is_exact_identifier_expression(token, path)
                for path in ("github.token", "secrets.GITHUB_TOKEN")
            )
            binding = "github.token" if job_token else "explicit input, effective scope unknown"
            flag_line = index.keys[flag_path][0].line
            if not (0 < flag_line <= len(lines) and "disable-releaser" in lines[flag_line - 1]):
                incomplete = True
                continue
            findings.append((flag_line, "disable-releaser"))
            notes.append(
                _Notes(
                    (
                        f"Job {job!r}, step {step + 1}: the pinned root action at line {uses.line} "
                        f"ignores disable-releaser for {', '.join(disabled)}. "
                        f"If this step runs it can request a draft release write.",
                        f"Configured action token: {binding}. "
                        f"Declared job Contents: {_contents(block)}{location}.",
                    )
                )
            )
        reason = "Release Drafter step context is unresolved" if incomplete else None
        return findings, notes, reason

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        matches, _, reason = self._review(content, lines)
        return IncompletePatternMatches(matches, reason=reason) if reason else matches

    def context_notes_for_matches(
        self, content: str, _filepath: str, matches: list[tuple[int, str]]
    ) -> list[_Notes | None]:
        if not matches:
            return []
        owned_matches, notes, _ = self._review(content, content.splitlines())
        if owned_matches != matches:
            return [None] * len(matches)
        return list(notes)


_PINNED_STEP = f"      - uses: {_ROOT}44a942e465867c7465b76aa808ddca6e0acae5da\n"
_PR_JOB = "on: pull_request\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n"
_DISABLE = "        with:\n          disable-releaser: true\n"

RULES = [
    Rule(
        id="SEC1-GH-004",
        title="Release Drafter ignores the configured PR release guard",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-1",
        finding_family="resource_controls",
        review_needed=True,
        confidence="medium",
        description=(
            "The selected immutable Release Drafter root bundle ignores disable-releaser. "
            "A pull request step that relies on this flag can still request draft creation "
            "or an update if it runs. The reported Contents scope comes from configuration. "
            "The effective token grant, request outcome and publication remain unverified."
        ),
        pattern=IgnoredReleaseDrafterGuard(),
        remediation=(
            "Use the dedicated autolabeler entrypoint for PR labeling and retain only its "
            "required permissions. Put draft creation in a separate trusted job and "
            "restrict its trigger and Contents write grant to that job."
        ),
        reference="https://github.com/release-drafter/release-drafter/issues/1562",
        test_positive=[_PR_JOB + _PINNED_STEP + _DISABLE],
        test_negative=[
            _PR_JOB
            + _PINNED_STEP.replace(_ROOT, "release-drafter/release-drafter/autolabeler@")
            + _DISABLE,
            _PR_JOB.replace("pull_request", "push") + _PINNED_STEP + _DISABLE,
        ],
    )
]
