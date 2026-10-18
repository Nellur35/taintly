"""GitHub Actions security rules — Dependency Chain Abuse and Poisoned Pipeline Execution.

These two categories cover the exact attack vectors used in documented supply chain campaigns.
"""

import re
from dataclasses import dataclass

from taintly.eventguard import event_guard_verdict
from taintly.github_event_availability import (
    EventSourceAvailability,
    IssueContextAvailability,
    direct_issue_expression_paths,
)
from taintly.models import (
    CompromisedActionPattern,
    ContextPattern,
    IncompletePatternMatches,
    Platform,
    RegexPattern,
    Rule,
    Severity,
)
from taintly.parsers.gha_expr import (
    ExprSyntaxError,
    context_paths,
    iter_expression_bodies,
    structural_expr_enabled,
)
from taintly.parsers.segmentation import for_each_step
from taintly.parsers.structural import Event, EventKind, triggers, walk_workflow
from taintly.platform import github_archived_check, github_sha_verify
from taintly.structural_pattern import StructuralPattern
from taintly.workflow_aware_pattern import PredicateContext

# ---------------------------------------------------------------------------
# Regex-equivalent predicates the StructuralPattern rules call.
# Kept module-local so each predicate sits next to the rule that
# uses it: structural target on the right, predicate body here.
# ---------------------------------------------------------------------------

_FULL_SHA_RE = re.compile(r"^[a-f0-9]{40}$")
_BRANCH_REF_NAMES = frozenset({"main", "master", "develop", "dev"})


_EXTERNAL_USES_RE = re.compile(r"([\w.-]+/(?:[\w.-]+/)*[\w.-]+)@([^@\s]+)\Z")
_MAX_SEC3_CONTEXT_EVENTS = 20_000


def _sec3_gh_006_occurrences(
    content: str,
    lines: list[str],
    filepath: str,
    *,
    event_limit: int | None = None,
) -> tuple[list[Event], list[tuple[Event, tuple[int, str]]], bool, bool]:
    events: list[Event] = []
    limit_hit = False
    for event in walk_workflow(
        filepath,
        content=content,
        include_keys=True,
        include_merge_origins=True,
    ):
        if event_limit is not None and len(events) >= event_limit:
            limit_hit = True
            break
        events.append(event)
    composite = filepath.replace("\\", "/").rsplit("/", 1)[-1].lower() in {
        "action.yml",
        "action.yaml",
    } and any(
        event.kind is EventKind.LEAF_SCALAR
        and event.path == ("runs", "using")
        and event.value == "composite"
        for event in events
    )
    occurrences: list[tuple[Event, tuple[int, str]]] = []
    for event in events:
        if event.kind is not EventKind.LEAF_SCALAR or event.path[-1:] != ("uses",):
            continue
        if not _GitHubUsesInventoryPattern._is_occurrence(event.path, composite=composite):
            continue
        if not _GitHubUsesInventoryPattern._is_external(event.value or ""):
            continue
        snippet = (
            lines[event.line - 1].strip() if 0 < event.line <= len(lines) else (event.value or "")
        )
        occurrences.append((event, (event.line, snippet)))
    incomplete = any(event.kind in {EventKind.ERROR, EventKind.CUTOFF} for event in events)
    return events, occurrences, incomplete, limit_hit


def _sec3_gh_006_line_owner_counts(events: list[Event]) -> dict[int, int]:
    owners_by_line: dict[int, set[tuple[object, ...]]] = {}
    for event in events:
        if event.kind not in {EventKind.LEAF_SCALAR, EventKind.MAP_KEY}:
            continue
        path = event.path
        owner: tuple[object, ...] | None = None
        if len(path) >= 2 and path[0] == "jobs" and isinstance(path[1], str):
            owner = path[:2]
            if len(path) >= 4 and path[2] == "steps" and isinstance(path[3], int):
                owner = path[:4]
        elif len(path) >= 3 and path[:2] == ("runs", "steps") and isinstance(path[2], int):
            owner = path[:3]
        elif len(path) >= 1 and isinstance(path[0], int):
            owner = path[:1]
        if owner is not None:
            owners_by_line.setdefault(event.line, set()).add(owner)
    counts = {}
    for line, owners in owners_by_line.items():
        # Job-level metadata is an ancestor of its step owners. Collapse it
        # when the same line also has a more specific structural owner so a
        # sole dead job/step remains suppressible.
        maximal = {
            owner
            for owner in owners
            if not any(len(other) > len(owner) and other[: len(owner)] == owner for other in owners)
        }
        counts[line] = len(maximal)
    return counts


def _expression_contexts(value: str) -> tuple[list[str], bool]:
    paths: list[str] = []
    unresolved = False
    bodies = list(iter_expression_bodies(value))
    for body in bodies:
        try:
            paths.extend(context_paths(body))
        except (ExprSyntaxError, RecursionError):
            unresolved = True
    if "${{" in value and not bodies:
        unresolved = True
    return sorted(set(paths)), unresolved


def _bounded_items(values: list[str], limit: int = 12, *, total_count: int | None = None) -> str:
    selected = values[:limit]
    rendered = ", ".join(selected) if selected else "none"
    omitted = (len(values) if total_count is None else total_count) - len(selected)
    if omitted:
        rendered += f" (+{omitted} omitted)"
    return rendered


def _bounded_context_note(note: str) -> str:
    if len(note) <= 500:
        return note
    marker = " [evidence truncated; remaining context omitted]"
    return note[: 500 - len(marker)] + marker


@dataclass(frozen=True)
class _InventoryOccurrenceContext:
    notes: list[str]
    owner_path: tuple[object, ...] | None
    line_owner_count: int = 1


class _GitHubUsesInventoryPattern:
    """Inventory external GitHub uses leaves without scanning arbitrary text."""

    @staticmethod
    def _is_external(value: str) -> bool:
        match = _EXTERNAL_USES_RE.fullmatch(value.strip())
        if match is None:
            return False
        package = match.group(1)
        return not (
            package.startswith(("actions/", "github/", "./", "../", "docker://"))
            or package.count("/") < 1
        )

    @staticmethod
    def _is_occurrence(path: tuple[object, ...], *, composite: bool) -> bool:
        if (
            len(path) == 5
            and path[0] == "jobs"
            and isinstance(path[1], str)
            and path[2] == "steps"
            and isinstance(path[3], int)
            and path[4] == "uses"
        ):
            return True
        if len(path) == 3 and path[0] == "jobs" and isinstance(path[1], str) and path[2] == "uses":
            return True
        if len(path) == 2 and isinstance(path[0], int) and path[1] == "uses":
            return True
        return (
            composite
            and len(path) == 4
            and path[:2] == ("runs", "steps")
            and isinstance(path[2], int)
            and path[3] == "uses"
        )

    def _check(self, content: str, lines: list[str], filepath: str) -> list[tuple[int, str]]:
        _events, occurrences, incomplete, _limit_hit = _sec3_gh_006_occurrences(
            content, lines, filepath
        )
        results = [hit for _, hit in occurrences]
        if incomplete:
            return IncompletePatternMatches(
                results, reason="structural YAML parsing reported an error or cutoff"
            )
        return results

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        return self._check(content, lines, "workflow.yml")

    def check_with_filepath(
        self, content: str, lines: list[str], filepath: str
    ) -> list[tuple[int, str]]:
        if not filepath.lower().endswith((".yml", ".yaml")):
            return []
        return self._check(content, lines, filepath)

    def context_notes_for_matches(
        self,
        content: str,
        filepath: str,
        matches: list[tuple[int, str]],
    ) -> list[_InventoryOccurrenceContext]:
        if not matches or not filepath.lower().endswith((".yml", ".yaml")):
            return []
        events, occurrences, _incomplete, limit_hit = _sec3_gh_006_occurrences(
            content,
            content.splitlines(),
            filepath,
            event_limit=_MAX_SEC3_CONTEXT_EVENTS,
        )
        if limit_hit:
            note = (
                f"Context indexing stopped at {_MAX_SEC3_CONTEXT_EVENTS} structural events; "
                "owner, permissions, and secret mapping context are unknown."
            )
            return [_InventoryOccurrenceContext([note], None) for _ in matches]
        hits = [hit for _, hit in occurrences]
        if hits != matches:
            note = (
                "Occurrence context could not be bound one-to-one to the pre-filter "
                "match list; owner, permissions, and secret mapping context are unknown."
            )
            return [_InventoryOccurrenceContext([note], None) for _ in matches]
        return _sec3_gh_006_context_notes(content, events, occurrences)


def _sec3_gh_006_context_notes(
    content: str,
    events: list[Event],
    occurrences: list[tuple[Event, tuple[int, str]]],
) -> list[_InventoryOccurrenceContext]:
    from taintly.authority_context import _Index

    index = _Index(content, events=events)
    line_owner_counts = _sec3_gh_006_line_owner_counts(events)
    if index.ambiguous:
        ambiguous_rows = []
        for event, _hit in occurrences:
            path = event.path
            if len(path) == 5 and path[0] == "jobs":
                owner = f"jobs.{path[1]}.steps[{path[3]}]"
                label = "action step"
            elif len(path) == 3 and path[0] == "jobs":
                owner = f"jobs.{path[1]}.uses"
                label = "reusable workflow call"
            elif len(path) == 2:
                owner = f"standalone sequence line {event.line}"
                label = "uses reference"
            else:
                owner = f"composite action line {event.line}"
                label = "action step"
            ambiguous_notes = [
                _bounded_context_note(
                    f"Observed external {label} at {owner}; the reference is {event.value!r}."
                ),
                "Structural ownership context is ambiguous (duplicate keys, merge provenance, "
                "parse error, cutoff, or event bound); authority and secret ownership remain unknown, "
                "and secret forwarding remains unresolved.",
            ]
            if len(path) == 3 and path[0] == "jobs":
                ambiguous_notes.append(
                    "No exact inherit or named secret mapping is attributed to this call. "
                    "GitHub reusable workflows receive github.token/GITHUB_TOKEN under the "
                    "provider contract; effective token permissions remain unknown, and "
                    "workflow-level env does not pass into the called workflow."
                )
            ambiguous_rows.append(
                _InventoryOccurrenceContext(
                    [_bounded_context_note(note) for note in ambiguous_notes],
                    path,
                    line_owner_counts.get(event.line, 1),
                )
            )
        return ambiguous_rows
    leaf_children: dict[tuple[object, ...], list[Event]] = {}
    for event in events:
        if event.kind is EventKind.LEAF_SCALAR:
            leaf_children.setdefault(event.path[:-1], []).append(event)

    complete_cache: dict[tuple[object, ...], bool] = {}

    def complete_mapping(scope: tuple[object, ...]) -> bool:
        if scope not in complete_cache:
            complete_cache[scope] = index.mapping_complete(scope)
        return complete_cache[scope]

    expression_cache: dict[str, tuple[list[str], bool]] = {}

    def expression_paths(value: str) -> tuple[list[str], bool]:
        if value not in expression_cache:
            expression_cache[value] = _expression_contexts(value)
        return expression_cache[value]

    rows: list[_InventoryOccurrenceContext] = []
    for event, _hit in occurrences:
        path = event.path
        notes: list[str] = []
        mixed_job_shape = (
            len(path) >= 2
            and path[0] == "jobs"
            and index.has(("jobs", path[1], "uses"))
            and index.has(("jobs", path[1], "steps"))
        )
        if len(path) == 5 and path[0] == "jobs" and isinstance(path[3], int):
            job, step = str(path[1]), path[3]
            notes.append(
                _bounded_context_note(
                    f"Observed external action step at jobs.{job}.steps[{step}]; "
                    f"the reference is {event.value!r}."
                )
            )
            grants = index.grants(job)
            if grants.known:
                notes.append(
                    "Declared local permission ceiling: "
                    + _bounded_items([f"{key}={value}" for key, value in grants.levels])
                    + f" (line {grants.line}); effective provider token permissions remain unknown."
                )
            else:
                notes.append(
                    "Declared local permission ceiling is ambiguous, absent, or unresolved; "
                    "effective token permissions remain unknown."
                )
            with_path = path[:-1] + ("with",)
            with_values = leaf_children.get(with_path, [])
            with_state_opaque = index.has(with_path) and not complete_mapping(with_path)
            env_scopes = [("env",), ("jobs", job, "env"), path[:-1] + ("env",)]
            env_values: list[tuple[tuple[object, ...], Event]] = []
            opaque_env_scopes: list[tuple[object, ...]] = []
            for scope in env_scopes:
                if index.has(scope) and not complete_mapping(scope):
                    opaque_env_scopes.append(scope)
                env_values.extend((scope, value) for value in leaf_children.get(scope, []))
                scalar = index.leaves.get(scope)
                if scalar is not None:
                    env_values.append((scope, scalar))
            with_fields = _bounded_items(
                [f"{value.path[-1]!s} (line {value.line})" for value in with_values[:12]],
                total_count=len(with_values),
            )
            env_fields = _bounded_items(
                [
                    f"{'.'.join(map(str, scope))}.{value.path[-1]!s} (line {value.line})"
                    for scope, value in env_values[:12]
                ],
                total_count=len(env_values),
            )
            context_paths_seen: list[str] = []
            expression_unresolved = False
            visible_values = [entry.value or "" for entry in with_values[:12]] + [
                entry.value or "" for _scope, entry in env_values[:12]
            ]
            with_scalar = index.leaves.get(with_path)
            if with_scalar is not None:
                visible_values.append(with_scalar.value or "")
            for value in visible_values:
                found, unresolved = expression_paths(value)
                context_paths_seen.extend(found)
                expression_unresolved = expression_unresolved or unresolved
            omitted_value_count = max(0, len(with_values) + len(env_values) - len(visible_values))
            unique_context_paths = sorted(set(context_paths_seen))
            opaque_notes = []
            if with_state_opaque:
                opaque_notes.append("step with map")
            if opaque_env_scopes:
                opaque_notes.append(
                    "env scope(s) "
                    + ", ".join(".".join(map(str, scope)) for scope in opaque_env_scopes)
                )
            if mixed_job_shape:
                opaque_notes.append("mixed job-level uses and steps shape")
            notes.append(
                _bounded_context_note(
                    f"Visible owning-step with keys: {with_fields}; visible workflow/job/step "
                    f"env keys: {env_fields}; expression AST context paths: "
                    f"{_bounded_items(unique_context_paths)}."
                )
            )
            if omitted_value_count:
                notes.append(
                    f"Context inspection omitted {omitted_value_count} additional with/env field(s); "
                    "their expression paths and effective bindings are unknown."
                )
            omitted_path_count = max(0, len(unique_context_paths) - 12)
            if omitted_path_count:
                notes.append(
                    f"Context path display omitted {omitted_path_count} additional expression path(s)."
                )
            if opaque_notes:
                notes.append(
                    _bounded_context_note(
                        "Visible with/env declarations are not a complete effective binding: "
                        + _bounded_items(opaque_notes)
                        + " remain ambiguous or opaque."
                    )
                )
            if expression_unresolved:
                notes.append(
                    "One or more expression bodies could not be parsed; expression context is unresolved."
                )
            notes.append(
                "Context paths do not establish value existence, release, or action consumption. "
                "Normal actions can access github.token without an explicit input; absence of a "
                "reference does not prove no token access or effective provider permissions."
            )
        elif len(path) == 3 and path[0] == "jobs":
            job = str(path[1])
            notes.append(
                _bounded_context_note(
                    f"Observed reusable workflow call at jobs.{job}.uses; "
                    f"the reference is {event.value!r}."
                )
            )
            grants = index.grants(job)
            if grants.known:
                notes.append(
                    "Caller-declared local permission ceiling: "
                    + _bounded_items([f"{key}={value}" for key, value in grants.levels])
                    + f" (line {grants.line}); the callee can narrow permissions, "
                    "while effective provider authority remains unknown."
                )
            else:
                notes.append(
                    "Caller-declared local permission ceiling is absent or unresolved; "
                    "effective provider authority remains unknown."
                )
            secrets_path = ("jobs", job, "secrets")
            secret_event = index.leaves.get(secrets_path)
            mapping_children = leaf_children.get(secrets_path, [])
            if secret_event is not None and secret_event.value == "inherit":
                notes.append(
                    f"This call declares secrets: inherit at line {secret_event.line}; "
                    "forwarding configuration does not establish secret existence, value, or release."
                )
            elif mixed_job_shape or (
                index.has(secrets_path) and not complete_mapping(secrets_path)
            ):
                notes.append(
                    "Secret forwarding remains unresolved: declaration is ambiguous or opaque; "
                    "no exact inherit or named mapping is attributed to this call."
                )
            elif mapping_children:
                declarations: list[str] = []
                for mapping in mapping_children[:12]:
                    paths, unresolved = expression_paths(mapping.value or "")
                    detail = _bounded_items(paths) if paths else "no static context path recognized"
                    suffix = "; expression unresolved" if unresolved else ""
                    declarations.append(
                        f"{mapping.path[-1]} (line {mapping.line}; value redacted; {detail}{suffix})"
                    )
                notes.append(
                    "This call declares secret forwarding fields: "
                    + _bounded_items(declarations, total_count=len(mapping_children))
                    + "."
                )
                if len(mapping_children) > 12:
                    notes.append(
                        f"Secret forwarding display omitted {len(mapping_children) - 12} additional field(s); "
                        "their individual declarations remain unreviewed."
                    )
            elif index.has(secrets_path):
                notes.append(
                    "A secrets field is present, but no named forwarding mapping could be read; "
                    "its forwarding semantics remain unresolved."
                )
            else:
                notes.append(
                    "No explicit secret-forwarding mapping is visible at this call; this does not "
                    "prove absence of GITHUB_TOKEN or effective provider authority."
                )
            notes.append(
                "Literal mapping values are redacted; configured mappings do not establish other "
                "secret existence, value, release, or callee consumption. GitHub reusable workflows "
                "receive github.token/GITHUB_TOKEN under the provider contract, while effective token "
                "permissions remain unknown. Workflow-level env does not pass into the called workflow."
            )
        elif len(path) == 2:
            notes.append(
                f"Observed external uses reference in a standalone sequence fragment at line "
                f"{event.line}; owner, permissions, and secret scope are unknown."
            )
        else:
            notes.append(
                f"Observed external action step in composite action at line {event.line}; "
                "runtime caller authority and secret scope are unknown."
            )
        if mixed_job_shape:
            notes.append(
                "The job declares both job-level uses and steps; invocation validity and ownership are unresolved."
            )
        rows.append(
            _InventoryOccurrenceContext(
                [_bounded_context_note(note) for note in notes],
                path,
                line_owner_counts.get(event.line, 1),
            )
        )
    return rows


_PR_HEAD_REF_PATHS = frozenset(
    {
        "github.event.pull_request.head.sha",
        "github.event.pull_request.head.ref",
        "github.head_ref",
    }
)
_SAFE_BASE_REF_PATHS = frozenset(
    {
        "github.ref",
        "github.ref_name",
        "github.sha",
        "github.workflow_sha",
        "github.base_ref",
        "github.event.pull_request.base.sha",
        "github.event.pull_request.base.ref",
        "github.event.merge_group.base_sha",
        "github.event.merge_group.base_ref",
    }
)
_PR_HEAD_REF_RE = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref", re.IGNORECASE
)


def _expression_context_paths(value: str) -> tuple[set[str], bool]:
    """Return canonical expression paths and whether parsing was uncertain."""
    paths: set[str] = set()
    uncertain = False
    bodies = list(iter_expression_bodies(value))
    if "${{" in value and not bodies:
        uncertain = True
    for body in bodies:
        try:
            paths.update(context_paths(body))
        except ExprSyntaxError:
            uncertain = True
    if "${{" in value and _PR_HEAD_REF_RE.search(value):
        # Preserve the existing literal form if the structural parser does not
        # understand a future expression extension or malformed interpolation.
        paths.add("github.event.pull_request.head.sha")
    return paths, uncertain


def _workflow_env_bindings(ctx: PredicateContext) -> dict[tuple[str, str], list[str]]:
    """Index only workflow/job/step env scalars used by checkout refs."""
    result: dict[tuple[str, str], list[str]] = {}
    for event in ctx.leaves:
        path = event.path
        if len(path) == 2 and path[0] == "env":
            scope = ("workflow", str(path[1]).lower())
        elif len(path) == 4 and path[0] == "jobs" and path[2] == "env":
            scope = (f"job:{path[1]}", str(path[3]).lower())
        elif (
            len(path) == 6
            and path[0] == "jobs"
            and path[2] == "steps"
            and isinstance(path[3], int)
            and path[4] == "env"
        ):
            scope = (f"step:{path[1]}:{path[3]}", str(path[5]).lower())
        else:
            continue
        result.setdefault(scope, []).append(event.value or "")
    return result


def _checkout_ref_provenance(
    value: str,
    path: tuple[object, ...],
    ctx: PredicateContext,
    bindings: dict[tuple[str, str], list[str]],
    visiting: frozenset[str] = frozenset(),
    depth: int = 0,
) -> str:
    """Classify a ref as PR-derived, known base/default, or unresolved."""
    if depth > 8:
        return "unknown"
    paths, malformed = _expression_context_paths(value)
    if paths & _PR_HEAD_REF_PATHS:
        return "untrusted"
    unknown = malformed
    job_id = str(path[1]) if len(path) >= 2 else ""
    step_index = path[3] if len(path) >= 4 and isinstance(path[3], int) else -1
    for context_path in paths:
        if context_path in _SAFE_BASE_REF_PATHS:
            continue
        if context_path.startswith("env."):
            variable = context_path.split(".", 1)[1]
            if variable in visiting:
                unknown = True
                continue
            candidates = (
                (f"step:{job_id}:{step_index}", variable),
                (f"job:{job_id}", variable),
                ("workflow", variable),
            )
            binding_values: list[str] | None = None
            for key in candidates:
                if key in bindings:
                    binding_values = bindings[key]
                    break
            if binding_values is None or len(binding_values) != 1:
                unknown = True
                continue
            resolved = _checkout_ref_provenance(
                binding_values[0],
                path,
                ctx,
                bindings,
                visiting | {variable},
                depth + 1,
            )
            if resolved == "untrusted":
                return "untrusted"
            if resolved == "unknown":
                unknown = True
            continue
        unknown = True
    return "unknown" if unknown else "safe"


def _has_pr_head_ref_source(ctx: PredicateContext) -> bool:
    """Whether any parsed workflow scalar carries an explicit PR-head ref."""
    for event in ctx.leaves:
        parts = [event.value or ""]
        if event.block_lines:
            parts.extend(text for _, text in event.block_lines)
        for value in parts:
            paths, _ = _expression_context_paths(value)
            if paths & _PR_HEAD_REF_PATHS:
                return True
    return False


def _is_untrusted_checkout_ref(
    value: str,
    _value_kind: str,
    path: tuple[object, ...],
    ctx: PredicateContext,
    bindings: dict[tuple[str, str], list[str]] | None = None,
    has_head_source: bool | None = None,
) -> bool:
    """SEC4-GH-001 sink predicate, called only for exact ``with.ref`` paths."""
    uses = ctx.step_uses(path)
    if not uses or uses.split("@", 1)[0].strip().lower() != "actions/checkout":
        return False
    if bindings is None:
        bindings = _workflow_env_bindings(ctx)
    provenance = _checkout_ref_provenance(value, path, ctx, bindings)
    if provenance == "untrusted":
        return True
    # Unknown or unsupported ref expressions stay conservative only when the
    # workflow itself has an explicit PR-head source. This avoids turning an
    # arbitrary dynamic checkout into a critical PRT finding without evidence.
    if has_head_source is None:
        has_head_source = _has_pr_head_ref_source(ctx)
    return provenance == "unknown" and has_head_source


class _PrivilegedPRCheckoutPattern:
    """Bind PR-head provenance to a real checkout input in a privileged flow."""

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        # Read the root trigger structurally: scalar, flow/block list, mapping,
        # and anchor/alias forms are equivalent. A string mention elsewhere is
        # not a privileged trigger. Skip unrelated workflows cheaply, but keep
        # walking when the trigger text is present so an earlier parser cutoff
        # remains visible even if structural trigger parsing cannot reach it.
        has_prt_trigger = "pull_request_target" in triggers(content)
        if not has_prt_trigger and "pull_request_target" not in content:
            return []
        leaves = []
        for event in walk_workflow("anonymous.yml", content=content, recover=True):
            if event.kind == EventKind.CUTOFF:
                cutoff_line = event.line
                break
            if event.kind == EventKind.LEAF_SCALAR:
                leaves.append(event)
        else:
            cutoff_line = 0

        ctx = PredicateContext(leaves=tuple(leaves))
        results: list[tuple[int, str]] = []
        if has_prt_trigger:
            bindings = _workflow_env_bindings(ctx)
            has_head_source = _has_pr_head_ref_source(ctx)
            for event in leaves:
                path = event.path
                if not (
                    len(path) == 6
                    and path[0] == "jobs"
                    and isinstance(path[1], str)
                    and path[2] == "steps"
                    and isinstance(path[3], int)
                    and path[4] == "with"
                    and path[5] == "ref"
                ):
                    continue
                if not _is_untrusted_checkout_ref(
                    event.value or "", "plain", path, ctx, bindings, has_head_source
                ):
                    continue
                line = event.line
                snippet = lines[line - 1].strip() if 0 < line <= len(lines) else event.value or ""
                results.append((line, snippet))

        if cutoff_line:
            cutoff_marker = (
                cutoff_line,
                f"STRUCTURAL-CUTOFF: structural reader stopped at "
                f"line {cutoff_line} (unsupported YAML construct); "
                "rule cannot evaluate this file fully",
            )
            results.append(cutoff_marker)
        return results


def _is_pull_request_target_trigger(
    value: str, _value_kind: str, _path: tuple[object, ...]
) -> bool:
    """SEC4-GH-002 predicate (structural). Fires when ``pull_request_target``
    is declared as a trigger under ``on:`` in ANY encoding — bare scalar,
    flow/block list item (a LEAF value), or block/flow mapping key (a MAP_KEY).
    The on:-anchored path globs scope it to real triggers, so a stray
    ``pull_request_target:`` key elsewhere, or the name appearing as a
    string-literal comparand in a defensive ``github.event_name == ...`` guard,
    does not match (the false-positive classes the old regex needed explicit
    excludes for)."""
    return value == "pull_request_target"


# First-party GitHub-published action namespaces.  The supply-chain
# threat model that motivates SEC3-GH-001 (force-push over a tag,
# maintainer compromise) applies in principle to any action; in
# practice GitHub-controlled namespaces are administered by the
# platform operator and tag-pinning here is industry-standard
# practice (every Microsoft / AWS / Google / dotnet repository in
# the corpus tag-pins these).  Firing HIGH on every
# ``actions/checkout@v4`` produces severe FP-density without
# precision gain — the same threat is more usefully reported via
# SEC3-GH-006 (third-party inventory).
# First-party action publishers — actions in these orgs are
# operationally trusted (the platform vendor itself or a vendor-
# equivalent foundation).  SEC3-GH-001 silences fires here so the
# rule's HIGH severity is reserved for genuinely third-party
# unpinned actions; SEC3-GH-006's inventory review is the right
# channel if a strict-pinning policy needs to enumerate first-party
# actions for SHA pinning.
#
# Adding to this set is a trust-posture decision — the org must be
# the documented vendor for the platforms / ecosystems we cover, not
# just a popular third-party.
_FIRST_PARTY_ACTION_ORGS = frozenset(
    {
        "actions",  # GitHub itself
        "github",  # GitHub secondary org
        "aws-actions",  # AWS official
        "azure",  # Azure / Microsoft official
        "google-github-actions",  # Google Cloud official
        "googleapis",  # Google official
        "pypa",  # Python Packaging Authority
    }
)

# Attacker-controlled GitHub-context expressions that turn an
# unguarded ``run:`` interpolation into shell injection.  Kept in
# sync with ``_TAINTED_CONTEXTS`` in ``taintly/taint.py``: any
# attacker-controlled context shape catchable by the cross-step
# taint analyzer must also be catchable directly here, otherwise
# the same byte appearing inline (without an intermediate ``env:``
# hop) goes unflagged.
_DANGEROUS_GITHUB_CONTEXT_RE = re.compile(
    r"\$\{\{\s*github\.("
    r"event\.("
    r"issue\.(title|body)|"
    r"discussion\.(title|body)|"
    r"pull_request\.(title|body|head\.(ref|label|repo\.default_branch)|user\.login)|"
    r"comment\.body|"
    r"review\.body|"
    r"review_comment\.body|"
    r"head_commit\.(message|(author|committer)\.(email|name))|"
    r"commits|"
    r"pages|"
    # ``workflow_run.head_branch`` is the branch name of the
    # upstream workflow's checkout.  For workflow_run triggered
    # by a fork PR's workflow, it carries the fork's branch
    # name -- attacker-controlled at the same layer as
    # ``head_ref``.
    r"workflow_run\.head_branch"
    r")|"
    r"head_ref"
    r")"
)


# ---------------------------------------------------------------------------
# SEC4-GH-005 — actions/checkout downstream-credential-consumer detector
# ---------------------------------------------------------------------------
#
# The previous rule fired on every actions/checkout that didn't
# explicitly set ``persist-credentials: false`` — corpus baseline
# showed ~80% of fires were FP-density (the persisted credential
# died with the runner, no later step used it).  That tradeoff is
# why the severity is LOW in the bare form (no downstream consumer).
#
# The path forward documented at the time was: fire only when a
# downstream step in the same job actually consumes the persisted
# credential.  Implementing that requires a job-scoped scan, which
# this custom pattern provides.

_CHECKOUT_USES_RE = re.compile(r"uses:\s*actions/checkout@", re.IGNORECASE)
# YAML boolean false accepts ``false``/``False``/``FALSE`` and
# ``no``/``No``/``NO``; quote the value or not.  IGNORECASE matches
# all surface forms.
_PERSIST_FALSE_RE = re.compile(
    r"""persist-credentials:\s*['"]?(?:false|no)['"]?\b""",
    re.IGNORECASE,
)
# Shell git operations that consume the persisted credential.
# - ``git push`` / ``git push origin foo``
# - ``git fetch <url>`` for cross-repo where the persisted helper is reused
# - ``git config user.email`` / ``git config user.name`` — these only
#   matter when a subsequent ``git push`` is run, but their presence
#   is a strong signal the workflow is preparing to push.
# - ``gh release create`` — uses ``GITHUB_TOKEN`` from the env, but
#   not from .git/config; intentionally NOT a consumer.
_GIT_CREDENTIAL_OP_RE = re.compile(r"\bgit\s+(?:push|fetch\s+(?:https?://|ssh://|git@))\b")
# Publishing-action candidates. Recognition alone does not establish which
# credential the implementation selects; configured tokens may be independent
# of the checkout credential. Retain the candidate without claiming that edge.
#
# Candidate names include ``peaceiris/actions-gh-pages``,
# ``crazy-max/ghaction-github-pages``, ``JamesIves/github-pages-deploy-action``,
# ``s0/git-publish-subdir-action``, ``cpina/github-action-push-to-another-repository``,
# ``ad-m/github-push-action``, ``stefanzweifel/git-auto-commit-action``,
# ``EndBug/add-and-commit``, ``peter-evans/create-pull-request``,
# ``pypa/gh-action-pypi-publish`` and ``softprops/action-gh-release``.
_GIT_PUSH_ACTION_RE = re.compile(
    r"uses:\s*(?:"
    r"peaceiris/actions-gh-pages"
    r"|ad-m/github-push-action"
    r"|stefanzweifel/git-auto-commit-action"
    r"|EndBug/add-and-commit"
    r"|crazy-max/ghaction-github-pages"
    r"|JamesIves/github-pages-deploy-action"
    r"|s0/git-publish-subdir-action"
    r"|cpina/github-action-push-to-another-repository"
    r"|peter-evans/create-pull-request"
    r"|pypa/gh-action-pypi-publish"
    r"|softprops/action-gh-release"
    r")",
    re.IGNORECASE,
)
_LINE_COMMENT_RE = re.compile(r"^\s*#")
_HEREDOC_RE = re.compile(r"<<-?\s*['\"]?([A-Za-z_][\w-]*)['\"]?")


def _credential_consumer_surface(lines: list[str]) -> str:
    """Return executable-ish lines for the credential-consumer check.

    This deliberately avoids treating comments and heredoc payload
    text as downstream credential use.  It is still regex-based, but it
    keeps SEC4-GH-005 from firing on prose or scripts merely written to
    disk.
    """
    surface: list[str] = []
    heredoc_end: str | None = None
    for line in lines:
        stripped = line.strip()
        if heredoc_end:
            if stripped == heredoc_end:
                heredoc_end = None
            continue
        if _LINE_COMMENT_RE.match(line):
            continue
        code = line.split("#", 1)[0]
        surface.append(code)
        m = _HEREDOC_RE.search(code)
        if m:
            heredoc_end = m.group(1)
    return "\n".join(surface)


class _CheckoutDownstreamCredentialConsumerPattern:
    """Pattern for SEC4-GH-005 — downstream-consumer form.

    Fires when ALL of:

    * a step uses ``actions/checkout@<ref>`` AND
    * that step does NOT explicitly set ``persist-credentials: false``
      within an 8-line lookahead AND
    * a subsequent step IN THE SAME JOB contains a possible credential
      consumer — either a ``git push`` / ``git fetch <url>`` shell op,
      OR a recognized git-pushing
      action (peaceiris/actions-gh-pages, ad-m/github-push-action,
      stefanzweifel/git-auto-commit-action, etc.).

    "Same job" is determined via ``_split_into_job_segments`` so a
    sibling job's git push doesn't false-trigger a finding on this
    job's checkout.

    Conforms to ``PatternProtocol``.
    """

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        from taintly.models import _split_into_job_segments

        results: list[tuple[int, str]] = []
        for seg_start, seg_lines in _split_into_job_segments(lines):
            seg_text = _credential_consumer_surface(seg_lines)
            has_consumer = bool(_GIT_CREDENTIAL_OP_RE.search(seg_text)) or bool(
                _GIT_PUSH_ACTION_RE.search(seg_text)
            )
            if not has_consumer:
                continue
            for j, line in enumerate(seg_lines):
                if _LINE_COMMENT_RE.match(line):
                    continue
                if not _CHECKOUT_USES_RE.search(line):
                    continue
                window = "\n".join(seg_lines[j : j + 8])
                if _PERSIST_FALSE_RE.search(window):
                    continue
                downstream = _credential_consumer_surface(seg_lines[j + 1 :])
                if not (
                    _GIT_CREDENTIAL_OP_RE.search(downstream)
                    or _GIT_PUSH_ACTION_RE.search(downstream)
                ):
                    continue
                results.append((seg_start + j + 1, line.strip()))
        return results


# Keep this posture rule's documented event scope; workflow_run provenance
# remains unknown without its parent workflow. Read declarations structurally.
_CHECKOUT_POSTURE_EVENTS = frozenset(
    {"pull_request", "pull_request_target", "issue_comment", "workflow_run"}
)


def _event_excluded_checkout_lines(content: str, events: frozenset[str]) -> set[int]:
    """Prove exclusions only at unique structural checkout/job/guard owners."""
    leaves = list(
        walk_workflow(
            "workflow.yml", content=content, include_keys=True, include_merge_origins=True
        )
    )
    if any(leaf.kind in {EventKind.ERROR, EventKind.CUTOFF} for leaf in leaves):
        return set()
    keys: set[tuple[object, ...]] = set()
    guards: dict[tuple[object, ...], str | None] = {}
    checkouts: dict[int, tuple[object, ...]] = {}
    for leaf in leaves:
        if leaf.kind is EventKind.MAP_KEY:
            if leaf.path in keys:
                return set()
            keys.add(leaf.path)
        elif leaf.kind is EventKind.LEAF_SCALAR:
            path = leaf.path
            if len(path) < 3 or path[0] != "jobs":
                continue
            if path[-1] == "if" and (len(path) == 3 or (len(path) == 5 and path[2] == "steps")):
                if leaf.merge_origins or path[:-1] in guards:
                    return set()
                guards[path[:-1]] = leaf.value
            if len(path) == 5 and path[2] == "steps" and path[-1] == "uses":
                if leaf.line in checkouts:
                    return set()
                checkouts[leaf.line] = path[:-1]
    return {
        line
        for line, step in checkouts.items()
        if all(
            event_guard_verdict(guards.get(step[:2]), event) is False
            or event_guard_verdict(guards.get(step), event) is False
            for event in events
        )
    }


class _CheckoutNoPersistPostureSiblingPattern:
    """Pattern for SEC4-GH-005B, the INFO posture sibling of SEC4-GH-005."""

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        from taintly.models import _split_into_job_segments

        # Workflow-level gate: must declare a fork-reachable trigger.
        # Without this, a push-only release workflow that legitimately
        # uses the persisted credential to push back to the repo
        # would still fire — re-creating the FP-density noise the
        # SEC4-GH-005 consumer detector was designed to eliminate.
        incomplete = any(
            leaf.kind in {EventKind.ERROR, EventKind.CUTOFF}
            for leaf in walk_workflow("workflow.yml", content=content, include_keys=True)
        )
        events = (
            _CHECKOUT_POSTURE_EVENTS if incomplete else triggers(content) & _CHECKOUT_POSTURE_EVENTS
        )
        if not events:
            return []
        excluded_lines = _event_excluded_checkout_lines(content, events)

        results: list[tuple[int, str]] = []
        for seg_start, seg_lines in _split_into_job_segments(lines):
            seg_text = _credential_consumer_surface(seg_lines)
            seg_has_consumer = bool(_GIT_CREDENTIAL_OP_RE.search(seg_text)) or bool(
                _GIT_PUSH_ACTION_RE.search(seg_text)
            )
            for j, line in enumerate(seg_lines):
                if seg_start + j + 1 in excluded_lines:
                    continue
                if _LINE_COMMENT_RE.match(line):
                    continue
                if not _CHECKOUT_USES_RE.search(line):
                    continue
                # ``persist-credentials: false`` makes this checkout
                # safe regardless of consumer presence.
                window = "\n".join(seg_lines[j : j + 8])
                if _PERSIST_FALSE_RE.search(window):
                    continue
                # If a consumer exists DOWNSTREAM of this checkout,
                # SEC4-GH-005 owns this finding — don't co-fire.
                if seg_has_consumer:
                    downstream = _credential_consumer_surface(seg_lines[j + 1 :])
                    if _GIT_CREDENTIAL_OP_RE.search(downstream) or _GIT_PUSH_ACTION_RE.search(
                        downstream
                    ):
                        continue
                results.append((seg_start + j + 1, line.strip()))
        return results


def _has_dangerous_github_context(value: str, _value_kind: str, _path: tuple[object, ...]) -> bool:
    """Predicate for SEC4-GH-004 (script injection).

    The ``**.run`` path query already filters to step ``run:``
    keys, so this predicate only needs to detect the dangerous
    GitHub-context expressions inside the shell-string value.

    Two-stage detection:
      1. The dot-literal regex ``_DANGEROUS_GITHUB_CONTEXT_RE`` — the fast
         path and the single source of truth for *which* contexts are
         dangerous.
      2. When the regex misses, parse each ``${{ }}`` body with the
         structural expression parser, normalise every context reference to a
         canonical lowercased dotted path, and re-test the SAME regex against
         that canonical form. This catches the documented-equivalent
         obfuscations the line regex is blind to — index/bracket access
         (``pull_request['title']``) and context-name case (``GITHUB.event``)
         — by reusing the regex's dangerous-path definition rather than
         duplicating it. Purely ADDITIVE: stage 2 can only add a detection,
         never remove one, and a parse error simply leaves the stage-1 result.
    """
    if _DANGEROUS_GITHUB_CONTEXT_RE.search(value):
        return True
    if not structural_expr_enabled():
        return False
    try:
        for body in iter_expression_bodies(value):
            for path in context_paths(body):
                if _DANGEROUS_GITHUB_CONTEXT_RE.search("${{ " + path + " }}"):
                    return True
    except ExprSyntaxError:
        return False
    return False


class _EventAwareScriptInjectionPattern(StructuralPattern):
    """Apply the narrow event-source absence fact to SEC4-GH-004 candidates."""

    def __init__(self) -> None:
        super().__init__(path="**.run", predicate=_has_dangerous_github_context)

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        profile: IssueContextAvailability | None = None

        def predicate(value: str, value_kind: str, path: tuple[object, ...]) -> bool:
            nonlocal profile
            if not _has_dangerous_github_context(value, value_kind, path):
                return False
            expression_info = direct_issue_expression_paths(value)
            if expression_info is None:
                return True
            paths, outside_text = expression_info
            if _DANGEROUS_GITHUB_CONTEXT_RE.search(outside_text):
                return True
            if profile is None:
                profile = IssueContextAvailability(content)
            for source_path in paths:
                field = source_path.rsplit(".", 1)[-1]
                if profile.issue_field_at(field, path) is not EventSourceAvailability.ABSENT:
                    return True
            return False

        return StructuralPattern(path="**.run", predicate=predicate).check(content, lines)


def _is_unpinned_uses_value(value: str, _value_kind: str, _path: tuple[object, ...]) -> bool:
    """Predicate for SEC3-GH-001 (unpinned action).

    Equivalent to the regex
    ``uses:\\s*([^@\\s]+)@(?![a-f0-9]{40}\\b)(\\S+)`` plus the
    historical exclude list (``./``, ``../``, ``docker://``,
    branch-ref dedup with SEC3-GH-002).
    """
    v = value.strip()
    if not v or "@" not in v:
        return False
    # Local action references (./local-action, ../shared) — not
    # remote, not a supply-chain risk in this rule's scope.
    if v.startswith(("./", "../")):
        return False
    if v.startswith("docker://"):
        return False
    head, _, ref = v.partition("@")
    if not ref:
        return False
    # First-party allowlist: platform-vendor-published action
    # namespaces are operationally trusted; SEC3-GH-006 is the right
    # channel for any inventory review of these.  GitHub matches
    # ``uses:`` owner/repo case-insensitively, so we lowercase to
    # match the set's canonical form.
    org = head.split("/", 1)[0].lower() if "/" in head else ""
    if org in _FIRST_PARTY_ACTION_ORGS:
        return False
    # Branch refs are SEC3-GH-002's CRITICAL scope; don't double-
    # report at HIGH here.
    ref_token = ref.split()[0].split("#")[0]
    if ref_token in _BRANCH_REF_NAMES:
        return False
    return not _FULL_SHA_RE.match(ref_token)


# ---------------------------------------------------------------------------
# SEC3-GH-009 — imposter-commit detection (opt-in, network-dependent)
# ---------------------------------------------------------------------------
#
# A ``uses: owner/repo@<sha>`` reference pinned to a 40-character hex
# SHA gives strong supply-chain integrity ONLY when the SHA is
# reachable from a ref in the action's repository.  When the
# maintainer force-pushes over the tag the SHA pointed at — or the SHA
# was published transiently and later garbage-collected — the
# reference resolves to an orphan commit that no audit trail covers.
# The action's repo no longer has the code review record that
# produced the SHA, and a future ref recreation could rebind the SHA
# to attacker-controlled content.
#
# The rule is opt-in (``--check-imposter-commits`` CLI flag) because
# verification requires per-action GitHub API calls; documentation
# recommends running it on a weekly cron rather than per-PR.

_USES_SHA_RE = re.compile(
    # ``uses: owner/repo@<40-char hex>`` with optional surrounding
    # whitespace and an optional trailing comment.  We require the
    # 40-char hex form because anything shorter is necessarily a tag
    # or branch (SEC3-GH-001 covers those).
    r"\buses:\s+([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)@([0-9a-fA-F]{40})\b"
)


# ---------------------------------------------------------------------------
# SEC3-GH-010 — archived-repo detection (opt-in, network-dependent)
# ---------------------------------------------------------------------------
#
# A ``uses: owner/repo@<ref>`` reference whose target repository has
# been archived on GitHub.  Archived repos are read-only — no new
# releases, no security patches, no maintainer response to compromise
# reports.  The check is opt-in via ``--check-archived-actions`` (per-
# action GitHub API calls).

_USES_OWNER_REPO_RE = re.compile(
    r"\buses:\s+([A-Za-z0-9][\w-]*)/([A-Za-z0-9][\w.-]*)(?:/[\w./-]+)?@\S+"
)


class ArchivedActionPattern:
    """Pattern for SEC3-GH-010.  Gated by
    :func:`github_archived_check.is_enabled`.  Skips first-party orgs.
    Conforms to ``PatternProtocol``."""

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        if not github_archived_check.is_enabled():
            return []
        seen: set[tuple[str, str, int]] = set()
        results: list[tuple[int, str]] = []
        for i, line in enumerate(lines):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            m = _USES_OWNER_REPO_RE.search(line)
            if not m:
                continue
            owner, repo = m.group(1), m.group(2)
            if owner.lower() in _FIRST_PARTY_ACTION_ORGS:
                continue
            key = (owner.lower(), repo.lower(), i + 1)
            if key in seen:
                continue
            seen.add(key)
            verdict = github_archived_check.is_archived(owner, repo)
            if verdict is True:
                snippet = (
                    f"{owner}/{repo} is archived on GitHub — no new releases, "
                    f"no security patches, no maintainer response to compromise."
                )
                results.append((i + 1, snippet))
        return results


class ImposterCommitPattern:
    """Pattern that fires on ``uses: owner/repo@<sha>`` whose SHA is
    not reachable from any ref in the action's repository.

    Conforms to ``PatternProtocol``: ``check(content, lines) ->
    list[(line_number, snippet)]``.

    Behaviour is gated by :func:`github_sha_verify.is_enabled`.  When
    disabled (the default), ``check`` returns ``[]`` immediately —
    the rule is silent under normal scans.  When enabled, each
    matched SHA is verified via :func:`github_sha_verify.is_sha_reachable`
    (which caches verdicts process-wide).
    """

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        if not github_sha_verify.is_enabled():
            return []
        results: list[tuple[int, str]] = []
        for i, line in enumerate(lines):
            # Comments don't reach the workflow runner — skip.
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            m = _USES_SHA_RE.search(line)
            if not m:
                continue
            owner, repo, sha = m.group(1), m.group(2), m.group(3)
            verdict = github_sha_verify.is_sha_reachable(owner, repo, sha.lower())
            if verdict is False:
                # Definitive 404 — orphan.  Indeterminate outcomes
                # (rate-limit, transport error) bypass emission so a
                # network blip never produces a false-positive SEC3
                # finding.
                snippet = (
                    f"{owner}/{repo}@{sha[:12]} not reachable from any ref "
                    f"in {owner}/{repo} (orphan SHA — force-push over tag "
                    f"or garbage-collected commit)"
                )
                results.append((i + 1, snippet))
        return results


_TRUSTED_FIRST_PARTY_OWNERS: frozenset[str] = frozenset(
    {
        "actions",  # GitHub itself
        "github",  # GitHub secondary org
        "dependabot",  # GitHub-operated (Dependabot)
        "aws-actions",  # AWS official
        "azure",  # Azure / Microsoft official
        "google-github-actions",  # Google Cloud official
        "googleapis",  # Google official
        "pypa",  # Python Packaging Authority (foundation)
    }
)


_FIRST_PARTY_OWNER_PREFIX_RE = (
    r"uses:\s*['\"]?(?:" + "|".join(sorted(_TRUSTED_FIRST_PARTY_OWNERS)) + r")/"
)


def _unpinned_classify(value: str) -> str:
    """Classify a ``uses:`` value into one of three buckets:

    * ``"third_party"`` — unpinned, owner not in
      ``_TRUSTED_FIRST_PARTY_OWNERS``.  HIGH severity (SEC3-GH-001).
    * ``"first_party"`` — unpinned, owner in
      ``_TRUSTED_FIRST_PARTY_OWNERS``.  LOW + ``review_needed=True``
      (SEC3-GH-001A) — flagged for trust-posture review, not
      confirmed risk.
    * ``""`` (empty string) — does not match the rule (pinned to
      40-char SHA, local action, docker URI, branch ref, a
      reusable-workflow call, or absent ``@``).  Caller should not fire
      either rule.
    """
    v = value.strip()
    if not v or "@" not in v:
        return ""
    if v.startswith(("./", "../")):
        return ""
    if v.startswith("docker://"):
        return ""
    head, _, ref = v.partition("@")
    if not ref:
        return ""
    # Reusable-workflow calls (owner/repo/.github/workflows/x.yml@ref)
    # are SEC8-GH-003's territory — not an action. Classifying them
    # here double-fires SEC3-GH-001 alongside SEC8-GH-003 on the same
    # unpinned line.
    if "/.github/workflows/" in head:
        return ""
    # Branch refs are SEC3-GH-002's scope; don't double-report here.
    ref_token = ref.split()[0].split("#")[0]
    if ref_token in _BRANCH_REF_NAMES:
        return ""
    if _FULL_SHA_RE.match(ref_token):
        return ""
    owner = head.split("/", 1)[0].lower()
    if owner in _TRUSTED_FIRST_PARTY_OWNERS:
        return "first_party"
    return "third_party"


def _is_unpinned_third_party_action(
    value: str, _value_kind: str, _path: tuple[object, ...]
) -> bool:
    """Predicate for SEC3-GH-001 (unpinned third-party action).

    Fires when the action's owner is NOT in
    ``_TRUSTED_FIRST_PARTY_OWNERS``.  Confirmed-risk supply-chain
    finding at HIGH severity.
    """
    return _unpinned_classify(value) == "third_party"


_UPLOAD_ARTIFACT_RE = re.compile(r"uses:\s*\S*upload-artifact", re.IGNORECASE)

# High-confidence private-secret file indicators.  Deliberately conservative:
# ``.pem`` / ``.key`` are excluded because they are just as often *public*
# certificates, which would inflate false positives.  p12/pfx/jks/keystore
# are private-key archives, so they stay.
_SECRET_FILE_RE = re.compile(
    r"(?:^|[\s/'\"=:])("
    r"\.env(?:\.[\w.-]+)?"
    r"|\.npmrc|\.netrc|\.pypirc|\.dockercfg"
    r"|id_rsa|id_ed25519|id_ecdsa|secring\.\w+"
    r"|kubeconfig|\.kube/config"
    r"|credentials(?:\.(?:json|ya?ml|ini))?"
    r"|service[-_]account[\w-]*\.json"
    r"|[\w./-]*\.(?:p12|pfx|keystore|jks)"
    r"|\.aws/|\.ssh/|\.gnupg/"
    r")(?:$|[\s/'\":,])",
    re.IGNORECASE,
)
_PATH_KEY_RE = re.compile(r"^(\s*)path\s*:\s*(.*)$")
_BLOCK_SCALAR = {"|", ">", "|-", ">-", "|+", ">+"}


class SecretsInArtifactPathPattern:
    """Fire when an ``actions/upload-artifact`` step's ``path:`` names a
    private-secret file (``.env``, ``id_rsa``, ``.npmrc``, ``credentials``,
    ``.aws/``, a keystore, …).  Uploaded artifacts are downloadable — on a
    public repo by anyone, on a fork PR by the PR author — so a secret in
    the upload set is an exfiltration channel.

    Distinct from SEC10's artifact rules (which concern *missing* artifacts
    / debug-log upload).  Matches the secret-file *pattern*, not arbitrary
    paths, so ordinary ``path: dist/`` uploads do not fire."""

    def check(self, content: str, _lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        for step in for_each_step(content):
            if not _UPLOAD_ARTIFACT_RE.search(step.text):
                continue
            in_path = False
            path_indent = -1
            for offset, line in enumerate(step.body_lines):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                m = _PATH_KEY_RE.match(line)
                if m:
                    path_indent = len(m.group(1))
                    inline = m.group(2).strip()
                    in_path = inline in _BLOCK_SCALAR or inline == ""
                    if inline and inline not in _BLOCK_SCALAR and _SECRET_FILE_RE.search(inline):
                        results.append((step.start_line + offset, stripped))
                    continue
                if in_path:
                    cur_indent = len(line) - len(line.lstrip())
                    if cur_indent <= path_indent:
                        in_path = False
                    elif _SECRET_FILE_RE.search(stripped):
                        results.append((step.start_line + offset, stripped))
        return results


RULES: list[Rule] = [
    # =========================================================================
    # SEC3-GH-011: secret file uploaded as a downloadable artifact
    # =========================================================================
    Rule(
        id="SEC3-GH-011",
        title="Private-secret file uploaded as a workflow artifact",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        review_needed=True,
        description=(
            "An ``actions/upload-artifact`` step uploads a path that names a "
            "private-secret file — a ``.env``, an SSH private key "
            "(``id_rsa``), ``.npmrc`` / ``.netrc`` credentials, a cloud "
            "``credentials`` file, a ``.aws/`` or ``.ssh/`` directory, or a "
            "key archive (``.p12``/``.pfx``/``.jks``). Workflow artifacts "
            "are downloadable — publicly on a public repo, and by the PR "
            "author on a fork pull request — so a secret in the upload set "
            "is an exfiltration channel that survives the run."
        ),
        pattern=SecretsInArtifactPathPattern(),
        remediation=(
            "Never include secret-bearing files in an artifact upload. "
            "Scope ``path:`` to build outputs only, and add an exclusion "
            "for secret patterns:\n"
            "\n"
            "    - uses: actions/upload-artifact@<sha>\n"
            "      with:\n"
            "        path: |\n"
            "          dist/\n"
            "          !**/.env\n"
            "          !**/*.p12\n"
        ),
        reference="https://docs.github.com/actions/using-workflows/storing-workflow-data-as-artifacts",
        test_positive=[
            "on: push\njobs:\n  x:\n    steps:\n"
            "      - uses: actions/upload-artifact@v4\n"
            "        with:\n          path: .env\n",
            "on: push\njobs:\n  x:\n    steps:\n"
            "      - uses: actions/upload-artifact@v4\n"
            "        with:\n          name: keys\n          path: |\n"
            "            dist/\n            secrets/id_rsa\n",
        ],
        test_negative=[
            # Ordinary build output — must not fire.
            "on: push\njobs:\n  x:\n    steps:\n"
            "      - uses: actions/upload-artifact@v4\n"
            "        with:\n          path: dist/\n",
            # Secret-looking path but NOT an upload-artifact step.
            "on: push\njobs:\n  x:\n    steps:\n      - run: cp .env /tmp/backup\n",
            # Public cert extension (.pem) is intentionally not flagged.
            "on: push\njobs:\n  x:\n    steps:\n"
            "      - uses: actions/upload-artifact@v4\n"
            "        with:\n          path: certs/server.pem\n",
        ],
        stride=["I"],
        threat_narrative=(
            "Uploading a secret file as an artifact turns a one-time "
            "in-run credential into a persistent, downloadable copy. On a "
            "public repository the artifact is world-readable; on a fork "
            "PR the very actor who opened the PR can download it — a clean "
            "exfiltration path that leaves the workflow looking green."
        ),
        confidence="high",
    ),
    # =========================================================================
    # CICD-SEC-3: Dependency Chain Abuse
    # =========================================================================
    Rule(
        id="SEC3-GH-001",
        title="Unpinned third-party action (mutable tag reference)",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "Third-party action referenced by mutable tag instead of commit SHA. Tags "
            "can be force-pushed to point at malicious code — a technique used in "
            "documented supply chain attacks against popular GitHub Actions "
            "(Trivy, Checkmarx, tj-actions)."
        ),
        pattern=StructuralPattern(
            path="**.uses",
            predicate=_is_unpinned_third_party_action,
        ),
        remediation="Pin to full 40-char commit SHA: uses: org/action@<sha> # vtag",
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
        test_positive=[
            "      - uses: aquasecurity/trivy-action@v0.33.0",
            "      - uses: tj-actions/changed-files@v40",
        ],
        test_negative=[
            "      - uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v0.33.0",
            "      - uses: ./local-action",
            "      - uses: ../shared-action",
            "      # uses: tj-actions/changed-files@v40",
            "      - uses: docker://alpine:3.18",
            # First-party orgs: covered by SEC3-GH-001A, must NOT fire here.
            "      - uses: actions/checkout@v4",
            "      - uses: aws-actions/configure-aws-credentials@v4",
            "      - uses: azure/login@v2",
            # dependabot/* is GitHub-operated — first-party (SEC3-GH-001A).
            "      - uses: dependabot/fetch-metadata@v2",
            # Reusable-workflow calls are SEC8-GH-003's territory, not here.
            "      - uses: some-org/shared/.github/workflows/ci.yml@v4",
        ],
        stride=["T"],
        threat_narrative=(
            "Mutable tags can be force-pushed to point at entirely different commits without any "
            "record in your repository's history, silently changing what code your pipeline executes. "
            "This technique was used in the Trivy, tj-actions/changed-files, and Checkmarx supply "
            "chain compromises of 2024-2026."
        ),
        incidents=[
            "Trivy supply chain (Mar 2026)",
            "tj-actions/changed-files (Mar 2025)",
            "Checkmarx (Mar 2025)",
        ],
        confidence="high",
    ),
    Rule(
        id="SEC3-GH-002",
        title="Action pinned to branch reference",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "Action referenced by branch name (e.g., @main, @master). Branch references "
            "change with every commit — any push to the branch changes what your workflow runs. "
            "This is the most dangerous form of unpinned reference."
        ),
        pattern=RegexPattern(
            match=r"uses:\s*[^@\s]+@(main|master|develop|dev)(\s*(#.*)?)?\s*$",
            exclude=[r"^\s*#", r"docker://", r"uses:\s*\./"],
        ),
        remediation="Pin to a specific commit SHA, not a branch name.",
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions",
        test_positive=[
            "      - uses: some-org/deploy@main",
            "      - uses: company/action@master",
            "      - uses: org/tool@develop",
        ],
        test_negative=[
            "      - uses: actions/checkout@57a97c7e7821a5776cebc9bb87c984fa69cba8f1",
            "      - uses: actions/checkout@v4",
            "      # uses: org/action@main",
        ],
        stride=["T"],
        threat_narrative=(
            "Branch references change with every commit, meaning any contributor to the action's "
            "repository can silently modify what your workflow runs by pushing a single commit. "
            "An attacker who gains temporary write access — via a compromised maintainer account — "
            "can substitute malicious code that runs with your workflow's full permissions and secrets."
        ),
        confidence="high",
    ),
    Rule(
        id="SEC3-GH-003",
        title="Known compromised action referenced",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "This workflow references an action that has been compromised in a documented "
            "supply chain attack. Verify you are using a confirmed safe version pinned to SHA."
        ),
        pattern=RegexPattern(
            match=r"uses:\s*(aquasecurity/trivy-action|aquasecurity/setup-trivy|Checkmarx/kics-github-action|Checkmarx/ast-github-action|tj-actions/changed-files)@",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Consult the authoritative GitHub Security Advisory for each incident before "
            "re-enabling the action. Relevant advisories:\n"
            "  - tj-actions/changed-files: GHSA-mrrh-fwg8-r2c3 / CVE-2025-30066\n"
            "  - aquasecurity/trivy-action: GHSA-69fq-xp46-6x23 (Mar 2026)\n"
            "  - Checkmarx/kics-github-action: published via the GitHub Advisory Database\n"
            "Browse: https://github.com/advisories\n"
            "\n"
            "Pin to a confirmed-safe 40-char commit SHA published after remediation, or "
            "replace with an alternative tool. Audit the workflow's full history for the "
            "window the action was present — rotate any secret that the compromised "
            "version could have exfiltrated."
        ),
        reference="https://github.com/advisories",
        test_positive=[
            "      - uses: aquasecurity/trivy-action@v0.33.0",
            "      - uses: tj-actions/changed-files@v35",
            "      - uses: Checkmarx/kics-github-action@v1.7.0",
        ],
        test_negative=[
            "      - uses: actions/checkout@v4",
            "      # uses: aquasecurity/trivy-action@v0.33.0",
        ],
        stride=["T", "I"],
        threat_narrative=(
            "This action was used in a confirmed supply chain attack where attackers modified it "
            "to silently exfiltrate CI secrets from all referencing workflows. "
            "Continuing to reference it keeps a known-compromised actor in your trust chain, "
            "even if you pin to a version predating the incident."
        ),
        incidents=[
            "Trivy supply chain (Mar 2026)",
            "tj-actions/changed-files (Mar 2025)",
            "Checkmarx (Mar 2025)",
        ],
        confidence="high",
    ),
    # =========================================================================
    # SEC3-GH-004 — known-vulnerable version of action in use (precise match)
    # =========================================================================
    #
    # Distinct from SEC3-GH-003 (always-fire on the package): this rule
    # checks the pinned ``@<ref>`` against the bundled GHSA-sourced
    # advisory list and fires only when the ref is in the affected
    # version range.  ``tj-actions/changed-files@v40`` fires both this
    # AND SEC3-GH-003 (history + active-vulnerable); ``@v46.0.1``
    # (patched) fires SEC3-GH-003 only.  See ``taintly/data/
    # compromised_actions.json`` for the bundled list and
    # ``taintly/advisories.py`` for the matcher.
    Rule(
        id="SEC3-GH-004",
        title="Action pinned to a known-vulnerable version (active GHSA advisory)",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "The workflow pins an action to a ref that falls in the "
            "affected version range of a published GitHub Security "
            "Advisory.  Bundled list refreshed at release time from "
            "``GET /advisories?ecosystem=actions``; current entries "
            "cover the tj-actions/changed-files compromises "
            "(GHSA-mrrh-fwg8-r2c3 / CVE-2025-30066 and the GHSL-2023-271 "
            "command-injection class), the Reviewdog March 2025 "
            "compromise (GHSA-qmg3-hpqr-gqvc / CVE-2025-30154), and "
            "the aquasecurity/trivy-action incidents "
            "(GHSA-69fq-xp46-6x23 / CVE-2026-33634 and "
            "GHSA-9p44-j4g5-cfx5 / CVE-2026-26189)."
        ),
        pattern=CompromisedActionPattern(
            exclude=[
                r"^\s*#",
                r"uses:\s*\./",
                r"uses:\s*\.\./",
                r"docker://",
            ],
        ),
        remediation=(
            "1. Upgrade to the action's first patched version (consult "
            "the GHSA listed in the finding's ``Code:`` field for the "
            "exact bound).\n"
            "2. After upgrading, pin to a 40-char commit SHA published "
            "AFTER the remediation commit so a future tag-force-push "
            "cannot re-introduce the vulnerable version.\n"
            "3. Audit secrets the workflow had access to during the "
            "compromise window — rotate anything the action could have "
            "read.\n"
            "4. Review the full advisory text via "
            "``https://github.com/advisories/<ghsa-id>``."
        ),
        reference="https://github.com/advisories",
        test_positive=[
            # tj-actions/changed-files Mar-2025 compromise (<= 45.0.7).
            "      - uses: tj-actions/changed-files@v40",
            "      - uses: tj-actions/changed-files@v45.0.7",
            # tj-actions GHSL-2023-271 (< 41).
            "      - uses: tj-actions/changed-files@v35",
            # Reviewdog Mar-2025 compromise (== v1).
            "      - uses: reviewdog/action-setup@v1",
            # aquasecurity/trivy-action Trivy compromise (< 0.35.0).
            "      - uses: aquasecurity/trivy-action@v0.33.0",
            # aquasecurity/setup-trivy (< 0.2.6) — same advisory.
            "      - uses: aquasecurity/setup-trivy@v0.2.0",
            # Trivy script-injection (>= 0.31.0, < 0.34.0).
            "      - uses: aquasecurity/trivy-action@v0.32.5",
        ],
        test_negative=[
            # Patched versions of the same actions — must NOT fire.
            "      - uses: tj-actions/changed-files@v46.0.1",
            "      - uses: tj-actions/changed-files@v45.0.8",
            "      - uses: aquasecurity/trivy-action@v0.35.0",
            "      - uses: aquasecurity/setup-trivy@v0.2.6",
            # Other actions entirely — never in advisory list.
            "      - uses: actions/checkout@v4",
            "      - uses: actions/setup-python@v5",
            # Local action and docker — excluded by patterns.
            "      - uses: ./local-action",
            "      - uses: docker://alpine:3.18",
            # Comment.
            "      # uses: tj-actions/changed-files@v40",
            # SHA pin — unparseable ref, conservatively does not fire.
            "      - uses: tj-actions/changed-files@a3b5c8d9e0f1234567890abcdef0123456789abcd",
            # Branch ref — unparseable, does not fire (SEC3-GH-002 covers).
            "      - uses: tj-actions/changed-files@main",
        ],
        stride=["T", "I", "E"],
        threat_narrative=(
            "An attacker who compromises a popular GitHub Action can "
            "exfiltrate every secret bound to every workflow that "
            "references it — across every consumer repository — for "
            "the duration of the attack window.  The "
            "tj-actions/changed-files March 2025 incident leaked "
            "secrets from thousands of public repositories within a "
            "single attack window because the malicious version was "
            "force-pushed onto the existing ``@v40`` / ``@v44`` mutable "
            "tags.  Pinning to a SHA published BEFORE the compromise "
            "does not save you if the SHA's content was rewritten in "
            "place via tag manipulation."
        ),
        incidents=[
            "tj-actions/changed-files (Mar 2025) — GHSA-mrrh-fwg8-r2c3",
            "tj-actions/changed-files (GHSL-2023-271) — GHSA-mcph-m25j-8j63",
            "Reviewdog (Mar 2025) — GHSA-qmg3-hpqr-gqvc",
            "Trivy supply chain (Mar 2026) — GHSA-69fq-xp46-6x23",
            "Trivy script-injection — GHSA-9p44-j4g5-cfx5",
        ],
        confidence="high",
    ),
    # =========================================================================
    # SEC3-GH-006 — third-party action inventory (review-needed)
    # =========================================================================
    #
    # Fires INFO for each parsed external action step or reusable-workflow
    # call. It also supports a narrow standalone ``- uses:`` fragment.
    #
    # Distinct from SEC3-GH-003 (always-fire on packages with confirmed
    # compromise history) and SEC3-GH-004 (fire on actually-vulnerable
    # versions): inventory has zero implicit threat assessment — it
    # surfaces the dependency surface so a human can decide.
    Rule(
        id="SEC3-GH-006",
        title="Third-party GitHub dependency referenced (inventory; review-needed)",
        severity=Severity.INFO,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        review_needed=True,
        finding_family="dependency_inventory",
        description=(
            "The workflow structurally declares an external GitHub action "
            "step or reusable-workflow call outside the ``actions/`` and "
            "``github/`` namespaces. This is dependency inventory evidence; "
            "it does not establish effective permissions, secret availability, "
            "runtime execution, or malicious behavior. Context notes report "
            "visible owner-local configuration and unresolved runtime facts."
        ),
        pattern=_GitHubUsesInventoryPattern(),
        remediation=(
            "Review the referenced action or reusable workflow's repository, "
            "publisher, and recent commits, and pin mutable references where "
            "appropriate. Each finding represents one structural occurrence; "
            "baseline and diff compare finding identities, not unique package "
            "names. If your organisation "
            "publishes its own actions under a stable namespace and you "
            "trust them, suppress with ``# taintly: ignore[SEC3-GH-006]`` "
            "on the line, or add a path-scoped ignore in ``.taintly.yml``."
        ),
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
        test_positive=[
            "      - uses: tj-actions/changed-files@v40",
            "      - uses: aquasecurity/trivy-action@v0.35.0",
            "      - uses: peter-evans/find-comment@v3",
            "      - uses: docker/build-push-action@v5",
            "      - uses: codecov/codecov-action@v3",
        ],
        test_negative=[
            # Trusted: actions/* and github/*.
            "      - uses: actions/checkout@v4",
            "      - uses: actions/setup-python@v5",
            "      - uses: github/codeql-action/init@v3",
            # Local action — not a third-party dependency.
            "      - uses: ./local-action",
            "      - uses: ../shared-action",
            # Docker image — separate concern, not in scope here.
            "      - uses: docker://alpine:3.18",
            # Comment.
            "      # uses: tj-actions/changed-files@v40",
        ],
        stride=["T"],
        threat_narrative=(
            "External action and reusable-workflow references are supply-chain "
            "dependencies. A mutable or compromised publisher reference can "
            "change what a workflow uses, but this inventory observation alone "
            "does not establish runtime execution, effective token authority, "
            "secret release, or malicious behavior. Review the owner-scoped "
            "configuration and provider/runtime prerequisites separately."
        ),
        confidence="medium",
    ),
    Rule(
        id="SEC3-GH-005",
        title="Docker container action without digest pinning",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "Docker image referenced by tag instead of SHA256 digest. Image tags are mutable "
            "and can be overwritten on the registry."
        ),
        pattern=RegexPattern(
            match=r"(image|uses):\s*docker://[^@\s]+(?!.*@sha256:)",
            exclude=[r"^\s*#", r"@sha256:"],
        ),
        remediation="Pin Docker images to digest: docker://alpine@sha256:abcdef...",
        reference="https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier",
        test_positive=[
            "      uses: docker://alpine:3.18",
            "      image: docker://node:20-slim",
        ],
        test_negative=[
            "      uses: docker://alpine@sha256:abcdef1234567890abcdef1234567890",
            "      # uses: docker://alpine:3.18",
        ],
        stride=["T"],
        threat_narrative=(
            "Image tags are mutable pointers: registry operators or attackers who compromise the "
            "image repository can push a new image under the same tag, replacing your job's execution "
            "environment without any visible change in your workflow file. "
            "A compromised container image executes with full access to all runner secrets, "
            "source code, and build artifacts."
        ),
        confidence="high",
    ),
    # =========================================================================
    # CICD-SEC-4: Poisoned Pipeline Execution
    # =========================================================================
    Rule(
        id="SEC4-GH-001",
        title="pull_request_target with untrusted PR checkout",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        review_needed=True,
        description=(
            "A structurally parsed ``actions/checkout`` step has a ``with.ref`` value bound "
            "to ``github.event.pull_request.head.sha`` or ``.head.ref`` in a "
            "``pull_request_target`` workflow. This identifies a configured PR-source "
            "checkout candidate, not proof of execution or impact. Review the owning "
            "event/job/step guard, exact action ref and ``allow-unsafe-pr-checkout`` setting, "
            "subsequent commands and local files, ``permissions``, ``persist-credentials``, "
            "and which explicit secrets are referenced and available to that same consumer."
        ),
        pattern=_PrivilegedPRCheckoutPattern(),
        remediation=(
            "Review the intended behavior before retaining PR-head checkout. Prefer "
            "``pull_request`` when base-repository access is unnecessary. For a retained "
            "``pull_request_target`` flow, confirm the exact checkout action ref and "
            "``allow-unsafe-pr-checkout`` contract; inspect the command and local files used "
            "after checkout to determine whether PR-controlled source runs or remains data. "
            "Check guards at the owning job/step, ``permissions``, ``persist-credentials``, "
            "and explicit secret references and availability for that consumer. A secret "
            "declared for a sibling job is not evidence it is available here; separate "
            "sensitive credentials from any job that executes untrusted source."
        ),
        reference="https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        test_positive=[
            "on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}",
        ],
        test_negative=[
            "on:\n  pull_request:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4",
            "on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - run: echo 'just a comment'",
        ],
        stride=["E", "I"],
        threat_narrative=(
            "When a later command executes a PR-controlled file selected by checkout, the "
            "code may run in the owning ``pull_request_target`` job. That consequence depends "
            "on the executed source, event/job/step guards, action contract, effective token "
            "permissions, credential persistence, and secrets actually referenced and "
            "available to the consumer. A checkout declaration alone does not establish "
            "execution, secret release, repository-write authority, or exfiltration; assess "
            "those configured paths before treating this candidate as impact."
        ),
        incidents=["Trivy supply chain (Mar 2026)", "Ultralytics (Dec 2024)"],
        confidence="high",
    ),
    Rule(
        id="SEC4-GH-002",
        title="pull_request_target trigger detected",
        # Severity is MEDIUM (not HIGH).  SEC4-GH-002 is the
        # BARE-TRIGGER signal (already in ``_REVIEW_NEEDED_RULES``
        # per families.py).  The actually-dangerous combination —
        # pull_request_target + checkout-of-PR-code — is covered
        # by SEC4-GH-001 [CRITICAL].  Bare-trigger detection at
        # MEDIUM keeps the signal visible without crowding the
        # HIGH bucket with known-safe trigger usage.  SEC4-GH-001
        # still escalates the
        # dangerous combination to CRITICAL.
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "The workflow declares ``pull_request_target``, which runs the workflow from the "
            "base repository context and is intended for trusted automation responding to "
            "pull requests. The event can provide an elevated ``GITHUB_TOKEN`` and "
            "repository/organization secret availability, but the effective token scopes are "
            "set by workflow/job permissions and a declaration does not show which secrets a "
            "consumer references. This trigger-level finding does not show that PR-controlled "
            "content is checked out or executed, or that any secret is released. Review "
            "intended behavior, owning event/job/step guards, commands, permission settings, "
            "and explicit credential references at their consuming steps."
        ),
        pattern=StructuralPattern(
            # Read the parsed config structurally instead of regex-matching
            # trigger shapes line-by-line. The globs cover every encoding:
            #   * ``on``                     bare scalar (``on: pull_request_target``)
            #   * ``on[*]``                  flow/block list item (LEAF value)
            #   * ``**.pull_request_target`` the trigger as a MAPPING KEY in any
            #                                position — block (``on:\n  pr_t:``)
            #                                AND flow (``on: { pr_t: {} }``) —
            #                                via the opt-in MAP_KEY events.
            # The key glob is deliberately position-independent (parity with the
            # prior ``^\s*pull_request_target\s*:`` regex, which matched the key
            # at any indent); structural matching still drops the FP classes the
            # regex needed explicit excludes for — a comment (tokenizer skips it)
            # and a string-literal comparand inside ``github.event_name == ...``
            # (that's a scalar value, not a key). Closes the flow-mapping form
            # the prior 4-branch regex missed.
            path=["on", "on[*]", "**.pull_request_target"],
            predicate=_is_pull_request_target_trigger,
            include_keys=True,
        ),
        remediation="Use ``pull_request`` where base-repository context and elevated permissions are "
        "not needed. If ``pull_request_target`` is required for trusted automation, keep "
        "PR-controlled values as data, explicitly limit token permissions, and inspect "
        "each owning job/step for a PR-head checkout, fetch, artifact, command, or secret "
        "reference. Confirm the actual credential bindings and guards there; do not "
        "assume the event declaration proves that PR source is executed or a secret is "
        "consumed.",
        reference="https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        test_positive=[
            "on:\n  pull_request_target:\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi",
            "on: pull_request_target\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi",
            "on: [pull_request_target]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi",
            "on: { pull_request_target: {} }\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi",
            "on:\n  - push\n  - pull_request_target\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi",
        ],
        test_negative=[
            "on:\n  pull_request:\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi",
            "on:\n  push:\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      # pull_request_target: in a comment is not a trigger\n      - run: echo hi",
            # FP-audit: defensive conditional that mentions the trigger
            # name as a string-literal comparand, NOT as a trigger.
            "on:\n  push:\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ (github.event_name == 'pull_request_target') && 'main' || github.sha }}\"",
            'on:\n  push:\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "event=$EVENT_NAME pull_request_target=$PRT"',
        ],
        stride=["E"],
        threat_narrative=(
            "This trigger runs the base-repository workflow and can be used for authenticated "
            "pull-request automation. It becomes a code-execution concern only if a path "
            "brings PR-controlled source to a command or tool that executes it; concrete "
            "impact also depends on that consumer's effective permissions, referenced "
            "secrets, and event/job/step guards. A trigger declaration alone does not "
            "establish those conditions or secret release."
        ),
        incidents=["Trivy supply chain (Mar 2026)"],
        confidence="high",
    ),
    Rule(
        id="SEC4-GH-003",
        title="workflow_run without conclusion check",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        review_needed=True,
        description=(
            "The file declares ``workflow_run`` but contains no recognized "
            "``github.event.workflow_run.conclusion`` reference. This file-level absence does "
            "not establish whether the owning job/step has an effective success guard or "
            "whether a downloaded artifact's producer and contents are validated. Review the "
            "consumer and any transfer path."
        ),
        pattern=ContextPattern(
            # The anchor matches the ``workflow_run`` trigger
            # DECLARATION line only, not every reference to
            # ``github.event.workflow_run.*`` later in the file.
            # Without this, the rule emits one finding per property
            # reference on a non-gated workflow_run-triggered job —
            # the missing conclusion gate is one bug, not N.
            #
            # Three accepted shapes:
            #   block-form key       ``  workflow_run:``
            #   inline shorthand     ``on: workflow_run``  (end-of-line)
            #   list form            ``on: [workflow_run, push]``
            #
            # The negative lookbehind ``(?<![.\w])`` rejects property
            # references like ``${{ github.event.workflow_run.* }}``
            # (preceded by ``.``) and identifiers that happen to end
            # in ``workflow_run`` (preceded by a word char).
            anchor=r"(?<![.\w])workflow_run\s*(?::|,|\]|$)",
            # FP-audit class A: bare ``workflow_run`` substring in
            # ``requires`` matched step names like
            # ``Trigger scheduled AMD CI via workflow_run`` and echo
            # bodies — content, not triggers.  Tighten to require a
            # real trigger-declaration shape.  ``(?m)`` because
            # ContextPattern compiles regexes without MULTILINE.
            requires=(
                r"(?m)("
                r"^\s*workflow_run\s*:"
                r"|^\s*-\s*workflow_run\s*$"
                r"|^on\s*:\s*workflow_run\s*$"
                r"|^on\s*:\s*\[[^\]]*\bworkflow_run\b[^\]]*\]"
                r")"
            ),
            requires_absent=r"workflow_run\.conclusion",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Gate the consumer on the upstream conclusion, but do not treat a successful run as a trust check. The upstream workflow may process pull-request code, and its artifacts may contain attacker-controlled data. For a parse-only consumer, use a complete job with read-only artifact access and bind the download to the triggering run:\n\njobs:\n  inspect-report:\n    if: github.event.workflow_run.conclusion == 'success'\n    runs-on: ubuntu-latest\n    permissions:\n      actions: read\n    steps:\n      - uses: actions/download-artifact@<pinned-sha>\n        with:\n          name: report\n          github-token: ${{ secrets.GITHUB_TOKEN }}\n          repository: ${{ github.repository }}\n          run-id: ${{ github.event.workflow_run.id }}\n          path: ./untrusted/\n      - name: Parse the expected report as data\n        shell: bash\n        run: jq -e '.summary | strings' ./untrusted/report.json > /dev/null\n\nDo not check out or execute `github.event.workflow_run.head_sha`, a branch name, or downloaded artifacts in this consumer. The download token, repository and run ID select the artifact source; they do not verify its producer or contents. Validate the expected producer, paths, format and allowed operations. Review the event actor, permissions and secrets separately. If a comment is needed, verify the associated pull request and post static text that does not reflect artifact content. Success is not artifact provenance. This example selects another run in the same repository. For another repository, use a credential authorized to read artifacts there; the workflow GITHUB_TOKEN is limited to its own repository."
        ),
        reference="https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        test_positive=[
            "on:\n  workflow_run:\n    workflows: [Build]\n    types: [completed]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: deploy.sh",
        ],
        test_negative=[
            "on:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest",
            "on:\n  workflow_run:\n    workflows: [Build]\n    types: [completed]\njobs:\n  deploy:\n    if: github.event.workflow_run.conclusion == 'success'\n    runs-on: ubuntu-latest",
        ],
        stride=["T"],
        threat_narrative=(
            "A workflow_run declaration without a recognized conclusion reference is a "
            "file-level missing-text observation, not proof that the consuming job lacks an "
            "effective success guard. Even when a consumer gates on ``conclusion == "
            "'success'``, that status does not establish which producer artifact was selected "
            "or whether its content is trustworthy. Review the owning job/step, exact run ID, "
            "repository, artifact name, token scope, and validation path; exposure depends on "
            "what the consumer actually downloads and does."
        ),
        confidence="high",
    ),
    Rule(
        id="SEC4-GH-004",
        title="Script injection via attacker-controlled GitHub context",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A GitHub context expression that may contain user-influenceable data is interpolated directly into a `run:` block's generated script. For contexts an untrusted actor can influence on the triggering event, shell syntax in the value can alter the script before execution. Review the exact event, field, configured shell and downstream use: the interpolation alone does not prove an external actor can reach the step, that a command executes, or that it can access credentials or permissions."
        ),
        # Structural form scopes the query to ``run:`` keys
        # directly — the path filter does the structural job that
        # the regex form's excludes (comment, ``if:`` context,
        # whole-expression-passthrough) were approximating.  Inside
        # multi-line ``run: |`` block scalars the rule fires once
        # at the block-header line rather than once per dangerous
        # interpolation, by design.
        pattern=_EventAwareScriptInjectionPattern(),
        remediation=(
            "First confirm the context value is untrusted for this event and that the step needs it. When it is data for a shell command, move the expression out of shell source and read the step environment using the configured shell. For Bash, quote the variable as a single argument; for PowerShell, use `$env:TITLE` as data:\n\n  - name: Print title (Bash)\n    shell: bash\n    env:\n      TITLE: ${{ github.event.pull_request.title }}\n    run: printf '%s\\n' \"$TITLE\"\n\n  - name: Print title (PowerShell)\n    shell: pwsh\n    env:\n      TITLE: ${{ github.event.pull_request.title }}\n    run: Write-Output $env:TITLE\n\nThis keeps the expression out of the generated script; it does not make later `eval`, `Invoke-Expression`, `bash -c`, generated code, or a downstream parser safe. Apply the consumer's proper encoding or validation only when its input format requires it. Do not treat environment routing as a universal sanitizer or isolation boundary. Run `taintly --guide SEC4-GH-004` for the full injection-vs-downstream-sanitization model."
        ),
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            '        run: echo "${{ github.event.pull_request.title }}"',
            '        run: echo "${{ github.event.issue.body }}"',
            "        run: git checkout ${{ github.head_ref }}",
            "        run: git checkout ${{ github.event.pull_request.head.ref }}",
            '        run: echo "${{ github.event.pull_request.head.label }}"',
            '        run: echo "${{ github.event.pull_request.user.login }}"',
        ],
        test_negative=[
            '        if: github.event.pull_request.title != ""',
            '        run: echo "$TITLE"',
            '        # run: echo "${{ github.event.pull_request.title }}"',
            # ref: in a with: block is an action string param, not a shell command
            "        with:\n          ref: ${{ github.head_ref }}",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Direct interpolation creates a shell-script injection candidate when the referenced context is untrusted and an actor can supply its value on this event. Whether that condition holds, what the configured shell parses, and what credentials or permissions are available require event- and job-specific review."
        ),
        incidents=["Ultralytics (Dec 2024)", "Langflow (2024)"],
        confidence="high",
    ),
    Rule(
        id="SEC4-GH-005",
        title="Checkout persists credentials before downstream Git activity",
        # Tightened from "fires on every actions/checkout without
        # persist-credentials: false" to "fires only when a downstream
        # step in the same job contains a possible credential consumer"
        # (git push/fetch or a recognized publishing action). Recognition
        # does not prove credential selection or runtime use. Severity is
        # MEDIUM; review the actual credential path. See
        # _CheckoutDownstreamCredentialConsumerPattern above for the
        # consumer detector.
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "actions/checkout is configured to persist authentication, and a later "
            "step in the same job contains `git push`, `git fetch <url>`, or a "
            "recognized publishing action. Credential storage depends on the exact "
            "checkout implementation: v4/v5 use local Git configuration; v6 "
            "introduced a separate credential file under $RUNNER_TEMP. Moving the "
            "credential does not establish isolation from later same-job code. "
            "The downstream operation may use the checkout credential, but action "
            "recognition alone does not prove that connection: a publishing action "
            "can receive its own token through inputs or environment variables. "
            "Review the exact action source and credential configuration before "
            "attributing credential use. This finding does not establish runtime "
            "execution, successful authentication, or credential disclosure."
        ),
        pattern=_CheckoutDownstreamCredentialConsumerPattern(),
        remediation=(
            "Set `persist-credentials: false` when later steps do not need checkout "
            "authentication. If a Git push or fetch needs it, preserve the required "
            "behavior with explicitly scoped, least-privilege authentication. "
            "Check publishing-action token inputs and environment separately; "
            "disabling checkout persistence does not remove an independently "
            "supplied credential."
        ),
        reference="https://github.com/actions/checkout#usage",
        test_positive=[
            # Checkout + downstream git push in the same job.
            (
                "jobs:\n  publish-pages:\n    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "      - run: |\n"
                "          git config user.email bot@example.com\n"
                "          git push origin gh-pages\n"
            ),
            # Checkout + a documented git-pushing action.
            (
                "jobs:\n  publish:\n    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "      - uses: peaceiris/actions-gh-pages@v3\n"
                "        with:\n          publish_dir: ./public\n"
            ),
        ],
        test_negative=[
            # persist-credentials: false explicitly.
            (
                "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "        with:\n          persist-credentials: false\n"
                "      - run: git push origin main\n"
            ),
            # Checkout-only; no downstream consumer — used to fire LOW,
            # now silent under the consumer-required tune.
            (
                "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "      - run: pytest\n"
            ),
            # Cross-job: sibling job pushes, but THIS job doesn't.
            (
                "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "      - run: pytest\n"
                "  publish:\n    runs-on: ubuntu-latest\n"
                "    needs: test\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "        with:\n          persist-credentials: false\n"
                "      - run: git push\n"
            ),
        ],
        stride=["I", "T"],
        threat_narrative=(
            "Persisted checkout authentication can remain accessible to later "
            "same-job code. The configured checkout may use GITHUB_TOKEN or a "
            "separately supplied credential with different authority. A downstream "
            "Git command or recognized publishing action identifies a possible "
            "consumer, not proof of which credential it uses or of exfiltration. "
            "Effective permissions, action source, execution and credential "
            "selection require separate evidence."
        ),
        confidence="high",
    ),
    # =========================================================================
    # SEC4-GH-005B: posture sibling of SEC4-GH-005.
    # =========================================================================
    Rule(
        id="SEC4-GH-005B",
        title="Checkout persists credentials under fork-reachable trigger (posture)",
        severity=Severity.INFO,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "actions/checkout persists the GITHUB_TOKEN by default "
            "(`persist-credentials: true`).  Under a fork-reachable "
            "trigger (`pull_request` / `pull_request_target` / "
            "`issue_comment` / `workflow_run`), the persisted token "
            "is reachable by any subsequent step in the same job, "
            "including third-party actions whose runtime behavior "
            "isn't fully audited at workflow-author time.\n"
            "\n"
            "This rule is a posture sibling of SEC4-GH-005: it fires "
            "INFO + review_needed when a fork-reachable workflow's "
            "checkout doesn't set `persist-credentials: false` and "
            "no in-job credential consumer was detected.  The risk "
            "is residual (a future/third-party step *might* read the "
            "token), not confirmed — SEC4-GH-005 owns the confirmed-"
            "consumer case at MEDIUM.\n"
            "\n"
            "Why a separate rule and not a SEC4-GH-005 severity "
            "downgrade?  SEC4-GH-005's May-17 precision tune removed "
            "~80% FP-density noise by requiring a proven consumer.  "
            "Re-enabling the bare-checkout firing on a downgraded "
            "severity would undo the tune.  This sibling gates on "
            "fork-reachable trigger to keep the surface narrow "
            "without losing operator visibility on the residual case."
        ),
        pattern=_CheckoutNoPersistPostureSiblingPattern(),
        remediation=(
            "Either:\n"
            "  1. Add `persist-credentials: false` to the checkout step "
            "(strongly preferred for fork-reachable workflows).\n"
            "  2. If a downstream step legitimately uses the persisted "
            "credential, accept the MEDIUM-severity SEC4-GH-005 "
            "finding instead by adding the consumer explicitly (a "
            "`git push` step or one of the documented git-pushing "
            "actions).\n"
            "  3. If neither applies, suppress this rule for the "
            "workflow via `.taintly.yml` with a documented rationale."
        ),
        reference="https://github.com/actions/checkout#usage",
        test_positive=[
            # Fork-reachable trigger, checkout without persist-creds: false,
            # NO downstream consumer.  Posture sibling fires.
            (
                "on:\n  pull_request:\n"
                "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "      - run: pytest\n"
            ),
            # pull_request_target — same shape, different trigger.
            (
                "on:\n  pull_request_target:\n"
                "jobs:\n  triage:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "      - run: echo hello\n"
            ),
        ],
        test_negative=[
            # persist-credentials: false on the checkout — safe.
            (
                "on:\n  pull_request: {}\n"
                "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "        with:\n          persist-credentials: false\n"
                "      - run: pytest\n"
            ),
            # Push-only trigger — not fork-reachable, SEC4-GH-005B does
            # not fire even with bare checkout.
            (
                "on:\n  push:\n    branches: [main]\n"
                "jobs:\n  release:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "      - run: make release\n"
            ),
            # Fork-reachable + downstream consumer → SEC4-GH-005's
            # territory; SEC4-GH-005B must NOT co-fire.
            (
                "on:\n  pull_request: {}\n"
                "jobs:\n  publish:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@v4\n"
                "      - run: git push origin gh-pages\n"
            ),
        ],
        stride=["I"],
        threat_narrative=(
            "A maintainer adds `actions/checkout` to a fork-reachable "
            "workflow (PR validation / triage) but doesn't set "
            "`persist-credentials: false`.  No current step uses the "
            "token, so SEC4-GH-005 stays silent.  Six months later a "
            "third-party action is added to the job — say a coverage "
            "uploader — that reads the `.git/config` token reference "
            "and exfiltrates it to the action's server.  The risk "
            "wasn't latent when the workflow was written; it became "
            "latent when the action was added.  This rule's INFO "
            "signal surfaces the posture so reviewers can decide "
            "whether to harden the checkout before that future risk."
        ),
        review_needed=True,
        confidence="high",
    ),
    # =========================================================================
    # SEC3-GH-007: Docker image reference (services.<name>.image: or
    # container.image:) without SHA256 digest pin.
    #
    # GitHub-side counterpart of SEC3-GL-005.  The cross-tool corpus
    # (88 labelled rows across 12 repos) measured taintly's
    # ``unpinned_image`` recall at 0.25 vs zizmor's 0.75 — every miss
    # was a GitHub workflow with a tag-pinned ``services.<svc>.image:``
    # block (postgres, redis, etc.).  This rule closes that gap.
    #
    # Same pattern as the GitLab rule: ``image: <name>:<tag>`` fires
    # when no ``@sha256:`` digest is present.  Excludes commented-out
    # lines and digests-with-tags (``alpine:3.18@sha256:abc...``).
    # =========================================================================
    Rule(
        id="SEC3-GH-007",
        title="Docker service / container image without digest pinning",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A GitHub Actions workflow references a Docker image by tag "
            "(``image: postgres:15``) under a ``services.<name>:`` or "
            "top-level ``container:`` block.  Image tags are mutable: a "
            "registry push under the same tag silently swaps what runs "
            "alongside or as the host of every job.  Pin to an immutable "
            "SHA256 digest so the registry can't change the bytes "
            "executed by a future workflow run."
        ),
        pattern=RegexPattern(
            # Match `image: <name>[:<tag>]` lines that don't contain
            # a digest reference.  The trailing ``\s*$`` (with optional
            # comment) anchors at end-of-line so we don't match
            # ``image: foo  # comment`` style annotations partial-way.
            # Allow expressions in the tag portion (``:${{ matrix.x }}``)
            # — those still resolve to a mutable tag at runtime.
            match=r"^\s*image:\s*['\"]?[a-zA-Z0-9._/-]+(?::[a-zA-Z0-9._${}\s-]+)?['\"]?\s*(#.*)?$",
            exclude=[
                r"^\s*#",
                # Digest pin in any position on the line — safe.
                r"@sha256:",
                # Bare ``image:`` block opener (no value on same line).
                r"^\s*image:\s*$",
            ],
        ),
        remediation=(
            "Pin the image to a SHA256 digest:\n"
            "  services:\n"
            "    postgres:\n"
            "      image: postgres@sha256:abcdef...\n"
            "Resolve the digest with ``docker buildx imagetools inspect``\n"
            "or ``crane digest <image>:<tag>`` and Renovate / Dependabot\n"
            "can keep it current."
        ),
        reference="https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier",
        test_positive=[
            "      image: postgres:15-alpine",
            "      image: redis:6",
            "      image: postgis/postgis:${{ matrix.postgis-version }}",
            "      image: 'ghcr.io/example/app:latest'",
        ],
        test_negative=[
            "      image: postgres@sha256:abcdef1234567890",
            "      image: alpine:3.18@sha256:abcdef1234567890",
            "      # image: postgres:15-alpine",
            "    image:",  # bare opener — not a pin reference
        ],
        stride=["T"],
        threat_narrative=(
            "An attacker who controls the upstream registry image (compromised "
            "publisher, account takeover, typosquat under a similar tag) can "
            "replace the bytes pulled by your jobs without changing the workflow "
            "file.  Service containers run alongside the job with access to job "
            "secrets via service ``env:`` and shared ``volumes``; container-runtime "
            "jobs (``container.image:``) run AS that image.  Pinning to a SHA256 "
            "digest makes the image reference immutable and breaks this attack."
        ),
        incidents=[
            # No high-profile published incident specifically for GitHub Actions
            # services-image swaps yet; the threat is the same shape as
            # ``actions/*@v4`` tag mutability (SEC3-GH-001) and the
            # general Docker-image-tag attack class.
        ],
        confidence="high",
    ),
    # =========================================================================
    # SEC3-GH-009: Imposter commit (SHA pinned to an orphan commit)
    # =========================================================================
    Rule(
        id="SEC3-GH-009",
        title="Action pinned to a SHA that is not reachable from any ref",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A ``uses: owner/repo@<sha>`` reference is pinned to a "
            "40-character hex SHA, but the SHA is not reachable from any "
            "ref (branch, tag, or open PR) in the action's repository.  "
            "Two scenarios produce this state: (1) the maintainer "
            "force-pushed over the tag the SHA originally pointed at, "
            "leaving the SHA orphaned; (2) the SHA was published "
            "transiently and later garbage-collected.  Either way, the "
            "SHA no longer has the ref-history audit trail that "
            "originally produced it.  A future ref recreation could "
            "rebind the SHA to attacker-controlled content with no "
            "warning to consumers.\n"
            "\n"
            "This rule is opt-in via ``--check-imposter-commits`` "
            "because verification requires a per-action GitHub API "
            "call; documentation recommends running it on a weekly "
            "cron rather than on every PR build."
        ),
        pattern=ImposterCommitPattern(),
        remediation=(
            "Confirm with the action's maintainers whether the SHA was\n"
            "intentionally orphaned.  If it was, repin to a current\n"
            "tag-reachable SHA and document the rotation.  If the\n"
            "maintainers do not respond, treat the action as untrusted\n"
            "and pin to a fork at a vetted SHA under your own account.\n"
            "\n"
            "Run ``taintly --guide SEC3-GH-009`` for the full checklist."
        ),
        reference=(
            "https://docs.github.com/en/actions/security-for-github-actions/"
            "security-guides/security-hardening-for-github-actions#using-third-party-actions"
        ),
        # Empty inline samples — verification requires a real or
        # stubbed verifier, exercised by tests/unit/test_imposter_commits.py.
        test_positive=[],
        test_negative=[],
        stride=["T", "S"],
        threat_narrative=(
            "An attacker who controls the action's repository (compromised "
            "maintainer account, account takeover) force-pushes the tag "
            "the SHA originally referenced.  The SHA itself remains "
            "valid for fetches until GitHub garbage-collects unreachable "
            "objects.  After GC, the SHA returns 404 — but consumers "
            "pinning to it have no automated way to learn that.  In the "
            "interim, an attacker who can recreate a ref pointing back "
            "at the SHA can also rebind it to fresh, attacker-supplied "
            "content if they win the race against GC."
        ),
        confidence="high",
        review_needed=True,
        finding_family="action_pin_drift",
    ),
    # =========================================================================
    # SEC3-GH-010: Archived action repository (opt-in, network-dependent)
    # =========================================================================
    Rule(
        id="SEC3-GH-010",
        title="Action references an archived GitHub repository",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        review_needed=True,
        confidence="high",
        description=(
            "A ``uses: owner/repo@<ref>`` reference points to a GitHub "
            "repository that is archived (read-only).  Archived repos "
            "receive no new releases, no security patches, and the "
            "maintainer is not actively monitoring compromise reports.  "
            "A vulnerability disclosed against an archived action is "
            "unlikely to be fixed; a maintainer-account compromise "
            "against an archived repo may go unnoticed indefinitely.\n"
            "\n"
            "This rule is opt-in via ``--check-archived-actions`` "
            "because verification requires a per-action GitHub API "
            "call (``GET /repos/{owner}/{repo}`` reading the "
            "``archived`` flag).  Recommended on a weekly cron rather "
            "than per-PR.  First-party orgs (``actions``, ``github``, "
            "``aws-actions``, ``azure``, etc.) are skipped — the "
            "platform vendors don't archive their own action repos."
        ),
        pattern=ArchivedActionPattern(),
        remediation=(
            "Migrate to a maintained fork or an alternative action that "
            "covers the same functionality.  Check the archived repo's "
            "README for a recommended successor; if none, search the "
            "GitHub Marketplace for actions with similar inputs.  If no "
            "alternative exists and the action is critical, fork it "
            "into your own org so security patches can be applied "
            "in-house — pinning to your fork's SHA makes the supply-"
            "chain explicit."
        ),
        reference="https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories",
        test_positive=[],
        test_negative=[
            # When the flag is disabled (the default), the pattern
            # returns [] and no positives are needed.
        ],
        stride=["T", "I"],
        threat_narrative=(
            "Archived action repositories are abandoned supply-chain "
            "surface.  When a CVE is published against an archived "
            "action, the disclosure-to-patch interval is unbounded — "
            "no maintainer is on the other end to triage.  An attacker "
            "with the dormant maintainer account can publish a new "
            "tag that downstream consumers will silently pick up if "
            "they aren't SHA-pinned; the archived flag prevents the "
            "owner from accepting external PRs but doesn't prevent the "
            "owner themselves from pushing fresh content.  Migrating "
            "off archived dependencies is the cheapest mitigation."
        ),
        finding_family="action_pin_drift",
    ),
    # =========================================================================
    # SEC3-GH-013: Privileged/release job restores a poisonable build cache
    # =========================================================================
    # The CONSUME/sink side of cache poisoning.  (The WRITE/poison side --
    # granting ``actions: write`` so a step can mutate caches -- is AI-GH-023's
    # job; this rule is its complement and the two can co-occur.)  A job that
    # restores a build cache AND holds release/write privilege trusts bytes that
    # a separate, less-trusted workflow run (a fork PR build, a branch a
    # contributor can push) could have written under the same cache key.  GitHub
    # Actions caches are shared across a repository's workflows with only
    # branch-scoped read restrictions, so a cache populated by an attacker-
    # influenced run can be restored into a privileged build and execute under
    # the production trigger's permissions and secrets.  The malicious bytes
    # live in a cache blob, not in git, so the attack survives PR review.
    # Field grounding: Cacheract (Adnan Khan, Dec 2024); Angular dev-infra
    # compromise (Dec 2025).  Whether an untrusted ref can actually reach the
    # same cache key is NOT statically decidable, so this is MEDIUM + review-
    # needed: it surfaces the cache-into-privileged-build shape for a human to
    # confirm the key scoping, rather than asserting a confident finding.
    Rule(
        id="SEC3-GH-013",
        title="Privileged or release job restores a build cache that a less-trusted workflow can poison",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A job restores a build cache (``actions/cache``, or a setup / "
            "build action that caches -- ``setup-go``, ``Swatinem/rust-cache``, "
            "``gradle-build-action``, or any ``setup-*`` with ``cache:`` "
            "enabled) AND that same job holds an exfil/release privilege "
            "(``id-token: write``, ``contents`` / ``packages`` / "
            "``deployments: write``, ``write-all``, or a publish step -- "
            "``npm publish``, ``goreleaser``, ``docker push``, "
            "``gh release``, a PyPI/release action). GitHub Actions caches are "
            "shared across a repository's workflows; a cache key populated by a "
            "less-trusted run (a fork pull-request build, or any workflow a "
            "contributor can trigger) is restored verbatim into this privileged "
            "build, so attacker-controlled cache bytes execute with the "
            "production job's token and secrets. Because the payload lives in a "
            "cache blob rather than in the repository, it is invisible to anyone "
            "reviewing the pull request. This is the cache-poisoning sink that "
            "Cacheract (Dec 2024) and the Angular dev-infra compromise "
            "(Dec 2025) weaponised."
        ),
        pattern=ContextPattern(
            # Anchor: genuine cache usage in the job.  ``setup-go`` and the
            # rust/gradle cache actions cache by default; ``setup-node`` /
            # ``setup-python`` / ``setup-java`` only cache when ``cache:`` is
            # set, so those are matched via the ``cache:`` key, not the bare
            # ``uses:`` line (which would over-fire on every repo).
            anchor=(
                r"uses:\s*actions/cache(?:/restore)?@"
                r"|uses:\s*actions/setup-go@"
                r"|uses:\s*Swatinem/rust-cache@"
                r"|uses:\s*gradle/(?:gradle-build-action|actions/setup-gradle)@"
                r"|^\s*cache:\s*['\"]?(?:true|npm|yarn|pip|pnpm|gradle|maven|sbt|poetry|gomod)\b"
            ),
            # Requires (same job): a release / write privilege.  Permissions can
            # sit at job level (in the segment) or workflow level (folded into
            # the first job's segment); the publish-step signals are always
            # job-local.
            requires=(
                r"id-token:\s*write"
                r"|(?:contents|packages|deployments)\s*:\s*write"
                r"|permissions:\s*write-all"
                r"|\b(?:npm\s+publish|twine\s+upload|goreleaser|docker\s+push"
                r"|gh\s+release\s+(?:create|upload))\b"
                r"|uses:\s*(?:softprops/action-gh-release|docker/build-push-action"
                r"|actions/deploy-pages|pypa/gh-action-pypi-publish"
                r"|ncipollo/release-action|goreleaser/goreleaser-action)@"
            ),
            scope="job",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Treat a restored cache as untrusted input to a privileged build:\n"
            "\n"
            "1. Scope cache keys so a less-trusted run cannot populate the key "
            "   a privileged build restores. Include a trusted discriminator in "
            "   the key (e.g. the protected ref / a content hash of vetted "
            "   inputs), and avoid broad ``restore-keys:`` prefixes that fall "
            "   back to a fork-populated entry.\n"
            "2. Split the pipeline: build/cache untrusted code in a job with no "
            "   secrets and no write token, and do the privileged release in a "
            "   separate job that does NOT restore that cache (or restores only "
            "   a cache it produced itself in the same run).\n"
            "3. Verify integrity before use -- restore into a scratch dir and "
            "   validate a signed manifest of the cached contents.\n"
            "4. Minimise the blast radius: keep ``actions: write`` off the "
            "   workflow (see AI-GH-023) so no step can mutate caches via the "
            "   GitHub API in the first place."
        ),
        reference="https://adnanthekhan.com/2024/12/21/cacheract-the-monster-in-your-actions-cache/",
        test_positive=[
            # goreleaser release job: setup-go (default cache) + contents:write
            # + a release action.
            "jobs:\n  goreleaser:\n    runs-on: ubuntu-latest\n"
            "    permissions:\n      contents: write\n"
            "    steps:\n      - uses: actions/setup-go@v5\n"
            "      - uses: goreleaser/goreleaser-action@v6\n",
            # explicit actions/cache restore + id-token:write + npm publish.
            "jobs:\n  publish:\n    runs-on: ubuntu-latest\n"
            "    permissions:\n      id-token: write\n"
            "    steps:\n      - uses: actions/cache@v4\n"
            "        with:\n          path: ~/.npm\n          key: npm-cache\n"
            "      - run: npm publish\n",
            # setup-node with cache: enabled + packages:write + docker push.
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    permissions:\n      packages: write\n"
            "    steps:\n      - uses: actions/setup-node@v4\n"
            "        with:\n          node-version: 20\n          cache: npm\n"
            "      - run: docker push ghcr.io/org/app:latest\n",
        ],
        test_negative=[
            # Cache in a plain test job with no privilege -- not a sink.
            "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
            "    permissions:\n      contents: read\n"
            "    steps:\n      - uses: actions/setup-go@v5\n"
            "      - run: go test ./...\n",
            # Privileged publish job with NO cache -- nothing to poison.
            "jobs:\n  publish:\n    runs-on: ubuntu-latest\n"
            "    permissions:\n      id-token: write\n"
            "    steps:\n      - run: npm publish\n",
            # setup-node WITHOUT caching (no cache: key) in a release job.
            "jobs:\n  publish:\n    runs-on: ubuntu-latest\n"
            "    permissions:\n      contents: write\n"
            "    steps:\n      - uses: actions/setup-node@v4\n"
            "        with:\n          node-version: 20\n      - run: npm publish\n",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker opens a fork pull request whose build job populates a "
            "shared cache key (lockfile-hash keys collide across the fork and "
            "the base repo). Later, a privileged release workflow on the "
            "default branch restores that key, and the attacker's cached "
            "build artefact -- a poisoned ``node_modules``, a tampered Go "
            "module cache, a swapped compiler plugin -- executes with the "
            "release job's ``id-token``/write token and secrets. The repo "
            "owner sees only innocent YAML in the PR; the payload is in the "
            "cache blob."
        ),
        confidence="medium",
        review_needed=True,
        incidents=[
            "https://adnanthekhan.com/2024/12/21/cacheract-the-monster-in-your-actions-cache/"
        ],
    ),
]
