"""Bounded source analysis for secret-derived file selection in an artifact upload.

A match is conditional on the
configured steps executing and the referenced secret being available; it does
not establish file contents, action behavior, audience, transfer, or disclosure.
"""

from __future__ import annotations

import re

from taintly.composer import _certified_composer_events
from taintly.eventguard import event_guard_verdict
from taintly.models import IncompletePatternMatches, Platform, Rule, Severity
from taintly.parsers.structural import Event, EventKind, walk_workflow
from taintly.parsers.structural.tokenizer import TokenKind, tokenize
from taintly.rules.github.secret_cache import _ROOT, _path, _scoped_env

_UPLOAD = "actions/upload-artifact"
_GLOB = re.compile(r"[*?\[]")
_SECRET_REF = re.compile(r"\s*\$\{\{\s*secrets\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}\s*\Z")
_SECRET_HINT = re.compile(r"\b(?:secrets\s*(?:\.|\[)|github\.token\b)", re.IGNORECASE)
_VAR_STATE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
_SINGLE_QUOTED_FMT = r"(?P<single_format>(?:[^'\\\r\n]|\\n)*)"
_DOUBLE_QUOTED_FMT = r'(?P<double_format>(?:[^"\\$`\r\n]|\\n)*)'
_PRINTF_FMT = rf"(?:'{_SINGLE_QUOTED_FMT}'|\"{_DOUBLE_QUOTED_FMT}\")"
_PRINTF_SECRET = re.compile(
    r"^[ \t]*printf[ \t]+"
    + _PRINTF_FMT
    + r"[ \t]+\"(?P<var>\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\}))\"[ \t]+>[ \t]*(?P<path>[A-Za-z0-9_./-]+)[ \t]*$"
)
_PRINTF_LITERAL = re.compile(
    r"^[ \t]*printf[ \t]+" + _PRINTF_FMT + r"[ \t]+>[ \t]*(?P<path>[A-Za-z0-9_./-]+)[ \t]*$"
)
_MKDIR = re.compile(r"^[ \t]*mkdir[ \t]+-p[ \t]+[A-Za-z0-9_./-]+[ \t]*$")
_SUPPORTED_UPLOAD_REFS = {"v4", "v5", "v6", "v7"}


def _event_map(events: tuple[Event, ...]):
    keys: dict[tuple[object, ...], list[Event]] = {}
    leaves: dict[tuple[object, ...], list[Event]] = {}
    for event in events:
        if event.kind is EventKind.MAP_KEY:
            keys.setdefault(event.path, []).append(event)
        elif event.kind is EventKind.LEAF_SCALAR:
            leaves.setdefault(event.path, []).append(event)
    return keys, leaves


def _single(leaves: dict[tuple[object, ...], list[Event]], path: tuple[object, ...]):
    matches = leaves.get(path, [])
    return matches[0] if len(matches) == 1 and not matches[0].merge_origins else None


def _env_fields(keys, leaves, tokens):
    """Collect only direct env scalars and retain present unsupported owner shapes."""
    fields: dict[tuple[object, ...], dict[str, str]] = {}
    invalid_owners: set[tuple[object, ...]] = set()
    invalid_values: set[tuple[tuple[object, ...], str]] = set()
    unknown_source_owners: set[tuple[object, ...]] = set()
    ambiguous = False
    env_paths = [path for path in keys if path[-1:] == ("env",)]
    for env_path in env_paths:
        owner = env_path[:-1]
        shape = _value_shape(keys, leaves, tokens, env_path)
        if shape != "mapping":
            invalid_owners.add(owner)
            if _subtree_has_secret_hint(env_path, leaves):
                unknown_source_owners.add(owner)
            continue
        names = {
            path[len(env_path)]
            for path in (*keys.keys(), *leaves.keys())
            if len(path) == len(env_path) + 1
            and path[: len(env_path)] == env_path
            and isinstance(path[-1], str)
        }
        for name in names:
            variable_path = (*env_path, name)
            value_shape = _value_shape(keys, leaves, tokens, variable_path)
            events = leaves.get(variable_path, [])
            if value_shape != "scalar":
                invalid_values.add((owner, name))
                if _subtree_has_secret_hint(variable_path, leaves):
                    unknown_source_owners.add(owner)
                continue
            if len(events) != 1 or events[0].merge_origins:
                ambiguous = True
                continue
            fields.setdefault(owner, {})[name] = events[0].value or ""
    return fields, ambiguous, invalid_owners, invalid_values, unknown_source_owners


def _env_scope_owners(job: str, step: int) -> tuple[tuple[object, ...], ...]:
    return (), ("jobs", job), ("jobs", job, "steps", step)


def _env_has_unknown_source(unknown_source_owners, job: str, step: int) -> bool:
    return any(owner in unknown_source_owners for owner in _env_scope_owners(job, step))


def _env_binding_is_unknown(
    invalid_owners, invalid_values, job: str, step: int, variable: str
) -> bool:
    owners = _env_scope_owners(job, step)
    return any(owner in invalid_owners for owner in owners) or any(
        (owner, variable) in invalid_values for owner in owners
    )


def _subtree_has_secret_hint(path: tuple[object, ...], leaves) -> bool:
    return any(
        len(candidate) >= len(path)
        and candidate[: len(path)] == path
        and any(_SECRET_HINT.search(event.value or "") for event in events)
        for candidate, events in leaves.items()
    )


def _layered_env(fields, job: str, step: int) -> dict[str, str]:
    result = dict(fields.get((), {}))
    result.update(fields.get(("jobs", job), {}))
    result.update(fields.get(("jobs", job, "steps", step), {}))
    return result


def _secret_state(raw_env: dict[str, str], name: str) -> bool | None:
    """True = directly declared secret source, False = literal non-secret, None = unknown."""
    value = raw_env.get(name)
    if value is None:
        return False
    if _SECRET_REF.fullmatch(value):
        return True
    if "${{" in value or _SECRET_HINT.search(value):
        return None
    return False


_SUPPORTED_GUARD_EVENTS = frozenset(
    {
        "pull_request",
        "pull_request_target",
        "push",
        "schedule",
        "repository_dispatch",
        "workflow_dispatch",
        "workflow_run",
    }
)


def _value_shape(keys, leaves, tokens, path: tuple[object, ...]) -> str:
    """Distinguish absent values from scalar, map, sequence, and malformed shapes."""
    if path in leaves:
        descendants = [
            p
            for p in (*keys.keys(), *leaves.keys())
            if len(p) > len(path) and p[: len(path)] == path
        ]
        return "invalid" if descendants else "scalar"
    child_parts = {
        p[len(path)]
        for p in (*keys.keys(), *leaves.keys())
        if len(p) > len(path) and p[: len(path)] == path
    }
    if any(isinstance(part, int) for part in child_parts):
        return "sequence"
    if child_parts:
        return "mapping"
    occurrences = keys.get(path, [])
    if len(occurrences) != 1 or occurrences[0].merge_origins:
        return "unknown" if occurrences else "missing"
    owner = occurrences[0]
    key_index = next(
        (
            index
            for index, token in enumerate(tokens)
            if token.kind is TokenKind.KEY
            and token.line == owner.line
            and token.column == owner.column
        ),
        None,
    )
    if key_index is None:
        return "unknown"
    following = next(
        (
            token
            for token in tokens[key_index + 1 :]
            if token.kind not in {TokenKind.INDENT, TokenKind.COMMENT}
        ),
        None,
    )
    if following is None:
        return "unknown"
    if following.kind is TokenKind.FLOW_OPEN_SEQ:
        return "sequence"
    if following.kind is TokenKind.FLOW_OPEN_MAP:
        return "mapping"
    if following.kind is TokenKind.SEQUENCE_DASH and following.indent > owner.indent:
        return "sequence"
    if (
        following.kind is TokenKind.KEY
        and following.line > owner.line
        and following.indent > owner.indent
    ):
        return "mapping"
    return "scalar"


def _valid_run_defaults(keys, leaves, tokens, job: str) -> bool:
    for path in (
        ("defaults",),
        ("defaults", "run"),
        ("jobs", job, "defaults"),
        ("jobs", job, "defaults", "run"),
    ):
        shape = _value_shape(keys, leaves, tokens, path)
        if shape not in {"missing", "mapping"}:
            return False
    return True


def _configured_scalar(keys, leaves, tokens, path: tuple[object, ...]):
    shape = _value_shape(keys, leaves, tokens, path)
    if shape == "missing":
        return False, None
    if shape != "scalar":
        return True, None
    return True, _single(leaves, path)


def _effective_shell(keys, leaves, tokens, job: str, step: int, *, container: bool) -> str | None:
    if not _valid_run_defaults(keys, leaves, tokens, job):
        return None
    owners = (
        ("jobs", job, "steps", step, "shell"),
        ("jobs", job, "defaults", "run", "shell"),
        ("defaults", "run", "shell"),
    )
    raw = None
    for path in owners:
        present, event = _configured_scalar(keys, leaves, tokens, path)
        if present:
            if event is None or event.value is None:
                return None
            raw = event.value
            break
    if raw is None:
        container_path = ("jobs", job, "container")
        container_shape = _value_shape(keys, leaves, tokens, container_path)
        if container_shape not in {"missing", "scalar", "mapping"}:
            return None
        if container:
            raw = "sh"
    if raw is None:
        runner_present, runner = _configured_scalar(keys, leaves, tokens, ("jobs", job, "runs-on"))
        if not runner_present or runner is None or runner.value is None:
            return None
        runner_name = runner.value.lower()
        if runner_name in {"windows-latest", "windows-2022", "windows-2025"}:
            return None
        if runner_name in {
            "ubuntu-latest",
            "ubuntu-22.04",
            "ubuntu-24.04",
            "macos-latest",
            "macos-14",
            "macos-15",
        }:
            raw = "bash"
        else:
            return None
    shell = raw.strip().lower()
    return shell if shell in {"bash", "sh"} else None


def _effective_working_directory(keys, leaves, tokens, job: str, step: int) -> str | None:
    if not _valid_run_defaults(keys, leaves, tokens, job):
        return None
    for path in (
        ("jobs", job, "steps", step, "working-directory"),
        ("jobs", job, "defaults", "run", "working-directory"),
        ("defaults", "run", "working-directory"),
    ):
        present, event = _configured_scalar(keys, leaves, tokens, path)
        if present:
            if event is None or event.value is None:
                return None
            if not isinstance(event.value, str):
                return None
            return event.value
    return "."


def _event_profile(content: str) -> set[str] | None:
    names = _certified_composer_events(content)
    if not names or not names <= _SUPPORTED_GUARD_EVENTS:
        # In particular, workflow_call inherits github.event_name from its caller.
        return None
    return set(names)


def _possible_events(guard: str | None, event_names: set[str]) -> set[str]:
    return {name for name in event_names if event_guard_verdict(guard, name) is not False}


def _format_profile(value: str) -> str | None:
    # Only printable ASCII, one optional %s, and the safe newline escape are modeled.
    if any(ord(char) < 32 or ord(char) > 126 for char in value) or value.startswith("-"):
        return None
    if value.count("\\") != value.count("\\n"):
        return None
    if value.replace("%s", "").find("%") >= 0 or value.count("%s") > 1:
        return None
    return value


def _matched_format(match: re.Match[str]) -> str:
    single_quoted = match.group("single_format")
    if single_quoted is not None:
        return single_quoted
    double_quoted = match.group("double_format")
    if double_quoted is not None:
        return double_quoted
    raise AssertionError("printf format did not match either supported quote form")


def _run_writer_profile(
    event: Event,
) -> tuple[int, str | None, str] | list[tuple[int, str | None, str]] | None:
    """Return the sole supported write, [] for no write, or None if script is unsupported."""
    if event.value_kind != "block_literal" or not event.block_lines:
        return None
    writes: list[tuple[int, str | None, str]] = []
    saw_write = False
    for line_no, raw in event.block_lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _MKDIR.fullmatch(raw):
            if saw_write:
                return None
            continue
        match = _PRINTF_SECRET.fullmatch(raw)
        if match:
            fmt = _format_profile(_matched_format(match))
            if fmt is None or fmt.count("%s") != 1:
                return None
            var = match.group("var").strip('"$')
            if var.startswith("{") and var.endswith("}"):
                var = var[1:-1]
            target = match.group("path")
            writes.append((line_no, var, target))
            saw_write = True
            continue
        match = _PRINTF_LITERAL.fullmatch(raw)
        if match:
            fmt = _format_profile(_matched_format(match))
            if fmt is None or "%" in fmt:
                return None
            writes.append((line_no, None, match.group("path")))
            saw_write = True
            continue
        # This rejects echo escape flags, printf %b/other conversions, control flow,
        # compound commands, substitutions, and all non-profile shell syntax.
        return None
    if len(writes) > 1:
        return None
    return writes[0] if writes else []


def _hidden_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return any(part.startswith(".") and part not in {".", ".."} for part in normalized.split("/"))


def _supported_upload(value: str) -> bool:
    action, sep, ref = (value or "").partition("@")
    return action.lower() == _UPLOAD and bool(sep) and ref.lower() in _SUPPORTED_UPLOAD_REFS


class SecretArtifactFlowPattern:
    """Bounded proof of a direct secret env binding written by printf then selected by upload."""

    def check(self, content: str, lines: list[str]):
        events = tuple(
            walk_workflow("workflow.yml", content=content, include_keys=True, recover=True)
        )
        scalar_values = [
            event.value or "" for event in events if event.kind is EventKind.LEAF_SCALAR
        ]
        candidate_hint = any(_SECRET_HINT.search(value) for value in scalar_values) and any(
            _UPLOAD in value.lower() for value in scalar_values
        )
        if not candidate_hint:
            return []
        if any(event.kind in {EventKind.CUTOFF, EventKind.ERROR} for event in events):
            return IncompletePatternMatches(
                [], reason="SEC6-GH-016 candidate workflow structure is incomplete"
            )
        keys, leaves = _event_map(events)
        if any(len(occurrences) != 1 for occurrences in keys.values()):
            return IncompletePatternMatches(
                [], reason="SEC6-GH-016 candidate mapping owner is ambiguous"
            )
        try:
            # The tokenizer yields a one-shot iterator. Keep all tokens because
            # owner-shape checks revisit the same stream for every env/default.
            yaml_tokens = tuple(tokenize(content))
        except Exception:
            return IncompletePatternMatches(
                [], reason="SEC6-GH-016 candidate YAML tokens are incomplete"
            )
        if any(
            token.kind in {TokenKind.MERGE_KEY, TokenKind.ALIAS, TokenKind.ANCHOR}
            for token in yaml_tokens
        ):
            return IncompletePatternMatches(
                [],
                reason="SEC6-GH-016 candidate aliases or merged owners are unsupported",
            )
        event_names = _event_profile(content)
        if not event_names:
            return IncompletePatternMatches(
                [], reason="SEC6-GH-016 candidate trigger profile is incomplete"
            )
        (
            env_fields,
            ambiguous_env,
            invalid_env_owners,
            invalid_env_values,
            unknown_env_sources,
        ) = _env_fields(keys, leaves, yaml_tokens)
        if ambiguous_env:
            return IncompletePatternMatches(
                [],
                reason="SEC6-GH-016 merged or duplicate env value prevents source proof",
            )
        workflow_env = _scoped_env(env_fields, (), {"GITHUB_WORKSPACE": _ROOT})
        guard_events = {
            path: occurrences[0]
            for path, occurrences in leaves.items()
            if path[-1:] == ("if",) and len(occurrences) == 1
        }
        jobs: dict[str, set[int]] = {}
        for path in leaves:
            if (
                len(path) >= 5
                and path[0] == "jobs"
                and path[2] == "steps"
                and isinstance(path[3], int)
            ):
                jobs.setdefault(str(path[1]), set()).add(path[3])
        hits: list[tuple[int, str]] = []
        unresolved = False
        for job, step_indices in jobs.items():
            job_scope = ("jobs", job)
            job_guard = guard_events.get(job_scope + ("if",))
            job_possible = _possible_events(job_guard.value if job_guard else None, event_names)
            if not job_possible:
                continue
            job_hits: list[tuple[int, str]] = []
            job_unresolved = False
            job_env = _scoped_env(env_fields, job_scope, workflow_env)
            uploads: dict[int, tuple[str | None, Event, set[str]]] = {}
            ambiguous_uploads: set[int] = set()
            step_envs: dict[int, dict[str, str]] = {}
            step_domains: dict[int, set[str]] = {}
            step_inputs: dict[int, tuple[Event | None, dict[str, str], bool]] = {}
            writers: dict[int, tuple[str, int, set[str]]] = {}
            for index in sorted(step_indices):
                scope = job_scope + ("steps", index)
                step_guard = guard_events.get(scope + ("if",))
                possible = job_possible & _possible_events(
                    step_guard.value if step_guard else None, event_names
                )
                if not possible:
                    continue
                step_domains[index] = possible
                run_event = _single(leaves, scope + ("run",))
                uses = _single(leaves, scope + ("uses",))
                if uses is None and scope + ("uses",) in keys:
                    ambiguous_uploads.add(index)
                if uses and (uses.value or "").split("@", 1)[0].lower() == _UPLOAD:
                    path_event = _single(leaves, scope + ("with", "path"))
                    uploads[index] = (
                        path_event.value if path_event else None,
                        path_event or uses,
                        possible,
                    )
                    if not _supported_upload(uses.value or ""):
                        ambiguous_uploads.add(index)
                    if path_event and _SECRET_HINT.search(path_event.value or ""):
                        job_unresolved = True
                raw_env = _layered_env(env_fields, job, index)
                step_envs[index] = _scoped_env(env_fields, scope, job_env)
                secret_states = {name: _secret_state(raw_env, name) for name in raw_env}
                has_candidate_source = any(
                    state is True or state is None for state in secret_states.values()
                )
                if _env_has_unknown_source(unknown_env_sources, job, index):
                    has_candidate_source = True
                if run_event and _SECRET_HINT.search(run_event.value or ""):
                    has_candidate_source = True
                step_inputs[index] = (run_event, raw_env, has_candidate_source)
            any_upload_declared = bool(uploads or ambiguous_uploads)
            if any_upload_declared:
                for index in sorted(step_inputs):
                    run_event, raw_env, has_candidate_source = step_inputs[index]
                    if not has_candidate_source:
                        continue
                    scope = job_scope + ("steps", index)
                    if run_event is None:
                        if scope + ("run",) in keys or scope + ("run",) in leaves:
                            job_unresolved = True
                        continue
                    profile = _run_writer_profile(run_event)
                    if profile is None:
                        job_unresolved = True
                        continue
                    if profile == []:
                        continue
                    if not isinstance(profile, tuple):
                        job_unresolved = True
                        continue
                    line_no, variable, raw_target = profile
                    if variable is not None and _env_binding_is_unknown(
                        invalid_env_owners, invalid_env_values, job, index, variable
                    ):
                        job_unresolved = True
                        continue
                    if _hidden_path(raw_target):
                        job_unresolved = True
                        continue
                    cwd_value = _effective_working_directory(keys, leaves, yaml_tokens, job, index)
                    if cwd_value is None:
                        job_unresolved = True
                        continue
                    cwd = _path(cwd_value, _ROOT, step_envs[index])
                    if cwd is None:
                        job_unresolved = True
                        continue
                    target = _path(raw_target, cwd, step_envs[index], shell=False)
                    if target is None:
                        job_unresolved = True
                        continue
                    if variable is None:
                        continue
                    state = _secret_state(raw_env, variable)
                    if state is None:
                        job_unresolved = True
                    elif state is True:
                        container_shape = _value_shape(
                            keys, leaves, yaml_tokens, job_scope + ("container",)
                        )
                        shell = _effective_shell(
                            keys,
                            leaves,
                            yaml_tokens,
                            job,
                            index,
                            container=container_shape != "missing",
                        )
                        if shell is None:
                            job_unresolved = True
                        else:
                            writers[index] = (target, line_no, step_domains[index])
            for upload_index, (
                raw_path,
                evidence_event,
                upload_events,
            ) in uploads.items():
                prior_writers = [
                    (writer_index, target, line_no, writer_events)
                    for writer_index, (
                        target,
                        line_no,
                        writer_events,
                    ) in writers.items()
                    if writer_index < upload_index and writer_events & upload_events
                ]
                if prior_writers and (
                    raw_path is None
                    or _GLOB.search(raw_path)
                    or "$" in raw_path
                    or "`" in raw_path
                    or "\n" in raw_path
                ):
                    job_unresolved = True
                    continue
                candidates = [
                    (writer_index, target, line_no, writer_events)
                    for writer_index, (
                        target,
                        line_no,
                        writer_events,
                    ) in writers.items()
                    if writer_index + 1 == upload_index and writer_events & upload_events
                ]
                if not candidates:
                    continue
                if (
                    raw_path is None
                    or _GLOB.search(raw_path)
                    or "$" in raw_path
                    or "`" in raw_path
                    or "\n" in raw_path
                ):
                    job_unresolved = True
                    continue
                if _hidden_path(raw_path):
                    job_unresolved = True
                    continue
                upload_path = _path(
                    raw_path, _ROOT, step_envs.get(upload_index, job_env), shell=False
                )
                if upload_path is None:
                    job_unresolved = True
                    continue
                for _writer_index, target, line_no, _writer_events in candidates:
                    if upload_path == target:
                        snippet = (
                            lines[line_no - 1].strip()
                            if 0 < line_no <= len(lines)
                            else "supported printf write"
                        )
                        job_hits.append(
                            (
                                line_no,
                                snippet + f" [literal artifact path at line {evidence_event.line}]",
                            )
                        )
                    elif target.startswith(upload_path.rstrip("/") + "/"):
                        # A directory selector can include this file; do not call it exact.
                        job_unresolved = True
            for upload_index in ambiguous_uploads:
                if any(
                    writer_index < upload_index
                    and writer_events & step_domains.get(upload_index, set())
                    for writer_index, (_target, _line, writer_events) in writers.items()
                ):
                    job_unresolved = True
            if job_unresolved:
                unresolved = True
            else:
                hits.extend(job_hits)
        if unresolved:
            return IncompletePatternMatches(
                hits,
                reason="SEC6-GH-016 bounded source, shell, or upload analysis is incomplete",
            )
        return hits


_SEALED_POSITIVE = """name: report-artifact-contrast
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - name: Write report
        env:
          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}
        run: |
          mkdir -p reports
          printf 'credential=%s\\n' "$REPORT_TOKEN" > reports/build-report.txt
      - name: Upload report
        uses: actions/upload-artifact@v7
        with:
          name: build-report
          path: reports/build-report.txt
          if-no-files-found: error
"""

_SEALED_FLOW_KEY_EQUIVALENT = _SEALED_POSITIVE.replace(
    "        env:\n          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}\n",
    '        env: {"REPORT_TOKEN": "${{ secrets.REPORT_TOKEN }}"}\n',
).replace(
    "        with:\n          name: build-report\n          path: reports/build-report.txt\n          if-no-files-found: error\n",
    '        with: {"name": "build-report", "path": "reports/build-report.txt", '
    '"if-no-files-found": "error"}\n',
)
_SEALED_REDACTED = _SEALED_POSITIVE.replace(
    "          printf 'credential=%s\\n' \"$REPORT_TOKEN\" > reports/build-report.txt\n",
    "          printf 'credential=[REDACTED]\\n' > reports/build-report.txt\n",
)

RULES = [
    Rule(
        id="SEC6-GH-016",
        title="Secret-derived file selected for artifact upload",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A supported Bash/sh step binds a direct secrets.* expression to an environment variable, "
            "a narrowly supported printf form writes that variable to a literal non-hidden path, and "
            "the immediately following same-job step selects that exact path with actions/upload-artifact. "
            "This is a configured file-selection candidate if the secret is available and both steps run; "
            "it does not prove actual file bytes, action behavior, transfer, audience, or disclosure."
        ),
        pattern=SecretArtifactFlowPattern(),
        remediation=(
            "Avoid writing credentials into workflow artifacts. Publish a redacted report or a "
            "presence-only status, and keep the credential in the step that needs it. Review artifact "
            "retention and access separately."
        ),
        reference="https://docs.github.com/actions/using-workflows/storing-workflow-data-as-artifacts",
        finding_family="credential_persistence",
        confidence="medium",
        review_needed=True,
        stride=["I"],
        threat_narrative=(
            "If the declared secret is available and both configured steps execute, the supported "
            "writer selects the same literal non-hidden file path as the following artifact action."
        ),
        test_positive=[_SEALED_POSITIVE, _SEALED_FLOW_KEY_EQUIVALENT],
        test_negative=[_SEALED_REDACTED],
    ),
]
