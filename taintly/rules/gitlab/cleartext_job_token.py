"""Review direct GitLab job-token form submission over cleartext HTTP."""

from __future__ import annotations

import re
import shlex
import tempfile
from dataclasses import dataclass
from pathlib import Path

from taintly.models import IncompletePatternMatches, Platform, Rule, Severity
from taintly.parsers.structural import EventKind, walk_workflow
from taintly.parsers.structural.tokenizer import TokenKind, tokenize
from taintly.rules._secret_network_shell import _physical_source

_TOKEN = re.compile(r"\$(?:CI_JOB_TOKEN\b|\{CI_JOB_TOKEN\})")
_FORM_HINT = re.compile(r"(?:--form|-F)(?:\s|=)")
_FORM_ARG = re.compile(r"""(?:^|\s)(?:--form|-F)\s+("[^"`]*"|'[^']*'|[^\s'"`]+)""")
_TOKEN_FORM = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*=\$(?:CI_JOB_TOKEN|\{CI_JOB_TOKEN\})\Z")
_VALUE_FLAGS = frozenset({"--request", "-X", "--form", "-F", "--header", "-H"})
_NO_VALUE_FLAGS = frozenset(
    {"-v", "--verbose", "-f", "--fail", "-s", "--silent", "-S", "--show-error", "-L", "--location"}
)


@dataclass(frozen=True)
class _Notes:
    notes: tuple[str, ...]


def _has_candidate(content: str) -> bool:
    # This profile models one direct command on one physical line. A commented
    # example must not create a coverage diagnostic on a different live job.
    return any(
        "curl" in line and _TOKEN.search(line) and "http://" in line and _FORM_HINT.search(line)
        for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def _direct_cleartext_form(command: str) -> bool | None:
    """True only for a direct token form and one literal HTTP URL; None is unknown."""
    if not command.startswith("curl "):
        return False
    if len(command) > 1024 or any(
        mark in command for mark in ("`", "$(", "${{", "\\", "\n", ";", "&&", "|", ">", "<")
    ):
        return None
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        return None
    if not words or words[0] != "curl" or len(words) > 64:
        return None
    forms: list[str] = []
    urls: list[str] = []
    index = 1
    while index < len(words):
        word = words[index]
        if word in _VALUE_FLAGS:
            if index + 1 >= len(words):
                return None
            if word in {"--form", "-F"}:
                forms.append(words[index + 1])
            index += 2
        elif word in _NO_VALUE_FLAGS:
            index += 1
        elif word.startswith(("http://", "https://")):
            urls.append(word)
            index += 1
        else:
            return None
    if len(urls) != 1 or not forms:
        return None
    if urls[0].startswith("https://"):
        return False
    if not re.fullmatch(r"http://[^\s$]+", urls[0]):
        return None
    raw_forms = [match.group(1) for match in _FORM_ARG.finditer(command)]
    if len(raw_forms) != len(forms):
        return None
    ambiguous_form = False
    for raw, cooked in zip(raw_forms, forms, strict=True):
        if raw.startswith("'"):
            continue  # A single-quoted dollar sign is literal shell data.
        if raw.strip('"') != cooked:
            return None
        if _TOKEN_FORM.fullmatch(cooked):
            return True
        if _TOKEN.search(cooked):
            ambiguous_form = True
    return None if ambiguous_form else False


class GitLabCleartextJobTokenPattern:
    def check(self, content: str, _lines: list[str]):
        if _has_candidate(content):
            return IncompletePatternMatches(
                [], reason="SEC6-GL-011 physical GitLab source is required"
            )
        return []

    def self_test_check(self, sample: str):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / ".gitlab-ci.yml"
            path.write_text(sample, encoding="utf8")
            return self.check_with_filepath(sample, sample.splitlines(), str(path))

    def _analyze(self, content: str, filepath: str):
        if not _has_candidate(content):
            return [], {}, None
        digest = _physical_source(filepath, content)
        if digest is None:
            return [], {}, "SEC6-GL-011 source identity is unavailable"
        events = tuple(walk_workflow(filepath, content=content, include_keys=True, recover=True))
        try:
            tokens = tuple(tokenize(content))
        except Exception:
            return [], {}, "SEC6-GL-011 YAML tokenization is incomplete"
        if any(
            e.kind in {EventKind.ERROR, EventKind.CUTOFF} or e.merge_origins for e in events
        ) or any(
            t.kind in {TokenKind.ALIAS, TokenKind.ANCHOR, TokenKind.MERGE_KEY} for t in tokens
        ):
            return [], {}, "SEC6-GL-011 candidate structure is ambiguous"
        leaves = [e for e in events if e.kind is EventKind.LEAF_SCALAR]
        if len({e.path for e in leaves}) != len(leaves):
            return [], {}, "SEC6-GL-011 duplicate source paths"
        if any(
            e.path == ("variables", "CI_JOB_TOKEN")
            or e.path == ("default", "variables", "CI_JOB_TOKEN")
            for e in leaves
        ):
            return [], {}, "SEC6-GL-011 CI_JOB_TOKEN is explicitly overridden in source"
        overridden_jobs = {
            e.path[0]
            for e in leaves
            if len(e.path) == 3
            and e.path[1:] == ("variables", "CI_JOB_TOKEN")
            and e.path[0] != "default"
        }
        source_lines = content.splitlines()
        matches: list[tuple[int, str]] = []
        notes: dict[tuple[int, str], _Notes] = {}
        incomplete = False
        for event in leaves:
            if not (
                event.value
                and "CI_JOB_TOKEN" in event.value
                and "http://" in event.value
                and _FORM_HINT.search(event.value)
                and any(key in event.path for key in ("script", "before_script", "after_script"))
            ):
                continue
            if not (
                len(event.path) == 3
                and isinstance(event.path[0], str)
                and not event.path[0].startswith(".")
                and event.path[1] == "script"
                and type(event.path[2]) is int
            ):
                incomplete = True
                continue
            if event.path[0] in overridden_jobs:
                incomplete = True
                continue
            if event.line < 1 or event.line > len(source_lines):
                incomplete = True
                continue
            physical_line = source_lines[event.line - 1]
            if not all(part in physical_line for part in ("curl", "CI_JOB_TOKEN", "http://")):
                incomplete = True
                continue
            result = _direct_cleartext_form(event.value.strip())
            if result is None:
                incomplete = True
                continue
            if not result:
                continue
            item = (event.line, event.value.strip())
            matches.append(item)
            notes[item] = _Notes(
                (
                    f"Source SHA256 {digest}; GitLab job {event.path[0]}, script item {event.path[2]} "
                    f"directly places a CI_JOB_TOKEN reference in a curl form field sent to a literal http:// "
                    "URL. This is configured cleartext transport, not proof that the job ran, the token retained "
                    "its predefined value, the request was delivered, or traffic was intercepted.",
                )
            )
        return (
            matches,
            notes,
            (
                "SEC6-GL-011 candidate command is outside the direct curl/form/HTTP profile"
                if incomplete
                else None
            ),
        )

    def check_with_filepath(self, content: str, _lines: list[str], filepath: str):
        matches, _notes, incomplete = self._analyze(content, filepath)
        return IncompletePatternMatches(matches, reason=incomplete) if incomplete else matches

    def context_notes_for_matches(
        self, content: str, filepath: str, matches: list[tuple[int, str]]
    ):
        _matches, notes, _incomplete = self._analyze(content, filepath)
        return [notes.get(item) for item in matches]


_SAMPLE = (
    "deploy:\n  script:\n"
    '    - "curl --request POST --form token=$CI_JOB_TOKEN http://ci.example.test/api/v4/projects/9/trigger/pipeline"\n'
)

RULES = [
    Rule(
        id="SEC6-GL-011",
        title="GitLab job token form sent to a cleartext HTTP endpoint",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        description="A direct GitLab script command places a CI_JOB_TOKEN reference in a curl form field for a literal http:// URL. This is a configured cleartext credential path, not proof of runtime disclosure.",
        pattern=GitLabCleartextJobTokenPattern(),
        remediation="Use HTTPS for the target GitLab API or a supported secure transport. Prefer the JOB-TOKEN header when the endpoint accepts it. Review the actual route and logs; investigate token exposure only if the job ran and the route was reachable.",
        reference="https://docs.gitlab.com/ci/jobs/ci_job_token/",
        test_positive=[_SAMPLE],
        test_negative=[_SAMPLE.replace("http://", "https://")],
        finding_family="credential_exposure",
        confidence="medium",
        review_needed=True,
    )
]
