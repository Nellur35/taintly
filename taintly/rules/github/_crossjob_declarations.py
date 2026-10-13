"""Fail-open structural certificates for cross-job output references.

The CHAIN-GH-105 composer may prune a candidate only when a complete,
unambiguous workflow structure proves that the referenced output or direct
dependency is absent. This is intentionally narrower than YAML parsing; any
shape outside the supported literal subset returns UNKNOWN.
"""

from __future__ import annotations

import re
from collections import Counter
from enum import Enum

from taintly.parsers.structural import Event, EventKind, walk_workflow
from taintly.parsers.structural.tokenizer import TokenizerError, TokenKind, tokenize

_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\Z")
_DOCUMENT_MARKER_RE = re.compile(r"(?:---|\.\.\.)(?:[ \t].*)?\Z")
_OUTPUT_ENTRY_RE = re.compile(
    r"^(?P<indent> *)(?P<key>[A-Za-z_][A-Za-z0-9_-]*|'[A-Za-z_][A-Za-z0-9_-]*'|\"[A-Za-z_][A-Za-z0-9_-]*\")"
    r" *: *(?P<value>\S.*)$"
)
_NEEDS_ID = r"(?:[A-Za-z_][A-Za-z0-9_-]*|'[A-Za-z_][A-Za-z0-9_-]*'|\"[A-Za-z_][A-Za-z0-9_-]*\")"
_NEEDS_SCALAR_RE = re.compile(rf"^{_NEEDS_ID}$")
_NEEDS_FLOW_RE = re.compile(rf"^\[\s*{_NEEDS_ID}(?:\s*,\s*{_NEEDS_ID})*\s*\]$")
_NEEDS_ITEM_RE = re.compile(rf"^(?P<indent> *)-\s*(?P<value>{_NEEDS_ID})\s*(?:#.*)?$")
_FLOW_OUTPUT_VALUE = r'(?:\$\{\{[^{}]*\}\}|"[^"\\]*"|\x27[^\x27]*\x27|[A-Za-z0-9_./$-]+)'
_FLOW_OUTPUT_ENTRY_RE = re.compile(
    rf"\s*(?P<key>{_NEEDS_ID})\s*:\s*(?P<value>{_FLOW_OUTPUT_VALUE})\s*"
)
_MAX_CONTENT_CHARS = 1_000_000


class DeclarationVerdict(Enum):
    """Whether complete supported structure proves presence or absence."""

    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class CrossJobDeclarationView:
    """Unique full-workflow key/value projection for negative certificates."""

    def __init__(self, content: str, tokens, events: tuple[Event, ...]) -> None:
        keys: dict[tuple[object, ...], Event] = {}
        key_counts: Counter[tuple[object, ...]] = Counter()
        values: dict[tuple[object, ...], Event] = {}
        value_counts: Counter[tuple[object, ...]] = Counter()

        for event in events:
            if event.kind in {EventKind.ERROR, EventKind.CUTOFF} or event.merge_origins:
                raise ValueError("workflow structure is incomplete or merged")
            if event.kind is EventKind.MAP_KEY:
                key_counts[event.path] += 1
                keys[event.path] = event
            elif event.kind is EventKind.LEAF_SCALAR:
                value_counts[event.path] += 1
                values[event.path] = event

        if any(count > 1 for count in key_counts.values()):
            raise ValueError("workflow contains duplicate mapping keys")
        if any(count > 1 for count in value_counts.values()):
            raise ValueError("workflow contains duplicate scalar paths")
        self.keys = keys
        self.values = values
        self.lines = content.splitlines()
        self.tokens = tokens

    @classmethod
    def build(cls, content: str) -> CrossJobDeclarationView | None:
        """Build one complete view, or return ``None`` when proof is unsafe."""
        if len(content) > _MAX_CONTENT_CHARS:
            return None
        if any(_DOCUMENT_MARKER_RE.fullmatch(line.strip()) for line in content.splitlines()):
            return None
        try:
            tokens = tuple(tokenize(content))
            if any(
                token.kind in {TokenKind.ANCHOR, TokenKind.ALIAS, TokenKind.MERGE_KEY}
                for token in tokens
            ):
                return None
            flow_stack: list[TokenKind] = []
            for token in tokens:
                if token.kind in {TokenKind.FLOW_OPEN_MAP, TokenKind.FLOW_OPEN_SEQ}:
                    flow_stack.append(
                        TokenKind.FLOW_CLOSE_MAP
                        if token.kind is TokenKind.FLOW_OPEN_MAP
                        else TokenKind.FLOW_CLOSE_SEQ
                    )
                    # Nested flow values can contain empty containers that
                    # the structural projection intentionally omits.
                    if len(flow_stack) > 1:
                        return None
                elif token.kind in {TokenKind.FLOW_CLOSE_MAP, TokenKind.FLOW_CLOSE_SEQ}:
                    if not flow_stack or flow_stack.pop() is not token.kind:
                        return None
            if flow_stack:
                return None
            events = tuple(
                walk_workflow(
                    "workflow.yml",
                    content=content,
                    recover=True,
                    include_keys=True,
                    include_merge_origins=True,
                )
            )
            return cls(content, tokens, events)
        except (RecursionError, TokenizerError, TypeError, ValueError):
            return None

    def _job_mapping_is_complete(self, job: str) -> bool:
        jobs_path = ("jobs",)
        job_path = jobs_path + (job,)
        jobs_event = self.keys.get(jobs_path)
        job_event = self.keys.get(job_path)
        if not (
            jobs_path in self.keys
            and jobs_path not in self.values
            and job_path in self.keys
            and job_path not in self.values
            and jobs_event is not None
            and job_event is not None
        ):
            return False
        return (
            self._block_mapping_header(jobs_event, "jobs")
            and self._block_mapping_children_complete(jobs_path, jobs_event)
            and self._block_mapping_header(job_event, job)
            and self._block_mapping_children_complete(job_path, job_event)
        )

    def _block_mapping_header(self, event: Event, key: str) -> bool:
        if event.line < 1 or event.line > len(self.lines):
            return False
        return (
            re.fullmatch(rf" *{re.escape(key)}\s*:\s*(?:#.*)?", self.lines[event.line - 1])
            is not None
        )

    def _block_mapping_children_complete(self, path: tuple[object, ...], event: Event) -> bool:
        """Match every immediate source key to its unique structural key."""
        if event.line < 1 or event.line > len(self.lines):
            return False
        header = self.lines[event.line - 1]
        header_indent = len(header) - len(header.lstrip(" "))
        child_lines = self._following_child_lines(event.line, header_indent)
        if not child_lines:
            return False

        direct_indent = len(child_lines[0][1]) - len(child_lines[0][1].lstrip(" "))
        if direct_indent <= header_indent:
            return False
        source_keys: dict[str, int] = {}
        for number, raw in child_lines:
            indent = len(raw) - len(raw.lstrip(" "))
            if indent < direct_indent:
                return False
            if indent != direct_indent:
                continue
            match = re.fullmatch(r" +(?P<key>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(?:.*)", raw)
            if match is None:
                return False
            key = match.group("key")
            if key in source_keys:
                return False
            source_keys[key] = number

        structural_keys = {
            str(child_path[-1]): child_event.line
            for child_path, child_event in self.keys.items()
            if len(child_path) == len(path) + 1 and child_path[:-1] == path
        }
        return bool(source_keys) and source_keys == structural_keys

    @staticmethod
    def _unquote_name(value: str) -> str | None:
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        return value if _NAME_RE.fullmatch(value) else None

    def _following_child_lines(self, line_number: int, parent_indent: int) -> list[tuple[int, str]]:
        """Return significant lines in a key's indented value span."""
        found: list[tuple[int, str]] = []
        for number in range(line_number + 1, len(self.lines) + 1):
            raw = self.lines[number - 1]
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            if indent <= parent_indent:
                break
            found.append((number, raw))
        return found

    def _output_mapping_entries(
        self, output_path: tuple[object, ...], key_event: Event
    ) -> set[str] | None:
        """Validate the complete simple block-map span and return its names."""
        if key_event.line < 1 or key_event.line > len(self.lines):
            return None
        header = self.lines[key_event.line - 1]
        header_indent = len(header) - len(header.lstrip(" "))
        direct_keys = {
            path[-1]: event
            for path, event in self.keys.items()
            if len(path) == len(output_path) + 1 and path[:-1] == output_path
        }
        direct_values = {
            path[-1]: event
            for path, event in self.values.items()
            if len(path) == len(output_path) + 1 and path[:-1] == output_path
        }
        flow_header = re.fullmatch(r" *outputs\s*:\s*(\{.*\})\s*(?:#.*)?", header)
        if flow_header is not None:
            if self._following_child_lines(key_event.line, header_indent):
                return None
            flow_tokens = [token for token in self.tokens if token.line == key_event.line]
            if (
                sum(token.kind is TokenKind.FLOW_OPEN_MAP for token in flow_tokens) != 1
                or sum(token.kind is TokenKind.FLOW_CLOSE_MAP for token in flow_tokens) != 1
            ):
                return None
            flow_body = flow_header.group(1)[1:-1]
            source_names: list[str] = []
            for entry in flow_body.split(","):
                entry_match = _FLOW_OUTPUT_ENTRY_RE.fullmatch(entry)
                if entry_match is None:
                    return None
                name = self._unquote_name(entry_match.group("key"))
                if name is None or name in source_names:
                    return None
                source_names.append(name)
            if not source_names:
                return None
            if not direct_keys or set(direct_keys) != set(direct_values):
                return None
            if any(
                not isinstance(name, str)
                or not _NAME_RE.fullmatch(name)
                or event.line != key_event.line
                for name, event in direct_keys.items()
            ):
                return None
            if any(
                event.line != key_event.line
                or event.value is None
                or event.value_kind not in {"plain", "quoted"}
                for event in direct_values.values()
            ):
                return None
            if set(source_names) != set(direct_keys):
                return None
            if any(
                len(path) > len(output_path) + 1 and path[: len(output_path)] == output_path
                for path in (*self.keys.keys(), *self.values.keys())
            ):
                return None
            return set(source_names)

        if re.fullmatch(r" *outputs\s*:\s*(?:#.*)?", header) is None:
            return None
        block_body_lines = {
            line_number
            for event in direct_values.values()
            for line_number, _body in (event.block_lines or ())
        }
        child_lines = [
            (number, raw)
            for number, raw in self._following_child_lines(key_event.line, header_indent)
            if number not in block_body_lines
        ]
        if not child_lines:
            return None

        entries: dict[str, int] = {}
        child_indent: int | None = None
        for number, raw in child_lines:
            match = _OUTPUT_ENTRY_RE.fullmatch(raw)
            if match is None:
                return None
            indent = len(match.group("indent"))
            name = self._unquote_name(match.group("key"))
            value = match.group("value").strip()
            value_event = direct_values.get(name) if name is not None else None
            is_block_scalar = (
                re.fullmatch(r"[|>](?:[1-9][+-]?|[+-][1-9]?)?(?: +#.*)?", value) is not None
            )
            if (
                name is None
                or value_event is None
                or (not is_block_scalar and not value)
                or (
                    is_block_scalar
                    and (
                        not isinstance(value_event.value_kind, str)
                        or not value_event.value_kind.startswith("block_")
                    )
                )
                or (
                    not is_block_scalar
                    and (
                        value_event.value_kind not in {"plain", "quoted"}
                        or re.fullmatch(_FLOW_OUTPUT_VALUE, value) is None
                    )
                )
                or value.startswith(("{", "[", "&", "*", "!"))
                or (child_indent is not None and indent != child_indent)
                or name in entries
            ):
                return None
            child_indent = indent
            entries[name] = number

        structural_keys = {name: event.line for name, event in direct_keys.items()}
        if structural_keys != entries:
            return None
        if set(direct_values) != set(entries):
            return None
        if any(
            len(path) > len(output_path) + 1 and path[: len(output_path)] == output_path
            for path in (*self.keys.keys(), *self.values.keys())
        ):
            return None
        return set(entries)

    def output_name_verdict(self, producer: str, output: str) -> DeclarationVerdict:
        """Certify a literal output name only from a complete direct map."""
        if not _NAME_RE.fullmatch(producer) or not _NAME_RE.fullmatch(output):
            return DeclarationVerdict.UNKNOWN
        if not self._job_mapping_is_complete(producer):
            return DeclarationVerdict.UNKNOWN

        output_path = ("jobs", producer, "outputs")
        output_event = self.keys.get(output_path)
        if output_event is None or output_path in self.values:
            return DeclarationVerdict.UNKNOWN
        direct_keys = self._output_mapping_entries(output_path, output_event)
        if direct_keys is None:
            return DeclarationVerdict.UNKNOWN

        if output in direct_keys:
            return DeclarationVerdict.PRESENT
        # Provider case semantics have not been established. A case-only
        # miss is therefore ambiguous, never a certificate of absence.
        if any(name.casefold() == output.casefold() for name in direct_keys):
            return DeclarationVerdict.UNKNOWN
        return DeclarationVerdict.ABSENT

    def direct_need_verdict(self, consumer: str, producer: str) -> DeclarationVerdict:
        """Certify whether a consumer directly lists the producer in needs."""
        if not _NAME_RE.fullmatch(consumer) or not _NAME_RE.fullmatch(producer):
            return DeclarationVerdict.UNKNOWN
        if not self._job_mapping_is_complete(consumer):
            return DeclarationVerdict.UNKNOWN

        needs_path = ("jobs", consumer, "needs")
        needs_event = self.keys.get(needs_path)
        if needs_event is None:
            if needs_path in self.values:
                return DeclarationVerdict.UNKNOWN
            return DeclarationVerdict.ABSENT

        key_line = (
            self.lines[needs_event.line - 1] if 0 < needs_event.line <= len(self.lines) else ""
        )
        indent = len(key_line) - len(key_line.lstrip(" "))
        match = re.fullmatch(r" *needs\s*:\s*(.*?)\s*(?:#.*)?", key_line)
        if match is None:
            return DeclarationVerdict.UNKNOWN
        tail = match.group(1).strip()
        child_lines = self._following_child_lines(needs_event.line, indent)

        scalar = self.values.get(needs_path)
        if scalar is not None:
            # The scalar's same-line value span must own the whole key value;
            # a dropped deeper child invalidates a negative certificate.
            if child_lines:
                return DeclarationVerdict.UNKNOWN
            if scalar.value_kind not in {"plain", "quoted"} or scalar.value is None:
                return DeclarationVerdict.UNKNOWN
            name = self._unquote_name(tail)
            if name is None or name != scalar.value:
                return DeclarationVerdict.UNKNOWN
            if name == producer:
                return DeclarationVerdict.PRESENT
            if name.casefold() == producer.casefold():
                return DeclarationVerdict.UNKNOWN
            return DeclarationVerdict.ABSENT

        if tail:
            # Only a simple one-line flow sequence is accepted here.
            if _NEEDS_FLOW_RE.fullmatch(tail) is None or child_lines:
                return DeclarationVerdict.UNKNOWN
            raw_names = [self._unquote_name(value.strip()) for value in tail[1:-1].split(",")]
            if not raw_names or any(name is None for name in raw_names):
                return DeclarationVerdict.UNKNOWN
            flow_names = [name for name in raw_names if name is not None]
            children = {
                path[-1]: event
                for path, event in self.values.items()
                if len(path) == len(needs_path) + 1 and path[:-1] == needs_path
            }
            if any(index not in children for index in range(len(flow_names))):
                return DeclarationVerdict.UNKNOWN
            if [children[index].value for index in range(len(flow_names))] != flow_names:
                return DeclarationVerdict.UNKNOWN
            if len(set(flow_names)) != len(flow_names):
                return DeclarationVerdict.UNKNOWN
            if producer in flow_names:
                return DeclarationVerdict.PRESENT
            if any(name.casefold() == producer.casefold() for name in flow_names):
                return DeclarationVerdict.UNKNOWN
            return DeclarationVerdict.ABSENT

        # A block sequence is supported only when every significant child
        # line is a plain scalar item at one consistent indentation.
        block_names: list[str] = []
        item_indent: int | None = None
        for _number, raw in child_lines:
            item_match = _NEEDS_ITEM_RE.fullmatch(raw)
            if item_match is None:
                return DeclarationVerdict.UNKNOWN
            current_indent = len(item_match.group("indent"))
            name = self._unquote_name(item_match.group("value"))
            if name is None or (item_indent is not None and current_indent != item_indent):
                return DeclarationVerdict.UNKNOWN
            item_indent = current_indent
            block_names.append(name)
        if not block_names or len(set(block_names)) != len(block_names):
            return DeclarationVerdict.UNKNOWN

        children = {
            path[-1]: event
            for path, event in self.values.items()
            if len(path) == len(needs_path) + 1 and path[:-1] == needs_path
        }
        if not children or any(not isinstance(index, int) for index in children):
            return DeclarationVerdict.UNKNOWN
        if set(children) != set(range(len(children))):
            return DeclarationVerdict.UNKNOWN
        if any(
            len(path) > len(needs_path) + 1 and path[: len(needs_path)] == needs_path
            for path in (*self.keys.keys(), *self.values.keys())
        ):
            return DeclarationVerdict.UNKNOWN

        names: list[str] = []
        for index in range(len(children)):
            child = children[index]
            if child.value_kind not in {"plain", "quoted"} or child.value is None:
                return DeclarationVerdict.UNKNOWN
            name = self._unquote_name(child.value)
            if name is None:
                return DeclarationVerdict.UNKNOWN
            names.append(name)
        if names != block_names:
            return DeclarationVerdict.UNKNOWN
        if len(set(names)) != len(names):
            return DeclarationVerdict.UNKNOWN
        if producer in names:
            return DeclarationVerdict.PRESENT
        if any(name.casefold() == producer.casefold() for name in names):
            return DeclarationVerdict.UNKNOWN
        return DeclarationVerdict.ABSENT


def build_crossjob_declaration_view(content: str) -> CrossJobDeclarationView | None:
    """Return one bounded structural view suitable for negative certificates."""
    return CrossJobDeclarationView.build(content)
