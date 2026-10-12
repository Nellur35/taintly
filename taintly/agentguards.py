"""Structural ownership and conservative execution proofs for agent rules.

Outside-trigger identity facts are opt-in. They never establish the integrity
of remote content fetched by a trusted actor. Unknown structure retains review.
"""

import re
import shlex

from taintly.eventguard import event_guard_verdict
from taintly.parsers.structural import EventKind, triggers, walk_workflow

Owner = tuple[object, ...]


class AgentGuardIndex:
    """One bounded structural view; ambiguous files cannot supply safe proofs."""

    def __init__(self, content: str):
        self.valid = True
        self.events = triggers(content)
        self.keys: dict[Owner, int] = {}
        self.values: dict[Owner, str | None] = {}
        self.owners: dict[int, set[Owner | None]] = {}
        self.lines = content.splitlines()
        for leaf in walk_workflow(
            "workflow.yml", content=content, include_keys=True, include_merge_origins=True
        ):
            if leaf.kind in {EventKind.ERROR, EventKind.CUTOFF} or leaf.merge_origins:
                self.valid = False
                continue
            path = leaf.path
            if leaf.kind is EventKind.MAP_KEY:
                if path in self.keys:
                    self.valid = False
                self.keys[path] = leaf.line
            elif leaf.kind is EventKind.LEAF_SCALAR:
                if path in self.values:
                    self.valid = False
                self.values[path] = leaf.value
            else:
                continue
            step = (
                path[:4]
                if len(path) >= 5
                and path[0] == "jobs"
                and isinstance(path[1], str)
                and path[2] == "steps"
                and isinstance(path[3], int)
                else None
            )
            for number in (leaf.line, *(n for n, _ in (leaf.block_lines or ()))):
                self.owners.setdefault(number, set()).add(step)

    def owner(self, line: int) -> Owner | None:
        choices = self.owners.get(line, set())
        return next(iter(choices)) if self.valid and len(choices) == 1 else None

    def excludes(self, owner: Owner, *, outside_actor: bool = True) -> bool:
        """Prove owning execution impossible for every relevant event."""
        if not self.valid:
            return False
        events = self.events
        if outside_actor:
            events = events - {"push", "schedule", "workflow_dispatch"}
        if not events:
            return False
        guards = (owner[:2], owner) if len(owner) == 4 else (owner,)
        for event in events:
            equalities = {}
            exclusions = {}
            if outside_actor:
                if event in {"pull_request", "pull_request_target"}:
                    equalities[
                        frozenset(
                            {"github.event.pull_request.head.repo.full_name", "github.repository"}
                        )
                    ] = False
                subject = {
                    "pull_request": "pull_request",
                    "pull_request_target": "pull_request",
                    "issue_comment": "comment",
                    "issues": "issue",
                    "discussion": "discussion",
                }.get(event)
                if subject:
                    exclusions[f"github.event.{subject}.author_association"] = frozenset(
                        {"owner", "member", "collaborator"}
                    )
            if not any(
                event_guard_verdict(
                    self.values.get(guard + ("if",)),
                    event,
                    path_equalities=equalities,
                    path_string_exclusions=exclusions,
                )
                is False
                for guard in guards
            ):
                return False
        return True

    def permissions_write(self, owner: Owner) -> bool | None:
        """Declared effective token grant; None never proves actual write."""
        if not self.valid:
            return None
        path = owner[:2] + ("permissions",)
        if path not in self.keys:
            path = ("permissions",)
        if path not in self.keys:
            return None
        line = self.lines[self.keys[path] - 1]
        if "{" in line or "}" in line:
            flow = re.search(r"\bpermissions\s*:\s*\{([^{}]*)\}\s*(?:#.*)?$", line)
            if not flow:
                return None
            entries = flow.group(1).split(",") if flow.group(1).strip() else []
            if any(
                not re.fullmatch(r"\s*[a-z][a-z-]*\s*:\s*(?:read|write|none)\s*", entry)
                for entry in entries
            ):
                return None
        scalar = self.values.get(path)
        if scalar in {"read-all", "write-all"}:
            return scalar == "write-all"
        if scalar is not None:
            return None
        grants = {p[-1]: v for p, v in self.values.items() if p[:-1] == path}
        if grants:
            children = {p for p in self.keys if p[: len(path)] == path and p != path}
            scopes = {
                "actions",
                "artifact-metadata",
                "attestations",
                "checks",
                "contents",
                "deployments",
                "discussions",
                "id-token",
                "issues",
                "models",
                "packages",
                "pages",
                "pull-requests",
                "security-events",
                "statuses",
            }
            if any(
                len(child) != len(path) + 1 or child[-1] not in scopes or child not in self.values
                for child in children
            ):
                return None
            if "write" in grants.values():
                return True
            if all(value in {"read", "none"} for value in grants.values()):
                return False
        # Null/unsupported containers are not the explicit empty permission map.
        if re.search(r"\bpermissions\s*:\s*\{\s*\}\s*(?:#.*)?$", line):
            return False
        return None

    def builtin_tools_closed(self, owner: Owner) -> bool:
        """Recognize literal read-only profiles, not permission approval text.

        This proves a bounded declared tool restriction, not absence of all
        possible agent risks. Unknown vendors, settings, flags and tools retain
        review. MCP execution needs an explicit deny in the Claude profile.
        """
        if not self.valid:
            return False
        action = self.values.get(owner + ("uses",))
        inputs = {p[-1]: value for p, value in self.values.items() if p[:-1] == owner + ("with",)}
        input_keys = {p[-1] for p in self.keys if p[:-1] == owner + ("with",)}
        if action == "anthropics/claude-code-action@v1":
            if not input_keys <= {
                "claude_args",
                "prompt",
                "anthropic_api_key",
                "claude_code_oauth_token",
                "github_token",
            }:
                return False
            args = inputs.get("claude_args")
            if not args or any(marker in args for marker in ("$", "`")):
                return False
            try:
                words = shlex.split(args)
            except ValueError:
                return False
            flags: dict[str, str] = {}
            while words:
                flag, sep, value = words.pop(0).partition("=")
                if flag not in {"--tools", "--disallowedTools", "--disallowed-tools"}:
                    return False
                flag = "--disallowedTools" if flag == "--disallowed-tools" else flag
                if flag in flags:
                    return False
                if not sep:
                    if not words or words[0].startswith("--"):
                        return False
                    value = words.pop(0)
                flags[flag] = value
            if set(flags) != {"--tools", "--disallowedTools"}:
                return False
            tools = flags["--tools"].split(",") if flags["--tools"] else []
            return set(tools) <= {"Read", "Grep", "Glob"} and flags["--disallowedTools"] == "mcp__*"
        # Gemini tools.core constrains built-ins, not the effective MCP or
        # extension registry. A core list alone cannot supply a closed proof.
        return False

    def _number_context(self, expression: str) -> bool:
        """Prove provider numeric atoms or empty, never a positive ID.

        The runner uses invariant G15 number formatting: decimal/exponent text
        or the single atoms NaN/Infinity/-Infinity, without shell syntax. A
        negative digit or -Infinity starts an unknown gh short flag and fails;
        it cannot enable a content selector. Missing context contributes empty.
        Only declared input types and provider-owned number fields are modeled;
        the default's lexical check below does not establish finite magnitude.
        """
        modeled = {
            "pull_request",
            "pull_request_target",
            "issues",
            "issue_comment",
            "workflow_dispatch",
            "workflow_call",
            "push",
            "schedule",
        }
        if not self.events or not self.events <= modeled:
            return False
        if expression in {"github.event.pull_request.number", "github.event.issue.number"}:
            return True
        match = re.fullmatch(r"inputs\.([A-Za-z_][A-Za-z_0-9-]*)", expression)
        if not match:
            return False
        input_events = self.events & {"workflow_dispatch", "workflow_call"}
        if not input_events:
            return False
        for event in input_events:
            path = ("on", event, "inputs", match.group(1))
            if self.values.get(path + ("type",)) != "number":
                return False
            default = self.values.get(path + ("default",))
            if default is not None and not re.fullmatch(
                r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", default
            ):
                return False
        return True

    def _posix_numeric_step(self, owner: Owner) -> bool:
        """Require a known shell and no visible output/startup-path overrides."""
        runner = self.values.get(owner[:2] + ("runs-on",), "")
        if (
            owner[:2] + ("container",) in self.keys
            or not isinstance(runner, str)
            or not re.fullmatch(r"(?:ubuntu|macos)-(?:latest|[0-9]+(?:\.[0-9]+)?)", runner)
        ):
            return False
        if re.search(
            r"(?<![A-Za-z_0-9])(?:BASH_ENV|ENV|GITHUB_ENV|GITHUB_PATH)(?![A-Za-z_0-9])"
            r"|(?<![A-Za-z_0-9])BASH_FUNC_",
            "\n".join(self.lines),
        ):
            return False
        for prefix in (("env",), owner[:2] + ("env",), owner + ("env",)):
            if self.values.get(prefix) is not None:
                return False
            if any(
                path[:-1] == prefix
                and path[-1] in {"PATH", "IFS", "GITHUB_OUTPUT", "BASH_ENV", "ENV"}
                for path in self.keys
            ):
                return False
        for path in (
            owner + ("shell",),
            owner[:2] + ("defaults", "run", "shell"),
            ("defaults", "run", "shell"),
        ):
            if path in self.keys:
                return self.values.get(path) in {"bash", "sh"}
        return True

    def _numeric_output(self, owner: Owner, step_id: str, output: str) -> bool:
        """One earlier pure writer; every branch writes number text or empty."""
        ids = {
            path[:4]: value
            for path, value in self.values.items()
            if len(path) == 5 and path[:3] == owner[:3] and path[-1] == "id"
        }
        if any(
            not isinstance(value, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9-]*", value)
            for value in ids.values()
        ):
            return False
        if len({value.lower() for value in ids.values() if value}) != len(ids):
            return False
        producers = [path for path, value in ids.items() if value == step_id]
        if len(producers) != 1:
            return False
        producer = producers[0]
        if (
            not isinstance(producer[3], int)
            or not isinstance(owner[3], int)
            or producer[3] >= owner[3]
            or producer + ("uses",) in self.keys
            or not self._posix_numeric_step(producer)
        ):
            return False
        run = self.values.get(producer + ("run",))
        if not isinstance(run, str):
            return False
        header = self.lines[self.keys[producer + ("run",)] - 1]
        if re.search(r"\brun\s*:\s*>[+-]?", header):
            return False
        commands = [
            line.strip()
            for line in run.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if len(commands) == 5:
            if not (
                re.fullmatch(
                    r"if\s+\[\s+(['\"])\$\{\{\s*github\.event_name\s*\}\}\1"
                    r"\s+={1,2}\s+(['\"])[A-Za-z_]+\2\s+\];\s*then",
                    commands[0],
                )
                and commands[2] == "else"
                and commands[4] == "fi"
            ):
                return False
            commands = [commands[1], commands[3]]
        elif len(commands) != 1:
            return False
        for command in commands:
            write = re.fullmatch(
                r"echo\s+(['\"])([A-Za-z_][A-Za-z_0-9-]*)="
                r"\$\{\{\s*([^{}]+?)\s*\}\}\1\s*>>\s*"
                r'(?:\$GITHUB_OUTPUT|"\$GITHUB_OUTPUT")',
                command,
            )
            if (
                not write
                or write.group(2) != output
                or not self._number_context(write.group(3).strip())
            ):
                return False
        return True

    def _numeric_read_operand(self, text: str, owner: Owner) -> str:
        """Abstract one standalone number-or-empty operand, never a flag value."""
        match = re.fullmatch(
            r"gh\s+(?:pr|issue)\s+view\s+(['\"]?)"
            r"(?P<expression>\$\{\{\s*(?P<path>[^{}]+?)\s*\}\})\1\s+.+",
            text,
        )
        if not match or not self._posix_numeric_step(owner):
            return text
        expression = match.group("path").strip()
        proved = self._number_context(expression)
        output = re.fullmatch(
            r"steps\.([A-Za-z_][A-Za-z_0-9-]*)\.outputs\.([A-Za-z_][A-Za-z_0-9-]*)",
            expression,
        )
        if output:
            proved = self._numeric_output(owner, output.group(1), output.group(2))
        return text.replace(match.group("expression"), "1", 1) if proved else text

    def read_selects_only_metadata(self, line: int) -> bool:
        """A fixed gh selector excludes title/body/comments from this read.

        This is not a proof that metadata is immutable, or that another read
        or the agent's own behavior is safe. Unsupported commands stay unknown.
        """
        owner = self.owner(line)
        if owner is None or owner + ("run",) not in self.values:
            return False
        header_line = self.keys[owner + ("run",)]
        if line != header_line and not re.fullmatch(
            r"\s*(?:-\s*)?run\s*:\s*\|[+-]?\s*(?:#.*)?", self.lines[header_line - 1]
        ):
            return False
        text = self.lines[line - 1].strip()
        # A scalar header may contain a direct command. Quoted YAML scalars,
        # folded commands and shell continuations are outside this proof.
        header = re.fullmatch(r"(?:-\s*)?run\s*:\s*(.*)", text)
        if header:
            text = header.group(1)
        assignment = re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*=\$\((.*)\)", text)
        if assignment:
            text = assignment.group(1)
        text = self._numeric_read_operand(text, owner)
        # Unproved GitHub interpolation is shell-source substitution, not one
        # argv operand. Even a quoted shell variable may supply an option.
        # Only the bounded numeric-or-empty domain above may be abstracted.
        if any(
            marker in text for marker in ("$", "`", "\\", "#", ";", "&", "|", "<", ">", "(", ")")
        ):
            return False
        try:
            words = shlex.split(text)
        except ValueError:
            return False
        if len(words) < 4 or words[:3] not in (["gh", "pr", "view"], ["gh", "issue", "view"]):
            return False
        fields_allowed = {
            "number",
            "id",
            "state",
            "mergeable",
            "isDraft",
            "baseRefName",
            "baseRefOid",
            "headRefOid",
        }
        is_issue = words[1] == "issue"
        if is_issue:
            fields_allowed = {"number", "id", "state"}
        flags: dict[str, str] = {}
        operand = False
        words = words[3:]
        while words:
            word = words.pop(0)
            if re.fullmatch(r"[1-9][0-9]*", word) and not operand:
                operand = True
                continue
            flag, sep, value = word.partition("=")
            flag = "--jq" if flag == "-q" else flag
            if flag not in {"--json", "--jq"} or flag in flags:
                return False
            if not sep:
                if not words:
                    return False
                value = words.pop(0)
            flags[flag] = value
        selector = flags.get("--json", "")
        fields = selector.split(",")
        if not selector or not set(fields) <= fields_allowed or (is_issue and not operand):
            return False
        # Output shaping never erases a fetched content field. Only a literal
        # simple field projection is admitted here; all other jq stays unknown.
        return "--jq" not in flags or flags["--jq"] in {"." + field for field in fields}
