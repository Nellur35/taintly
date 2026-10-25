"""Review source-owned GitLab Vault selectors that use external CI values.

GitLab Runner expands variables in the structured Vault path. A reported
GitLab regression leaves variables in the short ``vault: path@engine`` form
unexpanded. Without the provider version/effective configuration, that short
form is an unresolved candidate rather than evidence of a secret lookup.
"""

from __future__ import annotations

import re
from collections import Counter

from taintly.models import IncompletePatternMatches
from taintly.parsers.structural import EventKind, walk_workflow

_EXTERNAL_CI_VAR = (
    r"(?:CI_COMMIT_(?:REF_NAME|REF_SLUG|BRANCH|TITLE|MESSAGE|DESCRIPTION|AUTHOR|TAG_NAME)"
    r"|CI_MERGE_REQUEST_(?:SOURCE_BRANCH_NAME|TITLE|DESCRIPTION|LABELS)"
    r"|CI_EXTERNAL_PULL_REQUEST_\w+)"
)
_SELECTOR = re.compile(rf"\$(?:{_EXTERNAL_CI_VAR}\b|\{{{_EXTERNAL_CI_VAR}\}})")


class GitLabVaultSelectorPattern:
    """Bounded selector check for one physical GitLab YAML source file."""

    def self_test_mutation_applicable(self, source: str, mutant: str, operator: str) -> bool:
        if operator != "whitespace_pad":
            return True

        def selector_paths(text: str) -> set[tuple[object, ...]] | None:
            events = tuple(
                walk_workflow(
                    ".gitlab-ci.yml",
                    content=text,
                    include_keys=True,
                    include_merge_origins=True,
                    recover=True,
                )
            )
            if any(e.kind in {EventKind.ERROR, EventKind.CUTOFF} for e in events):
                return None
            return {
                e.path
                for e in events
                if e.kind is EventKind.LEAF_SCALAR
                and len(e.path) == 5
                and e.path[1] == "secrets"
                and e.path[3:] == ("vault", "path")
                and _SELECTOR.search(e.value or "")
            }

        before = selector_paths(source)
        after = selector_paths(mutant)
        return bool(before and after and before <= after)

    def check(self, content: str, lines: list[str]):
        return self.check_with_filepath(content, lines, ".gitlab-ci.yml")

    def check_with_filepath(self, content: str, lines: list[str], filepath: str):
        if "vault" not in content or not _SELECTOR.search(content):
            return []
        events = tuple(
            walk_workflow(
                filepath,
                content=content,
                include_keys=True,
                include_merge_origins=True,
                recover=True,
            )
        )
        if any(e.kind in {EventKind.ERROR, EventKind.CUTOFF} for e in events):
            return IncompletePatternMatches(
                [], reason="TAINT-GL-007 GitLab YAML structure could not be fully read"
            )
        leaves = [e for e in events if e.kind is EventKind.LEAF_SCALAR]
        counts = Counter(e.path for e in leaves)
        paths = {e.path for e in leaves}
        merged_paths = {e.path for e in leaves if e.merge_origins}
        matches: list[tuple[int, str]] = []
        incomplete: list[str] = []
        for event in leaves:
            path = event.path
            if (
                len(path) < 4
                or not isinstance(path[0], str)
                or path[1] != "secrets"
                or not isinstance(path[2], str)
                or path[3] != "vault"
                or not _SELECTOR.search(event.value or "")
            ):
                continue
            if path[0].startswith("."):
                incomplete.append("TAINT-GL-007 hidden Vault template needs an owning job")
                continue
            if event.merge_origins or counts[path] != 1:
                incomplete.append("TAINT-GL-007 Vault selector ownership is ambiguous")
                continue
            if len(path) == 4:
                incomplete.append(
                    "TAINT-GL-007 short-form Vault variable expansion needs provider-version evidence"
                )
                continue
            if len(path) != 5 or path[4] != "path":
                continue
            owner = path[:4]
            required = (
                owner + ("engine", "name"),
                owner + ("engine", "path"),
                owner + ("field",),
            )
            if any(
                sibling not in paths or counts[sibling] != 1 or sibling in merged_paths
                for sibling in required
            ):
                incomplete.append(
                    "TAINT-GL-007 structured Vault path needs explicit engine and field source"
                )
                continue
            if not 0 < event.line <= len(lines):
                incomplete.append("TAINT-GL-007 Vault path source line is unavailable")
                continue
            matches.append((event.line, lines[event.line - 1].strip()))
        if incomplete:
            return IncompletePatternMatches(matches, reason="; ".join(dict.fromkeys(incomplete)))
        return matches
