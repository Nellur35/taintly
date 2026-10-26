"""Owned GitHub Actions job/service image references for digest checks."""

from __future__ import annotations

import re

from taintly.models import IncompletePatternMatches
from taintly.parsers.structural import EventKind, walk_workflow

_DIGEST = re.compile(r"@sha256:[0-9a-fA-F]{64}\Z")


class GithubImageReferencePattern:
    """Classify only configured image consumers, never matrix data or script text.

    `kind` is one of `tagged`, `latest`, or `untagged`. The tagged
    variant carries incomplete coverage for dynamic or unsupported refs.
    """

    def __init__(self, kind: str) -> None:
        if kind not in {"tagged", "latest", "untagged"}:
            raise ValueError(f"Unsupported image-reference kind: {kind}")
        self.kind = kind

    def self_test_mutation_applicable(self, source: str, mutant: str, operator: str) -> bool:
        return not (
            operator == "whitespace_pad" and ": " in source and mutant == source.replace(": ", ":")
        )

    def check_with_filepath(
        self, content: str, lines: list[str], filepath: str
    ) -> list[tuple[int, str]]:
        if not filepath.lower().endswith((".yml", ".yaml")):
            return []
        return self.check(content, lines)

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if "jobs" not in content or ("container" not in content and "services" not in content):
            return []
        matches: list[tuple[int, str]] = []
        unresolved = False
        for event in walk_workflow(
            "workflow.yml", content=content, include_keys=True, recover=True
        ):
            if event.kind in {EventKind.ERROR, EventKind.CUTOFF}:
                unresolved = True
                continue
            if event.kind is not EventKind.LEAF_SCALAR or event.value is None:
                continue
            path = event.path
            if not (
                len(path) >= 3
                and path[0] == "jobs"
                and isinstance(path[1], str)
                and (
                    path[2:] == ("container",)
                    or path[2:] == ("container", "image")
                    or (
                        len(path) == 5
                        and path[2] == "services"
                        and isinstance(path[3], str)
                        and path[4] == "image"
                    )
                )
            ):
                continue
            reference = event.value.strip()
            if not reference:
                # GitHub allows an empty service image to disable it.
                continue
            if _DIGEST.search(reference):
                continue
            if "${{" in reference or "$" in reference or "@" in reference:
                unresolved = True
                continue
            image_name = reference.rsplit("/", 1)[-1]
            if ":" not in image_name:
                kind = "untagged"
            elif image_name.rsplit(":", 1)[-1] == "latest":
                kind = "latest"
            else:
                kind = "tagged"
            if kind == self.kind and 0 < event.line <= len(lines):
                matches.append((event.line, lines[event.line - 1].strip()))
        if unresolved and self.kind == "tagged":
            return IncompletePatternMatches(
                matches,
                reason="GitHub image reference or YAML structure could not be resolved",
            )
        return matches
