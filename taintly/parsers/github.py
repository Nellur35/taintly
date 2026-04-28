"""GitHub Actions workflow file parser utilities."""

from __future__ import annotations

import re

from .common import normalize_line_endings


def is_github_workflow(content: str) -> bool:
    """Heuristic: does this look like a GitHub Actions workflow?"""
    return bool(re.search(r"^(on|jobs):", content, re.MULTILINE))


def extract_triggers(content: str) -> list[str]:
    """Extract the list of event triggers from a workflow."""
    content = normalize_line_endings(content)
    triggers = []

    # Match: on: [push, pull_request]
    inline = re.search(r"^on:\s*\[([^\]]+)\]", content, re.MULTILINE)
    if inline:
        return [t.strip() for t in inline.group(1).split(",")]

    # Match multi-line on: block
    on_block = re.search(r"^on:\s*\n((?:[ \t]+\S.*\n?)*)", content, re.MULTILINE)
    if on_block:
        for line in on_block.group(1).splitlines():
            m = re.match(r"\s+(\w[\w_-]+):", line)
            if m:
                triggers.append(m.group(1))

    # Match: on: push
    simple = re.search(r"^on:\s+(\w+)\s*$", content, re.MULTILINE)
    if simple and not triggers:
        triggers.append(simple.group(1))

    return triggers


def extract_jobs(content: str) -> list[str]:
    """Extract job names from a workflow."""
    return re.findall(r"^  (\w[\w-]*):\s*$", content, re.MULTILINE)


def has_permission_block(content: str) -> bool:
    """Check if workflow has a top-level permissions block."""
    return bool(re.search(r"^permissions:", content, re.MULTILINE))


def extract_uses_refs(content: str) -> list[tuple[str, str, int]]:
    """Extract all 'uses:' references.

    Returns list of (action, ref, line_number) tuples.
    """
    results = []
    for i, line in enumerate(content.splitlines(), 1):
        m = re.search(r"uses:\s*([^@\s]+)@(\S+)", line)
        if m and not line.strip().startswith("#"):
            results.append((m.group(1), m.group(2), i))
    return results
