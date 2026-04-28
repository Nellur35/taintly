"""GitLab CI config file parser utilities."""

from __future__ import annotations

import re
from typing import Any


def is_gitlab_ci(content: str) -> bool:
    """Heuristic: does this look like a GitLab CI config?"""
    return bool(re.search(r"^(stages:|image:|variables:)", content, re.MULTILINE))


def extract_stages(content: str) -> list[str]:
    """Extract stage names from a GitLab CI config."""
    m = re.search(r"^stages:\s*\n((?:\s+-\s+\S+\n?)+)", content, re.MULTILINE)
    if not m:
        return []
    return re.findall(r"-\s+(\S+)", m.group(1))


def extract_includes(content: str) -> list[dict[str, Any]]:
    """Extract include directives from a GitLab CI config.

    Returns list of dicts with keys: type (local/remote/project/template), value.
    """
    includes: list[dict[str, Any]] = []
    include_block = re.search(r"^include:\s*\n((?:[ \t]+.*\n?)+)", content, re.MULTILINE)
    if not include_block:
        return includes

    block = include_block.group(1)
    for include_type in ("local", "remote", "project", "template", "component"):
        includes.extend(
            {"type": include_type, "value": m.group(1).strip()}
            for m in re.finditer(rf"{include_type}:\s*['\"]?([^'\"\\n]+)['\"]?", block)
        )

    return includes


def extract_image(content: str) -> str | None:
    """Extract the global image directive."""
    m = re.search(r"^image:\s*['\"]?([^'\"\\n]+)['\"]?", content, re.MULTILINE)
    return m.group(1).strip() if m else None


def extract_job_names(content: str) -> list[str]:
    """Extract top-level job names (non-keyword, non-hidden)."""
    keywords = {
        "image",
        "services",
        "stages",
        "types",
        "before_script",
        "after_script",
        "variables",
        "cache",
        "include",
        "workflow",
        "default",
        "pages",
    }
    jobs = []
    for m in re.finditer(r"^([a-zA-Z][a-zA-Z0-9_-]*):\s*$", content, re.MULTILINE):
        name = m.group(1)
        if name not in keywords and not name.startswith("."):
            jobs.append(name)
    return jobs
