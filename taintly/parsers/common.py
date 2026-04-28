"""Common parsing utilities shared across platform parsers."""

from __future__ import annotations

import re


def strip_comments(content: str) -> str:
    """Remove YAML comment lines from content."""
    lines = content.splitlines()
    return "\n".join(line for line in lines if not line.strip().startswith("#"))


def extract_yaml_key(content: str, key: str) -> str | None:
    """Extract the value of a top-level YAML key."""
    pattern = re.compile(rf"^{re.escape(key)}:\s*(.+)$", re.MULTILINE)
    m = pattern.search(content)
    return m.group(1).strip() if m else None


def find_block(content: str, block_key: str) -> str | None:
    """Extract the indented block following a top-level key."""
    lines = content.splitlines()
    in_block = False
    block_lines = []
    base_indent = 0

    for line in lines:
        if re.match(rf"^{re.escape(block_key)}:\s*$", line):
            in_block = True
            base_indent = len(line) - len(line.lstrip())
            continue

        if in_block:
            if line.strip() == "":
                block_lines.append(line)
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= base_indent and line.strip():
                break
            block_lines.append(line)

    return "\n".join(block_lines) if block_lines else None


def normalize_line_endings(content: str) -> str:
    """Normalize CRLF and CR to LF."""
    return content.replace("\r\n", "\n").replace("\r", "\n")
