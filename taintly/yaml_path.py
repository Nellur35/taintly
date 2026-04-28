"""Lightweight YAML path extractor for CI/CD configuration files.

Produces a flat list of (path, value, line_no) tuples from YAML content.
Handles the mapping-centric subset used by GitHub Actions, GitLab CI, and
Jenkins declarative pipelines.

Design constraints
------------------
- Zero external dependencies — pure stdlib
- Handles mapping keys at any indent depth
- Sequence items (- key: value) emit their inline key at the parent path level
  but do NOT create a persistent path component for subsequent sibling keys.
  This is a deliberate simplification: the rules that use PathPattern query
  job-level mapping paths (strategy.matrix.*, services.*.options) where
  sequences do not appear in the path itself.
- Block scalars (|, >) are detected and their content is skipped
- Inline comments are stripped from values
- Graceful degradation: lines that can't be parsed are silently skipped

Limitations (acceptable for current rules)
------------------------------------------
- Step-level paths (jobs.X.steps.Y.uses) are extracted but may be ambiguous
  when multiple steps exist — existing regex rules cover step-level checks
- Anchors/aliases (&name, *name) are not resolved
- Merge keys (<<:) are not supported
- Inline mappings ({key: val}) are skipped
"""

from __future__ import annotations

import re

# Block scalar indicators
_BLOCK_SCALAR_RE = re.compile(r"^[|>][+\-]?\d*$")


def _strip_inline_comment(raw_val: str) -> str:
    """Strip a trailing YAML inline comment from a value, respecting quotes.

    A naive ``\\s+#.*$`` regex truncates valid quoted scalars that contain
    ``#`` — for example the value ``"release #1 candidate"`` becomes
    ``"release``.  Walk the string character by character instead, tracking
    whether we're inside a single- or double-quoted scalar, and only treat
    ``#`` as a comment start when we're outside quotes.

    GitHub Actions expression strings like ``${{ ... }}`` are preserved.
    The rule is: a ``#`` preceded by whitespace, outside of quotes and
    outside of a ``${{ ... }}`` expression, starts a comment.
    """
    in_single = False
    in_double = False
    expr_depth = 0  # inside ${{ ... }}
    prev = ""
    for i, ch in enumerate(raw_val):
        if in_single:
            if ch == "'":
                in_single = False
        elif in_double:
            # YAML double-quoted: \" is an escape
            if ch == '"' and prev != "\\":
                in_double = False
        else:
            if ch == "'":
                in_single = True
            elif ch == '"':
                in_double = True
            elif ch == "{" and prev == "$":
                expr_depth += 1
            elif ch == "}" and expr_depth > 0:
                expr_depth -= 1
            elif ch == "#" and expr_depth == 0 and (i == 0 or raw_val[i - 1].isspace()):
                # Comment start — return the value up to (and excluding)
                # this character, trimmed.
                return raw_val[:i].rstrip()
        prev = ch
    return raw_val


def _unquote(s: str) -> str:
    """Strip surrounding single or double quotes from a YAML scalar."""
    s = s.strip()
    if len(s) >= 2 and s[0] in ('"', "'") and s[-1] == s[0]:
        return s[1:-1]
    return s


def extract_paths(content: str) -> list[tuple[str, str, int]]:
    """Extract (path, value, line_no) tuples from YAML content.

    Each tuple represents a scalar value at a specific YAML path:
    - path:    Dot-separated key path, e.g. "jobs.build.strategy.matrix.os"
    - value:   The scalar value at that path, unquoted
    - line_no: 1-based source line number

    Example
    -------
    For the snippet::

        on:
          workflow_dispatch:
            inputs:
              env:
                type: string
                description: Target environment

    Returns::

        [
          ("on.workflow_dispatch.inputs.env.type",        "string",             5),
          ("on.workflow_dispatch.inputs.env.description", "Target environment", 6),
        ]
    """
    lines = content.splitlines()
    results: list[tuple[str, str, int]] = []

    # Stack of (indent_level, key) representing the current path context.
    # indent_level is the number of leading spaces on the line that introduced
    # the key (for regular mapping keys) or the position of the '-' for
    # sequence items.
    stack: list[tuple[int, str]] = []

    # Block scalar tracking: when True, skip lines until indent drops back
    in_block_scalar = False
    block_scalar_indent = -1

    for lineno, raw in enumerate(lines, start=1):
        stripped = raw.lstrip()

        # Skip blank lines and comments
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(raw) - len(stripped)

        # -------------------------------------------------------------------
        # Block scalar content: skip until we return to the parent indent
        # -------------------------------------------------------------------
        if in_block_scalar:
            if indent > block_scalar_indent:
                continue  # still inside the block scalar
            in_block_scalar = False

        # -------------------------------------------------------------------
        # Sequence item: "- key: value" or "- scalar"
        # -------------------------------------------------------------------
        is_seq = stripped.startswith("- ")
        if is_seq:
            content_part = stripped[2:].strip()
            # Sequence items pop the stack to their '-' indent level but do
            # NOT push themselves — they are transient (no persistent path
            # component for sibling keys in the same step/item).
            stack = [(i, k) for i, k in stack if i < indent]
        else:
            content_part = stripped

        # -------------------------------------------------------------------
        # Must contain a colon to be a key or key-value pair
        # -------------------------------------------------------------------
        if ":" not in content_part:
            continue

        colon = content_part.index(":")
        raw_key = content_part[:colon].strip()
        raw_val = content_part[colon + 1 :].strip()

        # Skip keys with unquoted spaces (not a valid simple YAML key)
        if raw_key and " " in raw_key and raw_key[0] not in ('"', "'"):
            continue

        # Skip empty or purely numeric keys (YAML sequence indices, anchors)
        if not raw_key or raw_key.isdigit():
            continue

        key = _unquote(raw_key)

        # -------------------------------------------------------------------
        # Update path stack for regular mapping keys
        # -------------------------------------------------------------------
        if not is_seq:
            stack = [(i, k) for i, k in stack if i < indent]
            stack.append((indent, key))

        # -------------------------------------------------------------------
        # Build the dot-path for this key
        # -------------------------------------------------------------------
        if is_seq:
            # Sequence item key: emit under current stack path
            path = ".".join(k for _, k in stack) + ("." if stack else "") + key
        else:
            path = ".".join(k for _, k in stack)

        # -------------------------------------------------------------------
        # Process the value
        # -------------------------------------------------------------------
        if raw_val:
            # Strip inline comments, respecting quoted strings and GitHub
            # Actions ${{ }} expressions so a value like
            #   "release #1 candidate"
            # isn't truncated at the hash.
            val = _strip_inline_comment(raw_val).strip()

            if _BLOCK_SCALAR_RE.match(val):
                # Block scalar follows — record indent, skip content
                in_block_scalar = True
                block_scalar_indent = indent
            elif val and not val.startswith("{") and not val.startswith("["):
                # Emit this scalar
                results.append((path, _unquote(val), lineno))
        else:
            # Mapping/sequence block header — emit with empty value so the
            # PATH is registered in the path set for sibling-absence checks.
            # PathPattern skips empty-value entries for value matching.
            results.append((path, "", lineno))

    return results
