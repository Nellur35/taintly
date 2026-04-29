"""Schemas for the structural CI YAML reader.

A schema names the value-shape (string / sequence / mapping / etc.)
expected at well-known paths so the walker can disambiguate cases
where the token stream alone is ambiguous (most commonly: a key
whose value is a single-line scalar that happens to start with
a flow-indicator character).

Phase 1 ships GitHub Actions and GitLab CI schemas.  Jenkinsfile
is intentionally out of scope (Groovy DSL, not YAML); a separate
Groovy-DSL reader is a different decision.

Schemas are populated lazily — modules import these only when the
auto-detect path needs them.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Mapping


class ValueShape(Enum):
    STRING = "string"
    NUMBER = "number"
    BOOLEAN = "boolean"
    SEQUENCE_OF_STRING = "seq_str"
    MAPPING_OF_STRING = "map_str"
    STRING_OR_SEQUENCE_OF_STRING = "str_or_seq_str"
    STRING_OR_MAPPING = "str_or_map"
    STRING_OR_SEQUENCE_OR_MAPPING = "str_or_seq_or_map"
    UNKNOWN = "unknown"


def detect_schema_for_path(filepath: str) -> str:
    """Return the schema name for ``filepath`` based on its location.

    The detection rule is conservative: if the filepath looks like a
    GitHub Actions workflow (under ``.github/workflows/``), use the
    GH schema; if it looks like a GitLab CI file, use GL; otherwise
    return ``"unknown"`` (the walker still works, just with
    UNKNOWN value shapes for every path — token-shape inference
    handles the common cases).
    """
    p = str(filepath).replace("\\", "/").lower()
    if "/.github/workflows/" in p or p.endswith(".github/workflows/"):
        return "github_actions"
    if p.endswith(".gitlab-ci.yml") or "/.gitlab-ci.yml" in p:
        return "gitlab_ci"
    if "/.gitlab/" in p and (p.endswith(".yml") or p.endswith(".yaml")):
        return "gitlab_ci"
    if Path(filepath).name in {".gitlab-ci.yml", ".gitlab-ci.yaml"}:
        return "gitlab_ci"
    return "unknown"


def get_schema(name: str) -> Mapping[str, ValueShape]:
    """Return the schema dict for a registered schema name.

    Unknown names fall back to an empty schema (every path resolves
    to ``ValueShape.UNKNOWN``).
    """
    if name == "github_actions":
        from . import github_actions as _gh

        return _gh.SCHEMA
    if name == "gitlab_ci":
        from . import gitlab_ci as _gl

        return _gl.SCHEMA
    return {}


__all__ = ["ValueShape", "detect_schema_for_path", "get_schema"]
