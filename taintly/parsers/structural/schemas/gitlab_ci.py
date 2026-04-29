"""GitLab CI pipeline schema.

Path globs map to the value shape GitLab's pipeline configuration
expects.  Coverage scope: paths the existing rule pack queries
(per the ``scripts/audit_rule_paths.py`` audit).
"""

from __future__ import annotations

from . import ValueShape

SCHEMA: dict[str, ValueShape] = {
    # Top-level reserved keys
    "stages": ValueShape.SEQUENCE_OF_STRING,
    "image": ValueShape.STRING_OR_MAPPING,
    "image.name": ValueShape.STRING,
    "services": ValueShape.STRING_OR_SEQUENCE_OR_MAPPING,
    "variables": ValueShape.MAPPING_OF_STRING,
    "include": ValueShape.STRING_OR_SEQUENCE_OR_MAPPING,
    "default": ValueShape.STRING_OR_MAPPING,
    "default.image": ValueShape.STRING_OR_MAPPING,
    "default.before_script": ValueShape.SEQUENCE_OF_STRING,
    "default.after_script": ValueShape.SEQUENCE_OF_STRING,
    "default.cache": ValueShape.STRING_OR_MAPPING,
    "workflow": ValueShape.STRING_OR_MAPPING,
    "workflow.rules": ValueShape.STRING_OR_SEQUENCE_OR_MAPPING,

    # Per-job (``jobs.*`` is a glob even though GitLab jobs aren't
    # under a ``jobs:`` key — the structural reader normalises top-
    # level non-reserved mapping entries as job entries via the
    # ``**`` glob pattern in the walker for GitLab files).  This is
    # imperfect; phase-2 migrations refine.
    "*.image": ValueShape.STRING_OR_MAPPING,
    "*.script": ValueShape.STRING_OR_SEQUENCE_OF_STRING,
    "*.before_script": ValueShape.SEQUENCE_OF_STRING,
    "*.after_script": ValueShape.SEQUENCE_OF_STRING,
    "*.variables": ValueShape.MAPPING_OF_STRING,
    "*.environment": ValueShape.STRING_OR_MAPPING,
    "*.environment.name": ValueShape.STRING,
    "*.artifacts": ValueShape.STRING_OR_MAPPING,
    "*.cache": ValueShape.STRING_OR_MAPPING,
    "*.only": ValueShape.STRING_OR_SEQUENCE_OR_MAPPING,
    "*.except": ValueShape.STRING_OR_SEQUENCE_OR_MAPPING,
    "*.rules": ValueShape.STRING_OR_SEQUENCE_OR_MAPPING,
    "*.extends": ValueShape.STRING_OR_SEQUENCE_OF_STRING,
    "*.trigger": ValueShape.STRING_OR_MAPPING,
    "*.resource_group": ValueShape.STRING,
    "*.tags": ValueShape.SEQUENCE_OF_STRING,
    "*.stage": ValueShape.STRING,
    "*.needs": ValueShape.STRING_OR_SEQUENCE_OR_MAPPING,
    "*.dependencies": ValueShape.SEQUENCE_OF_STRING,
    "*.timeout": ValueShape.STRING,
    "*.retry": ValueShape.STRING_OR_MAPPING,
    "*.allow_failure": ValueShape.BOOLEAN,
    "*.parallel": ValueShape.STRING_OR_MAPPING,
}
