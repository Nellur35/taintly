"""GitHub Actions workflow schema.

Path globs map to the value shape the GitHub schema expects at
that path.  Used by the structural reader to disambiguate cases
where the token stream alone can't tell a string from a container.

Coverage scope: the paths the existing rule pack queries (per the
``scripts/audit_rule_paths.py`` audit).  Adding a path means
either a new rule needs it OR the audit revealed an existing
regex-based query that should be migrated to structural form.
"""

from __future__ import annotations

from . import ValueShape

SCHEMA: dict[str, ValueShape] = {
    # Top-level
    "name": ValueShape.STRING,
    "on": ValueShape.STRING_OR_SEQUENCE_OR_MAPPING,
    "permissions": ValueShape.STRING_OR_MAPPING,
    "permissions.*": ValueShape.STRING,
    "concurrency": ValueShape.STRING_OR_MAPPING,
    "concurrency.group": ValueShape.STRING,
    "concurrency.cancel-in-progress": ValueShape.BOOLEAN,
    "env": ValueShape.MAPPING_OF_STRING,
    "defaults": ValueShape.STRING_OR_MAPPING,
    "defaults.run.shell": ValueShape.STRING,
    "defaults.run.working-directory": ValueShape.STRING,

    # ``on:`` events
    "on.push": ValueShape.STRING_OR_MAPPING,
    "on.push.branches": ValueShape.SEQUENCE_OF_STRING,
    "on.push.tags": ValueShape.SEQUENCE_OF_STRING,
    "on.pull_request": ValueShape.STRING_OR_MAPPING,
    "on.pull_request_target": ValueShape.STRING_OR_MAPPING,
    "on.pull_request_target.types": ValueShape.SEQUENCE_OF_STRING,
    "on.workflow_run": ValueShape.STRING_OR_MAPPING,
    "on.workflow_run.workflows": ValueShape.SEQUENCE_OF_STRING,
    "on.workflow_run.types": ValueShape.SEQUENCE_OF_STRING,
    "on.workflow_dispatch": ValueShape.STRING_OR_MAPPING,
    "on.workflow_call": ValueShape.STRING_OR_MAPPING,
    "on.release": ValueShape.STRING_OR_MAPPING,
    "on.release.types": ValueShape.SEQUENCE_OF_STRING,
    "on.schedule": ValueShape.STRING_OR_MAPPING,
    "on.issue_comment": ValueShape.STRING_OR_MAPPING,
    "on.pull_request_review": ValueShape.STRING_OR_MAPPING,

    # ``jobs:``
    "jobs.*.name": ValueShape.STRING,
    "jobs.*.runs-on": ValueShape.STRING_OR_SEQUENCE_OF_STRING,
    "jobs.*.if": ValueShape.STRING,
    "jobs.*.permissions": ValueShape.STRING_OR_MAPPING,
    "jobs.*.permissions.*": ValueShape.STRING,
    "jobs.*.environment": ValueShape.STRING_OR_MAPPING,
    "jobs.*.environment.name": ValueShape.STRING,
    "jobs.*.timeout-minutes": ValueShape.NUMBER,
    "jobs.*.continue-on-error": ValueShape.BOOLEAN,
    "jobs.*.outputs": ValueShape.MAPPING_OF_STRING,
    "jobs.*.env": ValueShape.MAPPING_OF_STRING,
    "jobs.*.uses": ValueShape.STRING,
    "jobs.*.with": ValueShape.MAPPING_OF_STRING,
    "jobs.*.secrets": ValueShape.STRING_OR_MAPPING,
    "jobs.*.secrets.*": ValueShape.STRING,
    "jobs.*.concurrency": ValueShape.STRING_OR_MAPPING,
    "jobs.*.concurrency.group": ValueShape.STRING,
    "jobs.*.concurrency.cancel-in-progress": ValueShape.BOOLEAN,

    # Steps
    "jobs.*.steps[*].name": ValueShape.STRING,
    "jobs.*.steps[*].id": ValueShape.STRING,
    "jobs.*.steps[*].uses": ValueShape.STRING,
    "jobs.*.steps[*].run": ValueShape.STRING,
    "jobs.*.steps[*].if": ValueShape.STRING,
    "jobs.*.steps[*].with": ValueShape.MAPPING_OF_STRING,
    "jobs.*.steps[*].env": ValueShape.MAPPING_OF_STRING,
    "jobs.*.steps[*].shell": ValueShape.STRING,
    "jobs.*.steps[*].working-directory": ValueShape.STRING,
    "jobs.*.steps[*].timeout-minutes": ValueShape.NUMBER,
    "jobs.*.steps[*].continue-on-error": ValueShape.BOOLEAN,

    # Container / services
    "jobs.*.container": ValueShape.STRING_OR_MAPPING,
    "jobs.*.container.image": ValueShape.STRING,
    "jobs.*.services.*": ValueShape.STRING_OR_MAPPING,
    "jobs.*.services.*.image": ValueShape.STRING,
    "jobs.*.services.*.env": ValueShape.MAPPING_OF_STRING,
}
