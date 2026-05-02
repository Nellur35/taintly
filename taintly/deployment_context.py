"""Deployment-context hints for findings.

The context file is interpretation metadata. It may add notes and triage
flags, but it must not mutate rule severity, score, or detection truth.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Any

from .config import ConfigError, _parse_yaml_subset

CONTEXT_FILENAME = ".taintly-context.yml"
VALID_VALUES = {
    "repo_visibility": {"unknown", "public", "private", "internal"},
    "external_prs": {"unknown", "allowed", "blocked", "restricted"},
    "runner_topology": {"unknown", "github_hosted", "shared_self_hosted", "isolated_self_hosted"},
    "secret_scoping": {"unknown", "repo_scoped", "environment_scoped", "oidc_only"},
}


@dataclass(frozen=True)
class DeploymentContext:
    repo_visibility: str = "unknown"
    external_prs: str = "unknown"
    runner_topology: str = "unknown"
    secret_scoping: str = "unknown"

    def is_default(self) -> bool:
        return all(getattr(self, field) == "unknown" for field in VALID_VALUES)


def load_deployment_context(repo_path: str) -> DeploymentContext:
    path = _find_context_file(repo_path)
    if path is None:
        return DeploymentContext()
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = _parse_yaml_subset(fh.read(), warn_unknown=False)
    except OSError as exc:
        raise ConfigError(f"could not read {CONTEXT_FILENAME}: {exc}") from exc
    return _validate_context(raw)


def _find_context_file(scan_path: str) -> str | None:
    current = os.path.abspath(scan_path)
    if os.path.isfile(current):
        current = os.path.dirname(current)
    while True:
        path = os.path.join(current, CONTEXT_FILENAME)
        if os.path.isfile(path):
            return path
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def apply_context_notes_to_findings(findings: list[Any], ctx: DeploymentContext) -> None:
    if ctx.is_default():
        return
    for finding in findings:
        apply_context_notes(finding, ctx)


def apply_context_notes(finding: Any, ctx: DeploymentContext) -> None:
    notes = list(getattr(finding, "context_notes", []) or [])
    tags = set(getattr(finding, "context_tags", []) or [])
    family = getattr(finding, "finding_family", "")

    if family == "privileged_pr_trigger" and ctx.external_prs in {"blocked", "restricted"}:
        notes.append(
            "Exploitability may be over-weighted for deployments without open external PRs."
        )
        tags.add(f"external_prs:{ctx.external_prs}")

    if family == "credential_persistence" and ctx.secret_scoping == "oidc_only":  # nosec B105 - context enum value, not a credential.
        notes.append("Long-lived credential assumptions may not hold for OIDC-only deployments.")
        tags.add("secret_scoping:oidc_only")

    if family == "ungoverned_services" and ctx.runner_topology == "isolated_self_hosted":
        notes.append(
            "Runner exposure may be lower when self-hosted runners are isolated per trust boundary."
        )
        tags.add("runner_topology:isolated_self_hosted")

    if notes:
        finding.context_notes = _dedupe(notes)
        finding.context_tags = sorted(tags)
        finding.triage_needed = True


def _validate_context(raw: dict[str, Any]) -> DeploymentContext:
    values: dict[str, str] = {}
    for field, allowed in VALID_VALUES.items():
        val = str(raw.get(field, "unknown") or "unknown").strip()
        if val not in allowed:
            print(
                f"taintly: context warning: {field}={val!r} is unsupported; using 'unknown'",
                file=sys.stderr,
            )
            val = "unknown"
        values[field] = val
    return DeploymentContext(**values)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out
