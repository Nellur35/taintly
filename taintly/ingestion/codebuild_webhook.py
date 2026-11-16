"""Evaluate GitHub PR webhook filters in a trusted saved CodeBuild project receipt."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from .codebuild_snapshot import SnapshotError, _github_identity, _read_capture

WEBHOOK_PR_EVENTS = frozenset(
    {
        "PULL_REQUEST_CREATED",
        "PULL_REQUEST_UPDATED",
        "PULL_REQUEST_REOPENED",
        "PULL_REQUEST_MERGED",
        "PULL_REQUEST_CLOSED",
    }
)
_EVENT_TYPES = WEBHOOK_PR_EVENTS | {"PUSH", "RELEASED", "PRERELEASED", "WORKFLOW_JOB_QUEUED"}
_PROJECT_NAME = re.compile(r"[A-Za-z0-9_-]{2,150}")
WEBHOOK_PROJECT_ID = re.compile(r"public:([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+):[0-9a-f]{64}")
_SENDER = r"[1-9][0-9]{0,17}"
WEBHOOK_SENDER_ID = re.compile(_SENDER)
_ALTERNATIVES = rf"{_SENDER}(?:\|{_SENDER})*"
_EXACT_SENDERS = re.compile(rf"\^\(({_ALTERNATIVES})\)\$|\^({_SENDER})\$")
_SUBSTRING_SENDERS = re.compile(_ALTERNATIVES)
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z")
_FILTER_KIND = re.compile(r"[A-Z_]{1,32}")
_MAX_GROUPS = 32
_MAX_FILTERS_PER_GROUP = 32
_MAX_PATTERN = 1024
_FilterOutcome = Literal["excluded", "filter-match", "unresolved"]


@dataclass(frozen=True)
class WebhookFilterCheck:
    index: int
    kind: str
    matches: bool | None
    reason: str


@dataclass(frozen=True)
class WebhookFilterGroup:
    index: int
    matches: bool | None
    filters: tuple[WebhookFilterCheck, ...]


@dataclass(frozen=True)
class CodeBuildWebhookAssessment:
    project_id: str
    project_name: str
    region: str
    repository: str
    observed_at: str
    event: str
    sender_id: str | None
    filter_outcome: _FilterOutcome
    groups: tuple[WebhookFilterGroup, ...]


def _map(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise SnapshotError(f"{label} is missing or malformed")
    return value


def _observation_time(value: object) -> str:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise SnapshotError("A UTC project observation timestamp is required")
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise SnapshotError("Project observation timestamp is invalid") from exc
    return value


def _predicate(kind: str, pattern: str, event: str, sender: str | None) -> tuple[bool | None, str]:
    if len(pattern) > _MAX_PATTERN:
        return None, "Filter pattern exceeds the analysis limit"
    if kind == "EVENT":
        events = {item.strip() for item in pattern.split(",")}
        if not events <= _EVENT_TYPES:
            return None, "The event list contains an unsupported value"
        return event in events, "Event membership in the saved filter"
    if kind != "ACTOR_ACCOUNT_ID":
        return None, "This filter predicate is outside the event and sender profile"
    if sender is None:
        return None, "The webhook sender ID was not provided"
    exact = _EXACT_SENDERS.fullmatch(pattern)
    if exact:
        return sender in (exact[1] or exact[2]).split("|"), "Exact numeric sender comparison"
    if _SUBSTRING_SENDERS.fullmatch(pattern):
        matched = any(value in sender for value in pattern.split("|"))
        return matched, "Unanchored numeric sender substring comparison"
    return None, "The sender pattern is outside the bounded numeric RE2 subset"


def _filter_check(raw: object, index: int, event: str, sender: str | None) -> WebhookFilterCheck:
    record = _map(raw, "Webhook filter")
    kind, pattern, exclude = (
        record.get("type"),
        record.get("pattern"),
        record.get("excludeMatchedPattern"),
    )
    if (
        not isinstance(kind, str)
        or not _FILTER_KIND.fullmatch(kind)
        or not isinstance(pattern, str)
        or not isinstance(exclude, bool)
    ):
        raise SnapshotError("Malformed webhook filter")
    matches, reason = _predicate(kind, pattern, event, sender)
    if matches is not None and exclude:
        matches = not matches
        reason += " with the exclusion setting"
    return WebhookFilterCheck(index, kind, matches, reason)


def _group(raw: object, index: int, event: str, sender: str | None) -> WebhookFilterGroup:
    if not isinstance(raw, list) or not 1 <= len(raw) <= _MAX_FILTERS_PER_GROUP:
        raise SnapshotError("Missing, malformed or oversized webhook filter group")
    checks = tuple(_filter_check(row, i, event, sender) for i, row in enumerate(raw, start=1))
    if sum(item.kind == "EVENT" for item in checks) != 1:
        raise SnapshotError("Each supported webhook filter group requires exactly one EVENT")
    matches = tuple(item.matches for item in checks)
    result = False if False in matches else None if None in matches else True
    return WebhookFilterGroup(index, result, checks)


def assess_webhook_snapshot(
    path: Path, project_id: str, origin: str, event: str, sender: str | None
) -> CodeBuildWebhookAssessment:
    """Evaluate only the filter groups of the specific captured project."""
    identity = WEBHOOK_PROJECT_ID.fullmatch(project_id)
    if identity is None:
        raise SnapshotError("Expected a regional public project alias digest")
    if event not in WEBHOOK_PR_EVENTS or (
        sender is not None and not WEBHOOK_SENDER_ID.fullmatch(sender)
    ):
        raise SnapshotError("Expected a supported PR event and optional numeric sender ID")
    try:
        is_file = path.is_file()
    except OSError as exc:
        raise SnapshotError("Webhook receipt could not be inspected") from exc
    if not is_file:
        raise SnapshotError("Webhook receipt must be a regular file")
    capture = _read_capture(path, "Webhook receipt")
    region = identity[1]
    if capture.get("project_id") != project_id or capture.get("region") != region:
        raise SnapshotError(
            "Receipt does not match the selected public project identity and region"
        )
    project = _map(capture.get("project"), "Project")
    project_name = project.get("name")
    if not isinstance(project_name, str) or not _PROJECT_NAME.fullmatch(project_name):
        raise SnapshotError("Project name is missing or malformed")
    source = _map(project.get("source"), "Project source")
    repository = _github_identity(origin)
    if source.get("type") != "GITHUB" or _github_identity(source.get("location")) != repository:
        raise SnapshotError("Receipt does not match the selected GitHub source repository")
    observed_at = _observation_time(capture.get("observed_at"))
    webhook = _map(project.get("webhook"), "Project webhook")
    rows = webhook.get("filterGroups")
    if not isinstance(rows, list) or not 1 <= len(rows) <= _MAX_GROUPS:
        raise SnapshotError("Missing, malformed or oversized webhook filter group list")
    groups = tuple(_group(row, index, event, sender) for index, row in enumerate(rows, start=1))
    states = tuple(group.matches for group in groups)
    outcome: _FilterOutcome = (
        "filter-match" if True in states else "unresolved" if None in states else "excluded"
    )
    return CodeBuildWebhookAssessment(
        project_id, project_name, region, repository, observed_at, event, sender, outcome, groups
    )
