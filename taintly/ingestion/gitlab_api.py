"""GitLab API ingestion — fetches pipeline config files from a GitLab group.

Requires GITLAB_TOKEN environment variable.
Uses only stdlib urllib — no third-party dependencies.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from typing import Any

from taintly._gitlab_transport import GitLabTransportError, open_gitlab, validate_gitlab_base
from taintly.source_inventory import SourceInventory, SourceIssue


class GitLabSourceIncomplete(GitLabTransportError):
    """Stop credentialed acquisition while retaining already acquired sources."""

    def __init__(self, inventory: SourceInventory[tuple[str, str]]) -> None:
        super().__init__(
            "GitLab source acquisition stopped after unsafe redirect or recipient refusal"
        )
        self.inventory = inventory


def _gitlab_base() -> str:
    return validate_gitlab_base(os.environ.get("GITLAB_URL", "https://gitlab.com"))


def _get(path: str, token: str) -> dict[str, Any] | list[Any]:
    base = _gitlab_base()
    url = f"{base}/api/v4{path}"
    req = urllib.request.Request(
        url,
        headers={
            "PRIVATE-TOKEN": token,
            "Accept": "application/json",
        },
    )
    try:
        with open_gitlab(req, base_url=base, timeout=30) as resp:
            body = json.loads(resp.read())
            if not isinstance(body, dict | list):
                raise TypeError(
                    f"GitLab API returned non-object at {path!r}: {type(body).__name__}"
                )
            return body
    except urllib.error.HTTPError as error:
        error.close()
        raise


def _get_raw(path: str, token: str) -> bytes:
    """Fetch a GitLab ``.raw`` file endpoint as bytes — JSON decode
    would fail on arbitrary YAML / text content. Separate from
    ``_get`` because the API/Accept headers and return type differ.
    """
    base = _gitlab_base()
    url = f"{base}/api/v4{path}"
    req = urllib.request.Request(
        url,
        headers={
            "PRIVATE-TOKEN": token,
            "Accept": "text/plain",
        },
    )
    try:
        with open_gitlab(req, base_url=base, timeout=30) as resp:
            data = resp.read()
            assert isinstance(data, bytes)  # nosec B101
            return data
    except urllib.error.HTTPError as error:
        error.close()
        raise


def _paginate(path: str, token: str) -> Iterator[dict[str, Any]]:
    page = 1
    while True:
        sep = "&" if "?" in path else "?"
        data = _get(f"{path}{sep}per_page=100&page={page}", token)
        if not data:
            break
        if isinstance(data, list):
            yield from data
            if len(data) < 100:
                break
        page += 1


def list_group_projects(group: str, token: str) -> list[dict[str, Any]]:
    """Return list of projects in the group."""
    encoded = urllib.parse.quote(group, safe="")
    return list(_paginate(f"/groups/{encoded}/projects?include_subgroups=true", token))


def fetch_gitlab_ci(project_id: int | str, token: str) -> str | None:
    """Fetch .gitlab-ci.yml content for a project."""
    encoded = urllib.parse.quote(str(project_id), safe="")
    try:
        # Use the raw endpoint — the JSON-wrapped /files/<path> variant
        # returns base64-in-a-dict which just costs us an extra decode
        # step. `.raw` gives us the YAML bytes directly.
        raw = _get_raw(f"/projects/{encoded}/repository/files/.gitlab-ci.yml/raw?ref=HEAD", token)
        return raw.decode("utf-8")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def fetch_group_pipelines(group: str, token: str) -> SourceInventory[tuple[str, str]]:
    """Fetch all .gitlab-ci.yml files from a group.

    Return files and gaps; recipient refusal stops all further acquisition.
    """
    all_files = []
    issues = []
    projects = list_group_projects(group, token)
    for project in projects:
        pid = project["id"]
        name = project.get("path_with_namespace", str(pid))
        try:
            content = fetch_gitlab_ci(pid, token)
            if content is not None:
                all_files.append((f"{name}/.gitlab-ci.yml", content))
        except GitLabTransportError:
            issues.append(
                SourceIssue(
                    f"{name}/.gitlab-ci.yml",
                    "Credential transport refused a recipient; this pipeline and the remaining group sources were not acquired.",
                )
            )
            raise GitLabSourceIncomplete(SourceInventory(tuple(all_files), tuple(issues))) from None
        except Exception:
            issues.append(
                SourceIssue(
                    f"{name}/.gitlab-ci.yml",
                    "Pipeline source could not be fetched or decoded; this project's security questions were not analyzed.",
                )
            )
    return SourceInventory(tuple(all_files), tuple(issues))
