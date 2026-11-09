"""GitHub API ingestion — fetches workflow files from a GitHub org via the REST API.

Requires GITHUB_TOKEN environment variable with repo:read scope.
Uses only stdlib urllib — no third-party dependencies.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any

from taintly.source_inventory import SourceInventory, SourceIssue

_BASE = "https://api.github.com"


def _get(path: str, token: str) -> dict[str, Any] | list[Any]:
    """Make an authenticated GET request to the GitHub API."""
    url = f"{_BASE}{path}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 — URL is always https://api.github.com
            body = json.loads(resp.read())
            if not isinstance(body, dict | list):
                raise TypeError(
                    f"GitHub API returned non-object at {path!r}: {type(body).__name__}"
                )
            return body
    except urllib.error.HTTPError as error:
        # The private helper returns decoded data, not an open error body.
        error.close()
        raise


def _paginate(path: str, token: str) -> Iterator[dict[str, Any]]:
    """Yield all items from a paginated GitHub API endpoint."""
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
        else:
            # Wrapped response
            items = data.get("items") or data.get("repositories") or data.get("workflows") or []
            yield from items
            if len(items) < 100:
                break
        page += 1


def list_org_repos(org: str, token: str) -> list[str]:
    """Return list of repo full names in the org or user account.

    Tries the ``/orgs/{org}/repos`` endpoint first.  If that returns 404
    (the name is a user account, not an org), falls back to
    ``/users/{user}/repos`` which works for both personal accounts and
    organisation members listing their own repos.
    """
    try:
        return [
            repo["full_name"]
            for repo in _paginate(f"/orgs/{org}/repos", token)
            if not repo.get("archived") and not repo.get("disabled")
        ]
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
    # Fallback: treat as a user account
    return [
        repo["full_name"]
        for repo in _paginate(f"/users/{org}/repos", token)
        if not repo.get("archived") and not repo.get("disabled")
    ]


def _decode_workflow_file(file_data: dict[str, Any]) -> str:
    if file_data.get("encoding", "base64") != "base64":
        raise ValueError("unsupported workflow encoding")
    encoded = file_data["content"]
    if not isinstance(encoded, str):
        raise TypeError("workflow content is not base64 text")
    # GitHub wraps base64 lines; malformed bytes must not become an empty
    # or replacement-decoded workflow.
    return base64.b64decode("".join(encoded.split()), validate=True).decode("utf-8")


def fetch_workflow_files(repo_full_name: str, token: str) -> SourceInventory[tuple[str, str]]:
    """Fetch all workflow file contents from a repo.

    Return available files and source-bound acquisition gaps.
    """
    results = []
    issues = []
    try:
        items = _get(f"/repos/{repo_full_name}/contents/.github/workflows", token)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return SourceInventory()
        raise

    if not isinstance(items, list):
        return SourceInventory(
            issues=(
                SourceIssue(
                    f"{repo_full_name}/.github/workflows",
                    "Workflow listing was not a directory response; enumeration is incomplete.",
                ),
            )
        )

    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            issues.append(
                SourceIssue(
                    f"{repo_full_name}/.github/workflows",
                    "Workflow listing contained an invalid entry; enumeration is incomplete.",
                )
            )
            continue
        if item.get("type") != "file":
            continue
        name = item["name"]
        if not (name.endswith(".yml") or name.endswith(".yaml")):
            continue
        try:
            file_data = _get(f"/repos/{repo_full_name}/contents/.github/workflows/{name}", token)
            # /contents/<path> for a single file returns a dict; for a
            # directory it returns a list. We filtered to single-file
            # `.yml`/`.yaml` above, so the dict branch is the contract
            # here — assert it so the subscript is safe.
            assert isinstance(file_data, dict), "single-file GET must return dict"  # nosec B101
            content = _decode_workflow_file(file_data)
            results.append((f"{repo_full_name}/.github/workflows/{name}", content))
        except Exception:
            # Preserve siblings and the failed subject, not raw exception data.
            issues.append(
                SourceIssue(
                    f"{repo_full_name}/.github/workflows/{name}",
                    "Listed workflow could not be fetched or decoded; its security questions were not analyzed.",
                )
            )

    return SourceInventory(tuple(results), tuple(issues))


def fetch_org_workflows(org: str, token: str) -> SourceInventory[tuple[str, str]]:
    """Fetch all workflow files from all repos in an org.

    Return files and gaps. Top-level enumeration failure still raises.
    """
    all_files: list[tuple[str, str]] = []
    issues: list[SourceIssue] = []
    repos = list_org_repos(org, token)
    for repo in repos:
        try:
            files = fetch_workflow_files(repo, token)
            all_files.extend(files.items)
            issues.extend(files.issues)
        except Exception:
            issues.append(
                SourceIssue(
                    f"{repo}/.github/workflows",
                    "Workflow sources could not be enumerated; this repository was not fully analyzed.",
                )
            )
    return SourceInventory(tuple(all_files), tuple(issues))
