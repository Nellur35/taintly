"""GitHub API ingestion — fetches workflow files from a GitHub org via the REST API.

Requires GITHUB_TOKEN environment variable with repo:read scope.
Uses only stdlib urllib — no third-party dependencies.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any

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
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 — URL is always https://api.github.com
        body = json.loads(resp.read())
        if not isinstance(body, dict | list):
            raise TypeError(f"GitHub API returned non-object at {path!r}: {type(body).__name__}")
        return body


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


def fetch_workflow_files(repo_full_name: str, token: str) -> list[tuple[str, str]]:
    """Fetch all workflow file contents from a repo.

    Returns list of (filename, content) tuples.
    """
    results = []
    try:
        items = _get(f"/repos/{repo_full_name}/contents/.github/workflows", token)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []
        raise

    if not isinstance(items, list):
        return []

    for item in items:
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
            import base64

            content = base64.b64decode(file_data["content"]).decode("utf-8", errors="replace")
            results.append((f"{repo_full_name}/.github/workflows/{name}", content))
        except Exception:
            # Best-effort across many repos — one broken workflow must
            # never abort the whole org scan. Skip and keep going.
            continue  # nosec B112

    return results


def fetch_org_workflows(org: str, token: str) -> list[tuple[str, str]]:
    """Fetch all workflow files from all repos in an org.

    Returns list of (virtual_path, content) tuples.
    """
    all_files = []
    repos = list_org_repos(org, token)
    for repo in repos:
        try:
            files = fetch_workflow_files(repo, token)
            all_files.extend(files)
        except Exception:
            # Best-effort across many repos — keep scanning siblings.
            continue  # nosec B112
    return all_files
