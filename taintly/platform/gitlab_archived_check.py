"""Archived-project check for SEC3-GL-008.

The rule fires when an ``include:`` references a GitLab project that
has been archived.  Archived GitLab projects are read-only — no new
releases, no maintainer response.  Mirrors the SEC3-GH-010 opt-in
shape (GITLAB_TOKEN required, per-project caching, test override
hook).
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable

_ENABLED: bool = False
_CACHE: dict[str, bool] = {}
_OVERRIDE: Callable[[str], bool | None] | None = None


def set_enabled(enabled: bool) -> None:
    global _ENABLED
    _ENABLED = enabled


def is_enabled() -> bool:
    return _ENABLED


def reset_cache() -> None:
    _CACHE.clear()


def set_archived_check_override(
    fn: Callable[[str], bool | None] | None,
) -> None:
    global _OVERRIDE
    _OVERRIDE = fn


def is_archived(project_path: str) -> bool | None:
    """Return ``True`` if the GitLab project is archived, ``False`` if
    not, ``None`` on rate limit / transport failure / missing auth.

    ``project_path`` is the ``namespace/project`` slug (e.g.
    ``gitlab-org/gitlab``).  Cached process-wide.
    """
    if _OVERRIDE is not None:
        return _OVERRIDE(project_path)

    if project_path in _CACHE:
        return _CACHE[project_path]

    token = os.environ.get("GITLAB_TOKEN")
    if not token:
        sys.stderr.write(
            "warning: --check-archived-gitlab-projects requires GITLAB_TOKEN "
            "in the environment for authenticated GitLab API requests; "
            "archived-project check skipped.\n"
        )
        return None

    try:
        import json
        import urllib.error
        import urllib.parse
        import urllib.request

        encoded = urllib.parse.quote(project_path, safe="")
        url = f"https://gitlab.com/api/v4/projects/{encoded}"
        if not url.startswith("https://"):
            return None  # nosec B310 — defensive; literal https-only URL above
        req = urllib.request.Request(  # nosec B310 — https-only literal
            url,
            headers={
                "PRIVATE-TOKEN": token,
                "Accept": "application/json",
                "User-Agent": "taintly-gitlab-archived-check",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310 — https-only
            body = json.loads(resp.read().decode("utf-8"))
            archived = bool(body.get("archived", False))
            _CACHE[project_path] = archived
            return archived
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Deleted, private, moved, self-hosted, or token-scoped-out
            # projects are not proof of GitLab's archived flag.
            return None
        if e.code in (401, 403):
            sys.stderr.write(
                f"error: GitLab API returned {e.code} for {project_path}; "
                "check token scope or rate limit.\n"
            )
            return None
        return None
    except Exception:
        return None
