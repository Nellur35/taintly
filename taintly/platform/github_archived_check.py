"""Archived-repo check for SEC3-GH-008.

The rule fires when a ``uses: owner/repo@<ref>`` reference points to a
GitHub repository that has been archived.  Archived repos are
read-only — no new releases, no security patches, no maintainer
response to compromise reports.  Continuing to depend on an archived
action is a deferred-supply-chain-risk class on its own.

Design constraints (mirrored from ``github_sha_verify``):

* **Opt-in.**  Silent unless the CLI flag ``--check-archived-actions``
  is passed.  The flag toggles ``_ENABLED`` and the rule's pattern
  short-circuits to no-op otherwise.  Network checks are out of scope
  for default scans.
* **Process-lifetime cache.**  Verdicts for ``(owner, repo)`` are
  cached for the lifetime of the Python process.  An on-disk cache
  would re-issue stale "archived" verdicts after a maintainer
  un-archives; the process-lifetime model trades a little redundant
  API traffic for predictable behaviour within a run series.
* **Test override.**  ``set_archived_check_override(fn)`` replaces the
  real network call.
* **Authenticated when possible.**  GITHUB_TOKEN required for the
  real check; missing-token degrades to ``None`` (don't fire).
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from typing import Optional

_ENABLED: bool = False
_CACHE: dict[tuple[str, str], bool] = {}
_OVERRIDE: Optional[Callable[[str, str], Optional[bool]]] = None


def set_enabled(enabled: bool) -> None:
    """Toggle the rule's network check.  CLI handler calls once at
    startup; tests scope per-case in setUp/tearDown."""
    global _ENABLED
    _ENABLED = enabled


def is_enabled() -> bool:
    return _ENABLED


def reset_cache() -> None:
    _CACHE.clear()


def set_archived_check_override(
    fn: Optional[Callable[[str, str], Optional[bool]]],
) -> None:
    """Inject (or clear) a stub.  Tests use this to avoid real
    network calls.  Pass ``None`` to restore real behaviour."""
    global _OVERRIDE
    _OVERRIDE = fn


def is_archived(owner: str, repo: str) -> Optional[bool]:
    """Return ``True`` if the repo is archived, ``False`` if not,
    ``None`` on rate limit / transport failure / missing auth.

    Cached process-wide on ``(owner, repo)`` for definitive yes/no
    verdicts; indeterminate verdicts bypass the cache.
    """
    if _OVERRIDE is not None:
        return _OVERRIDE(owner, repo)

    key = (owner, repo)
    if key in _CACHE:
        return _CACHE[key]

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        sys.stderr.write(
            "warning: --check-archived-actions requires GITHUB_TOKEN in the "
            "environment for authenticated GitHub API requests; "
            "archived-repo check skipped.\n"
        )
        return None

    try:
        import urllib.error
        import urllib.request

        req = urllib.request.Request(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "taintly-archived-check",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            import json

            body = json.loads(resp.read().decode("utf-8"))
            archived = bool(body.get("archived", False))
            _CACHE[key] = archived
            return archived
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Repo doesn't exist (or was deleted entirely) — treat
            # as a stronger archived-equivalent signal.
            _CACHE[key] = True
            return True
        if e.code in (401, 403):
            sys.stderr.write(
                f"error: GitHub API returned {e.code} for {owner}/{repo}; "
                "check token scope or rate limit.\n"
            )
            return None
        return None
    except Exception:
        return None
