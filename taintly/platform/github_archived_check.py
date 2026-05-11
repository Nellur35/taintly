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

    Uses the shared :class:`GitHubClient` so transport, auth, retry,
    and rate-limit handling match SEC3-GH-009's implementation —
    keeping the two opt-in network rules consistent.
    """
    if _OVERRIDE is not None:
        return _OVERRIDE(owner, repo)

    key = (owner, repo)
    if key in _CACHE:
        return _CACHE[key]

    token_value = os.environ.get("GITHUB_TOKEN")
    if not token_value:
        sys.stderr.write(
            "warning: --check-archived-actions requires GITHUB_TOKEN in the "
            "environment for authenticated GitHub API requests; "
            "archived-repo check skipped.\n"
        )
        return None

    # Late imports keep this module light when the rule is disabled.
    from .github_client import APIError, GitHubClient
    from .token import TokenManager

    token = TokenManager(token_value, source="env")
    try:
        client = GitHubClient(token)
        body = client._request(f"/repos/{owner}/{repo}")
        if body is None:
            # 404 — repo deleted; treat as archived-equivalent.
            _CACHE[key] = True
            return True
        archived = bool(body.get("archived", False))
        _CACHE[key] = archived
        return archived
    except APIError as e:
        if e.status in (401, 403):
            sys.stderr.write(
                f"error: GitHub API returned {e.status} for {owner}/{repo}; "
                "check token scope or rate limit.\n"
            )
            return None
        return None
    except Exception:
        # Transport failure (network down, DNS, TLS) — degrade to
        # indeterminate rather than crashing the scan.
        return None
    finally:
        token.clear()
