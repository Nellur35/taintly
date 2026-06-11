"""Resolve a mutable action ref (tag / branch) to its current upstream SHA.

Powers the mutable-ref-repoint detector — the tj-actions/changed-files
CVE-2025-30066 class. A workflow pins ``uses: owner/repo@<mutable-ref>``; an
attacker repoints the tag to a malicious commit; the local YAML never changes.
By recording the resolved SHA of each mutable ref in the baseline and
re-resolving on a later scan, a *changed* resolution with no local YAML change is
the active-compromise signal the always-on static rule (SEC3-GH-001/003, which
only flags latent mutable-ref usage) cannot distinguish.

Design mirrors :mod:`taintly.platform.github_sha_verify` — opt-in, token-gated,
process-lifetime cache, test override — see that module for the full rationale.
The difference: this RESOLVES a ref to a SHA (``GET /commits/{ref}`` ->
``result["sha"]``); github_sha_verify CHECKS reachability of a SHA. Different
question, same authenticated client.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable

# CLI flips this when ``--check-ref-drift`` is passed; the diff path reads it
# before resolving anything.
_ENABLED: bool = False

# Process-lifetime cache. Key: (owner, repo, ref). Value: resolved 40-hex SHA.
# ``None`` outcomes (404 / rate limit / transport) are NOT cached so the next
# invocation retries rather than re-using an "unknown" verdict.
_CACHE: dict[tuple[str, str, str], str] = {}

# Test-time hook. When set, replaces the real network call. Signature:
# ``fn(owner, repo, ref) -> Optional[str]``.
_RESOLVER_OVERRIDE: Callable[[str, str, str], str | None] | None = None

_TOKEN_WARNED: bool = False


def set_enabled(enabled: bool) -> None:
    """Toggle the ref-drift resolver. The CLI flag handler calls this once at
    startup; tests scope it in setUp/tearDown."""
    global _ENABLED
    _ENABLED = enabled


def is_enabled() -> bool:
    return _ENABLED


def reset_cache() -> None:
    """Clear the process-lifetime resolution cache. Test helper."""
    _CACHE.clear()


def set_resolver_override(fn: Callable[[str, str, str], str | None] | None) -> None:
    """Inject (or clear) a stub resolver so tests never touch the network.
    Pass ``None`` to restore the real implementation."""
    global _RESOLVER_OVERRIDE
    _RESOLVER_OVERRIDE = fn


def resolve_ref_to_sha(owner: str, repo: str, ref: str) -> str | None:
    """Return the current commit SHA that ``owner/repo@ref`` resolves to, or
    ``None`` on 404 / rate-limit / transport failure.

    Cached process-wide on ``(owner, repo, ref)`` for definitive resolutions;
    indeterminate outcomes bypass the cache so the next call can retry.
    """
    key = (owner, repo, ref)
    if key in _CACHE:
        return _CACHE[key]

    if _RESOLVER_OVERRIDE is not None:
        sha = _RESOLVER_OVERRIDE(owner, repo, ref)
    else:
        sha = _network_resolve(owner, repo, ref)

    if sha is not None:
        _CACHE[key] = sha
    return sha


def _warn_once(message: str) -> None:
    global _TOKEN_WARNED
    if _TOKEN_WARNED:
        return
    _TOKEN_WARNED = True
    print(message, file=sys.stderr)


def _network_resolve(owner: str, repo: str, ref: str) -> str | None:
    """Real network implementation. ``GET /repos/{owner}/{repo}/commits/{ref}``
    resolves a tag/branch/ref and returns the commit object; we take its
    ``sha``. Requires ``GITHUB_TOKEN`` (the unauthenticated rate limit is too low
    for any real scan)."""
    token_value = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token_value:
        _warn_once(
            "warning: --check-ref-drift requires GITHUB_TOKEN in the environment "
            "for authenticated ref resolution; skipping ref-drift verification "
            "(set GITHUB_TOKEN to enable)"
        )
        return None

    # Late imports keep this module light when the check is disabled.
    from .github_client import APIError, GitHubClient
    from .token import TokenManager

    token = TokenManager(token_value, source="env")
    try:
        client = GitHubClient(token)
        result = client._request(f"/repos/{owner}/{repo}/commits/{ref}")
        if isinstance(result, dict):
            sha = result.get("sha")
            if isinstance(sha, str) and sha:
                return sha
        return None
    except APIError as e:
        if e.status == 403:
            print(
                f"error: GitHub API rate-limited while resolving "
                f"{owner}/{repo}@{ref}; ref-drift check cannot complete. "
                f"Use a higher-quota GITHUB_TOKEN or run on a longer cron.",
                file=sys.stderr,
            )
        # 404 (ref gone) / other statuses -> indeterminate.
        return None
    except Exception:
        # Transport failure (network down, DNS, TLS). Don't crash the scan.
        return None
    finally:
        token.clear()
