"""SHA reachability check for SEC3-GH-009 imposter-commit detection.

The rule fires when a ``uses: owner/repo@<sha>`` reference points to a
SHA that is not reachable from any ref in the action's repository —
i.e. the maintainer force-pushed over the tag (orphaning the SHA), or
the SHA was published transiently and later garbage-collected.  GitHub
returns 404 from the Commits API once a SHA is no longer reachable;
that 404 is the orphan signal this module exposes.

Design constraints:

* **Opt-in.**  The rule is silent unless the CLI flag
  ``--check-imposter-commits`` is passed.  The flag toggles the
  module-level ``_ENABLED`` state; the rule's pattern reads that flag
  and short-circuits to no-op when disabled.

* **Process-lifetime cache only.**  The reachability verdict for
  ``(owner, repo, sha)`` is cached for the lifetime of the Python
  process and re-checked fresh on the next invocation.  An on-disk
  cache would introduce flip-flop semantics — a ``not reachable`` row
  cached for an hour can re-flip to ``reachable`` after a ref is
  recreated, breaking determinism within a run series.  The
  process-lifetime model trades a little redundant API traffic for
  predictable behaviour.

* **Authenticated when possible.**  GitHub's unauthenticated rate
  limit is too low for any real scan; the verifier requires
  ``GITHUB_TOKEN`` in the environment and emits a stderr warning
  (then short-circuits to ``None``) when missing.

* **Hard fail on rate-limit.**  A 403 from the API is surfaced as a
  clear error rather than silently degraded — a security check that
  silently returns "unknown" is worse than one that errors.

* **Test override.**  ``set_verifier_override(fn)`` replaces the
  network call with a caller-provided callable, enabling unit tests
  that exercise the rule without touching the network.
"""

from __future__ import annotations

import os
import sys
from typing import Callable, Optional

# Module-level enable flag.  CLI flips this when
# ``--check-imposter-commits`` is passed; the rule's pattern reads it
# before invoking the verifier.
_ENABLED: bool = False

# Process-lifetime cache.  Key: (owner, repo, sha).  Value: bool —
# True if the SHA is reachable, False if 404.  ``None`` outcomes (rate
# limit, transport error) are NOT cached — the next invocation should
# retry rather than re-using an "unknown" verdict.
_CACHE: dict[tuple[str, str, str], bool] = {}

# Test-time hook.  When set, replaces the real network call with the
# given callable.  ``None`` clears the override.  Signature:
# ``fn(owner: str, repo: str, sha: str) -> Optional[bool]``.
_VERIFIER_OVERRIDE: Optional[Callable[[str, str, str], Optional[bool]]] = None


def set_enabled(enabled: bool) -> None:
    """Toggle the rule's network check.

    The CLI flag handler calls this once at startup; tests use it
    in setUp/tearDown to scope the enabled state to specific cases.
    """
    global _ENABLED
    _ENABLED = enabled


def is_enabled() -> bool:
    return _ENABLED


def reset_cache() -> None:
    """Clear the process-lifetime reachability cache.  Test helper."""
    _CACHE.clear()


def set_verifier_override(
    fn: Optional[Callable[[str, str, str], Optional[bool]]],
) -> None:
    """Inject (or clear) a stub verifier.  Tests use this to avoid
    real network calls.  Pass ``None`` to restore the real
    implementation.
    """
    global _VERIFIER_OVERRIDE
    _VERIFIER_OVERRIDE = fn


def is_sha_reachable(owner: str, repo: str, sha: str) -> Optional[bool]:
    """Return ``True`` if the SHA is reachable in the repo,
    ``False`` if GitHub returns 404 (orphan), ``None`` on rate limit
    or transport failure.

    Cached process-wide on ``(owner, repo, sha)`` for definitive
    yes/no verdicts.  Indeterminate verdicts (``None``) bypass the
    cache so the next invocation can retry.
    """
    key = (owner, repo, sha)
    if key in _CACHE:
        return _CACHE[key]

    if _VERIFIER_OVERRIDE is not None:
        verdict = _VERIFIER_OVERRIDE(owner, repo, sha)
    else:
        verdict = _network_check(owner, repo, sha)

    if verdict is not None:
        _CACHE[key] = verdict
    return verdict


# Track whether we've already warned about a missing token, so the
# first scanned file doesn't drown the user in N identical lines.
_TOKEN_WARNED: bool = False


def _warn_once(message: str) -> None:
    global _TOKEN_WARNED
    if _TOKEN_WARNED:
        return
    _TOKEN_WARNED = True
    print(message, file=sys.stderr)


def _network_check(owner: str, repo: str, sha: str) -> Optional[bool]:
    """Real network implementation.  Hits
    ``GET /repos/{owner}/{repo}/commits/{sha}`` via the existing
    GitHub client; the 404→None mapping the client already
    implements is exactly the orphan signal we need.
    """
    token_value = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token_value:
        _warn_once(
            "warning: --check-imposter-commits requires GITHUB_TOKEN in the "
            "environment for authenticated reachability checks; "
            "skipping per-SHA verification (set GITHUB_TOKEN to enable)"
        )
        return None

    # Late imports keep this module light when the rule is disabled —
    # the GitHub client / token machinery only loads when an
    # authenticated check actually runs.
    from .github_client import APIError, GitHubClient
    from .token import TokenManager

    token = TokenManager(token_value, source="env")
    try:
        client = GitHubClient(token)
        result = client._request(f"/repos/{owner}/{repo}/commits/{sha}")
        # 200 -> dict (reachable); 404 -> None (orphan).
        return result is not None
    except APIError as e:
        if e.status == 403:
            print(
                f"error: GitHub API rate-limited while checking "
                f"{owner}/{repo}@{sha[:12]}; SEC3-GH-009 cannot complete. "
                f"Use a higher-quota GITHUB_TOKEN or run on a longer cron.",
                file=sys.stderr,
            )
            return None
        # Other 5xx / unexpected statuses — treat as indeterminate.
        return None
    except Exception:
        # Transport failure (network down, DNS error, TLS).  Don't
        # crash the scan; surface as indeterminate.
        return None
    finally:
        token.clear()
