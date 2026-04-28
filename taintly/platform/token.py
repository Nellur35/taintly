"""Secure token handling for platform-posture API calls.

Section 13 of the v2 requirements document calls out that a security tool
mishandling credentials is the worst kind of irony.  This module implements
those requirements literally.

Priority order, safest first:
    1. ``--token-stdin``            reads from ``sys.stdin``
    2. Environment variable         ``GITHUB_TOKEN`` / ``GITLAB_TOKEN``
    3. Interactive prompt           ``getpass.getpass`` (only if stdin is a TTY)

Explicitly rejected:
    ``--token ghp_xxxxxx``   Visible in ``ps aux``, shell history, process
                             listings.  We never define a CLI flag for an
                             inline token value.

Threat-model honesty: the in-memory string is protected only against
accidental serialization (core dumps, debug repr, exception tracebacks).
It is **not** protected against an attacker who can read the process's
memory — we do not claim cryptographic properties we cannot deliver.

Lifecycle:
    - :class:`TokenManager` wraps the in-memory value.
    - :meth:`TokenManager.clear` zeros the backing string and drops the
      reference — idempotent; safe to call more than once.
    - An ``atexit`` hook calls ``clear()`` on every active manager, so
      abnormal termination still attempts the best-effort wipe.
"""

from __future__ import annotations

import atexit
import getpass
import os
import sys
from typing import ClassVar


class TokenError(Exception):
    """Raised when a token cannot be obtained, validated, or used."""


class TokenManager:
    """A self-clearing holder for a single API token.

    Use :attr:`value` to read; :attr:`masked` for error messages; call
    :meth:`clear` (or let ``atexit`` call it) when done.  Instances
    register themselves with the module-level cleanup list so a process
    exit always sweeps them.
    """

    # Cross-instance registry — intentionally shared class-level
    # state so the atexit sweeper can clear every live token regardless
    # of which caller created it.
    _active: ClassVar[list[TokenManager]] = []

    def __init__(self, value: str, source: str) -> None:
        if not value:
            raise TokenError("Cannot create a TokenManager with an empty value")
        self._value: str | None = value
        self._source = source
        TokenManager._active.append(self)

    @property
    def value(self) -> str:
        if self._value is None:
            raise TokenError("Token has already been cleared")
        return self._value

    @property
    def source(self) -> str:
        """Where the token came from: ``env`` | ``stdin`` | ``prompt``."""
        return self._source

    @property
    def masked(self) -> str:
        """First 4 chars + ellipsis, for use in error messages.

        Returns ``****`` for any token shorter than 4 characters, which
        is always a sign of misuse but we refuse to crash on it.
        """
        if self._value is None or len(self._value) < 4:
            return "****"
        return self._value[:4] + "..."

    def clear(self) -> None:
        """Zero the backing string, drop the reference, and deregister.

        Idempotent.  Previously a cleared manager stayed in the class-level
        ``_active`` registry; over the lifetime of a long-running process
        that would leak stale wrappers (the token value itself is gone,
        but the accounting metadata accumulates).  Deregister on clear so
        the registry only tracks live tokens.
        """
        if self._value is not None:
            # Best-effort: overwrite the object's characters before dropping
            # the reference.  In CPython this does NOT mutate the original
            # string (strings are immutable) — the assignment rebinds
            # self._value.  Still, the rebind encourages the GC to release
            # the original bytes sooner; combined with setting the
            # attribute to None, we've done everything we can from pure
            # Python.
            self._value = "\x00" * len(self._value)
            self._value = None
        try:
            TokenManager._active.remove(self)
        except ValueError:
            # Already deregistered — clear() is idempotent.
            pass


@atexit.register
def _sweep_tokens() -> None:
    """Clear every registered token on process exit."""
    # Iterate a snapshot: tm.clear() removes `tm` from _active, and
    # iterating a mutating list skips the element that shifts into the
    # just-vacated index — half the tokens would survive exit.
    for tm in list(TokenManager._active):
        try:
            tm.clear()
        except Exception:
            # atexit sweep — by contract must never propagate; a single
            # token failing to clear cannot prevent the rest from being
            # wiped. Any exception here is genuinely an "ignore and
            # continue" situation.
            pass  # nosec B110


def _is_truthy(s: str) -> bool:
    return bool(s) and s.lower() not in ("0", "false", "no")


def load_token(
    env_var: str,
    *,
    from_stdin: bool = False,
    interactive: bool = True,
    platform_name: str = "GitHub",
) -> TokenManager:
    """Load an API token using the documented priority chain.

    Args:
        env_var: Name of the environment variable to check (``GITHUB_TOKEN``
                 or ``GITLAB_TOKEN``).
        from_stdin: If ``True``, read the token from ``sys.stdin`` (ignores
                    the environment variable even if set).  Used with the
                    ``--token-stdin`` CLI flag for piping from a secrets
                    manager.
        interactive: If ``True`` and stdin is a TTY, prompt via
                     ``getpass.getpass``.  If ``False`` or stdin is not a
                     TTY and no other source applies, raises
                     :class:`TokenError`.
        platform_name: Human-readable platform name used in the prompt.

    Raises:
        TokenError: If no token is available via any source.
    """
    if from_stdin:
        token = sys.stdin.readline().strip()
        if not token:
            raise TokenError("--token-stdin was requested but stdin is empty")
        return TokenManager(token, source="stdin")

    env_token = os.environ.get(env_var, "").strip()
    if env_token:
        return TokenManager(env_token, source="env")

    if interactive and sys.stdin.isatty():
        token = getpass.getpass(
            f"{platform_name} token (hidden; or set {env_var} / use --token-stdin): "
        ).strip()
        if not token:
            raise TokenError("No token entered at the prompt")
        return TokenManager(token, source="prompt")

    raise TokenError(
        f"No token available. Set the {env_var} environment variable, pipe via "
        f"--token-stdin, or run the command interactively."
    )


def describe_source_for_user(tm: TokenManager) -> str:
    """Short message telling the user where the token came from."""
    if tm.source == "env":
        return (
            "Token loaded from environment variable. Reminder: unset it after this "
            "scan session if it was created for one-off use."
        )
    if tm.source == "stdin":
        return "Token read from stdin pipe."
    if tm.source == "prompt":
        return "Token entered via interactive prompt."
    return f"Token source: {tm.source}"
