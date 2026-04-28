"""Tests for secure token handling (taintly.platform.token)."""

from __future__ import annotations

import io

import pytest

from taintly.platform.token import (
    TokenError,
    TokenManager,
    describe_source_for_user,
    load_token,
)


# ---------------------------------------------------------------------------
# TokenManager
# ---------------------------------------------------------------------------


def test_token_manager_exposes_value():
    tm = TokenManager("ghp_abc123", source="env")
    assert tm.value == "ghp_abc123"
    assert tm.source == "env"


def test_token_manager_masked_shows_only_prefix():
    tm = TokenManager("ghp_verysecret", source="env")
    assert tm.masked.startswith("ghp_")
    assert "verysecret" not in tm.masked


def test_token_manager_masked_handles_short_token():
    # Under-4-char tokens are always a sign of misuse but must not crash.
    tm = TokenManager("xx", source="env")
    assert tm.masked == "****"


def test_token_manager_clear_is_idempotent():
    tm = TokenManager("ghp_xxx", source="env")
    tm.clear()
    tm.clear()  # must not raise
    with pytest.raises(TokenError):
        tm.value


def test_token_manager_rejects_empty_value():
    with pytest.raises(TokenError):
        TokenManager("", source="env")


# ---------------------------------------------------------------------------
# load_token — priority chain
# ---------------------------------------------------------------------------


def test_load_token_from_stdin(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("ghp_fromstdin\n"))
    tm = load_token("GITHUB_TOKEN", from_stdin=True)
    assert tm.value == "ghp_fromstdin"
    assert tm.source == "stdin"


def test_load_token_from_stdin_raises_when_empty(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    with pytest.raises(TokenError, match="stdin is empty"):
        load_token("GITHUB_TOKEN", from_stdin=True)


def test_load_token_from_env(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_fromenv")
    tm = load_token("GITHUB_TOKEN", from_stdin=False)
    assert tm.value == "ghp_fromenv"
    assert tm.source == "env"


def test_load_token_raises_when_no_source_available(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    # Non-TTY stdin and interactive=True → prompt path unreachable.
    class _NonTTY:
        def isatty(self):
            return False

        def readline(self):
            return ""

    monkeypatch.setattr("sys.stdin", _NonTTY())
    with pytest.raises(TokenError, match="No token available"):
        load_token("GITHUB_TOKEN", interactive=True)


def test_load_token_stdin_takes_priority_over_env(monkeypatch):
    """If both --token-stdin and GITHUB_TOKEN are set, stdin wins."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_fromenv")
    monkeypatch.setattr("sys.stdin", io.StringIO("ghp_fromstdin\n"))
    tm = load_token("GITHUB_TOKEN", from_stdin=True)
    assert tm.value == "ghp_fromstdin"


# ---------------------------------------------------------------------------
# describe_source_for_user
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source, expected_keyword",
    [
        ("env", "environment"),
        ("stdin", "stdin"),
        ("prompt", "interactive"),
    ],
)
def test_describe_source_for_user_includes_origin(source, expected_keyword):
    tm = TokenManager("ghp_x" * 4, source=source)
    msg = describe_source_for_user(tm)
    assert expected_keyword in msg.lower()


# ---------------------------------------------------------------------------
# Regression: the token value never appears in repr / str
# ---------------------------------------------------------------------------


def test_repr_does_not_leak_token():
    tm = TokenManager("ghp_SECRETVALUE", source="env")
    assert "SECRETVALUE" not in repr(tm)
    assert "SECRETVALUE" not in str(tm)


def test_clear_removes_manager_from_active_registry():
    """Regression: cleared managers must be deregistered from the
    class-level ``_active`` list so it doesn't grow monotonically
    across the process lifetime."""
    before = len(TokenManager._active)
    tm = TokenManager("ghp_abcdefghijklmnop", source="env")
    assert len(TokenManager._active) == before + 1
    tm.clear()
    assert len(TokenManager._active) == before, (
        "clear() should remove the manager from _active"
    )
    # Idempotent: calling clear() twice must not fail.
    tm.clear()
    assert len(TokenManager._active) == before
