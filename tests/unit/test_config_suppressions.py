"""Tests for v2 suppression metadata (reason / expires / owner).

The improvement report's Phase 3 ask for suppression governance:
justification and expiry to stop silent exceptions from accumulating.
These tests lock in the parser contract and the warning emission.
"""

from __future__ import annotations

import datetime as _dt

import pytest

from taintly.config import (
    ConfigError,
    IgnoreEntry,
    audit_ignores,
    load_config,
)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _write_config(tmp_path, body: str) -> str:
    p = tmp_path / ".taintly.yml"
    p.write_text(body, encoding="utf-8")
    return str(p)


def test_parser_accepts_reason_and_expires(tmp_path):
    """Full-form ignore entry with reason/expires/owner must parse."""
    path = _write_config(tmp_path, """
version: 1
ignore:
  - id: SEC4-GH-002
    path: .github/workflows/internal.yml
    reason: internal-only workflow — no fork triggers
    expires: 2030-01-15
    owner: platform-security@example.com
""")
    cfg = load_config(path)
    assert len(cfg.ignores) == 1
    entry = cfg.ignores[0]
    assert entry.rule_id == "SEC4-GH-002"
    assert entry.reason == "internal-only workflow — no fork triggers"
    assert entry.expires == _dt.date(2030, 1, 15)
    assert entry.owner == "platform-security@example.com"


def test_parser_rejects_bad_expires_date(tmp_path):
    """Malformed dates must fail the config load — silent garbage
    would turn into never-expiring suppressions."""
    path = _write_config(tmp_path, """
version: 1
ignore:
  - id: SEC4-GH-002
    path: a.yml
    expires: not-a-date
""")
    with pytest.raises(ConfigError, match="expires"):
        load_config(path)


def test_parser_reason_optional(tmp_path):
    """Entries without reason still parse (backwards-compatible)."""
    path = _write_config(tmp_path, """
version: 1
ignore:
  - id: SEC4-GH-002
    path: a.yml
""")
    cfg = load_config(path)
    assert cfg.ignores[0].reason is None


# ---------------------------------------------------------------------------
# audit_ignores — warning emission
# ---------------------------------------------------------------------------


def test_audit_ignores_warns_on_expired():
    """A suppression whose expires date is in the past must surface a
    warning even though the filter still applies."""
    entries = [
        IgnoreEntry(
            rule_id="SEC4-GH-002",
            path_prefix="a.yml",
            reason="short-term exception",
            expires=_dt.date(2020, 1, 1),
        ),
    ]
    today = _dt.date(2026, 4, 15)
    msgs = audit_ignores(entries, today=today)
    assert any("expired" in m for m in msgs)


def test_audit_ignores_does_not_warn_future_expiry():
    """Suppressions whose expires is in the future are silent."""
    entries = [
        IgnoreEntry(
            rule_id="SEC4-GH-002",
            path_prefix="a.yml",
            reason="pending refactor",
            expires=_dt.date(2099, 1, 1),
        ),
    ]
    msgs = audit_ignores(entries, today=_dt.date(2026, 4, 15))
    assert msgs == []


def test_audit_ignores_warns_on_missing_reason_for_rich_entry():
    """A path-scoped entry without a reason must warn — those are the
    entries most likely to become stale silent exceptions."""
    entries = [
        IgnoreEntry(
            rule_id="SEC4-GH-002",
            path_prefix=".github/workflows/x.yml",
            reason=None,
            owner="me",
        ),
    ]
    msgs = audit_ignores(entries)
    assert any("reason" in m for m in msgs)


def test_audit_ignores_exempts_bare_ruleid_list_items():
    """The short-form `- SEC4-GH-002` must not spam warnings — it's
    still explicit in the committed config, even without a reason."""
    entries = [IgnoreEntry(rule_id="SEC4-GH-002", path_prefix=None)]
    msgs = audit_ignores(entries)
    assert msgs == []


def test_is_expired_property():
    today = _dt.date(2026, 4, 15)
    fresh = IgnoreEntry(rule_id="A", path_prefix=None, expires=_dt.date(2026, 5, 1))
    old = IgnoreEntry(rule_id="A", path_prefix=None, expires=_dt.date(2025, 12, 31))
    forever = IgnoreEntry(rule_id="A", path_prefix=None, expires=None)
    assert fresh.is_expired(today) is False
    assert old.is_expired(today) is True
    assert forever.is_expired(today) is False
