"""Replay-mode tests for ``--platform-audit`` posture rules.

Posture rules (PLAT-GH-*, PLAT-GL-*) call the GitHub / GitLab REST APIs
to make assertions about repo / project state — branch protection,
default token permissions, fork-PR approval gates, etc.  They are
auth-dependent and network-dependent, so they are not exercised by
the rest of the test suite.

This module substitutes a tiny ``RecordedClient`` for the real API
client.  The recorded client maps endpoint paths onto canned JSON in
``tests/playground/api-fixtures/{gh,gl}/`` and returns those bytes
exactly the way the real client would.  The check function under test
is unchanged — it sees a normal client, makes its normal calls, and
returns its normal Findings.

Adding a scenario:

  1. Drop a new fixture file under ``api-fixtures/{gh,gl}/`` named for
     the endpoint slug (see ``api-fixtures/README.md``).
  2. Add a test below that wires the relevant check function to a
     ``RecordedClient`` over those fixtures.
  3. Assert on the rule_ids in the returned Findings list.

This catches regressions where:
  * A check stops calling an endpoint it should call.
  * A check mis-handles an absence signal (404 → None) and crashes.
  * A check's finding text drifts in a way that breaks user-facing
    documentation links.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

_API_FIXTURES = Path(__file__).parent / "api-fixtures"


def _endpoint_to_slug(endpoint: str) -> str:
    """Map ``/repos/owner/repo/branches/main/protection`` to
    ``repos__owner__repo__branches__main__protection``."""
    return endpoint.lstrip("/").replace("/", "__")


class _RecordedClient:
    """Minimal stand-in for ``taintly.platform.github_client.GitHubClient``.

    Implements the same public method surface used by ``check_*``
    functions in ``taintly.platform.github_checks``, sourced from
    canned JSON in ``api-fixtures/gh/``.  Returns ``None`` for any
    endpoint without a recorded fixture (that's the 404 absence
    signal that the real client returns from ``_request``).
    """

    def __init__(self, vendor: str = "gh") -> None:
        self._dir = _API_FIXTURES / vendor

    def _load(self, endpoint: str) -> Any | None:
        slug = _endpoint_to_slug(endpoint)
        path = self._dir / f"{slug}.json"
        if not path.exists():
            # Absence-signal mirror — checks must defend ``None`` from
            # the real client's 404 path; we surface the same here so
            # missing fixtures behave consistently rather than crash.
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            pytest.fail(f"malformed fixture {path}: {e}")

    # --- subset of GitHubClient surface used by tests below ----------------
    def repo(self, owner_repo: str) -> dict[str, Any] | None:
        return self._load(f"/repos/{owner_repo}")

    def default_branch(self, owner_repo: str) -> str | None:
        r = self.repo(owner_repo)
        return r.get("default_branch") if isinstance(r, dict) else None

    def branch_protection(self, owner_repo: str, branch: str) -> dict[str, Any] | None:
        return self._load(f"/repos/{owner_repo}/branches/{branch}/protection")

    def rulesets(self, owner_repo: str) -> list[dict[str, Any]]:
        data = self._load(f"/repos/{owner_repo}/rulesets")
        return data if isinstance(data, list) else []

    def ruleset_detail(self, owner_repo: str, ruleset_id: int) -> dict[str, Any] | None:
        return self._load(f"/repos/{owner_repo}/rulesets/{ruleset_id}")

    # Add more pass-throughs as new test scenarios reach for them.
    # Keep this client SMALL — bloating it with every GitHubClient
    # method makes it harder to keep in sync with the real client.


def test_unprotected_default_branch_fires_plat_gh_001() -> None:
    """Repo with default_branch=main, no classic branch protection,
    and no rulesets must trip PLAT-GH-001 (CRITICAL)."""
    from taintly.platform.github_checks import check_default_branch_protected

    client = _RecordedClient(vendor="gh")
    findings = check_default_branch_protected("test-org/unprotected-repo", client)  # type: ignore[arg-type]

    rule_ids = [f.rule_id for f in findings]
    assert "PLAT-GH-001" in rule_ids, (
        f"expected PLAT-GH-001 to fire on an unprotected default branch; "
        f"got: {rule_ids}"
    )
    # Quality-of-finding sanity: severity, OWASP mapping, and the
    # default-branch name must propagate into the finding.
    plat = next(f for f in findings if f.rule_id == "PLAT-GH-001")
    assert plat.severity.name == "CRITICAL"
    assert plat.owasp_cicd == "CICD-SEC-1"
    assert "main" in (plat.description or "")


def test_recorded_client_404_returns_none() -> None:
    """An endpoint with no fixture file should return ``None`` — same
    contract the real client uses for 404s — so check functions can
    rely on that absence signal even in replay mode."""
    client = _RecordedClient(vendor="gh")
    assert client.repo("test-org/does-not-exist") is None
    assert client.branch_protection("test-org/does-not-exist", "main") is None
    assert client.rulesets("test-org/does-not-exist") == []
