"""Unit tests for GitHub platform-posture checks.

The production code calls ``urllib.request.urlopen`` against a real GitHub
API. These tests inject a stub client that returns recorded JSON responses,
so the rules can be exercised deterministically without a token.

Each check has: at least one positive (rule fires), one clear negative
(rule silent), and at least one edge case (Rulesets coverage for
PLAT-GH-001, first-line entry for CODEOWNERS, etc.).
"""

from __future__ import annotations

import pytest

from taintly.platform.github_checks import (
    check_branch_protection_requires_reviews,
    check_codeowners_covers_workflows,
    check_default_branch_protected,
    check_default_token_permission,
    check_fork_pr_approval_gate,
    run_all_checks,
)
from taintly.platform.github_client import APIError, GitHubClient


class StubClient(GitHubClient):
    """GitHubClient that returns canned responses from a dict.

    Tests configure ``responses`` for JSON-body endpoints (used by
    ``_request``) and ``statuses`` for status-only endpoints (used by
    ``_request_status_only`` — the ``/vulnerability-alerts`` shape
    where GitHub signals state via HTTP status with no body).
    """

    def __init__(self, responses: dict, statuses: dict | None = None):
        self._responses = responses
        self._statuses = statuses or {}
        # Don't call super().__init__ — we never hit the network.

    def _request(self, endpoint):
        # Allow tests to configure responses either by exact endpoint or
        # by suffix (e.g. "/rulesets" matches "/repos/foo/bar/rulesets").
        if endpoint in self._responses:
            v = self._responses[endpoint]
            if isinstance(v, Exception):
                raise v
            return v
        for suffix, v in self._responses.items():
            if endpoint.endswith(suffix):
                if isinstance(v, Exception):
                    raise v
                return v
        return None

    def _request_status_only(self, endpoint):
        # Default to 204 (enabled) so the generic smoke test doesn't
        # have to configure a status for every status-only endpoint.
        # Tests that care configure an explicit status via `statuses=`.
        if endpoint in self._statuses:
            return self._statuses[endpoint]
        for suffix, v in self._statuses.items():
            if endpoint.endswith(suffix):
                return v
        return 204


REPO = "octo/hello"


# ---------------------------------------------------------------------------
# PLAT-GH-001 — default branch protection (with Rulesets awareness)
# ---------------------------------------------------------------------------


def test_plat001_fires_when_no_protection_and_no_ruleset():
    client = StubClient({
        f"/repos/{REPO}": {"default_branch": "main"},
        f"/repos/{REPO}/branches/main/protection": None,
        f"/repos/{REPO}/rulesets": [],
    })
    findings = check_default_branch_protected(REPO, client)
    assert len(findings) == 1
    assert findings[0].rule_id == "PLAT-GH-001"
    assert findings[0].origin == "platform"


def test_plat001_silent_when_classic_protection_exists():
    client = StubClient({
        f"/repos/{REPO}": {"default_branch": "main"},
        f"/repos/{REPO}/branches/main/protection": {"some": "config"},
    })
    assert check_default_branch_protected(REPO, client) == []


def test_plat001_silent_when_ruleset_targets_default_branch():
    """Modern repos use Rulesets, not classic protection — must not FP."""
    client = StubClient({
        f"/repos/{REPO}": {"default_branch": "main"},
        f"/repos/{REPO}/branches/main/protection": None,
        f"/repos/{REPO}/rulesets": [{"id": 42}],
        "/rulesets/42": {
            "id": 42,
            "enforcement": "active",
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"]}},
        },
    })
    assert check_default_branch_protected(REPO, client) == []


def test_plat001_silent_when_ruleset_uses_refs_heads_star_pattern():
    client = StubClient({
        f"/repos/{REPO}": {"default_branch": "main"},
        f"/repos/{REPO}/branches/main/protection": None,
        f"/repos/{REPO}/rulesets": [{"id": 7}],
        "/rulesets/7": {
            "id": 7,
            "enforcement": "active",
            "conditions": {"ref_name": {"include": ["refs/heads/*"]}},
        },
    })
    assert check_default_branch_protected(REPO, client) == []


def test_plat001_fires_when_ruleset_is_inactive():
    client = StubClient({
        f"/repos/{REPO}": {"default_branch": "main"},
        f"/repos/{REPO}/branches/main/protection": None,
        f"/repos/{REPO}/rulesets": [{"id": 9}],
        "/rulesets/9": {
            "id": 9,
            "enforcement": "disabled",   # NOT active
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"]}},
        },
    })
    findings = check_default_branch_protected(REPO, client)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# PLAT-GH-002 — reviews required
# ---------------------------------------------------------------------------


def test_plat002_fires_when_reviews_count_is_zero():
    client = StubClient({
        f"/repos/{REPO}": {"default_branch": "main"},
        f"/repos/{REPO}/branches/main/protection": {
            "required_pull_request_reviews": {"required_approving_review_count": 0},
        },
    })
    findings = check_branch_protection_requires_reviews(REPO, client)
    assert len(findings) == 1
    assert findings[0].rule_id == "PLAT-GH-002"


def test_plat002_silent_when_reviews_required():
    client = StubClient({
        f"/repos/{REPO}": {"default_branch": "main"},
        f"/repos/{REPO}/branches/main/protection": {
            "required_pull_request_reviews": {"required_approving_review_count": 2},
        },
    })
    assert check_branch_protection_requires_reviews(REPO, client) == []


def test_plat002_silent_when_no_classic_protection():
    """No classic protection is PLAT-GH-001's concern, not PLAT-GH-002."""
    client = StubClient({
        f"/repos/{REPO}": {"default_branch": "main"},
        f"/repos/{REPO}/branches/main/protection": None,
    })
    assert check_branch_protection_requires_reviews(REPO, client) == []


# ---------------------------------------------------------------------------
# PLAT-GH-005 — fork PR approval gate
# ---------------------------------------------------------------------------


def test_plat005_fires_when_fork_pr_permitted():
    client = StubClient({
        f"/repos/{REPO}/actions/permissions": {
            "fork_pr_workflows_from_fork_contributors_permitted": True,
        },
    })
    findings = check_fork_pr_approval_gate(REPO, client)
    assert len(findings) == 1
    assert findings[0].rule_id == "PLAT-GH-005"


def test_plat005_silent_when_approval_required():
    client = StubClient({
        f"/repos/{REPO}/actions/permissions": {
            "fork_pr_workflows_from_fork_contributors_permitted": False,
        },
        f"/repos/{REPO}/actions/permissions/access": {"access_level": "none"},
    })
    assert check_fork_pr_approval_gate(REPO, client) == []


# ---------------------------------------------------------------------------
# PLAT-GH-007 — default GITHUB_TOKEN permission
# ---------------------------------------------------------------------------


def test_plat007_fires_when_default_is_write():
    client = StubClient({
        f"/repos/{REPO}/actions/permissions/workflow": {
            "default_workflow_permissions": "write",
        },
    })
    findings = check_default_token_permission(REPO, client)
    assert len(findings) == 1
    assert findings[0].rule_id == "PLAT-GH-007"


def test_plat007_silent_when_default_is_read():
    client = StubClient({
        f"/repos/{REPO}/actions/permissions/workflow": {
            "default_workflow_permissions": "read",
        },
    })
    assert check_default_token_permission(REPO, client) == []


def test_plat007_silent_when_api_unavailable():
    client = StubClient({})   # 404 for everything
    assert check_default_token_permission(REPO, client) == []


# ---------------------------------------------------------------------------
# PLAT-GH-008 — CODEOWNERS coverage
# ---------------------------------------------------------------------------


def _codeowners_response(content: str):
    import base64

    return {
        "type": "file",
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
    }


def test_plat008_fires_when_no_codeowners_file():
    client = StubClient({})   # all contents endpoints 404
    findings = check_codeowners_covers_workflows(REPO, client)
    assert len(findings) == 1
    assert findings[0].rule_id == "PLAT-GH-008"
    assert "No CODEOWNERS file" in findings[0].title


def test_plat008_silent_when_workflows_covered():
    content = "# owners\n.github/workflows/ @org/security\n"
    client = StubClient({
        "contents/.github/CODEOWNERS": _codeowners_response(content),
    })
    assert check_codeowners_covers_workflows(REPO, client) == []


def test_plat008_silent_when_wildcard_covers_everything():
    content = "*  @org/security\n"
    client = StubClient({
        "contents/.github/CODEOWNERS": _codeowners_response(content),
    })
    assert check_codeowners_covers_workflows(REPO, client) == []


def test_plat008_fires_when_codeowners_missing_workflows_entry():
    content = "# covers src only\nsrc/  @org/devs\n"
    client = StubClient({
        "contents/.github/CODEOWNERS": _codeowners_response(content),
    })
    findings = check_codeowners_covers_workflows(REPO, client)
    assert len(findings) == 1
    assert "does not cover workflow" in findings[0].title.lower()


def test_plat008_ignores_codeowners_comments():
    """A comment line mentioning 'workflows' shouldn't count as coverage."""
    content = "# Remember to cover .github/workflows/ later\nsrc/  @org/devs\n"
    client = StubClient({
        "contents/.github/CODEOWNERS": _codeowners_response(content),
    })
    findings = check_codeowners_covers_workflows(REPO, client)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# run_all_checks — error handling
# ---------------------------------------------------------------------------


def test_run_all_checks_emits_error_finding_on_api_failure():
    """An APIError in one check must not abort the whole scan."""
    client = StubClient({
        f"/repos/{REPO}": {"default_branch": "main"},
        f"/repos/{REPO}/branches/main/protection": APIError("/branches/main/protection", 500, ""),
        # Everything else 404s naturally
    })
    findings = run_all_checks(REPO, client, checks=["PLAT-GH-001"])
    assert any(f.rule_id == "PLAT-GH-ERR" for f in findings)


def test_run_all_checks_skips_unknown_rule_ids():
    client = StubClient({})
    assert run_all_checks(REPO, client, checks=["PLAT-GH-999-nonexistent"]) == []


# ---------------------------------------------------------------------------
# All findings are tagged with origin=platform
# ---------------------------------------------------------------------------


def test_every_check_sets_origin_platform():
    """Regression guard: all platform findings must have origin='platform'."""
    # Construct a client that triggers every rule at least once.
    client = StubClient({
        f"/repos/{REPO}": {"default_branch": "main"},
        f"/repos/{REPO}/branches/main/protection": {
            "required_pull_request_reviews": {"required_approving_review_count": 0},
        },
        f"/repos/{REPO}/rulesets": [],
        f"/repos/{REPO}/actions/permissions": {
            "fork_pr_workflows_from_fork_contributors_permitted": True,
        },
        f"/repos/{REPO}/actions/permissions/workflow": {
            "default_workflow_permissions": "write",
        },
    })
    findings = run_all_checks(REPO, client)
    assert len(findings) >= 4
    assert all(f.origin == "platform" for f in findings)


# ---------------------------------------------------------------------------
# vulnerability_alerts_enabled — status-code signalling
# ---------------------------------------------------------------------------
#
# Regression for the `_base_url` leak: GitHub's /vulnerability-alerts
# returns 204/404 with no JSON body, which previously caused the method
# to bypass the client's layering (reaching into self._base_url directly)
# and broke every stubbed test that didn't happen to set _base_url.


def test_vulnerability_alerts_enabled_returns_true_on_204():
    client = StubClient({}, statuses={f"/repos/{REPO}/vulnerability-alerts": 204})
    assert client.vulnerability_alerts_enabled(REPO) is True


def test_vulnerability_alerts_enabled_returns_false_on_404():
    client = StubClient({}, statuses={f"/repos/{REPO}/vulnerability-alerts": 404})
    assert client.vulnerability_alerts_enabled(REPO) is False


def test_vulnerability_alerts_enabled_returns_none_on_transport_error():
    # Stub returns None from _request_status_only when configured that way.
    client = StubClient({}, statuses={f"/repos/{REPO}/vulnerability-alerts": None})
    assert client.vulnerability_alerts_enabled(REPO) is None


def test_vulnerability_alerts_enabled_returns_none_on_unexpected_status():
    # 5xx or other unexpected code — neither enabled nor disabled.
    client = StubClient({}, statuses={f"/repos/{REPO}/vulnerability-alerts": 500})
    assert client.vulnerability_alerts_enabled(REPO) is None
