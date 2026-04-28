"""Unit tests for GitLab platform-posture checks.

Uses a StubClient with canned responses — no network.
"""

from __future__ import annotations

import pytest

from taintly.platform.gitlab_checks import (
    check_default_branch_protected,
    check_mr_requires_approval,
    check_public_pipelines,
    check_variables_masked,
    check_variables_protected,
    run_all_checks,
)
from taintly.platform.gitlab_client import APIError, GitLabClient


class StubClient(GitLabClient):
    def __init__(self, responses: dict):
        self._responses = responses
        # Skip super().__init__ — no network.

    def _request(self, endpoint):
        if endpoint in self._responses:
            v = self._responses[endpoint]
            if isinstance(v, Exception):
                raise v
            return v
        # Fall through to suffix match for path-encoded project IDs.
        for suffix, v in self._responses.items():
            if endpoint.endswith(suffix):
                if isinstance(v, Exception):
                    raise v
                return v
        return None


PROJECT = "42"   # numeric id


# ---------------------------------------------------------------------------
# PLAT-GL-001 — default branch protected
# ---------------------------------------------------------------------------


def test_plat_gl_001_fires_when_default_branch_unprotected():
    client = StubClient({
        f"/projects/{PROJECT}": {"default_branch": "main"},
        f"/projects/{PROJECT}/protected_branches/main": None,
    })
    findings = check_default_branch_protected(PROJECT, client)
    assert len(findings) == 1
    assert findings[0].rule_id == "PLAT-GL-001"
    assert findings[0].origin == "platform"


def test_plat_gl_001_silent_when_default_branch_protected():
    client = StubClient({
        f"/projects/{PROJECT}": {"default_branch": "main"},
        f"/projects/{PROJECT}/protected_branches/main": {"name": "main"},
    })
    assert check_default_branch_protected(PROJECT, client) == []


# ---------------------------------------------------------------------------
# PLAT-GL-002 — MR approvals
# ---------------------------------------------------------------------------


def test_plat_gl_002_fires_when_zero_approvals_required():
    client = StubClient({
        f"/projects/{PROJECT}/approval_rules": [
            {"name": "default", "approvals_required": 0},
        ],
    })
    findings = check_mr_requires_approval(PROJECT, client)
    assert len(findings) == 1


def test_plat_gl_002_silent_when_at_least_one_rule_requires_approval():
    client = StubClient({
        f"/projects/{PROJECT}/approval_rules": [
            {"name": "default", "approvals_required": 0},
            {"name": "security", "approvals_required": 1},
        ],
    })
    assert check_mr_requires_approval(PROJECT, client) == []


def test_plat_gl_002_falls_back_to_legacy_approvals_endpoint():
    """Pre-Premium instances expose /projects/:id/approvals."""
    client = StubClient({
        f"/projects/{PROJECT}/approval_rules": [],
        f"/projects/{PROJECT}/approvals": {"approvals_before_merge": 2},
    })
    assert check_mr_requires_approval(PROJECT, client) == []


def test_plat_gl_002_fires_when_no_rules_and_legacy_summary_missing():
    client = StubClient({
        f"/projects/{PROJECT}/approval_rules": [],
        f"/projects/{PROJECT}/approvals": None,
    })
    findings = check_mr_requires_approval(PROJECT, client)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# PLAT-GL-003 / 004 — Variable Protected / Masked flags
# ---------------------------------------------------------------------------


def test_plat_gl_003_fires_when_secret_variable_not_protected():
    client = StubClient({
        f"/projects/{PROJECT}/variables": [
            {"key": "AWS_SECRET", "value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "protected": False, "masked": True},
        ],
    })
    findings = check_variables_protected(PROJECT, client)
    assert len(findings) == 1
    assert findings[0].rule_id == "PLAT-GL-003"


def test_plat_gl_003_silent_for_trivial_values():
    """Short, numeric, or boolean values are not treated as secrets."""
    client = StubClient({
        f"/projects/{PROJECT}/variables": [
            {"key": "ENABLE_X", "value": "true", "protected": False},
            {"key": "COUNT", "value": "42", "protected": False},
            {"key": "MODE", "value": "dev", "protected": False},
        ],
    })
    assert check_variables_protected(PROJECT, client) == []


def test_plat_gl_003_silent_when_all_credentials_are_protected():
    client = StubClient({
        f"/projects/{PROJECT}/variables": [
            {"key": "AWS_SECRET", "value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "protected": True, "masked": True},
        ],
    })
    assert check_variables_protected(PROJECT, client) == []


def test_plat_gl_003_silent_when_variables_endpoint_returns_nothing():
    """Token without Maintainer access → 404/empty → don't false-positive."""
    client = StubClient({
        f"/projects/{PROJECT}/variables": [],
    })
    assert check_variables_protected(PROJECT, client) == []


def test_plat_gl_004_fires_when_secret_variable_not_masked():
    client = StubClient({
        f"/projects/{PROJECT}/variables": [
            {"key": "DEPLOY_KEY", "value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "protected": True, "masked": False},
        ],
    })
    findings = check_variables_masked(PROJECT, client)
    assert len(findings) == 1
    assert findings[0].rule_id == "PLAT-GL-004"


def test_plat_gl_004_silent_when_all_secrets_masked():
    client = StubClient({
        f"/projects/{PROJECT}/variables": [
            {"key": "DEPLOY_KEY", "value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "protected": True, "masked": True},
        ],
    })
    assert check_variables_masked(PROJECT, client) == []


# ---------------------------------------------------------------------------
# PLAT-GL-008 — public pipelines on a public project
# ---------------------------------------------------------------------------


def test_plat_gl_008_fires_for_public_project_with_public_jobs():
    client = StubClient({
        f"/projects/{PROJECT}": {
            "default_branch": "main",
            "visibility": "public",
            "public_jobs": True,
        },
    })
    findings = check_public_pipelines(PROJECT, client)
    assert len(findings) == 1
    assert findings[0].rule_id == "PLAT-GL-008"


def test_plat_gl_008_silent_for_private_project():
    """Private project never exposes job logs anonymously regardless of flag."""
    client = StubClient({
        f"/projects/{PROJECT}": {
            "default_branch": "main",
            "visibility": "private",
            "public_jobs": True,
        },
    })
    assert check_public_pipelines(PROJECT, client) == []


def test_plat_gl_008_silent_for_public_project_with_public_jobs_disabled():
    client = StubClient({
        f"/projects/{PROJECT}": {
            "default_branch": "main",
            "visibility": "public",
            "public_jobs": False,
        },
    })
    assert check_public_pipelines(PROJECT, client) == []


def test_plat_gl_008_handles_legacy_public_builds_field():
    """Older GitLab versions return `public_builds` instead of `public_jobs`."""
    client = StubClient({
        f"/projects/{PROJECT}": {
            "default_branch": "main",
            "visibility": "public",
            "public_builds": True,   # legacy field name
        },
    })
    findings = check_public_pipelines(PROJECT, client)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# run_all_checks — error handling, origin tagging
# ---------------------------------------------------------------------------


def test_gitlab_run_all_checks_emits_error_finding_on_api_failure():
    client = StubClient({
        f"/projects/{PROJECT}": APIError("/projects/42", 500, ""),
    })
    findings = run_all_checks(PROJECT, client, checks=["PLAT-GL-001"])
    assert any(f.rule_id == "PLAT-GL-ERR" for f in findings)


def test_every_gitlab_check_sets_origin_platform():
    """Construct a client that triggers all five rules; verify origin tag."""
    client = StubClient({
        f"/projects/{PROJECT}": {
            "default_branch": "main",
            "visibility": "public",
            "public_jobs": True,
        },
        f"/projects/{PROJECT}/protected_branches/main": None,
        f"/projects/{PROJECT}/approval_rules": [],
        f"/projects/{PROJECT}/approvals": {"approvals_before_merge": 0},
        f"/projects/{PROJECT}/variables": [
            {"key": "SECRET", "value": "wJalrXUtnFEMI/K7MDENG", "protected": False, "masked": False},
        ],
    })
    findings = run_all_checks(PROJECT, client)
    assert len(findings) >= 4
    assert all(f.origin == "platform" for f in findings)


# ---------------------------------------------------------------------------
# URL-encoding of group/project paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, encoded",
    [
        ("42", "42"),
        ("group/project", "group%2Fproject"),
        ("g/sub/proj", "g%2Fsub%2Fproj"),
    ],
)
def test_encode_project_handles_numeric_and_path_forms(raw, encoded):
    assert GitLabClient.encode_project(raw) == encoded
