"""Unit tests for the Jenkins posture phase-2 checks (PLAT-JK-006/007/010).

The earlier checks (PLAT-JK-001..005) are exercised in
``test_platform_jenkins_legacy.py`` (or in-repo smoke tests). This file
adds coverage for the three rules added in the Jenkins-posture-phase-2
PR: advisory-feed cross-check, setup-wizard-skipped, and update-center
URL integrity.

Pattern mirrors ``test_platform_github.py``: a stub client returning
canned responses, no network.
"""

from __future__ import annotations

from typing import Any

import pytest

from taintly.platform.jenkins_checks import (
    check_plugin_advisories,
    check_setup_wizard_completed,
    check_update_center_integrity,
    run_all_checks,
)
from taintly.platform.jenkins_client import JenkinsClient


class StubClient(JenkinsClient):
    """JenkinsClient that returns canned responses instead of hitting
    the network. Tests configure the four method-level entry points
    used by the new checks (`instance_info`, `plugins`,
    `update_sites`, `fetch_external`).
    """

    def __init__(
        self,
        *,
        instance_info: dict | None = None,
        plugins: list | None = None,
        update_sites: list | None = None,
        external: dict | None = None,
    ) -> None:
        # Don't call super().__init__ — we never hit the network.
        self._base_url = "https://jenkins.example.com"
        self._user = "tester"
        self._token = "tok"
        self._timeout = 10
        self._instance_info = instance_info
        self._plugins = plugins or []
        self._update_sites = update_sites or []
        self._external = external or {}

    def instance_info(self) -> Any:  # type: ignore[override]
        return self._instance_info

    def plugins(self) -> list[dict[str, Any]]:  # type: ignore[override]
        return self._plugins

    def update_sites(self) -> list[dict[str, Any]]:  # type: ignore[override]
        return self._update_sites

    def fetch_external(  # type: ignore[override]
        self, url: str, *, timeout: int | None = None
    ) -> Any | None:
        return self._external.get(url)


INSTANCE = "https://jenkins.example.com"


# ---------------------------------------------------------------------------
# PLAT-JK-006 — Plugin advisory-feed cross-check
# ---------------------------------------------------------------------------


_FEED_URL = "https://www.jenkins.io/security/advisories/jenkins-data.json"


def test_plat006_fires_when_installed_version_in_advisory_range():
    """An installed plugin matching an advisory's affected version range
    must produce a HIGH (or CRITICAL) finding."""
    client = StubClient(
        plugins=[
            {"shortName": "script-security", "version": "1.78", "active": True},
            {"shortName": "git", "version": "5.0.0", "active": True},
        ],
        external={
            _FEED_URL: [
                {
                    "id": "2024-04-01-script-security-rce",
                    "name": "2024-04-01-script-security-rce",
                    "severity": "high",
                    "plugins": [
                        {
                            "name": "script-security",
                            "firstVersion": "1.0",
                            "lastVersion": "1.80",
                        }
                    ],
                }
            ]
        },
    )
    findings = check_plugin_advisories(INSTANCE, client)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "PLAT-JK-006"
    assert "script-security" in f.title
    assert "1.78" in f.title
    assert f.severity.value in ("HIGH", "CRITICAL")


def test_plat006_silent_when_installed_version_below_advisory_range():
    """An installed plugin below the advisory's firstVersion is not
    affected — must stay silent."""
    client = StubClient(
        plugins=[{"shortName": "script-security", "version": "0.5", "active": True}],
        external={
            _FEED_URL: [
                {
                    "id": "2024-04-01-script-security-rce",
                    "severity": "high",
                    "plugins": [
                        {
                            "name": "script-security",
                            "firstVersion": "1.0",
                            "lastVersion": "1.80",
                        }
                    ],
                }
            ]
        },
    )
    findings = check_plugin_advisories(INSTANCE, client)
    assert findings == []


def test_plat006_silent_when_installed_version_above_advisory_range():
    """Patched: installed > lastVersion. Rule must stay silent."""
    client = StubClient(
        plugins=[{"shortName": "script-security", "version": "2.0", "active": True}],
        external={
            _FEED_URL: [
                {
                    "id": "2024-04-01-script-security-rce",
                    "severity": "high",
                    "plugins": [
                        {
                            "name": "script-security",
                            "firstVersion": "1.0",
                            "lastVersion": "1.80",
                        }
                    ],
                }
            ]
        },
    )
    findings = check_plugin_advisories(INSTANCE, client)
    assert findings == []


def test_plat006_silent_for_inactive_plugin():
    """Disabled plugins don't run code — out of scope."""
    client = StubClient(
        plugins=[{"shortName": "script-security", "version": "1.78", "active": False}],
        external={
            _FEED_URL: [
                {
                    "id": "2024-04-01-script-security-rce",
                    "severity": "high",
                    "plugins": [
                        {
                            "name": "script-security",
                            "firstVersion": "1.0",
                            "lastVersion": "1.80",
                        }
                    ],
                }
            ]
        },
    )
    findings = check_plugin_advisories(INSTANCE, client)
    assert findings == []


def test_plat006_emits_low_finding_when_feed_unavailable():
    """When the advisory feed can't be fetched, surface a LOW finding
    (operational signal, not a security finding) — never silently skip."""
    client = StubClient(
        plugins=[{"shortName": "script-security", "version": "1.78", "active": True}],
        external={},  # feed not in stub -> returns None
    )
    findings = check_plugin_advisories(INSTANCE, client)
    assert len(findings) == 1
    assert findings[0].rule_id == "PLAT-JK-006"
    assert findings[0].severity.value == "LOW"
    assert "advisory feed unavailable" in findings[0].title.lower()


def test_plat006_critical_severity_for_critical_advisory():
    """Advisory severity 'critical' should escalate the finding to
    CRITICAL even though the rule's nominal severity is HIGH."""
    client = StubClient(
        plugins=[{"shortName": "remoting", "version": "4.6", "active": True}],
        external={
            _FEED_URL: [
                {
                    "id": "2024-04-01-remoting-rce",
                    "severity": "critical",
                    "plugins": [
                        {
                            "name": "remoting",
                            "firstVersion": "4.0",
                            "lastVersion": "4.10",
                        }
                    ],
                }
            ]
        },
    )
    findings = check_plugin_advisories(INSTANCE, client)
    assert len(findings) == 1
    assert findings[0].severity.value == "CRITICAL"


def test_plat006_dedupes_per_plugin_per_advisory():
    """The same (plugin, advisory) pair must fire exactly once even if
    the feed lists it multiple times (defensive against feed shape
    changes)."""
    adv = {
        "id": "dup-id",
        "severity": "high",
        "plugins": [
            {"name": "script-security", "firstVersion": "1.0", "lastVersion": "2.0"}
        ],
    }
    client = StubClient(
        plugins=[{"shortName": "script-security", "version": "1.5", "active": True}],
        external={_FEED_URL: [adv, adv]},
    )
    findings = check_plugin_advisories(INSTANCE, client)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# PLAT-JK-007 — Setup wizard skipped / security disabled
# ---------------------------------------------------------------------------


def test_plat007_fires_when_useSecurity_false():
    """``useSecurity: false`` is the most egregious misconfiguration —
    must fire CRITICAL."""
    client = StubClient(instance_info={"useSecurity": False})
    findings = check_setup_wizard_completed(INSTANCE, client)
    assert len(findings) == 1
    assert findings[0].rule_id == "PLAT-JK-007"
    assert findings[0].severity.value == "CRITICAL"
    assert "authentication disabled" in findings[0].title.lower()


def test_plat007_silent_when_useSecurity_true():
    client = StubClient(instance_info={"useSecurity": True})
    findings = check_setup_wizard_completed(INSTANCE, client)
    assert findings == []


def test_plat007_silent_when_useSecurity_absent():
    """Modern Jenkins enables security by default; absent field is OK."""
    client = StubClient(instance_info={})
    findings = check_setup_wizard_completed(INSTANCE, client)
    assert findings == []


def test_plat007_silent_when_instance_info_unavailable():
    """If we can't get the instance info, defer rather than fire on
    speculation."""
    client = StubClient(instance_info=None)
    findings = check_setup_wizard_completed(INSTANCE, client)
    assert findings == []


# ---------------------------------------------------------------------------
# PLAT-JK-010 — Update Center URL integrity
# ---------------------------------------------------------------------------


def test_plat010_silent_for_canonical_update_center():
    client = StubClient(
        update_sites=[
            {"id": "default", "url": "https://updates.jenkins.io/update-center.json"}
        ]
    )
    findings = check_update_center_integrity(INSTANCE, client)
    assert findings == []


def test_plat010_silent_for_canonical_lts_update_center():
    """Versioned LTS branches (stable-2.401/...) live under updates.jenkins.io."""
    client = StubClient(
        update_sites=[
            {
                "id": "default",
                "url": "https://updates.jenkins.io/stable-2.401/update-center.json",
            }
        ]
    )
    findings = check_update_center_integrity(INSTANCE, client)
    assert findings == []


def test_plat010_fires_for_custom_url():
    client = StubClient(
        update_sites=[
            {"id": "default", "url": "https://my-mirror.internal/update-center.json"}
        ]
    )
    findings = check_update_center_integrity(INSTANCE, client)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "PLAT-JK-010"
    assert f.severity.value == "HIGH"
    assert "my-mirror.internal" in f.description


def test_plat010_fires_for_http_url():
    """Non-HTTPS update center is doubly bad — non-canonical AND
    plaintext fetching."""
    client = StubClient(
        update_sites=[
            {"id": "default", "url": "http://updates.jenkins.io/update-center.json"}
        ]
    )
    findings = check_update_center_integrity(INSTANCE, client)
    assert len(findings) == 1


def test_plat010_silent_for_no_sites():
    """Empty sites list — controllers without update centers configured
    should not produce a finding (the absence isn't itself a smell)."""
    client = StubClient(update_sites=[])
    findings = check_update_center_integrity(INSTANCE, client)
    assert findings == []


# ---------------------------------------------------------------------------
# Registry sanity — the new rules are wired into ALL_CHECKS.
# ---------------------------------------------------------------------------


def test_new_rules_registered_in_all_checks():
    from taintly.platform.jenkins_checks import ALL_CHECKS

    for rule_id in ("PLAT-JK-006", "PLAT-JK-007", "PLAT-JK-010"):
        assert rule_id in ALL_CHECKS, (
            f"{rule_id} must be wired into ALL_CHECKS so run_all_checks "
            f"actually executes it"
        )


def test_run_all_checks_executes_new_rules():
    """End-to-end: run_all_checks should invoke the new checks and
    aggregate their findings without error."""
    client = StubClient(
        instance_info={"useSecurity": False},
        plugins=[],
        update_sites=[
            {"id": "default", "url": "https://my-mirror.internal/update-center.json"}
        ],
        external={_FEED_URL: []},
    )
    findings = run_all_checks(
        INSTANCE,
        client,
        checks=["PLAT-JK-007", "PLAT-JK-010"],
    )
    rule_ids = {f.rule_id for f in findings}
    assert "PLAT-JK-007" in rule_ids
    assert "PLAT-JK-010" in rule_ids
