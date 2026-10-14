"""Native CLI contract for qualified OIDC review findings."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "oidc_metadata_review"


def _scan_fixture(source: Path, workspace: Path) -> dict:
    repo = workspace / "repo"
    shutil.copytree(source, repo)
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [
            sys.executable,
            "-S",
            "-m",
            "taintly",
            str(repo),
            "--platform",
            "github",
            "--format",
            "json",
            "--no-color",
            "--no-config",
        ],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    assert result.stderr == ""
    report = json.loads(result.stdout)
    assert report["coverage_status"] == "complete", report.get("errors")
    assert report["engine_error_count"] == 0
    return report


def _rule_finding(report: dict, rule_id: str) -> dict:
    findings = [item for item in report["findings"] if item["rule_id"] == rule_id]
    assert len(findings) == 1, f"expected one {rule_id}, got {findings}"
    return findings[0]


def _assert_review_candidate(finding: dict, title: str) -> None:
    assert finding["title"] == title
    assert finding["severity"] == "MEDIUM"
    assert finding["confidence"] == "low"
    assert finding["review_needed"] is True
    message = " ".join(
        finding.get(field, "")
        for field in ("description", "remediation", "threat_narrative")
    ).lower()
    assert "very likely" not in message
    assert "no change is needed" not in message
    assert "persistent cloud access" not in message
    assert "any compromised step" not in message


@pytest.mark.parametrize(
    ("case", "rule_id", "title", "permission_line", "sibling_override_line"),
    [
        (
            "SEC5-GH-001-unknown-external-action",
            "SEC5-GH-001",
            "id-token: write declaration needs OIDC usage review",
            6,
            21,
        ),
        (
            "SEC5-GH-001B-local-composite",
            "SEC5-GH-001B",
            "id-token: write declaration and called code need OIDC usage review",
            11,
            20,
        ),
    ],
)
def test_oidc_declarations_are_qualified_review_candidates(
    case: str,
    rule_id: str,
    title: str,
    permission_line: int,
    sibling_override_line: int,
    tmp_path: Path,
) -> None:
    report = _scan_fixture(FIXTURES / case, tmp_path)
    finding = _rule_finding(report, rule_id)
    _assert_review_candidate(finding, title)

    # The exact physical workflow permission declaration is the finding anchor;
    # the separate documentation job's id-token:none must not become its owner.
    assert (
        finding["file"]
        .replace("\\", "/")
        .endswith("/.github/workflows/oidc-review.yml")
    )
    assert finding["line"] == permission_line
    assert finding["line"] != sibling_override_line
    assert finding["snippet"].strip() == "id-token: write"

    description = finding["description"].lower()
    remediation = finding["remediation"].lower()
    threat = finding["threat_narrative"].lower()
    assert "effective" in description + remediation + threat
    assert "owning job" in description + remediation
    assert "relying party" in remediation + threat
    assert "audience" in remediation
    assert "expiry" in remediation

    if rule_id == "SEC5-GH-001":
        assert "custom code or unsupported actions may consume oidc" in description
        assert "not proof that the permission is unused" in description
        assert "configured trust relationship" in threat
        assert "not established by this finding" in threat
        assert "job overrides" in remediation
        # The external action ref is not in the finite consumer marker list.
        assert (
            "shogo82148/actions-github-app-token@d75b03a80d0450d087a12b72dff2d987a4ced993"
            in (
                (
                    FIXTURES / case / ".github" / "workflows" / "oidc-review.yml"
                ).read_text(encoding="utf-8")
            )
        )
    else:
        assert "called code may consume oidc" in description
        assert "neither consumer presence nor absence is established" in description
        assert "do not prove that the declaration governs that call" in description
        assert "finding a consumer alone does not justify every grant" in remediation
        assert "only if the relying party accepts the token claims" in threat
        assert (
            FIXTURES / case / ".github" / "actions" / "harmless-check" / "action.yml"
        ).is_file()
        workflow = (
            FIXTURES / case / ".github" / "workflows" / "oidc-review.yml"
        ).read_text(encoding="utf-8")
        assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in workflow
