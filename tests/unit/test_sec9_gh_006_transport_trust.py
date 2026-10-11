from __future__ import annotations

from pathlib import Path

from taintly.engine import scan_file
from taintly.models import Platform, Severity
from taintly.rules.registry import load_rules_for_platform

GITHUB_RULES = load_rules_for_platform(Platform.GITHUB)


def _sec9_findings(tmp_path: Path, command: str):
    content = (
        "name: transport-trust\n"
        "on: push\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - run: {command}\n"
    )
    path = tmp_path / ".github" / "workflows" / "transport-trust.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return [
        finding
        for finding in scan_file(str(path), GITHUB_RULES, content)
        if finding.rule_id == "SEC9-GH-006"
    ]


def test_https_curl_to_shell_retains_finding_with_transport_prerequisite(
    tmp_path: Path,
) -> None:
    finding, = _sec9_findings(
        tmp_path,
        "curl -fsSL https://downloads.example.org/install.sh | bash",
    )

    assert finding.severity == Severity.HIGH
    wording = f"{finding.description}\n{finding.threat_narrative}".lower()
    assert "normal https certificate validation" in wording
    assert "dns or bgp interference alone" in wording
    assert "control of the authenticated endpoint" in wording
    assert "tls trust or identity validation" in wording
    assert "secrets available to that execution" in wording


def test_http_curl_to_shell_remains_a_direct_substitution_path(
    tmp_path: Path,
) -> None:
    finding, = _sec9_findings(
        tmp_path,
        "curl -fsSL http://downloads.example.org/install.sh | bash",
    )

    assert finding.severity == Severity.HIGH
    wording = f"{finding.description}\n{finding.threat_narrative}".lower()
    assert "plain http" in wording


def test_https_download_to_file_alone_is_not_remote_execution_finding(
    tmp_path: Path,
) -> None:
    assert _sec9_findings(
        tmp_path,
        "curl -fsSL https://downloads.example.org/install.sh -o install.sh",
    ) == []
