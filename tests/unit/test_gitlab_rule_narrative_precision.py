from __future__ import annotations

from pathlib import Path

from taintly.engine import scan_file
from taintly.models import Platform, Severity
from taintly.rules.registry import load_rules_for_platform

GITLAB_RULES = load_rules_for_platform(Platform.GITLAB)


def _findings(tmp_path: Path, rule_id: str, content: str):
    path = tmp_path / ".gitlab-ci.yml"
    path.write_text(content, encoding="utf-8")
    return [
        finding
        for finding in scan_file(str(path), GITLAB_RULES, content)
        if finding.rule_id == rule_id
    ]


def test_sec9_archive_extraction_finding_does_not_claim_execution(tmp_path: Path) -> None:
    content = (
        "build:\n"
        "  script:\n"
        "    - curl -fsSL -o tests.tar.gz https://example.org/releases/tests.tar.gz\n"
        "    - mkdir extracted && tar -xzf tests.tar.gz -C extracted\n"
    )

    (finding,) = _findings(tmp_path, "SEC9-GL-002", content)

    assert finding.severity == Severity.HIGH
    assert "integrity" in finding.description.lower()
    assert "does not establish" in finding.description.lower()
    assert "executes attacker-controlled code" not in finding.threat_narrative.lower()
    assert "may access" in finding.threat_narrative.lower()


def test_sec9_later_execution_remains_in_scope_with_conditional_wording(
    tmp_path: Path,
) -> None:
    content = (
        "build:\n"
        "  script:\n"
        "    - curl -fsSL -o tests.tar.gz https://example.org/releases/tests.tar.gz\n"
        "    - mkdir extracted && tar -xzf tests.tar.gz -C extracted\n"
        "    - cd extracted && ./run-tests.sh\n"
    )

    (finding,) = _findings(tmp_path, "SEC9-GL-002", content)

    assert finding.severity == Severity.HIGH
    assert "if a job later runs" in finding.description.lower()
    assert "if the job later executes" in finding.threat_narrative.lower()


def test_sec8_named_mutable_ref_is_not_described_as_default_branch_or_secret_access(
    tmp_path: Path,
) -> None:
    content = "include:\n  - project: org/shared-ci\n    ref: release-2026\n    file: /ci.yml\n"

    (finding,) = _findings(tmp_path, "SEC8-GL-002", content)

    assert finding.severity == Severity.HIGH
    assert "mutable" in finding.description.lower()
    assert "if `ref:` is omitted" in finding.description.lower()
    assert "project's `head`" in finding.description.lower()
    assert "resolves against the default branch" not in finding.description.lower()
    assert "depends on" in finding.threat_narrative.lower()
    assert "does not establish" in finding.threat_narrative.lower()


def test_sec8_omitted_ref_and_sha_pin_keep_existing_detection_boundary(
    tmp_path: Path,
) -> None:
    omitted_ref = "include:\n  - project: org/shared-ci\n    file: /ci.yml\n"
    pinned_ref = (
        "include:\n"
        "  - project: org/shared-ci\n"
        "    ref: abc123def456abc123def456abc123def456abc1\n"
        "    file: /ci.yml\n"
    )

    (finding,) = _findings(tmp_path, "SEC8-GL-002", omitted_ref)

    assert finding.severity == Severity.HIGH
    assert _findings(tmp_path, "SEC8-GL-002", pinned_ref) == []
