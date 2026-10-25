"""Authored GitLab artifact semantics; not real-world accuracy evidence."""

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.models import IncompletePatternMatches, Platform
from taintly.rules.gitlab.sec1_sec4_sec6_sec7_sec9 import HighRiskArtifactAccessPattern
from taintly.rules.registry import load_rules_for_platform

_CASES = {
    "block": "build:\n  script: make\n  artifacts:\n    paths:\n      - .env\n",
    "flow": "build:\n  script: make\n  artifacts: {paths: [.env]}\n",
    "quoted-key": 'build:\n  script: make\n  "artifacts":\n    paths:\n      - .env\n',
    "script-text": "build:\n  script: |\n    cat > example.yml <<'EOF'\n    artifacts:\n      paths:\n        - .env\n    EOF\n",
}


@pytest.mark.parametrize("case", _CASES)
def test_artifact_declaration_follows_structure_at_detector_and_product_boundaries(
    tmp_path: Path, case: str
) -> None:
    source = _CASES[case]
    expected = case != "script-text"
    detector = HighRiskArtifactAccessPattern().check(source, source.splitlines())
    assert bool(detector) is expected

    (tmp_path / ".gitlab-ci.yml").write_text(source, encoding="utf8")
    reports = scan_repo(str(tmp_path), load_rules_for_platform(Platform.GITLAB), Platform.GITLAB)
    assert len(reports) == 1
    target = [f for f in reports[0].findings if f.rule_id == "SEC9-GL-001"]
    assert bool(target) is expected
    if target:
        assert target[0].review_needed
        assert target[0].line == 3


@pytest.mark.parametrize(
    "source",
    [
        "build:\n  script: make\n  artifacts: {paths: [.env], access: developer}\n",
        'build:\n  script: make\n  "artifacts":\n    public: false\n    paths: [.env]\n',
        "build:\n  script: make\n  artifacts:\n    paths: [dist/]\nother:\n  script: make\n  artifacts:\n    paths: [.env]\n    access: none\n",
    ],
)
def test_restrictive_setting_must_belong_to_selected_artifact_mapping(source: str) -> None:
    assert not HighRiskArtifactAccessPattern().check(source, source.splitlines())


def test_sibling_access_does_not_restrict_high_risk_job() -> None:
    source = (
        "build:\n  script: make\n  artifacts: {paths: [.env]}\n"
        "other:\n  script: make\n  artifacts: {paths: [dist/], access: none}\n"
    )
    matches = HighRiskArtifactAccessPattern().check(source, source.splitlines())
    assert len(matches) == 1
    assert matches[0][0] == 3


def test_duplicate_artifact_mapping_stays_unresolved() -> None:
    source = (
        "build:\n  script: make\n  artifacts:\n    paths: [.env]\n"
        "  artifacts:\n    access: developer\n    paths: [dist/]\n"
    )
    outcome = HighRiskArtifactAccessPattern().check(source, source.splitlines())
    assert isinstance(outcome, IncompletePatternMatches)
    assert not outcome


def test_conflicting_access_values_stay_unresolved() -> None:
    source = (
        "build:\n  script: make\n  artifacts:\n    paths: [.env]\n"
        "    access: developer\n    access: all\n"
    )
    outcome = HighRiskArtifactAccessPattern().check(source, source.splitlines())
    assert isinstance(outcome, IncompletePatternMatches)
    assert not outcome


def test_duplicate_paths_do_not_choose_one_effective_artifact_value() -> None:
    source = "build:\n  script: make\n  artifacts:\n    paths: [.env]\n    paths: [dist/]\n"
    outcome = HighRiskArtifactAccessPattern().check(source, source.splitlines())
    assert isinstance(outcome, IncompletePatternMatches)
    assert not outcome


def test_unsupported_structure_before_artifact_is_not_reported_as_complete(
    tmp_path: Path,
) -> None:
    source = "build:\n  script: make\n%YAML 1.2\n  artifacts:\n    paths: [.env]\n"
    (tmp_path / ".gitlab-ci.yml").write_text(source, encoding="utf8")
    report = scan_repo(str(tmp_path), load_rules_for_platform(Platform.GITLAB), Platform.GITLAB)[0]
    assert report.semantic_coverage_status() == "incomplete"
    assert any(f.rule_id == "ENGINE-ERR" for f in report.findings)
