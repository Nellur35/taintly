"""Regression controls for the rule-confidence default and its consumers.

These use inert synthetic patterns so they exercise the real per-file and
corpus finding constructors without depending on a production detector.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from taintly.engine import scan_file, scan_repo
from taintly.families import _CONFIDENCE_OVERRIDES, _GRANDFATHERED_HIGH
from taintly.gitlab_workflow_corpus import GitLabCorpusPattern
from taintly.models import Platform, RegexPattern, Rule, Severity
from taintly.workflow_corpus import CorpusPattern


_ROOT = Path(__file__).resolve().parents[2]
_ADVISORY = _ROOT / "scripts" / "check_confidence_grandfather.py"


def _rule(
    rule_id: str,
    *,
    platform: Platform = Platform.GITHUB,
    pattern=None,
    **kwargs,
) -> Rule:
    return Rule(
        id=rule_id,
        title="Synthetic confidence control",
        severity=Severity.HIGH,
        platform=platform,
        owasp_cicd="CICD-SEC-4",
        description="Inert test-only rule.",
        pattern=pattern or RegexPattern(r"CONFIDENCE_CONTROL"),
        remediation="",
        reference="",
        **kwargs,
    )


def _scan_file_confidence(rule: Rule) -> tuple[str, bool]:
    findings = scan_file(".github/workflows/control.yml", [rule], _content="CONFIDENCE_CONTROL\n")
    (finding,) = [finding for finding in findings if finding.rule_id == rule.id]
    return finding.confidence, finding.review_needed


def _scan_corpus_confidence(tmp_path: Path, platform: Platform, rule_id: str, **kwargs) -> str:
    tmp_path.mkdir(parents=True, exist_ok=True)
    if platform is Platform.GITHUB:
        workflow = tmp_path / ".github" / "workflows" / "control.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: control\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n", encoding="utf-8")

        def emit(corpus):
            (summary,) = corpus.all()
            return [(summary.filepath, 1, "synthetic corpus evidence")]

        pattern = CorpusPattern(emit)
    else:
        workflow = tmp_path / ".gitlab-ci.yml"
        workflow.write_text("test:\n  script: echo ok\n", encoding="utf-8")

        def emit(corpus):
            (summary,) = corpus.all()
            return [(summary.filepath, 1, "synthetic corpus evidence")]

        pattern = GitLabCorpusPattern(emit)

    rule = _rule(rule_id, platform=platform, pattern=pattern, **kwargs)
    reports = scan_repo(str(tmp_path), [rule], platform=platform)
    (finding,) = [finding for report in reports for finding in report.findings if finding.rule_id == rule.id]
    assert finding.origin == "cross-workflow"
    return finding.confidence


def test_omitted_confidence_defaults_medium_in_scan_file_with_review_state():
    rule = _rule("TD029-UNKNOWN-FILE-OMITTED")

    assert rule.confidence == ""
    assert _scan_file_confidence(rule) == ("medium", False)


@pytest.mark.parametrize("confidence", ["high", "medium", "low"])
def test_explicit_confidence_is_preserved_by_scan_file(confidence: str):
    rule = _rule(f"TD029-EXPLICIT-{confidence.upper()}", confidence=confidence)

    assert _scan_file_confidence(rule) == (confidence, False)


def test_legacy_empty_confidence_uses_medium_fallback_in_scan_file():
    rule = _rule("TD029-UNKNOWN-EMPTY-FALLBACK", confidence="")

    assert _scan_file_confidence(rule)[0] == "medium"


def test_empty_confidence_uses_grandfather_and_override_fallbacks_in_scan_file():
    (grandfathered_id,) = sorted(_GRANDFATHERED_HIGH)[:1]
    override_id = next(iter(_CONFIDENCE_OVERRIDES))

    assert _scan_file_confidence(_rule(grandfathered_id, confidence=""))[0] == "high"
    assert _scan_file_confidence(_rule(override_id, confidence=""))[0] == _CONFIDENCE_OVERRIDES[override_id]


@pytest.mark.parametrize("platform", [Platform.GITHUB, Platform.GITLAB])
def test_omitted_confidence_defaults_medium_through_real_corpus_finding_paths(
    tmp_path: Path, platform: Platform
):
    assert _scan_corpus_confidence(tmp_path, platform, f"TD029-{platform.value.upper()}-OMITTED") == "medium"


@pytest.mark.parametrize("platform", [Platform.GITHUB, Platform.GITLAB])
@pytest.mark.parametrize("confidence", ["high", "medium", "low"])
def test_corpus_paths_preserve_explicit_confidence(
    tmp_path: Path, platform: Platform, confidence: str
):
    assert (
        _scan_corpus_confidence(
            tmp_path,
            platform,
            f"TD029-{platform.value.upper()}-EXPLICIT-{confidence.upper()}",
            confidence=confidence,
        )
        == confidence
    )


def test_corpus_paths_apply_empty_unknown_and_grandfather_fallbacks(tmp_path: Path):
    (grandfathered_id,) = sorted(_GRANDFATHERED_HIGH)[:1]
    override_id = next(iter(_CONFIDENCE_OVERRIDES))

    assert _scan_corpus_confidence(tmp_path / "unknown", Platform.GITHUB, "TD029-GH-EMPTY", confidence="") == "medium"
    assert _scan_corpus_confidence(tmp_path / "grandfather", Platform.GITHUB, grandfathered_id, confidence="") == "high"
    assert (
        _scan_corpus_confidence(
            tmp_path / "override", Platform.GITLAB, override_id, confidence=""
        )
        == _CONFIDENCE_OVERRIDES[override_id]
    )


def test_advisory_flags_omitted_and_empty_but_not_explicit_high(monkeypatch, capsys):
    spec = importlib.util.spec_from_file_location("_td029_confidence_advisory", _ADVISORY)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    omitted = _rule("TD029-ADVISORY-OMITTED")
    empty = _rule("TD029-ADVISORY-EMPTY", confidence="")
    explicit_high = _rule("TD029-ADVISORY-EXPLICIT-HIGH", confidence="high")

    from taintly.rules import registry

    monkeypatch.setattr(module, "_load_baseline", lambda: [])
    monkeypatch.setattr(registry, "load_all_rules", lambda: [omitted, empty, explicit_high])

    assert module._unvalidated_new_rules() == ["TD029-ADVISORY-EMPTY", "TD029-ADVISORY-OMITTED"]
    assert module.main([]) == 0
    output = capsys.readouterr().out
    assert "TD029-ADVISORY-OMITTED" in output
    assert "TD029-ADVISORY-EMPTY" in output
    assert "TD029-ADVISORY-EXPLICIT-HIGH" not in output
