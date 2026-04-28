"""Unit tests for baseline snapshot + diff.

Covers the round-trip (save → load → identical), fingerprint stability
under line-number shifts, version validation, and the diff contract.
"""

from __future__ import annotations

import json

import pytest

from taintly.baseline import (
    BASELINE_VERSION,
    BaselineError,
    apply_diff,
    classify_diff_kind,
    fingerprint,
    format_baseline_summary,
    format_diff_summary,
    load_baseline,
    save_baseline,
)
from taintly.models import Finding, Severity


def _finding(rule_id="SEC4-GH-001", file="a.yml", line=1, snippet="x"):
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        title="t",
        description="d",
        file=file,
        line=line,
        snippet=snippet,
        remediation="",
        reference="",
        owasp_cicd="CICD-SEC-4",
    )


def test_fingerprint_is_stable_across_line_shifts(tmp_path):
    """Fingerprint excludes line number — a finding that moves to a
    different line must still match the original fingerprint.
    """
    a = _finding(line=1, snippet="uses: actions/checkout@v4")
    b = _finding(line=42, snippet="uses: actions/checkout@v4")
    assert fingerprint(a, str(tmp_path)) == fingerprint(b, str(tmp_path))


def test_fingerprint_differs_by_rule_id(tmp_path):
    a = _finding(rule_id="SEC4-GH-001", snippet="x")
    b = _finding(rule_id="SEC4-GH-004", snippet="x")
    assert fingerprint(a, str(tmp_path)) != fingerprint(b, str(tmp_path))


def test_save_then_load_round_trips(tmp_path):
    findings = [_finding(snippet=f"snippet-{i}") for i in range(3)]
    path = str(tmp_path / "baseline.json")

    saved = save_baseline(findings, str(tmp_path), path)
    loaded = load_baseline(path)

    assert loaded.version == BASELINE_VERSION
    assert loaded.fingerprints == saved.fingerprints
    assert loaded.finding_count == 3


def test_load_baseline_rejects_wrong_version(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"version": 999, "fingerprints": []}))
    with pytest.raises(BaselineError, match="version"):
        load_baseline(str(path))


def test_load_baseline_rejects_malformed_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not valid json")
    with pytest.raises(BaselineError, match="not valid JSON"):
        load_baseline(str(path))


def test_load_baseline_rejects_non_object(tmp_path):
    path = tmp_path / "arr.json"
    path.write_text("[]")
    with pytest.raises(BaselineError, match="JSON object"):
        load_baseline(str(path))


def test_load_baseline_rejects_bad_fingerprint_shape(tmp_path):
    path = tmp_path / "bad-fps.json"
    path.write_text(
        json.dumps({"version": BASELINE_VERSION, "fingerprints": ["not-a-sha"]})
    )
    with pytest.raises(BaselineError, match="sha256"):
        load_baseline(str(path))


def test_load_baseline_rejects_oversized(tmp_path):
    path = tmp_path / "big.json"
    # 11 MB of zeros — above the 10 MB cap.
    path.write_bytes(b"0" * (11 * 1024 * 1024))
    with pytest.raises(BaselineError, match="large"):
        load_baseline(str(path))


def test_apply_diff_keeps_only_new_findings(tmp_path):
    existing = _finding(snippet="known")
    baseline_path = str(tmp_path / "b.json")
    save_baseline([existing], str(tmp_path), baseline_path)

    loaded = load_baseline(baseline_path)
    new_finding = _finding(snippet="novel")
    filtered, suppressed = apply_diff([existing, new_finding], loaded, str(tmp_path))

    assert [f.snippet for f in filtered] == ["novel"]
    assert suppressed == 1


def test_format_baseline_summary_mentions_count(tmp_path):
    saved = save_baseline([_finding(), _finding(snippet="b")], str(tmp_path),
                          str(tmp_path / "b.json"))
    out = format_baseline_summary(saved, str(tmp_path / "b.json"))
    assert "2 finding" in out


def test_format_diff_summary_reports_new_and_suppressed():
    out = format_diff_summary(suppressed=7, new_count=3, baseline_path="b.json")
    assert "3" in out
    assert "7" in out


def test_format_diff_summary_empty_case():
    out = format_diff_summary(suppressed=0, new_count=0, baseline_path="b.json")
    assert "no findings" in out


# =============================================================================
# classify_diff_kind — SHA churn vs. new dependency vs. new finding
# =============================================================================


def test_classify_diff_kind_sha_bump():
    """A finding whose snippet differs only in the SHA should be classified
    as sha_bump, not new_finding."""
    old = Finding(
        rule_id="SEC3-GH-006",
        severity=Severity.INFO,
        title="t",
        description="d",
        file="/r/.github/workflows/x.yml",
        line=10,
        snippet="- uses: cloudflare/wrangler-action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    new = Finding(
        rule_id="SEC3-GH-006",
        severity=Severity.INFO,
        title="t",
        description="d",
        file="/r/.github/workflows/x.yml",
        line=10,
        snippet="- uses: cloudflare/wrangler-action@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    baseline_fps = {fingerprint(old, "/r")}
    snippets = {fingerprint(old, "/r"): old.snippet}
    assert classify_diff_kind(new, baseline_fps, snippets, "/r") == "sha_bump"


def test_classify_diff_kind_new_dependency():
    old = Finding(
        rule_id="SEC3-GH-006",
        severity=Severity.INFO,
        title="t",
        description="d",
        file="/r/.github/workflows/x.yml",
        line=10,
        snippet="- uses: cloudflare/wrangler-action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    new = Finding(
        rule_id="SEC3-GH-006",
        severity=Severity.INFO,
        title="t",
        description="d",
        file="/r/.github/workflows/x.yml",
        line=10,
        snippet="- uses: docker/build-push-action@cccccccccccccccccccccccccccccccccccccccc",
    )
    baseline_fps = {fingerprint(old, "/r")}
    snippets = {fingerprint(old, "/r"): old.snippet}
    assert classify_diff_kind(new, baseline_fps, snippets, "/r") == "new_dependency"


def test_classify_diff_kind_unchanged_returns_unchanged():
    """Documented contract: a fingerprint that's still in baseline is
    classified ``unchanged``.  Caller should normally filter these out
    via apply_diff before invoking the classifier."""
    f = Finding(
        rule_id="SEC3-GH-001",
        severity=Severity.HIGH,
        title="t",
        description="d",
        file="/r/.github/workflows/x.yml",
        line=10,
        snippet="- uses: actions/checkout@v4",
    )
    fp = fingerprint(f, "/r")
    assert classify_diff_kind(f, {fp}, {fp: f.snippet}, "/r") == "unchanged"


def test_classify_diff_kind_no_uses_in_snippet():
    """A finding without a ``uses:`` shape can't be a SHA bump; it falls
    through to ``new_finding`` regardless of baseline contents."""
    f = Finding(
        rule_id="SEC2-GH-002",
        severity=Severity.MEDIUM,
        title="t",
        description="d",
        file="/r/.github/workflows/x.yml",
        line=3,
        snippet="permissions: write-all",
    )
    assert classify_diff_kind(f, set(), {}, "/r") == "new_finding"


def test_baseline_round_trip_persists_snippets(tmp_path):
    """save_baseline -> load_baseline must preserve the snippets map
    so SHA-bump classification survives a CI cold start."""
    f = Finding(
        rule_id="SEC3-GH-006",
        severity=Severity.INFO,
        title="t",
        description="d",
        file=str(tmp_path / "wf.yml"),
        line=1,
        snippet="- uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    out = tmp_path / "baseline.json"
    save_baseline([f], str(tmp_path), str(out))
    loaded = load_baseline(str(out))
    assert loaded.snippets, "snippets map dropped on round-trip"
    assert any("actions/checkout" in s for s in loaded.snippets.values())
