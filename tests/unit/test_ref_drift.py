"""Mutable-ref-repoint detector (SEC3-GH-T02) — the tj-actions/changed-files
CVE-2025-30066 class.

The attack: a workflow pins ``uses: owner/repo@<mutable-tag>``; the attacker
repoints the tag to a malicious commit; the local YAML never changes. The static
rules (SEC3-GH-001/003) only flag *latent* mutable-ref usage; this detector fires
on the *active-compromise moment* — same ref, resolved upstream SHA changed, no
local change.

Exercised via the resolver override so no test touches the network. Two scans
(T1 ``--baseline``, T2 ``--diff``) are simulated as separate runs by resetting
the process-lifetime cache between them.
"""

from __future__ import annotations

import pytest

from taintly import baseline as B
from taintly.__main__ import _build_drift_findings, _resolve_current_refs
from taintly.models import Finding, Severity
from taintly.platform import github_ref_resolve as R

SHA_A = "a" * 40
SHA_B = "b" * 40


def _finding(snippet: str) -> Finding:
    # Shaped like the static SEC3 finding the detector sources refs from.
    return Finding(
        rule_id="SEC3-GH-001",
        severity=Severity.HIGH,
        title="unpinned action",
        description="d",
        file="wf.yml",
        line=7,
        snippet=snippet,
    )


@pytest.fixture(autouse=True)
def _drift_env():
    R.set_enabled(True)
    R.reset_cache()
    yield
    R.set_resolver_override(None)
    R.reset_cache()
    R.set_enabled(False)


def test_mutable_ref_repoint_fires_critical(tmp_path):
    findings = [_finding("uses: tj-actions/changed-files@v44")]
    # T1: v44 -> SHA_A, save baseline.
    R.set_resolver_override(lambda o, r, ref: SHA_A)
    bpath = str(tmp_path / "bl.json")
    bl = B.save_baseline(findings, str(tmp_path), bpath, _resolve_current_refs(findings))
    assert bl.resolved_refs == {"tj-actions/changed-files@v44": SHA_A}

    # T2: identical YAML, v44 now -> SHA_B (the repoint). Separate run: reset cache.
    R.reset_cache()
    R.set_resolver_override(lambda o, r, ref: SHA_B)
    loaded = B.load_baseline(bpath)
    assert loaded.resolved_refs == {"tj-actions/changed-files@v44": SHA_A}
    drift = B.detect_ref_drift(_resolve_current_refs(findings), loaded.resolved_refs)
    assert drift == [("tj-actions/changed-files@v44", SHA_A, SHA_B)]

    out = _build_drift_findings(drift, findings)
    assert len(out) == 1
    assert out[0].rule_id == "SEC3-GH-T02"
    assert out[0].severity is Severity.CRITICAL
    assert out[0].line == 7  # anchored to the source uses: line
    assert "CVE-2025-30066" in out[0].description


def test_sha_pinned_ref_is_never_tracked(tmp_path):
    # A SHA-pinned uses: cannot drift -> excluded from resolution (0-FP control).
    findings = [_finding("uses: actions/checkout@" + "c" * 40)]
    R.set_resolver_override(lambda o, r, ref: SHA_B)
    assert _resolve_current_refs(findings) == {}


def test_unchanged_resolution_no_drift(tmp_path):
    findings = [_finding("uses: tj-actions/changed-files@v44")]
    R.set_resolver_override(lambda o, r, ref: SHA_A)
    bpath = str(tmp_path / "bl.json")
    B.save_baseline(findings, str(tmp_path), bpath, _resolve_current_refs(findings))
    R.reset_cache()  # same SHA again on the next run
    loaded = B.load_baseline(bpath)
    assert B.detect_ref_drift(_resolve_current_refs(findings), loaded.resolved_refs) == []


def test_cold_start_no_prior_resolution_no_finding():
    # No prior resolved_refs (cold start / old baseline) -> nothing to compare.
    findings = [_finding("uses: tj-actions/changed-files@v44")]
    R.set_resolver_override(lambda o, r, ref: SHA_B)
    assert B.detect_ref_drift(_resolve_current_refs(findings), {}) == []


def test_disabled_resolves_nothing_no_network():
    findings = [_finding("uses: tj-actions/changed-files@v44")]
    R.set_enabled(False)
    R.set_resolver_override(lambda o, r, ref: SHA_B)  # would resolve — but disabled
    assert _resolve_current_refs(findings) == {}
