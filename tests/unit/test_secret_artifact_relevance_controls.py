"""Portable direct-pattern contracts for the source-reviewed SEC6-GH-016 cases."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from taintly.models import IncompletePatternMatches
from taintly.rules.github.secret_artifact_flow import SecretArtifactFlowPattern

_FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "secret_artifact_relevance"
_MANIFEST = json.loads((_FIXTURE_ROOT / "manifest.json").read_text(encoding="utf-8"))
_EXPECTED_RETAINED_HIT = (
    15,
    r"""printf 'credential=%s\n' "$REPORT_TOKEN" > reports/build.txt [literal artifact path at line 20]""",
)


class SecretArtifactRelevanceControls(unittest.TestCase):
    def test_source_reviewed_relevance_controls(self) -> None:
        pattern = SecretArtifactFlowPattern()
        assert len(_MANIFEST["cases"]) == 21
        for case in _MANIFEST["cases"]:
            with self.subTest(case_id=case["case_id"]):
                raw = (_FIXTURE_ROOT / case["fixture"]).read_bytes()
                assert b"\r" not in raw.replace(b"\r\n", b"")
                canonical = raw.replace(b"\r\n", b"\n")
                assert hashlib.sha256(canonical).hexdigest() == case["canonical_lf_sha256"]
                content = canonical.decode("utf-8")
                result = pattern.check(content, content.splitlines())
                expected = case["expected"]
                if expected == "complete_no_named_finding":
                    assert not isinstance(result, IncompletePatternMatches)
                    assert list(result) == []
                elif expected == "confirmed_candidate":
                    assert not isinstance(result, IncompletePatternMatches)
                    assert len(result) == 1
                    if case["case_id"] == "R01-ordered-direct-secret-write":
                        assert list(result) == [_EXPECTED_RETAINED_HIT]
                elif expected == "incomplete_unknown_no_confirmed_finding":
                    assert isinstance(result, IncompletePatternMatches)
                    assert result.reason
                    assert list(result) == []
                elif expected == "incomplete_unknown_with_independent_finding":
                    assert isinstance(result, IncompletePatternMatches)
                    assert result.reason
                    assert case["case_id"] == "R10-mixed-valid-and-unknown-jobs"
                    assert list(result) == [_EXPECTED_RETAINED_HIT]
                else:
                    raise AssertionError(
                        f"unrecognized expected result for {case['case_id']}: {expected}"
                    )
