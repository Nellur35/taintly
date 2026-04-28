"""Tests for taintly.advisories — version parsing, range matching, bundled loader."""

from __future__ import annotations

import pytest

from taintly.advisories import (
    Advisory,
    _matches_range,
    _override_for_tests,
    _parse_ref,
    _reset_cache,
    find_advisories_for,
    load_bundled_advisories,
)


class TestParseRef:
    """Reference parser: maps v1 / v1.2 / v1.2.3 / 1.2.3 to (major, minor, patch)."""

    @pytest.mark.parametrize(
        ("ref", "expected"),
        [
            ("v1", (1, 0, 0)),
            ("v1.2", (1, 2, 0)),
            ("v1.2.3", (1, 2, 3)),
            ("1", (1, 0, 0)),
            ("1.2", (1, 2, 0)),
            ("1.2.3", (1, 2, 3)),
            # Suffixes — pre-release / metadata — keep numeric prefix.
            ("v1.2.3-beta", (1, 2, 3)),
            ("v1.2.3-rc.1", (1, 2, 3)),
            ("v1.2.3+build", (1, 2, 3)),
        ],
    )
    def test_parses_semver(self, ref, expected):
        assert _parse_ref(ref) == expected

    @pytest.mark.parametrize(
        "ref",
        [
            "main",
            "master",
            "develop",
            # 40-char SHA
            "a3b5c8d9e0f1234567890abcdef0123456789abcd",
            # short SHA
            "a3b5c8d",
            # empty / nonsense
            "",
            "not-a-version",
            "@@@",
        ],
    )
    def test_rejects_non_semver(self, ref):
        assert _parse_ref(ref) is None


class TestMatchesRange:
    """Version-range expressions used by GHSA: <=, <, >=, >, ==, comma-AND."""

    def test_le_inclusive(self):
        assert _matches_range("v45.0.7", "<= 45.0.7") is True
        assert _matches_range("v45.0.6", "<= 45.0.7") is True
        assert _matches_range("v45.0.8", "<= 45.0.7") is False

    def test_lt_exclusive(self):
        assert _matches_range("v40", "< 41") is True
        assert _matches_range("v41", "< 41") is False

    def test_compound_and(self):
        rng = ">= 0.31.0, < 0.34.0"
        assert _matches_range("v0.30.9", rng) is False
        assert _matches_range("v0.31.0", rng) is True
        assert _matches_range("v0.32.5", rng) is True
        assert _matches_range("v0.34.0", rng) is False

    def test_eq_major_only(self):
        # '== 1' matches the v1 line — both v1 and v1.0.0 are
        # semantically the same git tag and both satisfy.
        assert _matches_range("v1", "== 1") is True
        assert _matches_range("v1.0.0", "== 1") is True
        assert _matches_range("v2", "== 1") is False

    def test_unparseable_ref_does_not_match(self):
        # Branch refs and SHAs are conservatively treated as
        # "unknown" — never fire.  Other rules cover those shapes.
        assert _matches_range("main", "<= 45.0.7") is False
        assert _matches_range("a3b5c8d9e0f1234567890abcdef0123456789abcd", "<= 45.0.7") is False


class TestBundledLoader:
    """The bundled JSON file ships with the package and parses cleanly."""

    def setup_method(self):
        _reset_cache()

    def teardown_method(self):
        _reset_cache()

    def test_bundled_list_loads(self):
        advs = load_bundled_advisories()
        assert len(advs) >= 1
        for a in advs:
            assert a.ghsa.startswith("GHSA-")
            assert a.package
            assert a.affected
            assert a.severity in {"critical", "high", "medium", "low"}

    def test_bundled_includes_known_incidents(self):
        advs = load_bundled_advisories()
        ghsa_ids = {a.ghsa for a in advs}
        # tj-actions Mar 2025 supply chain compromise.
        assert "GHSA-mrrh-fwg8-r2c3" in ghsa_ids
        # Trivy supply chain.
        assert "GHSA-69fq-xp46-6x23" in ghsa_ids

    def test_caching_returns_same_list(self):
        first = load_bundled_advisories()
        second = load_bundled_advisories()
        assert first is second  # cache returns the same object


class TestFindAdvisoriesFor:
    """The convenience lookup used by the rule pattern."""

    def setup_method(self):
        _reset_cache()
        _override_for_tests(
            [
                Advisory(
                    ghsa="GHSA-test-1",
                    cve="CVE-2025-0001",
                    package="example/action",
                    severity="high",
                    summary="test",
                    affected="<= 1.0.0",
                    fixed="1.0.1",
                    discovered="2025-01-01",
                ),
            ]
        )

    def teardown_method(self):
        _reset_cache()

    def test_match_in_range(self):
        hits = find_advisories_for("example/action", "v1.0.0")
        assert len(hits) == 1
        assert hits[0].ghsa == "GHSA-test-1"

    def test_no_match_for_patched_version(self):
        assert find_advisories_for("example/action", "v1.0.1") == []

    def test_no_match_for_unrelated_package(self):
        assert find_advisories_for("other/action", "v1.0.0") == []

    def test_no_match_for_branch_ref(self):
        # main is unparseable — conservative non-match.
        assert find_advisories_for("example/action", "main") == []
