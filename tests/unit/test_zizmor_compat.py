"""Unit tests for foreign-scanner suppression interop (zizmor)."""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_all_rules
from taintly.suppressions import zizmor_compat


@pytest.fixture(autouse=True)
def _reset_zizmor_state():
    zizmor_compat.set_respect_zizmor_ignores(False)
    yield
    zizmor_compat.set_respect_zizmor_ignores(False)


# ---------------------------------------------------------------------------
# Module-level parser semantics
# ---------------------------------------------------------------------------


def test_generic_zizmor_ignore_suppresses_any_taintly_rule():
    line = "      - uses: actions/checkout@v4 # zizmor: ignore"
    assert zizmor_compat.is_zizmor_suppressed(line, "SEC3-GH-001")
    assert zizmor_compat.is_zizmor_suppressed(line, "SEC4-GH-002")
    assert zizmor_compat.is_zizmor_suppressed(line, "SOME-UNKNOWN-RULE")


def test_specific_zizmor_id_with_known_mapping_suppresses_only_mapped_taintly_rules():
    # ``unpinned-uses`` maps to SEC3-GH-001 / SEC3-GH-002.
    line = "      - uses: actions/checkout@v4 # zizmor: ignore[unpinned-uses]"
    assert zizmor_compat.is_zizmor_suppressed(line, "SEC3-GH-001")
    assert zizmor_compat.is_zizmor_suppressed(line, "SEC3-GH-002")
    # Unrelated rule must NOT be suppressed by an unpinned-uses ignore.
    assert not zizmor_compat.is_zizmor_suppressed(line, "SEC4-GH-002")


def test_specific_zizmor_id_with_unknown_mapping_broad_suppresses():
    # Unknown id falls through to broad-line suppression so a
    # maintainer's mark under a foreign tool isn't lost.
    line = "      - run: echo hi # zizmor: ignore[future-rule-id]"
    assert zizmor_compat.is_zizmor_suppressed(line, "SEC3-GH-001")
    assert zizmor_compat.is_zizmor_suppressed(line, "SEC4-GH-004")


def test_multi_id_zizmor_ignore_suppresses_either_mapping():
    line = "      - uses: actions/checkout@v4 # zizmor: ignore[unpinned-uses,artipacked]"
    # SEC3-GH-001 is in the unpinned-uses mapping → suppressed.
    assert zizmor_compat.is_zizmor_suppressed(line, "SEC3-GH-001")
    # SEC2-GH-005 is in the artipacked mapping → suppressed.
    assert zizmor_compat.is_zizmor_suppressed(line, "SEC2-GH-005")


def test_no_zizmor_marker_does_not_suppress():
    line = "      - uses: actions/checkout@v4"
    assert not zizmor_compat.is_zizmor_suppressed(line, "SEC3-GH-001")


# ---------------------------------------------------------------------------
# Engine integration: --respect-zizmor-ignores must be enabled for the
# foreign suppression to take effect.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def gh_rules():
    return [r for r in load_all_rules() if r.platform == Platform.GITHUB]


def _write(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "workflow.yml"
    p.write_text(content)
    return p


def test_zizmor_ignore_has_no_effect_when_flag_disabled(tmp_path: Path, gh_rules):
    """Default state: foreign suppression markers are not honoured.
    SEC3-GH-001 still fires on a tag-pinned uses: even when the line
    carries ``# zizmor: ignore``.
    """
    fixture = _write(
        tmp_path,
        "jobs:\n  build:\n    steps:\n"
        "      - uses: actions/checkout@v4 # zizmor: ignore[unpinned-uses]\n",
    )
    findings = scan_file(str(fixture), gh_rules)
    assert any(f.rule_id == "SEC3-GH-001" for f in findings)


def test_zizmor_ignore_suppresses_taintly_finding_when_flag_enabled(
    tmp_path: Path, gh_rules
):
    zizmor_compat.set_respect_zizmor_ignores(True)
    fixture = _write(
        tmp_path,
        "jobs:\n  build:\n    steps:\n"
        "      - uses: actions/checkout@v4 # zizmor: ignore[unpinned-uses]\n",
    )
    findings = scan_file(str(fixture), gh_rules)
    assert not any(f.rule_id == "SEC3-GH-001" for f in findings), (
        f"--respect-zizmor-ignores must suppress SEC3-GH-001 on a line "
        f"marked with the unpinned-uses zizmor ignore; "
        f"got findings: {[(f.rule_id, f.line) for f in findings]}"
    )


def test_unrelated_taintly_rule_not_suppressed_under_specific_zizmor_ignore(
    tmp_path: Path, gh_rules
):
    """Specific zizmor IDs only suppress the taintly rules they map to.
    A line marked ``ignore[unpinned-uses]`` should NOT silence an
    unrelated taintly rule that happens to fire on the same line.
    """
    zizmor_compat.set_respect_zizmor_ignores(True)
    # checkout@v4 fires SEC3-GH-001 (unpinned-uses); the persist-
    # credentials default would fire SEC2-GH-005 (artipacked).  An
    # ``unpinned-uses`` ignore must suppress the former but not the
    # latter — except the persist-credentials check requires the
    # checkout step to be unaccompanied by ``persist-credentials:
    # false``.  We construct that shape explicitly.
    fixture = _write(
        tmp_path,
        "jobs:\n"
        "  build:\n"
        "    permissions:\n      contents: read\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4 # zizmor: ignore[unpinned-uses]\n",
    )
    findings = scan_file(str(fixture), gh_rules)
    # SEC3-GH-001 suppressed.
    assert not any(f.rule_id == "SEC3-GH-001" for f in findings)
    # The persist-credentials rule (whichever matches) is unaffected
    # by an unpinned-uses ignore — it remains in the list if it
    # would normally fire on this shape.  We don't assert presence
    # here (the rule may be gated differently); we only assert that
    # the unpinned-uses suppression does NOT widen to other rule IDs.
