"""composition_tags routing split + family-coverage gate (R5/P3.1a).

These pin the decoupling of composer ROUTING from the reporting
``finding_family`` field:

* the composer pass selects rules by ``Rule.composition_tags`` membership,
  not by ``finding_family == "chain-composition"``;
* every shipped composer rule (CHAIN-GH-1xx) is tagged "chain-composition";
* non-composer rules carry an empty ``composition_tags`` (the field default),
  so they stay in the per-file / non-composer pass;
* an emitted composer finding still fires end-to-end and carries the tag onto
  the Finding, so post-composition steps can identify composer output without
  reading the reporting family;
* the family-coverage visibility gate matches its committed baseline and
  blocks a newly-introduced unmarked rule.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_all_rules

ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Rule-model tagging
# ---------------------------------------------------------------------------


def test_composer_rules_are_tagged() -> None:
    """The CHAIN-GH-1xx composer family carries the routing tag."""
    rules = load_all_rules()
    tagged = {r.id for r in rules if "chain-composition" in r.composition_tags}
    assert tagged == {
        "CHAIN-GH-101",
        "CHAIN-GH-102",
        "CHAIN-GH-103",
        "CHAIN-GH-104",
        "CHAIN-GH-105",
    }


def test_non_composer_rules_have_empty_composition_tags() -> None:
    """The field defaults empty for every non-composer rule."""
    rules = load_all_rules()
    tagged = {r.id for r in rules if r.composition_tags}
    # Only the composer family is tagged; everything else is the default
    # empty frozenset.
    assert tagged == {
        "CHAIN-GH-101",
        "CHAIN-GH-102",
        "CHAIN-GH-103",
        "CHAIN-GH-104",
        "CHAIN-GH-105",
    }
    # Public-repo divergence note: the lab pack also ships CHAIN-GH-001 (a
    # per-file ContextPattern) which must stay untagged; that rule is not in
    # the public curated subset, so it is not asserted here.  The public pack
    # DOES ship the GitLab CHAIN-GL-1xx composer rules — those route through
    # the dedicated GitLabCorpusPattern pass (``_run_gitlab_corpus_rules``),
    # NOT the GitHub ``composition_tags`` predicate, so they must stay untagged
    # (empty composition_tags) or they'd be mis-pulled into the GH composer
    # pass.  Pin that here so the GL composer routing can't silently change.
    for r in rules:
        if r.id.startswith("CHAIN-GL-"):
            assert r.composition_tags == frozenset(), (
                f"{r.id} is a GitLab composer rule routed via "
                "GitLabCorpusPattern; it must NOT carry the GitHub "
                "chain-composition routing tag"
            )


def test_routing_is_decoupled_from_reporting_family() -> None:
    """Renaming the reporting family must not change composer routing.

    Mutate a composer rule's ``finding_family`` to a bogus value and
    confirm it is still selected by ``composition_tags`` membership (the
    routing predicate the engine uses).
    """
    rules = load_all_rules()
    rule = next(r for r in rules if r.id == "CHAIN-GH-101")
    rule.finding_family = "renamed_for_reporting"
    # Engine routing predicate (engine.py _run_corpus_rules):
    assert "chain-composition" in rule.composition_tags
    # And the reporting family is independent.
    assert rule.finding_family == "renamed_for_reporting"


# ---------------------------------------------------------------------------
# End-to-end: a composer rule still fires and tags its finding
# ---------------------------------------------------------------------------

_CHAIN_105_POSITIVE = (
    "on: pull_request_target\n"
    "jobs:\n"
    "  produce:\n"
    "    runs-on: ubuntu-latest\n"
    "    permissions:\n"
    "      contents: read\n"
    "    outputs:\n"
    "      val: ${{ steps.s.outputs.v }}\n"
    "    steps:\n"
    "      - id: s\n"
    '        run: echo "v=hi" >> $GITHUB_OUTPUT\n'
    "  consume:\n"
    "    needs: produce\n"
    "    runs-on: ubuntu-latest\n"
    "    permissions:\n"
    "      contents: write\n"
    "      id-token: write\n"
    "    steps:\n"
    "      - run: echo ${{ needs.produce.outputs.val }}\n"
)


def test_composer_rule_fires_via_tag_routing(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / "w.yml").write_text(_CHAIN_105_POSITIVE, encoding="utf-8")

    rules = load_all_rules()
    reports = scan_repo(str(tmp_path), rules, Platform.GITHUB)
    composer_findings = [
        f for r in reports for f in r.findings if f.rule_id == "CHAIN-GH-105"
    ]
    assert len(composer_findings) == 1
    f = composer_findings[0]
    # The emitted finding carries the routing tag (so post-composition steps
    # can identify composer output without reading finding_family).
    assert "chain-composition" in f.composition_tags
    # Reporting family is still set for clustering.
    assert f.finding_family == "chain-composition"


# ---------------------------------------------------------------------------
# Family-coverage visibility gate
# ---------------------------------------------------------------------------


def _run_gate(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_family_coverage.py"), *args],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )


def test_family_coverage_gate_matches_baseline() -> None:
    """The committed baseline matches the current fallback population."""
    res = _run_gate("--check")
    assert res.returncode == 0, res.stdout + res.stderr


def test_family_coverage_baseline_is_accurate() -> None:
    """The baseline file enumerates exactly the rules with no explicit family."""
    baseline_path = ROOT / "tests" / "_family_fallback_baseline.json"
    data = json.loads(baseline_path.read_text())
    baseline_ids = set(data["rule_ids"])
    current = {r.id for r in load_all_rules() if not r.finding_family}
    assert baseline_ids == current
    assert data["count"] == len(baseline_ids)


def test_family_coverage_gate_blocks_new_unmarked() -> None:
    """A new unmarked rule ID (not in the baseline) fails the gate.

    Simulates "a new unmarked rule appeared since the baseline was cut" by
    temporarily shrinking the committed baseline by one entry, then asserting
    the gate exits non-zero and names the now-missing id.  The baseline file
    is backed up and restored so the test leaves no residue.
    """
    baseline_path = ROOT / "tests" / "_family_fallback_baseline.json"
    original_text = baseline_path.read_text()
    data = json.loads(original_text)
    full_ids = list(data["rule_ids"])
    assert full_ids, "expected some rules to rely on the fallback"

    dropped = full_ids[0]
    shrunk = full_ids[1:]  # the dropped id now looks like a 'new' unmarked rule
    try:
        baseline_path.write_text(
            json.dumps({"count": len(shrunk), "rule_ids": shrunk}, indent=2) + "\n",
            encoding="utf-8",
        )
        res = _run_gate("--check")
        assert res.returncode == 1, res.stdout + res.stderr
        assert dropped in res.stderr
    finally:
        baseline_path.write_text(original_text, encoding="utf-8")
