"""Composed chains honor only supported PR ref-context contradictions."""

from pathlib import Path

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform


def _workflow(producer_guard: str, consumer_guard: str, *, event: str = "pull_request_target"):
    return (
        f"on: {event}\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        f"    if: {producer_guard}\n"
        "    outputs:\n"
        "      val: ${{ steps.source.outputs.v }}\n"
        "    steps:\n"
        '      - id: source\n        run: echo "v=hi" >> $GITHUB_OUTPUT\n'
        "  consume:\n"
        "    needs: produce\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "      id-token: write\n"
        "    env:\n"
        "      VALUE: ${{ needs.produce.outputs.val }}\n"
        "    steps:\n"
        "      - name: edit issue\n"
        f"        if: {consumer_guard}\n"
        '        run: gh issue edit 1 --add-label "$VALUE"\n'
    )


def _rule_ids(tmp_path: Path, content: str) -> set[str]:
    workflow = tmp_path / ".github" / "workflows" / "pr-context.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(content, encoding="utf-8")
    reports = scan_repo(str(tmp_path), load_rules_for_platform(Platform.GITHUB))
    findings = [finding for report in reports for finding in report.findings]
    assert not [finding for finding in findings if finding.rule_id == "ENGINE-ERR"]
    return {finding.rule_id for finding in findings}


def test_disjoint_pr_head_ref_guards_remove_composed_chain(tmp_path: Path):
    content = _workflow(
        "github.head_ref == 'source-a'",
        "github.head_ref == 'source-b'",
    )
    assert "CHAIN-GH-105" not in _rule_ids(tmp_path, content)


def test_compatible_pr_head_ref_guards_keep_composed_chain(tmp_path: Path):
    content = _workflow(
        "github.head_ref == 'source-a'",
        "github.head_ref == 'SOURCE-A'",
    )
    assert "CHAIN-GH-105" in _rule_ids(tmp_path, content)


def test_independent_pr_base_and_head_fields_keep_composed_chain(tmp_path: Path):
    content = _workflow(
        "github.head_ref == 'source-branch'",
        "github.base_ref == 'target-branch'",
    )
    assert "CHAIN-GH-105" in _rule_ids(tmp_path, content)


def test_non_pr_ref_guards_remain_unknown_and_keep_composed_chain(tmp_path: Path):
    content = _workflow(
        "github.base_ref == 'source-a'",
        "github.base_ref == 'source-b'",
        event="issues",
    )
    assert "CHAIN-GH-105" in _rule_ids(tmp_path, content)
