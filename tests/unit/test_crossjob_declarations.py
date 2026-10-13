"""Focused absence certificates for CHAIN-GH-105 cross-job references."""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.github._crossjob_declarations import (
    CrossJobDeclarationView,
    build_crossjob_declaration_view,
)
from taintly.rules.github._crossjob_declarations import (
    DeclarationVerdict as Verdict,
)
from taintly.rules.registry import load_all_rules


def _workflow(
    *,
    outputs: str = "      val: ${{ steps.s.outputs.v }}\n",
    needs: str | None = "produce\n",
    ref: str = "val",
) -> str:
    needs_yaml = "" if needs is None else "    needs: " + needs
    return (
        "on: pull_request_target\n"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "    outputs:\n"
        f"{outputs}"
        "    steps:\n"
        "      - run: echo ok\n"
        "  bridge:\n"
        "    needs: produce\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "    steps:\n"
        "      - run: echo ok\n"
        "  other:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "    steps:\n"
        "      - run: echo ok\n"
        "  consume:\n"
        f"{needs_yaml}"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "      id-token: write\n"
        "    steps:\n"
        f'      - run: gh issue edit 1 --add-label "${{{{ needs.produce.outputs.{ref} }}}}"\n'
    )


def _flow_output_workflow(*, declared: str = "val", ref: str = "val") -> str:
    return _workflow(ref=ref).replace(
        "    outputs:\n      val: ${{ steps.s.outputs.v }}\n",
        f"    outputs: {{ {declared}: '${{{{ steps.s.outputs.v }}}}' }}\n",
    )


def _view(content: str) -> CrossJobDeclarationView:
    view = build_crossjob_declaration_view(content)
    assert view is not None
    return view


def _write_workflow(tmp_path: Path, content: str) -> Path:
    path = tmp_path / ".github" / "workflows" / "authored.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _chain_findings(tmp_path: Path) -> list:
    reports = scan_repo(str(tmp_path), load_all_rules(), Platform.GITHUB)
    assert all(not report.engine_errors() for report in reports)
    return [
        finding
        for report in reports
        for finding in report.findings
        if finding.rule_id == "CHAIN-GH-105"
    ]


def test_output_and_direct_needs_positive_certificates() -> None:
    view = _view(_workflow())
    assert view.output_name_verdict("produce", "val") is Verdict.PRESENT
    assert view.direct_need_verdict("consume", "produce") is Verdict.PRESENT


def test_block_scalar_output_value_is_still_a_declared_name() -> None:
    view = _view(_workflow(outputs="      val: |-\n        literal value\n"))
    assert view.output_name_verdict("produce", "val") is Verdict.PRESENT


def test_flat_flow_output_map_certifies_present_and_absent_names() -> None:
    view = _view(_flow_output_workflow())
    assert view.output_name_verdict("produce", "val") is Verdict.PRESENT
    assert view.output_name_verdict("produce", "missing") is Verdict.ABSENT


@pytest.mark.parametrize(
    "body",
    [
        "other: value,,",
        ",other: value",
        "other: value, stray",
    ],
    ids=["empty-member", "leading-empty-member", "stray-member"],
)
def test_malformed_flow_output_members_are_unknown(body: str) -> None:
    content = _workflow().replace(
        "    outputs:\n      val: ${{ steps.s.outputs.v }}",
        f"    outputs: {{{body}}}",
    )
    assert _view(content).output_name_verdict("produce", "missing") is Verdict.UNKNOWN


def test_missing_output_and_direct_dependencies_are_proven_absent() -> None:
    assert _view(_workflow()).output_name_verdict("produce", "missing") is Verdict.ABSENT
    assert _view(_workflow(needs=None)).direct_need_verdict("consume", "produce") is Verdict.ABSENT
    assert (
        _view(_workflow(needs="other\n")).direct_need_verdict("consume", "produce")
        is Verdict.ABSENT
    )


def test_anonymous_or_inline_job_containers_cannot_prove_missing_needs() -> None:
    anonymous = _workflow(needs=None).replace("  consume:\n", "  consume:\n    []\n")
    inline_root = _workflow().replace("jobs:\n", "jobs: {}\n")
    assert (
        build_crossjob_declaration_view(anonymous).direct_need_verdict("consume", "produce")
        is Verdict.UNKNOWN
    )
    assert _view(inline_root).direct_need_verdict("consume", "produce") is Verdict.UNKNOWN


def test_output_case_only_difference_is_unknown() -> None:
    content = _workflow(outputs="      Val: ${{ steps.s.outputs.v }}\n", ref="val")
    assert _view(content).output_name_verdict("produce", "val") is Verdict.UNKNOWN


@pytest.mark.parametrize(
    "needs",
    ["produce\n", "[produce, other]\n", "\n      - produce\n      - other\n"],
)
def test_supported_direct_needs_forms_certify_presence(needs: str) -> None:
    assert (
        _view(_workflow(needs=needs)).direct_need_verdict("consume", "produce") is Verdict.PRESENT
    )


def test_nontransitive_needs_does_not_prove_direct_dependency() -> None:
    view = _view(_workflow(needs="bridge\n"))
    assert view.direct_need_verdict("consume", "produce") is Verdict.ABSENT


@pytest.mark.parametrize(
    "content",
    [
        _workflow(outputs="      val: one\n      val: two\n"),
        _workflow(outputs="      val: *shared\n"),
        _workflow(outputs="      <<: *shared\n"),
        _workflow(outputs="      val: one\n---\n"),
        _workflow(outputs="      val: one\n--- {x: y}\n"),
        _workflow(outputs="      val: one\n", needs="[other, []]\n"),
        _workflow(outputs="      val: one\n", needs="[other}\n"),
    ],
    ids=[
        "duplicate-output-key",
        "output-alias",
        "output-merge",
        "document-marker",
        "document-marker-with-content",
        "nested-flow-item",
        "malformed-flow",
    ],
)
def test_ambiguous_shapes_return_unknown(content: str) -> None:
    assert build_crossjob_declaration_view(content) is None


@pytest.mark.parametrize(
    ("content", "verdict"),
    [
        (_workflow(outputs="      val:\n        nested: value\n"), "output"),
        (_workflow(outputs="      val: one\n      empty: []\n"), "output"),
        (_workflow(outputs="      val: 'one' trailing\n"), "output"),
        (_workflow(outputs="      val: ${{ steps.s.outputs.v }} trailing\n"), "output"),
        (
            _workflow(outputs="      val: one\n").replace(
                "    outputs:\n      val: one\n", "    outputs: {}\n"
            ),
            "output",
        ),
        (_workflow(outputs="      val: one\n", needs="[]\n"), "needs"),
        (_workflow(outputs="      val: one\n", needs="{ job: produce }\n"), "needs"),
        (_workflow(outputs="      val: one\n", needs="${{ matrix.job }}\n"), "needs"),
        (_workflow(outputs="      val: one\n", needs="produce\n      ignored: []\n"), "needs"),
    ],
    ids=[
        "nested-output-value",
        "empty-output-entry",
        "quoted-value-trailing-text",
        "expression-value-trailing-text",
        "empty-output-map",
        "empty-needs-sequence",
        "mapping-needs",
        "dynamic-needs",
        "scalar-needs-with-child",
    ],
)
def test_opaque_local_values_return_unknown(content: str, verdict: str) -> None:
    view = _view(content)
    if verdict == "output":
        assert view.output_name_verdict("produce", "missing") is Verdict.UNKNOWN
    else:
        assert view.direct_need_verdict("consume", "produce") is Verdict.UNKNOWN


@pytest.mark.parametrize(
    "content",
    [
        _workflow(outputs="      val: one\n", ref="missing"),
        _workflow(needs="other\n"),
        _workflow(needs="bridge\n"),
    ],
    ids=["missing-output", "no-direct-needs", "transitive-needs"],
)
def test_actual_composer_prunes_only_proven_absence(tmp_path: Path, content: str) -> None:
    _write_workflow(tmp_path, content)
    assert _chain_findings(tmp_path) == []


@pytest.mark.parametrize(
    "content",
    [
        _flow_output_workflow(),
        _flow_output_workflow(declared="val", ref="missing"),
    ],
    ids=["flow-output-positive", "flow-output-missing-name"],
)
def test_actual_composer_uses_complete_flow_output_map(tmp_path: Path, content: str) -> None:
    _write_workflow(tmp_path, content)
    findings = _chain_findings(tmp_path)
    if "needs.produce.outputs.val" in content:
        assert len(findings) == 1
    else:
        assert findings == []


@pytest.mark.parametrize(
    "content",
    [
        _workflow(outputs="      Val: one\n", ref="val"),
        _workflow(outputs="      val: one\n      val: two\n"),
        _workflow(outputs="      val: one\n", needs="[]\n"),
        _workflow(outputs="      val: one\n", needs="${{ matrix.job }}\n"),
    ],
    ids=["case-ambiguous", "duplicate-key", "empty-needs", "dynamic-needs"],
)
def test_unknown_shapes_keep_review_candidate(tmp_path: Path, content: str) -> None:
    _write_workflow(tmp_path, content)
    assert len(_chain_findings(tmp_path)) == 1
