"""Source ownership controls for CHAIN-GH-105 authority indicators."""

from __future__ import annotations

from pathlib import Path

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.github._crossjob_authority import build_authority_view
from taintly.rules.github.chain_compose import _scope_has_write_operation
from taintly.rules.registry import load_all_rules


def _workflow(consumer_steps: str, *, consumer_env: str = "") -> str:
    env = f"    env:\n{consumer_env}" if consumer_env else ""
    return (
        "on: [pull_request_target]\n"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ok\n"
        "  consume:\n"
        "    runs-on: ubuntu-latest\n"
        f"{env}"
        "    steps:\n"
        f"{consumer_steps}"
    )


def _view(source: str):
    return build_authority_view(source, _scope_has_write_operation)


def test_metadata_and_yaml_comment_do_not_supply_direct_operation() -> None:
    source = _workflow(
        "      - name: gh issue edit 1 --add-label danger\n"
        "        env:\n"
        "          VALUE: ${{ needs.produce.outputs.value }}\n"
        "        run: echo safe # git push origin main\n"
    )
    view = _view(source)
    assert view.complete
    assert view.step_evidence("consume", 0) == ()
    assert view.job_evidence("consume") == ()


def test_run_operation_is_source_owned_and_trigger_flow_remains_supported() -> None:
    view = _view(_workflow("      - run: gh issue edit 1 --add-label safe\n"))
    assert view.complete
    assert [(item.kind, item.line) for item in view.step_evidence("consume", 0)] == [
        ("operation", 10)
    ]


def test_only_github_script_script_is_direct_code_input() -> None:
    script = _workflow(
        "      - uses: actions/github-script@v7\n"
        "        with:\n"
        "          script: |\n"
        "            await github.rest.issues.update({ issue_number: 1 })\n"
        "          comment: gh issue edit 1 --add-label bait\n"
    )
    view = _view(script)
    assert view.complete
    evidence = view.step_evidence("consume", 0)
    assert sorted(item.kind for item in evidence) == ["operation", "possible-input"]


def test_other_action_input_is_unresolved_not_executable_proof() -> None:
    view = _view(
        _workflow(
            "      - uses: example/action@v1\n"
            "        with:\n"
            "          command: gh issue edit 1 --add-label bait\n"
        )
    )
    assert view.complete
    assert [item.kind for item in view.step_evidence("consume", 0)] == ["possible-input"]


def test_direct_token_handoff_and_environment_reference_are_distinguished() -> None:
    direct = _view(
        _workflow(
            "      - uses: example/action@v1\n"
            "        with:\n"
            "          token: ${{ secrets.STATUS_PAT }}\n"
        )
    )
    unresolved = _view(
        _workflow(
            "      - uses: example/action@v1\n"
            "        with:\n"
            "          token: ${{ env.GH_TOKEN }}\n"
            "        env:\n"
            "          GITHUB_TOKEN: ${{ secrets.STATUS_PAT }}\n"
        )
    )
    assert [item.kind for item in direct.step_evidence("consume", 0)] == ["token"]
    assert sorted(item.kind for item in unresolved.step_evidence("consume", 0)) == [
        "possible-input",
        "token",
    ]


def test_literal_named_token_input_does_not_imply_authority() -> None:
    view = _view(
        _workflow("      - uses: example/action@v1\n        with:\n          token: public-label\n")
    )
    assert view.complete
    assert view.step_evidence("consume", 0) == ()


def test_job_environment_operation_text_remains_an_unresolved_input() -> None:
    view = _view(
        _workflow(
            '      - run: eval "$COMMAND"\n',
            consumer_env="      COMMAND: gh issue edit 1 --add-label dynamic\n",
        )
    )
    assert view.complete
    assert [item.kind for item in view.step_evidence("consume", 0)] == ["possible-input"]


def test_job_environment_token_is_inherited_by_action_owner() -> None:
    view = _view(
        _workflow(
            "      - uses: example/action@v1\n",
            consumer_env="      GITHUB_TOKEN: ${{ secrets.STATUS_PAT }}\n",
        )
    )
    assert view.complete
    assert [item.kind for item in view.step_evidence("consume", 0)] == ["possible-input"]


def test_dynamic_token_named_environment_is_not_a_generic_echo_sink() -> None:
    env = "      TOKEN: ${{ needs.produce.outputs.value }}\n"
    run_view = _view(_workflow('      - run: echo "$TOKEN"\n', consumer_env=env))
    action_view = _view(_workflow("      - uses: example/action@v1\n", consumer_env=env))
    assert run_view.complete
    assert run_view.step_evidence("consume", 0) == ()
    assert action_view.complete
    assert [item.kind for item in action_view.step_evidence("consume", 0)] == ["possible-input"]


def test_dynamic_token_named_echo_does_not_create_crossjob_authority_finding(
    tmp_path: Path,
) -> None:
    source = (
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
        "    env:\n"
        "      TOKEN: ${{ needs.produce.outputs.val }}\n"
        "    steps:\n"
        '      - run: echo "$TOKEN"\n'
    )
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "dynamic-token.yml").write_text(source, encoding="utf-8")
    reports = scan_repo(str(tmp_path), load_all_rules(), Platform.GITHUB)
    assert all(not report.engine_errors() for report in reports)
    assert not [
        finding
        for report in reports
        for finding in report.findings
        if finding.rule_id == "CHAIN-GH-105"
    ]


def test_missing_or_ambiguous_executable_owner_fails_open() -> None:
    metadata_only = _view(_workflow("      - name: gh issue edit 1 --add-label bait\n"))
    both_fields = _view(_workflow("      - run: echo safe\n        uses: example/action@v1\n"))
    aliased_owner = _view(
        "on: push\njobs:\n  base: &base\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo ok\n  consume: *base\n"
    )
    duplicate_owner = _view(
        "on: push\njobs:\n  produce:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo ok\n  consume:\n"
        "    runs-on: ubuntu-latest\n    steps:\n      - run: echo first\n"
        "    steps:\n      - run: echo second\n"
    )
    assert not metadata_only.complete
    assert not both_fields.complete
    assert not aliased_owner.complete
    assert not duplicate_owner.complete


def test_step_local_evidence_does_not_borrow_sibling_operation() -> None:
    view = _view(
        _workflow(
            "      - run: echo '${{ needs.produce.outputs.value }}'\n"
            "      - run: gh issue edit 1 --add-label unrelated\n"
        )
    )
    assert view.complete
    assert view.step_evidence("consume", 0) == ()
    assert [item.kind for item in view.step_evidence("consume", 1)] == ["operation"]


def test_job_level_witness_names_only_event_compatible_authority_step(tmp_path: Path) -> None:
    source = (
        "on:\n"
        "  push:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  produce:\n"
        "    if: github.event_name == 'pull_request_target'\n"
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
        "    env:\n"
        "      VALUE: ${{ needs.produce.outputs.val }}\n"
        "    steps:\n"
        "      - if: github.event_name == 'push'\n"
        "        run: gh issue edit 1 --add-label unrelated\n"
        "      - if: github.event_name == 'pull_request_target'\n"
        "        run: gh issue edit 2 --add-label candidate\n"
    )
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "authority.yml").write_text(source, encoding="utf-8")
    reports = scan_repo(str(tmp_path), load_all_rules(), Platform.GITHUB)
    findings = [
        finding
        for report in reports
        for finding in report.findings
        if finding.rule_id == "CHAIN-GH-105"
    ]
    assert len(findings) == 1
    compatible_line = next(
        index
        for index, line in enumerate(source.splitlines(), start=1)
        if "run: gh issue edit 2" in line
    )
    incompatible_line = next(
        index
        for index, line in enumerate(source.splitlines(), start=1)
        if "run: gh issue edit 1" in line
    )
    assert f"line {compatible_line}" in findings[0].snippet
    assert f"line {incompatible_line}" not in findings[0].snippet


def test_opaque_guard_keeps_candidate_without_citing_known_disjoint_step(
    tmp_path: Path,
) -> None:
    source = (
        "on:\n"
        "  push:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  produce:\n"
        "    if: github.event_name == 'pull_request_target'\n"
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
        "    env:\n"
        "      VALUE: ${{ needs.produce.outputs.val }}\n"
        "    steps:\n"
        "      - if: github.event_name == 'push'\n"
        "        run: gh issue edit 1 --add-label unrelated\n"
        "      - if: []\n"
        "        run: gh issue edit 2 --add-label possible\n"
    )
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "opaque-authority.yml").write_text(source, encoding="utf-8")
    reports = scan_repo(str(tmp_path), load_all_rules(), Platform.GITHUB)
    assert all(not report.engine_errors() for report in reports)
    findings = [
        finding
        for report in reports
        for finding in report.findings
        if finding.rule_id == "CHAIN-GH-105"
    ]
    assert len(findings) == 1
    compatible_line = next(
        index
        for index, line in enumerate(source.splitlines(), start=1)
        if "run: gh issue edit 2" in line
    )
    incompatible_line = next(
        index
        for index, line in enumerate(source.splitlines(), start=1)
        if "run: gh issue edit 1" in line
    )
    assert f"line {compatible_line}" in findings[0].snippet
    assert f"line {incompatible_line}" not in findings[0].snippet
