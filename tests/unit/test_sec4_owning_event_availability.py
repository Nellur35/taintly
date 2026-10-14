"""Owning-event refinements for issue-context absence in SEC4 sinks."""

from __future__ import annotations

from pathlib import Path

import pytest

import taintly.github_event_availability as event_availability
from taintly.engine import scan_file
from taintly.models import Platform
from taintly.parsers.structural.tokenizer import TokenizerError
from taintly.rules.github.sec3_sec4_supply_chain_ppe import _EventAwareScriptInjectionPattern
from taintly.rules.registry import load_rules_for_platform


def _scan(tmp_path: Path, content: str):
    target = tmp_path / ".github" / "workflows" / "owning-event.yml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8", newline="")
    findings = scan_file(str(target), load_rules_for_platform(Platform.GITHUB))
    assert not [finding for finding in findings if finding.rule_id == "ENGINE-ERR"]
    return findings


def _rule(findings, rule_id: str):
    return [finding for finding in findings if finding.rule_id == rule_id]


def _line(content: str, fragment: str) -> int:
    return next(index for index, line in enumerate(content.splitlines(), 1) if fragment in line)


def test_004_uses_the_matching_job_guard_for_issue_availability(tmp_path):
    content = (
        "name: owning event\n"
        "on: [push, issues]\n"
        "jobs:\n"
        "  guarded:\n"
        "    if: github.event_name == 'push'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        '      - run: echo "${{ github.event.issue.title }}"\n'
    )

    findings = _scan(tmp_path, content)

    assert not _rule(findings, "SEC4-GH-004")


def test_004_step_guard_is_local_to_its_run_step(tmp_path):
    content = (
        "name: owning event\n"
        "on: [push, issues]\n"
        "jobs:\n"
        "  check:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - if: github.event_name == 'push'\n"
        '        run: echo "${{ github.event.issue.title }}"\n'
        '      - run: echo "${{ github.event.issue.body }}"\n'
    )

    findings = _scan(tmp_path, content)
    matches = _rule(findings, "SEC4-GH-004")

    assert len(matches) == 1
    assert matches[0].line == _line(content, "issue.body")
    assert "github.event.issue.body" in matches[0].snippet


def test_025_uses_its_owning_job_guard_and_keeps_taint013(tmp_path):
    content = (
        "name: owning event github-script\n"
        "on: [push, issues]\n"
        "jobs:\n"
        "  guarded:\n"
        "    if: github.event_name == 'push'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/github-script@v7\n"
        "        with:\n"
        "          script: |\n"
        "            const title = '${{ github.event.issue.title }}';\n"
    )

    findings = _scan(tmp_path, content)

    assert not _rule(findings, "SEC4-GH-025")
    assert _rule(findings, "TAINT-GH-013")


def test_025_step_guard_does_not_suppress_sibling_script(tmp_path):
    content = (
        "name: step owner isolation\n"
        "on: [push, issues]\n"
        "jobs:\n"
        "  check:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - if: github.event_name == 'push'\n"
        "        uses: actions/github-script@v7\n"
        "        with:\n"
        "          script: |\n"
        "            const title = '${{ github.event.issue.title }}';\n"
        "      - uses: actions/github-script@v7\n"
        "        with:\n"
        "          script: |\n"
        "            const body = '${{ github.event.issue.body }}';\n"
    )

    findings = _scan(tmp_path, content)
    matches = _rule(findings, "SEC4-GH-025")

    assert len(matches) == 1
    assert matches[0].line == _line(content, "issue.body")


def test_025_alias_owned_guard_remains_unresolved(tmp_path):
    content = (
        "name: aliased owner guard\n"
        "on: [push, issues]\n"
        "guard: &push_only github.event_name == 'push'\n"
        "jobs:\n"
        "  guarded:\n"
        "    if: *push_only\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/github-script@v7\n"
        "        with:\n"
        "          script: |\n"
        "            const title = '${{ github.event.issue.title }}';\n"
    )

    findings = _scan(tmp_path, content)

    assert len(_rule(findings, "SEC4-GH-025")) == 1


def test_guard_in_sibling_job_does_not_suppress_unowned_candidate(tmp_path):
    content = (
        "name: sibling owner isolation\n"
        "on: [push, issues]\n"
        "jobs:\n"
        "  push_only:\n"
        "    if: github.event_name == 'push'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo safe\n"
        "  issue_job:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        '      - run: echo "${{ github.event.issue.title }}"\n'
    )

    findings = _scan(tmp_path, content)
    matches = _rule(findings, "SEC4-GH-004")

    assert len(matches) == 1
    assert matches[0].line == _line(content, "issue.title")


def test_unknown_or_aliased_owner_guard_keeps_issue_candidate(tmp_path):
    sources = [
        "    if: env.ENABLE == 'true'\n",
        "guard: &push_only github.event_name == 'push'\n    if: *push_only\n",
    ]
    for index, guard in enumerate(sources):
        prefix = "guard: &push_only github.event_name == 'push'\n" if "*push_only" in guard else ""
        job_guard = "    if: *push_only\n" if "*push_only" in guard else guard
        content = (
            "name: unresolved owner guard\n"
            "on: [push, issues]\n"
            + prefix
            + "jobs:\n"
            + "  guarded:\n"
            + job_guard
            + "    runs-on: ubuntu-latest\n"
            + "    steps:\n"
            + '      - run: echo "${{ github.event.issue.title }}"\n'
        )
        findings = _scan(tmp_path / str(index), content)
        matches = _rule(findings, "SEC4-GH-004")
        assert len(matches) == 1
        assert matches[0].line == _line(content, "issue.title")


def test_duplicate_owner_guard_does_not_prove_event_absence(tmp_path):
    content = (
        "name: duplicate owner guard\n"
        "on: [push, issues]\n"
        "jobs:\n"
        "  guarded:\n"
        "    if: github.event_name == 'push'\n"
        "    if: github.event_name == 'issues'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        '      - run: echo "${{ github.event.issue.title }}"\n'
    )

    findings = _scan(tmp_path, content)
    matches = _rule(findings, "SEC4-GH-004")

    assert len(matches) == 1
    assert matches[0].line == _line(content, "issue.title")


def test_null_owner_guard_keeps_candidate_even_with_push_step_guard(tmp_path):
    content = (
        "name: null owner guard\n"
        "on: [push, issues]\n"
        "jobs:\n"
        "  check:\n"
        "    if: null\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - if: github.event_name == 'push'\n"
        '        run: echo "${{ github.event.issue.title }}"\n'
    )

    findings = _scan(tmp_path, content)
    matches = _rule(findings, "SEC4-GH-004")

    assert len(matches) == 1
    assert matches[0].line == _line(content, "issue.title")


def test_guard_proof_tokenizer_failure_keeps_direct_candidate(monkeypatch):
    content = (
        "name: parser failure\n"
        "on: [push, issues]\n"
        "jobs:\n"
        "  push_only:\n"
        "    if: github.event_name == 'push'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        '      - run: echo "${{ github.event.issue.title }}"\n'
    )
    pattern = _EventAwareScriptInjectionPattern()
    lines = content.splitlines()
    assert pattern.check(content, lines) == []

    original_tokenize = event_availability.tokenize
    calls = 0

    def fail_second_tokenization(value):
        nonlocal calls
        calls += 1
        if calls == 2:

            def broken():
                yield from ()
                raise TokenizerError(1, "injected generator-consumption failure")

            return broken()
        return original_tokenize(value)

    monkeypatch.setattr(event_availability, "tokenize", fail_second_tokenization)
    findings = pattern.check(content, lines)

    assert calls == 2
    assert len(findings) == 1


@pytest.mark.parametrize(
    ("trigger", "job_guard", "step_guard"),
    [
        ("on: issues", "push", None),
        ("on: [push, issues]", "issues", "push"),
    ],
    ids=("issues-event-excluded", "all-declared-events-excluded"),
)
def test_owner_exclusion_proves_issue_source_absent_without_execution(
    tmp_path, trigger, job_guard, step_guard
):
    lines = [
        "name: excluded owning event",
        trigger,
        "jobs:",
        "  check:",
        f"    if: github.event_name == '{job_guard}'",
        "    runs-on: ubuntu-latest",
        "    steps:",
    ]
    if step_guard is not None:
        lines.append(f"      - if: github.event_name == '{step_guard}'")
        lines.append('        run: echo "${{ github.event.issue.title }}"')
    else:
        lines.append('      - run: echo "${{ github.event.issue.title }}"')
    if step_guard is not None:
        lines.append(f"      - if: github.event_name == '{step_guard}'")
        lines.append("        uses: actions/github-script@v7")
    else:
        lines.append("      - uses: actions/github-script@v7")
    lines.extend(
        [
            "        with:",
            "          script: |",
            "            const title = '${{ github.event.issue.title }}';",
        ]
    )
    content = "\n".join(lines) + "\n"

    findings = _scan(tmp_path, content)

    assert not _rule(findings, "SEC4-GH-004")
    assert not _rule(findings, "SEC4-GH-025")
    interpolation_cautions = _rule(findings, "TAINT-GH-013")
    assert len(interpolation_cautions) == 1
    assert interpolation_cautions[0].line == _line(content, "const title")
