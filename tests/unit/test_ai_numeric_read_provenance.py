"""Typed numeric provenance narrows a declared selector, not workflow risk."""

import json
from pathlib import Path

import pytest

from taintly.agentguards import AgentGuardIndex
from taintly.rules.github.ai import RULES

CASES = json.loads(
    (Path(__file__).parents[1] / "fixtures/ai_numeric_read_provenance.json").read_text(
        encoding="utf-8"
    )
)
RULE = next(rule for rule in RULES if rule.id == "AI-GH-019")


@pytest.mark.parametrize("case", CASES, ids=lambda row: row["name"])
def test_independent_numeric_selector_controls(case):
    source = case["source_yaml"]
    line = next(
        number
        for number, text in enumerate(source.splitlines(), 1)
        if "gh pr view" in text or "gh issue view" in text
    )
    assert (
        AgentGuardIndex(source).read_selects_only_metadata(line)
        is not case["expected_ai019_review"]
    )
    source += "      - uses: anthropics/claude-code-action@v1\n"
    assert bool(RULE.pattern.check(source, source.splitlines())) is case["expected_ai019_review"]


BASE = (
    "on: pull_request\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n"
    "      - id: pr\n"
    '        run: echo "number=${{ github.event.pull_request.number }}" >> "$GITHUB_OUTPUT"\n'
    "      - run: gh pr view ${{ steps.pr.outputs.number }} --json state\n"
    "      - uses: anthropics/claude-code-action@v1\n"
)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("id: pr", "id: ${{ inputs.id }}"),
        ("id: pr", "id: pr\n      - id: PR\n        run: echo unknown"),
        ('>> "$GITHUB_OUTPUT"', ">> '$GITHUB_OUTPUT'"),
        ('>> "$GITHUB_OUTPUT"', '>> "$OTHER_OUTPUT"'),
        ("run: echo", "env:\n          GITHUB_OUTPUT: /tmp/fake\n        run: echo"),
        ("run: echo", "env:\n          PATH: /tmp/fake\n        run: echo"),
        ("run: echo", "env:\n          IFS: '1'\n        run: echo"),
        ("run: echo", "env:\n          BASH_ENV: startup.sh\n        run: echo"),
        ("runs-on: ubuntu-latest", "runs-on: self-hosted"),
        ("runs-on: ubuntu-latest", "runs-on: windows-latest"),
        ("runs-on: ubuntu-latest", "runs-on: ubuntu-latest\n    container: unknown/image"),
        ("run: echo", "shell: bash {0}\n        run: echo"),
        ("run: echo", "shell: pwsh\n        run: echo"),
        ("steps.pr.outputs.number }}", "steps.pr.outputs.number || inputs.fallback }}"),
        ("view ${{", "view prefix${{"),
        ("number }} --json", "number }}suffix --json"),
        ("--json state", "--json body"),
        (
            "view ${{ steps.pr.outputs.number }} --json state",
            "view 1 --json ${{ steps.pr.outputs.number }}",
        ),
        ("on: pull_request", "on: [pull_request, discussion_comment]"),
    ],
)
def test_unknown_numeric_provenance_keeps_read_review(before, after):
    source = BASE.replace(before, after)
    assert source != BASE
    assert RULE.pattern.check(source, source.splitlines())


@pytest.mark.parametrize(
    "options",
    ["if: ${{ false }}", "continue-on-error: true", "if: always()"],
)
def test_optional_writer_is_numeric_or_empty_not_a_positive_id(options):
    source = BASE.replace("id: pr", "id: pr\n        " + options)
    assert not RULE.pattern.check(source, source.splitlines())


def test_other_content_reads_survive_metadata_candidate_exclusion():
    source = BASE.replace("      - uses:", "      - run: gh pr view 1 --json body\n      - uses:")
    hits = RULE.pattern.check(source, source.splitlines())
    assert len(hits) == 1
    assert "--json body" in hits[0][1]


def test_extreme_numeric_default_does_not_claim_finiteness_or_positive_id():
    source = next(row["source_yaml"] for row in CASES if row["name"] == "exponent_number_input")
    source = source.replace("default: 1e3", "default: 1e999")
    source += "      - uses: anthropics/claude-code-action@v1\n"
    assert not RULE.pattern.check(source, source.splitlines())
