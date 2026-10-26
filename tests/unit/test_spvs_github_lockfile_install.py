"""Authored contrasts for the bounded npm release-install profile."""

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import IncompletePatternMatches
from taintly.parsers.structural import EventKind, walk_workflow
from taintly.rules.github.lockfile_install import RULES, NonFrozenNpmPublishPattern


def _scan(tmp_path: Path, workflow: str):
    path = tmp_path / "workflow.yml"
    path.write_text(workflow, encoding="utf-8")
    return [f for f in scan_file(str(path), RULES) if f.rule_id == "LOTP-GH-007"]


@pytest.mark.parametrize(
    ("workflow", "expected_lines"),
    [
        (
            "jobs:\n  release:\n    steps:\n      - run: npm install\n      - run: npm publish\n",
            [4],
        ),
        (
            "jobs:\n  release:\n    steps:\n      - run: |\n          npm install\n"
            "          npm publish\n",
            [5],
        ),
        (
            "jobs:\n  release:\n    steps:\n      - run: npm install --prefix backend\n"
            "      - run: npm publish --prefix backend\n",
            [4],
        ),
        (
            "jobs:\n  release:\n    steps:\n      - run: npm install --ignore-scripts\n"
            "      - run: npm publish\n",
            [4],
        ),
    ],
)
def test_supported_non_frozen_install_reaches_publish(
    tmp_path: Path, workflow: str, expected_lines
):
    findings = _scan(tmp_path, workflow)
    assert [f.line for f in findings] == expected_lines
    assert all(f.review_needed for f in findings)
    assert all("npm install" in f.snippet for f in findings)


@pytest.mark.parametrize(
    "workflow",
    [
        "jobs:\n  release:\n    steps:\n      - run: npm ci\n      - run: npm publish\n",
        "jobs:\n  release:\n    steps:\n      - run: npm install -g npm@latest\n"
        "      - run: npm ci\n      - run: npm publish\n",
        "jobs:\n  build:\n    steps:\n      - run: npm install\n"
        "  release:\n    steps:\n      - run: npm publish\n",
        "jobs:\n  release:\n    steps:\n      - run: npm publish\n      - run: npm install\n",
        "jobs:\n  release:\n    steps:\n      - run: npm install --prefix backend\n"
        "      - run: npm publish\n",
        "jobs:\n  release:\n    steps:\n      - run: npm install\n"
        "        working-directory: backend\n      - run: npm publish\n",
        "jobs:\n  release:\n    steps:\n      - run: echo npm install\n      - run: npm publish\n",
        "jobs:\n  release:\n    steps:\n      - run: |\n          # npm install\n"
        "          npm publish\n",
        "jobs:\n  release:\n    steps:\n      - run: npm install --dry-run\n"
        "      - run: npm publish\n",
    ],
)
def test_no_path_for_safe_or_unrelated_install(tmp_path: Path, workflow: str):
    assert _scan(tmp_path, workflow) == []


def test_conditional_ci_does_not_erase_prior_install(tmp_path: Path):
    workflow = (
        "jobs:\n  release:\n    steps:\n      - run: npm install\n"
        "      - if: github.ref == 'refs/heads/main'\n        run: npm ci\n"
        "      - run: npm publish\n"
    )
    assert [f.line for f in _scan(tmp_path, workflow)] == [4]


def test_later_ci_does_not_prove_earlier_install_kept_original_lockfile(tmp_path: Path):
    workflow = (
        "jobs:\n  release:\n    steps:\n      - run: npm install\n"
        "      - run: npm ci\n      - run: npm publish\n"
    )
    assert [f.line for f in _scan(tmp_path, workflow)] == [4]


def test_unresolved_working_directory_and_shell_are_not_clean_verdicts():
    pattern = NonFrozenNpmPublishPattern()
    cases = (
        "jobs:\n  release:\n    steps:\n      - run: npm install\n"
        "        working-directory: ${{ inputs.path }}\n      - run: npm publish\n",
        "jobs:\n  release:\n    steps:\n      - run: npm install && npm publish\n",
        "jobs:\n  release:\n    steps:\n      - if: inputs.release\n"
        "        run: npm install\n      - run: npm publish\n",
        "jobs:\n  release:\n    steps:\n      - run: npm install\n"
        "      - if: inputs.release\n        run: npm publish\n",
        "jobs:\n  release:\n    steps:\n      - run: |\n"
        "          npm install\n          cd backend\n          npm publish\n",
        "jobs:\n  release:\n    steps:\n      - run: |\n"
        "          cat > example.sh <<EOF\n          npm install\n          EOF\n"
        "          npm publish\n",
        "jobs:\n  release:\n    steps:\n      - run: |\n"
        "          function maybe_install() {\n          npm install\n          }\n"
        "          npm publish\n",
    )
    for workflow in cases:
        result = pattern.check(workflow, workflow.splitlines())
        assert isinstance(result, IncompletePatternMatches)
        assert not result
        assert result.reason


def test_whitespace_mutant_removes_yaml_run_keys_instead_of_preserving_semantics():
    source = "jobs:\n  publish:\n    steps:\n      - run: npm install\n      - run: npm publish\n"
    mutant = source.replace(": ", ":")

    def run_values(document: str) -> list[str]:
        return [
            event.value
            for event in walk_workflow("workflow.yml", content=document, recover=True)
            if event.kind is EventKind.LEAF_SCALAR and event.path[-1:] == ("run",)
        ]

    assert run_values(source) == ["npm install", "npm publish"]
    assert run_values(mutant) == []
