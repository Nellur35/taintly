"""Synthetic same-job output-domain contracts for SEC4-GH-021."""

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform

@pytest.fixture(scope="module")
def github_rules():
    return load_rules_for_platform(Platform.GITHUB)


def _sec4_gh_021(path: Path, github_rules):
    return [
        finding
        for finding in scan_file(str(path), github_rules)
        if finding.rule_id == "SEC4-GH-021"
    ]


def _scan_text(
    tmp_path: Path,
    github_rules,
    producer: str,
    consumer: str,
    *,
    trigger: str = "pull_request",
):
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        f"on: {trigger}\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"{producer}"
        f"{consumer}",
        encoding="utf-8",
    )
    return _sec4_gh_021(workflow, github_rules)


def test_all_literal_assignments_must_be_shell_safe(tmp_path, github_rules):
    findings = _scan_text(
        tmp_path,
        github_rules,
        "      - id: gate\n"
        "        run: |\n"
        "          if test -f safe; then\n"
        '            echo "decision=true" >> "$GITHUB_OUTPUT"\n'
        "          else\n"
        '            echo "decision=false" >> "$GITHUB_OUTPUT"\n'
        "          fi\n",
        '      - run: verify "${{ steps.gate.outputs.decision }}"\n',
    )

    assert findings == []


def test_mixed_literal_and_dynamic_assignment_still_fires(tmp_path, github_rules):
    findings = _scan_text(
        tmp_path,
        github_rules,
        "      - id: gate\n"
        "        run: |\n"
        '          echo "decision=true" >> "$GITHUB_OUTPUT"\n'
        '          echo "decision=$PR_TITLE" >> "$GITHUB_OUTPUT"\n',
        "      - run: verify ${{ steps.gate.outputs.decision }}\n",
    )

    assert len(findings) == 1


def test_dynamic_output_name_write_invalidates_literal_proof(tmp_path, github_rules):
    findings = _scan_text(
        tmp_path,
        github_rules,
        "      - id: gate\n"
        "        run: |\n"
        '          echo "decision=true" >> "$GITHUB_OUTPUT"\n'
        '          echo "$OUTPUT_NAME=$PR_TITLE" >> "$GITHUB_OUTPUT"\n',
        "      - run: verify ${{ steps.gate.outputs.decision }}\n",
    )

    assert len(findings) == 1


def test_shell_command_substitution_still_fires(tmp_path, github_rules):
    findings = _scan_text(
        tmp_path,
        github_rules,
        '      - id: gate\n        run: echo "decision=ok;$(id)" >> "$GITHUB_OUTPUT"\n',
        "      - run: verify ${{ steps.gate.outputs.decision }}\n",
    )

    assert len(findings) == 1


def test_closed_literal_with_spaces_and_punctuation_is_safe(tmp_path, github_rules):
    findings = _scan_text(
        tmp_path,
        github_rules,
        "      - id: gate\n"
        "        run: echo 'decision=approved: fixed value' >> \"$GITHUB_OUTPUT\"\n",
        '      - run: verify "${{ steps.gate.outputs.decision }}"\n',
    )

    assert findings == []


def test_unknown_action_output_still_fires(tmp_path, github_rules):
    findings = _scan_text(
        tmp_path,
        github_rules,
        "      - id: metadata\n        uses: example/read-pr@v1\n",
        "      - run: deploy ${{ steps.metadata.outputs.title }}\n",
    )

    assert len(findings) == 1


def test_producer_must_precede_consumer(tmp_path, github_rules):
    findings = _scan_text(
        tmp_path,
        github_rules,
        "      - run: deploy ${{ steps.metadata.outputs.value }}\n",
        '      - id: metadata\n        run: echo "value=safe" >> "$GITHUB_OUTPUT"\n',
    )

    assert len(findings) == 1


def test_same_step_id_in_another_job_does_not_supply_proof(tmp_path, github_rules):
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on: pull_request\n"
        "jobs:\n"
        "  safe-job:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - id: metadata\n"
        '        run: echo "value=safe" >> "$GITHUB_OUTPUT"\n'
        "  risky-job:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - id: metadata\n"
        "        uses: example/read-pr@v1\n"
        "      - run: deploy ${{ steps.metadata.outputs.value }}\n",
        encoding="utf-8",
    )

    assert len(_sec4_gh_021(workflow, github_rules)) == 1


def test_validated_npm_version_requires_prior_publish(tmp_path, github_rules):
    findings = _scan_text(
        tmp_path,
        github_rules,
        "      - id: package\n"
        "        run: |\n"
        "          VERSION=$(node -p \"require('./dist/pkg/package.json').version\")\n"
        '          echo "version=$VERSION" >> "$GITHUB_OUTPUT"\n',
        "      - run: npm install pkg@${{ steps.package.outputs.version }}\n",
    )

    assert len(findings) == 1


def test_validated_npm_version_is_safe_on_trusted_trigger(tmp_path, github_rules):
    findings = _scan_text(
        tmp_path,
        github_rules,
        "      - id: package\n"
        "        run: |\n"
        '          (cd "./dist/pkg" && npm publish)\n'
        "          VERSION=$(node -p \"require('./dist/pkg/package.json').version\")\n"
        '          echo "version=$VERSION" >> "$GITHUB_OUTPUT"\n',
        "      - run: npm install pkg@${{ steps.package.outputs.version }}\n",
        trigger="release",
    )

    assert findings == []


def test_validated_npm_version_still_fires_on_fork_trigger(tmp_path, github_rules):
    findings = _scan_text(
        tmp_path,
        github_rules,
        "      - id: package\n"
        "        run: |\n"
        '          (cd "./dist/pkg" && npm publish)\n'
        "          VERSION=$(node -p \"require('./dist/pkg/package.json').version\")\n"
        '          echo "version=$VERSION" >> "$GITHUB_OUTPUT"\n',
        "      - run: npm install pkg@${{ steps.package.outputs.version }}\n",
    )

    assert len(findings) == 1


def test_validated_npm_version_requires_same_package_path(tmp_path, github_rules):
    findings = _scan_text(
        tmp_path,
        github_rules,
        "      - id: package\n"
        "        run: |\n"
        '          (cd "./dist/other" && npm publish --registry http://localhost:4873/)\n'
        "          VERSION=$(node -p \"require('./dist/pkg/package.json').version\")\n"
        '          echo "version=$VERSION" >> "$GITHUB_OUTPUT"\n',
        "      - run: npm install pkg@${{ steps.package.outputs.version }}\n",
    )

    assert len(findings) == 1


def test_ignored_publish_failure_does_not_validate_version(tmp_path, github_rules):
    findings = _scan_text(
        tmp_path,
        github_rules,
        "      - id: package\n"
        "        run: |\n"
        '          (cd "./dist/pkg" && npm publish) || true\n'
        "          VERSION=$(node -p \"require('./dist/pkg/package.json').version\")\n"
        '          echo "version=$VERSION" >> "$GITHUB_OUTPUT"\n',
        "      - run: npm install pkg@${{ steps.package.outputs.version }}\n",
    )

    assert len(findings) == 1


def test_command_after_publish_invalidates_version_proof(tmp_path, github_rules):
    findings = _scan_text(
        tmp_path,
        github_rules,
        "      - id: package\n"
        "        run: |\n"
        '          (cd "./dist/pkg" && npm publish && node mutate.js)\n'
        "          VERSION=$(node -p \"require('./dist/pkg/package.json').version\")\n"
        '          echo "version=$VERSION" >> "$GITHUB_OUTPUT"\n',
        "      - run: npm install pkg@${{ steps.package.outputs.version }}\n",
    )

    assert len(findings) == 1


def test_variable_reassignment_invalidates_version_proof(tmp_path, github_rules):
    findings = _scan_text(
        tmp_path,
        github_rules,
        "      - id: package\n"
        "        run: |\n"
        '          (cd "./dist/pkg" && npm publish)\n'
        "          VERSION=$(node -p \"require('./dist/pkg/package.json').version\")\n"
        "          VERSION=$PR_TITLE\n"
        '          echo "version=$VERSION" >> "$GITHUB_OUTPUT"\n',
        "      - run: npm install pkg@${{ steps.package.outputs.version }}\n",
    )

    assert len(findings) == 1


def test_bracket_output_reference_uses_same_proof(tmp_path, github_rules):
    findings = _scan_text(
        tmp_path,
        github_rules,
        '      - id: gate\n        run: echo "decision=approved" >> "$GITHUB_OUTPUT"\n',
        "      - run: verify ${{ steps.gate.outputs['decision'] }}\n",
    )

    assert findings == []
