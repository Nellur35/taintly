from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file


def _scan_sec4_gh_008(
    tmp_path: Path,
    step: str,
    github_rules,
    *,
    input_type: str = "string",
):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    workflow = workflow_dir / "dispatch.yml"
    workflow.write_text(
        "on:\n"
        "  workflow_dispatch:\n"
        "    inputs:\n"
        "      tag:\n"
        f"        type: {input_type}\n"
        "jobs:\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"{step}\n",
        encoding="utf-8",
    )
    return [
        finding
        for finding in scan_file(str(workflow), github_rules)
        if finding.rule_id == "SEC4-GH-008"
    ]


def _scan_content(tmp_path: Path, content: str, github_rules):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    workflow = workflow_dir / "custom.yml"
    workflow.write_text(content, encoding="utf-8")
    return [
        finding
        for finding in scan_file(str(workflow), github_rules)
        if finding.rule_id == "SEC4-GH-008"
    ]


@pytest.mark.parametrize(
    "step",
    [
        "      - run: ${{ inputs.tag }}",
        "      - run: deploy ${{ inputs.tag || 'default' }}",
        "      - run: dist ${{ inputs.tag && format('--tag={0}', inputs.tag) || 'plan' }}",
        "      - run: echo ${{ inputs['tag'] }}",
        "      - run: echo ${{ toJSON(inputs.tag) }}",
        "      - run: echo ${{ join(fromJSON(inputs.tag), ',') }}",
        "      - run: echo ${{ fromJSON(inputs.tag).name }}",
        "      - run: echo ${{ inputs[matrix.input_name] }}",
        "      - uses: actions/github-script@v7\n"
        "        with:\n"
        "          script: console.log('${{ inputs.tag || 'default' }}')",
    ],
)
def test_data_bearing_input_in_executable_sink_is_detected(tmp_path, github_rules, step):
    assert _scan_sec4_gh_008(tmp_path, step, github_rules)


@pytest.mark.parametrize("input_type", ["boolean", "choice", "environment", "number"])
def test_restricted_input_type_in_run_is_not_reported(tmp_path, github_rules, input_type):
    assert (
        _scan_sec4_gh_008(
            tmp_path,
            '      - run: echo "${{ inputs.tag }}"',
            github_rules,
            input_type=input_type,
        )
        == []
    )


@pytest.mark.parametrize(
    "step",
    [
        "      - run: deploy ${{ inputs.tag && '--tagged' || '--default' }}",
        "      - run: echo ${{ inputs.tag == 'release' }}",
        "      - run: echo ${{ !inputs.tag }}",
        "      - run: echo ${{ contains(inputs.tag, 'release') }}",
        "      - if: inputs.tag != 'dry-run'",
        "      - name: Build ${{ inputs.tag || 'default' }}\n        run: ./build.sh",
        "      - run: deploy \"$TAG\"\n        env:\n          TAG: ${{ inputs.tag || 'default' }}",
        "      - uses: example/action@v1\n"
        "        with:\n"
        "          tag: ${{ inputs.tag || 'default' }}",
    ],
)
def test_non_tainted_or_non_executable_input_use_is_not_reported(tmp_path, github_rules, step):
    assert _scan_sec4_gh_008(tmp_path, step, github_rules) == []


def test_event_namespace_uses_only_dispatch_input_type(tmp_path, github_rules):
    content = (
        "on:\n"
        "  workflow_dispatch:\n"
        "    inputs:\n"
        "      tag:\n"
        "        type: number\n"
        "  workflow_call:\n"
        "    inputs:\n"
        "      tag:\n"
        "        type: string\n"
        "jobs:\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ${{ github.event.inputs.tag }}\n"
    )

    assert _scan_content(tmp_path, content, github_rules) == []


def test_top_level_namespace_requires_all_declared_types_to_be_safe(tmp_path, github_rules):
    content = (
        "on:\n"
        "  workflow_dispatch:\n"
        "    inputs:\n"
        "      tag:\n"
        "        type: number\n"
        "  workflow_call:\n"
        "    inputs:\n"
        "      tag:\n"
        "        type: string\n"
        "jobs:\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ${{ inputs.tag }}\n"
    )

    assert _scan_content(tmp_path, content, github_rules)


def test_shell_executing_action_slot_is_case_insensitive(tmp_path, github_rules):
    content = (
        "on: workflow_call\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: Azure/CLI@v2\n"
        "        with:\n"
        "          inlineScript: echo ${{ inputs.target }}\n"
    )

    assert _scan_content(tmp_path, content, github_rules)
