"""Keep GitHub input and credential remediation accurate and executable."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform


@pytest.fixture(scope="module")
def github_rules():
    return {rule.id: rule for rule in load_rules_for_platform(Platform.GITHUB)}


def _bash_executable() -> str:
    git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
    if git_bash.is_file():
        return str(git_bash)
    installed = shutil.which("bash")
    if installed and Path(installed).stat().st_size > 0:
        return installed
    pytest.skip("Bash is unavailable; static remediation contract still runs")


def _sec7_script(remediation: str) -> str:
    match = re.search(
        r"  run: \|\n(?P<body>.*?)\n  env:\n",
        remediation,
        flags=re.DOTALL,
    )
    assert match, "SEC7 advice must show a run block followed by its input env mapping"
    return textwrap.dedent(match.group("body"))


def _run_bash(script: str, message: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["MESSAGE"] = message
    return subprocess.run(
        [_bash_executable(), "-c", script],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_sec7_advice_keeps_free_text_out_of_shell_source(github_rules):
    rule = github_rules["SEC7-GH-004"]
    advice = rule.remediation
    script = _sec7_script(advice)

    assert "${{ inputs.message }}" not in script
    assert "MESSAGE: ${{ inputs.message }}" in advice
    assert "[[ ! $MESSAGE =~ $allowed ]]" in script
    assert "allowed='^[a-zA-Z0-9 .,!?-]+$'" in script
    assert "printf '%s\\n' \"$MESSAGE\"" in script
    assert "not inherently an injection" in rule.description
    assert "finite" in advice


@pytest.mark.parametrize(
    ("message", "expected_returncode", "expected_stdout", "expected_stderr"),
    [
        ("hello world", 0, "hello world\n", ""),
        (
            "$(printf REMEDIATION_PROBE >&2)",
            1,
            "Invalid input\n",
            "",
        ),
    ],
)
def test_sec7_advice_bash_validation_treats_input_as_data(
    github_rules, message, expected_returncode, expected_stdout, expected_stderr
):
    script = _sec7_script(github_rules["SEC7-GH-004"].remediation)
    result = _run_bash(script, message)

    assert result.returncode == expected_returncode
    assert result.stdout == expected_stdout
    assert result.stderr == expected_stderr


def test_sec6_advice_reviews_the_recipient_and_credential(github_rules):
    rule = github_rules["SEC6-GH-010"]
    title_and_advice = "\n".join(
        (rule.title, rule.description, rule.remediation, rule.threat_narrative)
    )

    assert "recipient" in title_and_advice.lower()
    assert "source and pin" in rule.remediation
    assert "narrowest credential" in rule.remediation
    assert "does not" in rule.remediation and "isolate" in rule.remediation
    assert "log masking" in rule.remediation
    assert "${{ env.NAME }}" not in rule.remediation
    assert "non-secret reference" not in rule.remediation
    assert "without env-block masking" not in rule.title
    assert "only ``env:`` values are" not in title_and_advice
    assert "does not establish" in rule.threat_narrative
    assert rule.review_needed
