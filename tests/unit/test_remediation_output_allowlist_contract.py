"""Contract for safe SEC4-GH-021 remediation examples."""

import re
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform


def _find_bash() -> str | None:
    candidates = [shutil.which("bash")]
    if os.name == "nt":
        candidates.extend(
            [
                r"C:\Program Files\Git\bin\bash.exe",
                r"C:\Program Files\Git\usr\bin\bash.exe",
            ]
        )
    for candidate in candidates:
        if not candidate:
            continue
        try:
            result = subprocess.run([candidate, "--version"], capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            return candidate
    return None


BASH = _find_bash()


def _sec4_gh_021_advice() -> str:
    rule = next(
        rule for rule in load_rules_for_platform(Platform.GITHUB) if rule.id == "SEC4-GH-021"
    )
    return rule.remediation


def _advised_run_block(advice: str) -> str:
    lines = advice.split("  run: |\n", maxsplit=1)[1].splitlines()
    block = []
    for line in lines:
        if not line.startswith("    "):
            break
        block.append(line[4:])
    return "\n".join(block) + "\n"


def test_step_output_advice_uses_exact_consumer_validation():
    advice = _sec4_gh_021_advice()

    # Finite-value validation is explicitly scoped to consumers with a finite
    # domain, and the snippet names its Bash shell.
    assert "finite set of values" in advice
    assert "shell: bash" in advice
    assert "DEPLOY_ENV: ${{ steps.choose.outputs.environment }}" in advice
    assert 'case "$DEPLOY_ENV" in staging|production)' in advice
    assert '*) echo "Unsupported deployment environment" >&2; exit 1 ;;' in advice
    assert './deploy.sh "$DEPLOY_ENV"' in advice

    case = re.search(r'case "\$DEPLOY_ENV" in ([^)]*)\)', advice)
    assert case is not None
    exact_choices = set(case.group(1).split("|"))
    assert {"staging", "production"} == exact_choices
    assert "staging$(id)" not in exact_choices
    assert "production;echo bad" not in exact_choices

    # Explain the trust boundary and do not imply quoting/env prevents later
    # reparsing in eval, sh -c, or a comparable interpreter.
    assert "inspect the producing step" in advice.lower()
    assert "consuming operation" in advice.lower()
    assert "arbitrary or free-text output" in advice.lower()
    assert "does not authorize the operation" in advice.lower()
    assert "eval" in advice.lower()
    assert "sh -c" in advice.lower()
    assert "Do not reparse" in advice

    # The former prefix glob is the defect: a character class plus * leaves
    # the remainder unconstrained. No such advice may return.
    assert "[A-Za-z0-9\\ -]*" not in advice


@pytest.mark.skipif(BASH is None, reason="Bash is unavailable")
@pytest.mark.parametrize("value", ["staging", "production"])
def test_advised_run_executes_deployment_for_exact_allowed_values(value):
    advice = _sec4_gh_021_advice()
    run_block = _advised_run_block(advice)

    with tempfile.TemporaryDirectory() as temp_dir:
        workspace = Path(temp_dir)
        marker = workspace / "deploy-invoked.txt"
        deploy_stub = workspace / "deploy.sh"
        deploy_stub.write_text(
            "#!/usr/bin/env bash\nprintf '%s\\n' \"$1\"\nprintf 'called\\n' > \"$DEPLOY_MARKER\"\n",
            encoding="utf-8",
        )
        deploy_stub.chmod(0o755)

        environment = os.environ.copy()
        environment["DEPLOY_ENV"] = value
        environment["DEPLOY_MARKER"] = str(marker)
        result = subprocess.run(
            [BASH, "-c", run_block],
            cwd=workspace,
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0, result.stderr
        assert result.stdout == f"{value}\n"
        assert result.stderr == ""
        assert marker.read_text(encoding="utf-8") == "called\n"


@pytest.mark.skipif(BASH is None, reason="Bash is unavailable")
@pytest.mark.parametrize("value", ["staging;echo bad", "staging$(touch should-not-run)"])
def test_advised_run_rejects_suffix_and_substitution_before_deploy(value):
    advice = _sec4_gh_021_advice()
    run_block = _advised_run_block(advice)

    with tempfile.TemporaryDirectory() as temp_dir:
        workspace = Path(temp_dir)
        marker = workspace / "deploy-invoked.txt"
        deploy_stub = workspace / "deploy.sh"
        deploy_stub.write_text(
            "#!/usr/bin/env bash\nprintf '%s\\n' \"$1\"\nprintf 'called\\n' > \"$DEPLOY_MARKER\"\n",
            encoding="utf-8",
        )
        deploy_stub.chmod(0o755)

        environment = os.environ.copy()
        environment["DEPLOY_ENV"] = value
        environment["DEPLOY_MARKER"] = str(marker)
        result = subprocess.run(
            [BASH, "-c", run_block],
            cwd=workspace,
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 1
        assert result.stdout == ""
        assert "Unsupported deployment environment" in result.stderr
        assert not marker.exists()
        assert not (workspace / "should-not-run").exists()
