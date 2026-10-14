"""Exercise the specific misleading advice reproduced in the whole-message audit."""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from taintly.guides import get_guide
from taintly.rules.registry import load_all_rules

RULES = {r.id: r for r in load_all_rules()}


@pytest.mark.parametrize('rid', ['SEC9-GH-002', 'SEC9-GH-003'])
def test_cache_advice_distinguishes_cache_configuration_from_writer_trust(rid):
    rule = RULES[rid]
    text = ' '.join([rule.description, rule.remediation, rule.threat_narrative]).lower()
    assert 'pinned' in text and 'version' in text
    assert 'writer' in text and 'reader' in text
    assert 'does not' in text
    assert 'package-manager-cache' in text
    assert 'cache-dependency-path' not in rule.remediation or 'does not add a commit-specific cache namespace' in rule.remediation
    assert 'cache: false' not in rule.remediation or 'universal' in rule.remediation or 'setup-go' in rule.remediation
    assert 'single biggest' not in text


def test_workflow_run_recipe_selects_the_actual_run_with_usable_read_access():
    rule = RULES['SEC4-GH-003']
    text = rule.remediation
    assert 'runs-on: ubuntu-latest' in text
    assert 'actions: read' in text
    assert 'github-token: ${{ secrets.GITHUB_TOKEN }}' in text
    assert 'repository: ${{ github.repository }}' in text
    assert 'run-id: ${{ github.event.workflow_run.id }}' in text
    assert 'name: report' in text and 'path: ./untrusted/' in text
    assert 'jq -e' in text and 'report.json' in text
    assert 'another repository' in text and 'authorized' in text
    assert 'issues: write' not in text and 'pull-requests: write' not in text
    assert 'Success is not artifact provenance' in text
    assert rule.review_needed


def test_injection_advice_is_shell_specific_and_does_not_call_env_a_sanitizer():
    rule = RULES['SEC4-GH-004']
    text = ' '.join([rule.description, rule.remediation, rule.threat_narrative])
    assert 'shell: bash' in text and 'shell: pwsh' in text
    assert 'Write-Output $env:TITLE' in text
    assert 'does not prove' in text
    assert 'universal sanitizer' in text
    assert '`eval`' in text and '`Invoke-Expression`' in text
    assert 'event' in text and 'permissions' in text


@pytest.mark.parametrize('value', ['hello world', '$(printf PROBE >&2)', "a'; printf PROBE >&2 #"])
def test_bash_recipe_prints_metacharacters_as_one_data_value(value):
    advice = RULES['SEC4-GH-004'].remediation
    match = re.search(r'run: (printf[^\n]+)', advice)
    assert match, 'The Bash example must supply a fixed-format data-print command'
    windows_bash = Path('C:/Program Files/Git/bin/bash.exe')
    bash = str(windows_bash) if windows_bash.is_file() else shutil.which('bash')
    if not bash or Path(bash).stat().st_size == 0:
        pytest.skip('Bash unavailable; static shell-specific contract remains required')
    env = os.environ.copy()
    env['TITLE'] = value
    result = subprocess.run([bash, '-c', match.group(1)], env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert result.stdout == value + '\n'
    assert result.stderr == ''


def test_split_guide_preserves_untrusted_artifacts_as_data():
    guide = get_guide('SEC4-GH-011')
    assert guide
    assert 'success' in guide and 'not a trust check' in guide
    assert 'run-id: ${{ github.event.workflow_run.id }}' in guide
    assert 'JSON.parse' in guide and "body: 'The CI report is ready." in guide
    assert 'head_branch ==' not in guide and 'head_repository.default_branch' not in guide
    assert 'does not make the upstream run' in guide
    assert 'same-repository PR' in guide
