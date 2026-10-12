"""Fresh-process contracts for CLI helper demand loading."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
OPTIONAL_MODULES = (
    "taintly.reporters.csv_report",
    "taintly.reporters.html_report",
    "taintly.reporters.score_text",
    "taintly.scorer",
    "taintly.testing.self_test",
)


def _run_fresh(source: str) -> subprocess.CompletedProcess[str]:
    """Run a stdlib-only interpreter with this checkout explicitly on sys.path."""
    bootstrap = f"import sys; sys.path.insert(0, {str(REPO_ROOT)!r});\n" + source
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    return subprocess.run(
        [sys.executable, "-S", "-c", bootstrap],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


def _assert_child_ok(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"


def test_importing_cli_does_not_import_optional_helpers():
    result = _run_fresh(
        """
import importlib.util
from pathlib import Path
import taintly
assert Path(taintly.__file__).resolve() == (Path(sys.path[0]) / 'taintly' / '__init__.py').resolve()
spec = importlib.util.spec_from_file_location('taintly.__main__', Path(taintly.__file__).parent / '__main__.py')
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)
assert Path(cli.__file__).resolve() == (Path(taintly.__file__).parent / '__main__.py').resolve()
optional = (
    'taintly.reporters.csv_report', 'taintly.reporters.html_report',
    'taintly.reporters.score_text', 'taintly.scorer', 'taintly.testing.self_test',
)
assert not [name for name in optional if name in __import__('sys').modules]
"""
    )
    _assert_child_ok(result)


def test_ordinary_json_cli_invocation_avoids_optional_helpers():
    result = _run_fresh(
        """
import importlib.util
from pathlib import Path
import sys
import taintly
from taintly.models import AuditReport
assert Path(taintly.__file__).resolve() == (Path(sys.path[0]) / 'taintly' / '__init__.py').resolve()
entry = Path(taintly.__file__).parent / '__main__.py'
spec = importlib.util.spec_from_file_location('taintly.__main__', entry)
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)
assert Path(cli.__file__).resolve() == entry.resolve()
cli.load_rules_for_platform = lambda _platform: []
cli.scan_repo = lambda path, rules, platform, **kwargs: [AuditReport(repo_path=str(path), platform='github')]
sys.argv = ['taintly', '.', '--platform', 'github', '--format', 'json', '--no-color', '--no-config']
try:
    cli.main()
except SystemExit as exc:
    assert exc.code == 0
optional = (
    'taintly.reporters.csv_report', 'taintly.reporters.html_report',
    'taintly.reporters.score_text', 'taintly.scorer', 'taintly.testing.self_test',
)
assert not [name for name in optional if name in sys.modules]
"""
    )
    _assert_child_ok(result)


@pytest.mark.parametrize(
    ("format_name", "expected_module", "expected_output", "also_loaded"),
    [
        ("csv", "taintly.reporters.csv_report", "rule_id", ()),
        ("html", "taintly.reporters.html_report", "<!DOCTYPE html", ("taintly.scorer",)),
    ],
)
def test_selected_report_format_loads_only_its_required_helpers(
    format_name, expected_module, expected_output, also_loaded
):
    result = _run_fresh(
        f"""
import importlib.util
from pathlib import Path
import sys
import taintly
from taintly.models import AuditReport
assert Path(taintly.__file__).resolve() == (Path(sys.path[0]) / 'taintly' / '__init__.py').resolve()
entry = Path(taintly.__file__).parent / '__main__.py'
spec = importlib.util.spec_from_file_location('taintly.__main__', entry)
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)
assert Path(cli.__file__).resolve() == entry.resolve()
cli.load_rules_for_platform = lambda _platform: []
cli.scan_repo = lambda path, rules, platform, **kwargs: [AuditReport(repo_path=str(path), platform='github')]
sys.argv = ['taintly', '.', '--platform', 'github', '--format', {format_name!r}, '--no-color', '--no-config']
try:
    cli.main()
except SystemExit as exc:
    assert exc.code == 0
assert {expected_module!r} in sys.modules
expected = {{ {expected_module!r}, *{also_loaded!r} }}
optional_names = {{
    'taintly.reporters.csv_report', 'taintly.reporters.html_report',
    'taintly.reporters.score_text', 'taintly.scorer', 'taintly.testing.self_test',
}}
assert optional_names.intersection(sys.modules) == expected
"""
    )
    _assert_child_ok(result)
    assert expected_output in result.stdout


def test_text_score_loads_scorer_and_score_formatter():
    result = _run_fresh(
        """
import importlib.util
from pathlib import Path
import sys
import taintly
from taintly.models import AuditReport
assert Path(taintly.__file__).resolve() == (Path(sys.path[0]) / 'taintly' / '__init__.py').resolve()
entry = Path(taintly.__file__).parent / '__main__.py'
spec = importlib.util.spec_from_file_location('taintly.__main__', entry)
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)
assert Path(cli.__file__).resolve() == entry.resolve()
cli.load_rules_for_platform = lambda _platform: []
cli.scan_repo = lambda path, rules, platform, **kwargs: [AuditReport(repo_path=str(path), platform='github')]
sys.argv = ['taintly', '.', '--platform', 'github', '--format', 'text', '--score', '--no-color', '--no-config']
try:
    cli.main()
except SystemExit as exc:
    assert exc.code == 0
assert 'taintly.scorer' in sys.modules
assert 'taintly.reporters.score_text' in sys.modules
optional_names = {
    'taintly.reporters.csv_report', 'taintly.reporters.html_report',
    'taintly.reporters.score_text', 'taintly.scorer', 'taintly.testing.self_test',
}
assert optional_names.intersection(sys.modules) == {'taintly.reporters.score_text', 'taintly.scorer'}
"""
    )
    _assert_child_ok(result)


def test_selected_self_test_rule_still_runs_and_loads_self_test_helper():
    result = _run_fresh(
        """
import importlib.util
from pathlib import Path
import sys
import taintly
assert Path(taintly.__file__).resolve() == (Path(sys.path[0]) / 'taintly' / '__init__.py').resolve()
entry = Path(taintly.__file__).parent / '__main__.py'
spec = importlib.util.spec_from_file_location('taintly.__main__', entry)
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)
assert Path(cli.__file__).resolve() == entry.resolve()
from taintly.rules.registry import load_all_rules
rules = load_all_rules()
rule = next(rule for rule in rules if rule.test_positive or rule.test_negative)
cli.load_all_rules = lambda: [rule]
sys.argv = ['taintly', '--self-test', '--rule', rule.id]
try:
    cli.main()
except SystemExit as exc:
    assert exc.code == 0
assert 'taintly.testing.self_test' in sys.modules
optional_names = {
    'taintly.reporters.csv_report', 'taintly.reporters.html_report',
    'taintly.reporters.score_text', 'taintly.scorer', 'taintly.testing.self_test',
}
assert optional_names.intersection(sys.modules) == {'taintly.testing.self_test'}
"""
    )
    _assert_child_ok(result)
