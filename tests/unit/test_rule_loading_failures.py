"""A rule-pack import failure must never look like a clean partial run."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

from taintly import __main__ as cli
from taintly.models import Platform
from taintly.rules import registry


@pytest.fixture(autouse=True)
def isolate_registry_failure_state():
    previous = registry._IMPORT_FAILURES[:]
    registry._IMPORT_FAILURES.clear()
    try:
        yield
    finally:
        registry._IMPORT_FAILURES[:] = previous


def test_load_all_rules_retains_multiple_failures_from_every_platform(monkeypatch):
    platforms = list(Platform)
    expected_failures = []

    def discover(_package_path, package_name):
        failures = [f"{package_name}.early_failed", f"{package_name}.later_failed"]
        expected_failures.extend(failures)
        registry._IMPORT_FAILURES.extend(failures)
        return [f"loaded:{package_name}:rule-1", f"loaded:{package_name}:rule-2"]

    monkeypatch.setattr(registry, "_discover_rules_in_package", discover)
    registry._IMPORT_FAILURES[:] = ["stale.failure.from.previous.call"]

    loaded = registry.load_all_rules()

    package_names = [f"taintly.rules.{registry._PLATFORM_DIR[platform]}" for platform in platforms]
    assert loaded == [
        f"loaded:{package_name}:rule-{ordinal}"
        for package_name in package_names
        for ordinal in (1, 2)
    ]
    assert registry._IMPORT_FAILURES == expected_failures
    assert "stale.failure.from.previous.call" not in registry._IMPORT_FAILURES


def test_clean_single_platform_call_clears_previous_failure_state(monkeypatch):
    discovery_calls = 0

    def discover(_path, package):
        nonlocal discovery_calls
        discovery_calls += 1
        if discovery_calls == 1:
            registry._IMPORT_FAILURES.append("taintly.rules.github.first_call_failure")
        return [f"loaded:{package}"]

    monkeypatch.setattr(registry, "_discover_rules_in_package", discover)
    registry._IMPORT_FAILURES.clear()

    first = registry.load_rules_for_platform(Platform.GITHUB)
    assert first == ["loaded:taintly.rules.github"]
    assert registry._IMPORT_FAILURES == ["taintly.rules.github.first_call_failure"]

    second = registry.load_rules_for_platform(Platform.GITHUB)

    assert second == ["loaded:taintly.rules.github"]
    assert registry._IMPORT_FAILURES == []


def test_clean_all_platform_call_clears_stale_failure_state(monkeypatch):
    monkeypatch.setattr(
        registry,
        "_discover_rules_in_package",
        lambda _path, package: [f"loaded:{package}"],
    )
    registry._IMPORT_FAILURES[:] = ["stale.failed.module"]

    loaded = registry.load_all_rules()

    expected_packages = [
        f"taintly.rules.{registry._PLATFORM_DIR[platform]}" for platform in Platform
    ]
    assert loaded == [f"loaded:{package}" for package in expected_packages]
    assert registry._IMPORT_FAILURES == []


_IMPORT_FAILURE_HOOK = b"""import importlib.abc
import os
import sys

class _FailOneRuleModule(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == os.environ.get("TAINTLY_TEST_FAIL_RULE_MODULE"):
            raise ImportError("controlled fresh-process rule module import failure")
        return None

sys.meta_path.insert(0, _FailOneRuleModule())
"""


def _run_fresh_cli_with_import_failure(tmp_path: Path, *, all_platforms: bool):
    hook_dir = tmp_path / "import-hook"
    hook_dir.mkdir()
    (hook_dir / "sitecustomize.py").write_bytes(_IMPORT_FAILURE_HOOK)
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(hook_dir) + (
        os.pathsep + existing_pythonpath if existing_pythonpath else ""
    )
    env["TAINTLY_TEST_FAIL_RULE_MODULE"] = "taintly.rules.github.ai"
    args = ["--format", "json"]
    if not all_platforms:
        args.extend(["--platform", "github"])
    project_path = tmp_path / "empty-project"
    project_path.mkdir()
    args.append(str(project_path))
    return subprocess.run(
        [sys.executable, "-m", "taintly", *args],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )


@pytest.mark.parametrize("all_platforms", [False, True], ids=["single-platform", "all-platforms"])
def test_cli_scan_fails_nonzero_on_real_rule_import_failure_in_json_mode(tmp_path, all_platforms):
    result = _run_fresh_cli_with_import_failure(tmp_path, all_platforms=all_platforms)

    assert b"taintly.rules.github.ai" in result.stderr
    assert result.returncode == 3, (
        f"expected initialization failure exit 3, got {result.returncode}; "
        f"stdout={result.stdout[-1000:]!r}"
    )
    assert result.stdout == b"", "incomplete initialization must not emit a clean JSON report"


@pytest.mark.parametrize("mode", ["self-test", "integration-test"])
def test_self_or_integration_test_cannot_pass_with_incomplete_registry(monkeypatch, mode):
    from taintly.testing import integration_tests, self_test

    def failed_loader():
        registry._IMPORT_FAILURES[:] = ["taintly.rules.github.controlled_failure"]
        return []

    monkeypatch.setattr(cli, "load_all_rules", failed_loader)
    if mode == "self-test":
        monkeypatch.setattr(self_test, "run_self_test", lambda _rules: [])
        monkeypatch.setattr(
            self_test,
            "format_test_results_json",
            lambda _results, _mutation_results=None: '{"status":"all_passed"}',
        )
        monkeypatch.setattr(sys, "argv", ["taintly", "--self-test", "--self-test-json"])
    else:
        monkeypatch.setattr(
            integration_tests, "run_integration_tests", lambda _rules, categories=None: []
        )
        monkeypatch.setattr(
            integration_tests, "format_integration_results", lambda _results: "all passed"
        )
        monkeypatch.setattr(sys, "argv", ["taintly", "--integration-test"])

    with pytest.raises(SystemExit) as exit_info:
        cli.main()

    assert exit_info.value.code == 3
