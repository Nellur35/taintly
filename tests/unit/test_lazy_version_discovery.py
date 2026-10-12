"""Public behavior checks for deferred package version discovery."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(os.environ.get("TAINTLY_PACKAGE_ROOT", Path(__file__).resolve().parents[2]))


def _python(
    code: str, *, cwd: Path, package_root: Path = PACKAGE_ROOT
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(package_root)
    return subprocess.run(
        [sys.executable, "-S", "-c", code],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _assert_ok(result: subprocess.CompletedProcess[str]) -> str:
    assert result.returncode == 0, f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    return result.stdout


def test_package_import_defers_metadata_and_version_resolution(tmp_path: Path) -> None:
    result = _python(
        """
import importlib.abc, json, sys
seen=[]
class Watch(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'importlib.metadata' or fullname == 'setuptools_scm': seen.append(fullname)
        return None
sys.meta_path.insert(0, Watch())
import taintly
print(json.dumps({'seen': seen, 'metadata_loaded': 'importlib.metadata' in sys.modules,
                  'scm_loaded': 'setuptools_scm' in sys.modules,
                  'version_cached': '__version__' in taintly.__dict__}))
""",
        cwd=tmp_path,
    )
    assert _assert_ok(result).strip() == (
        '{"seen": [], "metadata_loaded": false, "scm_loaded": false, "version_cached": false}'
    )


def test_version_attribute_contract_and_unknown_attribute(tmp_path: Path) -> None:
    result = _python(
        """
import json, taintly
listed = '__version__' in taintly.__all__ and '__version__' in dir(taintly)
try: taintly.not_a_taintly_attribute
except AttributeError: missing = True
else: missing = False
from taintly import __version__ as imported_version
print(json.dumps({'listed': listed, 'missing_raises': missing,
                  'version_type': type(imported_version).__name__}))
""",
        cwd=tmp_path,
    )
    assert _assert_ok(result).strip() == (
        '{"listed": true, "missing_raises": true, "version_type": "str"}'
    )


def test_metadata_resolution_is_cached_once_after_access(tmp_path: Path) -> None:
    result = _python(
        """
import importlib.metadata as metadata, json
calls=[]
metadata.version = lambda name: calls.append(name) or '1.2.3-test'
import taintly
before = list(calls)
first = taintly.__version__
second = taintly.__version__
print(json.dumps({'before': before, 'calls': calls, 'first': first, 'second': second}))
""",
        cwd=tmp_path,
    )
    assert _assert_ok(result).strip() == (
        '{"before": [], "calls": ["taintly"], "first": "1.2.3-test", "second": "1.2.3-test"}'
    )


def test_scm_fallback_follows_missing_metadata_and_is_cached(tmp_path: Path) -> None:
    result = _python(
        """
import importlib.metadata as metadata, json, sys, types
calls=[]
def missing(name):
    calls.append(('metadata', name))
    raise metadata.PackageNotFoundError(name)
metadata.version = missing
scm = types.ModuleType('setuptools_scm')
scm.get_version = lambda **kwargs: calls.append(('scm', kwargs.get('root'))) or '4.5.6'
sys.modules['setuptools_scm'] = scm
import taintly
resolved = taintly.__version__
again = taintly.__version__
print(json.dumps({'calls': calls, 'resolved': resolved, 'again': again}))
""",
        cwd=tmp_path,
    )
    payload = __import__("json").loads(_assert_ok(result))
    assert payload["resolved"] == payload["again"] == "4.5.6"
    assert [call[:2] for call in payload["calls"]] == [
        ["metadata", "taintly"],
        ["scm", payload["calls"][1][1]],
    ]


def test_unknown_fallback_is_cached_when_metadata_and_scm_are_absent(tmp_path: Path) -> None:
    result = _python(
        """
import importlib.abc, importlib.metadata as metadata, json, sys
calls=[]
def missing(name):
    calls.append(('metadata', name))
    raise metadata.PackageNotFoundError(name)
metadata.version = missing
class Watch(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'setuptools_scm': calls.append(('scm-import', fullname))
        return None
sys.meta_path.insert(0, Watch())
import taintly
first, second = taintly.__version__, taintly.__version__
print(json.dumps({'calls': calls, 'first': first, 'second': second}))
""",
        cwd=tmp_path,
    )
    payload = __import__("json").loads(_assert_ok(result))
    assert payload["first"] == payload["second"] == "0.0.0+unknown"
    assert payload["calls"] == [["metadata", "taintly"], ["scm-import", "setuptools_scm"]]


def test_no_site_version_cli_preserves_exact_output_and_exit(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PACKAGE_ROOT)
    probe = subprocess.run(
        [sys.executable, "-S", "-c", "import taintly; print(taintly.__version__)"],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert probe.returncode == 0, probe.stderr
    resolved_version = probe.stdout.rstrip("\n")
    assert resolved_version
    assert "\n" not in resolved_version
    result = subprocess.run(
        [sys.executable, "-S", "-m", "taintly", "--version"],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"taintly {resolved_version}\n"
    assert result.stderr == ""


def test_no_site_json_scan_does_not_resolve_version(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    workflow_dir = repo / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "ci.yml").write_text("name: CI\non: push\njobs: {}\n", encoding="utf-8")
    result = _python(
        """
import contextlib, importlib.abc, io, json, runpy, sys
seen=[]
class Watch(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'importlib.metadata' or fullname == 'setuptools_scm': seen.append(fullname)
        return None
sys.meta_path.insert(0, Watch())
sys.argv = ['taintly', sys.argv[1], '--format', 'json', '--platform', 'github', '--no-color']
out=io.StringIO()
try:
    with contextlib.redirect_stdout(out): runpy.run_module('taintly', run_name='__main__')
except SystemExit as exc:
    code=exc.code
else: code=0
report=json.loads(out.getvalue())
print(json.dumps({'exit': code, 'seen': seen, 'repo_path': report['repo_path']}))
""".replace("sys.argv[1]", repr(str(repo))),
        cwd=tmp_path,
    )
    payload = __import__("json").loads(_assert_ok(result))
    assert payload == {"exit": 0, "seen": [], "repo_path": str(repo)}


def test_sarif_resolves_version_on_first_render_and_caches(tmp_path: Path) -> None:
    result = _python(
        """
import importlib.metadata as metadata, json
calls=[]
metadata.version = lambda name: calls.append(name) or '7.8.9-test'
import taintly
from taintly.models import AuditReport
from taintly.reporters.sarif import format_sarif
before = list(calls)
output = json.loads(format_sarif(AuditReport(repo_path='.', platform='github')))
after = list(calls)
format_sarif(AuditReport(repo_path='.', platform='github'))
print(json.dumps({'before': before, 'after': after, 'final': calls,
                  'version': output['runs'][0]['tool']['driver']['version']}))
""",
        cwd=tmp_path,
    )
    payload = __import__("json").loads(_assert_ok(result))
    assert payload == {
        "before": [],
        "after": ["taintly"],
        "final": ["taintly"],
        "version": "7.8.9-test",
    }


def test_sarif_observes_public_version_override(tmp_path: Path) -> None:
    result = _python(
        """
import json, taintly
taintly.__version__ = 'test-override'
from taintly.models import AuditReport
from taintly.reporters.sarif import format_sarif
output = json.loads(format_sarif(AuditReport(repo_path='.', platform='github')))
print(output['runs'][0]['tool']['driver']['version'])
""",
        cwd=tmp_path,
    )
    assert _assert_ok(result).strip() == "test-override"


@pytest.mark.parametrize("workers", [8])
def test_concurrent_first_version_access_resolves_once(tmp_path: Path, workers: int) -> None:
    result = _python(
        f"""
import importlib.metadata as metadata, json, threading, time
calls=[]
lock=threading.Lock()
def resolve(name):
    with lock: calls.append(name)
    time.sleep(0.03)
    return 'concurrent-test'
metadata.version = resolve
import taintly
barrier=threading.Barrier({workers})
values=[]
def read():
    barrier.wait()
    values.append(taintly.__version__)
threads=[threading.Thread(target=read) for _ in range({workers})]
[thread.start() for thread in threads]
[thread.join() for thread in threads]
print(json.dumps({{'calls': calls, 'values': values}}))
""",
        cwd=tmp_path,
    )
    payload = __import__("json").loads(_assert_ok(result))
    assert payload == {"calls": ["taintly"], "values": ["concurrent-test"] * workers}
