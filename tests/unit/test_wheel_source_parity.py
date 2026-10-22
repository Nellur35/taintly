"""Packaging gate compares the bytes users install with tracked source."""

from __future__ import annotations

import importlib.util
import subprocess
import zipfile
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts/check_wheel_source_parity.py"
_SPEC = importlib.util.spec_from_file_location("check_wheel_source_parity", _SCRIPT)
assert _SPEC
assert _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
check_wheel = _MODULE.check_wheel


def _source_and_wheel(
    tmp_path: Path,
    *,
    payload: bytes = b"source",
    extra_file: bool = False,
    mandatory_dependency: bool = False,
) -> tuple[Path, Path]:
    source = tmp_path / "source"
    package = source / "taintly"
    package.mkdir(parents=True)
    (package / "__init__.py").write_bytes(b"source")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "add", "taintly/__init__.py"], cwd=source, check=True)
    wheel = tmp_path / "taintly-1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("taintly/__init__.py", payload)
        if extra_file:
            archive.writestr("taintly/extra.py", b"unexpected")
        metadata = "Metadata-Version: 2.1\nName: taintly\n"
        if mandatory_dependency:
            metadata += "Requires-Dist: requests>=2\n"
        archive.writestr("taintly-1.dist-info/METADATA", metadata)
    return source, wheel


def test_matching_wheel_passes(tmp_path):
    source, wheel = _source_and_wheel(tmp_path)
    assert check_wheel(source, wheel) == []


def test_stale_build_bytes_fail(tmp_path):
    source, wheel = _source_and_wheel(tmp_path, payload=b"stale build output")
    assert "Wheel bytes differ from source: taintly/__init__.py" in check_wheel(source, wheel)


def test_untracked_wheel_file_and_mandatory_dependency_fail(tmp_path):
    source, wheel = _source_and_wheel(tmp_path, extra_file=True, mandatory_dependency=True)
    errors = check_wheel(source, wheel)
    assert "Wheel contains untracked Taintly file: taintly/extra.py" in errors
    assert "Wheel declares a mandatory dependency: requests>=2" in errors
