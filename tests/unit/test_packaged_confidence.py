"""Confidence calibration must not depend on a source checkout's tests tree."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from taintly import families
from taintly.rules.registry import load_all_rules


def test_runtime_only_install_preserves_all_rule_defaults(tmp_path):
    site = tmp_path / "site"
    source = Path(families.__file__).parent
    shutil.copytree(source, site / "taintly", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    rule_ids = sorted({r.id for r in load_all_rules()} | {"BRAND-NEW-GH-99999"})
    probe = """
import json, sys
sys.path.insert(0, sys.argv[1])
from taintly import families
from taintly.rules.registry import load_all_rules
ids = sorted({r.id for r in load_all_rules()} | {'BRAND-NEW-GH-99999'})
print(json.dumps({rid: families.default_confidence(rid) for rid in ids}))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", probe, str(site)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout) == {rid: families.default_confidence(rid) for rid in rule_ids}
    assert not (site / "tests").exists()


def test_sibling_tests_cannot_supply_runtime_confidence(tmp_path, monkeypatch):
    package = tmp_path / "taintly"
    asset = package / "data" / "confidence_grandfather_baseline.json"
    legacy = tmp_path / "tests" / "_confidence_grandfather_baseline.json"
    legacy.parent.mkdir()
    legacy.write_text('["BRAND-NEW-GH-99999"]', encoding="utf-8")
    monkeypatch.setattr(families, "_GRANDFATHER_BASELINE_PATH", asset)
    assert families._load_grandfather_baseline() == frozenset()


@pytest.mark.parametrize("content", [None, "{broken", "{}"])
def test_missing_or_invalid_asset_retains_safe_fallback(tmp_path, monkeypatch, content):
    asset = tmp_path / "missing.json"
    if content is not None:
        asset.write_text(content, encoding="utf-8")
    monkeypatch.setattr(families, "_GRANDFATHER_BASELINE_PATH", asset)
    assert families._load_grandfather_baseline() == frozenset()
