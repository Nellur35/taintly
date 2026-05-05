"""Light e2e harness for tests/playground/.

Walks every directory under ``tests/playground/fixtures/<platform>/<name>/``
that has an ``expect.json`` and asserts:

  * ``vulnerable/`` triggers the ``must_fire`` rule_ids and not the
    ``must_not_fire`` rule_ids.
  * ``fixed/`` (when present) does NOT trigger any of the
    ``must_not_fire`` rule_ids and matches its own ``must_fire``
    (usually empty for clean fixes; non-empty when the fix only
    addresses one of multiple findings on the file).

Each fixture is a real repo-shape directory (``.github/workflows/``,
``.gitlab-ci.yml``, ``Jenkinsfile``, optionally a top-level
``CLAUDE.md`` etc.) so taintly's normal file discovery applies.

Why subprocess vs direct API: the harness invokes ``python -m taintly``
the same way users do.  This catches CLI regressions (argparse changes,
exit-code drift, format selection) that an in-process call would miss.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).parent / "fixtures"
_TAINTLY_REPO = Path(__file__).resolve().parents[2]


def _discover_cases() -> list[tuple[Path, dict]]:
    """Yield ``(fixture_dir, expect_json)`` for every fixture with an
    ``expect.json``.  Pytest parametrization consumes this — keeping
    discovery simple makes adding a fixture a single-directory drop-in
    with no harness change."""
    cases: list[tuple[Path, dict]] = []
    if not _ROOT.exists():
        return cases
    for expect_path in sorted(_ROOT.rglob("expect.json")):
        try:
            spec = json.loads(expect_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            pytest.fail(f"Malformed expect.json at {expect_path}: {e}")
        cases.append((expect_path.parent, spec))
    return cases


def _run_taintly(target: Path, platform: str | None) -> dict:
    """Invoke taintly's CLI on ``target`` and parse JSON output.

    Returns the parsed report dict.  Raises ``pytest.fail`` on
    non-zero exit codes that aren't the expected "findings present"
    signal (exit 1) — anything else (2 = arg error, 11 = engine
    coverage degraded, 3 = config error) is a real failure.
    """
    cmd = [sys.executable, "-m", "taintly", str(target), "--format", "json"]
    if platform:
        cmd += ["--platform", platform]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=_TAINTLY_REPO,
        check=False,
        encoding="utf-8",
    )
    # Multiple exit codes are normal taintly outcomes (per README):
    #   0  — clean
    #   1  — HIGH findings present
    #   2  — CRITICAL findings present (or argparse error)
    #   11 — engine coverage degraded (still emitted JSON)
    # 3 means config error and is a real failure.  We discriminate by
    # asking whether stdout parsed as JSON: if yes, the scan produced
    # output regardless of exit code.  If no, it's a CLI/parser problem.
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(
            f"taintly exited {proc.returncode} and produced no parseable "
            f"JSON for {target}: {e}\n"
            f"stdout[:400]: {proc.stdout[:400]}\n"
            f"stderr[:400]: {proc.stderr[:400]}"
        )


def _fired_rule_ids(report: dict) -> set[str]:
    return {f.get("rule_id", "") for f in report.get("findings", [])}


def _check_expectation(
    target: Path,
    spec: dict,
    fired: set[str],
    label: str,
) -> None:
    """Assert ``fired`` matches ``spec`` (must_fire / must_not_fire /
    must_fire_any_of)."""
    must_fire = set(spec.get("must_fire", []))
    must_not_fire = set(spec.get("must_not_fire", []))
    any_of = set(spec.get("must_fire_any_of", []))

    missing = must_fire - fired
    if missing:
        pytest.fail(
            f"[{label}] {target}: rule(s) failed to fire: "
            f"{sorted(missing)}; got: {sorted(fired)}"
        )
    leaked = must_not_fire & fired
    if leaked:
        pytest.fail(
            f"[{label}] {target}: rule(s) fired but must NOT have: "
            f"{sorted(leaked)}; got: {sorted(fired)}"
        )
    if any_of and not (any_of & fired):
        pytest.fail(
            f"[{label}] {target}: none of the any-of rules fired: "
            f"expected at least one of {sorted(any_of)}; got: {sorted(fired)}"
        )


@pytest.mark.parametrize("fixture_dir,spec", _discover_cases(), ids=lambda x: getattr(x, "name", ""))
def test_vulnerable_fires_expected_rules(fixture_dir: Path, spec: dict) -> None:
    """The ``vulnerable/`` subtree of every fixture must fire the
    rule(s) named in expect.json's ``vulnerable.must_fire``."""
    target = fixture_dir / "vulnerable"
    if not target.exists():
        pytest.skip(f"no vulnerable/ subtree at {target}")
    platform = spec.get("platform")
    report = _run_taintly(target, platform)
    _check_expectation(target, spec.get("vulnerable", {}), _fired_rule_ids(report), "vulnerable")


@pytest.mark.parametrize("fixture_dir,spec", _discover_cases(), ids=lambda x: getattr(x, "name", ""))
def test_fixed_does_not_regress(fixture_dir: Path, spec: dict) -> None:
    """The ``fixed/`` subtree (when present) must satisfy expect.json's
    ``fixed`` block — typically empty must_fire and the rule that fired
    on vulnerable/ now under must_not_fire."""
    target = fixture_dir / "fixed"
    if not target.exists():
        pytest.skip(f"no fixed/ subtree at {target}")
    platform = spec.get("platform")
    report = _run_taintly(target, platform)
    _check_expectation(target, spec.get("fixed", {}), _fired_rule_ids(report), "fixed")


def test_at_least_one_fixture_per_platform() -> None:
    """Smoke check: at least one fixture for each platform we ship
    rules on.  Forces playground coverage to grow with the rule pack
    (someone adding 60 new GL rules without any GL fixture is a smell)."""
    cases = _discover_cases()
    assert cases, "tests/playground/fixtures is empty — at least one fixture required"
    platforms = {spec.get("platform") for _, spec in cases}
    for required in ("github", "gitlab", "jenkins"):
        assert required in platforms, (
            f"no playground fixture for platform '{required}'; "
            f"add one under tests/playground/fixtures/{required}/"
        )
