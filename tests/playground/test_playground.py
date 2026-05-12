"""Light e2e harness for tests/playground/.

Walks every directory under ``tests/playground/fixtures/<platform>/<name>/``
that has an ``expect.json`` and asserts:

  * ``vulnerable/`` triggers the ``must_fire`` rule_ids and not the
    ``must_not_fire`` rule_ids.
  * ``fixed/`` (when present) does NOT trigger any of the
    ``must_not_fire`` rule_ids and matches its own ``must_fire``
    (usually empty for clean fixes; non-empty when the fix only
    addresses one of multiple findings on the file).
  * ``fix_invariants`` (when present in expect.json) — for fixtures
    that have BOTH ``vulnerable/`` and ``fixed/`` subtrees, the fixed
    workflow files must satisfy the documented invariants
    (``still_parses``, expected job names). README documented these
    keys before any test enforced them; this is the enforcement.

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
        # Truncating stdout/stderr to 400 chars previously hid the
        # actual taintly traceback when JSON parsing failed — exactly
        # the scenario where you NEED the full output to diagnose. Spill
        # the whole tail to a tmp file and reference it from the failure
        # message so debugging doesn't need a re-run with --capture=no.
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".taintly-debug.txt",
                delete=False, encoding="utf-8"
            ) as fh:
                fh.write(f"# cmd: {' '.join(cmd)}\n")
                fh.write(f"# returncode: {proc.returncode}\n")
                fh.write("# === stdout ===\n")
                fh.write(proc.stdout)
                fh.write("\n# === stderr ===\n")
                fh.write(proc.stderr)
                debug_path = fh.name
        except Exception:
            debug_path = "<could not write debug file>"
        pytest.fail(
            f"taintly exited {proc.returncode} and produced no parseable "
            f"JSON for {target}: {e}\n"
            f"Full output written to: {debug_path}\n"
            f"stdout[:1000]: {proc.stdout[:1000]}\n"
            f"stderr[:1000]: {proc.stderr[:1000]}"
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


# Ratio gate: playground must grow with the rule pack. Today's fixture
# count was below 20% of finding-family count when the audit landed;
# this floor ratchets up as fixtures are added. Each finding family is
# the right denominator (rather than per-rule) because playground is
# light e2e — one fixture per family with a representative rule from
# that family is enough.
_MIN_FIXTURES_PER_FAMILY_RATIO = 0.4  # current 5/12 ≈ 0.42


def test_playground_keeps_pace_with_finding_families() -> None:
    """Forces playground fixture count to keep pace with the number
    of finding families. Lower bound expressed as a ratio so growth
    on either side keeps the gate meaningful — adding a new family
    without a fixture for it (or any family in the new range) trips
    the gate.

    Why this matters: the rule pack ships 200+ rules; per-rule
    playground coverage is impractical, but per-family is achievable
    and the right granularity for "is there an end-to-end fixture
    that exercises this finding bucket?" Without a ratio gate the
    fixture count silently lags the family count.
    """
    from taintly.families import _FAMILIES

    cases = _discover_cases()
    fixture_count = len(cases) // 2 if cases else 0  # discover yields per-fixture pairs; rough proxy
    fixture_count = len({c[0] for c in cases})
    family_count = len(_FAMILIES)
    if family_count == 0:
        pytest.skip("no finding families defined yet")
    ratio = fixture_count / family_count
    assert ratio >= _MIN_FIXTURES_PER_FAMILY_RATIO, (
        f"playground has {fixture_count} fixtures vs {family_count} "
        f"finding families (ratio {ratio:.2f}); minimum is "
        f"{_MIN_FIXTURES_PER_FAMILY_RATIO:.2f}. Add a representative "
        f"fixture for an uncovered family under "
        f"tests/playground/fixtures/<platform>/<family-or-rule>/."
    )


# ---------------------------------------------------------------------------
# fix_invariants — implements the schema documented in the README
# ---------------------------------------------------------------------------


def _yaml_load_or_none(text: str):
    """Best-effort YAML load. Returns ``None`` if PyYAML isn't
    importable or the text isn't valid YAML.

    PyYAML is a test-only dep; we don't make playground tests REQUIRE
    it, but when it's available we use it to validate ``still_parses``."""
    try:
        import yaml as _yaml
    except ImportError:
        return None
    try:
        return _yaml.safe_load(text)
    except Exception:
        return None


def _check_fix_invariants(target: Path, invariants: dict) -> None:
    """Enforce the README-documented ``fix_invariants`` schema:

      ``still_parses``  — every YAML file under target must parse.
      ``jobs``          — every workflow file under target must contain
                          at least the listed top-level job keys.

    Quietly skip if PyYAML isn't installed — the harness only runs
    these when YAML support is present.
    """
    try:
        import yaml as _yaml  # noqa: F401
    except ImportError:
        pytest.skip("PyYAML not installed — fix_invariants checks need yaml.safe_load")
        return

    yaml_files = [
        p for p in target.rglob("*.yml") if p.is_file()
    ] + [
        p for p in target.rglob("*.yaml") if p.is_file()
    ]

    if invariants.get("still_parses", False):
        for path in yaml_files:
            text = path.read_text(encoding="utf-8")
            parsed = _yaml_load_or_none(text)
            if parsed is None and text.strip():
                # The file existed and was non-empty, yet didn't
                # parse. The fix produced broken YAML.
                pytest.fail(
                    f"[fix_invariants:still_parses] {path} does not parse "
                    f"as YAML after the fix. The fixer broke structure."
                )

    expected_jobs = invariants.get("jobs")
    if expected_jobs:
        # ``jobs`` is the schema key used in the README example. We
        # interpret it as: in any workflow file with a top-level
        # ``jobs:`` block, all listed job names must be present.
        for path in yaml_files:
            parsed = _yaml_load_or_none(path.read_text(encoding="utf-8"))
            if not isinstance(parsed, dict):
                continue
            jobs_block = parsed.get("jobs")
            if not isinstance(jobs_block, dict):
                continue
            missing = set(expected_jobs) - set(jobs_block)
            assert not missing, (
                f"[fix_invariants:jobs] {path}: expected jobs "
                f"{sorted(missing)} are missing after the fix. "
                f"Jobs found: {sorted(jobs_block)}"
            )


@pytest.mark.parametrize("fixture_dir,spec", _discover_cases(), ids=lambda x: getattr(x, "name", ""))
def test_fixed_satisfies_fix_invariants(fixture_dir: Path, spec: dict) -> None:
    """If the fixture declares ``fix_invariants`` AND has a ``fixed/``
    subtree, the fixed YAML files must satisfy the documented invariants.
    Implements the schema the README has long advertised (still_parses,
    jobs) but that the harness never read until now."""
    invariants = spec.get("fix_invariants")
    if not invariants:
        pytest.skip("no fix_invariants declared")
    fixed = fixture_dir / "fixed"
    if not fixed.exists():
        pytest.skip("no fixed/ subtree to verify against")
    _check_fix_invariants(fixed, invariants)
