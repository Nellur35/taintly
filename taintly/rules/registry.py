"""Rule registry — auto-discovers and loads rules from rule modules.

Loads are platform-scoped where possible: ``load_rules_for_platform(p)``
imports only the rule modules under ``rules/<p>/``, which on a GitHub-
only repo skips the GitLab+Jenkins rule packs and shaves cold-start
cost.  ``load_all_rules()`` is kept for the org-wide audit and
``--self-test`` paths that genuinely need every rule loaded.
"""

from __future__ import annotations

import importlib
import sys
import traceback
from pathlib import Path

from taintly.models import Platform, Rule

# Module-level so both readers and writers share state.
_IMPORT_FAILURES: list[str] = []

# Platform → package-name segment used under taintly/rules/.
_PLATFORM_DIR: dict[Platform, str] = {
    Platform.GITHUB: "github",
    Platform.GITLAB: "gitlab",
    Platform.JENKINS: "jenkins",
}


def _discover_rules_in_package(package_path: str, package_name: str) -> list[Rule]:
    """Import all modules in a package and collect RULES lists.

    A rule module that fails to import is a real bug — silently
    dropping its rules produces a scanner that reports clean on files
    it should have flagged. We print the full traceback (not just the
    exception message) so the diagnostic is a copy-pasteable stack,
    and we track failures so the loader can escalate loudly.
    """
    rules: list[Rule] = []
    pkg_path = Path(package_path)

    if not pkg_path.is_dir():
        return rules

    for item in sorted(pkg_path.iterdir()):
        if item.suffix == ".py" and item.stem != "__init__" and not item.stem.startswith("_"):
            module_name = f"{package_name}.{item.stem}"
            try:
                mod = importlib.import_module(module_name)
                if hasattr(mod, "RULES"):
                    rules.extend(mod.RULES)
            except Exception:
                _IMPORT_FAILURES.append(module_name)
                print(
                    f"ERROR: Failed to load rule module {module_name} — "
                    f"its rules will NOT be applied to scanned files.\n"
                    f"{traceback.format_exc()}",
                    file=sys.stderr,
                )

    return rules


def load_rules_for_platform(platform: Platform) -> list[Rule]:
    """Load rules for ONE platform — does not import the others.

    This is the hot path for typical CI invocations.  Skipping unused
    platform rule packs is the primary cold-start optimisation; the
    GitLab and Jenkins rule packs together carry ~150 AI-family rules
    whose import cost is wasted on a GitHub-only repo.
    """
    _IMPORT_FAILURES.clear()
    base = Path(__file__).parent
    pkg_dir = _PLATFORM_DIR[platform]
    rules = _discover_rules_in_package(
        str(base / pkg_dir), f"taintly.rules.{pkg_dir}"
    )
    if _IMPORT_FAILURES:
        print(
            f"ERROR: {len(_IMPORT_FAILURES)} rule module(s) failed to load: "
            f"{_IMPORT_FAILURES}. Scanner coverage is degraded.",
            file=sys.stderr,
        )
    return rules


def load_all_rules() -> list[Rule]:
    """Load rules for every platform.

    Use the platform-specific loader when the platform is known; this
    is the fallback for ``--self-test``, multi-platform scans, and the
    org-wide audit modes.  Per-platform import failures don't cascade
    — each platform is loaded independently.
    """
    _IMPORT_FAILURES.clear()
    rules: list[Rule] = []
    for plat in (Platform.GITHUB, Platform.GITLAB, Platform.JENKINS):
        rules.extend(load_rules_for_platform(plat))
    return rules


def get_rule_by_id(rule_id: str) -> Rule | None:
    """Find a specific rule by ID. Loads all rules — slow path."""
    for r in load_all_rules():
        if r.id == rule_id:
            return r
    return None
