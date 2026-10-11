"""Real-workflow fixture pair for SEC6-GH-015."""

from pathlib import Path

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform

RULE_ID = "SEC6-GH-015"
FIXTURES = Path(__file__).parent.parent / "fixtures" / "github" / "secret_cache"


def test_secret_cache_unsafe_and_safe_fixture_pair() -> None:
    rules = load_rules_for_platform(Platform.GITHUB)
    unsafe = scan_file(str(FIXTURES / "unsafe.yml"), rules)
    safe = scan_file(str(FIXTURES / "safe.yml"), rules)

    assert any(finding.rule_id == RULE_ID for finding in unsafe)
    assert not any(finding.rule_id == RULE_ID for finding in safe)
