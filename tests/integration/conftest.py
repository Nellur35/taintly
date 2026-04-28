"""Shared fixtures for tests/integration/.

Currently exposes the rule-set loader as a session-scoped fixture so
both `test_grammar_oracle.py` and the EXT-C mutation tests
(`test_grammar_oracle_mutations.py`) reuse the same loaded list.
"""

from __future__ import annotations

import pytest

from taintly.models import AbsencePattern, ContextPattern, Rule
from taintly.rules.registry import load_all_rules


def _is_file_scope_absence_rule(rule: Rule) -> bool:
    """Does this rule fire on absence of whole-file context?

    See test_grammar_oracle.py for the full rationale; both shapes
    qualify (AbsencePattern, file-scope ContextPattern with
    requires_absent set).
    """
    if isinstance(rule.pattern, AbsencePattern):
        return True
    if isinstance(rule.pattern, ContextPattern):
        if rule.pattern.requires_absent and rule.pattern.scope == "file":
            return True
    return False


@pytest.fixture(scope="session")
def loaded_rules() -> list[Rule]:
    """All rules minus file-scope absence patterns, loaded once per session."""
    return [r for r in load_all_rules() if not _is_file_scope_absence_rule(r)]
