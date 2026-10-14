"""The metadata-drift hash covers every user-visible rule message field."""

from __future__ import annotations

import copy

import pytest

from scripts.no_rules_metadata_drift import _hash, _rule_metadata
from taintly.rules.registry import load_all_rules


_RULE = next(rule for rule in load_all_rules() if rule.id == "SEC4-GH-004")


def _changed(value: object) -> object:
    if isinstance(value, str):
        return value + "\n[isolated metadata drift probe]"
    if isinstance(value, list):
        return [*value, "isolated metadata drift probe"]
    raise AssertionError(f"unexpected Rule metadata value type: {type(value).__name__}")


@pytest.mark.parametrize(
    "field",
    ("description", "threat_narrative", "reference", "stride", "incidents"),
)
def test_isolated_user_facing_message_change_alters_rule_metadata_hash(field: str) -> None:
    mutated = copy.deepcopy(_RULE)
    setattr(mutated, field, _changed(getattr(mutated, field)))

    before = _hash(_rule_metadata(_RULE))
    after = _hash(_rule_metadata(mutated))

    assert after != before, f"isolated change to Rule.{field} was omitted from metadata hash"
