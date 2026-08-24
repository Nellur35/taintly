"""Regression tests for honest mutation-gap accounting."""

from __future__ import annotations

import json

from taintly.testing.self_test import TestResult as SelfTestResult
from taintly.testing.self_test import format_test_results_json


def test_known_survivor_is_not_reported_as_a_kill() -> None:
    payload = format_test_results_json(
        [],
        [
            SelfTestResult(
                rule_id="TST-GH-001",
                test_type="mutation_positive",
                sample="run:  echo hi",
                expected="trigger",
                actual="no_trigger",
                passed=True,
                mutation_op="whitespace_pad",
                known_gap=True,
            )
        ],
    )

    data = json.loads(payload)
    mutation = data["mutation"]
    assert data["schema_version"] == 2
    assert mutation["killed"] == 0
    assert mutation["known_gaps"] == 1
    assert mutation["unexpected_survivors"] == 0
    assert mutation["raw_kill_rate"] == 0.0
    assert len(mutation["known_gap_survivors"]) == 1
