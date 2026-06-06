"""SARIF 2.1.0 schema-conformance gate (Domain 6 / §8.3 serialization).

taintly emits SARIF that GitHub Advanced Security ingests — a serialization
contract.  The existing reporter tests assert individual fields and pin a
snapshot, but neither proves the document *conforms to the SARIF schema*:
a structural violation in an unchecked region would ship green and GHAS
would silently discard the run (the tool looks like it ran, but no findings
reach the security tab).  This gate closes that hole.

Uses an embedded minimal subset of the 2.1.0 schema covering the structural
invariants GHAS actually requires to ingest a run — self-contained, so no
schema file needs vendoring or fetching.  Degrades safely (skips) if
``jsonschema`` is not installed.
"""

from __future__ import annotations

import json

import pytest

from taintly.reporters.sarif import format_sarif

_SARIF_210_MINIMAL_SCHEMA = {
    "type": "object",
    "required": ["version", "runs"],
    "properties": {
        "version": {"const": "2.1.0"},
        "$schema": {"type": "string"},
        "runs": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["tool", "results"],
                "properties": {
                    "tool": {
                        "type": "object",
                        "required": ["driver"],
                        "properties": {
                            "driver": {
                                "type": "object",
                                "required": ["name", "rules"],
                                "properties": {
                                    "name": {"type": "string"},
                                    "version": {"type": "string"},
                                    "rules": {"type": "array"},
                                },
                            }
                        },
                    },
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["ruleId", "message", "locations"],
                            "properties": {
                                "ruleId": {"type": "string"},
                                "level": {"enum": ["none", "note", "warning", "error"]},
                                "message": {"type": "object", "required": ["text"]},
                                "locations": {"type": "array", "minItems": 1},
                            },
                        },
                    },
                },
            },
        },
    },
}


def test_sarif_conforms_to_2_1_0_schema(one_report):
    """Emitted SARIF must validate against the 2.1.0 schema, not merely
    carry the right field values."""
    jsonschema = pytest.importorskip("jsonschema")
    sarif = json.loads(format_sarif(one_report))
    jsonschema.validate(instance=sarif, schema=_SARIF_210_MINIMAL_SCHEMA)


def test_empty_report_sarif_conforms(empty_report):
    """An empty run (zero findings) must still be schema-valid — GHAS
    rejects a malformed empty document the same as a populated one."""
    jsonschema = pytest.importorskip("jsonschema")
    sarif = json.loads(format_sarif(empty_report))
    jsonschema.validate(instance=sarif, schema=_SARIF_210_MINIMAL_SCHEMA)


def test_sarif_results_locations_are_well_formed(one_report):
    """Every result needs at least one location — the part GHAS uses to
    attach a finding to a file. A result with an empty locations array is
    silently dropped."""
    sarif = json.loads(format_sarif(one_report))
    for result in sarif["runs"][0]["results"]:
        assert result.get("locations"), f"result {result.get('ruleId')} has no locations"


def test_schema_gate_actually_rejects_malformed_sarif():
    """Guard the guard: a structurally-invalid SARIF must fail validation,
    proving the gate has teeth (not a no-op schema)."""
    jsonschema = pytest.importorskip("jsonschema")
    broken = {"version": "2.1.0", "runs": [{"tool": {}}]}  # missing driver + results
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=broken, schema=_SARIF_210_MINIMAL_SCHEMA)
