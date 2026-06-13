"""Tests for the P3.6 confidence-grandfather advisory gate.

The gate (``scripts/check_confidence_grandfather.py``) must:
  * stay advisory — never fail the build (always exit 0), and
  * flag a NEW rule that has no explicit confidence and is not in the
    baseline, telling the author it defaults to MEDIUM until validated, while
  * staying silent for the current pack (every rule is overridden,
    grandfathered, or carries an explicit confidence).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
_GATE = _ROOT / "scripts" / "check_confidence_grandfather.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("_confidence_grandfather_gate", _GATE)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_gate_is_advisory_and_clean_on_current_pack(capsys):
    """On the shipped pack the gate reports clean and exits 0 (advisory)."""
    gate = _load_gate()
    rc = gate.main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "no un-validated new rules" in out.lower()


def test_gate_flags_a_synthetic_new_rule(monkeypatch, capsys):
    """A new rule with no explicit confidence + not in the baseline is flagged
    as defaulting to MEDIUM — and the gate still exits 0.
    """
    gate = _load_gate()
    from taintly.models import Platform, Rule, Severity
    from taintly.rules import registry

    new_rule = Rule(
        id="BRAND-NEW-GH-99999",
        title="synthetic new rule",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description="",
        pattern=None,  # type: ignore[arg-type]  # gate never evaluates the pattern
        remediation="",
        reference="",
        # No explicit confidence= → relies on the default → should be flagged.
    )

    real_loader = registry.load_all_rules

    def _patched():
        return [*real_loader(), new_rule]

    # The gate imports load_all_rules inside its functions, so patch the source.
    monkeypatch.setattr(registry, "load_all_rules", _patched)

    rc = gate.main([])
    out = capsys.readouterr().out
    assert rc == 0  # advisory — never blocks
    assert "BRAND-NEW-GH-99999" in out
    assert "medium" in out.lower()


def test_gate_does_not_flag_explicit_confidence_new_rule(monkeypatch, capsys):
    """A new rule that sets an explicit confidence= is a deliberate call and
    must NOT be flagged (only default-reliant new rules are advisory).
    """
    gate = _load_gate()
    from taintly.models import Platform, Rule, Severity
    from taintly.rules import registry

    new_rule = Rule(
        id="BRAND-NEW-GH-88888",
        title="synthetic new rule with explicit confidence",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description="",
        pattern=None,  # type: ignore[arg-type]  # gate never evaluates the pattern
        remediation="",
        reference="",
        confidence="low",
    )

    real_loader = registry.load_all_rules
    monkeypatch.setattr(registry, "load_all_rules", lambda: [*real_loader(), new_rule])

    rc = gate.main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "BRAND-NEW-GH-88888" not in out
