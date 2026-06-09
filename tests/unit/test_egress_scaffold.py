"""Golden tests for the egress allow-list scaffold fix (feature A, fix half)."""

from __future__ import annotations

from taintly.egress_endpoints import compute_egress
from taintly.fixes import ALL_FIXERS, OPT_IN_FIXERS, fix_egress_allowlist_scaffold

_WF = """\
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install build
"""


def test_scaffold_injects_harden_runner_in_audit_mode(tmp_path):
    p = tmp_path / "wf.yml"
    p.write_text(_WF, encoding="utf-8")
    results = fix_egress_allowlist_scaffold(str(p), dry_run=False)
    assert results
    assert results[0].applied
    out = p.read_text(encoding="utf-8")
    assert "step-security/harden-runner" in out
    assert "egress-policy: audit" in out  # audit, never block — review-first
    assert "allowed-endpoints: >" in out
    # Every computed endpoint is rendered.  Assert via the computed hosts (an
    # f-string with a variable), not a host-literal ``in out`` — the latter trips
    # CodeQL's py/incomplete-url-substring-sanitization query.
    rendered = compute_egress(_WF).allowed
    assert rendered
    for host in rendered:
        assert f"{host}:443" in out
    # The scaffold is the FIRST step (before the existing checkout).
    assert out.index("harden-runner") < out.index("actions/checkout")
    # The action is intentionally left unpinned for the user to SHA-pin.
    assert "pin to a SHA before use" in out


def test_scaffold_dry_run_does_not_modify(tmp_path):
    p = tmp_path / "wf.yml"
    p.write_text(_WF, encoding="utf-8")
    results = fix_egress_allowlist_scaffold(str(p), dry_run=True)
    assert results
    assert not results[0].applied
    assert p.read_text(encoding="utf-8") == _WF  # file untouched in dry-run


def test_scaffold_is_idempotent_and_respects_existing(tmp_path):
    p = tmp_path / "wf.yml"
    p.write_text(_WF, encoding="utf-8")
    fix_egress_allowlist_scaffold(str(p), dry_run=False)
    # Second run: harden-runner is now present -> no-op (don't layer a second).
    assert fix_egress_allowlist_scaffold(str(p), dry_run=False) == []


def test_scaffold_is_opt_in_only():
    assert "egress_allowlist_scaffold" in OPT_IN_FIXERS
    assert "egress_allowlist_scaffold" not in ALL_FIXERS  # never runs by default


def test_unknown_action_is_a_comment_not_an_endpoint(tmp_path):
    wf = _WF.replace(
        "      - run: pip install build",
        "      - uses: some-org/unmapped-action@v1\n      - run: pip install build",
    )
    p = tmp_path / "wf.yml"
    p.write_text(wf, encoding="utf-8")
    fix_egress_allowlist_scaffold(str(p), dry_run=False)
    out = p.read_text(encoding="utf-8")
    assert "# UNRECOGNIZED" in out
    assert "some-org/unmapped-action" in out
    # The note is a real comment BEFORE the endpoints block, never folded into it.
    assert out.index("# UNRECOGNIZED") < out.index("allowed-endpoints:")
    # The scaffolded YAML still parses (no structural cutoff).
    from taintly.parsers.structural import EventKind, walk_workflow

    assert not [
        e for e in walk_workflow(str(p), content=out, recover=True) if e.kind is EventKind.CUTOFF
    ]
