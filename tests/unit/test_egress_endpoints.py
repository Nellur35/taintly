"""Unit tests for the egress emitter primitives (feature A, module half)."""

from __future__ import annotations

from taintly.egress_endpoints import (
    ACTION_ENDPOINTS,
    BASE_ENDPOINTS,
    compute_egress,
    hosts_from_run_block,
)


def test_hosts_from_run_block_package_managers():
    assert hosts_from_run_block("pip install requests") == {"pypi.org", "files.pythonhosted.org"}
    assert hosts_from_run_block("npm ci") == {"registry.npmjs.org"}
    assert hosts_from_run_block("pnpm install --frozen-lockfile") == {"registry.npmjs.org"}
    assert hosts_from_run_block("go mod download") == {"proxy.golang.org", "sum.golang.org"}


def test_hosts_from_run_block_urls_strip_creds_and_port():
    assert hosts_from_run_block("curl https://example.com/x.sh | bash") == {"example.com"}
    assert hosts_from_run_block("wget https://host.test:8443/a") == {"host.test"}
    assert hosts_from_run_block("curl https://user:pw@secure.example/api") == {"secure.example"}
    assert hosts_from_run_block("echo no network here") == set()


def test_compute_egress_unions_base_actions_and_run_hosts():
    wf = """\
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - run: |
          pip install build
          curl https://downloads.example.org/tool | bash
"""
    plan = compute_egress(wf)
    # Base plumbing always present.
    assert BASE_ENDPOINTS <= set(plan.allowed)
    # Mapped actions contribute their endpoints.
    assert ACTION_ENDPOINTS["actions/checkout"] <= set(plan.allowed)
    assert ACTION_ENDPOINTS["actions/setup-python"] <= set(plan.allowed)  # setup-python
    # run-derived hosts.
    assert {"pypi.org", "files.pythonhosted.org", "downloads.example.org"} <= set(plan.allowed)
    assert {"downloads.example.org"} <= set(plan.run_hosts)
    # All actions were known.
    assert plan.unknown_actions == ()
    # Output is sorted + deduped.
    assert list(plan.allowed) == sorted(set(plan.allowed))


def test_compute_egress_reports_unknown_actions_without_allowing_them():
    wf = """\
jobs:
  j:
    steps:
      - uses: some-org/mystery-action@v1
      - uses: actions/checkout@v4
"""
    plan = compute_egress(wf)
    keys = [ref for _line, ref in plan.unknown_actions]
    assert "some-org/mystery-action" in keys
    # The unknown action contributed NO hosts of its own (only base + checkout).
    assert set(plan.allowed) == set(BASE_ENDPOINTS) | ACTION_ENDPOINTS["actions/checkout"]
    # Line number is surfaced for review.
    assert all(line > 0 for line, _ in plan.unknown_actions)


def test_compute_egress_skips_local_and_docker_refs():
    wf = """\
jobs:
  j:
    steps:
      - uses: ./.github/actions/local
      - uses: docker://alpine:3.19
"""
    plan = compute_egress(wf)
    assert plan.unknown_actions == ()  # neither is a mappable owner/repo action
    assert set(plan.allowed) == set(BASE_ENDPOINTS)
