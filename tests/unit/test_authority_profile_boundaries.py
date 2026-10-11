"""Refuse authority conclusions across incomplete context boundaries."""

import pytest

from taintly.authority_context import calibrate_lotp_authority
from taintly.models import Finding, Severity

_BASE = """on: pull_request_target
permissions: {contents: write}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: true
      - run: npm ci
"""


def _calibrated(content):
    finding = Finding(
        rule_id="LOTP-GH-001",
        severity=Severity.CRITICAL,
        title="build",
        description="candidate",
        file="workflow.yml",
        exploitability="high",
        line=next(i for i, s in enumerate(content.splitlines(), 1) if "npm ci" in s),
    )
    calibrate_lotp_authority([finding], content)
    return finding


@pytest.mark.parametrize(
    "old,new",
    [
        ("permissions: {contents: write}", "permissions: {}"),
        ("permissions: {contents: write}", "permissions: {id-token: write}"),
        ("permissions: {contents: write}", "permissions: {future-permission: write}"),
        ("permissions: {contents: write}", "permissions: null"),
        ("permissions: {contents: write}", "permissions: [write]"),
        ("jobs:", "env: ${{ fromJSON(inputs.environment) }}\njobs:"),
        ("    steps:", "    env: ${{ fromJSON(inputs.environment) }}\n    steps:"),
        (
            "      - run: npm ci",
            "      - run: npm ci\n        env: ${{ fromJSON(inputs.environment) }}",
        ),
        ("    steps:", "    container: ubuntu:latest\n    steps:"),
        (
            "      - run: npm ci",
            "      - run: npm ci\n        working-directory: ${{ inputs.path }}",
        ),
        ("      - run: npm ci", "      - run: |\n          unset GH_TOKEN\n          npm ci"),
        ("      - run: npm ci", "      - run: rm credentials; npm ci"),
        ("actions/checkout@v4", "actions/checkout@v99"),
        ("actions/checkout@v4", "actions/checkout@v4.99.99"),
        ("      - run: npm ci", "      - run: npm ci\n        shell: custom-sandbox {0}"),
        ("    runs-on:", "    if: inputs.run_build\n    runs-on:"),
    ],
)
def test_incomplete_links_remain_unresolved(old, new):
    finding = _calibrated(_BASE.replace(old, new))
    assert "authority-unresolved" in finding.context_tags
    assert finding.review_needed
    assert finding.exploitability == "medium"
    assert finding.severity == Severity.CRITICAL


def test_profile_budgets_never_prove_limited_or_elevated_authority(monkeypatch):
    import taintly.authority_context as authority

    for name in ["_MAX_PROFILE_EVENTS", "_MAX_PROFILE_STEPS"]:
        with monkeypatch.context() as patch:
            patch.setattr(authority, name, 1)
            finding = _calibrated(_BASE)
            assert "authority-unresolved" in finding.context_tags
            assert finding.review_needed


def test_unrelated_findings_are_untouched():
    finding = _calibrated(_BASE)
    finding.rule_id = "OTHER-GH-001"
    before = finding.to_dict()
    calibrate_lotp_authority([finding], _BASE)
    assert finding.to_dict() == before


@pytest.mark.parametrize("addition", [
    "    strategy:\n      matrix: ${{ fromJSON(vars.CREDENTIAL_MATRIX) }}\n",
    "    services:\n      db:\n        image: postgres:16\n        env:\n          POSTGRES_PASSWORD: ${{ secrets.DB_PASSWORD }}\n",
])
def test_unresolved_matrix_and_service_credentials_prevent_limited(addition):
    safe = _BASE.replace("pull_request_target", "pull_request").replace("contents: write", "contents: read").replace("persist-credentials: true", "persist-credentials: false")
    content = safe.replace("    steps:", addition + "    steps:")
    if "matrix:" in addition:
        content += "        env:\n          CREDENTIAL: ${{ matrix.credential }}\n"
    finding = _calibrated(content)
    assert "authority-unresolved" in finding.context_tags


def test_v7_ordinary_pr_does_not_infer_privileged_checkout_block():
    safe = _BASE.replace("pull_request_target", "pull_request").replace("contents: write", "contents: read").replace("persist-credentials: true", "persist-credentials: false").replace("checkout@v4", "checkout@v7")
    finding = _calibrated(safe)
    assert "authority-limited" in finding.context_tags
    assert not any("blocks privileged" in note for note in finding.context_notes)
