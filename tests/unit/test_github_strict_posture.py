"""Validate the selected advisory rules through the actual CLI."""

import json
import subprocess
import sys
from pathlib import Path

from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform

ROOT = Path(__file__).resolve().parents[2]
PIN = "SEC3-GH-001B"
CHECKOUT = "SEC4-GH-005C"
MORE_SPECIFIC = {"SEC4-GH-005", "SEC4-GH-005B"}
HEADER = "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n"


def _workflow(repo: Path, body: str) -> Path:
    path = repo / ".github" / "workflows" / "ci.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(HEADER + body, encoding="utf-8")
    return path


def _run(repo: Path, *args: str):
    return subprocess.run(
        [
            sys.executable,
            "-X",
            "utf8",
            "-m",
            "taintly",
            str(repo),
            "--no-config",
            "--format",
            "json",
            *args,
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
        check=False,
    )


def test_advisories_require_opt_in_and_respect_explicit_gate(tmp_path):
    _workflow(
        tmp_path,
        "      - uses: actions/checkout@" + "a" * 40 + "\n"
        "      - {uses: github/codeql-action/init@v3}\n"
        "      - uses: actions/setup-python@" + "b" * 40 + "\n"
        "        with:\n"
        "          uses: actions/setup-python@v5\n"
        "      - run: |\n"
        "          printf '%s\\n' 'uses: actions/setup-python@v5'\n"
        "      - uses: actions/checkout@" + "b" * 40 + "\n"
        "        with: {persist-credentials: false}\n",
    )
    default = _run(tmp_path)
    selected = _run(tmp_path, "--github-strict-posture")
    before = json.loads(default.stdout)
    after = json.loads(selected.stdout)
    extra = [f for f in after["findings"] if f["rule_id"] in {PIN, CHECKOUT}]
    assert {(f["rule_id"], f["line"]) for f in extra} == {(CHECKOUT, 8), (PIN, 9)}
    assert all(f["severity"] == "INFO" and f["review_needed"] for f in extra)
    assert [f for f in after["findings"] if f not in extra] == before["findings"]
    assert default.returncode == selected.returncode == 0
    gate = ["--fail-on", "INFO"]
    for rule_id in {f["rule_id"] for f in before["findings"]}:
        gate.extend(("--exclude-rule", rule_id))
    assert _run(tmp_path, *gate).returncode == 0
    assert _run(tmp_path, "--github-strict-posture", *gate).returncode == 1
    assert _run(tmp_path, "--github-strict-posture", "--review-advisory", *gate).returncode == 0
    assert {rule.id for rule in load_rules_for_platform(Platform.GITHUB)}.isdisjoint(
        {PIN, CHECKOUT}
    )


def test_unresolved_owning_input_preserves_a_separate_advisory(tmp_path):
    _workflow(
        tmp_path,
        "      - uses: actions/checkout@" + "a" * 40 + "\n"
        "        with: {persist-credentials: ${{ inputs.keep }}}\n"
        "      - uses: actions/checkout@" + "b" * 40 + "\n"
        "        with: {persist-credentials: true}\n"
        "      - uses: actions/checkout@" + "c" * 40 + "\n"
        "        with:\n"
        "          persist-credentials: true\n"
        "          persist-credentials: false\n",
    )
    result = _run(tmp_path, "--github-strict-posture")
    payload = json.loads(result.stdout)
    assert [(f["rule_id"], f["line"]) for f in payload["findings"] if f["rule_id"] == CHECKOUT] == [
        (CHECKOUT, 10)
    ]
    assert b"Rule SEC4-GH-005C returned incomplete" in result.stderr
    assert any(
        f["rule_id"] == "ENGINE-ERR" and "owning configuration at line 8" in f["description"]
        for f in payload["findings"]
    )
    assert result.returncode == 11


def test_specific_checkout_finding_takes_precedence(tmp_path):
    _workflow(
        tmp_path,
        "      - uses: actions/checkout@" + "a" * 40 + "\n      - run: git push origin example\n",
    )
    result = _run(tmp_path, "--github-strict-posture")
    findings = json.loads(result.stdout)["findings"]
    assert {f["rule_id"] for f in findings} & (MORE_SPECIFIC | {CHECKOUT}) == {"SEC4-GH-005"}


def test_source_bound_lock_takes_precedence_over_mutable_ref(tmp_path):
    workflow = _workflow(tmp_path, "      - uses: actions/setup-python@v5\n")
    lock = workflow.with_name("actions.lock")
    lock.write_text(
        "version: v0.0.2\nworkflows:\n  '.github/workflows/ci.yml':\n"
        "    - 'actions/setup-python@v5'\ndependencies:\n"
        "  'actions/setup-python@v5':\n"
        "    ref: v5\n    commit: sha1-" + "a" * 40 + "\n    owner_id: 11\n    repo_id: 22\n",
        encoding="utf-8",
    )
    result = _run(tmp_path, "--github-strict-posture")
    assert PIN not in {f["rule_id"] for f in json.loads(result.stdout)["findings"]}
    lock.write_text(
        lock.read_text(encoding="utf-8").replace("ref: v5", "ref: v4"), encoding="utf-8"
    )
    result = _run(tmp_path, "--github-strict-posture")
    assert PIN in {f["rule_id"] for f in json.loads(result.stdout)["findings"]}


def test_uncertain_reference_keeps_other_owning_reference(tmp_path):
    _workflow(
        tmp_path,
        "      - uses: actions/setup-python@${{ vars.PYTHON_REF }}\n"
        "      - uses: actions/setup-python@v5\n"
        "        uses: actions/setup-python@" + "a" * 40 + "\n"
        "      - uses: actions/setup-node@v5\n",
    )
    result = _run(tmp_path, "--github-strict-posture")
    payload = json.loads(result.stdout)
    assert [f["line"] for f in payload["findings"] if f["rule_id"] == PIN] == [11]
    assert payload["coverage_status"] == "incomplete"
    assert b"Rule SEC3-GH-001B returned incomplete" in result.stderr
    assert result.returncode == 11


def test_reject_incompatible_scan_modes(tmp_path):
    wrong_provider = _run(tmp_path, "--github-strict-posture", "--platform", "gitlab")
    assert wrong_provider.returncode == 2
    assert b"requires GitHub" in wrong_provider.stderr
    wrong_mode = _run(tmp_path, "--github-strict-posture", "--fix-dry-run")
    assert wrong_mode.returncode == 2
    assert b"requires a local GitHub source scan" in wrong_mode.stderr
