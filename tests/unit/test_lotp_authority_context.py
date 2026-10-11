"""Authority calibration contracts for the two GitHub LOTP rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Finding, Severity
from taintly.rules.github.lotp import RULES

_RULE_IDS = {"LOTP-GH-001", "LOTP-GH-003"}
_LOTP_RULES = [rule for rule in RULES if rule.id in _RULE_IDS]
_RULE_BY_ID = {rule.id: rule for rule in _LOTP_RULES}


def _scan(path: Path) -> dict[str, Finding]:
    findings = scan_file(str(path), _LOTP_RULES)
    selected = {finding.rule_id: finding for finding in findings if finding.rule_id in _RULE_IDS}
    assert set(selected) == _RULE_IDS
    return selected


def _assert_state(
    findings: dict[str, Finding],
    state: str,
    path: Path,
) -> None:
    for rule_id, finding in findings.items():
        tags = set(finding.context_tags)
        authority_tags = {tag for tag in tags if tag.startswith("authority-")}
        assert authority_tags == {state}
        assert finding.confidence == _RULE_BY_ID[rule_id].confidence
        assert finding.file == str(path)
        assert finding.origin == "file"
        assert finding.line > 0
        assert "npm" in finding.snippet.lower()

        if state == "authority-evidenced":
            assert finding.severity == _RULE_BY_ID[rule_id].severity
            assert finding.review_needed is False
        elif state == "authority-limited":
            assert finding.severity == Severity.MEDIUM
            assert finding.exploitability == "low"
            assert finding.review_needed is True
        else:
            assert finding.severity == _RULE_BY_ID[rule_id].severity
            assert finding.exploitability in {"low", "medium"}
            assert finding.review_needed is True


def _workflow(
    *,
    trigger: str = "pull_request_target",
    permissions: str | None = "permissions:\n  contents: write",
    job_permissions: str | None = None,
    runner: str = "ubuntu-latest",
    checkout: str = "actions/checkout@v4",
    checkout_inputs: str = "          persist-credentials: true\n",
    root_env: str = "",
    job_env: str = "",
    build_env: str = "",
    after_build_steps: str = "",
    extra_jobs: str = "",
) -> str:
    permission_block = f"{permissions}\n" if permissions else ""
    job_permission_block = f"{job_permissions}\n" if job_permissions else ""
    root_env_block = f"{root_env}\n" if root_env else ""
    job_env_block = f"{job_env}\n" if job_env else ""
    build_env_block = f"        env:\n{build_env}" if build_env else ""
    return (
        "name: authority context test\n"
        f"on:\n  {trigger}:\n"
        f"{root_env_block}"
        f"{permission_block}"
        "jobs:\n"
        "  build:\n"
        "    if: github.event.pull_request.head.repo.fork == true\n"
        f"{job_permission_block}"
        f"{job_env_block}"
        f"    runs-on: {runner}\n"
        "    steps:\n"
        f"      - uses: {checkout}\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "          repository: ${{ github.event.pull_request.head.repo.full_name }}\n"
        f"{checkout_inputs}"
        "      - run: npm ci\n"
        f"{build_env_block}"
        f"{after_build_steps}"
        f"{extra_jobs}"
    )


def _scan_text(tmp_path: Path, content: str, name: str) -> tuple[Path, dict[str, Finding]]:
    path = tmp_path / name / ".github" / "workflows" / "control.yml"
    path.parent.mkdir(parents=True)
    path.write_text(content, encoding="utf-8")
    return path, _scan(path)


def test_inline_control_workflows_calibrate_authority_and_keep_source(tmp_path):
    safe_content = _workflow(
        trigger="pull_request",
        permissions="permissions:\n  contents: read",
        checkout_inputs="          persist-credentials: false\n",
    )
    threat_content = _workflow(
        permissions="permissions:\n  contents: write",
        checkout_inputs="          persist-credentials: true\n",
    )
    safe_path, safe = _scan_text(tmp_path, safe_content, "control_safe")
    threat_path, threat = _scan_text(tmp_path, threat_content, "control_threat")

    _assert_state(safe, "authority-limited", safe_path)
    _assert_state(threat, "authority-evidenced", threat_path)

    for finding in threat.values():
        evidence = " ".join([*finding.context_notes, finding.calibration_reason]).lower()
        source = threat_content.splitlines()
        permission_line = next(i for i, line in enumerate(source, 1) if "contents: write" in line)
        persist_line = next(
            i for i, line in enumerate(source, 1) if "persist-credentials: true" in line
        )
        assert "permission" in evidence
        assert "persist" in evidence or "checkout" in evidence
        assert str(permission_line) in evidence
        assert str(persist_line) in evidence


def test_explicit_hosted_pr_permissions_limit_lotp_findings(tmp_path):
    cases = {
        "block_read": _workflow(
            trigger="pull_request",
            permissions="permissions:\n  contents: read",
            checkout_inputs="          persist-credentials: false\n",
        ),
        "flow_read": _workflow(
            trigger="pull_request",
            permissions="permissions: { contents: read }",
            checkout_inputs="          persist-credentials: false\n",
        ),
        "empty_permissions": _workflow(
            trigger="pull_request",
            permissions="permissions: {}",
            checkout_inputs="          persist-credentials: false\n",
        ),
        "builtin_read_token_env": _workflow(
            trigger="pull_request",
            permissions="permissions:\n  contents: read",
            checkout_inputs="          persist-credentials: false\n",
            build_env="          GH_TOKEN: ${{ github.token }}\n",
        ),
        "job_override": _workflow(
            trigger="pull_request",
            permissions="permissions:\n  contents: write",
            job_permissions="    permissions:\n      contents: read",
            checkout_inputs="          persist-credentials: false\n",
        ),
        "privileged_sibling_job": _workflow(
            trigger="pull_request",
            permissions="permissions:\n  contents: read",
            checkout_inputs="          persist-credentials: false\n",
            extra_jobs=(
                "  publish:\n    runs-on: ubuntu-latest\n"
                "    if: github.event_name == 'push'\n"
                "    permissions:\n      contents: write\n"
                "    steps:\n      - run: echo publish\n"
            ),
        ),
    }

    for name, content in cases.items():
        path, findings = _scan_text(tmp_path, content, name)
        _assert_state(findings, "authority-limited", path)


def test_same_job_secret_exposure_blocks_limited_classification(tmp_path):
    cases = {
        "build_step_secret": _workflow(
            trigger="pull_request",
            permissions="permissions:\n  contents: read",
            checkout_inputs="          persist-credentials: false\n",
            build_env="          RELEASE_TOKEN: ${{ secrets.RELEASE_TOKEN }}\n",
        ),
        "later_step_secret": _workflow(
            trigger="pull_request",
            permissions="permissions:\n  contents: read",
            checkout_inputs="          persist-credentials: false\n",
            after_build_steps=(
                "      - name: prepare credentials\n"
                "        env:\n          RELEASE_TOKEN: ${{ secrets.RELEASE_TOKEN }}\n"
                "        run: echo prepared\n"
            ),
        ),
        "token_env_with_persist_false": _workflow(
            trigger="pull_request",
            permissions="permissions:\n  contents: read",
            checkout_inputs="          persist-credentials: false\n",
            build_env="          GH_TOKEN: ${{ secrets.CI_TOKEN }}\n",
        ),
    }

    for name, content in cases.items():
        path, findings = _scan_text(tmp_path, content, name)
        _assert_state(findings, "authority-unresolved", path)


def test_environment_precedence_and_secret_scope_are_accounted_for(tmp_path):
    cases = {
        "root_secret_overridden_by_job_value": (
            _workflow(
                trigger="pull_request",
                permissions="permissions:\n  contents: read",
                checkout_inputs="          persist-credentials: false\n",
                root_env="env:\n  RELEASE_TOKEN: ${{ secrets.RELEASE_TOKEN }}",
                job_env="    env:\n      RELEASE_TOKEN: public-value",
            ),
            "authority-limited",
        ),
        "job_secret_reaches_checkout_even_if_build_step_overrides": (
            _workflow(
                trigger="pull_request",
                permissions="permissions:\n  contents: read",
                checkout_inputs="          persist-credentials: false\n",
                root_env="env:\n  RELEASE_TOKEN: public-root-value",
                job_env="    env:\n      RELEASE_TOKEN: ${{ secrets.RELEASE_TOKEN }}",
                build_env="          RELEASE_TOKEN: public-step-value\n",
            ),
            "authority-unresolved",
        ),
        "step_secret_overrides_safe_job_value": (
            _workflow(
                trigger="pull_request",
                permissions="permissions:\n  contents: read",
                checkout_inputs="          persist-credentials: false\n",
                root_env="env:\n  RELEASE_TOKEN: public-root-value",
                job_env="    env:\n      RELEASE_TOKEN: public-job-value",
                build_env="          RELEASE_TOKEN: ${{ secrets.RELEASE_TOKEN }}\n",
            ),
            "authority-unresolved",
        ),
    }

    for name, (content, state) in cases.items():
        path, findings = _scan_text(tmp_path, content, name)
        _assert_state(findings, state, path)


@pytest.mark.parametrize(
    ("name", "content"),
    [
        (
            "missing_permissions",
            _workflow(permissions=None),
        ),
        (
            "dynamic_permissions",
            _workflow(permissions="permissions: ${{ inputs.permission_set }}"),
        ),
        (
            "custom_runner",
            _workflow(
                trigger="pull_request",
                permissions="permissions:\n  contents: read",
                runner="[self-hosted, linux]",
                checkout_inputs="          persist-credentials: false\n",
            ),
        ),
        (
            "merge_permissions",
            "name: merge permission context\non: pull_request_target\n"
            "permissions: &write_permissions\n  contents: write\n"
            "jobs:\n  build:\n    permissions:\n      <<: *write_permissions\n"
            "    if: github.event.pull_request.head.repo.fork == true\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
            "          repository: ${{ github.event.pull_request.head.repo.full_name }}\n"
            "          persist-credentials: true\n      - run: npm ci\n",
        ),
        (
            "duplicate_permissions",
            "name: duplicate permission context\non: pull_request_target\n"
            "permissions:\n  contents: read\npermissions:\n  contents: write\n"
            "jobs:\n  build:\n    if: github.event.pull_request.head.repo.fork == true\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
            "          repository: ${{ github.event.pull_request.head.repo.full_name }}\n"
            "          persist-credentials: true\n      - run: npm ci\n",
        ),
        (
            "checkout_v7_default",
            _workflow(checkout="actions/checkout@v7", checkout_inputs=""),
        ),
        (
            "pinned_unknown_checkout",
            _workflow(
                checkout="actions/checkout@0123456789abcdef0123456789abcdef01234567",
            ),
        ),
        (
            "custom_pat_token",
            _workflow(
                checkout_inputs=(
                    "          persist-credentials: true\n"
                    "          token: ${{ secrets.CHECKOUT_PAT }}\n"
                ),
            ),
        ),
        (
            "ssh_checkout_key",
            _workflow(
                checkout_inputs=(
                    "          persist-credentials: true\n"
                    "          ssh-key: ${{ secrets.CHECKOUT_SSH_KEY }}\n"
                ),
            ),
        ),
        (
            "secret_only",
            _workflow(
                trigger="pull_request",
                permissions="permissions:\n  contents: read",
                checkout_inputs="          persist-credentials: false\n",
                build_env="          RELEASE_TOKEN: ${{ secrets.RELEASE_TOKEN }}\n",
            ),
        ),
        (
            "ordinary_pr_issues_write",
            _workflow(
                trigger="pull_request",
                permissions="permissions:\n  issues: write",
                checkout_inputs="          persist-credentials: false\n",
            ),
        ),
        (
            "ordinary_pr_custom_runner_persist_false",
            _workflow(
                trigger="pull_request",
                permissions="permissions:\n  contents: read",
                runner="[self-hosted, linux]",
                checkout_inputs="          persist-credentials: false\n",
            ),
        ),
    ],
)
def test_unresolved_authority_inputs_keep_findings_reviewable(tmp_path, name, content):
    path, findings = _scan_text(tmp_path, content, name)

    _assert_state(findings, "authority-unresolved", path)


def test_checkout_v6_persisted_credentials_remain_evidenced(tmp_path):
    content = _workflow(
        checkout="actions/checkout@v6",
        checkout_inputs="          persist-credentials: true\n",
    )
    path, findings = _scan_text(tmp_path, content, "checkout_v6")

    _assert_state(findings, "authority-evidenced", path)


def test_flow_write_permissions_are_evidenced(tmp_path):
    path, findings = _scan_text(
        tmp_path,
        _workflow(permissions="permissions: { contents: write }"),
        "flow_write",
    )

    _assert_state(findings, "authority-evidenced", path)


@pytest.mark.parametrize(
    "permissions",
    ["permissions:\n  issues: write", "permissions: { issues: write }"],
)
def test_pull_request_target_nonshortlist_write_permission_is_evidenced(tmp_path, permissions):
    path, findings = _scan_text(
        tmp_path,
        _workflow(permissions=permissions),
        "target_issues_write",
    )

    _assert_state(findings, "authority-evidenced", path)


def test_self_hosted_pull_request_target_with_persisted_token_is_evidenced(tmp_path):
    path, findings = _scan_text(
        tmp_path,
        _workflow(runner="[self-hosted, linux]"),
        "target_self_hosted_persisted",
    )

    _assert_state(findings, "authority-evidenced", path)


def test_write_token_explicitly_available_with_persist_false_is_evidenced(tmp_path):
    path, findings = _scan_text(
        tmp_path,
        _workflow(
            checkout_inputs="          persist-credentials: false\n",
            build_env="          GH_TOKEN: ${{ github.token }}\n",
        ),
        "write_token_env_persist_false",
    )

    _assert_state(findings, "authority-evidenced", path)
