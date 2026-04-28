"""Tests for PSE-GH-002 — IAM-policy escalation of PSE-GH-001 findings.

The escalation pass must:
  * Promote a HIGH PSE-GH-001 finding to CRITICAL when the matched
    local IAM policy classifies as :attr:`BlastRadius.CRITICAL`.
  * Leave the finding at HIGH when no matching policy is found
    (absence of evidence is not evidence of absence).
  * Leave the finding at HIGH when the matched policy classifies
    below CRITICAL (HIGH/MODERATE policies are consistent with the
    base rule's HIGH severity).
  * Match policy files by either full ARN string OR role-name suffix.
  * Handle Terraform heredoc inline policies (`policy = <<EOF ... EOF`).
  * Cache verdicts so identical files aren't classified twice.
"""

from __future__ import annotations

from pathlib import Path

from taintly.models import Finding, Severity
from taintly.pse_enrichment import (
    enrich_pse_findings,
    extract_role_arns,
    find_matching_policies,
)

# ---------------------------------------------------------------------------
# extract_role_arns
# ---------------------------------------------------------------------------


def test_extract_role_arns_finds_role_to_assume_key():
    workflow = (
        "on: pull_request\n"
        "jobs:\n  triage:\n    steps:\n"
        "      - uses: aws-actions/configure-aws-credentials@<SHA>\n"
        "        with:\n"
        "          role-to-assume: arn:aws:iam::123456789012:role/MyTriageRole\n"
    )
    arns = extract_role_arns(workflow)
    assert arns == ["arn:aws:iam::123456789012:role/MyTriageRole"]


def test_extract_role_arns_handles_quoted_value():
    workflow = (
        "        with:\n          role-to-assume: 'arn:aws:iam::1:role/Q'\n"
        "        with:\n"
        '          role-to-assume: "arn:aws:iam::2:role/QQ"\n'
    )
    assert extract_role_arns(workflow) == [
        "arn:aws:iam::1:role/Q",
        "arn:aws:iam::2:role/QQ",
    ]


def test_extract_role_arns_handles_role_arn_alias():
    workflow = "          role-arn: arn:aws:iam::987:role/AltKey\n"
    assert extract_role_arns(workflow) == ["arn:aws:iam::987:role/AltKey"]


def test_extract_role_arns_empty_when_absent():
    assert extract_role_arns("on: pull_request\njobs: {}\n") == []


def test_extract_role_arns_ignores_arn_in_comment_or_run():
    # A bare ARN string in a comment or `run:` block is not an OIDC
    # configuration — only `role-to-assume:` / `role-arn:` keys are
    # extracted.  Otherwise PSE-GH-002 would fire on every workflow
    # that mentions an ARN in a printf debug line.
    workflow = (
        "jobs:\n"
        "  echo:\n"
        "    steps:\n"
        "      - run: echo 'use arn:aws:iam::1:role/Foo for prod'\n"
        "      # role-to-assume: arn:aws:iam::2:role/Bar (commented out)\n"
    )
    assert extract_role_arns(workflow) == []


# ---------------------------------------------------------------------------
# find_matching_policies
# ---------------------------------------------------------------------------


def test_find_matching_policies_matches_by_role_name(tmp_path: Path) -> None:
    role_arn = "arn:aws:iam::123:role/MyRole"
    policy_dir = tmp_path / "iam"
    policy_dir.mkdir()
    policy_file = policy_dir / "MyRole.json"
    policy_file.write_text('{"Statement": [{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}')

    matches = find_matching_policies(role_arn, str(tmp_path))
    assert len(matches) == 1
    assert matches[0][0] == str(policy_file)


def test_find_matching_policies_matches_by_full_arn(tmp_path: Path) -> None:
    role_arn = "arn:aws:iam::123:role/MyRole"
    policy_file = tmp_path / "policies" / "infra.json"
    policy_file.parent.mkdir()
    # Role NAME does not appear, but full ARN does.
    policy_file.write_text(
        '{"_attached_to":"arn:aws:iam::123:role/MyRole",'
        '"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}'
    )

    matches = find_matching_policies(role_arn, str(tmp_path))
    assert len(matches) == 1


def test_find_matching_policies_skips_unrelated_files(tmp_path: Path) -> None:
    role_arn = "arn:aws:iam::123:role/MyRole"
    (tmp_path / "iam").mkdir()
    other = tmp_path / "iam" / "OtherRole.json"
    other.write_text('{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}')

    assert find_matching_policies(role_arn, str(tmp_path)) == []


def test_find_matching_policies_extracts_terraform_heredoc(tmp_path: Path) -> None:
    role_arn = "arn:aws:iam::123:role/MyRole"
    tf_file = tmp_path / "terraform" / "iam.tf"
    tf_file.parent.mkdir()
    tf_file.write_text(
        'resource "aws_iam_role_policy" "MyRole_policy" {\n'
        "  role = aws_iam_role.MyRole.name\n"
        "  policy = <<EOF\n"
        '{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}\n'
        "EOF\n"
        "}\n"
    )
    matches = find_matching_policies(role_arn, str(tmp_path))
    assert len(matches) == 1
    assert '"Action":"iam:*"' in matches[0][1]


def test_find_matching_policies_skips_non_iam_heredocs(tmp_path: Path) -> None:
    # A user-data heredoc named `policy` doesn't contain "Statement":
    # it should NOT be classified.  This guards against the trigger
    # extracting bash scripts on every Terraform file in the repo.
    role_arn = "arn:aws:iam::123:role/MyRole"
    tf_file = tmp_path / "iam" / "noise.tf"
    tf_file.parent.mkdir()
    tf_file.write_text(
        "# MyRole reference here\n"
        'resource "aws_instance" "x" {\n'
        "  policy = <<EOF\n"
        "#!/usr/bin/env bash\n"
        "echo hi\n"
        "EOF\n"
        "}\n"
    )
    assert find_matching_policies(role_arn, str(tmp_path)) == []


def test_find_matching_policies_skips_node_modules(tmp_path: Path) -> None:
    role_arn = "arn:aws:iam::123:role/MyRole"
    junk = tmp_path / "node_modules" / "leftpad" / "iam"
    junk.mkdir(parents=True)
    (junk / "MyRole.json").write_text(
        '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
    )
    assert find_matching_policies(role_arn, str(tmp_path)) == []


# ---------------------------------------------------------------------------
# enrich_pse_findings — end-to-end escalation behaviour
# ---------------------------------------------------------------------------


def _write_workflow(tmp_path: Path, content: str, name: str = "ai-pr.yml") -> str:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    wf_path = wf_dir / name
    wf_path.write_text(content)
    return str(wf_path)


def _make_pse_finding(workflow_path: str) -> Finding:
    return Finding(
        rule_id="PSE-GH-001",
        severity=Severity.HIGH,
        title="AI agent with cloud-credential grant on a fork-reachable event",
        description="Original PSE-GH-001 description.",
        file=workflow_path,
        line=10,
        snippet="role-to-assume: arn:aws:iam::123:role/MyRole",
    )


def test_enrich_escalates_to_critical_on_iam_star_policy(tmp_path: Path) -> None:
    wf_path = _write_workflow(
        tmp_path,
        "on: pull_request\n"
        "jobs:\n  agent:\n    steps:\n"
        "      - uses: aws-actions/configure-aws-credentials@<SHA>\n"
        "        with:\n"
        "          role-to-assume: arn:aws:iam::123:role/MyRole\n",
    )
    (tmp_path / "iam").mkdir()
    (tmp_path / "iam" / "MyRole.json").write_text(
        '{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}'
    )

    findings = [_make_pse_finding(wf_path)]
    enriched = enrich_pse_findings(findings, str(tmp_path))

    assert enriched[0].severity == Severity.CRITICAL
    assert "[CRITICAL IAM blast radius]" in enriched[0].title
    assert "iam:*" in enriched[0].description
    assert "PSE-GH-002 escalation" in enriched[0].description


def test_enrich_does_not_escalate_when_policy_is_high_only(tmp_path: Path) -> None:
    # Specific bucket → s3:* is HIGH, not CRITICAL.  PSE-GH-001 stays
    # at HIGH (the existing rule severity is consistent).
    wf_path = _write_workflow(
        tmp_path,
        "on: pull_request\n"
        "jobs:\n  agent:\n    steps:\n"
        "      - uses: aws-actions/configure-aws-credentials@<SHA>\n"
        "        with:\n"
        "          role-to-assume: arn:aws:iam::123:role/MyRole\n",
    )
    (tmp_path / "iam").mkdir()
    (tmp_path / "iam" / "MyRole.json").write_text(
        '{"Statement":[{"Effect":"Allow","Action":"s3:*",'
        '"Resource":"arn:aws:s3:::my-specific-bucket/*"}]}'
    )

    findings = [_make_pse_finding(wf_path)]
    enriched = enrich_pse_findings(findings, str(tmp_path))

    assert enriched[0].severity == Severity.HIGH
    assert "PSE-GH-002" not in enriched[0].description


def test_enrich_does_not_escalate_without_local_policy(tmp_path: Path) -> None:
    # No local IAM policy file at all — absence of evidence is NOT
    # evidence of CRITICAL.  Stay at HIGH.
    wf_path = _write_workflow(
        tmp_path,
        "on: pull_request\n"
        "jobs:\n  agent:\n    steps:\n"
        "      - uses: aws-actions/configure-aws-credentials@<SHA>\n"
        "        with:\n"
        "          role-to-assume: arn:aws:iam::123:role/MyRole\n",
    )

    findings = [_make_pse_finding(wf_path)]
    enriched = enrich_pse_findings(findings, str(tmp_path))

    assert enriched[0].severity == Severity.HIGH


def test_enrich_does_not_touch_non_pse_findings(tmp_path: Path) -> None:
    wf_path = _write_workflow(tmp_path, "on: pull_request\n")
    other = Finding(
        rule_id="SEC3-GH-001",
        severity=Severity.HIGH,
        title="Unpinned action",
        description="x",
        file=wf_path,
    )
    enriched = enrich_pse_findings([other], str(tmp_path))
    assert enriched[0].severity == Severity.HIGH
    assert enriched[0].title == "Unpinned action"


def test_enrich_handles_terraform_heredoc_critical_policy(tmp_path: Path) -> None:
    wf_path = _write_workflow(
        tmp_path,
        "on: pull_request\n        with:\n          role-to-assume: arn:aws:iam::123:role/TfRole\n",
    )
    tf_dir = tmp_path / "terraform"
    tf_dir.mkdir()
    (tf_dir / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "TfRole_policy" {\n'
        "  role = aws_iam_role.TfRole.name\n"
        "  policy = <<EOF\n"
        '{"Statement":[{"Effect":"Allow","Action":"sts:*","Resource":"*"}]}\n'
        "EOF\n"
        "}\n"
    )

    findings = [_make_pse_finding(wf_path)]
    enriched = enrich_pse_findings(findings, str(tmp_path))

    assert enriched[0].severity == Severity.CRITICAL
    assert "sts:*" in enriched[0].description


def test_enrich_takes_worst_when_workflow_assumes_multiple_roles(tmp_path: Path) -> None:
    # Workflow that assumes two roles in the same job — the worst
    # blast-radius wins.  Auditors care about the upper bound.
    wf_path = _write_workflow(
        tmp_path,
        "on: pull_request\n"
        "jobs:\n  agent:\n    steps:\n"
        "      - uses: aws-actions/configure-aws-credentials@<SHA>\n"
        "        with:\n"
        "          role-to-assume: arn:aws:iam::1:role/NarrowRole\n"
        "      - uses: aws-actions/configure-aws-credentials@<SHA>\n"
        "        with:\n"
        "          role-to-assume: arn:aws:iam::2:role/CriticalRole\n",
    )
    (tmp_path / "iam").mkdir()
    (tmp_path / "iam" / "NarrowRole.json").write_text(
        '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject",'
        '"Resource":"arn:aws:s3:::bucket/*"}]}'
    )
    (tmp_path / "iam" / "CriticalRole.json").write_text(
        '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
    )

    findings = [_make_pse_finding(wf_path)]
    enriched = enrich_pse_findings(findings, str(tmp_path))

    assert enriched[0].severity == Severity.CRITICAL
    assert "CriticalRole" in enriched[0].description


def test_enrich_handles_missing_workflow_file(tmp_path: Path) -> None:
    # File on the finding has been deleted between scan and enrichment.
    # Should silently skip rather than raise.
    finding = Finding(
        rule_id="PSE-GH-001",
        severity=Severity.HIGH,
        title="x",
        description="x",
        file=str(tmp_path / "ghost.yml"),
    )
    enriched = enrich_pse_findings([finding], str(tmp_path))
    assert enriched[0].severity == Severity.HIGH


def test_enrich_handles_finding_with_no_file_attribute(tmp_path: Path) -> None:
    finding = Finding(
        rule_id="PSE-GH-001",
        severity=Severity.HIGH,
        title="x",
        description="x",
        file="",
    )
    enriched = enrich_pse_findings([finding], str(tmp_path))
    assert enriched[0].severity == Severity.HIGH


def test_enrich_caches_repeated_policy_classifications(tmp_path: Path) -> None:
    # Two findings in two different workflow files both pointing at
    # the same role — the policy should be classified once, not twice.
    # We verify by spying on classify_policy via monkeypatch.
    import taintly.pse_enrichment as pse_mod

    wf1 = _write_workflow(
        tmp_path,
        "on: pull_request\n"
        "        with:\n          role-to-assume: arn:aws:iam::1:role/SharedRole\n",
        name="a.yml",
    )
    wf2 = _write_workflow(
        tmp_path,
        "on: pull_request\n"
        "        with:\n          role-to-assume: arn:aws:iam::1:role/SharedRole\n",
        name="b.yml",
    )
    (tmp_path / "iam").mkdir()
    (tmp_path / "iam" / "SharedRole.json").write_text(
        '{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}'
    )

    call_count = 0
    real_classify = pse_mod.classify_policy

    def counting_classify(policy_json):  # type: ignore[no-untyped-def]
        nonlocal call_count
        call_count += 1
        return real_classify(policy_json)

    pse_mod.classify_policy = counting_classify
    try:
        findings = [_make_pse_finding(wf1), _make_pse_finding(wf2)]
        enrich_pse_findings(findings, str(tmp_path))
    finally:
        pse_mod.classify_policy = real_classify

    assert call_count == 1, (
        f"classify_policy was invoked {call_count} times across two findings "
        "pointing at the same SharedRole.json — verdict cache failed."
    )


# ---------------------------------------------------------------------------
# Integration with engine.scan_repo
# ---------------------------------------------------------------------------


def test_scan_repo_escalates_pse_finding_via_iam_policy(tmp_path: Path) -> None:
    """End-to-end: a workflow that fires PSE-GH-001 and ships a
    CRITICAL local IAM policy should be reported at CRITICAL after
    scan_repo runs.  This is the user-visible PSE-GH-002 contract.
    """
    from taintly.engine import scan_repo
    from taintly.models import Platform
    from taintly.rules.registry import load_all_rules

    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "agent.yml").write_text(
        "on: pull_request\n"
        "permissions:\n  id-token: write\n"
        "jobs:\n"
        "  agent:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: aws-actions/configure-aws-credentials@<SHA>\n"
        "        with:\n"
        "          role-to-assume: arn:aws:iam::123:role/AgentRole\n"
        "      - uses: anthropics/claude-code-action@v1\n"
    )
    (tmp_path / "iam").mkdir()
    (tmp_path / "iam" / "AgentRole.json").write_text(
        '{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}'
    )

    rules = load_all_rules()
    reports = scan_repo(str(tmp_path), rules, Platform.GITHUB)

    pse_findings = [f for r in reports for f in r.findings if f.rule_id == "PSE-GH-001"]
    assert len(pse_findings) == 1
    assert pse_findings[0].severity == Severity.CRITICAL
    assert "PSE-GH-002 escalation" in pse_findings[0].description


def test_scan_repo_leaves_pse_at_high_without_iam_policy(tmp_path: Path) -> None:
    from taintly.engine import scan_repo
    from taintly.models import Platform
    from taintly.rules.registry import load_all_rules

    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "agent.yml").write_text(
        "on: pull_request\n"
        "permissions:\n  id-token: write\n"
        "jobs:\n"
        "  agent:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: aws-actions/configure-aws-credentials@<SHA>\n"
        "        with:\n"
        "          role-to-assume: arn:aws:iam::123:role/AgentRole\n"
        "      - uses: anthropics/claude-code-action@v1\n"
    )
    # No iam/ directory — no local policy to escalate against.

    rules = load_all_rules()
    reports = scan_repo(str(tmp_path), rules, Platform.GITHUB)

    pse_findings = [f for r in reports for f in r.findings if f.rule_id == "PSE-GH-001"]
    assert len(pse_findings) == 1
    assert pse_findings[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Path-handling robustness
# ---------------------------------------------------------------------------


def test_iter_candidate_files_caps_at_max(tmp_path: Path) -> None:
    """A pathological monorepo with thousands of JSON files in iam/
    must not iterate past the cap.  Guards the scan budget.
    """
    from taintly.pse_enrichment import _MAX_POLICY_FILES, _iter_candidate_files

    iam = tmp_path / "iam"
    iam.mkdir()
    # Write _MAX_POLICY_FILES + 50 stub files.
    for i in range(_MAX_POLICY_FILES + 50):
        (iam / f"role_{i}.json").write_text("{}")

    out = _iter_candidate_files(str(tmp_path))
    assert len(out) == _MAX_POLICY_FILES


def test_role_name_extraction_handles_nested_path():
    # IAM allows nested role paths; the rightmost component is the name.
    from taintly.pse_enrichment import _role_name_from_arn

    assert _role_name_from_arn("arn:aws:iam::123:role/path/to/MyRole") == "MyRole"


def test_role_name_extraction_returns_empty_on_malformed():
    from taintly.pse_enrichment import _role_name_from_arn

    assert _role_name_from_arn("not-an-arn") == ""
