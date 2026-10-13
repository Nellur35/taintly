from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from taintly.composer import run_composer
from taintly.engine import scan_file, scan_repo
from taintly.models import Platform, Severity
from taintly.rules.github.chain_compose import COMPOSER_RULES
from taintly.rules.registry import load_all_rules
from taintly.workflow_corpus import build_corpus

BASE = """on: pull_request_target
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: true
      - run: {command}
"""


def scan(tmp_path: Path, content: str):
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(content, encoding="utf-8")
    reports = scan_repo(str(tmp_path), load_all_rules(), Platform.GITHUB)
    findings = [finding for report in reports for finding in report.findings]
    assert not [finding for finding in findings if finding.rule_id == "ENGINE-ERR"]
    return workflow, findings


def _script_leaves(findings):
    return [finding for finding in findings if finding.rule_id == "LOTP-GH-006"]


def _chains(findings):
    return [finding for finding in findings if finding.rule_id == "CHAIN-GH-101"]


def scan_local_script_file(
    filepath: Path, content: str, *, expect_merged_shell_diagnostic: bool = False
):
    findings = scan_file(str(filepath), load_all_rules(), _content=content)
    errors = [finding for finding in findings if finding.rule_id == "ENGINE-ERR"]
    if expect_merged_shell_diagnostic:
        assert len(errors) == 1
        (error,) = errors
        assert error.file == str(filepath)
        assert error.title == (
            f"Rule SEC10-GH-002 returned incomplete pattern results for {filepath}"
        )
        assert error.description == (
            "Pattern analysis stopped before full coverage; already-found matches "
            "are retained. Reasons: merged structural value"
        )
    else:
        assert not errors
    return [finding for finding in findings if finding.rule_id == "LOTP-GH-006"]


def _assert_source_sha256(content: str, expected: str):
    assert hashlib.sha256(content.encode("utf-8")).hexdigest() == expected


def test_pr_head_bash_script_gets_source_bound_review_chain(tmp_path):
    content = BASE.replace("{command}", "bash ./scripts/check.sh")
    workflow, findings = scan(tmp_path, content)

    (leaf,) = _script_leaves(findings)
    (chain,) = _chains(findings)
    witness = leaf._checkout_build
    assert leaf.file == str(workflow)
    assert leaf.line == 13
    assert leaf.severity == Severity.HIGH
    assert "authority-evidenced" in leaf.context_tags
    assert witness.job == "build"
    assert leaf.confidence == "medium"
    assert leaf.review_needed is True
    assert witness.execution_kind == "script"
    assert witness.script_path == "scripts/check.sh"
    assert witness.interpreter == "bash"
    assert chain.file == str(workflow)
    assert chain.line == 8
    assert "checkout-local-script-path-evidenced" in chain.context_tags
    assert "configured local-file invocation" in chain.snippet.lower()
    assert "bash" in chain.snippet
    assert "scripts/check.sh" in chain.snippet
    assert "line 13" in chain.snippet
    assert "runtime" in chain.snippet.lower()
    assert "effective" in chain.snippet.lower()
    assert chain.snippet.lower().count("unverified") >= 2
    assert "bash scripts/check.sh" in chain.remediation
    assert "checkout at line 8" in chain.remediation
    assert "persistence input/default at line 12" in chain.remediation
    assert "invocation `bash scripts/check.sh` at line 13" in chain.remediation
    assert "contents:write at line 3" in chain.remediation
    assert "permissions block at line 2" in chain.remediation
    assert "untrusted build" not in chain.remediation.lower()
    assert "build definitions" not in chain.remediation.lower()


def test_script_witness_is_rebound_to_path_and_current_source(tmp_path):
    workflow, findings = scan(tmp_path, BASE.replace("{command}", "bash ./scripts/check.sh"))
    (leaf,) = _script_leaves(findings)
    corpus = build_corpus(str(tmp_path))

    def composed(candidate, source=corpus):
        return [
            finding
            for finding in run_composer(source, [candidate], COMPOSER_RULES)
            if finding.chain_id == "CHAIN-GH-101"
        ]

    assert len(composed(leaf)) == 1
    forged = replace(leaf._checkout_build, script_path="other.sh")
    assert composed(replace(leaf, _checkout_build=forged)) == []

    workflow.write_text(BASE.replace("{command}", "bash ./other.sh"), encoding="utf-8")
    assert composed(leaf, build_corpus(str(tmp_path))) == []


def test_existing_make_chain_keeps_its_build_witness(tmp_path):
    workflow, findings = scan(tmp_path, BASE.replace("{command}", "make"))

    (legacy_build,) = [f for f in findings if f.rule_id == "LOTP-GH-001"]
    (chain,) = _chains(findings)
    assert legacy_build.line == 13
    assert chain.file == str(workflow)
    assert chain.line == 8
    assert "local build `make` at line 13" in chain.snippet
    assert not _script_leaves(findings)
    assert chain.remediation == (
        "In job 'build', set `persist-credentials: false` on the checkout at line 8 "
        "(persistence input/default at line 12), and run the untrusted build at line 13 in a "
        "separate unprivileged job. Minimize the requested permissions at line 2. Verify the "
        "checked-out build definitions, tool configuration, guards, approvals and provider-granted "
        "token scopes before concluding that this path is exploitable."
    )


def test_literal_script_command_uses_physical_body_line(tmp_path):
    content = BASE.replace("{command}", "|\n          bash ./scripts/check.sh")
    workflow, findings = scan(tmp_path, content)

    (leaf,) = _script_leaves(findings)
    assert leaf.file == str(workflow)
    assert leaf.line == 14
    source_line = workflow.read_text(encoding="utf-8").splitlines()[leaf.line - 1]
    assert leaf.snippet.strip() == source_line.strip()
    assert leaf._checkout_build.script_path == "scripts/check.sh"


def test_folded_script_command_reports_scalar_origin(tmp_path):
    content = BASE.replace("{command}", ">-\n          bash\n          ./scripts/check.sh")
    workflow, findings = scan(tmp_path, content)

    (leaf,) = _script_leaves(findings)
    assert leaf.file == str(workflow)
    assert leaf.line == 13
    source_line = workflow.read_text(encoding="utf-8").splitlines()[leaf.line - 1]
    assert leaf.snippet.strip() == source_line.strip()
    assert leaf._checkout_build.script_path == "scripts/check.sh"
    assert any("scalar" in note.lower() and "line 13" in note for note in leaf.context_notes)


def test_folded_default_chomp_command_keeps_supported_chain(tmp_path):
    content = BASE.replace("{command}", ">\n          bash\n          ./scripts/check.sh")
    workflow, findings = scan(tmp_path, content)

    (leaf,) = _script_leaves(findings)
    (chain,) = _chains(findings)
    assert leaf.file == str(workflow)
    assert leaf.line == 13
    assert leaf._checkout_build.script_path == "scripts/check.sh"
    assert any("scalar" in note.lower() and "line 13" in note for note in leaf.context_notes)
    assert chain.line == 8
    assert "configured local-file invocation" in chain.snippet.lower()


def test_compact_pr_checkout_expressions_keep_supported_chain(tmp_path):
    content = (
        BASE.replace("{command}", "bash ./scripts/check.sh")
        .replace(
            "${{ github.event.pull_request.head.repo.full_name }}",
            "${{github.event.pull_request.head.repo.full_name}}",
        )
        .replace(
            "${{ github.event.pull_request.head.sha }}", "${{github.event.pull_request.head.sha}}"
        )
    )
    workflow, findings = scan(tmp_path, content)

    (leaf,) = _script_leaves(findings)
    (chain,) = _chains(findings)
    assert leaf.file == str(workflow)
    assert leaf._checkout_build.script_path == "scripts/check.sh"
    assert chain.line == 8
    assert "configured local-file invocation" in chain.snippet.lower()


def test_echoed_and_heredoc_script_text_are_not_executable_candidates(tmp_path):
    content = BASE.replace(
        "{command}",
        "|\n"
        "          echo 'bash ./scripts/check.sh'\n"
        "          cat <<'EOF'\n"
        "          bash ./scripts/check.sh\n"
        "          EOF",
    )
    _, findings = scan(tmp_path, content)

    assert not _script_leaves(findings)
    assert not _chains(findings)


def test_literal_later_command_is_reviewed_without_elevated_witness(tmp_path):
    content = BASE.replace(
        "{command}",
        "|\n          echo safe\n          bash ./scripts/check.sh",
    )
    workflow, findings = scan(tmp_path, content)

    (leaf,) = _script_leaves(findings)
    assert leaf.file == str(workflow)
    assert leaf.line == 15
    source_line = workflow.read_text(encoding="utf-8").splitlines()[leaf.line - 1]
    assert leaf.snippet.strip() == source_line.strip()
    assert leaf.review_needed is True
    assert leaf._checkout_build is None
    assert not _chains(findings)


def test_folded_echo_does_not_promote_script_text(tmp_path):
    content = BASE.replace("{command}", ">-\n          echo bash\n          ./scripts/check.sh")
    _, findings = scan(tmp_path, content)

    assert not _script_leaves(findings)
    assert not _chains(findings)


@pytest.mark.parametrize("scope", ["workflow", "job"], ids=["workflow-default", "job-default"])
def test_python_default_run_shell_does_not_parse_command_as_posix(scope, tmp_path):
    content = BASE.replace("{command}", "bash ./scripts/check.sh")
    defaults = (
        "defaults:\n  run:\n    shell: python\n"
        if scope == "workflow"
        else "    defaults:\n      run:\n        shell: python\n"
    )
    anchor = "on: pull_request_target\n" if scope == "workflow" else "    runs-on: ubuntu-latest\n"
    content = content.replace(anchor, anchor + defaults, 1)
    _, findings = scan(tmp_path, content)

    assert not _script_leaves(findings)


def test_multiline_quoted_print_data_does_not_create_script_candidate(tmp_path):
    content = BASE.replace(
        "{command}",
        "|\n"
        "          printf '%s\\n' \"ordinary data\n"
        "          bash ./scripts/check.sh\n"
        '          still ordinary data"',
    )
    _, findings = scan(tmp_path, content)

    assert not _script_leaves(findings)
    assert not _chains(findings)


def test_inherited_working_directory_resolves_under_checkout_path(tmp_path):
    content = (
        BASE.replace("{command}", "bash ./scripts/check.sh")
        .replace(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n"
            "    defaults:\n"
            "      run:\n"
            "        working-directory: fork\n",
        )
        .replace(
            "        with:\n",
            "        with:\n          path: fork\n",
            1,
        )
    )
    workflow, findings = scan(tmp_path, content)

    (leaf,) = _script_leaves(findings)
    assert leaf.file == str(workflow)
    assert leaf.review_needed is True
    assert leaf._checkout_build is None
    assert leaf.severity == Severity.MEDIUM
    assert "authority-unresolved" in leaf.context_tags
    assert not _chains(findings)


def test_nested_trusted_operand_path_does_not_inherit_pr_checkout_source(tmp_path):
    content = BASE.replace("{command}", "bash ./trusted/scripts/check.sh").replace(
        "      - run: bash ./trusted/scripts/check.sh\n",
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: main\n"
        "          path: trusted\n"
        "      - run: bash ./trusted/scripts/check.sh\n",
    )
    assert content.count("uses: actions/checkout@v4") == 2
    assert "path: trusted" in content
    assert "run: bash ./trusted/scripts/check.sh" in content
    _, findings = scan(tmp_path, content)

    assert not _script_leaves(findings)
    assert not _chains(findings)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("permissions:\n  contents: write", "permissions:\n  contents: read"),
        ("persist-credentials: true", "persist-credentials: false"),
        (
            "persist-credentials: true",
            "persist-credentials: true\n          token: ${{ secrets.PAT }}",
        ),
    ],
    ids=["read-only-grant", "persistence-disabled", "custom-credential"],
)
def test_authority_boundaries_keep_script_review_without_configured_chain(tmp_path, old, new):
    content = BASE.replace("{command}", "bash ./scripts/check.sh").replace(old, new)
    _, findings = scan(tmp_path, content)

    script_findings = _script_leaves(findings)
    assert script_findings
    assert all(f.review_needed for f in script_findings)
    assert all(f.severity == Severity.MEDIUM for f in script_findings)
    assert all("authority-unresolved" in f.context_tags for f in script_findings)
    assert not _chains(findings)


def test_limited_ordinary_pull_request_suppresses_script_candidate(tmp_path):
    content = (
        BASE.replace("on: pull_request_target", "on: pull_request")
        .replace("contents: write", "contents: read")
        .replace("persist-credentials: true", "persist-credentials: false")
        .replace("{command}", "bash ./scripts/check.sh")
    )
    _, findings = scan(tmp_path, content)

    assert not _script_leaves(findings)
    assert not _chains(findings)


def test_step_empty_token_overrides_workflow_and_job_env_for_ordinary_pr(tmp_path):
    content = (
        BASE.replace("on: pull_request_target", "on: pull_request")
        .replace("contents: write", "contents: read")
        .replace("persist-credentials: true", "persist-credentials: false")
        .replace(
            "on: pull_request\n",
            "on: pull_request\nenv:\n  GH_TOKEN: workflow-token-placeholder\n",
        )
        .replace(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    env:\n      GH_TOKEN: job-token-placeholder\n",
        )
        .replace(
            "      - uses: actions/checkout@v4\n",
            "      - uses: actions/checkout@v4\n        env:\n          GH_TOKEN: ''\n",
        )
        .replace(
            "      - run: {command}\n",
            "      - run: bash ./scripts/check.sh\n        env:\n          GH_TOKEN: ''\n",
        )
    )
    assert content.count("GH_TOKEN: ''") == 2
    _, findings = scan(tmp_path, content)

    assert not _script_leaves(findings)
    assert not _chains(findings)


def test_nonempty_literal_gh_token_env_keeps_ordinary_pr_unresolved(tmp_path):
    content = (
        BASE.replace("on: pull_request_target", "on: pull_request")
        .replace("contents: write", "contents: read")
        .replace("persist-credentials: true", "persist-credentials: false")
        .replace(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    env:\n      GH_TOKEN: token-placeholder\n",
        )
        .replace("{command}", "bash ./scripts/check.sh")
    )
    _, findings = scan(tmp_path, content)

    (leaf,) = _script_leaves(findings)
    assert leaf.severity == Severity.MEDIUM
    assert leaf.confidence == "medium"
    assert leaf.review_needed is True
    assert leaf._checkout_build is None
    assert "authority-unresolved" in leaf.context_tags
    assert not _chains(findings)


@pytest.mark.parametrize(
    "command",
    [
        "bash -c './scripts/check.sh'",
        "bash ${{ inputs.script }}",
        "python3 -c 'import runpy; runpy.run_path(\"./scripts/check.sh\")'",
    ],
    ids=["shell-command-string", "dynamic-path", "python-eval"],
)
def test_wrappers_and_dynamic_operands_do_not_form_local_file_witness(tmp_path, command):
    _, findings = scan(tmp_path, BASE.replace("{command}", command))

    assert not [f for f in _script_leaves(findings) if f._checkout_build is not None]
    assert not _chains(findings)


def test_step_before_checkout_cannot_get_source_bound_chain(tmp_path):
    content = BASE.replace("{command}", "bash ./scripts/check.sh")
    content = content.replace("      - run: bash ./scripts/check.sh\n", "", 1)
    content = content.replace(
        "      - uses: actions/checkout@v4\n",
        "      - run: bash ./scripts/check.sh\n      - uses: actions/checkout@v4\n",
        1,
    )
    _, findings = scan(tmp_path, content)

    assert not _script_leaves(findings)
    assert not _chains(findings)


INHERITED_PYTHON_SHELL = """on: pull_request_target
permissions:
  contents: write
jobs:
  shell_source:
    runs-on: ubuntu-latest
    defaults:
      run: &python_defaults
        shell: python
    steps:
      - run: print("safe")
  build:
    defaults:
      run:
        <<: *python_defaults
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: true
      - run: bash ./scripts/check.sh
"""


def test_merged_inherited_python_shell_has_no_local_script_candidate(tmp_path):
    _assert_source_sha256(
        INHERITED_PYTHON_SHELL,
        "a0f932d9c2a96a79a0db4f439ddd0d06fc8d8dc532023a292a7caf7aaf75cc7f",
    )
    path = tmp_path / ".github" / "workflows" / "inherited-python-shell.yml"

    assert not scan_local_script_file(
        path, INHERITED_PYTHON_SHELL, expect_merged_shell_diagnostic=True
    )


def test_step_bash_shell_overrides_inherited_python_default(tmp_path):
    content = INHERITED_PYTHON_SHELL.replace(
        "      - run: bash ./scripts/check.sh\n",
        "      - run: bash ./scripts/check.sh\n        shell: bash\n",
    )
    path = tmp_path / ".github" / "workflows" / "explicit-bash-shell.yml"

    (leaf,) = scan_local_script_file(path, content, expect_merged_shell_diagnostic=True)
    assert leaf.line == 23
    assert leaf.review_needed is True


@pytest.mark.parametrize(
    ("command", "expected_sha256"),
    [
        (
            "cat <<\\EOF\n          bash ./scripts/check.sh\n          EOF",
            "f99763e46cb1625979676d91ddb560e2e0287ee252001e39c1832d9a181f95c5",
        ),
        (
            "cat <<'1'\n          bash ./scripts/check.sh\n          1",
            "4ed44584b72d40bc63c1ab0db72c111ef794834db64283c5e46f2596276c2ec9",
        ),
    ],
    ids=["escaped-delimiter", "quoted-numeric-delimiter"],
)
def test_valid_heredoc_bodies_are_not_local_script_invocations(tmp_path, command, expected_sha256):
    content = BASE.replace("{command}", f"|\n          {command}")
    _assert_source_sha256(content, expected_sha256)
    path = tmp_path / ".github" / "workflows" / "heredoc.yml"

    assert not scan_local_script_file(path, content)


def test_unquoted_heredoc_opener_suppresses_its_body_candidate(tmp_path):
    content = BASE.replace(
        "{command}",
        "|\n          cat <<EOF\n          bash ./scripts/check.sh\n          EOF",
    )
    path = tmp_path / ".github" / "workflows" / "unquoted-heredoc.yml"

    assert not scan_local_script_file(path, content)


def test_unsupported_heredoc_keeps_prior_literal_invocation_only(tmp_path):
    content = BASE.replace(
        "{command}",
        "|\n"
        "          bash ./scripts/first.sh\n"
        "          cat <<\\EOF\n"
        "          bash ./scripts/body.sh\n"
        "          EOF",
    )
    path = tmp_path / ".github" / "workflows" / "heredoc-after-command.yml"

    (leaf,) = scan_local_script_file(path, content)
    assert leaf.line == 14
    assert "first.sh" in leaf.snippet
    assert "body.sh" not in leaf.snippet
    assert leaf._checkout_build is None

    workflow = tmp_path / ".github" / "workflows" / "heredoc-after-command.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(content, encoding="utf-8")
    reports = scan_repo(str(tmp_path), load_all_rules(), Platform.GITHUB)
    findings = [finding for report in reports for finding in report.findings]
    assert not [finding for finding in findings if finding.rule_id == "CHAIN-GH-101"]


def test_scan_file_accepts_standalone_github_yaml_but_not_jenkinsfile(tmp_path):
    content = BASE.replace("{command}", "bash ./scripts/check.sh")
    _assert_source_sha256(
        content,
        "45f001d8973e021ea77fd195188d05376b5d3ed9dd76b1c5747900155b95c902",
    )

    canonical = tmp_path / ".github" / "workflows" / "true-posix-invocation.yml"
    standalone = tmp_path / "standalone-workflow.yml"
    jenkinsfile = tmp_path / "Jenkinsfile"
    (leaf,) = scan_local_script_file(canonical, content)
    (standalone_leaf,) = scan_local_script_file(standalone, content)

    assert leaf.line == 13
    assert standalone_leaf.line == 13
    assert not scan_local_script_file(jenkinsfile, content)
