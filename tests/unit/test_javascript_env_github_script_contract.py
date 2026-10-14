"""Bounded tests for github-script's inline JavaScript input."""

from __future__ import annotations

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform


def _workflow(script: str, *, use: str = "actions/github-script@v7", env: str = "") -> str:
    env_block = f"        env:\n{env}" if env else ""
    return (
        "name: github-script-owned-inline-contract\non: pull_request\n"
        "permissions:\n  contents: read\njobs:\n  inspect:\n"
        "    runs-on: ubuntu-latest\n    steps:\n"
        f"      - uses: {use}\n{env_block}"
        "        with:\n          script: |\n"
        + "\n".join(f"            {line}" for line in script.splitlines())
        + "\n"
    )


def _findings(content: str):
    return scan_file(
        ".github/workflows/inline.yml",
        load_rules_for_platform(Platform.GITHUB),
        _content=content,
    )


def _taint_hits(content: str):
    return [f for f in _findings(content) if f.rule_id == "TAINT-GH-020"]


def _taint020_incomplete(findings) -> bool:
    return any(
        finding.rule_id == "ENGINE-ERR"
        and finding.title.startswith("Rule TAINT-GH-020 returned incomplete pattern results for ")
        for finding in findings
    )


def test_unique_tracked_step_env_reaching_github_script_eval_is_reported():
    content = _workflow(
        "eval(process.env.PR_TEXT)",
        env="          PR_TEXT: ${{ github.event.pull_request.title }}\n",
    )
    hits = _taint_hits(content)
    script_body_line = next(
        i
        for i, line in enumerate(content.splitlines(), 1)
        if line.strip() == "eval(process.env.PR_TEXT)"
    )
    assert len(hits) == 1
    assert hits[0].line == script_body_line
    assert hits[0].review_needed is True
    assert "conditional" in hits[0].description.lower()
    assert "github-script@v7" in hits[0].description


def test_github_script_console_use_is_a_safe_data_twin():
    content = _workflow(
        "console.log(process.env.PR_TEXT)",
        env="          PR_TEXT: ${{ github.event.pull_request.title }}\n",
    )
    findings = _findings(content)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert not any(f.rule_id == "ENGINE-ERR" for f in findings)


def test_github_script_eval_alias_is_unknown_not_reported_safe():
    content = _workflow(
        "const compile = eval\ncompile(process.env.PR_TEXT)",
        env="          PR_TEXT: ${{ github.event.pull_request.title }}\n",
    )
    findings = _findings(content)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(f.rule_id == "ENGINE-ERR" for f in findings)


def test_workflow_expression_inside_javascript_string_is_not_erased_as_data():
    findings = _findings(_workflow('eval("${{ github.event.pull_request.title }}")', env=""))
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(f.rule_id == "ENGINE-ERR" for f in findings)


def test_unsupported_github_script_ref_remains_unknown():
    content = _workflow(
        "eval(process.env.PR_TEXT)",
        use="actions/github-script@main",
        env="          PR_TEXT: ${{ github.event.pull_request.title }}\n",
    )
    findings = _findings(content)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(f.rule_id == "ENGINE-ERR" for f in findings)


def test_unowned_process_env_read_by_eval_remains_unknown():
    findings = _findings(_workflow("eval(process.env.PR_TEXT)"))
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(f.rule_id == "ENGINE-ERR" for f in findings)


def test_duplicate_with_script_owner_is_unknown():
    content = _workflow(
        "eval(process.env.PR_TEXT)",
        env="          PR_TEXT: ${{ github.event.pull_request.title }}\n",
    ).replace("        with:\n", "        with: {}\n        with:\n")
    findings = _findings(content)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(f.rule_id == "ENGINE-ERR" for f in findings)


def test_github_script_with_both_uses_and_run_is_unknown():
    content = _workflow(
        "eval(process.env.PR_TEXT)",
        env="          PR_TEXT: ${{ github.event.pull_request.title }}\n",
    ).replace(
        "      - uses: actions/github-script@v7\n",
        "      - uses: actions/github-script@v7\n        run: echo noop\n",
    )
    findings = _findings(content)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(f.rule_id == "ENGINE-ERR" for f in findings)


def test_github_script_computed_global_dispatch_is_unknown():
    content = _workflow(
        "globalThis[process.env.HANDLER](process.env.PR_TEXT)",
        env=(
            "          PR_TEXT: ${{ github.event.pull_request.title }}\n"
            "          HANDLER: ${{ vars.TITLE_HANDLER }}\n"
        ),
    )
    findings = _findings(content)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(f.rule_id == "ENGINE-ERR" for f in findings)


def test_github_script_scalar_env_alias_is_unknown():
    content = _workflow(
        "eval(process.env.PR_TEXT)",
        env="          PR_TEXT: &tracked ${{ github.event.pull_request.title }}\n",
    )
    findings = _findings(content)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(f.rule_id == "ENGINE-ERR" for f in findings)


def test_github_script_scalar_script_alias_is_unknown():
    content = _workflow(
        "eval(process.env.PR_TEXT)",
        env="          PR_TEXT: ${{ github.event.pull_request.title }}\n",
    ).replace(
        "        with:\n          script: |\n            eval(process.env.PR_TEXT)\n",
        "        with:\n          source: &program eval(process.env.PR_TEXT)\n"
        "          script: *program\n",
    )
    findings = _findings(content)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(f.rule_id == "ENGINE-ERR" for f in findings)


def test_unverified_github_script_subref_remains_unknown():
    content = _workflow(
        "eval(process.env.PR_TEXT)",
        use="actions/github-script@v7.1",
        env="          PR_TEXT: ${{ github.event.pull_request.title }}\n",
    )
    findings = _findings(content)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(f.rule_id == "ENGINE-ERR" for f in findings)


def test_external_anchor_alias_in_candidate_job_is_unknown():
    content = (
        "name: external anchor source boundary\non: pull_request\njobs:\n"
        "  source:\n    runs-on: ubuntu-latest\n    env:\n"
        "      PR_TEXT: &tracked ${{ github.event.pull_request.title }}\n"
        "    steps: []\n  inspect:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/github-script@v7\n"
        "        env:\n          PR_TEXT:    *tracked\n"
        "        with:\n          script: |\n"
        "            eval(process.env.PR_TEXT)\n"
    )
    findings = _findings(content)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(f.rule_id == "ENGINE-ERR" for f in findings)


def test_flow_script_alias_with_closing_brace_is_unknown():
    content = (
        "name: flow alias script boundary\non: pull_request\njobs:\n"
        "  inspect:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/github-script@v7\n        env:\n"
        "          PR_TEXT: ${{ github.event.pull_request.title }}\n"
        "        with: {source: &program 'eval(process.env.PR_TEXT)', script: *program}\n"
    )
    findings = _findings(content)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(f.rule_id == "ENGINE-ERR" for f in findings)


def test_yaml_reuse_in_unrelated_sibling_job_does_not_hide_match():
    content = (
        "name: sibling reuse should be scoped\non: pull_request\njobs:\n"
        "  inspect:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/github-script@v7\n        env:\n"
        "          PR_TEXT: ${{ github.event.pull_request.title }}\n"
        "        with:\n          script: |\n"
        "            eval(process.env.PR_TEXT)\n"
        "  other:\n    runs-on: ubuntu-latest\n    env:\n"
        "      COPY: &copy value\n    steps:\n      - env:\n"
        "          COPY: *copy\n"
    )
    findings = _findings(content)
    hits = [f for f in findings if f.rule_id == "TAINT-GH-020"]
    assert len(hits) == 1


def test_github_script_finding_line_points_to_sink_after_comments():
    content = _workflow(
        "// explanatory comment\n/* eval(process.env.PR_TEXT) is only text */\n"
        "eval(process.env.PR_TEXT)",
        env="          PR_TEXT: ${{ github.event.pull_request.title }}\n",
    )
    hits = _taint_hits(content)
    sink_line = next(
        i
        for i, line in enumerate(content.splitlines(), 1)
        if line.strip() == "eval(process.env.PR_TEXT)"
    )
    assert len(hits) == 1
    assert hits[0].line == sink_line


def test_candidate_job_merge_is_unknown():
    content = (
        "name: merge ownership boundary\non: pull_request\n"
        "x-template: &template\n  env:\n"
        "    PR_TEXT: ${{ github.event.pull_request.title }}\njobs:\n"
        "  inspect:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/github-script@v7\n        <<: *template\n"
        "        with:\n          script: |\n"
        "            eval(process.env.PR_TEXT)\n"
    )
    findings = _findings(content)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(f.rule_id == "ENGINE-ERR" for f in findings)


def test_folded_github_script_source_is_unknown_for_physical_line_mapping():
    content = _workflow(
        "/* note */\neval(process.env.PR_TEXT)",
        env="          PR_TEXT: ${{ github.event.pull_request.title }}\n",
    ).replace("          script: |\n", "          script: >\n")
    findings = _findings(content)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(f.rule_id == "ENGINE-ERR" for f in findings)


def test_unrelated_github_script_interpolation_remains_with_context_rule():
    content = (
        "name: context interpolation is not env-to-code\non: issues\njobs:\n"
        "  inspect:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/github-script@v7\n        env:\n"
        "          PR_TEXT: ${{ github.event.issue.body }}\n        with:\n"
        "          script: |\n"
        "            console.log('${{ github.event.issue.title }}');\n"
    )
    findings = _findings(content)
    ids = {finding.rule_id for finding in findings}

    assert "TAINT-GH-020" not in ids
    assert "ENGINE-ERR" not in ids
    assert "SEC4-GH-025" in ids


def test_computed_process_env_argument_to_eval_remains_unknown():
    content = _workflow(
        'eval(process.env["PR_TEXT"])',
        env="          PR_TEXT: ${{ github.event.pull_request.title }}\n",
    )
    findings = _findings(content)

    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(f.rule_id == "ENGINE-ERR" for f in findings)


def test_lexically_unsupported_computed_dispatch_with_tracked_env_is_unknown():
    content = _workflow(
        "globalThis[process.env.HANDLER](process.env.PR_TEXT); /x/.test('x')",
        env=(
            "          PR_TEXT: ${{ github.event.pull_request.title }}\n"
            "          HANDLER: ${{ vars.TITLE_HANDLER }}\n"
        ),
    )
    findings = _findings(content)

    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert _taint020_incomplete(findings)


def test_lexically_unsupported_string_handler_with_tracked_env_is_unknown():
    content = _workflow(
        "globalThis['eval'](process.env.PR_TEXT); /x/.test('x')",
        env="          PR_TEXT: ${{ github.event.pull_request.title }}\n",
    )
    findings = _findings(content)

    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert _taint020_incomplete(findings)


def test_lexically_unsupported_spaced_computed_dispatch_is_unknown():
    content = _workflow(
        "globalThis[process . env.HANDLER](process . env.PR_TEXT); /x/.test('x')",
        env=(
            "          PR_TEXT: ${{ github.event.pull_request.title }}\n"
            "          HANDLER: ${{ vars.TITLE_HANDLER }}\n"
        ),
    )
    findings = _findings(content)

    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert _taint020_incomplete(findings)


def test_tracked_env_with_unsupported_commented_script_syntax_is_unknown():
    content = _workflow(
        "globalThis [ /* dispatch */ process . env . HANDLER ] "
        "(process . env . PR_TEXT); /x/.test('x')",
        env=(
            "          PR_TEXT: ${{ github.event.pull_request.title }}\n"
            "          HANDLER: ${{ vars.TITLE_HANDLER }}\n"
        ),
    )
    findings = _findings(content)

    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert _taint020_incomplete(findings)


def test_tracked_env_with_unsupported_non_code_syntax_is_unknown_not_a_finding():
    content = _workflow(
        "console.log(process.env.PR_TEXT); /x/.test('x')",
        env="          PR_TEXT: ${{ github.event.pull_request.title }}\n",
    )
    findings = _findings(content)

    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert _taint020_incomplete(findings)


def test_tracked_env_with_non_scalar_github_script_input_is_unknown():
    content = _workflow(
        "unused",
        env="          PR_TEXT: ${{ github.event.pull_request.title }}\n",
    ).replace(
        "          script: |\n            unused\n",
        "          script: [unused, other]\n",
    )
    findings = _findings(content)

    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert _taint020_incomplete(findings)
