"""JavaScript environment data is unsafe only when a supported consumer compiles it."""

from __future__ import annotations

import pytest

from taintly.engine import scan_file
from taintly.families import classify_rule
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform


def _workflow(run: str, *, binding: str = "github.event.pull_request.title") -> str:
    return (
        "name: js-env-contract\non:\n  pull_request:\n    types: [opened, synchronize]\n"
        "permissions:\n  contents: read\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - name: inspect title\n        env:\n"
        f"          PR_TITLE: ${{{{ {binding} }}}}\n"
        f"        run: |\n          {run}\n"
    )


def _hits(content: str):
    rules = load_rules_for_platform(Platform.GITHUB)
    findings = scan_file(".github/workflows/workflow.yml", rules, _content=content)
    return [finding for finding in findings if finding.rule_id == "TAINT-GH-020"]


def _findings(content: str):
    return scan_file(
        ".github/workflows/workflow.yml",
        load_rules_for_platform(Platform.GITHUB),
        _content=content,
    )


def test_pr_title_in_node_eval_is_reported_by_actual_registry_scan():
    content = _workflow("node -e 'eval(process.env.PR_TITLE)'")
    hits = _hits(content)
    expected_line = next(
        i for i, line in enumerate(content.splitlines(), 1) if line.strip().startswith("node -e")
    )
    assert len(hits) == 1
    assert hits[0].line == expected_line
    assert hits[0].snippet == content.splitlines()[expected_line - 1].strip()
    assert hits[0].review_needed is True
    assert "conditional" in hits[0].description.lower()
    assert "environment indirection does not sanitize" in hits[0].remediation.lower()
    assert "allowlist" in hits[0].remediation.lower()


def test_flow_style_run_reports_exact_physical_command_line():
    content = (
        "on: pull_request\n"
        "jobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n"
        '      - env: { PR_TITLE: "${{ github.event.pull_request.title }}" }\n'
        "        run: node -e 'eval(process.env.PR_TITLE)'\n"
    )
    hits = _hits(content)
    expected_line = next(i for i, line in enumerate(content.splitlines(), 1) if "run:" in line)
    assert len(hits) == 1
    assert hits[0].line == expected_line
    assert hits[0].snippet == content.splitlines()[expected_line - 1].strip()


def test_folded_split_command_cites_the_physical_node_token():
    content = _workflow("node -e 'eval(process.env.PR_TITLE)'").replace(
        "run: |\n          node -e 'eval(process.env.PR_TITLE)'",
        "run: >-\n          node\n          -e 'eval(process.env.PR_TITLE)'",
    )
    hits = _hits(content)
    expected_line = content.splitlines().index("          node") + 1
    assert len(hits) == 1
    assert hits[0].line == expected_line
    assert hits[0].snippet == "node"


def test_pr_title_in_invoked_function_constructor_is_reported():
    hits = _hits(_workflow("node --eval 'new Function(process.env.PR_TITLE)()'"))
    assert len(hits) == 1
    assert "conditional" in hits[0].description.lower()


def test_json_logging_is_data_not_dynamic_code():
    hits = _hits(_workflow("node -e 'console.log(JSON.stringify({title: process.env.PR_TITLE}))'"))
    assert hits == []


def test_transformed_eval_argument_is_unknown_not_proven_code_use():
    findings = _findings(_workflow("node -e 'eval(JSON.stringify(process.env.PR_TITLE))'"))
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(
        f.rule_id == "ENGINE-ERR"
        and "transformed JavaScript eval/Function argument" in f.description
        for f in findings
    )


def test_string_plus_environment_in_eval_argument_is_unknown_not_proven_code_use():
    findings = _findings(_workflow("node -e 'eval(\"literal\" + process.env.PR_TITLE)'"))
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(
        f.rule_id == "ENGINE-ERR"
        and "transformed JavaScript eval/Function argument" in f.description
        for f in findings
    )


def test_undefined_console_result_passed_to_eval_is_not_treated_as_source_flow():
    findings = _findings(_workflow("node -e 'eval(console.log(process.env.PR_TITLE))'"))
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(
        f.rule_id == "ENGINE-ERR"
        and "transformed JavaScript eval/Function argument" in f.description
        for f in findings
    )


def test_dynamic_global_handler_is_unresolved_not_reported_as_safe_or_confirmed():
    findings = _findings(
        _workflow("node -e 'globalThis[process.env.TITLE_HANDLER](process.env.PR_TITLE)'").replace(
            "PR_TITLE: ${{ github.event.pull_request.title }}",
            "PR_TITLE: ${{ github.event.pull_request.title }}\n          TITLE_HANDLER: ${{ vars.TITLE_HANDLER }}",
        )
    )
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    diagnostics = [f for f in findings if f.rule_id == "ENGINE-ERR"]
    assert any("unresolved computed JavaScript dispatch" in f.description for f in diagnostics)


def test_strings_comments_shadowing_and_shell_wrappers_are_not_direct_builtin_sinks():
    cases = [
        "node -e 'console.log(\"eval(process.env.PR_TITLE)\")'",
        "node -e '/* eval(process.env.PR_TITLE) */ console.log(process.env.PR_TITLE)'",
        "node -e 'const eval = other; eval(process.env.PR_TITLE)'",
        "node -e 'const { eval } = api; eval(process.env.PR_TITLE)'",
        "node -e 'const { process } = api; eval(process.env.PR_TITLE)'",
        "env node -e 'eval(process.env.PR_TITLE)'",
        "node -e 'eval(process.env.PR_TITLE)'; echo done",
    ]
    for command in cases:
        assert _hits(_workflow(command)) == [], command


def test_job_scope_environment_is_outside_the_supported_step_local_flow():
    content = (
        _workflow("node -e 'eval(process.env.PR_TITLE)'")
        .replace("        env:\n          PR_TITLE: ${{ github.event.pull_request.title }}\n", "")
        .replace(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    env:\n      PR_TITLE: ${{ github.event.pull_request.title }}\n",
        )
    )
    assert _hits(content) == []


def test_possible_eval_alias_is_disclosed_as_incomplete_not_called_safe():
    findings = _findings(_workflow("node -e 'const compile = eval; compile(process.env.PR_TITLE)'"))
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(
        f.rule_id == "ENGINE-ERR" and "possible JavaScript code-constructor alias" in f.description
        for f in findings
    )


def test_prior_environment_overwrite_is_unresolved_not_trusted_as_source():
    findings = _findings(
        _workflow("node -e 'process.env.PR_TITLE = \"fixed\"; eval(process.env.PR_TITLE)'")
    )
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(
        f.rule_id == "ENGINE-ERR"
        and "transformed JavaScript eval/Function argument" in f.description
        for f in findings
    )


def test_effective_workflow_and_job_shell_defaults_are_resolved():
    workflow_default = _workflow("node -e 'eval(process.env.PR_TITLE)'").replace(
        "permissions:\n  contents: read\n",
        "defaults:\n  run:\n    shell: bash\npermissions:\n  contents: read\n",
    )
    assert len(_hits(workflow_default)) == 1

    job_override = _workflow("node -e 'eval(process.env.PR_TITLE)'").replace(
        "    runs-on: ubuntu-latest\n",
        "    runs-on: ubuntu-latest\n    defaults:\n      run:\n        shell: pwsh\n",
    )
    findings = _findings(job_override)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(
        f.rule_id == "ENGINE-ERR" and "outside the supported Bash profile" in f.description
        for f in findings
    )

    step_override = job_override.replace(
        "        run: |\n", "        shell: bash\n        run: |\n"
    )
    assert len(_hits(step_override)) == 1


def test_duplicate_effective_shell_and_container_owners_are_unknown():
    duplicate_shell = _workflow("node -e 'eval(process.env.PR_TITLE)'").replace(
        "permissions:\n  contents: read\n",
        "defaults:\n  run:\n    shell: bash\n    shell: bash\npermissions:\n  contents: read\n",
    )
    findings = _findings(duplicate_shell)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(f.rule_id == "ENGINE-ERR" for f in findings)

    duplicate_container = _workflow("node -e 'eval(process.env.PR_TITLE)'").replace(
        "    runs-on: ubuntu-latest\n",
        "    runs-on: ubuntu-latest\n    container: ubuntu:latest\n    container: ubuntu:latest\n",
    )
    findings = _findings(duplicate_container)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(
        f.rule_id == "ENGINE-ERR" and "duplicate job container keys" in f.description
        for f in findings
    )

    duplicate_env_owner = _workflow("node -e 'eval(process.env.PR_TITLE)'").replace(
        "        run: |\n",
        "        env:\n          OTHER: fixed\n        run: |\n",
    )
    findings = _findings(duplicate_env_owner)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(
        f.rule_id == "ENGINE-ERR" and "ownership ambiguous" in f.description for f in findings
    )


def test_duplicate_ancestor_mappings_do_not_combine_separate_owners():
    base = _workflow("node -e 'eval(process.env.PR_TITLE)'")
    cases = [
        base.replace(
            "jobs:\n", "jobs:\n  other:\n    runs-on: ubuntu-latest\n    steps: []\njobs:\n", 1
        ),
        base.replace(
            "  inspect:\n", "  inspect: {runs-on: ubuntu-latest, steps: []}\n  inspect:\n", 1
        ),
        base.replace("    steps:\n", "    steps: []\n    steps:\n", 1),
        base.replace(
            "permissions:\n  contents: read\n",
            "defaults:\n  run:\n    shell: bash\ndefaults:\n  run:\n    shell: bash\npermissions:\n  contents: read\n",
            1,
        ),
    ]
    for content in cases:
        findings = _findings(content)
        assert not any(f.rule_id == "TAINT-GH-020" for f in findings), content
        assert any(f.rule_id == "ENGINE-ERR" for f in findings), content


def test_unbalanced_quotes_and_shell_expansions_are_unknown():
    cases = [
        "node -e 'eval(process.env.PR_TITLE)",
        "node -e eval(process.env.PR_TITLE)",
        "node -e 'eval(process.env.PR_TITLE)' \"$EXTRA\"",
    ]
    for command in cases:
        findings = _findings(_workflow(command))
        assert not any(f.rule_id == "TAINT-GH-020" for f in findings), command
        assert any(f.rule_id == "ENGINE-ERR" for f in findings), command


def test_unquoted_newline_is_a_command_boundary_not_an_argv_separator():
    content = _workflow("node\n-e 'eval(process.env.PR_TITLE)'").replace(
        "\n-e 'eval(process.env.PR_TITLE)'", "\n          -e 'eval(process.env.PR_TITLE)'"
    )
    findings = _findings(content)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(f.rule_id == "ENGINE-ERR" for f in findings)


def test_duplicate_step_environment_key_is_ambiguous_not_falsely_owned():
    content = _workflow("node -e 'eval(process.env.PR_TITLE)'").replace(
        "          PR_TITLE: ${{ github.event.pull_request.title }}\n",
        "          PR_TITLE: fixed\n          PR_TITLE: ${{ github.event.pull_request.title }}\n",
    )
    findings = _findings(content)
    assert not any(f.rule_id == "TAINT-GH-020" for f in findings)
    assert any(
        f.rule_id == "ENGINE-ERR" and "duplicate step environment key" in f.description
        for f in findings
    )


def test_rule_metadata_and_self_test_examples_are_registered():
    rules = load_rules_for_platform(Platform.GITHUB)
    rule = next(rule for rule in rules if rule.id == "TAINT-GH-020")
    assert rule.severity.value == "HIGH"
    assert rule.finding_family == "script_injection"
    assert classify_rule(rule.id, rule.owasp_cicd) == "script_injection"
    assert rule.review_needed is True
    assert rule.test_positive
    assert rule.test_negative
    assert "environment indirection does not sanitize" in rule.remediation.lower()
    assert "allowlist" in rule.remediation.lower()


def test_supported_and_unknown_source_fixtures_are_valid_yaml():
    yaml_module = pytest.importorskip("ruamel.yaml")
    yaml = yaml_module.YAML(typ="safe")
    cases = [
        _workflow("node -e 'console.log(JSON.stringify({title: process.env.PR_TITLE}))'"),
        _workflow("node -e 'globalThis[process.env.TITLE_HANDLER](process.env.PR_TITLE)'").replace(
            "PR_TITLE: ${{ github.event.pull_request.title }}",
            "PR_TITLE: ${{ github.event.pull_request.title }}\n          TITLE_HANDLER: ${{ vars.TITLE_HANDLER }}",
        ),
    ]
    for rule in load_rules_for_platform(Platform.GITHUB):
        if rule.id == "TAINT-GH-020":
            cases.extend(rule.test_positive)
            cases.extend(rule.test_negative)
            break
    for source in cases:
        yaml.load(source)
