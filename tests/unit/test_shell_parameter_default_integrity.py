from __future__ import annotations

from dataclasses import replace

from taintly.composer import run_composer
from taintly.engine import _qualify_shell_use, scan_file
from taintly.models import Finding, Severity
from taintly.rules.github.chain_compose import _compose_chain_gh_103
from taintly.shell_use import (
    NonemptyParameterDefault,
    ShellUse,
    classify_shell_use,
    validate_shell_use,
)
from taintly.taint import analyze
from taintly.workflow_corpus import WorkflowCorpus, _summarize_workflow


def _workflow() -> str:
    return (
        "on: pull_request_target\n"
        "jobs:\n"
        "  greet:\n"
        "    runs-on: ubuntu-latest\n"
        "    env:\n"
        "      TITLE: ${{ github.event.pull_request.title }}\n"
        "    steps:\n"
        "      - name: consume\n"
        '        run: eval "${TITLE:-literal}"\n'
        "        shell: bash\n"
    )


def test_modified_parameter_condition_is_not_serialized_or_composed(tmp_path, github_rules):
    content = _workflow()
    path = next(
        item
        for item in analyze(content, content.splitlines())
        if item.env_var == "TITLE" and item.sink_kind == "run"
    )
    witness = classify_shell_use(content, path, "workflow.yml")
    forged = replace(
        witness,
        parameter_default=NonemptyParameterDefault("INJECTED", "other_literal"),
    )
    assert witness.disposition is ShellUse.CODE
    assert not validate_shell_use(forged, content, "workflow.yml", path.sink_line)

    stale = Finding(
        rule_id="TAINT-GH-001",
        severity=Severity.CRITICAL,
        title="candidate",
        description="candidate",
        file="workflow.yml",
        line=path.sink_line,
        context_notes=list(forged.notes),
    )
    _qualify_shell_use(stale, forged, content)
    assert stale.review_needed is True
    assert "INJECTED contributes" not in " ".join(stale.to_dict()["context_notes"])
    assert "INJECTED contributes" not in stale.to_dict()["description"]

    workflow_path = tmp_path / ".github" / "workflows" / "conditional.yml"
    workflow_path.parent.mkdir(parents=True)
    workflow_path.write_text(content, encoding="utf-8")
    rule = next(rule for rule in github_rules if rule.id == "TAINT-GH-001")
    (finding,) = scan_file(str(workflow_path), [rule], _content=content)
    finding_witness = finding._shell_use
    assert finding_witness.file == finding.file
    assert finding_witness.path_key == witness.path_key
    corpus = WorkflowCorpus(
        repo_path=str(tmp_path),
        workflows={
            str(workflow_path): _summarize_workflow(str(workflow_path), content),
        },
    )
    invalid_contributor = replace(
        finding,
        context_notes=list(finding.context_notes),
        context_tags=list(finding.context_tags),
    )
    invalid_contributor._shell_use = replace(
        finding_witness,
        parameter_default=NonemptyParameterDefault("INJECTED", "other_literal"),
    )
    (chain,) = run_composer(corpus, [invalid_contributor, finding], [_compose_chain_gh_103])
    assert chain.chain_id == "CHAIN-GH-103"
    assert "TITLE contributes only when it is set and nonempty" in chain.snippet
    assert "INJECTED contributes" not in chain.snippet

    (invalid_only_chain,) = run_composer(corpus, [invalid_contributor], [_compose_chain_gh_103])
    assert invalid_only_chain.chain_id == "CHAIN-GH-103"
    assert "set and nonempty" not in invalid_only_chain.snippet


def test_wrong_condition_payload_type_fails_closed_without_losing_other_notes():
    content = _workflow()
    path = next(
        item
        for item in analyze(content, content.splitlines())
        if item.env_var == "TITLE" and item.sink_kind == "run"
    )
    evidence = classify_shell_use(content, path, "workflow.yml")
    malformed = replace(evidence, parameter_default="bad")
    assert malformed.notes == (evidence.reason,)
    assert not validate_shell_use(malformed, content, "workflow.yml", path.sink_line)

    finding = Finding(
        rule_id="TAINT-GH-001",
        severity=Severity.CRITICAL,
        title="candidate",
        description="candidate",
        file="workflow.yml",
        line=path.sink_line,
        context_notes=[*malformed.notes, "independent owner note remains available"],
    )
    _qualify_shell_use(finding, malformed, content)
    assert finding._shell_use is None
    assert finding.review_needed is True
    assert "shell-use-unknown" in finding.context_tags
    assert "independent owner note remains available" in finding.context_notes
    assert not any("set and nonempty" in note for note in finding.context_notes)
