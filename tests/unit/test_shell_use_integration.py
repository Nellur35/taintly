"""Distinct binding, propagation and composition obligations for shell-role evidence."""

from dataclasses import replace

import pytest

from taintly.composer import run_composer
from taintly.engine import scan_repo
from taintly.models import Finding, Platform, Severity
from taintly.rules.github import taint as taint_rules
from taintly.rules.github.chain_compose import _compose_chain_gh_103
from taintly.shell_use import ShellUse, classify_shell_use
from taintly.taint import analyze
from taintly.workflow_corpus import WorkflowCorpus, _summarize_workflow


def _content(command):
    return (
        "on: pull_request_target\npermissions: write-all\njobs:\n  inspect:\n"
        "    runs-on: ubuntu-latest\n    steps:\n      - shell: bash\n"
        "        env:\n          TITLE: ${{ github.event.pull_request.title }}\n"
        f"        run: {command}\n"
    )


def _corpus(content):
    return WorkflowCorpus(
        repo_path="/repo",
        workflows={"ci.yml": _summarize_workflow("ci.yml", content)},
    )


def _finding(content):
    (path,) = analyze(content, content.splitlines())
    finding = Finding("TAINT-GH-001", Severity.MEDIUM, "review", "review", "ci.yml", path.sink_line)
    finding.snippet = taint_rules._format_chain(path)
    finding._shell_use = classify_shell_use(content, path, "ci.yml")
    return finding


def test_filtered_and_reordered_matches_keep_their_source_identity():
    content = _content("printf '%s\\n' $TITLE") + (
        "      - shell: bash\n        env:\n"
        "          BODY: ${{ github.event.pull_request.body }}\n"
        '        run: eval "$BODY"\n'
    )
    pattern = taint_rules.TaintPattern(kind_filter="shallow", sink_quote_filter="unsafe_only")
    matches = pattern.check(content, content.splitlines())
    assert len(matches) == 2
    contexts = pattern.context_notes_for_matches(content, "ci.yml", matches[::-1])
    assert [ctx.path_key[0] for ctx in contexts] == [
        "github.event.pull_request.body",
        "github.event.pull_request.title",
    ]
    assert [ctx.disposition for ctx in contexts] == [ShellUse.CODE, ShellUse.DATA]
    (single,) = pattern.context_notes_for_matches(content, "ci.yml", matches[:1])
    assert single == contexts[1]
    assert pattern.context_notes_for_matches(content, "ci.yml", [(999, "absent")]) == [None]


def test_rendered_match_collisions_do_not_choose_a_path(monkeypatch):
    content = _content("printf '%s\\n' $TITLE")
    (path,) = analyze(content, content.splitlines())
    duplicate = replace(
        path, hops=[replace(hop, detail=hop.detail + " alternate") for hop in path.hops]
    )
    monkeypatch.setattr(taint_rules, "taint_analyze", lambda *_: [path, duplicate])
    pattern = taint_rules.TaintPattern(kind_filter="shallow", sink_quote_filter="unsafe_only")
    matches = pattern.check(content, content.splitlines())
    assert len(matches) == 2 and matches[0] == matches[1]
    contexts = pattern.context_notes_for_matches(content, "ci.yml", matches)
    assert all(context.disposition is ShellUse.UNKNOWN for context in contexts)


def test_only_validated_all_data_can_remove_the_execution_chain():
    content = _content("printf '%s\\n' $TITLE")
    finding = _finding(content)
    assert finding._shell_use.disposition is ShellUse.DATA
    corpus = _corpus(content)
    assert run_composer(corpus, [finding], [_compose_chain_gh_103]) == []
    legacy = replace(finding, _shell_use=None)
    stale = replace(finding, _shell_use=replace(finding._shell_use, source_sha256="stale"))
    foreign = replace(finding, origin="platform")
    wrong_owner = replace(
        finding, _shell_use=replace(finding._shell_use, owner_path=("jobs", "other", "steps", 0))
    )
    for supplied in (legacy, stale, foreign, wrong_owner):
        (chain,) = run_composer(corpus, [supplied], [_compose_chain_gh_103])
        assert "consumption remains unresolved" in chain.snippet
    # Identity collapse must not discard a second unresolved contributor.
    assert len(run_composer(corpus, [finding, legacy], [_compose_chain_gh_103])) == 1


def test_valid_code_contributor_survives_an_earlier_forged_data_witness():
    content = _content('eval "$TITLE"')
    finding = _finding(content)
    assert finding._shell_use.disposition is ShellUse.CODE
    forged = replace(
        finding,
        snippet="forged data explanation",
        _shell_use=replace(finding._shell_use, disposition=ShellUse.DATA),
    )
    observed = []

    def capture(db):
        observed[:] = db.all("finding")
        return []

    corpus = _corpus(content)
    (chain,) = run_composer(corpus, [forged, finding], [capture, _compose_chain_gh_103])
    assert len(observed) == 1 and observed[0].shell_use == "code"
    assert observed[0].snippet == finding.snippet
    assert finding.snippet in chain.snippet and forged.snippet not in chain.snippet
    assert "configured code use is source-bound" in chain.snippet
    (unknown,) = run_composer(corpus, [forged], [_compose_chain_gh_103])
    assert "consumption remains unresolved" in unknown.snippet


@pytest.mark.parametrize(
    "bridge,rule_id",
    [("multi_hop", "TAINT-GH-002"), ("github_env", "TAINT-GH-003"), ("inputs", "TAINT-GH-017")],
)
def test_shared_propagation_adapters_qualify_data(tmp_path, github_rules, bridge, rule_id):
    content = _content("printf '%s\\n' $TITLE")
    if bridge == "multi_hop":
        content = content.replace(
            "TITLE: ${{ github.event.pull_request.title }}",
            "RAW: ${{ github.event.pull_request.title }}\n          TITLE: ${{ env.RAW }}",
        )
    elif bridge == "github_env":
        content = content.replace(
            "TITLE: ${{ github.event.pull_request.title }}",
            "RAW: ${{ github.event.pull_request.title }}",
        )
        content = content.replace(
            "        run: printf '%s\\n' $TITLE",
            '        run: echo "TITLE=$RAW" >> "$GITHUB_ENV"\n      - shell: bash\n        run: printf \'%s\\n\' $TITLE',
        )
    else:
        content = content.replace("github.event.pull_request.title", "inputs.title")
        content = content.replace("on: pull_request_target", "on: workflow_call")
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(content, encoding="utf-8")
    rules = [rule for rule in github_rules if rule.id == rule_id]
    reports = scan_repo(str(tmp_path), rules, Platform.GITHUB)
    assert len(reports) == 1 and reports[0].engine_errors() == []
    (finding,) = reports[0].findings
    assert finding.rule_id == rule_id and finding._shell_use.disposition is ShellUse.DATA
    assert finding.severity is Severity.MEDIUM and finding.review_needed
    assert finding.exploitability != "high"
    assert "_shell_use" not in finding.to_dict()


def test_unknown_stays_reviewable_without_mutating_shared_rules(tmp_path, github_rules):
    content = _content("arbitrary-tool $TITLE")
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(content, encoding="utf-8")
    rules = [rule for rule in github_rules if rule.id in {"TAINT-GH-001", "CHAIN-GH-103"}]
    metadata = [(r.id, r.title, r.description, r.severity, list(r.stride)) for r in rules]
    (report,) = scan_repo(str(tmp_path), rules, Platform.GITHUB)
    assert report.engine_errors() == []
    (finding,) = [f for f in report.findings if f.rule_id == "TAINT-GH-001"]
    assert finding.review_needed and finding.confidence == "low"
    assert finding.severity is Severity.MEDIUM and finding.exploitability != "high"
    assert "unresolved" in finding.title
    assert len([f for f in report.findings if f.rule_id == "CHAIN-GH-103"]) == 1
    assert [(r.id, r.title, r.description, r.severity, list(r.stride)) for r in rules] == metadata


@pytest.mark.parametrize(
    "command,expected",
    [
        ('printf "$FMT%s" "$TITLE"', ShellUse.UNKNOWN),
        ('printf "$FMT%s" "$TITLE" | sh', ShellUse.UNKNOWN),
        ("printf '$FMT%s' \"$TITLE\"", ShellUse.DATA),
        ("printf '$FMT%s' \"$TITLE\" | sh", ShellUse.CODE),
    ],
)
def test_printf_format_must_be_literal_under_actual_shell_quoting(command, expected):
    content = _content(command)
    finding = _finding(content)
    assert finding._shell_use.disposition is expected


def test_canonical_taint_missing_occurrence_evidence_stays_unknown(
    tmp_path, github_rules, monkeypatch
):
    content = _content('eval "$TITLE"')
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(content, encoding="utf-8")
    (rule,) = [rule for rule in github_rules if rule.id == "TAINT-GH-001"]
    monkeypatch.setattr(rule.pattern, "context_notes_for_matches", lambda *_: None)
    (report,) = scan_repo(str(tmp_path), [rule], Platform.GITHUB)
    assert report.engine_errors() == []
    (finding,) = report.findings
    assert finding.rule_id == "TAINT-GH-001"
    assert finding._shell_use is None
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence == "low" and finding.review_needed
    assert "shell-use-unknown" in finding.context_tags
