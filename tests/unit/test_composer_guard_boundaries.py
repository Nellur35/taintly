"""Regression tests for guard spans and cross-job authority ownership."""

from __future__ import annotations

from taintly.agentguards import AgentGuardIndex
from taintly.composer import (
    Database,
    ExecutionContextFact,
    JobContextFact,
    _certified_guards,
    _execution_structure,
)
from taintly.rules.github.chain_compose import _compose_chain_gh_105


def _guarded_job_env_workflow() -> str:
    return (
        "on: [pull_request_target, issues]\n"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "    outputs:\n"
        "      val: '${{ steps.s.outputs.v }}'\n"
        "    steps:\n"
        "      - id: s\n"
        "        run: echo v=hi >> $GITHUB_OUTPUT\n"
        "  consume:\n"
        "    if: github.event_name == 'pull_request_target'\n"
        "    needs: produce\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "    env:\n"
        "      VALUE: '${{ needs.produce.outputs.val }}'\n"
        "    steps:\n"
        "      - if: github.event_name == 'issues'\n"
        "        uses: example/publish@0123456789012345678901234567890123456789\n"
        "        with:\n"
        "          token: '${{ secrets.STATUS_PAT }}'\n"
    )


def test_certified_step_guard_stops_at_same_item_sibling_key() -> None:
    content = _guarded_job_env_workflow()
    index = AgentGuardIndex(content)

    guards = dict(_certified_guards(content, index))

    assert guards[("jobs", "consume", "steps", 0, "if")] == ("github.event_name == 'issues'")


def test_disjoint_job_and_authority_step_events_do_not_compose(tmp_path) -> None:
    content = _guarded_job_env_workflow()
    workflow = tmp_path / "workflow.yml"
    workflow.write_text(content, encoding="utf-8")
    file = str(workflow)
    structure = _execution_structure(content)
    db = Database()
    db.add("job_context", JobContextFact(file, "produce", True, True, False, False))
    db.add("job_context", JobContextFact(file, "consume", True, True, True, False))
    db.add(
        "execution_context",
        ExecutionContextFact(
            file,
            frozenset({"pull_request_target", "issues"}),
            frozenset({"pull_request_target", "issues"}),
            structure.keys,
            structure.guards,
            structure.owners,
        ),
    )

    assert list(_compose_chain_gh_105(db)) == []


def test_collection_valued_step_guard_stays_uncertified() -> None:
    content = (
        "on: issues\n"
        "jobs:\n"
        "  consume:\n"
        "    steps:\n"
        "      - if:\n"
        "          event_name: issues\n"
        "        run: echo ok\n"
    )
    index = AgentGuardIndex(content)

    assert ("jobs", "consume", "steps", 0, "if") not in dict(_certified_guards(content, index))
