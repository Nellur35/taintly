"""CHAIN-GH-105 — cross-job privilege-escalation composer rule (P1.3).

CHAIN-GH-105 fires when a LOW-privilege producer job (read-only token)
declares an output that a HIGH-privilege consumer job (write-capable
token) reads via ``${{ needs.<producer>.outputs.<name> }}``. The
producer is the attacker-influenceable surface; its output crossing
the job boundary into a write-capable job that exercises authority is
a candidate privilege-escalation path. Argument-level provenance remains
review-needed.

CorpusPattern composer rules don't fit the single-file self-test
harness (the join spans jobs and per-job permission context), so they
are exercised here against ``tmp_path`` repos with realistic
``.github/workflows/`` layouts — the same convention as
``test_cross_workflow_rules.py``.

The rule depends on per-job ``permissions:`` attribution: when both
jobs inherit the workflow default, the gradient is unobservable and
the rule conservatively does not fire (a documented precision choice,
pinned by ``test_negative_workflow_default_only``).
"""

from __future__ import annotations

from pathlib import Path

from taintly.engine import scan_repo
from taintly.models import Platform, Severity
from taintly.rules.registry import load_all_rules


def _write_workflow(tmp_path: Path, name: str, content: str) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    p = wf_dir / name
    p.write_text(content, encoding="utf-8")
    return p


def _fires(tmp_path: Path) -> list:
    rules = load_all_rules()
    reports = scan_repo(str(tmp_path), rules, Platform.GITHUB)
    return [f for r in reports for f in r.findings if f.rule_id == "CHAIN-GH-105"]


# ---------------------------------------------------------------------------
# Positive — read-only producer output flows into a write-capable consumer
# ---------------------------------------------------------------------------

_POSITIVE = (
    "on: pull_request_target\n"
    "jobs:\n"
    "  produce:\n"
    "    runs-on: ubuntu-latest\n"
    "    permissions:\n"
    "      contents: read\n"
    "    outputs:\n"
    "      val: ${{ steps.s.outputs.v }}\n"
    "    steps:\n"
    "      - id: s\n"
    '        run: echo "v=hi" >> $GITHUB_OUTPUT\n'
    "  consume:\n"
    "    needs: produce\n"
    "    runs-on: ubuntu-latest\n"
    "    permissions:\n"
    "      contents: write\n"
    "      id-token: write\n"
    "    steps:\n"
    '      - run: gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"\n'
)


def test_positive_read_producer_into_write_consumer(tmp_path: Path) -> None:
    _write_workflow(tmp_path, "w.yml", _POSITIVE)
    fires = _fires(tmp_path)
    assert len(fires) == 1
    f = fires[0]
    # Anchored on the consumer's escalation point (the needs-output ref).
    assert f.line == 19
    assert f.severity == Severity.MEDIUM
    # Provenance names the producer -> consumer gradient.
    assert "produce" in f.snippet
    assert "consume" in f.snippet
    assert "needs.produce.outputs.val" in f.snippet


def test_positive_external_issue_event_can_retain_write_token(tmp_path: Path) -> None:
    content = _POSITIVE.replace("on: pull_request_target", "on: issues")
    _write_workflow(tmp_path, "w.yml", content)
    assert len(_fires(tmp_path)) == 1


def test_negative_workflow_run_with_push_only_parent(tmp_path: Path) -> None:
    child = _POSITIVE.replace(
        "on: pull_request_target\n",
        "on:\n  workflow_run:\n    workflows: ['Trusted Build']\n    types: [completed]\n",
    )
    _write_workflow(tmp_path, "child.yml", child)
    _write_workflow(
        tmp_path,
        "parent.yml",
        "name: Trusted Build\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo ok\n",
    )
    assert _fires(tmp_path) == []


def test_positive_workflow_run_with_pull_request_parent(tmp_path: Path) -> None:
    child = _POSITIVE.replace(
        "on: pull_request_target\n",
        "on:\n  workflow_run:\n    workflows: ['PR Build']\n    types: [completed]\n",
    )
    _write_workflow(tmp_path, "child.yml", child)
    _write_workflow(
        tmp_path,
        "parent.yml",
        "name: PR Build\non: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo ok\n",
    )
    assert len(_fires(tmp_path)) == 1


# ---------------------------------------------------------------------------
# Negatives
# ---------------------------------------------------------------------------


def test_negative_same_privilege(tmp_path: Path) -> None:
    """Both jobs read-only: no gradient, no fire."""
    content = _POSITIVE.replace(
        "      contents: write\n      id-token: write\n",
        "      contents: read\n",
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []


def test_negative_fork_pull_request_write_scope_is_downgraded(tmp_path: Path) -> None:
    """Workflow YAML alone cannot prove the private-repo setting that opts a
    fork pull request out of GitHub's default write-to-read downgrade."""
    content = _POSITIVE.replace("on: pull_request_target", "on: pull_request")
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []


def test_negative_maintainer_only_release_trigger(tmp_path: Path) -> None:
    content = _POSITIVE.replace("on: pull_request_target", "on: release")
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []


def test_negative_write_permission_without_authority_operation(tmp_path: Path) -> None:
    content = _POSITIVE.replace(
        'gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"',
        'echo "${{ needs.produce.outputs.val }}"',
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []


def test_negative_summary_only_github_script(tmp_path: Path) -> None:
    content = _POSITIVE.replace(
        '      - run: gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"\n',
        "      - uses: actions/github-script@v9\n"
        "        env:\n"
        "          VALUE: ${{ needs.produce.outputs.val }}\n"
        "        with:\n"
        "          script: |\n"
        "            core.summary.addCodeBlock(process.env.VALUE).write()\n",
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []


def test_positive_authority_action_receives_token_and_output(tmp_path: Path) -> None:
    content = _POSITIVE.replace(
        '      - run: gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"\n',
        "      - uses: example/set-status@0123456789012345678901234567890123456789\n"
        "        with:\n"
        "          sha: ${{ needs.produce.outputs.val }}\n"
        "          token: '${{ secrets.STATUS_PAT }}'\n",
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert len(_fires(tmp_path)) == 1


def test_negative_read_only_github_api_call_is_not_authority_use(tmp_path: Path) -> None:
    content = _POSITIVE.replace(
        '      - run: gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"\n',
        "      - uses: actions/github-script@v9\n"
        "        env:\n"
        "          VALUE: ${{ needs.produce.outputs.val }}\n"
        "        with:\n"
        "          script: |\n"
        "            await github.rest.issues.get({ issue_number: process.env.VALUE })\n",
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []


def test_positive_mutating_github_request(tmp_path: Path) -> None:
    content = _POSITIVE.replace(
        '      - run: gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"\n',
        "      - uses: actions/github-script@v9\n"
        "        env:\n"
        "          VALUE: ${{ needs.produce.outputs.val }}\n"
        "        with:\n"
        "          script: |\n"
        "            await github.request('POST /repos/{owner}/{repo}/dispatches', {\n"
        "              event_type: process.env.VALUE\n"
        "            })\n",
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert len(_fires(tmp_path)) == 1


def test_positive_mutating_github_rest_call(tmp_path: Path) -> None:
    content = _POSITIVE.replace(
        'gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"',
        "github.rest.issues.createComment({ body: '${{ needs.produce.outputs.val }}' })",
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert len(_fires(tmp_path)) == 1


def test_positive_graphql_mutation(tmp_path: Path) -> None:
    content = _POSITIVE.replace(
        'gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"',
        "github.graphql(`mutation { addComment(input: "
        "${{ needs.produce.outputs.val }}) { clientMutationId } }`)",
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert len(_fires(tmp_path)) == 1


def test_negative_http_verb_elsewhere_does_not_make_request_mutating(tmp_path: Path) -> None:
    content = _POSITIVE.replace(
        '      - run: gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"\n',
        "      - uses: actions/github-script@v9\n"
        "        env:\n"
        "          VALUE: ${{ needs.produce.outputs.val }}\n"
        "        with:\n"
        "          script: |\n"
        "            core.info('POST is documented here')\n"
        "            await github.request('GET /repos/{owner}/{repo}')\n",
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []


def test_positive_gh_api_implicit_post_from_field(tmp_path: Path) -> None:
    content = _POSITIVE.replace(
        'gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"',
        'gh api repos/o/r/dispatches -f event_type="${{ needs.produce.outputs.val }}"',
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert len(_fires(tmp_path)) == 1


def test_negative_gh_api_explicit_get_with_field(tmp_path: Path) -> None:
    content = _POSITIVE.replace(
        'gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"',
        'gh api --method GET search/issues -f q="${{ needs.produce.outputs.val }}"',
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []


def test_positive_push_operation(tmp_path: Path) -> None:
    content = _POSITIVE.replace(
        'gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"',
        'git tag "${{ needs.produce.outputs.val }}" && git push origin --tags',
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert len(_fires(tmp_path)) == 1


def test_negative_step_reference_cannot_borrow_authority_from_other_step(
    tmp_path: Path,
) -> None:
    content = _POSITIVE.replace(
        '      - run: gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"\n',
        '      - run: echo "${{ needs.produce.outputs.val }}"\n'
        "      - run: gh issue edit 1 --add-label unrelated\n",
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []


def test_positive_job_env_can_feed_later_authority_step(tmp_path: Path) -> None:
    content = _POSITIVE.replace(
        '    steps:\n      - run: gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"\n',
        "    env:\n"
        "      VALUE: ${{ needs.produce.outputs.val }}\n"
        "    steps:\n"
        '      - run: gh issue edit 1 --add-label "$VALUE"\n',
        1,
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert len(_fires(tmp_path)) == 1


def test_negative_env_output_used_only_by_multiline_log_after_write(tmp_path: Path) -> None:
    content = _POSITIVE.replace(
        '      - run: gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"\n',
        "      - uses: actions/github-script@v9\n"
        "        with:\n"
        "          github-token: ${{ github.token }}\n"
        "          script: |\n"
        "            await github.request('POST /repos/o/r/dispatches', {})\n"
        "            console.info(\n"
        "              `Completed: ${process.env.VALUE}`\n"
        "            )\n"
        "        env:\n"
        "          VALUE: ${{ needs.produce.outputs.val }}\n",
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []


def test_positive_env_output_nested_write_inside_log_is_not_suppressed(tmp_path: Path) -> None:
    content = _POSITIVE.replace(
        '      - run: gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"\n',
        "      - uses: actions/github-script@v9\n"
        "        with:\n"
        "          github-token: ${{ github.token }}\n"
        "          script: |\n"
        "            console.info(await github.request(\n"
        "              'POST /repos/o/r/dispatches',\n"
        "              { value: process.env.VALUE }\n"
        "            ))\n"
        "        env:\n"
        "          VALUE: ${{ needs.produce.outputs.val }}\n",
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert len(_fires(tmp_path)) == 1


def test_positive_env_output_assigned_before_privileged_call(tmp_path: Path) -> None:
    content = _POSITIVE.replace(
        '      - run: gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"\n',
        "      - uses: actions/github-script@v9\n"
        "        with:\n"
        "          github-token: ${{ github.token }}\n"
        "          script: |\n"
        "            const value = process.env.VALUE\n"
        "            await github.request('POST /repos/o/r/dispatches', { value })\n"
        "        env:\n"
        "          VALUE: ${{ needs.produce.outputs.val }}\n",
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert len(_fires(tmp_path)) == 1


def test_positive_env_output_logged_and_used_by_privileged_call(tmp_path: Path) -> None:
    content = _POSITIVE.replace(
        '      - run: gh issue edit 1 --add-label "${{ needs.produce.outputs.val }}"\n',
        "      - uses: actions/github-script@v9\n"
        "        with:\n"
        "          github-token: ${{ github.token }}\n"
        "          script: |\n"
        "            console.info(`Value: ${process.env.VALUE}`)\n"
        "            await github.request('POST /repos/o/r/dispatches', {\n"
        "              value: process.env.VALUE\n"
        "            })\n"
        "        env:\n"
        "          VALUE: ${{ needs.produce.outputs.val }}\n",
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert len(_fires(tmp_path)) == 1


def test_negative_high_to_low(tmp_path: Path) -> None:
    """Producer write, consumer read: the gradient runs the safe
    direction (privileged data into an unprivileged job), no fire."""
    content = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "    outputs:\n"
        "      val: ${{ steps.s.outputs.v }}\n"
        "    steps:\n"
        "      - id: s\n"
        '        run: echo "v=hi" >> $GITHUB_OUTPUT\n'
        "  consume:\n"
        "    needs: produce\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "    steps:\n"
        "      - run: echo ${{ needs.produce.outputs.val }}\n"
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []


def test_negative_no_crossjob_edge(tmp_path: Path) -> None:
    """A write-capable job exists, but it never reads the read-only
    job's output via needs.*.outputs — no cross-job data edge, no fire."""
    content = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "    outputs:\n"
        "      val: x\n"
        "    steps:\n"
        "      - run: echo hi\n"
        "  consume:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "    steps:\n"
        "      - run: echo standalone\n"
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []


def test_negative_workflow_default_only(tmp_path: Path) -> None:
    """Neither job declares its own permissions: block. The gradient
    is unobservable (both inherit the workflow default) and the rule
    conservatively does NOT fire — the documented precision choice."""
    content = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        "    outputs:\n"
        "      val: ${{ steps.s.outputs.v }}\n"
        "    steps:\n"
        "      - id: s\n"
        '        run: echo "v=hi" >> $GITHUB_OUTPUT\n'
        "  consume:\n"
        "    needs: produce\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ${{ needs.produce.outputs.val }}\n"
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []


def test_negative_trusted_bot_gate(tmp_path: Path) -> None:
    """A dependabot-gated consumer suppresses the chain: the producer
    surface is not externally attacker-controllable."""
    content = (
        "on: pull_request_target\n"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "    outputs:\n"
        "      val: ${{ steps.s.outputs.v }}\n"
        "    steps:\n"
        "      - id: s\n"
        '        run: echo "v=hi" >> $GITHUB_OUTPUT\n'
        "  consume:\n"
        "    needs: produce\n"
        "    if: github.actor == 'dependabot[bot]'\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "    steps:\n"
        "      - run: echo ${{ needs.produce.outputs.val }}\n"
    )
    _write_workflow(tmp_path, "w.yml", content)
    assert _fires(tmp_path) == []
