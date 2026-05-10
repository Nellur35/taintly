"""Integration test for ``--github-repo`` flag on the scan path.

The flag was originally registered solely for ``--platform-audit``;
this test asserts that the same flag now drives the static-guard
``WorkflowContext`` on the ordinary scan path, so users running
taintly against a non-git directory (or one whose remote is not
``origin``) can still get repo-mismatch suppression by passing
``--github-repo OWNER/REPO`` explicitly.
"""

from __future__ import annotations

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform
from taintly.staticguard import WorkflowContext


def _write_workflow(tmp_path):
    workflow = tmp_path / ".github" / "workflows" / "wf.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on: pull_request_target\n"
        "jobs:\n"
        "  dead:\n"
        "    if: github.repository_owner == 'someone-else'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        '      - run: echo "${{ github.event.pull_request.title }}"\n'
    )
    return workflow


def test_github_repo_flag_drives_static_guard_on_non_git_dir(tmp_path):
    """``--github-repo`` populates ``WorkflowContext`` on the scan path.

    Without the flag (and without an auto-detectable git remote),
    SEC4-GH-004 fires inside the would-be-dead job.  With the flag
    populated, the static-guard suppresses the finding because the
    ``github.repository_owner`` comparison evaluates to STATIC_FALSE.
    """
    _write_workflow(tmp_path)
    rules = load_rules_for_platform(Platform.GITHUB)

    reports_no_ctx = scan_repo(
        str(tmp_path), rules, Platform.GITHUB, explicit_github_repoctx=None
    )
    findings_no_ctx = [f for r in reports_no_ctx for f in r.findings]
    sec4_no_ctx = [f for f in findings_no_ctx if f.rule_id == "SEC4-GH-004"]
    assert sec4_no_ctx, (
        "Without explicit context (and no git remote), SEC4-GH-004 must fire "
        "in the would-be-dead job; otherwise the test cannot detect the "
        "wiring fix."
    )

    ctx = WorkflowContext(repository="me/myrepo", repository_owner="me")
    reports_with_ctx = scan_repo(
        str(tmp_path), rules, Platform.GITHUB, explicit_github_repoctx=ctx
    )
    findings_with_ctx = [f for r in reports_with_ctx for f in r.findings]
    sec4_with_ctx = [f for f in findings_with_ctx if f.rule_id == "SEC4-GH-004"]
    assert not sec4_with_ctx, (
        "With repo-mismatch context, SEC4-GH-004 inside the dead job must "
        f"be suppressed; got {[(f.line, f.rule_id) for f in sec4_with_ctx]}"
    )
