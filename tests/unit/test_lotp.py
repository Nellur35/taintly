"""Integration-style tests for LOTP rules across all three platforms.

Each test exercises the rule pattern directly against a YAML / Groovy
snippet and asserts whether the rule fires. These are in addition to the
rule-level self-test samples — the value here is regression coverage
across platforms using a uniform fixture style.
"""

from __future__ import annotations

import pytest

from taintly.rules.registry import get_rule_by_id


def _fires(rule_id: str, body: str) -> bool:
    rule = get_rule_by_id(rule_id)
    assert rule is not None, f"Rule {rule_id} not loaded"
    return bool(rule.pattern.check(body, body.splitlines()))


# ---------------------------------------------------------------------------
# GitHub (LOTP-GH-001) — covered in depth by the self-test samples;
# re-check the central claim here.
# ---------------------------------------------------------------------------


def test_gh_lotp_fires_on_pr_head_checkout_plus_build_tool():
    yaml = (
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: npm install\n"
    )
    assert _fires("LOTP-GH-001", yaml)


def test_gh_lotp_silent_without_pr_head_checkout():
    yaml = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: npm install\n"
    )
    assert not _fires("LOTP-GH-001", yaml)


def test_gh_lotp_flow_style_trigger_does_not_downgrade_exploitability():
    """A flow-style ``on:`` block must NOT collapse the exploitability
    context of the finding it gates.

    LOTP-GH-001 fires off the PR-head checkout + build tool, so it
    surfaces regardless of how the trigger is written — but the
    per-file context analyzer derives exploitability from the trigger,
    and a line-anchored regex used to miss flow-style triggers,
    silently downgrading a CRITICAL finding's exploitability from
    ``medium`` to ``low`` and pushing it down the report. Lock the fix:
    the flow-style fixture must produce the SAME exploitability as the
    block-style equivalent.
    """
    from taintly.engine import scan_file
    from taintly.models import Platform
    from taintly.rules.registry import load_rules_for_platform

    rules = load_rules_for_platform(Platform.GITHUB)
    ref = "${{ github.event.pull_request.head.sha }}"
    body = (
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n          ref: " + ref + "\n"
        "      - run: pip install .\n"
    )
    block = "on:\n  pull_request_target:\n    types: [opened]\n" + body
    flow = "on: { pull_request_target: { types: [opened] } }\n" + body

    def _lotp(content: str):
        findings = scan_file("wf.yml", rules, _content=content)
        hits = [f for f in findings if f.rule_id == "LOTP-GH-001"]
        assert hits, "LOTP-GH-001 must fire on PR-head checkout + build tool"
        return hits[0]

    assert _lotp(flow).exploitability == _lotp(block).exploitability


# ---------------------------------------------------------------------------
# GitLab (LOTP-GL-001)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body, should_fire",
    [
        # Fire: modern rules: if merge_request_event + build tool
        (
            "build:\n"
            "  rules:\n"
            "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
            "  script:\n"
            "    - npm install\n",
            True,
        ),
        # Fire: legacy only: merge_requests list + build tool
        (
            "test:\n"
            "  only:\n"
            "    - merge_requests\n"
            "  script:\n"
            "    - pip install -r requirements.txt\n",
            True,
        ),
        # Fire: docker build under MR event
        (
            "image:\n"
            "  rules:\n"
            "    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'\n"
            "  script:\n"
            "    - docker build -t app .\n",
            True,
        ),
        # No fire: MR-event job without a build tool
        (
            "lint:\n"
            "  only:\n"
            "    - merge_requests\n"
            "  script:\n"
            "    - echo linting\n",
            False,
        ),
        # No fire: build tool in a default-branch-gated job
        (
            "deploy:\n"
            "  rules:\n"
            "    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'\n"
            "  script:\n"
            "    - npm ci --production\n",
            False,
        ),
        # No fire: pip install of a named PyPI package (repo manifest not read)
        (
            "review:\n"
            "  rules:\n"
            "    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'\n"
            "  script:\n"
            "    - pip install PyGithub\n",
            False,
        ),
    ],
)
def test_gl_lotp_behaviour(body, should_fire):
    assert _fires("LOTP-GL-001", body) == should_fire


# ---------------------------------------------------------------------------
# Jenkins (LOTP-JK-001)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body, should_fire",
    [
        # Fire: env.CHANGE_ID + npm install
        (
            "pipeline {\n"
            "    agent any\n"
            "    stages {\n"
            "        stage('build') {\n"
            "            when { changeRequest() }\n"
            "            steps {\n"
            "                echo \"PR #${env.CHANGE_ID}\"\n"
            "                sh 'npm install'\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n",
            True,
        ),
        # Fire: ghprb legacy plugin + pip install .
        (
            "node {\n"
            "    if (env.ghprbPullId) {\n"
            "        sh 'pip install .'\n"
            "    }\n"
            "}\n",
            True,
        ),
        # Fire: GERRIT_CHANGE_ID + docker build
        (
            "pipeline {\n"
            "    agent any\n"
            "    stages {\n"
            "        stage('image') {\n"
            "            steps {\n"
            "                echo \"${GERRIT_CHANGE_ID}\"\n"
            "                sh 'docker build -t review .'\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n",
            True,
        ),
        # No fire: no PR context
        (
            "pipeline {\n"
            "    agent any\n"
            "    stages {\n"
            "        stage('build') { steps { sh 'npm install' } }\n"
            "    }\n"
            "}\n",
            False,
        ),
        # No fire: PR context with non-build command
        (
            "pipeline {\n"
            "    agent any\n"
            "    stages {\n"
            "        stage('status') {\n"
            "            steps {\n"
            "                echo \"PR ${env.CHANGE_ID}\"\n"
            "                sh 'curl -X POST https://hooks/ping'\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n",
            False,
        ),
    ],
)
def test_jk_lotp_behaviour(body, should_fire):
    assert _fires("LOTP-JK-001", body) == should_fire


# ---------------------------------------------------------------------------
# Shared anchor reachable by all three platforms
# ---------------------------------------------------------------------------


def test_shared_build_tool_anchor_module_is_importable():
    """Regression: the anchor module lives at rules/_build_tools.py so
    platform-specific rule files can import it consistently via
    `.._build_tools`."""
    from taintly.rules._build_tools import BUILD_TOOL_ANCHOR, BUILD_TOOL_FRAGMENTS

    assert isinstance(BUILD_TOOL_ANCHOR, str)
    assert len(BUILD_TOOL_FRAGMENTS) >= 12, "fewer tool families than the v2 target of ≥12"
