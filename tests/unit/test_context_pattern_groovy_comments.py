"""Tests for Groovy-comment-aware ``requires`` / ``requires_absent``
gating in :meth:`ContextPattern._check_file_scoped`.

The motivating case: LOTP-JK-001 fires on ``build tool + PR-context
variable in same Jenkinsfile``.  A Jenkinsfile that *only mentions*
``env.CHANGE_ID`` inside a ``/* */`` documentation comment (and
runs on cron, not on PRs) used to satisfy the ``requires`` gate and
produce a HIGH false positive on every build-tool invocation.

The fix blanks Groovy ``//`` and ``/* */`` comments from the
content used for the ``requires`` / ``requires_absent`` checks,
leaving the per-line anchor pass (and its own ``exclude``
patterns) untouched.
"""

from __future__ import annotations

from textwrap import dedent

from taintly.models import Platform, _strip_groovy_comments
from taintly.rules.registry import load_rules_for_platform


def _jenkins_rule(rule_id: str):
    for r in load_rules_for_platform(Platform.JENKINS):
        if r.id == rule_id:
            return r
    raise AssertionError(f"rule {rule_id} not registered")


def test_strip_groovy_comments_blanks_block_comment():
    content = dedent(
        """
        /*
         * uses env.CHANGE_ID in some places
         */
        pipeline { agent any }
        """
    ).lstrip()
    stripped = _strip_groovy_comments(content)
    assert "env.CHANGE_ID" not in stripped
    assert "pipeline { agent any }" in stripped


def test_strip_groovy_comments_blanks_line_comment():
    content = "sh 'echo hi'   // do not delete env.CHANGE_ID reference"
    stripped = _strip_groovy_comments(content)
    assert "env.CHANGE_ID" not in stripped
    assert "sh 'echo hi'" in stripped


def test_strip_groovy_comments_preserves_url_scheme():
    """``http://example.com`` in a YAML scalar must not be stripped —
    the ``://`` is not a Groovy line comment."""
    content = dedent(
        """
        build:
          script: curl http://example.com
        test:
          script: make test
        """
    ).lstrip()
    assert _strip_groovy_comments(content) == content


def test_strip_groovy_comments_preserves_string_body():
    """A ``//`` inside a triple-quoted Groovy string is shell heredoc
    content, not a comment — must survive the strip."""
    content = "sh '''cat <<EOF\n// not a comment, shell body\nEOF\n'''"
    stripped = _strip_groovy_comments(content)
    assert "// not a comment, shell body" in stripped


def test_strip_groovy_comments_preserves_line_count():
    content = "/*\nmulti\nline\ncomment\n*/\ncode here"
    assert content.count("\n") == _strip_groovy_comments(content).count("\n")


def test_strip_groovy_comments_no_op_on_yaml():
    """No ``//`` or ``/*`` markers anywhere -> identity."""
    content = "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
    assert _strip_groovy_comments(content) is content


def test_lotp_jk_001_does_not_fire_on_doc_comment_pr_context():
    """LOTP-JK-001 used to fire when the PR-context variable was
    mentioned only in a ``/* */`` documentation comment.  After the
    comment-aware strip, the rule must NOT fire on a cron-only
    pipeline whose only ``env.CHANGE_ID`` reference is in a comment."""
    content = dedent(
        """
        /* Documentation
         * This Jenkinsfile uses env.CHANGE_ID in some places.
         * Currently it's only used for logging — never to gate execution.
         */

        pipeline {
            agent any
            triggers { cron('H 2 * * *') }
            stages {
                stage('Build') {
                    steps {
                        sh 'npm install'
                        sh 'npm test'
                    }
                }
            }
        }
        """
    ).lstrip()
    rule = _jenkins_rule("LOTP-JK-001")
    assert rule.pattern.check(content, content.splitlines()) == []


def test_lotp_jk_001_still_fires_when_pr_context_in_real_code():
    """Sanity: a Jenkinsfile that genuinely references env.CHANGE_ID
    in code (not just a comment) MUST still fire LOTP-JK-001."""
    content = dedent(
        """
        pipeline {
            agent any
            stages {
                stage('build') {
                    when { changeRequest() }
                    steps {
                        echo "Building PR #${env.CHANGE_ID}"
                        sh 'npm install'
                    }
                }
            }
        }
        """
    ).lstrip()
    rule = _jenkins_rule("LOTP-JK-001")
    findings = rule.pattern.check(content, content.splitlines())
    assert findings, "rule should still fire when PR context is in real code"


def test_lotp_jk_001_does_not_fire_on_line_comment_pr_context():
    """A ``// uses env.CHANGE_ID`` mid-line comment is also not real
    PR-context evidence."""
    content = dedent(
        """
        pipeline {
            agent any
            stages {
                stage('build') {
                    steps {
                        // Migration note: env.CHANGE_ID will be removed
                        sh 'npm install'
                    }
                }
            }
        }
        """
    ).lstrip()
    rule = _jenkins_rule("LOTP-JK-001")
    assert rule.pattern.check(content, content.splitlines()) == []


def test_context_pattern_binds_platform_from_rule():
    """``Rule.__post_init__`` propagates the rule's platform onto the
    pattern so the comment-strip can gate on it.  All ContextPattern
    instances reachable through the rule registry must carry their
    rule's platform."""
    for platform in (Platform.JENKINS, Platform.GITHUB, Platform.GITLAB):
        for rule in load_rules_for_platform(platform):
            if hasattr(rule.pattern, "_platform"):
                assert rule.pattern._platform is platform, (
                    f"{rule.id}: pattern._platform={rule.pattern._platform!r} "
                    f"but rule.platform={platform!r}"
                )


def test_strip_does_not_apply_to_github_rules():
    """GitHub workflows can carry inline JavaScript (``actions/github-script``)
    whose ``//`` comments must NOT be blanked by the Groovy-comment-strip.
    The strip is gated on ``platform == Platform.JENKINS``.

    Construct a ContextPattern instance directly with each platform and
    confirm the requires-gate sees the original content (JS comments
    intact) on non-Jenkins platforms.
    """
    from taintly.models import ContextPattern

    # A pattern whose ``requires`` would match the JS-in-YAML comment
    # text iff the comment is NOT stripped.
    pat = ContextPattern(
        anchor=r"console\.log",
        requires=r"workflow_dispatch",
    )

    workflow_with_js = dedent(
        """
        name: ci
        on: [pull_request]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@v7
                with:
                  script: |
                    // For workflow_dispatch, use the explicitly provided PR.
                    console.log("ok");
        """
    ).lstrip()
    lines = workflow_with_js.splitlines()

    # Default: no platform bound -> no strip -> requires matches.
    assert pat._platform is None
    assert pat.check(workflow_with_js, lines), "default (unbound) should not strip"

    # GitHub-bound: strip is gated off, requires still matches.
    pat._platform = Platform.GITHUB
    assert pat.check(workflow_with_js, lines), "GitHub-bound must not strip"

    # Jenkins-bound: strip is on, comment blanked, requires no longer matches.
    pat._platform = Platform.JENKINS
    assert pat.check(workflow_with_js, lines) == [], (
        "Jenkins-bound should strip the JS comment from the gating content"
    )
