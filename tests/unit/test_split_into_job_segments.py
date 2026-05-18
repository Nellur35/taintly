"""Tests for :func:`taintly.models._split_into_job_segments`.

The segmenter has three branches: GitHub Actions (``jobs:`` block),
GitLab CI (0-indent keys), and Jenkinsfile (single segment).  The
Jenkinsfile branch closes a real bug — without it, a Groovy ``//``
comment that contains a colon (a license-header URL, a vim modeline,
etc.) was treated as a 0-indent job key and produced fake segments.
"""

from __future__ import annotations

from textwrap import dedent

from taintly.models import _split_into_job_segments


def test_github_actions_jobs_block_segments_correctly():
    lines = (
        dedent(
            """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo hi
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo bye
        """
        )
        .lstrip()
        .splitlines()
    )
    # Pre-job preamble + 2 jobs.
    assert len(_split_into_job_segments(lines)) == 3


def test_gitlab_ci_zero_indent_keys_segment_correctly():
    lines = (
        dedent(
            """
        image: alpine
        build:
          script: make build
        test:
          script: make test
        deploy:
          script: make deploy
        """
        )
        .lstrip()
        .splitlines()
    )
    # Pre-job preamble + 3 jobs.
    assert len(_split_into_job_segments(lines)) == 3


def test_jenkinsfile_with_pipeline_block_is_single_segment():
    """A declarative ``pipeline { ... }`` Jenkinsfile is one job."""
    lines = (
        dedent(
            """
        #!/usr/bin/env groovy
        pipeline {
            agent any
            stages {
                stage('Build') { steps { sh 'make' } }
            }
        }
        """
        )
        .lstrip()
        .splitlines()
    )
    assert _split_into_job_segments(lines) == [(0, lines)]


def test_jenkinsfile_with_license_header_url_does_not_fake_segments():
    """Regression: a ``//`` comment whose body contains a colon-bearing
    URL (license headers, vim modelines) used to be treated as a
    0-indent job key, producing one fake segment per comment line."""
    lines = (
        dedent(
            """
        // Licensed under the Apache License, Version 2.0
        //     http://www.apache.org/licenses/LICENSE-2.0
        // See: https://example.com/docs for more info
        pipeline {
            agent any
            stages {
                stage('Build') { steps { sh 'make' } }
            }
        }
        """
        )
        .lstrip()
        .splitlines()
    )
    segments = _split_into_job_segments(lines)
    assert len(segments) == 1
    assert segments[0] == (0, lines)


def test_jenkinsfile_shared_library_call_is_single_segment():
    """Some Jenkinsfiles are just a shared-library call with a leading
    ``//`` comment (e.g. ``buildPlugin(...)``).  Must still collapse."""
    lines = (
        dedent(
            """
        // Windows controller tests crash with unexpected errors
        buildPlugin(useContainerAgent: true, forkCount: '0.5C', timeout: 360, configurations: [
            [platform: 'linux', jdk: 25],
            [platform: 'windows', jdk: 21],
        ])
        """
        )
        .lstrip()
        .splitlines()
    )
    assert _split_into_job_segments(lines) == [(0, lines)]


def test_jenkinsfile_scripted_node_block_is_single_segment():
    lines = (
        dedent(
            """
        node('docker') {
            stage('Build') { sh 'make' }
            stage('Test') { sh 'make test' }
        }
        """
        )
        .lstrip()
        .splitlines()
    )
    assert _split_into_job_segments(lines) == [(0, lines)]


def test_jenkinsfile_with_def_helper_is_single_segment():
    lines = (
        dedent(
            """
        def buildIt(jdk) {
            sh "JAVA_HOME=${jdk} ./mvnw install"
        }

        pipeline {
            agent any
            stages {
                stage('Build') { steps { buildIt('jdk21') } }
            }
        }
        """
        )
        .lstrip()
        .splitlines()
    )
    assert _split_into_job_segments(lines) == [(0, lines)]


def test_github_actions_with_inline_javascript_still_segments():
    """A GitHub Actions workflow that embeds JavaScript via
    ``actions/github-script@v7`` ``script: |`` blocks must not be
    misclassified as a Jenkinsfile.  Inline JS uses ``//`` line
    comments which are always indented (nested under ``script: |``)
    — the Jenkinsfile heuristic's ``//`` marker requires column 0
    so indented JS comments don't trigger it.
    """
    lines = (
        dedent(
            """
        name: ci
        on:
          workflow_dispatch:
          pull_request:
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@v7
                with:
                  script: |
                    // For workflow_dispatch, use the explicit PR number.
                    // Otherwise, fall back to the head sha.
                    const pr = Number(inputs.pr);
          test:
            runs-on: ubuntu-latest
            steps:
              - run: npm test
        """
        )
        .lstrip()
        .splitlines()
    )
    # Preamble + 2 jobs (build, test) — NOT a single segment.
    segments = _split_into_job_segments(lines)
    assert len(segments) == 3, (
        f"expected 3 segments (preamble + 2 jobs), got {len(segments)}: "
        f"JS-in-YAML may have triggered the Jenkinsfile heuristic"
    )


def test_yaml_with_http_url_value_still_segments():
    """``http://`` inside a YAML scalar value must not trigger the
    Jenkinsfile heuristic — the ``//`` marker requires line start."""
    lines = (
        dedent(
            """
        build:
          script: curl http://example.com
        test:
          script: make test
        """
        )
        .lstrip()
        .splitlines()
    )
    # Pre-job preamble (none here) + 2 jobs.
    assert len(_split_into_job_segments(lines)) == 2
