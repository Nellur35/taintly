from __future__ import annotations

from taintly.staticguard import Verdict, WorkflowContext, evaluate_if, find_dead_line_ranges


def test_evaluate_if_static_true_cases():
    assert evaluate_if(None) is Verdict.STATIC_TRUE
    assert evaluate_if("true") is Verdict.STATIC_TRUE
    assert evaluate_if("${{ true }}") is Verdict.STATIC_TRUE
    assert evaluate_if("! false") is Verdict.STATIC_TRUE


def test_evaluate_if_static_false_cases():
    assert evaluate_if("false") is Verdict.STATIC_FALSE
    assert evaluate_if("${{ false }}") is Verdict.STATIC_FALSE
    assert evaluate_if("! true") is Verdict.STATIC_FALSE


def test_evaluate_if_repo_identity_comparison():
    ctx = WorkflowContext(repository="Nellur35/taintly", repository_owner="Nellur35")

    assert evaluate_if("github.repository == 'Nellur35/taintly'", ctx) is Verdict.STATIC_TRUE
    assert evaluate_if("github.repository == 'other/repo'", ctx) is Verdict.STATIC_FALSE
    assert evaluate_if("github.repository_owner != 'other'", ctx) is Verdict.STATIC_TRUE


def test_evaluate_if_runtime_fallback():
    ctx = WorkflowContext(repository="Nellur35/taintly", repository_owner="Nellur35")

    assert evaluate_if("github.event_name == 'pull_request'", ctx) is Verdict.RUNTIME
    assert evaluate_if("success() && github.repository == 'Nellur35/taintly'", ctx) is Verdict.RUNTIME
    assert evaluate_if("${{ inputs.deploy == 'prod' }}", ctx) is Verdict.RUNTIME


def test_find_dead_line_ranges_for_dead_job_and_step():
    content = (
        "on:\n"
        "  pull_request:\n"
        "jobs:\n"
        "  dead_job:\n"
        "    if: false\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo dead job\n"
        "  live_job:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - if: ${{ false }}\n"
        "        run: echo dead step\n"
        "      - if: github.event_name == 'pull_request'\n"
        "        run: echo runtime step\n"
    )

    assert find_dead_line_ranges(content) == [(4, 8), (12, 13)]


def test_find_dead_line_ranges_for_repo_mismatch():
    content = (
        "on:\n"
        "  push:\n"
        "jobs:\n"
        "  release:\n"
        "    if: github.repository == 'other/repo'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo dead\n"
    )
    ctx = WorkflowContext(repository="Nellur35/taintly", repository_owner="Nellur35")

    assert find_dead_line_ranges(content, ctx) == [(4, 8)]
