"""A shell comment transform is not a valid JavaScript benign variant."""

from taintly.rules.github.taint import RULES
from taintly.testing.fp_simulator import run_fp_simulation


def test_github_script_is_outside_shell_comment_probe():
    rule = next(rule for rule in RULES if rule.id == "TAINT-GH-013")
    assert type(rule.pattern).__name__ == "GithubScriptInterpolationPattern"
    assert run_fp_simulation([rule]) == []


def test_actual_yaml_comments_do_not_create_a_script_sink():
    rule = next(rule for rule in RULES if rule.id == "TAINT-GH-013")
    source = """on: pull_request
jobs:
  inspect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: console.log('static');
        # description: ${{ github.event.pull_request.title }}
"""
    assert rule.pattern.check(source, source.splitlines()) == []
